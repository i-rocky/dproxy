package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/i-rocky/dproxy/internal/engine"
	networkpolicy "github.com/i-rocky/dproxy/internal/network"
	"github.com/i-rocky/dproxy/internal/policy"

	"github.com/stretchr/testify/require"
)

type fakeEngine struct {
	mu                 sync.Mutex
	calls              []string
	exit               int
	waitErr            error
	removeErr          error
	waitDelay          time.Duration
	commandPlan        policy.Plan
	commandTarget      string
	attachmentCloseErr error
}

func (f *fakeEngine) call(s string)                              { f.mu.Lock(); defer f.mu.Unlock(); f.calls = append(f.calls, s) }
func (f *fakeEngine) Verify(context.Context) error               { f.call("verify"); return nil }
func (f *fakeEngine) PullByDigest(context.Context, string) error { f.call("pull"); return nil }
func (f *fakeEngine) CreateNetwork(context.Context, policy.Plan) (engine.Resource, error) {
	f.call("create-network")
	return engine.Resource{ID: "network", Role: "network"}, nil
}
func (f *fakeEngine) StartGateway(context.Context, engine.GatewaySpec) (engine.Resource, error) {
	f.call("start-gateway")
	return engine.Resource{ID: "gateway", Role: engine.GatewayRole}, nil
}
func (f *fakeEngine) GatewayHealth(context.Context, engine.Resource, string) error {
	f.call("gateway-health")
	return nil
}
func (f *fakeEngine) StartCommand(_ context.Context, p policy.Plan, target string, _ bool) (engine.Resource, error) {
	f.call("create-command")
	f.commandPlan = p
	f.commandTarget = target
	return engine.Resource{ID: "command", Role: engine.CommandRole}, nil
}
func (f *fakeEngine) Attach(context.Context, string, engine.IO) (engine.Attachment, error) {
	f.call("attach-start")
	return fakeAttachment{closeErr: f.attachmentCloseErr}, nil
}
func (f *fakeEngine) Wait(context.Context, string) (int, error) {
	f.call("wait")
	time.Sleep(f.waitDelay)
	return f.exit, f.waitErr
}
func (f *fakeEngine) Signal(context.Context, string, os.Signal) error { f.call("signal"); return nil }
func (f *fakeEngine) Resize(_ context.Context, _ engine.ContainerID, height, width uint) error {
	f.call(fmt.Sprintf("resize-%dx%d", height, width))
	return nil
}
func (f *fakeEngine) RemoveContainer(context.Context, engine.Resource) error {
	f.call("remove-" + f.resourceRole())
	return f.removeErr
}
func (f *fakeEngine) resourceRole() string { // cleanup calls are LIFO and IDs are inspected below by wrapper
	return "container"
}
func (f *fakeEngine) RemoveNetwork(context.Context, engine.Resource) error {
	f.call("remove-network")
	return f.removeErr
}
func (f *fakeEngine) ListOwned(context.Context, engine.Ownership) ([]engine.Resource, error) {
	return nil, nil
}

type recordingEngine struct{ *fakeEngine }

func (f recordingEngine) RemoveContainer(ctx context.Context, r engine.Resource) error {
	f.call("remove-" + r.ID)
	return f.removeErr
}

type resizeFailingEngine struct{ *fakeEngine }

func (resizeFailingEngine) Resize(context.Context, engine.ContainerID, uint, uint) error {
	return errors.New("docker unreachable")
}

func TestResizeSurfacesTerminalAndEngineErrors(t *testing.T) {
	err := resize(context.Background(), &fakeEngine{}, "cmd", func() (uint, uint, error) { return 0, 0, errors.New("no tty") })
	require.ErrorContains(t, err, "query terminal size")

	err = resize(context.Background(), resizeFailingEngine{&fakeEngine{}}, "cmd", func() (uint, uint, error) { return 40, 120, nil })
	require.ErrorContains(t, err, "resize command terminal")
}

type fakeAttachment struct{ closeErr error }

func (fakeAttachment) Wait() error    { return nil }
func (a fakeAttachment) Close() error { return a.closeErr }

type fakeNetworkSession struct {
	id, gateway string
	calls       *[]string
}

func (s *fakeNetworkSession) InvocationID() string { return s.id }
func (s *fakeNetworkSession) GatewayID() string    { return s.gateway }
func (s *fakeNetworkSession) Close(context.Context) error {
	*s.calls = append(*s.calls, "close-network-session")
	return nil
}

type fakeNetworkManager struct{ calls *[]string }

func (m fakeNetworkManager) Begin(_ context.Context, r networkpolicy.Request) (networkpolicy.RuntimeSession, error) {
	*m.calls = append(*m.calls, "orchestrator-start-"+r.Plan.Network.Mode)
	gateway := ""
	if r.Plan.Network.Mode != "none" {
		gateway = "gateway"
	}
	return &fakeNetworkSession{id: "crypto-invocation", gateway: gateway, calls: m.calls}, nil
}

func runtimePlan(mode string) policy.Plan {
	p := policy.Plan{InvocationID: "inv", ProjectID: "project", Image: "repo@sha256:x", Network: policy.Network{Mode: mode}}
	return p
}
func testIO() IO { return IO{Stdin: bytes.NewReader(nil), Stdout: io.Discard, Stderr: io.Discard} }

func TestRunReturnsExitAndCleansUp(t *testing.T) {
	f := &fakeEngine{exit: 42}
	code, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Network: fakeNetworkManager{&f.calls}, CleanupTimeout: time.Second}, runtimePlan("public"), testIO())
	require.NoError(t, err)
	require.Equal(t, 42, code)
	require.Equal(t, []string{"verify", "pull", "orchestrator-start-public", "create-command", "attach-start", "wait", "remove-command", "close-network-session"}, f.calls)
	require.NotContains(t, f.calls, "create-network")
	require.NotContains(t, f.calls, "start-gateway")
	require.Equal(t, "crypto-invocation", f.commandPlan.InvocationID)
	require.Equal(t, "gateway", f.commandTarget)
}

func TestRunCleansWithBoundedFreshContextAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeEngine{exit: 130}
	cancel()
	code, err := Run(ctx, Dependencies{Engine: recordingEngine{f}, Network: fakeNetworkManager{&f.calls}, CleanupTimeout: 20 * time.Millisecond}, runtimePlan("none"), testIO())
	require.Equal(t, 130, code)
	require.NoError(t, err)
	require.Contains(t, f.calls, "remove-command")
}

func TestRunReturnsSetupErrorSeparatelyFromCommandExit(t *testing.T) {
	f := &fakeEngine{exit: 7, waitErr: errors.New("wait transport failed")}
	code, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Network: fakeNetworkManager{&f.calls}}, runtimePlan("none"), testIO())
	require.Equal(t, 7, code)
	require.ErrorContains(t, err, "wait")
}

func TestRunRelaysSignals(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGINT
	close(signals)
	f := &fakeEngine{waitDelay: 10 * time.Millisecond}
	_, _ = Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Network: fakeNetworkManager{&f.calls}, Signals: signals}, runtimePlan("none"), testIO())
	require.Contains(t, f.calls, "signal")
}

func TestRunRestoresTTYAndReportsCleanupFailure(t *testing.T) {
	restored := false
	f := &fakeEngine{removeErr: errors.New("remove failed")}
	code, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Network: fakeNetworkManager{&f.calls}}, runtimePlan("none"), IO{Stdin: bytes.NewReader(nil), Stdout: io.Discard, Stderr: io.Discard, TTY: true, MakeRaw: func() (func() error, error) { return func() error { restored = true; return nil }, nil }, TerminalSize: func() (uint, uint, error) { return 24, 80, nil }})
	require.Zero(t, code)
	require.ErrorContains(t, err, "cleanup")
	require.True(t, restored)
}

func TestRunPreservesKnownCommandStatusOnCleanupFailure(t *testing.T) {
	f := &fakeEngine{exit: 37, removeErr: errors.New("remove failed")}
	code, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Network: fakeNetworkManager{&f.calls}}, runtimePlan("none"), testIO())
	require.Equal(t, 37, code)
	var post *PostStartError
	require.ErrorAs(t, err, &post)
	status, known := post.PostStartStatus()
	require.True(t, known)
	require.Equal(t, 37, status)
}

func TestRunPreservesKnownCommandStatusOnAttachmentCloseFailure(t *testing.T) {
	f := &fakeEngine{exit: 37, attachmentCloseErr: errors.New("close failed")}
	code, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Network: fakeNetworkManager{&f.calls}}, runtimePlan("none"), testIO())
	require.Equal(t, 37, code)
	var post *PostStartError
	require.ErrorAs(t, err, &post)
	require.True(t, post.StatusKnown)
}

func TestRunRejectsTTYWithoutRawModeAndStillCleans(t *testing.T) {
	f := &fakeEngine{}
	_, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Network: fakeNetworkManager{&f.calls}}, runtimePlan("none"), IO{TTY: true})
	require.ErrorContains(t, err, "raw-mode")
	require.Contains(t, f.calls, "remove-command")
}

func TestRunDoesNotRequireCallerToCloseSignalChannel(t *testing.T) {
	f := &fakeEngine{}
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Network: fakeNetworkManager{&f.calls}, Signals: make(chan os.Signal)}, runtimePlan("none"), testIO())
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Run blocked waiting for caller-owned signal channel")
	}
}

func TestRunResizesTTYInitiallyAndOnWINCHWithoutSendingSignal(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGWINCH
	close(signals)
	sizes := [][2]uint{{24, 80}, {40, 120}}
	var i int
	f := &fakeEngine{waitDelay: 10 * time.Millisecond}
	_, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Network: fakeNetworkManager{&f.calls}, Signals: signals}, runtimePlan("none"), IO{TTY: true, MakeRaw: func() (func() error, error) { return func() error { return nil }, nil }, TerminalSize: func() (uint, uint, error) { size := sizes[i]; i++; return size[0], size[1], nil }})
	require.NoError(t, err)
	require.Contains(t, f.calls, "resize-24x80")
	require.Contains(t, f.calls, "resize-40x120")
	require.NotContains(t, f.calls, "signal")
}
