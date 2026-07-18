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

	"dproxy/internal/engine"
	"dproxy/internal/policy"

	"github.com/stretchr/testify/require"
)

type fakeEngine struct {
	mu        sync.Mutex
	calls     []string
	exit      int
	waitErr   error
	removeErr error
	waitDelay time.Duration
}

func (f *fakeEngine) call(s string)                              { f.mu.Lock(); defer f.mu.Unlock(); f.calls = append(f.calls, s) }
func (f *fakeEngine) Verify(context.Context) error               { f.call("verify"); return nil }
func (f *fakeEngine) PullByDigest(context.Context, string) error { f.call("pull"); return nil }
func (f *fakeEngine) CreateNetwork(context.Context, policy.Plan) (engine.Resource, error) {
	f.call("create-network")
	return engine.Resource{ID: "network", Role: "network"}, nil
}
func (f *fakeEngine) StartGateway(context.Context, policy.Plan, string) (engine.Resource, error) {
	f.call("start-gateway")
	return engine.Resource{ID: "gateway", Role: engine.GatewayRole}, nil
}
func (f *fakeEngine) StartCommand(context.Context, policy.Plan, string, bool) (engine.Resource, error) {
	f.call("create-command")
	return engine.Resource{ID: "command", Role: engine.CommandRole}, nil
}
func (f *fakeEngine) Attach(context.Context, string, engine.IO) (engine.Attachment, error) {
	f.call("attach-start")
	return fakeAttachment{}, nil
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

type fakeAttachment struct{}

func (fakeAttachment) Wait() error  { return nil }
func (fakeAttachment) Close() error { return nil }

func runtimePlan(mode string) policy.Plan {
	p := policy.Plan{InvocationID: "inv", ProjectID: "project", Image: "repo@sha256:x", Network: policy.Network{Mode: mode}}
	return p
}
func testIO() IO { return IO{Stdin: bytes.NewReader(nil), Stdout: io.Discard, Stderr: io.Discard} }

func TestRunReturnsExitAndCleansUp(t *testing.T) {
	f := &fakeEngine{exit: 42}
	code, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, CleanupTimeout: time.Second}, runtimePlan("public"), testIO())
	require.NoError(t, err)
	require.Equal(t, 42, code)
	require.Equal(t, []string{"verify", "pull", "create-network", "start-gateway", "create-command", "attach-start", "wait", "remove-command", "remove-gateway", "remove-network"}, f.calls)
}

func TestRunCleansWithBoundedFreshContextAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeEngine{exit: 130}
	cancel()
	code, err := Run(ctx, Dependencies{Engine: recordingEngine{f}, CleanupTimeout: 20 * time.Millisecond}, runtimePlan("none"), testIO())
	require.Equal(t, 130, code)
	require.NoError(t, err)
	require.Contains(t, f.calls, "remove-command")
}

func TestRunReturnsSetupErrorSeparatelyFromCommandExit(t *testing.T) {
	f := &fakeEngine{exit: 7, waitErr: errors.New("wait transport failed")}
	code, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}}, runtimePlan("none"), testIO())
	require.Equal(t, 7, code)
	require.ErrorContains(t, err, "wait")
}

func TestRunRelaysSignals(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGINT
	close(signals)
	f := &fakeEngine{waitDelay: 10 * time.Millisecond}
	_, _ = Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Signals: signals}, runtimePlan("none"), testIO())
	require.Contains(t, f.calls, "signal")
}

func TestRunRestoresTTYAndReportsCleanupFailure(t *testing.T) {
	restored := false
	f := &fakeEngine{removeErr: errors.New("remove failed")}
	code, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}}, runtimePlan("none"), IO{Stdin: bytes.NewReader(nil), Stdout: io.Discard, Stderr: io.Discard, TTY: true, MakeRaw: func() (func() error, error) { return func() error { restored = true; return nil }, nil }, TerminalSize: func() (uint, uint, error) { return 24, 80, nil }})
	require.Zero(t, code)
	require.ErrorContains(t, err, "cleanup")
	require.True(t, restored)
}

func TestRunRejectsTTYWithoutRawModeAndStillCleans(t *testing.T) {
	f := &fakeEngine{}
	_, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}}, runtimePlan("none"), IO{TTY: true})
	require.ErrorContains(t, err, "raw-mode")
	require.Contains(t, f.calls, "remove-command")
}

func TestRunDoesNotRequireCallerToCloseSignalChannel(t *testing.T) {
	f := &fakeEngine{}
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Signals: make(chan os.Signal)}, runtimePlan("none"), testIO())
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
	_, err := Run(context.Background(), Dependencies{Engine: recordingEngine{f}, Signals: signals}, runtimePlan("none"), IO{TTY: true, MakeRaw: func() (func() error, error) { return func() error { return nil }, nil }, TerminalSize: func() (uint, uint, error) { size := sizes[i]; i++; return size[0], size[1], nil }})
	require.NoError(t, err)
	require.Contains(t, f.calls, "resize-24x80")
	require.Contains(t, f.calls, "resize-40x120")
	require.NotContains(t, f.calls, "signal")
}
