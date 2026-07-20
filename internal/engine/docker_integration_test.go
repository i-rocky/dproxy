//go:build integration

package engine

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"dproxy/internal/policy"
	"dproxy/internal/testimage"

	"github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
)

type readinessWriter struct {
	mu    sync.Mutex
	seen  strings.Builder
	ready chan struct{}
	once  sync.Once
}

func (w *readinessWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.seen.Write(p)
	if strings.Contains(w.seen.String(), "ready") {
		w.once.Do(func() { close(w.ready) })
	}
	return len(p), nil
}

func integrationDocker(t *testing.T) (*Docker, policy.Plan) {
	t.Helper()
	api, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err, "Docker is required for integration qualification")
	t.Cleanup(func() { _ = api.Close() })
	image := os.Getenv("DPROXY_INTEGRATION_IMAGE")
	if image == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		image, err = testimage.Scratch(ctx, api, "test/fixtures/attacker", "attacker")
		require.NoError(t, err, "offline local integration image provisioning is release-fatal")
	}
	if !digestReference(image) {
		t.Fatal("integration image must be a local sha256 ID or repository digest")
	}
	d := NewDocker(api)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, d.Verify(ctx), "a supported Linux Docker Engine is required for integration qualification")
	p := lockedDownPlan()
	p.Image, p.Workdir, p.Environment, p.Mounts, p.Tmpfs, p.Ports = image, "/", nil, nil, nil, nil
	p.UID, p.GID = os.Getuid(), os.Getgid()
	p.InvocationID = strings.ReplaceAll(t.Name(), "/", "-") + "-" + time.Now().Format("150405.000000000")
	return d, p
}

func runIntegrationCommand(t *testing.T, d *Docker, p policy.Plan, tty bool) (int, string, Resource) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, err := d.StartCommand(ctx, p, "", tty)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = d.RemoveContainer(cleanupCtx, r)
	})
	var output bytes.Buffer
	a, err := d.Attach(ctx, r.ID, IO{Stdout: &output, Stderr: &output, TTY: tty})
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	code, err := d.Wait(ctx, r.ID)
	require.NoError(t, err)
	require.NoError(t, a.Wait())
	return code, output.String(), r
}

func TestDockerIntegrationCreateAttachWaitExactExit(t *testing.T) {
	d, p := integrationDocker(t)
	p.Command = []string{"exit-37"}
	code, output, _ := runIntegrationCommand(t, d, p, false)
	require.Equal(t, 37, code)
	require.Empty(t, output)
}

func TestDockerIntegrationTTYResize(t *testing.T) {
	d, p := integrationDocker(t)
	p.Command = []string{"terminal-size"}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, err := d.StartCommand(ctx, p, "", true)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = d.RemoveContainer(cleanupCtx, r)
	})
	var output bytes.Buffer
	a, err := d.Attach(ctx, r.ID, IO{Stdout: &output, Stderr: &output, TTY: true})
	require.NoError(t, err)
	defer a.Close()
	require.NoError(t, d.Resize(ctx, ContainerID(r.ID), 33, 111))
	code, err := d.Wait(ctx, r.ID)
	require.NoError(t, err)
	require.NoError(t, a.Wait())
	require.Zero(t, code)
	require.Contains(t, output.String(), "33 111")
}

func TestDockerIntegrationSIGTERM(t *testing.T) {
	d, p := integrationDocker(t)
	p.Command = []string{"wait-term"}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, err := d.StartCommand(ctx, p, "", false)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = d.RemoveContainer(cleanupCtx, r)
	})
	output := &readinessWriter{ready: make(chan struct{})}
	a, err := d.Attach(ctx, r.ID, IO{Stdout: output, Stderr: output})
	require.NoError(t, err)
	defer a.Close()
	select {
	case <-output.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not report readiness")
	}
	require.NoError(t, d.Signal(ctx, r.ID, syscall.SIGTERM))
	code, err := d.Wait(ctx, r.ID)
	require.NoError(t, err)
	require.NoError(t, a.Wait())
	require.Equal(t, 42, code)
}

func TestDockerIntegrationEnforcesPIDLimit(t *testing.T) {
	d, p := integrationDocker(t)
	p.Command = []string{"pids-limit"}
	code, _, _ := runIntegrationCommand(t, d, p, false)
	require.Equal(t, 73, code, "fixture must observe process creation denied by the PID limit")
}

func TestDockerIntegrationEnforcesMemoryLimit(t *testing.T) {
	d, p := integrationDocker(t)
	p.Command = []string{"memory-limit"}
	code, _, _ := runIntegrationCommand(t, d, p, false)
	require.NotZero(t, code, "allocation fixture must be terminated by the memory limit")
}
