//go:build integration

package engine

import (
	"bytes"
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"dproxy/internal/policy"

	"github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
)

func integrationDocker(t *testing.T) (*Docker, policy.Plan) {
	t.Helper()
	image := os.Getenv("DPROXY_INTEGRATION_IMAGE")
	if image == "" {
		t.Fatal("DPROXY_INTEGRATION_IMAGE must name a pre-provisioned digest-pinned local image; integration qualification never skips")
	}
	if !digestReference(image) {
		t.Fatal("DPROXY_INTEGRATION_IMAGE must be pinned as repository@sha256:<64 lowercase hex>")
	}
	api, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err, "Docker is required for integration qualification")
	t.Cleanup(func() { _ = api.Close() })
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
	p.Command = []string{"/bin/sh", "-c", "printf dproxy-ok; exit 37"}
	code, output, _ := runIntegrationCommand(t, d, p, false)
	require.Equal(t, 37, code)
	require.Equal(t, "dproxy-ok", output)
}

func TestDockerIntegrationTTYResize(t *testing.T) {
	d, p := integrationDocker(t)
	p.Command = []string{"/bin/sh", "-c", "sleep 0.2; stty size"}
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
	p.Command = []string{"/bin/sh", "-c", "trap 'exit 42' TERM; while :; do sleep 1; done"}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, err := d.StartCommand(ctx, p, "", false)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = d.RemoveContainer(cleanupCtx, r)
	})
	a, err := d.Attach(ctx, r.ID, IO{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	require.NoError(t, err)
	defer a.Close()
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, d.Signal(ctx, r.ID, syscall.SIGTERM))
	code, err := d.Wait(ctx, r.ID)
	require.NoError(t, err)
	require.NoError(t, a.Wait())
	require.Equal(t, 42, code)
}
