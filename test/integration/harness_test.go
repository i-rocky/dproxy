//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"dproxy/internal/engine"
	"dproxy/internal/policy"
	"dproxy/internal/testimage"

	"github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
)

var fixtureOnce sync.Once
var fixtureAPI *client.Client
var attackerImage, gatewayImage string
var fixtureErr error

type attackResult struct {
	ProjectWrite, HostCanaryRead, HostEnvRead, DockerSocketPresent bool
	Probes                                                         map[string]bool
	GoRoutines                                                     int
}

func fixtures(t *testing.T) (*client.Client, string, string) {
	t.Helper()
	fixtureOnce.Do(func() {
		fixtureAPI, fixtureErr = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if fixtureErr != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if _, fixtureErr = fixtureAPI.Ping(ctx); fixtureErr != nil {
			return
		}
		attackerImage, fixtureErr = testimage.Scratch(ctx, fixtureAPI, "test/fixtures/attacker", "attacker")
		if fixtureErr != nil {
			return
		}
		gatewayImage, fixtureErr = testimage.Scratch(ctx, fixtureAPI, "cmd/gateway", "dproxy-gateway")
		if fixtureErr == nil {
			fixtureErr = os.Setenv("DPROXY_INTEGRATION_IMAGE", attackerImage)
		}
	})
	require.NoError(t, fixtureErr, "privileged Docker integration qualification cannot skip")
	return fixtureAPI, attackerImage, gatewayImage
}

func runAttacker(t *testing.T) (attackResult, engine.Ownership) {
	return runAttackerProject(t, "integration-project")
}

func runAttackerProject(t *testing.T, projectID string) (attackResult, engine.Ownership) {
	t.Helper()
	api, image, _ := fixtures(t)
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, ownership, err := executeAttack(ctx, api, image, root, projectID)
	require.NoError(t, err)
	return result, ownership
}

func executeAttack(ctx context.Context, api any, image, root, projectID string) (result attackResult, ownership engine.Ownership, retErr error) {
	de := engine.NewDocker(api)
	plan := policy.Plan{InvocationID: fmt.Sprintf("integration-%d", time.Now().UnixNano()), ProjectID: projectID, Image: image, Workdir: "/workspace", Command: []string{"/attacker"}, Mounts: []policy.Mount{{Source: root, Target: "/workspace"}}, Tmpfs: []policy.Tmpfs{{Target: "/tmp", Mode: 01777}, {Target: "/home/dproxy", Mode: 0700}}, UID: os.Getuid(), GID: os.Getgid(), Pids: 32, MemoryBytes: 64 << 20, CPUs: 1, ReadOnlyRoot: true, NoNewPrivileges: true, AutoRemove: true, CapDrop: []string{"ALL"}, Network: policy.Network{Mode: "none"}}
	if err := de.Verify(ctx); err != nil {
		return result, ownership, err
	}
	if err := de.PullByDigest(ctx, image); err != nil {
		return result, ownership, err
	}
	container, err := de.StartCommand(ctx, plan, "", false)
	if err != nil {
		return result, ownership, err
	}
	ownership = container.Ownership
	defer func() { retErr = errors.Join(retErr, de.RemoveContainer(ctx, container)) }()
	var output bytes.Buffer
	attachment, err := de.Attach(ctx, container.ID, engine.IO{Stdout: &output, Stderr: &output})
	if err != nil {
		return result, ownership, err
	}
	code, err := de.Wait(ctx, container.ID)
	if err != nil {
		return result, ownership, err
	}
	if code != 0 {
		return result, ownership, fmt.Errorf("attacker exited with status %d", code)
	}
	if err = attachment.Wait(); err != nil {
		return result, ownership, err
	}
	if err = attachment.Close(); err != nil {
		return result, ownership, err
	}
	if err = json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result); err != nil {
		return result, ownership, fmt.Errorf("decode attacker output %q: %w", output.String(), err)
	}
	return result, ownership, nil
}
