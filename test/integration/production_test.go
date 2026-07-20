//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"dproxy/internal/cli"
	"dproxy/internal/config"
	"dproxy/internal/lock"
	"dproxy/internal/project"
	"dproxy/plugins/official"

	"github.com/stretchr/testify/require"
)

func TestProductionExecuteRunsModeNoneAndDeniesHostState(t *testing.T) {
	_, localImage, _ := fixtures(t)
	root := t.TempDir()
	for key, path := range map[string]string{
		"HOME": root + "/home", "XDG_CONFIG_HOME": root + "/config",
		"XDG_CACHE_HOME": root + "/cache", "XDG_DATA_HOME": root + "/data", "XDG_STATE_HOME": root + "/state",
	} {
		require.NoError(t, os.MkdirAll(path, 0700))
		t.Setenv(key, path)
	}
	projectRoot := filepath.Join(root, "project")
	require.NoError(t, os.Mkdir(projectRoot, 0700))
	hostCanary := filepath.Join(root, "host-canary")
	require.NoError(t, os.WriteFile(hostCanary, []byte("host-only"), 0600))
	hostMarker := hostProcMarker(t)
	cfg := config.Config{Schema: 1, Tools: map[string]string{"node": "24"}, Sandbox: config.Sandbox{
		Network: "none", Memory: "64MiB", CPUs: 1, PIDs: 32,
		Environment: map[string]string{"ATTACK_HOST_CANARY_PATH": hostCanary, "ATTACK_HOST_PROC_PATH": "/proc/1/environ"},
	}}
	configPath := filepath.Join(projectRoot, ".dproxy.toml")
	require.NoError(t, config.WriteAtomic(configPath, cfg))
	oldWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectRoot))
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	p, err := project.Find(".")
	require.NoError(t, err)
	require.NotEmpty(t, p.ID)

	oldRepo, oldCommit := official.OfficialRepository, official.Commit
	official.OfficialRepository, official.Commit = "https://example.test/dproxy-plugins.git", strings.Repeat("b", 40)
	t.Cleanup(func() { official.OfficialRepository, official.Commit = oldRepo, oldCommit })
	manifests, err := official.Load()
	require.NoError(t, err)
	manifest := manifests["node"]
	rawConfig, err := os.ReadFile(configPath)
	require.NoError(t, err)
	lockedReference := "registry.test/integration/attacker@sha256:" + strings.Repeat("c", 64)
	require.NoError(t, lock.WriteAtomic(filepath.Join(projectRoot, ".dproxy.lock"), lock.File{
		Schema: 1, ConfigSHA256: lock.HashConfig(rawConfig),
		Plugins: map[string]lock.Plugin{manifest.Name: {Repository: manifest.Provenance.Repository, Commit: manifest.Provenance.Commit, ManifestSHA256: manifest.Provenance.ManifestSHA256, Schema: 1}},
		Tools:   map[string]lock.Tool{"node": {Requested: "24", Version: "24.1.0", Image: strings.Split(lockedReference, "@")[0], Tag: "24.1.0", Digest: strings.Split(lockedReference, "@")[1], Platform: runtime.GOOS + "/" + runtime.GOARCH}},
	}))
	userRoot, err := os.UserConfigDir()
	require.NoError(t, err)
	require.NoError(t, config.WriteUserAtomic(filepath.Join(userRoot, "dproxy", "config.toml"), config.UserConfig{Schema: 1, GatewayImage: "registry.test/gateway@sha256:" + strings.Repeat("d", 64)}))
	restore, err := cli.SetIntegrationImageReferenceMapper(lockedReference, localImage)
	require.NoError(t, err)
	t.Cleanup(restore)
	var output bytes.Buffer
	require.Zero(t, cli.Execute(context.Background(), "dproxy", []string{"--dry-run", "cache", "prune", "--all"}, &output, &output), output.String())
	require.Contains(t, output.String(), "would remove every managed project cache")
	output.Reset()
	code := cli.Execute(context.Background(), "dproxy", []string{"node", "--host-proc-marker=" + hex.EncodeToString(hostMarker)}, &output, &output)
	require.Zero(t, code, output.String())
	var result attackResult
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result), output.String())
	require.True(t, result.ProjectWrite)
	require.False(t, result.HostCanaryRead)
	require.False(t, result.HostEnvRead)
	require.False(t, result.DockerSocketPresent)
}

func hostProcMarker(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("/proc/1/environ")
	require.NoError(t, err)
	for _, entry := range bytes.Split(raw, []byte{0}) {
		if len(entry) > 8 && !bytes.HasPrefix(entry, []byte("PATH=")) {
			return entry
		}
	}
	t.Fatal("host PID 1 environment has no marker")
	return nil
}
