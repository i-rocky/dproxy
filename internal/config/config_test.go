package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/i-rocky/dproxy/internal/fault"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".dproxy.toml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))
	return path
}

func TestConfigRejectsUnknownSecurityField(t *testing.T) {
	const secret = "do-not-disclose-unknown-value"
	path := writeConfig(t, "schema=1\n[sandbox]\nprivileged=\""+secret+"\"\n")
	_, err := Load(path)
	require.ErrorContains(t, err, "unknown field")
	require.NotContains(t, err.Error(), secret)
	var typed *fault.Error
	require.ErrorAs(t, err, &typed)
	require.NotNil(t, errors.Unwrap(err))
}

func TestConfigMalformedErrorDoesNotDiscloseInput(t *testing.T) {
	const secret = "do-not-disclose-malformed-value"
	path := writeConfig(t, "schema=1\n[tools]\nnode=\""+secret)
	_, err := Load(path)
	require.Error(t, err)
	require.NotContains(t, err.Error(), secret)
	var typed *fault.Error
	require.ErrorAs(t, err, &typed)
	require.NotNil(t, errors.Unwrap(err))
}

func TestConfigReadErrorIsTypedAndSanitized(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing-secret-name.toml"))
	require.EqualError(t, err, "load configuration: read failed")
	var typed *fault.Error
	require.ErrorAs(t, err, &typed)
	require.NotNil(t, errors.Unwrap(err))
}

func TestConfigRejectsUnsupportedSchema(t *testing.T) {
	_, err := Load(writeConfig(t, "schema=2\n"))
	require.ErrorIs(t, err, ErrSchema)
}

func TestConfigRejectsInvalidNetwork(t *testing.T) {
	_, err := Load(writeConfig(t, "schema=1\n[sandbox]\nnetwork=\"host\"\n"))
	require.ErrorContains(t, err, "network policy")
}

func TestConfigAcceptsSupportedNetworks(t *testing.T) {
	for _, network := range []string{"", "none", "public", "allowlist"} {
		t.Run(network, func(t *testing.T) {
			_, err := Load(writeConfig(t, "schema=1\n[sandbox]\nnetwork=\""+network+"\"\n"))
			require.NoError(t, err)
		})
	}
}

func TestConfigLoadsTypedFields(t *testing.T) {
	path := writeConfig(t, `schema = 1
[tools]
node = "24"
[sandbox]
network = "allowlist"
network_allowlist = ["example.com:443"]
memory = "4GiB"
cpus = 4
pids = 512
[sandbox.ports]
"3000" = 3000
[sandbox.environment]
NODE_ENV = "development"
`)
	c, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "24", c.Tools["node"])
	require.Equal(t, []string{"example.com:443"}, c.Sandbox.NetworkAllowlist)
	require.Equal(t, 3000, c.Sandbox.Ports["3000"])
	require.Equal(t, "development", c.Sandbox.Environment["NODE_ENV"])
}

func TestAtomicConfigWriteAndToolUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".dproxy.toml")
	c := Config{Schema: 1, Tools: map[string]string{}}
	require.NoError(t, c.SetTool("node", "24"))
	require.NoError(t, WriteAtomic(path, c))
	loaded, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "24", loaded.Tools["node"])
	require.NoError(t, loaded.RemoveTool("node"))
	require.Empty(t, loaded.Tools)
}

func TestUserConfigRequiresPinnedGatewayAndHTTPSRepositories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	u := UserConfig{Schema: 1, GatewayImage: "registry.example/dproxy/gateway@sha256:" + strings.Repeat("a", 64)}
	require.NoError(t, WriteUserAtomic(path, u))
	loaded, err := LoadUser(path)
	require.NoError(t, err)
	require.Equal(t, u, loaded)
	u.GatewayImage = "gateway:latest"
	require.Error(t, WriteUserAtomic(path, u))
}

func TestAtomicConfigOperationsRejectUnsafeInputs(t *testing.T) {
	c := Config{Schema: 1, Tools: map[string]string{"node": "24"}}
	require.Error(t, c.SetTool("../node", "24"))
	require.Error(t, c.SetTool("node", ""))
	require.Error(t, c.RemoveTool("missing"))
	require.Error(t, WriteAtomic(filepath.Join(t.TempDir(), "config"), Config{Schema: 2}))
	dir := t.TempDir()
	target := filepath.Join(dir, "config")
	require.NoError(t, os.Mkdir(target, 0700))
	require.Error(t, WriteAtomic(target, c))
	_, err := LoadUser(filepath.Join(dir, "missing"))
	require.Error(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad"), []byte("unknown = 1\n"), 0600))
	_, err = LoadUser(filepath.Join(dir, "bad"))
	require.Error(t, err)
}

func TestUserConfigRejectsUnsafeFields(t *testing.T) {
	base := UserConfig{Schema: 1, GatewayImage: "registry.example/dproxy/gateway@sha256:" + strings.Repeat("a", 64)}
	for _, mutate := range []func(*UserConfig){
		func(c *UserConfig) { c.Schema = 2 },
		func(c *UserConfig) { c.EngineEndpoint = "bad\nendpoint" },
	} {
		candidate := base
		mutate(&candidate)
		require.Error(t, WriteUserAtomic(filepath.Join(t.TempDir(), "config"), candidate))
	}
}
