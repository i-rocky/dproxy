package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".dproxy.toml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))
	return path
}

func TestConfigRejectsUnknownSecurityField(t *testing.T) {
	path := writeConfig(t, "schema=1\n[sandbox]\nprivileged=true\n")
	_, err := Load(path)
	require.ErrorContains(t, err, "unknown field")
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
