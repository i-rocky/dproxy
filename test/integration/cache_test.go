//go:build integration

package integration

import (
	"dproxy/internal/cache"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestCacheRejectsCrossProjectPoisonAndSymlinkSwap(t *testing.T) {
	fixtures(t)
	root := filepath.Join(t.TempDir(), "managed-cache")
	manager := cache.Manager{Root: root}
	one, err := manager.Path("project-one", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	two, err := manager.Path("project-two", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.NotEqual(t, one, two)
	out := t.TempDir()
	require.NoError(t, os.RemoveAll(one))
	require.NoError(t, os.Symlink(out, one))
	require.Error(t, manager.Clean("project-one", "node", "npm", "24", "linux-amd64"))
	require.DirExists(t, filepath.Clean(out))
}
