package shim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func newShimManager(t *testing.T) Manager {
	t.Helper()
	root := t.TempDir()
	executable := filepath.Join(root, "dproxy")
	require.NoError(t, os.WriteFile(executable, []byte("binary"), 0700))
	return Manager{BinDir: filepath.Join(root, "bin"), ShimDir: filepath.Join(root, "shims"), Executable: executable}
}

func TestSyncCreatesGenericManagedShims(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}, "npm": {Binary: "npm"}}))
	generic := filepath.Join(m.ShimDir, genericName)
	require.FileExists(t, generic)
	for _, name := range []string{"node", "npm"} {
		target, err := os.Readlink(filepath.Join(m.BinDir, name))
		require.NoError(t, err)
		expected, err := filepath.Rel(m.BinDir, generic)
		require.NoError(t, err)
		require.Equal(t, expected, target)
		owned, err := m.Owned(name)
		require.NoError(t, err)
		require.True(t, owned)
	}
}

func TestShimRefusesUnmanagedCollision(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, os.MkdirAll(m.BinDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(m.BinDir, "node"), []byte("mine"), 0600))
	require.ErrorIs(t, m.Sync(map[string]Target{"node": {Binary: "node"}}), ErrCollision)
}

func TestShimRejectsUnsafeNames(t *testing.T) {
	m := newShimManager(t)
	require.ErrorIs(t, m.Sync(map[string]Target{"../node": {Binary: "node"}}), ErrUnsafeName)
	require.ErrorIs(t, m.Sync(map[string]Target{"node": {Binary: "../node"}}), ErrUnsafeName)
}

func TestRemoveVerifiesManagedLink(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	require.NoError(t, m.Remove("node"))
	require.NoFileExists(t, filepath.Join(m.BinDir, "node"))

	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	require.NoError(t, os.Remove(filepath.Join(m.BinDir, "node")))
	require.NoError(t, os.WriteFile(filepath.Join(m.BinDir, "node"), []byte("mine"), 0600))
	require.ErrorIs(t, m.Remove("node"), ErrCollision)
	require.FileExists(t, filepath.Join(m.BinDir, "node"))
}

func TestSyncDoesNotRemoveUnrequestedManagedShims(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}, "npm": {Binary: "npm"}}))
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	require.FileExists(t, filepath.Join(m.BinDir, "npm"))
}

func TestSyncUpdatesOwnedShim(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.True(t, owned)
}

func TestOwnedRejectsTamperedMetadataAndLink(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	require.NoError(t, os.WriteFile(m.recordPath("node"), []byte("bad"), 0600))
	_, err := m.Owned("node")
	require.ErrorIs(t, err, ErrCollision)

	m = newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	require.NoError(t, os.Remove(filepath.Join(m.BinDir, "node")))
	require.NoError(t, os.Symlink("elsewhere", filepath.Join(m.BinDir, "node")))
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.False(t, owned)
}

func TestManagerRejectsUnsafeRootsAndExecutable(t *testing.T) {
	require.ErrorIs(t, (Manager{}).Sync(nil), ErrUnsafeName)
	m := newShimManager(t)
	require.NoError(t, os.Remove(m.Executable))
	require.NoError(t, os.Mkdir(m.Executable, 0700))
	require.ErrorIs(t, m.Sync(map[string]Target{"node": {Binary: "node"}}), ErrUnsafeName)
}

func TestRemoveRejectsUnknownAndUnsafeShim(t *testing.T) {
	m := newShimManager(t)
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.False(t, owned)
	require.ErrorIs(t, m.Remove("../node"), ErrUnsafeName)
	require.ErrorIs(t, m.Remove("node"), ErrCollision)
}

func TestSyncRejectsNonDirectoryManagedRoots(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, os.WriteFile(m.BinDir, []byte("file"), 0600))
	require.Error(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))

	m = newShimManager(t)
	require.NoError(t, os.WriteFile(m.ShimDir, []byte("file"), 0600))
	require.Error(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
}

func TestOwnedReturnsFalseWhenManagedLinkDisappears(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	require.NoError(t, os.Remove(filepath.Join(m.BinDir, "node")))
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.False(t, owned)
}

func TestOwnedRejectsOversizedAndSymlinkedMetadata(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	require.NoError(t, os.WriteFile(m.recordPath("node"), make([]byte, 4097), 0600))
	_, err := m.Owned("node")
	require.ErrorIs(t, err, ErrCollision)

	m = newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	require.NoError(t, os.Remove(m.recordPath("node")))
	require.NoError(t, os.Symlink(filepath.Join(m.ShimDir, genericName), m.recordPath("node")))
	_, err = m.Owned("node")
	require.Error(t, err)
}

func TestManagerRejectsOverlappingOrRootDirectories(t *testing.T) {
	m := newShimManager(t)
	m.ShimDir = m.BinDir
	require.ErrorIs(t, m.Sync(nil), ErrUnsafeName)
	m = newShimManager(t)
	m.BinDir = "/"
	require.ErrorIs(t, m.Sync(nil), ErrUnsafeName)
}
