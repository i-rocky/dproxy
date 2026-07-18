package cache

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func newCache(t *testing.T) Manager {
	t.Helper()
	return Manager{Root: filepath.Join(t.TempDir(), "cache")}
}

func TestPathCreatesOwnedCache(t *testing.T) {
	m := newCache(t)
	got, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.DirExists(t, got)
	require.FileExists(t, filepath.Join(m.Root, ownerFile))
	again, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.Equal(t, got, again)
}

func TestCacheRejectsTraversal(t *testing.T) {
	_, err := newCache(t).Path("project", "node", "../escape", "24", "linux-amd64")
	require.ErrorIs(t, err, ErrUnsafeKey)
}

func TestCacheRejectsEmptyAndAbsoluteKeys(t *testing.T) {
	m := newCache(t)
	for _, key := range []string{"", "/tmp", "two/parts", "white space", ".."} {
		_, err := m.Path("project", key, "npm", "24", "linux-amd64")
		require.ErrorIs(t, err, ErrUnsafeKey, key)
	}
}

func TestCleanOnlyRemovesOwnedCache(t *testing.T) {
	m := newCache(t)
	path, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(path, "data"), []byte("x"), 0600))
	require.NoError(t, m.Clean("project", "node", "npm", "24", "linux-amd64"))
	require.NoDirExists(t, path)

	unmanaged := filepath.Join(m.Root, "unmanaged", "node", "npm", "24", "linux-amd64")
	require.NoError(t, os.MkdirAll(unmanaged, 0700))
	require.ErrorIs(t, m.Clean("unmanaged", "node", "npm", "24", "linux-amd64"), ErrNotOwned)
	require.DirExists(t, unmanaged)
}

func TestCleanRecursivelyRemovesOwnedSubdirectories(t *testing.T) {
	m := newCache(t)
	path, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	sub := filepath.Join(path, "nested")
	require.NoError(t, os.Mkdir(sub, 0700))
	fd, err := unix.Open(sub, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	require.NoError(t, err)
	require.NoError(t, createOwner(fd))
	require.NoError(t, unix.Close(fd))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "data"), []byte("x"), 0600))
	require.NoError(t, m.Clean("project", "node", "npm", "24", "linux-amd64"))
	require.NoDirExists(t, path)
}

func TestPathRefusesToAdoptExistingUnmanagedDirectory(t *testing.T) {
	m := newCache(t)
	require.NoError(t, os.MkdirAll(filepath.Join(m.Root, "project"), 0700))
	_, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.ErrorIs(t, err, ErrNotOwned)
}

func TestCleanRejectsSymlinkReplacement(t *testing.T) {
	m := newCache(t)
	path, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	outside := t.TempDir()
	require.NoError(t, os.RemoveAll(path))
	require.NoError(t, os.Symlink(outside, path))
	require.Error(t, m.Clean("project", "node", "npm", "24", "linux-amd64"))
	require.DirExists(t, outside)
}

func TestPruneRemovesOnlyOwnedTopLevelCaches(t *testing.T) {
	m := newCache(t)
	kept, err := m.Path("keep", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	removed, err := m.Path("remove", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.NoError(t, m.Prune(map[string]struct{}{"keep": {}}))
	require.DirExists(t, kept)
	require.NoDirExists(t, removed)
}

func TestPruneMissingRootAndRejectsUnsafeEntry(t *testing.T) {
	m := newCache(t)
	require.NoError(t, m.Prune(nil))
	_, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(m.Root, "bad name"), []byte("x"), 0600))
	require.ErrorIs(t, m.Prune(nil), ErrUnsafeKey)
}

func TestPruneRefusesUnownedProjectDirectory(t *testing.T) {
	m := newCache(t)
	_, err := m.Path("owned", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(filepath.Join(m.Root, "unowned"), 0700))
	require.ErrorIs(t, m.Prune(map[string]struct{}{"owned": {}}), ErrNotOwned)
	require.DirExists(t, filepath.Join(m.Root, "unowned"))
}

func TestCacheRejectsUnsafeRoot(t *testing.T) {
	_, err := (Manager{Root: "/"}).Path("project", "node", "npm", "24", "linux-amd64")
	require.ErrorIs(t, err, ErrUnsafeKey)
}

func TestCleanMissingCacheFailsClosed(t *testing.T) {
	m := newCache(t)
	_, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.Error(t, m.Clean("project", "node", "npm", "25", "linux-amd64"))
}

func TestCleanConcurrentSymlinkReplacementNeverTouchesOutside(t *testing.T) {
	m := newCache(t)
	path, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	outside := t.TempDir()
	canary := filepath.Join(outside, "canary")
	require.NoError(t, os.WriteFile(canary, []byte("safe"), 0600))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = os.Remove(path)
			_ = os.Symlink(outside, path)
			_ = os.Remove(path)
		}
	}()
	_ = m.Clean("project", "node", "npm", "24", "linux-amd64")
	wg.Wait()
	require.FileExists(t, canary)
}
