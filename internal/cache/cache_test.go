package cache

import (
	"os"
	"path/filepath"
	"strings"
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

func TestPlannedPathComputesWithoutCreatingState(t *testing.T) {
	m := newCache(t)
	got, err := m.PlannedPath("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.Contains(t, got, m.Root)
	_, err = os.Stat(filepath.Join(m.Root, ownerFile))
	require.ErrorIs(t, err, os.ErrNotExist) // no ownership marker written
	_, err = newCache(t).PlannedPath("project", "node", "../escape", "24", "linux-amd64")
	require.ErrorIs(t, err, ErrUnsafeKey)
	_, err = Manager{Root: ""}.PlannedPath("project", "node", "npm", "24", "linux-amd64")
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
	require.NoError(t, createMarker(fd))
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

func TestCacheRefusesSymlinkedAncestor(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(real, link))
	_, err := (Manager{Root: filepath.Join(link, "cache")}).Path("project", "node", "npm", "24", "linux-amd64")
	require.Error(t, err)
	require.NoDirExists(t, filepath.Join(real, "cache"))
}

func TestCacheRejectsMarkerNotBoundToDirectory(t *testing.T) {
	m := newCache(t)
	path, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(path, ownerFile), []byte(`{"schema":1,"device":0,"inode":0}`), 0600))
	_, err = m.Path("project", "node", "npm", "24", "linux-amd64")
	require.ErrorIs(t, err, ErrNotOwned)
}

// A failure opening an intermediate cache directory must not leak the previous
// iteration's descriptor. openOrPublishManagedDir fails on the leaf here only
// after four intermediate directory descriptors were opened, so a missing close
// on the error path surfaces as a net +1 in open file descriptors.
func TestPathClosesDescriptorOnIntermediateFailure(t *testing.T) {
	m := newCache(t)
	path, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(path, ownerFile), []byte(`{"schema":1,"device":0,"inode":0}`), 0600))
	before := countOpenFDs(t)
	_, err = m.Path("project", "node", "npm", "24", "linux-amd64")
	require.ErrorIs(t, err, ErrNotOwned)
	require.Equal(t, before, countOpenFDs(t), "intermediate directory descriptor leaked on open failure")
}

func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(entries)
}

func TestCacheFinalSubstitutionPreservesUnmanagedReplacement(t *testing.T) {
	m := newCache(t)
	path, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	beforeDelete = func(trashFD int, name string) {
		beforeDelete = nil
		_ = unix.Renameat(trashFD, name, trashFD, name+"-owned")
		_ = unix.Mkdirat(trashFD, name, 0700)
		fd, _ := openBeneath(trashFD, name)
		if fd >= 0 {
			survivor, _ := unix.Openat(fd, "survivor", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0600)
			if survivor >= 0 {
				_ = unix.Close(survivor)
			}
			_ = unix.Close(fd)
		}
	}
	t.Cleanup(func() { beforeDelete = nil })
	require.ErrorIs(t, m.Clean("project", "node", "npm", "24", "linux-amd64"), ErrNotOwned)
	require.NoDirExists(t, path)
	trash := filepath.Join(m.Root, trashName)
	entries, err := os.ReadDir(trash)
	require.NoError(t, err)
	found := false
	for _, entry := range entries {
		if _, err := os.Stat(filepath.Join(trash, entry.Name(), "survivor")); err == nil {
			found = true
		}
	}
	require.True(t, found)
}

func TestCacheDirectoryPublishRefusesRacerSubstitution(t *testing.T) {
	m := newCache(t)
	beforeDirPublish = func(parentFD int, _, final string) {
		beforeDirPublish = nil
		_ = unix.Mkdirat(parentFD, final, 0700)
	}
	t.Cleanup(func() { beforeDirPublish = nil })
	_, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.ErrorIs(t, err, ErrNotOwned)
	require.DirExists(t, m.Root)
	entries, err := os.ReadDir(filepath.Dir(m.Root))
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, strings.HasPrefix(entry.Name(), ".dir-"))
	}
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

func TestPruneSkipsStrayRegularFile(t *testing.T) {
	m := newCache(t)
	_, err := m.Path("project", "node", "npm", "24", "linux-amd64")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(m.Root, "stray-file"), []byte("x"), 0600))
	// "stray-file" matches keyPattern but is a regular file, not a cache dir;
	// Prune must skip it rather than abort on an O_DIRECTORY mismatch.
	require.NoError(t, m.Prune(nil))
}
