package shim

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
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

func TestIsManagedShimClassifiesResolvedPath(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	// A synced dproxy shim is recognized as managed (relative symlink resolved).
	require.True(t, m.IsManagedShim(filepath.Join(m.BinDir, "node")))
	// A plain file is not a managed shim.
	plain := filepath.Join(m.BinDir, "uv")
	require.NoError(t, os.WriteFile(plain, []byte("real"), 0700))
	require.False(t, m.IsManagedShim(plain))
	// A symlink pointing somewhere else is not a managed shim.
	rogue := filepath.Join(m.BinDir, "go")
	require.NoError(t, os.Symlink("/usr/local/go/bin/go", rogue))
	require.False(t, m.IsManagedShim(rogue))
	// A missing path is not a managed shim.
	require.False(t, m.IsManagedShim(filepath.Join(m.BinDir, "nope")))
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

func TestOwnedReturnsFalseWhenBinDirectoryDisappears(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(nil))
	require.NoError(t, os.Remove(m.BinDir))
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

func TestSyncRefusesUnmanagedGenericCollision(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(nil))
	require.NoError(t, os.Remove(m.recordPath(genericName)))
	generic := filepath.Join(m.ShimDir, genericName)
	want, err := os.ReadFile(generic)
	require.NoError(t, err)
	require.ErrorIs(t, m.Sync(nil), ErrCollision)
	got, err := os.ReadFile(generic)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestRemoveFinalSubstitutionRestoresOwnedLinkAndPreservesReplacement(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	var replacement string
	beforeRemoveVerify = func(trashFD int, name string) {
		beforeRemoveVerify = nil
		_ = unix.Renameat(trashFD, name, trashFD, name+"-moved")
		_ = unix.Symlinkat("unmanaged", trashFD, name)
		replacement = filepath.Join(m.ShimDir, ".trash", name)
	}
	t.Cleanup(func() { beforeRemoveVerify = nil })
	require.ErrorIs(t, m.Remove("node"), ErrCollision)
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.True(t, owned)
	target, err := os.Readlink(replacement)
	require.NoError(t, err)
	require.Equal(t, "unmanaged", target)
}

func TestSyncRecordFailureRollsBackWithoutStaleOwnership(t *testing.T) {
	m := newShimManager(t)
	beforeRecordCommit = func(name string) error {
		if name == "node" {
			return errors.New("injected record failure")
		}
		return nil
	}
	t.Cleanup(func() { beforeRecordCommit = nil })
	require.Error(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	beforeRecordCommit = nil
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.False(t, owned)
	require.NoFileExists(t, filepath.Join(m.BinDir, "node"))
}

func TestSyncFinalRecordFailureRestoresOldLinkAndMetadata(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	old, err := os.Lstat(filepath.Join(m.BinDir, "node"))
	require.NoError(t, err)
	beforeFinalRecord = func(name string) error {
		if name == "node" {
			return errors.New("injected final fsync failure")
		}
		return nil
	}
	t.Cleanup(func() { beforeFinalRecord = nil })
	require.Error(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	beforeFinalRecord = nil
	now, err := os.Lstat(filepath.Join(m.BinDir, "node"))
	require.NoError(t, err)
	require.True(t, os.SameFile(old, now))
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.True(t, owned)
}

func TestSyncRecoversInterruptedPublishedUpdate(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	afterObjectPublish = func(name string) error {
		if name == "node" {
			return errInterrupted
		}
		return nil
	}
	require.Error(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	record, err := readRecordAtPath(m, "node")
	require.NoError(t, err)
	require.NotEmpty(t, record.Temp)
	require.NotZero(t, record.PreviousInode)
	require.FileExists(t, filepath.Join(m.BinDir, record.Temp))
	afterObjectPublish = nil
	t.Cleanup(func() { afterObjectPublish = nil })
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.True(t, owned)
}

func TestSyncRecoversInterruptedPublishedFreshCreate(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(nil))
	afterObjectPublish = func(name string) error {
		if name == "node" {
			return errInterrupted
		}
		return nil
	}
	require.ErrorIs(t, m.Sync(map[string]Target{"node": {Binary: "node"}}), errInterrupted)
	record, err := readRecordAtPath(m, "node")
	require.NoError(t, err)
	require.Zero(t, record.PreviousInode)
	require.NotEmpty(t, record.Temp)
	require.FileExists(t, filepath.Join(m.BinDir, "node"))
	afterObjectPublish = nil
	t.Cleanup(func() { afterObjectPublish = nil })
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
}

func TestSyncRecoversInterruptedPublishedGenericUpdate(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(nil))
	afterObjectPublish = func(name string) error {
		if name == genericName {
			return errInterrupted
		}
		return nil
	}
	require.ErrorIs(t, m.Sync(nil), errInterrupted)
	record, err := readRecordAtPath(m, genericName)
	require.NoError(t, err)
	require.NotEmpty(t, record.Temp)
	require.NotZero(t, record.PreviousInode)
	require.FileExists(t, filepath.Join(m.ShimDir, record.Temp))
	afterObjectPublish = nil
	t.Cleanup(func() { afterObjectPublish = nil })
	require.NoError(t, m.Sync(nil))
}

func TestSyncRecoversInterruptedPublishedFreshGeneric(t *testing.T) {
	m := newShimManager(t)
	afterObjectPublish = func(name string) error {
		if name == genericName {
			return errInterrupted
		}
		return nil
	}
	require.ErrorIs(t, m.Sync(nil), errInterrupted)
	record, err := readRecordAtPath(m, genericName)
	require.NoError(t, err)
	require.Zero(t, record.PreviousInode)
	require.FileExists(t, filepath.Join(m.ShimDir, genericName))
	afterObjectPublish = nil
	t.Cleanup(func() { afterObjectPublish = nil })
	require.NoError(t, m.Sync(nil))
}

func TestSyncRecoversInterruptedTransitionBeforeCreate(t *testing.T) {
	m := newShimManager(t)
	afterTransition = func(name string) error {
		if name == "node" {
			return errInterrupted
		}
		return nil
	}
	require.Error(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	afterTransition = nil
	t.Cleanup(func() { afterTransition = nil })
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.True(t, owned)
}

func TestSyncRecoversInterruptedTransitionBeforeUpdate(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	afterTransition = func(name string) error {
		if name == "node" {
			return errInterrupted
		}
		return nil
	}
	require.Error(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	afterTransition = nil
	t.Cleanup(func() { afterTransition = nil })
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.True(t, owned)
}

func TestSyncNeverDeletesCollidingRandomTemp(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(nil))
	collision := filepath.Join(m.ShimDir, ".generic-"+string(bytes.Repeat([]byte{'0'}, 32)))
	require.NoError(t, os.WriteFile(collision, []byte("unmanaged"), 0600))
	randomReader = bytes.NewReader(make([]byte, 64))
	t.Cleanup(func() { randomReader = rand.Reader })
	require.Error(t, m.Sync(nil))
	got, err := os.ReadFile(collision)
	require.NoError(t, err)
	require.Equal(t, []byte("unmanaged"), got)
}

func TestOwnershipWriteNeverDeletesCollidingRandomTemp(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(nil))
	owners := filepath.Join(m.ShimDir, ".owners")
	collision := filepath.Join(owners, ".record-"+string(bytes.Repeat([]byte{'0'}, 32)))
	require.NoError(t, os.WriteFile(collision, []byte("unmanaged"), 0600))
	randomReader = bytes.NewReader(make([]byte, 16))
	t.Cleanup(func() { randomReader = rand.Reader })
	fd, err := unix.Open(owners, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	require.Error(t, writeRecordAt(fd, ownership{Schema: 1, Name: "node"}))
	got, err := os.ReadFile(collision)
	require.NoError(t, err)
	require.Equal(t, []byte("unmanaged"), got)
}

func TestShimRefusesSymlinkedManagedRootAncestor(t *testing.T) {
	m := newShimManager(t)
	base := t.TempDir()
	real := filepath.Join(base, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(real, link))
	m.ShimDir = filepath.Join(link, "shims")
	require.Error(t, m.Sync(nil))
	require.NoDirExists(t, filepath.Join(real, "shims"))
}

func TestShimManagedDirectoryPublishRefusesRacerSubstitution(t *testing.T) {
	m := newShimManager(t)
	beforeDirPublish = func(parentFD int, _, final string) { beforeDirPublish = nil; _ = unix.Mkdirat(parentFD, final, 0700) }
	t.Cleanup(func() { beforeDirPublish = nil })
	require.ErrorIs(t, m.Sync(nil), ErrCollision)
	require.DirExists(t, m.ShimDir)
}

func TestShimManagedChildPublishRefusesRacerSubstitution(t *testing.T) {
	m := newShimManager(t)
	beforeDirPublish = func(parentFD int, _, final string) {
		if final == ".owners" {
			beforeDirPublish = nil
			_ = unix.Mkdirat(parentFD, final, 0700)
		}
	}
	t.Cleanup(func() { beforeDirPublish = nil })
	require.ErrorIs(t, m.Sync(nil), ErrCollision)
}

func TestShimPlainBinDirectoryPublishKeepsRacerDirectory(t *testing.T) {
	m := newShimManager(t)
	beforePlainDirPublish = func(parentFD int, _, final string) {
		beforePlainDirPublish = nil
		_ = unix.Mkdirat(parentFD, final, 0700)
	}
	t.Cleanup(func() { beforePlainDirPublish = nil })
	require.NoError(t, m.Sync(nil))
	require.DirExists(t, m.BinDir)
}

func TestShimRandomFailureLeavesNoPublishedRoots(t *testing.T) {
	m := newShimManager(t)
	randomReader = errorReader{}
	t.Cleanup(func() { randomReader = rand.Reader })
	require.Error(t, m.Sync(nil))
	require.NoDirExists(t, m.ShimDir)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("random failure") }

func TestRemoveRecordFailuresRestoreLiveLinkAndFinalRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inject func()
	}{
		{"before unlink", func() { beforeRemoveCommit = func(string) error { return errors.New("record unlink failure") } }},
		{"after unlink", func() { afterRemoveUnlink = func(string) error { return errors.New("record fsync failure") } }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newShimManager(t)
			require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
			tc.inject()
			t.Cleanup(func() { beforeRemoveCommit = nil; afterRemoveUnlink = nil })
			require.Error(t, m.Remove("node"))
			beforeRemoveCommit = nil
			afterRemoveUnlink = nil
			owned, err := m.Owned("node")
			require.NoError(t, err)
			require.True(t, owned)
			record, err := readRecordAtPath(m, "node")
			require.NoError(t, err)
			require.False(t, record.Removing)
		})
	}
}

func TestRemoveMissingManagedLinkRestoresFinalRecord(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	require.NoError(t, os.Remove(filepath.Join(m.BinDir, "node")))
	require.Error(t, m.Remove("node"))
	record, err := readRecordAtPath(m, "node")
	require.NoError(t, err)
	require.False(t, record.Removing)
}

func TestRemoveRecoversInterruptedRename(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	afterRemoveRename = func(string) error { return errInterrupted }
	t.Cleanup(func() { afterRemoveRename = nil })
	require.ErrorIs(t, m.Remove("node"), errInterrupted)
	record, err := readRecordAtPath(m, "node")
	require.NoError(t, err)
	require.True(t, record.Removing)
	require.NoFileExists(t, filepath.Join(m.BinDir, "node"))
	require.FileExists(t, filepath.Join(m.ShimDir, ".trash", record.RemoveQ))
	require.FileExists(t, filepath.Join(m.ShimDir, ".trash", record.Backup))
	afterRemoveRename = nil
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.False(t, owned)
	require.NoFileExists(t, m.recordPath("node"))
}

func TestRemoveRecoversInterruptedTransitionBeforeMutation(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	afterRemoveTransition = func(string) error { return errInterrupted }
	t.Cleanup(func() { afterRemoveTransition = nil })
	require.ErrorIs(t, m.Remove("node"), errInterrupted)
	record, err := readRecordAtPath(m, "node")
	require.NoError(t, err)
	require.True(t, record.Removing)
	require.FileExists(t, filepath.Join(m.BinDir, "node"))
	afterRemoveTransition = nil
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.True(t, owned)
	record, err = readRecordAtPath(m, "node")
	require.NoError(t, err)
	require.False(t, record.Removing)
}

func TestRemoveRecoveryRestoresWhenQuarantineWasSubstituted(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"node": {Binary: "node"}}))
	afterRemoveRename = func(string) error { return errInterrupted }
	require.ErrorIs(t, m.Remove("node"), errInterrupted)
	afterRemoveRename = nil
	t.Cleanup(func() { afterRemoveRename = nil })
	record, err := readRecordAtPath(m, "node")
	require.NoError(t, err)
	trashFD, err := unix.Open(filepath.Join(m.ShimDir, ".trash"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	require.NoError(t, err)
	require.NoError(t, unix.Renameat(trashFD, record.RemoveQ, trashFD, record.RemoveQ+"-owned"))
	require.NoError(t, unix.Symlinkat("unmanaged", trashFD, record.RemoveQ))
	require.NoError(t, unix.Close(trashFD))
	owned, err := m.Owned("node")
	require.NoError(t, err)
	require.True(t, owned)
	target, err := os.Readlink(filepath.Join(m.ShimDir, ".trash", record.RemoveQ))
	require.NoError(t, err)
	require.Equal(t, "unmanaged", target)
}

func readRecordAtPath(m Manager, name string) (ownership, error) {
	fd, err := unix.Open(filepath.Join(m.ShimDir, ".owners"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ownership{}, err
	}
	defer unix.Close(fd)
	return readRecordAt(fd, name)
}

func TestSyncWritesTargetRecordForReexec(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"python": {Binary: "python"}}))

	record := filepath.Join(m.ShimDir, TargetRecordName)
	got, err := os.ReadFile(record)
	require.NoError(t, err, "Sync must write the target record")
	require.Equal(t, m.Executable, strings.TrimSpace(string(got)), "record must pin the managing binary path")
}

func TestSyncRefreshesTargetRecordAcrossRuns(t *testing.T) {
	m := newShimManager(t)
	require.NoError(t, m.Sync(map[string]Target{"python": {Binary: "python"}}))
	record := filepath.Join(m.ShimDir, TargetRecordName)
	require.NoError(t, os.WriteFile(record, []byte("/tmp/stale-path"), 0600))
	require.NoError(t, m.Sync(map[string]Target{"python": {Binary: "python"}}))
	got, err := os.ReadFile(record)
	require.NoError(t, err)
	require.NotEqual(t, "/tmp/stale-path", strings.TrimSpace(string(got)))
}
