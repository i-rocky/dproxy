package project

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindNearestProject(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	require.NoError(t, os.MkdirAll(nested, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".dproxy.toml"), []byte("schema = 1\n"), 0644))
	p, err := Find(nested)
	require.NoError(t, err)
	require.Equal(t, root, p.Root)
	require.Equal(t, "a/b", p.RelativeWorkdir)
	require.Len(t, p.ID, 32)
}

func TestFindResolvesIntermediateSymlinkWithinProject(t *testing.T) {
	root := projectRoot(t)
	physical := filepath.Join(root, "physical", "nested")
	require.NoError(t, os.MkdirAll(physical, 0755))
	require.NoError(t, os.Symlink(filepath.Join(root, "physical"), filepath.Join(root, "alias")))

	p, err := Find(filepath.Join(root, "alias", "nested"))
	require.NoError(t, err)
	require.Equal(t, root, p.Root)
	require.Equal(t, "physical/nested", p.RelativeWorkdir)
}

func TestFindDoesNotEscapeThroughIntermediateSymlink(t *testing.T) {
	root := projectRoot(t)
	outside := t.TempDir()
	nested := filepath.Join(outside, "nested")
	require.NoError(t, os.Mkdir(nested, 0755))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "escape")))

	_, err := Find(filepath.Join(root, "escape", "nested"))
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFindRejectsSymlinkedIdentityFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".dproxy.toml"), []byte("schema = 1\n"), 0644))
	require.NoError(t, os.Mkdir(filepath.Join(root, ".dproxy"), 0755))
	target := filepath.Join(root, "id-target")
	require.NoError(t, os.WriteFile(target, []byte("0123456789abcdef0123456789abcdef\n"), 0600))
	require.NoError(t, os.Symlink(target, filepath.Join(root, ".dproxy", "id")))
	_, err := Find(root)
	require.ErrorContains(t, err, "symlink")
}

func TestFindRejectsSymlinkedConfiguration(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "config-target")
	require.NoError(t, os.WriteFile(target, []byte("schema=1\n"), 0600))
	require.NoError(t, os.Symlink(target, filepath.Join(root, configName)))
	_, err := Find(root)
	require.ErrorContains(t, err, "symlink")
}

func TestFindRejectsNonRegularConfiguration(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, configName), 0700))
	_, err := Find(root)
	require.ErrorContains(t, err, "regular file")
}

func TestFindRejectsSymlinkedMetadataDirectory(t *testing.T) {
	root := projectRoot(t)
	target := t.TempDir()
	require.NoError(t, os.Symlink(target, filepath.Join(root, ".dproxy")))
	_, err := Find(root)
	require.ErrorContains(t, err, "metadata directory")
}

func TestFindRejectsNonDirectoryMetadata(t *testing.T) {
	root := projectRoot(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, ".dproxy"), nil, 0600))
	_, err := Find(root)
	require.ErrorContains(t, err, "metadata directory")
}

func TestFindRejectsNonRegularIdentity(t *testing.T) {
	root := projectRoot(t)
	require.NoError(t, os.Mkdir(filepath.Join(root, ".dproxy"), 0700))
	require.NoError(t, os.Mkdir(filepath.Join(root, ".dproxy", "id"), 0700))
	_, err := Find(root)
	require.ErrorContains(t, err, "regular file")
}

func TestFindRejectsInvalidIdentity(t *testing.T) {
	root := projectRoot(t)
	require.NoError(t, os.Mkdir(filepath.Join(root, ".dproxy"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".dproxy", "id"), []byte("not-a-valid-id\n"), 0600))
	_, err := Find(root)
	require.ErrorContains(t, err, "invalid")
}

func TestFindRejectsInvalidIdentityEncoding(t *testing.T) {
	root := projectRoot(t)
	require.NoError(t, os.Mkdir(filepath.Join(root, ".dproxy"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".dproxy", "id"), []byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n"), 0600))
	_, err := Find(root)
	require.ErrorContains(t, err, "invalid encoding")
}

func TestLoadProjectRejectsOutsideWorkdir(t *testing.T) {
	root := t.TempDir()
	_, err := loadProject(root, filepath.Dir(root))
	require.ErrorContains(t, err, "outside project root")
}

func TestLoadProjectRejectsInvalidRoot(t *testing.T) {
	_, err := loadProject(filepath.Join(t.TempDir(), "missing"), "/")
	require.ErrorContains(t, err, "open project root")
}

func TestConcurrentFindCreatesOneIdentity(t *testing.T) {
	root := projectRoot(t)
	const workers = 24
	ids := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := Find(root)
			if err != nil {
				errs <- err
				return
			}
			ids <- p.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	var want string
	for id := range ids {
		if want == "" {
			want = id
		}
		require.Equal(t, want, id)
	}
}

func TestFindNotFound(t *testing.T) {
	_, err := Find(t.TempDir())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestIdentityOperationsStayOnOpenedDirectory(t *testing.T) {
	root := projectRoot(t)
	metadata := filepath.Join(root, ".dproxy")
	require.NoError(t, os.Mkdir(metadata, 0700))
	opened, err := os.Open(metadata)
	require.NoError(t, err)
	defer opened.Close()
	moved := filepath.Join(root, "original-metadata")
	require.NoError(t, os.Rename(metadata, moved))
	attacker := t.TempDir()
	require.NoError(t, os.Symlink(attacker, metadata))

	id, err := loadOrCreateIDAt(int(opened.Fd()))
	require.NoError(t, err)
	require.Len(t, id, 32)
	_, err = os.Stat(filepath.Join(attacker, "id"))
	require.ErrorIs(t, err, os.ErrNotExist)
	stored, err := os.ReadFile(filepath.Join(moved, "id"))
	require.NoError(t, err)
	require.Equal(t, id+"\n", string(stored))
}

func projectRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".dproxy.toml"), []byte("schema = 1\n"), 0644))
	return root
}
