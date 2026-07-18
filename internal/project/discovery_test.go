package project

import (
	"os"
	"path/filepath"
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
