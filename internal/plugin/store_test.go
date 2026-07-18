package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommunityRepositoryRequiresTrust(t *testing.T) {
	s, err := NewStore(t.TempDir(), nil)
	require.NoError(t, err)
	_, err = s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{})
	require.ErrorIs(t, err, ErrTrustRequired)
}

type fakeGit struct {
	t          *testing.T
	manifest   string
	tree       string
	commit     string
	calls      [][]string
	repository string
}

func (f *fakeGit) Run(_ context.Context, directory string, args []string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	require.GreaterOrEqual(f.t, len(args), 3)
	require.Equal(f.t, "-c", args[0])
	require.True(f.t, strings.HasPrefix(args[1], "core.hooksPath="))
	command := args[2:]
	switch command[0] {
	case "remote":
		f.repository = command[3]
	case "rev-parse":
		return []byte(f.commit + "\n"), nil
	case "checkout":
		require.Equal(f.t, []string{"checkout", "--detach", "--force", f.commit}, command)
		require.NoError(f.t, os.WriteFile(filepath.Join(directory, "tool.toml"), []byte(f.manifest), 0o600))
	case "ls-tree":
		return []byte(f.tree), nil
	}
	return nil, nil
}

func validManifest(name, binary string) string {
	return fmt.Sprintf("schema=1\nname=%q\nbins=[%q]\ncommands={%s=[%q]}\n[images.default]\nrepository=%q\ntag=\"1\"\n", name, binary, binary, binary, "example/"+name)
}

func TestStoreAddsSyncsAndResolvesLiteralRepositoryURL(t *testing.T) {
	root := t.TempDir()
	commit := strings.Repeat("a", 40)
	git := &fakeGit{t: t, manifest: validManifest("tool", "tool"), tree: "100644 blob abc\ttool.toml\x00", commit: commit}
	s, err := NewStore(root, git)
	require.NoError(t, err)
	repositoryURL := "https://example.test/a;touch-pwned.git"
	repository, err := s.Add(context.Background(), repositoryURL, TrustDecision{Explicit: true})
	require.NoError(t, err)
	require.Equal(t, repositoryURL, git.repository)
	require.Equal(t, commit, repository.Commit)
	manifest, err := s.Resolve("tool")
	require.NoError(t, err)
	require.Equal(t, "tool", manifest.Name)
	_, err = s.Resolve("missing")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.Sync(context.Background(), repository.Name)
	require.NoError(t, err)
	_, err = NewStore(root, git)
	require.NoError(t, err)
	index, err := os.ReadFile(filepath.Join(root, "index.toml"))
	require.NoError(t, err)
	require.Contains(t, string(index), commit)
}

func TestStoreRejectsUnsafeIndexedTrees(t *testing.T) {
	for _, tree := range []string{
		"120000 blob abc\ttool.toml\x00",
		"100755 blob abc\ttool.toml\x00",
		"100644 blob abc\tREADME\x00",
		"100644 blob abc\t../tool.toml\x00",
	} {
		git := &fakeGit{t: t, manifest: validManifest("tool", "tool"), tree: tree, commit: strings.Repeat("b", 40)}
		s, err := NewStore(t.TempDir(), git)
		require.NoError(t, err)
		_, err = s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{Explicit: true})
		require.Error(t, err)
	}
}

func TestStoreRejectsInvalidURLAndMissingRepository(t *testing.T) {
	s, err := NewStore(t.TempDir(), &fakeGit{t: t})
	require.NoError(t, err)
	_, err = s.Add(context.Background(), "file:///tmp/repo", TrustDecision{Explicit: true})
	require.Error(t, err)
	_, err = s.Sync(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestStoreRejectsInvalidCommitAndDuplicateRepository(t *testing.T) {
	git := &fakeGit{t: t, manifest: validManifest("tool", "tool"), tree: "100644 blob abc\ttool.toml\x00", commit: "not-a-commit"}
	s, err := NewStore(t.TempDir(), git)
	require.NoError(t, err)
	_, err = s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{Explicit: true})
	require.Error(t, err)

	git.commit = strings.Repeat("c", 40)
	s, err = NewStore(t.TempDir(), git)
	require.NoError(t, err)
	_, err = s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{Explicit: true})
	require.NoError(t, err)
	_, err = s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{Explicit: true})
	require.Error(t, err)
}

func TestStoreDetectsAmbiguousAndTamperedProviders(t *testing.T) {
	git := &fakeGit{t: t, manifest: validManifest("one", "tool"), tree: "100644 blob abc\ttool.toml\x00", commit: strings.Repeat("d", 40)}
	s, err := NewStore(t.TempDir(), git)
	require.NoError(t, err)
	first, err := s.Add(context.Background(), "https://example.test/one.git", TrustDecision{Explicit: true})
	require.NoError(t, err)
	git.manifest = validManifest("two", "tool")
	_, err = s.Add(context.Background(), "https://example.test/two.git", TrustDecision{Explicit: true})
	require.NoError(t, err)
	_, err = s.Resolve("tool")
	require.ErrorIs(t, err, ErrAmbiguous)

	require.NoError(t, os.WriteFile(filepath.Join(s.root, "repos", first.Name, "tool.toml"), []byte("tampered"), 0o600))
	_, err = s.Resolve("tool")
	require.Error(t, err)
}

func TestNewStoreRejectsInvalidIndex(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "index.toml"), []byte("schema=1\nsecret=\"value\""), 0o600))
	_, err := NewStore(root, &fakeGit{t: t})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "value")
}

func TestNewStoreRejectsTraversalRepositoryRecord(t *testing.T) {
	root := t.TempDir()
	raw := "schema=1\n[[repositories]]\nname=\"../escape\"\nurl=\"https://example.test/x.git\"\ncommit=\"" + strings.Repeat("a", 40) + "\"\nmanifest_hashes={\"x.toml\"=\"" + strings.Repeat("b", 64) + "\"}\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "index.toml"), []byte(raw), 0o600))
	_, err := NewStore(root, &fakeGit{t: t})
	require.Error(t, err)
}

func TestExecGitRunsLiteralArguments(t *testing.T) {
	out, err := (execGit{}).Run(context.Background(), t.TempDir(), []string{"--version"})
	require.NoError(t, err)
	require.Contains(t, string(out), "git version")
}
