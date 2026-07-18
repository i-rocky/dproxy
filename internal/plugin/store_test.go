package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type gitInvocation struct {
	Args []string
	Env  []string
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "-c" {
		record, _ := json.Marshal(gitInvocation{Args: os.Args[1:], Env: os.Environ()})
		_ = os.WriteFile("git-invocation.json", record, 0o600)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

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
	return fmt.Sprintf("schema=1\nname=%q\nbins=[%q]\ncommands={%s=[%q]}\n[images.default]\nrepository=%q\ntag_template=\"{version}\"\n", name, binary, binary, binary, "registry.example/"+name)
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
	require.Equal(t, Provenance{Repository: repositoryURL, Commit: commit, ManifestSHA256: repository.ManifestHashes["tool.toml"], Schema: 1}, manifest.Provenance)
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
		"100644 blob abc\tnested/.hidden/tool.toml\x00",
		"100644 blob abc\tnested\\tool.toml\x00",
		"100644 blob abc\tnested/line\ntool.toml\x00",
	} {
		git := &fakeGit{t: t, manifest: validManifest("tool", "tool"), tree: tree, commit: strings.Repeat("b", 40)}
		s, err := NewStore(t.TempDir(), git)
		require.NoError(t, err)
		_, err = s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{Explicit: true})
		require.Error(t, err)
	}
}

func TestReadRegularAtRejectsSymlinkedComponents(t *testing.T) {
	base := t.TempDir()
	target := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(target, "tool.toml"), []byte("secret"), 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(base, "nested")))
	_, err := readRegularAt(base, "nested/tool.toml")
	require.Error(t, err)
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
	require.ErrorIs(t, err, ErrAmbiguous)
	manifest, err := s.Resolve("tool")
	require.NoError(t, err)
	require.Equal(t, "one", manifest.Name)

	require.NoError(t, os.WriteFile(filepath.Join(s.root, "repos", first.Name, first.Commit, "tool.toml"), []byte("tampered"), 0o600))
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
	out, err := (execGit{executable: "/usr/bin/git", home: t.TempDir()}).Run(context.Background(), t.TempDir(), []string{"--version"})
	require.NoError(t, err)
	require.Contains(t, string(out), "git version")
}

func TestExecGitUsesLiteralArgumentsAndAllowlistedEnvironment(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("DPROXY_HOSTILE_SECRET", "must-not-leak")
	t.Setenv("GIT_DIR", "/hostile/repository")
	args := []string{"-c", "core.hooksPath=" + filepath.Join(directory, "empty-hooks"), "remote", "add", "origin", "https://example.test/a;touch pwned.git"}
	_, err := (execGit{executable: os.Args[0], home: filepath.Join(directory, "home")}).Run(context.Background(), directory, args)
	require.NoError(t, err)
	raw, err := os.ReadFile(filepath.Join(directory, "git-invocation.json"))
	require.NoError(t, err)
	var invocation gitInvocation
	require.NoError(t, json.Unmarshal(raw, &invocation))
	require.Equal(t, args, invocation.Args)
	require.NotContains(t, strings.Join(invocation.Env, "\n"), "DPROXY_HOSTILE_SECRET")
	require.Contains(t, invocation.Env, "GIT_CONFIG_NOSYSTEM=1")
	require.Contains(t, invocation.Env, "GIT_CONFIG_GLOBAL=/dev/null")
	require.Contains(t, invocation.Env, "GIT_TERMINAL_PROMPT=0")
	require.Contains(t, invocation.Env, "GIT_ASKPASS=/bin/false")
	require.Contains(t, invocation.Env, "SSH_ASKPASS=/bin/false")
	require.Contains(t, invocation.Env, "HOME="+filepath.Join(directory, "home"))
	require.NotContains(t, invocation.Env, "GIT_DIR=/hostile/repository")
	require.NoFileExists(t, filepath.Join(directory, "pwned.git"))
}

func TestStorePersistenceFailureDoesNotChangeMemoryAndAllowsRetry(t *testing.T) {
	git := &fakeGit{t: t, manifest: validManifest("tool", "tool"), tree: "100644 blob abc\ttool.toml\x00", commit: strings.Repeat("e", 40)}
	s, err := NewStore(t.TempDir(), git)
	require.NoError(t, err)
	realRename := s.renameIndex
	s.renameIndex = func(_, _ string) error { return fmt.Errorf("injected persistence failure") }
	_, err = s.Add(context.Background(), "https://EXAMPLE.test/plugins.git", TrustDecision{Explicit: true})
	require.Error(t, err)
	require.Empty(t, s.index.Repositories)
	_, err = s.Resolve("tool")
	require.ErrorIs(t, err, ErrNotFound)
	require.DirExists(t, filepath.Join(s.root, "repos", repositoryName("https://example.test/plugins.git"), git.commit))
	stages, globErr := filepath.Glob(filepath.Join(s.root, ".repo-*"))
	require.NoError(t, globErr)
	require.Empty(t, stages)
	s.renameIndex = realRename
	repository, err := s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{Explicit: true})
	require.NoError(t, err)
	require.Equal(t, "https://example.test/plugins.git", repository.URL)
}

func TestSyncPersistenceFailureRestoresLiveRepositoryAndAllowsRetry(t *testing.T) {
	git := &fakeGit{t: t, manifest: validManifest("old", "tool"), tree: "100644 blob abc\ttool.toml\x00", commit: strings.Repeat("1", 40)}
	s, err := NewStore(t.TempDir(), git)
	require.NoError(t, err)
	repository, err := s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{Explicit: true})
	require.NoError(t, err)
	git.manifest = validManifest("new", "tool")
	git.commit = strings.Repeat("2", 40)
	realRename := s.renameIndex
	s.renameIndex = func(_, _ string) error { return fmt.Errorf("injected persistence failure") }
	_, err = s.Sync(context.Background(), repository.Name)
	require.Error(t, err)
	require.Equal(t, strings.Repeat("1", 40), s.index.Repositories[0].Commit)
	manifest, err := s.Resolve("tool")
	require.NoError(t, err)
	require.Equal(t, "old", manifest.Name)
	s.renameIndex = realRename
	updated, err := s.Sync(context.Background(), repository.Name)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("2", 40), updated.Commit)
	manifest, err = s.Resolve("tool")
	require.NoError(t, err)
	require.Equal(t, "new", manifest.Name)
	stages, err := filepath.Glob(filepath.Join(s.root, ".repo-*"))
	require.NoError(t, err)
	require.Empty(t, stages)
}

func TestGenerationParentSyncFailureLeavesIndexedRepositoryUnchanged(t *testing.T) {
	git := &fakeGit{t: t, manifest: validManifest("old", "tool"), tree: "100644 blob abc\ttool.toml\x00", commit: strings.Repeat("3", 40)}
	s, err := NewStore(t.TempDir(), git)
	require.NoError(t, err)
	repository, err := s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{Explicit: true})
	require.NoError(t, err)
	git.manifest = validManifest("new", "tool")
	git.commit = strings.Repeat("4", 40)
	realSync := s.syncGenerationParent
	s.syncGenerationParent = func(string) error { return fmt.Errorf("injected generation parent sync failure") }
	_, err = s.Sync(context.Background(), repository.Name)
	require.Error(t, err)
	require.Equal(t, strings.Repeat("3", 40), s.index.Repositories[0].Commit)
	require.DirExists(t, filepath.Join(s.root, "repos", repository.Name, strings.Repeat("4", 40)))
	manifest, err := s.Resolve("tool")
	require.NoError(t, err)
	require.Equal(t, "old", manifest.Name)
	s.syncGenerationParent = realSync
	updated, err := s.Sync(context.Background(), repository.Name)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("4", 40), updated.Commit)
}

func TestRepositoryRootSyncFailurePreventsIndexPublicationAndAllowsRetry(t *testing.T) {
	git := &fakeGit{t: t, manifest: validManifest("tool", "tool"), tree: "100644 blob abc\ttool.toml\x00", commit: strings.Repeat("7", 40)}
	s, err := NewStore(t.TempDir(), git)
	require.NoError(t, err)
	indexPublications := 0
	realRename := s.renameIndex
	s.renameIndex = func(old, new string) error {
		indexPublications++
		return realRename(old, new)
	}
	realSync := s.syncReposRoot
	s.syncReposRoot = func() error { return fmt.Errorf("injected repositories root sync failure") }
	_, err = s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{Explicit: true})
	require.Error(t, err)
	require.Zero(t, indexPublications)
	require.Empty(t, s.index.Repositories)
	require.NoFileExists(t, filepath.Join(s.root, "index.toml"))
	s.syncReposRoot = realSync
	_, err = s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{Explicit: true})
	require.NoError(t, err)
	require.Equal(t, 1, indexPublications)
}

func TestStoreRejectsDuplicateManifestNamesAcrossRepositories(t *testing.T) {
	git := &fakeGit{t: t, manifest: validManifest("same", "one"), tree: "100644 blob abc\ttool.toml\x00", commit: strings.Repeat("5", 40)}
	s, err := NewStore(t.TempDir(), git)
	require.NoError(t, err)
	_, err = s.Add(context.Background(), "https://example.test/one.git", TrustDecision{Explicit: true})
	require.NoError(t, err)
	git.manifest = validManifest("same", "two")
	git.commit = strings.Repeat("6", 40)
	_, err = s.Add(context.Background(), "https://example.test/two.git", TrustDecision{Explicit: true})
	require.Error(t, err)
}

func TestCloneIndexDeepCopiesManifestHashes(t *testing.T) {
	original := storeIndex{Schema: 1, Repositories: []Repository{{ManifestHashes: map[string]string{"x.toml": "old"}}}}
	cloned := cloneIndex(original)
	cloned.Repositories[0].ManifestHashes["x.toml"] = "new"
	require.Equal(t, "old", original.Repositories[0].ManifestHashes["x.toml"])
}

func TestPersistRestoresIndexWhenParentSyncFails(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, &fakeGit{t: t})
	require.NoError(t, err)
	s.syncRoot = func() error { return fmt.Errorf("injected directory sync failure") }
	err = s.persist(storeIndex{Schema: 1})
	require.Error(t, err)
	require.NoFileExists(t, filepath.Join(root, "index.toml"))

	previous := []byte("schema = 1\n")
	require.NoError(t, os.WriteFile(filepath.Join(root, "index.toml"), previous, 0o600))
	err = s.persist(storeIndex{Schema: 1, Repositories: []Repository{{Name: "candidate"}}})
	require.Error(t, err)
	raw, readErr := os.ReadFile(filepath.Join(root, "index.toml"))
	require.NoError(t, readErr)
	require.Equal(t, previous, raw)
}

func TestRepositoryURLRestrictions(t *testing.T) {
	for _, value := range []string{
		"ssh://example.test/x.git", "https://user@example.test/x.git", "https://example.test", "https://example.test/x?secret=y",
		"https://example.test/x#frag", "https://example.test:080/x", "https://example.test:70000/x", "https://example.test/x\\y",
	} {
		_, err := normalizeRepositoryURL(value)
		require.Error(t, err, value)
	}
	normalized, err := normalizeRepositoryURL("HTTPS://EXAMPLE.TEST:443/plugins.git")
	require.NoError(t, err)
	require.Equal(t, "https://example.test/plugins.git", normalized)
}
