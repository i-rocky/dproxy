package lock

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func validFile() File {
	return File{Schema: 1, ConfigSHA256: strings.Repeat("a", 64), Tools: map[string]Tool{
		"node": {Requested: "24", Version: "24.4.1", Image: "docker.io/library/node", Tag: "24.4.1", Digest: "sha256:" + strings.Repeat("d", 64), Platform: "linux/amd64"},
	}, Plugins: map[string]Plugin{"node": {Repository: "https://example.test/plugins", Commit: strings.Repeat("b", 40), ManifestSHA256: strings.Repeat("c", 64), Schema: 1}}}
}

func TestCanonicalAndWriteAtomicAreDeterministic(t *testing.T) {
	f := validFile()
	a, err := f.Canonical()
	require.NoError(t, err)
	b, err := f.Canonical()
	require.NoError(t, err)
	require.Equal(t, a, b)
	require.Contains(t, string(a), `"config_sha256"`)
	require.Contains(t, string(a), `"manifest_sha256"`)
	require.Less(t, strings.Index(string(a), `"plugins"`), strings.Index(string(a), `"tools"`))

	path := filepath.Join(t.TempDir(), ".dproxy.lock")
	require.NoError(t, WriteAtomic(path, f))
	first, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, WriteAtomic(path, f))
	second, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, first, second)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	loaded, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, f, loaded)
}

func TestFileVerifyFailsClosed(t *testing.T) {
	f := validFile()
	require.NoError(t, f.Verify(strings.Repeat("a", 64), "linux/amd64"))
	cases := []func(*File){
		func(f *File) { f.Schema = 2 },
		func(f *File) { f.ConfigSHA256 = strings.Repeat("A", 64) },
		func(f *File) { f.Tools["node"] = Tool{} },
		func(f *File) { x := f.Tools["node"]; x.Version = "24"; f.Tools["node"] = x },
		func(f *File) {
			x := f.Tools["node"]
			x.Digest = "sha256:" + strings.Repeat("D", 64)
			f.Tools["node"] = x
		},
		func(f *File) { x := f.Tools["node"]; x.Platform = "linux/arm64"; f.Tools["node"] = x },
		func(f *File) { x := f.Plugins["node"]; x.ManifestSHA256 = "bad"; f.Plugins["node"] = x },
		func(f *File) { x := f.Plugins["node"]; x.Commit = strings.Repeat("B", 40); f.Plugins["node"] = x },
		func(f *File) { x := f.Plugins["node"]; x.Commit = strings.Repeat("b", 41); f.Plugins["node"] = x },
		func(f *File) {
			x := f.Plugins["node"]
			x.Repository = "http://example.test/plugins"
			f.Plugins["node"] = x
		},
	}
	for i, mutate := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			bad := validFile()
			mutate(&bad)
			require.Error(t, bad.Verify(strings.Repeat("a", 64), "linux/amd64"))
		})
	}
	require.Error(t, f.Verify(strings.Repeat("e", 64), "linux/amd64"))
}

func TestWriteAtomicRenameFailurePreservesExistingLockAndCleansTemporary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	old := renameFile
	renameFile = func(string, string) error { return errors.New("injected rename failure") }
	t.Cleanup(func() { renameFile = old })
	require.Error(t, WriteAtomic(path, validFile()))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "original", string(raw))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestWriteAtomicReportsDirectorySyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	old := syncParent
	syncParent = func(string) error { return errors.New("injected sync failure") }
	t.Cleanup(func() { syncParent = old })
	require.Error(t, WriteAtomic(path, validFile()))
	_, err := os.Stat(path)
	require.NoError(t, err)
}

func TestWriteAtomicFileSyncFailurePreservesExistingLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	old := syncFile
	syncFile = func(*os.File) error { return errors.New("injected file sync failure") }
	t.Cleanup(func() { syncFile = old })
	require.Error(t, WriteAtomic(path, validFile()))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "original", string(raw))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestHashConfig(t *testing.T) {
	got := HashConfig([]byte("config"))
	require.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte("config"))), got)
}

func TestGlobalConfigHashVerifies(t *testing.T) {
	platform := "linux/amd64"
	f := File{Schema: 1, ConfigSHA256: GlobalConfigHash(), Plugins: map[string]Plugin{"node": {Repository: "https://example.test/plugins", Commit: strings.Repeat("b", 40), ManifestSHA256: strings.Repeat("c", 64), Schema: 1}}, Tools: map[string]Tool{"node": {Requested: "*", Version: "24.1.0", Image: "registry.test/node", Tag: "24.1.0", Digest: "sha256:" + strings.Repeat("d", 64), Platform: platform}}}
	require.NoError(t, f.Verify(GlobalConfigHash(), platform))
	// A project config hash must not satisfy a global (no-project) lock.
	require.Error(t, f.Verify(HashConfig([]byte("schema=1\n")), platform))
}

func TestCanonicalHTTPSRepository(t *testing.T) {
	require.True(t, canonicalHTTPSRepository("https://example.com/repo"))
	for _, bad := range []string{"http://example.com/repo", "https://example.com/", "https://example.com/repo?x=1", "https://user:pass@example.com/repo", "https://example.com:443/repo", "https://Example.com/repo", "ftp://example.com/repo", "https://127.0.0.1/repo", "https://169.254.169.254/repo", "https://10.0.0.1/repo"} {
		require.False(t, canonicalHTTPSRepository(bad), bad)
	}
}

func TestLockFormatValidators(t *testing.T) {
	require.True(t, ValidExactVersion("1.2.3"))
	require.True(t, ValidExactVersion("1.2.3-rc.1+build"))
	for _, bad := range []string{"", "1", "v1.2.3", "1.2", "1.2.3.4"} {
		require.False(t, ValidExactVersion(bad), bad)
	}
	require.True(t, ValidDigest("sha256:"+strings.Repeat("a", 64)))
	require.False(t, ValidDigest("sha256:short"))
	require.True(t, ValidSHA256(strings.Repeat("a", 64)))
	require.False(t, ValidSHA256(strings.Repeat("a", 63)))
}

func TestLoadRejectsUnknownOrTrailingData(t *testing.T) {
	for _, raw := range []string{`{"schema":1,"unknown":true}`, `{"schema":1}{}`} {
		path := filepath.Join(t.TempDir(), "lock")
		require.NoError(t, os.WriteFile(path, []byte(raw), 0600))
		_, err := Load(path)
		require.Error(t, err)
	}
}
