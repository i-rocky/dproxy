package lock

import (
	"crypto/sha256"
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

func TestHashConfig(t *testing.T) {
	got := HashConfig([]byte("config"))
	require.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte("config"))), got)
}

func TestLoadRejectsUnknownOrTrailingData(t *testing.T) {
	for _, raw := range []string{`{"schema":1,"unknown":true}`, `{"schema":1}{}`} {
		path := filepath.Join(t.TempDir(), "lock")
		require.NoError(t, os.WriteFile(path, []byte(raw), 0600))
		_, err := Load(path)
		require.Error(t, err)
	}
}
