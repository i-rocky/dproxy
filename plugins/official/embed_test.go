package official

import (
	"bytes"
	"strings"
	"testing"

	"github.com/i-rocky/dproxy/internal/plugin"
	"github.com/stretchr/testify/require"
)

func TestLoadRequiresImmutableReleaseMetadata(t *testing.T) {
	oldRepo, oldCommit := OfficialRepository, Commit
	t.Cleanup(func() { OfficialRepository, Commit = oldRepo, oldCommit })
	OfficialRepository, Commit = "", ""
	_, err := Load()
	require.Error(t, err)
	OfficialRepository, Commit = "https://github.com/example/dproxy.git", strings.Repeat("a", 40)
	manifests, err := Load()
	require.NoError(t, err)
	require.Contains(t, manifests, "npm")
	require.Equal(t, Commit, manifests["npm"].Provenance.Commit)
}

// TestLoadProvenanceValidation covers the fail-closed checks that prevent a
// non-https or un-pinned official repository from being trusted.
func TestLoadProvenanceValidation(t *testing.T) {
	oldRepo, oldCommit := OfficialRepository, Commit
	t.Cleanup(func() { OfficialRepository, Commit = oldRepo, oldCommit })
	valid := strings.Repeat("a", 40)
	cases := map[string]struct{ repo, commit string }{
		"non-https scheme": {"http://github.com/example/dproxy.git", valid},
		"empty host":       {"https:///dproxy.git", valid},
		"userinfo present": {"https://user@github.com/example/dproxy.git", valid},
		"query present":    {"https://github.com/example/dproxy.git?x=1", valid},
		"fragment present": {"https://github.com/example/dproxy.git#frag", valid},
		"commit too short": {"https://github.com/example/dproxy.git", "abc123"},
		"commit non-hex":   {"https://github.com/example/dproxy.git", strings.Repeat("z", 40)},
		"commit empty":     {"https://github.com/example/dproxy.git", ""},
		"empty repository": {"", valid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			OfficialRepository, Commit = c.repo, c.commit
			_, err := Load()
			require.Error(t, err)
		})
	}
	// A 64-hex (sha256) commit is also acceptable and must load.
	t.Run("64-hex commit accepted", func(t *testing.T) {
		OfficialRepository, Commit = "https://github.com/example/dproxy.git", strings.Repeat("b", 64)
		loaded, err := Load()
		require.NoError(t, err)
		require.NotEmpty(t, loaded)
	})
}

// TestDeriveProvenanceFromBuildInfo confirms a plain `go install module@version`
// build (no ldflags, no vcs.revision) still derives verifiable provenance from
// the module path and pseudo-version, so the bundled plugins load without
// release ldflags.
func TestDeriveProvenanceFromBuildInfo(t *testing.T) {
	require.Equal(t, "1536a011c5f6", commitFromPseudoVersion("v0.0.0-20260720162621-1536a011c5f6"))
	require.Equal(t, "", commitFromPseudoVersion("v1.2.3"), "a real tag is not a pseudo-version")
	require.Equal(t, "https://github.com/i-rocky/dproxy", repositoryFromModule("github.com/i-rocky/dproxy"))
	require.Equal(t, "", repositoryFromModule("example/local"), "non-host module path yields no repository")
}

// TestOfficialManifestsWireCacheEnvironment locks the contract that each bundled
// tool is configured (via its own cache-home env var) to write into its mounted
// cache. The sandbox overrides HOME, so without this wiring the tools would
// write to an ephemeral path and re-download every run.
func TestOfficialManifestsWireCacheEnvironment(t *testing.T) {
	cacheEnv := map[string]string{
		"node":   "npm_config_cache",
		"python": "PIP_CACHE_DIR",
		"rust":   "CARGO_HOME",
		"go":     "GOPATH",
		"bun":    "BUN_INSTALL",
	}
	entries, err := manifests.ReadDir(".")
	require.NoError(t, err)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		raw, err := manifests.ReadFile(entry.Name())
		require.NoError(t, err)
		m, err := plugin.LoadManifest(bytes.NewReader(raw))
		require.NoError(t, err)
		envVar, ok := cacheEnv[m.Name]
		require.True(t, ok, "no cache-env mapping for plugin %q", m.Name)
		require.Len(t, m.Caches, 1, m.Name)
		require.Equal(t, m.Caches[0].Path, m.Environment[envVar],
			"%s: %s must point at the cache mount so the tool actually uses it", m.Name, envVar)
	}
}

// TestBinariesEnumeratesUniqueTools confirms shim enumeration yields each bundled
// binary exactly once across all manifests.
func TestBinariesEnumeratesUniqueTools(t *testing.T) {
	bins, err := Binaries()
	require.NoError(t, err)
	require.NotEmpty(t, bins)
	seen := map[string]int{}
	for _, b := range bins {
		seen[b]++
	}
	for name, n := range seen {
		require.Equal(t, 1, n, "binary %q listed %d times", name, n)
	}
	require.Contains(t, bins, "npm")
}
