package official

import (
	"strings"
	"testing"

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
