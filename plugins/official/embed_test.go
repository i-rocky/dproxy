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
