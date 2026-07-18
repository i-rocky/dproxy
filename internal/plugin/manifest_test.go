package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManifestRejectsExecutableFields(t *testing.T) {
	for _, field := range []string{`hook="sh evil"`, `docker_args=["--privileged"]`, `mount="/:/host"`} {
		input := "schema=1\nname=\"x\"\nbins=[\"x\"]\n" + field
		_, err := LoadManifest(strings.NewReader(input))
		require.Error(t, err, field)
		require.NotContains(t, err.Error(), "evil")
	}
}

func TestManifestLoadsOfficialManifestsAndCommands(t *testing.T) {
	files, err := filepath.Glob("../../plugins/official/*.toml")
	require.NoError(t, err)
	require.Len(t, files, 5)
	for _, file := range files {
		raw, err := os.ReadFile(file)
		require.NoError(t, err)
		manifest, err := LoadManifest(strings.NewReader(string(raw)))
		require.NoError(t, err, file)
		for _, binary := range manifest.Bins {
			command, ok := manifest.Command(binary)
			require.True(t, ok)
			require.Equal(t, binary, command[0])
			command[0] = "changed"
			again, _ := manifest.Command(binary)
			require.Equal(t, binary, again[0])
		}
		_, ok := manifest.Command("missing")
		require.False(t, ok)
	}
}

func TestManifestValidation(t *testing.T) {
	valid := "schema=1\nname=\"x\"\nbins=[\"x\"]\n[images.default]\nrepository=\"example/x\"\ntag=\"1\"\ncommands={x=[\"x\"]}\n"
	cases := []string{
		strings.Replace(valid, `schema=1`, `schema=2`, 1),
		strings.Replace(valid, `name="x"`, `name="../x"`, 1),
		strings.Replace(valid, `bins=["x"]`, `bins=["../x"]`, 1),
		strings.Replace(valid, `bins=["x"]`, `bins=["x","x"]`, 1),
		strings.Replace(valid, `bins=["x"]`, `bins=[]`, 1),
		strings.Replace(valid, `commands={x=["x"]}`, `commands={x=["other"]}`, 1),
		strings.Replace(valid, `commands={x=["x"]}`, `commands={x=["x"],y=["y"]}`, 1),
		strings.Replace(valid, `repository="example/x"`, `repository=""`, 1),
		valid + "[[caches]]\npath=\"relative\"\n",
		valid + "[[caches]]\npath=\"/tmp/../cache\"\n",
		valid + "[environment]\n\"BAD=KEY\"=\"x\"\n",
		valid + "[[platforms]]\nos=\"linux\"\narch=\"\"\n",
	}
	for _, input := range cases {
		_, err := LoadManifest(strings.NewReader(input))
		require.Error(t, err)
	}
}
