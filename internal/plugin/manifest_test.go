package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
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
	valid := "schema=1\nname=\"x\"\nbins=[\"x\"]\n[images.default]\nrepository=\"registry.example/x\"\ntag_template=\"{version}\"\ncommands={x=[\"x\"]}\n"
	cases := []string{
		strings.Replace(valid, `schema=1`, `schema=2`, 1),
		strings.Replace(valid, `name="x"`, `name="../x"`, 1),
		strings.Replace(valid, `name="x"`, `name="Bad Name"`, 1),
		strings.Replace(valid, `name="x"`, `name="bad\\name"`, 1),
		strings.Replace(valid, `bins=["x"]`, `bins=["../x"]`, 1),
		strings.Replace(valid, `bins=["x"]`, `bins=["x","x"]`, 1),
		strings.Replace(valid, `bins=["x"]`, `bins=[]`, 1),
		strings.Replace(valid, `commands={x=["x"]}`, `commands={x=["other"]}`, 1),
		strings.Replace(valid, `commands={x=["x"]}`, `commands={x=["x",""]}`, 1),
		strings.Replace(valid, `commands={x=["x"]}`, `commands={x=["x","bad\\u0001arg"]}`, 1),
		strings.Replace(valid, `commands={x=["x"]}`, `commands={x=["x"],y=["y"]}`, 1),
		strings.Replace(valid, `repository="registry.example/x"`, `repository=""`, 1),
		strings.Replace(valid, `repository="registry.example/x"`, `repository="HTTPS://registry.example/x:tag"`, 1),
		strings.Replace(valid, `repository="registry.example/x"`, `repository="registry.example:70000/x"`, 1),
		strings.Replace(valid, `tag_template="{version}"`, `tag_template="latest"`, 1),
		strings.Replace(valid, `tag_template="{version}"`, `tag_template="{version}-{version}"`, 1),
		strings.Replace(valid, `tag_template="{version}"`, `tag_template="{{version}}"`, 1),
		strings.Replace(valid, `tag_template="{version}"`, `tag_template="{version}{}"`, 1),
		strings.Replace(valid, `tag_template="{version}"`, `tag_template=".{version}"`, 1),
		strings.Replace(valid, `tag_template="{version}"`, `tag_template="-{version}"`, 1),
		strings.Replace(valid, `tag_template="{version}"`, `tag_template="`+strings.Repeat("a", 129)+`{version}"`, 1),
		valid + "[[caches]]\npath=\"relative\"\n",
		valid + "[[caches]]\npath=\"/tmp/../cache\"\n",
		valid + "[[caches]]\npath=\"/cache\"\n[[caches]]\npath=\"/cache\"\n",
		valid + "[environment]\n\"BAD=KEY\"=\"x\"\n",
		valid + "[[platforms]]\nos=\"linux\"\narch=\"\"\n",
		valid + "[[egress]]\nhost=\"no-dot\"\nports=[443]\n",
		valid + "[[egress]]\nhost=\"10.0.0.1\"\nports=[443]\n",
		valid + "[[egress]]\nhost=\"127.1\"\nports=[443]\n",
		valid + "[[egress]]\nhost=\"bad label.example\"\nports=[443]\n",
		valid + "[[egress]]\nhost=\"a.example\"\nports=[]\n",
		valid + "[[egress]]\nhost=\"a.example\"\nports=[0]\n",
		valid + "[[egress]]\nhost=\"a.example\"\nports=[70000]\n",
		valid + "[[egress]]\nhost=\"a.example\"\nports=[443,443]\n",
		valid + "[[egress]]\nhost=\"a.example\"\nports=[443]\n[[egress]]\nhost=\"a.example\"\nports=[80]\n",
	}
	for _, input := range cases {
		_, err := LoadManifest(strings.NewReader(input))
		require.Error(t, err)
	}
}

func TestManifestAcceptsEgress(t *testing.T) {
	input := "schema=1\nname=\"x\"\nbins=[\"x\"]\ncommands={x=[\"x\"]}\n[images.default]\nrepository=\"registry.example/x\"\ntag_template=\"{version}\"\n[[egress]]\nhost=\"registry.example\"\nports=[443,80]\n"
	manifest, err := LoadManifest(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, manifest.Egress, 1)
	require.Equal(t, "registry.example", manifest.Egress[0].Host)
	require.Equal(t, []int{443, 80}, manifest.Egress[0].Ports)
}

func TestValidEgressHostAcceptsAndRejects(t *testing.T) {
	for _, ok := range []string{"registry.npmjs.org", "files.pythonhosted.org", "a.b.c.example"} {
		require.True(t, validEgressHost(ok), ok)
	}
	for _, bad := range []string{"", "no-dot", "10.0.0.1", "127.1", "0x7f.1", "a..b", "-bad.example", strings.Repeat("a.", 127) + "x"} {
		require.False(t, validEgressHost(bad), bad)
	}
}

func TestValidImageRepositoryPorts(t *testing.T) {
	require.True(t, validImageRepository("registry.example:5000/x"))
	for _, bad := range []string{"registry.example:70000/x", "registry.example:abc/x", "registry.example:0500/x"} {
		require.False(t, validImageRepository(bad), bad)
	}
}

func TestValidTagTemplate(t *testing.T) {
	for _, ok := range []string{"{version}", "{version}-alpine", "v{version}"} {
		require.True(t, validTagTemplate(ok), ok)
	}
	for _, bad := range []string{"latest", "{version}{version}", "{{version}}", "{version}{}", "-{version}", ".*"} {
		require.False(t, validTagTemplate(bad), bad)
	}
}

func TestValidateRejectsProgrammaticManifestMutation(t *testing.T) {
	manifest, err := LoadManifest(strings.NewReader("schema=1\nname=\"x\"\nbins=[\"x\"]\ncommands={x=[\"x\"]}\n[images.default]\nrepository=\"registry.example/x\"\ntag_template=\"{version}\"\n"))
	require.NoError(t, err)
	manifest.Commands["x"][0] = "other"
	require.Error(t, Validate(manifest))
}

func TestManifestProvenanceIsNotSerializedAsManifestData(t *testing.T) {
	manifest, err := LoadManifest(strings.NewReader("schema=1\nname=\"x\"\nbins=[\"x\"]\ncommands={x=[\"x\"]}\n[images.default]\nrepository=\"registry.example/x\"\ntag_template=\"{version}\"\n"))
	require.NoError(t, err)
	manifest.Provenance = Provenance{Repository: "https://secret.example/plugins", Commit: strings.Repeat("a", 40), ManifestSHA256: strings.Repeat("b", 64), Schema: 1}
	raw, err := toml.Marshal(manifest)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "secret.example")
	require.NotContains(t, string(raw), "manifestsha")
}
