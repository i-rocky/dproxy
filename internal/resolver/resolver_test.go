package resolver

import (
	"context"
	"errors"
	"strings"
	"testing"

	"dproxy/internal/config"
	"dproxy/internal/plugin"
	"github.com/stretchr/testify/require"
)

type fakeRegistry struct {
	tags   []string
	digest string
	err    error
}

func (f fakeRegistry) Tags(context.Context, string) ([]string, error) {
	return append([]string(nil), f.tags...), f.err
}
func (f fakeRegistry) Digest(context.Context, string, string) (string, error) { return f.digest, f.err }

func manifests() map[string]plugin.Manifest {
	return map[string]plugin.Manifest{"node": {Schema: 1, Name: "node", Images: map[string]plugin.Image{"default": {Repository: "docker.io/library/node", TagTemplate: "{version}"}}, Platforms: []plugin.Platform{{OS: "linux", Arch: "amd64"}}}}
}

func TestResolveHighestMatchingDigest(t *testing.T) {
	reg := fakeRegistry{tags: []string{"23.9.0", "24.1.0", "24.4.1", "25.0.0"}, digest: "sha256:" + strings.Repeat("d", 64)}
	got, err := Resolve(context.Background(), config.Config{Schema: 1, Tools: map[string]string{"node": "24"}}, manifests(), "linux/amd64", strings.Repeat("a", 64), reg)
	require.NoError(t, err)
	require.Equal(t, "24.4.1", got.Tools["node"].Version)
	require.Equal(t, reg.digest, got.Tools["node"].Digest)
}

func TestResolveRejectsUntrustedResolution(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.Config
		manifests map[string]plugin.Manifest
		platform  string
		reg       fakeRegistry
	}{
		{"missing manifest", config.Config{Tools: map[string]string{"bad": "1"}}, manifests(), "linux/amd64", fakeRegistry{}},
		{"unsupported platform", config.Config{Tools: map[string]string{"node": "24"}}, manifests(), "linux/arm64", fakeRegistry{}},
		{"bad constraint", config.Config{Tools: map[string]string{"node": "nope"}}, manifests(), "linux/amd64", fakeRegistry{}},
		{"no match", config.Config{Tools: map[string]string{"node": "24"}}, manifests(), "linux/amd64", fakeRegistry{tags: []string{"23.0.0"}}},
		{"bad digest", config.Config{Tools: map[string]string{"node": "24"}}, manifests(), "linux/amd64", fakeRegistry{tags: []string{"24.0.0"}, digest: "latest"}},
		{"registry error", config.Config{Tools: map[string]string{"node": "24"}}, manifests(), "linux/amd64", fakeRegistry{err: errors.New("offline")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Resolve(context.Background(), tc.cfg, tc.manifests, tc.platform, strings.Repeat("a", 64), tc.reg)
			require.Error(t, err)
		})
	}
}

func TestResolveExactMinorAndIgnoresNonSemverTags(t *testing.T) {
	reg := fakeRegistry{tags: []string{"latest", "3.14.0-rc.1", "3.14.0", "3.14.2", "3.15.0"}, digest: "sha256:" + strings.Repeat("e", 64)}
	got, err := Resolve(context.Background(), config.Config{Tools: map[string]string{"node": "3.14"}}, manifests(), "linux/amd64", strings.Repeat("a", 64), reg)
	require.NoError(t, err)
	require.Equal(t, "3.14.2", got.Tools["node"].Version)
}

func TestResolveCompoundConstraint(t *testing.T) {
	reg := fakeRegistry{tags: []string{"1.2.9", "1.3.0", "1.9.4", "2.0.0"}, digest: "sha256:" + strings.Repeat("f", 64)}
	got, err := Resolve(context.Background(), config.Config{Tools: map[string]string{"node": ">=1.3, <2"}}, manifests(), "linux/amd64", strings.Repeat("a", 64), reg)
	require.NoError(t, err)
	require.Equal(t, "1.9.4", got.Tools["node"].Version)
}
