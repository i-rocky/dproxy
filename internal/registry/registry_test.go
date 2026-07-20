package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) *http.Response

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r), nil }
func response(status int, header http.Header, body string) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}

func TestRegistryRejectsRedirectsOversizeAndTrailingJSON(t *testing.T) {
	redirectClient := &http.Client{Transport: roundTripFunc(func(*http.Request) *http.Response {
		return response(http.StatusFound, http.Header{"Location": {"http://registry.test/downgrade"}}, "")
	})}
	_, err := New(redirectClient).Tags(context.Background(), "registry.test/team/tool")
	require.ErrorContains(t, err, "status 302")

	for name, body := range map[string]string{
		"oversize":      `{"tags":["` + strings.Repeat("x", maxResponse) + `"]}`,
		"trailing json": `{"tags":[]} {"tags":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) *http.Response { return response(200, nil, body) })}
			_, err := New(client).Tags(context.Background(), "registry.test/team/tool")
			require.Error(t, err)
		})
	}
}

func TestRegistryTagsPaginationAndBearerAuthentication(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) *http.Response {
		if r.URL.Path == "/token" {
			return response(200, nil, `{"token":"secret"}`)
		}
		if r.Header.Get("Authorization") != "Bearer secret" {
			return response(401, http.Header{"Www-Authenticate": {`Bearer realm="https://registry.test/token",service="fixture",scope="repository:team/tool:pull"`}}, "")
		}
		if r.URL.Query().Get("last") == "v1" {
			return response(200, nil, `{"tags":["v2"]}`)
		}
		return response(200, http.Header{"Link": {`</v2/team/tool/tags/list?last=v1>; rel="next"`}}, `{"tags":["v1"]}`)
	})}
	tags, err := New(client).Tags(context.Background(), "registry.test/team/tool")
	require.NoError(t, err)
	require.Equal(t, []string{"v1", "v2"}, tags)
}

func TestRegistryResolvesPlatformManifestDigest(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	sum := sha256.Sum256(manifest)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) *http.Response {
		if r.URL.Path == "/v2/team/tool/manifests/v1" {
			body := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}}]}`, digest)
			return response(200, http.Header{"Content-Type": {"application/vnd.oci.image.index.v1+json"}}, body)
		}
		return response(200, http.Header{"Docker-Content-Digest": {digest}, "Content-Type": {"application/vnd.oci.image.manifest.v1+json"}}, string(manifest))
	})}
	got, err := New(client).Digest(context.Background(), "registry.test/team/tool:v1", "linux/amd64")
	require.NoError(t, err)
	require.Equal(t, digest, got)
}

func TestRegistryRejectsInsecureOrAmbiguousReferences(t *testing.T) {
	r := New(http.DefaultClient)
	_, err := r.Tags(context.Background(), "http://registry.example/tool")
	require.Error(t, err)
	_, err = r.Digest(context.Background(), "registry.example/tool:latest", "linux")
	require.Error(t, err)
}

func TestRegistryRejectsUnsafePaginationAndDigestMismatches(t *testing.T) {
	for name, transport := range map[string]roundTripFunc{
		"cross origin pagination": func(*http.Request) *http.Response {
			return response(200, http.Header{"Link": {`<https://evil.test/next>; rel="next"`}}, `{"tags":[]}`)
		},
		"bad status": func(*http.Request) *http.Response { return response(500, nil, "") },
		"unsupported auth": func(*http.Request) *http.Response {
			return response(401, http.Header{"Www-Authenticate": {"Basic realm=x"}}, "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(&http.Client{Transport: transport}).Tags(context.Background(), "registry.test/team/tool")
			require.Error(t, err)
		})
	}
	manifest := `{"schemaVersion":2}`
	bad := "sha256:" + strings.Repeat("b", 64)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) *http.Response {
		return response(200, http.Header{"Content-Type": {"application/vnd.oci.image.manifest.v1+json"}, "Docker-Content-Digest": {bad}}, manifest)
	})}
	_, err := New(client).Digest(context.Background(), "registry.test/team/tool:v1", "linux/amd64")
	require.Error(t, err)
}

func TestRegistrySingleManifestAndMissingPlatform(t *testing.T) {
	manifest := `{"schemaVersion":2}`
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) *http.Response {
		return response(200, http.Header{"Content-Type": {"application/vnd.oci.image.manifest.v1+json"}}, manifest)
	})}
	got, err := New(client).Digest(context.Background(), "registry.test/team/tool:v1", "linux/arm64")
	require.NoError(t, err)
	require.Equal(t, contentDigest([]byte(manifest)), got)
	indexClient := &http.Client{Transport: roundTripFunc(func(*http.Request) *http.Response {
		return response(200, http.Header{"Content-Type": {"application/vnd.oci.image.index.v1+json"}}, `{"manifests":[]}`)
	})}
	_, err = New(indexClient).Digest(context.Background(), "registry.test/team/tool:v1", "linux/arm64")
	require.Error(t, err)
}

func TestParseRepositoryMapsDockerHubNamespaceToRegistry(t *testing.T) {
	host, path, err := parseRepository("docker.io/library/python")
	require.NoError(t, err)
	require.Equal(t, "registry-1.docker.io", host, "docker.io must resolve to Docker Hub's registry API endpoint")
	require.Equal(t, "library/python", path)

	host, _, err = parseRepository("ghcr.io/owner/tool")
	require.NoError(t, err)
	require.Equal(t, "ghcr.io", host, "other registries pass through unchanged")
}
