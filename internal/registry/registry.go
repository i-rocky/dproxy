package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxResponse = 4 << 20

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Registry struct{ client *http.Client }

func New(client *http.Client) *Registry {
	if client == nil {
		client = &http.Client{}
	}
	copy := *client
	if copy.Timeout == 0 {
		copy.Timeout = 20 * time.Second
	}
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Registry{client: &copy}
}

func (r *Registry) Tags(ctx context.Context, repository string) ([]string, error) {
	host, path, err := parseRepository(repository)
	if err != nil {
		return nil, err
	}
	next := &url.URL{Scheme: "https", Host: host, Path: "/v2/" + path + "/tags/list"}
	var result []string
	for page := 0; next != nil && page < 100; page++ {
		resp, err := r.get(ctx, next, "application/json")
		if err != nil {
			return nil, err
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		err = decode(resp, &body)
		if err != nil {
			return nil, err
		}
		result = append(result, body.Tags...)
		next, err = nextLink(next, resp.Header.Get("Link"))
		if err != nil {
			return nil, err
		}
	}
	if next != nil {
		return nil, errors.New("registry pagination limit exceeded")
	}
	return result, nil
}

func (r *Registry) Digest(ctx context.Context, reference, platform string) (string, error) {
	host, repository, tag, err := parseTagged(reference)
	if err != nil {
		return "", err
	}
	parts := strings.Split(platform, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("invalid platform")
	}
	manifestURL := &url.URL{Scheme: "https", Host: host, Path: "/v2/" + repository + "/manifests/" + tag}
	accept := strings.Join([]string{"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}, ", ")
	resp, err := r.get(ctx, manifestURL, accept)
	if err != nil {
		return "", err
	}
	body, mediaType, headerDigest, err := readManifest(resp)
	if err != nil {
		return "", err
	}
	if strings.Contains(mediaType, "index") || strings.Contains(mediaType, "manifest.list") {
		var index struct {
			Manifests []struct {
				Digest   string `json:"digest"`
				Platform struct {
					OS           string `json:"os"`
					Architecture string `json:"architecture"`
				} `json:"platform"`
			} `json:"manifests"`
		}
		if err := json.Unmarshal(body, &index); err != nil {
			return "", errors.New("invalid registry index")
		}
		selected := ""
		for _, descriptor := range index.Manifests {
			if descriptor.Platform.OS == parts[0] && descriptor.Platform.Architecture == parts[1] {
				if selected != "" {
					return "", errors.New("ambiguous platform manifest")
				}
				selected = descriptor.Digest
			}
		}
		if !digestPattern.MatchString(selected) {
			return "", errors.New("platform manifest not found")
		}
		manifestURL.Path = "/v2/" + repository + "/manifests/" + selected
		resp, err = r.get(ctx, manifestURL, accept)
		if err != nil {
			return "", err
		}
		body, _, headerDigest, err = readManifest(resp)
		if err != nil {
			return "", err
		}
		if headerDigest != "" && headerDigest != selected {
			return "", errors.New("registry digest mismatch")
		}
		if contentDigest(body) != selected {
			return "", errors.New("registry manifest content mismatch")
		}
		return selected, nil
	}
	computed := contentDigest(body)
	if headerDigest != "" && headerDigest != computed {
		return "", errors.New("registry digest mismatch")
	}
	return computed, nil
}

func (r *Registry) get(ctx context.Context, target *url.URL, accept string) (*http.Response, error) {
	resp, err := r.request(ctx, target, accept, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return validateResponse(resp, nil)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	realm, values, err := bearerChallenge(challenge)
	if err != nil {
		return nil, err
	}
	tokenURL, err := url.Parse(realm)
	if err != nil || tokenURL.Scheme != "https" {
		return nil, errors.New("invalid bearer token realm")
	}
	query := tokenURL.Query()
	for _, key := range []string{"service", "scope"} {
		if values[key] != "" {
			query.Set(key, values[key])
		}
	}
	tokenURL.RawQuery = query.Encode()
	tokenResp, err := r.request(ctx, tokenURL, "application/json", "")
	if err != nil {
		return nil, err
	}
	if tokenResp.StatusCode != http.StatusOK {
		tokenResp.Body.Close()
		return nil, fmt.Errorf("registry token status %d", tokenResp.StatusCode)
	}
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := decode(tokenResp, &token); err != nil {
		return nil, err
	}
	if token.Token == "" {
		token.Token = token.AccessToken
	}
	if token.Token == "" || strings.ContainsAny(token.Token, "\r\n") {
		return nil, errors.New("invalid registry bearer token")
	}
	return validateResponse(r.request(ctx, target, accept, "Bearer "+token.Token))
}

func (r *Registry) request(ctx context.Context, target *url.URL, accept, authorization string) (*http.Response, error) {
	if target.Scheme != "https" || target.User != nil {
		return nil, errors.New("registry transport must use HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return r.client.Do(req)
}

func validateResponse(resp *http.Response, err error) (*http.Response, error) {
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("registry status %d", resp.StatusCode)
	}
	return resp, nil
}
func decode(resp *http.Response, target any) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(body) > maxResponse {
		return errors.New("invalid registry JSON response")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid registry JSON response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("invalid trailing registry JSON")
	}
	return nil
}
func readManifest(resp *http.Response) ([]byte, string, string, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(body) > maxResponse {
		return nil, "", "", errors.New("invalid registry manifest response")
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	header := resp.Header.Get("Docker-Content-Digest")
	if header != "" && !digestPattern.MatchString(header) {
		return nil, "", "", errors.New("invalid registry digest header")
	}
	return body, mediaType, header, nil
}
func contentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func parseRepository(raw string) (string, string, error) {
	if strings.Contains(raw, "://") || strings.ContainsAny(raw, "?#@") {
		return "", "", errors.New("invalid repository")
	}
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[1], "..") {
		return "", "", errors.New("invalid repository")
	}
	host := parts[0]
	if host == "docker.io" {
		// "docker.io" is Docker Hub's canonical namespace; its registry API is
		// served by registry-1.docker.io. Hitting https://docker.io/v2/... 302-
		// redirects and the client does not follow redirects.
		host = "registry-1.docker.io"
	}
	return host, strings.Trim(parts[1], "/"), nil
}
func parseTagged(raw string) (string, string, string, error) {
	i := strings.LastIndex(raw, ":")
	if i <= strings.LastIndex(raw, "/") || i == len(raw)-1 {
		return "", "", "", errors.New("tagged image required")
	}
	host, repository, err := parseRepository(raw[:i])
	return host, repository, raw[i+1:], err
}
func nextLink(base *url.URL, raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	left, right := strings.Index(raw, "<"), strings.Index(raw, ">")
	if left < 0 || right <= left || !strings.Contains(raw[right:], `rel="next"`) {
		return nil, errors.New("invalid registry pagination link")
	}
	next, err := base.Parse(raw[left+1 : right])
	if err != nil || next.Scheme != "https" || next.Host != base.Host {
		return nil, errors.New("unsafe registry pagination link")
	}
	return next, nil
}
func bearerChallenge(raw string) (string, map[string]string, error) {
	if !strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		return "", nil, errors.New("unsupported registry authentication")
	}
	values := map[string]string{}
	for _, item := range strings.Split(raw[len("Bearer "):], ",") {
		pair := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(pair) != 2 {
			return "", nil, errors.New("invalid bearer challenge")
		}
		values[strings.ToLower(pair[0])] = strings.Trim(pair[1], `"`)
	}
	if values["realm"] == "" {
		return "", nil, errors.New("missing bearer realm")
	}
	return values["realm"], values, nil
}
