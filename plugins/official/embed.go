package official

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"dproxy/internal/plugin"
)

// Set by release ldflags. Development builds intentionally have no synthetic
// provenance and must use an explicitly added plugin repository.
var OfficialRepository, Commit string

//go:embed *.toml
var manifests embed.FS

var commitPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

func Load() (map[string]plugin.Manifest, error) {
	parsed, err := url.Parse(OfficialRepository)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !commitPattern.MatchString(Commit) {
		return nil, errors.New("official plugins lack immutable release metadata; run dproxy plugin add --trust <https-repository> or install a release build")
	}
	entries, err := manifests.ReadDir(".")
	if err != nil {
		return nil, err
	}
	result := map[string]plugin.Manifest{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		raw, err := manifests.ReadFile(entry.Name())
		if err != nil {
			return nil, err
		}
		manifest, err := plugin.LoadManifest(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		manifest.Provenance = plugin.Provenance{Repository: OfficialRepository, Commit: Commit, ManifestSHA256: hex.EncodeToString(sum[:]), Schema: manifest.Schema}
		for _, binary := range manifest.Bins {
			if _, exists := result[binary]; exists {
				return nil, errors.New("ambiguous bundled official provider")
			}
			result[binary] = manifest
		}
	}
	return result, nil
}

// Binaries enumerates the binary names provided by the bundled official
// manifests without requiring release provenance. Shims only point at the
// dproxy binary; provenance is enforced when a tool is resolved and locked, so
// enumeration for shim installation is safe without immutable release metadata.
func Binaries() ([]string, error) {
	entries, err := manifests.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var bins []string
	seen := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		raw, err := manifests.ReadFile(entry.Name())
		if err != nil {
			return nil, err
		}
		manifest, err := plugin.LoadManifest(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		for _, binary := range manifest.Bins {
			if _, ok := seen[binary]; !ok {
				seen[binary] = struct{}{}
				bins = append(bins, binary)
			}
		}
	}
	return bins, nil
}
