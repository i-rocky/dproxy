package official

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/i-rocky/dproxy/internal/plugin"
)

// OfficialRepository and Commit pin the source of the bundled official plugins.
// They may be set by release ldflags; otherwise deriveOfficialProvenance fills
// them from Go's build info so a plain `go install ...@latest` build carries
// verifiable provenance without ldflags.
var OfficialRepository, Commit string

//go:embed *.toml
var manifests embed.FS

// commitPattern accepts Git commit identifiers: full sha1/sha256 hashes (40/64
// hex) and the short-SHA form Go records in a module pseudo-version (12 hex,
// Git's modern short length). External trusted repos always pin the full hash;
// the 12-hex form is only used for bundled plugins in a plain go-install build.
var commitPattern = regexp.MustCompile(`^(?:[0-9a-f]{12}|[0-9a-f]{40}|[0-9a-f]{64})$`)

func init() {
	deriveOfficialProvenance()
}

// deriveOfficialProvenance populates OfficialRepository and Commit from the
// build info when ldflags did not set them. A local VCS build exposes the full
// vcs.revision; a plain `go install module@version` build exposes only the
// module path and a pseudo-version, whose 12-hex suffix is the commit.
func deriveOfficialProvenance() {
	if OfficialRepository != "" && Commit != "" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if OfficialRepository == "" {
		OfficialRepository = repositoryFromModule(info.Main.Path)
	}
	if Commit == "" {
		Commit = commitFromBuildInfo(info)
	}
}

func repositoryFromModule(path string) string {
	if path == "" {
		return ""
	}
	host := strings.SplitN(path, "/", 2)[0]
	if !strings.Contains(host, ".") {
		return "" // not a host-prefixed module path (e.g. a local replace)
	}
	repo := "https://" + path
	parsed, err := url.Parse(repo)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return repo
}

func commitFromBuildInfo(info *debug.BuildInfo) string {
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && commitPattern.MatchString(s.Value) {
			return s.Value
		}
	}
	return commitFromPseudoVersion(info.Main.Version)
}

var pseudoVersionPattern = regexp.MustCompile(`^v\d+\.\d+\.\d+-\d{14}-([0-9a-f]{12})$`)

func commitFromPseudoVersion(version string) string {
	if m := pseudoVersionPattern.FindStringSubmatch(version); len(m) == 2 {
		return m[1]
	}
	return ""
}

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
