package plugin

import (
	"errors"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"dproxy/internal/fault"
	"github.com/pelletier/go-toml/v2"
)

var ErrManifest = errors.New("invalid plugin manifest")

type Manifest struct {
	Schema      int                 `toml:"schema"`
	Name        string              `toml:"name"`
	Bins        []string            `toml:"bins"`
	Images      map[string]Image    `toml:"images"`
	Commands    map[string][]string `toml:"commands"`
	Caches      []Cache             `toml:"caches"`
	Environment map[string]string   `toml:"environment"`
	Platforms   []Platform          `toml:"platforms"`
	Provenance  Provenance          `toml:"-"`
}

type Provenance struct {
	Repository, Commit, ManifestSHA256 string
	Schema                             int
}

type Image struct {
	Repository  string `toml:"repository"`
	TagTemplate string `toml:"tag_template"`
}

type Cache struct {
	Path          string `toml:"path"`
	Compatibility string `toml:"compatibility"`
}

type Platform struct {
	OS   string `toml:"os"`
	Arch string `toml:"arch"`
}

func LoadManifest(r io.Reader) (Manifest, error) {
	var manifest Manifest
	decoder := toml.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fault.New("load plugin manifest", "malformed or unknown field", ErrManifest)
	}
	if err := Validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manifest) Command(binary string) ([]string, bool) {
	command, ok := m.Commands[binary]
	if !ok {
		return nil, false
	}
	return append([]string(nil), command...), true
}

func Validate(m Manifest) error {
	fail := func(kind string) error { return fault.New("validate plugin manifest", kind, ErrManifest) }
	if m.Schema != 1 || !pluginNamePattern.MatchString(m.Name) {
		return fail("invalid identity")
	}
	seen := make(map[string]struct{}, len(m.Bins))
	for _, binary := range m.Bins {
		if binary == "" || path.Base(binary) != binary || strings.ContainsAny(binary, `/\\`) {
			return fail("invalid binary")
		}
		if _, exists := seen[binary]; exists {
			return fail("duplicate binary")
		}
		seen[binary] = struct{}{}
		command, ok := m.Commands[binary]
		if !ok || len(command) == 0 || command[0] != binary {
			return fail("invalid command prefix")
		}
	}
	if len(m.Bins) == 0 || len(m.Commands) != len(m.Bins) {
		return fail("invalid commands")
	}
	for binary := range m.Commands {
		if _, ok := seen[binary]; !ok {
			return fail("command for undeclared binary")
		}
	}
	for _, command := range m.Commands {
		for _, element := range command {
			if element == "" || strings.IndexFunc(element, unicode.IsControl) >= 0 {
				return fail("invalid command element")
			}
		}
	}
	for _, image := range m.Images {
		if !validImageRepository(image.Repository) || !validTagTemplate(image.TagTemplate) {
			return fail("invalid image mapping")
		}
	}
	if len(m.Images) == 0 {
		return fail("missing image mapping")
	}
	cachePaths := make(map[string]struct{}, len(m.Caches))
	for _, cache := range m.Caches {
		if cache.Path == "" || !path.IsAbs(cache.Path) || path.Clean(cache.Path) != cache.Path || cache.Path == "/" {
			return fail("invalid cache path")
		}
		if _, exists := cachePaths[cache.Path]; exists {
			return fail("duplicate cache path")
		}
		cachePaths[cache.Path] = struct{}{}
	}
	for key, value := range m.Environment {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
			return fail("invalid fixed environment")
		}
	}
	for _, platform := range m.Platforms {
		if platform.OS == "" || platform.Arch == "" {
			return fail("invalid platform")
		}
	}
	return nil
}

var (
	imageRepositoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[1-9][0-9]{0,4})?/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	pluginNamePattern      = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	dockerTagPattern       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

func validImageRepository(repository string) bool {
	if !imageRepositoryPattern.MatchString(repository) {
		return false
	}
	registry := strings.SplitN(repository, "/", 2)[0]
	if colon := strings.LastIndexByte(registry, ':'); colon >= 0 {
		port := registry[colon+1:]
		n, err := strconv.Atoi(port)
		return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == port
	}
	return true
}

func validTagTemplate(template string) bool {
	if strings.Count(template, "{version}") != 1 || strings.ContainsAny(strings.Replace(template, "{version}", "", 1), "{}") {
		return false
	}
	for _, version := range []string{"1.2.3", strings.Repeat("9", 64)} {
		if !dockerTagPattern.MatchString(strings.Replace(template, "{version}", version, 1)) {
			return false
		}
	}
	return true
}
