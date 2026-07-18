package plugin

import (
	"errors"
	"io"
	"path"
	"strings"

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
}

type Image struct {
	Repository string `toml:"repository"`
	Tag        string `toml:"tag"`
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
	if err := validateManifest(manifest); err != nil {
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

func validateManifest(m Manifest) error {
	fail := func(kind string) error { return fault.New("validate plugin manifest", kind, ErrManifest) }
	if m.Schema != 1 || m.Name == "" || path.Base(m.Name) != m.Name {
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
	for _, image := range m.Images {
		if image.Repository == "" || image.Tag == "" {
			return fail("invalid image mapping")
		}
	}
	if len(m.Images) == 0 {
		return fail("missing image mapping")
	}
	for _, cache := range m.Caches {
		if cache.Path == "" || !path.IsAbs(cache.Path) || path.Clean(cache.Path) != cache.Path || cache.Path == "/" {
			return fail("invalid cache path")
		}
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
