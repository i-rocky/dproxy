package resolver

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"dproxy/internal/config"
	"dproxy/internal/lock"
	"dproxy/internal/plugin"
	"github.com/Masterminds/semver/v3"
)

type Registry interface {
	Tags(context.Context, string) ([]string, error)
	Digest(context.Context, string, string) (string, error)
}

func Resolve(ctx context.Context, cfg config.Config, manifests map[string]plugin.Manifest, platform, configSHA256 string, registry Registry) (lock.File, error) {
	result := lock.File{Schema: 1, ConfigSHA256: configSHA256, Tools: make(map[string]lock.Tool), Plugins: make(map[string]lock.Plugin)}
	names := make([]string, 0, len(cfg.Tools))
	for name := range cfg.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		requested := cfg.Tools[name]
		manifest, ok := manifests[name]
		if !ok {
			return lock.File{}, fmt.Errorf("no manifest for tool %q", name)
		}
		if !supports(manifest, platform) {
			return lock.File{}, fmt.Errorf("tool %q does not support platform", name)
		}
		image, ok := manifest.Images["default"]
		if !ok {
			return lock.File{}, fmt.Errorf("tool %q has no default image", name)
		}
		matcher, err := semver.NewConstraint(normalizeConstraint(requested))
		if err != nil {
			return lock.File{}, fmt.Errorf("invalid constraint for %q", name)
		}
		tags, err := registry.Tags(ctx, image.Repository)
		if err != nil {
			return lock.File{}, fmt.Errorf("list tags for %q: %w", name, err)
		}
		versions := make([]*semver.Version, 0, len(tags))
		for _, tag := range tags {
			v, parseErr := semver.StrictNewVersion(tag)
			if parseErr == nil && v.Prerelease() == "" && matcher.Check(v) {
				versions = append(versions, v)
			}
		}
		if len(versions) == 0 {
			return lock.File{}, fmt.Errorf("no version satisfies %q", requested)
		}
		sort.Slice(versions, func(i, j int) bool { return versions[i].GreaterThan(versions[j]) })
		selected := versions[0]
		tag := strings.Replace(image.TagTemplate, "{version}", selected.String(), 1)
		digest, err := registry.Digest(ctx, image.Repository+":"+tag, platform)
		if err != nil {
			return lock.File{}, fmt.Errorf("resolve digest for %q: %w", name, err)
		}
		if !lock.ValidDigest(digest) {
			return lock.File{}, errors.New("registry returned invalid image digest")
		}
		result.Tools[name] = lock.Tool{Requested: requested, Version: selected.String(), Image: image.Repository, Tag: tag, Digest: digest, Platform: platform}
	}
	return result, nil
}

func supports(m plugin.Manifest, p string) bool {
	parts := strings.Split(p, "/")
	if len(parts) != 2 {
		return false
	}
	for _, v := range m.Platforms {
		if v.OS == parts[0] && v.Arch == parts[1] {
			return true
		}
	}
	return false
}

func normalizeConstraint(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if strings.ContainsAny(trimmed, "<>=!~^*,| ") {
		return trimmed
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) == 1 {
		if n, err := strconv.ParseUint(parts[0], 10, 64); err == nil && n < ^uint64(0) {
			return fmt.Sprintf(">=%d.0.0, <%d.0.0", n, n+1)
		}
	}
	if len(parts) == 2 {
		major, e1 := strconv.ParseUint(parts[0], 10, 64)
		minor, e2 := strconv.ParseUint(parts[1], 10, 64)
		if e1 == nil && e2 == nil && minor < ^uint64(0) {
			return fmt.Sprintf(">=%d.%d.0, <%d.%d.0", major, minor, major, minor+1)
		}
	}
	return trimmed
}
