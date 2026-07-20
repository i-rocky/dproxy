package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type UserConfig struct {
	Schema             int      `toml:"schema"`
	EngineEndpoint     string   `toml:"engine_endpoint,omitempty"`
	GatewayImage       string   `toml:"gateway_image"`
	PluginRepositories []string `toml:"plugin_repositories,omitempty"`
}

// gatewayPattern accepts either a registry digest reference
// (host[:port]/path@sha256:...) or a bare local image ID (sha256:...). The
// registry form is the production path (a published gateway); the local-ID form
// lets a from-source build pin a locally-built gateway without a registry. The
// run path (engine + orchestrator) already treats a sha256: ID as a local image.
var gatewayPattern = regexp.MustCompile(`^(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[1-9][0-9]{0,4})?/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64})$`)

func (c *Config) SetTool(name, constraint string) error {
	if !safeTool(name) || strings.TrimSpace(constraint) == "" {
		return errors.New("invalid tool declaration")
	}
	if c.Tools == nil {
		c.Tools = make(map[string]string)
	}
	c.Tools[name] = constraint
	return nil
}
func (c *Config) RemoveTool(name string) error {
	if !safeTool(name) {
		return errors.New("invalid tool name")
	}
	if _, ok := c.Tools[name]; !ok {
		return errors.New("tool not configured")
	}
	delete(c.Tools, name)
	return nil
}
func safeTool(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return false
		}
	}
	return true
}

func WriteAtomic(path string, c Config) error {
	if c.Schema != 1 {
		return ErrSchema
	}
	if err := validate(c); err != nil {
		return err
	}
	return marshalAtomic(path, c)
}

func LoadUser(path string) (UserConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return UserConfig{}, fmt.Errorf("read user configuration: %w", err)
	}
	var result UserConfig
	decoder := toml.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return UserConfig{}, errors.New("invalid user configuration")
	}
	if err := validateUser(result); err != nil {
		return UserConfig{}, err
	}
	return result, nil
}
func WriteUserAtomic(path string, c UserConfig) error {
	if err := validateUser(c); err != nil {
		return err
	}
	return marshalAtomic(path, c)
}
func validateUser(c UserConfig) error {
	if c.Schema != 1 || !gatewayPattern.MatchString(c.GatewayImage) {
		return errors.New("user configuration requires a digest-pinned gateway image")
	}
	for _, repository := range c.PluginRepositories {
		if !strings.HasPrefix(repository, "https://") || strings.ContainsAny(repository, "?#@") {
			return errors.New("plugin repository must use canonical HTTPS")
		}
	}
	if strings.ContainsAny(c.EngineEndpoint, "\r\n\x00") {
		return errors.New("invalid engine endpoint")
	}
	return nil
}
func marshalAtomic(path string, value any) error {
	raw, err := toml.Marshal(value)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".dproxy-config-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(raw)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write configuration: %w", err)
	}
	if info, statErr := os.Lstat(path); statErr == nil && !info.Mode().IsRegular() {
		return errors.New("configuration target must be a regular file")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
