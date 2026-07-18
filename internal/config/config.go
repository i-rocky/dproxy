package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

var ErrSchema = errors.New("unsupported configuration schema")

type Config struct {
	Schema  int               `toml:"schema"`
	Tools   map[string]string `toml:"tools"`
	Sandbox Sandbox           `toml:"sandbox"`
}

type Sandbox struct {
	Network          string            `toml:"network"`
	NetworkAllowlist []string          `toml:"network_allowlist"`
	Memory           string            `toml:"memory"`
	CPUs             int               `toml:"cpus"`
	PIDs             int               `toml:"pids"`
	Ports            map[string]int    `toml:"ports"`
	Environment      map[string]string `toml:"environment"`
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	var c Config
	dec := toml.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		var unknown *toml.StrictMissingError
		if errors.As(err, &unknown) {
			return Config{}, fmt.Errorf("decode configuration: unknown field: %w", err)
		}
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	if c.Schema != 1 {
		return Config{}, ErrSchema
	}
	return c, validate(c)
}

func validate(c Config) error {
	if c.Sandbox.Network != "" && c.Sandbox.Network != "none" && c.Sandbox.Network != "public" && c.Sandbox.Network != "allowlist" {
		return errors.New("invalid sandbox network policy")
	}
	return nil
}
