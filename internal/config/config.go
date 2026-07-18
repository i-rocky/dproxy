package config

import (
	"bytes"
	"errors"
	"os"

	"dproxy/internal/fault"
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
		return Config{}, fault.New("load configuration", "read failed", err)
	}
	var c Config
	dec := toml.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		var unknown *toml.StrictMissingError
		if errors.As(err, &unknown) {
			return Config{}, fault.New("load configuration", "unknown field", err)
		}
		return Config{}, fault.New("load configuration", "malformed TOML", err)
	}
	if c.Schema != 1 {
		return Config{}, fault.New("load configuration", "unsupported schema", ErrSchema)
	}
	return c, validate(c)
}

func validate(c Config) error {
	if c.Sandbox.Network != "" && c.Sandbox.Network != "none" && c.Sandbox.Network != "public" && c.Sandbox.Network != "allowlist" {
		return fault.New("validate configuration", "invalid sandbox network policy", nil)
	}
	return nil
}
