package lock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Tool struct {
	Requested string `json:"requested"`
	Version   string `json:"version"`
	Image     string `json:"image"`
	Tag       string `json:"tag"`
	Digest    string `json:"digest"`
	Platform  string `json:"platform"`
}
type Plugin struct {
	Repository     string `json:"repository"`
	Commit         string `json:"commit"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Schema         int    `json:"schema"`
}
type File struct {
	Schema       int               `json:"schema"`
	ConfigSHA256 string            `json:"config_sha256"`
	Plugins      map[string]Plugin `json:"plugins"`
	Tools        map[string]Tool   `json:"tools"`
}

var (
	shaPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionPattern  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	platformPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
)

func HashConfig(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func (f File) Verify(configSHA256, platform string) error {
	if f.Schema != 1 || !shaPattern.MatchString(f.ConfigSHA256) || f.ConfigSHA256 != configSHA256 || !platformPattern.MatchString(platform) {
		return errors.New("lock metadata is invalid or stale")
	}
	if len(f.Tools) == 0 {
		return errors.New("lock has no tools")
	}
	for name, tool := range f.Tools {
		if name == "" || tool.Requested == "" || !versionPattern.MatchString(tool.Version) || tool.Image == "" || tool.Tag == "" || !digestPattern.MatchString(tool.Digest) || tool.Platform != platform {
			return fmt.Errorf("locked tool %q is invalid", name)
		}
	}
	for name, p := range f.Plugins {
		if name == "" || p.Repository == "" || p.Commit == "" || p.Schema != 1 || !shaPattern.MatchString(p.ManifestSHA256) {
			return fmt.Errorf("locked plugin %q is invalid", name)
		}
	}
	return nil
}

func (f File) Canonical() ([]byte, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("serialize lock: %w", err)
	}
	return append(data, '\n'), nil
}

func Load(path string) (File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return File{}, fmt.Errorf("inspect lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		return File{}, errors.New("lock must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return File{}, fmt.Errorf("open lock: %w", err)
	}
	defer file.Close()
	var result File
	dec := json.NewDecoder(io.LimitReader(file, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return File{}, errors.New("decode lock")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return File{}, errors.New("lock contains trailing data")
	}
	return result, nil
}

func WriteAtomic(path string, f File) error {
	data, err := f.Canonical()
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) {
		return errors.New("invalid lock path")
	}
	tmp, err := os.CreateTemp(parent, "."+base+"-*")
	if err != nil {
		return fmt.Errorf("create temporary lock: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	defer cleanup()
	if err = tmp.Chmod(0600); err == nil {
		_, err = io.Copy(tmp, bytes.NewReader(data))
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("write temporary lock")
	}
	if info, statErr := os.Lstat(path); statErr == nil && !info.Mode().IsRegular() {
		return errors.New("lock target must be a regular file")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect lock target: %w", statErr)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace lock: %w", err)
	}
	dir, err := os.Open(parent)
	if err != nil {
		return fmt.Errorf("open lock directory: %w", err)
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("sync lock directory: %w", err)
	}
	return nil
}

func ValidDigest(value string) bool { return digestPattern.MatchString(value) }

func ValidExactVersion(value string) bool {
	return versionPattern.MatchString(strings.TrimSpace(value))
}
