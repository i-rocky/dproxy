package project

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const configName = ".dproxy.toml"

var ErrNotFound = errors.New("dproxy project not found")

type Project struct {
	Root            string
	RelativeWorkdir string
	ID              string
}

func Find(start string) (Project, error) {
	workdir, err := filepath.Abs(start)
	if err != nil {
		return Project{}, fmt.Errorf("resolve start directory: %w", err)
	}
	workdir = filepath.Clean(workdir)
	for dir := workdir; ; dir = filepath.Dir(dir) {
		info, statErr := os.Lstat(filepath.Join(dir, configName))
		if statErr == nil {
			if info.Mode()&fs.ModeSymlink != 0 {
				return Project{}, errors.New("project configuration must not be a symlink")
			}
			return loadProject(dir, workdir)
		}
		if !errors.Is(statErr, fs.ErrNotExist) {
			return Project{}, fmt.Errorf("inspect project configuration: %w", statErr)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return Project{}, ErrNotFound
		}
	}
}

func loadProject(root, workdir string) (Project, error) {
	rel, err := filepath.Rel(root, workdir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return Project{}, errors.New("working directory is outside project root")
	}
	id, err := loadOrCreateID(root)
	if err != nil {
		return Project{}, err
	}
	return Project{Root: root, RelativeWorkdir: filepath.ToSlash(rel), ID: id}, nil
}

func loadOrCreateID(root string) (string, error) {
	dir := filepath.Join(root, ".dproxy")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("create project metadata directory: %w", err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("inspect project metadata directory: %w", err)
	}
	if dirInfo.Mode()&fs.ModeSymlink != 0 || !dirInfo.IsDir() {
		return "", errors.New("project metadata directory must be a real directory")
	}
	path := filepath.Join(dir, "id")
	for {
		info, err := os.Lstat(path)
		if err == nil {
			if info.Mode()&fs.ModeSymlink != 0 {
				return "", errors.New("project identity must not be a symlink")
			}
			if !info.Mode().IsRegular() {
				return "", errors.New("project identity must be a regular file")
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return "", fmt.Errorf("read project identity: %w", readErr)
			}
			id := strings.TrimSpace(string(data))
			if len(id) != 32 {
				return "", errors.New("project identity has invalid length")
			}
			if _, err := hex.DecodeString(id); err != nil {
				return "", errors.New("project identity has invalid encoding")
			}
			return id, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("inspect project identity: %w", err)
		}
		idBytes := make([]byte, 16)
		if _, err := rand.Read(idBytes); err != nil {
			return "", errors.New("generate project identity")
		}
		id := hex.EncodeToString(idBytes)
		tmp, err := os.CreateTemp(dir, "id-*")
		if err != nil {
			return "", fmt.Errorf("create project identity: %w", err)
		}
		tmpPath := tmp.Name()
		if err := tmp.Chmod(0600); err == nil {
			_, err = fmt.Fprintln(tmp, id)
		}
		if closeErr := tmp.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Link(tmpPath, path)
		}
		_ = os.Remove(tmpPath)
		if err == nil {
			return id, nil
		}
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return "", fmt.Errorf("publish project identity: %w", err)
	}
}
