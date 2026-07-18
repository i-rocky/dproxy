package project

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
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
		rootFD, openErr := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return Project{}, fmt.Errorf("open project candidate: %w", openErr)
		}
		configFD, configErr := unix.Openat(rootFD, configName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if configErr == nil {
			var stat unix.Stat_t
			statErr := unix.Fstat(configFD, &stat)
			_ = unix.Close(configFD)
			if statErr != nil {
				_ = unix.Close(rootFD)
				return Project{}, fmt.Errorf("inspect project configuration: %w", statErr)
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFREG {
				_ = unix.Close(rootFD)
				return Project{}, errors.New("project configuration must be a regular file")
			}
			project, loadErr := loadProjectAt(dir, workdir, rootFD)
			_ = unix.Close(rootFD)
			return project, loadErr
		}
		_ = unix.Close(rootFD)
		if configErr != unix.ENOENT {
			if configErr == unix.ELOOP {
				return Project{}, errors.New("project configuration must not be a symlink")
			}
			return Project{}, fmt.Errorf("inspect project configuration: %w", configErr)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return Project{}, ErrNotFound
		}
	}
}

func loadProject(root, workdir string) (Project, error) {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Project{}, fmt.Errorf("open project root: %w", err)
	}
	defer unix.Close(rootFD)
	return loadProjectAt(root, workdir, rootFD)
}

func loadProjectAt(root, workdir string, rootFD int) (Project, error) {
	rel, err := filepath.Rel(root, workdir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return Project{}, errors.New("working directory is outside project root")
	}
	id, err := loadOrCreateID(rootFD)
	if err != nil {
		return Project{}, err
	}
	return Project{Root: root, RelativeWorkdir: filepath.ToSlash(rel), ID: id}, nil
}

func loadOrCreateID(rootFD int) (string, error) {
	if err := unix.Mkdirat(rootFD, ".dproxy", 0700); err != nil && err != unix.EEXIST {
		return "", fmt.Errorf("create project metadata directory: %w", err)
	}
	metadataFD, err := unix.Openat(rootFD, ".dproxy", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", errors.New("project metadata directory must be a real directory")
	}
	defer unix.Close(metadataFD)
	return loadOrCreateIDAt(metadataFD)
}

func loadOrCreateIDAt(metadataFD int) (string, error) {
	for {
		id, err := readIDAt(metadataFD)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		id, err = createIDAt(metadataFD)
		if err == nil {
			return id, nil
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return "", err
	}
}

func readIDAt(metadataFD int) (string, error) {
	fd, err := unix.Openat(metadataFD, "id", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if err == unix.ENOENT {
			return "", os.ErrNotExist
		}
		if err == unix.ELOOP {
			return "", errors.New("project identity must not be a symlink")
		}
		return "", fmt.Errorf("open project identity: %w", err)
	}
	file := os.NewFile(uintptr(fd), "project identity")
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return "", fmt.Errorf("inspect project identity: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", errors.New("project identity must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 35))
	if err != nil {
		return "", fmt.Errorf("read project identity: %w", err)
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

func createIDAt(metadataFD int) (string, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", errors.New("generate project identity")
	}
	id := hex.EncodeToString(idBytes)
	tmpName := ".id-" + id
	fd, err := unix.Openat(metadataFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return "", fmt.Errorf("create temporary project identity: %w", err)
	}
	file := os.NewFile(uintptr(fd), "temporary project identity")
	_, writeErr := io.WriteString(file, id+"\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = unix.Unlinkat(metadataFD, tmpName, 0)
		return "", errors.New("write project identity")
	}
	linkErr := unix.Linkat(metadataFD, tmpName, metadataFD, "id", 0)
	_ = unix.Unlinkat(metadataFD, tmpName, 0)
	if linkErr != nil {
		if linkErr == unix.EEXIST {
			return "", os.ErrExist
		}
		return "", fmt.Errorf("publish project identity: %w", linkErr)
	}
	return id, nil
}
