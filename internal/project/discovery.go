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
	return find(start, true)
}

// FindReadOnly discovers an initialized project without creating its identity.
func FindReadOnly(start string) (Project, error) {
	return find(start, false)
}

// FindOrGlobal discovers a project by walking up from start. If no project is
// found it returns a synthetic global project rooted at start whose stable
// identity lives under globalDir, so tools run outside any project still get a
// sandboxed, auto-locked execution path instead of a hard failure.
func FindOrGlobal(start, globalDir string) (Project, error) {
	p, err := Find(start)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Project{}, err
	}
	return globalProject(start, globalDir)
}

// globalProject materializes the global default project: the current directory
// becomes /workspace and a stable identity is loaded or created under globalDir.
func globalProject(start, globalDir string) (Project, error) {
	root, err := filepath.Abs(start)
	if err != nil {
		return Project{}, fmt.Errorf("resolve global project root: %w", err)
	}
	if err := os.MkdirAll(globalDir, 0700); err != nil {
		return Project{}, fmt.Errorf("create global project state: %w", err)
	}
	fd, err := unix.Open(filepath.Clean(globalDir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Project{}, fmt.Errorf("open global project state: %w", err)
	}
	defer unix.Close(fd)
	id, err := loadOrCreateIDAt(fd)
	if err != nil {
		return Project{}, err
	}
	return Project{Root: root, RelativeWorkdir: ".", ID: id}, nil
}

func find(start string, createIdentity bool) (Project, error) {
	startPath, err := filepath.Abs(start)
	if err != nil {
		return Project{}, fmt.Errorf("resolve start directory: %w", err)
	}
	currentFD, err := unix.Open(filepath.Clean(startPath), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return Project{}, fmt.Errorf("open start directory: %w", err)
	}
	defer func() { _ = unix.Close(currentFD) }()
	workdir, err := descriptorPath(currentFD)
	if err != nil {
		return Project{}, err
	}
	for {
		configFD, configErr := unix.Openat(currentFD, configName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if configErr == nil {
			var stat unix.Stat_t
			statErr := unix.Fstat(configFD, &stat)
			_ = unix.Close(configFD)
			if statErr != nil {
				return Project{}, fmt.Errorf("inspect project configuration: %w", statErr)
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFREG {
				return Project{}, errors.New("project configuration must be a regular file")
			}
			root, pathErr := descriptorPath(currentFD)
			if pathErr != nil {
				return Project{}, pathErr
			}
			return loadProjectAtMode(root, workdir, currentFD, createIdentity)
		}
		if configErr != unix.ENOENT {
			if configErr == unix.ELOOP {
				return Project{}, errors.New("project configuration must not be a symlink")
			}
			return Project{}, fmt.Errorf("inspect project configuration: %w", configErr)
		}
		parentFD, openErr := unix.Openat(currentFD, "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return Project{}, fmt.Errorf("open parent directory: %w", openErr)
		}
		same, compareErr := sameDirectory(currentFD, parentFD)
		if compareErr != nil {
			_ = unix.Close(parentFD)
			return Project{}, compareErr
		}
		if same {
			_ = unix.Close(parentFD)
			return Project{}, ErrNotFound
		}
		_ = unix.Close(currentFD)
		currentFD = parentFD
	}
}

func descriptorPath(fd int) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return "", fmt.Errorf("resolve directory descriptor: %w", err)
	}
	if !filepath.IsAbs(path) || strings.HasSuffix(path, " (deleted)") {
		return "", errors.New("directory moved during project discovery")
	}
	return filepath.Clean(path), nil
}

func sameDirectory(leftFD, rightFD int) (bool, error) {
	var left, right unix.Stat_t
	if err := unix.Fstat(leftFD, &left); err != nil {
		return false, fmt.Errorf("inspect current directory: %w", err)
	}
	if err := unix.Fstat(rightFD, &right); err != nil {
		return false, fmt.Errorf("inspect parent directory: %w", err)
	}
	return left.Dev == right.Dev && left.Ino == right.Ino, nil
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
	return loadProjectAtMode(root, workdir, rootFD, true)
}

func loadProjectAtMode(root, workdir string, rootFD int, createIdentity bool) (Project, error) {
	rel, err := filepath.Rel(root, workdir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return Project{}, errors.New("working directory is outside project root")
	}
	var id string
	if createIdentity {
		id, err = loadOrCreateID(rootFD)
	} else {
		metadataFD, openErr := unix.Openat(rootFD, ".dproxy", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return Project{}, errors.New("project identity is not initialized; run dproxy init")
		}
		id, err = readIDAt(metadataFD)
		unix.Close(metadataFD)
	}
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
