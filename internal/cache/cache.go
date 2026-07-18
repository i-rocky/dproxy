package cache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"golang.org/x/sys/unix"
)

const ownerFile = ".dproxy-cache-owner"

var (
	ErrUnsafeKey = errors.New("unsafe cache key")
	ErrNotOwned  = errors.New("cache is not owned by dproxy")
	keyPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

type Manager struct{ Root string }

func (m Manager) Path(projectID, pluginName, tool, compatibility, platform string) (string, error) {
	keys, err := cacheKeys(projectID, pluginName, tool, compatibility, platform)
	if err != nil {
		return "", err
	}
	rootFD, err := m.openRoot(true)
	if err != nil {
		return "", err
	}
	defer unix.Close(rootFD)
	fd := rootFD
	for _, key := range keys {
		created := false
		if err := unix.Mkdirat(fd, key, 0700); err == nil {
			created = true
		} else if err != unix.EEXIST {
			return "", fmt.Errorf("create cache: %w", err)
		}
		next, err := openBeneath(fd, key)
		if err != nil {
			return "", fmt.Errorf("open cache: %w", err)
		}
		if fd != rootFD {
			unix.Close(fd)
		}
		fd = next
		var ownerErr error
		if created {
			ownerErr = createOwner(fd)
		} else {
			ownerErr = verifyOwner(fd)
		}
		if ownerErr != nil {
			unix.Close(fd)
			return "", ownerErr
		}
	}
	unix.Close(fd)
	return filepath.Join(append([]string{filepath.Clean(m.Root)}, keys...)...), nil
}

func (m Manager) Clean(projectID, pluginName, tool, compatibility, platform string) error {
	keys, err := cacheKeys(projectID, pluginName, tool, compatibility, platform)
	if err != nil {
		return err
	}
	rootFD, err := m.openRoot(false)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	parentFD, err := walk(rootFD, keys[:len(keys)-1])
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	return removeOwnedAt(parentFD, keys[len(keys)-1])
}

func (m Manager) Prune(keep map[string]struct{}) error {
	rootFD, err := m.openRoot(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	dupFD, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dupFD), "cache root")
	if f == nil {
		return errors.New("duplicate cache root descriptor")
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		if name == ownerFile {
			continue
		}
		if _, ok := keep[name]; ok {
			continue
		}
		if !keyPattern.MatchString(name) {
			return ErrUnsafeKey
		}
		if err := removeOwnedAt(rootFD, name); err != nil {
			return err
		}
	}
	return nil
}

func cacheKeys(keys ...string) ([]string, error) {
	for _, key := range keys {
		if !keyPattern.MatchString(key) || key == "." || key == ".." {
			return nil, ErrUnsafeKey
		}
	}
	return keys, nil
}

func (m Manager) openRoot(create bool) (int, error) {
	root := filepath.Clean(m.Root)
	if m.Root == "" || !filepath.IsAbs(root) || root == string(filepath.Separator) {
		return -1, ErrUnsafeKey
	}
	created := false
	if create {
		if err := os.Mkdir(root, 0700); err == nil {
			created = true
		} else if !errors.Is(err, os.ErrExist) {
			return -1, err
		}
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == unix.ENOENT {
		return -1, os.ErrNotExist
	}
	if err != nil {
		return -1, err
	}
	var ownerErr error
	if created {
		ownerErr = createOwner(fd)
	} else {
		ownerErr = verifyOwner(fd)
	}
	if ownerErr != nil {
		unix.Close(fd)
		return -1, ownerErr
	}
	return fd, nil
}

func openBeneath(dirFD int, name string) (int, error) {
	return unix.Openat2(dirFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
}

func walk(rootFD int, keys []string) (int, error) {
	fd, err := unix.Dup(rootFD)
	if err != nil {
		return -1, err
	}
	for _, key := range keys {
		next, err := openBeneath(fd, key)
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

func createOwner(dirFD int) error {
	fd, err := unix.Openat(dirFD, ownerFile, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		unix.Close(fd)
		return err
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	return unix.Fsync(dirFD)
}

func verifyOwner(dirFD int) error {
	fd, err := unix.Openat(dirFD, ownerFile, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrNotOwned
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Getuid() {
		return ErrNotOwned
	}
	return nil
}

func removeOwnedAt(parentFD int, name string) error {
	fd, err := openBeneath(parentFD, name)
	if err != nil {
		return fmt.Errorf("securely open cache for removal: %w", err)
	}
	defer unix.Close(fd)
	if err := verifyOwner(fd); err != nil {
		return err
	}
	dupFD, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dupFD), "owned cache")
	entries, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == ownerFile {
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			if err := removeOwnedAt(fd, name); err != nil {
				return err
			}
		} else if err := unix.Unlinkat(fd, name, 0); err != nil {
			return err
		}
	}
	if err := unix.Unlinkat(fd, ownerFile, 0); err != nil {
		return err
	}
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return nil
}
