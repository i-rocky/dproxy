package cache

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const ownerFile = ".dproxy-cache-owner"
const trashName = ".dproxy-trash"

var (
	ErrUnsafeKey     = errors.New("unsafe cache key")
	ErrNotOwned      = errors.New("cache is not owned by dproxy")
	keyPattern       = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	beforeDelete     func(int, string)         // test-only fault/race injection
	beforeDirPublish func(int, string, string) // test-only publish-race injection
)

type Manager struct{ Root string }
type marker struct {
	Schema int    `json:"schema"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// PlannedPath returns the managed location without creating or opening it.
func (m Manager) PlannedPath(projectID, pluginName, tool, compatibility, platform string) (string, error) {
	keys, err := cacheKeys(projectID, pluginName, tool, compatibility, platform)
	root := filepath.Clean(m.Root)
	if err != nil || m.Root == "" || !filepath.IsAbs(root) || root == "/" {
		return "", ErrUnsafeKey
	}
	return filepath.Join(append([]string{root}, keys...)...), nil
}

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
		next, err := openOrPublishManagedDir(fd, key)
		if err != nil {
			// fd is the previous iteration's directory descriptor (rootFD on the
			// first iteration, closed by the deferred close). A failure here must
			// not leak it — unlike openAbsoluteManagedDir/walk, which close before
			// the error check, this loop closed only on success.
			if fd != rootFD {
				unix.Close(fd)
			}
			return "", fmt.Errorf("open cache: %w", err)
		}
		if fd != rootFD {
			unix.Close(fd)
		}
		fd = next
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
	parentFD, err := walk(rootFD, keys[:4])
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	return quarantineAndDelete(rootFD, parentFD, keys[4])
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
	names, err := dirNames(rootFD)
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		if name == ownerFile || name == trashName {
			continue
		}
		if _, ok := keep[name]; ok {
			continue
		}
		if !keyPattern.MatchString(name) {
			return ErrUnsafeKey
		}
		// A cache key is a directory. A stray regular file whose name happens to
		// match keyPattern is not a cache entry; skip it rather than letting
		// quarantineAndDelete abort the whole prune on an O_DIRECTORY mismatch.
		var st unix.Stat_t
		if err := unix.Fstatat(rootFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		if err := quarantineAndDelete(rootFD, rootFD, name); err != nil {
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
	if m.Root == "" || !filepath.IsAbs(root) || root == "/" {
		return -1, ErrUnsafeKey
	}
	fd, err := openAbsoluteManagedDir(root, create)
	if err != nil {
		if err == unix.ENOENT {
			return -1, os.ErrNotExist
		}
		return -1, err
	}
	return fd, nil
}

func openAbsoluteManagedDir(path string, createFinal bool) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for i, part := range parts {
		var next int
		var e error
		if i == len(parts)-1 && createFinal {
			next, e = openOrPublishManagedDir(fd, part)
		} else {
			next, e = openBeneath(fd, part)
			if e == nil && i == len(parts)-1 {
				e = verifyMarker(next)
			}
		}
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
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
		next, e := openBeneath(fd, key)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}

func createMarker(dirFD int) error {
	var st unix.Stat_t
	if err := unix.Fstat(dirFD, &st); err != nil {
		return err
	}
	data, _ := json.Marshal(marker{Schema: 1, Device: uint64(st.Dev), Inode: st.Ino})
	data = append(data, '\n')
	fd, err := unix.Openat(dirFD, ownerFile, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "cache marker")
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = unix.Unlinkat(dirFD, ownerFile, 0)
		return err
	}
	return unix.Fsync(dirFD)
}

func verifyMarker(dirFD int) error {
	fd, err := unix.Openat(dirFD, ownerFile, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrNotOwned
	}
	f := os.NewFile(uintptr(fd), "cache marker")
	data, readErr := io.ReadAll(io.LimitReader(f, 257))
	f.Close()
	if readErr != nil || len(data) > 256 {
		return ErrNotOwned
	}
	var got marker
	var st unix.Stat_t
	if json.Unmarshal(data, &got) != nil || unix.Fstat(dirFD, &st) != nil || got.Schema != 1 || got.Device != uint64(st.Dev) || got.Inode != st.Ino {
		return ErrNotOwned
	}
	return nil
}

func ensureTrash(rootFD int) (int, error) {
	return openOrPublishManagedDir(rootFD, trashName)
}

func openOrPublishManagedDir(parentFD int, name string) (int, error) {
	fd, err := openBeneath(parentFD, name)
	if err == nil {
		if err := verifyMarker(fd); err != nil {
			unix.Close(fd)
			return -1, err
		}
		return fd, nil
	}
	if err != unix.ENOENT {
		return -1, err
	}
	tmp, err := randomName(".dir-")
	if err != nil {
		return -1, err
	}
	if err := unix.Mkdirat(parentFD, tmp, 0700); err != nil {
		return -1, err
	}
	ownedFD, err := openBeneath(parentFD, tmp)
	if err != nil {
		_ = unix.Unlinkat(parentFD, tmp, unix.AT_REMOVEDIR)
		return -1, err
	}
	cleanup := func() {
		_ = unix.Unlinkat(ownedFD, ownerFile, 0)
		_ = unix.Close(ownedFD)
		_ = unix.Unlinkat(parentFD, tmp, unix.AT_REMOVEDIR)
	}
	if err := createMarker(ownedFD); err != nil {
		cleanup()
		return -1, err
	}
	if beforeDirPublish != nil {
		beforeDirPublish(parentFD, tmp, name)
	}
	if err := unix.Renameat2(parentFD, tmp, parentFD, name, unix.RENAME_NOREPLACE); err != nil {
		cleanup()
		if err != unix.EEXIST {
			return -1, err
		}
		existing, openErr := openBeneath(parentFD, name)
		if openErr != nil {
			return -1, openErr
		}
		if verifyErr := verifyMarker(existing); verifyErr != nil {
			unix.Close(existing)
			return -1, verifyErr
		}
		return existing, nil
	}
	if err := unix.Fsync(parentFD); err != nil {
		unix.Close(ownedFD)
		return -1, err
	}
	return ownedFD, nil
}

func randomName(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func quarantineAndDelete(rootFD, parentFD int, name string) error {
	trashFD, err := ensureTrash(rootFD)
	if err != nil {
		return err
	}
	defer unix.Close(trashFD)
	q, err := randomName("q-")
	if err != nil {
		return err
	}
	if err := unix.Renameat2(parentFD, name, trashFD, q, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	restore := func() error {
		if err := unix.Renameat2(trashFD, q, parentFD, name, unix.RENAME_NOREPLACE); err != nil {
			return fmt.Errorf("restore unverified cache: %w", err)
		}
		return unix.Fsync(parentFD)
	}
	fd, err := openBeneath(trashFD, q)
	if err != nil {
		_ = restore()
		return ErrNotOwned
	}
	var owned unix.Stat_t
	_ = unix.Fstat(fd, &owned)
	if err := verifyMarker(fd); err != nil {
		unix.Close(fd)
		if restoreErr := restore(); restoreErr != nil {
			return restoreErr
		}
		return err
	}
	if err := deleteContents(fd); err != nil {
		unix.Close(fd)
		return err
	}
	if beforeDelete != nil {
		beforeDelete(trashFD, q)
	}
	var live unix.Stat_t
	if err := unix.Fstatat(trashFD, q, &live, unix.AT_SYMLINK_NOFOLLOW); err != nil || live.Dev != owned.Dev || live.Ino != owned.Ino {
		unix.Close(fd)
		return ErrNotOwned
	}
	if err := unix.Unlinkat(fd, ownerFile, 0); err != nil {
		unix.Close(fd)
		return err
	}
	unix.Close(fd)
	if err := unix.Unlinkat(trashFD, q, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return unix.Fsync(trashFD)
}

func deleteContents(fd int) error {
	names, err := dirNames(fd)
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == ownerFile {
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			child, err := openBeneath(fd, name)
			if err != nil {
				return err
			}
			err = deleteContents(child)
			if err == nil {
				e := unix.Unlinkat(child, ownerFile, 0)
				if e != nil && e != unix.ENOENT {
					err = e
				}
			}
			unix.Close(child)
			if err != nil {
				return err
			}
			if err := unix.Unlinkat(fd, name, unix.AT_REMOVEDIR); err != nil {
				return err
			}
		} else if err := unix.Unlinkat(fd, name, 0); err != nil {
			return err
		}
	}
	return nil
}
func dirNames(fd int) ([]string, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "directory")
	names, err := f.Readdirnames(-1)
	f.Close()
	return names, err
}
