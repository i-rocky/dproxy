package shim

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"
)

const genericName = "dproxy-shim"

var (
	ErrCollision  = errors.New("unmanaged shim collision")
	ErrUnsafeName = errors.New("unsafe shim name")
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

type Target struct{ Binary string }
type Manager struct{ BinDir, ShimDir, Executable string }
type ownership struct {
	Name, Binary, Target string
	Device               uint64
	Inode                uint64
}

func (m Manager) Sync(targets map[string]Target) error {
	if err := m.validateRoots(); err != nil {
		return err
	}
	for name, target := range targets {
		if !validName(name) || !validName(target.Binary) || name != target.Binary {
			return ErrUnsafeName
		}
	}
	if err := os.MkdirAll(m.BinDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(m.ownerDir(), 0700); err != nil {
		return err
	}
	if err := m.publishGeneric(); err != nil {
		return err
	}
	binFD, err := unix.Open(m.BinDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(binFD)
	for name, target := range targets {
		owned, err := m.Owned(name)
		if err != nil {
			return err
		}
		var st unix.Stat_t
		statErr := unix.Fstatat(binFD, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if statErr == nil && !owned {
			return ErrCollision
		}
		if statErr != nil && statErr != unix.ENOENT {
			return statErr
		}
		relTarget, err := filepath.Rel(m.BinDir, filepath.Join(m.ShimDir, genericName))
		if err != nil || !beneathByPath(m.ShimDir, filepath.Join(m.BinDir, relTarget)) {
			return ErrUnsafeName
		}
		tmp := fmt.Sprintf(".dproxy-%s-%d", name, os.Getpid())
		_ = unix.Unlinkat(binFD, tmp, 0)
		if err := unix.Symlinkat(relTarget, binFD, tmp); err != nil {
			return err
		}
		if !owned {
			if err := unix.Renameat2(binFD, tmp, binFD, name, unix.RENAME_NOREPLACE); err != nil {
				_ = unix.Unlinkat(binFD, tmp, 0)
				if err == unix.EEXIST {
					return ErrCollision
				}
				return err
			}
		} else {
			record, err := m.readOwnership(name)
			if err != nil {
				_ = unix.Unlinkat(binFD, tmp, 0)
				return err
			}
			if err := unix.Renameat2(binFD, tmp, binFD, name, unix.RENAME_EXCHANGE); err != nil {
				_ = unix.Unlinkat(binFD, tmp, 0)
				return err
			}
			var old unix.Stat_t
			if err := unix.Fstatat(binFD, tmp, &old, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint64(old.Dev) != record.Device || old.Ino != record.Inode {
				_ = unix.Renameat2(binFD, tmp, binFD, name, unix.RENAME_EXCHANGE)
				_ = unix.Unlinkat(binFD, tmp, 0)
				return ErrCollision
			}
			if err := unix.Unlinkat(binFD, tmp, 0); err != nil {
				return err
			}
		}
		if err := unix.Fsync(binFD); err != nil {
			return err
		}
		if err := unix.Fstatat(binFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		record := ownership{Name: name, Binary: target.Binary, Target: relTarget, Device: uint64(st.Dev), Inode: st.Ino}
		if err := m.writeOwnership(record); err != nil {
			return err
		}
	}
	return nil
}

func (m Manager) Remove(name string) error {
	if !validName(name) {
		return ErrUnsafeName
	}
	owned, err := m.Owned(name)
	if err != nil {
		return err
	}
	if !owned {
		return ErrCollision
	}
	binFD, err := unix.Open(m.BinDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(binFD)
	if err := unix.Unlinkat(binFD, name, 0); err != nil {
		return err
	}
	if err := unix.Fsync(binFD); err != nil {
		return err
	}
	return os.Remove(m.recordPath(name))
}

func (m Manager) Owned(name string) (bool, error) {
	if !validName(name) {
		return false, ErrUnsafeName
	}
	record, err := m.readOwnership(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	expected, err := filepath.Rel(m.BinDir, filepath.Join(m.ShimDir, genericName))
	if err != nil || record.Target != expected || !beneathByPath(m.ShimDir, filepath.Join(m.BinDir, record.Target)) {
		return false, ErrCollision
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(m.BinDir, name), &st); errors.Is(err, unix.ENOENT) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK || uint64(st.Dev) != record.Device || st.Ino != record.Inode {
		return false, nil
	}
	target, err := os.Readlink(filepath.Join(m.BinDir, name))
	if err != nil || target != record.Target {
		return false, nil
	}
	return true, nil
}

func (m Manager) readOwnership(name string) (ownership, error) {
	fd, err := unix.Open(m.recordPath(name), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err == unix.ENOENT {
		return ownership{}, os.ErrNotExist
	}
	if err != nil {
		return ownership{}, err
	}
	file := os.NewFile(uintptr(fd), "shim ownership")
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return ownership{}, ErrCollision
	}
	var record ownership
	if json.Unmarshal(data, &record) != nil || record.Name != name || record.Binary != name {
		return ownership{}, ErrCollision
	}
	return record, nil
}

func (m Manager) validateRoots() error {
	for _, root := range []string{m.BinDir, m.ShimDir, m.Executable} {
		if root == "" || !filepath.IsAbs(root) {
			return ErrUnsafeName
		}
	}
	if filepath.Clean(m.BinDir) == "/" || filepath.Clean(m.ShimDir) == "/" || m.BinDir == m.ShimDir {
		return ErrUnsafeName
	}
	return nil
}
func validName(name string) bool                { return namePattern.MatchString(name) && name != "." && name != ".." }
func (m Manager) ownerDir() string              { return filepath.Join(m.ShimDir, ".owners") }
func (m Manager) recordPath(name string) string { return filepath.Join(m.ownerDir(), name+".json") }
func beneathByPath(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && !(len(rel) > 3 && rel[:3] == ".."+string(filepath.Separator))
}

func (m Manager) publishGeneric() error {
	shimFD, err := unix.Open(m.ShimDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(shimFD)
	sourceFD, err := unix.Open(m.Executable, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if unix.Fstat(sourceFD, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(sourceFD)
		return ErrUnsafeName
	}
	source := os.NewFile(uintptr(sourceFD), "dproxy executable")
	defer source.Close()
	tmp := fmt.Sprintf(".%s-%d", genericName, os.Getpid())
	fd, err := unix.Openat(shimFD, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0700)
	if err == unix.EEXIST {
		_ = unix.Unlinkat(shimFD, tmp, 0)
		fd, err = unix.Openat(shimFD, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0700)
	}
	if err != nil {
		return err
	}
	dest := os.NewFile(uintptr(fd), "generic shim")
	_, copyErr := io.Copy(dest, source)
	if copyErr == nil {
		copyErr = dest.Sync()
	}
	closeErr := dest.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = unix.Unlinkat(shimFD, tmp, 0)
		return copyErr
	}
	if err := unix.Renameat(shimFD, tmp, shimFD, genericName); err != nil {
		_ = unix.Unlinkat(shimFD, tmp, 0)
		return err
	}
	return unix.Fsync(shimFD)
}

func (m Manager) writeOwnership(record ownership) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dirFD, err := unix.Open(m.ownerDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	tmp := fmt.Sprintf(".%s-%d", record.Name, os.Getpid())
	fd, err := unix.Openat(dirFD, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err == unix.EEXIST {
		_ = unix.Unlinkat(dirFD, tmp, 0)
		fd, err = unix.Openat(dirFD, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "shim ownership")
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = unix.Unlinkat(dirFD, tmp, 0)
		return err
	}
	if err := unix.Renameat(dirFD, tmp, dirFD, record.Name+".json"); err != nil {
		_ = unix.Unlinkat(dirFD, tmp, 0)
		return err
	}
	return unix.Fsync(dirFD)
}
