package shim

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
	"strings"

	"golang.org/x/sys/unix"
)

const genericName = "dproxy-shim"
const rootMarker = ".dproxy-shim-owner"

var (
	ErrCollision                          = errors.New("unmanaged shim collision")
	ErrUnsafeName                         = errors.New("unsafe shim name")
	errInterrupted                        = errors.New("simulated interrupted transaction")
	namePattern                           = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	randomReader       io.Reader          = rand.Reader
	beforeRecordCommit func(string) error // test-only fault injection
	afterTransition    func(string) error // test-only crash injection
	afterObjectPublish func(string) error // test-only crash injection
	beforeFinalRecord  func(string) error // test-only durable-commit fault injection
	beforeRemoveVerify func(int, string)  // test-only race injection
)

type Target struct{ Binary string }
type Manager struct{ BinDir, ShimDir, Executable string }
type ownership struct {
	Schema                                       int `json:"schema"`
	Name, Binary, Target, Kind                   string
	Device, Inode, PreviousDevice, PreviousInode uint64
	Temp, TempDir                                string
}
type dirOwner struct {
	Schema        int `json:"schema"`
	Device, Inode uint64
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
	shimFD, ownersFD, trashFD, err := m.openManagedRoots(true)
	if err != nil {
		return err
	}
	defer unix.Close(shimFD)
	defer unix.Close(ownersFD)
	defer unix.Close(trashFD)
	binFD, _, err := openAbsoluteDir(m.BinDir, true)
	if err != nil {
		return err
	}
	defer unix.Close(binFD)
	if err := m.recover(ownersFD, binFD, shimFD); err != nil {
		return err
	}
	if err := m.syncGeneric(shimFD, ownersFD); err != nil {
		return err
	}
	relTarget, err := filepath.Rel(m.BinDir, filepath.Join(m.ShimDir, genericName))
	if err != nil || !beneathByPath(m.ShimDir, filepath.Join(m.BinDir, relTarget)) {
		return ErrUnsafeName
	}
	for name, target := range targets {
		tmp, err := randomName(".dproxy-link-")
		if err != nil {
			return err
		}
		if err := unix.Symlinkat(relTarget, binFD, tmp); err != nil {
			return err
		}
		if err := m.publish(binFD, ownersFD, name, target.Binary, relTarget, "symlink", tmp, "bin"); err != nil {
			if !errors.Is(err, errInterrupted) {
				_ = unix.Unlinkat(binFD, tmp, 0)
			}
			return err
		}
	}
	return nil
}

func (m Manager) Remove(name string) error {
	if !validName(name) {
		return ErrUnsafeName
	}
	shimFD, ownersFD, trashFD, err := m.openManagedRoots(false)
	if err != nil {
		if err == unix.ENOENT || errors.Is(err, os.ErrNotExist) {
			return ErrCollision
		}
		return err
	}
	defer unix.Close(shimFD)
	defer unix.Close(ownersFD)
	defer unix.Close(trashFD)
	binFD, _, err := openAbsoluteDir(m.BinDir, false)
	if err != nil {
		return err
	}
	defer unix.Close(binFD)
	if err := m.recover(ownersFD, binFD, shimFD); err != nil {
		return err
	}
	record, err := readRecordAt(ownersFD, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrCollision
		}
		return err
	}
	q, err := randomName("removed-")
	if err != nil {
		return err
	}
	backup, err := randomName("backup-")
	if err != nil {
		return err
	}
	if err := unix.Linkat(binFD, name, trashFD, backup, 0); err != nil {
		return err
	}
	var backupStat unix.Stat_t
	if err := unix.Fstatat(trashFD, backup, &backupStat, unix.AT_SYMLINK_NOFOLLOW); err != nil || !matches(record, backupStat) {
		_ = unix.Unlinkat(trashFD, backup, 0)
		return ErrCollision
	}
	if err := unix.Renameat2(binFD, name, trashFD, q, unix.RENAME_NOREPLACE); err != nil {
		_ = unix.Unlinkat(trashFD, backup, 0)
		return err
	}
	restore := func() error { return unix.Renameat2(trashFD, backup, binFD, name, unix.RENAME_NOREPLACE) }
	if beforeRemoveVerify != nil {
		beforeRemoveVerify(trashFD, q)
	}
	var st unix.Stat_t
	target, readErr := readlinkAt(trashFD, q)
	if unix.Fstatat(trashFD, q, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || readErr != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK || !matches(record, st) || target != record.Target {
		if err := restore(); err != nil {
			return fmt.Errorf("restore unverified shim: %w", err)
		}
		return ErrCollision
	}
	if err := unix.Unlinkat(trashFD, q, 0); err != nil {
		return err
	}
	if err := unix.Unlinkat(trashFD, backup, 0); err != nil {
		return err
	}
	if err := unix.Fsync(trashFD); err != nil {
		return err
	}
	if err := unix.Unlinkat(ownersFD, recordName(name), 0); err != nil {
		return err
	}
	return unix.Fsync(ownersFD)
}

func (m Manager) Owned(name string) (bool, error) {
	if !validName(name) {
		return false, ErrUnsafeName
	}
	shimFD, ownersFD, _, err := m.openManagedRoots(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer unix.Close(shimFD)
	defer unix.Close(ownersFD)
	binFD, _, err := openAbsoluteDir(m.BinDir, false)
	if err != nil {
		if err == unix.ENOENT {
			return false, nil
		}
		return false, err
	}
	defer unix.Close(binFD)
	if err := m.recover(ownersFD, binFD, shimFD); err != nil {
		return false, err
	}
	record, err := readRecordAt(ownersFD, name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(binFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == unix.ENOENT {
		return false, nil
	} else if err != nil {
		return false, err
	}
	target, err := readlinkAt(binFD, name)
	return err == nil && record.Kind == "symlink" && st.Mode&unix.S_IFMT == unix.S_IFLNK && matches(record, st) && target == record.Target && beneathByPath(m.ShimDir, filepath.Join(m.BinDir, target)), nil
}

func (m Manager) syncGeneric(shimFD, ownersFD int) error {
	sourceFD, err := openAbsoluteFile(m.Executable)
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(sourceFD), "dproxy executable")
	defer source.Close()
	tmp, err := randomName(".generic-")
	if err != nil {
		return err
	}
	fd, err := unix.Openat(shimFD, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0700)
	if err != nil {
		return err
	}
	dest := os.NewFile(uintptr(fd), "generic shim")
	_, err = io.Copy(dest, source)
	if err == nil {
		err = dest.Sync()
	}
	closeErr := dest.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = unix.Unlinkat(shimFD, tmp, 0)
		return err
	}
	if err := m.publish(shimFD, ownersFD, genericName, genericName, "", "regular", tmp, "shim"); err != nil {
		if !errors.Is(err, errInterrupted) {
			_ = unix.Unlinkat(shimFD, tmp, 0)
		}
		return err
	}
	return nil
}

func (m Manager) publish(objectFD, ownersFD int, name, binary, target, kind, tmp, tempDir string) error {
	var fresh unix.Stat_t
	if err := unix.Fstatat(objectFD, tmp, &fresh, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	old, recordErr := readRecordAt(ownersFD, name)
	var live unix.Stat_t
	liveErr := unix.Fstatat(objectFD, name, &live, unix.AT_SYMLINK_NOFOLLOW)
	if liveErr == nil && (recordErr != nil || !matches(old, live) || old.Kind != kind || old.Target != target) {
		return ErrCollision
	}
	if liveErr != nil && liveErr != unix.ENOENT {
		return liveErr
	}
	if recordErr != nil && !errors.Is(recordErr, os.ErrNotExist) {
		return recordErr
	}
	if liveErr == unix.ENOENT && recordErr == nil {
		return ErrCollision
	}
	transition := ownership{Schema: 1, Name: name, Binary: binary, Target: target, Kind: kind, Device: uint64(fresh.Dev), Inode: fresh.Ino, Temp: tmp, TempDir: tempDir}
	if liveErr == nil {
		transition.PreviousDevice, transition.PreviousInode = uint64(live.Dev), live.Ino
	}
	if err := writeRecordAt(ownersFD, transition); err != nil {
		return err
	}
	if beforeRecordCommit != nil {
		if err := beforeRecordCommit(name); err != nil {
			_ = restoreRecord(ownersFD, name, old, recordErr)
			return err
		}
	}
	if afterTransition != nil {
		if err := afterTransition(name); err != nil {
			return err
		}
	}
	if liveErr == unix.ENOENT {
		err := unix.Renameat2(objectFD, tmp, objectFD, name, unix.RENAME_NOREPLACE)
		if err != nil {
			_ = restoreRecord(ownersFD, name, old, recordErr)
			if err == unix.EEXIST {
				return ErrCollision
			}
			return err
		}
	} else {
		if err := unix.Renameat2(objectFD, tmp, objectFD, name, unix.RENAME_EXCHANGE); err != nil {
			_ = restoreRecord(ownersFD, name, old, recordErr)
			return err
		}
		var moved unix.Stat_t
		if unix.Fstatat(objectFD, tmp, &moved, unix.AT_SYMLINK_NOFOLLOW) != nil || !matches(old, moved) {
			_ = unix.Renameat2(objectFD, tmp, objectFD, name, unix.RENAME_EXCHANGE)
			_ = restoreRecord(ownersFD, name, old, recordErr)
			return ErrCollision
		}
	}
	rollback := func() {
		if liveErr == nil {
			_ = unix.Renameat2(objectFD, tmp, objectFD, name, unix.RENAME_EXCHANGE)
		} else {
			_ = unix.Renameat2(objectFD, name, objectFD, tmp, unix.RENAME_NOREPLACE)
		}
		_ = unix.Fsync(objectFD)
		_ = restoreRecord(ownersFD, name, old, recordErr)
	}
	if err := unix.Fsync(objectFD); err != nil {
		rollback()
		return err
	}
	if afterObjectPublish != nil {
		if err := afterObjectPublish(name); err != nil {
			if !errors.Is(err, errInterrupted) {
				rollback()
			}
			return err
		}
	}
	final := transition
	final.PreviousDevice, final.PreviousInode, final.Temp, final.TempDir = 0, 0, "", ""
	if beforeFinalRecord != nil {
		if err := beforeFinalRecord(name); err != nil {
			rollback()
			return err
		}
	}
	if err := writeRecordAt(ownersFD, final); err != nil {
		rollback()
		return err
	}
	if liveErr == nil {
		if err := unix.Unlinkat(objectFD, tmp, 0); err != nil {
			return err
		}
		return unix.Fsync(objectFD)
	}
	return nil
}

func (m Manager) recover(ownersFD, binFD, shimFD int) error {
	names, err := dirNames(ownersFD)
	if err != nil {
		return err
	}
	for _, file := range names {
		if !strings.HasSuffix(file, ".json") {
			continue
		}
		name := strings.TrimSuffix(file, ".json")
		record, err := readRecordAt(ownersFD, name)
		if err != nil {
			return err
		}
		if record.Temp == "" {
			continue
		}
		objectFD := binFD
		if record.TempDir == "shim" {
			objectFD = shimFD
		} else if record.TempDir != "bin" {
			return ErrCollision
		}
		var live, temp unix.Stat_t
		liveErr := unix.Fstatat(objectFD, name, &live, unix.AT_SYMLINK_NOFOLLOW)
		tempErr := unix.Fstatat(objectFD, record.Temp, &temp, unix.AT_SYMLINK_NOFOLLOW)
		if liveErr == nil && matches(record, live) {
			final := record
			final.PreviousDevice, final.PreviousInode, final.Temp, final.TempDir = 0, 0, "", ""
			if err := writeRecordAt(ownersFD, final); err != nil {
				return err
			}
			if tempErr == nil && uint64(temp.Dev) == record.PreviousDevice && temp.Ino == record.PreviousInode {
				if err := unix.Unlinkat(objectFD, record.Temp, 0); err != nil {
					return err
				}
			}
			continue
		}
		if record.PreviousInode != 0 && liveErr == nil && uint64(live.Dev) == record.PreviousDevice && live.Ino == record.PreviousInode {
			old := record
			old.Device, old.Inode, old.PreviousDevice, old.PreviousInode, old.Temp, old.TempDir = record.PreviousDevice, record.PreviousInode, 0, 0, "", ""
			if err := writeRecordAt(ownersFD, old); err != nil {
				return err
			}
			if tempErr == nil && matches(record, temp) {
				if err := unix.Unlinkat(objectFD, record.Temp, 0); err != nil {
					return err
				}
			}
			continue
		}
		if record.PreviousInode == 0 && liveErr == unix.ENOENT && tempErr == nil && matches(record, temp) {
			if err := unix.Unlinkat(objectFD, record.Temp, 0); err != nil {
				return err
			}
			if err := unix.Unlinkat(ownersFD, recordName(name), 0); err != nil {
				return err
			}
			continue
		}
		return ErrCollision
	}
	return nil
}

func (m Manager) openManagedRoots(create bool) (int, int, int, error) {
	shimFD, created, err := openAbsoluteDir(m.ShimDir, create)
	if err != nil {
		return -1, -1, -1, err
	}
	if created {
		err = createDirOwner(shimFD)
	} else {
		err = verifyDirOwner(shimFD)
	}
	if err != nil {
		unix.Close(shimFD)
		return -1, -1, -1, err
	}
	ownersFD, err := managedChild(shimFD, ".owners", create)
	if err != nil {
		unix.Close(shimFD)
		return -1, -1, -1, err
	}
	trashFD, err := managedChild(shimFD, ".trash", create)
	if err != nil {
		unix.Close(shimFD)
		unix.Close(ownersFD)
		return -1, -1, -1, err
	}
	return shimFD, ownersFD, trashFD, nil
}

func managedChild(parent int, name string, create bool) (int, error) {
	created := false
	fd, err := openDirAt(parent, name)
	if err == unix.ENOENT && create {
		if err = unix.Mkdirat(parent, name, 0700); err == nil {
			created = true
			fd, err = openDirAt(parent, name)
		}
	}
	if err != nil {
		return -1, err
	}
	if created {
		err = createDirOwner(fd)
	} else {
		err = verifyDirOwner(fd)
	}
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}
func createDirOwner(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	data, _ := json.Marshal(dirOwner{1, uint64(st.Dev), st.Ino})
	data = append(data, '\n')
	marker, err := unix.Openat(fd, rootMarker, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(marker), "dir owner")
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	_ = f.Close()
	if err != nil {
		return err
	}
	return unix.Fsync(fd)
}
func verifyDirOwner(fd int) error {
	marker, err := unix.Openat(fd, rootMarker, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrCollision
	}
	f := os.NewFile(uintptr(marker), "dir owner")
	data, err := io.ReadAll(io.LimitReader(f, 257))
	f.Close()
	var got dirOwner
	var st unix.Stat_t
	if err != nil || len(data) > 256 || json.Unmarshal(data, &got) != nil || unix.Fstat(fd, &st) != nil || got.Schema != 1 || got.Device != uint64(st.Dev) || got.Inode != st.Ino {
		return ErrCollision
	}
	return nil
}

func readRecordAt(fd int, name string) (ownership, error) {
	rfd, err := unix.Openat(fd, recordName(name), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err == unix.ENOENT {
		return ownership{}, os.ErrNotExist
	}
	if err != nil {
		return ownership{}, err
	}
	f := os.NewFile(uintptr(rfd), "ownership")
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	f.Close()
	var r ownership
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &r) != nil || r.Schema != 1 || r.Name != name {
		return ownership{}, ErrCollision
	}
	return r, nil
}
func writeRecordAt(fd int, r ownership) error {
	data, _ := json.Marshal(r)
	data = append(data, '\n')
	tmp, err := randomName(".record-")
	if err != nil {
		return err
	}
	tfd, err := unix.Openat(fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(tfd), "record")
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	_ = f.Close()
	if err != nil {
		_ = unix.Unlinkat(fd, tmp, 0)
		return err
	}
	if err = unix.Renameat(fd, tmp, fd, recordName(r.Name)); err != nil {
		_ = unix.Unlinkat(fd, tmp, 0)
		return err
	}
	return unix.Fsync(fd)
}
func restoreRecord(fd int, name string, old ownership, oldErr error) error {
	if errors.Is(oldErr, os.ErrNotExist) {
		e := unix.Unlinkat(fd, recordName(name), 0)
		if e == unix.ENOENT {
			return nil
		}
		return e
	}
	if oldErr != nil {
		return oldErr
	}
	return writeRecordAt(fd, old)
}

func (m Manager) validateRoots() error {
	for _, root := range []string{m.BinDir, m.ShimDir, m.Executable} {
		if root == "" || !filepath.IsAbs(root) {
			return ErrUnsafeName
		}
	}
	if filepath.Clean(m.BinDir) == "/" || filepath.Clean(m.ShimDir) == "/" || filepath.Clean(m.BinDir) == filepath.Clean(m.ShimDir) {
		return ErrUnsafeName
	}
	return nil
}
func validName(name string) bool    { return namePattern.MatchString(name) && name != "." && name != ".." }
func recordName(name string) string { return name + ".json" }
func (m Manager) recordPath(name string) string {
	return filepath.Join(m.ShimDir, ".owners", recordName(name))
}
func matches(r ownership, st unix.Stat_t) bool {
	return uint64(st.Dev) == r.Device && st.Ino == r.Inode
}
func randomName(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(randomReader, b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}
func beneathByPath(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func readlinkAt(fd int, name string) (string, error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(fd, name, buf)
	if err != nil {
		return "", err
	}
	if n == len(buf) {
		return "", ErrCollision
	}
	return string(buf[:n]), nil
}
func openDirAt(fd int, name string) (int, error) {
	return unix.Openat2(fd, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
}
func openAbsoluteDir(path string, createFinal bool) (int, bool, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false, err
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	created := false
	for i, p := range parts {
		next, e := openDirAt(fd, p)
		if e == unix.ENOENT && createFinal && i == len(parts)-1 {
			if e = unix.Mkdirat(fd, p, 0700); e == nil {
				created = true
				next, e = openDirAt(fd, p)
			}
		}
		unix.Close(fd)
		if e != nil {
			return -1, false, e
		}
		fd = next
	}
	return fd, created, nil
}
func openAbsoluteFile(path string) (int, error) {
	parent, name := filepath.Split(filepath.Clean(path))
	fd, _, err := openAbsoluteDir(parent, false)
	if err != nil {
		return -1, err
	}
	defer unix.Close(fd)
	file, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if unix.Fstat(file, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(file)
		return -1, ErrUnsafeName
	}
	return file, nil
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
