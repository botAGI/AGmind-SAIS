package durablefile

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

var ErrUnsafePath = errors.New("unsafe filesystem path")

type secureParent struct {
	fd   int
	base string
}

func splitSecureAbsolute(path string) ([]string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || !filepath.IsAbs(path) || absolute != filepath.Clean(path) {
		return nil, fmt.Errorf("%w: path must be clean and absolute", ErrUnsafePath)
	}
	parts := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("%w: invalid path component", ErrUnsafePath)
		}
	}
	return parts, nil
}

// openSecureParent resolves every ancestor through held directory descriptors.
// Later create/rename/open operations are relative to the returned descriptor,
// so an attacker swapping an already-open ancestor cannot redirect I/O.
func openSecureParent(path string) (secureParent, error) {
	parts, err := splitSecureAbsolute(path)
	if err != nil || len(parts) < 1 {
		return secureParent{}, ErrUnsafePath
	}
	current, err := unix.Open(
		string(filepath.Separator),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return secureParent{}, err
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(
			current,
			part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		_ = unix.Close(current)
		if openErr != nil {
			return secureParent{}, fmt.Errorf("%w: unsafe parent", ErrUnsafePath)
		}
		current = next
	}
	return secureParent{fd: current, base: parts[len(parts)-1]}, nil
}

func regularSingleLink(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		stat.Nlink == 1 &&
		stat.Mode&0o777 == 0o600 &&
		stat.Uid == uint32(os.Geteuid())
}

func privateDirectory(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		stat.Mode&0o777 == 0o700 &&
		stat.Uid == uint32(os.Geteuid())
}

// EnsurePrivateDirectory creates missing path components without following
// symlinks and verifies that the final directory is owned by the effective
// user with mode 0700.
func EnsurePrivateDirectory(path string) error {
	parts, err := splitSecureAbsolute(path)
	if err != nil {
		return err
	}
	current, err := unix.Open(
		string(filepath.Separator),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(current) }()
	for index, part := range parts {
		next, openErr := unix.Openat(
			current,
			part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(current, part, 0o700); mkdirErr != nil &&
				!errors.Is(mkdirErr, unix.EEXIST) {
				return mkdirErr
			}
			if syncErr := syncDirectoryFD(current); syncErr != nil {
				return syncErr
			}
			next, openErr = unix.Openat(
				current,
				part,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
				0,
			)
		}
		if openErr != nil {
			return fmt.Errorf("%w: unsafe directory component", ErrUnsafePath)
		}
		var stat unix.Stat_t
		if statErr := unix.Fstat(next, &stat); statErr != nil {
			_ = unix.Close(next)
			return statErr
		}
		if index == len(parts)-1 && !privateDirectory(stat) {
			_ = unix.Close(next)
			return fmt.Errorf("%w: private directory metadata", ErrUnsafePath)
		}
		_ = unix.Close(current)
		current = next
	}
	return nil
}

// ReadDirectoryNames lists a private directory through a nofollow descriptor.
func ReadDirectoryNames(path string) ([]string, error) {
	if err := EnsurePrivateDirectory(path); err != nil {
		return nil, err
	}
	parent, err := openSecureParent(filepath.Join(path, ".directory-entry"))
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(parent.fd), path)
	if file == nil {
		_ = unix.Close(parent.fd)
		return nil, fmt.Errorf("failed to own directory descriptor")
	}
	defer file.Close()
	return file.Readdirnames(-1)
}

func statDestination(parent secureParent) (unix.Stat_t, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(parent.fd, parent.base, &stat, unix.AT_SYMLINK_NOFOLLOW)
	return stat, err
}

func validateExistingDestination(parent secureParent) error {
	stat, err := statDestination(parent)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || !regularSingleLink(stat) {
		return fmt.Errorf("%w: destination is not a single-link regular file", ErrUnsafePath)
	}
	return nil
}

func createExclusiveTemp(parent secureParent) (*os.File, string, error) {
	for range 32 {
		var random [16]byte
		if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
			return nil, "", err
		}
		name := "." + parent.base + ".tmp-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(
			parent.fd,
			name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0o600,
		)
		if err == nil {
			file := os.NewFile(uintptr(fd), name)
			if file == nil {
				_ = unix.Close(fd)
				return nil, "", fmt.Errorf("failed to own temporary descriptor")
			}
			return file, name, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("unable to allocate atomic temporary file")
}

func syncDirectoryFD(fd int) error {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "directory")
	if directory == nil {
		_ = unix.Close(duplicate)
		return fmt.Errorf("failed to own directory descriptor")
	}
	defer directory.Close()
	return directory.Sync()
}

// SyncDirectory durably records directory-entry changes without following a
// symlinked ancestor.
func SyncDirectory(path string) error {
	parent, err := openSecureParent(filepath.Join(path, ".sync-target"))
	if err != nil {
		return err
	}
	defer unix.Close(parent.fd)
	return syncDirectoryFD(parent.fd)
}

// AtomicWrite replaces a mode-0600 regular file using fd-relative nofollow
// operations, a synced same-directory temporary file, rename, and directory
// sync.
func AtomicWrite(path string, payload []byte) (returnErr error) {
	parent, err := openSecureParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent.fd)
	if err := validateExistingDestination(parent); err != nil {
		return err
	}
	temporary, temporaryName, err := createExclusiveTemp(parent)
	if err != nil {
		return err
	}
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		if returnErr != nil && temporaryName != "" {
			_ = unix.Unlinkat(parent.fd, temporaryName, 0)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	written := 0
	for written < len(payload) {
		count, writeErr := temporary.Write(payload[written:])
		if writeErr != nil {
			return writeErr
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		written += count
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporary = nil
	if err := validateExistingDestination(parent); err != nil {
		return err
	}
	if err := unix.Renameat(
		parent.fd,
		temporaryName,
		parent.fd,
		parent.base,
	); err != nil {
		return err
	}
	temporaryName = ""
	return syncDirectoryFD(parent.fd)
}

// CreateOnly durably publishes a complete mode-0600 file without ever
// replacing an existing name. The final name appears only after the temporary
// file has been fully written and synced.
func CreateOnly(path string, payload []byte) (returnErr error) {
	parent, err := openSecureParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent.fd)
	if stat, statErr := statDestination(parent); statErr == nil {
		if !regularSingleLink(stat) {
			return ErrUnsafePath
		}
		return os.ErrExist
	} else if !errors.Is(statErr, unix.ENOENT) {
		return ErrUnsafePath
	}
	temporary, temporaryName, err := createExclusiveTemp(parent)
	if err != nil {
		return err
	}
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		if temporaryName != "" {
			_ = unix.Unlinkat(parent.fd, temporaryName, 0)
		}
	}()
	written := 0
	for written < len(payload) {
		count, writeErr := temporary.Write(payload[written:])
		if writeErr != nil {
			return writeErr
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		written += count
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporary = nil
	if err := unix.Linkat(
		parent.fd,
		temporaryName,
		parent.fd,
		parent.base,
		0,
	); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return os.ErrExist
		}
		return err
	}
	if err := syncDirectoryFD(parent.fd); err != nil {
		return err
	}
	if err := unix.Unlinkat(parent.fd, temporaryName, 0); err != nil {
		return err
	}
	temporaryName = ""
	return syncDirectoryFD(parent.fd)
}

// ReadRegular reads one single-link regular file through fd-relative nofollow
// resolution with an explicit byte bound.
func ReadRegular(path string, maxBytes int64) ([]byte, error) {
	if maxBytes < 1 {
		return nil, fmt.Errorf("maxBytes must be positive")
	}
	parent, err := openSecureParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent.fd)
	before, err := statDestination(parent)
	if err != nil {
		return nil, err
	}
	if !regularSingleLink(before) || before.Size < 0 || before.Size > maxBytes {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Openat(
		parent.fd,
		parent.base,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), parent.base)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to own file descriptor")
	}
	defer file.Close()
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if !regularSingleLink(after) ||
		before.Dev != after.Dev ||
		before.Ino != after.Ino {
		return nil, ErrUnsafePath
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, ErrUnsafePath
	}
	return raw, nil
}

// Remove durably unlinks one owned, mode-0600, single-link regular file.
func Remove(path string) error {
	parent, err := openSecureParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent.fd)
	stat, err := statDestination(parent)
	if err != nil {
		return err
	}
	if !regularSingleLink(stat) {
		return ErrUnsafePath
	}
	if err := unix.Unlinkat(parent.fd, parent.base, 0); err != nil {
		return err
	}
	return syncDirectoryFD(parent.fd)
}
