//go:build linux

package uds

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
	"golang.org/x/sys/unix"
)

const (
	socketOwnerSchema   = "agmind.uds-socket-owner.v1"
	socketOwnerMaxBytes = 4096
)

type socketOwnershipBoundary string

const (
	socketBoundaryPendingWritten  socketOwnershipBoundary = "pending_written"
	socketBoundaryBound           socketOwnershipBoundary = "socket_bound"
	socketBoundaryConfigured      socketOwnershipBoundary = "socket_configured"
	socketBoundaryActiveWritten   socketOwnershipBoundary = "active_written"
	socketBoundaryStaleUnlinked   socketOwnershipBoundary = "stale_unlinked"
	socketBoundaryParentPreRename socketOwnershipBoundary = "parent_pre_rename"
	socketBoundaryParentRenamed   socketOwnershipBoundary = "parent_renamed"
)

type listenOwnedOptions struct {
	boundary func(socketOwnershipBoundary)
}

type socketOwnerMarker struct {
	SchemaVersion string `json:"schema_version"`
	State         string `json:"state"`
	SocketBase    string `json:"socket_base"`
	Mode          uint32 `json:"mode"`
	GID           uint32 `json:"gid"`
	Generation    string `json:"generation"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
}

func (marker socketOwnerMarker) Validate() error {
	generation, err := hex.DecodeString(marker.Generation)
	if err != nil || len(generation) != 16 ||
		marker.SchemaVersion != socketOwnerSchema ||
		marker.SocketBase == "" ||
		filepath.Base(marker.SocketBase) != marker.SocketBase ||
		marker.Mode != 0o600 && marker.Mode != 0o660 {
		return ErrUnsafeSocket
	}
	switch marker.State {
	case "pending":
		if marker.Device != 0 || marker.Inode != 0 {
			return ErrUnsafeSocket
		}
	case "active":
		if marker.Device == 0 || marker.Inode == 0 {
			return ErrUnsafeSocket
		}
	default:
		return ErrUnsafeSocket
	}
	return nil
}

func (marker socketOwnerMarker) validateFor(
	parent parentHandle,
	mode os.FileMode,
	gid int,
) error {
	if err := marker.Validate(); err != nil ||
		marker.SocketBase != parent.base ||
		marker.Mode != uint32(mode.Perm()) ||
		gid < 0 ||
		marker.GID != uint32(gid) {
		return ErrUnsafeSocket
	}
	return nil
}

func socketSidecarName(parent parentHandle, suffix string) string {
	return "." + parent.base + suffix
}

func socketOwnerPath(parent parentHandle) string {
	return filepath.Join(
		parent.path,
		socketSidecarName(parent, ".owner.json"),
	)
}

func socketLockPath(parent parentHandle) string {
	return filepath.Join(parent.path, socketSidecarName(parent, ".lock"))
}

func syncDirectoryDescriptor(fd int) error {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "socket-parent")
	if directory == nil {
		_ = unix.Close(duplicate)
		return ErrUnsafeSocket
	}
	defer directory.Close()
	return directory.Sync()
}

func publishSocketParent(
	ancestorFD int,
	name string,
	gid int,
	boundary func(socketOwnershipBoundary),
) (returnFD int, returnErr error) {
	returnFD = -1
	var temporaryName string
	defer func() {
		if returnErr != nil && returnFD >= 0 {
			_ = unix.Close(returnFD)
			returnFD = -1
		}
		if temporaryName != "" {
			_ = unix.Unlinkat(
				ancestorFD,
				temporaryName,
				unix.AT_REMOVEDIR,
			)
		}
	}()
	for range 32 {
		generation, err := newSocketGeneration()
		if err != nil {
			return -1, err
		}
		temporaryName = "." + name + ".tmp-" + generation
		err = unix.Mkdirat(ancestorFD, temporaryName, 0o700)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EEXIST) {
			return -1, err
		}
		temporaryName = ""
	}
	if temporaryName == "" {
		return -1, ErrUnsafeSocket
	}
	fd, err := unix.Openat(
		ancestorFD,
		temporaryName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, err
	}
	returnFD = fd
	if err := unix.Fchown(fd, 0, gid); err != nil {
		return -1, err
	}
	if err := unix.Fchmod(fd, 0o750); err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != 0 ||
		stat.Gid != uint32(gid) ||
		stat.Mode&0o777 != 0o750 {
		return -1, ErrUnsafeSocket
	}
	if err := syncDirectoryDescriptor(fd); err != nil {
		return -1, err
	}
	if boundary != nil {
		boundary(socketBoundaryParentPreRename)
	}
	err = unix.Renameat2(
		ancestorFD,
		temporaryName,
		ancestorFD,
		name,
		unix.RENAME_NOREPLACE,
	)
	if errors.Is(err, unix.EEXIST) {
		_ = unix.Close(returnFD)
		returnFD = -1
		if err := unix.Unlinkat(
			ancestorFD,
			temporaryName,
			unix.AT_REMOVEDIR,
		); err != nil {
			return -1, err
		}
		temporaryName = ""
		return unix.Openat(
			ancestorFD,
			name,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
	}
	if err != nil {
		return -1, err
	}
	temporaryName = ""
	if boundary != nil {
		boundary(socketBoundaryParentRenamed)
	}
	if err := syncDirectoryDescriptor(ancestorFD); err != nil {
		return -1, err
	}
	return returnFD, nil
}

func safeRootRegular(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		stat.Mode&0o777 == 0o600 &&
		stat.Uid == 0 &&
		stat.Gid == 0 &&
		stat.Nlink == 1
}

func safeRootLock(stat unix.Stat_t) bool {
	return safeRootRegular(stat) && stat.Size == 0
}

func ensureSocketLockFile(parent parentHandle) error {
	createErr := durablefile.CreateOnly(socketLockPath(parent), nil)
	if createErr != nil &&
		!errors.Is(createErr, os.ErrExist) &&
		!errors.Is(createErr, durablefile.ErrCommitUncertain) {
		return ErrUnsafeSocket
	}
	name := socketSidecarName(parent, ".lock")
	var stat unix.Stat_t
	err := unix.Fstatat(parent.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil || !safeRootLock(stat) {
		return ErrUnsafeSocket
	}
	if errors.Is(createErr, durablefile.ErrCommitUncertain) {
		if err := syncDirectoryDescriptor(parent.fd); err != nil {
			return err
		}
	}
	return nil
}

func acquireSocketLock(parent parentHandle) (*durablefile.Journal, error) {
	if err := ensureSocketLockFile(parent); err != nil {
		return nil, err
	}
	lock, err := durablefile.NewJournal(
		socketLockPath(parent),
		durablefile.WithMaxFrame(1),
	)
	if errors.Is(err, durablefile.ErrJournalLocked) {
		return nil, ErrSocketInUse
	}
	if err != nil {
		return nil, err
	}
	name := socketSidecarName(parent, ".lock")
	var stat unix.Stat_t
	if err := unix.Fstatat(
		parent.fd,
		name,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil || !safeRootLock(stat) {
		_ = lock.Close()
		return nil, ErrUnsafeSocket
	}
	return lock, nil
}

func newSocketGeneration() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func encodeSocketOwner(marker socketOwnerMarker) ([]byte, error) {
	if err := marker.Validate(); err != nil {
		return nil, err
	}
	raw, err := contracts.CanonicalJSON(marker)
	if err != nil || len(raw) == 0 || len(raw) > socketOwnerMaxBytes {
		return nil, ErrUnsafeSocket
	}
	return raw, nil
}

func decodeSocketOwner(raw []byte) (socketOwnerMarker, error) {
	if len(raw) == 0 || len(raw) > socketOwnerMaxBytes {
		return socketOwnerMarker{}, ErrUnsafeSocket
	}
	marker, err := contracts.DecodeStrict[socketOwnerMarker](
		bytes.NewReader(raw),
		socketOwnerMaxBytes,
	)
	if err != nil {
		return socketOwnerMarker{}, ErrUnsafeSocket
	}
	return marker, nil
}

func readSocketOwner(parent parentHandle) (socketOwnerMarker, error) {
	name := socketSidecarName(parent, ".owner.json")
	var before unix.Stat_t
	if err := unix.Fstatat(
		parent.fd,
		name,
		&before,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return socketOwnerMarker{}, os.ErrNotExist
		}
		return socketOwnerMarker{}, ErrUnsafeSocket
	}
	if !safeRootRegular(before) ||
		before.Size <= 0 ||
		before.Size > socketOwnerMaxBytes {
		return socketOwnerMarker{}, ErrUnsafeSocket
	}
	fd, err := unix.Openat(
		parent.fd,
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return socketOwnerMarker{}, ErrUnsafeSocket
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return socketOwnerMarker{}, ErrUnsafeSocket
	}
	defer file.Close()
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil ||
		!safeRootRegular(after) ||
		before.Dev != after.Dev ||
		before.Ino != after.Ino ||
		before.Size != after.Size {
		return socketOwnerMarker{}, ErrUnsafeSocket
	}
	raw, err := io.ReadAll(io.LimitReader(file, socketOwnerMaxBytes+1))
	if err != nil || len(raw) > socketOwnerMaxBytes {
		return socketOwnerMarker{}, ErrUnsafeSocket
	}
	return decodeSocketOwner(raw)
}

func saveSocketOwner(
	parent parentHandle,
	marker socketOwnerMarker,
) (returnErr error) {
	raw, err := encodeSocketOwner(marker)
	if err != nil {
		return err
	}
	var temporaryName string
	var temporary *os.File
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		if temporaryName != "" {
			_ = unix.Unlinkat(parent.fd, temporaryName, 0)
		}
	}()
	for range 32 {
		generation, generationErr := newSocketGeneration()
		if generationErr != nil {
			return generationErr
		}
		temporaryName = socketSidecarName(
			parent,
			".owner.tmp-"+generation,
		)
		fd, openErr := unix.Openat(
			parent.fd,
			temporaryName,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0o600,
		)
		if openErr == nil {
			temporary = os.NewFile(uintptr(fd), temporaryName)
			if temporary == nil {
				_ = unix.Close(fd)
				return ErrUnsafeSocket
			}
			break
		}
		if !errors.Is(openErr, unix.EEXIST) {
			return openErr
		}
		temporaryName = ""
	}
	if temporary == nil {
		return ErrUnsafeSocket
	}
	fd := int(temporary.Fd())
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return err
	}
	written := 0
	for written < len(raw) {
		count, writeErr := temporary.Write(raw[written:])
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
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		!safeRootRegular(stat) ||
		stat.Size != int64(len(raw)) {
		return ErrUnsafeSocket
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporary = nil
	if err := unix.Renameat(
		parent.fd,
		temporaryName,
		parent.fd,
		socketSidecarName(parent, ".owner.json"),
	); err != nil {
		return err
	}
	temporaryName = ""
	if err := syncDirectoryDescriptor(parent.fd); err != nil {
		return err
	}
	persisted, err := readSocketOwner(parent)
	if err != nil || persisted != marker {
		return ErrUnsafeSocket
	}
	return nil
}

func removeSocketOwner(
	parent parentHandle,
	expected socketOwnerMarker,
) error {
	current, err := readSocketOwner(parent)
	if err != nil || current != expected {
		return ErrUnsafeSocket
	}
	if err := unix.Unlinkat(
		parent.fd,
		socketSidecarName(parent, ".owner.json"),
		0,
	); err != nil {
		return err
	}
	return syncDirectoryDescriptor(parent.fd)
}
