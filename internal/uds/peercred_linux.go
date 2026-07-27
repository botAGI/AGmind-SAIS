//go:build linux

package uds

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

var umaskMutex sync.Mutex

const (
	peerStatusMaxBytes  = 16 * 1024
	peerStatusMaxGroups = 256
)

type syscallConnection interface {
	SyscallConn() (syscall.RawConn, error)
}

func PeerCredentials(connection net.Conn) (Peer, error) {
	if _, ok := connection.LocalAddr().(*net.UnixAddr); !ok {
		return Peer{}, ErrInvalidPeer
	}
	rawConnection, ok := connection.(syscallConnection)
	if !ok {
		return Peer{}, ErrInvalidPeer
	}
	raw, err := rawConnection.SyscallConn()
	if err != nil {
		return Peer{}, ErrInvalidPeer
	}
	var credentials *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	}); err != nil {
		return Peer{}, ErrInvalidPeer
	}
	if socketErr != nil || credentials == nil || credentials.Pid <= 0 {
		return Peer{}, ErrInvalidPeer
	}
	return Peer{
		PID: credentials.Pid,
		UID: credentials.Uid,
		GID: credentials.Gid,
	}, nil
}

func peerInGroupStatus(peer Peer, group uint32, raw []byte) (bool, error) {
	if peer.PID <= 0 ||
		len(raw) == 0 ||
		len(raw) > peerStatusMaxBytes ||
		!utf8.Valid(raw) ||
		strings.IndexByte(string(raw), 0) >= 0 {
		return false, ErrInvalidPeer
	}
	var pidSeen, uidSeen, gidSeen, groupsSeen bool
	member := false
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "Pid:":
			if pidSeen || len(fields) != 2 {
				return false, ErrInvalidPeer
			}
			value, err := strconv.ParseInt(fields[1], 10, 32)
			if err != nil || int32(value) != peer.PID {
				return false, ErrInvalidPeer
			}
			pidSeen = true
		case "Uid:":
			if uidSeen || len(fields) != 5 {
				return false, ErrInvalidPeer
			}
			for _, field := range fields[1:] {
				value, err := strconv.ParseUint(field, 10, 32)
				if err != nil || uint32(value) != peer.UID {
					return false, ErrInvalidPeer
				}
			}
			uidSeen = true
		case "Gid:":
			if gidSeen || len(fields) != 5 {
				return false, ErrInvalidPeer
			}
			for _, field := range fields[1:] {
				value, err := strconv.ParseUint(field, 10, 32)
				if err != nil || uint32(value) != peer.GID {
					return false, ErrInvalidPeer
				}
			}
			gidSeen = true
		case "Groups:":
			if groupsSeen ||
				len(fields) < 2 ||
				len(fields)-1 > peerStatusMaxGroups {
				return false, ErrInvalidPeer
			}
			for _, field := range fields[1:] {
				value, err := strconv.ParseUint(field, 10, 32)
				if err != nil {
					return false, ErrInvalidPeer
				}
				member = member || uint32(value) == group
			}
			groupsSeen = true
		}
	}
	if !pidSeen || !uidSeen || !gidSeen || !groupsSeen {
		return false, ErrInvalidPeer
	}
	return member, nil
}

// PeerInGroup verifies a supplementary group through a bounded parse of the
// kernel-owned /proc status for the SO_PEERCRED PID. Request headers are never
// consulted.
func PeerInGroup(peer Peer, group uint32) (bool, error) {
	if peer.PID <= 0 {
		return false, ErrInvalidPeer
	}
	file, err := os.Open(
		"/proc/" + strconv.FormatInt(int64(peer.PID), 10) + "/status",
	)
	if err != nil {
		return false, ErrInvalidPeer
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, peerStatusMaxBytes+1))
	if err != nil {
		return false, ErrInvalidPeer
	}
	return peerInGroupStatus(peer, group, raw)
}

type parentHandle struct {
	fd   int
	path string
	base string
}

func splitAbsolute(path string) ([]string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || absolute != filepath.Clean(path) || !filepath.IsAbs(path) {
		return nil, ErrUnsafeSocket
	}
	parts := strings.Split(strings.TrimPrefix(absolute, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, ErrUnsafeSocket
		}
	}
	return parts, nil
}

func openParent(path string) (parentHandle, error) {
	if os.Geteuid() != 0 {
		return parentHandle{}, ErrUnsupportedPlatform
	}
	parts, err := splitAbsolute(path)
	if err != nil || len(parts) < 2 {
		return parentHandle{}, ErrUnsafeSocket
	}
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return parentHandle{}, err
	}
	fail := func(result error) (parentHandle, error) {
		_ = unix.Close(current)
		return parentHandle{}, result
	}
	for index, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(
			current,
			part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if openErr != nil && errors.Is(openErr, unix.ENOENT) &&
			index == len(parts)-2 {
			if mkdirErr := unix.Mkdirat(current, part, 0o750); mkdirErr != nil {
				return fail(ErrUnsafeSocket)
			}
			next, openErr = unix.Openat(
				current,
				part,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
				0,
			)
			if openErr == nil {
				_ = unix.Fchmod(next, 0o750)
				_ = unix.Fchown(next, 0, 0)
			}
		}
		if openErr != nil {
			return fail(ErrUnsafeSocket)
		}
		_ = unix.Close(current)
		current = next
	}
	var stat unix.Stat_t
	if err := unix.Fstat(current, &stat); err != nil {
		return fail(err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != 0 ||
		stat.Mode&0o777 != 0o750 {
		return fail(ErrUnsafeSocket)
	}
	return parentHandle{
		fd:   current,
		path: filepath.Dir(path),
		base: filepath.Base(path),
	}, nil
}

func socketStat(parent parentHandle) (unix.Stat_t, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(parent.fd, parent.base, &stat, unix.AT_SYMLINK_NOFOLLOW)
	return stat, err
}

func existingSocketActive(path string) bool {
	connection, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func listenOwned(path string, mode os.FileMode, gid int) (*ownedListener, error) {
	if mode != 0o600 && mode != 0o660 || gid < 0 {
		return nil, ErrUnsafeSocket
	}
	parent, err := openParent(path)
	if err != nil {
		return nil, err
	}
	fail := func(result error) (*ownedListener, error) {
		_ = unix.Close(parent.fd)
		return nil, result
	}
	if stat, statErr := socketStat(parent); statErr == nil {
		if stat.Mode&unix.S_IFMT != unix.S_IFSOCK ||
			stat.Uid != uint32(os.Geteuid()) ||
			stat.Gid != uint32(gid) ||
			stat.Mode&0o777 != uint32(mode.Perm()) ||
			stat.Nlink != 1 {
			return fail(ErrUnsafeSocket)
		}
		if existingSocketActive(path) {
			return fail(ErrSocketInUse)
		}
		if err := unix.Unlinkat(parent.fd, parent.base, 0); err != nil {
			return fail(ErrUnsafeSocket)
		}
	} else if !errors.Is(statErr, unix.ENOENT) {
		return fail(ErrUnsafeSocket)
	}

	procPath := "/proc/self/fd/" + strconv.Itoa(parent.fd) + "/" + parent.base
	umaskMutex.Lock()
	previousMask := syscall.Umask(0o077)
	listener, listenErr := net.ListenUnix("unix", &net.UnixAddr{Name: procPath, Net: "unix"})
	syscall.Umask(previousMask)
	umaskMutex.Unlock()
	if listenErr != nil {
		return fail(fmt.Errorf("%w: bind failed", ErrUnsafeSocket))
	}
	listener.SetUnlinkOnClose(false)
	closeListener := func(result error) (*ownedListener, error) {
		_ = listener.Close()
		_ = unix.Unlinkat(parent.fd, parent.base, 0)
		return fail(result)
	}
	if err := unix.Fchownat(
		parent.fd,
		parent.base,
		os.Geteuid(),
		gid,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return closeListener(ErrUnsafeSocket)
	}
	if err := unix.Fchmodat(parent.fd, parent.base, uint32(mode.Perm()), 0); err != nil {
		return closeListener(ErrUnsafeSocket)
	}
	boundStat, err := socketStat(parent)
	if err != nil ||
		boundStat.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		boundStat.Uid != uint32(os.Geteuid()) ||
		boundStat.Gid != uint32(gid) ||
		boundStat.Mode&0o777 != uint32(mode.Perm()) ||
		boundStat.Nlink != 1 {
		return closeListener(ErrUnsafeSocket)
	}
	device, inode := boundStat.Dev, boundStat.Ino
	var removeOnce sync.Once
	var removeErr error
	remove := func() error {
		removeOnce.Do(func() {
			current, err := socketStat(parent)
			if err == nil && current.Dev == device && current.Ino == inode {
				removeErr = unix.Unlinkat(parent.fd, parent.base, 0)
				if removeErr == nil {
					directory := os.NewFile(uintptr(parent.fd), parent.path)
					if directory != nil {
						removeErr = directory.Sync()
						_ = directory.Close()
						parent.fd = -1
					}
				}
			} else if err != nil && !errors.Is(err, unix.ENOENT) {
				removeErr = ErrUnsafeSocket
			}
			if parent.fd >= 0 {
				closeErr := unix.Close(parent.fd)
				removeErr = errors.Join(removeErr, closeErr)
				parent.fd = -1
			}
		})
		return removeErr
	}
	return &ownedListener{listener: listener, remove: remove}, nil
}
