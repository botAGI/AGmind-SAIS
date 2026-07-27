//go:build linux

package uds

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var umaskMutex sync.Mutex

const (
	peerGroupsInitial = 16
	peerGroupsMax     = 256
)

type syscallConnection interface {
	SyscallConn() (syscall.RawConn, error)
}

type socketPeerGroupsReader func(int) ([]uint32, error)

type socketPeerGroupsCall func(int, []uint32) (uint32, error)

func callSocketPeerGroups(fd int, groups []uint32) (uint32, error) {
	if fd < 0 || len(groups) == 0 {
		return 0, ErrInvalidPeer
	}
	length := uint32(len(groups) * 4)
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_SOCKET),
		uintptr(unix.SO_PEERGROUPS),
		uintptr(unsafe.Pointer(&groups[0])),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	runtime.KeepAlive(groups)
	if errno != 0 {
		return length, errno
	}
	return length, nil
}

func readSocketPeerGroupsWith(
	fd int,
	call socketPeerGroupsCall,
) ([]uint32, error) {
	if fd < 0 || call == nil {
		return nil, ErrInvalidPeer
	}
	groups := make([]uint32, peerGroupsInitial)
	for attempt := 0; attempt < 2; attempt++ {
		length, err := call(fd, groups)
		if err != nil && !errors.Is(err, unix.ERANGE) {
			return nil, err
		}
		if length%4 != 0 {
			if errors.Is(err, unix.ERANGE) {
				return nil, unix.ERANGE
			}
			return nil, ErrInvalidPeer
		}
		count := int(length / 4)
		if count > peerGroupsMax {
			if errors.Is(err, unix.ERANGE) {
				return nil, unix.ERANGE
			}
			return nil, ErrInvalidPeer
		}
		if err == nil {
			if count > len(groups) {
				return nil, ErrInvalidPeer
			}
			return append([]uint32(nil), groups[:count]...), nil
		}
		if count <= len(groups) {
			return nil, unix.ERANGE
		}
		if attempt == 1 {
			return nil, unix.ERANGE
		}
		groups = make([]uint32, count)
	}
	return nil, unix.ERANGE
}

func readSocketPeerGroups(fd int) ([]uint32, error) {
	return readSocketPeerGroupsWith(fd, callSocketPeerGroups)
}

func applySocketPeerGroups(
	peer Peer,
	groups []uint32,
	groupErr error,
) (Peer, error) {
	if groupErr != nil {
		if errors.Is(groupErr, unix.ENOPROTOOPT) ||
			errors.Is(groupErr, unix.EOPNOTSUPP) ||
			errors.Is(groupErr, unix.ERANGE) {
			// SO_PEERCRED remains authoritative. Supplementary-only
			// authorization fails closed when the socket option is absent or
			// the bounded capture cannot contain the peer's group list.
			return peer, nil
		}
		return Peer{}, ErrInvalidPeer
	}
	if len(groups) > peerGroupsMax {
		return Peer{}, ErrInvalidPeer
	}
	peer.supplementaryGroups = append([]uint32(nil), groups...)
	peer.supplementaryGroupsCaptured = true
	return peer, nil
}

func peerCredentialsFromFD(
	fd int,
	readGroups socketPeerGroupsReader,
) (Peer, error) {
	if readGroups == nil {
		return Peer{}, ErrInvalidPeer
	}
	credentials, err := unix.GetsockoptUcred(
		fd,
		unix.SOL_SOCKET,
		unix.SO_PEERCRED,
	)
	if err != nil || credentials == nil || credentials.Pid <= 0 {
		return Peer{}, ErrInvalidPeer
	}
	peer := Peer{
		PID: credentials.Pid,
		UID: credentials.Uid,
		GID: credentials.Gid,
	}
	groups, groupErr := readGroups(fd)
	return applySocketPeerGroups(peer, groups, groupErr)
}

// PeerCredentials captures process and supplementary group credentials from
// the accepted Unix socket. No PID-indexed process metadata is consulted.
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
	var peer Peer
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		peer, socketErr = peerCredentialsFromFD(
			int(fd),
			readSocketPeerGroups,
		)
	}); err != nil {
		return Peer{}, ErrInvalidPeer
	}
	if socketErr != nil || peer.PID <= 0 {
		return Peer{}, ErrInvalidPeer
	}
	return peer, nil
}

// PeerInGroup trusts only the primary GID from SO_PEERCRED and supplementary
// groups captured by SO_PEERGROUPS on the accepted socket.
func PeerInGroup(peer Peer, group uint32) (bool, error) {
	if peer.GID == group {
		return true, nil
	}
	return peer.inSupplementaryGroup(group), nil
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

func openParent(path string, gid int) (parentHandle, error) {
	return openParentWithBoundary(path, gid, nil)
}

func openParentWithBoundary(
	path string,
	gid int,
	boundary func(socketOwnershipBoundary),
) (parentHandle, error) {
	if os.Geteuid() != 0 || gid < 0 || int(uint32(gid)) != gid {
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
		final := index == len(parts)-2
		next, openErr := unix.Openat(
			current,
			part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if openErr != nil && errors.Is(openErr, unix.ENOENT) && final {
			next, openErr = publishSocketParent(current, part, gid, boundary)
		}
		if openErr != nil {
			return fail(ErrUnsafeSocket)
		}
		if final {
			var stat unix.Stat_t
			if err := unix.Fstat(next, &stat); err != nil {
				_ = unix.Close(next)
				return fail(err)
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
				stat.Uid != 0 ||
				stat.Gid != uint32(gid) ||
				stat.Mode&0o777 != 0o750 {
				_ = unix.Close(next)
				return fail(ErrUnsafeSocket)
			}
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
		stat.Gid != uint32(gid) ||
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

func pendingSocketSafe(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFSOCK &&
		stat.Uid == 0 &&
		stat.Nlink == 1
}

func activeSocketSafe(stat unix.Stat_t, mode os.FileMode, gid int) bool {
	return pendingSocketSafe(stat) &&
		stat.Gid == uint32(gid) &&
		stat.Mode&0o777 == uint32(mode.Perm())
}

func listenOwned(path string, mode os.FileMode, gid int) (*ownedListener, error) {
	return listenOwnedWithOptions(path, mode, gid, listenOwnedOptions{})
}

func listenOwnedWithOptions(
	path string,
	mode os.FileMode,
	gid int,
	options listenOwnedOptions,
) (*ownedListener, error) {
	if mode != 0o600 && mode != 0o660 ||
		gid < 0 ||
		int(uint32(gid)) != gid {
		return nil, ErrUnsafeSocket
	}
	parent, err := openParentWithBoundary(path, gid, options.boundary)
	if err != nil {
		return nil, err
	}
	lock, err := acquireSocketLock(parent)
	if err != nil {
		_ = unix.Close(parent.fd)
		return nil, err
	}
	var releaseOnce sync.Once
	var releaseErr error
	release := func() error {
		releaseOnce.Do(func() {
			lockErr := lock.Close()
			closeErr := unix.Close(parent.fd)
			parent.fd = -1
			releaseErr = errors.Join(lockErr, closeErr)
		})
		return releaseErr
	}
	fail := func(result error) (*ownedListener, error) {
		return nil, errors.Join(result, release())
	}

	marker, markerErr := readSocketOwner(parent)
	markerExists := markerErr == nil
	if markerExists {
		if err := marker.validateFor(parent, mode, gid); err != nil {
			return fail(err)
		}
	} else if !errors.Is(markerErr, os.ErrNotExist) {
		return fail(ErrUnsafeSocket)
	}
	stat, statErr := socketStat(parent)
	if statErr == nil {
		if !markerExists {
			return fail(ErrUnsafeSocket)
		}
		switch marker.State {
		case "pending":
			if !pendingSocketSafe(stat) {
				return fail(ErrUnsafeSocket)
			}
		case "active":
			if !activeSocketSafe(stat, mode, gid) ||
				marker.Device != uint64(stat.Dev) ||
				marker.Inode != uint64(stat.Ino) {
				return fail(ErrUnsafeSocket)
			}
		default:
			return fail(ErrUnsafeSocket)
		}
		if err := unix.Unlinkat(parent.fd, parent.base, 0); err != nil {
			return fail(err)
		}
		if err := syncDirectoryDescriptor(parent.fd); err != nil {
			return fail(err)
		}
		if options.boundary != nil {
			options.boundary(socketBoundaryStaleUnlinked)
		}
	} else if !errors.Is(statErr, unix.ENOENT) {
		return fail(ErrUnsafeSocket)
	}

	generation, err := newSocketGeneration()
	if err != nil {
		return fail(err)
	}
	pending := socketOwnerMarker{
		SchemaVersion: socketOwnerSchema,
		State:         "pending",
		SocketBase:    parent.base,
		Mode:          uint32(mode.Perm()),
		GID:           uint32(gid),
		Generation:    generation,
	}
	if err := saveSocketOwner(parent, pending); err != nil {
		return fail(err)
	}
	if options.boundary != nil {
		options.boundary(socketBoundaryPendingWritten)
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
	if options.boundary != nil {
		options.boundary(socketBoundaryBound)
	}
	closeListener := func(result error) (*ownedListener, error) {
		_ = listener.Close()
		return fail(result)
	}
	if err := unix.Fchownat(
		parent.fd,
		parent.base,
		0,
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
		!activeSocketSafe(boundStat, mode, gid) {
		return closeListener(ErrUnsafeSocket)
	}
	if err := syncDirectoryDescriptor(parent.fd); err != nil {
		return closeListener(err)
	}
	if options.boundary != nil {
		options.boundary(socketBoundaryConfigured)
	}
	active := pending
	active.State = "active"
	active.Device = uint64(boundStat.Dev)
	active.Inode = uint64(boundStat.Ino)
	if err := saveSocketOwner(parent, active); err != nil {
		return closeListener(err)
	}
	if options.boundary != nil {
		options.boundary(socketBoundaryActiveWritten)
	}
	device, inode := boundStat.Dev, boundStat.Ino
	var removeOnce sync.Once
	var removeErr error
	remove := func() error {
		removeOnce.Do(func() {
			currentMarker, markerErr := readSocketOwner(parent)
			if markerErr != nil || currentMarker != active {
				removeErr = ErrUnsafeSocket
				removeErr = errors.Join(removeErr, release())
				return
			}
			current, err := socketStat(parent)
			if err == nil &&
				activeSocketSafe(current, mode, gid) &&
				current.Dev == device &&
				current.Ino == inode {
				removeErr = unix.Unlinkat(parent.fd, parent.base, 0)
				if removeErr == nil {
					removeErr = syncDirectoryDescriptor(parent.fd)
				}
				if removeErr == nil {
					removeErr = removeSocketOwner(parent, active)
				}
			} else {
				removeErr = ErrUnsafeSocket
			}
			removeErr = errors.Join(removeErr, release())
		})
		return removeErr
	}
	return &ownedListener{
		listener: listener,
		remove:   remove,
		abandon:  release,
	}, nil
}
