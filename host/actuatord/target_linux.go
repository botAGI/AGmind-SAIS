//go:build linux

package actuatord

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	maxProcIdentityBytes = 64 * 1024
	capNetAdminBit       = uint64(1) << 12
)

type linuxTargetResolver struct{}

type linuxPrepareTargetHandle struct {
	mutex    sync.Mutex
	snapshot PrepareTargetSnapshot
	pidfd    int
	netns    int
	closed   bool
}

func (handle *linuxPrepareTargetHandle) Snapshot() PrepareTargetSnapshot {
	if handle == nil {
		return PrepareTargetSnapshot{}
	}
	return handle.snapshot
}

func (handle *linuxPrepareTargetHandle) Close() error {
	if handle == nil {
		return nil
	}
	handle.mutex.Lock()
	defer handle.mutex.Unlock()
	if handle.closed {
		return nil
	}
	handle.closed = true
	netns := handle.netns
	pidfd := handle.pidfd
	handle.netns = -1
	handle.pidfd = -1
	var netnsErr, pidfdErr error
	if netns >= 0 {
		netnsErr = unix.Close(netns)
	}
	if pidfd >= 0 {
		pidfdErr = unix.Close(pidfd)
	}
	return errors.Join(netnsErr, pidfdErr)
}

type linuxProcessFacts struct {
	startTicks  uint64
	cgroupPath  string
	capNetAdmin bool
}

func NewPlatformTargetResolver() TargetResolver {
	return linuxTargetResolver{}
}

func platformClockSample() (ClockSample, error) {
	var boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return ClockSample{}, err
	}
	if boot.Sec < 0 || boot.Nsec < 0 {
		return ClockSample{}, fmt.Errorf("invalid CLOCK_BOOTTIME sample")
	}
	seconds := uint64(boot.Sec)
	if seconds > (math.MaxUint64-uint64(boot.Nsec))/uint64(time.Second) {
		return ClockSample{}, fmt.Errorf("CLOCK_BOOTTIME overflow")
	}
	return ClockSample{
		Wall:       time.Now().UTC(),
		BootTimeNS: seconds*uint64(time.Second) + uint64(boot.Nsec),
	}, nil
}

func closeFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

func pidfdAlive(fd int) error {
	if fd < 0 {
		return nil
	}
	if err := unix.PidfdSendSignal(fd, 0, nil, 0); err != nil {
		return errors.Join(ErrTargetStale, err)
	}
	return nil
}

func openProcDirectory(parent int, name string) (int, error) {
	fd, err := unix.Openat(
		parent,
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, errors.Join(ErrTargetStale, err)
	}
	return fd, nil
}

func readProcLeaf(pidDirectory int, name string) ([]byte, error) {
	fd, err := unix.Openat(
		pidDirectory,
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errors.Join(ErrTargetStale, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		closeFD(fd)
		return nil, fmt.Errorf("failed to own proc descriptor")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxProcIdentityBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(ErrTargetStale, readErr, closeErr)
	}
	if len(raw) > maxProcIdentityBytes {
		return nil, fmt.Errorf("%w: proc identity exceeds byte limit", ErrTargetStale)
	}
	return raw, nil
}

func parseProcStartTicks(raw []byte, expectedPID int) (uint64, error) {
	if expectedPID <= 0 || len(raw) == 0 || len(raw) > maxProcIdentityBytes ||
		!utf8.Valid(raw) || raw[len(raw)-1] != '\n' {
		return 0, fmt.Errorf("invalid bounded proc stat")
	}
	line := strings.TrimSuffix(string(raw), "\n")
	if strings.ContainsAny(line, "\r\n") ||
		!strings.HasPrefix(line, strconv.Itoa(expectedPID)+" (") {
		return 0, fmt.Errorf("proc stat PID mismatch")
	}
	commandEnd := strings.LastIndex(line, ") ")
	if commandEnd < 3 {
		return 0, fmt.Errorf("malformed proc stat command")
	}
	fields := strings.Fields(line[commandEnd+2:])
	if len(fields) < 20 || len(fields[0]) != 1 {
		return 0, fmt.Errorf("truncated proc stat")
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("invalid proc start ticks")
	}
	return value, nil
}

func parseEffectiveCapNetAdmin(raw []byte) (bool, error) {
	if len(raw) == 0 || len(raw) > maxProcIdentityBytes || !utf8.Valid(raw) {
		return false, fmt.Errorf("invalid bounded proc status")
	}
	var value string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		if value != "" {
			return false, fmt.Errorf("duplicate CapEff")
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "CapEff:" {
			return false, fmt.Errorf("malformed CapEff")
		}
		value = fields[1]
	}
	if value == "" || len(value) > 16 {
		return false, fmt.Errorf("missing CapEff")
	}
	effective, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		return false, fmt.Errorf("invalid CapEff: %w", err)
	}
	return effective&capNetAdminBit != 0, nil
}

func parseDockerCgroupV2(raw []byte, fullID string) (string, error) {
	if !fullDockerIDPattern.MatchString(fullID) || len(raw) == 0 ||
		len(raw) > maxProcIdentityBytes || !utf8.Valid(raw) ||
		raw[len(raw)-1] != '\n' {
		return "", fmt.Errorf("invalid bounded proc cgroup")
	}
	line := strings.TrimSuffix(string(raw), "\n")
	if strings.ContainsAny(line, "\r\n") {
		return "", fmt.Errorf("proc cgroup must have one v2 entry")
	}
	parts := strings.Split(line, ":")
	if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
		return "", fmt.Errorf("proc cgroup is not unified v2")
	}
	path := parts[2]
	if path != "/docker/"+fullID &&
		path != "/system.slice/docker-"+fullID+".scope" {
		return "", fmt.Errorf("proc cgroup does not bind Docker ID")
	}
	return path, nil
}

func readLinuxProcessFacts(pidDirectory, pid int, fullID string) (linuxProcessFacts, error) {
	stat, statErr := readProcLeaf(pidDirectory, "stat")
	status, statusErr := readProcLeaf(pidDirectory, "status")
	cgroup, cgroupErr := readProcLeaf(pidDirectory, "cgroup")
	if err := errors.Join(statErr, statusErr, cgroupErr); err != nil {
		return linuxProcessFacts{}, err
	}
	startTicks, startErr := parseProcStartTicks(stat, pid)
	capability, capErr := parseEffectiveCapNetAdmin(status)
	cgroupPath, pathErr := parseDockerCgroupV2(cgroup, fullID)
	if err := errors.Join(startErr, capErr, pathErr); err != nil {
		return linuxProcessFacts{}, errors.Join(ErrTargetStale, err)
	}
	return linuxProcessFacts{
		startTicks:  startTicks,
		cgroupPath:  cgroupPath,
		capNetAdmin: capability,
	}, nil
}

func openNetworkNamespace(nsDirectory int) (int, uint64, error) {
	// procfs namespace leaves are intentional magic symlinks. Every ancestor is
	// no-follow; this one leaf is followed and then proven to be NSFS.
	fd, err := unix.Openat(nsDirectory, "net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, errors.Join(ErrTargetStale, err)
	}
	var stat unix.Stat_t
	var statfs unix.Statfs_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Ino == 0 ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG {
		closeFD(fd)
		return -1, 0, errors.Join(ErrTargetStale, err)
	}
	if err := unix.Fstatfs(fd, &statfs); err != nil || statfs.Type != unix.NSFS_MAGIC {
		closeFD(fd)
		return -1, 0, errors.Join(ErrTargetStale, err)
	}
	namespaceType, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || namespaceType != unix.CLONE_NEWNET {
		closeFD(fd)
		return -1, 0, errors.Join(ErrTargetStale, err)
	}
	return fd, stat.Ino, nil
}

func (linuxTargetResolver) ResolveForPrepare(
	ctx context.Context,
	fullID string,
	initPID uint64,
) (PrepareTargetHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !fullDockerIDPattern.MatchString(fullID) || initPID == 0 ||
		initPID > uint64(math.MaxInt) {
		return nil, ErrTargetStale
	}
	pid := int(initPID)
	pidfd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ENOSYS) {
		pidfd = -1
	} else if err != nil {
		return nil, errors.Join(ErrTargetStale, err)
	}
	defer func() { closeFD(pidfd) }()
	if err := pidfdAlive(pidfd); err != nil {
		return nil, err
	}

	proc, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer closeFD(proc)
	var procfs unix.Statfs_t
	if err := unix.Fstatfs(proc, &procfs); err != nil ||
		procfs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errors.Join(ErrTargetStale, err)
	}
	pidDirectory, err := openProcDirectory(proc, strconv.Itoa(pid))
	if err != nil {
		return nil, err
	}
	defer closeFD(pidDirectory)
	nsDirectory, err := openProcDirectory(pidDirectory, "ns")
	if err != nil {
		return nil, err
	}
	defer closeFD(nsDirectory)

	before, err := readLinuxProcessFacts(pidDirectory, pid, fullID)
	if err != nil {
		return nil, err
	}
	netns, inode, err := openNetworkNamespace(nsDirectory)
	if err != nil {
		return nil, err
	}
	defer func() { closeFD(netns) }()
	after, err := readLinuxProcessFacts(pidDirectory, pid, fullID)
	if err != nil || before != after {
		return nil, errors.Join(
			ErrTargetStale,
			err,
			fmt.Errorf("process identity changed during resolution"),
		)
	}
	if err := pidfdAlive(pidfd); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cgroupDigest := sha256.Sum256([]byte(before.cgroupPath))
	snapshot := PrepareTargetSnapshot{
		InitPID:               initPID,
		PIDStartTicks:         before.startTicks,
		CgroupPathSHA256:      hex.EncodeToString(cgroupDigest[:]),
		NetworkNamespaceInode: inode,
		EffectiveCapNetAdmin:  before.capNetAdmin,
	}
	if err := snapshot.validate(); err != nil {
		return nil, err
	}
	handle := &linuxPrepareTargetHandle{
		snapshot: snapshot,
		pidfd:    pidfd,
		netns:    netns,
	}
	pidfd = -1
	netns = -1
	return handle, nil
}
