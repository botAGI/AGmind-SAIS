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

type linuxApplyTargetHandle struct {
	mutex        sync.Mutex
	snapshot     PrepareTargetSnapshot
	fullID       string
	pid          int
	pidfd        int
	pidDirectory int
	netns        int
	hostNetNS    uint64
	closed       bool
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

func (handle *linuxApplyTargetHandle) Snapshot() PrepareTargetSnapshot {
	if handle == nil {
		return PrepareTargetSnapshot{}
	}
	return handle.snapshot
}

func (handle *linuxApplyTargetHandle) NetNSFD() int {
	if handle == nil {
		return -1
	}
	handle.mutex.Lock()
	defer handle.mutex.Unlock()
	if handle.closed || handle.netns < 3 {
		return -1
	}
	return handle.netns
}

func (handle *linuxApplyTargetHandle) HostNetworkNamespaceInode() uint64 {
	if handle == nil {
		return 0
	}
	return handle.hostNetNS
}

func (handle *linuxApplyTargetHandle) Recheck(ctx context.Context) error {
	if handle == nil {
		return ErrTargetStale
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	handle.mutex.Lock()
	defer handle.mutex.Unlock()
	if handle.closed || handle.pidDirectory < 3 || handle.netns < 3 {
		return ErrTargetStale
	}
	if err := pidfdAlive(handle.pidfd); err != nil {
		return err
	}
	facts, err := readLinuxProcessFacts(handle.pidDirectory, handle.pid, handle.fullID)
	if err != nil {
		return err
	}
	currentNetNS, err := currentNetworkNamespaceInode(handle.pidDirectory)
	if err != nil {
		return err
	}
	cgroupDigest := sha256.Sum256([]byte(facts.cgroupPath))
	var stat unix.Stat_t
	if err := unix.Fstat(handle.netns, &stat); err != nil || stat.Ino == 0 ||
		stat.Ino != handle.snapshot.NetworkNamespaceInode ||
		currentNetNS != handle.snapshot.NetworkNamespaceInode ||
		handle.snapshot.NetworkNamespaceInode == handle.hostNetNS ||
		facts.startTicks != handle.snapshot.PIDStartTicks ||
		hex.EncodeToString(cgroupDigest[:]) != handle.snapshot.CgroupPathSHA256 ||
		facts.capNetAdmin != handle.snapshot.EffectiveCapNetAdmin {
		return errors.Join(ErrTargetStale, err)
	}
	currentHost, err := platformHostNetworkNamespaceInode()
	if err != nil || currentHost != handle.hostNetNS {
		return errors.Join(ErrTargetStale, err)
	}
	return ctx.Err()
}

func (handle *linuxApplyTargetHandle) Close() error {
	if handle == nil {
		return nil
	}
	handle.mutex.Lock()
	defer handle.mutex.Unlock()
	if handle.closed {
		return nil
	}
	handle.closed = true
	netns, pidDirectory, pidfd := handle.netns, handle.pidDirectory, handle.pidfd
	handle.netns, handle.pidDirectory, handle.pidfd = -1, -1, -1
	var netnsErr, directoryErr, pidfdErr error
	if netns >= 0 {
		netnsErr = unix.Close(netns)
	}
	if pidDirectory >= 0 {
		directoryErr = unix.Close(pidDirectory)
	}
	if pidfd >= 0 {
		pidfdErr = unix.Close(pidfd)
	}
	return errors.Join(netnsErr, directoryErr, pidfdErr)
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
	bootIDRaw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ClockSample{}, fmt.Errorf("read kernel boot ID: %w", err)
	}
	if len(bootIDRaw) != 37 || bootIDRaw[36] != '\n' {
		return ClockSample{}, fmt.Errorf("invalid kernel boot ID")
	}
	bootID := string(bootIDRaw[:36])
	if !bootIDPattern.MatchString(bootID) {
		return ClockSample{}, fmt.Errorf("invalid kernel boot ID")
	}
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
		BootID:     bootID,
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

func currentNetworkNamespaceInode(pidDirectory int) (uint64, error) {
	nsDirectory, err := openProcDirectory(pidDirectory, "ns")
	if err != nil {
		return 0, err
	}
	defer closeFD(nsDirectory)
	netns, inode, err := openNetworkNamespace(nsDirectory)
	if err != nil {
		return 0, err
	}
	closeFD(netns)
	return inode, nil
}

func platformHostNetworkNamespaceInode() (uint64, error) {
	fd, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer closeFD(fd)
	var stat unix.Stat_t
	var statfs unix.Statfs_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Ino == 0 {
		return 0, errors.Join(ErrTargetStale, err)
	}
	if err := unix.Fstatfs(fd, &statfs); err != nil || statfs.Type != unix.NSFS_MAGIC {
		return 0, errors.Join(ErrTargetStale, err)
	}
	namespaceType, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || namespaceType != unix.CLONE_NEWNET {
		return 0, errors.Join(ErrTargetStale, err)
	}
	return stat.Ino, nil
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
	hostNetNS, err := platformHostNetworkNamespaceInode()
	if err != nil {
		return nil, err
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
	if inode == hostNetNS {
		return nil, errors.Join(ErrTargetStale, fmt.Errorf("host network namespace is forbidden"))
	}
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

func (linuxTargetResolver) OpenForApply(
	ctx context.Context,
	fullID string,
	initPID uint64,
) (ApplyTargetHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !fullDockerIDPattern.MatchString(fullID) || initPID == 0 ||
		initPID > uint64(math.MaxInt) {
		return nil, ErrTargetStale
	}
	hostNetNS, err := platformHostNetworkNamespaceInode()
	if err != nil {
		return nil, err
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
	proc, err := unix.Open(
		"/proc",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
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
	defer func() { closeFD(pidDirectory) }()
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
	if netns < 3 {
		return nil, errors.Join(ErrTargetStale, fmt.Errorf("unsafe network namespace descriptor"))
	}
	if inode == hostNetNS {
		return nil, errors.Join(ErrTargetStale, fmt.Errorf("host network namespace is forbidden"))
	}
	after, err := readLinuxProcessFacts(pidDirectory, pid, fullID)
	if err != nil || before != after {
		return nil, errors.Join(
			ErrTargetStale,
			err,
			fmt.Errorf("process identity changed during apply resolution"),
		)
	}
	if err := pidfdAlive(pidfd); err != nil {
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
	handle := &linuxApplyTargetHandle{
		snapshot:     snapshot,
		fullID:       fullID,
		pid:          pid,
		pidfd:        pidfd,
		pidDirectory: pidDirectory,
		netns:        netns,
		hostNetNS:    hostNetNS,
	}
	pidfd, pidDirectory, netns = -1, -1, -1
	if err := handle.Recheck(ctx); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return handle, nil
}
