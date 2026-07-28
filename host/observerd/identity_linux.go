//go:build linux

package observerd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	maxProcIdentityBytes = 64 * 1024
	capNetAdminBit       = uint64(1) << 12
)

type linuxProcessIdentityReader struct{}

func newPlatformProcessIdentityReader() processIdentityReader {
	return linuxProcessIdentityReader{}
}

func parseEffectiveCapNetAdmin(raw []byte) (bool, error) {
	if len(raw) == 0 ||
		len(raw) > maxProcIdentityBytes ||
		!utf8.Valid(raw) {
		return false, fmt.Errorf("invalid bounded proc status")
	}
	var value string
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		if found {
			return false, fmt.Errorf("duplicate CapEff field")
		}
		found = true
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "CapEff:" {
			return false, fmt.Errorf("malformed CapEff field")
		}
		value = fields[1]
	}
	if !found || len(value) == 0 || len(value) > 16 {
		return false, fmt.Errorf("missing or oversized CapEff field")
	}
	effective, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		return false, fmt.Errorf("invalid CapEff field: %w", err)
	}
	return effective&capNetAdminBit != 0, nil
}

func parseProcStartTicks(raw []byte, expectedPID int) (uint64, error) {
	if expectedPID <= 0 ||
		len(raw) == 0 ||
		len(raw) > maxProcIdentityBytes ||
		!utf8.Valid(raw) ||
		raw[len(raw)-1] != '\n' {
		return 0, fmt.Errorf("invalid bounded proc stat")
	}
	line := strings.TrimSuffix(string(raw), "\n")
	if strings.ContainsAny(line, "\r\n") {
		return 0, fmt.Errorf("proc stat contains trailing data")
	}
	prefix := strconv.Itoa(expectedPID) + " ("
	if !strings.HasPrefix(line, prefix) {
		return 0, fmt.Errorf("proc stat PID mismatch")
	}
	commandEnd := strings.LastIndex(line, ") ")
	if commandEnd < len(prefix) {
		return 0, fmt.Errorf("proc stat command is malformed")
	}
	fields := strings.Fields(line[commandEnd+2:])
	// fields[0] is stat field 3 (state), so fields[19] is field 22.
	if len(fields) < 20 || len(fields[0]) != 1 {
		return 0, fmt.Errorf("proc stat is truncated")
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTicks == 0 {
		return 0, fmt.Errorf("invalid proc start ticks")
	}
	return startTicks, nil
}

func parseDockerCgroupV2(raw []byte, fullID string) (string, error) {
	if !dockerIDPattern.MatchString(fullID) ||
		len(raw) == 0 ||
		len(raw) > maxProcIdentityBytes ||
		!utf8.Valid(raw) ||
		raw[len(raw)-1] != '\n' {
		return "", fmt.Errorf("invalid bounded proc cgroup")
	}
	line := strings.TrimSuffix(string(raw), "\n")
	if strings.ContainsAny(line, "\r\n") {
		return "", fmt.Errorf("proc cgroup must contain one v2 entry")
	}
	parts := strings.Split(line, ":")
	if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
		return "", fmt.Errorf("proc cgroup is not unified v2")
	}
	path := parts[2]
	if path != "/docker/"+fullID &&
		path != "/system.slice/docker-"+fullID+".scope" {
		return "", fmt.Errorf("proc cgroup does not bind the exact Docker ID")
	}
	return path, nil
}

func readBoundedProcFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxProcIdentityBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxProcIdentityBytes {
		return nil, fmt.Errorf("proc identity file exceeds explicit byte limit")
	}
	return raw, nil
}

func (linuxProcessIdentityReader) NetworkNamespaceInode(
	pid int,
) (uint64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid init PID")
	}
	file, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return 0, fmt.Errorf("invalid network namespace identity")
	}
	return stat.Ino, nil
}

func (reader linuxProcessIdentityReader) ReadProcessIdentity(
	fullID string,
	pid int,
) (processIdentity, error) {
	if !dockerIDPattern.MatchString(fullID) || pid <= 0 {
		return processIdentity{}, ErrContainerIdentityMismatch
	}
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	statBefore, err := readBoundedProcFile(statPath)
	if err != nil {
		return processIdentity{}, errors.Join(ErrInventoryStale, err)
	}
	statusBefore, err := readBoundedProcFile(statusPath)
	if err != nil {
		return processIdentity{}, errors.Join(ErrInventoryStale, err)
	}
	cgroupBefore, err := readBoundedProcFile(cgroupPath)
	if err != nil {
		return processIdentity{}, errors.Join(ErrInventoryStale, err)
	}
	namespaceBefore, err := reader.NetworkNamespaceInode(pid)
	if err != nil {
		return processIdentity{}, errors.Join(ErrInventoryStale, err)
	}
	statAfter, err := readBoundedProcFile(statPath)
	if err != nil {
		return processIdentity{}, errors.Join(ErrInventoryStale, err)
	}
	statusAfter, err := readBoundedProcFile(statusPath)
	if err != nil {
		return processIdentity{}, errors.Join(ErrInventoryStale, err)
	}
	cgroupAfter, err := readBoundedProcFile(cgroupPath)
	if err != nil {
		return processIdentity{}, errors.Join(ErrInventoryStale, err)
	}
	namespaceAfter, err := reader.NetworkNamespaceInode(pid)
	if err != nil {
		return processIdentity{}, errors.Join(ErrInventoryStale, err)
	}

	startBefore, startErr := parseProcStartTicks(statBefore, pid)
	startAfter, endErr := parseProcStartTicks(statAfter, pid)
	cgroupBeforePath, cgroupErr := parseDockerCgroupV2(
		cgroupBefore,
		fullID,
	)
	cgroupAfterPath, finalCgroupErr := parseDockerCgroupV2(
		cgroupAfter,
		fullID,
	)
	capabilityBefore, capErr := parseEffectiveCapNetAdmin(statusBefore)
	capabilityAfter, finalCapErr := parseEffectiveCapNetAdmin(statusAfter)
	if joined := errors.Join(
		startErr,
		endErr,
		cgroupErr,
		finalCgroupErr,
		capErr,
		finalCapErr,
	); joined != nil {
		return processIdentity{}, errors.Join(ErrInventoryStale, joined)
	}
	if startBefore != startAfter ||
		cgroupBeforePath != cgroupAfterPath ||
		capabilityBefore != capabilityAfter ||
		namespaceBefore != namespaceAfter {
		return processIdentity{}, fmt.Errorf(
			"%w: proc identity changed during read",
			ErrInventoryStale,
		)
	}
	cgroupDigest := sha256.Sum256([]byte(cgroupBeforePath))
	return processIdentity{
		PIDStartTicks:         startBefore,
		CgroupPathSHA256:      hex.EncodeToString(cgroupDigest[:]),
		NetworkNamespaceInode: namespaceBefore,
		EffectiveCapNetAdmin:  capabilityBefore,
	}, nil
}
