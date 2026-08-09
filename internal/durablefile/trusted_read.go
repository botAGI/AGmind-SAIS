package durablefile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"golang.org/x/sys/unix"
)

const trustedRootUID = uint32(0)

func trustedDirectory(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		stat.Uid == trustedRootUID &&
		stat.Mode&0o022 == 0
}

func trustedRegular(stat unix.Stat_t, allowedModes []fs.FileMode) bool {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != trustedRootUID ||
		stat.Nlink != 1 ||
		stat.Size < 0 {
		return false
	}
	mode := fs.FileMode(stat.Mode & 0o7777)
	return slices.Contains(allowedModes, mode)
}

type trustedFileTimes struct {
	modificationSeconds     int64
	modificationNanoseconds int64
	changeSeconds           int64
	changeNanoseconds       int64
}

func reflectedTimespec(
	stat reflect.Value,
	names ...string,
) (int64, int64, bool) {
	for _, name := range names {
		value := stat.FieldByName(name)
		if !value.IsValid() || value.Kind() != reflect.Struct {
			continue
		}
		seconds := value.FieldByName("Sec")
		nanoseconds := value.FieldByName("Nsec")
		if !seconds.IsValid() || !seconds.CanInt() ||
			!nanoseconds.IsValid() || !nanoseconds.CanInt() {
			return 0, 0, false
		}
		return seconds.Int(), nanoseconds.Int(), true
	}
	return 0, 0, false
}

func trustedTimes(stat unix.Stat_t) (trustedFileTimes, bool) {
	value := reflect.ValueOf(stat)
	modificationSeconds, modificationNanoseconds, modificationOK := reflectedTimespec(
		value,
		"Mtim",
		"Mtimespec",
	)
	changeSeconds, changeNanoseconds, changeOK := reflectedTimespec(
		value,
		"Ctim",
		"Ctimespec",
	)
	if !modificationOK || !changeOK {
		return trustedFileTimes{}, false
	}
	return trustedFileTimes{
		modificationSeconds:     modificationSeconds,
		modificationNanoseconds: modificationNanoseconds,
		changeSeconds:           changeSeconds,
		changeNanoseconds:       changeNanoseconds,
	}, true
}

func sameTrustedFileVersion(first, second unix.Stat_t) bool {
	firstTimes, firstOK := trustedTimes(first)
	secondTimes, secondOK := trustedTimes(second)
	return firstOK && secondOK && firstTimes == secondTimes
}

func normalizeTrustedModes(values []fs.FileMode) ([]fs.FileMode, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: trusted file mode allowlist is empty", ErrUnsafePath)
	}
	normalized := make([]fs.FileMode, 0, len(values))
	for _, value := range values {
		if value == 0 || value != value.Perm() || slices.Contains(normalized, value) {
			return nil, fmt.Errorf("%w: invalid exact trusted file mode", ErrUnsafePath)
		}
		normalized = append(normalized, value)
	}
	return normalized, nil
}

// ReadTrustedRoot reads one bounded root-owned regular file after resolving
// every path component through nofollow descriptors. Every directory must be
// root-owned and not group/world-writable; the file must have one link and one
// of the exact caller-provided modes.
func ReadTrustedRoot(
	path string,
	maxBytes int64,
	allowedModes ...fs.FileMode,
) ([]byte, error) {
	if maxBytes < 1 {
		return nil, fmt.Errorf("%w: maxBytes must be positive", ErrUnsafePath)
	}
	modes, err := normalizeTrustedModes(allowedModes)
	if err != nil {
		return nil, err
	}
	parts, err := splitSecureAbsolute(path)
	if err != nil || len(parts) == 0 {
		return nil, ErrUnsafePath
	}
	current, err := unix.Open(
		string(filepath.Separator),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(current) }()
	var rootStat unix.Stat_t
	if err := unix.Fstat(current, &rootStat); err != nil || !trustedDirectory(rootStat) {
		return nil, errors.Join(ErrUnsafePath, err)
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(
			current,
			part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if openErr != nil {
			return nil, errors.Join(ErrUnsafePath, openErr)
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(next, &stat)
		if statErr != nil || !trustedDirectory(stat) {
			_ = unix.Close(next)
			return nil, errors.Join(ErrUnsafePath, statErr)
		}
		_ = unix.Close(current)
		current = next
	}

	var before unix.Stat_t
	if err := unix.Fstatat(
		current,
		parts[len(parts)-1],
		&before,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return nil, errors.Join(ErrUnsafePath, err)
	}
	if !trustedRegular(before, modes) || before.Size > maxBytes {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Openat(
		current,
		parts[len(parts)-1],
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errors.Join(ErrUnsafePath, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to own trusted file descriptor")
	}
	defer file.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil ||
		!trustedRegular(opened, modes) ||
		before.Dev != opened.Dev ||
		before.Ino != opened.Ino ||
		before.Size != opened.Size ||
		before.Mode != opened.Mode ||
		!sameTrustedFileVersion(before, opened) {
		return nil, errors.Join(ErrUnsafePath, err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes || int64(len(raw)) != opened.Size {
		return nil, ErrUnsafePath
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil ||
		!trustedRegular(after, modes) ||
		opened.Dev != after.Dev ||
		opened.Ino != after.Ino ||
		opened.Size != after.Size ||
		opened.Mode != after.Mode ||
		!sameTrustedFileVersion(opened, after) {
		return nil, errors.Join(ErrUnsafePath, err)
	}
	return slices.Clone(raw), nil
}
