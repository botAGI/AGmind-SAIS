package durablefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrUnsafePath = errors.New("unsafe filesystem path")
var ErrCommitUncertain = errors.New("filesystem commit durability uncertain")

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

// defaultRegularMode is the mode files this package WRITES always carry: AtomicWrite chmods to
// 0600. Readers of self-written runtime state keep exactly this expectation.
const defaultRegularMode = 0o600

func regularSingleLink(stat unix.Stat_t) bool {
	return regularSingleLinkModes(stat, defaultRegularMode)
}

// regularSingleLinkModes is regularSingleLink with an explicit mode allowlist, for artifacts this
// package did not write. The installer ships root-owned files read-only (0400) and non-secret
// configs world-readable (0444); demanding 0600 from them made observerd unable to load its own
// config on a real host. Every other property — regular file, single link, owned by the reading
// euid, reached through a secure nofollow parent walk — is unchanged.
func regularSingleLinkModes(stat unix.Stat_t, allowed ...uint32) bool {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Nlink != 1 ||
		stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	perm := stat.Mode & 0o777
	for _, mode := range allowed {
		if perm == mode {
			return true
		}
	}
	return false
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
	if err := syncDirectoryFD(parent.fd); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

type CreateOnlyBoundary string

const (
	CreateOnlyTempCreated       CreateOnlyBoundary = "temp_created"
	CreateOnlyPayloadWritten    CreateOnlyBoundary = "payload_written"
	CreateOnlyFileSynced        CreateOnlyBoundary = "file_synced"
	CreateOnlyRenamedPreDirSync CreateOnlyBoundary = "renamed_pre_dirsync"
	CreateOnlyDirSynced         CreateOnlyBoundary = "dir_synced"
)

type createOnlyOptions struct {
	boundaryHook func(CreateOnlyBoundary)
}

type CreateOnlyOption interface {
	applyCreateOnly(*createOnlyOptions)
}

type createOnlyOptionFunc func(*createOnlyOptions)

func (option createOnlyOptionFunc) applyCreateOnly(options *createOnlyOptions) {
	option(options)
}

// WithCreateOnlyBoundaryHook observes completed publication boundaries. It is
// intended for process-crash verification; the hook runs synchronously while
// CreateOnly still owns its file and directory descriptors.
func WithCreateOnlyBoundaryHook(
	hook func(CreateOnlyBoundary),
) CreateOnlyOption {
	return createOnlyOptionFunc(func(options *createOnlyOptions) {
		options.boundaryHook = hook
	})
}

// CreateOnly durably publishes a complete mode-0600 file without ever
// replacing an existing name. The final name appears only after the temporary
// file has been fully written and synced.
func CreateOnly(
	path string,
	payload []byte,
	options ...CreateOnlyOption,
) error {
	config := createOnlyOptions{}
	for _, option := range options {
		if option == nil {
			return fmt.Errorf("nil create-only option")
		}
		option.applyCreateOnly(&config)
	}
	return createOnlyWithOps(path, payload, createOnlyOps{
		syncFile:        func(file *os.File) error { return file.Sync() },
		renameNoReplace: renameNoReplace,
		syncDir:         syncDirectoryFD,
		boundaryHook:    config.boundaryHook,
	})
}

type createOnlyOps struct {
	syncFile        func(*os.File) error
	renameNoReplace func(int, string, int, string) error
	syncDir         func(int) error
	boundaryHook    func(CreateOnlyBoundary)
}

func createOnlyWithOps(
	path string,
	payload []byte,
	operations createOnlyOps,
) (returnErr error) {
	if operations.syncFile == nil ||
		operations.renameNoReplace == nil ||
		operations.syncDir == nil {
		return fmt.Errorf("invalid create-only operations")
	}
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
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if operations.boundaryHook != nil {
		operations.boundaryHook(CreateOnlyTempCreated)
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
	if operations.boundaryHook != nil {
		operations.boundaryHook(CreateOnlyPayloadWritten)
	}
	if err := operations.syncFile(temporary); err != nil {
		return err
	}
	if operations.boundaryHook != nil {
		operations.boundaryHook(CreateOnlyFileSynced)
	}
	var temporaryStat unix.Stat_t
	if err := unix.Fstat(int(temporary.Fd()), &temporaryStat); err != nil {
		return err
	}
	if !regularSingleLink(temporaryStat) ||
		temporaryStat.Size != int64(len(payload)) {
		return ErrUnsafePath
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporary = nil
	if err := operations.renameNoReplace(
		parent.fd,
		temporaryName,
		parent.fd,
		parent.base,
	); err != nil {
		return err
	}
	temporaryName = ""
	finalStat, err := statDestination(parent)
	if err != nil ||
		!regularSingleLink(finalStat) ||
		finalStat.Dev != temporaryStat.Dev ||
		finalStat.Ino != temporaryStat.Ino ||
		finalStat.Size != temporaryStat.Size {
		return ErrUnsafePath
	}
	if operations.boundaryHook != nil {
		operations.boundaryHook(CreateOnlyRenamedPreDirSync)
	}
	if err := operations.syncDir(parent.fd); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	if operations.boundaryHook != nil {
		operations.boundaryHook(CreateOnlyDirSynced)
	}
	return nil
}

// PromoteNoReplace atomically moves one private regular file to a new name in
// the same private directory without replacing an existing destination.
func PromoteNoReplace(sourcePath string, destinationPath string) error {
	if filepath.Dir(sourcePath) != filepath.Dir(destinationPath) ||
		filepath.Base(sourcePath) == filepath.Base(destinationPath) {
		return ErrUnsafePath
	}
	source, err := openSecureParent(sourcePath)
	if err != nil {
		return err
	}
	defer unix.Close(source.fd)
	destination, err := openSecureParent(destinationPath)
	if err != nil {
		return err
	}
	defer unix.Close(destination.fd)
	var sourceDirectory unix.Stat_t
	var destinationDirectory unix.Stat_t
	if err := unix.Fstat(source.fd, &sourceDirectory); err != nil {
		return err
	}
	if err := unix.Fstat(destination.fd, &destinationDirectory); err != nil {
		return err
	}
	if sourceDirectory.Dev != destinationDirectory.Dev ||
		sourceDirectory.Ino != destinationDirectory.Ino {
		return ErrUnsafePath
	}
	sourceStat, err := statDestination(source)
	if err != nil || !regularSingleLink(sourceStat) {
		return ErrUnsafePath
	}
	var destinationStat unix.Stat_t
	destinationErr := unix.Fstatat(
		destination.fd,
		destination.base,
		&destinationStat,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	if destinationErr == nil {
		if !regularSingleLink(destinationStat) {
			return ErrUnsafePath
		}
		return os.ErrExist
	}
	if !errors.Is(destinationErr, unix.ENOENT) {
		return ErrUnsafePath
	}
	if err := renameNoReplace(
		source.fd,
		source.base,
		destination.fd,
		destination.base,
	); err != nil {
		return err
	}
	if err := unix.Fstatat(
		destination.fd,
		destination.base,
		&destinationStat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil ||
		!regularSingleLink(destinationStat) ||
		destinationStat.Dev != sourceStat.Dev ||
		destinationStat.Ino != sourceStat.Ino ||
		destinationStat.Size != sourceStat.Size {
		return ErrUnsafePath
	}
	if err := syncDirectoryFD(destination.fd); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

type FileIdentity struct {
	Device uint64
	Inode  uint64
	Size   uint64
}

// ReadRegularIdentity reads one single-link regular file through fd-relative
// nofollow resolution and returns the exact opened inode identity.
func ReadRegularIdentity(
	path string,
	maxBytes int64,
) ([]byte, FileIdentity, error) {
	return readRegularIdentity(path, maxBytes, defaultRegularMode)
}

// readRegularIdentity is ReadRegularIdentity with an explicit mode allowlist. Every caller-facing
// wrapper funnels through here so the secure-parent walk, the nofollow open and the
// re-validation on the OPENED descriptor can never diverge between mode policies.
func readRegularIdentity(
	path string,
	maxBytes int64,
	permitted ...uint32,
) ([]byte, FileIdentity, error) {
	if maxBytes < 1 {
		return nil, FileIdentity{}, fmt.Errorf("maxBytes must be positive")
	}
	if len(permitted) == 0 {
		return nil, FileIdentity{}, fmt.Errorf("mode allowlist must not be empty")
	}
	parent, err := openSecureParent(path)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	defer unix.Close(parent.fd)
	before, err := statDestination(parent)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	if !regularSingleLinkModes(before, permitted...) || before.Size < 0 || before.Size > maxBytes {
		return nil, FileIdentity{}, ErrUnsafePath
	}
	fd, err := unix.Openat(
		parent.fd,
		parent.base,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), parent.base)
	if file == nil {
		_ = unix.Close(fd)
		return nil, FileIdentity{}, fmt.Errorf("failed to own file descriptor")
	}
	defer file.Close()
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, FileIdentity{}, err
	}
	if !regularSingleLinkModes(after, permitted...) ||
		before.Dev != after.Dev ||
		before.Ino != after.Ino {
		return nil, FileIdentity{}, ErrUnsafePath
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, FileIdentity{}, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, FileIdentity{}, ErrUnsafePath
	}
	return raw, FileIdentity{
		Device: uint64(after.Dev),
		Inode:  uint64(after.Ino),
		Size:   uint64(after.Size),
	}, nil
}

// ReadRegular reads one bounded single-link regular file.
func ReadRegular(path string, maxBytes int64) ([]byte, error) {
	raw, _, err := ReadRegularIdentity(path, maxBytes)
	return raw, err
}

// ReadRegularModes reads one installed artifact whose mode this package did not choose, using the
// SAME secure parent walk, nofollow open, single-link/ownership checks and open-descriptor
// re-validation as ReadRegular — only the accepted mode set differs. Use it for files the
// INSTALLER creates; use ReadRegular for state this package wrote itself.
func ReadRegularModes(path string, maxBytes int64, allowed ...fs.FileMode) ([]byte, error) {
	modes, err := normalizeTrustedModes(allowed)
	if err != nil {
		return nil, err
	}
	permitted := make([]uint32, 0, len(modes))
	for _, mode := range modes {
		permitted = append(permitted, uint32(mode.Perm()))
	}
	raw, _, err := readRegularIdentity(path, maxBytes, permitted...)
	return raw, err
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
	if err := syncDirectoryFD(parent.fd); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

// RemoveIfIdentity durably unlinks only the exact previously opened inode.
func RemoveIfIdentity(path string, identity FileIdentity) error {
	return removeIfIdentity(
		path,
		identity,
		syncDirectoryFD,
	)
}

// RemoveIfIdentityWithDirectorySync exposes the post-unlink directory-sync
// boundary for process-crash and commit-uncertainty verification.
func RemoveIfIdentityWithDirectorySync(
	path string,
	identity FileIdentity,
	syncDirectory func() error,
) error {
	if syncDirectory == nil {
		return fmt.Errorf("nil remove directory sync")
	}
	return removeIfIdentity(
		path,
		identity,
		func(int) error { return syncDirectory() },
	)
}

func removeIfIdentity(
	path string,
	identity FileIdentity,
	syncDirectory func(int) error,
) error {
	parent, err := openSecureParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent.fd)
	stat, err := statDestination(parent)
	if err != nil {
		return err
	}
	if !regularSingleLink(stat) ||
		uint64(stat.Dev) != identity.Device ||
		uint64(stat.Ino) != identity.Inode ||
		stat.Size < 0 ||
		uint64(stat.Size) != identity.Size {
		return ErrUnsafePath
	}
	if err := unix.Unlinkat(parent.fd, parent.base, 0); err != nil {
		return err
	}
	if err := syncDirectory(parent.fd); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}
