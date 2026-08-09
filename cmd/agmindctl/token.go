//go:build linux || darwin

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	coreAPITokenPath        = "/etc/agmind-sais/secrets/core-api.token"
	coreAPIGroupName        = "agmind-core"
	coreAPITokenRandomBytes = 32
	coreAPITokenMode        = 0o640
)

type coreAPITokenReceipt struct {
	path  string
	keyID string
}

type coreAPITokenParent struct {
	fd   int
	base string
}

func openCoreAPITokenParent(path string, ownerUID, ownerGID int) (coreAPITokenParent, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || !filepath.IsAbs(path) || absolute != filepath.Clean(path) ||
		filepath.Base(path) != "core-api.token" || ownerUID < 0 || int(uint32(ownerUID)) != ownerUID ||
		ownerGID < 0 || int(uint32(ownerGID)) != ownerGID {
		return coreAPITokenParent{}, fmt.Errorf("unsafe Core API token path")
	}
	parts := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) < 2 {
		return coreAPITokenParent{}, fmt.Errorf("unsafe Core API token path")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return coreAPITokenParent{}, fmt.Errorf("unsafe Core API token path")
		}
	}
	current, err := unix.Open(
		string(filepath.Separator),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return coreAPITokenParent{}, err
	}
	fail := func(result error) (coreAPITokenParent, error) {
		_ = unix.Close(current)
		return coreAPITokenParent{}, result
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(
			current,
			part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if openErr != nil {
			return fail(fmt.Errorf("unsafe Core API token parent: %w", openErr))
		}
		_ = unix.Close(current)
		current = next
	}
	var parentStat unix.Stat_t
	if err := unix.Fstat(current, &parentStat); err != nil {
		return fail(err)
	}
	if parentStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		parentStat.Uid != uint32(ownerUID) || parentStat.Gid != uint32(ownerGID) ||
		parentStat.Mode&0o777 != 0o710 {
		return fail(fmt.Errorf("unsafe Core API token parent metadata"))
	}
	return coreAPITokenParent{fd: current, base: parts[len(parts)-1]}, nil
}

func validCoreAPITokenStat(value unix.Stat_t, ownerUID, ownerGID int) bool {
	return ownerUID >= 0 && int(uint32(ownerUID)) == ownerUID &&
		ownerGID >= 0 && int(uint32(ownerGID)) == ownerGID &&
		value.Mode&unix.S_IFMT == unix.S_IFREG &&
		value.Mode&0o777 == coreAPITokenMode &&
		value.Uid == uint32(ownerUID) && value.Gid == uint32(ownerGID) &&
		value.Nlink == 1
}

func coreAPITokenDestinationStat(
	parent coreAPITokenParent,
	ownerUID, ownerGID int,
) (unix.Stat_t, error) {
	var value unix.Stat_t
	if err := unix.Fstatat(parent.fd, parent.base, &value, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unix.Stat_t{}, err
	}
	if !validCoreAPITokenStat(value, ownerUID, ownerGID) {
		return unix.Stat_t{}, fmt.Errorf("existing Core API token is unsafe")
	}
	return value, nil
}

func createCoreAPITokenTemporary(parent coreAPITokenParent) (*os.File, string, error) {
	for range 32 {
		var suffix [16]byte
		if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
			return nil, "", fmt.Errorf("allocate Core API token temporary: %w", err)
		}
		name := ".core-api.token.tmp-" + hex.EncodeToString(suffix[:])
		descriptor, err := unix.Openat(
			parent.fd,
			name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0o600,
		)
		if err == nil {
			file := os.NewFile(uintptr(descriptor), name)
			if file == nil {
				_ = unix.Close(descriptor)
				return nil, "", fmt.Errorf("own Core API token temporary descriptor")
			}
			return file, name, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return nil, "", fmt.Errorf("create Core API token temporary: %w", err)
		}
	}
	return nil, "", fmt.Errorf("allocate Core API token temporary")
}

func syncCoreAPITokenParent(parent coreAPITokenParent) error {
	duplicate, err := unix.Dup(parent.fd)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "core-api-token-parent")
	if directory == nil {
		_ = unix.Close(duplicate)
		return fmt.Errorf("own Core API token parent descriptor")
	}
	defer directory.Close()
	return directory.Sync()
}

func publishCoreAPIToken(
	path string,
	payload []byte,
	ownerUID, ownerGID int,
) (returnErr error) {
	parent, err := openCoreAPITokenParent(path, ownerUID, ownerGID)
	if err != nil {
		return err
	}
	defer unix.Close(parent.fd)
	if _, err := coreAPITokenDestinationStat(parent, ownerUID, ownerGID); err != nil {
		return err
	}
	temporary, temporaryName, err := createCoreAPITokenTemporary(parent)
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
	descriptor := int(temporary.Fd())
	if err := unix.Fchown(descriptor, ownerUID, ownerGID); err != nil {
		return fmt.Errorf("set Core API token owner: %w", err)
	}
	if err := unix.Fchmod(descriptor, coreAPITokenMode); err != nil {
		return fmt.Errorf("set Core API token mode: %w", err)
	}
	written := 0
	for written < len(payload) {
		count, writeErr := temporary.Write(payload[written:])
		if writeErr != nil {
			return fmt.Errorf("write Core API token: %w", writeErr)
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		written += count
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync Core API token: %w", err)
	}
	var temporaryStat unix.Stat_t
	if err := unix.Fstat(descriptor, &temporaryStat); err != nil ||
		!validCoreAPITokenStat(temporaryStat, ownerUID, ownerGID) ||
		temporaryStat.Size != int64(len(payload)) {
		return fmt.Errorf("Core API token temporary metadata is unsafe")
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Core API token temporary: %w", err)
	}
	temporary = nil
	if _, err := coreAPITokenDestinationStat(parent, ownerUID, ownerGID); err != nil {
		return err
	}
	if err := unix.Renameat(parent.fd, temporaryName, parent.fd, parent.base); err != nil {
		return fmt.Errorf("publish Core API token: %w", err)
	}
	temporaryName = ""
	if err := syncCoreAPITokenParent(parent); err != nil {
		return fmt.Errorf("Core API token publication durability is uncertain: %w", err)
	}
	published, err := coreAPITokenDestinationStat(parent, ownerUID, ownerGID)
	if err != nil || published.Dev != temporaryStat.Dev || published.Ino != temporaryStat.Ino ||
		published.Size != int64(len(payload)) {
		return fmt.Errorf("published Core API token metadata is unsafe")
	}
	return nil
}

func rotateCoreAPITokenFile(
	path string,
	ownerUID, ownerGID int,
	entropy io.Reader,
) (coreAPITokenReceipt, error) {
	if entropy == nil {
		return coreAPITokenReceipt{}, fmt.Errorf("Core API token entropy is unavailable")
	}
	randomBytes := make([]byte, coreAPITokenRandomBytes)
	defer clear(randomBytes)
	if _, err := io.ReadFull(entropy, randomBytes); err != nil {
		return coreAPITokenReceipt{}, fmt.Errorf("generate Core API token: %w", err)
	}
	encodedLength := base64.RawURLEncoding.EncodedLen(len(randomBytes))
	payload := make([]byte, encodedLength+1)
	defer clear(payload)
	base64.RawURLEncoding.Encode(payload[:encodedLength], randomBytes)
	payload[encodedLength] = '\n'
	keyHash := sha256.Sum256(payload[:encodedLength])
	if err := publishCoreAPIToken(path, payload, ownerUID, ownerGID); err != nil {
		return coreAPITokenReceipt{}, err
	}
	return coreAPITokenReceipt{
		path:  path,
		keyID: "sha256:" + hex.EncodeToString(keyHash[:]),
	}, nil
}

func renderCoreAPITokenReceipt(writer io.Writer, receipt coreAPITokenReceipt) error {
	if writer == nil || receipt.path == "" || receipt.keyID == "" {
		return fmt.Errorf("invalid Core API token rotation receipt")
	}
	_, err := fmt.Fprintf(
		writer,
		"Core API token path: %s\nKey ID: %s\n",
		receipt.path,
		receipt.keyID,
	)
	return err
}

func rotateCoreAPITokenCommand(writer io.Writer) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("token rotation requires Linux EUID 0")
	}
	group, err := user.LookupGroup(coreAPIGroupName)
	if err != nil {
		return fmt.Errorf("resolve %s group: %w", coreAPIGroupName, err)
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || gid == 0 || strconv.FormatUint(gid, 10) != group.Gid ||
		uint64(int(gid)) != gid {
		return fmt.Errorf("resolve %s group: invalid GID", coreAPIGroupName)
	}
	receipt, err := rotateCoreAPITokenFile(
		coreAPITokenPath,
		0,
		int(gid),
		rand.Reader,
	)
	if err != nil {
		return err
	}
	return renderCoreAPITokenReceipt(writer, receipt)
}
