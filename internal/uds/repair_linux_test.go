//go:build linux

package uds

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBoundedJSONAppliesMediaTypePolicyToEveryNonemptyMethodBody(t *testing.T) {
	called := false
	handler := boundedJSON(1024, http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		called = true
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(
		http.MethodGet,
		"http://unix/v1/resource",
		strings.NewReader(`{"query":"x"}`),
	)
	request.Header.Set("Content-Type", "text/plain")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType || called {
		t.Fatalf("status=%d handler_called=%v", response.Code, called)
	}
}

func TestExistingOwnedSocketWithoutOwnerIntentIsNeverUnlinked(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "run")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "service.sock")
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chown(path, os.Geteuid(), 0); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if err := unix.Lstat(path, &before); err != nil {
		t.Fatal(err)
	}

	owned, err := listenOwned(path, 0o600, 0)
	if owned != nil {
		_ = owned.listener.Close()
		_ = owned.remove()
		t.Fatal("stale-looking socket was unlinked and replaced")
	}
	if !errors.Is(err, ErrUnsafeSocket) {
		t.Fatalf("got %v, want ErrUnsafeSocket", err)
	}
	var after unix.Stat_t
	if err := unix.Lstat(path, &after); err != nil {
		t.Fatal(err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatal("existing socket inode changed")
	}
}

func TestOwnedSocketCrashLikeRestartRecoversExactStaleInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "service.sock")
	first, err := listenOwned(path, 0o600, 0)
	if err != nil {
		t.Fatal(err)
	}
	var stale unix.Stat_t
	if err := unix.Lstat(path, &stale); err != nil {
		t.Fatal(err)
	}
	if err := first.listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.abandon(); err != nil {
		t.Fatal(err)
	}

	second, err := listenOwned(path, 0o600, 0)
	if err != nil {
		t.Fatalf("restart did not recover exact stale socket: %v", err)
	}
	defer second.remove()
	defer second.listener.Close()
	var current unix.Stat_t
	if err := unix.Lstat(path, &current); err != nil {
		t.Fatal(err)
	}
	if current.Dev == stale.Dev && current.Ino == stale.Ino {
		t.Fatal("restart retained stale socket inode")
	}
}

func TestOwnedSocketLiveLockPreventsConcurrentUnlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "service.sock")
	first, err := listenOwned(path, 0o600, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer first.remove()
	defer first.listener.Close()
	var before unix.Stat_t
	if err := unix.Lstat(path, &before); err != nil {
		t.Fatal(err)
	}

	second, err := listenOwned(path, 0o600, 0)
	if second != nil {
		_ = second.listener.Close()
		_ = second.remove()
		t.Fatal("concurrent listener acquired live socket ownership")
	}
	if !errors.Is(err, ErrSocketInUse) {
		t.Fatalf("got %v, want ErrSocketInUse", err)
	}
	var after unix.Stat_t
	if err := unix.Lstat(path, &after); err != nil {
		t.Fatal(err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatal("lock refusal changed live socket inode")
	}
}

func TestOwnedSocketCleanCloseCanReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "service.sock")
	first, err := listenOwned(path, 0o600, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.remove(); err != nil {
		t.Fatal(err)
	}
	second, err := listenOwned(path, 0o600, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.remove()
	defer second.listener.Close()
}

func TestSocketParentUsesConfiguredGroupAndRejectsWrongGroup(t *testing.T) {
	const targetGID = 23456
	root := t.TempDir()
	path := filepath.Join(root, "run", "service.sock")
	owned, err := listenOwned(path, 0o660, targetGID)
	if err != nil {
		t.Fatal(err)
	}
	var parent unix.Stat_t
	if err := unix.Lstat(filepath.Dir(path), &parent); err != nil {
		t.Fatal(err)
	}
	if parent.Uid != 0 ||
		parent.Gid != targetGID ||
		parent.Mode&0o777 != 0o750 {
		t.Fatalf(
			"parent uid=%d gid=%d mode=%#o",
			parent.Uid,
			parent.Gid,
			parent.Mode&0o777,
		)
	}
	for _, path := range []string{
		filepath.Join(filepath.Dir(path), ".service.sock.lock"),
		filepath.Join(filepath.Dir(path), ".service.sock.owner.json"),
	} {
		var sidecar unix.Stat_t
		if err := unix.Lstat(path, &sidecar); err != nil {
			t.Fatal(err)
		}
		if !safeRootRegular(sidecar) {
			t.Fatalf("unsafe root-only sidecar %s: %+v", path, sidecar)
		}
	}
	if err := owned.listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owned.remove(); err != nil {
		t.Fatal(err)
	}

	if err := os.Chown(filepath.Dir(path), 0, targetGID+1); err != nil {
		t.Fatal(err)
	}
	reopened, err := listenOwned(path, 0o660, targetGID)
	if reopened != nil {
		_ = reopened.listener.Close()
		_ = reopened.remove()
		t.Fatal("wrong-GID parent was accepted")
	}
	if !errors.Is(err, ErrUnsafeSocket) {
		t.Fatalf("got %v, want ErrUnsafeSocket", err)
	}
}

func TestOwnedSocketMismatchedActiveMarkerNeverUnlinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "service.sock")
	first, err := listenOwned(path, 0o600, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.abandon(); err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if err := unix.Lstat(path, &before); err != nil {
		t.Fatal(err)
	}
	parent, err := openParent(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	marker, err := readSocketOwner(parent)
	if err != nil {
		_ = unix.Close(parent.fd)
		t.Fatal(err)
	}
	marker.Inode++
	if err := saveSocketOwner(parent, marker); err != nil {
		_ = unix.Close(parent.fd)
		t.Fatal(err)
	}
	if err := unix.Close(parent.fd); err != nil {
		t.Fatal(err)
	}

	restarted, err := listenOwned(path, 0o600, 0)
	if restarted != nil {
		_ = restarted.listener.Close()
		_ = restarted.remove()
		t.Fatal("mismatched marker was accepted")
	}
	if !errors.Is(err, ErrUnsafeSocket) {
		t.Fatalf("got %v, want ErrUnsafeSocket", err)
	}
	var after unix.Stat_t
	if err := unix.Lstat(path, &after); err != nil {
		t.Fatal(err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatal("mismatched marker changed stale socket inode")
	}
}

func TestSocketOwnerMarkerRejectsNonStrictJSON(t *testing.T) {
	marker := socketOwnerMarker{
		SchemaVersion: socketOwnerSchema,
		State:         "pending",
		SocketBase:    "service.sock",
		Mode:          0o600,
		GID:           0,
		Generation:    "00112233445566778899aabbccddeeff",
	}
	raw, err := encodeSocketOwner(marker)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(
		raw,
		[]byte(`"state":"pending"`),
		[]byte(`"state":"pending","state":"pending"`),
		1,
	)
	duplicateDevice := bytes.Replace(
		raw,
		[]byte(`"device":0`),
		[]byte(`"device":0,"device":1`),
		1,
	)
	duplicateInode := bytes.Replace(
		raw,
		[]byte(`"inode":0`),
		[]byte(`"inode":0,"inode":1`),
		1,
	)
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":1}`)...)
	trailing := append(append([]byte(nil), raw...), []byte(`{}`)...)
	invalidUTF8 := bytes.Replace(
		raw,
		[]byte(socketOwnerSchema),
		[]byte{0xff},
		1,
	)
	for name, candidate := range map[string][]byte{
		"duplicate_state":  duplicate,
		"duplicate_device": duplicateDevice,
		"duplicate_inode":  duplicateInode,
		"unknown":          unknown,
		"trailing":         trailing,
		"invalid_utf8":     invalidUTF8,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSocketOwner(candidate); !errors.Is(
				err,
				ErrUnsafeSocket,
			) {
				t.Fatalf("got %v, want ErrUnsafeSocket", err)
			}
		})
	}
}

func TestPreexistingPrivateSocketParentIsRejectedUnchanged(t *testing.T) {
	const targetGID = 23459
	for name, existingGID := range map[string]int{
		"root_gid":   0,
		"target_gid": targetGID,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "run")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(parent, 0, existingGID); err != nil {
				t.Fatal(err)
			}
			var before unix.Stat_t
			if err := unix.Lstat(parent, &before); err != nil {
				t.Fatal(err)
			}
			owned, err := listenOwned(
				filepath.Join(parent, "service.sock"),
				0o660,
				targetGID,
			)
			if owned != nil {
				_ = owned.listener.Close()
				_ = owned.remove()
				t.Fatal("preexisting private directory was repurposed")
			}
			if !errors.Is(err, ErrUnsafeSocket) {
				t.Fatalf("got %v, want ErrUnsafeSocket", err)
			}
			var after unix.Stat_t
			if err := unix.Lstat(parent, &after); err != nil {
				t.Fatal(err)
			}
			if before.Uid != after.Uid ||
				before.Gid != after.Gid ||
				before.Mode&0o777 != after.Mode&0o777 {
				t.Fatalf(
					"directory changed before=%+v after=%+v",
					before,
					after,
				)
			}
		})
	}
}

func TestDuplicateOwnerMarkerCannotAuthorizeStaleSocketUnlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "service.sock")
	first, err := listenOwned(path, 0o600, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.abandon(); err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if err := unix.Lstat(path, &before); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(
		filepath.Dir(path),
		"."+filepath.Base(path)+".owner.json",
	)
	raw, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(
		raw,
		[]byte(`"state":"active"`),
		[]byte(`"state":"active","state":"pending"`),
		1,
	)
	if err := os.WriteFile(markerPath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}

	restarted, err := listenOwned(path, 0o600, 0)
	if restarted != nil {
		_ = restarted.listener.Close()
		_ = restarted.remove()
		t.Fatal("duplicate owner marker authorized stale cleanup")
	}
	if !errors.Is(err, ErrUnsafeSocket) {
		t.Fatalf("got %v, want ErrUnsafeSocket", err)
	}
	var after unix.Stat_t
	if err := unix.Lstat(path, &after); err != nil {
		t.Fatal(err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatal("duplicate owner marker changed stale socket inode")
	}
}

func TestSocketLockRejectsRestrictivePartialFileUnchanged(t *testing.T) {
	const targetGID = 23459
	root := t.TempDir()
	parent := filepath.Join(root, "run")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 0, targetGID); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(parent, ".service.sock.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0); err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if err := unix.Lstat(lockPath, &before); err != nil {
		t.Fatal(err)
	}
	owned, err := listenOwned(
		filepath.Join(parent, "service.sock"),
		0o660,
		targetGID,
	)
	if owned != nil {
		_ = owned.listener.Close()
		_ = owned.remove()
		t.Fatal("partial lock file was converged")
	}
	if !errors.Is(err, ErrUnsafeSocket) {
		t.Fatalf("got %v, want ErrUnsafeSocket", err)
	}
	var after unix.Stat_t
	if err := unix.Lstat(lockPath, &after); err != nil {
		t.Fatal(err)
	}
	if before.Dev != after.Dev ||
		before.Ino != after.Ino ||
		before.Mode&0o777 != after.Mode&0o777 {
		t.Fatalf("partial lock changed before=%+v after=%+v", before, after)
	}
}

func TestSocketLockRejectsNonzeroOrWrongGroupFile(t *testing.T) {
	const targetGID = 23460
	for _, name := range []string{"nonzero", "wrong_group"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "run")
			if err := os.Mkdir(parent, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(parent, 0, targetGID); err != nil {
				t.Fatal(err)
			}
			lockPath := filepath.Join(parent, ".service.sock.lock")
			payload := []byte(nil)
			if name == "nonzero" {
				payload = []byte("x")
			}
			if err := os.WriteFile(lockPath, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if name == "wrong_group" {
				if err := os.Chown(lockPath, 0, targetGID); err != nil {
					t.Fatal(err)
				}
			}
			owned, err := listenOwned(
				filepath.Join(parent, "service.sock"),
				0o660,
				targetGID,
			)
			if owned != nil {
				_ = owned.listener.Close()
				_ = owned.remove()
				t.Fatal("unsafe lock file was accepted")
			}
			if !errors.Is(err, ErrUnsafeSocket) {
				t.Fatalf("got %v, want ErrUnsafeSocket", err)
			}
		})
	}
}

func TestNonRootGroupCanTraverseAndConnect(t *testing.T) {
	if helperPath := os.Getenv("AGMIND_UDS_GROUP_HELPER_PATH"); helperPath != "" {
		gid, err := strconv.Atoi(os.Getenv("AGMIND_UDS_GROUP_HELPER_GID"))
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Setgroups([]int{gid}); err != nil {
			t.Fatal(err)
		}
		if err := unix.Setgid(gid); err != nil {
			t.Fatal(err)
		}
		if err := unix.Setuid(65534); err != nil {
			t.Fatal(err)
		}
		connection, err := net.Dial("unix", helperPath)
		if err != nil {
			t.Fatalf("group-authorized connect: %v", err)
		}
		_ = connection.Close()
		lockPath := filepath.Join(
			filepath.Dir(helperPath),
			"."+filepath.Base(helperPath)+".lock",
		)
		if lock, err := os.OpenFile(lockPath, os.O_RDWR, 0); err == nil {
			_ = lock.Close()
			t.Fatal("configured group could open root-only socket lock")
		} else if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("root-only lock open error=%v, want permission denied", err)
		}
		return
	}

	const targetGID = 23457
	root, err := os.MkdirTemp("", "agmind-uds-group-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "run", "service.sock")
	owned, err := listenOwned(path, 0o660, targetGID)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.remove()
	defer owned.listener.Close()
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestNonRootGroupCanTraverseAndConnect$",
		"-test.v",
	)
	command.Env = append(
		os.Environ(),
		"AGMIND_UDS_GROUP_HELPER_PATH="+path,
		"AGMIND_UDS_GROUP_HELPER_GID="+strconv.Itoa(targetGID),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("nonroot helper: %v\n%s", err, output)
	}
}

func TestOwnedSocketCrashBoundariesRecover(t *testing.T) {
	if target := os.Getenv("AGMIND_UDS_CRASH_BOUNDARY"); target != "" {
		path := os.Getenv("AGMIND_UDS_CRASH_PATH")
		gid, err := strconv.Atoi(os.Getenv("AGMIND_UDS_CRASH_GID"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = listenOwnedWithOptions(
			path,
			0o660,
			gid,
			listenOwnedOptions{boundary: func(boundary socketOwnershipBoundary) {
				if string(boundary) == target {
					os.Exit(86)
				}
			}},
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("boundary %s was not reached", target)
	}

	const targetGID = 23458
	runCrash := func(
		t *testing.T,
		path string,
		boundary socketOwnershipBoundary,
	) {
		t.Helper()
		command := exec.Command(
			os.Args[0],
			"-test.run=^TestOwnedSocketCrashBoundariesRecover$",
			"-test.v",
		)
		command.Env = append(
			os.Environ(),
			"AGMIND_UDS_CRASH_PATH="+path,
			"AGMIND_UDS_CRASH_GID="+strconv.Itoa(targetGID),
			"AGMIND_UDS_CRASH_BOUNDARY="+string(boundary),
		)
		output, err := command.CombinedOutput()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 86 {
			t.Fatalf(
				"boundary %s exit=%v\n%s",
				boundary,
				err,
				output,
			)
		}
	}
	assertRestart := func(t *testing.T, path string) {
		t.Helper()
		owned, err := listenOwned(path, 0o660, targetGID)
		if err != nil {
			t.Fatalf("restart: %v", err)
		}
		if err := owned.listener.Close(); err != nil {
			t.Fatal(err)
		}
		if err := owned.remove(); err != nil {
			t.Fatal(err)
		}
	}

	for name, boundary := range map[string]socketOwnershipBoundary{
		"parent_pre_rename": socketBoundaryParentPreRename,
		"parent_renamed":    socketBoundaryParentRenamed,
		"intent":            socketBoundaryPendingWritten,
		"bind":              socketBoundaryBound,
		"chmod":             socketBoundaryConfigured,
		"bound_marker":      socketBoundaryActiveWritten,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "run", "service.sock")
			runCrash(t, path, boundary)
			assertRestart(t, path)
		})
	}
	t.Run("stale_unlink", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "run", "service.sock")
		runCrash(t, path, socketBoundaryActiveWritten)
		runCrash(t, path, socketBoundaryStaleUnlinked)
		assertRestart(t, path)
	})
	t.Run("rebind", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "run", "service.sock")
		runCrash(t, path, socketBoundaryActiveWritten)
		runCrash(t, path, socketBoundaryBound)
		assertRestart(t, path)
	})
}

func TestStableReplacementProcSnapshotCannotGrantSupplementaryAccess(t *testing.T) {
	// Even data that looks like a stable, matching /proc snapshot is not
	// authoritative unless it came from SO_PEERGROUPS on the accepted socket.
	peer := Peer{
		PID:                 123,
		UID:                 1000,
		GID:                 1000,
		supplementaryGroups: []uint32{2000},
	}
	member, err := PeerInGroup(peer, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if member {
		t.Fatal("PID-replacement /proc snapshot granted supplementary access")
	}
}

func TestPeerCredentialsCapturesSocketBoundSupplementaryGroups(t *testing.T) {
	fds, err := unix.Socketpair(
		unix.AF_UNIX,
		unix.SOCK_STREAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	peer, err := peerCredentialsFromFD(
		fds[0],
		func(fd int) ([]uint32, error) {
			if fd != fds[0] {
				t.Fatalf("read groups fd=%d, want accepted fd=%d", fd, fds[0])
			}
			return []uint32{1000, 2000}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !peer.supplementaryGroupsCaptured ||
		!peer.inSupplementaryGroup(2000) ||
		peer.inSupplementaryGroup(3000) {
		t.Fatalf("socket-bound group snapshot is wrong: %+v", peer)
	}
}

func TestPeerCredentialsCapturesRealSOPEERGROUPS(t *testing.T) {
	fds, err := unix.Socketpair(
		unix.AF_UNIX,
		unix.SOCK_STREAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	leftFile := os.NewFile(uintptr(fds[0]), "peer-groups-left")
	if leftFile == nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		t.Fatal("socket file is nil")
	}
	leftConnection, err := net.FileConn(leftFile)
	_ = leftFile.Close()
	if err != nil {
		_ = unix.Close(fds[1])
		t.Fatal(err)
	}
	defer leftConnection.Close()
	defer unix.Close(fds[1])

	expected, err := unix.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) > peerGroupsMax {
		t.Skipf("process has %d groups, exceeds bounded capture", len(expected))
	}
	peer, err := PeerCredentials(leftConnection)
	if err != nil {
		t.Fatal(err)
	}
	if !peer.supplementaryGroupsCaptured {
		t.Fatal("SO_PEERGROUPS is supported but snapshot was not captured")
	}
	actual := make(map[uint32]int, len(peer.supplementaryGroups))
	for _, group := range peer.supplementaryGroups {
		actual[group]++
	}
	for _, group := range expected {
		value := uint32(group)
		if actual[value] == 0 {
			t.Fatalf(
				"captured groups %v missing kernel group %d",
				peer.supplementaryGroups,
				group,
			)
		}
		actual[value]--
	}
	for group, count := range actual {
		if count != 0 {
			t.Fatalf(
				"captured groups %v contain unexpected group %d",
				peer.supplementaryGroups,
				group,
			)
		}
	}
}

func TestUnsupportedSocketPeerGroupsPreservesRootAndPrimaryOnly(t *testing.T) {
	for errorName, groupErr := range map[string]error{
		"unsupported": unix.ENOPROTOOPT,
		"bounded":     unix.ERANGE,
	} {
		t.Run(errorName, func(t *testing.T) {
			fds, err := unix.Socketpair(
				unix.AF_UNIX,
				unix.SOCK_STREAM|unix.SOCK_CLOEXEC,
				0,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])

			peer, err := peerCredentialsFromFD(
				fds[0],
				func(int) ([]uint32, error) {
					return nil, groupErr
				},
			)
			if err != nil {
				t.Fatalf(
					"unavailable SO_PEERGROUPS rejected SO_PEERCRED: %v",
					err,
				)
			}
			if peer.supplementaryGroupsCaptured {
				t.Fatalf("unavailable groups marked captured: %+v", peer)
			}
			primary, err := PeerInGroup(peer, peer.GID)
			if err != nil || !primary {
				t.Fatalf("primary GID member=%v err=%v", primary, err)
			}
			supplementary := peer.GID ^ 1
			member, err := PeerInGroup(peer, supplementary)
			if err != nil || member {
				t.Fatalf("supplementary member=%v err=%v", member, err)
			}

			for name, authorizedPeer := range map[string]Peer{
				"root":    {UID: 0, GID: supplementary},
				"primary": peer,
			} {
				t.Run(name, func(t *testing.T) {
					called := false
					handler := RequireRootOrGroup(peer.GID)(http.HandlerFunc(
						func(
							writer http.ResponseWriter,
							_ *http.Request,
						) {
							called = true
							writer.WriteHeader(http.StatusNoContent)
						},
					))
					request := httptest.NewRequest(
						http.MethodGet,
						"http://unix/v1/admin",
						nil,
					)
					request = request.WithContext(context.WithValue(
						request.Context(),
						peerContextKey{},
						authorizedPeer,
					))
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					if response.Code != http.StatusNoContent || !called {
						t.Fatalf(
							"status=%d handler_called=%v",
							response.Code,
							called,
						)
					}
				})
			}
		})
	}
}

func TestPeerCredentialsRejectsUnexpectedPeerGroupsFailure(t *testing.T) {
	fds, err := unix.Socketpair(
		unix.AF_UNIX,
		unix.SOCK_STREAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if _, err := peerCredentialsFromFD(
		fds[0],
		func(int) ([]uint32, error) {
			return nil, unix.EIO
		},
	); !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("got %v, want ErrInvalidPeer", err)
	}
}

func TestSocketPeerGroupsAllowsEmptySupplementaryGroupList(t *testing.T) {
	snapshot, err := applySocketPeerGroups(
		Peer{PID: 125, UID: 1000, GID: 1000},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("primary-GID-only peer rejected: %v", err)
	}
	if !snapshot.supplementaryGroupsCaptured ||
		len(snapshot.supplementaryGroups) != 0 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestApplySocketPeerGroupsCopiesAndBoundsSnapshot(t *testing.T) {
	groups := []uint32{1000, 2000}
	snapshot, err := applySocketPeerGroups(
		Peer{PID: 126, UID: 1000, GID: 1000},
		groups,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	groups[1] = 3000
	if !snapshot.inSupplementaryGroup(2000) ||
		snapshot.inSupplementaryGroup(3000) {
		t.Fatal("caller mutation changed captured socket groups")
	}
	if _, err := applySocketPeerGroups(
		Peer{PID: 126, UID: 1000, GID: 1000},
		make([]uint32, peerGroupsMax+1),
		nil,
	); !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("oversized snapshot got %v, want ErrInvalidPeer", err)
	}
}

func TestReadSocketPeerGroupsRetriesBoundedERANGE(t *testing.T) {
	calls := 0
	groups, err := readSocketPeerGroupsWith(
		42,
		func(fd int, destination []uint32) (uint32, error) {
			calls++
			if fd != 42 {
				t.Fatalf("fd=%d, want 42", fd)
			}
			switch calls {
			case 1:
				if len(destination) >= 24 {
					t.Fatalf("initial bound=%d, want less than 24", len(destination))
				}
				return 24 * 4, unix.ERANGE
			case 2:
				if len(destination) != 24 {
					t.Fatalf("retry bound=%d, want 24", len(destination))
				}
				for index := range destination {
					destination[index] = uint32(1000 + index)
				}
				return uint32(len(destination) * 4), nil
			default:
				t.Fatalf("unexpected call %d", calls)
				return 0, unix.EIO
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(groups) != 24 ||
		groups[0] != 1000 || groups[23] != 1023 {
		t.Fatalf("calls=%d groups=%v", calls, groups)
	}
}

func TestReadSocketPeerGroupsBoundsAndValidatesKernelLength(t *testing.T) {
	for name, testCase := range map[string]struct {
		length uint32
		err    error
		want   error
	}{
		"oversized": {
			length: uint32((peerGroupsMax + 1) * 4),
			err:    unix.ERANGE,
			want:   unix.ERANGE,
		},
		"misaligned": {
			length: 3,
			err:    unix.ERANGE,
			want:   unix.ERANGE,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readSocketPeerGroupsWith(
				42,
				func(int, []uint32) (uint32, error) {
					return testCase.length, testCase.err
				},
			)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("got %v, want %v", err, testCase.want)
			}
		})
	}
	calls := 0
	if _, err := readSocketPeerGroupsWith(
		42,
		func(int, []uint32) (uint32, error) {
			calls++
			return 24 * 4, unix.ERANGE
		},
	); !errors.Is(err, unix.ERANGE) || calls != 2 {
		t.Fatalf("repeated ERANGE got err=%v calls=%d", err, calls)
	}
}

func TestRequireRootOrGroupAuthorizesPrimaryGIDWithoutProcReread(t *testing.T) {
	called := false
	handler := RequireRootOrGroup(2000)(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		called = true
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://unix/v1/admin", nil)
	request = request.WithContext(
		context.WithValue(request.Context(), peerContextKey{}, Peer{
			PID: -1,
			UID: 1000,
			GID: 2000,
		}),
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("status=%d handler_called=%v", response.Code, called)
	}
}

func TestBoundedJSONRejectsChunkedNonJSONForGetAndDelete(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			called := false
			handler := boundedJSON(1024, http.HandlerFunc(func(
				writer http.ResponseWriter,
				_ *http.Request,
			) {
				called = true
				writer.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(
				method,
				"http://unix/v1/resource",
				strings.NewReader(`{"value":1}`),
			)
			request.TransferEncoding = []string{"chunked"}
			request.ContentLength = -1
			request.Header.Set("Content-Type", "application/octet-stream")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnsupportedMediaType || called {
				t.Fatalf("status=%d handler_called=%v", response.Code, called)
			}
		})
	}
}

func TestBoundedJSONRejectsInvalidUTF8BeforeHandler(t *testing.T) {
	called := false
	handler := boundedJSON(1024, http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		called = true
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(
		http.MethodDelete,
		"http://unix/v1/resource",
		strings.NewReader(string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || called {
		t.Fatalf("status=%d handler_called=%v", response.Code, called)
	}
}

func TestBoundedJSONRejectsContentEncodingEvenWhenBodyIsEmpty(t *testing.T) {
	called := false
	handler := boundedJSON(1024, http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		called = true
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "http://unix/v1/resource", nil)
	request.Header.Set("Content-Encoding", "gzip")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType || called {
		t.Fatalf("status=%d handler_called=%v", response.Code, called)
	}
}
