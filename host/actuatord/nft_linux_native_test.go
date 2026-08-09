//go:build linux && native

package actuatord

import (
	"context"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type nativeSelfTarget struct {
	fd        int
	inode     uint64
	hostInode uint64
}

func (target *nativeSelfTarget) Snapshot() PrepareTargetSnapshot {
	return PrepareTargetSnapshot{NetworkNamespaceInode: target.inode}
}

func (target *nativeSelfTarget) NetNSFD() int { return target.fd }

func (target *nativeSelfTarget) HostNetworkNamespaceInode() uint64 {
	return target.hostInode
}

func (*nativeSelfTarget) Recheck(context.Context) error { return nil }

func (target *nativeSelfTarget) Close() error { return unix.Close(target.fd) }

func TestNativeNftApplyUsesOneExactExpiringElement(t *testing.T) {
	// Build a disposable network namespace without ever mutating the namespace
	// that launched the test. The held descriptor keeps it alive for readback
	// and closing it destroys the complete test ruleset.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	originalFD, err := unix.Open(
		"/proc/thread-self/ns/net",
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(originalFD)
	var hostStat unix.Stat_t
	if err := unix.Fstat(originalFD, &hostStat); err != nil || hostStat.Ino == 0 {
		t.Fatalf("host netns stat=%+v err=%v", hostStat, err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatal(err)
	}
	fd, openErr := unix.Open(
		"/proc/thread-self/ns/net",
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if restoreErr := unix.Setns(originalFD, unix.CLONE_NEWNET); restoreErr != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		t.Fatal(restoreErr)
	}
	if openErr != nil {
		t.Fatal(openErr)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Ino == 0 {
		_ = unix.Close(fd)
		t.Fatalf("netns stat=%+v err=%v", stat, err)
	}
	target := &nativeSelfTarget{fd: fd, inode: stat.Ino, hostInode: hostStat.Ino}
	defer target.Close()
	spec := NftApplySpec{
		PlanID:           "plan_0123456789abcdef0123456789abcdef",
		DestinationIPv4:  "1.1.1.1",
		TTL:              30 * time.Second,
		TargetNetNSInode: stat.Ino,
	}
	mutation, err := (platformNftBackend{}).Prepare(context.Background(), target, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer mutation.Close()
	observation, err := mutation.FlushOnceAndVerify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := observation.validate(spec); err != nil {
		t.Fatal(err)
	}
}
