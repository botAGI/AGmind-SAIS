package durablefile_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"agmind.local/sais/internal/durablefile"
	"golang.org/x/sys/unix"
)

func TestNewJournalFirstCreateRequiresParentDirectorySync(t *testing.T) {
	syncErr := errors.New("injected parent directory sync failure")
	path := filepath.Join(t.TempDir(), "events.log")
	journal, err := durablefile.NewJournal(
		path,
		durablefile.WithDirectorySync(func(int) error { return syncErr }),
	)
	if journal != nil {
		_ = journal.Close()
		t.Fatal("journal became usable before its first directory entry was durable")
	}
	if !errors.Is(err, syncErr) {
		t.Fatalf("got %v, want parent sync failure", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("uncertain first create did not leave a recoverable file: %v", statErr)
	}

	retrySyncs := 0
	reopened, err := durablefile.NewJournal(
		path,
		durablefile.WithDirectorySync(func(fd int) error {
			retrySyncs++
			return unix.Fsync(fd)
		}),
	)
	if err != nil {
		t.Fatalf("retry did not reconcile the uncertain create: %v", err)
	}
	if retrySyncs != 1 {
		t.Fatalf("retry parent sync calls=%d want=1", retrySyncs)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointForcesMode0600UnderRestrictiveUmask(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "acked.agf")
	journal, err := durablefile.NewJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	previous := syscall.Umask(0o777)
	if _, err := journal.Checkpoint([]byte("checkpoint")); err != nil {
		syscall.Umask(previous)
		_ = journal.Close()
		t.Fatal(err)
	}
	syscall.Umask(previous)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}
	reopened, err := durablefile.NewJournal(path)
	if err != nil {
		t.Fatalf("checkpoint cannot be reopened: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateOnlyForcesMode0600UnderRestrictiveUmask(t *testing.T) {
	previous := syscall.Umask(0o777)
	t.Cleanup(func() { syscall.Umask(previous) })
	path := filepath.Join(t.TempDir(), "event.agf")
	if err := durablefile.CreateOnly(path, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}
}

func TestRemoveIfIdentityRefusesReplacementInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "event.agf")
	if err := durablefile.CreateOnly(path, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	raw, identity, err := durablefile.ReadRegularIdentity(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.CreateOnly(path, raw); err != nil {
		t.Fatal(err)
	}
	// ext4/overlayfs hand the freed inode number straight back, so a
	// byte-identical recreate can land on the exact (device, inode, size)
	// triple the recorded identity names — that file IS the identity, so
	// refusing it would be wrong. Park the recycled inode under a pinned
	// sibling name and recreate once more, forcing the replacement onto a
	// provably different inode.
	var replacement unix.Stat_t
	if err := unix.Lstat(path, &replacement); err != nil {
		t.Fatal(err)
	}
	if uint64(replacement.Dev) == identity.Device &&
		uint64(replacement.Ino) == identity.Inode {
		if err := os.Rename(path, path+".inode-pin"); err != nil {
			t.Fatal(err)
		}
		if err := durablefile.CreateOnly(path, raw); err != nil {
			t.Fatal(err)
		}
		if err := unix.Lstat(path, &replacement); err != nil {
			t.Fatal(err)
		}
	}
	if uint64(replacement.Dev) == identity.Device &&
		uint64(replacement.Ino) == identity.Inode {
		t.Fatal("pinned sibling did not force a fresh replacement inode")
	}
	if err := durablefile.RemoveIfIdentity(path, identity); !errors.Is(
		err,
		durablefile.ErrUnsafePath,
	) {
		t.Fatalf("got %v, want ErrUnsafePath", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("replacement inode was removed: %v", err)
	}
}
