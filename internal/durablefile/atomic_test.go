package durablefile_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"agmind.local/sais/internal/durablefile"
)

func TestAtomicWriteReplacesRegularFileWithMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "new" {
		t.Fatalf("content=%q", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}
}

func TestAtomicWriteRejectsSymlinkParentDestinationHardlinkAndNonregular(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix filesystem safety semantics")
	}
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(root, "parent-link")
	if err := os.Symlink(realParent, parentLink); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(
		filepath.Join(parentLink, "state"),
		[]byte("x"),
	); !errors.Is(err, durablefile.ErrUnsafePath) {
		t.Fatalf("symlink parent got %v", err)
	}

	target := filepath.Join(realParent, "target")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	destinationLink := filepath.Join(realParent, "destination-link")
	if err := os.Symlink(target, destinationLink); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(
		destinationLink,
		[]byte("x"),
	); !errors.Is(err, durablefile.ErrUnsafePath) {
		t.Fatalf("symlink destination got %v", err)
	}

	hardlink := filepath.Join(realParent, "hardlink")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(
		target,
		[]byte("x"),
	); !errors.Is(err, durablefile.ErrUnsafePath) {
		t.Fatalf("hardlink got %v", err)
	}

	directory := filepath.Join(realParent, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(
		directory,
		[]byte("x"),
	); !errors.Is(err, durablefile.ErrUnsafePath) {
		t.Fatalf("directory got %v", err)
	}
}

func TestJournalRejectsSymlinkHardlinkAndNonregularPath(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := durablefile.NewJournal(link); !errors.Is(
		err,
		durablefile.ErrUnsafePath,
	) {
		t.Fatalf("symlink got %v", err)
	}
	hardlink := filepath.Join(root, "hardlink")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := durablefile.NewJournal(target); !errors.Is(
		err,
		durablefile.ErrUnsafePath,
	) {
		t.Fatalf("hardlink got %v", err)
	}
	if _, err := durablefile.NewJournal(root); !errors.Is(
		err,
		durablefile.ErrUnsafePath,
	) {
		t.Fatalf("directory got %v", err)
	}
}

func TestCreateOnlyPublishesCompleteFileWithoutReplacingExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "event.agf")
	if err := durablefile.CreateOnly(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.CreateOnly(path, []byte("second")); !errors.Is(
		err,
		os.ErrExist,
	) {
		t.Fatalf("got %v, want os.ErrExist", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "first" {
		t.Fatalf("existing content replaced: %q", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}
}

func TestEnsurePrivateDirectoryCreatesSafelyAndRejectsUnsafeMetadata(t *testing.T) {
	root := t.TempDir()
	created := filepath.Join(root, "one", "two")
	if err := durablefile.EnsurePrivateDirectory(created); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(created)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}

	wrongMode := filepath.Join(root, "wrong-mode")
	if err := os.Mkdir(wrongMode, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.EnsurePrivateDirectory(wrongMode); !errors.Is(
		err,
		durablefile.ErrUnsafePath,
	) {
		t.Fatalf("wrong mode got %v", err)
	}

	realParent := filepath.Join(root, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(root, "parent-link")
	if err := os.Symlink(realParent, parentLink); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.EnsurePrivateDirectory(
		filepath.Join(parentLink, "child"),
	); !errors.Is(err, durablefile.ErrUnsafePath) {
		t.Fatalf("symlink ancestor got %v", err)
	}
}

func TestReadRegularRejectsWrongModeAndOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := durablefile.ReadRegular(path, 128); !errors.Is(
		err,
		durablefile.ErrUnsafePath,
	) {
		t.Fatalf("wrong mode got %v", err)
	}
	if os.Geteuid() != 0 {
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 12345, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := durablefile.ReadRegular(path, 128); !errors.Is(
		err,
		durablefile.ErrUnsafePath,
	) {
		t.Fatalf("wrong owner got %v", err)
	}
}
