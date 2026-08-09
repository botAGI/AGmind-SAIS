//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRotateCoreAPITokenFileIsAtomicPrivateAndDoesNotLeakSecret(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "core-api.token")
	if err := os.Chmod(directory, 0o710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old-token\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if err := unix.Lstat(path, &before); err != nil {
		t.Fatal(err)
	}

	entropy := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	receipt, err := rotateCoreAPITokenFile(
		path,
		os.Geteuid(),
		os.Getegid(),
		bytes.NewReader(entropy),
	)
	if err != nil {
		t.Fatal(err)
	}

	const token = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	const keyID = "sha256:ea866a757e4c38babfa8127cbe9a409d3e1f93a00ff1488ff735fcf917afffd0"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != token+"\n" {
		t.Fatalf("token bytes=%q", raw)
	}
	if receipt.path != path || receipt.keyID != keyID {
		t.Fatalf("receipt=%+v", receipt)
	}
	var output bytes.Buffer
	if err := renderCoreAPITokenReceipt(&output, receipt); err != nil {
		t.Fatal(err)
	}
	wantOutput := "Core API token path: " + path + "\nKey ID: " + keyID + "\n"
	if output.String() != wantOutput || strings.Contains(output.String(), token) {
		t.Fatalf("unsafe rotation output=%q", output.String())
	}

	var after unix.Stat_t
	if err := unix.Lstat(path, &after); err != nil {
		t.Fatal(err)
	}
	if after.Ino == before.Ino || after.Mode&0o777 != 0o640 ||
		after.Uid != uint32(os.Geteuid()) || after.Gid != uint32(os.Getegid()) ||
		after.Nlink != 1 {
		t.Fatalf(
			"unsafe published metadata: old_inode=%d new_inode=%d mode=%#o uid=%d gid=%d links=%d",
			before.Ino,
			after.Ino,
			after.Mode&0o777,
			after.Uid,
			after.Gid,
			after.Nlink,
		)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "core-api.token" {
		t.Fatalf("temporary publication artifacts remain: %v", entries)
	}
}
