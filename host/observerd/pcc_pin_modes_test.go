package observerd

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The four PCC safety pins are shipped by the installer, root-owned and non-secret. They were read
// with readSingleLinkRegular, which demands the 0600 that durablefile.AtomicWrite produces and the
// installer never creates, so on a real host EVERY pin load failed with ErrUnsafePath: each
// correlation snapshot recorded outcome "failed" with detector_bundle_unavailable,
// special_use_registry_unavailable, operator_denylist_unavailable and
// management_denylist_unavailable, and no candidate could ever reach OPA. The product could record
// evidence and nothing else.
//
// This is the same two-sided permission contract the 2026-08-11 audit caught for observer.json, so
// this guard DERIVES the modes from scripts/install-linux.sh — including the ones applied inside
// its config loop, where the destination is a shell template — and feeds the PRODUCTION reader a
// file at exactly each of those modes instead of restating 0444 here.

// installerNonSecretMode matches an atomic_install_file destination line for a root-owned artifact
// the product reads back: the immutable configs, the detector rule and the registry. The
// destinations are matched by the places the pin loader reads from — config_root, share_root and
// the Falco rules directory — so the templated config loop is covered too, while systemd units and
// sysusers/tmpfiles drop-ins (which observerd never reads) are not.
var installerNonSecretMode = regexp.MustCompile(
	`(?m)^\s*"?(?:\$\{config_root\}|\$\{share_root\}|/etc/falco/rules\.d)\S*"?\s+(0[0-7]{3})\s+root\s+root\s*$`,
)

func installedNonSecretModes(t *testing.T) []os.FileMode {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "scripts/install-linux.sh"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[os.FileMode]bool{}
	modes := make([]os.FileMode, 0, 4)
	for _, line := range strings.Split(string(raw), "\n") {
		match := installerNonSecretMode.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		// Secrets (0400/0600) are read through readInstalledSecret, not the pin reader.
		if match[1] == "0400" || match[1] == "0600" || match[1] == "0755" {
			continue
		}
		parsed, err := strconv.ParseUint(match[1], 8, 32)
		if err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(parsed)
		if !seen[mode] {
			seen[mode] = true
			modes = append(modes, mode)
		}
	}
	return modes
}

func TestPCCSafetyPinsAreReadableAtInstallerModes(t *testing.T) {
	modes := installedNonSecretModes(t)
	if len(modes) == 0 {
		t.Fatal("discovered no installer modes for non-secret artifacts; install-linux.sh moved")
	}

	// Exactly the reader LoadPCCSafetyPinSnapshot hands to the loader.
	reader := readInstalledConfig

	for _, mode := range modes {
		path := filepath.Join(t.TempDir(), "pinned")
		if err := os.WriteFile(path, []byte("pinned-content\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		raw, err := reader(path, pccSafetyPinMaxBytes)
		if err != nil {
			t.Fatalf(
				"the PCC pin reader refuses an artifact at the installer's own mode %#o: %v",
				mode,
				err,
			)
		}
		if string(raw) != "pinned-content\n" {
			t.Fatalf("pin reader returned %q at mode %#o", raw, mode)
		}
	}
}
