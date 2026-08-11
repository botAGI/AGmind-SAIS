package observerd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"testing"
)

// The installer ships observerd's three immutable artifacts; observerd must be able to READ them
// at exactly the modes the installer creates. Nothing enforced that contract before, and the two
// sides drifted: the reader demanded 0600 while the installer shipped 0444 and 0400, so observerd
// could not load its own config on a real host and the signed-evidence leg never started. Every
// unit test missed it because each one wrote its fixture with os.WriteFile(..., 0o600) — the one
// mode the installer never produces.
//
// This guard therefore DERIVES the expected modes from scripts/install-linux.sh rather than
// restating them. If either side moves, this test goes red instead of production.

// installerArtifact is one file the installer creates for observerd, with the shell variable
// prefix the installer uses for its directory.
type installerArtifact struct {
	// name is the trailing path element as it appears in install-linux.sh.
	name string
	// what identifies it in failure output.
	what string
	// secret marks artifacts that must never be group- or world-readable.
	secret bool
}

var observerInstalledArtifacts = []installerArtifact{
	{name: "observer.json", what: "observer config", secret: false},
	{name: "identity/host-id", what: "host identity", secret: true},
	{name: "observer-ed25519.key", what: "observer signing key", secret: true},
}

func acceptedModesFor(artifact installerArtifact) []fs.FileMode {
	if artifact.secret {
		return installedSecretModes
	}
	return installedConfigModes
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for range 8 {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate repository root from %s", dir)
	return ""
}

// installerModes returns the mode each observer artifact is installed with, parsed out of the
// installer. Both installer helpers put the mode in the argument position after the destination.
func installerModes(t *testing.T) map[string]fs.FileMode {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", "install-linux.sh")
	raw, err := os.ReadFile(script) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	text := string(raw)

	// secure_artifact "<path>" <mode> <owner> <group>
	secure := regexp.MustCompile(`secure_artifact\s+"([^"]+)"\s+0([0-7]{3})`)
	// atomic_install_file <src> "<dst>" <mode> <owner> <group>  (dst may span the previous line)
	atomic := regexp.MustCompile(`atomic_install_file\s+\\?\s*"[^"]*"\s*\\?\s*"([^"]+)"\s+0([0-7]{3})`)

	found := map[string]fs.FileMode{}
	record := func(path, octal string) {
		mode, convErr := strconv.ParseUint(octal, 8, 32)
		if convErr != nil {
			t.Fatalf("bad mode %q in installer: %v", octal, convErr)
		}
		for _, artifact := range observerInstalledArtifacts {
			if matchesArtifact(path, artifact.name) {
				found[artifact.name] = fs.FileMode(mode)
			}
		}
	}
	for _, m := range secure.FindAllStringSubmatch(text, -1) {
		record(m[1], m[2])
	}
	for _, m := range atomic.FindAllStringSubmatch(text, -1) {
		record(m[1], m[2])
	}

	// The config loop installs every ${config_name}.json in one statement, so observer.json is
	// only reachable through the loop variable. Resolve it explicitly.
	if _, ok := found["observer.json"]; !ok {
		loop := regexp.MustCompile(
			`for config_name in ([^\n;]*observer[^\n;]*); do[\s\S]{0,400}?\$\{config_name\}\.json"\s+0([0-7]{3})`)
		if m := loop.FindStringSubmatch(text); m != nil {
			mode, convErr := strconv.ParseUint(m[2], 8, 32)
			if convErr != nil {
				t.Fatalf("bad config-loop mode %q: %v", m[2], convErr)
			}
			found["observer.json"] = fs.FileMode(mode)
		}
	}
	return found
}

func matchesArtifact(installerPath, artifact string) bool {
	if len(installerPath) < len(artifact) {
		return false
	}
	return installerPath[len(installerPath)-len(artifact):] == artifact
}

// Guard the guard: an empty or partial parse would make the assertion below vacuous.
func TestInstallerModeDiscoveryIsComplete(t *testing.T) {
	modes := installerModes(t)
	for _, artifact := range observerInstalledArtifacts {
		if _, ok := modes[artifact.name]; !ok {
			t.Fatalf(
				"installer discovery failed for %s (%s): parser found %v — fix the parser, "+
					"do not weaken the assertion",
				artifact.name, artifact.what, modes,
			)
		}
	}
}

func TestObserverAcceptsEveryModeTheInstallerCreates(t *testing.T) {
	modes := installerModes(t)
	var problems []string
	for _, artifact := range observerInstalledArtifacts {
		mode := modes[artifact.name]
		accepted := acceptedModesFor(artifact)
		if !slices.Contains(accepted, mode) {
			problems = append(problems, fmt.Sprintf(
				"%s (%s): installer creates %#o, observerd accepts %v",
				artifact.name, artifact.what, mode, formatModes(accepted),
			))
		}
	}
	if len(problems) > 0 {
		t.Fatalf(
			"observerd cannot read artifacts the installer produces — it will fail to start on a "+
				"real host and the signed-evidence leg never runs:\n  %v",
			problems,
		)
	}
}

// Rotation rewrites the signing key through durablefile.AtomicWrite, which chmods to 0600. The
// key is therefore 0400 as installed and 0600 after the first rotation, and BOTH must be readable
// or rotation bricks the sensor.
func TestRotatedKeyModeStaysReadable(t *testing.T) {
	if !slices.Contains(installedSecretModes, fs.FileMode(0o600)) {
		t.Fatalf(
			"0600 missing from accepted secret modes: durablefile.AtomicWrite chmods rotated files "+
				"to 0600, so the first key rotation would make the key unreadable. accepted=%v",
			formatModes(installedSecretModes),
		)
	}
}

// The whole point of separating the two sets: relaxing the config mode must never relax secrets.
func TestSecretModesAreOwnerOnly(t *testing.T) {
	for _, mode := range installedSecretModes {
		if mode&0o077 != 0 {
			t.Fatalf(
				"secret mode %#o grants group or world access — the signing key and host identity "+
					"must stay owner-only no matter what the config mode allows",
				mode,
			)
		}
	}
	if len(installedSecretModes) == 0 {
		t.Fatal("secret mode allowlist is empty, which would make the check above vacuous")
	}
}

func formatModes(modes []fs.FileMode) []string {
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		out = append(out, fmt.Sprintf("%#o", m))
	}
	return out
}
