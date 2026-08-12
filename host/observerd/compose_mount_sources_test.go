package observerd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every relative bind-mount source in the Compose file must be a file the installer actually
// copies into the install root. A missing source is not a visible failure: Docker silently
// creates an empty DIRECTORY at the mount point and the container starts against it. That is
// exactly how the OPA authorization policy went missing on a real host — compose mounted and
// loaded policies/authz.rego, the installer's allowlist copied only policies/pcc.rego, Docker
// made /opt/agmind-sais/policies/authz.rego a directory, OPA found no system.authz rule, and
// with --authorization=basic it answered EVERY request, including Core's admission queries,
// with 500 "authorization policy missing or undefined". The admission gate was dead and nothing
// went red.
//
// This guard therefore DERIVES both sides from the source of truth — the mount list from
// deploy/compose/compose.yaml and the shipped set from scripts/install-linux.sh — instead of
// restating either. Adding a mount without shipping its source turns this test red.

var (
	composeMountPattern   = regexp.MustCompile(`(?m)^\s+-\s+(\.\.[^:\s]*):`)
	installerFilePattern  = regexp.MustCompile(`(?s)for relative_file in\s+(.*?);\s*do`)
	installerTreePattern  = regexp.MustCompile(`(?s)for relative_tree in\s+(.*?);\s*do`)
	installerCopyFileLine = regexp.MustCompile(`(?m)^\s*copy_file\s+(\S+)`)
)

// shellListEntries splits a shell for-loop word list, dropping line continuations and comments.
func shellListEntries(list string) []string {
	entries := make([]string, 0, 8)
	for _, line := range strings.Split(list, "\n") {
		if index := strings.Index(line, "#"); index >= 0 {
			line = line[:index]
		}
		line = strings.ReplaceAll(line, "\\", " ")
		for _, field := range strings.Fields(line) {
			entries = append(entries, field)
		}
	}
	return entries
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestEveryComposeBindMountSourceIsInstalled(t *testing.T) {
	root := repositoryRoot(t)

	compose, err := os.ReadFile(filepath.Join(root, "deploy/compose/compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	installer, err := os.ReadFile(filepath.Join(root, "scripts/install-linux.sh"))
	if err != nil {
		t.Fatal(err)
	}

	// The mount sources are written relative to deploy/compose/, so resolve them against it.
	mounts := composeMountPattern.FindAllStringSubmatch(string(compose), -1)
	if len(mounts) == 0 {
		t.Fatal("discovered no relative bind-mount sources; the pattern or the compose file moved")
	}

	shipped := make([]string, 0, 16)
	for _, match := range installerFilePattern.FindAllStringSubmatch(string(installer), -1) {
		shipped = append(shipped, shellListEntries(match[1])...)
	}
	for _, match := range installerCopyFileLine.FindAllStringSubmatch(string(installer), -1) {
		shipped = append(shipped, match[1])
	}
	trees := make([]string, 0, 8)
	for _, match := range installerTreePattern.FindAllStringSubmatch(string(installer), -1) {
		trees = append(trees, shellListEntries(match[1])...)
	}
	if len(shipped) == 0 || len(trees) == 0 {
		t.Fatal("discovered no installer allowlist; install-linux.sh moved")
	}

	installs := func(relative string) bool {
		for _, candidate := range shipped {
			if candidate == relative {
				return true
			}
		}
		for _, tree := range trees {
			if strings.HasPrefix(relative, tree+"/") {
				return true
			}
		}
		return false
	}

	for _, mount := range mounts {
		source := mount[1]
		relative, err := filepath.Rel(
			root,
			filepath.Join(root, "deploy/compose", source),
		)
		if err != nil {
			t.Fatalf("mount %q does not resolve inside the repository: %v", source, err)
		}
		if strings.HasPrefix(relative, "..") {
			t.Fatalf("mount %q escapes the repository", source)
		}
		// The file must exist here, or the mount can only ever produce a directory.
		info, err := os.Stat(filepath.Join(root, relative))
		if err != nil {
			t.Fatalf("compose mounts %q but %s is missing: %v", source, relative, err)
		}
		if info.IsDir() {
			t.Fatalf("compose mounts %q but %s is a directory", source, relative)
		}
		if !installs(relative) {
			t.Fatalf(
				"compose mounts %q but the installer never copies %s; "+
					"Docker would create an empty directory there on a real host",
				source,
				relative,
			)
		}
	}
}
