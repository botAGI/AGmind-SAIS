package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/uds"
)

func validConfig(root string) string {
	return `{
		"schema_version":"agmind.observer-config.v1",
		"host_id_file":"` + filepath.Join(root, "identity", "host-id") + `",
		"private_key_file":"` + filepath.Join(root, "secrets", "observer.key") + `",
		"state_dir":"` + filepath.Join(root, "state") + `",
		"run_dir":"` + filepath.Join(root, "run") + `",
		"spool_max_bytes":268435456,
		"spool_priority_reserve_bytes":33554432
	}`
}

func TestLoadConfigIsStrictAndRejectsSymlinkOrNonregularFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "observer.json")
	if err := os.WriteFile(path, []byte(validConfig(root)), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.StateDir != filepath.Join(root, "state") {
		t.Fatalf("state dir=%q", config.StateDir)
	}

	unknown := strings.Replace(
		validConfig(root),
		`"schema_version":`,
		`"unknown":true,"schema_version":`,
		1,
	)
	if err := os.WriteFile(path, []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown config field must fail")
	}

	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(validConfig(root)), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link); err == nil {
		t.Fatal("symlink config must fail")
	}
	if _, err := LoadConfig(root); err == nil {
		t.Fatal("directory config must fail")
	}
	realParent := filepath.Join(root, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedConfig := filepath.Join(realParent, "observer.json")
	if err := os.WriteFile(
		nestedConfig,
		[]byte(validConfig(root)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(root, "parent-link")
	if err := os.Symlink(realParent, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(
		filepath.Join(parentLink, "observer.json"),
	); err == nil {
		t.Fatal("symlinked config ancestor must fail")
	}
}

func TestConfigRejectsCapacityThatEliminatesPriorityReserve(t *testing.T) {
	root := t.TempDir()
	raw := strings.Replace(
		validConfig(root),
		`"spool_priority_reserve_bytes":33554432`,
		`"spool_priority_reserve_bytes":268435456`,
		1,
	)
	path := filepath.Join(root, "observer.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("reserve equal to total must fail")
	}
}

func TestBootstrapStartsDockerFreeAndFencedReconcileRequired(t *testing.T) {
	configPath, config, oldKey, _ := rotationFixture(t)
	daemon, err := Bootstrap(
		context.Background(),
		configPath,
		WithBootstrapBootID(func() (string, error) { return testBootID, nil }),
		WithBootstrapNow(func() time.Time {
			return time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	if !daemon.ReconcileRequired() {
		t.Fatal("Task 2 daemon started mutation-ready")
	}
	if err := RotateKeys(
		configPath,
		append(
			fixedRotationOptions(testKey(t, 41)),
			WithRotationBootID(func() (string, error) { return testBootID, nil }),
		)...,
	); !errors.Is(err, ErrStateLocked) {
		t.Fatalf("live daemon did not exclude rotation: %v", err)
	}
	items, err := daemon.spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("startup items=%d", len(items))
	}
	boundary, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
		bytes.NewReader(items[0].Canonical),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
		bytes.NewReader(items[1].Canonical),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	if boundary.EventType != "observer_boot_boundary" ||
		boundary.SourceSequence != 1 ||
		!exactFlags(
			boundary.CoverageFlags,
			"boot_transition",
			"reconcile_required",
		) ||
		event.EventType != "observer_start" ||
		event.SourceSequence != 2 ||
		event.CoverageFlags[0] != "reconcile_required" {
		t.Fatalf("boundary=%+v startup=%+v", boundary, event)
	}
	for _, published := range []contracts.EventEnvelopeV1{boundary, event} {
		if err := contracts.VerifyEventSignature(
			published,
			oldKey.Public().(ed25519.PublicKey),
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(config.StateDir, "docker-state")); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatal("Task 2 bootstrap created Docker state")
	}
}

func TestBootstrapSignsReservedSequenceGapExactlyOnce(t *testing.T) {
	configPath, _, _, _ := rotationFixture(t)
	options := []BootstrapOption{
		WithBootstrapBootID(func() (string, error) { return testBootID, nil }),
		WithBootstrapNow(func() time.Time {
			return time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)
		}),
	}
	daemon, err := Bootstrap(context.Background(), configPath, options...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"bad": 1.5},
		metadata(),
	); err == nil {
		t.Fatal("expected post-reservation failure")
	}
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}

	countGaps := func() int {
		daemon, err = Bootstrap(context.Background(), configPath, options...)
		if err != nil {
			t.Fatal(err)
		}
		items, err := daemon.spool.Fetch(0, 100, 4*1024*1024)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, item := range items {
			event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
				bytes.NewReader(item.Canonical),
				65_536,
			)
			if err != nil {
				t.Fatal(err)
			}
			if event.EventType == "coverage" &&
				event.NormalizedFields["kind"] == "observer_sequence_gap" {
				count++
			}
		}
		return count
	}
	if got := countGaps(); got != 1 {
		t.Fatalf("first restart gaps=%d", got)
	}
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}
	if got := countGaps(); got != 1 {
		t.Fatalf("second restart duplicated gap, total=%d", got)
	}
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapWithMissingPrivateKeyRunsReadOnlyWithoutUnsignedEvent(t *testing.T) {
	configPath, config, _, _ := rotationFixture(t)
	options := []BootstrapOption{
		WithBootstrapBootID(func() (string, error) { return testBootID, nil }),
		WithBootstrapNow(func() time.Time {
			return time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)
		}),
	}
	healthy, err := Bootstrap(context.Background(), configPath, options...)
	if err != nil {
		t.Fatal(err)
	}
	if err := healthy.Close(); err != nil {
		t.Fatal(err)
	}
	before := 0
	for _, tier := range []Tier{RoutineTier, PriorityTier} {
		entries, err := os.ReadDir(
			filepath.Join(config.StateDir, "spool", string(tier)),
		)
		if err != nil {
			t.Fatal(err)
		}
		before += len(entries)
	}
	if err := os.Remove(config.PrivateKeyFile); err != nil {
		t.Fatal(err)
	}
	degraded, err := Bootstrap(context.Background(), configPath, options...)
	if err != nil {
		t.Fatalf("missing key did not start degraded daemon: %v", err)
	}
	if !degraded.MutationReadOnly() ||
		degraded.signer != nil ||
		degraded.spool != nil {
		t.Fatalf(
			"degraded daemon readonly=%v signer=%v spool=%v",
			degraded.MutationReadOnly(),
			degraded.signer,
			degraded.spool,
		)
	}
	after := 0
	for _, tier := range []Tier{RoutineTier, PriorityTier} {
		entries, err := os.ReadDir(
			filepath.Join(config.StateDir, "spool", string(tier)),
		)
		if err != nil {
			t.Fatal(err)
		}
		after += len(entries)
	}
	if after != before {
		t.Fatalf("missing key changed signed spool items: before=%d after=%d", before, after)
	}
	if err := degraded.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.PrivateKeyFile, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid, err := Bootstrap(context.Background(), configPath, options...)
	if err != nil {
		t.Fatalf("invalid key did not start degraded daemon: %v", err)
	}
	defer invalid.Close()
	if !invalid.MutationReadOnly() ||
		invalid.signer != nil ||
		invalid.spool != nil {
		t.Fatal("invalid key did not remain unsigned and read-only")
	}
}

func TestPrivilegedPlatformGuardRejectsNonLinux(t *testing.T) {
	if err := requireLinuxPlatform("darwin"); !errors.Is(
		err,
		uds.ErrUnsupportedPlatform,
	) {
		t.Fatalf("darwin guard got %v", err)
	}
	if err := requireLinuxPlatform("linux"); err != nil {
		t.Fatalf("linux guard got %v", err)
	}
}
