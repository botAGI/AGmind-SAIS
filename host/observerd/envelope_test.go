package observerd

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
)

const (
	testHostID  = "123e4567-e89b-42d3-a456-426614174000"
	testBootID  = "123e4567-e89b-42d3-b456-426614174001"
	testBootID2 = "123e4567-e89b-42d3-8456-426614174002"
	testBootID3 = "123e4567-e89b-42d3-9456-426614174003"
)

func testKey(t *testing.T, fill byte) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = fill
	}
	return ed25519.NewKeyFromSeed(seed)
}

func openSignerFixture(
	t *testing.T,
	root string,
	bootID string,
	privateKey ed25519.PrivateKey,
) (*StateStore, *Spool, *EnvelopeSigner) {
	return openSignerFixtureWithBoundaryState(
		t,
		root,
		bootID,
		privateKey,
		true,
	)
}

func openPendingSignerFixture(
	t *testing.T,
	root string,
	bootID string,
	privateKey ed25519.PrivateKey,
) (*StateStore, *Spool, *EnvelopeSigner) {
	return openSignerFixtureWithBoundaryState(
		t,
		root,
		bootID,
		privateKey,
		false,
	)
}

func openSignerFixtureWithBoundaryState(
	t *testing.T,
	root string,
	bootID string,
	privateKey ed25519.PrivateKey,
	commitTestBoundary bool,
) (*StateStore, *Spool, *EnvelopeSigner) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	keyID, err := contracts.KeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateStore(
		filepath.Join(root, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   bootID,
			KeyID:    keyID,
			KeyEpoch: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if commitTestBoundary {
		state.mutex.Lock()
		next := cloneObserverState(state.state)
		last := len(next.BootHistory) - 1
		next.BootHistory[last].BoundaryEventID =
			"evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		next.BootHistory[last].BoundaryEventType = "observer_boot_boundary"
		next.BootBoundaryState = bootBoundaryCommitted
		next.PendingBootBoundary = nil
		if err := state.replaceLocked(next); err != nil {
			state.mutex.Unlock()
			t.Fatal(err)
		}
		state.mutex.Unlock()
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	spool, err := NewSpool(
		SpoolConfig{
			StateDir:             root,
			MaxBytes:             4 * 1024 * 1024,
			PriorityReserveBytes: 1024 * 1024,
		},
		state,
		keys,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	signer, err := NewEnvelopeSigner(
		SignerConfig{
			HostID:        testHostID,
			BootID:        bootID,
			KeyEpoch:      1,
			SourceID:      "agmind-observerd",
			SourceVersion: "0.1.0",
			Now: func() time.Time {
				return time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
			},
		},
		state,
		spool,
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return state, spool, signer
}

func metadata() EventMetadata {
	payload := sha256.Sum256([]byte("source payload"))
	return EventMetadata{
		EventTime:           time.Date(2026, 7, 27, 11, 59, 59, 0, time.UTC),
		ClockUncertaintyMS:  20,
		InventoryGeneration: 0,
		RedactionFlags:      []string{},
		CoverageFlags:       []string{"reconcile_required"},
		SourcePayloadHash:   hex.EncodeToString(payload[:]),
	}
}

func TestWrapReservesPersistsSignsValidatesAndDurablySpools(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 1)
	_, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	normalized := map[string]any{"kind": "observer_start", "count": uint64(1)}
	event, err := signer.Wrap(
		context.Background(),
		"observer_start",
		normalized,
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	normalized["kind"] = "caller_mutated_after_wrap"
	if event.SourceSequence != 1 ||
		event.HostID != testHostID ||
		event.BootID != testBootID ||
		event.KeyEpoch != 1 {
		t.Fatalf("authority tuple changed: %+v", event)
	}
	if event.NormalizedFields["kind"] != "observer_start" {
		t.Fatal("signer retained caller-owned normalized map")
	}
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyEventSignature(
		event,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatal(err)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Sequence != 1 || items[0].EventID != event.EventID {
		t.Fatalf("spooled items=%+v", items)
	}
	if items[0].Tier != PriorityTier {
		t.Fatalf("observer_start tier=%s", items[0].Tier)
	}
}

func TestSequenceIsHostGlobalAcrossRestartBootAndEpoch(t *testing.T) {
	root := t.TempDir()
	keyOne := testKey(t, 2)
	_, spool, signer := openSignerFixture(t, root, testBootID, keyOne)
	first, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}

	_, spool, signer = openSignerFixture(t, root, testBootID, keyOne)
	second, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}

	_, _, signer = openSignerFixture(t, root, testBootID2, keyOne)
	third, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if [3]uint64{first.SourceSequence, second.SourceSequence, third.SourceSequence} !=
		[3]uint64{1, 2, 3} {
		t.Fatalf(
			"sequences=%d,%d,%d",
			first.SourceSequence,
			second.SourceSequence,
			third.SourceSequence,
		)
	}
	if third.BootID != testBootID2 {
		t.Fatalf("new boot id=%q", third.BootID)
	}
}

func TestMissingPrivateKeyPersistsReadOnlyAndEmitsNothingUnsigned(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 3)
	state, spool, _ := openSignerFixture(t, root, testBootID, privateKey)
	if _, err := NewEnvelopeSigner(
		SignerConfig{
			HostID:        testHostID,
			BootID:        testBootID,
			KeyEpoch:      1,
			SourceID:      "agmind-observerd",
			SourceVersion: "0.1.0",
			Now:           time.Now,
		},
		state,
		spool,
		nil,
	); err == nil {
		t.Fatal("missing key must fail")
	}
	snapshot := state.Snapshot()
	if !snapshot.MutationReadOnly {
		t.Fatal("missing key did not persist read-only state")
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatal("missing key emitted an unsigned event")
	}
}

func TestPostReservationFailureLeavesGapButPreReservationCancellationDoesNot(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 4)
	state, _, signer := openSignerFixture(t, root, testBootID, privateKey)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.Wrap(
		cancelled,
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	); err == nil {
		t.Fatal("pre-reservation cancellation must fail")
	}
	if state.Snapshot().LastSequence != 0 {
		t.Fatal("pre-reservation cancellation consumed a sequence")
	}

	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"forbidden_float": 1.5},
		metadata(),
	); err == nil {
		t.Fatal("post-reservation canonicalization failure must fail")
	}
	if state.Snapshot().LastSequence != 1 {
		t.Fatal("post-reservation failure did not leave an explicit gap")
	}
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if event.SourceSequence != 2 {
		t.Fatalf("failed sequence was reused: %d", event.SourceSequence)
	}
}

func TestWrapDeepCopiesPointerMetadata(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 5)
	_, _, signer := openSignerFixture(t, root, testBootID, privateKey)
	containerID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	startedAt := "2026-07-27T11:00:00Z"
	releaseID := "rel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revision := uint64(7)
	meta := metadata()
	meta.ContainerID = &containerID
	meta.ContainerStartTime = &startedAt
	meta.ReleaseID = &releaseID
	meta.InventoryRevision = &revision
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		meta,
	)
	if err != nil {
		t.Fatal(err)
	}
	containerID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	startedAt = "2026-07-27T12:00:00Z"
	releaseID = "rel_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	revision = 8
	if *event.ContainerID == containerID ||
		*event.ContainerStartTime == startedAt ||
		*event.ReleaseID == releaseID ||
		*event.InventoryRevision == revision {
		t.Fatal("event retained caller-owned pointer metadata")
	}
}

func TestSequenceExhaustionAndReadOnlyPersistenceFailureStayFailClosedInMemory(
	t *testing.T,
) {
	root := t.TempDir()
	privateKey := testKey(t, 6)
	state, _, signer := openSignerFixture(t, root, testBootID, privateKey)
	state.mutex.Lock()
	exhausted := state.state
	exhausted.LastSequence = math.MaxUint64
	if err := state.replaceLocked(exhausted); err != nil {
		state.mutex.Unlock()
		t.Fatal(err)
	}
	state.mutex.Unlock()
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	); err == nil {
		t.Fatal("exhausted sequence must fail")
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("sequence exhaustion did not hold read-only")
	}

	state.mutex.Lock()
	state.path = filepath.Join(root, "missing-parent", "state.json")
	state.mutex.Unlock()
	if err := state.PersistReadOnly("injected_persist_failure"); err == nil {
		t.Fatal("expected persistence failure")
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("persistence failure cleared live read-only state")
	}
}
