package observerd

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

func legacyStateDocument(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	lastSequence uint64,
) []byte {
	t.Helper()
	keyID, err := contracts.KeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"schema_version":            "agmind.observer-state.v1",
		"host_id":                   testHostID,
		"boot_id":                   testBootID,
		"key_id":                    keyID,
		"key_epoch":                 uint64(1),
		"last_sequence":             lastSequence,
		"mutation_read_only":        false,
		"read_only_reason":          "",
		"reconcile_required":        true,
		"routine_dropped":           uint64(0),
		"drop_event_pending":        false,
		"ack_sequence":              uint64(0),
		"ack_event_id":              "",
		"ack_content_sha256":        "",
		"ack_record_hash":           "",
		"ack_payload_sha256":        "",
		"last_covered_gap_end":      uint64(0),
		"boot_history":              []map[string]any{{"boot_id": testBootID, "first_sequence": uint64(1)}},
		"ack_repair_pending":        false,
		"ack_repair_reason":         "",
		"publication_base_sequence": uint64(0),
		"publication_base_hash":     zeroPublicationHash,
		"publication_head_sequence": uint64(0),
		"publication_head_hash":     zeroPublicationHash,
	}
	raw, err := contracts.CanonicalJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeLegacyState(t *testing.T, root string, raw []byte) string {
	t.Helper()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "observer-state.json")
	if err := durablefile.AtomicWrite(path, raw); err != nil {
		t.Fatal(err)
	}
	return path
}

func stateIdentityForKey(
	t *testing.T,
	privateKey ed25519.PrivateKey,
) StateIdentity {
	t.Helper()
	keyID, err := contracts.KeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return StateIdentity{
		HostID:   testHostID,
		BootID:   testBootID,
		KeyID:    keyID,
		KeyEpoch: 1,
	}
}

func TestStateV2CreatesAndPersistsPendingGenesisBoundary(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := testKey(t, 121)
	path := filepath.Join(root, "observer-state.json")
	state, err := OpenStateStore(path, stateIdentityForKey(t, privateKey))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	if snapshot.SchemaVersion != observerStateSchema ||
		snapshot.BootBoundaryState != bootBoundaryPending ||
		snapshot.PendingBootBoundary == nil ||
		snapshot.PendingBootBoundary.ReasonCode != "observer_genesis" ||
		snapshot.PendingBootBoundary.PreviousBootID != nil ||
		snapshot.PendingBootBoundary.PreviousSourceSequence != 0 {
		t.Fatalf("fresh pending boundary=%+v", snapshot)
	}
	persisted, err := loadObserverState(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.BootBoundaryState != bootBoundaryPending ||
		persisted.PendingBootBoundary == nil {
		t.Fatalf("persisted pending boundary=%+v", persisted)
	}
}

func TestStateV1MigrationIsStrictlyPendingOrLegacyReadOnly(t *testing.T) {
	privateKey := testKey(t, 122)
	identity := stateIdentityForKey(t, privateKey)

	t.Run("pristine becomes pending genesis", func(t *testing.T) {
		root := t.TempDir()
		path := writeLegacyState(
			t,
			root,
			legacyStateDocument(t, privateKey, 0),
		)
		state, err := OpenStateStore(path, identity)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := state.Snapshot()
		if snapshot.SchemaVersion != observerStateSchema ||
			snapshot.BootBoundaryState != bootBoundaryPending ||
			snapshot.PendingBootBoundary == nil ||
			snapshot.MutationReadOnly {
			t.Fatalf("pristine migration=%+v", snapshot)
		}
	})

	t.Run("nonempty unproven state is fenced", func(t *testing.T) {
		root := t.TempDir()
		path := writeLegacyState(
			t,
			root,
			legacyStateDocument(t, privateKey, 1),
		)
		state, err := OpenStateStore(path, identity)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := state.Snapshot()
		if snapshot.SchemaVersion != observerStateSchema ||
			snapshot.BootBoundaryState != bootBoundaryLegacyUnproven ||
			snapshot.PendingBootBoundary != nil ||
			!snapshot.MutationReadOnly ||
			snapshot.ReadOnlyReason !=
				"observer_legacy_boot_boundary_unproven" {
			t.Fatalf("nonempty migration=%+v", snapshot)
		}
		persisted, err := loadObserverState(path)
		if err != nil {
			t.Fatal(err)
		}
		if persisted.ReadOnlyReason !=
			"observer_legacy_boot_boundary_unproven" {
			t.Fatalf("migration fence was not persisted: %+v", persisted)
		}
	})

	for _, test := range []struct {
		name      string
		epoch     uint64
		reconcile bool
	}{
		{name: "non-genesis epoch is fenced", epoch: 2, reconcile: true},
		{name: "missing reconcile fence is fenced", epoch: 1, reconcile: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			document := map[string]any{
				"schema_version":       "agmind.observer-state.v1",
				"host_id":              testHostID,
				"boot_id":              testBootID,
				"key_id":               identity.KeyID,
				"key_epoch":            test.epoch,
				"last_sequence":        uint64(0),
				"mutation_read_only":   false,
				"read_only_reason":     "",
				"reconcile_required":   test.reconcile,
				"routine_dropped":      uint64(0),
				"drop_event_pending":   false,
				"ack_sequence":         uint64(0),
				"ack_event_id":         "",
				"ack_content_sha256":   "",
				"ack_record_hash":      "",
				"ack_payload_sha256":   "",
				"last_covered_gap_end": uint64(0),
				"boot_history": []map[string]any{{
					"boot_id": testBootID, "first_sequence": uint64(1),
				}},
				"ack_repair_pending":        false,
				"ack_repair_reason":         "",
				"publication_base_sequence": uint64(0),
				"publication_base_hash":     zeroPublicationHash,
				"publication_head_sequence": uint64(0),
				"publication_head_hash":     zeroPublicationHash,
			}
			raw, err := contracts.CanonicalJSON(document)
			if err != nil {
				t.Fatal(err)
			}
			path := writeLegacyState(t, root, raw)
			candidateIdentity := identity
			candidateIdentity.KeyEpoch = test.epoch
			state, err := OpenStateStore(path, candidateIdentity)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot := state.Snapshot(); !snapshot.MutationReadOnly ||
				snapshot.BootBoundaryState != bootBoundaryLegacyUnproven {
				t.Fatalf("unsafe pristine migration=%+v", snapshot)
			}
		})
	}
}

func TestPendingBootBoundaryGatesGenericWrapUntilTypedPublication(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 123)
	state, _, signer := openPendingSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	if _, err := signer.Wrap(
		context.Background(),
		"observer_start",
		map[string]any{"kind": "observer_start"},
		metadata(),
	); !errors.Is(err, ErrBootBoundaryPending) {
		t.Fatalf("generic first publication error=%v", err)
	}
	if state.Snapshot().LastSequence != 0 {
		t.Fatal("publication gate consumed a sequence")
	}

	mismatched := map[string]any{
		"schema_version":           "agmind.observer-boot-boundary.v1",
		"kind":                     "observer_boot_boundary",
		"reason_code":              "kernel_boot_id_changed",
		"previous_boot_id":         testBootID2,
		"previous_source_sequence": uint64(7),
	}
	mismatchedCanonical, err := contracts.CanonicalJSON(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	mismatchedHash := sha256.Sum256(mismatchedCanonical)
	if _, err := signer.wrapAuthorizedBootBoundary(
		context.Background(),
		observerBootBoundaryPublication,
		"observer_boot_boundary",
		mismatched,
		EventMetadata{
			EventTime:         time.Date(2026, 7, 27, 11, 59, 59, 0, time.UTC),
			RedactionFlags:    []string{},
			CoverageFlags:     []string{"boot_transition", "reconcile_required"},
			SourcePayloadHash: hex.EncodeToString(mismatchedHash[:]),
		},
	); !errors.Is(err, ErrBootBoundaryPayloadMismatch) {
		t.Fatalf("mismatched pending predecessor error=%v", err)
	}
	if state.Snapshot().LastSequence != 0 {
		t.Fatal("payload mismatch consumed a sequence")
	}

	fields := map[string]any{
		"schema_version":           "agmind.observer-boot-boundary.v1",
		"kind":                     "observer_boot_boundary",
		"reason_code":              "observer_genesis",
		"previous_source_sequence": uint64(0),
	}
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		t.Fatal(err)
	}
	payload := sha256.Sum256(canonical)
	boundary, err := signer.wrapAuthorizedBootBoundary(
		context.Background(),
		observerBootBoundaryPublication,
		"observer_boot_boundary",
		fields,
		EventMetadata{
			EventTime:         time.Date(2026, 7, 27, 11, 59, 59, 0, time.UTC),
			RedactionFlags:    []string{},
			CoverageFlags:     []string{"boot_transition", "reconcile_required"},
			SourcePayloadHash: hex.EncodeToString(payload[:]),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	if boundary.SourceSequence != 1 ||
		snapshot.BootBoundaryState != bootBoundaryCommitted ||
		snapshot.PendingBootBoundary != nil ||
		snapshot.BootHistory[len(snapshot.BootHistory)-1].BoundaryEventID !=
			boundary.EventID {
		t.Fatalf("committed boundary event=%+v state=%+v", boundary, snapshot)
	}
	if _, err := signer.wrapAuthorizedBootBoundary(
		context.Background(),
		observerBootBoundaryPublication,
		"observer_boot_boundary",
		fields,
		EventMetadata{
			EventTime:         time.Date(2026, 7, 27, 11, 59, 59, 0, time.UTC),
			RedactionFlags:    []string{},
			CoverageFlags:     []string{"boot_transition", "reconcile_required"},
			SourcePayloadHash: hex.EncodeToString(payload[:]),
		},
	); !errors.Is(err, ErrBootBoundaryNotPending) {
		t.Fatalf("committed authorization error=%v", err)
	}
	if state.Snapshot().LastSequence != 1 {
		t.Fatal("rejected committed authorization consumed a sequence")
	}
	ordinary, err := signer.Wrap(
		context.Background(),
		"observer_start",
		map[string]any{"kind": "observer_start"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.SourceSequence != 2 {
		t.Fatalf("ordinary sequence=%d", ordinary.SourceSequence)
	}
}

func createDurableUnmarkedBoundary(
	t *testing.T,
	root string,
	privateKey ed25519.PrivateKey,
) (*StateStore, *Spool) {
	t.Helper()
	state, spool, signer := openPendingSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	state.persist = func(path string, next ObserverState) error {
		if next.BootBoundaryState == bootBoundaryCommitted {
			return errors.New("injected boundary marker failure")
		}
		return persistState(path, next)
	}
	fields := map[string]any{
		"schema_version":           "agmind.observer-boot-boundary.v1",
		"kind":                     "observer_boot_boundary",
		"reason_code":              "observer_genesis",
		"previous_source_sequence": uint64(0),
	}
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	if _, err := signer.wrapAuthorizedBootBoundary(
		context.Background(),
		observerBootBoundaryPublication,
		"observer_boot_boundary",
		fields,
		EventMetadata{
			EventTime:         time.Date(2026, 7, 27, 11, 59, 59, 0, time.UTC),
			RedactionFlags:    []string{},
			CoverageFlags:     []string{"boot_transition", "reconcile_required"},
			SourcePayloadHash: hex.EncodeToString(digest[:]),
		},
	); err == nil {
		t.Fatal("expected injected marker failure")
	}
	if snapshot := state.Snapshot(); snapshot.BootBoundaryState !=
		bootBoundaryPending || snapshot.PublicationHeadSequence != 1 {
		t.Fatalf("durable unmarked state=%+v", snapshot)
	}
	return state, spool
}

func TestDurableDedicatedBoundaryRecoversMarkerBeforeRetry(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 124)
	_, spool := createDurableUnmarkedBoundary(t, root, privateKey)
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	identity := stateIdentityForKey(t, privateKey)
	state, err := OpenStateStore(
		filepath.Join(root, "observer-state.json"),
		identity,
	)
	if err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewSpool(
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
	defer recovered.Close()
	if snapshot := state.Snapshot(); snapshot.BootBoundaryState !=
		bootBoundaryCommitted || snapshot.PendingBootBoundary != nil {
		t.Fatalf("boundary marker was not recovered: %+v", snapshot)
	}
}

func TestRecoverPendingBootBoundaryBeforeBootChange(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 125)
	_, spool := createDurableUnmarkedBoundary(t, root, privateKey)
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	identity := stateIdentityForKey(t, privateKey)
	identity.BootID = testBootID2
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "observer-state.json")
	if err := recoverPendingBootBoundaryBeforeBootChange(
		statePath,
		identity,
		SpoolConfig{
			StateDir:             root,
			MaxBytes:             4 * 1024 * 1024,
			PriorityReserveBytes: 1024 * 1024,
		},
		keys,
	); err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateStore(statePath, identity)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	if snapshot.BootID != testBootID2 ||
		snapshot.BootBoundaryState != bootBoundaryPending ||
		snapshot.PendingBootBoundary == nil ||
		snapshot.PendingBootBoundary.ReasonCode != "kernel_boot_id_changed" ||
		snapshot.MutationReadOnly {
		t.Fatalf("changed boot state=%+v", snapshot)
	}
}

func TestNonCommittedStateRequiresReconcileFence(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := testKey(t, 126)
	state, err := OpenStateStore(
		filepath.Join(root, "observer-state.json"),
		stateIdentityForKey(t, privateKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	snapshot.ReconcileRequired = false
	if err := snapshot.Validate(); err == nil {
		t.Fatal("pending state accepted without reconcile_required")
	}
}
