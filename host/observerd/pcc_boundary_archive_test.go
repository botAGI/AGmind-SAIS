package observerd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const pccArchiveTestTime = "2026-07-29T12:00:00Z"

func pccArchiveEnvelope(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	epoch uint64,
	bootID string,
	sequence uint64,
	eventType string,
	fields map[string]any,
	flags []string,
) contracts.EventEnvelopeV1 {
	t.Helper()
	keyID, err := contracts.KeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	event := contracts.EventEnvelopeV1{
		SchemaVersion:          "agmind.event-envelope.v1",
		EventType:              eventType,
		SourceID:               "agmind-observerd",
		SourceVersion:          "0.1.0",
		KeyID:                  keyID,
		KeyEpoch:               epoch,
		HostID:                 testHostID,
		BootID:                 bootID,
		SourceSequence:         sequence,
		EventTime:              pccArchiveTestTime,
		IngestTime:             pccArchiveTestTime,
		NormalizedFields:       fields,
		NormalizedFieldsSHA256: hex.EncodeToString(digest[:]),
		RedactionFlags:         []string{},
		CoverageFlags:          append([]string(nil), flags...),
		SourcePayloadHash:      hex.EncodeToString(digest[:]),
	}
	event.EventID, err = contracts.DeriveEventID(event)
	if err != nil {
		t.Fatal(err)
	}
	message, err := contracts.EventSigningMessage(event)
	if err != nil {
		t.Fatal(err)
	}
	event.SourceSignature = hex.EncodeToString(ed25519.Sign(privateKey, message))
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	return event
}

func pccArchiveDedicated(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	bootID string,
	sequence uint64,
	previousBootID string,
	previousSequence uint64,
) contracts.EventEnvelopeV1 {
	t.Helper()
	return pccArchiveEnvelope(
		t,
		privateKey,
		1,
		bootID,
		sequence,
		"observer_boot_boundary",
		map[string]any{
			"schema_version":           "agmind.observer-boot-boundary.v1",
			"kind":                     "observer_boot_boundary",
			"reason_code":              "kernel_boot_id_changed",
			"previous_boot_id":         previousBootID,
			"previous_source_sequence": previousSequence,
		},
		[]string{"boot_transition", "reconcile_required"},
	)
}

func pccArchiveRotationPair(
	t *testing.T,
	oldKey ed25519.PrivateKey,
	newKey ed25519.PrivateKey,
	transitionBootID string,
	startBootID string,
	transitionSequence uint64,
	transitionFlags []string,
	startFlags []string,
) (contracts.EventEnvelopeV1, contracts.EventEnvelopeV1) {
	t.Helper()
	oldKeyID, err := contracts.KeyID(oldKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	newKeyID, err := contracts.KeyID(newKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	transition := contracts.KeyTransitionV1{
		SchemaVersion: "agmind.key-transition.v1",
		OldKeyID:      oldKeyID,
		NewKeyID:      newKeyID,
		OldEpoch:      1,
		NewEpoch:      2,
		NewPublicKey:  hex.EncodeToString(newKey.Public().(ed25519.PublicKey)),
		HostID:        testHostID,
		OccurredAt:    pccArchiveTestTime,
		OldSignature:  strings.Repeat("0", ed25519.SignatureSize*2),
		NewSignature:  strings.Repeat("0", ed25519.SignatureSize*2),
	}
	message, err := contracts.KeyTransitionSigningMessage(transition)
	if err != nil {
		t.Fatal(err)
	}
	transition.OldSignature = hex.EncodeToString(ed25519.Sign(oldKey, message))
	transition.NewSignature = hex.EncodeToString(ed25519.Sign(newKey, message))
	transitionFields, err := transitionMap(transition)
	if err != nil {
		t.Fatal(err)
	}
	transitionEvent := pccArchiveEnvelope(
		t,
		oldKey,
		1,
		transitionBootID,
		transitionSequence,
		"observer_key_transition",
		transitionFields,
		transitionFlags,
	)
	startEvent := pccArchiveEnvelope(
		t,
		newKey,
		2,
		startBootID,
		transitionSequence+1,
		"observer_key_epoch_start",
		map[string]any{
			"kind":      "observer_key_epoch_start",
			"key_id":    newKeyID,
			"key_epoch": uint64(2),
		},
		startFlags,
	)
	return transitionEvent, startEvent
}

func pccArchiveKeyring(
	t *testing.T,
	keys ...ed25519.PrivateKey,
) *Keyring {
	t.Helper()
	keyring := NewKeyring()
	keyring.hostID = testHostID
	for index, key := range keys {
		if err := keyring.Add(
			uint64(index+1),
			key.Public().(ed25519.PublicKey),
		); err != nil {
			t.Fatal(err)
		}
	}
	keyring.metadataEpoch = uint64(len(keys))
	return keyring
}

func pccArchiveState(
	t *testing.T,
	root string,
	privateKey ed25519.PrivateKey,
	bootID string,
	epoch uint64,
) *StateStore {
	t.Helper()
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
			KeyEpoch: epoch,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func pccArchiveAdoptState(
	t *testing.T,
	state *StateStore,
	next ObserverState,
) {
	t.Helper()
	if err := persistState(state.path, next); err != nil {
		t.Fatal(err)
	}
	state.mutex.Lock()
	state.state = cloneObserverState(next)
	state.mutex.Unlock()
}

func pccArchivePendingCrossBoot(
	t *testing.T,
	state *StateStore,
	currentBoot string,
	firstSequence uint64,
	previousBoot string,
	previousSequence uint64,
) {
	t.Helper()
	next := state.Snapshot()
	next.BootID = currentBoot
	next.LastSequence = firstSequence
	next.BootHistory = []BootBoundary{
		{
			BootID:            previousBoot,
			FirstSequence:     1,
			BoundaryEventID:   "evt_" + strings.Repeat("1", 64),
			BoundaryEventType: "observer_boot_boundary",
		},
		{
			BootID:        currentBoot,
			FirstSequence: firstSequence,
		},
	}
	next.BootBoundaryState = bootBoundaryPending
	next.PendingBootBoundary = &PendingBootBoundary{
		ReasonCode:             "kernel_boot_id_changed",
		PreviousBootID:         &next.BootHistory[0].BootID,
		PreviousSourceSequence: previousSequence,
	}
	next.ReconcileRequired = true
	pccArchiveAdoptState(t, state, next)
}

func pccArchiveCommitForTest(
	t *testing.T,
	state *StateStore,
	event contracts.EventEnvelopeV1,
) {
	t.Helper()
	next := state.Snapshot()
	last := len(next.BootHistory) - 1
	next.BootHistory[last].BoundaryEventID = event.EventID
	next.BootHistory[last].BoundaryEventType = event.EventType
	next.BootBoundaryState = bootBoundaryCommitted
	next.PendingBootBoundary = nil
	pccArchiveAdoptState(t, state, next)
}

func pccEnvelopeContentHash(
	t *testing.T,
	event contracts.EventEnvelopeV1,
) string {
	t.Helper()
	raw, err := contracts.CanonicalJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func pccResignArchiveEvent(
	t *testing.T,
	event contracts.EventEnvelopeV1,
	privateKey ed25519.PrivateKey,
	recomputeNormalized bool,
) contracts.EventEnvelopeV1 {
	t.Helper()
	if recomputeNormalized {
		raw, err := contracts.CanonicalJSON(event.NormalizedFields)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		event.NormalizedFieldsSHA256 = hex.EncodeToString(sum[:])
		event.SourcePayloadHash = event.NormalizedFieldsSHA256
	}
	event.EventID = ""
	event.SourceSignature = ""
	var err error
	event.EventID, err = contracts.DeriveEventID(event)
	if err != nil {
		t.Fatal(err)
	}
	message, err := contracts.EventSigningMessage(event)
	if err != nil {
		t.Fatal(err)
	}
	event.SourceSignature = hex.EncodeToString(ed25519.Sign(privateKey, message))
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestPCCBoundaryArchiveDedicatedBoundarySurvivesAckAndRestart(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 213)
	state := pccArchiveState(t, root, privateKey, testBootID2, 1)
	boundary := pccArchiveDedicated(
		t,
		privateKey,
		testBootID2,
		10,
		testBootID,
		9,
	)
	pccArchivePendingCrossBoot(t, state, testBootID2, 10, testBootID, 9)
	archive, err := OpenPCCBoundaryArchive(
		root,
		state,
		pccArchiveKeyring(t, privateKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.RecordCommittedBoundary(boundary, nil); err != nil {
		t.Fatal(err)
	}
	pccArchiveCommitForTest(t, state, boundary)
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenPCCBoundaryArchive(
		root,
		state,
		pccArchiveKeyring(t, privateKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	chain, err := restarted.Chain(testBootID, testBootID2)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 ||
		chain[0].EventID != boundary.EventID ||
		chain[0].ContentSHA256 != pccEnvelopeContentHash(t, boundary) {
		t.Fatalf("unexpected dedicated chain: %+v", chain)
	}
}

func TestPCCBoundaryArchiveDerivesRotationPathsBAndC(t *testing.T) {
	oldKey := testKey(t, 214)
	newKey := testKey(t, 215)
	tests := []struct {
		name     string
		boundary func(
			contracts.EventEnvelopeV1,
			contracts.EventEnvelopeV1,
		) contracts.EventEnvelopeV1
		companion func(
			contracts.EventEnvelopeV1,
			contracts.EventEnvelopeV1,
		) contracts.EventEnvelopeV1
		oldBoot string
		newBoot string
		flags   []string
	}{
		{
			name:     "B",
			boundary: func(transition, _ contracts.EventEnvelopeV1) contracts.EventEnvelopeV1 { return transition },
			companion: func(_, start contracts.EventEnvelopeV1) contracts.EventEnvelopeV1 {
				return start
			},
			oldBoot: testBootID,
			newBoot: testBootID2,
		},
		{
			name:     "C",
			boundary: func(_, start contracts.EventEnvelopeV1) contracts.EventEnvelopeV1 { return start },
			companion: func(transition, _ contracts.EventEnvelopeV1) contracts.EventEnvelopeV1 {
				return transition
			},
			oldBoot: testBootID,
			newBoot: testBootID2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			state := pccArchiveState(t, root, oldKey, test.newBoot, 1)
			transitionBoot := test.newBoot
			transitionFlags := []string{"boot_transition", "key_rotation"}
			startFlags := []string{"key_rotation"}
			if test.name == "C" {
				transitionBoot = test.oldBoot
				transitionFlags = []string{"key_rotation"}
				startFlags = []string{"boot_transition", "key_rotation"}
			}
			transition, start := pccArchiveRotationPair(
				t,
				oldKey,
				newKey,
				transitionBoot,
				test.newBoot,
				10,
				transitionFlags,
				startFlags,
			)
			boundary := test.boundary(transition, start)
			companion := test.companion(transition, start)
			firstSequence := boundary.SourceSequence
			previousSequence := firstSequence - 1
			pccArchivePendingCrossBoot(
				t,
				state,
				test.newBoot,
				firstSequence,
				test.oldBoot,
				previousSequence,
			)
			if test.name == "B" {
				pccArchiveCommitForTest(t, state, boundary)
				next := state.Snapshot()
				next.LastSequence = start.SourceSequence
				pccArchiveAdoptState(t, state, next)
			}
			archive, err := OpenPCCBoundaryArchive(
				root,
				state,
				pccArchiveKeyring(t, oldKey, newKey),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			if err := archive.RecordCommittedBoundary(
				boundary,
				&companion,
			); err != nil {
				t.Fatal(err)
			}
			if test.name == "C" {
				pccArchiveCommitForTest(t, state, boundary)
			}
			chain, err := archive.Chain(test.oldBoot, test.newBoot)
			if err != nil {
				t.Fatal(err)
			}
			if len(chain) != 1 ||
				chain[0].BoundaryEventType != boundary.EventType ||
				chain[0].RotationCompanionEventID == nil ||
				*chain[0].RotationCompanionEventID != companion.EventID {
				t.Fatalf("unexpected %s chain: %+v", test.name, chain)
			}
		})
	}
}

func TestPCCBoundaryArchiveBuildsMultipleConsecutiveHops(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 216)
	state := pccArchiveState(t, root, privateKey, testBootID3, 1)
	first := pccArchiveDedicated(
		t, privateKey, testBootID2, 10, testBootID, 9,
	)
	second := pccArchiveDedicated(
		t, privateKey, testBootID3, 20, testBootID2, 19,
	)
	next := state.Snapshot()
	next.LastSequence = 20
	next.BootHistory = []BootBoundary{
		{
			BootID:            testBootID,
			FirstSequence:     1,
			BoundaryEventID:   "evt_" + strings.Repeat("1", 64),
			BoundaryEventType: "observer_boot_boundary",
		},
		{
			BootID:            testBootID2,
			FirstSequence:     10,
			BoundaryEventID:   first.EventID,
			BoundaryEventType: first.EventType,
		},
		{
			BootID:            testBootID3,
			FirstSequence:     20,
			BoundaryEventID:   second.EventID,
			BoundaryEventType: second.EventType,
		},
	}
	next.BootBoundaryState = bootBoundaryCommitted
	next.PendingBootBoundary = nil
	pccArchiveAdoptState(t, state, next)
	archive, err := OpenPCCBoundaryArchive(
		root,
		state,
		pccArchiveKeyring(t, privateKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if err := archive.RecordCommittedBoundary(first, nil); err != nil {
		t.Fatal(err)
	}
	if err := archive.RecordCommittedBoundary(second, nil); err != nil {
		t.Fatal(err)
	}
	chain, err := archive.Chain(testBootID, testBootID3)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 ||
		chain[0].BootID != testBootID2 ||
		chain[1].PreviousBootID != testBootID2 ||
		chain[1].BootID != testBootID3 {
		t.Fatalf("unexpected multi-hop chain: %+v", chain)
	}
}

func TestPCCBoundaryArchiveMigratedPrefixFailsClosedForOldTrigger(
	t *testing.T,
) {
	root := t.TempDir()
	privateKey := testKey(t, 221)
	state := pccArchiveState(t, root, privateKey, testBootID3, 1)
	legacy := pccArchiveDedicated(
		t, privateKey, testBootID2, 10, testBootID, 9,
	)
	retained := pccArchiveDedicated(
		t, privateKey, testBootID3, 20, testBootID2, 19,
	)
	next := state.Snapshot()
	next.LastSequence = 20
	next.BootHistory = []BootBoundary{
		{
			BootID:            testBootID,
			FirstSequence:     1,
			BoundaryEventID:   "evt_" + strings.Repeat("1", 64),
			BoundaryEventType: "observer_boot_boundary",
		},
		{
			BootID:            testBootID2,
			FirstSequence:     10,
			BoundaryEventID:   legacy.EventID,
			BoundaryEventType: legacy.EventType,
		},
		{
			BootID:            testBootID3,
			FirstSequence:     20,
			BoundaryEventID:   retained.EventID,
			BoundaryEventType: retained.EventType,
		},
	}
	next.BootBoundaryState = bootBoundaryCommitted
	next.PendingBootBoundary = nil
	pccArchiveAdoptState(t, state, next)
	archive, err := OpenPCCBoundaryArchive(
		root,
		state,
		pccArchiveKeyring(t, privateKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	// This models V4-to-V5 migration after the earlier boundary was already
	// ACK-cleaned: compact BootHistory knows it existed, but no authenticated
	// envelope may be synthesized into the new archive.
	if err := archive.RecordCommittedBoundary(retained, nil); err != nil {
		t.Fatal(err)
	}
	if chain, err := archive.Chain(testBootID, testBootID3); err == nil ||
		len(chain) != 0 {
		t.Fatalf(
			"legacy compact prefix synthesized: chain=%+v err=%v",
			chain,
			err,
		)
	}
	chain, err := archive.Chain(testBootID2, testBootID3)
	if err != nil || len(chain) != 1 ||
		chain[0].EventID != retained.EventID {
		t.Fatalf("authenticated suffix unavailable: chain=%+v err=%v", chain, err)
	}
}

func pccWriteArchiveRecords(
	t *testing.T,
	root string,
	state *StateStore,
	records []PCCBoundaryArchiveRecord,
) {
	t.Helper()
	spoolRoot := filepath.Join(root, "spool")
	if err := durablefile.EnsurePrivateDirectory(spoolRoot); err != nil {
		t.Fatal(err)
	}
	journal, err := durablefile.NewJournal(
		filepath.Join(spoolRoot, "pcc-boundaries.agf"),
		durablefile.WithMaxFrame(pccBoundaryArchiveMaxFrame),
	)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	var head string
	for _, record := range records {
		raw, err := contracts.CanonicalJSON(record)
		if err != nil {
			t.Fatal(err)
		}
		meta, err := journal.Append(raw, true)
		if err != nil {
			t.Fatal(err)
		}
		total += meta.Size
		head = hex.EncodeToString(meta.Hash[:])
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	next := state.Snapshot()
	next.PCCBoundaryCount = uint64(len(records))
	next.PCCBoundaryBytes = total
	next.PCCBoundaryHeadHash = head
	if len(records) == 0 {
		next.PCCBoundaryHeadHash = zeroPCCJournalHash
	}
	pccArchiveAdoptState(t, state, next)
}

func TestPCCBoundaryArchiveRejectsInvalidAuthenticatedHistory(t *testing.T) {
	privateKey := testKey(t, 217)
	base := pccArchiveDedicated(
		t, privateKey, testBootID2, 10, testBootID, 9,
	)
	tests := map[string]func(*testing.T, *PCCBoundaryArchiveRecord){
		"record schema": func(
			_ *testing.T,
			record *PCCBoundaryArchiveRecord,
		) {
			record.SchemaVersion = "agmind.pcc-boundary-archive-record.v2"
		},
		"signature": func(_ *testing.T, record *PCCBoundaryArchiveRecord) {
			record.BoundaryEvent.SourceSignature = strings.Repeat("0", 128)
		},
		"event ID": func(_ *testing.T, record *PCCBoundaryArchiveRecord) {
			record.BoundaryEvent.EventID = "evt_" + strings.Repeat("2", 64)
		},
		"content hash": func(_ *testing.T, record *PCCBoundaryArchiveRecord) {
			record.BoundaryEvent.NormalizedFieldsSHA256 = strings.Repeat("2", 64)
		},
		"boundary flags": func(
			t *testing.T,
			record *PCCBoundaryArchiveRecord,
		) {
			record.BoundaryEvent.CoverageFlags = []string{"reconcile_required"}
			record.BoundaryEvent = pccResignArchiveEvent(
				t,
				record.BoundaryEvent,
				privateKey,
				false,
			)
		},
		"key epoch": func(_ *testing.T, record *PCCBoundaryArchiveRecord) {
			record.BoundaryEvent.KeyEpoch++
		},
		"key ID": func(_ *testing.T, record *PCCBoundaryArchiveRecord) {
			record.BoundaryEvent.KeyID = strings.Repeat("2", 32)
		},
		"boot IDs": func(t *testing.T, record *PCCBoundaryArchiveRecord) {
			record.BoundaryEvent.BootID = testBootID3
			record.BoundaryEvent.NormalizedFields["boot_id"] = testBootID3
			record.BoundaryEvent = pccResignArchiveEvent(
				t,
				record.BoundaryEvent,
				privateKey,
				true,
			)
		},
		"predecessor sequence": func(
			t *testing.T,
			record *PCCBoundaryArchiveRecord,
		) {
			record.BoundaryEvent.NormalizedFields["previous_source_sequence"] =
				uint64(8)
			record.BoundaryEvent = pccResignArchiveEvent(
				t,
				record.BoundaryEvent,
				privateKey,
				true,
			)
		},
		"extra companion": func(
			_ *testing.T,
			record *PCCBoundaryArchiveRecord,
		) {
			companion := record.BoundaryEvent
			record.RotationCompanionEvent = &companion
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			state := pccArchiveState(t, root, privateKey, testBootID2, 1)
			pccArchivePendingCrossBoot(
				t, state, testBootID2, 10, testBootID, 9,
			)
			pccArchiveCommitForTest(t, state, base)
			record, err := clonePCCBoundaryRecord(PCCBoundaryArchiveRecord{
				SchemaVersion: pccBoundaryArchiveSchema,
				BoundaryEvent: base,
			})
			if err != nil {
				t.Fatal(err)
			}
			mutate(t, &record)
			pccWriteArchiveRecords(t, root, state, []PCCBoundaryArchiveRecord{record})
			if archive, err := OpenPCCBoundaryArchive(
				root,
				state,
				pccArchiveKeyring(t, privateKey),
			); !errors.Is(err, ErrPCCJournalCorrupt) {
				if archive != nil {
					_ = archive.Close()
				}
				t.Fatalf("invalid %s history err=%v", name, err)
			}
		})
	}

	t.Run("pair ordering adjacency and missing companion", func(t *testing.T) {
		oldKey := testKey(t, 225)
		newKey := testKey(t, 226)
		transition, start := pccArchiveRotationPair(
			t,
			oldKey,
			newKey,
			testBootID2,
			testBootID2,
			10,
			[]string{"boot_transition", "key_rotation"},
			[]string{"key_rotation"},
		)
		tests := map[string]PCCBoundaryArchiveRecord{
			"pair ordering": {
				SchemaVersion:          pccBoundaryArchiveSchema,
				BoundaryEvent:          start,
				RotationCompanionEvent: &transition,
			},
			"missing companion": {
				SchemaVersion: pccBoundaryArchiveSchema,
				BoundaryEvent: transition,
			},
			"pair adjacency": func() PCCBoundaryArchiveRecord {
				changed := start
				changed.SourceSequence++
				changed = pccResignArchiveEvent(
					t,
					changed,
					newKey,
					false,
				)
				return PCCBoundaryArchiveRecord{
					SchemaVersion:          pccBoundaryArchiveSchema,
					BoundaryEvent:          transition,
					RotationCompanionEvent: &changed,
				}
			}(),
		}
		for name, record := range tests {
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				state := pccArchiveState(t, root, oldKey, testBootID2, 1)
				pccArchivePendingCrossBoot(
					t, state, testBootID2, 10, testBootID, 9,
				)
				pccArchiveCommitForTest(t, state, transition)
				next := state.Snapshot()
				next.LastSequence = 12
				pccArchiveAdoptState(t, state, next)
				pccWriteArchiveRecords(
					t,
					root,
					state,
					[]PCCBoundaryArchiveRecord{record},
				)
				if archive, err := OpenPCCBoundaryArchive(
					root,
					state,
					pccArchiveKeyring(t, oldKey, newKey),
				); !errors.Is(err, ErrPCCJournalCorrupt) {
					if archive != nil {
						_ = archive.Close()
					}
					t.Fatalf("invalid %s err=%v", name, err)
				}
			})
		}
	})

	t.Run("duplicated event", func(t *testing.T) {
		root := t.TempDir()
		state := pccArchiveState(t, root, privateKey, testBootID2, 1)
		pccArchivePendingCrossBoot(t, state, testBootID2, 10, testBootID, 9)
		pccArchiveCommitForTest(t, state, base)
		record := PCCBoundaryArchiveRecord{
			SchemaVersion: pccBoundaryArchiveSchema,
			BoundaryEvent: base,
		}
		pccWriteArchiveRecords(
			t,
			root,
			state,
			[]PCCBoundaryArchiveRecord{record, record},
		)
		if archive, err := OpenPCCBoundaryArchive(
			root,
			state,
			pccArchiveKeyring(t, privateKey),
		); !errors.Is(err, ErrPCCJournalCorrupt) {
			if archive != nil {
				_ = archive.Close()
			}
			t.Fatalf("duplicated history err=%v", err)
		}
	})

	t.Run("archive order", func(t *testing.T) {
		root := t.TempDir()
		first := pccArchiveDedicated(
			t, privateKey, testBootID2, 10, testBootID, 9,
		)
		second := pccArchiveDedicated(
			t, privateKey, testBootID3, 20, testBootID2, 19,
		)
		state := pccArchiveState(t, root, privateKey, testBootID3, 1)
		next := state.Snapshot()
		next.LastSequence = 20
		next.BootHistory = []BootBoundary{
			{
				BootID:            testBootID,
				FirstSequence:     1,
				BoundaryEventID:   "evt_" + strings.Repeat("1", 64),
				BoundaryEventType: "observer_boot_boundary",
			},
			{
				BootID:            testBootID2,
				FirstSequence:     10,
				BoundaryEventID:   first.EventID,
				BoundaryEventType: first.EventType,
			},
			{
				BootID:            testBootID3,
				FirstSequence:     20,
				BoundaryEventID:   second.EventID,
				BoundaryEventType: second.EventType,
			},
		}
		next.BootBoundaryState = bootBoundaryCommitted
		next.PendingBootBoundary = nil
		pccArchiveAdoptState(t, state, next)
		pccWriteArchiveRecords(
			t,
			root,
			state,
			[]PCCBoundaryArchiveRecord{
				{
					SchemaVersion: pccBoundaryArchiveSchema,
					BoundaryEvent: second,
				},
				{
					SchemaVersion: pccBoundaryArchiveSchema,
					BoundaryEvent: first,
				},
			},
		)
		if archive, err := OpenPCCBoundaryArchive(
			root,
			state,
			pccArchiveKeyring(t, privateKey),
		); !errors.Is(err, ErrPCCJournalCorrupt) {
			if archive != nil {
				_ = archive.Close()
			}
			t.Fatalf("reordered archive err=%v", err)
		}
	})
}

func TestPCCBoundaryArchiveRejectsTailAnchorAndQuotaViolations(t *testing.T) {
	privateKey := testKey(t, 218)
	boundary := pccArchiveDedicated(
		t, privateKey, testBootID2, 10, testBootID, 9,
	)
	record := PCCBoundaryArchiveRecord{
		SchemaVersion: pccBoundaryArchiveSchema,
		BoundaryEvent: boundary,
	}
	t.Run("unanchored complete tail", func(t *testing.T) {
		root := t.TempDir()
		state := pccArchiveState(t, root, privateKey, testBootID2, 1)
		pccArchivePendingCrossBoot(t, state, testBootID2, 10, testBootID, 9)
		pccArchiveCommitForTest(t, state, boundary)
		pccWriteArchiveRecords(
			t, root, state, []PCCBoundaryArchiveRecord{record},
		)
		journal, err := durablefile.NewJournal(
			filepath.Join(root, "spool", "pcc-boundaries.agf"),
			durablefile.WithMaxFrame(pccBoundaryArchiveMaxFrame),
		)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := contracts.CanonicalJSON(record)
		if _, err := journal.Append(raw, true); err != nil {
			t.Fatal(err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		if archive, err := OpenPCCBoundaryArchive(
			root,
			state,
			pccArchiveKeyring(t, privateKey),
		); !errors.Is(err, ErrPCCJournalCorrupt) {
			if archive != nil {
				_ = archive.Close()
			}
			t.Fatalf("unanchored complete tail err=%v", err)
		}
	})

	t.Run("unanchored torn tail remains", func(t *testing.T) {
		root := t.TempDir()
		state := pccArchiveState(t, root, privateKey, testBootID2, 1)
		pccArchivePendingCrossBoot(t, state, testBootID2, 10, testBootID, 9)
		pccArchiveCommitForTest(t, state, boundary)
		pccWriteArchiveRecords(
			t, root, state, []PCCBoundaryArchiveRecord{record},
		)
		path := filepath.Join(root, "spool", "pcc-boundaries.agf")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("AGF1")); err != nil {
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if archive, err := OpenPCCBoundaryArchive(
			root,
			state,
			pccArchiveKeyring(t, privateKey),
		); !errors.Is(err, ErrPCCJournalCorrupt) {
			if archive != nil {
				_ = archive.Close()
			}
			t.Fatalf("unanchored torn tail err=%v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Fatal("rejected torn tail was destructively repaired")
		}
	})

	t.Run("payload 128 KiB plus one", func(t *testing.T) {
		root := t.TempDir()
		state := pccArchiveState(t, root, privateKey, testBootID2, 1)
		spoolRoot := filepath.Join(root, "spool")
		if err := durablefile.EnsurePrivateDirectory(spoolRoot); err != nil {
			t.Fatal(err)
		}
		frame, _, err := durablefile.EncodeFrame(
			make([]byte, int(pccBoundaryArchiveMaxFrame)+1),
			[sha256.Size]byte{},
			pccBoundaryArchiveMaxFrame+1,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := durablefile.CreateOnly(
			filepath.Join(spoolRoot, "pcc-boundaries.agf"),
			frame,
		); err != nil {
			t.Fatal(err)
		}
		if archive, err := OpenPCCBoundaryArchive(
			root,
			state,
			pccArchiveKeyring(t, privateKey),
		); !errors.Is(err, ErrPCCJournalCorrupt) {
			if archive != nil {
				_ = archive.Close()
			}
			t.Fatalf("oversize payload err=%v", err)
		}
	})

	t.Run("count 1025", func(t *testing.T) {
		root := t.TempDir()
		state := pccArchiveState(t, root, privateKey, testBootID2, 1)
		spoolRoot := filepath.Join(root, "spool")
		if err := durablefile.EnsurePrivateDirectory(spoolRoot); err != nil {
			t.Fatal(err)
		}
		journal, err := durablefile.NewJournal(
			filepath.Join(spoolRoot, "pcc-boundaries.agf"),
			durablefile.WithMaxFrame(pccBoundaryArchiveMaxFrame),
		)
		if err != nil {
			t.Fatal(err)
		}
		for index := 0; index < 1_025; index++ {
			if _, err := journal.Append([]byte("{}"), false); err != nil {
				t.Fatal(err)
			}
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		if archive, err := OpenPCCBoundaryArchive(
			root,
			state,
			pccArchiveKeyring(t, privateKey),
		); !errors.Is(err, ErrPCCJournalCorrupt) {
			if archive != nil {
				_ = archive.Close()
			}
			t.Fatalf("count overflow err=%v", err)
		}
	})

	t.Run("verified bytes 64 MiB plus one", func(t *testing.T) {
		root := t.TempDir()
		state := pccArchiveState(t, root, privateKey, testBootID2, 1)
		spoolRoot := filepath.Join(root, "spool")
		if err := durablefile.EnsurePrivateDirectory(spoolRoot); err != nil {
			t.Fatal(err)
		}
		journal, err := durablefile.NewJournal(
			filepath.Join(spoolRoot, "pcc-boundaries.agf"),
			durablefile.WithMaxFrame(pccBoundaryArchiveMaxFrame),
		)
		if err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, int(pccBoundaryArchiveMaxFrame))
		var written uint64
		for written <= pccBoundaryArchiveMaxBytes {
			meta, err := journal.Append(payload, false)
			if err != nil {
				t.Fatal(err)
			}
			written += meta.Size
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		if archive, err := OpenPCCBoundaryArchive(
			root,
			state,
			pccArchiveKeyring(t, privateKey),
		); !errors.Is(err, ErrPCCJournalCorrupt) {
			if archive != nil {
				_ = archive.Close()
			}
			t.Fatalf("verified-byte overflow err=%v", err)
		}
	})
}

func TestPCCBoundaryArchivePersistsReadOnlyAfterUncertainMutation(
	t *testing.T,
) {
	privateKey := testKey(t, 227)
	boundary := pccArchiveDedicated(
		t, privateKey, testBootID2, 10, testBootID, 9,
	)

	t.Run("append", func(t *testing.T) {
		root := t.TempDir()
		state := pccArchiveState(t, root, privateKey, testBootID2, 1)
		pccArchivePendingCrossBoot(
			t, state, testBootID2, 10, testBootID, 9,
		)
		pccArchiveCommitForTest(t, state, boundary)
		injected := errors.New("injected uncertain archive append")
		archive, err := openPCCBoundaryArchive(
			root,
			state,
			pccArchiveKeyring(t, privateKey),
			durablefile.WithSync(func(*os.File) error {
				return errors.Join(durablefile.ErrCommitUncertain, injected)
			}),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer archive.Close()
		err = archive.RecordCommittedBoundary(boundary, nil)
		if !errors.Is(err, durablefile.ErrCommitUncertain) ||
			!errors.Is(err, injected) {
			t.Fatalf("append error=%v", err)
		}
		snapshot := state.Snapshot()
		if !snapshot.MutationReadOnly ||
			snapshot.ReadOnlyReason !=
				"observer_pcc_boundary_archive_append_failed" {
			t.Fatalf("append failure did not persist read-only: %+v", snapshot)
		}
	})

	t.Run("anchor", func(t *testing.T) {
		root := t.TempDir()
		state := pccArchiveState(t, root, privateKey, testBootID2, 1)
		pccArchivePendingCrossBoot(
			t, state, testBootID2, 10, testBootID, 9,
		)
		pccArchiveCommitForTest(t, state, boundary)
		archive, err := OpenPCCBoundaryArchive(
			root,
			state,
			pccArchiveKeyring(t, privateKey),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer archive.Close()
		injected := errors.New("injected uncertain archive anchor")
		state.persist = func(path string, next ObserverState) error {
			if next.PCCBoundaryCount == 1 && !next.MutationReadOnly {
				return errors.Join(durablefile.ErrCommitUncertain, injected)
			}
			return persistState(path, next)
		}
		err = archive.RecordCommittedBoundary(boundary, nil)
		if !errors.Is(err, durablefile.ErrCommitUncertain) ||
			!errors.Is(err, injected) {
			t.Fatalf("anchor error=%v", err)
		}
		snapshot := state.Snapshot()
		if !snapshot.MutationReadOnly ||
			snapshot.ReadOnlyReason !=
				"observer_pcc_boundary_archive_anchor_failed" ||
			snapshot.PCCBoundaryCount != 1 {
			t.Fatalf("anchor failure did not persist read-only: %+v", snapshot)
		}
	})
}

func TestPCCBoundaryArchiveDoesNotExpandPublicKeyMetadata(t *testing.T) {
	metadata := PublicKeyMetadata{Keys: make([]PublicKeyEpoch, 17)}
	if err := metadata.Validate(); err == nil {
		t.Fatal("public key metadata accepted more than 16 epochs")
	}
}

func TestPCCBoundaryArchiveSkipsGenesisBoundary(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 219)
	state := pccArchiveState(t, root, privateKey, testBootID, 1)
	genesis := pccArchiveEnvelope(
		t,
		privateKey,
		1,
		testBootID,
		1,
		"observer_boot_boundary",
		map[string]any{
			"schema_version":           "agmind.observer-boot-boundary.v1",
			"kind":                     "observer_boot_boundary",
			"reason_code":              "observer_genesis",
			"previous_source_sequence": uint64(0),
		},
		[]string{"boot_transition", "reconcile_required"},
	)
	archive, err := OpenPCCBoundaryArchive(
		root,
		state,
		pccArchiveKeyring(t, privateKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if err := archive.RecordCommittedBoundary(genesis, nil); err != nil {
		t.Fatal(err)
	}
	anchor := state.Snapshot()
	if anchor.PCCBoundaryCount != 0 ||
		anchor.PCCBoundaryBytes != 0 ||
		anchor.PCCBoundaryHeadHash != zeroPCCJournalHash {
		t.Fatalf("genesis expanded PCC archive: %+v", anchor)
	}
	if chain, err := archive.Chain(testBootID2, testBootID); err == nil ||
		len(chain) != 0 {
		t.Fatalf("genesis synthesized a PCC hop: chain=%+v err=%v", chain, err)
	}
}
