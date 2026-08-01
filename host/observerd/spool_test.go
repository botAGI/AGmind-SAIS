package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

func resignEvent(
	t *testing.T,
	event contracts.EventEnvelopeV1,
	privateKey ed25519.PrivateKey,
	normalized map[string]any,
) contracts.EventEnvelopeV1 {
	t.Helper()
	canonical, err := contracts.CanonicalJSON(normalized)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	event.NormalizedFields = normalized
	event.NormalizedFieldsSHA256 = hex.EncodeToString(digest[:])
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

func TestSpoolAppendIsCreateOnlyIdempotentAndConflictsFailClosed(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 10)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "one"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := spool.Append(event, RoutineTier)
	if err != nil {
		t.Fatal(err)
	}
	second, err := spool.Append(event, RoutineTier)
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentSHA256 != second.ContentSHA256 || first.path != second.path {
		t.Fatal("same payload retry was not idempotent")
	}
	conflict := resignEvent(
		t,
		event,
		privateKey,
		map[string]any{"kind": "different"},
	)
	if _, err := spool.Append(
		conflict,
		RoutineTier,
	); !errors.Is(err, ErrSpoolCorrupt) {
		t.Fatalf("got %v, want ErrSpoolCorrupt", err)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("sequence conflict did not persist read-only")
	}
}

func TestSpoolPublishFailureNeverExposesFinalName(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 17)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	publishErr := errors.New("injected pre-publish failure")
	spool.publish = func(string, []byte) error { return publishErr }
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "one"},
		metadata(),
	); !errors.Is(err, publishErr) {
		t.Fatalf("got %v, want publish error", err)
	}
	path := filepath.Join(spool.directory(RoutineTier), "00000000000000000001.agf")
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed publication exposed final name: %v", err)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("uncertain publish did not hold read-only")
	}
}

func TestFetchRevalidatesSignatureAndStandaloneCorruptionNeverTruncates(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 11)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "one"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	event.SourceSignature = stringsOf("0", 128)
	canonical, err := contracts.CanonicalJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := durablefile.EncodeFrame(canonical, [32]byte{}, 65_536)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(item.path, frame, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(item.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Fetch(0, 100, 4*1024*1024); !errors.Is(
		err,
		ErrSpoolCorrupt,
	) {
		t.Fatalf("got %v, want ErrSpoolCorrupt", err)
	}
	after, err := os.Stat(item.path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() || !state.Snapshot().MutationReadOnly {
		t.Fatal("invalid standalone frame was truncated or did not fail closed")
	}
}

func stringsOf(value string, count int) string {
	var buffer bytes.Buffer
	for range count {
		buffer.WriteString(value)
	}
	return buffer.String()
}

func TestStartupRejectsSequenceRollbackAndSymlinkAlias(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string, *StateStore, *Spool){
		"sequence rollback": func(t *testing.T, _ string, state *StateStore, _ *Spool) {
			t.Helper()
			state.mutex.Lock()
			next := state.state
			next.LastSequence = 0
			next.PublicationHeadSequence = 0
			next.PublicationHeadHash = zeroPublicationHash
			if err := state.replaceLocked(next); err != nil {
				state.mutex.Unlock()
				t.Fatal(err)
			}
			state.mutex.Unlock()
		},
		"symlink alias": func(t *testing.T, root string, _ *StateStore, spool *Spool) {
			t.Helper()
			for _, item := range spool.items {
				alias := filepath.Join(
					spool.directory(PriorityTier),
					filepath.Base(item.path),
				)
				if err := os.Symlink(item.path, alias); err != nil {
					t.Fatal(err)
				}
				return
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 12)
			state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
			if _, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": "one"},
				metadata(),
			); err != nil {
				t.Fatal(err)
			}
			mutate(t, root, state, spool)
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			keys := NewKeyring()
			if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal(err)
			}
			reopenedState, err := OpenStateStore(
				filepath.Join(root, "observer-state.json"),
				StateIdentity{
					HostID:   testHostID,
					BootID:   testBootID,
					KeyID:    state.Snapshot().KeyID,
					KeyEpoch: 1,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewSpool(
				SpoolConfig{
					StateDir:             root,
					MaxBytes:             4 * 1024 * 1024,
					PriorityReserveBytes: 1024 * 1024,
				},
				reopenedState,
				keys,
			); err == nil {
				t.Fatal("unsafe startup spool unexpectedly opened")
			}
			if !reopenedState.Snapshot().MutationReadOnly {
				t.Fatal("unsafe startup did not persist read-only")
			}
		})
	}
}

func TestSpoolStartupRejectsUnownedPCCReceiptJournal(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 233)
	state, spool, _ := openSignerFixture(t, root, testBootID, privateKey)
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.CreateOnly(
		filepath.Join(root, "spool", "pcc-receipts.agf"),
		[]byte("unowned"),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSpool(
		SpoolConfig{
			StateDir:             root,
			MaxBytes:             4 * 1024 * 1024,
			PriorityReserveBytes: 1024 * 1024,
		},
		state,
		pccArchiveKeyring(t, privateKey),
	); !errors.Is(err, ErrSpoolCorrupt) {
		t.Fatalf("V5 startup accepted unowned receipt journal: %v", err)
	}
	if snapshot := state.Snapshot(); !snapshot.MutationReadOnly ||
		snapshot.ReadOnlyReason != "observer_spool_root_unknown" {
		t.Fatalf("unowned receipt journal did not fail closed: %+v", snapshot)
	}
}

func TestStateAndSpoolDirectoriesRejectUnsafeMode(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	privateKey := testKey(t, 37)
	keyID, err := contracts.KeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStateStore(
		filepath.Join(stateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    keyID,
			KeyEpoch: 1,
		},
	); !errors.Is(err, durablefile.ErrUnsafePath) {
		t.Fatalf("unsafe state directory got %v", err)
	}

	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateStore(
		filepath.Join(stateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    keyID,
			KeyEpoch: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	spoolRoot := filepath.Join(stateDir, "spool")
	if err := os.Mkdir(spoolRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSpool(
		SpoolConfig{
			StateDir:             stateDir,
			MaxBytes:             4 * 1024 * 1024,
			PriorityReserveBytes: 1024 * 1024,
		},
		state,
		keys,
	); !errors.Is(err, durablefile.ErrUnsafePath) {
		t.Fatalf("unsafe spool directory got %v", err)
	}
}

func TestFetchMergesTiersBySequenceAndHonorsFirstByteBoundary(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 13)
	_, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	routine, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	priority, err := signer.Wrap(
		context.Background(),
		"observer_start",
		map[string]any{"kind": "priority"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 ||
		items[0].Sequence != routine.SourceSequence ||
		items[1].Sequence != priority.SourceSequence {
		t.Fatalf("fetch order=%+v", items)
	}
	tooSmall := uint64(len(items[0].Canonical) - 1)
	items, err = spool.Fetch(0, 100, tooSmall)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatal("fetch skipped the earliest event to fit a later event")
	}
}

func TestAckIsDurableBeforeDeleteAndLogicalOnCleanupFailure(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 14)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	removeErr := errors.New("injected remove failure")
	spool.remove = func(string, durablefile.FileIdentity) error { return removeErr }
	if err := spool.Ack(
		item.Sequence,
		item.EventID,
		item.ContentSHA256,
	); !errors.Is(err, removeErr) {
		t.Fatalf("got %v, want remove failure", err)
	}
	snapshot := state.Snapshot()
	if snapshot.AckSequence != item.Sequence ||
		snapshot.AckRecordHash == "" {
		t.Fatal("ack identity/head was not persisted before delete")
	}
	if _, err := os.Stat(item.path); err != nil {
		t.Fatalf("injected failure unexpectedly removed file: %v", err)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatal("durably acked item was redelivered after cleanup failure")
	}
	spool.remove = func(path string, identity durablefile.FileIdentity) error {
		return durablefile.RemoveIfIdentity(path, identity)
	}
	if err := spool.Ack(item.Sequence, item.EventID, item.ContentSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(item.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("idempotent ack did not reconcile cleanup: %v", err)
	}
}

func TestAckJournalAheadReconcilesForwardButJournalRegressionFailsClosed(t *testing.T) {
	for name, testCase := range map[string]struct {
		mutate    func(*testing.T, string, []byte)
		wantError bool
	}{
		"cleaned journal ahead without durable anchor": {
			mutate: func(t *testing.T, statePath string, oldState []byte) {
				t.Helper()
				if err := durablefile.AtomicWrite(statePath, oldState); err != nil {
					t.Fatal(err)
				}
			},
			wantError: true,
		},
		"journal regression": {
			mutate: func(t *testing.T, statePath string, _ []byte) {
				t.Helper()
				ackPath := filepath.Join(filepath.Dir(statePath), "spool", "acked.agf")
				if err := os.Truncate(ackPath, 0); err != nil {
					t.Fatal(err)
				}
			},
			wantError: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 15)
			state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
			event, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": "routine"},
				metadata(),
			)
			if err != nil {
				t.Fatal(err)
			}
			statePath := filepath.Join(root, "observer-state.json")
			oldState, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			item := spool.items[event.SourceSequence]
			if err := spool.Ack(
				item.Sequence,
				item.EventID,
				item.ContentSHA256,
			); err != nil {
				t.Fatal(err)
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(t, statePath, oldState)
			keys := NewKeyring()
			if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal(err)
			}
			state, err = OpenStateStore(
				statePath,
				StateIdentity{
					HostID:   testHostID,
					BootID:   testBootID,
					KeyID:    state.Snapshot().KeyID,
					KeyEpoch: 1,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := NewSpool(
				SpoolConfig{
					StateDir:             root,
					MaxBytes:             4 * 1024 * 1024,
					PriorityReserveBytes: 1024 * 1024,
				},
				state,
				keys,
			)
			if testCase.wantError {
				if err == nil || !state.Snapshot().MutationReadOnly {
					if reopened != nil {
						_ = reopened.Close()
					}
					t.Fatalf("regression err=%v readonly=%v", err, state.Snapshot().MutationReadOnly)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if state.Snapshot().AckSequence != item.Sequence ||
				state.Snapshot().AckRecordHash == "" {
				t.Fatal("journal-ahead state did not reconcile forward")
			}
		})
	}
}

func TestAckHistoryAheadOfReservationStateFailsReadOnly(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 38)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	for sequence := 1; sequence <= 2; sequence++ {
		if _, err := signer.Wrap(
			context.Background(),
			"falco_connect",
			map[string]any{"sequence": sequence},
			metadata(),
		); err != nil {
			t.Fatal(err)
		}
	}
	statePath := filepath.Join(root, "observer-state.json")
	oldState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := 3; sequence <= 5; sequence++ {
		if _, err := signer.Wrap(
			context.Background(),
			"falco_connect",
			map[string]any{"sequence": sequence},
			metadata(),
		); err != nil {
			t.Fatal(err)
		}
	}
	for sequence := uint64(1); sequence <= 5; sequence++ {
		item := spool.items[sequence]
		if err := spool.Ack(
			item.Sequence,
			item.EventID,
			item.ContentSHA256,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(statePath, oldState); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	reopenedState, err := OpenStateStore(
		statePath,
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    state.Snapshot().KeyID,
			KeyEpoch: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSpool(
		SpoolConfig{
			StateDir:             root,
			MaxBytes:             4 * 1024 * 1024,
			PriorityReserveBytes: 1024 * 1024,
		},
		reopenedState,
		keys,
	)
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!reopenedState.Snapshot().MutationReadOnly {
		t.Fatalf(
			"err=%v readonly=%v",
			err,
			reopenedState.Snapshot().MutationReadOnly,
		)
	}
}

func TestUncoveredGapsDoesNotWrapAtMaxAcknowledgedSequence(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 39)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "last"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	if err := spool.Ack(
		item.Sequence,
		item.EventID,
		item.ContentSHA256,
	); err != nil {
		t.Fatal(err)
	}
	state.mutex.Lock()
	state.state.LastSequence = ^uint64(0)
	state.state.AckSequence = ^uint64(0)
	state.mutex.Unlock()
	if gaps := spool.UncoveredGaps(0); len(gaps) != 0 {
		t.Fatalf("wrapped max ack into gaps: %+v", gaps)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("max acknowledged sequence did not persist read-only exhaustion")
	}
}

func TestAckAnchorWriteFailureCannotAppendDuplicateOnRetry(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 34)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	statePath := state.path
	state.path = filepath.Join(root, "missing", "observer-state.json")
	if err := spool.Ack(
		item.Sequence,
		item.EventID,
		item.ContentSHA256,
	); err == nil {
		t.Fatal("injected state-anchor persistence failure succeeded")
	}
	if state.Snapshot().AckSequence != item.Sequence {
		t.Fatal("durable journal head was not adopted in memory after state failure")
	}
	state.path = statePath
	if err := spool.Ack(item.Sequence, item.EventID, item.ContentSHA256); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err := durablefile.Recover(
		filepath.Join(root, "spool", "acked.agf"),
		4_096,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovery.Records) != 1 {
		t.Fatalf("ack retry wrote %d records, want one", len(recovery.Records))
	}
}

func TestAckJournalCountsTowardQuotaAndCompactsToOneCheckpoint(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 35)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	for index := range 4 {
		if _, err := signer.Wrap(
			context.Background(),
			"falco_connect",
			map[string]any{"index": index},
			metadata(),
		); err != nil {
			t.Fatal(err)
		}
	}
	for sequence := uint64(1); sequence <= 4; sequence++ {
		item := spool.items[sequence]
		if err := spool.Ack(
			item.Sequence,
			item.EventID,
			item.ContentSHA256,
		); err != nil {
			t.Fatal(err)
		}
		ackInfo, err := os.Stat(filepath.Join(root, "spool", "acked.agf"))
		if err != nil {
			t.Fatal(err)
		}
		var wantTotal uint64 = uint64(ackInfo.Size())
		for _, remaining := range spool.items {
			wantTotal += remaining.frameBytes + remaining.publicationBytes
		}
		if spool.totalBytes != wantTotal ||
			spool.totalBytes > spool.config.MaxBytes {
			t.Fatalf(
				"total=%d want=%d max=%d",
				spool.totalBytes,
				wantTotal,
				spool.config.MaxBytes,
			)
		}
	}
	if state.Snapshot().AckPayloadSHA256 == "" {
		t.Fatal("checkpoint payload hash was not anchored")
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err := durablefile.Recover(
		filepath.Join(root, "spool", "acked.agf"),
		4_096,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovery.Records) != 1 {
		t.Fatalf("ack journal retained %d records, want one checkpoint", len(recovery.Records))
	}
}

func TestAckJournalCannotExceedConfiguredTotalQuota(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 36)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	spool.config.MaxBytes = spool.totalBytes + 1
	if err := spool.Ack(
		item.Sequence,
		item.EventID,
		item.ContentSHA256,
	); !errors.Is(err, ErrPriorityQuota) {
		t.Fatalf("got %v, want priority quota", err)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("ack quota exhaustion did not fail read-only")
	}
}

func TestRoutineQuotaPreservesReserveAndPriorityExhaustionIsReadOnly(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 16)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	spool.config.MaxBytes = spool.totalBytes + 100_000
	spool.config.PriorityReserveBytes = 100_000
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine-two"},
		metadata(),
	); !errors.Is(err, ErrRoutineQuota) {
		t.Fatalf("got %v, want routine quota", err)
	}
	if state.Snapshot().MutationReadOnly {
		t.Fatal("routine pressure consumed priority/read-only state")
	}
	spool.config.MaxBytes = spool.totalBytes + 1
	spool.config.PriorityReserveBytes = 1
	if _, err := signer.Wrap(
		context.Background(),
		"observer_start",
		map[string]any{"kind": "priority"},
		metadata(),
	); !errors.Is(err, ErrPriorityQuota) {
		t.Fatalf("got %v, want priority quota", err)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("priority exhaustion did not persist read-only")
	}
}
