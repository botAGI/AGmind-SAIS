package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
	"golang.org/x/sys/unix"
)

func TestMalformedEd25519PrivateKeyIsRejectedBeforeReservation(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := append(ed25519.PrivateKey(nil), testKey(t, 71)...)
	privateKey[len(privateKey)-1] ^= 1
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := contracts.KeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateStore(
		filepath.Join(root, "observer-state.json"),
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
	keys := NewKeyring()
	if err := keys.Add(1, publicKey); err != nil {
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
	defer spool.Close()

	signer, err := NewEnvelopeSigner(
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
		privateKey,
	)
	if err == nil || signer != nil {
		t.Fatal("seed/public-half mismatch was accepted")
	}
	if state.Snapshot().LastSequence != 0 {
		t.Fatal("invalid private key consumed a sequence")
	}
}

func TestSignerBootMismatchRefusesWithoutMutatingState(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 72)
	state, spool, _ := openSignerFixture(t, root, testBootID, privateKey)
	beforeSnapshot := state.Snapshot()
	beforeRaw, err := os.ReadFile(state.path)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewEnvelopeSigner(
		SignerConfig{
			HostID:        testHostID,
			BootID:        testBootID2,
			KeyEpoch:      1,
			SourceID:      "agmind-observerd",
			SourceVersion: "0.1.0",
			Now:           time.Now,
		},
		state,
		spool,
		privateKey,
	)
	if err == nil || signer != nil {
		t.Fatal("signer accepted a boot ID different from durable state")
	}
	afterRaw, readErr := os.ReadFile(state.path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(state.Snapshot(), beforeSnapshot) ||
		!bytes.Equal(afterRaw, beforeRaw) {
		t.Fatal("signer identity mismatch mutated durable or in-memory state")
	}
}

func TestPublicMetadataCurrentKeyMustBeFinalMaximumEpoch(t *testing.T) {
	keyOne := testKey(t, 73).Public().(ed25519.PublicKey)
	keyTwo := testKey(t, 74).Public().(ed25519.PublicKey)
	keyOneID, err := contracts.KeyID(keyOne)
	if err != nil {
		t.Fatal(err)
	}
	keyTwoID, err := contracts.KeyID(keyTwo)
	if err != nil {
		t.Fatal(err)
	}
	metadata := PublicKeyMetadata{
		SchemaVersion: "agmind.observer-public-keys.v1",
		HostID:        testHostID,
		CurrentKeyID:  keyOneID,
		CurrentEpoch:  1,
		Keys: []PublicKeyEpoch{
			{KeyID: keyOneID, Epoch: 1, PublicKey: encodePublicKey(keyOne)},
			{KeyID: keyTwoID, Epoch: 2, PublicKey: encodePublicKey(keyTwo)},
		},
	}
	if err := metadata.Validate(); err == nil {
		t.Fatal("metadata accepted a current key behind the final/max epoch")
	}
}

func encodePublicKey(key ed25519.PublicKey) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(key)*2)
	for index, value := range key {
		out[index*2] = alphabet[value>>4]
		out[index*2+1] = alphabet[value&0x0f]
	}
	return string(out)
}

func TestSpoolDerivesTierAndRejectsCallerTierSwitch(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 75)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"observer_start",
		map[string]any{"kind": "observer_start"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Append(event, RoutineTier); !errors.Is(err, ErrSpoolCorrupt) {
		t.Fatalf("priority event accepted in routine tier: %v", err)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("caller tier switch did not persist mutation read-only")
	}
}

func TestExistingFileRetryRestoresExactPhysicalByteAccounting(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 76)
	_, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
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
	wantTotal := spool.totalBytes
	wantRoutine := spool.routineBytes
	delete(spool.items, event.SourceSequence)
	itemBytes := item.frameBytes + item.publicationBytes
	spool.totalBytes -= itemBytes
	spool.routineBytes -= itemBytes

	if _, err := spool.Append(event, RoutineTier); err != nil {
		t.Fatal(err)
	}
	if spool.totalBytes != wantTotal || spool.routineBytes != wantRoutine {
		t.Fatalf(
			"existing retry accounting total=%d/%d routine=%d/%d",
			spool.totalBytes,
			wantTotal,
			spool.routineBytes,
			wantRoutine,
		)
	}
}

func TestExistingFileRetryOverflowHasNoPartialCounterOrMapMutation(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 79)
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
	delete(spool.items, event.SourceSequence)
	spool.totalBytes -= item.frameBytes + item.publicationBytes
	spool.routineBytes = ^uint64(0)
	beforeTotal := spool.totalBytes
	beforeRoutine := spool.routineBytes

	if _, err := spool.Append(event, RoutineTier); !errors.Is(err, ErrSpoolCorrupt) {
		t.Fatalf("got %v, want ErrSpoolCorrupt", err)
	}
	if _, exists := spool.items[event.SourceSequence]; exists ||
		spool.totalBytes != beforeTotal ||
		spool.routineBytes != beforeRoutine {
		t.Fatalf(
			"partial mutation exists=%v total=%d/%d routine=%d/%d",
			exists,
			spool.totalBytes,
			beforeTotal,
			spool.routineBytes,
			beforeRoutine,
		)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("counter overflow did not persist read-only")
	}
}

func TestSpoolStartupRejectsUnknownRootArtifact(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 77)
	state, spool, _ := openSignerFixture(t, root, testBootID, privateKey)
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(root, "spool", "unknown")
	if err := os.WriteFile(unknown, []byte("unaccounted"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
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
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!state.Snapshot().MutationReadOnly {
		t.Fatalf("unknown root artifact err=%v readonly=%v", err, state.Snapshot().MutationReadOnly)
	}
}

func TestAckRevalidatesExactDiskIdentityAfterFetch(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 78)
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
	fetched, err := spool.Fetch(0, 1, 4*1024*1024)
	if err != nil || len(fetched) != 1 {
		t.Fatalf("fetch err=%v items=%d", err, len(fetched))
	}
	item := spool.items[event.SourceSequence]
	raw, err := os.ReadFile(item.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.Remove(item.path); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.CreateOnly(item.path, raw); err != nil {
		t.Fatal(err)
	}
	// ext4/overlayfs hand the freed inode number straight back, so a
	// byte-identical recreate can land on the exact (device, inode, size)
	// triple the compare-only revalidation recorded — indistinguishable by
	// construction, not a checker defect. Park the recycled inode under a
	// pinned sibling name and recreate once more, which forces the
	// replacement onto a provably different inode.
	var replacement unix.Stat_t
	if err := unix.Lstat(item.path, &replacement); err != nil {
		t.Fatal(err)
	}
	if uint64(replacement.Dev) == item.identity.Device &&
		uint64(replacement.Ino) == item.identity.Inode {
		if err := os.Rename(item.path, item.path+".inode-pin"); err != nil {
			t.Fatal(err)
		}
		if err := durablefile.CreateOnly(item.path, raw); err != nil {
			t.Fatal(err)
		}
		if err := unix.Lstat(item.path, &replacement); err != nil {
			t.Fatal(err)
		}
	}
	if uint64(replacement.Dev) == item.identity.Device &&
		uint64(replacement.Ino) == item.identity.Inode {
		t.Fatal("pinned sibling did not force a fresh replacement inode")
	}

	err = spool.Ack(item.Sequence, item.EventID, item.ContentSHA256)
	if !errors.Is(err, ErrSpoolCorrupt) {
		t.Fatalf("ack accepted byte-identical replacement inode: %v", err)
	}
	snapshot := state.Snapshot()
	if !snapshot.MutationReadOnly ||
		snapshot.ReadOnlyReason != "observer_ack_disk_identity_changed" {
		t.Fatalf(
			"disk identity replacement did not persist the exact fence: %+v",
			snapshot,
		)
	}
}

func TestAckCleanupRevalidatesIdentityImmediatelyBeforeUnlink(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 80)
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
	raw, err := os.ReadFile(item.path)
	if err != nil {
		t.Fatal(err)
	}
	spool.beforeRemove = func(removing SpoolItem) {
		spool.beforeRemove = nil
		if err := durablefile.Remove(removing.path); err != nil {
			t.Fatal(err)
		}
		if err := durablefile.CreateOnly(removing.path, raw); err != nil {
			t.Fatal(err)
		}
	}

	err = spool.Ack(item.Sequence, item.EventID, item.ContentSHA256)
	if !errors.Is(err, ErrSpoolCorrupt) {
		t.Fatalf("cleanup accepted replacement inode: %v", err)
	}
	if state.Snapshot().AckSequence != item.Sequence {
		t.Fatal("cleanup race lost the already durable acknowledgement")
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("cleanup identity change did not persist read-only")
	}
	if _, err := os.Stat(item.path); err != nil {
		t.Fatalf("changed file was removed: %v", err)
	}
}

func TestPublishedUnackedFileCannotDisappearIntoCoveredGap(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 81)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "published"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	if err := state.markGapCovered(event.SourceSequence); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.Remove(item.path); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
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
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!state.Snapshot().MutationReadOnly {
		t.Fatalf(
			"published deletion became a gap err=%v readonly=%v",
			err,
			state.Snapshot().MutationReadOnly,
		)
	}
}

func TestPreparedPublicationWithExactFrameRecoversPromotion(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 88)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "prepared-crash"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	published := publicationPublishedPath(root, event.SourceSequence)
	prepared := publicationPreparedPath(root, event.SourceSequence)
	if err := os.Rename(published, prepared); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.SyncDirectory(filepath.Dir(prepared)); err != nil {
		t.Fatal(err)
	}
	state.mutex.Lock()
	state.state.PublicationHeadSequence = 0
	state.state.PublicationHeadHash = zeroPublicationHash
	if err := state.persistLocked(state.state); err != nil {
		state.mutex.Unlock()
		t.Fatal(err)
	}
	state.mutex.Unlock()
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
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
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := os.Lstat(prepared); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepared record survived recovery: %v", err)
	}
	if _, err := os.Stat(published); err != nil {
		t.Fatalf("published record missing after recovery: %v", err)
	}
	items, err := reopened.Fetch(0, 1, 4*1024*1024)
	if err != nil || len(items) != 1 || items[0].EventID != event.EventID {
		t.Fatalf("recovered fetch err=%v items=%+v", err, items)
	}
}

func TestUncommittedPreparedPublicationWithoutFrameBecomesReservedGap(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 89)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "prepared-missing-frame"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	published := publicationPublishedPath(root, event.SourceSequence)
	prepared := publicationPreparedPath(root, event.SourceSequence)
	if err := os.Rename(published, prepared); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.SyncDirectory(filepath.Dir(prepared)); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.Remove(item.path); err != nil {
		t.Fatal(err)
	}
	state.mutex.Lock()
	state.state.PublicationHeadSequence = 0
	state.state.PublicationHeadHash = zeroPublicationHash
	if err := state.persistLocked(state.state); err != nil {
		state.mutex.Unlock()
		t.Fatal(err)
	}
	state.mutex.Unlock()
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
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
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if state.Snapshot().MutationReadOnly {
		t.Fatal("uncommitted prepared-only transaction fenced mutation")
	}
	if _, err := os.Lstat(prepared); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted prepared marker survived: %v", err)
	}
	gaps := reopened.UncoveredGaps(0)
	if !reflect.DeepEqual(gaps, []SequenceGap{{Start: 1, End: 1}}) {
		t.Fatalf("reserved gaps=%+v", gaps)
	}
}

func TestFrameWithoutPublicationRecordIsCorruption(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 90)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "missing-ledger"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.Remove(
		publicationPublishedPath(root, event.SourceSequence),
	); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
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
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!state.Snapshot().MutationReadOnly {
		t.Fatalf("unbound frame err=%v readonly=%v", err, state.Snapshot().MutationReadOnly)
	}
}

func TestSpoolRejectsForeignHostEvenWhenKeyIsTrusted(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 82)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	first, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "first"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := state.reserve(StateIdentity{
		HostID:   testHostID,
		BootID:   testBootID,
		KeyID:    first.KeyID,
		KeyEpoch: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	forged := first
	forged.SourceSequence = sequence
	forged.HostID = "223e4567-e89b-42d3-a456-426614174000"
	forged = resignEvent(
		t,
		forged,
		privateKey,
		map[string]any{"kind": "foreign-host"},
	)
	if _, err := spool.Append(forged, RoutineTier); !errors.Is(
		err,
		ErrSpoolCorrupt,
	) {
		t.Fatalf("foreign host accepted: %v", err)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("foreign host did not persist read-only")
	}
}

func TestSpoolRejectsFutureEpochWithoutDurableTransitionHistory(t *testing.T) {
	root := t.TempDir()
	keyOne := testKey(t, 83)
	keyTwo := testKey(t, 84)
	state, spool, signer := openSignerFixture(t, root, testBootID, keyOne)
	first, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "first"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.keys.Add(2, keyTwo.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	sequence, err := state.reserve(StateIdentity{
		HostID:   testHostID,
		BootID:   testBootID,
		KeyID:    first.KeyID,
		KeyEpoch: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyTwoID, err := contracts.KeyID(keyTwo.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	forged := first
	forged.SourceSequence = sequence
	forged.KeyID = keyTwoID
	forged.KeyEpoch = 2
	forged = resignEvent(
		t,
		forged,
		keyTwo,
		map[string]any{"kind": "future-epoch"},
	)
	if _, err := spool.Append(forged, RoutineTier); !errors.Is(
		err,
		ErrSpoolCorrupt,
	) {
		t.Fatalf("future epoch accepted: %v", err)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("future epoch did not persist read-only")
	}
}

func TestAckCheckpointTempIsRecoveredAndPersistentlyReported(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 85)
	state, spool, _ := openSignerFixture(t, root, testBootID, privateKey)
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	tempPath := filepath.Join(
		root,
		"spool",
		".acked.agf.tmp-0123456789abcdef0123456789abcdef",
	)
	if err := os.WriteFile(tempPath, []byte("torn-temp"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
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
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := os.Lstat(tempPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checkpoint temp was not removed: %v", err)
	}
	snapshot := state.Snapshot()
	if !snapshot.AckRepairPending ||
		snapshot.AckRepairReason != "observer_ack_checkpoint_temp_removed" {
		t.Fatalf("repair evidence missing: %+v", snapshot)
	}
}

func TestTornAckTailIsPersistentlyReported(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 86)
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
	if err := spool.Ack(item.Sequence, item.EventID, item.ContentSHA256); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	ackPath := filepath.Join(root, "spool", "acked.agf")
	file, err := os.OpenFile(ackPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("AGF1")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
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
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !state.Snapshot().AckRepairPending ||
		state.Snapshot().AckRepairReason != "observer_ack_torn_tail_repaired" {
		t.Fatalf("torn tail repair was silent: %+v", state.Snapshot())
	}
}

func TestUncertainStateCommitNeverReusesReservedSequence(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 87)
	state, _, _ := openSignerFixture(t, root, testBootID, privateKey)
	originalPersist := state.persist
	injected := errors.New("injected state directory sync failure")
	first := true
	state.persist = func(path string, next ObserverState) error {
		if !first {
			return originalPersist(path, next)
		}
		first = false
		if err := originalPersist(path, next); err != nil {
			return err
		}
		return errors.Join(durablefile.ErrCommitUncertain, injected)
	}
	identity := StateIdentity{
		HostID:   testHostID,
		BootID:   testBootID,
		KeyID:    state.Snapshot().KeyID,
		KeyEpoch: 1,
	}
	if _, err := state.reserve(identity); !errors.Is(err, injected) {
		t.Fatalf("got %v, want injected uncertainty", err)
	}
	after := state.Snapshot()
	if after.LastSequence != 1 || !after.MutationReadOnly {
		t.Fatalf("uncertain reservation not adopted/fenced: %+v", after)
	}
	if _, err := state.reserve(identity); err == nil {
		t.Fatal("retry reused a possibly committed sequence")
	}
	if state.Snapshot().LastSequence != 1 {
		t.Fatal("fenced retry changed the reserved sequence")
	}
}

func TestBootstrapFencesEveryIncompleteRotationStageWithoutSigning(t *testing.T) {
	for _, stage := range []string{
		"new_key_written",
		"prepared",
		"transition_spooled",
		"key_switched",
		"start_spooled",
		"rotation_key_removed",
	} {
		t.Run(stage, func(t *testing.T) {
			configPath, config, _, newKey := rotationFixture(t)
			options := append(
				fixedRotationOptions(newKey),
				WithRotationStopAfter(stage),
			)
			if err := RotateKeys(configPath, options...); !errors.Is(
				err,
				ErrInjectedRotationStop,
			) {
				t.Fatalf("rotation stop err=%v", err)
			}
			before, err := loadObserverState(
				filepath.Join(config.StateDir, "observer-state.json"),
			)
			if err != nil {
				t.Fatal(err)
			}
			daemon, err := Bootstrap(
				context.Background(),
				configPath,
				WithBootstrapBootID(func() (string, error) {
					return testBootID, nil
				}),
				WithBootstrapNow(func() time.Time {
					return time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)
				}),
			)
			if err != nil {
				t.Fatalf("bootstrap did not return fenced daemon: %v", err)
			}
			defer daemon.Close()
			after := daemon.state.Snapshot()
			if daemon.signer != nil || daemon.spool != nil ||
				!after.MutationReadOnly ||
				after.ReadOnlyReason != "observer_rotation_incomplete" {
				t.Fatalf(
					"bootstrap crossed rotation boundary signer=%v spool=%v state=%+v",
					daemon.signer != nil,
					daemon.spool != nil,
					after,
				)
			}
			if after.LastSequence != before.LastSequence ||
				after.KeyID != before.KeyID ||
				after.KeyEpoch != before.KeyEpoch {
				t.Fatalf("fenced bootstrap changed authority tuple before=%+v after=%+v", before, after)
			}
			if _, err := AcquireStateLock(config.StateDir); !errors.Is(
				err,
				ErrStateLocked,
			) {
				t.Fatalf("fenced daemon did not retain state lock: %v", err)
			}
		})
	}
}

func TestLiveAppendRequiresCurrentBootNotHistoricalMembership(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 91)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	first, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "first-boot"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	state, spool, signer = openSignerFixture(t, root, testBootID2, privateKey)
	current, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "current-boot"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := state.reserve(StateIdentity{
		HostID:   testHostID,
		BootID:   testBootID2,
		KeyID:    current.KeyID,
		KeyEpoch: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	forged := first
	forged.SourceSequence = sequence
	forged = resignEvent(
		t,
		forged,
		privateKey,
		map[string]any{"kind": "historical-boot-replay"},
	)
	if _, err := spool.Append(forged, RoutineTier); !errors.Is(
		err,
		ErrSpoolCorrupt,
	) {
		t.Fatalf("historical boot accepted on live append: %v", err)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("historical live append did not persist read-only")
	}
}

func TestInMemoryIdempotentRetryRevalidatesFrameAndPublication(t *testing.T) {
	for _, target := range []string{"frame", "publication"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 92)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			event, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": "idempotent"},
				metadata(),
			)
			if err != nil {
				t.Fatal(err)
			}
			item := spool.items[event.SourceSequence]
			path := item.path
			maxBytes := int64(65_536 + 76)
			if target == "publication" {
				path = item.publicationPath
				maxBytes = 4_096
			}
			raw, _, err := durablefile.ReadRegularIdentity(path, maxBytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := durablefile.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := durablefile.CreateOnly(path, raw); err != nil {
				t.Fatal(err)
			}
			if _, err := spool.Append(event, RoutineTier); !errors.Is(
				err,
				ErrSpoolCorrupt,
			) {
				t.Fatalf("%s replacement accepted: %v", target, err)
			}
			if !state.Snapshot().MutationReadOnly {
				t.Fatalf("%s replacement did not persist read-only", target)
			}
		})
	}
}

func TestAckCleanupUnsafeRemovePersistsReadOnly(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 93)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "cleanup-unsafe"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	spool.remove = func(string, durablefile.FileIdentity) error {
		return durablefile.ErrUnsafePath
	}
	if err := spool.Ack(
		item.Sequence,
		item.EventID,
		item.ContentSHA256,
	); !errors.Is(err, durablefile.ErrUnsafePath) {
		t.Fatalf("got %v, want unsafe remove", err)
	}
	if !state.Snapshot().MutationReadOnly {
		t.Fatal("unsafe cleanup error did not persist read-only")
	}
}

func TestRotationFenceDoesNotConsultBootReader(t *testing.T) {
	configPath, _, _, newKey := rotationFixture(t)
	options := append(
		fixedRotationOptions(newKey),
		WithRotationStopAfter("prepared"),
	)
	if err := RotateKeys(configPath, options...); !errors.Is(
		err,
		ErrInjectedRotationStop,
	) {
		t.Fatal(err)
	}
	bootCalls := 0
	daemon, err := Bootstrap(
		context.Background(),
		configPath,
		WithBootstrapBootID(func() (string, error) {
			bootCalls++
			return "", errors.New("injected boot reader failure")
		}),
	)
	if err != nil {
		t.Fatalf("rotation fence was routed through boot reader: %v", err)
	}
	defer daemon.Close()
	if bootCalls != 0 || daemon.signer != nil ||
		!daemon.state.Snapshot().MutationReadOnly {
		t.Fatalf(
			"boot_calls=%d signer=%v state=%+v",
			bootCalls,
			daemon.signer != nil,
			daemon.state.Snapshot(),
		)
	}
}

func TestRotationFenceRetainsLockWhenReadOnlyPersistenceFails(t *testing.T) {
	configPath, config, _, newKey := rotationFixture(t)
	options := append(
		fixedRotationOptions(newKey),
		WithRotationStopAfter("prepared"),
	)
	if err := RotateKeys(configPath, options...); !errors.Is(
		err,
		ErrInjectedRotationStop,
	) {
		t.Fatal(err)
	}
	injected := errors.New("injected read-only persistence failure")
	daemon, err := Bootstrap(
		context.Background(),
		configPath,
		withBootstrapStatePersist(func(string, ObserverState) error {
			return injected
		}),
	)
	if err != nil {
		t.Fatalf("persistence failure released fenced daemon: %v", err)
	}
	defer daemon.Close()
	if !errors.Is(daemon.degraded, injected) ||
		!daemon.state.Snapshot().MutationReadOnly {
		t.Fatalf("degraded=%v state=%+v", daemon.degraded, daemon.state.Snapshot())
	}
	if _, err := AcquireStateLock(config.StateDir); !errors.Is(
		err,
		ErrStateLocked,
	) {
		t.Fatalf("persistence failure released state lock: %v", err)
	}
}

func TestRotateKeysRefusesUnrelatedReadOnlyBeforeCreatingArtifacts(
	t *testing.T,
) {
	configPath, config, oldKey, newKey := rotationFixture(t)
	keyID, err := contracts.KeyID(oldKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(config.StateDir, "observer-state.json")
	state, err := OpenStateStore(
		statePath,
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
	const reason = "manual_or_identity_fault"
	if err := state.PersistReadOnly(reason); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	if err := RotateKeys(
		configPath,
		fixedRotationOptions(newKey)...,
	); err == nil {
		t.Fatal("rotation crossed unrelated read-only fence")
	}
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("refused rotation mutated observer state")
	}
	persisted, err := loadObserverState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.MutationReadOnly || persisted.ReadOnlyReason != reason {
		t.Fatalf("unrelated fence changed: %+v", persisted)
	}
	for _, path := range []string{
		rotationKeyPath(config.StateDir),
		markerPath(config.StateDir),
		publicMetadataPath(config.StateDir),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused rotation created %s: %v", path, err)
		}
	}
}

func TestRotateKeysReconcilesUncertainPublicMetadataCommit(
	t *testing.T,
) {
	t.Run("exact canonical metadata is resynced", func(t *testing.T) {
		configPath, config, _, newKey := rotationFixture(t)
		injected := errors.New("injected post-rename directory sync failure")
		syncCalls := 0
		options := append(
			fixedRotationOptions(newKey),
			RotationOption(func(options *rotationOptions) {
				save := options.saveMetadata
				options.saveMetadata = func(
					stateDir string,
					metadata PublicKeyMetadata,
				) error {
					if err := save(stateDir, metadata); err != nil {
						return err
					}
					if metadata.CurrentEpoch == 2 {
						return errors.Join(
							durablefile.ErrCommitUncertain,
							injected,
						)
					}
					return nil
				}
				options.syncMetadataDirectory = func(path string) error {
					syncCalls++
					return durablefile.SyncDirectory(path)
				}
			}),
		)
		if err := RotateKeys(configPath, options...); err != nil {
			t.Fatalf("exact visible metadata was not reconciled: %v", err)
		}
		if syncCalls != 1 {
			t.Fatalf("metadata parent resync calls=%d want=1", syncCalls)
		}
		metadata, err := LoadPublicKeyMetadata(config.StateDir)
		if err != nil {
			t.Fatal(err)
		}
		state, err := loadObserverState(
			filepath.Join(config.StateDir, "observer-state.json"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if metadata.CurrentEpoch != 2 ||
			state.KeyEpoch != 2 ||
			state.MutationReadOnly {
			t.Fatalf("metadata=%+v state=%+v", metadata, state)
		}
	})

	t.Run("old metadata remains correlated and retryable", func(t *testing.T) {
		configPath, config, _, newKey := rotationFixture(t)
		injected := errors.New("injected uncertain metadata commit")
		options := append(
			fixedRotationOptions(newKey),
			RotationOption(func(options *rotationOptions) {
				save := options.saveMetadata
				options.saveMetadata = func(
					stateDir string,
					metadata PublicKeyMetadata,
				) error {
					if metadata.CurrentEpoch == 2 {
						return errors.Join(
							durablefile.ErrCommitUncertain,
							injected,
						)
					}
					return save(stateDir, metadata)
				}
			}),
		)
		if err := RotateKeys(configPath, options...); !errors.Is(
			err,
			injected,
		) {
			t.Fatalf("uncertain old-metadata commit err=%v", err)
		}
		state, err := loadObserverState(
			filepath.Join(config.StateDir, "observer-state.json"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !state.MutationReadOnly ||
			state.ReadOnlyReason != "observer_rotation_incomplete" {
			t.Fatalf("uncertain rotation fence=%+v", state)
		}
		if !rotationArtifactsPresent(config.StateDir) {
			t.Fatal("uncertain rotation lost correlated artifacts")
		}
		if err := RotateKeys(
			configPath,
			fixedRotationOptions(newKey)...,
		); err != nil {
			t.Fatalf("correlated retry failed: %v", err)
		}
		state, err = loadObserverState(
			filepath.Join(config.StateDir, "observer-state.json"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if state.MutationReadOnly ||
			state.KeyEpoch != 2 ||
			rotationArtifactsPresent(config.StateDir) {
			t.Fatalf("retry did not complete exact rotation: %+v", state)
		}
	})

	t.Run("exact metadata resync failure remains retryable", func(t *testing.T) {
		configPath, config, _, newKey := rotationFixture(t)
		injected := errors.New("injected metadata parent resync failure")
		options := append(
			fixedRotationOptions(newKey),
			RotationOption(func(options *rotationOptions) {
				save := options.saveMetadata
				options.saveMetadata = func(
					stateDir string,
					metadata PublicKeyMetadata,
				) error {
					if err := save(stateDir, metadata); err != nil {
						return err
					}
					if metadata.CurrentEpoch == 2 {
						return durablefile.ErrCommitUncertain
					}
					return nil
				}
				options.syncMetadataDirectory = func(string) error {
					return injected
				}
			}),
		)
		if err := RotateKeys(configPath, options...); !errors.Is(
			err,
			injected,
		) {
			t.Fatalf("metadata resync failure err=%v", err)
		}
		state, err := loadObserverState(
			filepath.Join(config.StateDir, "observer-state.json"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !state.MutationReadOnly ||
			state.ReadOnlyReason != "observer_rotation_incomplete" ||
			!rotationArtifactsPresent(config.StateDir) {
			t.Fatalf("resync failure lost correlated transaction: %+v", state)
		}
		if err := RotateKeys(
			configPath,
			fixedRotationOptions(newKey)...,
		); err != nil {
			t.Fatalf("resync-failure retry failed: %v", err)
		}
	})

	for _, testCase := range []struct {
		name  string
		write func(string, PublicKeyMetadata) error
	}{
		{
			name: "malformed metadata",
			write: func(stateDir string, _ PublicKeyMetadata) error {
				return durablefile.AtomicWrite(
					publicMetadataPath(stateDir),
					[]byte("{"),
				)
			},
		},
		{
			name: "noncanonical metadata",
			write: func(
				stateDir string,
				metadata PublicKeyMetadata,
			) error {
				raw, err := contracts.CanonicalJSON(metadata)
				if err != nil {
					return err
				}
				return durablefile.AtomicWrite(
					publicMetadataPath(stateDir),
					append(raw, '\n'),
				)
			},
		},
	} {
		t.Run(testCase.name+" remains fenced", func(t *testing.T) {
			configPath, config, _, newKey := rotationFixture(t)
			syncCalls := 0
			options := append(
				fixedRotationOptions(newKey),
				RotationOption(func(options *rotationOptions) {
					save := options.saveMetadata
					options.saveMetadata = func(
						stateDir string,
						metadata PublicKeyMetadata,
					) error {
						if metadata.CurrentEpoch != 2 {
							return save(stateDir, metadata)
						}
						if err := testCase.write(
							stateDir,
							metadata,
						); err != nil {
							return err
						}
						return durablefile.ErrCommitUncertain
					}
					options.syncMetadataDirectory = func(string) error {
						syncCalls++
						return nil
					}
				}),
			)
			if err := RotateKeys(configPath, options...); !errors.Is(
				err,
				durablefile.ErrCommitUncertain,
			) {
				t.Fatalf("mismatched metadata uncertainty err=%v", err)
			}
			state, err := loadObserverState(
				filepath.Join(config.StateDir, "observer-state.json"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if syncCalls != 0 ||
				!state.MutationReadOnly ||
				state.ReadOnlyReason != "observer_rotation_incomplete" ||
				!rotationArtifactsPresent(config.StateDir) {
				t.Fatalf(
					"sync_calls=%d mismatched metadata state=%+v",
					syncCalls,
					state,
				)
			}
		})
	}
}

func TestRotationIncompleteFenceNeverReplacesUnrelatedReason(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 124)
	state, spool, _ := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	const reason = "observer_identity_history_corrupt"
	if err := state.PersistReadOnly(reason); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(state.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.persistRotationIncomplete(); err == nil {
		t.Fatal("rotation fence replaced unrelated reason")
	}
	after, err := os.ReadFile(state.path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	if !bytes.Equal(before, after) ||
		!snapshot.MutationReadOnly ||
		snapshot.ReadOnlyReason != reason {
		t.Fatalf("unrelated reason changed: %+v", snapshot)
	}
}

func TestRotationArtifactsCannotLaunderUnrelatedReadOnlyFence(t *testing.T) {
	configPath, config, oldKey, newKey := rotationFixture(t)
	options := append(
		fixedRotationOptions(newKey),
		WithRotationStopAfter("prepared"),
	)
	if err := RotateKeys(configPath, options...); !errors.Is(
		err,
		ErrInjectedRotationStop,
	) {
		t.Fatalf("prepare rotation: %v", err)
	}
	keyID, err := contracts.KeyID(oldKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(config.StateDir, "observer-state.json")
	state, err := OpenStateStore(
		statePath,
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
	const reason = "observer_identity_history_corrupt"
	if err := state.PersistReadOnly(reason); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		statePath,
		rotationKeyPath(config.StateDir),
		markerPath(config.StateDir),
		publicMetadataPath(config.StateDir),
	}
	before := make(map[string][]byte, len(paths))
	for _, path := range paths {
		before[path], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}

	daemon, err := Bootstrap(
		context.Background(),
		configPath,
		WithBootstrapBootID(func() (string, error) {
			t.Fatal("rotation fence consulted boot reader")
			return "", nil
		}),
	)
	if err != nil {
		t.Fatalf("Bootstrap did not retain fenced daemon: %v", err)
	}
	if daemon.degraded == nil || daemon.signer != nil || daemon.spool != nil {
		_ = daemon.Close()
		t.Fatalf(
			"degraded=%v signer=%v spool=%v",
			daemon.degraded,
			daemon.signer != nil,
			daemon.spool != nil,
		)
	}
	snapshot := daemon.state.Snapshot()
	if !snapshot.MutationReadOnly || snapshot.ReadOnlyReason != reason {
		_ = daemon.Close()
		t.Fatalf("Bootstrap laundered unrelated fence: %+v", snapshot)
	}
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}

	if err := RotateKeys(
		configPath,
		fixedRotationOptions(newKey)...,
	); err == nil {
		t.Fatal("resume crossed unrelated read-only fence")
	}
	for _, path := range paths {
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before[path], after) {
			t.Fatalf("refused recovery mutated %s", path)
		}
	}
	persisted, err := loadObserverState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.MutationReadOnly || persisted.ReadOnlyReason != reason {
		t.Fatalf("resume cleared unrelated fence: %+v", persisted)
	}
}

func TestStartupRejectsReturnToEarlierBootHistoryEntry(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 94)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "boot-one"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	state, spool, signer = openSignerFixture(t, root, testBootID2, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "boot-two"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	event.BootID = testBootID
	event = resignEvent(t, event, privateKey, event.NormalizedFields)
	canonical, err := contracts.CanonicalJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := durablefile.EncodeFrame(canonical, [32]byte{}, 65_536)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(item.path, frame); err != nil {
		t.Fatal(err)
	}
	contentHash := sha256.Sum256(canonical)
	publication := item.publication
	publication.EventID = event.EventID
	publication.ContentSHA256 = hex.EncodeToString(contentHash[:])
	publication.BootID = testBootID
	publicationRaw, err := contracts.CanonicalJSON(publication)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(item.publicationPath, publicationRaw); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(1, privateKey.Public().(ed25519.PublicKey)); err != nil {
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
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!state.Snapshot().MutationReadOnly {
		t.Fatalf("boot rollback err=%v readonly=%v", err, state.Snapshot().MutationReadOnly)
	}
}

func TestPublicMetadataRequiresExactTransitionAndEpochStartProofs(t *testing.T) {
	keyOne := testKey(t, 95).Public().(ed25519.PublicKey)
	keyTwo := testKey(t, 96).Public().(ed25519.PublicKey)
	keyOneID, err := contracts.KeyID(keyOne)
	if err != nil {
		t.Fatal(err)
	}
	keyTwoID, err := contracts.KeyID(keyTwo)
	if err != nil {
		t.Fatal(err)
	}
	metadata := PublicKeyMetadata{
		SchemaVersion: "agmind.observer-public-keys.v1",
		HostID:        testHostID,
		CurrentKeyID:  keyTwoID,
		CurrentEpoch:  2,
		Keys: []PublicKeyEpoch{
			{KeyID: keyOneID, Epoch: 1, PublicKey: encodePublicKey(keyOne)},
			{KeyID: keyTwoID, Epoch: 2, PublicKey: encodePublicKey(keyTwo)},
		},
	}
	if err := metadata.Validate(); err == nil {
		t.Fatal("epoch 2 metadata without transition/start proofs was accepted")
	}
}

func TestBootstrapRejectsForeignMetadataHostID(t *testing.T) {
	configPath, config, _, _ := rotationFixture(t)
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
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}
	public, err := LoadPublicKeyMetadata(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	public.HostID = "223e4567-e89b-42d3-a456-426614174000"
	raw, err := contracts.CanonicalJSON(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(publicMetadataPath(config.StateDir), raw); err != nil {
		t.Fatal(err)
	}
	daemon, err = Bootstrap(context.Background(), configPath, options...)
	if daemon != nil {
		_ = daemon.Close()
	}
	if err == nil {
		t.Fatal("bootstrap accepted foreign metadata host")
	}
	state, loadErr := loadObserverState(
		filepath.Join(config.StateDir, "observer-state.json"),
	)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !state.MutationReadOnly {
		t.Fatal("foreign metadata host did not persist read-only")
	}
}

func TestConsecutiveEmptyBootsReplaceTrailingBoundary(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := testKey(t, 97)
	const bootThree = "00000000-0000-4000-8000-000000000003"
	keyID, err := contracts.KeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "observer-state.json")
	for _, bootID := range []string{testBootID, testBootID2, bootThree} {
		if _, err := OpenStateStore(
			statePath,
			StateIdentity{
				HostID:   testHostID,
				BootID:   bootID,
				KeyID:    keyID,
				KeyEpoch: 1,
			},
		); err != nil {
			t.Fatalf("open empty boot %s: %v", bootID, err)
		}
	}
	state, err := loadObserverState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.BootID != bootThree ||
		len(state.BootHistory) != 1 ||
		state.BootHistory[0] != (BootBoundary{
			BootID:        bootThree,
			FirstSequence: 1,
		}) {
		t.Fatalf("boot history=%+v current=%s", state.BootHistory, state.BootID)
	}
}

func TestPersistStateRejectsOversizeBeforeReplacing(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := testKey(t, 98)
	keyID, err := contracts.KeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "observer-state.json")
	store, err := OpenStateStore(
		path,
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
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oversize := store.Snapshot()
	oversize.LastSequence = 1_023
	oversize.BootHistory = make([]BootBoundary, 1_024)
	for index := range oversize.BootHistory {
		oversize.BootHistory[index] = BootBoundary{
			BootID: fmt.Sprintf(
				"00000000-0000-4000-8000-%012x",
				index+1,
			),
			FirstSequence: uint64(index + 1),
		}
	}
	oversize.BootID = oversize.BootHistory[len(oversize.BootHistory)-1].BootID
	if err := persistState(path, oversize); err == nil {
		t.Fatal("oversize observer state was persisted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("oversize preflight replaced the prior state")
	}
}

func TestRecoveredAckMustBindExactNextOutstandingPublication(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		record func(first, second SpoolItem) ackRecord
	}{
		{
			name: "wrong identity",
			record: func(first, second SpoolItem) ackRecord {
				return ackRecord{
					SchemaVersion: "agmind.spool-ack.v1",
					Sequence:      first.Sequence,
					EventID:       second.EventID,
					ContentSHA256: second.ContentSHA256,
					AckedAt:       "2026-07-27T12:00:00Z",
				}
			},
		},
		{
			name: "skips lower outstanding sequence",
			record: func(_, second SpoolItem) ackRecord {
				return ackRecord{
					SchemaVersion: "agmind.spool-ack.v1",
					Sequence:      second.Sequence,
					EventID:       second.EventID,
					ContentSHA256: second.ContentSHA256,
					AckedAt:       "2026-07-27T12:00:00Z",
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 99)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			for _, kind := range []string{"first", "second"} {
				if _, err := signer.Wrap(
					context.Background(),
					"falco_connect",
					map[string]any{"kind": kind},
					metadata(),
				); err != nil {
					t.Fatal(err)
				}
			}
			first := spool.items[1]
			second := spool.items[2]
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			record := testCase.record(first, second)
			canonical, err := contracts.CanonicalJSON(record)
			if err != nil {
				t.Fatal(err)
			}
			frame, _, err := durablefile.EncodeFrame(
				canonical,
				[32]byte{},
				4_096,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := durablefile.AtomicWrite(
				filepath.Join(root, "spool", "acked.agf"),
				frame,
			); err != nil {
				t.Fatal(err)
			}
			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if reopened != nil {
				_ = reopened.Close()
			}
			if !errors.Is(err, ErrSpoolCorrupt) ||
				!state.Snapshot().MutationReadOnly {
				t.Fatalf(
					"forged recovered ack err=%v readonly=%v",
					err,
					state.Snapshot().MutationReadOnly,
				)
			}
			for _, item := range []SpoolItem{first, second} {
				if _, statErr := os.Stat(item.path); statErr != nil {
					t.Fatalf("event %d was removed: %v", item.Sequence, statErr)
				}
				if _, statErr := os.Stat(item.publicationPath); statErr != nil {
					t.Fatalf(
						"publication %d was removed: %v",
						item.Sequence,
						statErr,
					)
				}
			}
		})
	}
}

func TestRotationProofsSurviveAckDeletionAndBootstrapRestart(t *testing.T) {
	configPath, config, _, newKey := rotationFixture(t)
	if err := RotateKeys(configPath, fixedRotationOptions(newKey)...); err != nil {
		t.Fatal(err)
	}
	publicMetadata, err := LoadPublicKeyMetadata(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(publicMetadata.Keys) != 2 ||
		publicMetadata.Keys[1].TransitionEnvelope == nil ||
		publicMetadata.Keys[1].EpochStartEnvelope == nil {
		t.Fatal("rotation metadata lacks durable envelope proofs")
	}
	state, err := OpenStateStore(
		filepath.Join(config.StateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    publicMetadata.CurrentKeyID,
			KeyEpoch: publicMetadata.CurrentEpoch,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := publicMetadata.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	spool, err := NewSpool(
		SpoolConfig{
			StateDir:             config.StateDir,
			MaxBytes:             config.SpoolMaxBytes,
			PriorityReserveBytes: config.SpoolPriorityReserveBytes,
		},
		state,
		keys,
	)
	if err != nil {
		t.Fatal(err)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("rotation items=%d", len(items))
	}
	for _, item := range items {
		if err := spool.Ack(
			item.Sequence,
			item.EventID,
			item.ContentSHA256,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(item.path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("acked frame survived: %v", err)
		}
		if _, err := os.Lstat(item.publicationPath); !errors.Is(
			err,
			os.ErrNotExist,
		) {
			t.Fatalf("acked publication survived: %v", err)
		}
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	daemon, err := Bootstrap(
		context.Background(),
		configPath,
		WithBootstrapBootID(func() (string, error) {
			return testBootID, nil
		}),
		WithBootstrapNow(func() time.Time {
			return time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)
		}),
	)
	if err != nil {
		t.Fatalf("restart lost acknowledged rotation proofs: %v", err)
	}
	defer daemon.Close()
	if daemon.MutationReadOnly() || daemon.signer == nil {
		t.Fatal("restart did not recover a writable proven epoch")
	}
	if daemon.state.Snapshot().LastSequence != 3 {
		t.Fatalf(
			"restart sequence=%d want=3",
			daemon.state.Snapshot().LastSequence,
		)
	}
}

func TestRepairRecoversBoundaryArchiveBeforeStateCommit(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 224)
	_, initialSpool, initialSigner := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	if _, err := initialSigner.Wrap(
		context.Background(),
		"observer_start",
		map[string]any{"kind": "observer_start"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	if err := initialSpool.Close(); err != nil {
		t.Fatal(err)
	}
	state, spool, signer := openPendingSignerFixture(
		t,
		root,
		testBootID2,
		privateKey,
	)
	injected := errors.New("injected boundary-state commit failure")
	state.persist = func(path string, next ObserverState) error {
		if next.BootBoundaryState == bootBoundaryCommitted &&
			next.PCCBoundaryCount == 1 {
			return injected
		}
		return persistState(path, next)
	}
	if err := ensureDedicatedBootBoundary(
		context.Background(),
		state,
		signer,
		time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	); !errors.Is(err, injected) {
		t.Fatalf("boundary commit err=%v", err)
	}
	pending := state.Snapshot()
	if pending.BootBoundaryState != bootBoundaryPending ||
		pending.PCCBoundaryCount != 1 {
		t.Fatalf("failure did not retain anchored pending boundary: %+v", pending)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedState, err := OpenStateStore(
		filepath.Join(root, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID2,
			KeyID:    pending.KeyID,
			KeyEpoch: pending.KeyEpoch,
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
		pccArchiveKeyring(t, privateKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered := reopenedState.Snapshot()
	if recovered.BootBoundaryState != bootBoundaryCommitted ||
		recovered.PendingBootBoundary != nil ||
		recovered.PCCBoundaryCount != 1 {
		t.Fatalf("boundary archive recovery failed: %+v", recovered)
	}
	chain, err := reopened.boundaryArchive.Chain(testBootID, testBootID2)
	if err != nil || len(chain) != 1 {
		t.Fatalf("recovered chain=%+v err=%v", chain, err)
	}
}

func TestRepairPCCReceiptPreAnchorFailureFencesAndRejectsTail(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 252)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	_, receipt := pccReceiptSnapshotFixture(t, spool, signer, "preanchor")
	injected := errors.New("injected PCC receipt anchor failure")
	state.persist = func(path string, next ObserverState) error {
		if next.PCCReceiptCount == 1 {
			return injected
		}
		return persistState(path, next)
	}
	if err := spool.pccReceipts.Append(receipt); !errors.Is(err, injected) {
		t.Fatalf("receipt append error=%v", err)
	}
	if snapshot := state.Snapshot(); !snapshot.MutationReadOnly ||
		snapshot.ReadOnlyReason != "observer_pcc_receipt_anchor_failed" ||
		snapshot.PCCReceiptCount != 0 {
		t.Fatalf("pre-anchor failure did not retain exact fence: %+v", snapshot)
	}
	path := pccReceiptJournalPath(root)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := NewSpool(
		SpoolConfig{
			StateDir:             root,
			MaxBytes:             4 * 1024 * 1024,
			PriorityReserveBytes: 1024 * 1024,
		},
		state,
		pccReceiptKeys(t, privateKey),
	)
	if opened != nil {
		_ = opened.Close()
	}
	if !errors.Is(err, ErrPCCReceiptCorrupt) {
		t.Fatalf("restart adopted unanchored receipt tail: %v", err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("restart truncated or rewrote unanchored receipt tail")
	}
}

func TestOpenStateStoreRejectsHistoricalBootIDAndPersistsFence(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 100)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "old-boot"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	identity := StateIdentity{
		HostID:   testHostID,
		BootID:   testBootID2,
		KeyID:    state.Snapshot().KeyID,
		KeyEpoch: 1,
	}
	if _, err := OpenStateStore(
		filepath.Join(root, "observer-state.json"),
		identity,
	); err != nil {
		t.Fatal(err)
	}
	identity.BootID = testBootID
	if reopened, err := OpenStateStore(
		filepath.Join(root, "observer-state.json"),
		identity,
	); err == nil || reopened != nil {
		t.Fatal("historical boot ID was accepted")
	}
	persisted, err := loadObserverState(
		filepath.Join(root, "observer-state.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.MutationReadOnly ||
		persisted.ReadOnlyReason != "observer_boot_id_rollback" {
		t.Fatalf("historical boot fence=%+v", persisted)
	}
}

func TestOldBootHighSequenceReplayRejectedAfterCurrentBootCleanup(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 101)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "boot-one"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	state, spool, signer = openSignerFixture(
		t,
		root,
		testBootID2,
		privateKey,
	)
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "boot-two"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if err := spool.Ack(
			item.Sequence,
			item.EventID,
			item.ContentSHA256,
		); err != nil {
			t.Fatal(err)
		}
	}
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "forged-high-sequence"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	event.BootID = testBootID
	event = resignEvent(t, event, privateKey, event.NormalizedFields)
	canonical, err := contracts.CanonicalJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := durablefile.EncodeFrame(canonical, [32]byte{}, 65_536)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(item.path, frame); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	publication := item.publication
	publication.EventID = event.EventID
	publication.ContentSHA256 = hex.EncodeToString(sum[:])
	publication.BootID = testBootID
	publicationRaw, err := contracts.CanonicalJSON(publication)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(
		item.publicationPath,
		publicationRaw,
	); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(
		1,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
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
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!state.Snapshot().MutationReadOnly {
		t.Fatalf(
			"old-boot high sequence err=%v readonly=%v",
			err,
			state.Snapshot().MutationReadOnly,
		)
	}
}

func TestAckRejectsInvalidTimestampBeforeDurableMutation(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 102)
	_, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "invalid-ack-time"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	spool.config.Now = func() time.Time {
		return time.Date(10_000, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if err := spool.Ack(
		item.Sequence,
		item.EventID,
		item.ContentSHA256,
	); err == nil {
		t.Fatal("invalid acknowledgement timestamp was persisted")
	}
	for _, path := range []string{item.path, item.publicationPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("invalid ack removed %s: %v", path, err)
		}
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
	if len(recovery.Records) != 0 {
		t.Fatal("invalid acknowledgement reached the journal")
	}
}

func TestAckRepairIntentPersistsBeforeDestructiveRecovery(t *testing.T) {
	for _, artifact := range []string{"checkpoint temp", "torn tail"} {
		t.Run(artifact, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 103)
			state, spool, _ := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			ackPath := filepath.Join(root, "spool", "acked.agf")
			var artifactPath string
			switch artifact {
			case "checkpoint temp":
				artifactPath = filepath.Join(
					root,
					"spool",
					".acked.agf.tmp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				)
				if err := os.WriteFile(
					artifactPath,
					[]byte("checkpoint"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
			case "torn tail":
				artifactPath = ackPath
				file, err := os.OpenFile(
					ackPath,
					os.O_WRONLY|os.O_APPEND,
					0,
				)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write([]byte("AGF1")); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Sync(); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			originalPersist := state.persist
			injected := errors.New("injected repair-intent persistence failure")
			state.persist = func(path string, next ObserverState) error {
				if next.AckRepairPending {
					return injected
				}
				return originalPersist(path, next)
			}
			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if reopened != nil {
				_ = reopened.Close()
			}
			if !errors.Is(err, injected) {
				t.Fatalf("first recovery err=%v", err)
			}
			if _, err := os.Lstat(artifactPath); err != nil {
				t.Fatalf("repair evidence was destroyed before intent: %v", err)
			}
			state.persist = originalPersist
			reopened, err = NewSpool(
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
			defer reopened.Close()
			if !state.Snapshot().AckRepairPending {
				t.Fatal("second recovery silently lost repair intent")
			}
			if artifact == "checkpoint temp" {
				if _, err := os.Lstat(artifactPath); !errors.Is(
					err,
					os.ErrNotExist,
				) {
					t.Fatalf("checkpoint temp survived committed intent: %v", err)
				}
			} else {
				info, err := os.Stat(ackPath)
				if err != nil {
					t.Fatal(err)
				}
				if info.Size() != 0 {
					t.Fatalf("torn journal size=%d", info.Size())
				}
			}
		})
	}
}

func TestDeleteAnchoredHeadFrameAndMarkerFailsClosed(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 104)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "anchored-head"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{item.path, item.publicationPath} {
		if err := durablefile.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	keys := NewKeyring()
	if err := keys.Add(
		1,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
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
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!state.Snapshot().MutationReadOnly {
		t.Fatalf(
			"paired anchored deletion err=%v readonly=%v",
			err,
			state.Snapshot().MutationReadOnly,
		)
	}
}

func TestPublicationSuffixBehindLatestReservationFailsClosed(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 105)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "anchored-prefix"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "stale-suffix"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	first := spool.items[1]
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	state.mutex.Lock()
	next := state.state
	next.PublicationHeadSequence = first.Sequence
	next.PublicationHeadHash = first.publicationHash
	next.LastSequence = 3
	if err := state.persistLocked(next); err != nil {
		state.mutex.Unlock()
		t.Fatal(err)
	}
	state.state = next
	state.mutex.Unlock()

	keys := NewKeyring()
	if err := keys.Add(
		1,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
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
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!state.Snapshot().MutationReadOnly {
		t.Fatalf(
			"stale suffix err=%v readonly=%v",
			err,
			state.Snapshot().MutationReadOnly,
		)
	}
}

func TestUncommittedCreateOnlySpoolTempsRecoverAsReservedGap(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		kind       string
		payloadFor func(SpoolItem) []byte
	}{
		{
			name: "publication temp created",
			kind: "publication",
			payloadFor: func(SpoolItem) []byte {
				return nil
			},
		},
		{
			name: "publication payload written",
			kind: "publication",
			payloadFor: func(item SpoolItem) []byte {
				return item.publicationRaw
			},
		},
		{
			name: "frame temp created",
			kind: "frame",
			payloadFor: func(SpoolItem) []byte {
				return nil
			},
		},
		{
			name: "frame payload written",
			kind: "frame",
			payloadFor: func(item SpoolItem) []byte {
				raw, err := os.ReadFile(item.path)
				if err != nil {
					panic(err)
				}
				return raw
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 106)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			event, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": testCase.name},
				metadata(),
			)
			if err != nil {
				t.Fatal(err)
			}
			item := spool.items[event.SourceSequence]
			tempPayload := testCase.payloadFor(item)
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			prepared := publicationPreparedPath(
				root,
				event.SourceSequence,
			)
			switch testCase.kind {
			case "publication":
				if err := durablefile.Remove(item.path); err != nil {
					t.Fatal(err)
				}
				if err := durablefile.Remove(item.publicationPath); err != nil {
					t.Fatal(err)
				}
			case "frame":
				if err := os.Rename(item.publicationPath, prepared); err != nil {
					t.Fatal(err)
				}
				if err := durablefile.SyncDirectory(
					filepath.Dir(prepared),
				); err != nil {
					t.Fatal(err)
				}
				if err := durablefile.Remove(item.path); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unknown kind %q", testCase.kind)
			}
			state.mutex.Lock()
			state.state.PublicationHeadSequence = 0
			state.state.PublicationHeadHash = zeroPublicationHash
			if err := state.persistLocked(state.state); err != nil {
				state.mutex.Unlock()
				t.Fatal(err)
			}
			state.mutex.Unlock()
			var tempPath string
			if testCase.kind == "publication" {
				tempPath = filepath.Join(
					publicationDirectory(root),
					fmt.Sprintf(
						".%020d.prepared.tmp-%032x",
						event.SourceSequence,
						1,
					),
				)
			} else {
				tempPath = filepath.Join(
					filepath.Dir(item.path),
					fmt.Sprintf(
						".%020d.agf.tmp-%032x",
						event.SourceSequence,
						1,
					),
				)
			}
			if err := durablefile.AtomicWrite(
				tempPath,
				tempPayload,
			); err != nil {
				t.Fatal(err)
			}

			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if state.Snapshot().MutationReadOnly {
				t.Fatal("uncommitted create-only temp fenced mutation")
			}
			for _, path := range []string{tempPath, prepared} {
				if _, err := os.Lstat(path); !errors.Is(
					err,
					os.ErrNotExist,
				) {
					t.Fatalf("recovery artifact survived %s: %v", path, err)
				}
			}
			if gaps := reopened.UncoveredGaps(0); !reflect.DeepEqual(
				gaps,
				[]SequenceGap{{Start: 1, End: 1}},
			) {
				t.Fatalf("reserved gaps=%+v", gaps)
			}
		})
	}
}

func TestCreateOnlySpoolTempCountsTowardStartupQuotaBeforeCleanup(
	t *testing.T,
) {
	root := t.TempDir()
	privateKey := testKey(t, 107)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "oversized-frame-temp"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	if err := os.Rename(
		item.publicationPath,
		publicationPreparedPath(root, event.SourceSequence),
	); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.SyncDirectory(
		publicationDirectory(root),
	); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.Remove(item.path); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	state.mutex.Lock()
	state.state.PublicationHeadSequence = 0
	state.state.PublicationHeadHash = zeroPublicationHash
	if err := state.persistLocked(state.state); err != nil {
		state.mutex.Unlock()
		t.Fatal(err)
	}
	state.mutex.Unlock()
	tempPath := filepath.Join(
		filepath.Dir(item.path),
		fmt.Sprintf(
			".%020d.agf.tmp-%032x",
			event.SourceSequence,
			2,
		),
	)
	if err := durablefile.AtomicWrite(
		tempPath,
		bytes.Repeat([]byte{'x'}, 6_000),
	); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(
		1,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSpool(
		SpoolConfig{
			StateDir:             root,
			MaxBytes:             5_000,
			PriorityReserveBytes: 500,
		},
		state,
		keys,
	)
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!state.Snapshot().MutationReadOnly {
		t.Fatalf(
			"oversized temp err=%v readonly=%v",
			err,
			state.Snapshot().MutationReadOnly,
		)
	}
	if _, err := os.Lstat(tempPath); err != nil {
		t.Fatalf("quota failure removed recovery evidence: %v", err)
	}
}

func TestStartupRejectsMoreThanOneInFlightTransactionTemp(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		setup func(*testing.T, string, *StateStore)
	}{
		{
			name: "two ack checkpoint temps",
			setup: func(t *testing.T, root string, _ *StateStore) {
				for _, suffix := range []string{
					"11111111111111111111111111111111",
					"22222222222222222222222222222222",
				} {
					if err := durablefile.AtomicWrite(
						filepath.Join(
							root,
							"spool",
							".acked.agf.tmp-"+suffix,
						),
						[]byte("checkpoint"),
					); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "ack and publication temp",
			setup: func(t *testing.T, root string, state *StateStore) {
				snapshot := state.Snapshot()
				if _, err := state.reserve(StateIdentity{
					HostID:   snapshot.HostID,
					BootID:   snapshot.BootID,
					KeyID:    snapshot.KeyID,
					KeyEpoch: snapshot.KeyEpoch,
				}); err != nil {
					t.Fatal(err)
				}
				for path, payload := range map[string][]byte{
					filepath.Join(
						root,
						"spool",
						".acked.agf.tmp-33333333333333333333333333333333",
					): []byte("checkpoint"),
					filepath.Join(
						publicationDirectory(root),
						".00000000000000000001.prepared.tmp-"+
							"44444444444444444444444444444444",
					): nil,
				} {
					if err := durablefile.AtomicWrite(path, payload); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 109)
			state, spool, _ := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			testCase.setup(t, root, state)
			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if reopened != nil {
				_ = reopened.Close()
			}
			if !errors.Is(err, ErrSpoolCorrupt) ||
				!state.Snapshot().MutationReadOnly {
				t.Fatalf(
					"multiple transaction temps err=%v readonly=%v",
					err,
					state.Snapshot().MutationReadOnly,
				)
			}
		})
	}
}

func TestUnknownPublicationTempDoesNotConsumeRoutineReserve(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 110)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "routine-at-cap"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	routineBytes := item.frameBytes + item.publicationBytes
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	if _, err := state.reserve(StateIdentity{
		HostID:   snapshot.HostID,
		BootID:   snapshot.BootID,
		KeyID:    snapshot.KeyID,
		KeyEpoch: snapshot.KeyEpoch,
	}); err != nil {
		t.Fatal(err)
	}
	tempPath := filepath.Join(
		publicationDirectory(root),
		".00000000000000000002.prepared.tmp-"+
			"55555555555555555555555555555555",
	)
	if err := durablefile.AtomicWrite(tempPath, nil); err != nil {
		t.Fatal(err)
	}
	maxBytes := routineBytes + ackJournalMaxFrameBytes + 1
	keys := NewKeyring()
	if err := keys.Add(
		1,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSpool(
		SpoolConfig{
			StateDir:             root,
			MaxBytes:             maxBytes,
			PriorityReserveBytes: maxBytes - routineBytes,
		},
		state,
		keys,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if state.Snapshot().MutationReadOnly {
		t.Fatal("unknown-tier publication temp consumed routine reserve")
	}
	if _, err := os.Lstat(tempPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publication temp survived recovery: %v", err)
	}
	if gaps := reopened.UncoveredGaps(1); !reflect.DeepEqual(
		gaps,
		[]SequenceGap{{Start: 2, End: 2}},
	) {
		t.Fatalf("reserved gaps=%+v", gaps)
	}
}

func TestEmptyAckCheckpointTempConsumesPhysicalQuota(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 111)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	if _, err := signer.Wrap(
		context.Background(),
		"observer_start",
		map[string]any{
			"kind":    "priority-fills-quota",
			"padding": strings.Repeat("x", 8_192),
		},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	maxBytes := spool.totalBytes
	if maxBytes <= ackJournalMaxFrameBytes {
		t.Fatalf("fixture bytes=%d", maxBytes)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	tempPath := filepath.Join(
		root,
		"spool",
		".acked.agf.tmp-66666666666666666666666666666666",
	)
	if err := durablefile.AtomicWrite(tempPath, nil); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(
		1,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSpool(
		SpoolConfig{
			StateDir:             root,
			MaxBytes:             maxBytes,
			PriorityReserveBytes: maxBytes / 2,
		},
		state,
		keys,
	)
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!state.Snapshot().MutationReadOnly {
		t.Fatalf(
			"empty ack temp err=%v readonly=%v",
			err,
			state.Snapshot().MutationReadOnly,
		)
	}
	if _, err := os.Lstat(tempPath); err != nil {
		t.Fatalf("quota failure removed empty ack temp: %v", err)
	}
}

func TestStartupRejectsConflictingUnresolvedTransactionProvenance(
	t *testing.T,
) {
	t.Run("ack temp and adoptable suffix", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 112)
		state, spool, signer := openSignerFixture(
			t,
			root,
			testBootID,
			privateKey,
		)
		for _, kind := range []string{"prefix", "suffix"} {
			if _, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": kind},
				metadata(),
			); err != nil {
				t.Fatal(err)
			}
		}
		first := spool.items[1]
		second := spool.items[2]
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		state.mutex.Lock()
		state.state.PublicationHeadSequence = first.Sequence
		state.state.PublicationHeadHash = first.publicationHash
		if err := state.persistLocked(state.state); err != nil {
			state.mutex.Unlock()
			t.Fatal(err)
		}
		state.mutex.Unlock()
		ackTemp := filepath.Join(
			root,
			"spool",
			".acked.agf.tmp-77777777777777777777777777777777",
		)
		if err := durablefile.AtomicWrite(ackTemp, nil); err != nil {
			t.Fatal(err)
		}
		keys := NewKeyring()
		if err := keys.Add(
			1,
			privateKey.Public().(ed25519.PublicKey),
		); err != nil {
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
		if reopened != nil {
			_ = reopened.Close()
		}
		if !errors.Is(err, ErrSpoolCorrupt) ||
			state.Snapshot().PublicationHeadSequence != first.Sequence {
			t.Fatalf(
				"conflicting suffix err=%v snapshot=%+v",
				err,
				state.Snapshot(),
			)
		}
		for _, path := range []string{
			ackTemp,
			second.path,
			second.publicationPath,
		} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("conflict evidence %s missing: %v", path, err)
			}
		}
	})

	for _, provenance := range []string{
		"ack checkpoint temp",
		"torn ack tail",
	} {
		t.Run(provenance+" and prepared without frame", func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 113)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			event, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": provenance},
				metadata(),
			)
			if err != nil {
				t.Fatal(err)
			}
			item := spool.items[event.SourceSequence]
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			prepared := publicationPreparedPath(
				root,
				event.SourceSequence,
			)
			if err := os.Rename(item.publicationPath, prepared); err != nil {
				t.Fatal(err)
			}
			if err := durablefile.SyncDirectory(
				publicationDirectory(root),
			); err != nil {
				t.Fatal(err)
			}
			if err := durablefile.Remove(item.path); err != nil {
				t.Fatal(err)
			}
			state.mutex.Lock()
			state.state.PublicationHeadSequence = 0
			state.state.PublicationHeadHash = zeroPublicationHash
			if err := state.persistLocked(state.state); err != nil {
				state.mutex.Unlock()
				t.Fatal(err)
			}
			state.mutex.Unlock()
			ackPath := filepath.Join(root, "spool", "acked.agf")
			var otherArtifact string
			switch provenance {
			case "ack checkpoint temp":
				otherArtifact = filepath.Join(
					root,
					"spool",
					".acked.agf.tmp-"+
						"88888888888888888888888888888888",
				)
				if err := durablefile.AtomicWrite(
					otherArtifact,
					nil,
				); err != nil {
					t.Fatal(err)
				}
			case "torn ack tail":
				otherArtifact = ackPath
				file, err := os.OpenFile(
					ackPath,
					os.O_WRONLY|os.O_APPEND,
					0,
				)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write([]byte("AGF1")); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Sync(); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if reopened != nil {
				_ = reopened.Close()
			}
			if !errors.Is(err, ErrSpoolCorrupt) ||
				state.Snapshot().PublicationHeadSequence != 0 {
				t.Fatalf(
					"provenance=%s err=%v snapshot=%+v",
					provenance,
					err,
					state.Snapshot(),
				)
			}
			if _, err := os.Lstat(prepared); err != nil {
				t.Fatalf("prepared evidence missing: %v", err)
			}
			if _, err := os.Lstat(otherArtifact); err != nil {
				t.Fatalf("other evidence missing: %v", err)
			}
			if provenance == "torn ack tail" {
				info, err := os.Stat(ackPath)
				if err != nil {
					t.Fatal(err)
				}
				if info.Size() != 4 {
					t.Fatalf("torn tail was truncated to %d", info.Size())
				}
			}
		})
	}
}

func TestAckBaseCommitCrashLeftoversAreCleanedOnRestart(t *testing.T) {
	for _, leftover := range []string{"full pair", "marker only"} {
		t.Run(leftover, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 114)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			items := make([]SpoolItem, 0, 2)
			for sequence := 1; sequence <= 2; sequence++ {
				event, err := signer.Wrap(
					context.Background(),
					"falco_connect",
					map[string]any{
						"kind":     leftover,
						"sequence": sequence,
					},
					metadata(),
				)
				if err != nil {
					t.Fatal(err)
				}
				items = append(items, spool.items[event.SourceSequence])
			}
			injected := errors.New("crash before ack cleanup")
			spool.remove = func(
				string,
				durablefile.FileIdentity,
			) error {
				return injected
			}
			for _, item := range items {
				if err := spool.Ack(
					item.Sequence,
					item.EventID,
					item.ContentSHA256,
				); !errors.Is(err, injected) {
					t.Fatalf("Ack(%d) err=%v", item.Sequence, err)
				}
			}
			snapshot := state.Snapshot()
			if snapshot.AckSequence != items[1].Sequence ||
				snapshot.PublicationBaseSequence != items[1].Sequence ||
				snapshot.PublicationBaseHash != items[1].publicationHash {
				t.Fatalf("ack/base snapshot=%+v", snapshot)
			}
			if leftover == "marker only" {
				if err := durablefile.Remove(items[0].path); err != nil {
					t.Fatal(err)
				}
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if state.Snapshot().MutationReadOnly {
				t.Fatal("committed ack cleanup leftovers fenced mutation")
			}
			for _, item := range items {
				for _, path := range []string{item.path, item.publicationPath} {
					if _, err := os.Lstat(path); !errors.Is(
						err,
						os.ErrNotExist,
					) {
						t.Fatalf("acked artifact survived %s: %v", path, err)
					}
				}
			}
			fetched, err := reopened.Fetch(0, 10, 4*1024*1024)
			if err != nil || len(fetched) != 0 {
				t.Fatalf("Fetch err=%v items=%+v", err, fetched)
			}
		})
	}
}

func TestPublicationLedgerRejectsMiddleAndSubtreePairDeletion(t *testing.T) {
	for _, deletion := range []string{"middle pair", "active subtree"} {
		t.Run(deletion, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 115)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			for sequence := 1; sequence <= 3; sequence++ {
				if _, err := signer.Wrap(
					context.Background(),
					"falco_connect",
					map[string]any{"sequence": sequence},
					metadata(),
				); err != nil {
					t.Fatal(err)
				}
			}
			toDelete := []uint64{2}
			if deletion == "active subtree" {
				toDelete = []uint64{1, 2, 3}
			}
			for _, sequence := range toDelete {
				item := spool.items[sequence]
				for _, path := range []string{
					item.path,
					item.publicationPath,
				} {
					if err := durablefile.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if reopened != nil {
				_ = reopened.Close()
			}
			if !errors.Is(err, ErrSpoolCorrupt) ||
				!state.Snapshot().MutationReadOnly {
				t.Fatalf(
					"deletion=%s err=%v readonly=%v",
					deletion,
					err,
					state.Snapshot().MutationReadOnly,
				)
			}
		})
	}
}

func TestPublicationLedgerRejectsTwoNodeSuffixBeyondStoredHead(
	t *testing.T,
) {
	root := t.TempDir()
	privateKey := testKey(t, 116)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	for sequence := 1; sequence <= 3; sequence++ {
		if _, err := signer.Wrap(
			context.Background(),
			"falco_connect",
			map[string]any{"sequence": sequence},
			metadata(),
		); err != nil {
			t.Fatal(err)
		}
	}
	first := spool.items[1]
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	state.mutex.Lock()
	state.state.PublicationHeadSequence = first.Sequence
	state.state.PublicationHeadHash = first.publicationHash
	if err := state.persistLocked(state.state); err != nil {
		state.mutex.Unlock()
		t.Fatal(err)
	}
	state.mutex.Unlock()
	keys := NewKeyring()
	if err := keys.Add(
		1,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
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
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrSpoolCorrupt) ||
		!state.Snapshot().MutationReadOnly {
		t.Fatalf(
			"two-node suffix err=%v readonly=%v",
			err,
			state.Snapshot().MutationReadOnly,
		)
	}
}

func TestConcurrentWrapPublishesInSourceSequenceOrder(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 117)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	const count = 24
	type result struct {
		event contracts.EventEnvelopeV1
		err   error
	}
	results := make(chan result, count)
	var start sync.WaitGroup
	start.Add(1)
	for index := 0; index < count; index++ {
		index := index
		go func() {
			start.Wait()
			event, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"index": index},
				metadata(),
			)
			results <- result{event: event, err: err}
		}()
	}
	start.Done()
	seen := make(map[uint64]struct{}, count)
	for range count {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		seen[got.event.SourceSequence] = struct{}{}
	}
	if len(seen) != count {
		t.Fatalf("unique source sequences=%d", len(seen))
	}
	previousHash := zeroPublicationHash
	for sequence := uint64(1); sequence <= count; sequence++ {
		item, ok := spool.items[sequence]
		if !ok {
			t.Fatalf("missing sequence=%d", sequence)
		}
		if item.publication.PreviousPublicationHash != previousHash {
			t.Fatalf(
				"sequence=%d previous=%s want=%s",
				sequence,
				item.publication.PreviousPublicationHash,
				previousHash,
			)
		}
		previousHash = item.publicationHash
	}
	if snapshot := state.Snapshot(); snapshot.LastSequence != count ||
		snapshot.PublicationHeadSequence != count ||
		snapshot.PublicationHeadHash != previousHash {
		t.Fatalf("final snapshot=%+v", snapshot)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	keys := NewKeyring()
	if err := keys.Add(
		1,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
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
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	items, err := reopened.Fetch(0, count, 4*1024*1024)
	if err != nil || len(items) != count {
		t.Fatalf("reopened Fetch err=%v count=%d", err, len(items))
	}
	for index, item := range items {
		if item.Sequence != uint64(index+1) {
			t.Fatalf("item[%d].Sequence=%d", index, item.Sequence)
		}
	}
}

func TestAckMarkerUnlinkSyncFailureIsIdempotentAcrossRetryAndRestart(
	t *testing.T,
) {
	for _, recovery := range []string{"live retry", "restart"} {
		t.Run(recovery, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 118)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			event, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": recovery},
				metadata(),
			)
			if err != nil {
				t.Fatal(err)
			}
			item := spool.items[event.SourceSequence]
			injected := errors.New("injected publication directory fsync failure")
			spool.removePublication = func(
				path string,
				identity durablefile.FileIdentity,
			) error {
				return durablefile.RemoveIfIdentityWithDirectorySync(
					path,
					identity,
					func() error { return injected },
				)
			}
			spool.syncDirectory = func(string) error { return injected }
			if err := spool.Ack(
				item.Sequence,
				item.EventID,
				item.ContentSHA256,
			); !errors.Is(err, durablefile.ErrCommitUncertain) ||
				!errors.Is(err, injected) {
				t.Fatalf("first Ack err=%v", err)
			}
			snapshot := state.Snapshot()
			if snapshot.AckSequence != item.Sequence ||
				snapshot.PublicationBaseSequence != item.Sequence {
				t.Fatalf("durable ack/base=%+v", snapshot)
			}
			for _, path := range []string{item.path, item.publicationPath} {
				if _, err := os.Lstat(path); !errors.Is(
					err,
					os.ErrNotExist,
				) {
					t.Fatalf("unlink did not occur for %s: %v", path, err)
				}
			}
			spool.removePublication = durablefile.RemoveIfIdentity
			spool.syncDirectory = durablefile.SyncDirectory
			switch recovery {
			case "live retry":
			case "restart":
				if err := spool.Close(); err != nil {
					t.Fatal(err)
				}
				keys := NewKeyring()
				if err := keys.Add(
					1,
					privateKey.Public().(ed25519.PublicKey),
				); err != nil {
					t.Fatal(err)
				}
				spool, err = NewSpool(
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
			}
			if err := spool.Ack(
				item.Sequence,
				item.EventID,
				item.ContentSHA256,
			); err != nil {
				t.Fatalf("identical Ack retry err=%v", err)
			}
			if state.Snapshot().MutationReadOnly {
				t.Fatal("uncertain marker cleanup fenced mutation")
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			recovered, err := durablefile.Recover(
				filepath.Join(root, "spool", "acked.agf"),
				4_096,
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(recovered.Records) != 1 {
				t.Fatalf(
					"identical retry duplicated ack records=%d",
					len(recovered.Records),
				)
			}
		})
	}
}

func TestExactPublicationSuffixRecoveryPreservesExistingReadOnlyFence(
	t *testing.T,
) {
	for _, markerState := range []string{"published", "prepared"} {
		t.Run(markerState, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 119)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			event, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": markerState},
				metadata(),
			)
			if err != nil {
				t.Fatal(err)
			}
			item := spool.items[event.SourceSequence]
			preparedPath := publicationPreparedPath(
				root,
				item.Sequence,
			)
			if markerState == "prepared" {
				if err := os.Rename(
					item.publicationPath,
					preparedPath,
				); err != nil {
					t.Fatal(err)
				}
				if err := durablefile.SyncDirectory(
					publicationDirectory(root),
				); err != nil {
					t.Fatal(err)
				}
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			state.mutex.Lock()
			state.state.PublicationHeadSequence = 0
			state.state.PublicationHeadHash = zeroPublicationHash
			state.state.MutationReadOnly = true
			state.state.ReadOnlyReason = "observer_spool_write_uncertain"
			state.state.ReconcileRequired = true
			if err := state.persistLocked(state.state); err != nil {
				state.mutex.Unlock()
				t.Fatal(err)
			}
			state.mutex.Unlock()
			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			snapshot := state.Snapshot()
			if !snapshot.MutationReadOnly ||
				snapshot.ReadOnlyReason !=
					"observer_spool_write_uncertain" ||
				snapshot.PublicationHeadSequence != item.Sequence ||
				snapshot.PublicationHeadHash != item.publicationHash {
				t.Fatalf("recovered fenced snapshot=%+v", snapshot)
			}
			items, err := reopened.Fetch(0, 10, 4*1024*1024)
			if err != nil || len(items) != 1 ||
				items[0].EventID != item.EventID {
				t.Fatalf("Fetch err=%v items=%+v", err, items)
			}
			if _, err := os.Stat(item.publicationPath); err != nil {
				t.Fatalf("published marker missing: %v", err)
			}
			if _, err := os.Lstat(preparedPath); !errors.Is(
				err,
				os.ErrNotExist,
			) {
				t.Fatalf("prepared marker survived: %v", err)
			}
		})
	}
}

func TestUncertainRecoveryPersistDoesNotReplaceExistingReadOnlyReason(
	t *testing.T,
) {
	root := t.TempDir()
	privateKey := testKey(t, 121)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "preserve-fence-reason"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	state.mutex.Lock()
	state.state.PublicationHeadSequence = 0
	state.state.PublicationHeadHash = zeroPublicationHash
	state.state.MutationReadOnly = true
	state.state.ReadOnlyReason = "observer_spool_write_uncertain"
	state.state.ReconcileRequired = true
	state.mutex.Unlock()
	uncertain := errors.Join(
		durablefile.ErrCommitUncertain,
		errors.New("injected state directory sync failure"),
	)
	state.persist = func(string, ObserverState) error {
		return uncertain
	}
	if err := state.recoverPublicationHead(
		zeroPublicationHash,
		item.Sequence,
		item.publicationHash,
	); !errors.Is(err, durablefile.ErrCommitUncertain) {
		t.Fatalf("recoverPublicationHead err=%v", err)
	}
	snapshot := state.Snapshot()
	if !snapshot.MutationReadOnly ||
		snapshot.ReadOnlyReason != "observer_spool_write_uncertain" ||
		snapshot.PublicationHeadSequence != item.Sequence ||
		snapshot.PublicationHeadHash != item.publicationHash {
		t.Fatalf("uncertain recovery snapshot=%+v", snapshot)
	}
}

func TestBootstrapRetainsRecoveredSuffixInDegradedReadOnlyDaemon(
	t *testing.T,
) {
	for _, markerState := range []string{"published", "prepared"} {
		t.Run(markerState, func(t *testing.T) {
			configPath, config, _, _ := rotationFixture(t)
			options := []BootstrapOption{
				WithBootstrapBootID(func() (string, error) {
					return testBootID, nil
				}),
				WithBootstrapNow(func() time.Time {
					return time.Date(
						2026,
						7,
						27,
						14,
						0,
						0,
						0,
						time.UTC,
					)
				}),
			}
			healthy, err := Bootstrap(
				context.Background(),
				configPath,
				options...,
			)
			if err != nil {
				t.Fatal(err)
			}
			prefix := healthy.state.Snapshot()
			event, err := healthy.signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": markerState},
				metadata(),
			)
			if err != nil {
				_ = healthy.Close()
				t.Fatal(err)
			}
			item := healthy.spool.items[event.SourceSequence]
			if err := healthy.Close(); err != nil {
				t.Fatal(err)
			}
			preparedPath := publicationPreparedPath(
				config.StateDir,
				item.Sequence,
			)
			if markerState == "prepared" {
				if err := os.Rename(
					item.publicationPath,
					preparedPath,
				); err != nil {
					t.Fatal(err)
				}
				if err := durablefile.SyncDirectory(
					publicationDirectory(config.StateDir),
				); err != nil {
					t.Fatal(err)
				}
			}
			healthy.state.mutex.Lock()
			next := healthy.state.state
			next.PublicationHeadSequence =
				prefix.PublicationHeadSequence
			next.PublicationHeadHash = prefix.PublicationHeadHash
			next.MutationReadOnly = true
			next.ReadOnlyReason = "observer_spool_write_uncertain"
			next.ReconcileRequired = true
			if err := healthy.state.persistLocked(next); err != nil {
				healthy.state.mutex.Unlock()
				t.Fatal(err)
			}
			healthy.state.state = next
			healthy.state.mutex.Unlock()

			degraded, err := Bootstrap(
				context.Background(),
				configPath,
				options...,
			)
			if err != nil {
				t.Fatalf("degraded Bootstrap err=%v", err)
			}
			defer degraded.Close()
			snapshot := degraded.state.Snapshot()
			if !snapshot.MutationReadOnly ||
				snapshot.ReadOnlyReason !=
					"observer_spool_write_uncertain" ||
				snapshot.PublicationHeadSequence != item.Sequence ||
				snapshot.PublicationHeadHash != item.publicationHash ||
				snapshot.LastSequence != item.Sequence {
				t.Fatalf("degraded snapshot=%+v", snapshot)
			}
			if degraded.spool == nil ||
				degraded.signer != nil ||
				degraded.coverage != nil ||
				degraded.degraded == nil {
				t.Fatalf(
					"degraded fields spool=%v signer=%v coverage=%v err=%v",
					degraded.spool != nil,
					degraded.signer != nil,
					degraded.coverage != nil,
					degraded.degraded,
				)
			}
			items, err := degraded.spool.Fetch(
				prefix.PublicationHeadSequence,
				10,
				4*1024*1024,
			)
			if err != nil || len(items) != 1 ||
				items[0].EventID != item.EventID {
				t.Fatalf("degraded Fetch err=%v items=%+v", err, items)
			}
			if _, err := AcquireStateLock(config.StateDir); !errors.Is(
				err,
				ErrStateLocked,
			) {
				t.Fatalf("degraded daemon released lock: %v", err)
			}
			if _, err := os.Stat(item.publicationPath); err != nil {
				t.Fatalf("published suffix missing: %v", err)
			}
			if _, err := os.Lstat(preparedPath); !errors.Is(
				err,
				os.ErrNotExist,
			) {
				t.Fatalf("prepared suffix survived: %v", err)
			}
		})
	}
}

const spoolCreateOnlyCrashExit = 89

func TestSpoolCreateOnlyKillHelper(t *testing.T) {
	if os.Getenv("AGMIND_TEST_HELPER") != "spool-create-only" {
		return
	}
	root := os.Getenv("AGMIND_TEST_ROOT")
	stage := os.Getenv("AGMIND_TEST_STAGE")
	privateKey := testKey(t, 108)
	_, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	spool.publish = func(path string, payload []byte) error {
		return durablefile.CreateOnly(
			path,
			payload,
			durablefile.WithCreateOnlyBoundaryHook(
				func(boundary durablefile.CreateOnlyBoundary) {
					if stage == string(boundary) {
						os.Exit(spoolCreateOnlyCrashExit)
					}
				},
			),
		)
	}
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": stage},
		metadata(),
	); err != nil {
		os.Exit(90)
	}
	os.Exit(91)
}

func TestSpoolRecoversCreateOnlyKillStages(t *testing.T) {
	for _, stage := range []string{
		string(durablefile.CreateOnlyTempCreated),
		string(durablefile.CreateOnlyPayloadWritten),
		string(durablefile.CreateOnlyFileSynced),
		string(durablefile.CreateOnlyRenamedPreDirSync),
		string(durablefile.CreateOnlyDirSynced),
	} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			command := exec.Command(
				os.Args[0],
				"-test.run=^TestSpoolCreateOnlyKillHelper$",
			)
			command.Env = append(
				os.Environ(),
				"AGMIND_TEST_HELPER=spool-create-only",
				"AGMIND_TEST_ROOT="+root,
				"AGMIND_TEST_STAGE="+stage,
			)
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) ||
				exitError.ExitCode() != spoolCreateOnlyCrashExit {
				t.Fatalf(
					"stage=%s err=%v output=%s",
					stage,
					err,
					output,
				)
			}
			privateKey := testKey(t, 108)
			keyID, err := contracts.KeyID(
				privateKey.Public().(ed25519.PublicKey),
			)
			if err != nil {
				t.Fatal(err)
			}
			state, err := OpenStateStore(
				filepath.Join(root, "observer-state.json"),
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
			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			items, err := reopened.Fetch(0, 10, 4*1024*1024)
			if err != nil {
				t.Fatal(err)
			}
			if stage == string(durablefile.CreateOnlyTempCreated) ||
				stage == string(durablefile.CreateOnlyPayloadWritten) ||
				stage == string(durablefile.CreateOnlyFileSynced) {
				if len(items) != 0 ||
					!reflect.DeepEqual(
						reopened.UncoveredGaps(0),
						[]SequenceGap{{Start: 1, End: 1}},
					) {
					t.Fatalf(
						"pre-rename stage=%s items=%+v gaps=%+v",
						stage,
						items,
						reopened.UncoveredGaps(0),
					)
				}
				if state.Snapshot().PublicationHeadSequence != 0 {
					t.Fatalf(
						"pre-rename stage=%s head=%d",
						stage,
						state.Snapshot().PublicationHeadSequence,
					)
				}
			} else {
				if len(items) != 1 || items[0].Sequence != 1 {
					t.Fatalf("stage=%s items=%+v", stage, items)
				}
				snapshot := state.Snapshot()
				if snapshot.PublicationHeadSequence != 1 ||
					snapshot.PublicationHeadHash !=
						items[0].publicationHash {
					t.Fatalf("stage=%s snapshot=%+v", stage, snapshot)
				}
			}
			for _, directory := range []string{
				filepath.Join(root, "spool", string(RoutineTier)),
				publicationDirectory(root),
			} {
				entries, err := os.ReadDir(directory)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.Contains(entry.Name(), ".tmp-") ||
						strings.HasSuffix(entry.Name(), ".prepared") {
						t.Fatalf(
							"stage=%s recovery artifact=%s",
							stage,
							entry.Name(),
						)
					}
				}
			}
		})
	}
}

const ackTransactionCrashExit = 92

func TestAckTransactionKillHelper(t *testing.T) {
	if os.Getenv("AGMIND_TEST_HELPER") != "ack-transaction" {
		return
	}
	root := os.Getenv("AGMIND_TEST_ROOT")
	stage := os.Getenv("AGMIND_TEST_STAGE")
	privateKey := testKey(t, 120)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	items := make([]SpoolItem, 0, 2)
	for sequence := 1; sequence <= 2; sequence++ {
		event, err := signer.Wrap(
			context.Background(),
			"falco_connect",
			map[string]any{"sequence": sequence},
			metadata(),
		)
		if err != nil {
			os.Exit(93)
		}
		items = append(items, spool.items[event.SourceSequence])
	}
	if err := spool.Ack(
		items[0].Sequence,
		items[0].EventID,
		items[0].ContentSHA256,
	); err != nil {
		os.Exit(94)
	}
	if err := spool.ackJournal.Close(); err != nil {
		os.Exit(95)
	}
	syncCalls := 0
	directorySyncCalls := 0
	ackPath := filepath.Join(root, "spool", "acked.agf")
	journal, err := durablefile.NewJournal(
		ackPath,
		durablefile.WithMaxFrame(4_096),
		durablefile.WithSync(func(file *os.File) error {
			syncCalls++
			err := file.Sync()
			if err == nil &&
				syncCalls == 2 &&
				stage == "checkpoint_temp_fsynced" {
				os.Exit(ackTransactionCrashExit)
			}
			return err
		}),
		durablefile.WithDirectorySync(func(fd int) error {
			directorySyncCalls++
			if directorySyncCalls == 2 &&
				stage == "checkpoint_renamed_pre_dirsync" {
				os.Exit(ackTransactionCrashExit)
			}
			err := unix.Fsync(fd)
			if err == nil &&
				directorySyncCalls == 2 &&
				stage == "checkpoint_dirsynced" {
				os.Exit(ackTransactionCrashExit)
			}
			return err
		}),
	)
	if err != nil {
		os.Exit(96)
	}
	spool.ackJournal = journal
	originalPersist := state.persist
	persistCalls := 0
	state.persist = func(path string, next ObserverState) error {
		persistCalls++
		if persistCalls == 1 && stage == "before_anchor1" {
			os.Exit(ackTransactionCrashExit)
		}
		err := originalPersist(path, next)
		if err == nil &&
			persistCalls == 1 &&
			stage == "after_anchor1" {
			os.Exit(ackTransactionCrashExit)
		}
		if err == nil &&
			persistCalls == 2 &&
			stage == "after_anchor2" {
			os.Exit(ackTransactionCrashExit)
		}
		return err
	}
	if err := spool.Ack(
		items[1].Sequence,
		items[1].EventID,
		items[1].ContentSHA256,
	); err != nil {
		os.Exit(97)
	}
	os.Exit(98)
}

func TestAckTransactionKillBoundariesRecoverExactlyOnce(t *testing.T) {
	for _, stage := range []string{
		"before_anchor1",
		"after_anchor1",
		"checkpoint_temp_fsynced",
		"checkpoint_renamed_pre_dirsync",
		"checkpoint_dirsynced",
		"after_anchor2",
	} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			command := exec.Command(
				os.Args[0],
				"-test.run=^TestAckTransactionKillHelper$",
			)
			command.Env = append(
				os.Environ(),
				"AGMIND_TEST_HELPER=ack-transaction",
				"AGMIND_TEST_ROOT="+root,
				"AGMIND_TEST_STAGE="+stage,
			)
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) ||
				exitError.ExitCode() != ackTransactionCrashExit {
				t.Fatalf(
					"stage=%s err=%v output=%s",
					stage,
					err,
					output,
				)
			}
			framePath := filepath.Join(
				root,
				"spool",
				string(RoutineTier),
				"00000000000000000002.agf",
			)
			publicationPath := publicationPublishedPath(root, 2)
			for _, path := range []string{framePath, publicationPath} {
				if _, err := os.Lstat(path); err != nil {
					t.Fatalf(
						"stage=%s lacks ack-or-artifact invariant %s: %v",
						stage,
						path,
						err,
					)
				}
			}
			publication, _, _, err := readPublication(publicationPath)
			if err != nil {
				t.Fatal(err)
			}
			_, publicationHash, err := publicationNodeHash(publication)
			if err != nil {
				t.Fatal(err)
			}
			privateKey := testKey(t, 120)
			keyID, err := contracts.KeyID(
				privateKey.Public().(ed25519.PublicKey),
			)
			if err != nil {
				t.Fatal(err)
			}
			state, err := OpenStateStore(
				filepath.Join(root, "observer-state.json"),
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
			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if err != nil {
				t.Fatal(err)
			}
			snapshot := state.Snapshot()
			if snapshot.MutationReadOnly ||
				snapshot.AckSequence != 2 ||
				snapshot.PublicationBaseSequence != 2 ||
				snapshot.PublicationBaseHash != publicationHash ||
				snapshot.AckEventID != publication.EventID ||
				snapshot.AckContentSHA256 !=
					publication.ContentSHA256 {
				_ = reopened.Close()
				t.Fatalf("stage=%s snapshot=%+v", stage, snapshot)
			}
			if (stage == "checkpoint_temp_fsynced") !=
				snapshot.AckRepairPending {
				_ = reopened.Close()
				t.Fatalf(
					"stage=%s repair pending=%v reason=%s",
					stage,
					snapshot.AckRepairPending,
					snapshot.AckRepairReason,
				)
			}
			fetched, err := reopened.Fetch(0, 10, 4*1024*1024)
			if err != nil || len(fetched) != 0 {
				_ = reopened.Close()
				t.Fatalf(
					"stage=%s Fetch err=%v items=%+v",
					stage,
					err,
					fetched,
				)
			}
			for _, path := range []string{framePath, publicationPath} {
				if _, err := os.Lstat(path); !errors.Is(
					err,
					os.ErrNotExist,
				) {
					_ = reopened.Close()
					t.Fatalf(
						"stage=%s acked artifact survived %s: %v",
						stage,
						path,
						err,
					)
				}
			}
			rootEntries, err := os.ReadDir(filepath.Join(root, "spool"))
			if err != nil {
				_ = reopened.Close()
				t.Fatal(err)
			}
			for _, entry := range rootEntries {
				if ackTempNamePattern.MatchString(entry.Name()) {
					_ = reopened.Close()
					t.Fatalf(
						"stage=%s checkpoint temp survived %s",
						stage,
						entry.Name(),
					)
				}
			}
			if err := reopened.Ack(
				2,
				publication.EventID,
				publication.ContentSHA256,
			); err != nil {
				_ = reopened.Close()
				t.Fatalf("stage=%s identical Ack err=%v", stage, err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
			recovery, err := durablefile.Recover(
				filepath.Join(root, "spool", "acked.agf"),
				4_096,
			)
			if err != nil {
				t.Fatal(err)
			}
			sequenceTwoRecords := 0
			for _, framed := range recovery.Records {
				record, err := contracts.DecodeStrict[ackRecord](
					bytes.NewReader(framed.Payload),
					4_096,
				)
				if err != nil {
					t.Fatal(err)
				}
				if record.Sequence == 2 {
					sequenceTwoRecords++
				}
			}
			if sequenceTwoRecords != 1 {
				t.Fatalf(
					"stage=%s sequence-2 ack records=%d total=%d",
					stage,
					sequenceTwoRecords,
					len(recovery.Records),
				)
			}
		})
	}
}

func TestAckRejectsUncoveredReservedGapBeforeJournalMutation(
	t *testing.T,
) {
	for _, priorAck := range []bool{false, true} {
		name := "initial gap"
		if priorAck {
			name = "gap after prior ack"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 122)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			if priorAck {
				event, err := signer.Wrap(
					context.Background(),
					"falco_connect",
					map[string]any{"kind": "prior"},
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
			}
			if _, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"invalid_number": 1.5},
				metadata(),
			); err == nil {
				t.Fatal("expected post-reservation normalization failure")
			}
			event, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": "after-gap"},
				metadata(),
			)
			if err != nil {
				t.Fatal(err)
			}
			item := spool.items[event.SourceSequence]
			before := state.Snapshot()
			ackPath := filepath.Join(root, "spool", "acked.agf")
			beforeInfo, err := os.Stat(ackPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := spool.Ack(
				item.Sequence,
				item.EventID,
				item.ContentSHA256,
			); !errors.Is(err, ErrAckInvalid) {
				t.Fatalf("uncovered gap Ack err=%v", err)
			}
			after := state.Snapshot()
			afterInfo, err := os.Stat(ackPath)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) ||
				beforeInfo.Size() != afterInfo.Size() {
				t.Fatalf(
					"rejected Ack mutated state/journal before=%+v after=%+v sizes=%d/%d",
					before,
					after,
					beforeInfo.Size(),
					afterInfo.Size(),
				)
			}
			if err := state.markGapCovered(item.Sequence - 1); err != nil {
				t.Fatal(err)
			}
			if err := spool.Ack(
				item.Sequence,
				item.EventID,
				item.ContentSHA256,
			); err != nil {
				t.Fatalf("covered gap Ack err=%v", err)
			}
		})
	}
}

func TestAckRecoveryRejectsDurableRecordAcrossUncoveredReservedGap(
	t *testing.T,
) {
	for _, priorAck := range []bool{false, true} {
		name := "initial gap"
		if priorAck {
			name = "gap after prior ack"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 123)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			if priorAck {
				event, err := signer.Wrap(
					context.Background(),
					"falco_connect",
					map[string]any{"kind": "prior"},
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
			}
			if _, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"invalid_number": 1.5},
				metadata(),
			); err == nil {
				t.Fatal("expected post-reservation normalization failure")
			}
			event, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": "after-gap"},
				metadata(),
			)
			if err != nil {
				t.Fatal(err)
			}
			item := spool.items[event.SourceSequence]
			before := state.Snapshot()
			if before.LastCoveredGapEnd >= item.Sequence-1 {
				t.Fatalf("fixture unexpectedly covered gap: %+v", before)
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}

			record := ackRecord{
				SchemaVersion: "agmind.spool-ack.v1",
				Sequence:      item.Sequence,
				EventID:       item.EventID,
				ContentSHA256: item.ContentSHA256,
				AckedAt:       "2026-07-27T12:00:00Z",
			}
			canonical, err := contracts.CanonicalJSON(record)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := durablefile.NewJournal(
				filepath.Join(root, "spool", "acked.agf"),
				durablefile.WithMaxFrame(4_096),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := journal.Append(canonical, true); err != nil {
				_ = journal.Close()
				t.Fatal(err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			ackPath := filepath.Join(root, "spool", "acked.agf")
			journalBefore, err := os.ReadFile(ackPath)
			if err != nil {
				t.Fatal(err)
			}

			keys := NewKeyring()
			if err := keys.Add(
				1,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
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
			if reopened != nil {
				_ = reopened.Close()
			}
			after := state.Snapshot()
			journalAfter, readErr := os.ReadFile(ackPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !errors.Is(err, ErrSpoolCorrupt) ||
				!after.MutationReadOnly ||
				after.AckSequence != before.AckSequence ||
				after.AckEventID != before.AckEventID ||
				after.AckContentSHA256 != before.AckContentSHA256 ||
				after.AckRecordHash != before.AckRecordHash ||
				after.AckPayloadSHA256 != before.AckPayloadSHA256 ||
				after.PublicationBaseSequence !=
					before.PublicationBaseSequence ||
				after.PublicationBaseHash != before.PublicationBaseHash ||
				after.LastCoveredGapEnd != before.LastCoveredGapEnd ||
				!bytes.Equal(journalBefore, journalAfter) {
				t.Fatalf(
					"recovered uncovered-gap ack mutated anchor/journal err=%v before=%+v after=%+v journal_equal=%v",
					err,
					before,
					after,
					bytes.Equal(journalBefore, journalAfter),
				)
			}
			if _, statErr := os.Stat(item.path); statErr != nil {
				t.Fatalf("event was removed during failed recovery: %v", statErr)
			}
			if _, statErr := os.Stat(item.publicationPath); statErr != nil {
				t.Fatalf(
					"publication was removed during failed recovery: %v",
					statErr,
				)
			}
		})
	}
}

func TestAckGapPredicateIsOverflowSafe(t *testing.T) {
	maximum := ^uint64(0)
	for _, testCase := range []struct {
		name              string
		after             uint64
		sequence          uint64
		lastCoveredGapEnd uint64
		want              bool
	}{
		{
			name:     "wrapped sequence is not forward",
			after:    maximum,
			sequence: 0,
			want:     false,
		},
		{
			name:     "maximum adjacent sequence has no gap",
			after:    maximum - 1,
			sequence: maximum,
			want:     false,
		},
		{
			name:              "maximum sequence detects uncovered gap",
			sequence:          maximum,
			lastCoveredGapEnd: maximum - 2,
			want:              true,
		},
		{
			name:              "maximum sequence accepts covered gap",
			sequence:          maximum,
			lastCoveredGapEnd: maximum - 1,
			want:              false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ackCrossesUncoveredGap(
				testCase.after,
				testCase.sequence,
				testCase.lastCoveredGapEnd,
			); got != testCase.want {
				t.Fatalf("got=%v want=%v", got, testCase.want)
			}
		})
	}
}

func TestBootstrapCoversReservedGapExactlyOnceBeforeAckAdvances(
	t *testing.T,
) {
	configPath, _, _, _ := rotationFixture(t)
	options := []BootstrapOption{
		WithBootstrapBootID(func() (string, error) {
			return testBootID, nil
		}),
		WithBootstrapNow(func() time.Time {
			return time.Date(
				2026,
				7,
				27,
				14,
				0,
				0,
				0,
				time.UTC,
			)
		}),
	}
	daemon, err := Bootstrap(context.Background(), configPath, options...)
	if err != nil {
		t.Fatal(err)
	}
	start := daemon.spool.items[1]
	if err := daemon.spool.Ack(
		start.Sequence,
		start.EventID,
		start.ContentSHA256,
	); err != nil {
		_ = daemon.Close()
		t.Fatal(err)
	}
	if _, err := daemon.signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"invalid_number": 1.5},
		metadata(),
	); err == nil {
		_ = daemon.Close()
		t.Fatal("expected post-reservation normalization failure")
	}
	event, err := daemon.signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "after-gap"},
		metadata(),
	)
	if err != nil {
		_ = daemon.Close()
		t.Fatal(err)
	}
	item := daemon.spool.items[event.SourceSequence]
	if err := daemon.spool.Ack(
		item.Sequence,
		item.EventID,
		item.ContentSHA256,
	); !errors.Is(err, ErrAckInvalid) {
		_ = daemon.Close()
		t.Fatalf("pre-coverage Ack err=%v", err)
	}
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}

	daemon, err = Bootstrap(context.Background(), configPath, options...)
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := daemon.spool.Fetch(1, 10, 4*1024*1024)
	if err != nil {
		_ = daemon.Close()
		t.Fatal(err)
	}
	gapEvents := 0
	for _, fetchedItem := range fetched {
		event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(fetchedItem.Canonical),
			65_536,
		)
		if err != nil {
			_ = daemon.Close()
			t.Fatal(err)
		}
		if event.EventType == "coverage" &&
			event.NormalizedFields["kind"] ==
				"observer_sequence_gap" {
			gapEvents++
		}
	}
	if gapEvents != 1 ||
		daemon.state.Snapshot().LastCoveredGapEnd != 3 {
		_ = daemon.Close()
		t.Fatalf(
			"gap events=%d snapshot=%+v",
			gapEvents,
			daemon.state.Snapshot(),
		)
	}
	for _, fetchedItem := range fetched {
		if err := daemon.spool.Ack(
			fetchedItem.Sequence,
			fetchedItem.EventID,
			fetchedItem.ContentSHA256,
		); err != nil {
			_ = daemon.Close()
			t.Fatalf(
				"covered progression Ack(%d) err=%v",
				fetchedItem.Sequence,
				err,
			)
		}
	}
	ackedThrough := daemon.state.Snapshot().AckSequence
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}

	daemon, err = Bootstrap(context.Background(), configPath, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	fetched, err = daemon.spool.Fetch(
		ackedThrough,
		10,
		4*1024*1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, fetchedItem := range fetched {
		event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(fetchedItem.Canonical),
			65_536,
		)
		if err != nil {
			t.Fatal(err)
		}
		if event.EventType == "coverage" &&
			event.NormalizedFields["kind"] ==
				"observer_sequence_gap" {
			t.Fatal("restart duplicated reserved-sequence gap coverage")
		}
	}
}

func TestStateStoreDoesNotExposeBootHistorySliceAliases(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 123)
	state, spool, _ := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	defer spool.Close()
	snapshot := state.Snapshot()
	snapshot.BootHistory[0].BootID = testBootID2
	if got := state.Snapshot().BootHistory[0].BootID; got != testBootID {
		t.Fatalf("Snapshot mutation changed live BootID=%s", got)
	}

	state.persist = func(_ string, next ObserverState) error {
		next.BootHistory[0].BootID = testBootID2
		return nil
	}
	if err := state.markGapCovered(0); err != nil {
		t.Fatal(err)
	}
	if got := state.Snapshot().BootHistory[0].BootID; got != testBootID {
		t.Fatalf("persist callback mutation changed live BootID=%s", got)
	}
}
