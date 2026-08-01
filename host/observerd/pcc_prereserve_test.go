package observerd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
)

type pccPublicationSurface struct {
	state         ObserverState
	totalBytes    uint64
	items         map[uint64]SpoolItem
	receiptAnchor PCCReceiptAnchor
	receipts      map[string]PCCPublicationReceipt
}

func observePCCPublicationSurface(
	state *StateStore,
	spool *Spool,
) pccPublicationSurface {
	observed := pccPublicationSurface{state: state.Snapshot()}
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	observed.totalBytes = spool.totalBytes
	observed.items = make(map[uint64]SpoolItem, len(spool.items))
	for sequence, item := range spool.items {
		observed.items[sequence] = cloneSpoolItem(item)
	}
	spool.pccReceipts.mutex.Lock()
	defer spool.pccReceipts.mutex.Unlock()
	observed.receiptAnchor = spool.pccReceipts.anchor
	observed.receipts = make(
		map[string]PCCPublicationReceipt,
		len(spool.pccReceipts.receipts),
	)
	for operationKey, receipt := range spool.pccReceipts.receipts {
		observed.receipts[operationKey] = receipt
	}
	return observed
}

func assertPCCPublicationSurfaceUnchanged(
	t *testing.T,
	before pccPublicationSurface,
	after pccPublicationSurface,
) {
	t.Helper()
	if !reflect.DeepEqual(after.state, before.state) {
		t.Errorf("observer state changed before reserve: before=%+v after=%+v", before.state, after.state)
	}
	if after.totalBytes != before.totalBytes {
		t.Errorf("spool total bytes changed before reserve: before=%d after=%d", before.totalBytes, after.totalBytes)
	}
	if !reflect.DeepEqual(after.items, before.items) {
		t.Errorf("spool items changed before reserve: before=%+v after=%+v", before.items, after.items)
	}
	if after.receiptAnchor != before.receiptAnchor {
		t.Errorf("PCC receipt anchor changed before reserve: before=%+v after=%+v", before.receiptAnchor, after.receiptAnchor)
	}
	if !reflect.DeepEqual(after.receipts, before.receipts) {
		t.Errorf("PCC receipt metadata changed before reserve: before=%+v after=%+v", before.receipts, after.receipts)
	}
}

func assertNoPCCSequenceArtifacts(
	t *testing.T,
	spool *Spool,
	sequence uint64,
) {
	t.Helper()
	for _, path := range []string{
		filepath.Join(
			spool.directory(PriorityTier),
			fmt.Sprintf("%020d.agf", sequence),
		),
		publicationPreparedPath(spool.config.StateDir, sequence),
		publicationPublishedPath(spool.config.StateDir, sequence),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pre-reserve PCC artifact path=%q err=%v", path, err)
		}
	}
}

func TestPCCPublishPreReserveFailuresExposeNothing(t *testing.T) {
	injectedPersistErr := errors.New("injected ordinary PCC reserve persistence failure")
	tests := []struct {
		name                 string
		wantErr              error
		injectReserveError   bool
		constrainPCCCapacity bool
		wantReserveAttempts  int
	}{
		{
			name:                 "preflight preserves ACK journal reserve",
			wantErr:              ErrPriorityQuota,
			constrainPCCCapacity: true,
			wantReserveAttempts:  0,
		},
		{
			name:                "ordinary reserve persistence failure",
			wantErr:             injectedPersistErr,
			injectReserveError:  true,
			wantReserveAttempts: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPCCFailedPublishFixture(t)
			before := observePCCPublicationSurface(fixture.state, fixture.spool)
			targetSequence := before.state.LastSequence + 1
			operationKey := "pcc_correlation_snapshot:" + fixture.request.TriggerEventID

			reserveAttempts := 0
			persist := fixture.state.persist
			fixture.state.persist = func(path string, next ObserverState) error {
				if next.LastSequence == targetSequence {
					reserveAttempts++
					if test.injectReserveError {
						return injectedPersistErr
					}
				}
				return persist(path, next)
			}
			if test.constrainPCCCapacity {
				fixture.spool.config.MaxBytes = fixture.spool.totalBytes +
					ackJournalMaxFrameBytes
			}

			publication, err := fixture.service.PublishPCCCorrelationSnapshot(
				context.Background(),
				fixture.request,
			)
			if !errors.Is(err, test.wantErr) {
				t.Errorf("publication error=%v want errors.Is %v", err, test.wantErr)
			}
			if !reflect.DeepEqual(publication, PCCCorrelationPublication{}) {
				t.Errorf("pre-reserve failure exposed publication=%+v", publication)
			}
			if reserveAttempts != test.wantReserveAttempts {
				t.Errorf("reserve persistence attempts=%d want=%d", reserveAttempts, test.wantReserveAttempts)
			}

			after := observePCCPublicationSurface(fixture.state, fixture.spool)
			assertPCCPublicationSurfaceUnchanged(t, before, after)
			assertNoPCCSequenceArtifacts(t, fixture.spool, targetSequence)
			if _, found := after.receipts[operationKey]; found {
				t.Errorf("pre-reserve failure exposed receipt metadata for %q", operationKey)
			}
		})
	}
}

func TestPCCPublishGenericAppendRequiresSpecializedReceipt(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 127)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	trigger, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "pcc-generic-append-trigger"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	triggerItem := spool.items[trigger.SourceSequence]
	fields, _ := pccReceiptFields(t, triggerItem)
	normalized, err := contracts.CanonicalJSON(fields)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := contracts.DecodeStrict[contracts.PCCCorrelationSnapshotV1](
		bytes.NewReader(normalized),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	stateSnapshot := state.Snapshot()
	sequence := stateSnapshot.LastSequence + 1
	event, err := signPCCSnapshotAt(
		signer,
		stateSnapshot,
		sequence,
		time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		proof,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("PCC envelope fixture is not independently valid: %v", err)
	}

	before := observePCCPublicationSurface(state, spool)
	item, err := spool.Append(event, PriorityTier)
	if !errors.Is(err, ErrPCCReceiptRequired) {
		t.Errorf("generic priority PCC append error=%v want ErrPCCReceiptRequired", err)
	}
	if !reflect.DeepEqual(item, SpoolItem{}) {
		t.Errorf("generic priority PCC append exposed item=%+v", item)
	}
	after := observePCCPublicationSurface(state, spool)
	assertPCCPublicationSurfaceUnchanged(t, before, after)
	assertNoPCCSequenceArtifacts(t, spool, sequence)
	operationKey := "pcc_correlation_snapshot:" + proof.Trigger.EventID
	if _, found := after.receipts[operationKey]; found {
		t.Errorf("generic priority PCC append exposed receipt metadata for %q", operationKey)
	}
}

func TestPCCPublishGenericSignerRejectsBeforeReservation(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 128)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	trigger, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "pcc-generic-signer-trigger"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := pccReceiptFields(t, spool.items[trigger.SourceSequence])
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)

	before := observePCCPublicationSurface(state, spool)
	sequence := before.state.LastSequence + 1
	event, err := signer.Wrap(
		context.Background(),
		"pcc_correlation_snapshot",
		fields,
		EventMetadata{
			EventTime:           time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
			RedactionFlags:      []string{},
			CoverageFlags:       []string{},
			SourcePayloadHash:   hex.EncodeToString(digest[:]),
			InventoryGeneration: 0,
		},
	)
	if !errors.Is(err, ErrPCCReceiptRequired) {
		t.Errorf("generic PCC signer error=%v want ErrPCCReceiptRequired", err)
	}
	if !reflect.DeepEqual(event, contracts.EventEnvelopeV1{}) {
		t.Errorf("generic PCC signer exposed event=%+v", event)
	}
	after := observePCCPublicationSurface(state, spool)
	assertPCCPublicationSurfaceUnchanged(t, before, after)
	assertNoPCCSequenceArtifacts(t, spool, sequence)
}
