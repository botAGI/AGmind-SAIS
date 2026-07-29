package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
	"golang.org/x/sys/unix"
)

const controlReceiptTestOperationID = "123e4567-e89b-42d3-a456-426614174010"

func controlReceiptTestItem(
	t *testing.T,
	sequence uint64,
	eventType string,
	operationField string,
	operationID string,
) CoreEventV1 {
	t.Helper()
	var request CoreControlRequest
	switch eventType {
	case "evidence_repair_authorized":
		value := coreControlAuthorizeFixture()
		value.RepairID = operationID
		request = value
	case "evidence_repair_completed":
		value := coreControlCompleteFixture()
		value.RepairID = operationID
		request = value
	case "retention_tombstone":
		value := coreControlTombstoneFixture()
		value.TombstoneID = operationID
		request = value
	case "retention_blocked_priority_evidence":
		value := coreControlBlockedFixture()
		value.BlockedID = operationID
		request = value
	default:
		t.Fatalf("unsupported control receipt event type %q", eventType)
	}
	fields := request.NormalizedFields()
	if fields[operationField] != operationID {
		t.Fatalf("operation field %q does not bind %q", operationField, operationID)
	}
	normalized, err := contracts.CanonicalJSON(fields)
	if err != nil {
		t.Fatal(err)
	}
	normalizedHash := sha256.Sum256(normalized)
	normalizedSHA256 := hex.EncodeToString(normalizedHash[:])
	envelope := contracts.EventEnvelopeV1{
		SchemaVersion:          "agmind.event-envelope.v1",
		EventType:              eventType,
		SourceID:               "agmind-observerd",
		SourceVersion:          "0.1.0",
		KeyID:                  strings.Repeat("a", 32),
		KeyEpoch:               1,
		HostID:                 testHostID,
		BootID:                 testBootID,
		SourceSequence:         sequence,
		EventTime:              "2026-07-29T12:00:00Z",
		IngestTime:             "2026-07-29T12:00:00Z",
		ClockUncertaintyMS:     0,
		InventoryGeneration:    0,
		NormalizedFields:       fields,
		NormalizedFieldsSHA256: normalizedSHA256,
		RedactionFlags:         []string{},
		CoverageFlags:          []string{},
		SourcePayloadHash:      normalizedSHA256,
		SourceSignature:        strings.Repeat("b", 128),
	}
	envelope.EventID, err = contracts.DeriveEventID(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	canonical, err := contracts.CanonicalJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := sha256.Sum256(canonical)
	return CoreEventV1{
		Sequence:      sequence,
		EventID:       envelope.EventID,
		ContentSHA256: hex.EncodeToString(contentHash[:]),
		Envelope:      envelope,
	}
}

func controlReceiptTestValue(
	t *testing.T,
	key string,
	item CoreEventV1,
) ControlReceipt {
	t.Helper()
	receipt := ControlReceipt{
		SchemaVersion: "agmind.control-receipt.v1",
		Key:           key,
		RequestSHA256: item.Envelope.NormalizedFieldsSHA256,
		Item:          item,
	}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func controlReceiptTestItemsEqual(
	t *testing.T,
	left CoreEventV1,
	right CoreEventV1,
) bool {
	t.Helper()
	leftRaw, leftErr := contracts.CanonicalJSON(left)
	rightRaw, rightErr := contracts.CanonicalJSON(right)
	if leftErr != nil || rightErr != nil {
		t.Fatalf("canonical item comparison: left=%v right=%v", leftErr, rightErr)
	}
	return bytes.Equal(leftRaw, rightRaw)
}

func mutateControlReceiptTestItem(item *CoreEventV1) {
	item.Envelope.NormalizedFields["reason"] = "caller_mutated_receipt"
	item.Envelope.RedactionFlags = append(
		item.Envelope.RedactionFlags,
		"caller_mutated_receipt",
	)
}

func sealedControlReceiptTestProof(
	key string,
	item CoreEventV1,
) ControlReceiptLiveProof {
	return ControlReceiptLiveProof{
		key:           key,
		requestSHA256: item.Envelope.NormalizedFieldsSHA256,
		item:          item,
		sealed:        true,
	}
}

func appendLiveControlSpoolItemFixture(
	t *testing.T,
) (*Spool, SpoolItem) {
	t.Helper()
	service, _, spool, _, _ := observerServiceFixture(t)
	request := coreControlAuthorizeFixture()
	publication, err := service.PublishCoreControl(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	var item *SpoolItem
	for index := range items {
		if items[index].Sequence == publication.Item.Sequence {
			item = &items[index]
			break
		}
	}
	if item == nil || item.Tier != PriorityTier {
		t.Fatalf("unexpected live control items: %+v", items)
	}
	return spool, *item
}

func signedControlPreflightFixture(
	t *testing.T,
	state ObserverState,
	privateKey ed25519.PrivateKey,
	request CoreControlRequest,
) contracts.EventEnvelopeV1 {
	t.Helper()
	fields := request.NormalizedFields()
	normalized, err := contracts.CanonicalJSON(fields)
	if err != nil {
		t.Fatal(err)
	}
	normalizedHash := sha256.Sum256(normalized)
	normalizedSHA256 := hex.EncodeToString(normalizedHash[:])
	event := contracts.EventEnvelopeV1{
		SchemaVersion:          "agmind.event-envelope.v1",
		EventType:              request.EventType(),
		SourceID:               "agmind-observerd",
		SourceVersion:          "0.1.0",
		KeyID:                  state.KeyID,
		KeyEpoch:               state.KeyEpoch,
		HostID:                 state.HostID,
		BootID:                 state.BootID,
		SourceSequence:         state.LastSequence + 1,
		EventTime:              "2026-07-29T12:00:00Z",
		IngestTime:             "2026-07-29T12:00:00Z",
		ClockUncertaintyMS:     0,
		InventoryGeneration:    0,
		NormalizedFields:       fields,
		NormalizedFieldsSHA256: normalizedSHA256,
		RedactionFlags:         []string{},
		CoverageFlags:          []string{},
		SourcePayloadHash:      normalizedSHA256,
	}
	event.EventID, err = contracts.DeriveEventID(event)
	if err != nil {
		t.Fatal(err)
	}
	message, err := contracts.EventSigningMessage(event)
	if err != nil {
		t.Fatal(err)
	}
	event.SourceSignature = hex.EncodeToString(
		ed25519.Sign(privateKey, message),
	)
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyEventSignature(
		event,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatal(err)
	}
	return event
}

func createControlReceiptDirectory(t *testing.T, stateDir string) {
	t.Helper()
	path := filepath.Join(stateDir, "spool")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func appendControlReceiptFixture(
	t *testing.T,
	stateDir string,
	payloads ...[]byte,
) ControlReceiptAnchor {
	t.Helper()
	createControlReceiptDirectory(t, stateDir)
	journal, err := durablefile.NewJournal(
		controlReceiptJournalPath(stateDir),
		durablefile.WithMaxFrame(controlReceiptMaxFramePayload),
	)
	if err != nil {
		t.Fatal(err)
	}
	anchor := EmptyControlReceiptAnchor()
	for _, payload := range payloads {
		meta, appendErr := journal.Append(payload, true)
		if appendErr != nil {
			_ = journal.Close()
			t.Fatal(appendErr)
		}
		anchor, err = advanceControlReceiptAnchor(anchor, meta)
		if err != nil {
			_ = journal.Close()
			t.Fatal(err)
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	return anchor
}

func TestControlReceiptJournalExactRetryConflictQuotaAndRestart(t *testing.T) {
	stateDir := t.TempDir()
	anchor := EmptyControlReceiptAnchor()
	journal, err := OpenControlReceiptJournal(stateDir, anchor)
	if err != nil {
		t.Fatal(err)
	}

	key := "evidence_repair_authorized:" + controlReceiptTestOperationID
	item := controlReceiptTestItem(
		t,
		1,
		"evidence_repair_authorized",
		"repair_id",
		controlReceiptTestOperationID,
	)
	requestSHA256 := item.Envelope.NormalizedFieldsSHA256
	commitCalls := 0
	stored, created, err := journal.Store(
		key,
		requestSHA256,
		item,
		func(previous, next ControlReceiptAnchor) error {
			commitCalls++
			if previous != anchor {
				t.Fatalf("previous anchor=%+v, want %+v", previous, anchor)
			}
			anchor = next
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !created || commitCalls != 1 ||
		!controlReceiptTestItemsEqual(t, stored, item) {
		t.Fatalf(
			"created=%t commit_calls=%d stored=%+v",
			created,
			commitCalls,
			stored,
		)
	}
	if anchor.Count != 1 ||
		anchor.Bytes <= uint64(len(requestSHA256)) ||
		anchor.HeadHash == zeroControlReceiptHash {
		t.Fatalf("invalid committed anchor: %+v", anchor)
	}

	retried, created, err := journal.Store(
		key,
		requestSHA256,
		controlReceiptTestItem(
			t,
			99,
			"evidence_repair_authorized",
			"repair_id",
			controlReceiptTestOperationID,
		),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if created || !controlReceiptTestItemsEqual(t, retried, item) ||
		commitCalls != 1 || journal.Anchor() != anchor {
		t.Fatalf(
			"retry created=%t calls=%d anchor=%+v item=%+v",
			created,
			commitCalls,
			journal.Anchor(),
			retried,
		)
	}
	differentRequest := strings.Repeat("f", 64)
	if differentRequest == requestSHA256 {
		differentRequest = strings.Repeat("e", 64)
	}
	if _, _, err := journal.Store(
		key,
		differentRequest,
		item,
		nil,
	); !errors.Is(err, ErrControlReceiptConflict) {
		t.Fatalf("different body error=%v, want operation conflict", err)
	}
	if _, err := journal.Lookup(key, differentRequest); !errors.Is(
		err,
		ErrControlReceiptConflict,
	) {
		t.Fatalf("lookup conflict error=%v", err)
	}
	lookedUp, err := journal.Lookup(key, requestSHA256)
	if err != nil || !controlReceiptTestItemsEqual(t, lookedUp, item) {
		t.Fatalf("lookup item=%+v error=%v", lookedUp, err)
	}
	receipt, found, err := journal.Find(key)
	if err != nil || !found ||
		receipt.RequestSHA256 != requestSHA256 ||
		!controlReceiptTestItemsEqual(t, receipt.Item, item) {
		t.Fatalf("find found=%t receipt=%+v error=%v", found, receipt, err)
	}

	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenControlReceiptJournal(stateDir, anchor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	retried, created, err = journal.Store(key, requestSHA256, item, nil)
	if err != nil || created || !controlReceiptTestItemsEqual(t, retried, item) {
		t.Fatalf(
			"restart retry created=%t item=%+v error=%v",
			created,
			retried,
			err,
		)
	}

	fullCount := ControlReceiptAnchor{
		Count:    controlReceiptMaxCount,
		Bytes:    1,
		HeadHash: strings.Repeat("a", 64),
	}
	meta := durablefile.RecordMeta{
		Hash: [sha256.Size]byte{1},
		Size: 1,
	}
	if _, err := advanceControlReceiptAnchor(
		fullCount,
		meta,
	); !errors.Is(err, ErrControlReceiptQuota) {
		t.Fatalf("record quota error=%v", err)
	}
	fullBytes := ControlReceiptAnchor{
		Count:    1,
		Bytes:    controlReceiptMaxBytes,
		HeadHash: strings.Repeat("a", 64),
	}
	if _, err := advanceControlReceiptAnchor(
		fullBytes,
		meta,
	); !errors.Is(err, ErrControlReceiptQuota) {
		t.Fatalf("byte quota error=%v", err)
	}
}

func TestControlReceiptJournalRejectsCorruptionAndReconcilesOneProvenTail(
	t *testing.T,
) {
	t.Run("complete unanchored tail needs exact live priority proof", func(t *testing.T) {
		stateDir := t.TempDir()
		key := "retention_tombstone:" + controlReceiptTestOperationID
		item := controlReceiptTestItem(
			t,
			4,
			"retention_tombstone",
			"tombstone_id",
			controlReceiptTestOperationID,
		)
		receipt := controlReceiptTestValue(t, key, item)
		canonical, err := contracts.CanonicalJSON(receipt)
		if err != nil {
			t.Fatal(err)
		}
		wantAnchor := appendControlReceiptFixture(t, stateDir, canonical)
		empty := EmptyControlReceiptAnchor()

		recovery, err := InspectControlReceiptJournal(stateDir, empty)
		if err != nil {
			t.Fatal(err)
		}
		if recovery.Kind != ControlReceiptRecoveryCompleteTail ||
			recovery.Candidate == nil ||
			recovery.JournalAnchor != wantAnchor {
			t.Fatalf("unexpected recovery: %+v", recovery)
		}
		before, err := os.ReadFile(controlReceiptJournalPath(stateDir))
		if err != nil {
			t.Fatal(err)
		}
		if opened, err := OpenControlReceiptJournal(stateDir, empty); opened != nil ||
			!errors.Is(err, ErrControlReceiptReconciliationRequired) {
			t.Fatalf("open journal=%v error=%v", opened, err)
		}
		after, err := os.ReadFile(controlReceiptJournalPath(stateDir))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("ordinary startup changed an unanchored complete tail")
		}

		proof := sealedControlReceiptTestProof(key, item)
		commitCalls := 0
		next, err := ReconcileControlReceiptJournal(
			stateDir,
			empty,
			proof,
			func(previous, proposed ControlReceiptAnchor) error {
				commitCalls++
				if previous != empty || proposed != wantAnchor {
					t.Fatalf(
						"recovery transition %+v -> %+v",
						previous,
						proposed,
					)
				}
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if commitCalls != 1 || next != wantAnchor {
			t.Fatalf("calls=%d next=%+v", commitCalls, next)
		}
		journal, err := OpenControlReceiptJournal(stateDir, next)
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("incomplete tail is unchanged until its exact proof completes it", func(t *testing.T) {
		stateDir := t.TempDir()
		createControlReceiptDirectory(t, stateDir)
		key := "retention_blocked_priority_evidence:" +
			controlReceiptTestOperationID
		item := controlReceiptTestItem(
			t,
			7,
			"retention_blocked_priority_evidence",
			"blocked_id",
			controlReceiptTestOperationID,
		)
		receipt := controlReceiptTestValue(t, key, item)
		canonical, err := contracts.CanonicalJSON(receipt)
		if err != nil {
			t.Fatal(err)
		}
		frame, meta, err := durablefile.EncodeFrame(
			canonical,
			[sha256.Size]byte{},
			controlReceiptMaxFramePayload,
		)
		if err != nil {
			t.Fatal(err)
		}
		torn := append([]byte(nil), frame[:len(frame)-9]...)
		path := controlReceiptJournalPath(stateDir)
		if err := os.WriteFile(path, torn, 0o600); err != nil {
			t.Fatal(err)
		}
		empty := EmptyControlReceiptAnchor()
		recovery, err := InspectControlReceiptJournal(stateDir, empty)
		if err != nil {
			t.Fatal(err)
		}
		if recovery.Kind != ControlReceiptRecoveryIncompleteTail ||
			recovery.UnanchoredBytes != uint64(len(torn)) {
			t.Fatalf("unexpected torn recovery: %+v", recovery)
		}
		if opened, err := OpenControlReceiptJournal(stateDir, empty); opened != nil ||
			!errors.Is(err, ErrControlReceiptReconciliationRequired) {
			t.Fatalf("open journal=%v error=%v", opened, err)
		}
		unchanged, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(unchanged, torn) {
			t.Fatal("ordinary startup silently repaired an incomplete tail")
		}

		wrongItem := controlReceiptTestItem(
			t,
			8,
			"retention_blocked_priority_evidence",
			"blocked_id",
			"123e4567-e89b-42d3-a456-426614174011",
		)
		wrongProof := sealedControlReceiptTestProof(
			"retention_blocked_priority_evidence:"+
				"123e4567-e89b-42d3-a456-426614174011",
			wrongItem,
		)
		if _, err := ReconcileControlReceiptJournal(
			stateDir,
			empty,
			wrongProof,
			func(ControlReceiptAnchor, ControlReceiptAnchor) error {
				t.Fatal("mismatched proof reached anchor commit")
				return nil
			},
		); err == nil {
			t.Fatal("mismatched proof must fail closed")
		}
		unchanged, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(unchanged, torn) {
			t.Fatal("mismatched proof changed the incomplete tail")
		}

		proof := sealedControlReceiptTestProof(key, item)
		wantAnchor, err := advanceControlReceiptAnchor(empty, meta)
		if err != nil {
			t.Fatal(err)
		}
		next, err := ReconcileControlReceiptJournal(
			stateDir,
			empty,
			proof,
			func(previous, proposed ControlReceiptAnchor) error {
				if previous != empty || proposed != wantAnchor {
					t.Fatalf(
						"recovery transition %+v -> %+v",
						previous,
						proposed,
					)
				}
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if next != wantAnchor {
			t.Fatalf("next=%+v, want %+v", next, wantAnchor)
		}
		repaired, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(repaired, frame) {
			t.Fatal("proven incomplete tail was not completed exactly")
		}
		recovery, err = InspectControlReceiptJournal(stateDir, next)
		if err != nil || recovery.Kind != ControlReceiptRecoveryExact {
			t.Fatalf("post-recovery state=%+v error=%v", recovery, err)
		}
	})

	t.Run("noncanonical duplicate ambiguous and rollback state fail closed", func(t *testing.T) {
		key := "evidence_repair_completed:" + controlReceiptTestOperationID
		first := controlReceiptTestValue(
			t,
			key,
			controlReceiptTestItem(
				t,
				10,
				"evidence_repair_completed",
				"repair_id",
				controlReceiptTestOperationID,
			),
		)
		second := controlReceiptTestValue(
			t,
			key,
			controlReceiptTestItem(
				t,
				11,
				"evidence_repair_completed",
				"repair_id",
				controlReceiptTestOperationID,
			),
		)
		reorderedOperationID := "123e4567-e89b-42d3-a456-426614174011"
		reordered := controlReceiptTestValue(
			t,
			"evidence_repair_completed:"+reorderedOperationID,
			controlReceiptTestItem(
				t,
				9,
				"evidence_repair_completed",
				"repair_id",
				reorderedOperationID,
			),
		)
		firstCanonical, err := contracts.CanonicalJSON(first)
		if err != nil {
			t.Fatal(err)
		}
		secondCanonical, err := contracts.CanonicalJSON(second)
		if err != nil {
			t.Fatal(err)
		}
		reorderedCanonical, err := contracts.CanonicalJSON(reordered)
		if err != nil {
			t.Fatal(err)
		}

		tests := []struct {
			name        string
			payloads    [][]byte
			stateAnchor func(ControlReceiptAnchor) ControlReceiptAnchor
		}{
			{
				name:     "two complete unanchored records",
				payloads: [][]byte{firstCanonical, secondCanonical},
				stateAnchor: func(ControlReceiptAnchor) ControlReceiptAnchor {
					return EmptyControlReceiptAnchor()
				},
			},
			{
				name:     "duplicate operation key",
				payloads: [][]byte{firstCanonical, secondCanonical},
				stateAnchor: func(journalAnchor ControlReceiptAnchor) ControlReceiptAnchor {
					return journalAnchor
				},
			},
			{
				name:     "reordered receipt sequence",
				payloads: [][]byte{firstCanonical, reorderedCanonical},
				stateAnchor: func(journalAnchor ControlReceiptAnchor) ControlReceiptAnchor {
					return journalAnchor
				},
			},
			{
				name: "noncanonical receipt",
				payloads: func() [][]byte {
					var indented bytes.Buffer
					if err := json.Indent(
						&indented,
						firstCanonical,
						"",
						"  ",
					); err != nil {
						t.Fatal(err)
					}
					return [][]byte{indented.Bytes()}
				}(),
				stateAnchor: func(journalAnchor ControlReceiptAnchor) ControlReceiptAnchor {
					return journalAnchor
				},
			},
			{
				name:     "anchored journal rollback",
				payloads: nil,
				stateAnchor: func(ControlReceiptAnchor) ControlReceiptAnchor {
					return ControlReceiptAnchor{
						Count:    1,
						Bytes:    100,
						HeadHash: strings.Repeat("c", 64),
					}
				},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				stateDir := t.TempDir()
				journalAnchor := EmptyControlReceiptAnchor()
				if len(test.payloads) > 0 {
					journalAnchor = appendControlReceiptFixture(
						t,
						stateDir,
						test.payloads...,
					)
				}
				_, err := InspectControlReceiptJournal(
					stateDir,
					test.stateAnchor(journalAnchor),
				)
				if !errors.Is(err, ErrControlReceiptCorrupt) {
					t.Fatalf("error=%v, want receipt corruption", err)
				}
			})
		}
	})
}

func TestControlReceiptMutableAliasesAreIsolated(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(
			*testing.T,
			*ControlReceiptJournal,
			string,
			string,
			*CoreEventV1,
			CoreEventV1,
		)
	}{
		{
			name: "store input",
			mutate: func(
				_ *testing.T,
				_ *ControlReceiptJournal,
				_ string,
				_ string,
				input *CoreEventV1,
				_ CoreEventV1,
			) {
				mutateControlReceiptTestItem(input)
			},
		},
		{
			name: "store response",
			mutate: func(
				_ *testing.T,
				_ *ControlReceiptJournal,
				_ string,
				_ string,
				_ *CoreEventV1,
				stored CoreEventV1,
			) {
				mutateControlReceiptTestItem(&stored)
			},
		},
		{
			name: "find response",
			mutate: func(
				t *testing.T,
				journal *ControlReceiptJournal,
				key string,
				_ string,
				_ *CoreEventV1,
				_ CoreEventV1,
			) {
				receipt, found, err := journal.Find(key)
				if err != nil || !found {
					t.Fatalf("find found=%t error=%v", found, err)
				}
				mutateControlReceiptTestItem(&receipt.Item)
			},
		},
		{
			name: "lookup response",
			mutate: func(
				t *testing.T,
				journal *ControlReceiptJournal,
				key string,
				requestSHA256 string,
				_ *CoreEventV1,
				_ CoreEventV1,
			) {
				item, err := journal.Lookup(key, requestSHA256)
				if err != nil {
					t.Fatal(err)
				}
				mutateControlReceiptTestItem(&item)
			},
		},
		{
			name: "existing preview response",
			mutate: func(
				t *testing.T,
				journal *ControlReceiptJournal,
				key string,
				requestSHA256 string,
				input *CoreEventV1,
				_ CoreEventV1,
			) {
				item, created, receiptBytes, err := journal.Preview(
					key,
					requestSHA256,
					*input,
				)
				if err != nil {
					t.Fatal(err)
				}
				if created || receiptBytes != 0 {
					t.Fatalf(
						"existing preview created=%t receipt_bytes=%d",
						created,
						receiptBytes,
					)
				}
				mutateControlReceiptTestItem(&item)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateDir := t.TempDir()
			anchor := EmptyControlReceiptAnchor()
			journal, err := OpenControlReceiptJournal(stateDir, anchor)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = journal.Close() })

			key := "evidence_repair_authorized:" +
				controlReceiptTestOperationID
			input := controlReceiptTestItem(
				t,
				1,
				"evidence_repair_authorized",
				"repair_id",
				controlReceiptTestOperationID,
			)
			requestSHA256 := input.Envelope.NormalizedFieldsSHA256
			want, err := contracts.CanonicalJSON(input)
			if err != nil {
				t.Fatal(err)
			}
			stored, created, err := journal.Store(
				key,
				requestSHA256,
				input,
				func(_ ControlReceiptAnchor, next ControlReceiptAnchor) error {
					anchor = next
					return nil
				},
			)
			if err != nil || !created {
				t.Fatalf("store created=%t error=%v", created, err)
			}
			test.mutate(
				t,
				journal,
				key,
				requestSHA256,
				&input,
				stored,
			)

			authoritative, err := journal.Lookup(key, requestSHA256)
			if err != nil {
				t.Fatal(err)
			}
			got, err := contracts.CanonicalJSON(authoritative)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf(
					"caller mutation changed authoritative receipt\n got=%s\nwant=%s",
					got,
					want,
				)
			}
			if journal.Anchor() != anchor {
				t.Fatalf(
					"caller mutation changed anchor: got %+v want %+v",
					journal.Anchor(),
					anchor,
				)
			}
		})
	}
}

func TestControlReceiptRejectsUnsealedForgedProof(t *testing.T) {
	stateDir := t.TempDir()
	key := "retention_tombstone:" + controlReceiptTestOperationID
	item := controlReceiptTestItem(
		t,
		4,
		"retention_tombstone",
		"tombstone_id",
		controlReceiptTestOperationID,
	)
	receipt := controlReceiptTestValue(t, key, item)
	canonical, err := contracts.CanonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	appendControlReceiptFixture(t, stateDir, canonical)
	empty := EmptyControlReceiptAnchor()
	before, err := os.ReadFile(controlReceiptJournalPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}

	forged := ControlReceiptLiveProof{
		key:           key,
		requestSHA256: item.Envelope.NormalizedFieldsSHA256,
		item:          item,
		sealed:        false,
	}
	commitCalled := false
	if _, err := ReconcileControlReceiptJournal(
		stateDir,
		empty,
		forged,
		func(ControlReceiptAnchor, ControlReceiptAnchor) error {
			commitCalled = true
			return nil
		},
	); err == nil {
		t.Fatal("caller-constructed recovery proof was accepted")
	}
	if commitCalled {
		t.Fatal("unsealed proof reached receipt anchor commit")
	}
	after, err := os.ReadFile(controlReceiptJournalPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("unsealed proof changed the receipt journal")
	}
}

func TestControlReceiptLockedTornTailIntent(t *testing.T) {
	stateDir := t.TempDir()
	createControlReceiptDirectory(t, stateDir)
	key := "retention_blocked_priority_evidence:" +
		controlReceiptTestOperationID
	item := controlReceiptTestItem(
		t,
		7,
		"retention_blocked_priority_evidence",
		"blocked_id",
		controlReceiptTestOperationID,
	)
	receipt := controlReceiptTestValue(t, key, item)
	canonical, err := contracts.CanonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := durablefile.EncodeFrame(
		canonical,
		[sha256.Size]byte{},
		controlReceiptMaxFramePayload,
	)
	if err != nil {
		t.Fatal(err)
	}
	torn := append([]byte(nil), frame[:len(frame)-11]...)
	path := controlReceiptJournalPath(stateDir)
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	empty := EmptyControlReceiptAnchor()

	if opened, err := OpenControlReceiptJournal(stateDir, empty); opened != nil ||
		!errors.Is(err, ErrControlReceiptReconciliationRequired) {
		t.Fatalf("open journal=%v error=%v", opened, err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged, torn) {
		t.Fatal("open silently truncated a torn receipt tail")
	}

	locked, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(
		int(locked.Fd()),
		unix.LOCK_EX|unix.LOCK_NB,
	); err != nil {
		_ = locked.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Flock(int(locked.Fd()), unix.LOCK_UN)
		_ = locked.Close()
	})
	proof := sealedControlReceiptTestProof(key, item)
	commitCalled := false
	if _, err := ReconcileControlReceiptJournal(
		stateDir,
		empty,
		proof,
		func(ControlReceiptAnchor, ControlReceiptAnchor) error {
			commitCalled = true
			return nil
		},
	); !errors.Is(err, durablefile.ErrJournalLocked) {
		t.Fatalf("locked reconciliation error=%v", err)
	}
	if commitCalled {
		t.Fatal("locked torn tail reached receipt anchor commit")
	}
	unchanged, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged, torn) {
		t.Fatal("reconcile replaced a torn journal without owning its lock")
	}
}

func TestControlReceiptLiveProofRequiresExactDurableSpoolBindings(t *testing.T) {
	t.Run("exact signed priority frame and publication", func(t *testing.T) {
		spool, item := appendLiveControlSpoolItemFixture(t)
		proof, control, err := controlReceiptProofFromLiveSpoolItem(
			item,
			spool.keys,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !control || !proof.sealed ||
			proof.item.Sequence != item.Sequence ||
			proof.item.EventID != item.EventID ||
			proof.item.ContentSHA256 != item.ContentSHA256 {
			t.Fatalf("invalid sealed live proof: control=%t proof=%+v", control, proof)
		}
	})

	inMemoryCases := []struct {
		name   string
		mutate func(*SpoolItem)
	}{
		{
			name: "frame identity",
			mutate: func(item *SpoolItem) {
				item.identity.Inode++
			},
		},
		{
			name: "canonical envelope",
			mutate: func(item *SpoolItem) {
				item.Canonical = append([]byte(nil), item.Canonical...)
				item.Canonical[len(item.Canonical)-1] ^= 1
			},
		},
		{
			name: "publication identity",
			mutate: func(item *SpoolItem) {
				item.publicationIdentity.Inode++
			},
		},
		{
			name: "publication canonical",
			mutate: func(item *SpoolItem) {
				item.publicationRaw = append([]byte(nil), item.publicationRaw...)
				item.publicationRaw[len(item.publicationRaw)-1] ^= 1
			},
		},
	}
	for _, test := range inMemoryCases {
		t.Run("in-memory "+test.name, func(t *testing.T) {
			spool, item := appendLiveControlSpoolItemFixture(t)
			test.mutate(&item)
			if _, _, err := controlReceiptProofFromLiveSpoolItem(
				item,
				spool.keys,
			); !errors.Is(err, ErrControlReceiptCorrupt) {
				t.Fatalf("mutated %s error=%v", test.name, err)
			}
		})
	}

	onDiskCases := []struct {
		name string
		path func(SpoolItem) string
	}{
		{
			name: "frame",
			path: func(item SpoolItem) string { return item.path },
		},
		{
			name: "publication",
			path: func(item SpoolItem) string { return item.publicationPath },
		},
	}
	for _, test := range onDiskCases {
		t.Run("on-disk "+test.name, func(t *testing.T) {
			spool, item := appendLiveControlSpoolItemFixture(t)
			path := test.path(item)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)-1] ^= 1
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := controlReceiptProofFromLiveSpoolItem(
				item,
				spool.keys,
			); !errors.Is(err, ErrControlReceiptCorrupt) {
				t.Fatalf("changed on-disk %s error=%v", test.name, err)
			}
		})
	}
}

func TestControlReceiptCompleteTailRecoversThroughStartupPath(t *testing.T) {
	service, state, spool, _, _ := observerServiceFixture(t)
	request := coreControlAuthorizeFixture()
	requestSHA256, err := CoreControlRequestSHA256(request)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := service.PublishCoreControl(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	committedAnchor := controlReceiptAnchorFromState(state.Snapshot())
	if committedAnchor.Count != 1 {
		t.Fatalf("committed receipt anchor=%+v", committedAnchor)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	liveItems := make(map[uint64]SpoolItem, 1)
	for _, item := range items {
		if item.Sequence == publication.Item.Sequence {
			liveItems[item.Sequence] = item
		}
	}
	if len(liveItems) != 1 {
		t.Fatalf("missing durable control item: %+v", items)
	}

	spool.mutex.Lock()
	stateDir := spool.config.StateDir
	keys := spool.keys
	baseBytes := spool.totalBytes - spool.controlReceiptBytes
	maxReceiptBytes := spool.config.MaxBytes - baseBytes
	spool.mutex.Unlock()
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}

	state.mutex.Lock()
	behind := cloneObserverState(state.state)
	behind.ControlReceiptCount = 0
	behind.ControlReceiptBytes = 0
	behind.ControlReceiptHeadHash = zeroControlReceiptHash
	err = state.replaceLocked(behind)
	state.mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := InspectControlReceiptJournal(
		stateDir,
		EmptyControlReceiptAnchor(),
	)
	if err != nil ||
		recovery.Kind != ControlReceiptRecoveryCompleteTail ||
		recovery.Candidate == nil {
		t.Fatalf("pre-restart recovery=%+v err=%v", recovery, err)
	}

	recovered, err := recoverControlReceiptJournal(
		stateDir,
		state,
		liveItems,
		keys,
		maxReceiptBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if recovered.Anchor() != committedAnchor ||
		controlReceiptAnchorFromState(state.Snapshot()) != committedAnchor {
		t.Fatalf(
			"complete tail was not re-anchored: journal=%+v state=%+v want=%+v",
			recovered.Anchor(),
			controlReceiptAnchorFromState(state.Snapshot()),
			committedAnchor,
		)
	}
	stored, err := recovered.Lookup(request.OperationKey(), requestSHA256)
	if err != nil || !coreControlEventsEqual(stored, publication.Item) {
		t.Fatalf("recovered receipt=%+v err=%v", stored, err)
	}
}

func TestControlReceiptExactJournalRejectsCompletelyMissingReceipt(t *testing.T) {
	service, state, spool, _, _ := observerServiceFixture(t)
	request := coreControlAuthorizeFixture()
	publication, err := service.PublishCoreControl(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	liveItems := make(map[uint64]SpoolItem, 1)
	for _, item := range items {
		if item.Sequence == publication.Item.Sequence {
			liveItems[item.Sequence] = item
		}
	}
	if len(liveItems) != 1 {
		t.Fatalf("missing durable control item: %+v", items)
	}

	spool.mutex.Lock()
	stateDir := spool.config.StateDir
	keys := spool.keys
	baseBytes := spool.totalBytes - spool.controlReceiptBytes
	maxReceiptBytes := spool.config.MaxBytes - baseBytes
	spool.mutex.Unlock()
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}

	state.mutex.Lock()
	behind := cloneObserverState(state.state)
	behind.ControlReceiptCount = 0
	behind.ControlReceiptBytes = 0
	behind.ControlReceiptHeadHash = zeroControlReceiptHash
	err = state.replaceLocked(behind)
	state.mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	path := controlReceiptJournalPath(stateDir)
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.SyncDirectory(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	recovery, err := InspectControlReceiptJournal(
		stateDir,
		EmptyControlReceiptAnchor(),
	)
	if err != nil || recovery.Kind != ControlReceiptRecoveryExact {
		t.Fatalf("empty receipt journal recovery=%+v err=%v", recovery, err)
	}

	recovered, err := recoverControlReceiptJournal(
		stateDir,
		state,
		liveItems,
		keys,
		maxReceiptBytes,
	)
	if recovered != nil {
		_ = recovered.Close()
		t.Fatal("missing receipt was reconstructed")
	}
	if !errors.Is(err, ErrControlReceiptCorrupt) {
		t.Fatalf("missing receipt error=%v", err)
	}
	if controlReceiptAnchorFromState(state.Snapshot()) !=
		EmptyControlReceiptAnchor() {
		t.Fatalf("missing receipt changed state: %+v", state.Snapshot())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 0 {
		t.Fatal("missing receipt was written into exact journal")
	}
}

func TestControlReceiptCompletionRequiresPriorAuthorizationAtJournalBoundaries(
	t *testing.T,
) {
	key := "evidence_repair_completed:" + controlReceiptTestOperationID
	item := controlReceiptTestItem(
		t,
		10,
		"evidence_repair_completed",
		"repair_id",
		controlReceiptTestOperationID,
	)
	receipt := controlReceiptTestValue(t, key, item)
	canonical, err := contracts.CanonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("preview", func(t *testing.T) {
		root := t.TempDir()
		createControlReceiptDirectory(t, root)
		journal, err := OpenControlReceiptJournal(
			root,
			EmptyControlReceiptAnchor(),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer journal.Close()
		if _, created, _, err := journal.Preview(
			receipt.Key,
			receipt.RequestSHA256,
			receipt.Item,
		); err == nil || created {
			t.Fatalf(
				"completion without authorization previewed: created=%t err=%v",
				created,
				err,
			)
		}
	})

	t.Run("store", func(t *testing.T) {
		root := t.TempDir()
		createControlReceiptDirectory(t, root)
		journal, err := OpenControlReceiptJournal(
			root,
			EmptyControlReceiptAnchor(),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer journal.Close()
		path := controlReceiptJournalPath(root)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		commitCalled := false
		if _, created, err := journal.Store(
			receipt.Key,
			receipt.RequestSHA256,
			receipt.Item,
			func(ControlReceiptAnchor, ControlReceiptAnchor) error {
				commitCalled = true
				return nil
			},
		); err == nil || created {
			t.Fatalf(
				"completion without authorization stored: created=%t err=%v",
				created,
				err,
			)
		}
		if commitCalled ||
			journal.Anchor() != EmptyControlReceiptAnchor() {
			t.Fatalf(
				"rejected completion changed journal state: commit=%t anchor=%+v",
				commitCalled,
				journal.Anchor(),
			)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Fatal("rejected completion changed journal bytes")
		}
	})

	for _, parser := range []string{"inspect", "locked open"} {
		t.Run(parser, func(t *testing.T) {
			root := t.TempDir()
			anchor := appendControlReceiptFixture(t, root, canonical)
			switch parser {
			case "inspect":
				if _, err := InspectControlReceiptJournal(
					root,
					anchor,
				); !errors.Is(err, ErrControlReceiptCorrupt) {
					t.Fatalf("completion-only inspect error=%v", err)
				}
			case "locked open":
				journal, err := OpenControlReceiptJournal(root, anchor)
				if journal != nil {
					_ = journal.Close()
				}
				if !errors.Is(err, ErrControlReceiptCorrupt) {
					t.Fatalf("completion-only open error=%v", err)
				}
			}
		})
	}
}

func TestControlReceiptRecoveryRejectsForgedACKRetainedSignature(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 43)
	state, spool, _ := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	request := coreControlAuthorizeFixture()
	event := signedControlPreflightFixture(
		t,
		state.Snapshot(),
		privateKey,
		request,
	)
	event.SourceSignature = strings.Repeat("0", ed25519.SignatureSize*2)
	if err := event.Validate(); err != nil {
		t.Fatalf("forged event is not structurally valid: %v", err)
	}
	if err := contracts.VerifyEventSignature(
		event,
		privateKey.Public().(ed25519.PublicKey),
	); err == nil {
		t.Fatal("forged event unexpectedly verifies")
	}
	canonicalEvent, err := contracts.CanonicalJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := sha256.Sum256(canonicalEvent)
	item := CoreEventV1{
		Sequence:      event.SourceSequence,
		EventID:       event.EventID,
		ContentSHA256: hex.EncodeToString(contentHash[:]),
		Envelope:      event,
	}
	receipt := controlReceiptTestValue(
		t,
		request.OperationKey(),
		item,
	)
	canonicalReceipt, err := contracts.CanonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	keys := spool.keys
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	anchor := appendControlReceiptFixture(t, root, canonicalReceipt)

	state.mutex.Lock()
	acked := cloneObserverState(state.state)
	acked.LastSequence = item.Sequence
	acked.AckSequence = item.Sequence
	acked.AckEventID = item.EventID
	acked.AckContentSHA256 = item.ContentSHA256
	acked.AckRecordHash = strings.Repeat("a", 64)
	acked.AckPayloadSHA256 = strings.Repeat("b", 64)
	acked.PublicationBaseSequence = item.Sequence
	acked.PublicationBaseHash = strings.Repeat("c", 64)
	acked.PublicationHeadSequence = item.Sequence
	acked.PublicationHeadHash = strings.Repeat("c", 64)
	acked.ControlReceiptCount = anchor.Count
	acked.ControlReceiptBytes = anchor.Bytes
	acked.ControlReceiptHeadHash = anchor.HeadHash
	err = state.replaceLocked(acked)
	state.mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Snapshot().Validate(); err != nil {
		t.Fatalf("forged-signature test state is invalid: %v", err)
	}
	path := controlReceiptJournalPath(root)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := recoverControlReceiptJournal(
		root,
		state,
		map[uint64]SpoolItem{},
		keys,
		4*1024*1024,
	)
	if recovered != nil {
		_ = recovered.Close()
		t.Fatal("forged ACK-retained receipt recovered")
	}
	if !errors.Is(err, ErrControlReceiptCorrupt) {
		t.Fatalf("forged ACK-retained receipt error=%v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) ||
		controlReceiptAnchorFromState(state.Snapshot()) != anchor {
		t.Fatalf(
			"forged receipt rejection changed durable state: bytes_equal=%t anchor=%+v",
			bytes.Equal(after, before),
			controlReceiptAnchorFromState(state.Snapshot()),
		)
	}
}

func TestControlReceiptInvalidIncompleteTailIsNeverTruncated(t *testing.T) {
	tests := []struct {
		name        string
		stateAnchor func(*testing.T, string) ControlReceiptAnchor
		candidate   func(*testing.T) (string, CoreEventV1)
	}{
		{
			name: "completion without authorization",
			stateAnchor: func(*testing.T, string) ControlReceiptAnchor {
				return EmptyControlReceiptAnchor()
			},
			candidate: func(t *testing.T) (string, CoreEventV1) {
				return "evidence_repair_completed:" +
						controlReceiptTestOperationID,
					controlReceiptTestItem(
						t,
						10,
						"evidence_repair_completed",
						"repair_id",
						controlReceiptTestOperationID,
					)
			},
		},
		{
			name: "reordered sequence",
			stateAnchor: func(
				t *testing.T,
				root string,
			) ControlReceiptAnchor {
				prefix := controlReceiptTestValue(
					t,
					"retention_tombstone:"+
						controlReceiptTestOperationID,
					controlReceiptTestItem(
						t,
						10,
						"retention_tombstone",
						"tombstone_id",
						controlReceiptTestOperationID,
					),
				)
				canonical, err := contracts.CanonicalJSON(prefix)
				if err != nil {
					t.Fatal(err)
				}
				return appendControlReceiptFixture(
					t,
					root,
					canonical,
				)
			},
			candidate: func(t *testing.T) (string, CoreEventV1) {
				operationID :=
					"123e4567-e89b-42d3-a456-426614174099"
				return "retention_blocked_priority_evidence:" +
						operationID,
					controlReceiptTestItem(
						t,
						9,
						"retention_blocked_priority_evidence",
						"blocked_id",
						operationID,
					)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			createControlReceiptDirectory(t, root)
			anchor := test.stateAnchor(t, root)
			key, item := test.candidate(t)
			receipt := controlReceiptTestValue(t, key, item)
			canonical, err := contracts.CanonicalJSON(receipt)
			if err != nil {
				t.Fatal(err)
			}
			previous, err := anchorHashBytes(anchor)
			if err != nil {
				t.Fatal(err)
			}
			frame, _, err := durablefile.EncodeFrame(
				canonical,
				previous,
				controlReceiptMaxFramePayload,
			)
			if err != nil {
				t.Fatal(err)
			}
			path := controlReceiptJournalPath(root)
			prefix, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			torn := append(
				append([]byte(nil), prefix...),
				frame[:len(frame)-9]...,
			)
			if err := os.WriteFile(path, torn, 0o600); err != nil {
				t.Fatal(err)
			}
			before := append([]byte(nil), torn...)
			commitCalled := false
			if _, err := ReconcileControlReceiptJournal(
				root,
				anchor,
				sealedControlReceiptTestProof(key, item),
				func(ControlReceiptAnchor, ControlReceiptAnchor) error {
					commitCalled = true
					return nil
				},
			); !errors.Is(err, ErrControlReceiptCorrupt) {
				t.Fatalf("invalid torn-tail error=%v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if commitCalled || !bytes.Equal(after, before) {
				t.Fatalf(
					"invalid torn tail mutated: commit=%t bytes_equal=%t",
					commitCalled,
					bytes.Equal(after, before),
				)
			}
		})
	}
}

func TestControlReceiptForgedPrefixNeverAdvancesTailRecovery(t *testing.T) {
	for _, completeTail := range []bool{false, true} {
		name := "incomplete tail"
		if completeTail {
			name = "complete tail"
		}
		t.Run(name, func(t *testing.T) {
			service, state, spool, _, _ := observerServiceFixture(t)
			authorization := coreControlAuthorizeFixture()
			authorized, err := service.PublishCoreControl(
				context.Background(),
				authorization,
			)
			if err != nil {
				t.Fatal(err)
			}
			tombstone := coreControlTombstoneFixture()
			publishedTail, err := service.PublishCoreControl(
				context.Background(),
				tombstone,
			)
			if err != nil {
				t.Fatal(err)
			}
			prefixReceipt, found, err := spool.FindControl(
				authorization.OperationKey(),
			)
			if err != nil || !found {
				t.Fatalf("authorization receipt found=%t err=%v", found, err)
			}
			tailReceipt, found, err := spool.FindControl(
				tombstone.OperationKey(),
			)
			if err != nil || !found {
				t.Fatalf("tail receipt found=%t err=%v", found, err)
			}
			if err := spool.Ack(
				authorized.Item.Sequence,
				authorized.Item.EventID,
				authorized.Item.ContentSHA256,
			); err != nil {
				t.Fatal(err)
			}
			items, err := spool.Fetch(0, 100, 4*1024*1024)
			if err != nil {
				t.Fatal(err)
			}
			liveItems := make(map[uint64]SpoolItem, 1)
			for _, item := range items {
				if item.Sequence == publishedTail.Item.Sequence {
					liveItems[item.Sequence] = item
				}
			}
			if len(liveItems) != 1 {
				t.Fatalf("missing live tail item: %+v", items)
			}
			stateDir := spool.config.StateDir
			keys := spool.keys
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}

			prefixReceipt.Item.Envelope.SourceSignature = strings.Repeat(
				"0",
				ed25519.SignatureSize*2,
			)
			prefixEnvelope, err := contracts.CanonicalJSON(
				prefixReceipt.Item.Envelope,
			)
			if err != nil {
				t.Fatal(err)
			}
			prefixHash := sha256.Sum256(prefixEnvelope)
			prefixReceipt.Item.ContentSHA256 = hex.EncodeToString(
				prefixHash[:],
			)
			if err := prefixReceipt.Validate(); err != nil {
				t.Fatalf("forged prefix is not structurally valid: %v", err)
			}
			if err := keys.Verify(prefixReceipt.Item.Envelope); err == nil {
				t.Fatal("forged prefix signature unexpectedly verifies")
			}
			prefixCanonical, err := contracts.CanonicalJSON(prefixReceipt)
			if err != nil {
				t.Fatal(err)
			}
			tailCanonical, err := contracts.CanonicalJSON(tailReceipt)
			if err != nil {
				t.Fatal(err)
			}
			prefixFrame, prefixMeta, err := durablefile.EncodeFrame(
				prefixCanonical,
				[sha256.Size]byte{},
				controlReceiptMaxFramePayload,
			)
			if err != nil {
				t.Fatal(err)
			}
			prefixAnchor, err := advanceControlReceiptAnchor(
				EmptyControlReceiptAnchor(),
				prefixMeta,
			)
			if err != nil {
				t.Fatal(err)
			}
			tailFrame, _, err := durablefile.EncodeFrame(
				tailCanonical,
				prefixMeta.Hash,
				controlReceiptMaxFramePayload,
			)
			if err != nil {
				t.Fatal(err)
			}
			if !completeTail {
				tailFrame = tailFrame[:len(tailFrame)-9]
			}
			journalBytes := append(
				append([]byte(nil), prefixFrame...),
				tailFrame...,
			)
			path := controlReceiptJournalPath(stateDir)
			if err := os.WriteFile(path, journalBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			state.mutex.Lock()
			behind := cloneObserverState(state.state)
			behind.ControlReceiptCount = prefixAnchor.Count
			behind.ControlReceiptBytes = prefixAnchor.Bytes
			behind.ControlReceiptHeadHash = prefixAnchor.HeadHash
			err = state.replaceLocked(behind)
			state.mutex.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			beforeState := state.Snapshot()
			beforeBytes := append([]byte(nil), journalBytes...)

			recovered, err := recoverControlReceiptJournal(
				stateDir,
				state,
				liveItems,
				keys,
				4*1024*1024,
			)
			if recovered != nil {
				_ = recovered.Close()
				t.Fatal("forged prefix tail recovery succeeded")
			}
			if !errors.Is(err, ErrControlReceiptCorrupt) {
				t.Fatalf("forged prefix recovery error=%v", err)
			}
			afterBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			afterState := state.Snapshot()
			if !bytes.Equal(afterBytes, beforeBytes) ||
				controlReceiptAnchorFromState(afterState) !=
					controlReceiptAnchorFromState(beforeState) {
				t.Fatalf(
					"forged prefix recovery mutated bytes/state: bytes_equal=%t before=%+v after=%+v",
					bytes.Equal(afterBytes, beforeBytes),
					controlReceiptAnchorFromState(beforeState),
					controlReceiptAnchorFromState(afterState),
				)
			}
		})
	}
}

func TestControlReceiptPreflightQuotaIsBeforeSequenceReservation(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Spool)
		wantErr error
	}{
		{
			name: "global quota",
			prepare: func(spool *Spool) {
				spool.config.MaxBytes =
					spool.totalBytes + ackJournalMaxFrameBytes
			},
			wantErr: ErrPriorityQuota,
		},
		{
			name: "receipt record quota",
			prepare: func(spool *Spool) {
				spool.controlReceipts.mutex.Lock()
				defer spool.controlReceipts.mutex.Unlock()
				spool.controlReceipts.anchor = ControlReceiptAnchor{
					Count:    controlReceiptMaxCount,
					Bytes:    1,
					HeadHash: strings.Repeat("a", 64),
				}
			},
			wantErr: ErrControlReceiptQuota,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 42)
			state, spool, _ := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			request := coreControlAuthorizeFixture()
			requestSHA256, err := CoreControlRequestSHA256(request)
			if err != nil {
				t.Fatal(err)
			}
			beforeState := state.Snapshot()
			event := signedControlPreflightFixture(
				t,
				beforeState,
				privateKey,
				request,
			)
			test.prepare(spool)
			beforeAnchor := spool.controlReceipts.Anchor()
			beforeReceiptJournal, err := os.ReadFile(
				controlReceiptJournalPath(root),
			)
			if err != nil {
				t.Fatal(err)
			}
			beforeTotalBytes := spool.totalBytes
			beforeItems := len(spool.items)

			err = spool.PreflightControl(
				event,
				controlReceiptAppend{
					key:           request.OperationKey(),
					requestSHA256: requestSHA256,
				},
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("preflight error=%v, want %v", err, test.wantErr)
			}

			afterState := state.Snapshot()
			if afterState.LastSequence != beforeState.LastSequence ||
				afterState.ControlReceiptCount !=
					beforeState.ControlReceiptCount ||
				afterState.ControlReceiptBytes !=
					beforeState.ControlReceiptBytes ||
				afterState.ControlReceiptHeadHash !=
					beforeState.ControlReceiptHeadHash {
				t.Fatalf(
					"quota preflight changed reserved/receipt state: before=%+v after=%+v",
					beforeState,
					afterState,
				)
			}
			if spool.controlReceipts.Anchor() != beforeAnchor {
				t.Fatalf(
					"quota preflight changed receipt anchor: before=%+v after=%+v",
					beforeAnchor,
					spool.controlReceipts.Anchor(),
				)
			}
			afterReceiptJournal, err := os.ReadFile(
				controlReceiptJournalPath(root),
			)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(afterReceiptJournal, beforeReceiptJournal) {
				t.Fatal("quota preflight changed receipt journal bytes")
			}
			if spool.totalBytes != beforeTotalBytes ||
				len(spool.items) != beforeItems {
				t.Fatalf(
					"quota preflight changed spool: bytes %d->%d items %d->%d",
					beforeTotalBytes,
					spool.totalBytes,
					beforeItems,
					len(spool.items),
				)
			}
		})
	}
}
