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
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

func pccReceiptPointer[T any](value T) *T {
	return &value
}

func pccReceiptTrigger(item SpoolItem) contracts.PCCFalcoTriggerProjectionV1 {
	return contracts.PCCFalcoTriggerProjectionV1{
		SchemaVersion:          "agmind.pcc-falco-trigger-projection.v1",
		EventID:                item.EventID,
		ContentSHA256:          item.ContentSHA256,
		NormalizedFieldsSHA256: strings.Repeat("c", 64),
		SourceSequence:         item.Sequence,
		SourceID:               "agmind-observerd",
		SourceVersion:          "0.1.0",
		HostID:                 testHostID,
		BootID:                 testBootID,
		EventTime:              "2026-07-27T11:59:59Z",
		IngestTime:             "2026-07-27T12:00:00Z",
		ClockUncertaintyMS:     100,
		InventoryGeneration:    7,
		InventoryRevision:      3,
		ContainerID:            strings.Repeat("d", 64),
		ContainerStartTime:     "2026-07-27T11:59:00Z",
		ReleaseID:              "rel_2c9c95784f8c31c4eb4c3f75a770277e",
		DetectorRule:           "AGmind PCC Suspicious Process Outbound Connect",
		DetectorRuleVersion:    "agmind-pcc-rules-v1",
		FalcoVersion:           "0.44.1",
		EvtRawres:              pccReceiptPointer(int64(0)),
		EvtRes:                 "SUCCESS",
		SuccessfulConnect:      true,
		InvestigationOnly:      false,
		ImageID:                "sha256:" + strings.Repeat("e", 64),
		RepoDigests:            []string{},
		ImmutableSpecSHA256:    strings.Repeat("f", 64),
		ProcName:               pccReceiptPointer("curl"),
		ProcExePath:            pccReceiptPointer("/usr/bin/curl"),
		ProcParentName:         pccReceiptPointer("sh"),
		DestinationIPv4:        "1.1.1.1",
		DestinationPort:        443,
		L4Protocol:             "tcp",
		MissingRequiredFields:  []string{},
		CoverageFlags:          []string{},
		RawEventSHA256:         strings.Repeat("1", 64),
	}
}

func pccReceiptFields(
	t *testing.T,
	trigger SpoolItem,
) (map[string]any, string) {
	t.Helper()
	reasons := []string{"inventory_stale"}
	snapshot := contracts.PCCCorrelationSnapshotV1{
		SchemaVersion:           "agmind.pcc-correlation-snapshot.v1",
		Outcome:                 "failed",
		Trigger:                 pccReceiptTrigger(trigger),
		DecisionTime:            "2026-07-27T12:00:00Z",
		RequestedTTLSeconds:     120,
		FailureReasons:          &reasons,
		CoverageThroughSequence: trigger.Sequence,
		HardLimitsVersion:       "pcc-hard-limits-v1",
	}
	request := contracts.PCCCorrelationSnapshotRequestV1{
		SchemaVersion:         "agmind.pcc-correlation-snapshot-request.v1",
		TriggerEventID:        snapshot.Trigger.EventID,
		TriggerContentSHA256:  snapshot.Trigger.ContentSHA256,
		TriggerSourceSequence: snapshot.Trigger.SourceSequence,
		RequestedTTLSeconds:   snapshot.RequestedTTLSeconds,
	}
	requestSHA256, err := contracts.PCCCorrelationRequestSHA256(request)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.RequestSHA256 = requestSHA256
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := contracts.CanonicalJSON(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var fields map[string]any
	if err := decoder.Decode(&fields); err != nil {
		t.Fatal(err)
	}
	return fields, requestSHA256
}

func pccReceiptSnapshotFixture(
	t *testing.T,
	spool *Spool,
	signer *EnvelopeSigner,
	label string,
) (SpoolItem, PCCPublicationReceipt) {
	t.Helper()
	trigger, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "pcc-receipt-trigger-" + label},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	triggerItem := spool.items[trigger.SourceSequence]
	fields, requestSHA256 := pccReceiptFields(t, triggerItem)
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
	state := spool.state
	state.publicationMutex.Lock()
	defer state.publicationMutex.Unlock()
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
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
	eventCanonical, err := contracts.CanonicalJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	contentDigest := sha256.Sum256(eventCanonical)
	receipt := PCCPublicationReceipt{
		OperationKey: "pcc_correlation_snapshot:" +
			triggerItem.EventID,
		RequestSHA256:            requestSHA256,
		SnapshotNormalizedSHA256: event.NormalizedFieldsSHA256,
		SnapshotEventID:          event.EventID,
		SnapshotContentSHA256:    hex.EncodeToString(contentDigest[:]),
	}
	identity := StateIdentity{
		HostID: stateSnapshot.HostID, BootID: stateSnapshot.BootID,
		KeyID: stateSnapshot.KeyID, KeyEpoch: stateSnapshot.KeyEpoch,
	}
	if _, err := state.reserveExpected(identity, sequence); err != nil {
		t.Fatal(err)
	}
	item, err := spool.appendLocked(event, PriorityTier, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return item, receipt
}

func pccReceiptKeys(
	t *testing.T,
	privateKey ed25519.PrivateKey,
) *Keyring {
	t.Helper()
	return pccArchiveKeyring(t, privateKey)
}

func pccReceiptReopenSpool(
	t *testing.T,
	root string,
	state *StateStore,
	privateKey ed25519.PrivateKey,
) *Spool {
	t.Helper()
	spool, err := NewSpool(
		SpoolConfig{
			StateDir:             root,
			MaxBytes:             4 * 1024 * 1024,
			PriorityReserveBytes: 1024 * 1024,
		},
		state,
		pccReceiptKeys(t, privateKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	return spool
}

func TestPCCReceiptHasExactNestedFiveFieldSchema(t *testing.T) {
	record := PCCPublicationReceiptRecord{
		SchemaVersion: pccReceiptRecordSchema,
		Receipt: PCCPublicationReceipt{
			OperationKey:             "pcc_correlation_snapshot:evt_" + strings.Repeat("a", 64),
			RequestSHA256:            strings.Repeat("b", 64),
			SnapshotNormalizedSHA256: strings.Repeat("c", 64),
			SnapshotEventID:          "evt_" + strings.Repeat("d", 64),
			SnapshotContentSHA256:    strings.Repeat("e", 64),
		},
	}
	raw, err := contracts.CanonicalJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatal(err)
	}
	if got := sortedJSONKeys(outer); !reflect.DeepEqual(
		got,
		[]string{"receipt", "schema_version"},
	) {
		t.Fatalf("outer keys=%q", got)
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(outer["receipt"], &nested); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"operation_key",
		"request_sha256",
		"snapshot_content_sha256",
		"snapshot_event_id",
		"snapshot_normalized_sha256",
	}
	if got := sortedJSONKeys(nested); !reflect.DeepEqual(got, want) {
		t.Fatalf("receipt keys=%q want=%q raw=%s", got, want, raw)
	}
	if bytes.Contains(raw, []byte(`"sequence"`)) {
		t.Fatalf("receipt schema contains a sequence: %s", raw)
	}
}

func sortedJSONKeys(fields map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func pccReceiptSyntheticRecord(fill string) PCCPublicationReceiptRecord {
	return PCCPublicationReceiptRecord{
		SchemaVersion: pccReceiptRecordSchema,
		Receipt: PCCPublicationReceipt{
			OperationKey: "pcc_correlation_snapshot:evt_" +
				strings.Repeat(fill, 64),
			RequestSHA256:            strings.Repeat(fill, 64),
			SnapshotNormalizedSHA256: strings.Repeat(fill, 64),
			SnapshotEventID:          "evt_" + strings.Repeat(fill, 64),
			SnapshotContentSHA256:    strings.Repeat(fill, 64),
		},
	}
}

func TestPCCReceiptExactRetryConflictQuotaAndRestart(t *testing.T) {
	t.Run("retry conflict and restart", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 234)
		state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
		_, receipt := pccReceiptSnapshotFixture(t, spool, signer, "retry")
		if err := spool.pccReceipts.Append(receipt); err != nil {
			t.Fatal(err)
		}
		before := state.Snapshot()
		if err := spool.pccReceipts.Append(receipt); err != nil {
			t.Fatalf("exact retry error=%v", err)
		}
		if got := state.Snapshot(); got.PCCReceiptCount != before.PCCReceiptCount ||
			got.PCCReceiptBytes != before.PCCReceiptBytes ||
			got.PCCReceiptHeadHash != before.PCCReceiptHeadHash {
			t.Fatalf("exact retry appended a second receipt: before=%+v after=%+v", before, got)
		}
		actualTotal := spool.totalBytes
		spool.totalBytes = spool.config.MaxBytes
		if err := spool.pccReceipts.Append(receipt); err != nil {
			t.Fatalf("exact retry was blocked by exhausted append capacity: %v", err)
		}
		spool.totalBytes = actualTotal
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		spool = pccReceiptReopenSpool(t, root, state, privateKey)
		got, found, err := spool.pccReceipts.Lookup(
			receipt.OperationKey,
			receipt.RequestSHA256,
		)
		if err != nil || !found || got != receipt {
			t.Fatalf("restart lookup found=%t receipt=%+v err=%v", found, got, err)
		}
		conflict := receipt
		conflict.RequestSHA256 = strings.Repeat("9", 64)
		conflict.SnapshotEventID = "evt_" + strings.Repeat("9", 64)
		if err := spool.pccReceipts.Append(conflict); !errors.Is(
			err,
			ErrPCCReceiptConflict,
		) {
			t.Fatalf("conflict error=%v", err)
		}
		if snapshot := state.Snapshot(); !snapshot.MutationReadOnly ||
			snapshot.ReadOnlyReason != "observer_pcc_request_conflict" {
			t.Fatalf("conflict did not persist exact fence: %+v", snapshot)
		}
	})

	t.Run("quota", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 235)
		state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
		_, receipt := pccReceiptSnapshotFixture(t, spool, signer, "quota")
		exhausted := PCCReceiptAnchor{
			Count:    pccReceiptMaxCount,
			Bytes:    1,
			HeadHash: strings.Repeat("a", 64),
		}
		spool.pccReceipts.mutex.Lock()
		spool.pccReceipts.anchor = exhausted
		spool.pccReceipts.mutex.Unlock()
		state.mutex.Lock()
		state.state.PCCReceiptCount = exhausted.Count
		state.state.PCCReceiptBytes = exhausted.Bytes
		state.state.PCCReceiptHeadHash = exhausted.HeadHash
		state.mutex.Unlock()
		if err := spool.pccReceipts.Append(receipt); !errors.Is(
			err,
			ErrPCCReceiptQuota,
		) {
			t.Fatalf("quota error=%v", err)
		}
	})
}

func TestPCCReceiptPreservesAckJournalReserve(t *testing.T) {
	for name, short := range map[string]uint64{
		"exact reserve":  0,
		"one byte short": 1,
	} {
		t.Run("append/"+name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 248)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			_, receipt := pccReceiptSnapshotFixture(
				t,
				spool,
				signer,
				"append-reserve-"+name,
			)
			spool.pccReceipts.mutex.Lock()
			_, meta, _, err := spool.pccReceipts.previewAppendLocked(receipt)
			spool.pccReceipts.mutex.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			spool.config.MaxBytes = spool.totalBytes + meta.Size +
				ackJournalMaxFrameBytes - short
			err = spool.pccReceipts.Append(receipt)
			if short == 0 {
				if err != nil {
					t.Fatalf("exact ACK reserve append error=%v", err)
				}
				return
			}
			if !errors.Is(err, ErrPCCReceiptQuota) {
				t.Fatalf("short ACK reserve append error=%v", err)
			}
			if snapshot := state.Snapshot(); !snapshot.MutationReadOnly ||
				snapshot.ReadOnlyReason !=
					"observer_pcc_receipt_quota_exhausted" {
				t.Fatalf("short ACK reserve append did not fence: %+v", snapshot)
			}
		})

		t.Run("startup/"+name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 247)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			_, receipt := pccReceiptSnapshotFixture(
				t,
				spool,
				signer,
				"startup-reserve-"+name,
			)
			if err := spool.pccReceipts.Append(receipt); err != nil {
				t.Fatal(err)
			}
			used := spool.totalBytes
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err := NewSpool(
				SpoolConfig{
					StateDir: root,
					MaxBytes: used + ackJournalMaxFrameBytes -
						short,
					PriorityReserveBytes: 1024,
				},
				state,
				pccReceiptKeys(t, privateKey),
			)
			if short == 0 {
				if err != nil {
					t.Fatalf("exact ACK reserve startup error=%v", err)
				}
				if closeErr := opened.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
				return
			}
			if opened != nil {
				_ = opened.Close()
			}
			if !errors.Is(err, ErrSpoolCorrupt) {
				t.Fatalf("short ACK reserve startup error=%v", err)
			}
			if snapshot := state.Snapshot(); !snapshot.MutationReadOnly ||
				snapshot.ReadOnlyReason != "observer_spool_quota_invalid" {
				t.Fatalf("short ACK reserve startup did not fence: %+v", snapshot)
			}
		})
	}
}

func TestPCCReceiptRebindsIndependentRequestAndNormalizedHashes(t *testing.T) {
	for name, mutate := range map[string]func(*PCCPublicationReceipt){
		"request": func(receipt *PCCPublicationReceipt) {
			receipt.RequestSHA256 = strings.Repeat("8", 64)
		},
		"normalized": func(receipt *PCCPublicationReceipt) {
			receipt.SnapshotNormalizedSHA256 = strings.Repeat("7", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 236)
			state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
			_, receipt := pccReceiptSnapshotFixture(t, spool, signer, name)
			mutate(&receipt)
			before := state.Snapshot()
			if err := spool.pccReceipts.Append(receipt); !errors.Is(
				err,
				ErrPCCReceiptCorrupt,
			) {
				t.Fatalf("%s mismatch error=%v", name, err)
			}
			after := state.Snapshot()
			if after.PCCReceiptCount != before.PCCReceiptCount ||
				after.PCCReceiptBytes != before.PCCReceiptBytes ||
				after.PCCReceiptHeadHash != before.PCCReceiptHeadHash {
				t.Fatalf("%s mismatch mutated receipt anchor", name)
			}
		})
	}

	t.Run("lookup disk identity", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 254)
		state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
		item, receipt := pccReceiptSnapshotFixture(t, spool, signer, "lookup-disk")
		if err := spool.pccReceipts.Append(receipt); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(item.publicationPath, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, found, err := spool.pccReceipts.Lookup(
			receipt.OperationKey,
			receipt.RequestSHA256,
		); err == nil || found {
			t.Fatalf("changed publication lookup found=%t err=%v", found, err)
		}
		if snapshot := state.Snapshot(); !snapshot.MutationReadOnly ||
			snapshot.ReadOnlyReason != "observer_pcc_receipt_binding_invalid" {
			t.Fatalf("changed publication lookup did not fence: %+v", snapshot)
		}
	})
}

func TestPCCReceiptLookupRejectsReadOnlyBeforeLiveBinding(t *testing.T) {
	for _, hidden := range []string{"frame", "publication"} {
		t.Run(hidden, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 255)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			item, receipt := pccReceiptSnapshotFixture(
				t,
				spool,
				signer,
				"fenced-receipt-"+hidden,
			)
			if err := spool.pccReceipts.Append(receipt); err != nil {
				t.Fatal(err)
			}
			const reason = "test_pcc_receipt_lookup_read_only"
			if err := state.PersistReadOnly(reason); err != nil {
				t.Fatal(err)
			}
			path := item.path
			if hidden == "publication" {
				path = item.publicationPath
			}
			hiddenPath := path + ".hidden"
			if err := os.Rename(path, hiddenPath); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Rename(hiddenPath, path) })

			if _, found, err := spool.pccReceipts.Lookup(
				receipt.OperationKey,
				receipt.RequestSHA256,
			); !errors.Is(err, ErrPCCReceiptCorrupt) || found {
				t.Fatalf("fenced receipt lookup found=%t err=%v", found, err)
			}
			if snapshot := state.Snapshot(); snapshot.ReadOnlyReason != reason {
				t.Fatalf("fenced receipt lookup touched live binding: %+v", snapshot)
			}
		})
	}

	t.Run("conflict metadata precedes fence", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 251)
		state, spool, signer := openSignerFixture(
			t,
			root,
			testBootID,
			privateKey,
		)
		_, receipt := pccReceiptSnapshotFixture(
			t,
			spool,
			signer,
			"fenced-conflict",
		)
		if err := spool.pccReceipts.Append(receipt); err != nil {
			t.Fatal(err)
		}
		if err := state.PersistReadOnly("test_pcc_lookup_conflict_order"); err != nil {
			t.Fatal(err)
		}
		if _, found, err := spool.pccReceipts.Lookup(
			receipt.OperationKey,
			strings.Repeat("9", 64),
		); !errors.Is(err, ErrPCCReceiptConflict) || found {
			t.Fatalf("fenced conflict lookup found=%t err=%v", found, err)
		}
		if snapshot := state.Snapshot(); snapshot.ReadOnlyReason != "observer_pcc_request_conflict" {
			t.Fatalf("request conflict did not precede fence: %+v", snapshot)
		}
	})
}

func TestPCCReceiptCannotUseGenericControlReceiptJournal(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 237)
	_, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	item, receipt := pccReceiptSnapshotFixture(t, spool, signer, "dedicated")
	coreEvent, err := coreEventFromSpoolItem(item)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := spool.controlReceipts.Store(
		receipt.OperationKey,
		receipt.RequestSHA256,
		coreEvent,
		func(ControlReceiptAnchor, ControlReceiptAnchor) error { return nil },
	); !errors.Is(err, ErrControlReceiptCorrupt) {
		t.Fatalf("generic receipt journal accepted PCC receipt: %v", err)
	}
	if err := spool.pccReceipts.Append(receipt); err != nil {
		t.Fatal(err)
	}
	if controlReceiptJournalPath(root) == pccReceiptJournalPath(root) {
		t.Fatal("PCC receipt reused generic receipt path")
	}
	if _, found, err := spool.controlReceipts.Find(receipt.OperationKey); err != nil || found {
		t.Fatalf("PCC receipt leaked into generic journal found=%t err=%v", found, err)
	}
}

func TestPCCReceiptRecoveryRejectsCorruptionAndUnanchoredTail(t *testing.T) {
	t.Run("wrong schema historical store", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 253)
		state, spool, _ := openSignerFixture(t, root, testBootID, privateKey)
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		pccReceiptInstallRecords(t, root, state, []PCCPublicationReceiptRecord{{
			SchemaVersion: "agmind.pcc-publication-receipt-record.v2",
			Receipt:       pccReceiptSyntheticRecord("f").Receipt,
		}}, 1)
		opened, err := OpenPCCReceiptStore(root, state)
		if opened != nil {
			_ = opened.Close()
		}
		if !errors.Is(err, ErrPCCReceiptCorrupt) {
			t.Fatalf("historical wrong-schema receipt opened: %v", err)
		}
	})

	t.Run("forged live receipt", func(t *testing.T) {
		for name, mutate := range map[string]func(*PCCPublicationReceipt){
			"request": func(receipt *PCCPublicationReceipt) {
				receipt.RequestSHA256 = strings.Repeat("6", 64)
			},
			"event": func(receipt *PCCPublicationReceipt) {
				receipt.SnapshotEventID = "evt_" + strings.Repeat("6", 64)
			},
			"content": func(receipt *PCCPublicationReceipt) {
				receipt.SnapshotContentSHA256 = strings.Repeat("6", 64)
			},
			"normalized": func(receipt *PCCPublicationReceipt) {
				receipt.SnapshotNormalizedSHA256 = strings.Repeat("6", 64)
			},
		} {
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				privateKey := testKey(t, 245)
				state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
				_, receipt := pccReceiptSnapshotFixture(t, spool, signer, name)
				mutate(&receipt)
				if err := spool.Close(); err != nil {
					t.Fatal(err)
				}
				pccReceiptInstallRecords(t, root, state, []PCCPublicationReceiptRecord{{
					SchemaVersion: pccReceiptRecordSchema,
					Receipt:       receipt,
				}}, 1)
				pccReceiptExpectStartupCorrupt(t, root, state, privateKey)
			})
		}
	})

	t.Run("wrong schema and duplicate conflict", func(t *testing.T) {
		for name, records := range map[string][]PCCPublicationReceiptRecord{
			"wrong schema": {{
				SchemaVersion: "agmind.pcc-publication-receipt-record.v2",
				Receipt: PCCPublicationReceipt{
					OperationKey:             "pcc_correlation_snapshot:evt_" + strings.Repeat("a", 64),
					RequestSHA256:            strings.Repeat("b", 64),
					SnapshotNormalizedSHA256: strings.Repeat("c", 64),
					SnapshotEventID:          "evt_" + strings.Repeat("d", 64),
					SnapshotContentSHA256:    strings.Repeat("e", 64),
				},
			}},
			"duplicate": {
				{SchemaVersion: pccReceiptRecordSchema, Receipt: PCCPublicationReceipt{
					OperationKey:             "pcc_correlation_snapshot:evt_" + strings.Repeat("a", 64),
					RequestSHA256:            strings.Repeat("b", 64),
					SnapshotNormalizedSHA256: strings.Repeat("c", 64),
					SnapshotEventID:          "evt_" + strings.Repeat("d", 64),
					SnapshotContentSHA256:    strings.Repeat("e", 64),
				}},
				{SchemaVersion: pccReceiptRecordSchema, Receipt: PCCPublicationReceipt{
					OperationKey:             "pcc_correlation_snapshot:evt_" + strings.Repeat("a", 64),
					RequestSHA256:            strings.Repeat("f", 64),
					SnapshotNormalizedSHA256: strings.Repeat("c", 64),
					SnapshotEventID:          "evt_" + strings.Repeat("d", 64),
					SnapshotContentSHA256:    strings.Repeat("e", 64),
				}},
			},
			"duplicate snapshot event": func() []PCCPublicationReceiptRecord {
				first := pccReceiptSyntheticRecord("a")
				second := pccReceiptSyntheticRecord("b")
				second.Receipt.SnapshotEventID = first.Receipt.SnapshotEventID
				return []PCCPublicationReceiptRecord{first, second}
			}(),
			"duplicate snapshot content": func() []PCCPublicationReceiptRecord {
				first := pccReceiptSyntheticRecord("a")
				second := pccReceiptSyntheticRecord("b")
				second.Receipt.SnapshotContentSHA256 =
					first.Receipt.SnapshotContentSHA256
				return []PCCPublicationReceiptRecord{first, second}
			}(),
		} {
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				privateKey := testKey(t, 238)
				state, spool, _ := openSignerFixture(t, root, testBootID, privateKey)
				if err := spool.Close(); err != nil {
					t.Fatal(err)
				}
				pccReceiptInstallRecords(t, root, state, records, len(records))
				pccReceiptExpectStartupCorrupt(t, root, state, privateKey)
			})
		}
	})

	t.Run("complete and torn unanchored tails remain intact", func(t *testing.T) {
		for _, torn := range []bool{false, true} {
			name := "complete"
			if torn {
				name = "torn"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				privateKey := testKey(t, 239)
				state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
				_, receipt := pccReceiptSnapshotFixture(t, spool, signer, name)
				if err := spool.Close(); err != nil {
					t.Fatal(err)
				}
				record := PCCPublicationReceiptRecord{
					SchemaVersion: pccReceiptRecordSchema,
					Receipt:       receipt,
				}
				pccReceiptInstallRecords(t, root, state, []PCCPublicationReceiptRecord{record}, 0)
				path := pccReceiptJournalPath(root)
				if torn {
					file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := file.Write([]byte("AGF1\x00")); err != nil {
						_ = file.Close()
						t.Fatal(err)
					}
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				pccReceiptExpectStartupCorrupt(t, root, state, privateKey)
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("recovery truncated or adopted an unanchored tail")
				}
			})
		}
	})

	t.Run("anchor quota", func(t *testing.T) {
		for name, mutate := range map[string]func(*ObserverState){
			"count 4097": func(snapshot *ObserverState) {
				snapshot.PCCReceiptCount = 4_097
				snapshot.PCCReceiptBytes = 1
				snapshot.PCCReceiptHeadHash = strings.Repeat("a", 64)
			},
			"bytes 16 MiB plus one": func(snapshot *ObserverState) {
				snapshot.PCCReceiptCount = 1
				snapshot.PCCReceiptBytes = 16*1024*1024 + 1
				snapshot.PCCReceiptHeadHash = strings.Repeat("a", 64)
			},
		} {
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				privateKey := testKey(t, 240)
				state, spool, _ := openSignerFixture(t, root, testBootID, privateKey)
				if err := spool.Close(); err != nil {
					t.Fatal(err)
				}
				state.mutex.Lock()
				mutate(&state.state)
				state.mutex.Unlock()
				pccReceiptExpectStartupCorrupt(t, root, state, privateKey)
			})
		}
	})

	t.Run("interior frame", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 247)
		state, spool, _ := openSignerFixture(t, root, testBootID, privateKey)
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		pccReceiptInstallRecords(
			t,
			root,
			state,
			[]PCCPublicationReceiptRecord{
				pccReceiptSyntheticRecord("a"),
				pccReceiptSyntheticRecord("b"),
			},
			2,
		)
		path := pccReceiptJournalPath(root)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		corrupt := bytes.Clone(before)
		corrupt[20] ^= 0xff
		if err := os.WriteFile(path, corrupt, 0o600); err != nil {
			t.Fatal(err)
		}
		pccReceiptExpectStartupCorrupt(t, root, state, privateKey)
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, corrupt) {
			t.Fatal("interior corruption was truncated or rewritten")
		}
	})

	t.Run("payload 128 KiB plus one", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 248)
		state, spool, _ := openSignerFixture(t, root, testBootID, privateKey)
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		journal, err := durablefile.NewJournal(
			pccReceiptJournalPath(root),
			durablefile.WithMaxFrame(pccReceiptMaxFrame+1),
		)
		if err != nil {
			t.Fatal(err)
		}
		meta, err := journal.Append(
			bytes.Repeat([]byte("x"), int(pccReceiptMaxFrame)+1),
			true,
		)
		if err != nil {
			_ = journal.Close()
			t.Fatal(err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		state.mutex.Lock()
		next := cloneObserverState(state.state)
		next.PCCReceiptCount = 1
		next.PCCReceiptBytes = meta.Size
		next.PCCReceiptHeadHash = hex.EncodeToString(meta.Hash[:])
		if err := state.replaceLocked(next); err != nil {
			state.mutex.Unlock()
			t.Fatal(err)
		}
		state.mutex.Unlock()
		pccReceiptExpectStartupCorrupt(t, root, state, privateKey)
	})
}

func TestPCCReceiptRecoveryPrecedesAckAnchorRecovery(t *testing.T) {
	for name, damage := range map[string]func(*testing.T, string){
		"missing": func(t *testing.T, path string) {
			t.Helper()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
		"invalid": func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 254)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			item, receipt := pccReceiptSnapshotFixture(
				t,
				spool,
				signer,
				"ack-recovery-"+name,
			)
			if err := spool.pccReceipts.Append(receipt); err != nil {
				t.Fatal(err)
			}
			trigger := spool.items[item.Sequence-1]
			if err := spool.Ack(
				trigger.Sequence,
				trigger.EventID,
				trigger.ContentSHA256,
			); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected snapshot ACK anchor failure")
			state.persist = func(path string, next ObserverState) error {
				if next.AckSequence == item.Sequence {
					return injected
				}
				return persistState(path, next)
			}
			if err := spool.Ack(
				item.Sequence,
				item.EventID,
				item.ContentSHA256,
			); !errors.Is(err, injected) {
				t.Fatalf("snapshot ACK error=%v", err)
			}
			state.persist = nil
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			damage(t, pccReceiptJournalPath(root))

			reopenedState, err := OpenStateStore(
				filepath.Join(root, "observer-state.json"),
				stateIdentityForKey(t, privateKey),
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := reopenedState.Snapshot().AckSequence; got != trigger.Sequence {
				t.Fatalf("durable fixture ACK=%d want=%d", got, trigger.Sequence)
			}
			opened, err := NewSpool(
				SpoolConfig{
					StateDir:             root,
					MaxBytes:             4 * 1024 * 1024,
					PriorityReserveBytes: 1024 * 1024,
				},
				reopenedState,
				pccReceiptKeys(t, privateKey),
			)
			if opened != nil {
				_ = opened.Close()
			}
			if err == nil {
				t.Fatal("startup accepted missing or invalid PCC receipt")
			}
			if got := reopenedState.Snapshot().AckSequence; got != trigger.Sequence {
				t.Fatalf(
					"startup applied snapshot ACK before receipt recovery: got=%d want=%d",
					got,
					trigger.Sequence,
				)
			}
		})
	}
}

func pccReceiptInstallRecords(
	t *testing.T,
	root string,
	state *StateStore,
	records []PCCPublicationReceiptRecord,
	anchorCount int,
) {
	t.Helper()
	path := pccReceiptJournalPath(root)
	journal, err := durablefile.NewJournal(
		path,
		durablefile.WithMaxFrame(pccReceiptMaxFrame),
	)
	if err != nil {
		t.Fatal(err)
	}
	var metas []durablefile.RecordMeta
	for _, record := range records {
		canonical, err := contracts.CanonicalJSON(record)
		if err != nil {
			_ = journal.Close()
			t.Fatal(err)
		}
		meta, err := journal.Append(canonical, true)
		if err != nil {
			_ = journal.Close()
			t.Fatal(err)
		}
		metas = append(metas, meta)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	var count, framedBytes uint64
	head := zeroPCCJournalHash
	for index := 0; index < anchorCount; index++ {
		count++
		framedBytes += metas[index].Size
		head = hex.EncodeToString(metas[index].Hash[:])
	}
	state.mutex.Lock()
	next := cloneObserverState(state.state)
	next.PCCReceiptCount = count
	next.PCCReceiptBytes = framedBytes
	next.PCCReceiptHeadHash = head
	if err := state.replaceLocked(next); err != nil {
		state.mutex.Unlock()
		t.Fatal(err)
	}
	state.mutex.Unlock()
}

func pccReceiptExpectStartupCorrupt(
	t *testing.T,
	root string,
	state *StateStore,
	privateKey ed25519.PrivateKey,
) {
	t.Helper()
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
		t.Fatalf("startup error=%v, want PCC receipt corruption", err)
	}
}

func TestPCCReceiptRequiresExactLiveSpoolBinding(t *testing.T) {
	for name, mutate := range map[string]func(*PCCPublicationReceipt){
		"event": func(receipt *PCCPublicationReceipt) {
			receipt.SnapshotEventID = "evt_" + strings.Repeat("6", 64)
		},
		"content": func(receipt *PCCPublicationReceipt) {
			receipt.SnapshotContentSHA256 = strings.Repeat("5", 64)
		},
		"normalized": func(receipt *PCCPublicationReceipt) {
			receipt.SnapshotNormalizedSHA256 = strings.Repeat("4", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 241)
			state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
			_, receipt := pccReceiptSnapshotFixture(t, spool, signer, name)
			mutate(&receipt)
			if err := spool.pccReceipts.Append(receipt); !errors.Is(
				err,
				ErrPCCReceiptCorrupt,
			) {
				t.Fatalf("binding error=%v", err)
			}
			if state.Snapshot().PCCReceiptCount != 0 {
				t.Fatal("invalid live binding was persisted")
			}
		})
	}

	t.Run("receipt without spool event", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 242)
		state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
		item, receipt := pccReceiptSnapshotFixture(t, spool, signer, "orphan")
		if err := os.Remove(item.path); err != nil {
			t.Fatal(err)
		}
		if err := spool.pccReceipts.Append(receipt); !errors.Is(
			err,
			ErrPCCReceiptCorrupt,
		) {
			t.Fatalf("orphan append error=%v", err)
		}
		if state.Snapshot().PCCReceiptCount != 0 {
			t.Fatal("receipt without a live spool event was persisted")
		}
	})

	t.Run("startup snapshot without receipt", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 246)
		state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
		_, _ = pccReceiptSnapshotFixture(t, spool, signer, "startup-missing")
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		pccReceiptExpectStartupCorrupt(t, root, state, privateKey)
	})
}

func TestPCCReceiptNewAppendFailureHardFencesAndRetainsEvidence(t *testing.T) {
	type failureCase struct {
		wantErr    error
		wantReason string
		prepare    func(*StateStore, *Spool, *PCCPublicationReceipt)
	}
	for name, testCase := range map[string]failureCase{
		"validation": {
			wantErr:    ErrPCCReceiptCorrupt,
			wantReason: "observer_pcc_receipt_append_invalid",
			prepare: func(_ *StateStore, _ *Spool, receipt *PCCPublicationReceipt) {
				receipt.SnapshotNormalizedSHA256 = strings.Repeat("7", 64)
			},
		},
		"receipt quota": {
			wantErr:    ErrPCCReceiptQuota,
			wantReason: "observer_pcc_receipt_quota_exhausted",
			prepare: func(state *StateStore, spool *Spool, _ *PCCPublicationReceipt) {
				exhausted := PCCReceiptAnchor{
					Count:    pccReceiptMaxCount,
					Bytes:    1,
					HeadHash: strings.Repeat("a", 64),
				}
				spool.pccReceipts.mutex.Lock()
				spool.pccReceipts.anchor = exhausted
				spool.pccReceipts.mutex.Unlock()
				state.mutex.Lock()
				state.state.PCCReceiptCount = exhausted.Count
				state.state.PCCReceiptBytes = exhausted.Bytes
				state.state.PCCReceiptHeadHash = exhausted.HeadHash
				state.mutex.Unlock()
			},
		},
		"global capacity": {
			wantErr:    ErrPCCReceiptQuota,
			wantReason: "observer_pcc_receipt_quota_exhausted",
			prepare: func(_ *StateStore, spool *Spool, _ *PCCPublicationReceipt) {
				spool.config.MaxBytes = spool.totalBytes
			},
		},
		"preanchor": {
			wantErr:    ErrPCCReceiptCorrupt,
			wantReason: "observer_pcc_receipt_preanchor_invalid",
			prepare: func(_ *StateStore, spool *Spool, _ *PCCPublicationReceipt) {
				spool.pccReceipts.mutex.Lock()
				spool.pccReceipts.anchor = PCCReceiptAnchor{
					Count:    1,
					Bytes:    1,
					HeadHash: strings.Repeat("b", 64),
				}
				spool.pccReceipts.mutex.Unlock()
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 249)
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				privateKey,
			)
			item, receipt := pccReceiptSnapshotFixture(
				t,
				spool,
				signer,
				"append-failure-"+name,
			)
			frameBefore, err := os.ReadFile(item.path)
			if err != nil {
				t.Fatal(err)
			}
			publicationBefore, err := os.ReadFile(item.publicationPath)
			if err != nil {
				t.Fatal(err)
			}
			testCase.prepare(state, spool, &receipt)
			if err := spool.pccReceipts.Append(receipt); !errors.Is(
				err,
				testCase.wantErr,
			) {
				t.Fatalf("append failure error=%v", err)
			}
			if snapshot := state.Snapshot(); !snapshot.MutationReadOnly ||
				snapshot.ReadOnlyReason != testCase.wantReason {
				t.Fatalf("append failure did not hard-fence: %+v", snapshot)
			}
			persisted, err := OpenStateStore(
				state.path,
				stateIdentityForKey(t, privateKey),
			)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot := persisted.Snapshot(); !snapshot.MutationReadOnly ||
				snapshot.ReadOnlyReason != testCase.wantReason {
				t.Fatalf("append fence was not durable: %+v", snapshot)
			}
			frameAfter, err := os.ReadFile(item.path)
			if err != nil {
				t.Fatal(err)
			}
			publicationAfter, err := os.ReadFile(item.publicationPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(frameBefore, frameAfter) ||
				!bytes.Equal(publicationBefore, publicationAfter) {
				t.Fatal("append failure changed live PCC evidence")
			}
		})
	}
}

func TestPCCSnapshotAckRequiresValidSpecializedReceipt(t *testing.T) {
	for name, install := range map[string]func(*testing.T, *Spool, PCCPublicationReceipt){
		"missing": func(_ *testing.T, _ *Spool, _ PCCPublicationReceipt) {},
		"changed normalized": func(t *testing.T, spool *Spool, receipt PCCPublicationReceipt) {
			t.Helper()
			if err := spool.pccReceipts.Append(receipt); err != nil {
				t.Fatal(err)
			}
			spool.pccReceipts.mutex.Lock()
			stored := spool.pccReceipts.receipts[receipt.OperationKey]
			stored.SnapshotNormalizedSHA256 = strings.Repeat("3", 64)
			spool.pccReceipts.receipts[receipt.OperationKey] = stored
			spool.pccReceipts.mutex.Unlock()
		},
		"changed event": func(t *testing.T, spool *Spool, receipt PCCPublicationReceipt) {
			t.Helper()
			if err := spool.pccReceipts.Append(receipt); err != nil {
				t.Fatal(err)
			}
			spool.pccReceipts.mutex.Lock()
			stored := spool.pccReceipts.receipts[receipt.OperationKey]
			stored.SnapshotEventID = "evt_" + strings.Repeat("3", 64)
			spool.pccReceipts.receipts[receipt.OperationKey] = stored
			spool.pccReceipts.mutex.Unlock()
		},
		"changed content": func(t *testing.T, spool *Spool, receipt PCCPublicationReceipt) {
			t.Helper()
			if err := spool.pccReceipts.Append(receipt); err != nil {
				t.Fatal(err)
			}
			spool.pccReceipts.mutex.Lock()
			stored := spool.pccReceipts.receipts[receipt.OperationKey]
			stored.SnapshotContentSHA256 = strings.Repeat("3", 64)
			spool.pccReceipts.receipts[receipt.OperationKey] = stored
			spool.pccReceipts.mutex.Unlock()
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 243)
			state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
			item, receipt := pccReceiptSnapshotFixture(t, spool, signer, name)
			install(t, spool, receipt)
			trigger := spool.items[item.Sequence-1]
			if err := spool.Ack(
				trigger.Sequence,
				trigger.EventID,
				trigger.ContentSHA256,
			); err != nil {
				t.Fatal(err)
			}
			ackPath := filepath.Join(root, "spool", "acked.agf")
			before, err := os.ReadFile(ackPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := spool.Ack(
				item.Sequence,
				item.EventID,
				item.ContentSHA256,
			); !errors.Is(err, ErrPCCReceiptCorrupt) {
				t.Fatalf("ACK error=%v", err)
			}
			after, err := os.ReadFile(ackPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) ||
				state.Snapshot().AckSequence >= item.Sequence {
				t.Fatal("invalid PCC receipt reached ACK journal or state")
			}
			if _, err := os.Stat(item.path); err != nil {
				t.Fatalf("invalid receipt deleted snapshot frame: %v", err)
			}
			if _, err := os.Stat(item.publicationPath); err != nil {
				t.Fatalf("invalid receipt deleted publication: %v", err)
			}
		})
	}

	t.Run("valid receipt remains anchored historical audit", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 249)
		state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
		item, receipt := pccReceiptSnapshotFixture(t, spool, signer, "valid-ack")
		if err := spool.pccReceipts.Append(receipt); err != nil {
			t.Fatal(err)
		}
		trigger := spool.items[item.Sequence-1]
		if err := spool.Ack(
			trigger.Sequence,
			trigger.EventID,
			trigger.ContentSHA256,
		); err != nil {
			t.Fatal(err)
		}
		if err := spool.Ack(item.Sequence, item.EventID, item.ContentSHA256); err != nil {
			t.Fatal(err)
		}
		anchored := state.Snapshot()
		if anchored.PCCReceiptCount != 1 || anchored.PCCReceiptBytes == 0 {
			t.Fatalf("valid ACK removed receipt anchor: %+v", anchored)
		}
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		spool = pccReceiptReopenSpool(t, root, state, privateKey)
		if got := state.Snapshot(); got.PCCReceiptCount != anchored.PCCReceiptCount ||
			got.PCCReceiptBytes != anchored.PCCReceiptBytes ||
			got.PCCReceiptHeadHash != anchored.PCCReceiptHeadHash {
			t.Fatalf("historical receipt anchor changed: before=%+v after=%+v", anchored, got)
		}
		if _, found, err := spool.pccReceipts.Lookup(
			receipt.OperationKey,
			receipt.RequestSHA256,
		); err == nil || found {
			t.Fatalf("historical receipt rebound without live event found=%t err=%v", found, err)
		}
	})

	t.Run("mutation read-only blocks ACK before journal and delete", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 253)
		state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
		item, receipt := pccReceiptSnapshotFixture(t, spool, signer, "read-only")
		if err := spool.pccReceipts.Append(receipt); err != nil {
			t.Fatal(err)
		}
		trigger := spool.items[item.Sequence-1]
		if err := spool.Ack(
			trigger.Sequence,
			trigger.EventID,
			trigger.ContentSHA256,
		); err != nil {
			t.Fatal(err)
		}
		if err := state.PersistReadOnly("test_pcc_ack_read_only"); err != nil {
			t.Fatal(err)
		}
		ackPath := filepath.Join(root, "spool", "acked.agf")
		before, err := os.ReadFile(ackPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := spool.Ack(
			item.Sequence,
			item.EventID,
			item.ContentSHA256,
		); !errors.Is(err, ErrAckInvalid) {
			t.Fatalf("mutation read-only ACK error=%v", err)
		}
		after, err := os.ReadFile(ackPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) ||
			state.Snapshot().AckSequence != trigger.Sequence {
			t.Fatal("mutation read-only ACK changed journal or anchor")
		}
		if _, err := os.Stat(item.path); err != nil {
			t.Fatalf("mutation read-only ACK deleted frame: %v", err)
		}
		if _, err := os.Stat(item.publicationPath); err != nil {
			t.Fatalf("mutation read-only ACK deleted publication: %v", err)
		}
	})
}

func TestSpoolLookupUnacknowledgedRequiresExactTriple(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 244)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "lookup"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := spool.items[event.SourceSequence]
	got, err := spool.LookupUnacknowledged(
		item.Sequence,
		item.EventID,
		item.ContentSHA256,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != item.Sequence || got.EventID != item.EventID ||
		got.ContentSHA256 != item.ContentSHA256 {
		t.Fatalf("lookup=%+v want=%+v", got, item)
	}
	got.Canonical[0] ^= 0xff
	if bytes.Equal(got.Canonical, spool.items[item.Sequence].Canonical) {
		t.Fatal("lookup returned caller-owned canonical bytes")
	}
	byEvent, err := spool.LookupUnacknowledgedEvent(
		item.EventID,
		item.ContentSHA256,
	)
	if err != nil || byEvent.Sequence != item.Sequence {
		t.Fatalf("event lookup=%+v err=%v", byEvent, err)
	}
	for name, mismatch := range map[string]struct {
		sequence uint64
		eventID  string
		content  string
	}{
		"sequence": {item.Sequence + 1, item.EventID, item.ContentSHA256},
		"event":    {item.Sequence, "evt_" + strings.Repeat("2", 64), item.ContentSHA256},
		"content":  {item.Sequence, item.EventID, strings.Repeat("2", 64)},
	} {
		if _, err := spool.LookupUnacknowledged(
			mismatch.sequence,
			mismatch.eventID,
			mismatch.content,
		); err == nil {
			t.Fatalf("%s mismatch was accepted", name)
		}
	}
	if err := spool.Ack(item.Sequence, item.EventID, item.ContentSHA256); err != nil {
		t.Fatal(err)
	}
	if state.Snapshot().AckSequence != item.Sequence {
		t.Fatal("fixture acknowledgement did not advance")
	}
	if _, err := spool.LookupUnacknowledged(
		item.Sequence,
		item.EventID,
		item.ContentSHA256,
	); err == nil {
		t.Fatal("acknowledged item was returned")
	}

	t.Run("event lookup rejects duplicate matches", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 250)
		state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
		event, err := signer.Wrap(
			context.Background(),
			"falco_connect",
			map[string]any{"kind": "duplicate-lookup"},
			metadata(),
		)
		if err != nil {
			t.Fatal(err)
		}
		item := spool.items[event.SourceSequence]
		spool.items[item.Sequence+100] = item
		if _, err := spool.LookupUnacknowledgedEvent(
			item.EventID,
			item.ContentSHA256,
		); !errors.Is(err, ErrSpoolCorrupt) {
			t.Fatalf("duplicate event lookup error=%v", err)
		}
		if !state.Snapshot().MutationReadOnly {
			t.Fatal("ambiguous event lookup did not fail closed")
		}
	})

	for name, mutate := range map[string]func(*testing.T, SpoolItem){
		"missing frame": func(t *testing.T, item SpoolItem) {
			t.Helper()
			if err := os.Remove(item.path); err != nil {
				t.Fatal(err)
			}
		},
		"changed frame": func(t *testing.T, item SpoolItem) {
			t.Helper()
			if err := os.WriteFile(item.path, []byte("changed"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"changed publication": func(t *testing.T, item SpoolItem) {
			t.Helper()
			if err := os.WriteFile(item.publicationPath, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			privateKey := testKey(t, 251)
			state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
			event, err := signer.Wrap(
				context.Background(),
				"falco_connect",
				map[string]any{"kind": name},
				metadata(),
			)
			if err != nil {
				t.Fatal(err)
			}
			item := spool.items[event.SourceSequence]
			mutate(t, item)
			if _, err := spool.LookupUnacknowledged(
				item.Sequence,
				item.EventID,
				item.ContentSHA256,
			); !errors.Is(err, ErrSpoolCorrupt) {
				t.Fatalf("identity mutation lookup error=%v", err)
			}
			if !state.Snapshot().MutationReadOnly {
				t.Fatal("identity mutation did not fail closed")
			}
		})
	}
}

func TestSpoolLookupUnacknowledgedRejectsReadOnlyBeforeDisk(t *testing.T) {
	for _, lookup := range []string{"sequence", "event"} {
		for _, hidden := range []string{"frame", "publication"} {
			t.Run(lookup+"/"+hidden, func(t *testing.T) {
				root := t.TempDir()
				privateKey := testKey(t, 252)
				state, spool, signer := openSignerFixture(
					t,
					root,
					testBootID,
					privateKey,
				)
				event, err := signer.Wrap(
					context.Background(),
					"falco_connect",
					map[string]any{"kind": "fenced-spool-" + lookup + "-" + hidden},
					metadata(),
				)
				if err != nil {
					t.Fatal(err)
				}
				item := spool.items[event.SourceSequence]
				const reason = "test_spool_lookup_read_only"
				if err := state.PersistReadOnly(reason); err != nil {
					t.Fatal(err)
				}
				path := item.path
				if hidden == "publication" {
					path = item.publicationPath
				}
				hiddenPath := path + ".hidden"
				if err := os.Rename(path, hiddenPath); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Rename(hiddenPath, path) })

				var lookupErr error
				if lookup == "sequence" {
					_, lookupErr = spool.LookupUnacknowledged(
						item.Sequence,
						item.EventID,
						item.ContentSHA256,
					)
				} else {
					_, lookupErr = spool.LookupUnacknowledgedEvent(
						item.EventID,
						item.ContentSHA256,
					)
				}
				if !errors.Is(lookupErr, ErrSpoolCorrupt) {
					t.Fatalf("fenced spool lookup error=%v", lookupErr)
				}
				if snapshot := state.Snapshot(); snapshot.ReadOnlyReason != reason {
					t.Fatalf("fenced spool lookup touched disk: %+v", snapshot)
				}
			})
		}
	}

	t.Run("event/map scan", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 250)
		state, spool, signer := openSignerFixture(
			t,
			root,
			testBootID,
			privateKey,
		)
		event, err := signer.Wrap(
			context.Background(),
			"falco_connect",
			map[string]any{"kind": "fenced-event-map"},
			metadata(),
		)
		if err != nil {
			t.Fatal(err)
		}
		item := spool.items[event.SourceSequence]
		spool.items[item.Sequence+100] = item
		const reason = "test_spool_event_lookup_read_only"
		if err := state.PersistReadOnly(reason); err != nil {
			t.Fatal(err)
		}
		if _, err := spool.LookupUnacknowledgedEvent(
			item.EventID,
			item.ContentSHA256,
		); !errors.Is(err, ErrSpoolCorrupt) {
			t.Fatalf("fenced event lookup error=%v", err)
		}
		if snapshot := state.Snapshot(); snapshot.ReadOnlyReason != reason {
			t.Fatalf("fenced event lookup scanned item map: %+v", snapshot)
		}
	})
}
