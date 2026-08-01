package observerd

import (
	"encoding/json"
	"strings"
	"testing"

	"agmind.local/sais/internal/contracts"
)

func TestC2AObserverStateReceiptAnchorMatrix(t *testing.T) {
	service, state, _, _, _ := observerServiceFixture(t)
	t.Cleanup(func() { _ = service.daemon.Close() })

	initial := state.Snapshot()
	if initial.SchemaVersion != observerStateSchema ||
		initial.ControlReceiptCount != 0 ||
		initial.ControlReceiptBytes != 0 ||
		initial.ControlReceiptHeadHash != zeroControlReceiptHash {
		t.Fatalf("initial receipt anchor=%+v", initial)
	}

	firstHash := strings.Repeat("a", 64)
	if err := state.anchorControlReceipt(
		0,
		0,
		zeroControlReceiptHash,
		1,
		1_024,
		firstHash,
	); err != nil {
		t.Fatal(err)
	}
	anchored := state.Snapshot()
	if anchored.ControlReceiptCount != 1 ||
		anchored.ControlReceiptBytes != 1_024 ||
		anchored.ControlReceiptHeadHash != firstHash {
		t.Fatalf("anchored receipt state=%+v", anchored)
	}

	if err := state.anchorControlReceipt(
		0,
		0,
		zeroControlReceiptHash,
		2,
		2_048,
		strings.Repeat("b", 64),
	); err == nil {
		t.Fatal("stale receipt anchor transition accepted")
	}
	if got := state.Snapshot(); got.ControlReceiptCount != 1 ||
		got.ControlReceiptBytes != 1_024 ||
		got.ControlReceiptHeadHash != firstHash {
		t.Fatalf("failed transition changed state=%+v", got)
	}
}

func TestC2AObserverStateV3MigratesToEmptyReceiptAnchor(t *testing.T) {
	service, state, _, _, _ := observerServiceFixture(t)
	t.Cleanup(func() { _ = service.daemon.Close() })

	raw, err := contracts.CanonicalJSON(state.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["schema_version"] = json.RawMessage(`"` + observerStateSchemaV3 + `"`)
	delete(fields, "control_receipt_count")
	delete(fields, "control_receipt_bytes")
	delete(fields, "control_receipt_head_sha256")
	delete(fields, "pcc_boundary_count")
	delete(fields, "pcc_boundary_bytes")
	delete(fields, "pcc_boundary_head_sha256")
	delete(fields, "pcc_receipt_count")
	delete(fields, "pcc_receipt_bytes")
	delete(fields, "pcc_receipt_head_sha256")
	legacyRaw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}

	migrated, changed, err := decodeObserverState(legacyRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !changed ||
		migrated.SchemaVersion != observerStateSchema ||
		migrated.ControlReceiptCount != 0 ||
		migrated.ControlReceiptBytes != 0 ||
		migrated.ControlReceiptHeadHash != zeroControlReceiptHash {
		t.Fatalf("migrated state=%+v changed=%t", migrated, changed)
	}
}

func TestC2AControlEventTypesArePriority(t *testing.T) {
	for _, eventType := range []string{
		"pcc_correlation_snapshot",
		"evidence_repair_authorized",
		"evidence_repair_completed",
		"retention_tombstone",
		"retention_blocked_priority_evidence",
	} {
		if !priorityEventType(eventType) {
			t.Fatalf("control event %q is not priority", eventType)
		}
	}
}
