package observerd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

func v3StateWithReceiptJournalFixture(
	t *testing.T,
) (string, StateIdentity, []byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := testKey(t, 211)
	identity := stateIdentityForKey(t, privateKey)
	statePath := filepath.Join(root, "observer-state.json")
	state, err := OpenStateStore(statePath, identity)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := contracts.CanonicalJSON(state.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["schema_version"] = json.RawMessage(
		`"` + observerStateSchemaV3 + `"`,
	)
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
	if err := durablefile.AtomicWrite(statePath, legacyRaw); err != nil {
		t.Fatal(err)
	}
	spoolRoot := filepath.Join(root, "spool")
	if err := durablefile.EnsurePrivateDirectory(spoolRoot); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.CreateOnly(
		filepath.Join(spoolRoot, "control-receipts.agf"),
		nil,
	); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	return statePath, identity, before
}

func assertV3StateUnchanged(
	t *testing.T,
	statePath string,
	before []byte,
) {
	t.Helper()
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("rejected v3 migration changed durable observer state")
	}
}

func TestOpenStateStoreRejectsV3WithExistingControlReceiptJournalBeforeMigration(
	t *testing.T,
) {
	statePath, identity, before := v3StateWithReceiptJournalFixture(t)
	if _, err := OpenStateStore(statePath, identity); !errors.Is(
		err,
		ErrControlReceiptCorrupt,
	) {
		t.Fatalf("open v3 with receipt journal err=%v", err)
	}
	assertV3StateUnchanged(t, statePath, before)
}

func TestLoadObserverStateRejectsV3WithExistingControlReceiptJournalBeforeMigration(
	t *testing.T,
) {
	statePath, _, before := v3StateWithReceiptJournalFixture(t)
	if _, err := loadObserverState(statePath); !errors.Is(
		err,
		ErrControlReceiptCorrupt,
	) {
		t.Fatalf("load v3 with receipt journal err=%v", err)
	}
	assertV3StateUnchanged(t, statePath, before)
}

func v4StateWithoutPCCAnchorsFixture(
	t *testing.T,
) (string, StateIdentity, []byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := testKey(t, 212)
	identity := stateIdentityForKey(t, privateKey)
	statePath := filepath.Join(root, "observer-state.json")
	state, err := OpenStateStore(statePath, identity)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := contracts.CanonicalJSON(state.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["schema_version"] = json.RawMessage(
		`"agmind.observer-state.v4"`,
	)
	for _, field := range []string{
		"pcc_boundary_count",
		"pcc_boundary_bytes",
		"pcc_boundary_head_sha256",
		"pcc_receipt_count",
		"pcc_receipt_bytes",
		"pcc_receipt_head_sha256",
	} {
		delete(fields, field)
	}
	legacyRaw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(statePath, legacyRaw); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	return statePath, identity, before
}

func installEmptyPCCJournal(t *testing.T, statePath, name string) {
	t.Helper()
	spoolRoot := filepath.Join(filepath.Dir(statePath), "spool")
	if err := durablefile.EnsurePrivateDirectory(spoolRoot); err != nil {
		t.Fatal(err)
	}
	if err := durablefile.CreateOnly(
		filepath.Join(spoolRoot, name),
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func assertObserverStateBytesUnchanged(
	t *testing.T,
	statePath string,
	before []byte,
) {
	t.Helper()
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("rejected observer-state migration changed durable bytes")
	}
}

func TestObserverStateV4MigratesToV5OnlyWithBothPCCJournalsAbsent(
	t *testing.T,
) {
	t.Run("both absent", func(t *testing.T) {
		statePath, identity, _ := v4StateWithoutPCCAnchorsFixture(t)
		state, err := OpenStateStore(statePath, identity)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := state.Snapshot()
		if snapshot.SchemaVersion != "agmind.observer-state.v5" ||
			snapshot.PCCBoundaryCount != 0 ||
			snapshot.PCCBoundaryBytes != 0 ||
			snapshot.PCCBoundaryHeadHash != zeroPCCJournalHash ||
			snapshot.PCCReceiptCount != 0 ||
			snapshot.PCCReceiptBytes != 0 ||
			snapshot.PCCReceiptHeadHash != zeroPCCJournalHash {
			t.Fatalf("unexpected migrated V5 anchor: %+v", snapshot)
		}
	})

	for _, journal := range []string{
		"pcc-boundaries.agf",
		"pcc-receipts.agf",
	} {
		t.Run(journal, func(t *testing.T) {
			statePath, identity, before := v4StateWithoutPCCAnchorsFixture(t)
			installEmptyPCCJournal(t, statePath, journal)
			if _, err := OpenStateStore(statePath, identity); !errors.Is(
				err,
				ErrPCCJournalCorrupt,
			) {
				t.Fatalf("open V4 with %s err=%v", journal, err)
			}
			assertObserverStateBytesUnchanged(t, statePath, before)
		})
	}
}

func TestObserverStateV5ValidatesBothPCCAnchors(t *testing.T) {
	statePath, identity, _ := v4StateWithoutPCCAnchorsFixture(t)
	store, err := OpenStateStore(statePath, identity)
	if err != nil {
		t.Fatal(err)
	}
	valid := store.Snapshot()
	nonzeroHash := strings.Repeat("a", 64)
	tests := map[string]func(*ObserverState){
		"boundary count without bytes": func(state *ObserverState) {
			state.PCCBoundaryCount = 1
			state.PCCBoundaryHeadHash = nonzeroHash
		},
		"boundary bytes without count": func(state *ObserverState) {
			state.PCCBoundaryBytes = 1
			state.PCCBoundaryHeadHash = nonzeroHash
		},
		"boundary zero count with nonzero head": func(state *ObserverState) {
			state.PCCBoundaryHeadHash = nonzeroHash
		},
		"boundary count overflow": func(state *ObserverState) {
			state.PCCBoundaryCount = 1_025
			state.PCCBoundaryBytes = 1
			state.PCCBoundaryHeadHash = nonzeroHash
		},
		"boundary bytes overflow": func(state *ObserverState) {
			state.PCCBoundaryCount = 1
			state.PCCBoundaryBytes = 64*1024*1024 + 1
			state.PCCBoundaryHeadHash = nonzeroHash
		},
		"receipt count without bytes": func(state *ObserverState) {
			state.PCCReceiptCount = 1
			state.PCCReceiptHeadHash = nonzeroHash
		},
		"receipt bytes without count": func(state *ObserverState) {
			state.PCCReceiptBytes = 1
			state.PCCReceiptHeadHash = nonzeroHash
		},
		"receipt zero count with nonzero head": func(state *ObserverState) {
			state.PCCReceiptHeadHash = nonzeroHash
		},
		"receipt count overflow": func(state *ObserverState) {
			state.PCCReceiptCount = 4_097
			state.PCCReceiptBytes = 1
			state.PCCReceiptHeadHash = nonzeroHash
		},
		"receipt bytes overflow": func(state *ObserverState) {
			state.PCCReceiptCount = 1
			state.PCCReceiptBytes = 16*1024*1024 + 1
			state.PCCReceiptHeadHash = nonzeroHash
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid PCC anchor accepted")
			}
		})
	}
}

func TestObserverStateRejectsUnanchoredPCCJournalBeforeMigration(t *testing.T) {
	for _, journal := range []string{
		"pcc-boundaries.agf",
		"pcc-receipts.agf",
	} {
		t.Run(journal, func(t *testing.T) {
			statePath, _, before := v4StateWithoutPCCAnchorsFixture(t)
			installEmptyPCCJournal(t, statePath, journal)
			if _, err := loadObserverState(statePath); !errors.Is(
				err,
				ErrPCCJournalCorrupt,
			) {
				t.Fatalf("load V4 with %s err=%v", journal, err)
			}
			assertObserverStateBytesUnchanged(t, statePath, before)
		})
	}
}
