package observerd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
