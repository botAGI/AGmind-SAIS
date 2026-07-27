package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"agmind.local/sais/internal/contracts"
)

func TestRoutinePressureCoalescesOnePriorityCoverageEvent(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 20)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "first"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	spool.config.MaxBytes = spool.totalBytes + 100_000
	spool.config.PriorityReserveBytes = 100_000
	for _, kind := range []string{"dropped-one", "dropped-two"} {
		if _, err := signer.Wrap(
			context.Background(),
			"falco_connect",
			map[string]any{"kind": kind},
			metadata(),
		); !errors.Is(err, ErrRoutineQuota) {
			t.Fatalf("got %v, want routine quota", err)
		}
	}
	snapshot := state.Snapshot()
	if snapshot.RoutineDropped != 2 || !snapshot.DropEventPending {
		t.Fatalf("drop state=%+v", snapshot)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	coverageCount := 0
	for _, item := range items {
		event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(item.Canonical),
			65_536,
		)
		if err != nil {
			t.Fatal(err)
		}
		if event.EventType == "coverage" {
			coverageCount++
			if item.Tier != PriorityTier ||
				event.NormalizedFields["kind"] != "observer_spool_drop" {
				t.Fatalf("bad coverage item=%+v event=%+v", item, event)
			}
		}
	}
	if coverageCount != 1 {
		t.Fatalf("coverage events=%d want=1", coverageCount)
	}
}

func TestCoverageRecoveryIsSignedOnceAndClearsCoalescedState(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 21)
	state, spool, signer := openSignerFixture(t, root, testBootID, privateKey)
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "first"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	spool.config.MaxBytes = spool.totalBytes + 100_000
	spool.config.PriorityReserveBytes = 100_000
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "dropped"},
		metadata(),
	); !errors.Is(err, ErrRoutineQuota) {
		t.Fatalf("got %v", err)
	}
	coverage := NewCoverage(state, signer)
	if err := coverage.RecoverSpoolPressure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := coverage.RecoverSpoolPressure(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	if snapshot.RoutineDropped != 0 || snapshot.DropEventPending {
		t.Fatalf("recovery state=%+v", snapshot)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	recoveries := 0
	for _, item := range items {
		event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(item.Canonical),
			65_536,
		)
		if err != nil {
			t.Fatal(err)
		}
		if event.EventType == "coverage" &&
			event.NormalizedFields["kind"] == "observer_spool_drop_recovered" {
			recoveries++
			if err := contracts.VerifyEventSignature(
				event,
				privateKey.Public().(ed25519.PublicKey),
			); err != nil {
				t.Fatal(err)
			}
		}
	}
	if recoveries != 1 {
		t.Fatalf("recovery events=%d", recoveries)
	}
}
