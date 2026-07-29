package observerd

import (
	"context"
	"errors"
	"testing"
)

func TestControlEventsRequireAtomicReceiptPublication(t *testing.T) {
	t.Run("generic signer rejects control type before sequence reservation", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 61)
		state, spool, signer := openSignerFixture(
			t,
			root,
			testBootID,
			privateKey,
		)
		request := coreControlAuthorizeFixture()
		before := state.Snapshot()

		_, err := signer.Wrap(
			context.Background(),
			request.EventType(),
			request.NormalizedFields(),
			EventMetadata{},
		)
		if !errors.Is(err, ErrCoreControlReceiptRequired) {
			t.Fatalf("Wrap error=%v, want receipt-required", err)
		}
		after := state.Snapshot()
		if after.LastSequence != before.LastSequence {
			t.Fatalf(
				"rejected generic control publication reserved sequence: %d -> %d",
				before.LastSequence,
				after.LastSequence,
			)
		}
		items, fetchErr := spool.Fetch(0, 1, 4*1024*1024)
		if fetchErr != nil {
			t.Fatal(fetchErr)
		}
		if len(items) != 0 {
			t.Fatalf("rejected generic publication reached spool: %+v", items)
		}
	})

	t.Run("spool rejects a valid signed control event without receipt context", func(t *testing.T) {
		root := t.TempDir()
		privateKey := testKey(t, 62)
		state, spool, _ := openSignerFixture(
			t,
			root,
			testBootID,
			privateKey,
		)
		request := coreControlAuthorizeFixture()
		before := state.Snapshot()
		event := signedControlPreflightFixture(
			t,
			before,
			privateKey,
			request,
		)
		identity := StateIdentity{
			HostID:   before.HostID,
			BootID:   before.BootID,
			KeyID:    before.KeyID,
			KeyEpoch: before.KeyEpoch,
		}
		if sequence, err := state.reserveExpected(
			identity,
			event.SourceSequence,
		); err != nil || sequence != event.SourceSequence {
			t.Fatalf("reserve sequence=%d error=%v", sequence, err)
		}

		if _, err := spool.Append(event, PriorityTier); !errors.Is(
			err,
			ErrCoreControlReceiptRequired,
		) {
			t.Fatalf("Append error=%v, want receipt-required", err)
		}
		items, err := spool.Fetch(0, 1, 4*1024*1024)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 0 {
			t.Fatalf("receipt-less control event reached spool: %+v", items)
		}
		if receipt, found, err := spool.FindControl(
			request.OperationKey(),
		); err != nil || found {
			t.Fatalf(
				"receipt-less control event was legitimized: found=%v receipt=%+v error=%v",
				found,
				receipt,
				err,
			)
		}
	})
}

func TestSpoolAppendReturnCanonicalIsIsolated(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 63)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	event, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "alias-proof"},
		metadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	returned, err := spool.Append(event, RoutineTier)
	if err != nil {
		t.Fatal(err)
	}
	if len(returned.Canonical) == 0 {
		t.Fatal("append returned empty canonical payload")
	}
	returned.Canonical[0] ^= 1

	retry, err := spool.Append(event, RoutineTier)
	if err != nil {
		t.Fatalf("caller mutation poisoned stored item: %v", err)
	}
	if len(retry.Canonical) == 0 || retry.Canonical[0] != '{' {
		t.Fatalf("stored canonical was aliased: %q", retry.Canonical)
	}
	if state.Snapshot().MutationReadOnly {
		t.Fatal("caller-owned mutation fenced an otherwise valid spool")
	}
}
