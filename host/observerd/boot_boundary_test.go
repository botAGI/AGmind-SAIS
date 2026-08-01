package observerd

import (
	"bytes"
	"context"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
)

func fetchEnvelopeEvents(
	t *testing.T,
	spool *Spool,
) []contracts.EventEnvelopeV1 {
	t.Helper()
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	events := make([]contracts.EventEnvelopeV1, 0, len(items))
	for _, item := range items {
		event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(item.Canonical),
			65_536,
		)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	return events
}

func TestObserverBootBoundaryPrecedesGapAndStart(t *testing.T) {
	t.Run("bootstrap boundary precedes gap and start", func(t *testing.T) {
		configPath, _, _, _ := rotationFixture(t)
		now := func() time.Time {
			return time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)
		}
		first, err := Bootstrap(
			context.Background(),
			configPath,
			WithBootstrapBootID(func() (string, error) { return testBootID, nil }),
			WithBootstrapNow(now),
		)
		if err != nil {
			t.Fatal(err)
		}
		firstEvents := fetchEnvelopeEvents(t, first.spool)
		if len(firstEvents) != 2 ||
			firstEvents[0].EventType != "observer_boot_boundary" ||
			firstEvents[1].EventType != "observer_start" {
			t.Fatalf("genesis events=%+v", firstEvents)
		}
		if _, err := first.signer.Wrap(
			context.Background(),
			"falco_connect",
			map[string]any{"invalid": 1.5},
			metadata(),
		); err == nil {
			t.Fatal("expected reserved-but-unpublished sequence")
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}

		second, err := Bootstrap(
			context.Background(),
			configPath,
			WithBootstrapBootID(func() (string, error) { return testBootID2, nil }),
			WithBootstrapNow(now),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		events := fetchEnvelopeEvents(t, second.spool)
		var newBoot []contracts.EventEnvelopeV1
		for _, event := range events {
			if event.BootID == testBootID2 {
				newBoot = append(newBoot, event)
			}
		}
		if len(newBoot) != 3 ||
			newBoot[0].EventType != "observer_boot_boundary" ||
			newBoot[1].EventType != "coverage" ||
			newBoot[1].NormalizedFields["kind"] != "observer_sequence_gap" ||
			newBoot[2].EventType != "observer_start" {
			t.Fatalf("new boot events=%+v", newBoot)
		}
		if newBoot[0].SourceSequence != 4 ||
			newBoot[1].SourceSequence != 5 ||
			newBoot[2].SourceSequence != 6 {
			t.Fatalf("new boot sequences=%d,%d,%d",
				newBoot[0].SourceSequence,
				newBoot[1].SourceSequence,
				newBoot[2].SourceSequence,
			)
		}
	})
}

func TestBootBoundaryPCCArchivePrecedesAckCleanup(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 220)
	_, firstSpool, firstSigner := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	if _, err := firstSigner.Wrap(
		context.Background(),
		"observer_start",
		map[string]any{"kind": "observer_start"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	if err := firstSpool.Close(); err != nil {
		t.Fatal(err)
	}
	state, spool, signer := openPendingSignerFixture(
		t,
		root,
		testBootID2,
		privateKey,
	)
	if err := ensureDedicatedBootBoundary(
		context.Background(),
		state,
		signer,
		time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	if snapshot.PCCBoundaryCount != 1 ||
		spool.boundaryArchive == nil {
		t.Fatalf("boundary was committed without PCC archive: %+v", snapshot)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("boundary items=%d", len(items))
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
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	keys := pccArchiveKeyring(t, privateKey)
	restarted, err := NewSpool(
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
	defer restarted.Close()
	chain, err := restarted.boundaryArchive.Chain(testBootID, testBootID2)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 || chain[0].EventID != items[1].EventID {
		t.Fatalf("restarted boundary chain=%+v", chain)
	}
}

func TestBootBoundaryPCCArchiveBlocksAckUntilAnchor(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 228)
	_, firstSpool, firstSigner := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	if _, err := firstSigner.Wrap(
		context.Background(),
		"observer_start",
		map[string]any{"kind": "observer_start"},
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	if err := firstSpool.Close(); err != nil {
		t.Fatal(err)
	}
	state, spool, signer := openPendingSignerFixture(
		t,
		root,
		testBootID2,
		privateKey,
	)
	defer spool.Close()
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil || len(items) != 1 {
		t.Fatalf("pre-boundary items=%d err=%v", len(items), err)
	}
	if err := spool.Ack(
		items[0].Sequence,
		items[0].EventID,
		items[0].ContentSHA256,
	); err != nil {
		t.Fatal(err)
	}

	// Hold the archive lock so the authorized publisher stops after the
	// boundary frame is durable but before its V5 archive anchor exists.
	spool.boundaryArchive.mutex.Lock()
	archiveLocked := true
	defer func() {
		if archiveLocked {
			spool.boundaryArchive.mutex.Unlock()
		}
	}()
	publishDone := make(chan error, 1)
	go func() {
		publishDone <- ensureDedicatedBootBoundary(
			context.Background(),
			state,
			signer,
			time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
		)
	}()

	var boundary SpoolItem
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for boundary.EventID == "" {
		spool.mutex.Lock()
		boundary = cloneSpoolItem(spool.items[2])
		spool.mutex.Unlock()
		if boundary.EventID != "" {
			break
		}
		select {
		case err := <-publishDone:
			spool.boundaryArchive.mutex.Unlock()
			archiveLocked = false
			t.Fatalf("publisher returned before archive gate: %v", err)
		case <-deadline.C:
			spool.boundaryArchive.mutex.Unlock()
			archiveLocked = false
			t.Fatal("boundary frame was not durably published")
		case <-ticker.C:
		}
	}

	ackAttempted := make(chan struct{})
	ackDone := make(chan error, 1)
	go func() {
		close(ackAttempted)
		ackDone <- spool.Ack(
			boundary.Sequence,
			boundary.EventID,
			boundary.ContentSHA256,
		)
	}()
	<-ackAttempted
	var prematureAck error
	ackCrossedGate := false
	select {
	case prematureAck = <-ackDone:
		ackCrossedGate = true
	case <-time.After(100 * time.Millisecond):
	}
	spool.mutex.Lock()
	_, boundaryStillPresent := spool.items[boundary.Sequence]
	spool.mutex.Unlock()

	spool.boundaryArchive.mutex.Unlock()
	archiveLocked = false
	publishErr := <-publishDone
	if !ackCrossedGate {
		prematureAck = <-ackDone
	}
	if ackCrossedGate || !boundaryStillPresent {
		t.Fatalf(
			"ACK crossed unanchored boundary gate: crossed=%v present=%v err=%v",
			ackCrossedGate,
			boundaryStillPresent,
			prematureAck,
		)
	}
	if publishErr != nil || prematureAck != nil {
		t.Fatalf("publish=%v ack=%v", publishErr, prematureAck)
	}
	snapshot := state.Snapshot()
	if snapshot.PCCBoundaryCount != 1 ||
		snapshot.BootBoundaryState != bootBoundaryCommitted {
		t.Fatalf("anchored boundary state=%+v", snapshot)
	}
}
