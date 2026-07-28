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
