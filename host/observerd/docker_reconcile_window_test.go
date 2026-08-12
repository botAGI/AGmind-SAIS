package observerd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
	"github.com/moby/moby/api/types/events"
)

type dockerCoverageWindow struct {
	kind       string
	openedAt   string
	closedAt   string
	generation uint64
	sequence   uint64
}

// decodeDockerCoverageWindows reads the frames the observer actually wrote to
// the spool directory, authenticates them and returns every Docker reconcile
// open and close in sequence order.
func decodeDockerCoverageWindows(
	t *testing.T,
	spool *Spool,
) []dockerCoverageWindow {
	t.Helper()
	written, err := spool.authenticatedPriorityEvents()
	if err != nil {
		t.Fatal(err)
	}
	decoded := make([]dockerCoverageWindow, 0, len(written))
	for _, event := range written {
		kind, _ := stringField(event.NormalizedFields, "kind")
		if kind != "docker_reconcile_gap" &&
			kind != "docker_reconcile_recovered" {
			continue
		}
		openedAt, openedOK := stringField(event.NormalizedFields, "opened_at")
		generation, generationOK := uint64Field(
			event.NormalizedFields,
			"reconcile_generation",
		)
		if !openedOK || !generationOK {
			t.Fatalf("Docker coverage frame is malformed: %+v", event)
		}
		closedAt, _ := stringField(event.NormalizedFields, "closed_at")
		decoded = append(decoded, dockerCoverageWindow{
			kind:       kind,
			openedAt:   openedAt,
			closedAt:   closedAt,
			generation: generation,
			sequence:   event.SourceSequence,
		})
	}
	return decoded
}

// TestDockerReconcileRetryReusesTheOneSignedGapWindow drives the real reconcile
// path with a Docker reader that fails once and then succeeds, exactly as the
// monitor loop does in production (monitorDockerContinuously retries a failed
// reconcile with "docker_event_reconcile_retry"). Before the window became
// singular and owned, the retry signed a SECOND docker_reconcile_gap with a new
// opened_at and closed only that one, so the first open was orphaned in the
// spool forever and Core latched mutation_readiness on "docker_reconcile_missing".
// The counts are asserted so any future leak fails loudly instead of hiding
// behind a matching pair.
func TestDockerReconcileRetryReusesTheOneSignedGapWindow(t *testing.T) {
	service, state, spool, inventory, docker := observerServiceFixture(t)
	t.Cleanup(service.closeDockerEventSession)
	docker.eventsResult = &DockerEventStream{
		Messages: make(chan events.Message),
		Err:      make(chan error),
	}
	// Production retries about a second after the failure. A frozen clock would
	// hide a leaked second open behind an identical opened_at.
	var ticks int
	service.now = func() time.Time {
		ticks++
		return time.Date(2026, 7, 27, 12, 1, 0, 0, time.UTC).
			Add(time.Duration(ticks) * time.Second)
	}

	injected := errors.New("injected Docker reconcile failure")
	docker.listErr = injected
	if err := service.recoverDockerWithSubscribedSession(
		context.Background(),
		"observer_startup",
	); !errors.Is(err, injected) {
		t.Fatalf("first reconcile err=%v want=%v", err, injected)
	}

	window := state.Snapshot().PendingDockerReconcile
	if window == nil {
		t.Fatal("failed reconcile left no owned Docker gap window")
	}
	if !state.Snapshot().ReconcileRequired || !inventory.ReconcileGapOpen() {
		t.Fatalf("failed reconcile lifted a fence: %+v", state.Snapshot())
	}
	// The window has to survive the process, otherwise a restart between the
	// open and the close orphans the open exactly as the retry used to.
	persisted, err := loadObserverState(state.path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.PendingDockerReconcile == nil ||
		*persisted.PendingDockerReconcile != *window {
		t.Fatalf(
			"durable window=%+v live=%+v",
			persisted.PendingDockerReconcile,
			window,
		)
	}

	docker.listErr = nil
	if err := service.recoverDockerWithSubscribedSession(
		context.Background(),
		"docker_event_reconcile_retry",
	); err != nil {
		t.Fatal(err)
	}
	if remaining := state.Snapshot().PendingDockerReconcile; remaining != nil {
		t.Fatalf("closed window is still owned: %+v", remaining)
	}
	if state.Snapshot().ReconcileRequired || inventory.ReconcileGapOpen() {
		t.Fatalf("recovered reconcile kept the fence: %+v", state.Snapshot())
	}

	decoded := decodeDockerCoverageWindows(t, spool)
	opens := make([]dockerCoverageWindow, 0, len(decoded))
	closes := make([]dockerCoverageWindow, 0, len(decoded))
	for _, frame := range decoded {
		if frame.kind == "docker_reconcile_gap" {
			opens = append(opens, frame)
			continue
		}
		closes = append(closes, frame)
	}
	if len(opens) != 1 || len(closes) != 1 {
		t.Fatalf(
			"docker_reconcile_gap opens=%d closes=%d want=1/1: %+v",
			len(opens),
			len(closes),
			decoded,
		)
	}
	if opens[0].openedAt != closes[0].openedAt ||
		opens[0].generation != closes[0].generation ||
		closes[0].sequence &lt;= opens[0].sequence {
		t.Fatalf("unpaired Docker reconcile window: %+v", decoded)
	}
	if opens[0].openedAt != window.OpenedAt ||
		opens[0].generation != window.Generation {
		t.Fatalf(
			"closed window %+v is not the owned window %+v",
			opens[0],
			window,
		)
	}
	if opens[0].generation != inventory.Generation() {
		t.Fatalf(
			"window generation=%d inventory generation=%d",
			opens[0].generation,
			inventory.Generation(),
		)
	}
	if _, err := spool.scanSequenceGapProofs(); err != nil {
		t.Fatalf("observer cannot authenticate its own proofs: %v", err)
	}
}

// TestDockerReconcileRetiresWindowWhoseReconcileAlreadyLanded covers the other
// abort point named by finishDockerReconcileLockedReceipt: the reconcile is
// durable but the commit that signs the close never runs (a dead event session
// aborts CommitIfLive). The next reconcile must retire that window with its own
// close before opening a new one, because the fresh reconcile advances the
// generation past the one the stale open announced.
func TestDockerReconcileRetiresWindowWhoseReconcileAlreadyLanded(t *testing.T) {
	service, state, spool, inventory, docker := observerServiceFixture(t)
	t.Cleanup(service.closeDockerEventSession)
	docker.eventsResult = &DockerEventStream{
		Messages: make(chan events.Message),
		Err:      make(chan error),
	}
	var ticks int
	service.now = func() time.Time {
		ticks++
		return time.Date(2026, 7, 27, 12, 1, 0, 0, time.UTC).
			Add(time.Duration(ticks) * time.Second)
	}
	if err := service.recoverDockerWithSubscribedSession(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}

	// Re-create the residue of an aborted commit: the open is signed and owned,
	// the reconcile it announced then lands durably, and nothing signs a close.
	staleOpenedAt := service.now().UTC()
	staleGeneration := inventory.Generation() + 1
	if err := service.openDockerReconcileFences(); err != nil {
		t.Fatal(err)
	}
	if err := service.signDockerCoverage(
		context.Background(),
		"docker_reconcile_gap",
		"CRITICAL",
		"docker_inventory_event",
		staleOpenedAt,
		nil,
		staleGeneration,
	); err != nil {
		t.Fatal(err)
	}
	if err := state.beginDockerReconcile(PendingDockerReconcile{
		OpenedAt:   staleOpenedAt.Format(time.RFC3339Nano),
		Generation: staleGeneration,
	}); err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inventory.Generation() != staleGeneration {
		t.Fatalf(
			"landed generation=%d want=%d",
			inventory.Generation(),
			staleGeneration,
		)
	}

	if err := service.recoverDockerWithSubscribedSession(
		context.Background(),
		"docker_event_reconcile_retry",
	); err != nil {
		t.Fatal(err)
	}
	if remaining := state.Snapshot().PendingDockerReconcile; remaining != nil {
		t.Fatalf("closed window is still owned: %+v", remaining)
	}

	decoded := decodeDockerCoverageWindows(t, spool)
	openedFor := make(map[string]int, len(decoded))
	closedFor := make(map[string]int, len(decoded))
	for _, frame := range decoded {
		key := frame.openedAt
		if frame.kind == "docker_reconcile_gap" {
			openedFor[key]++
			continue
		}
		closedFor[key]++
	}
	if len(openedFor) != 3 || len(closedFor) != 3 {
		t.Fatalf("window count opens=%d closes=%d want=3/3: %+v",
			len(openedFor), len(closedFor), decoded)
	}
	for openedAt, count := range openedFor {
		if count != 1 || closedFor[openedAt] != 1 {
			t.Fatalf(
				"window %s opens=%d closes=%d want=1/1: %+v",
				openedAt,
				count,
				closedFor[openedAt],
				decoded,
			)
		}
	}
	if closedFor[staleOpenedAt.Format(time.RFC3339Nano)] != 1 {
		t.Fatalf("stale window was never retired: %+v", decoded)
	}
}

// TestObserverStateV5MigratesToCurrentWithoutADockerWindow pins the migration
// added with the durable window: a state written before it records no window,
// so its already-orphaned open is not mistaken for one this process owns.
func TestObserverStateV5MigratesToCurrentWithoutADockerWindow(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := testKey(t, 213)
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
	fields["schema_version"] = json.RawMessage(`"agmind.observer-state.v5"`)
	delete(fields, "pending_docker_reconcile")
	legacyRaw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(statePath, legacyRaw); err != nil {
		t.Fatal(err)
	}

	migrated, err := OpenStateStore(statePath, identity)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := migrated.Snapshot()
	if snapshot.SchemaVersion != observerStateSchema ||
		snapshot.PendingDockerReconcile != nil {
		t.Fatalf("unexpected migrated V5 state: %+v", snapshot)
	}
	reloaded, err := loadObserverState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.SchemaVersion != observerStateSchema {
		t.Fatalf("migration was not persisted: %+v", reloaded)
	}
}
