package observerd

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestPCCPublishDockerGapOpeningLinearizesWithPublication(t *testing.T) {
	service, state, spool, inventory, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	trigger, err := service.IngestFalco(
		context.Background(),
		falcoIngestFixture(),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := pccRequestForItem(spool.items[trigger.SourceSequence])
	decision := service.now().UTC()
	service.pccLoadPins = func() (PCCSafetyPinSnapshot, error) {
		return pccPublishValidPins(t), nil
	}
	service.pccNow = func() time.Time {
		return decision
	}

	statePersist := state.persist
	lastPersistedReconcileRequired := state.Snapshot().ReconcileRequired
	var stateTransitions atomic.Int32
	var stateTryLockSucceeded atomic.Bool
	state.persist = func(path string, next ObserverState) error {
		if !lastPersistedReconcileRequired && next.ReconcileRequired {
			stateTransitions.Add(1)
			if state.publicationMutex.TryLock() {
				stateTryLockSucceeded.Store(true)
				state.publicationMutex.Unlock()
			}
		}
		err := statePersist(path, next)
		if err == nil {
			lastPersistedReconcileRequired = next.ReconcileRequired
		}
		return err
	}

	inventoryPersist := inventory.persist
	lastPersistedDockerGap := inventory.ReconcileGapOpen()
	var inventoryTransitions atomic.Int32
	var inventoryTryLockSucceeded atomic.Bool
	inventory.persist = func(path string, next inventoryDiskState) error {
		if !lastPersistedDockerGap && next.DockerReconcileGap {
			inventoryTransitions.Add(1)
			if state.publicationMutex.TryLock() {
				inventoryTryLockSucceeded.Store(true)
				state.publicationMutex.Unlock()
			}
		}
		err := inventoryPersist(path, next)
		if err == nil {
			lastPersistedDockerGap = next.DockerReconcileGap
		}
		return err
	}

	if err := service.openDockerReconcileFences(); err != nil {
		t.Fatal(err)
	}
	if got := stateTransitions.Load(); got != 1 {
		t.Errorf("ReconcileRequired false-to-true persistence transitions=%d want=1", got)
	}
	if got := inventoryTransitions.Load(); got != 1 {
		t.Errorf("DockerReconcileGap false-to-true persistence transitions=%d want=1", got)
	}
	if !state.Snapshot().ReconcileRequired || !inventory.ReconcileGapOpen() {
		t.Errorf(
			"Docker fences did not both open: state=%+v inventory_gap=%t",
			state.Snapshot(),
			inventory.ReconcileGapOpen(),
		)
	}
	if stateTryLockSucceeded.Load() {
		t.Errorf("publicationMutex.TryLock succeeded during ReconcileRequired transition")
	}
	if inventoryTryLockSucceeded.Load() {
		t.Errorf("publicationMutex.TryLock succeeded during DockerReconcileGap transition")
	}

	before := state.Snapshot()
	publication, err := service.PublishPCCCorrelationSnapshot(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := pccDecodeSnapshot(t, publication)
	if snapshot.Outcome != "failed" || snapshot.FailureReasons == nil ||
		!reflect.DeepEqual(*snapshot.FailureReasons, []string{
			"docker_reconcile_gap",
			"reconcile_required",
		}) {
		t.Fatalf("Docker-gap publication snapshot=%+v", snapshot)
	}
	if !publication.Created || publication.Item.Sequence != before.LastSequence+1 {
		t.Fatalf("Docker-gap publication=%+v before=%+v", publication, before)
	}
}

func TestPCCPublishRoutineDropDetectionLinearizesWithPublication(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 20)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
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

	statePersist := state.persist
	lastDropEventPending := state.Snapshot().DropEventPending
	var transitions atomic.Int32
	var tryLockSucceeded atomic.Bool
	state.persist = func(path string, next ObserverState) error {
		if !lastDropEventPending && next.DropEventPending {
			transitions.Add(1)
			if state.publicationMutex.TryLock() {
				tryLockSucceeded.Store(true)
				state.publicationMutex.Unlock()
			}
		}
		err := statePersist(path, next)
		if err == nil {
			lastDropEventPending = next.DropEventPending
		}
		return err
	}

	_, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"kind": "dropped-one"},
		metadata(),
	)
	if !errors.Is(err, ErrRoutineQuota) {
		t.Errorf("Wrap error=%v want ErrRoutineQuota", err)
	}
	if got := transitions.Load(); got != 1 {
		t.Errorf("DropEventPending false-to-true persistence transitions=%d want=1", got)
	}
	snapshot := state.Snapshot()
	if snapshot.RoutineDropped != 1 || !snapshot.DropEventPending {
		t.Errorf("routine drop state=%+v", snapshot)
	}
	if tryLockSucceeded.Load() {
		t.Errorf("publicationMutex.TryLock succeeded during DropEventPending transition")
	}
}
