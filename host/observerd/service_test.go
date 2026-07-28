package observerd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

type scriptedDockerReader struct {
	*fakeDockerReader
	mutex                 sync.Mutex
	eventResults          []DockerEventStream
	eventErrors           []error
	eventContexts         []context.Context
	listCalls             int
	listEventCounts       []int
	inspectCalls          int
	afterContainerInspect func(int, string)
}

func (reader *scriptedDockerReader) Events(
	ctx context.Context,
	_ client.EventsListOptions,
) (DockerEventStream, error) {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()
	index := len(reader.eventContexts)
	reader.eventContexts = append(reader.eventContexts, ctx)
	if index < len(reader.eventErrors) &&
		reader.eventErrors[index] != nil {
		return DockerEventStream{}, reader.eventErrors[index]
	}
	if index >= len(reader.eventResults) {
		messages := make(chan events.Message)
		errs := make(chan error)
		return DockerEventStream{Messages: messages, Err: errs}, nil
	}
	return reader.eventResults[index], nil
}

func (reader *scriptedDockerReader) ContainerList(
	ctx context.Context,
	options client.ContainerListOptions,
) (client.ContainerListResult, error) {
	result, err := reader.fakeDockerReader.ContainerList(ctx, options)
	result.Items = append([]container.Summary{}, result.Items...)
	reader.mutex.Lock()
	reader.listCalls++
	reader.listEventCounts = append(
		reader.listEventCounts,
		len(reader.eventContexts),
	)
	reader.mutex.Unlock()
	return result, err
}

func (reader *scriptedDockerReader) ContainerInspect(
	ctx context.Context,
	fullID string,
	options client.ContainerInspectOptions,
) (client.ContainerInspectResult, error) {
	result, err := reader.fakeDockerReader.ContainerInspect(
		ctx,
		fullID,
		options,
	)
	if result.Container.State != nil {
		state := *result.Container.State
		result.Container.State = &state
	}
	reader.mutex.Lock()
	reader.inspectCalls++
	call := reader.inspectCalls
	hook := reader.afterContainerInspect
	reader.mutex.Unlock()
	if hook != nil {
		hook(call, fullID)
	}
	return result, err
}

func (reader *scriptedDockerReader) eventSnapshot() ([]context.Context, []int) {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()
	return append([]context.Context{}, reader.eventContexts...),
		append([]int{}, reader.listEventCounts...)
}

func observerServiceFixture(
	t *testing.T,
) (*Service, *StateStore, *Spool, *Inventory, *fakeDockerReader) {
	t.Helper()
	root := inventoryTempDir(t)
	privateKey := testKey(t, 125)
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	now := func() time.Time {
		return time.Date(2026, 7, 27, 12, 1, 0, 0, time.UTC)
	}
	inventory, err := openInventory(
		root,
		docker,
		fakeProcessIdentityReader{byPID: map[int]processIdentity{
			4242: validProcessIdentity(),
		}},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	daemon := &Daemon{
		state:    state,
		spool:    spool,
		signer:   signer,
		coverage: NewCoverage(state, signer),
	}
	return newObserverService(daemon, inventory, docker, now),
		state,
		spool,
		inventory,
		docker
}

func TestServiceReconcileClosesDockerGapOnlyAfterSignedCoverage(
	t *testing.T,
) {
	service, state, spool, inventory, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	if state.Snapshot().ReconcileRequired {
		t.Fatalf("successful reconcile retained state fence: %+v", state.Snapshot())
	}
	identity, err := inventory.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if identity.InventoryGeneration != 1 {
		t.Fatalf("generation=%d want=1", identity.InventoryGeneration)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	kinds := make([]string, 0, len(items))
	for _, item := range items {
		event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(item.Canonical),
			65_536,
		)
		if err != nil {
			t.Fatal(err)
		}
		if event.EventType != "coverage" {
			t.Fatalf("unexpected event type %s", event.EventType)
		}
		kind, ok := event.NormalizedFields["kind"].(string)
		if !ok {
			t.Fatalf("coverage lacks kind: %+v", event.NormalizedFields)
		}
		kinds = append(kinds, kind)
	}
	want := []string{"docker_reconcile_gap", "docker_reconcile_recovered"}
	if len(kinds) != len(want) ||
		kinds[0] != want[0] ||
		kinds[1] != want[1] {
		t.Fatalf("coverage kinds=%v want=%v", kinds, want)
	}
}

func TestServiceDockerEventDisconnectFencesUntilFullReconcile(
	t *testing.T,
) {
	service, state, _, inventory, docker := observerServiceFixture(t)
	t.Cleanup(service.closeDockerEventSession)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	messages := make(chan events.Message)
	eventErrors := make(chan error, 1)
	docker.eventsResult = &DockerEventStream{
		Messages: messages,
		Err:      eventErrors,
	}
	if err := service.prepareDockerEventSession(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
	eventErrors <- io.EOF
	<-service.eventSession.terminalSignal
	injected := errors.New("injected Docker reconnect failure")
	docker.listErr = injected
	if err := service.MonitorDockerOnce(
		context.Background(),
	); !errors.Is(err, injected) {
		t.Fatalf("event disconnect err=%v", err)
	}
	snapshot := state.Snapshot()
	if !snapshot.ReconcileRequired || snapshot.MutationReadOnly {
		t.Fatalf("event gap fence=%+v", snapshot)
	}
	if _, err := inventory.ResolvePrefix(
		inventoryTestIDOne[:12],
	); !errors.Is(err, ErrInventoryReconcileRequired) {
		t.Fatalf("event gap admitted stale identity: %v", err)
	}

	docker.listErr = nil
	if err := service.ReconcileDocker(
		context.Background(),
		"docker_event_stream_recovered",
	); err != nil {
		t.Fatal(err)
	}
	recovered, err := inventory.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.InventoryGeneration != 2 ||
		state.Snapshot().ReconcileRequired {
		t.Fatalf(
			"recovery identity=%+v state=%+v",
			recovered,
			state.Snapshot(),
		)
	}
}

func TestDockerMonitorKeepsOneSubscriptionAcrossEventReconciles(
	t *testing.T,
) {
	service, _, _, inventory, docker := observerServiceFixture(t)
	firstMessages := make(chan events.Message, 2)
	firstErrors := make(chan error)
	secondMessages := make(chan events.Message)
	secondErrors := make(chan error)
	scripted := &scriptedDockerReader{
		fakeDockerReader: docker,
		eventResults: []DockerEventStream{
			{Messages: firstMessages, Err: firstErrors},
			{Messages: secondMessages, Err: secondErrors},
		},
	}
	service.docker = scripted
	inventory.docker = scripted
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := service.prepareDockerEventSession(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.closeDockerEventSession)
	if err := service.ReconcileDocker(
		ctx,
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}

	scripted.afterContainerInspect = func(call int, fullID string) {
		if call != 2 || fullID != inventoryTestIDOne {
			return
		}
		inspect := docker.inspectByID[inventoryTestIDOne]
		inspect.Container.State.Running = false
		inspect.Container.State.Status = container.StateExited
		docker.inspectByID[inventoryTestIDOne] = inspect
		docker.listResult.Items[0].State = container.StateExited
		firstMessages <- events.Message{}
	}
	firstMessages <- events.Message{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.monitorDockerContinuously(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if inventory.Generation() >= 3 {
			_, err := inventory.LookupFullID(inventoryTestIDOne)
			if errors.Is(err, ErrContainerNotFound) {
				break
			}
		}
		if time.Now().After(deadline) {
			contexts, _ := scripted.eventSnapshot()
			t.Fatalf(
				"event queued during reconcile was lost: generation=%d subscriptions=%d",
				inventory.Generation(),
				len(contexts),
			)
		}
		time.Sleep(10 * time.Millisecond)
	}
	contexts, _ := scripted.eventSnapshot()
	if len(contexts) != 1 {
		t.Fatalf("normal events created %d subscriptions want=1", len(contexts))
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Docker monitor did not stop")
	}
}

func TestDockerMonitorFencesThenSubscribesReplacementBeforeReconcile(
	t *testing.T,
) {
	service, state, _, inventory, docker := observerServiceFixture(t)
	firstMessages := make(chan events.Message)
	firstErrors := make(chan error, 1)
	secondMessages := make(chan events.Message)
	secondErrors := make(chan error)
	scripted := &scriptedDockerReader{
		fakeDockerReader: docker,
		eventResults: []DockerEventStream{
			{Messages: firstMessages, Err: firstErrors},
			{Messages: secondMessages, Err: secondErrors},
		},
	}
	service.docker = scripted
	inventory.docker = scripted
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := service.prepareDockerEventSession(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.closeDockerEventSession)
	if err := service.ReconcileDocker(
		ctx,
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	firstErrors <- io.EOF
	<-service.eventSession.terminalSignal
	if err := service.MonitorDockerOnce(ctx); !errors.Is(
		err,
		ErrDockerEventGap,
	) {
		t.Fatalf("disconnect err=%v", err)
	}
	contexts, listEventCounts := scripted.eventSnapshot()
	if len(contexts) != 2 {
		t.Fatalf("replacement subscriptions=%d want=2", len(contexts))
	}
	select {
	case <-contexts[0].Done():
	default:
		t.Fatal("replaced Docker event session context was not canceled")
	}
	select {
	case <-contexts[1].Done():
		t.Fatal("active replacement Docker event session was canceled")
	default:
	}
	if len(listEventCounts) != 2 ||
		listEventCounts[0] != 1 ||
		listEventCounts[1] != 2 {
		t.Fatalf(
			"reconcile subscription ordering=%v want=[1 2]",
			listEventCounts,
		)
	}
	if state.Snapshot().ReconcileRequired || inventory.ReconcileGapOpen() {
		t.Fatalf(
			"replacement reconcile did not recover: state=%+v gap=%v",
			state.Snapshot(),
			inventory.ReconcileGapOpen(),
		)
	}
}

func TestPendingDockerRecoverySubscribesBeforeReconcile(t *testing.T) {
	service, state, _, inventory, docker := observerServiceFixture(t)
	messages := make(chan events.Message)
	eventErrors := make(chan error)
	scripted := &scriptedDockerReader{
		fakeDockerReader: docker,
		eventResults: []DockerEventStream{{
			Messages: messages,
			Err:      eventErrors,
		}},
	}
	service.docker = scripted
	inventory.docker = scripted
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(service.closeDockerEventSession)

	if !state.Snapshot().ReconcileRequired ||
		!inventory.ReconcileGapOpen() {
		t.Fatalf(
			"fixture is not pending: state=%+v gap=%v",
			state.Snapshot(),
			inventory.ReconcileGapOpen(),
		)
	}
	if err := service.recoverDockerWithSubscribedSession(
		ctx,
		"docker_event_reconcile_retry",
	); err != nil {
		t.Fatal(err)
	}
	contexts, listEventCounts := scripted.eventSnapshot()
	if len(contexts) != 1 ||
		len(listEventCounts) != 1 ||
		listEventCounts[0] != 1 {
		t.Fatalf(
			"pending recovery ordering subscriptions=%d list_event_counts=%v",
			len(contexts),
			listEventCounts,
		)
	}
	if state.Snapshot().ReconcileRequired || inventory.ReconcileGapOpen() {
		t.Fatalf(
			"pending recovery retained fence: state=%+v gap=%v",
			state.Snapshot(),
			inventory.ReconcileGapOpen(),
		)
	}
}

func TestPendingDockerRecoveryRejectsReadySubscriptionErrorBeforeList(
	t *testing.T,
) {
	service, state, _, inventory, docker := observerServiceFixture(t)
	messages := make(chan events.Message)
	eventErrors := make(chan error, 1)
	injected := errors.New("injected ready Docker events GET failure")
	eventErrors <- injected
	scripted := &scriptedDockerReader{
		fakeDockerReader: docker,
		eventResults: []DockerEventStream{{
			Messages: messages,
			Err:      eventErrors,
		}},
	}
	service.docker = scripted
	inventory.docker = scripted
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(service.closeDockerEventSession)

	if err := service.recoverDockerWithSubscribedSession(
		ctx,
		"docker_event_reconcile_retry",
	); !errors.Is(err, injected) {
		t.Fatalf("ready subscription error=%v", err)
	}
	contexts, listEventCounts := scripted.eventSnapshot()
	if len(contexts) != 1 || len(listEventCounts) != 0 {
		t.Fatalf(
			"failed subscription contexts=%d list_event_counts=%v",
			len(contexts),
			listEventCounts,
		)
	}
	select {
	case <-contexts[0].Done():
	default:
		t.Fatal("failed subscription child context was not canceled")
	}
	if inventory.Generation() != 0 ||
		!inventory.ReconcileGapOpen() ||
		!state.Snapshot().ReconcileRequired {
		t.Fatalf(
			"failed subscription closed fence: generation=%d gap=%v state=%+v",
			inventory.Generation(),
			inventory.ReconcileGapOpen(),
			state.Snapshot(),
		)
	}
}

func TestDockerTerminalDuringSnapshotForbidsRecoveredFenceClose(
	t *testing.T,
) {
	service, state, spool, inventory, docker := observerServiceFixture(t)
	messages := make(chan events.Message)
	eventErrors := make(chan error)
	injected := errors.New("injected terminal during Docker snapshot")
	scripted := &scriptedDockerReader{
		fakeDockerReader: docker,
		eventResults: []DockerEventStream{{
			Messages: messages,
			Err:      eventErrors,
		}},
	}
	service.docker = scripted
	inventory.docker = scripted
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(service.closeDockerEventSession)
	scripted.afterContainerInspect = func(call int, _ string) {
		if call != 1 {
			return
		}
		eventErrors <- injected
		<-service.eventSession.terminalSignal
	}

	if err := service.recoverDockerWithSubscribedSession(
		ctx,
		"observer_startup",
	); !errors.Is(err, injected) {
		t.Fatalf("terminal-during-snapshot err=%v", err)
	}
	if !state.Snapshot().ReconcileRequired ||
		!inventory.ReconcileGapOpen() {
		t.Fatalf(
			"terminal snapshot closed fence: state=%+v gap=%v",
			state.Snapshot(),
			inventory.ReconcileGapOpen(),
		)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(item.Canonical),
			65_536,
		)
		if err != nil {
			t.Fatal(err)
		}
		if event.NormalizedFields["kind"] ==
			"docker_reconcile_recovered" {
			t.Fatal("terminal snapshot emitted a recovered close record")
		}
	}
}

func TestDockerEventSessionTerminalBeforeCommitRejectsClose(t *testing.T) {
	docker := inventoryDocker(nil)
	messages := make(chan events.Message)
	eventErrors := make(chan error)
	docker.eventsResult = &DockerEventStream{
		Messages: messages,
		Err:      eventErrors,
	}
	fenced := make(chan struct{})
	var fenceOnce sync.Once
	session, err := newDockerEventSession(
		context.Background(),
		docker,
		func() error {
			fenceOnce.Do(func() { close(fenced) })
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.close)
	injected := errors.New("injected terminal before commit")
	sent := make(chan struct{})
	go func() {
		eventErrors <- injected
		close(sent)
	}()
	<-sent
	<-session.terminalSignal
	committed := false
	if err := session.CommitIfLive(func() error {
		committed = true
		return nil
	}); !errors.Is(err, injected) {
		t.Fatalf("terminal-before-commit err=%v", err)
	}
	if committed {
		t.Fatal("terminal session executed fence-close commit")
	}
	select {
	case <-fenced:
	default:
		t.Fatal("terminal transition did not open reconcile fences")
	}
}

func TestDockerEventSessionCommitBeforeTerminalReopensFence(t *testing.T) {
	docker := inventoryDocker(nil)
	messages := make(chan events.Message)
	eventErrors := make(chan error)
	docker.eventsResult = &DockerEventStream{
		Messages: messages,
		Err:      eventErrors,
	}
	commitApplied := make(chan struct{})
	terminalApplied := make(chan struct{})
	session, err := newDockerEventSession(
		context.Background(),
		docker,
		func() error {
			select {
			case <-commitApplied:
			default:
				t.Error("terminal fence ran before in-flight commit")
			}
			close(terminalApplied)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.close)

	commitEntered := make(chan struct{})
	releaseCommit := make(chan struct{})
	commitResult := make(chan error, 1)
	go func() {
		commitResult <- session.CommitIfLive(func() error {
			close(commitEntered)
			<-releaseCommit
			close(commitApplied)
			return nil
		})
	}()
	<-commitEntered
	terminalSent := make(chan struct{})
	go func() {
		eventErrors <- errors.New("injected terminal after commit start")
		close(terminalSent)
	}()
	<-terminalSent
	close(releaseCommit)
	if err := <-commitResult; err != nil {
		t.Fatalf("in-flight live commit err=%v", err)
	}
	<-session.terminalSignal
	<-terminalApplied
	if err := session.CommitIfLive(func() error {
		t.Fatal("post-terminal commit callback ran")
		return nil
	}); err == nil {
		t.Fatal("post-commit terminal did not reject later close")
	}
}

func TestDockerEventSessionCoalescesWithoutBlockingEventDrain(
	t *testing.T,
) {
	docker := inventoryDocker(nil)
	messages := make(chan events.Message)
	eventErrors := make(chan error)
	docker.eventsResult = &DockerEventStream{
		Messages: messages,
		Err:      eventErrors,
	}
	session, err := newDockerEventSession(
		context.Background(),
		docker,
		func() error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.close)
	sent := make(chan struct{})
	go func() {
		for range 1_000 {
			messages <- events.Message{}
		}
		close(sent)
	}()
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("event pump blocked on coalesced dirty notification")
	}
	select {
	case <-session.dirty:
	default:
		t.Fatal("event pump did not retain coalesced dirty notification")
	}
	select {
	case <-session.dirty:
		t.Fatal("event pump emitted more than one coalesced notification")
	default:
	}
}

func TestReconcilePersistenceFailureFencesLiveStateAndInventory(
	t *testing.T,
) {
	service, state, _, inventory, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	persistedBefore, err := loadObserverState(state.path)
	if err != nil {
		t.Fatal(err)
	}
	if persistedBefore.ReconcileRequired {
		t.Fatalf("healthy persisted state=%+v", persistedBefore)
	}

	originalPersist := state.persist
	injected := errors.New("injected pre-rename state disk-full")
	state.persist = func(string, ObserverState) error {
		return injected
	}
	if err := service.ReconcileDocker(
		context.Background(),
		"docker_event_stream_error",
	); !errors.Is(err, injected) {
		t.Fatalf("reconcile persistence err=%v", err)
	}
	if !state.Snapshot().ReconcileRequired {
		t.Fatal("state persistence failure left live readiness open")
	}
	if _, err := inventory.LookupFullID(inventoryTestIDOne); !errors.Is(
		err,
		ErrInventoryReconcileRequired,
	) {
		t.Fatalf("state persistence failure left inventory lookup open: %v", err)
	}
	if _, err := service.LookupPrivateContainer(
		context.Background(),
		inventoryTestIDOne,
	); !errors.Is(err, ErrInventoryReconcileRequired) {
		t.Fatalf("private lookup did not fail closed: %v", err)
	}
	if _, err := service.IngestFalco(
		context.Background(),
		falcoIngestFixture(),
	); err == nil {
		t.Fatal("Falco ingest admitted while state persistence was failing")
	}
	persistedAfter, err := loadObserverState(state.path)
	if err != nil {
		t.Fatal(err)
	}
	if persistedAfter.ReconcileRequired ||
		persistedAfter.LastSequence != persistedBefore.LastSequence {
		t.Fatalf(
			"pre-rename error changed durable observer state: before=%+v after=%+v",
			persistedBefore,
			persistedAfter,
		)
	}

	state.persist = originalPersist
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	if state.Snapshot().ReconcileRequired || inventory.ReconcileGapOpen() {
		t.Fatalf(
			"startup retry did not recover fences: state=%+v gap=%v",
			state.Snapshot(),
			inventory.ReconcileGapOpen(),
		)
	}
}

type recordingRuntimeServer struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func (server *recordingRuntimeServer) Serve() error {
	<-server.closed
	return http.ErrServerClosed
}

func (server *recordingRuntimeServer) Close() error {
	server.closeOnce.Do(func() { close(server.closed) })
	return nil
}

type recordedListener struct {
	path    string
	mode    os.FileMode
	gid     int
	maxBody int64
	handler http.Handler
}

func TestDaemonRunReconcilesAndOwnsThreeSeparatedUDSServers(t *testing.T) {
	service, _, _, inventory, docker := observerServiceFixture(t)
	runDir := filepath.Join(inventoryTempDir(t), "run")
	service.daemon.config = Config{
		SchemaVersion:             "agmind.observer-config.v1",
		HostIDFile:                "/var/lib/agmind-sais/identity/host-id",
		PrivateKeyFile:            "/etc/agmind-sais/secrets/observer.key",
		StateDir:                  filepath.Dir(inventory.path),
		RunDir:                    runDir,
		SpoolMaxBytes:             4 * 1024 * 1024,
		SpoolPriorityReserveBytes: 1024 * 1024,
	}
	messages := make(chan events.Message)
	eventErrors := make(chan error)
	docker.eventsResult = &DockerEventStream{
		Messages: messages,
		Err:      eventErrors,
	}
	scripted := &scriptedDockerReader{
		fakeDockerReader: docker,
		eventResults: []DockerEventStream{{
			Messages: messages,
			Err:      eventErrors,
		}},
	}
	var mutex sync.Mutex
	recorded := make([]recordedListener, 0, 3)
	threeReady := make(chan struct{})
	var readyOnce sync.Once
	options := observerRuntimeOptions{
		openDocker: func() (DockerReader, io.Closer, error) {
			return scripted, io.NopCloser(bytes.NewReader(nil)), nil
		},
		processes: fakeProcessIdentityReader{
			byPID: map[int]processIdentity{
				4242: validProcessIdentity(),
			},
		},
		groupID: func(name string) (uint32, error) {
			switch name {
			case "agmind-sensor":
				return 2001, nil
			case "agmind-core":
				return 2002, nil
			default:
				return 0, errors.New("unexpected group")
			}
		},
		userID: func(name string) (uint32, error) {
			if name != "agmind-core" {
				return 0, errors.New("unexpected user")
			}
			return 1002, nil
		},
		listen: func(
			path string,
			mode os.FileMode,
			gid int,
			maxBody int64,
			handler http.Handler,
		) (observerRuntimeServer, error) {
			mutex.Lock()
			recorded = append(recorded, recordedListener{
				path:    path,
				mode:    mode,
				gid:     gid,
				maxBody: maxBody,
				handler: handler,
			})
			if len(recorded) == 3 {
				readyOnce.Do(func() { close(threeReady) })
			}
			mutex.Unlock()
			return &recordingRuntimeServer{
				closed: make(chan struct{}),
			}, nil
		},
		now: service.now,
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- service.daemon.runWithOptions(ctx, options)
	}()
	select {
	case <-threeReady:
	case <-time.After(2 * time.Second):
		t.Fatal("three observer sockets were not created")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observer runtime did not stop")
	}

	mutex.Lock()
	got := append([]recordedListener{}, recorded...)
	mutex.Unlock()
	sort.Slice(got, func(left, right int) bool {
		return got[left].path < got[right].path
	})
	want := []recordedListener{
		{
			path:    filepath.Join(runDir, "observer-actuator", "socket"),
			mode:    0o600,
			gid:     0,
			maxBody: 65_536,
		},
		{
			path:    filepath.Join(runDir, "observer-core", "socket"),
			mode:    0o660,
			gid:     2002,
			maxBody: 65_536,
		},
		{
			path:    filepath.Join(runDir, "observer-ingest", "socket"),
			mode:    0o660,
			gid:     2001,
			maxBody: 65_536,
		},
	}
	for index := range want {
		if got[index].path != want[index].path ||
			got[index].mode != want[index].mode ||
			got[index].gid != want[index].gid ||
			got[index].maxBody != want[index].maxBody ||
			got[index].handler == nil {
			t.Fatalf("listener[%d]=%+v want=%+v", index, got[index], want[index])
		}
		response := httptest.NewRecorder()
		got[index].handler.ServeHTTP(
			response,
			httptest.NewRequest(
				http.MethodPost,
				"http://unix/v1/events/retention-tombstone",
				nil,
			),
		)
		wantRouteStatus := http.StatusNotFound
		if got[index].path == filepath.Join(
			runDir,
			"observer-core",
			"socket",
		) {
			wantRouteStatus = http.StatusForbidden
		}
		if response.Code != wantRouteStatus {
			t.Fatalf(
				"listener %s tombstone route status=%d want=%d",
				got[index].path,
				response.Code,
				wantRouteStatus,
			)
		}
	}
	persistedInventory, err := loadInventoryState(inventory.path)
	if err != nil {
		t.Fatal(err)
	}
	if service.daemon.ReconcileRequired() ||
		persistedInventory.Generation != 1 {
		t.Fatalf(
			"startup reconcile state=%+v generation=%d",
			service.daemon.state.Snapshot(),
			persistedInventory.Generation,
		)
	}
	contexts, listEventCounts := scripted.eventSnapshot()
	if len(contexts) != 1 ||
		len(listEventCounts) == 0 ||
		listEventCounts[0] != 1 {
		t.Fatalf(
			"startup ordering subscriptions=%d list_event_counts=%v",
			len(contexts),
			listEventCounts,
		)
	}
	select {
	case <-contexts[0].Done():
	default:
		t.Fatal("runtime shutdown did not cancel Docker event session")
	}
}

func TestDaemonRunFailsBeforeBindingWhenIdentityResolutionFails(t *testing.T) {
	service, _, _, inventory, docker := observerServiceFixture(t)
	service.daemon.config = Config{
		SchemaVersion:             "agmind.observer-config.v1",
		HostIDFile:                "/var/lib/agmind-sais/identity/host-id",
		PrivateKeyFile:            "/etc/agmind-sais/secrets/observer.key",
		StateDir:                  filepath.Dir(inventory.path),
		RunDir:                    filepath.Join(inventoryTempDir(t), "run"),
		SpoolMaxBytes:             4 * 1024 * 1024,
		SpoolPriorityReserveBytes: 1024 * 1024,
	}
	listenCalled := false
	err := service.daemon.runWithOptions(
		context.Background(),
		observerRuntimeOptions{
			openDocker: func() (DockerReader, io.Closer, error) {
				return docker, io.NopCloser(bytes.NewReader(nil)), nil
			},
			processes: fakeProcessIdentityReader{
				byPID: map[int]processIdentity{
					4242: validProcessIdentity(),
				},
			},
			groupID: func(string) (uint32, error) {
				return 0, errors.New("missing service group")
			},
			userID: func(string) (uint32, error) {
				return 0, nil
			},
			listen: func(
				string,
				os.FileMode,
				int,
				int64,
				http.Handler,
			) (observerRuntimeServer, error) {
				listenCalled = true
				return nil, nil
			},
			now: service.now,
		},
	)
	if err == nil || listenCalled {
		t.Fatalf("err=%v listen_called=%v", err, listenCalled)
	}
}
