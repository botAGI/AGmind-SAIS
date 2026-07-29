package observerd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

func signSequenceGapProofForTest(
	t *testing.T,
	signer *EnvelopeSigner,
	severity string,
	openedAt time.Time,
	closedAt *time.Time,
	start uint64,
	end uint64,
	reason string,
	generation uint64,
) contracts.EventEnvelopeV1 {
	t.Helper()
	fields := map[string]any{
		"component":                      "observer",
		"kind":                           "observer_sequence_gap",
		"severity":                       severity,
		"opened_at":                      openedAt.UTC().Format(time.RFC3339Nano),
		"affected_source_sequence_start": start,
		"affected_source_sequence_end":   end,
		"reason_code":                    reason,
	}
	eventTime := openedAt
	if closedAt != nil {
		fields["closed_at"] = closedAt.UTC().Format(time.RFC3339Nano)
		fields["reconcile_generation"] = generation
		eventTime = *closedAt
	}
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	event, err := signer.Wrap(
		context.Background(),
		"coverage",
		fields,
		EventMetadata{
			EventTime:           eventTime,
			InventoryGeneration: generation,
			RedactionFlags:      []string{},
			CoverageFlags: []string{
				"reconcile_required",
				"sequence_gap",
			},
			SourcePayloadHash: hex.EncodeToString(sum[:]),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func reserveUnpublishedSequenceForTest(
	t *testing.T,
	signer *EnvelopeSigner,
) {
	t.Helper()
	if _, err := signer.Wrap(
		context.Background(),
		"falco_connect",
		map[string]any{"invalid_number": 1.5},
		metadata(),
	); err == nil {
		t.Fatal("expected post-reservation normalization failure")
	}
}

func rewriteObserverStateAsV2ForTest(
	t *testing.T,
	path string,
	state ObserverState,
) {
	rewriteObserverStateAsLegacyForTest(
		t,
		path,
		state,
		observerStateSchemaV2,
		nil,
	)
}

func rewriteObserverStateAsLegacyForTest(
	t *testing.T,
	path string,
	state ObserverState,
	schema string,
	mutate func(map[string]any),
) {
	t.Helper()
	raw, err := contracts.CanonicalJSON(state)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	value["schema_version"] = schema
	delete(value, "sequence_gap_protocol")
	if schema == observerStateSchemaV1 {
		delete(value, "boot_boundary_state")
		delete(value, "pending_boot_boundary")
		if history, ok := value["boot_history"].([]any); ok {
			for _, entry := range history {
				if boundary, ok := entry.(map[string]any); ok {
					delete(boundary, "boundary_event_id")
					delete(boundary, "boundary_event_type")
				}
			}
		}
	}
	if mutate != nil {
		mutate(value)
	}
	legacy, err := contracts.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := durablefile.AtomicWrite(path, legacy); err != nil {
		t.Fatal(err)
	}
}

type c8BootstrapFixture struct {
	configPath string
	config     Config
	options    []BootstrapOption
	daemon     *Daemon
}

func newC8BootstrapFixture(t *testing.T) *c8BootstrapFixture {
	t.Helper()
	configPath, config, _, _ := rotationFixture(t)
	fixture := &c8BootstrapFixture{
		configPath: configPath,
		config:     config,
		options: []BootstrapOption{
			WithBootstrapBootID(func() (string, error) {
				return testBootID, nil
			}),
			WithBootstrapNow(func() time.Time {
				return time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)
			}),
		},
	}
	fixture.bootstrap(t)
	return fixture
}

func (fixture *c8BootstrapFixture) close(t *testing.T) {
	t.Helper()
	if fixture.daemon != nil {
		if err := fixture.daemon.Close(); err != nil {
			t.Fatal(err)
		}
		fixture.daemon = nil
	}
}

func (fixture *c8BootstrapFixture) bootstrap(t *testing.T) {
	t.Helper()
	daemon, err := Bootstrap(
		context.Background(),
		fixture.configPath,
		fixture.options...,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.daemon = daemon
}

func (fixture *c8BootstrapFixture) openPhysicalGap(t *testing.T) {
	t.Helper()
	reserveUnpublishedSequenceForTest(t, fixture.daemon.signer)
	fixture.close(t)
	fixture.bootstrap(t)
}

func (fixture *c8BootstrapFixture) closeGapsAndAck(t *testing.T) {
	t.Helper()
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	now := func() time.Time {
		return time.Date(2026, 7, 29, 8, 1, 0, 0, time.UTC)
	}
	inventory, err := openInventory(
		fixture.config.StateDir,
		docker,
		fakeProcessIdentityReader{
			byPID: map[int]processIdentity{4242: validProcessIdentity()},
		},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	service := newObserverService(fixture.daemon, inventory, docker, now)
	docker.eventsResult = &DockerEventStream{
		Messages: make(chan events.Message),
		Err:      make(chan error),
	}
	baseline := inventory.Generation()
	receipt, err := service.recoverDockerWithSubscribedSessionReceipt(
		context.Background(),
		"observer_startup",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.closeOutstandingSequenceGaps(
		context.Background(),
		baseline,
		receipt,
	); err != nil {
		t.Fatal(err)
	}
	service.closeDockerEventSession()
	items, err := fixture.daemon.spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if err := fixture.daemon.spool.Ack(
			item.Sequence,
			item.EventID,
			item.ContentSHA256,
		); err != nil {
			t.Fatal(err)
		}
	}
}

func dockerGapFixture(
	t *testing.T,
) (*Service, *StateStore, *Spool, *Inventory, *fakeDockerReader) {
	return dockerGapFixtureAt(
		t,
		time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
	)
}

func dockerGapFixtureAt(
	t *testing.T,
	openedAt time.Time,
) (*Service, *StateStore, *Spool, *Inventory, *fakeDockerReader) {
	t.Helper()
	service, state, spool, inventory, docker := observerServiceFixture(t)
	reserveUnpublishedSequenceForTest(t, service.daemon.signer)
	signSequenceGapProofForTest(
		t,
		service.daemon.signer,
		"CRITICAL",
		openedAt,
		nil,
		1,
		1,
		"reserved_sequence_not_published",
		0,
	)
	if err := state.markGapCovered(1); err != nil {
		t.Fatal(err)
	}
	return service, state, spool, inventory, docker
}

func gapRuntimeOptions(
	docker DockerReader,
	now func() time.Time,
	listenCalled *bool,
) observerRuntimeOptions {
	return observerRuntimeOptions{
		openDocker: func() (DockerReader, io.Closer, error) {
			return docker, io.NopCloser(bytes.NewReader(nil)), nil
		},
		processes: fakeProcessIdentityReader{
			byPID: map[int]processIdentity{4242: validProcessIdentity()},
		},
		groupID: func(name string) (uint32, error) {
			if name == "agmind-sensor" {
				return 2001, nil
			}
			return 2002, nil
		},
		userID: func(string) (uint32, error) { return 1002, nil },
		listen: func(
			string,
			os.FileMode,
			int,
			int64,
			http.Handler,
		) (observerRuntimeServer, error) {
			*listenCalled = true
			return nil, errors.New("listener must not be reached")
		},
		now: now,
	}
}

func requireNoCoverageKind(t *testing.T, spool *Spool, kinds ...string) {
	t.Helper()
	rejected := make(map[string]bool, len(kinds))
	for _, kind := range kinds {
		rejected[kind] = true
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
		kind, _ := event.NormalizedFields["kind"].(string)
		if rejected[kind] &&
			(kind != "observer_sequence_gap" ||
				event.NormalizedFields["severity"] == "INFO") {
			t.Fatalf("unexpected coverage kind %q", kind)
		}
	}
}

func TestSequenceGapOpenRecoveryIsExactAndIdempotent(t *testing.T) {
	root := t.TempDir()
	state, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		testKey(t, 201),
	)
	defer spool.Close()
	reserveUnpublishedSequenceForTest(t, signer)
	signSequenceGapProofForTest(
		t,
		signer,
		"CRITICAL",
		time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC),
		nil,
		1,
		1,
		"reserved_sequence_not_published",
		0,
	)

	if got := state.Snapshot().LastCoveredGapEnd; got != 0 {
		t.Fatalf("fixture unexpectedly persisted marker=%d", got)
	}
	if err := spool.recoverSequenceGapMarkers(); err != nil {
		t.Fatal(err)
	}
	if got := state.Snapshot().LastCoveredGapEnd; got != 1 {
		t.Fatalf("recovered marker=%d want=1", got)
	}
	before := state.Snapshot().LastSequence
	if err := spool.recoverSequenceGapMarkers(); err != nil {
		t.Fatal(err)
	}
	if after := state.Snapshot(); after.LastCoveredGapEnd != 1 ||
		after.LastSequence != before ||
		after.MutationReadOnly {
		t.Fatalf("idempotent recovery mutated state: %+v", after)
	}
}

func TestBootstrapRecoversDurableOpenMarkerBeforePublishingDuplicate(
	t *testing.T,
) {
	configPath, _, _, _ := rotationFixture(t)
	options := []BootstrapOption{
		WithBootstrapBootID(func() (string, error) {
			return testBootID, nil
		}),
		WithBootstrapNow(func() time.Time {
			return time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)
		}),
	}
	daemon, err := Bootstrap(context.Background(), configPath, options...)
	if err != nil {
		t.Fatal(err)
	}
	reserveUnpublishedSequenceForTest(t, daemon.signer)
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}
	daemon, err = Bootstrap(context.Background(), configPath, options...)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := daemon.spool.scanSequenceGapProofs()
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Opens) != 1 {
		t.Fatalf("gap opens=%d want=1", len(scan.Opens))
	}
	open := scan.Opens[0]
	daemon.state.mutex.Lock()
	next := cloneObserverState(daemon.state.state)
	next.LastCoveredGapEnd = open.Start - 1
	err = daemon.state.replaceLocked(next)
	daemon.state.mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}

	daemon, err = Bootstrap(context.Background(), configPath, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	recovered, err := daemon.spool.scanSequenceGapProofs()
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.Opens) != 1 ||
		daemon.state.Snapshot().LastCoveredGapEnd != open.End {
		t.Fatalf(
			"restart duplicated open or missed marker: opens=%d state=%+v",
			len(recovered.Opens),
			daemon.state.Snapshot(),
		)
	}
}

func TestC8ActivationDistinguishesLegacyMarkerFromCleanedHistory(
	t *testing.T,
) {
	fixture := newC8BootstrapFixture(t)
	fixture.openPhysicalGap(t)
	fixture.closeGapsAndAck(t)
	activated := fixture.daemon.state.Snapshot()
	if activated.SequenceGapProtocol != sequenceGapProtocolC8 {
		t.Fatalf("activation proof unavailable: %+v", activated)
	}

	t.Run("activated cleaned history", func(t *testing.T) {
		fixture.close(t)
		fixture.bootstrap(t)
		fixture.close(t)
	})

	// A second gap leaves an authenticated tail open, but a raw V2 predecessor
	// cannot prove that the ACK-cleaned prefix was protected by C8.
	fixture.bootstrap(t)
	fixture.openPhysicalGap(t)
	scan, err := fixture.daemon.spool.scanSequenceGapProofs()
	if err != nil || len(scan.Opens) != 1 {
		t.Fatalf("retained tail scan=%+v err=%v", scan, err)
	}
	legacy := fixture.daemon.state.Snapshot()
	fixture.close(t)
	statePath := filepath.Join(fixture.config.StateDir, "observer-state.json")
	rewriteObserverStateAsV2ForTest(t, statePath, legacy)
	fixture.bootstrap(t)
	snapshot := fixture.daemon.state.Snapshot()
	if !fixture.daemon.MutationReadOnly() ||
		snapshot.SequenceGapProtocol != sequenceGapProtocolLegacyUnproven ||
		snapshot.ReadOnlyReason != "observer_sequence_gap_enrollment_required" ||
		fixture.daemon.signer != nil {
		t.Fatalf("legacy marker-only state was auto-enrolled: %+v", snapshot)
	}
	openCalled, listenCalled := false, false
	runtimeOptions := defaultObserverRuntimeOptions()
	runtimeOptions.openDocker = func() (DockerReader, io.Closer, error) {
		openCalled = true
		return nil, nil, errors.New("must not open Docker")
	}
	runtimeOptions.listen = func(
		string,
		os.FileMode,
		int,
		int64,
		http.Handler,
	) (observerRuntimeServer, error) {
		listenCalled = true
		return nil, errors.New("must not listen")
	}
	if err := fixture.daemon.runWithOptions(
		context.Background(),
		runtimeOptions,
	); err == nil || openCalled || listenCalled {
		t.Fatalf("legacy runtime err=%v open=%v listen=%v", err, openCalled, listenCalled)
	}
	fixture.close(t)
	persisted, err := loadObserverState(statePath)
	if err != nil ||
		!persisted.MutationReadOnly ||
		persisted.SequenceGapProtocol != sequenceGapProtocolLegacyUnproven {
		t.Fatalf("persisted enrollment fence=%+v err=%v", persisted, err)
	}
}

func TestC8ActivationMigratesZeroMarkerV2BeforePublishing(t *testing.T) {
	fixture := newC8BootstrapFixture(t)
	state := fixture.daemon.state.Snapshot()
	if state.LastCoveredGapEnd != 0 {
		t.Fatalf("greenfield fixture has marker=%d", state.LastCoveredGapEnd)
	}
	fixture.close(t)
	statePath := filepath.Join(fixture.config.StateDir, "observer-state.json")
	rewriteObserverStateAsV2ForTest(t, statePath, state)
	fixture.bootstrap(t)
	defer fixture.close(t)
	activated := fixture.daemon.state.Snapshot()
	if activated.SchemaVersion != observerStateSchema ||
		activated.SequenceGapProtocol != sequenceGapProtocolC8 ||
		activated.MutationReadOnly {
		t.Fatalf("zero-marker V2 did not activate safely: %+v", activated)
	}
}

func TestC8MigrationRejectsInvalidAndPreservesExistingFence(
	t *testing.T,
) {
	for _, testCase := range []struct {
		name            string
		schema          string
		existingFence   string
		wantFence       string
		clearFence      bool
		invalidMutation func(map[string]any)
	}{
		{
			name:   "invalid V2 is not laundered",
			schema: observerStateSchemaV2,
			invalidMutation: func(value map[string]any) {
				value["mutation_read_only"] = false
				value["read_only_reason"] = "inconsistent_preexisting_reason"
			},
		},
		{
			name:   "invalid V1 is not laundered",
			schema: observerStateSchemaV1,
			invalidMutation: func(value map[string]any) {
				value["mutation_read_only"] = false
				value["read_only_reason"] = "inconsistent_preexisting_reason"
			},
		},
		{
			name:          "existing fence is preserved",
			schema:        observerStateSchemaV2,
			existingFence: "observer_existing_fence",
			wantFence:     "observer_existing_fence",
		},
		{
			name:      "V1 marker creates boot fence",
			schema:    observerStateSchemaV1,
			wantFence: "observer_legacy_boot_boundary_unproven",
		},
		{
			name:          "V1 marker preserves rotation fence",
			schema:        observerStateSchemaV1,
			existingFence: "observer_rotation_incomplete",
			wantFence:     "observer_rotation_incomplete",
			clearFence:    true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newC8BootstrapFixture(t)
			fixture.openPhysicalGap(t)
			if testCase.existingFence != "" {
				if err := fixture.daemon.state.PersistReadOnly(
					testCase.existingFence,
				); err != nil {
					t.Fatal(err)
				}
			}
			state := fixture.daemon.state.Snapshot()
			statePath := filepath.Join(fixture.config.StateDir, "observer-state.json")
			fixture.close(t)
			rewriteObserverStateAsLegacyForTest(
				t,
				statePath,
				state,
				testCase.schema,
				testCase.invalidMutation,
			)

			restarted, restartErr := Bootstrap(
				context.Background(),
				fixture.configPath,
				fixture.options...,
			)
			if testCase.invalidMutation != nil {
				if restartErr == nil || restarted != nil {
					t.Fatalf(
						"invalid V2 was laundered: daemon=%v err=%v",
						restarted,
						restartErr,
					)
				}
				raw, err := os.ReadFile(statePath)
				if err != nil {
					t.Fatal(err)
				}
				var header struct {
					SchemaVersion string `json:"schema_version"`
				}
				if err := json.Unmarshal(raw, &header); err != nil {
					t.Fatal(err)
				}
				if header.SchemaVersion != testCase.schema {
					t.Fatalf("invalid predecessor was rewritten as %s", header.SchemaVersion)
				}
				return
			}
			if restartErr != nil || restarted == nil {
				t.Fatalf("existing fence restart=%v err=%v", restarted, restartErr)
			}
			defer restarted.Close()
			persisted := restarted.state.Snapshot()
			if persisted.SequenceGapProtocol !=
				sequenceGapProtocolLegacyUnproven ||
				!persisted.MutationReadOnly ||
				persisted.ReadOnlyReason != testCase.wantFence {
				t.Fatalf("existing fence was not preserved: %+v", persisted)
			}
			if testCase.clearFence {
				if err := restarted.state.clearRotationFence(); err == nil {
					t.Fatal("legacy sequence-gap protocol cleared rotation fence")
				}
				after := restarted.state.Snapshot()
				if !after.MutationReadOnly ||
					after.ReadOnlyReason != testCase.wantFence ||
					after.SequenceGapProtocol != sequenceGapProtocolLegacyUnproven {
					t.Fatalf("failed clear mutated legacy fence: %+v", after)
				}
			}
		})
	}
}

func TestSequenceGapOpenRecoveryRejectsDuplicateOverlapAndConflict(
	t *testing.T,
) {
	tests := []struct {
		name  string
		build func(*testing.T, *EnvelopeSigner)
	}{
		{
			name: "duplicate",
			build: func(t *testing.T, signer *EnvelopeSigner) {
				reserveUnpublishedSequenceForTest(t, signer)
				for range 2 {
					signSequenceGapProofForTest(
						t,
						signer,
						"CRITICAL",
						time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC),
						nil,
						1,
						1,
						"reserved_sequence_not_published",
						0,
					)
				}
			},
		},
		{
			name: "overlap",
			build: func(t *testing.T, signer *EnvelopeSigner) {
				reserveUnpublishedSequenceForTest(t, signer)
				reserveUnpublishedSequenceForTest(t, signer)
				signSequenceGapProofForTest(
					t,
					signer,
					"CRITICAL",
					time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC),
					nil,
					1,
					2,
					"reserved_sequence_not_published",
					0,
				)
				signSequenceGapProofForTest(
					t,
					signer,
					"CRITICAL",
					time.Date(2026, 7, 29, 8, 0, 1, 0, time.UTC),
					nil,
					2,
					2,
					"reserved_sequence_not_published",
					0,
				)
			},
		},
		{
			name: "conflicting form",
			build: func(t *testing.T, signer *EnvelopeSigner) {
				reserveUnpublishedSequenceForTest(t, signer)
				signSequenceGapProofForTest(
					t,
					signer,
					"WARNING",
					time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC),
					nil,
					1,
					1,
					"reserved_sequence_not_published",
					0,
				)
			},
		},
	}
	for index, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				testKey(t, byte(210+index)),
			)
			defer spool.Close()
			testCase.build(t, signer)

			err := spool.recoverSequenceGapMarkers()
			if !errors.Is(err, ErrSpoolCorrupt) {
				t.Fatalf("recovery err=%v want=%v", err, ErrSpoolCorrupt)
			}
			snapshot := state.Snapshot()
			if !snapshot.MutationReadOnly ||
				snapshot.ReadOnlyReason != "observer_sequence_gap_proof_conflict" ||
				snapshot.LastCoveredGapEnd != 0 {
				t.Fatalf("conflict did not fail closed: %+v", snapshot)
			}
		})
	}
}

func TestSequenceGapScanFencesPostOpenFrameAndPublicationTamper(
	t *testing.T,
) {
	for _, target := range []string{"frame", "publication"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			state, spool, signer := openSignerFixture(
				t,
				root,
				testBootID,
				testKey(t, 230),
			)
			defer spool.Close()
			reserveUnpublishedSequenceForTest(t, signer)
			open := signSequenceGapProofForTest(
				t,
				signer,
				"CRITICAL",
				time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC),
				nil,
				1,
				1,
				"reserved_sequence_not_published",
				0,
			)
			item := spool.items[open.SourceSequence]
			path := item.path
			if target == "publication" {
				path = item.publicationPath
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)-1] ^= 1
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}

			err = spool.recoverSequenceGapMarkers()
			if !errors.Is(err, ErrSpoolCorrupt) {
				t.Fatalf("tamper err=%v want=%v", err, ErrSpoolCorrupt)
			}
			snapshot := state.Snapshot()
			if !snapshot.MutationReadOnly ||
				snapshot.ReadOnlyReason !=
					"observer_sequence_gap_proof_conflict" {
				t.Fatalf("tamper did not fence mutation: %+v", snapshot)
			}
		})
	}
}

func TestStartupSequenceGapCloseUsesExactReceiptOnce(t *testing.T) {
	service, state, spool, inventory, docker := observerServiceFixture(t)
	t.Cleanup(service.closeDockerEventSession)
	reserveUnpublishedSequenceForTest(t, service.daemon.signer)
	openedAt := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	open := signSequenceGapProofForTest(
		t,
		service.daemon.signer,
		"CRITICAL",
		openedAt,
		nil,
		1,
		1,
		"reserved_sequence_not_published",
		0,
	)
	if err := state.markGapCovered(1); err != nil {
		t.Fatal(err)
	}
	messages := make(chan events.Message)
	eventErrors := make(chan error)
	docker.eventsResult = &DockerEventStream{
		Messages: messages,
		Err:      eventErrors,
	}
	baseline := inventory.Generation()
	receipt, err := service.recoverDockerWithSubscribedSessionReceipt(
		context.Background(),
		"observer_startup",
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Generation <= baseline ||
		receipt.SourceSequence <= open.SourceSequence ||
		receipt.ClosedAt == "" {
		t.Fatalf("invalid recovery receipt: %+v baseline=%d", receipt, baseline)
	}
	if err := service.closeOutstandingSequenceGaps(
		context.Background(),
		receipt.Generation,
		receipt,
	); err == nil {
		t.Fatal("stale baseline accepted recovery receipt")
	}
	staleScan, err := spool.scanSequenceGapProofs()
	if err != nil {
		t.Fatal(err)
	}
	if len(staleScan.Unpaired) != 1 || len(staleScan.Closes) != 0 {
		t.Fatalf("stale receipt published a close: %+v", staleScan)
	}
	if err := service.closeOutstandingSequenceGaps(
		context.Background(),
		baseline,
		receipt,
	); err != nil {
		t.Fatal(err)
	}
	firstScan, err := spool.scanSequenceGapProofs()
	if err != nil {
		t.Fatal(err)
	}
	if len(firstScan.Unpaired) != 0 || len(firstScan.Closes) != 1 {
		t.Fatalf("first close scan=%+v", firstScan)
	}
	closeProof := firstScan.Closes[0]
	if closeProof.Start != 1 ||
		closeProof.End != 1 ||
		closeProof.OpenedAt != openedAt.Format(time.RFC3339Nano) ||
		closeProof.ClosedAt != receipt.ClosedAt ||
		closeProof.Generation != receipt.Generation {
		t.Fatalf("close=%+v receipt=%+v", closeProof, receipt)
	}

	before := state.Snapshot().LastSequence
	if err := service.closeOutstandingSequenceGaps(
		context.Background(),
		baseline,
		receipt,
	); err != nil {
		t.Fatal(err)
	}
	secondScan, err := spool.scanSequenceGapProofs()
	if err != nil {
		t.Fatal(err)
	}
	if state.Snapshot().LastSequence != before ||
		len(secondScan.Unpaired) != 0 ||
		len(secondScan.Closes) != 1 {
		t.Fatalf(
			"idempotent close mutated sequence/proofs: before=%d state=%+v scan=%+v",
			before,
			state.Snapshot(),
			secondScan,
		)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Sequence >= secondScan.Closes[0].SourceSequence {
			break
		}
		if err := spool.Ack(
			item.Sequence,
			item.EventID,
			item.ContentSHA256,
		); err != nil {
			t.Fatalf("Ack(%d) err=%v", item.Sequence, err)
		}
	}
	orphanCloseScan, err := spool.scanSequenceGapProofs()
	if err != nil {
		t.Fatal(err)
	}
	if len(orphanCloseScan.Opens) != 0 ||
		len(orphanCloseScan.Closes) != 1 ||
		len(orphanCloseScan.Unpaired) != 0 {
		t.Fatalf("monotonic cleanup invalidated orphan close: %+v", orphanCloseScan)
	}
}

func TestSequenceGapCloseRejectsConflictMatrix(t *testing.T) {
	tests := []struct {
		name  string
		build func(
			*testing.T,
			*EnvelopeSigner,
			time.Time,
			dockerReconcileReceipt,
		)
	}{
		{
			name: "wrong range",
			build: func(
				t *testing.T,
				signer *EnvelopeSigner,
				openedAt time.Time,
				receipt dockerReconcileReceipt,
			) {
				closedAt, _ := time.Parse(time.RFC3339Nano, receipt.ClosedAt)
				signSequenceGapProofForTest(
					t,
					signer,
					"INFO",
					openedAt,
					&closedAt,
					1,
					2,
					"reserved_sequence_reconciled",
					receipt.Generation,
				)
			},
		},
		{
			name: "wrong opened time",
			build: func(
				t *testing.T,
				signer *EnvelopeSigner,
				openedAt time.Time,
				receipt dockerReconcileReceipt,
			) {
				closedAt, _ := time.Parse(time.RFC3339Nano, receipt.ClosedAt)
				signSequenceGapProofForTest(
					t,
					signer,
					"INFO",
					openedAt.Add(time.Second),
					&closedAt,
					1,
					1,
					"reserved_sequence_reconciled",
					receipt.Generation,
				)
			},
		},
		{
			name: "wrong generation",
			build: func(
				t *testing.T,
				signer *EnvelopeSigner,
				openedAt time.Time,
				receipt dockerReconcileReceipt,
			) {
				closedAt, _ := time.Parse(time.RFC3339Nano, receipt.ClosedAt)
				signSequenceGapProofForTest(
					t,
					signer,
					"INFO",
					openedAt,
					&closedAt,
					1,
					1,
					"reserved_sequence_reconciled",
					receipt.Generation+1,
				)
			},
		},
		{
			name: "duplicate",
			build: func(
				t *testing.T,
				signer *EnvelopeSigner,
				openedAt time.Time,
				receipt dockerReconcileReceipt,
			) {
				closedAt, _ := time.Parse(time.RFC3339Nano, receipt.ClosedAt)
				for range 2 {
					signSequenceGapProofForTest(
						t,
						signer,
						"INFO",
						openedAt,
						&closedAt,
						1,
						1,
						"reserved_sequence_reconciled",
						receipt.Generation,
					)
				}
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			service, state, _, _, docker := observerServiceFixture(t)
			t.Cleanup(service.closeDockerEventSession)
			reserveUnpublishedSequenceForTest(t, service.daemon.signer)
			openedAt := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
			signSequenceGapProofForTest(
				t,
				service.daemon.signer,
				"CRITICAL",
				openedAt,
				nil,
				1,
				1,
				"reserved_sequence_not_published",
				0,
			)
			if err := state.markGapCovered(1); err != nil {
				t.Fatal(err)
			}
			docker.eventsResult = &DockerEventStream{
				Messages: make(chan events.Message),
				Err:      make(chan error),
			}
			receipt, err := service.recoverDockerWithSubscribedSessionReceipt(
				context.Background(),
				"observer_startup",
			)
			if err != nil {
				t.Fatal(err)
			}
			testCase.build(t, service.daemon.signer, openedAt, receipt)
			err = service.closeOutstandingSequenceGaps(
				context.Background(),
				0,
				receipt,
			)
			if !errors.Is(err, ErrSpoolCorrupt) {
				t.Fatalf("conflicting close err=%v", err)
			}
			snapshot := state.Snapshot()
			if !snapshot.MutationReadOnly ||
				snapshot.ReadOnlyReason !=
					"observer_sequence_gap_proof_conflict" {
				t.Fatalf("conflicting close did not fence mutation: %+v", snapshot)
			}
		})
	}
}

func TestStartupReconcileFailurePublishesNoSequenceCloseOrListener(
	t *testing.T,
) {
	service, state, spool, inventory, docker := observerServiceFixture(t)
	service.daemon.config = Config{
		SchemaVersion:             "agmind.observer-config.v1",
		HostIDFile:                "/var/lib/agmind-sais/identity/host-id",
		PrivateKeyFile:            "/etc/agmind-sais/secrets/observer.key",
		StateDir:                  filepath.Dir(inventory.path),
		RunDir:                    t.TempDir(),
		SpoolMaxBytes:             4 * 1024 * 1024,
		SpoolPriorityReserveBytes: 1024 * 1024,
	}
	reserveUnpublishedSequenceForTest(t, service.daemon.signer)
	signSequenceGapProofForTest(
		t,
		service.daemon.signer,
		"CRITICAL",
		time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		nil,
		1,
		1,
		"reserved_sequence_not_published",
		0,
	)
	if err := state.markGapCovered(1); err != nil {
		t.Fatal(err)
	}
	messages := make(chan events.Message)
	eventErrors := make(chan error)
	docker.eventsResult = &DockerEventStream{
		Messages: messages,
		Err:      eventErrors,
	}
	injected := errors.New("injected startup reconcile failure")
	docker.listErr = injected
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
			groupID: func(name string) (uint32, error) {
				if name == "agmind-sensor" {
					return 2001, nil
				}
				return 2002, nil
			},
			userID: func(string) (uint32, error) {
				return 1002, nil
			},
			listen: func(
				string,
				os.FileMode,
				int,
				int64,
				http.Handler,
			) (observerRuntimeServer, error) {
				listenCalled = true
				return nil, errors.New("listener must not be reached")
			},
			now: service.now,
		},
	)
	if !errors.Is(err, injected) || listenCalled {
		t.Fatalf("startup err=%v listen_called=%v", err, listenCalled)
	}
	scan, scanErr := spool.scanSequenceGapProofs()
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	if len(scan.Unpaired) != 1 || len(scan.Closes) != 0 {
		t.Fatalf("failed reconcile changed sequence-gap pairing: %+v", scan)
	}
}

func TestReverseDockerRecoveryTimePublishesNoRecoveryCloseOrListener(
	t *testing.T,
) {
	service, _, spool, inventory, docker := dockerGapFixture(t)
	service.daemon.config = Config{
		SchemaVersion:             "agmind.observer-config.v1",
		HostIDFile:                "/var/lib/agmind-sais/identity/host-id",
		PrivateKeyFile:            "/etc/agmind-sais/secrets/observer.key",
		StateDir:                  filepath.Dir(inventory.path),
		RunDir:                    t.TempDir(),
		SpoolMaxBytes:             4 * 1024 * 1024,
		SpoolPriorityReserveBytes: 1024 * 1024,
	}
	docker.eventsResult = &DockerEventStream{
		Messages: make(chan events.Message),
		Err:      make(chan error),
	}
	var nowCalls int
	reverseNow := func() time.Time {
		nowCalls++
		if nowCalls < 3 {
			return time.Date(2026, 7, 27, 12, 2, 0, 0, time.UTC)
		}
		return time.Date(2026, 7, 27, 12, 1, 0, 0, time.UTC)
	}
	listenCalled := false
	err := service.daemon.runWithOptions(
		context.Background(),
		gapRuntimeOptions(docker, reverseNow, &listenCalled),
	)
	if err == nil || listenCalled {
		t.Fatalf("reverse recovery err=%v listen_called=%v", err, listenCalled)
	}
	requireNoCoverageKind(
		t,
		spool,
		"docker_reconcile_recovered",
		"observer_sequence_gap",
	)
}

func TestRecoveryBeforeSequenceGapReopensFenceWithoutPoisoningRetry(
	t *testing.T,
) {
	gapOpenedAt := time.Date(2026, 7, 27, 12, 2, 0, 0, time.UTC)
	service, state, spool, inventory, docker := dockerGapFixtureAt(
		t,
		time.Date(2026, 7, 27, 11, 59, 0, 0, time.UTC),
	)
	secondGap := state.Snapshot().LastSequence + 1
	reserveUnpublishedSequenceForTest(t, service.daemon.signer)
	signSequenceGapProofForTest(
		t,
		service.daemon.signer,
		"CRITICAL",
		gapOpenedAt,
		nil,
		secondGap,
		secondGap,
		"reserved_sequence_not_published",
		0,
	)
	if err := state.markGapCovered(secondGap); err != nil {
		t.Fatal(err)
	}
	service.daemon.config = Config{
		SchemaVersion:             "agmind.observer-config.v1",
		HostIDFile:                "/var/lib/agmind-sais/identity/host-id",
		PrivateKeyFile:            "/etc/agmind-sais/secrets/observer.key",
		StateDir:                  filepath.Dir(inventory.path),
		RunDir:                    t.TempDir(),
		SpoolMaxBytes:             4 * 1024 * 1024,
		SpoolPriorityReserveBytes: 1024 * 1024,
	}
	docker.eventsResult = &DockerEventStream{
		Messages: make(chan events.Message),
		Err:      make(chan error),
	}
	var nowCalls int
	recoveryBeforeGap := func() time.Time {
		nowCalls++
		if nowCalls == 1 {
			return time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
		}
		return time.Date(2026, 7, 27, 12, 1, 0, 0, time.UTC)
	}
	listenCalled := false
	err := service.daemon.runWithOptions(
		context.Background(),
		gapRuntimeOptions(docker, recoveryBeforeGap, &listenCalled),
	)
	if err == nil || errors.Is(err, ErrSpoolCorrupt) || listenCalled {
		t.Fatalf("preflight err=%v listen_called=%v", err, listenCalled)
	}
	scan, scanErr := spool.scanSequenceGapProofs()
	if scanErr != nil || len(scan.Unpaired) != 2 || len(scan.Closes) != 0 {
		t.Fatalf("preflight poisoned retained proofs: scan=%+v err=%v", scan, scanErr)
	}
	snapshot := state.Snapshot()
	if snapshot.MutationReadOnly ||
		snapshot.ReadOnlyReason != "" ||
		!snapshot.ReconcileRequired {
		t.Fatalf("preflight observer fence=%+v", snapshot)
	}
	persistedInventory, err := loadInventoryState(inventory.path)
	if err != nil || !persistedInventory.DockerReconcileGap {
		t.Fatalf("preflight inventory fence=%+v err=%v", persistedInventory, err)
	}
	requireNoCoverageKind(t, spool, "observer_sequence_gap")

	retryNow := func() time.Time {
		return time.Date(2026, 7, 27, 12, 4, 0, 0, time.UTC)
	}
	retryInventory, err := openInventory(
		service.daemon.config.StateDir,
		docker,
		fakeProcessIdentityReader{
			byPID: map[int]processIdentity{4242: validProcessIdentity()},
		},
		retryNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	retry := newObserverService(service.daemon, retryInventory, docker, retryNow)
	docker.eventsResult = &DockerEventStream{
		Messages: make(chan events.Message),
		Err:      make(chan error),
	}
	baseline := retryInventory.Generation()
	receipt, err := retry.recoverDockerWithSubscribedSessionReceipt(
		context.Background(),
		"observer_startup",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := retry.closeOutstandingSequenceGaps(
		context.Background(),
		baseline,
		receipt,
	); err != nil {
		t.Fatal(err)
	}
	retry.closeDockerEventSession()
	finalScan, err := spool.scanSequenceGapProofs()
	if err != nil ||
		len(finalScan.Unpaired) != 0 ||
		len(finalScan.Closes) != 2 ||
		state.Snapshot().ReconcileRequired ||
		retryInventory.ReconcileGapOpen() {
		t.Fatalf("valid retry scan=%+v state=%+v err=%v", finalScan, state.Snapshot(), err)
	}
}

func TestRetainedReverseDockerRecoveryFencesAuthenticatedProofScan(
	t *testing.T,
) {
	service, state, spool, _, _ := dockerGapFixture(t)
	openedAt := time.Date(2026, 7, 27, 12, 2, 0, 0, time.UTC)
	closedAt := time.Date(2026, 7, 27, 12, 1, 0, 0, time.UTC)
	if err := service.signDockerCoverage(
		context.Background(),
		"docker_reconcile_gap",
		"CRITICAL",
		"observer_startup",
		openedAt,
		nil,
		1,
	); err != nil {
		t.Fatal(err)
	}
	recovered, err := service.signDockerCoverageEnvelope(
		context.Background(),
		"docker_reconcile_recovered",
		"INFO",
		"docker_full_reconcile_succeeded",
		openedAt,
		&closedAt,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = service.closeOutstandingSequenceGaps(
		context.Background(),
		0,
		dockerReconcileReceipt{
			SourceSequence: recovered.SourceSequence,
			Generation:     1,
			ClosedAt:       recovered.EventTime,
			openedAt:       openedAt.Format(time.RFC3339Nano),
		},
	)
	if !errors.Is(err, ErrSpoolCorrupt) {
		t.Fatalf("reverse retained recovery err=%v", err)
	}
	snapshot := state.Snapshot()
	if !snapshot.MutationReadOnly ||
		snapshot.ReadOnlyReason != "observer_sequence_gap_proof_conflict" {
		t.Fatalf("reverse retained recovery did not fence: %+v", snapshot)
	}
	requireNoCoverageKind(t, spool, "observer_sequence_gap")
}
