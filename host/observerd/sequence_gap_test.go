package observerd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"github.com/moby/moby/api/types/events"
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
