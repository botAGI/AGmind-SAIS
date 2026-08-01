package observerd

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
)

type pccRestartFixture struct {
	service      *Service
	state        *StateStore
	spool        *Spool
	inventory    *Inventory
	docker       *fakeDockerReader
	request      contracts.PCCCorrelationSnapshotRequestV1
	root         string
	privateKey   ed25519.PrivateKey
	spoolConfig  SpoolConfig
	signerConfig SignerConfig
	decision     time.Time
}

func newPCCRestartFixture(t *testing.T) *pccRestartFixture {
	t.Helper()
	oldService, _, oldSpool, inventory, docker := observerServiceFixture(t)
	if err := oldService.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	trigger, err := oldService.IngestFalco(
		context.Background(),
		falcoIngestFixture(),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := pccRequestForItem(oldSpool.items[trigger.SourceSequence])
	root := oldSpool.config.StateDir
	privateKey := append(
		ed25519.PrivateKey(nil),
		oldService.daemon.signer.privateKey...,
	)
	if err := oldSpool.Close(); err != nil {
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
		time.Date(2026, 7, 29, 13, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatal(err)
	}
	decision := time.Date(
		2026, 7, 29, 13, 1, 0, 987654321, time.UTC,
	)
	daemon := &Daemon{state: state, spool: spool, signer: signer}
	return &pccRestartFixture{
		service: newObserverService(
			daemon,
			inventory,
			docker,
			func() time.Time { return decision },
		),
		state:        state,
		spool:        spool,
		inventory:    inventory,
		docker:       docker,
		request:      request,
		root:         root,
		privateKey:   privateKey,
		spoolConfig:  spool.config,
		signerConfig: signer.config,
		decision:     decision,
	}
}

func pccRestartChainForPath(
	t *testing.T,
	path string,
	dedicated []contracts.PCCBootTransitionHopV1,
) []contracts.PCCBootTransitionHopV1 {
	t.Helper()
	chain := append([]contracts.PCCBootTransitionHopV1{}, dedicated...)
	if path == "A" {
		return chain
	}
	hop := chain[0]
	companionType := "observer_key_epoch_start"
	companionBoot := hop.BootID
	companionSequence := hop.SourceSequence + 1
	if path == "B" {
		hop.BoundaryEventType = "observer_key_transition"
	} else {
		hop.BoundaryEventType = "observer_key_epoch_start"
		hop.PreviousSourceSequence--
		companionType = "observer_key_transition"
		companionBoot = hop.PreviousBootID
		companionSequence = hop.SourceSequence - 1
	}
	companionID := "evt_" + strings.Repeat(strings.ToLower(path), 64)
	companionHash := strings.Repeat(strings.ToLower(path), 64)
	hop.RotationCompanionEventType = &companionType
	hop.RotationCompanionEventID = &companionID
	hop.RotationCompanionContentSHA256 = &companionHash
	hop.RotationCompanionSourceSequence = &companionSequence
	hop.RotationCompanionBootID = &companionBoot
	chain[0] = hop
	if _, err := contracts.PCCBootTransitionChainSHA256(chain); err != nil {
		t.Fatalf("invalid synthetic authenticated path %s: %v", path, err)
	}
	return chain
}

func pccRestartBreakCoverage(t *testing.T, fixture *pccRestartFixture) {
	t.Helper()
	for sequence := range fixture.spool.items {
		if sequence < fixture.request.TriggerSourceSequence {
			delete(fixture.spool.items, sequence)
			return
		}
	}
	t.Fatal("no pre-trigger item available for coverage gap")
}

func pccRestartRetry(
	t *testing.T,
	fixture *pccRestartFixture,
	first PCCCorrelationPublication,
) {
	t.Helper()
	if err := fixture.spool.Close(); err != nil {
		t.Fatal(err)
	}
	identity := fixture.state.Snapshot()
	state, err := OpenStateStore(
		fixture.state.path,
		StateIdentity{
			HostID: identity.HostID, BootID: identity.BootID,
			KeyID: identity.KeyID, KeyEpoch: identity.KeyEpoch,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	spool, err := NewSpool(
		fixture.spoolConfig,
		state,
		pccArchiveKeyring(t, fixture.privateKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	signer, err := NewEnvelopeSigner(
		fixture.signerConfig,
		state,
		spool,
		fixture.privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	service := newObserverService(
		&Daemon{state: state, spool: spool, signer: signer},
		fixture.inventory,
		fixture.docker,
		func() time.Time { return fixture.decision },
	)
	calls := 0
	service.pccInventorySnapshot = func(string) (CorrelationInventorySnapshot, error) {
		calls++
		return CorrelationInventorySnapshot{}, errors.New("unexpected inventory")
	}
	service.pccLoadPins = func() (PCCSafetyPinSnapshot, error) {
		calls++
		return PCCSafetyPinSnapshot{}, errors.New("unexpected pins")
	}
	service.pccBoundaryChain = func(string, string) ([]contracts.PCCBootTransitionHopV1, error) {
		calls++
		return nil, errors.New("unexpected chain")
	}
	service.pccNow = func() time.Time { calls++; return fixture.decision }
	before := state.Snapshot()
	retry, err := service.PublishPCCCorrelationSnapshot(
		context.Background(), fixture.request,
	)
	if err != nil || retry.Created || calls != 0 ||
		!coreControlEventsEqual(retry.Item, first.Item) {
		t.Fatalf("restart retry=%+v calls=%d err=%v", retry, calls, err)
	}
	after := state.Snapshot()
	if after.LastSequence != before.LastSequence ||
		after.PCCReceiptCount != before.PCCReceiptCount {
		t.Fatalf("restart retry changed state: before=%+v after=%+v", before, after)
	}
}

func TestPCCRestartPublishesAuthenticatedCrossBootPathsABC(t *testing.T) {
	for _, path := range []string{"A", "B", "C"} {
		t.Run(path, func(t *testing.T) {
			fixture := newPCCRestartFixture(t)
			defaultChain := fixture.service.pccBoundaryChain
			dedicated, err := defaultChain(testBootID, testBootID2)
			if err != nil || len(dedicated) != 1 {
				t.Fatalf("real A chain=%+v err=%v", dedicated, err)
			}
			chain := pccRestartChainForPath(t, path, dedicated)
			chainHash, err := contracts.PCCBootTransitionChainSHA256(chain)
			if err != nil {
				t.Fatal(err)
			}
			pccMutateState(t, fixture.state, func(state *ObserverState) {
				state.ReconcileRequired = true
				state.RoutineDropped = 1
				state.DropEventPending = true
			})
			pccRestartBreakCoverage(t, fixture)
			inventoryCalls, pinCalls, clockCalls, chainCalls := 0, 0, 0, 0
			fixture.service.pccInventorySnapshot = func(string) (CorrelationInventorySnapshot, error) {
				inventoryCalls++
				return CorrelationInventorySnapshot{}, ErrInventoryStale
			}
			fixture.service.pccLoadPins = func() (PCCSafetyPinSnapshot, error) {
				pinCalls++
				return PCCSafetyPinSnapshot{}, ErrPCCDetectorBundleUnavailable
			}
			fixture.service.pccNow = func() time.Time { clockCalls++; return fixture.decision }
			fixture.service.pccBoundaryChain = func(from, to string) ([]contracts.PCCBootTransitionHopV1, error) {
				chainCalls++
				if from != testBootID || to != testBootID2 {
					t.Fatalf("chain request=%s -> %s", from, to)
				}
				return chain, nil
			}
			before := fixture.state.Snapshot()
			publication, err := fixture.service.PublishPCCCorrelationSnapshot(
				context.Background(), fixture.request,
			)
			if err != nil {
				t.Fatal(err)
			}
			snapshot := pccDecodeSnapshot(t, publication)
			wantTime := fixture.decision.Truncate(time.Microsecond).Format(time.RFC3339Nano)
			if !publication.Created || publication.Item.Sequence != before.LastSequence+1 ||
				snapshot.Outcome != "failed" || snapshot.FailureReasons == nil ||
				!reflect.DeepEqual(*snapshot.FailureReasons, []string{"observer_boot_changed"}) ||
				snapshot.BootTransitionHopCount == nil || *snapshot.BootTransitionHopCount != uint64(len(chain)) ||
				snapshot.BootTransitionChainSHA256 == nil || *snapshot.BootTransitionChainSHA256 != chainHash ||
				snapshot.DecisionTime != wantTime || snapshot.CoverageThroughSequence != publication.Item.Sequence-1 ||
				publication.Item.Envelope.BootID != testBootID2 || publication.Item.Envelope.InventoryGeneration != 0 ||
				publication.Item.Envelope.ContainerID != nil || publication.Item.Envelope.InventoryRevision != nil {
				t.Fatalf("path %s publication=%+v snapshot=%+v", path, publication, snapshot)
			}
			if inventoryCalls != 0 || pinCalls != 0 || clockCalls != 1 || chainCalls != 1 ||
				fixture.state.Snapshot().PCCReceiptCount != before.PCCReceiptCount+1 {
				t.Fatalf("path %s calls/receipt=%d/%d/%d/%d/%d", path, inventoryCalls, pinCalls, clockCalls, chainCalls, fixture.state.Snapshot().PCCReceiptCount)
			}
			if path == "A" {
				pccRestartRetry(t, fixture, publication)
			}
		})
	}
}

func TestPCCRestartRejectsMissingReorderedOrForgedBoundary(t *testing.T) {
	for _, failure := range []string{"missing", "reordered", "forged"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newPCCRestartFixture(t)
			dedicated, err := fixture.service.pccBoundaryChain(testBootID, testBootID2)
			if err != nil {
				t.Fatal(err)
			}
			chainCalls, inventoryCalls, pinCalls := 0, 0, 0
			fixture.service.pccBoundaryChain = func(string, string) ([]contracts.PCCBootTransitionHopV1, error) {
				chainCalls++
				if failure != "reordered" {
					return nil, ErrPCCJournalCorrupt
				}
				second := dedicated[0]
				second.EventID = "evt_" + strings.Repeat("f", 64)
				second.ContentSHA256 = strings.Repeat("f", 64)
				second.PreviousBootID = second.BootID
				second.BootID = testBootID3
				second.PreviousSourceSequence = second.SourceSequence
				second.SourceSequence++
				return []contracts.PCCBootTransitionHopV1{second, dedicated[0]}, nil
			}
			fixture.service.pccInventorySnapshot = func(string) (CorrelationInventorySnapshot, error) {
				inventoryCalls++
				return CorrelationInventorySnapshot{}, errors.New("unexpected inventory")
			}
			fixture.service.pccLoadPins = func() (PCCSafetyPinSnapshot, error) {
				pinCalls++
				return PCCSafetyPinSnapshot{}, errors.New("unexpected pins")
			}
			before := fixture.state.Snapshot()
			publication, err := fixture.service.PublishPCCCorrelationSnapshot(
				context.Background(), fixture.request,
			)
			if !errors.Is(err, ErrPCCPublicationUnavailable) ||
				!reflect.DeepEqual(publication, PCCCorrelationPublication{}) ||
				chainCalls != 1 || inventoryCalls != 0 || pinCalls != 0 {
				t.Fatalf("failure=%s publication=%+v calls=%d/%d/%d err=%v", failure, publication, chainCalls, inventoryCalls, pinCalls, err)
			}
			after := fixture.state.Snapshot()
			if after.LastSequence != before.LastSequence || after.PCCReceiptCount != before.PCCReceiptCount {
				t.Fatalf("failure=%s changed state", failure)
			}
		})
	}
}
