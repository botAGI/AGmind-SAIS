package observerd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
)

func pccPublishRequestFixture() contracts.PCCCorrelationSnapshotRequestV1 {
	return contracts.PCCCorrelationSnapshotRequestV1{
		SchemaVersion:         "agmind.pcc-correlation-snapshot-request.v1",
		TriggerEventID:        "evt_" + strings.Repeat("a", 64),
		TriggerContentSHA256:  strings.Repeat("b", 64),
		TriggerSourceSequence: 1,
		RequestedTTLSeconds:   120,
	}
}

func pccRequestForItem(item SpoolItem) contracts.PCCCorrelationSnapshotRequestV1 {
	return contracts.PCCCorrelationSnapshotRequestV1{
		SchemaVersion:         "agmind.pcc-correlation-snapshot-request.v1",
		TriggerEventID:        item.EventID,
		TriggerContentSHA256:  item.ContentSHA256,
		TriggerSourceSequence: item.Sequence,
		RequestedTTLSeconds:   120,
	}
}

func pccFailDownstreamSubstrates(service *Service, calls *[]string) {
	service.pccInventorySnapshot = func(string) (CorrelationInventorySnapshot, error) {
		*calls = append(*calls, "inventory")
		return CorrelationInventorySnapshot{}, errors.New("unexpected inventory call")
	}
	service.pccLoadPins = func() (PCCSafetyPinSnapshot, error) {
		*calls = append(*calls, "pins")
		return PCCSafetyPinSnapshot{}, errors.New("unexpected pins call")
	}
	service.pccBoundaryChain = func(string, string) (
		[]contracts.PCCBootTransitionHopV1,
		error,
	) {
		*calls = append(*calls, "boundary")
		return nil, errors.New("unexpected boundary call")
	}
	service.pccNow = func() time.Time {
		*calls = append(*calls, "clock")
		return time.Time{}
	}
}

func TestPCCPublishHardFenceReturnsUnavailableWithoutPublication(t *testing.T) {
	service, state, _, _, _ := observerServiceFixture(t)
	if err := state.PersistReadOnly("test_pcc_hard_fence"); err != nil {
		t.Fatal(err)
	}
	before := state.Snapshot()
	called := []string{}
	pccFailDownstreamSubstrates(service, &called)

	_, err := service.PublishPCCCorrelationSnapshot(
		context.Background(),
		pccPublishRequestFixture(),
	)
	if !errors.Is(err, ErrPCCPublicationUnavailable) {
		t.Fatalf("hard-fence error=%v", err)
	}
	if len(called) != 0 {
		t.Fatalf("hard fence invoked substrates: %v", called)
	}
	after := state.Snapshot()
	if after.LastSequence != before.LastSequence ||
		after.PCCReceiptCount != before.PCCReceiptCount {
		t.Fatalf("hard fence published state: before=%+v after=%+v", before, after)
	}
}

func TestPCCPublishReceiptMetadataConflictPrecedesHardFence(t *testing.T) {
	service, state, spool, _, _ := observerServiceFixture(t)
	_, receipt := pccReceiptSnapshotFixture(
		t,
		spool,
		service.daemon.signer,
		"producer-conflict-order",
	)
	if err := spool.pccReceipts.Append(receipt); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistReadOnly("test_preexisting_pcc_fence"); err != nil {
		t.Fatal(err)
	}
	before := state.Snapshot()
	request := pccPublishRequestFixture()
	request.TriggerEventID = strings.TrimPrefix(
		receipt.OperationKey,
		"pcc_correlation_snapshot:",
	)
	request.TriggerContentSHA256 = strings.Repeat("9", 64)
	request.TriggerSourceSequence = 99
	requestSHA256, err := contracts.PCCCorrelationRequestSHA256(request)
	if err != nil {
		t.Fatal(err)
	}
	if requestSHA256 == receipt.RequestSHA256 {
		t.Fatal("conflict fixture unexpectedly reused the receipt request hash")
	}
	called := []string{}
	pccFailDownstreamSubstrates(service, &called)

	publication, err := service.PublishPCCCorrelationSnapshot(
		context.Background(),
		request,
	)
	if !errors.Is(err, ErrPCCPublicationConflict) {
		t.Fatalf("metadata conflict was hidden by hard fence: %v", err)
	}
	if !reflect.DeepEqual(publication, PCCCorrelationPublication{}) {
		t.Fatalf("metadata conflict exposed publication=%+v", publication)
	}
	if len(called) != 0 {
		t.Fatalf("metadata conflict invoked substrates: %v", called)
	}
	after := state.Snapshot()
	if after.LastSequence != before.LastSequence ||
		after.PCCReceiptCount != before.PCCReceiptCount ||
		after.PCCReceiptBytes != before.PCCReceiptBytes ||
		after.PCCReceiptHeadHash != before.PCCReceiptHeadHash ||
		!after.MutationReadOnly ||
		after.ReadOnlyReason != "observer_pcc_request_conflict" {
		t.Fatalf("metadata conflict state: before=%+v after=%+v", before, after)
	}
	reopened, err := OpenStateStore(
		state.path,
		StateIdentity{
			HostID: after.HostID, BootID: after.BootID,
			KeyID: after.KeyID, KeyEpoch: after.KeyEpoch,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	durable := reopened.Snapshot()
	if !durable.MutationReadOnly ||
		durable.ReadOnlyReason != "observer_pcc_request_conflict" ||
		durable.LastSequence != before.LastSequence ||
		durable.PCCReceiptCount != before.PCCReceiptCount ||
		durable.PCCReceiptBytes != before.PCCReceiptBytes ||
		durable.PCCReceiptHeadHash != before.PCCReceiptHeadHash {
		t.Fatalf("metadata conflict durable state=%+v", durable)
	}
}

func TestPCCPublishRequiresExactUnacknowledgedCandidateTrigger(t *testing.T) {
	type fixture struct {
		service *Service
		state   *StateStore
		spool   *Spool
		request contracts.PCCCorrelationSnapshotRequestV1
	}
	newCandidate := func(t *testing.T) fixture {
		t.Helper()
		service, state, spool, _, _ := observerServiceFixture(t)
		if err := service.ReconcileDocker(
			context.Background(),
			"observer_startup",
		); err != nil {
			t.Fatal(err)
		}
		event, err := service.IngestFalco(
			context.Background(),
			falcoIngestFixture(),
		)
		if err != nil {
			t.Fatal(err)
		}
		return fixture{
			service: service,
			state:   state,
			spool:   spool,
			request: pccRequestForItem(spool.items[event.SourceSequence]),
		}
	}
	newInvestigationOnly := func(t *testing.T) fixture {
		t.Helper()
		service, state, spool, _, _ := observerServiceFixture(t)
		event, err := service.IngestFalco(
			context.Background(),
			falcoIngestFixture(),
		)
		if err != nil {
			t.Fatal(err)
		}
		return fixture{
			service: service,
			state:   state,
			spool:   spool,
			request: pccRequestForItem(spool.items[event.SourceSequence]),
		}
	}

	tests := map[string]func(*testing.T) fixture{
		"missing sequence": func(t *testing.T) fixture {
			value := newCandidate(t)
			value.request.TriggerSourceSequence = value.state.Snapshot().LastSequence + 100
			return value
		},
		"mismatched event ID": func(t *testing.T) fixture {
			value := newCandidate(t)
			value.request.TriggerEventID = "evt_" + strings.Repeat("9", 64)
			return value
		},
		"mismatched content hash": func(t *testing.T) fixture {
			value := newCandidate(t)
			value.request.TriggerContentSHA256 = strings.Repeat("9", 64)
			return value
		},
		"priority event": func(t *testing.T) fixture {
			value := newCandidate(t)
			sequences := make([]uint64, 0, len(value.spool.items))
			for sequence, item := range value.spool.items {
				if item.Tier == PriorityTier {
					sequences = append(sequences, sequence)
				}
			}
			sort.Slice(sequences, func(left, right int) bool {
				return sequences[left] < sequences[right]
			})
			if len(sequences) == 0 {
				t.Fatal("fixture has no priority event")
			}
			value.request = pccRequestForItem(value.spool.items[sequences[0]])
			return value
		},
		"investigation-only trigger": newInvestigationOnly,
		"already acknowledged trigger": func(t *testing.T) fixture {
			value := newCandidate(t)
			for sequence := uint64(1); sequence <= value.request.TriggerSourceSequence; sequence++ {
				item := value.spool.items[sequence]
				if err := value.spool.Ack(
					item.Sequence,
					item.EventID,
					item.ContentSHA256,
				); err != nil {
					t.Fatal(err)
				}
			}
			return value
		},
		"forged in-memory trigger": func(t *testing.T) fixture {
			value := newCandidate(t)
			item := value.spool.items[value.request.TriggerSourceSequence]
			item.Canonical = bytes.Replace(
				item.Canonical,
				[]byte(`"falco_version":"0.44.1"`),
				[]byte(`"falco_version":"9.9.9"`),
				1,
			)
			value.spool.items[item.Sequence] = item
			return value
		},
	}

	for name, prepare := range tests {
		t.Run(name, func(t *testing.T) {
			value := prepare(t)
			before := value.state.Snapshot()
			called := []string{}
			pccFailDownstreamSubstrates(value.service, &called)
			if _, err := value.service.PublishPCCCorrelationSnapshot(
				context.Background(),
				value.request,
			); err == nil {
				t.Fatal("invalid trigger published a PCC snapshot")
			}
			after := value.state.Snapshot()
			if after.LastSequence != before.LastSequence ||
				after.PCCReceiptCount != before.PCCReceiptCount {
				t.Fatalf("rejected trigger published state: before=%+v after=%+v", before, after)
			}
			if len(called) != 0 {
				t.Fatalf("rejected trigger invoked downstream substrates: %v", called)
			}
		})
	}
}

func pccPublishValidPins(t *testing.T) PCCSafetyPinSnapshot {
	t.Helper()
	operatorHash, err := contracts.PCCOperatorDenylistSHA256(
		[]string{},
		[]string{},
	)
	if err != nil {
		t.Fatal(err)
	}
	managementHash, err := contracts.PCCManagementDenylistSHA256(
		[]string{},
		[]string{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return PCCSafetyPinSnapshot{
		DetectorBundleSHA256:      strings.Repeat("a", 64),
		SpecialUseRegistrySHA256:  pccSpecialUseRegistrySHA256,
		OperatorDeniedNetworks:    []string{},
		OperatorDeniedAddresses:   []string{},
		OperatorDenylistSHA256:    operatorHash,
		ManagementDeniedNetworks:  []string{},
		ManagementDeniedAddresses: []string{},
		ManagementDenylistSHA256:  managementHash,
	}
}

func TestPCCPublishCompleteBindsOneGenerationPinsTimestampAndCoverage(
	t *testing.T,
) {
	service, state, spool, inventory, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	identity, err := inventory.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	trigger, err := service.IngestFalco(
		context.Background(),
		falcoIngestFixture(),
	)
	if err != nil {
		t.Fatal(err)
	}
	triggerItem := spool.items[trigger.SourceSequence]
	request := pccRequestForItem(triggerItem)
	pins := pccPublishValidPins(t)
	decision := time.Date(
		2026,
		7,
		27,
		12,
		1,
		0,
		123456789,
		time.UTC,
	)
	inventoryCalls := 0
	pinCalls := 0
	clockCalls := 0
	service.pccInventorySnapshot = func(fullID string) (
		CorrelationInventorySnapshot,
		error,
	) {
		inventoryCalls++
		return inventory.SnapshotForCorrelation(fullID)
	}
	service.pccLoadPins = func() (PCCSafetyPinSnapshot, error) {
		pinCalls++
		return pins, nil
	}
	service.pccNow = func() time.Time {
		clockCalls++
		return decision
	}
	before := state.Snapshot()

	first, err := service.PublishPCCCorrelationSnapshot(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || first.Item.Sequence != before.LastSequence+1 {
		t.Fatalf("publication=%+v before=%+v", first, before)
	}
	if inventoryCalls != 1 || pinCalls != 1 || clockCalls != 1 {
		t.Fatalf(
			"substrate calls inventory=%d pins=%d clock=%d",
			inventoryCalls,
			pinCalls,
			clockCalls,
		)
	}
	raw, err := contracts.CanonicalJSON(first.Item.Envelope.NormalizedFields)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := contracts.DecodeStrict[contracts.PCCCorrelationSnapshotV1](
		bytes.NewReader(raw),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestSHA256, err := contracts.PCCCorrelationRequestSHA256(request)
	if err != nil {
		t.Fatal(err)
	}
	wantTime := decision.Truncate(time.Microsecond).Format(time.RFC3339Nano)
	if snapshot.Outcome != "complete" ||
		snapshot.RequestSHA256 != requestSHA256 ||
		snapshot.Trigger.EventID != triggerItem.EventID ||
		snapshot.Trigger.ContentSHA256 != triggerItem.ContentSHA256 ||
		snapshot.Trigger.SourceSequence != triggerItem.Sequence ||
		snapshot.DecisionTime != wantTime ||
		first.Item.Envelope.EventTime != wantTime ||
		first.Item.Envelope.IngestTime != wantTime ||
		snapshot.CoverageThroughSequence != first.Item.Sequence-1 ||
		first.Item.Envelope.ContainerID == nil ||
		*first.Item.Envelope.ContainerID != identity.FullContainerID ||
		first.Item.Envelope.ContainerStartTime == nil ||
		*first.Item.Envelope.ContainerStartTime != identity.DockerStartedAt ||
		first.Item.Envelope.InventoryGeneration != identity.InventoryGeneration ||
		first.Item.Envelope.InventoryRevision == nil ||
		*first.Item.Envelope.InventoryRevision != identity.InventoryRevision ||
		first.Item.Envelope.SourcePayloadHash != first.Item.Envelope.NormalizedFieldsSHA256 {
		t.Fatalf("complete binding mismatch: item=%+v snapshot=%+v", first.Item, snapshot)
	}
	inventorySnapshot, err := inventory.SnapshotForCorrelation(identity.FullContainerID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DockerNetworks == nil ||
		!reflect.DeepEqual(*snapshot.DockerNetworks, inventorySnapshot.DockerNetworks) ||
		snapshot.DetectorBundleSHA256 == nil ||
		*snapshot.DetectorBundleSHA256 != pins.DetectorBundleSHA256 ||
		snapshot.SpecialUseRegistrySHA256 == nil ||
		*snapshot.SpecialUseRegistrySHA256 != pins.SpecialUseRegistrySHA256 {
		t.Fatalf("complete inputs mismatch: %+v", snapshot)
	}
	item := spool.items[first.Item.Sequence]
	if item.Tier != PriorityTier {
		t.Fatalf("PCC snapshot tier=%q", item.Tier)
	}
	receipt, found, err := spool.pccReceipts.Lookup(
		"pcc_correlation_snapshot:"+request.TriggerEventID,
		requestSHA256,
	)
	if err != nil || !found {
		t.Fatalf("receipt found=%t err=%v", found, err)
	}
	wantReceipt := PCCPublicationReceipt{
		OperationKey:             "pcc_correlation_snapshot:" + request.TriggerEventID,
		RequestSHA256:            requestSHA256,
		SnapshotNormalizedSHA256: first.Item.Envelope.NormalizedFieldsSHA256,
		SnapshotEventID:          first.Item.EventID,
		SnapshotContentSHA256:    first.Item.ContentSHA256,
	}
	if receipt != wantReceipt {
		t.Fatalf("receipt=%+v want=%+v", receipt, wantReceipt)
	}
	afterFirst := state.Snapshot()
	if afterFirst.PCCReceiptCount != before.PCCReceiptCount+1 {
		t.Fatalf("receipt count=%d want=%d", afterFirst.PCCReceiptCount, before.PCCReceiptCount+1)
	}

	inventoryCalls = 0
	pinCalls = 0
	clockCalls = 0
	retry, err := service.PublishPCCCorrelationSnapshot(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Created || !coreControlEventsEqual(retry.Item, first.Item) ||
		inventoryCalls != 0 || pinCalls != 0 || clockCalls != 0 {
		t.Fatalf(
			"retry=%+v first=%+v calls=%d/%d/%d",
			retry,
			first,
			inventoryCalls,
			pinCalls,
			clockCalls,
		)
	}
	afterRetry := state.Snapshot()
	if afterRetry.LastSequence != afterFirst.LastSequence ||
		afterRetry.PCCReceiptCount != afterFirst.PCCReceiptCount {
		t.Fatalf("retry changed state: before=%+v after=%+v", afterFirst, afterRetry)
	}
}

type pccFailedPublishFixture struct {
	service        *Service
	state          *StateStore
	spool          *Spool
	inventory      *Inventory
	request        contracts.PCCCorrelationSnapshotRequestV1
	identity       ContainerIdentityV1
	inventoryValue CorrelationInventorySnapshot
	pins           PCCSafetyPinSnapshot
	decision       time.Time
	inventoryErr   error
	pinErr         error
	inventoryCalls int
	pinCalls       int
	clockCalls     int
}

func newPCCFailedPublishFixture(t *testing.T) *pccFailedPublishFixture {
	t.Helper()
	service, state, spool, inventory, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	identity, err := inventory.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	inventoryValue, err := inventory.SnapshotForCorrelation(identity.FullContainerID)
	if err != nil {
		t.Fatal(err)
	}
	trigger, err := service.IngestFalco(
		context.Background(),
		falcoIngestFixture(),
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &pccFailedPublishFixture{
		service:        service,
		state:          state,
		spool:          spool,
		inventory:      inventory,
		request:        pccRequestForItem(spool.items[trigger.SourceSequence]),
		identity:       identity,
		inventoryValue: inventoryValue,
		pins:           pccPublishValidPins(t),
		decision: time.Date(
			2026,
			7,
			27,
			12,
			1,
			0,
			987654321,
			time.UTC,
		),
	}
	service.pccInventorySnapshot = func(string) (
		CorrelationInventorySnapshot,
		error,
	) {
		fixture.inventoryCalls++
		return fixture.inventoryValue, fixture.inventoryErr
	}
	service.pccLoadPins = func() (PCCSafetyPinSnapshot, error) {
		fixture.pinCalls++
		return fixture.pins, fixture.pinErr
	}
	service.pccNow = func() time.Time {
		fixture.clockCalls++
		return fixture.decision
	}
	return fixture
}

func pccMutateState(
	t *testing.T,
	state *StateStore,
	mutate func(*ObserverState),
) {
	t.Helper()
	state.mutex.Lock()
	defer state.mutex.Unlock()
	next := cloneObserverState(state.state)
	mutate(&next)
	if err := state.replaceLocked(next); err != nil {
		t.Fatal(err)
	}
}

func pccDecodeSnapshot(
	t *testing.T,
	publication PCCCorrelationPublication,
) contracts.PCCCorrelationSnapshotV1 {
	t.Helper()
	raw, err := contracts.CanonicalJSON(publication.Item.Envelope.NormalizedFields)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := contracts.DecodeStrict[contracts.PCCCorrelationSnapshotV1](
		bytes.NewReader(raw),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func pccAssertFailedPublication(
	t *testing.T,
	fixture *pccFailedPublishFixture,
	before ObserverState,
	publication PCCCorrelationPublication,
	wantReasons []string,
) {
	t.Helper()
	if !publication.Created || publication.Item.Sequence != before.LastSequence+1 {
		t.Fatalf("failed publication=%+v before=%+v", publication, before)
	}
	snapshot := pccDecodeSnapshot(t, publication)
	wantTime := fixture.decision.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	if snapshot.Outcome != "failed" || snapshot.FailureReasons == nil ||
		!reflect.DeepEqual(*snapshot.FailureReasons, wantReasons) ||
		snapshot.DecisionTime != wantTime ||
		publication.Item.Envelope.EventTime != wantTime ||
		publication.Item.Envelope.IngestTime != wantTime ||
		snapshot.CoverageThroughSequence != publication.Item.Sequence-1 ||
		snapshot.Trigger.EventID != fixture.request.TriggerEventID ||
		snapshot.Trigger.ContentSHA256 != fixture.request.TriggerContentSHA256 ||
		snapshot.Trigger.SourceSequence != fixture.request.TriggerSourceSequence {
		t.Fatalf("failed snapshot=%+v item=%+v want reasons=%v", snapshot, publication.Item, wantReasons)
	}
	if snapshot.DetectorBundleSHA256 != nil ||
		snapshot.SpecialUseRegistrySHA256 != nil ||
		snapshot.OperatorDeniedNetworks != nil ||
		snapshot.OperatorDeniedAddresses != nil ||
		snapshot.OperatorDenylistSHA256 != nil ||
		snapshot.ManagementDeniedNetworks != nil ||
		snapshot.ManagementDeniedAddresses != nil ||
		snapshot.ManagementDenylistSHA256 != nil ||
		snapshot.DockerNetworks != nil ||
		snapshot.DockerNetworkSnapshotSHA256 != nil ||
		snapshot.DockerContainerID != nil ||
		snapshot.DockerStartedAt != nil ||
		snapshot.ImageID != nil || snapshot.RepoDigests != nil ||
		snapshot.ImmutableSpecSHA256 != nil ||
		snapshot.InventoryGeneration != nil || snapshot.InventoryRevision != nil ||
		snapshot.InventoryObservedAt != nil || snapshot.NetworkMode != nil ||
		snapshot.NetworkDriver != nil || snapshot.Privileged != nil ||
		snapshot.ConfiguredCapAdd != nil || snapshot.ConfiguredCapDrop != nil ||
		snapshot.EffectiveCapNetAdmin != nil || snapshot.Running != nil ||
		publication.Item.Envelope.ContainerID != nil ||
		publication.Item.Envelope.ContainerStartTime != nil ||
		publication.Item.Envelope.ReleaseID != nil ||
		publication.Item.Envelope.InventoryRevision != nil ||
		publication.Item.Envelope.InventoryGeneration != 0 {
		t.Fatalf("failed proof leaked complete-only identity: snapshot=%+v envelope=%+v", snapshot, publication.Item.Envelope)
	}
	item := fixture.spool.items[publication.Item.Sequence]
	if item.Tier != PriorityTier {
		t.Fatalf("failed PCC tier=%q", item.Tier)
	}
	after := fixture.state.Snapshot()
	if after.PCCReceiptCount != before.PCCReceiptCount+1 {
		t.Fatalf("failed PCC receipt count=%d want=%d", after.PCCReceiptCount, before.PCCReceiptCount+1)
	}
}

func pccValidOverflowInputs(
	t *testing.T,
	fixture *pccFailedPublishFixture,
) {
	t.Helper()
	addresses := make([]string, 0, 128)
	for third := 0; third < 2; third++ {
		for fourth := 1; fourth <= 64; fourth++ {
			addresses = append(addresses, fmt.Sprintf("10.0.%d.%d", third, fourth))
		}
	}
	networks := make([]string, len(addresses))
	for index, address := range addresses {
		networks[index] = address + "/32"
	}
	sort.Strings(addresses)
	sort.Strings(networks)
	fixture.pins.OperatorDeniedAddresses = append([]string{}, addresses...)
	fixture.pins.OperatorDeniedNetworks = append([]string{}, networks...)
	fixture.pins.ManagementDeniedAddresses = append([]string{}, addresses...)
	fixture.pins.ManagementDeniedNetworks = append([]string{}, networks...)
	operatorHash, err := contracts.PCCOperatorDenylistSHA256(networks, addresses)
	if err != nil {
		t.Fatal(err)
	}
	managementHash, err := contracts.PCCManagementDenylistSHA256(networks, addresses)
	if err != nil {
		t.Fatal(err)
	}
	fixture.pins.OperatorDenylistSHA256 = operatorHash
	fixture.pins.ManagementDenylistSHA256 = managementHash
	dockerNetworks := make([]contracts.PCCDockerNetworkV1, 0, 64)
	for index := 0; index < 64; index++ {
		dockerNetworks = append(dockerNetworks, contracts.PCCDockerNetworkV1{
			NetworkID:        fmt.Sprintf("%064x", index+1),
			Driver:           strings.Repeat("d", 64),
			SubnetCIDRs:      []string{fmt.Sprintf("10.%d.0.0/16", index)},
			GatewayAddresses: []string{fmt.Sprintf("10.%d.0.1", index)},
		})
	}
	if _, err := contracts.PCCDockerNetworkSnapshotSHA256(dockerNetworks); err != nil {
		t.Fatalf("overflow fixture Docker networks are not independently valid: %v", err)
	}
	fixture.inventoryValue.DockerNetworks = dockerNetworks
}

func TestPCCPublishEmitsExactLocallyProducibleFailedUnions(t *testing.T) {
	tests := map[string]struct {
		reason string
		setup  func(*testing.T, *pccFailedPublishFixture)
	}{
		"reconcile_required": {
			reason: "reconcile_required",
			setup: func(t *testing.T, fixture *pccFailedPublishFixture) {
				pccMutateState(t, fixture.state, func(state *ObserverState) {
					state.ReconcileRequired = true
				})
			},
		},
		"docker_reconcile_gap": {
			reason: "docker_reconcile_gap",
			setup: func(_ *testing.T, fixture *pccFailedPublishFixture) {
				fixture.inventoryErr = ErrInventoryReconcileRequired
			},
		},
		"routine_drop_pending": {
			reason: "routine_drop_pending",
			setup: func(t *testing.T, fixture *pccFailedPublishFixture) {
				pccMutateState(t, fixture.state, func(state *ObserverState) {
					state.RoutineDropped = 1
					state.DropEventPending = true
				})
			},
		},
		"inventory_stale": {
			reason: "inventory_stale",
			setup: func(_ *testing.T, fixture *pccFailedPublishFixture) {
				fixture.inventoryValue.Identity.ObservedAt = fixture.decision.Add(
					-11 * time.Second,
				).Format(time.RFC3339Nano)
			},
		},
		"docker_network_snapshot_unavailable": {
			reason: "docker_network_snapshot_unavailable",
			setup: func(_ *testing.T, fixture *pccFailedPublishFixture) {
				fixture.inventoryErr = ErrPCCDockerNetworkSnapshotUnavailable
			},
		},
		"docker_network_snapshot_overflow": {
			reason: "docker_network_snapshot_overflow",
			setup:  pccValidOverflowInputs,
		},
		"detector_bundle_unavailable": {
			reason: "detector_bundle_unavailable",
			setup: func(_ *testing.T, fixture *pccFailedPublishFixture) {
				fixture.pinErr = ErrPCCDetectorBundleUnavailable
			},
		},
		"special_use_registry_unavailable": {
			reason: "special_use_registry_unavailable",
			setup: func(_ *testing.T, fixture *pccFailedPublishFixture) {
				fixture.pinErr = ErrPCCSpecialUseRegistryUnavailable
			},
		},
		"operator_denylist_unavailable": {
			reason: "operator_denylist_unavailable",
			setup: func(_ *testing.T, fixture *pccFailedPublishFixture) {
				fixture.pinErr = ErrPCCOperatorDenylistUnavailable
			},
		},
		"management_denylist_unavailable": {
			reason: "management_denylist_unavailable",
			setup: func(_ *testing.T, fixture *pccFailedPublishFixture) {
				fixture.pinErr = ErrPCCManagementDenylistUnavailable
			},
		},
		"container_not_running": {
			reason: "container_not_running",
			setup: func(_ *testing.T, fixture *pccFailedPublishFixture) {
				fixture.inventoryErr = ErrContainerNotFound
			},
		},
		"container_identity_changed": {
			reason: "container_identity_changed",
			setup: func(_ *testing.T, fixture *pccFailedPublishFixture) {
				fixture.inventoryValue.Identity.DockerStartedAt = "2026-07-27T11:59:59Z"
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newPCCFailedPublishFixture(t)
			test.setup(t, fixture)
			before := fixture.state.Snapshot()
			publication, err := fixture.service.PublishPCCCorrelationSnapshot(
				context.Background(),
				fixture.request,
			)
			if err != nil {
				t.Fatal(err)
			}
			pccAssertFailedPublication(
				t,
				fixture,
				before,
				publication,
				[]string{test.reason},
			)
			if fixture.inventoryCalls != 1 || fixture.pinCalls != 1 || fixture.clockCalls != 1 {
				t.Fatalf("failure substrate calls=%d/%d/%d", fixture.inventoryCalls, fixture.pinCalls, fixture.clockCalls)
			}
		})
	}

	t.Run("combined sorted unique and continues safe observation", func(t *testing.T) {
		fixture := newPCCFailedPublishFixture(t)
		pccMutateState(t, fixture.state, func(state *ObserverState) {
			state.ReconcileRequired = true
			state.RoutineDropped = 2
			state.DropEventPending = true
		})
		fixture.inventoryValue.Identity.ObservedAt = fixture.decision.Add(
			-11 * time.Second,
		).Format(time.RFC3339Nano)
		fixture.inventoryValue.Identity.DockerStartedAt = "2026-07-27T11:59:59Z"
		fixture.pinErr = errors.Join(
			ErrPCCDetectorBundleUnavailable,
			ErrPCCOperatorDenylistUnavailable,
			ErrPCCOperatorDenylistUnavailable,
		)
		before := fixture.state.Snapshot()
		publication, err := fixture.service.PublishPCCCorrelationSnapshot(
			context.Background(),
			fixture.request,
		)
		if err != nil {
			t.Fatal(err)
		}
		pccAssertFailedPublication(t, fixture, before, publication, []string{
			"container_identity_changed",
			"detector_bundle_unavailable",
			"inventory_stale",
			"operator_denylist_unavailable",
			"reconcile_required",
			"routine_drop_pending",
		})
		if fixture.inventoryCalls != 1 || fixture.pinCalls != 1 || fixture.clockCalls != 1 {
			t.Fatalf("combined failure short-circuited safe observation: %d/%d/%d", fixture.inventoryCalls, fixture.pinCalls, fixture.clockCalls)
		}
	})

	t.Run("source gap is typed unavailable and publishes nothing", func(t *testing.T) {
		fixture := newPCCFailedPublishFixture(t)
		beforeGap := fixture.state.Snapshot()
		identity := StateIdentity{
			HostID: beforeGap.HostID, BootID: beforeGap.BootID,
			KeyID: beforeGap.KeyID, KeyEpoch: beforeGap.KeyEpoch,
		}
		if _, err := fixture.state.reserveExpected(
			identity,
			beforeGap.LastSequence+1,
		); err != nil {
			t.Fatal(err)
		}
		reserved := fixture.state.Snapshot()
		publication, err := fixture.service.PublishPCCCorrelationSnapshot(
			context.Background(),
			fixture.request,
		)
		if !errors.Is(err, ErrPCCPublicationUnavailable) ||
			!reflect.DeepEqual(publication, PCCCorrelationPublication{}) {
			t.Fatalf("source-gap publication=%+v err=%v", publication, err)
		}
		after := fixture.state.Snapshot()
		if after.LastSequence != reserved.LastSequence ||
			after.PCCReceiptCount != reserved.PCCReceiptCount {
			t.Fatalf("source gap changed state: reserved=%+v after=%+v", reserved, after)
		}
	})
}
