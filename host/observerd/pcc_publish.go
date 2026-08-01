package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"time"

	"agmind.local/sais/internal/contracts"
)

var (
	ErrPCCPublicationUnavailable           = errors.New("PCC publication unavailable")
	ErrPCCPublicationConflict              = errors.New("PCC publication request conflict")
	ErrPCCTriggerInvalid                   = errors.New("PCC trigger authority invalid")
	ErrPCCReceiptRequired                  = errors.New("PCC snapshot requires specialized receipt")
	ErrPCCDockerNetworkSnapshotUnavailable = errors.New(
		"PCC Docker network snapshot unavailable",
	)
	errPCCCompleteSnapshotOverflow = errors.New(
		"PCC complete normalized snapshot exceeds 24 KiB",
	)
)

type PCCCorrelationPublication struct {
	Item    CoreEventV1
	Created bool
}

type pccCorrelationPublisher interface {
	PublishPCCCorrelationSnapshot(
		context.Context,
		contracts.PCCCorrelationSnapshotRequestV1,
	) (PCCCorrelationPublication, error)
}

func validatePCCTriggerItem(
	item SpoolItem,
) (contracts.PCCFalcoTriggerProjectionV1, error) {
	if item.Tier != RoutineTier {
		return contracts.PCCFalcoTriggerProjectionV1{}, ErrPCCTriggerInvalid
	}
	outer, err := coreEventFromSpoolItem(item)
	if err != nil {
		return contracts.PCCFalcoTriggerProjectionV1{}, errors.Join(
			ErrPCCTriggerInvalid,
			err,
		)
	}
	event := outer.Envelope
	if event.EventType != "falco_connect" ||
		event.SourceID != "agmind-observerd" ||
		event.SourceVersion != "0.1.0" ||
		event.ContainerID == nil ||
		event.ContainerStartTime == nil ||
		event.ReleaseID == nil ||
		event.InventoryGeneration == 0 ||
		event.InventoryRevision == nil {
		return contracts.PCCFalcoTriggerProjectionV1{}, ErrPCCTriggerInvalid
	}
	raw, err := contracts.CanonicalJSON(event.NormalizedFields)
	if err != nil {
		return contracts.PCCFalcoTriggerProjectionV1{}, errors.Join(
			ErrPCCTriggerInvalid,
			err,
		)
	}
	falco, err := contracts.DecodeStrict[contracts.FalcoConnectV1](
		bytes.NewReader(raw),
		65_536,
	)
	if err != nil ||
		!falco.SuccessfulConnect ||
		falco.InvestigationOnly ||
		falco.DockerContainerID == nil ||
		falco.DockerStartedAt == nil ||
		falco.ImageID == nil ||
		falco.ImmutableSpecSHA256 == nil ||
		falco.InventoryRevision == nil ||
		falco.ProcName == nil ||
		falco.ProcExePath == nil ||
		falco.ProcParentName == nil ||
		falco.DestinationIPv4 == nil ||
		falco.DestinationPort == nil ||
		falco.L4Protocol == nil {
		return contracts.PCCFalcoTriggerProjectionV1{}, errors.Join(
			ErrPCCTriggerInvalid,
			err,
		)
	}
	releaseID, err := contracts.ReleaseID(
		*falco.ImageID,
		*falco.ImmutableSpecSHA256,
	)
	if err != nil ||
		*event.ContainerID != *falco.DockerContainerID ||
		*event.ContainerStartTime != *falco.DockerStartedAt ||
		*event.ReleaseID != releaseID ||
		*event.InventoryRevision != *falco.InventoryRevision ||
		event.EventTime != falco.EventTime ||
		event.SourcePayloadHash != falco.RawEventSHA256 {
		return contracts.PCCFalcoTriggerProjectionV1{}, errors.Join(
			ErrPCCTriggerInvalid,
			err,
		)
	}
	projection := contracts.PCCFalcoTriggerProjectionV1{
		SchemaVersion:          "agmind.pcc-falco-trigger-projection.v1",
		EventID:                item.EventID,
		ContentSHA256:          item.ContentSHA256,
		NormalizedFieldsSHA256: event.NormalizedFieldsSHA256,
		SourceSequence:         item.Sequence,
		SourceID:               event.SourceID,
		SourceVersion:          event.SourceVersion,
		HostID:                 event.HostID,
		BootID:                 event.BootID,
		EventTime:              event.EventTime,
		IngestTime:             event.IngestTime,
		ClockUncertaintyMS:     event.ClockUncertaintyMS,
		InventoryGeneration:    event.InventoryGeneration,
		InventoryRevision:      *event.InventoryRevision,
		ContainerID:            *event.ContainerID,
		ContainerStartTime:     *event.ContainerStartTime,
		ReleaseID:              *event.ReleaseID,
		DetectorRule:           falco.DetectorRule,
		DetectorRuleVersion:    falco.DetectorRuleVersion,
		FalcoVersion:           falco.FalcoVersion,
		EvtRawres:              falco.EvtRawres,
		EvtRes:                 falco.EvtRes,
		SuccessfulConnect:      falco.SuccessfulConnect,
		InvestigationOnly:      falco.InvestigationOnly,
		ImageID:                *falco.ImageID,
		RepoDigests:            append([]string{}, falco.RepoDigests...),
		ImmutableSpecSHA256:    *falco.ImmutableSpecSHA256,
		ProcName:               falco.ProcName,
		ProcExePath:            falco.ProcExePath,
		ProcParentName:         falco.ProcParentName,
		DestinationIPv4:        *falco.DestinationIPv4,
		DestinationPort:        *falco.DestinationPort,
		L4Protocol:             *falco.L4Protocol,
		MissingRequiredFields:  append([]string{}, falco.MissingRequiredFields...),
		CoverageFlags:          append([]string{}, event.CoverageFlags...),
		RawEventSHA256:         falco.RawEventSHA256,
	}
	if err := projection.Validate(); err != nil {
		return contracts.PCCFalcoTriggerProjectionV1{}, errors.Join(
			ErrPCCTriggerInvalid,
			err,
		)
	}
	return projection, nil
}

func pccCoverageProvenThroughLocked(
	spool *Spool,
	state ObserverState,
	through uint64,
) bool {
	if spool == nil || through != state.LastSequence ||
		state.SequenceGapProtocol != sequenceGapProtocolC8 ||
		state.PublicationHeadSequence > through {
		return false
	}
	covered := state.AckSequence
	if state.LastCoveredGapEnd > covered {
		covered = state.LastCoveredGapEnd
	}
	if covered >= through {
		return true
	}
	start := covered + 1
	for sequence := start; sequence <= through; sequence++ {
		item, found := spool.items[sequence]
		if !found {
			return false
		}
		event, canonical, contentHash, frameBytes, identity, err :=
			readStandaloneFrame(item.path, spool.keys)
		if err != nil ||
			item.Sequence != sequence ||
			event.SourceSequence != item.Sequence ||
			event.EventID != item.EventID ||
			contentHash != item.ContentSHA256 ||
			tierForEvent(event) != item.Tier ||
			frameBytes != item.frameBytes ||
			identity != item.identity ||
			!bytes.Equal(canonical, item.Canonical) ||
			validatePublicationItem(item) != nil {
			_ = spool.state.PersistReadOnly("observer_pcc_coverage_corrupt")
			return false
		}
		if sequence == math.MaxUint64 {
			break
		}
	}
	return true
}

func pccCompleteSnapshot(
	request contracts.PCCCorrelationSnapshotRequestV1,
	requestSHA256 string,
	trigger contracts.PCCFalcoTriggerProjectionV1,
	inventory CorrelationInventorySnapshot,
	pins PCCSafetyPinSnapshot,
	decision time.Time,
	coverageThrough uint64,
) (contracts.PCCCorrelationSnapshotV1, error) {
	identity := inventory.Identity
	if inventory.Generation == 0 ||
		inventory.Generation != identity.InventoryGeneration ||
		identity.FullContainerID != trigger.ContainerID ||
		identity.DockerStartedAt != trigger.ContainerStartTime ||
		identity.ImageID != trigger.ImageID ||
		!slices.Equal(identity.RepoDigests, trigger.RepoDigests) ||
		identity.ImmutableSpecSHA256 != trigger.ImmutableSpecSHA256 ||
		identity.InventoryGeneration != trigger.InventoryGeneration ||
		identity.InventoryRevision != trigger.InventoryRevision ||
		!identity.Running {
		return contracts.PCCCorrelationSnapshotV1{}, ErrPCCPublicationUnavailable
	}
	networkHash, err := contracts.PCCDockerNetworkSnapshotSHA256(
		inventory.DockerNetworks,
	)
	if err != nil {
		return contracts.PCCCorrelationSnapshotV1{}, errors.Join(
			ErrPCCPublicationUnavailable,
			err,
		)
	}
	observedAt, err := time.Parse(time.RFC3339Nano, identity.ObservedAt)
	if err != nil || observedAt.After(decision) ||
		decision.Sub(observedAt) > 10*time.Second {
		return contracts.PCCCorrelationSnapshotV1{}, errors.Join(
			ErrPCCPublicationUnavailable,
			err,
		)
	}
	detectorHash := pins.DetectorBundleSHA256
	specialUseHash := pins.SpecialUseRegistrySHA256
	operatorNetworks := append([]string{}, pins.OperatorDeniedNetworks...)
	operatorAddresses := append([]string{}, pins.OperatorDeniedAddresses...)
	operatorHash := pins.OperatorDenylistSHA256
	managementNetworks := append([]string{}, pins.ManagementDeniedNetworks...)
	managementAddresses := append([]string{}, pins.ManagementDeniedAddresses...)
	managementHash := pins.ManagementDenylistSHA256
	dockerNetworks := cloneDockerNetworks(inventory.DockerNetworks)
	containerID := identity.FullContainerID
	startedAt := identity.DockerStartedAt
	imageID := identity.ImageID
	repoDigests := append([]string{}, identity.RepoDigests...)
	immutableSpec := identity.ImmutableSpecSHA256
	generation := identity.InventoryGeneration
	revision := identity.InventoryRevision
	inventoryObservedAt := identity.ObservedAt
	networkMode := identity.NetworkMode
	networkDriver := identity.NetworkDriver
	privileged := identity.Privileged
	capAdd := append([]string{}, identity.ConfiguredCapAdd...)
	capDrop := append([]string{}, identity.ConfiguredCapDrop...)
	effectiveCapNetAdmin := identity.EffectiveCapNetAdmin
	running := identity.Running
	snapshot := contracts.PCCCorrelationSnapshotV1{
		SchemaVersion:               "agmind.pcc-correlation-snapshot.v1",
		Outcome:                     "complete",
		RequestSHA256:               requestSHA256,
		Trigger:                     trigger,
		DecisionTime:                decision.Format(time.RFC3339Nano),
		DetectorBundleSHA256:        &detectorHash,
		RequestedTTLSeconds:         request.RequestedTTLSeconds,
		SpecialUseRegistrySHA256:    &specialUseHash,
		OperatorDeniedNetworks:      &operatorNetworks,
		OperatorDeniedAddresses:     &operatorAddresses,
		OperatorDenylistSHA256:      &operatorHash,
		ManagementDeniedNetworks:    &managementNetworks,
		ManagementDeniedAddresses:   &managementAddresses,
		ManagementDenylistSHA256:    &managementHash,
		DockerNetworks:              &dockerNetworks,
		DockerNetworkSnapshotSHA256: &networkHash,
		DockerContainerID:           &containerID,
		DockerStartedAt:             &startedAt,
		ImageID:                     &imageID,
		RepoDigests:                 &repoDigests,
		ImmutableSpecSHA256:         &immutableSpec,
		InventoryGeneration:         &generation,
		InventoryRevision:           &revision,
		InventoryObservedAt:         &inventoryObservedAt,
		NetworkMode:                 &networkMode,
		NetworkDriver:               &networkDriver,
		Privileged:                  &privileged,
		ConfiguredCapAdd:            &capAdd,
		ConfiguredCapDrop:           &capDrop,
		EffectiveCapNetAdmin:        &effectiveCapNetAdmin,
		Running:                     &running,
		CoverageThroughSequence:     coverageThrough,
		HardLimitsVersion:           "pcc-hard-limits-v1",
	}
	canonical, err := contracts.CanonicalJSON(snapshot)
	if err != nil {
		return contracts.PCCCorrelationSnapshotV1{}, errors.Join(
			ErrPCCPublicationUnavailable,
			err,
		)
	}
	if len(canonical) > 24*1024 {
		return contracts.PCCCorrelationSnapshotV1{}, errPCCCompleteSnapshotOverflow
	}
	if err := snapshot.Validate(); err != nil {
		return contracts.PCCCorrelationSnapshotV1{}, errors.Join(
			ErrPCCPublicationUnavailable,
			err,
		)
	}
	return snapshot, nil
}

func pccFailureReasons(
	state ObserverState,
	trigger contracts.PCCFalcoTriggerProjectionV1,
	inventory CorrelationInventorySnapshot,
	inventoryErr error,
	pinErr error,
	decision time.Time,
) ([]string, error) {
	reasons := make(map[string]struct{})
	add := func(reason string) {
		reasons[reason] = struct{}{}
	}
	if state.ReconcileRequired {
		add("reconcile_required")
	}
	if state.DropEventPending {
		add("routine_drop_pending")
	}

	if inventoryErr != nil {
		classified := false
		for _, classification := range []struct {
			err    error
			reason string
		}{
			{ErrInventoryReconcileRequired, "docker_reconcile_gap"},
			{ErrInventoryStale, "inventory_stale"},
			{ErrPCCDockerNetworkSnapshotUnavailable, "docker_network_snapshot_unavailable"},
			{ErrContainerNotFound, "container_not_running"},
		} {
			if errors.Is(inventoryErr, classification.err) {
				classified = true
				add(classification.reason)
			}
		}
		if !classified {
			return nil, errors.Join(
				ErrPCCPublicationUnavailable,
				inventoryErr,
			)
		}
	} else {
		identity := inventory.Identity
		if inventory.Generation == 0 ||
			inventory.Generation != identity.InventoryGeneration {
			add("inventory_stale")
		}
		observedAt, err := time.Parse(time.RFC3339Nano, identity.ObservedAt)
		if err != nil || observedAt.After(decision) ||
			decision.Sub(observedAt) > 10*time.Second {
			add("inventory_stale")
		}
		if !identity.Running {
			add("container_not_running")
		}
		if identity.FullContainerID != trigger.ContainerID ||
			identity.DockerStartedAt != trigger.ContainerStartTime ||
			identity.ImageID != trigger.ImageID ||
			!slices.Equal(identity.RepoDigests, trigger.RepoDigests) ||
			identity.ImmutableSpecSHA256 != trigger.ImmutableSpecSHA256 ||
			identity.InventoryGeneration != trigger.InventoryGeneration ||
			identity.InventoryRevision != trigger.InventoryRevision {
			add("container_identity_changed")
		}
		if _, err := contracts.PCCDockerNetworkSnapshotSHA256(
			inventory.DockerNetworks,
		); err != nil {
			add("docker_network_snapshot_unavailable")
		}
	}

	if pinErr != nil {
		classified := false
		for _, classification := range []struct {
			err    error
			reason string
		}{
			{ErrPCCDetectorBundleUnavailable, "detector_bundle_unavailable"},
			{ErrPCCSpecialUseRegistryUnavailable, "special_use_registry_unavailable"},
			{ErrPCCOperatorDenylistUnavailable, "operator_denylist_unavailable"},
			{ErrPCCManagementDenylistUnavailable, "management_denylist_unavailable"},
		} {
			if errors.Is(pinErr, classification.err) {
				classified = true
				add(classification.reason)
			}
		}
		if !classified {
			return nil, errors.Join(ErrPCCPublicationUnavailable, pinErr)
		}
	}

	result := make([]string, 0, len(reasons))
	for reason := range reasons {
		result = append(result, reason)
	}
	slices.Sort(result)
	return result, nil
}

func pccFailedSnapshot(
	request contracts.PCCCorrelationSnapshotRequestV1,
	requestSHA256 string,
	trigger contracts.PCCFalcoTriggerProjectionV1,
	decision time.Time,
	coverageThrough uint64,
	reasons []string,
) (contracts.PCCCorrelationSnapshotV1, error) {
	failureReasons := append([]string{}, reasons...)
	slices.Sort(failureReasons)
	failureReasons = slices.Compact(failureReasons)
	snapshot := contracts.PCCCorrelationSnapshotV1{
		SchemaVersion:           "agmind.pcc-correlation-snapshot.v1",
		Outcome:                 "failed",
		RequestSHA256:           requestSHA256,
		Trigger:                 trigger,
		DecisionTime:            decision.Format(time.RFC3339Nano),
		RequestedTTLSeconds:     request.RequestedTTLSeconds,
		FailureReasons:          &failureReasons,
		CoverageThroughSequence: coverageThrough,
		HardLimitsVersion:       "pcc-hard-limits-v1",
	}
	if err := snapshot.Validate(); err != nil {
		return contracts.PCCCorrelationSnapshotV1{}, errors.Join(
			ErrPCCPublicationUnavailable,
			err,
		)
	}
	return snapshot, nil
}

func assembleCrossBootPCC(
	service *Service,
	state *StateStore,
	baseline ObserverState,
	request contracts.PCCCorrelationSnapshotRequestV1,
	requestSHA256 string,
	trigger contracts.PCCFalcoTriggerProjectionV1,
) (
	contracts.PCCCorrelationSnapshotV1,
	ObserverState,
	uint64,
	time.Time,
	error,
) {
	if trigger.HostID != baseline.HostID ||
		trigger.BootID == baseline.BootID {
		return contracts.PCCCorrelationSnapshotV1{}, ObserverState{}, 0,
			time.Time{}, ErrPCCPublicationUnavailable
	}
	chain, err := service.pccBoundaryChain(trigger.BootID, baseline.BootID)
	if err != nil || len(chain) == 0 || len(chain) > 1_024 ||
		chain[0].PreviousBootID != trigger.BootID ||
		chain[len(chain)-1].BootID != baseline.BootID {
		return contracts.PCCCorrelationSnapshotV1{}, ObserverState{}, 0,
			time.Time{}, errors.Join(ErrPCCPublicationUnavailable, err)
	}
	chainHash, err := contracts.PCCBootTransitionChainSHA256(chain)
	if err != nil {
		return contracts.PCCCorrelationSnapshotV1{}, ObserverState{}, 0,
			time.Time{}, errors.Join(ErrPCCPublicationUnavailable, err)
	}
	decision := service.pccNow().UTC().Truncate(time.Microsecond)
	assemblyState := state.Snapshot()
	if assemblyState.MutationReadOnly ||
		assemblyState.LastSequence == math.MaxUint64 ||
		assemblyState.HostID != baseline.HostID ||
		assemblyState.BootID != baseline.BootID ||
		assemblyState.KeyID != baseline.KeyID ||
		assemblyState.KeyEpoch != baseline.KeyEpoch {
		return contracts.PCCCorrelationSnapshotV1{}, ObserverState{}, 0,
			time.Time{}, ErrPCCPublicationUnavailable
	}
	sequence := assemblyState.LastSequence + 1
	failureReasons := []string{"observer_boot_changed"}
	hopCount := uint64(len(chain))
	proof := contracts.PCCCorrelationSnapshotV1{
		SchemaVersion:             "agmind.pcc-correlation-snapshot.v1",
		Outcome:                   "failed",
		RequestSHA256:             requestSHA256,
		Trigger:                   trigger,
		DecisionTime:              decision.Format(time.RFC3339Nano),
		RequestedTTLSeconds:       request.RequestedTTLSeconds,
		FailureReasons:            &failureReasons,
		CoverageThroughSequence:   sequence - 1,
		HardLimitsVersion:         "pcc-hard-limits-v1",
		BootTransitionHopCount:    &hopCount,
		BootTransitionChainSHA256: &chainHash,
	}
	if err := proof.Validate(); err != nil {
		return contracts.PCCCorrelationSnapshotV1{}, ObserverState{}, 0,
			time.Time{}, errors.Join(ErrPCCPublicationUnavailable, err)
	}
	return proof, assemblyState, sequence, decision, nil
}

func assembleSameBootPCC(
	service *Service,
	state *StateStore,
	spool *Spool,
	baseline ObserverState,
	request contracts.PCCCorrelationSnapshotRequestV1,
	requestSHA256 string,
	trigger contracts.PCCFalcoTriggerProjectionV1,
) (
	contracts.PCCCorrelationSnapshotV1,
	ObserverState,
	uint64,
	time.Time,
	error,
) {
	inventory, inventoryErr := service.pccInventorySnapshot(trigger.ContainerID)
	pins, pinErr := service.pccLoadPins()
	decision := service.pccNow().UTC().Truncate(time.Microsecond)
	assemblyState := state.Snapshot()
	if assemblyState.MutationReadOnly ||
		assemblyState.LastSequence == math.MaxUint64 ||
		assemblyState.HostID != baseline.HostID ||
		assemblyState.BootID != baseline.BootID ||
		assemblyState.KeyID != baseline.KeyID ||
		assemblyState.KeyEpoch != baseline.KeyEpoch {
		return contracts.PCCCorrelationSnapshotV1{}, ObserverState{}, 0,
			time.Time{}, ErrPCCPublicationUnavailable
	}
	sequence := assemblyState.LastSequence + 1
	coverageThrough := sequence - 1
	if !pccCoverageProvenThroughLocked(spool, assemblyState, coverageThrough) {
		return contracts.PCCCorrelationSnapshotV1{}, ObserverState{}, 0,
			time.Time{}, ErrPCCPublicationUnavailable
	}
	reasons, err := pccFailureReasons(
		assemblyState,
		trigger,
		inventory,
		inventoryErr,
		pinErr,
		decision,
	)
	if err != nil {
		return contracts.PCCCorrelationSnapshotV1{}, ObserverState{}, 0,
			time.Time{}, err
	}
	var proof contracts.PCCCorrelationSnapshotV1
	if len(reasons) == 0 {
		proof, err = pccCompleteSnapshot(
			request,
			requestSHA256,
			trigger,
			inventory,
			pins,
			decision,
			coverageThrough,
		)
		if errors.Is(err, errPCCCompleteSnapshotOverflow) {
			proof, err = pccFailedSnapshot(
				request,
				requestSHA256,
				trigger,
				decision,
				coverageThrough,
				[]string{"docker_network_snapshot_overflow"},
			)
		}
	} else {
		proof, err = pccFailedSnapshot(
			request,
			requestSHA256,
			trigger,
			decision,
			coverageThrough,
			reasons,
		)
	}
	if err != nil {
		return contracts.PCCCorrelationSnapshotV1{}, ObserverState{}, 0,
			time.Time{}, err
	}
	return proof, assemblyState, sequence, decision, nil
}

func pccSnapshotNormalizedFields(
	snapshot contracts.PCCCorrelationSnapshotV1,
) (map[string]any, []byte, error) {
	canonical, err := contracts.CanonicalJSON(snapshot)
	if err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var fields map[string]any
	if err := decoder.Decode(&fields); err != nil {
		return nil, nil, err
	}
	return fields, canonical, nil
}

func signPCCSnapshotAt(
	signer *EnvelopeSigner,
	state ObserverState,
	sequence uint64,
	decision time.Time,
	snapshot contracts.PCCCorrelationSnapshotV1,
) (contracts.EventEnvelopeV1, error) {
	if signer == nil || signer.config.SourceID != "agmind-observerd" ||
		signer.config.SourceVersion != "0.1.0" ||
		len(signer.privateKey) != ed25519.PrivateKeySize ||
		sequence == 0 || state.HostID != signer.config.HostID ||
		state.BootID != signer.config.BootID || state.KeyID != signer.keyID ||
		state.KeyEpoch != signer.config.KeyEpoch {
		return contracts.EventEnvelopeV1{}, ErrPCCPublicationUnavailable
	}
	fields, canonical, err := pccSnapshotNormalizedFields(snapshot)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	normalizedDigest := sha256.Sum256(canonical)
	normalizedHash := hex.EncodeToString(normalizedDigest[:])
	var containerID *string
	var containerStart *string
	var releaseID *string
	var revision *uint64
	inventoryGeneration := uint64(0)
	switch snapshot.Outcome {
	case "complete":
		if snapshot.DockerContainerID == nil ||
			snapshot.DockerStartedAt == nil || snapshot.ImageID == nil ||
			snapshot.ImmutableSpecSHA256 == nil ||
			snapshot.InventoryGeneration == nil ||
			snapshot.InventoryRevision == nil {
			return contracts.EventEnvelopeV1{}, ErrPCCPublicationUnavailable
		}
		derivedRelease, err := contracts.ReleaseID(
			*snapshot.ImageID,
			*snapshot.ImmutableSpecSHA256,
		)
		if err != nil {
			return contracts.EventEnvelopeV1{}, err
		}
		containerIDValue := *snapshot.DockerContainerID
		containerStartValue := *snapshot.DockerStartedAt
		revisionValue := *snapshot.InventoryRevision
		containerID = &containerIDValue
		containerStart = &containerStartValue
		releaseID = &derivedRelease
		revision = &revisionValue
		inventoryGeneration = *snapshot.InventoryGeneration
	case "failed":
		if snapshot.FailureReasons == nil {
			return contracts.EventEnvelopeV1{}, ErrPCCPublicationUnavailable
		}
	default:
		return contracts.EventEnvelopeV1{}, ErrPCCPublicationUnavailable
	}
	timestamp := decision.Format(time.RFC3339Nano)
	event := contracts.EventEnvelopeV1{
		SchemaVersion:          "agmind.event-envelope.v1",
		EventType:              "pcc_correlation_snapshot",
		SourceID:               signer.config.SourceID,
		SourceVersion:          signer.config.SourceVersion,
		KeyID:                  signer.keyID,
		KeyEpoch:               signer.config.KeyEpoch,
		HostID:                 state.HostID,
		BootID:                 state.BootID,
		SourceSequence:         sequence,
		EventTime:              timestamp,
		IngestTime:             timestamp,
		ClockUncertaintyMS:     0,
		ContainerID:            containerID,
		ContainerStartTime:     containerStart,
		ReleaseID:              releaseID,
		InventoryGeneration:    inventoryGeneration,
		InventoryRevision:      revision,
		NormalizedFields:       fields,
		NormalizedFieldsSHA256: normalizedHash,
		RedactionFlags:         []string{},
		CoverageFlags:          []string{},
		SourcePayloadHash:      normalizedHash,
	}
	event.EventID, err = contracts.DeriveEventID(event)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	message, err := contracts.EventSigningMessage(event)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	event.SourceSignature = hex.EncodeToString(
		ed25519.Sign(signer.privateKey, message),
	)
	if err := event.Validate(); err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	return event, nil
}

func (service *Service) PublishPCCCorrelationSnapshot(
	ctx context.Context,
	request contracts.PCCCorrelationSnapshotRequestV1,
) (PCCCorrelationPublication, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.state == nil ||
		service.daemon.spool == nil ||
		service.daemon.spool.pccReceipts == nil {
		return PCCCorrelationPublication{}, ErrPCCPublicationUnavailable
	}
	if err := ctx.Err(); err != nil {
		return PCCCorrelationPublication{}, err
	}
	if err := request.Validate(); err != nil || request.RequestedTTLSeconds != 120 {
		return PCCCorrelationPublication{}, errors.Join(
			ErrPCCTriggerInvalid,
			err,
		)
	}
	requestSHA256, err := contracts.PCCCorrelationRequestSHA256(request)
	if err != nil {
		return PCCCorrelationPublication{}, err
	}
	operationKey := "pcc_correlation_snapshot:" + request.TriggerEventID
	state := service.daemon.state
	spool := service.daemon.spool

	state.publicationMutex.Lock()
	defer state.publicationMutex.Unlock()
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return PCCCorrelationPublication{}, err
	}

	receipt, found, err := spool.pccReceipts.lookupMetadataLocked(
		operationKey,
		requestSHA256,
	)
	if errors.Is(err, ErrPCCPublicationUnavailable) {
		return PCCCorrelationPublication{}, err
	}
	if errors.Is(err, ErrPCCReceiptConflict) {
		return PCCCorrelationPublication{}, errors.Join(
			ErrPCCPublicationConflict,
			err,
		)
	}
	if err != nil {
		pccReceiptFailState(state, "observer_pcc_receipt_binding_invalid")
		return PCCCorrelationPublication{}, errors.Join(
			ErrPCCPublicationUnavailable,
			err,
		)
	}
	snapshot := state.Snapshot()
	if snapshot.MutationReadOnly {
		return PCCCorrelationPublication{}, ErrPCCPublicationUnavailable
	}
	if found {
		item, bindErr := spool.pccReceipts.rebindLocked(receipt)
		if bindErr != nil {
			pccReceiptFailState(state, "observer_pcc_receipt_binding_invalid")
			return PCCCorrelationPublication{}, errors.Join(
				ErrPCCPublicationUnavailable,
				bindErr,
			)
		}
		published, publishErr := coreEventFromSpoolItem(item)
		if publishErr != nil {
			pccReceiptFailState(state, "observer_pcc_receipt_binding_invalid")
			return PCCCorrelationPublication{}, errors.Join(
				ErrPCCPublicationUnavailable,
				publishErr,
			)
		}
		return PCCCorrelationPublication{Item: published, Created: false}, nil
	}

	trigger, err := spool.lookupUnacknowledgedLocked(
		request.TriggerSourceSequence,
		request.TriggerEventID,
		request.TriggerContentSHA256,
	)
	if err != nil {
		if errors.Is(err, errSpoolReadOnly) {
			return PCCCorrelationPublication{}, ErrPCCPublicationUnavailable
		}
		if errors.Is(err, ErrSpoolCorrupt) {
			_ = state.PersistReadOnly("observer_pcc_trigger_lookup_corrupt")
		}
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrSpoolCorrupt) {
			return PCCCorrelationPublication{}, errors.Join(
				ErrPCCTriggerInvalid,
				err,
			)
		}
		return PCCCorrelationPublication{}, err
	}
	triggerProjection, err := validatePCCTriggerItem(trigger)
	if err != nil {
		return PCCCorrelationPublication{}, err
	}
	if service.daemon.signer == nil {
		return PCCCorrelationPublication{}, ErrPCCPublicationUnavailable
	}
	var proof contracts.PCCCorrelationSnapshotV1
	var assemblyState ObserverState
	var sequence uint64
	var decision time.Time
	if triggerProjection.BootID != snapshot.BootID {
		if service.pccBoundaryChain == nil || service.pccNow == nil {
			return PCCCorrelationPublication{}, ErrPCCPublicationUnavailable
		}
		proof, assemblyState, sequence, decision, err = assembleCrossBootPCC(
			service,
			state,
			snapshot,
			request,
			requestSHA256,
			triggerProjection,
		)
	} else {
		if service.pccInventorySnapshot == nil || service.pccLoadPins == nil ||
			service.pccNow == nil {
			return PCCCorrelationPublication{}, ErrPCCPublicationUnavailable
		}
		proof, assemblyState, sequence, decision, err = assembleSameBootPCC(
			service,
			state,
			spool,
			snapshot,
			request,
			requestSHA256,
			triggerProjection,
		)
	}
	if err != nil {
		return PCCCorrelationPublication{}, err
	}
	event, err := signPCCSnapshotAt(
		service.daemon.signer,
		assemblyState,
		sequence,
		decision,
		proof,
	)
	if err != nil {
		return PCCCorrelationPublication{}, err
	}
	canonical, err := contracts.CanonicalJSON(event)
	if err != nil {
		return PCCCorrelationPublication{}, err
	}
	contentDigest := sha256.Sum256(canonical)
	publicationReceipt := PCCPublicationReceipt{
		OperationKey:             operationKey,
		RequestSHA256:            requestSHA256,
		SnapshotNormalizedSHA256: event.NormalizedFieldsSHA256,
		SnapshotEventID:          event.EventID,
		SnapshotContentSHA256:    hex.EncodeToString(contentDigest[:]),
	}
	identity := StateIdentity{
		HostID: assemblyState.HostID, BootID: assemblyState.BootID,
		KeyID: assemblyState.KeyID, KeyEpoch: assemblyState.KeyEpoch,
	}
	item, err := spool.publishPCCLocked(
		event,
		publicationReceipt,
		func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			reserved, reserveErr := state.reserveExpected(identity, sequence)
			if reserveErr != nil {
				return reserveErr
			}
			if reserved != sequence {
				return fmt.Errorf("observer reserved unexpected PCC sequence")
			}
			return nil
		},
	)
	if err != nil {
		return PCCCorrelationPublication{}, err
	}
	published, err := coreEventFromSpoolItem(item)
	if err != nil {
		_ = state.PersistReadOnly("observer_pcc_publication_binding_invalid")
		return PCCCorrelationPublication{}, errors.Join(
			ErrPCCPublicationUnavailable,
			err,
		)
	}
	return PCCCorrelationPublication{Item: published, Created: true}, nil
}
