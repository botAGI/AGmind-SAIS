package actuatord

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"

	"agmind.local/sais/host/observerd"
	"agmind.local/sais/internal/contracts"
)

type Observer interface {
	Integrity(context.Context) (observerd.ObserverIntegrityV1, error)
	LookupContainer(context.Context, string) (observerd.ContainerIdentityV1, error)
	CheckNetNS(
		context.Context,
		observerd.NetNSUniquenessRequestV1,
	) (observerd.NetNSUniquenessV1, error)
}

type SafetyProvider interface {
	Snapshot(context.Context) (SafetySnapshot, error)
}

type ClockSample struct {
	Wall       time.Time
	BootTimeNS uint64
	BootID     string
}

func (sample ClockSample) validate() error {
	if sample.Wall.Location() != time.UTC || sample.Wall.IsZero() ||
		sample.BootTimeNS == 0 || !bootIDPattern.MatchString(sample.BootID) {
		return fmt.Errorf("invalid actuator clock sample")
	}
	return nil
}

type planDependencies struct {
	observer Observer
	target   TargetResolver
	safety   SafetyProvider
	clock    func() (ClockSample, error)
	random   io.Reader
}

type preparedBuild struct {
	plan                       contracts.PreparedTemporaryEgressDenyPlanV1
	approvalDeadlineBootTimeNS uint64
}

func (dependencies planDependencies) validate() error {
	if dependencies.observer == nil || dependencies.target == nil ||
		dependencies.safety == nil || dependencies.clock == nil ||
		dependencies.random == nil {
		return fmt.Errorf("incomplete actuator dependencies")
	}
	return nil
}

func exactObserverBinding(
	intent contracts.TemporaryEgressDenyIntentV1,
	integrity observerd.ObserverIntegrityV1,
	identity observerd.ContainerIdentityV1,
) error {
	if err := integrity.Validate(); err != nil {
		return errors.Join(ErrObserverUnhealthy, err)
	}
	if !integrity.Healthy || len(integrity.Reasons) != 0 {
		return ErrObserverUnhealthy
	}
	if err := identity.Validate(); err != nil {
		return errors.Join(ErrTargetStale, err)
	}
	if integrity.HostID != intent.HostID ||
		integrity.InventoryGeneration != intent.InventoryGeneration ||
		!intentMatchesIdentity(intent, identity) {
		return ErrTargetStale
	}
	return nil
}

func cloneIntent(
	intent contracts.TemporaryEgressDenyIntentV1,
) contracts.TemporaryEgressDenyIntentV1 {
	cloned := intent
	cloned.RepoDigests = slices.Clone(intent.RepoDigests)
	cloned.EvidenceIDs = slices.Clone(intent.EvidenceIDs)
	return cloned
}

func cloneContainerIdentity(
	identity observerd.ContainerIdentityV1,
) observerd.ContainerIdentityV1 {
	cloned := identity
	cloned.RepoDigests = slices.Clone(identity.RepoDigests)
	cloned.ConfiguredCapAdd = slices.Clone(identity.ConfiguredCapAdd)
	cloned.ConfiguredCapDrop = slices.Clone(identity.ConfiguredCapDrop)
	cloned.AttachedNetworks = make(
		[]observerd.AttachedNetworkV1,
		len(identity.AttachedNetworks),
	)
	for index, network := range identity.AttachedNetworks {
		cloned.AttachedNetworks[index] = network
		cloned.AttachedNetworks[index].SubnetCIDRs = slices.Clone(network.SubnetCIDRs)
		cloned.AttachedNetworks[index].GatewayAddresses = slices.Clone(network.GatewayAddresses)
	}
	return cloned
}

func cloneIntegrity(
	integrity observerd.ObserverIntegrityV1,
) observerd.ObserverIntegrityV1 {
	cloned := integrity
	cloned.Reasons = slices.Clone(integrity.Reasons)
	return cloned
}

func cloneDockerNetworks(
	networks []contracts.PCCDockerNetworkV1,
) []contracts.PCCDockerNetworkV1 {
	cloned := make([]contracts.PCCDockerNetworkV1, len(networks))
	for index, network := range networks {
		cloned[index] = network
		cloned[index].SubnetCIDRs = slices.Clone(network.SubnetCIDRs)
		cloned[index].GatewayAddresses = slices.Clone(network.GatewayAddresses)
	}
	return cloned
}

func cloneSafety(snapshot SafetySnapshot) SafetySnapshot {
	cloned := snapshot
	cloned.SpecialUseRegistryRaw = slices.Clone(snapshot.SpecialUseRegistryRaw)
	cloned.ManagementDeniedNetworks = slices.Clone(snapshot.ManagementDeniedNetworks)
	cloned.ManagementDeniedAddresses = slices.Clone(snapshot.ManagementDeniedAddresses)
	return cloned
}

func clonePlan(
	plan contracts.PreparedTemporaryEgressDenyPlanV1,
) contracts.PreparedTemporaryEgressDenyPlanV1 {
	cloned := plan
	cloned.RepoDigests = slices.Clone(plan.RepoDigests)
	cloned.EvidenceIDs = slices.Clone(plan.EvidenceIDs)
	return cloned
}

func exactIntegrityContinuation(
	first observerd.ObserverIntegrityV1,
	last observerd.ObserverIntegrityV1,
) bool {
	return last.Healthy && len(last.Reasons) == 0 &&
		first.HostID == last.HostID && first.BootID == last.BootID &&
		first.KeyID == last.KeyID && first.KeyEpoch == last.KeyEpoch &&
		first.InventoryGeneration == last.InventoryGeneration
}

func parseFreshObservation(
	value string,
	now time.Time,
	maximumAge time.Duration,
) (time.Time, error) {
	observed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || observed.After(now) || now.Sub(observed) > maximumAge {
		return time.Time{}, ErrTargetStale
	}
	return observed, nil
}

func validateObservationOrder(
	now time.Time,
	identity observerd.ContainerIdentityV1,
	first observerd.ObserverIntegrityV1,
	uniqueness observerd.NetNSUniquenessV1,
	last observerd.ObserverIntegrityV1,
) error {
	identityAt, err := parseFreshObservation(
		identity.ObservedAt,
		now,
		maxInventoryObservationAge,
	)
	if err != nil {
		return err
	}
	firstAt, err := parseFreshObservation(
		first.ObservedAt,
		now,
		maxIntegrityObservationAge,
	)
	if err != nil {
		return err
	}
	uniqueAt, err := parseFreshObservation(
		uniqueness.CheckedAt,
		now,
		maxUniquenessObservationAge,
	)
	if err != nil {
		return err
	}
	lastAt, err := parseFreshObservation(
		last.ObservedAt,
		now,
		maxIntegrityObservationAge,
	)
	if err != nil {
		return err
	}
	if identityAt.After(firstAt) || firstAt.After(uniqueAt) ||
		uniqueAt.After(lastAt) {
		return ErrTargetStale
	}
	return nil
}

func buildPreparedPlan(
	ctx context.Context,
	intent contracts.TemporaryEgressDenyIntentV1,
	dependencies planDependencies,
) (preparedBuild, error) {
	if err := dependencies.validate(); err != nil {
		return preparedBuild{}, err
	}
	intent = cloneIntent(intent)
	if err := intent.Validate(); err != nil {
		return preparedBuild{}, errors.Join(ErrIntentRejected, err)
	}
	integrity, err := dependencies.observer.Integrity(ctx)
	if err != nil {
		return preparedBuild{}, errors.Join(ErrObserverUnhealthy, err)
	}
	integrity = cloneIntegrity(integrity)
	identity, err := dependencies.observer.LookupContainer(
		ctx,
		intent.DockerContainerID,
	)
	if err != nil {
		return preparedBuild{}, errors.Join(ErrTargetStale, err)
	}
	identity = cloneContainerIdentity(identity)
	if err := exactObserverBinding(intent, integrity, identity); err != nil {
		return preparedBuild{}, err
	}
	targetHandle, err := dependencies.target.ResolveForPrepare(
		ctx,
		intent.DockerContainerID,
		identity.InitPID,
	)
	if err != nil || targetHandle == nil {
		return preparedBuild{}, errors.Join(ErrTargetStale, err)
	}
	target := targetHandle.Snapshot()
	if err := target.validate(); err != nil ||
		target.InitPID != identity.InitPID ||
		target.EffectiveCapNetAdmin != identity.EffectiveCapNetAdmin ||
		target.EffectiveCapNetAdmin {
		closeErr := targetHandle.Close()
		return preparedBuild{}, errors.Join(ErrTargetStale, err, closeErr)
	}
	uniqueness, err := dependencies.observer.CheckNetNS(
		ctx,
		observerd.NetNSUniquenessRequestV1{
			FullContainerID:       intent.DockerContainerID,
			NetworkNamespaceInode: target.NetworkNamespaceInode,
		},
	)
	closeErr := targetHandle.Close()
	if err != nil || closeErr != nil {
		return preparedBuild{}, errors.Join(ErrTargetStale, err, closeErr)
	}
	uniqueness.DockerNetworks = cloneDockerNetworks(uniqueness.DockerNetworks)
	if err := uniqueness.Validate(); err != nil ||
		uniqueness.FullContainerID != intent.DockerContainerID ||
		uniqueness.NetworkNamespaceInode != target.NetworkNamespaceInode ||
		uniqueness.InventoryGeneration != integrity.InventoryGeneration {
		return preparedBuild{}, errors.Join(ErrTargetStale, err)
	}
	safety, err := dependencies.safety.Snapshot(ctx)
	if err != nil {
		return preparedBuild{}, errors.Join(ErrIntentRejected, err)
	}
	safety = cloneSafety(safety)
	finalIntegrity, err := dependencies.observer.Integrity(ctx)
	if err != nil {
		return preparedBuild{}, errors.Join(ErrObserverUnhealthy, err)
	}
	finalIntegrity = cloneIntegrity(finalIntegrity)
	if err := finalIntegrity.Validate(); err != nil ||
		!exactIntegrityContinuation(integrity, finalIntegrity) {
		return preparedBuild{}, errors.Join(ErrObserverUnhealthy, err)
	}
	clock, err := dependencies.clock()
	if err != nil {
		return preparedBuild{}, err
	}
	if err := clock.validate(); err != nil {
		return preparedBuild{}, err
	}
	if clock.BootID != integrity.BootID {
		return preparedBuild{}, ErrTargetStale
	}
	if err := validateObservationOrder(
		clock.Wall,
		identity,
		integrity,
		uniqueness,
		finalIntegrity,
	); err != nil {
		return preparedBuild{}, err
	}
	if err := validateHardLimits(
		intent,
		identity,
		uniqueness.DockerNetworks,
		safety,
		clock.Wall,
	); err != nil {
		return preparedBuild{}, err
	}
	if err := ctx.Err(); err != nil {
		return preparedBuild{}, err
	}
	var nonce [32]byte
	if _, err := io.ReadFull(dependencies.random, nonce[:]); err != nil {
		return preparedBuild{}, err
	}
	planID, err := contracts.PlanID(intent.IntentID, nonce[:])
	if err != nil {
		return preparedBuild{}, err
	}
	preparedAt := clock.Wall.UTC()
	deadlineDelta := uint64(ApprovalTTL)
	if clock.BootTimeNS > math.MaxUint64-deadlineDelta {
		return preparedBuild{}, fmt.Errorf("approval deadline overflow")
	}
	plan := contracts.PreparedTemporaryEgressDenyPlanV1{
		EgressDenyFields:            intent.EgressDenyFields,
		PlanID:                      planID,
		BootID:                      integrity.BootID,
		InitPID:                     target.InitPID,
		PIDStartTicks:               target.PIDStartTicks,
		CgroupPathSHA256:            target.CgroupPathSHA256,
		NetworkNamespaceInode:       target.NetworkNamespaceInode,
		DockerNetworkSnapshotSHA256: uniqueness.DockerNetworkSnapshotSHA256,
		SpecialUseRegistrySHA256:    safety.SpecialUseRegistrySHA256,
		ManagementDenylistSHA256:    safety.ManagementDenylistSHA256,
		HardLimitsVersion:           "pcc-hard-limits-v1",
		PreparedAt:                  preparedAt.Format(time.RFC3339Nano),
		ApprovalExpiresAt:           preparedAt.Add(ApprovalTTL).Format(time.RFC3339Nano),
		Nonce:                       hex.EncodeToString(nonce[:]),
	}
	plan.SchemaVersion = "agmind.prepared-temporary-egress-deny-plan.v1"
	planHash, err := contracts.PlanHash(plan)
	if err != nil {
		return preparedBuild{}, err
	}
	plan.PlanHashValue = planHash
	if err := plan.Validate(); err != nil {
		return preparedBuild{}, err
	}
	return preparedBuild{
		plan:                       plan,
		approvalDeadlineBootTimeNS: clock.BootTimeNS + deadlineDelta,
	}, nil
}

func defaultPlanDependencies() planDependencies {
	return planDependencies{
		target: NewPlatformTargetResolver(),
		clock:  platformClockSample,
		random: rand.Reader,
	}
}
