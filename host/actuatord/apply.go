package actuatord

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"agmind.local/sais/host/observerd"
	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const postAttemptApplyTimeout = 15 * time.Second

type revalidatedApply struct {
	handle ApplyTargetHandle
	sample ClockSample
}

func targetMatchesPlan(
	target PrepareTargetSnapshot,
	plan contracts.PreparedTemporaryEgressDenyPlanV1,
) bool {
	return target.InitPID == plan.InitPID &&
		target.PIDStartTicks == plan.PIDStartTicks &&
		target.CgroupPathSHA256 == plan.CgroupPathSHA256 &&
		target.NetworkNamespaceInode == plan.NetworkNamespaceInode &&
		!target.EffectiveCapNetAdmin
}

func containerGenerationMatchesPlan(
	identity observerd.ContainerIdentityV1,
	plan contracts.PreparedTemporaryEgressDenyPlanV1,
) bool {
	return identity.FullContainerID == plan.DockerContainerID &&
		identity.DockerStartedAt == plan.DockerStartedAt &&
		identity.ImageID == plan.ImageID &&
		slices.Equal(identity.RepoDigests, plan.RepoDigests) &&
		identity.ImmutableSpecSHA256 == plan.ImmutableSpecSHA256 &&
		!identity.Privileged &&
		!configuredNamespaceMutationCapability(identity.ConfiguredCapAdd) &&
		!identity.EffectiveCapNetAdmin
}

// reopenAppliedPlan binds a read-only recovery or expiry query to the original
// container/process/netns generation. Unlike pre-mutation revalidation, it
// intentionally permits unrelated observer inventory generations to advance.
func reopenAppliedPlan(
	ctx context.Context,
	plan contracts.PreparedTemporaryEgressDenyPlanV1,
	dependencies planDependencies,
	resolver ApplyTargetResolver,
) (revalidatedApply, error) {
	if resolver == nil {
		return revalidatedApply{}, ErrUnsupportedPlatform
	}
	if err := plan.Validate(); err != nil {
		return revalidatedApply{}, errors.Join(ErrTargetStale, err)
	}
	first, err := dependencies.observer.Integrity(ctx)
	first = cloneIntegrity(first)
	if err != nil || first.Validate() != nil || !first.Healthy ||
		len(first.Reasons) != 0 || first.HostID != plan.HostID || first.BootID != plan.BootID {
		return revalidatedApply{}, errors.Join(ErrObserverUnhealthy, err)
	}
	identity, err := dependencies.observer.LookupContainer(ctx, plan.DockerContainerID)
	identity = cloneContainerIdentity(identity)
	if err != nil || identity.Validate() != nil ||
		identity.InventoryGeneration != first.InventoryGeneration ||
		!containerGenerationMatchesPlan(identity, plan) {
		return revalidatedApply{}, errors.Join(ErrTargetStale, err)
	}
	handle, err := resolver.OpenForApply(ctx, plan.DockerContainerID, identity.InitPID)
	if err != nil || handle == nil {
		return revalidatedApply{}, errors.Join(ErrTargetStale, err)
	}
	fail := func(cause error) (revalidatedApply, error) {
		return revalidatedApply{}, errors.Join(cause, handle.Close())
	}
	target := handle.Snapshot()
	if err := target.validate(); err != nil || !targetMatchesPlan(target, plan) ||
		target.InitPID != identity.InitPID ||
		target.EffectiveCapNetAdmin != identity.EffectiveCapNetAdmin ||
		handle.NetNSFD() < 3 || handle.HostNetworkNamespaceInode() == 0 {
		return fail(errors.Join(ErrTargetStale, err))
	}
	uniqueness, err := dependencies.observer.CheckNetNS(
		ctx,
		observerd.NetNSUniquenessRequestV1{
			FullContainerID:       plan.DockerContainerID,
			NetworkNamespaceInode: plan.NetworkNamespaceInode,
		},
	)
	uniqueness.DockerNetworks = cloneDockerNetworks(uniqueness.DockerNetworks)
	if err != nil || uniqueness.Validate() != nil || !uniqueness.Unique ||
		uniqueness.FullContainerID != plan.DockerContainerID ||
		uniqueness.NetworkNamespaceInode != plan.NetworkNamespaceInode ||
		uniqueness.InventoryGeneration != first.InventoryGeneration {
		return fail(errors.Join(ErrTargetStale, err))
	}
	last, err := dependencies.observer.Integrity(ctx)
	last = cloneIntegrity(last)
	if err != nil || last.Validate() != nil || !exactIntegrityContinuation(first, last) {
		return fail(errors.Join(ErrObserverUnhealthy, err))
	}
	sample, err := dependencies.clock()
	if err != nil || sample.validate() != nil || sample.BootID != plan.BootID {
		return fail(errors.Join(ErrTargetStale, err))
	}
	if err := validateObservationOrder(sample.Wall, identity, first, uniqueness, last); err != nil {
		return fail(err)
	}
	if err := handle.Recheck(ctx); err != nil {
		return fail(errors.Join(ErrTargetStale, err))
	}
	return revalidatedApply{handle: handle, sample: sample}, nil
}

func revalidateApprovedPlan(
	ctx context.Context,
	plan contracts.PreparedTemporaryEgressDenyPlanV1,
	dependencies planDependencies,
	resolver ApplyTargetResolver,
) (revalidatedApply, error) {
	if resolver == nil {
		return revalidatedApply{}, ErrUnsupportedPlatform
	}
	if err := plan.Validate(); err != nil {
		return revalidatedApply{}, errors.Join(ErrTargetStale, err)
	}
	intent := intentFromPlan(plan)
	integrity, err := dependencies.observer.Integrity(ctx)
	if err != nil {
		return revalidatedApply{}, errors.Join(ErrObserverUnhealthy, err)
	}
	integrity = cloneIntegrity(integrity)
	if integrity.BootID != plan.BootID {
		return revalidatedApply{}, ErrTargetStale
	}
	identity, err := dependencies.observer.LookupContainer(ctx, plan.DockerContainerID)
	if err != nil {
		return revalidatedApply{}, errors.Join(ErrTargetStale, err)
	}
	identity = cloneContainerIdentity(identity)
	if err := exactObserverBinding(intent, integrity, identity); err != nil {
		return revalidatedApply{}, err
	}
	// The observer's fresh PID is the only address used here. The plan PID is
	// compared only after a pidfd/proc/netns handle has been opened.
	handle, err := resolver.OpenForApply(
		ctx,
		plan.DockerContainerID,
		identity.InitPID,
	)
	if err != nil || handle == nil {
		return revalidatedApply{}, errors.Join(ErrTargetStale, err)
	}
	fail := func(cause error) (revalidatedApply, error) {
		return revalidatedApply{}, errors.Join(cause, handle.Close())
	}
	target := handle.Snapshot()
	if err := target.validate(); err != nil || !targetMatchesPlan(target, plan) ||
		target.InitPID != identity.InitPID ||
		target.EffectiveCapNetAdmin != identity.EffectiveCapNetAdmin ||
		handle.NetNSFD() < 3 || handle.HostNetworkNamespaceInode() == 0 {
		return fail(errors.Join(ErrTargetStale, err))
	}
	uniqueness, err := dependencies.observer.CheckNetNS(
		ctx,
		observerd.NetNSUniquenessRequestV1{
			FullContainerID:       plan.DockerContainerID,
			NetworkNamespaceInode: target.NetworkNamespaceInode,
		},
	)
	if err != nil {
		return fail(errors.Join(ErrTargetStale, err))
	}
	uniqueness.DockerNetworks = cloneDockerNetworks(uniqueness.DockerNetworks)
	if err := uniqueness.Validate(); err != nil || !uniqueness.Unique ||
		uniqueness.FullContainerID != plan.DockerContainerID ||
		uniqueness.NetworkNamespaceInode != plan.NetworkNamespaceInode ||
		uniqueness.InventoryGeneration != plan.InventoryGeneration ||
		uniqueness.DockerNetworkSnapshotSHA256 != plan.DockerNetworkSnapshotSHA256 {
		return fail(errors.Join(ErrTargetStale, err))
	}
	safety, err := dependencies.safety.Snapshot(ctx)
	if err != nil {
		return fail(errors.Join(ErrIntentRejected, err))
	}
	safety = cloneSafety(safety)
	if safety.SpecialUseRegistrySHA256 != plan.SpecialUseRegistrySHA256 ||
		safety.ManagementDenylistSHA256 != plan.ManagementDenylistSHA256 {
		return fail(ErrTargetStale)
	}
	finalIntegrity, err := dependencies.observer.Integrity(ctx)
	if err != nil {
		return fail(errors.Join(ErrObserverUnhealthy, err))
	}
	finalIntegrity = cloneIntegrity(finalIntegrity)
	if err := finalIntegrity.Validate(); err != nil ||
		!exactIntegrityContinuation(integrity, finalIntegrity) {
		return fail(errors.Join(ErrObserverUnhealthy, err))
	}
	sample, err := dependencies.clock()
	if err != nil {
		return fail(err)
	}
	if err := sample.validate(); err != nil || sample.BootID != plan.BootID {
		return fail(errors.Join(ErrTargetStale, err))
	}
	if err := validateObservationOrder(
		sample.Wall,
		identity,
		integrity,
		uniqueness,
		finalIntegrity,
	); err != nil {
		return fail(err)
	}
	if err := validateApplyHardLimits(
		intent,
		identity,
		uniqueness.DockerNetworks,
		safety,
		sample.Wall,
	); err != nil {
		return fail(errors.Join(ErrTargetStale, err))
	}
	if err := handle.Recheck(ctx); err != nil {
		return fail(errors.Join(ErrTargetStale, err))
	}
	return revalidatedApply{handle: handle, sample: sample}, nil
}

func (journal *actionJournal) mutationLocked() bool {
	for planID, outcome := range journal.outcomes {
		if outcome.State == "FAILED_DIRTY" || outcome.State == "APPLIED" {
			return true
		}
		if outcome.State == "APPROVED" {
			if _, attempted := journal.attempts[planID]; attempted {
				return true
			}
		}
	}
	return false
}

func (service *Service) KillSwitchActive() bool {
	return service.KillSwitchStatus().EffectiveActive
}

func (journal *actionJournal) nextApprovedPlan() (preparedState, bool) {
	planIDs := make([]string, 0)
	for planID, outcome := range journal.outcomes {
		if outcome.State != "APPROVED" {
			continue
		}
		if _, attempted := journal.attempts[planID]; attempted {
			continue
		}
		planIDs = append(planIDs, planID)
	}
	slices.SortFunc(planIDs, func(left, right string) int {
		leftPlan, rightPlan := journal.byPlan[left].Plan, journal.byPlan[right].Plan
		if leftPlan.PreparedAt < rightPlan.PreparedAt {
			return -1
		}
		if leftPlan.PreparedAt > rightPlan.PreparedAt {
			return 1
		}
		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
		return 0
	})
	if len(planIDs) == 0 {
		return preparedState{}, false
	}
	return journal.byPlan[planIDs[0]], true
}

func (journal *actionJournal) activeContainmentAllowed(plan preparedState) bool {
	activeHost := 0
	for otherID, outcome := range journal.outcomes {
		if otherID == plan.Plan.PlanID {
			continue
		}
		active := outcome.State == "APPLIED" || outcome.State == "VERIFIED"
		if outcome.State == "APPROVED" {
			_, active = journal.attempts[otherID]
		}
		if !active {
			continue
		}
		activeHost++
		other := journal.byPlan[otherID].Plan
		if other.DockerContainerID == plan.Plan.DockerContainerID &&
			other.DockerStartedAt == plan.Plan.DockerStartedAt {
			return false
		}
	}
	return activeHost < 5
}

func lifecycleSample(
	dependencies planDependencies,
) (ClockSample, error) {
	sample, err := dependencies.clock()
	if err != nil {
		return ClockSample{}, err
	}
	if err := sample.validate(); err != nil {
		return ClockSample{}, err
	}
	return sample, nil
}

func (service *Service) appendPreMutationTerminal(
	prepared preparedState,
	state string,
	reason string,
	basis string,
) (contracts.ActionRecordV1, error) {
	sample, err := lifecycleSample(service.dependencies)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	return service.journal.appendLifecycle(
		prepared,
		sample,
		state,
		reason,
		basis,
		nil,
	)
}

func (service *Service) failDirtyAfterAttempt(
	prepared preparedState,
	basis string,
	cause error,
) (contracts.ActionRecordV1, error) {
	sample, sampleErr := lifecycleSample(service.dependencies)
	if sampleErr != nil {
		return contracts.ActionRecordV1{}, errors.Join(
			ErrNftMutationUncertain,
			cause,
			sampleErr,
		)
	}
	record, journalErr := service.journal.appendLifecycle(
		prepared,
		sample,
		"FAILED_DIRTY",
		"nft_result_uncertain",
		basis,
		nil,
	)
	return record, errors.Join(ErrNftMutationUncertain, cause, journalErr)
}

func (service *Service) ApplyNext(
	ctx context.Context,
) (contracts.ActionRecordV1, error) {
	if service == nil {
		return contracts.ActionRecordV1{}, fmt.Errorf("nil actuator service")
	}
	if err := ctx.Err(); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.closed {
		return contracts.ActionRecordV1{}, durablefile.ErrJournalClosed
	}
	if service.journal.failed() {
		return contracts.ActionRecordV1{}, durablefile.ErrJournalFailed
	}
	if service.manualKillSwitch || service.auditUncertain ||
		service.journal.mutationLocked() {
		return contracts.ActionRecordV1{}, ErrKillSwitchActive
	}
	prepared, ok := service.journal.nextApprovedPlan()
	if !ok {
		return contracts.ActionRecordV1{}, ErrNoApprovedPlan
	}
	if !service.journal.activeContainmentAllowed(prepared) {
		record, err := service.appendPreMutationTerminal(
			prepared,
			"REJECTED",
			"nft_preflight_rejected",
			"active_containment_limit",
		)
		return record, errors.Join(ErrIntentRejected, err)
	}
	current, err := lifecycleSample(service.dependencies)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	expiryBasis, err := planExpiryBasis(prepared, current)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	if expiryBasis != "" {
		record, appendErr := service.journal.appendLifecycle(
			prepared,
			current,
			"STALE_ABORT",
			"target_revalidation_failed",
			"approval_window_"+expiryBasis,
			nil,
		)
		return record, errors.Join(ErrTargetStale, appendErr)
	}
	resolved, err := revalidateApprovedPlan(
		ctx,
		prepared.Plan,
		service.dependencies,
		service.applyTarget,
	)
	if err != nil {
		if errors.Is(err, ErrTargetStale) || errors.Is(err, ErrIntentRejected) {
			record, appendErr := service.appendPreMutationTerminal(
				prepared,
				"STALE_ABORT",
				"target_revalidation_failed",
				"fresh_fact_mismatch",
			)
			return record, errors.Join(err, appendErr)
		}
		return contracts.ActionRecordV1{}, err
	}
	defer resolved.handle.Close()
	spec := NftApplySpec{
		PlanID:           prepared.Plan.PlanID,
		DestinationIPv4:  prepared.Plan.DestinationIPv4,
		TTL:              time.Duration(prepared.Plan.TTLSeconds) * time.Second,
		TargetNetNSInode: prepared.Plan.NetworkNamespaceInode,
	}
	if err := spec.validate(); err != nil {
		return service.appendPreMutationTerminal(
			prepared,
			"STALE_ABORT",
			"target_revalidation_failed",
			"invalid_fixed_nft_spec",
		)
	}
	if service.nftBackend == nil {
		return contracts.ActionRecordV1{}, ErrUnsupportedPlatform
	}
	mutation, err := service.nftBackend.Prepare(ctx, resolved.handle, spec)
	if err != nil || mutation == nil {
		if errors.Is(err, ErrForeignNftCollision) {
			record, appendErr := service.appendPreMutationTerminal(
				prepared,
				"REJECTED",
				"nft_preflight_rejected",
				"foreign_nft_collision",
			)
			return record, errors.Join(err, appendErr)
		}
		return contracts.ActionRecordV1{}, err
	}
	defer mutation.Close()
	if err := resolved.handle.Recheck(ctx); err != nil {
		record, appendErr := service.appendPreMutationTerminal(
			prepared,
			"STALE_ABORT",
			"target_revalidation_failed",
			"final_kernel_recheck",
		)
		return record, errors.Join(ErrTargetStale, err, appendErr)
	}
	applyCtx, cancel := context.WithTimeout(context.Background(), postAttemptApplyTimeout)
	defer cancel()
	attemptSample, err := lifecycleSample(service.dependencies)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	if attemptSample.BootID != prepared.Plan.BootID {
		record, appendErr := service.journal.appendLifecycle(
			prepared,
			attemptSample,
			"STALE_ABORT",
			"target_revalidation_failed",
			"host_boot_changed",
			nil,
		)
		return record, errors.Join(ErrTargetStale, appendErr)
	}
	if expiryBasis, err = planExpiryBasis(prepared, attemptSample); err != nil || expiryBasis != "" {
		if err != nil {
			return contracts.ActionRecordV1{}, err
		}
		record, appendErr := service.journal.appendLifecycle(
			prepared,
			attemptSample,
			"STALE_ABORT",
			"target_revalidation_failed",
			"approval_window_"+expiryBasis,
			nil,
		)
		return record, errors.Join(ErrTargetStale, appendErr)
	}
	expectedRuleset := mutation.ExpectedRulesetSHA256()
	attempt, err := service.journal.appendApplyAttempt(
		prepared,
		attemptSample,
		expectedRuleset,
	)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	if deadlineErr := applyCtx.Err(); deadlineErr != nil {
		sample, sampleErr := lifecycleSample(service.dependencies)
		if sampleErr != nil {
			return contracts.ActionRecordV1{}, errors.Join(ErrNftNotApplied, deadlineErr, sampleErr)
		}
		record, appendErr := service.journal.appendLifecycle(
			prepared,
			sample,
			"REJECTED",
			"nft_apply_proven_absent",
			"pre_flush_deadline_elapsed",
			nil,
		)
		return record, errors.Join(ErrNftNotApplied, deadlineErr, appendErr)
	}
	if recheckErr := resolved.handle.Recheck(applyCtx); recheckErr != nil {
		sample, sampleErr := lifecycleSample(service.dependencies)
		if sampleErr != nil {
			return contracts.ActionRecordV1{}, errors.Join(ErrNftNotApplied, recheckErr, sampleErr)
		}
		record, appendErr := service.journal.appendLifecycle(
			prepared,
			sample,
			"REJECTED",
			"nft_apply_proven_absent",
			"pre_flush_target_changed",
			nil,
		)
		return record, errors.Join(ErrNftNotApplied, recheckErr, appendErr)
	}
	observation, applyErr := mutation.FlushOnceAndVerify(applyCtx)
	if applyErr == nil {
		applyErr = observation.validate(spec)
	}
	if applyErr == nil && observation.RulesetSHA256 != expectedRuleset {
		applyErr = ErrNftMutationUncertain
	}
	if applyErr != nil && !errors.Is(applyErr, ErrNftMutationUncertain) &&
		errors.Is(applyErr, ErrNftNotApplied) {
		sample, sampleErr := lifecycleSample(service.dependencies)
		if sampleErr != nil {
			return contracts.ActionRecordV1{}, errors.Join(applyErr, sampleErr)
		}
		record, appendErr := service.journal.appendLifecycle(
			prepared,
			sample,
			"REJECTED",
			"nft_apply_proven_absent",
			"flush_not_sent",
			nil,
		)
		return record, errors.Join(applyErr, appendErr)
	}
	if recheckErr := resolved.handle.Recheck(applyCtx); recheckErr != nil {
		applyErr = errors.Join(ErrNftMutationUncertain, applyErr, recheckErr)
	}
	if applyErr != nil {
		return service.failDirtyAfterAttempt(prepared, "apply_or_readback_ambiguous", applyErr)
	}
	if observation.HostNetNSBefore != resolved.handle.HostNetworkNamespaceInode() {
		return service.failDirtyAfterAttempt(
			prepared,
			"host_namespace_changed",
			ErrNftMutationUncertain,
		)
	}
	appliedSample, err := lifecycleSample(service.dependencies)
	if err != nil {
		return contracts.ActionRecordV1{}, errors.Join(ErrNftMutationUncertain, err)
	}
	auditDelta := observation.RemainingTimeoutMilliseconds*uint64(time.Millisecond) +
		uint64(5*time.Second)
	if appliedSample.BootTimeNS > math.MaxUint64-auditDelta {
		return service.failDirtyAfterAttempt(
			prepared,
			"expiry_deadline_overflow",
			ErrNftMutationUncertain,
		)
	}
	auditDeadline := appliedSample.BootTimeNS + auditDelta
	applied, err := service.journal.appendLifecycle(
		prepared,
		appliedSample,
		"APPLIED",
		"nft_apply_observed",
		"exact_kernel_readback",
		appliedDetails(attempt, observation),
	)
	if err != nil {
		return contracts.ActionRecordV1{}, errors.Join(ErrNftMutationUncertain, err)
	}
	verifiedSample, err := lifecycleSample(service.dependencies)
	if err != nil || verifiedSample.BootID != prepared.Plan.BootID ||
		verifiedSample.BootTimeNS >= auditDeadline {
		return applied, errors.Join(ErrNftMutationUncertain, err)
	}
	verified, err := service.journal.appendLifecycle(
		prepared,
		verifiedSample,
		"VERIFIED",
		"nft_apply_verified",
		"proof_committed",
		verifiedDetails(applied.RecordSHA256, auditDeadline),
	)
	if err != nil {
		return contracts.ActionRecordV1{}, errors.Join(ErrNftMutationUncertain, err)
	}
	return verified, nil
}
