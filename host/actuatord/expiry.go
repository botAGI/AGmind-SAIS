package actuatord

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"agmind.local/sais/host/observerd"
	"agmind.local/sais/internal/contracts"
)

func (journal *actionJournal) hasVerifiedActions() bool {
	for _, outcome := range journal.outcomes {
		if outcome.State == "VERIFIED" {
			return true
		}
	}
	return false
}

func (service *Service) appendExpiryDirty(
	prepared preparedState,
	sample ClockSample,
	basis string,
) error {
	_, err := service.journal.appendLifecycle(
		prepared,
		sample,
		"FAILED_DIRTY",
		"nft_result_uncertain",
		basis,
		nil,
	)
	return err
}

func observerAbsenceIsCurrent(
	first observerd.ObserverIntegrityV1,
	last observerd.ObserverIntegrityV1,
	planBootID string,
	now time.Time,
) bool {
	if err := first.Validate(); err != nil {
		return false
	}
	if err := last.Validate(); err != nil {
		return false
	}
	if !first.Healthy || len(first.Reasons) != 0 || first.BootID != planBootID ||
		last.BootID != planBootID || !exactIntegrityContinuation(first, last) {
		return false
	}
	firstAt, err := parseFreshObservation(
		first.ObservedAt,
		now,
		maxIntegrityObservationAge,
	)
	if err != nil {
		return false
	}
	lastAt, err := parseFreshObservation(
		last.ObservedAt,
		now,
		maxIntegrityObservationAge,
	)
	return err == nil && !lastAt.Before(firstAt)
}

func (service *Service) observeContainerGeneration(
	ctx context.Context,
	plan contracts.PreparedTemporaryEgressDenyPlanV1,
) (ClockSample, bool, error) {
	first, err := service.dependencies.observer.Integrity(ctx)
	first = cloneIntegrity(first)
	if err != nil || first.Validate() != nil || !first.Healthy ||
		len(first.Reasons) != 0 || first.BootID != plan.BootID {
		return ClockSample{}, false, errors.Join(ErrObserverUnhealthy, err)
	}
	proveAbsence := func(cause error) (ClockSample, bool, error) {
		last, integrityErr := service.dependencies.observer.Integrity(ctx)
		last = cloneIntegrity(last)
		sample, sampleErr := lifecycleSample(service.dependencies)
		if integrityErr != nil || sampleErr != nil || sample.BootID != plan.BootID ||
			!observerAbsenceIsCurrent(first, last, plan.BootID, sample.Wall) {
			return sample, false, errors.Join(cause, integrityErr, sampleErr)
		}
		return sample, true, nil
	}
	identity, lookupErr := service.dependencies.observer.LookupContainer(
		ctx,
		plan.DockerContainerID,
	)
	if lookupErr == nil {
		identity = cloneContainerIdentity(identity)
		if identity.Validate() != nil || identity.FullContainerID != plan.DockerContainerID ||
			identity.InventoryGeneration != first.InventoryGeneration {
			return ClockSample{}, false, ErrTargetStale
		}
		if identity.DockerStartedAt != plan.DockerStartedAt {
			sample, absent, proofErr := proveAbsence(ErrTargetStale)
			if !absent {
				return sample, false, proofErr
			}
			if _, observationErr := parseFreshObservation(
				identity.ObservedAt,
				sample.Wall,
				maxInventoryObservationAge,
			); observationErr != nil {
				return sample, false, observationErr
			}
			return sample, true, nil
		}
		return ClockSample{}, false, nil
	}
	if !errors.Is(lookupErr, observerd.ErrContainerNotFound) {
		return ClockSample{}, false, lookupErr
	}
	return proveAbsence(lookupErr)
}

func (service *Service) auditDueLocked(
	ctx context.Context,
	sample ClockSample,
) (int, error) {
	planIDs := make([]string, 0)
	for planID, outcome := range service.journal.outcomes {
		if outcome.State == "VERIFIED" {
			planIDs = append(planIDs, planID)
		}
	}
	slices.Sort(planIDs)
	completed := 0
	for _, planID := range planIDs {
		if err := ctx.Err(); err != nil {
			return completed, err
		}
		prepared := service.journal.byPlan[planID]
		verified, ok := service.journal.verified[planID]
		if !ok || verified.AuditDeadlineBootTimeNS == 0 {
			return completed, fmt.Errorf("verified action lacks audit deadline")
		}
		if sample.BootID != prepared.Plan.BootID {
			if _, err := service.journal.appendLifecycle(
				prepared,
				sample,
				"EXPIRED",
				"native_timeout_expired",
				"host_boot_changed",
				nil,
			); err != nil {
				return completed, err
			}
			completed++
			continue
		}
		if sample.BootTimeNS < verified.AuditDeadlineBootTimeNS {
			continue
		}
		absenceSample, absent, err := service.observeContainerGeneration(
			ctx,
			prepared.Plan,
		)
		if err != nil {
			service.auditUncertain = true
			return completed, errors.Join(ErrTargetStale, err)
		}
		if absent {
			if _, err := service.journal.appendLifecycle(
				prepared,
				absenceSample,
				"EXPIRED",
				"native_timeout_expired",
				"namespace_destroyed",
				nil,
			); err != nil {
				return completed, err
			}
			completed++
			continue
		}
		resolved, err := reopenAppliedPlan(
			ctx,
			prepared.Plan,
			service.dependencies,
			service.applyTarget,
		)
		if err != nil {
			disappearanceSample, disappeared, disappearanceErr :=
				service.observeContainerGeneration(ctx, prepared.Plan)
			if disappearanceErr == nil && disappeared {
				if _, appendErr := service.journal.appendLifecycle(
					prepared,
					disappearanceSample,
					"EXPIRED",
					"native_timeout_expired",
					"namespace_destroyed",
					nil,
				); appendErr != nil {
					return completed, appendErr
				}
				completed++
				continue
			}
			service.auditUncertain = true
			return completed, errors.Join(ErrTargetStale, err, disappearanceErr)
		}
		var postRecheckErr error
		func() {
			defer resolved.handle.Close()
			inspector, ok := service.nftBackend.(NftExpiryBackend)
			if !ok {
				err = ErrUnsupportedPlatform
				return
			}
			spec := NftApplySpec{
				PlanID:           prepared.Plan.PlanID,
				DestinationIPv4:  prepared.Plan.DestinationIPv4,
				TTL:              time.Duration(prepared.Plan.TTLSeconds) * time.Second,
				TargetNetNSInode: prepared.Plan.NetworkNamespaceInode,
			}
			var observation ExpiryObservation
			observation, err = inspector.InspectExpiry(ctx, resolved.handle, spec)
			if err == nil {
				err = observation.validate(spec)
			}
			if err == nil && observation.RulesetSHA256 !=
				service.journal.attempts[planID].ExpectedRulesetSHA256 {
				err = ErrNftMutationUncertain
			}
			if err == nil && observation.ElementPresent {
				err = fmt.Errorf("native timeout element overstayed")
			}
			if err == nil {
				postRecheckErr = resolved.handle.Recheck(ctx)
				if postRecheckErr != nil {
					err = postRecheckErr
				}
			}
		}()
		readbackSample, sampleErr := lifecycleSample(service.dependencies)
		if sampleErr != nil || readbackSample.BootID != prepared.Plan.BootID {
			err = errors.Join(err, sampleErr, ErrTargetStale)
		}
		if postRecheckErr != nil {
			disappearanceSample, disappeared, disappearanceErr :=
				service.observeContainerGeneration(ctx, prepared.Plan)
			if disappearanceErr == nil && disappeared {
				if _, appendErr := service.journal.appendLifecycle(
					prepared,
					disappearanceSample,
					"EXPIRED",
					"native_timeout_expired",
					"namespace_destroyed",
					nil,
				); appendErr != nil {
					return completed, appendErr
				}
				completed++
				continue
			}
			service.auditUncertain = true
			return completed, errors.Join(ErrTargetStale, postRecheckErr, disappearanceErr)
		}
		if err != nil {
			failureSample := sample
			if sampleErr == nil && readbackSample.BootID == prepared.Plan.BootID {
				failureSample = readbackSample
			}
			if dirtyErr := service.appendExpiryDirty(
				prepared,
				failureSample,
				"expiry_readback_ambiguous",
			); dirtyErr != nil {
				return completed, errors.Join(err, dirtyErr)
			}
			completed++
			continue
		}
		if _, err := service.journal.appendLifecycle(
			prepared,
			readbackSample,
			"EXPIRED",
			"native_timeout_expired",
			"kernel_timeout_observed",
			nil,
		); err != nil {
			return completed, err
		}
		completed++
	}
	service.auditUncertain = false
	return completed, nil
}
