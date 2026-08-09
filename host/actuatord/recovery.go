package actuatord

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

func (service *Service) appendRecoveryDirty(
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

func recoveryObservationBounded(
	journal *actionJournal,
	planID string,
	prior PlanOutcome,
	observation ApplyObservation,
	sample ClockSample,
	ttl time.Duration,
) bool {
	attempt, ok := journal.attempts[planID]
	if !ok || sample.BootID != attempt.BootID || ttl <= 0 {
		return false
	}
	if observation.RemainingTimeoutMilliseconds >
		math.MaxUint64/uint64(time.Millisecond) {
		return false
	}
	remaining := observation.RemainingTimeoutMilliseconds * uint64(time.Millisecond)
	if remaining > math.MaxUint64-uint64(time.Millisecond) ||
		sample.BootTimeNS > math.MaxUint64-remaining-uint64(time.Millisecond) {
		return false
	}
	observedExpiryUpperBound := sample.BootTimeNS + remaining + uint64(time.Millisecond)
	maximumMutationDelay := uint64(postAttemptApplyTimeout)
	if uint64(ttl) > math.MaxUint64-maximumMutationDelay ||
		attempt.BootTimeNS > math.MaxUint64-maximumMutationDelay-uint64(ttl) {
		return false
	}
	latestLegitimateExpiry := attempt.BootTimeNS + maximumMutationDelay + uint64(ttl)
	if observedExpiryUpperBound > latestLegitimateExpiry {
		return false
	}
	if prior.State != "APPLIED" {
		return true
	}
	durable, ok := journal.applied[planID]
	if !ok {
		return false
	}
	return observation.RemainingTimeoutMilliseconds <=
		durable.Observation.RemainingTimeoutMilliseconds &&
		observation.CounterPackets >= durable.Observation.CounterPackets &&
		observation.CounterBytes >= durable.Observation.CounterBytes
}

func (service *Service) ReconcileIncomplete(
	ctx context.Context,
) (int, error) {
	if service == nil {
		return 0, durablefile.ErrJournalClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.closed {
		return 0, durablefile.ErrJournalClosed
	}
	if service.journal.failed() {
		return 0, durablefile.ErrJournalFailed
	}
	planIDs := make([]string, 0)
	for planID, outcome := range service.journal.outcomes {
		_, attempted := service.journal.attempts[planID]
		if (outcome.State == "APPROVED" && attempted) || outcome.State == "APPLIED" {
			planIDs = append(planIDs, planID)
		}
	}
	slices.Sort(planIDs)
	reconciled := 0
	for _, planID := range planIDs {
		if err := ctx.Err(); err != nil {
			return reconciled, err
		}
		prepared := service.journal.byPlan[planID]
		prior := service.journal.outcomes[planID]
		sample, err := lifecycleSample(service.dependencies)
		if err != nil {
			return reconciled, err
		}
		if sample.BootID != prepared.Plan.BootID {
			state, reason := "REJECTED", "nft_apply_proven_absent"
			if prior.State == "APPLIED" {
				state, reason = "EXPIRED", "native_timeout_expired"
			}
			if _, err := service.journal.appendLifecycle(
				prepared,
				sample,
				state,
				reason,
				"host_boot_changed",
				nil,
			); err != nil {
				return reconciled, err
			}
			reconciled++
			continue
		}
		absenceSample, absent, err := service.observeContainerGeneration(
			ctx,
			prepared.Plan,
		)
		if err != nil {
			return reconciled, errors.Join(ErrTargetStale, err)
		}
		if absent {
			state, reason := "REJECTED", "nft_apply_proven_absent"
			if prior.State == "APPLIED" {
				state, reason = "EXPIRED", "native_timeout_expired"
			}
			if _, err := service.journal.appendLifecycle(
				prepared,
				absenceSample,
				state,
				reason,
				"namespace_destroyed",
				nil,
			); err != nil {
				return reconciled, err
			}
			reconciled++
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
				state, reason := "REJECTED", "nft_apply_proven_absent"
				if prior.State == "APPLIED" {
					state, reason = "EXPIRED", "native_timeout_expired"
				}
				if _, appendErr := service.journal.appendLifecycle(
					prepared,
					disappearanceSample,
					state,
					reason,
					"namespace_destroyed",
					nil,
				); appendErr != nil {
					return reconciled, appendErr
				}
				reconciled++
				continue
			}
			return reconciled, errors.Join(ErrTargetStale, err, disappearanceErr)
		}
		var observation ApplyObservation
		present := false
		var postRecheckErr error
		func() {
			defer resolved.handle.Close()
			inspector, ok := service.nftBackend.(NftRecoveryBackend)
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
			observation, present, err = inspector.InspectApplied(
				ctx,
				resolved.handle,
				spec,
			)
			if err == nil && observation.RulesetSHA256 !=
				service.journal.attempts[planID].ExpectedRulesetSHA256 {
				err = ErrNftMutationUncertain
			}
			if err == nil && present {
				err = observation.validate(spec)
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
				state, reason := "REJECTED", "nft_apply_proven_absent"
				if prior.State == "APPLIED" {
					state, reason = "EXPIRED", "native_timeout_expired"
				}
				if _, appendErr := service.journal.appendLifecycle(
					prepared,
					disappearanceSample,
					state,
					reason,
					"namespace_destroyed",
					nil,
				); appendErr != nil {
					return reconciled, appendErr
				}
				reconciled++
				continue
			}
			return reconciled, errors.Join(ErrTargetStale, postRecheckErr, disappearanceErr)
		}
		if err != nil {
			failureSample := sample
			if sampleErr == nil && readbackSample.BootID == prepared.Plan.BootID {
				failureSample = readbackSample
			}
			if dirtyErr := service.appendRecoveryDirty(
				prepared,
				failureSample,
				"recovery_readback_ambiguous",
			); dirtyErr != nil {
				return reconciled, errors.Join(err, dirtyErr)
			}
			reconciled++
			continue
		}
		if !present {
			state, reason := "REJECTED", "nft_apply_proven_absent"
			if prior.State == "APPLIED" {
				state, reason = "EXPIRED", "native_timeout_expired"
			}
			if _, err := service.journal.appendLifecycle(
				prepared,
				readbackSample,
				state,
				reason,
				"kernel_timeout_observed",
				nil,
			); err != nil {
				return reconciled, err
			}
			reconciled++
			continue
		}
		ttl := time.Duration(prepared.Plan.TTLSeconds) * time.Second
		if sampleErr != nil || !recoveryObservationBounded(
			service.journal,
			planID,
			prior,
			observation,
			readbackSample,
			ttl,
		) {
			if dirtyErr := service.appendRecoveryDirty(
				prepared,
				sample,
				"recovery_timeout_or_counter_extended",
			); dirtyErr != nil {
				return reconciled, errors.Join(sampleErr, dirtyErr)
			}
			reconciled++
			continue
		}
		var applied contracts.ActionRecordV1
		if prior.State == "APPROVED" {
			attempt := service.journal.attempts[planID]
			applied, err = service.journal.appendLifecycle(
				prepared,
				readbackSample,
				"APPLIED",
				"nft_apply_observed",
				"exact_kernel_readback",
				appliedDetails(attempt, observation),
			)
			if err != nil {
				return reconciled, err
			}
		} else {
			applied = contracts.ActionRecordV1{
				RecordSHA256: prior.RecordSHA256,
			}
		}
		auditDelta := observation.RemainingTimeoutMilliseconds*uint64(time.Millisecond) +
			uint64(5*time.Second)
		if readbackSample.BootTimeNS > math.MaxUint64-auditDelta {
			return reconciled, ErrNftMutationUncertain
		}
		auditDeadline := readbackSample.BootTimeNS + auditDelta
		verifiedSample, err := lifecycleSample(service.dependencies)
		if err != nil || verifiedSample.BootID != prepared.Plan.BootID ||
			verifiedSample.BootTimeNS >= auditDeadline {
			return reconciled, errors.Join(ErrNftMutationUncertain, err)
		}
		if _, err := service.journal.appendLifecycle(
			prepared,
			verifiedSample,
			"VERIFIED",
			"nft_apply_verified",
			"proof_committed",
			verifiedDetails(
				applied.RecordSHA256,
				auditDeadline,
			),
		); err != nil {
			return reconciled, err
		}
		reconciled++
	}
	return reconciled, nil
}
