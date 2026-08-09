package actuatord

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const (
	applyAttemptHashDomain    = "AGMIND_APPLY_ATTEMPT_HASH_V1\x00"
	applyAttemptSigningDomain = "AGMIND_APPLY_ATTEMPT_V1\x00"
	maxLifecycleFramesPerPlan = 6
)

var applyAttemptIDPattern = regexp.MustCompile(`^aa_[0-9a-f]{32}$`)

type applyAttemptV1 struct {
	SchemaVersion              string `json:"schema_version"`
	AttemptID                  string `json:"attempt_id"`
	PlanID                     string `json:"plan_id"`
	PlanHashValue              string `json:"plan_hash"`
	StartedAt                  string `json:"started_at"`
	BootID                     string `json:"boot_id"`
	BootTimeNS                 uint64 `json:"boottime_ns"`
	TargetNetNSInode           uint64 `json:"target_netns_inode"`
	DestinationIPv4            string `json:"destination_ipv4"`
	TTLSeconds                 uint64 `json:"ttl_seconds"`
	ExpectedRulesetSHA256      string `json:"expected_ruleset_sha256"`
	PreviousActionRecordSHA256 string `json:"previous_action_record_sha256"`
	PreviousRecordSHA256       string `json:"previous_record_sha256"`
	RecordSHA256               string `json:"record_sha256"`
	ActuatorKeyID              string `json:"actuator_key_id"`
	ActuatorSignature          string `json:"actuator_signature"`
}

type applyAttemptState struct {
	RecordSHA256          string
	StartedAt             string
	BootID                string
	BootTimeNS            uint64
	TargetNetNSInode      uint64
	ExpectedRulesetSHA256 string
}

type verifiedActionState struct {
	AuditDeadlineBootTimeNS uint64
}

type appliedActionState struct {
	Observation ApplyObservation
}

func decodeAppliedObservation(
	details map[string]any,
) (ApplyObservation, error) {
	netns, netnsOK := uintDetail(details["target_netns_inode"], 64)
	configured, configuredOK := uintDetail(details["configured_timeout_ms"], 64)
	remaining, remainingOK := uintDetail(details["remaining_timeout_ms"], 64)
	packets, packetsOK := uintDetail(details["counter_packets"], 64)
	byteCount, bytesOK := uintDetail(details["counter_bytes"], 64)
	hostBefore, beforeOK := uintDetail(details["host_netns_before"], 64)
	hostAfter, afterOK := uintDetail(details["host_netns_after"], 64)
	ruleset, rulesetOK := detailString(details, "ruleset_sha256")
	if !netnsOK || !configuredOK || !remainingOK || !packetsOK || !bytesOK ||
		!beforeOK || !afterOK || !rulesetOK {
		return ApplyObservation{}, fmt.Errorf("invalid APPLIED observation fields")
	}
	return ApplyObservation{
		TargetNetNSInode:              netns,
		RulesetSHA256:                 ruleset,
		ConfiguredTimeoutMilliseconds: configured,
		RemainingTimeoutMilliseconds:  remaining,
		CounterPackets:                packets,
		CounterBytes:                  byteCount,
		HostNetNSBefore:               hostBefore,
		HostNetNSAfter:                hostAfter,
	}, nil
}

func (record applyAttemptV1) Validate() error {
	destination, err := netip.ParseAddr(record.DestinationIPv4)
	if record.SchemaVersion != "agmind.apply-attempt.v1" ||
		!applyAttemptIDPattern.MatchString(record.AttemptID) ||
		!planIDPattern.MatchString(record.PlanID) ||
		!digestPattern.MatchString(record.PlanHashValue) ||
		!bootIDPattern.MatchString(record.BootID) || record.BootTimeNS == 0 ||
		record.TargetNetNSInode == 0 || err != nil || !destination.Is4() ||
		destination.String() != record.DestinationIPv4 ||
		record.TTLSeconds < MinTTLSeconds || record.TTLSeconds > MaxTTLSeconds ||
		!digestPattern.MatchString(record.ExpectedRulesetSHA256) ||
		!digestPattern.MatchString(record.PreviousActionRecordSHA256) ||
		!digestPattern.MatchString(record.PreviousRecordSHA256) ||
		!digestPattern.MatchString(record.RecordSHA256) ||
		!rateReservationKeyIDPattern.MatchString(record.ActuatorKeyID) ||
		!rateReservationSignaturePattern.MatchString(record.ActuatorSignature) {
		return fmt.Errorf("invalid apply attempt")
	}
	started, err := time.Parse(time.RFC3339Nano, record.StartedAt)
	if err != nil || record.StartedAt != started.UTC().Format(time.RFC3339Nano) {
		return fmt.Errorf("invalid apply attempt timestamp")
	}
	expected, err := applyAttemptHash(record)
	if err != nil || expected != record.RecordSHA256 ||
		record.AttemptID != "aa_"+expected[:32] {
		return fmt.Errorf("invalid apply attempt hash")
	}
	return nil
}

func applyAttemptHash(record applyAttemptV1) (string, error) {
	document, err := objectFromCanonical(record)
	if err != nil {
		return "", err
	}
	delete(document, "attempt_id")
	delete(document, "record_sha256")
	delete(document, "actuator_signature")
	canonical, err := contracts.CanonicalJSON(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(applyAttemptHashDomain), canonical...))
	return hex.EncodeToString(sum[:]), nil
}

func applyAttemptSigningMessage(record applyAttemptV1) ([]byte, error) {
	document, err := objectFromCanonical(record)
	if err != nil {
		return nil, err
	}
	delete(document, "actuator_signature")
	canonical, err := contracts.CanonicalJSON(document)
	if err != nil {
		return nil, err
	}
	return append([]byte(applyAttemptSigningDomain), canonical...), nil
}

func verifyApplyAttempt(record applyAttemptV1, publicKey ed25519.PublicKey) error {
	if err := record.Validate(); err != nil {
		return err
	}
	keyID, err := contracts.KeyID(publicKey)
	if err != nil || keyID != record.ActuatorKeyID {
		return fmt.Errorf("apply attempt key binding mismatch")
	}
	signature, err := hex.DecodeString(record.ActuatorSignature)
	message, messageErr := applyAttemptSigningMessage(record)
	if err != nil || messageErr != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("invalid apply attempt signature")
	}
	return nil
}

func validateRecoveredApplyAttempt(
	payload []byte,
	record applyAttemptV1,
	publicKey ed25519.PublicKey,
	expectedPrevious string,
	prepared preparedState,
	approved PlanOutcome,
) (applyAttemptState, error) {
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil || !bytes.Equal(canonical, payload) {
		return applyAttemptState{}, fmt.Errorf("apply attempt is not canonical")
	}
	if err := verifyApplyAttempt(record, publicKey); err != nil {
		return applyAttemptState{}, err
	}
	if approved.State != "APPROVED" ||
		record.PreviousRecordSHA256 != expectedPrevious ||
		record.PreviousActionRecordSHA256 != approved.RecordSHA256 ||
		record.PlanID != prepared.Plan.PlanID ||
		record.PlanHashValue != prepared.Plan.PlanHashValue ||
		record.BootID != prepared.Plan.BootID ||
		record.TargetNetNSInode != prepared.Plan.NetworkNamespaceInode ||
		record.DestinationIPv4 != prepared.Plan.DestinationIPv4 ||
		record.TTLSeconds != prepared.Plan.TTLSeconds {
		return applyAttemptState{}, fmt.Errorf("apply attempt does not bind approved plan")
	}
	return applyAttemptState{
		RecordSHA256:          record.RecordSHA256,
		StartedAt:             record.StartedAt,
		BootID:                record.BootID,
		BootTimeNS:            record.BootTimeNS,
		TargetNetNSInode:      record.TargetNetNSInode,
		ExpectedRulesetSHA256: record.ExpectedRulesetSHA256,
	}, nil
}

func (journal *actionJournal) appendApplyAttempt(
	prepared preparedState,
	sample ClockSample,
	expectedRulesetSHA256 string,
) (applyAttemptState, error) {
	if journal.closed {
		return applyAttemptState{}, durablefile.ErrJournalClosed
	}
	if journal.failed() {
		return applyAttemptState{}, durablefile.ErrJournalFailed
	}
	approved, ok := journal.outcomes[prepared.Plan.PlanID]
	if !ok || approved.State != "APPROVED" {
		return applyAttemptState{}, ErrNoApprovedPlan
	}
	if _, exists := journal.attempts[prepared.Plan.PlanID]; exists {
		return applyAttemptState{}, ErrKillSwitchActive
	}
	if err := sample.validate(); err != nil || sample.BootID != prepared.Plan.BootID ||
		!digestPattern.MatchString(expectedRulesetSHA256) {
		return applyAttemptState{}, fmt.Errorf("invalid apply attempt inputs")
	}
	record := applyAttemptV1{
		SchemaVersion:              "agmind.apply-attempt.v1",
		PlanID:                     prepared.Plan.PlanID,
		PlanHashValue:              prepared.Plan.PlanHashValue,
		StartedAt:                  sample.Wall.Format(time.RFC3339Nano),
		BootID:                     sample.BootID,
		BootTimeNS:                 sample.BootTimeNS,
		TargetNetNSInode:           prepared.Plan.NetworkNamespaceInode,
		DestinationIPv4:            prepared.Plan.DestinationIPv4,
		TTLSeconds:                 prepared.Plan.TTLSeconds,
		ExpectedRulesetSHA256:      expectedRulesetSHA256,
		PreviousActionRecordSHA256: approved.RecordSHA256,
		PreviousRecordSHA256:       journal.previous,
		ActuatorKeyID:              journal.keyID,
	}
	hash, err := applyAttemptHash(record)
	if err != nil {
		return applyAttemptState{}, err
	}
	record.RecordSHA256 = hash
	record.AttemptID = "aa_" + hash[:32]
	message, err := applyAttemptSigningMessage(record)
	if err != nil {
		return applyAttemptState{}, err
	}
	record.ActuatorSignature = hex.EncodeToString(ed25519.Sign(journal.privateKey, message))
	if err := verifyApplyAttempt(record, journal.publicKey); err != nil {
		return applyAttemptState{}, err
	}
	payload, err := contracts.CanonicalJSON(record)
	if err != nil {
		return applyAttemptState{}, err
	}
	if err := journal.ensureTransitionCapacity(
		prepared.Plan.PlanID,
		int64(len(payload))+actionFrameOverhead,
		lifecycleFutureFrames("APPROVED", true),
	); err != nil {
		return applyAttemptState{}, err
	}
	meta, err := journal.stream.Append(payload, true)
	if err != nil {
		return applyAttemptState{}, err
	}
	state := applyAttemptState{
		RecordSHA256:          record.RecordSHA256,
		StartedAt:             record.StartedAt,
		BootID:                record.BootID,
		BootTimeNS:            record.BootTimeNS,
		TargetNetNSInode:      record.TargetNetNSInode,
		ExpectedRulesetSHA256: record.ExpectedRulesetSHA256,
	}
	journal.previous = record.RecordSHA256
	journal.attempts[prepared.Plan.PlanID] = state
	journal.recordCount++
	journal.byteCount += int64(meta.Size)
	return state, nil
}

func lifecycleReasonAllowed(state, reason, basis string) bool {
	switch state {
	case "STALE_ABORT":
		return reason == "target_revalidation_failed" && basis != ""
	case "REJECTED":
		return (reason == "nft_preflight_rejected" || reason == "nft_apply_proven_absent") && basis != ""
	case "FAILED_DIRTY":
		return reason == "nft_result_uncertain" && basis != ""
	case "APPLIED":
		return reason == "nft_apply_observed" && basis == "exact_kernel_readback"
	case "VERIFIED":
		return reason == "nft_apply_verified" && basis == "proof_committed"
	case "EXPIRED":
		return reason == "native_timeout_expired" &&
			(basis == "kernel_timeout_observed" || basis == "namespace_destroyed" ||
				basis == "host_boot_changed")
	default:
		return false
	}
}

func detailString(values map[string]any, key string) (string, bool) {
	value, ok := values[key].(string)
	return value, ok
}

func validateLifecycleDetails(
	record contracts.ActionRecordV1,
	expectedPerPlanPrevious string,
	prepared preparedState,
) error {
	previous, ok := detailString(record.Details, "previous_action_record_sha256")
	if !ok || previous != expectedPerPlanPrevious {
		return fmt.Errorf("lifecycle action lacks per-plan predecessor")
	}
	basis, ok := detailString(record.Details, "transition_basis")
	if !ok || !lifecycleReasonAllowed(record.State, record.ReasonCode, basis) {
		return fmt.Errorf("invalid lifecycle reason")
	}
	bootID, bootOK := detailString(record.Details, "transition_boot_id")
	bootTime, timeOK := uintDetail(record.Details["transition_boottime_ns"], 64)
	if !bootOK || !timeOK || bootTime == 0 || !bootIDPattern.MatchString(bootID) {
		return fmt.Errorf("invalid lifecycle clock")
	}
	if record.State != "EXPIRED" && record.State != "STALE_ABORT" &&
		record.State != "REJECTED" &&
		bootID != prepared.Plan.BootID {
		return fmt.Errorf("lifecycle boot changed")
	}
	switch record.State {
	case "STALE_ABORT", "REJECTED", "FAILED_DIRTY":
		if len(record.Details) != 4 {
			return fmt.Errorf("unexpected terminal lifecycle details")
		}
	case "APPLIED":
		if len(record.Details) != 13 {
			return fmt.Errorf("unexpected APPLIED details")
		}
		observation, observationErr := decodeAppliedObservation(record.Details)
		attemptHash, attemptOK := detailString(record.Details, "apply_attempt_sha256")
		configuredExpected := prepared.Plan.TTLSeconds * 1000
		if observationErr != nil || !digestPattern.MatchString(observation.RulesetSHA256) ||
			observation.TargetNetNSInode != prepared.Plan.NetworkNamespaceInode ||
			observation.ConfiguredTimeoutMilliseconds != configuredExpected ||
			observation.RemainingTimeoutMilliseconds == 0 ||
			observation.RemainingTimeoutMilliseconds > observation.ConfiguredTimeoutMilliseconds ||
			observation.HostNetNSBefore == 0 ||
			observation.HostNetNSBefore != observation.HostNetNSAfter || !attemptOK ||
			attemptHash != expectedPerPlanPrevious {
			return fmt.Errorf("invalid APPLIED observation")
		}
	case "VERIFIED":
		if len(record.Details) != 6 {
			return fmt.Errorf("unexpected VERIFIED details")
		}
		appliedHash, appliedOK := detailString(record.Details, "applied_record_sha256")
		auditDeadline, auditOK := uintDetail(record.Details["audit_deadline_boottime_ns"], 64)
		if !appliedOK || appliedHash != expectedPerPlanPrevious || !auditOK ||
			auditDeadline <= bootTime {
			return fmt.Errorf("invalid VERIFIED binding")
		}
	case "EXPIRED":
		if len(record.Details) != 4 {
			return fmt.Errorf("unexpected EXPIRED details")
		}
	}
	return nil
}

func lifecycleTransitionAllowed(
	prior string,
	hasAttempt bool,
	next string,
) bool {
	switch prior {
	case "APPROVED":
		if hasAttempt {
			return next == "APPLIED" || next == "REJECTED" || next == "FAILED_DIRTY"
		}
		return next == "STALE_ABORT" || next == "REJECTED"
	case "APPLIED":
		return hasAttempt &&
			(next == "VERIFIED" || next == "EXPIRED" || next == "FAILED_DIRTY")
	case "VERIFIED":
		return hasAttempt && (next == "EXPIRED" || next == "FAILED_DIRTY")
	default:
		return false
	}
}

func validateRecoveredLifecycleRecord(
	payload []byte,
	record contracts.ActionRecordV1,
	publicKey ed25519.PublicKey,
	expectedGlobalPrevious string,
	prepared preparedState,
	prior PlanOutcome,
	attempt applyAttemptState,
	hasAttempt bool,
) (PlanOutcome, error) {
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil || !bytes.Equal(canonical, payload) {
		return PlanOutcome{}, fmt.Errorf("lifecycle action record is not canonical")
	}
	if err := contracts.VerifyActionRecord(record, publicKey); err != nil {
		return PlanOutcome{}, err
	}
	if record.ActionID == nil || record.PreviousRecordSHA256 != expectedGlobalPrevious ||
		record.PlanID != prepared.Plan.PlanID ||
		record.PlanHashValue != prepared.Plan.PlanHashValue ||
		!lifecycleTransitionAllowed(prior.State, hasAttempt, record.State) {
		return PlanOutcome{}, fmt.Errorf("invalid lifecycle transition")
	}
	perPlanPrevious := prior.RecordSHA256
	if prior.State == "APPROVED" && hasAttempt {
		perPlanPrevious = attempt.RecordSHA256
	}
	if err := validateLifecycleDetails(record, perPlanPrevious, prepared); err != nil {
		return PlanOutcome{}, err
	}
	if record.State == "APPLIED" {
		observation, err := decodeAppliedObservation(record.Details)
		if err != nil || observation.RulesetSHA256 != attempt.ExpectedRulesetSHA256 {
			return PlanOutcome{}, fmt.Errorf("APPLIED ruleset does not bind apply attempt")
		}
	}
	return PlanOutcome{
		State:        record.State,
		RecordID:     record.RecordID,
		RecordSHA256: record.RecordSHA256,
		ObservedAt:   record.ObservedAt,
	}, nil
}

func lifecycleFutureFrames(state string, hasAttempt bool) int {
	switch state {
	case "":
		return maxLifecycleFramesPerPlan
	case "APPROVED":
		if hasAttempt {
			return 4
		}
		return 5
	case "APPLIED":
		return 3
	case "VERIFIED":
		return 2
	case "FAILED_DIRTY":
		// Preserve a durable operator-control transition even at the journal
		// byte/record bound. The clear command is implemented separately.
		return 1
	default:
		return 0
	}
}

func futureFrameBudget(
	byPlan map[string]preparedState,
	outcomes map[string]PlanOutcome,
	attempts map[string]applyAttemptState,
) int {
	total := 0
	for planID := range byPlan {
		outcome := outcomes[planID]
		_, attempted := attempts[planID]
		total += lifecycleFutureFrames(outcome.State, attempted)
	}
	return total
}

func (journal *actionJournal) ensureTransitionCapacity(
	planID string,
	frameSize int64,
	newPlanBudget int,
) error {
	oldOutcome := journal.outcomes[planID]
	_, oldAttempted := journal.attempts[planID]
	oldBudget := lifecycleFutureFrames(oldOutcome.State, oldAttempted)
	totalBudget := futureFrameBudget(journal.byPlan, journal.outcomes, journal.attempts)
	newTotal := totalBudget - oldBudget + newPlanBudget
	if newTotal < 0 || journal.recordCount+1+newTotal > actionJournalMaxRecords ||
		frameSize+int64(newTotal)*(int64(actionJournalMaxFrame)+actionFrameOverhead) >
			actionJournalMaxBytes-journal.byteCount {
		return ErrPendingLimit
	}
	return nil
}

func signActionRecord(
	journal *actionJournal,
	record contracts.ActionRecordV1,
) (contracts.ActionRecordV1, []byte, error) {
	hash, err := contracts.ActionRecordHash(record)
	if err != nil {
		return contracts.ActionRecordV1{}, nil, err
	}
	record.RecordSHA256 = hash
	record.RecordID = contracts.ActionRecordID(hash)
	message, err := contracts.ActionRecordSigningMessage(record)
	if err != nil {
		return contracts.ActionRecordV1{}, nil, err
	}
	record.ActuatorSignature = hex.EncodeToString(ed25519.Sign(journal.privateKey, message))
	if err := contracts.VerifyActionRecord(record, journal.publicKey); err != nil {
		return contracts.ActionRecordV1{}, nil, err
	}
	payload, err := contracts.CanonicalJSON(record)
	return record, payload, err
}

func (journal *actionJournal) appendLifecycle(
	prepared preparedState,
	sample ClockSample,
	state string,
	reason string,
	basis string,
	extra map[string]any,
) (contracts.ActionRecordV1, error) {
	if journal.closed {
		return contracts.ActionRecordV1{}, durablefile.ErrJournalClosed
	}
	if journal.failed() {
		return contracts.ActionRecordV1{}, durablefile.ErrJournalFailed
	}
	prior, ok := journal.outcomes[prepared.Plan.PlanID]
	if !ok {
		return contracts.ActionRecordV1{}, fmt.Errorf("lifecycle action lacks approved plan")
	}
	attempt, attempted := journal.attempts[prepared.Plan.PlanID]
	if !lifecycleTransitionAllowed(prior.State, attempted, state) ||
		!lifecycleReasonAllowed(state, reason, basis) {
		return contracts.ActionRecordV1{}, fmt.Errorf("invalid lifecycle transition")
	}
	if err := sample.validate(); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	perPlanPrevious := prior.RecordSHA256
	if prior.State == "APPROVED" && attempted {
		perPlanPrevious = attempt.RecordSHA256
	}
	details := make(map[string]any, len(extra)+4)
	for key, value := range extra {
		details[key] = value
	}
	details["previous_action_record_sha256"] = perPlanPrevious
	details["transition_boot_id"] = sample.BootID
	details["transition_boottime_ns"] = sample.BootTimeNS
	details["transition_basis"] = basis
	actionID, err := contracts.ActionID(prepared.Plan.PlanHashValue)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	record := contracts.ActionRecordV1{
		SchemaVersion:        "agmind.action-record.v1",
		ActionID:             &actionID,
		PlanID:               prepared.Plan.PlanID,
		PlanHashValue:        prepared.Plan.PlanHashValue,
		State:                state,
		ReasonCode:           reason,
		ObservedAt:           sample.Wall.Format(time.RFC3339Nano),
		PreviousRecordSHA256: journal.previous,
		Details:              details,
		ActuatorKeyID:        journal.keyID,
	}
	record, payload, err := signActionRecord(journal, record)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	if err := validateLifecycleDetails(record, perPlanPrevious, prepared); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	newBudget := lifecycleFutureFrames(state, attempted)
	if err := journal.ensureTransitionCapacity(
		prepared.Plan.PlanID,
		int64(len(payload))+actionFrameOverhead,
		newBudget,
	); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	meta, err := journal.stream.Append(payload, true)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	outcome := PlanOutcome{
		State:        state,
		RecordID:     record.RecordID,
		RecordSHA256: record.RecordSHA256,
		ObservedAt:   record.ObservedAt,
	}
	journal.previous = record.RecordSHA256
	journal.outcomes[prepared.Plan.PlanID] = outcome
	if state == "APPLIED" {
		observation, decodeErr := decodeAppliedObservation(details)
		if decodeErr != nil {
			return contracts.ActionRecordV1{}, decodeErr
		}
		journal.applied[prepared.Plan.PlanID] = appliedActionState{
			Observation: observation,
		}
	}
	if state == "VERIFIED" {
		deadline, ok := uintDetail(details["audit_deadline_boottime_ns"], 64)
		if !ok || deadline == 0 {
			return contracts.ActionRecordV1{}, fmt.Errorf("invalid verified audit deadline")
		}
		journal.verified[prepared.Plan.PlanID] = verifiedActionState{
			AuditDeadlineBootTimeNS: deadline,
		}
	}
	journal.recordCount++
	journal.byteCount += int64(meta.Size)
	return record, nil
}

func appliedDetails(
	attempt applyAttemptState,
	observation ApplyObservation,
) map[string]any {
	return map[string]any{
		"apply_attempt_sha256":  attempt.RecordSHA256,
		"target_netns_inode":    observation.TargetNetNSInode,
		"ruleset_sha256":        observation.RulesetSHA256,
		"configured_timeout_ms": observation.ConfiguredTimeoutMilliseconds,
		"remaining_timeout_ms":  observation.RemainingTimeoutMilliseconds,
		"counter_packets":       observation.CounterPackets,
		"counter_bytes":         observation.CounterBytes,
		"host_netns_before":     observation.HostNetNSBefore,
		"host_netns_after":      observation.HostNetNSAfter,
	}
}

func verifiedDetails(appliedRecordSHA256 string, auditDeadline uint64) map[string]any {
	return map[string]any{
		"applied_record_sha256":      appliedRecordSHA256,
		"audit_deadline_boottime_ns": auditDeadline,
	}
}

func decodeVerifiedAuditDeadline(details map[string]any) (uint64, error) {
	value, ok := details["audit_deadline_boottime_ns"]
	if !ok {
		return 0, fmt.Errorf("missing audit deadline")
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, fmt.Errorf("invalid audit deadline")
	}
	deadline, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil || deadline == 0 {
		return 0, fmt.Errorf("invalid audit deadline")
	}
	return deadline, nil
}
