package actuatord

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

var (
	ErrPlanNotFound     = errors.New("prepared plan not found")
	ErrApprovalMismatch = errors.New("approval does not match prepared plan")
	ErrApprovalReplay   = errors.New("plan decision already consumed")
	ErrApprovalExpired  = errors.New("prepared plan approval expired")
	ErrApprovalClock    = errors.New("approval clock moved backwards")
	planIDPattern       = regexp.MustCompile(`^plan_[0-9a-f]{32}$`)
)

type ExactPlanRef struct {
	PlanID        string
	PlanHashValue string
	Nonce         string
}

func (reference ExactPlanRef) validate() error {
	if !planIDPattern.MatchString(reference.PlanID) ||
		!digestPattern.MatchString(reference.PlanHashValue) ||
		!digestPattern.MatchString(reference.Nonce) {
		return ErrApprovalMismatch
	}
	return nil
}

type AdminAuthority struct {
	UID                uint32
	GID                uint32
	AuthorizationBasis string
}

func (authority AdminAuthority) validate() error {
	switch authority.AuthorizationBasis {
	case "root":
		if authority.UID != 0 {
			return fmt.Errorf("invalid root admin authority")
		}
	case "primary_group", "supplementary_group":
		if authority.UID == 0 {
			return fmt.Errorf("invalid group admin authority")
		}
	case "system_expiry":
		if authority.UID != 0 || authority.GID != 0 {
			return fmt.Errorf("invalid system expiry authority")
		}
	default:
		return fmt.Errorf("invalid admin authorization basis")
	}
	return nil
}

type PlanOutcome struct {
	State        string
	RecordID     string
	RecordSHA256 string
	ObservedAt   string
}

type decisionDetails struct {
	previousActionRecordSHA256 string
	decisionBootID             string
	decisionBootTimeNS         uint64
	adminUID                   uint32
	adminGID                   uint32
	authorizationBasis         string
	decisionBasis              string
}

func decisionReason(state, basis string) (string, bool) {
	switch {
	case state == "APPROVED" && basis == "local_admin_approval":
		return "local_admin_approved", true
	case state == "REJECTED" && basis == "local_admin_rejection":
		return "local_admin_rejected", true
	case state == "EXPIRED_UNAPPLIED" &&
		(basis == "wall_deadline" || basis == "boottime_deadline"):
		return "approval_deadline_elapsed", true
	case state == "EXPIRED_UNAPPLIED" && basis == "host_boot_changed":
		return "host_boot_changed", true
	default:
		return "", false
	}
}

var systemExpiryAuthority = AdminAuthority{
	UID:                0,
	GID:                0,
	AuthorizationBasis: "system_expiry",
}

func uintDetail(value any, bits int) (uint64, bool) {
	var raw string
	switch number := value.(type) {
	case json.Number:
		raw = number.String()
	case uint64:
		raw = strconv.FormatUint(number, 10)
	case uint32:
		raw = strconv.FormatUint(uint64(number), 10)
	case uint:
		raw = strconv.FormatUint(uint64(number), 10)
	case int:
		if number < 0 {
			return 0, false
		}
		raw = strconv.FormatUint(uint64(number), 10)
	default:
		return 0, false
	}
	parsed, err := strconv.ParseUint(raw, 10, bits)
	return parsed, err == nil
}

func decodeDecisionDetails(values map[string]any) (decisionDetails, error) {
	if len(values) != 7 {
		return decisionDetails{}, fmt.Errorf("unexpected decision detail fields")
	}
	previous, previousOK := values["previous_action_record_sha256"].(string)
	bootID, bootOK := values["decision_boot_id"].(string)
	authorization, authorizationOK := values["authorization_basis"].(string)
	basis, basisOK := values["decision_basis"].(string)
	bootTime, bootTimeOK := uintDetail(values["decision_boottime_ns"], 64)
	uid, uidOK := uintDetail(values["admin_uid"], 32)
	gid, gidOK := uintDetail(values["admin_gid"], 32)
	if !previousOK || !digestPattern.MatchString(previous) ||
		!bootOK || !bootIDPattern.MatchString(bootID) ||
		!authorizationOK || !basisOK || !bootTimeOK || bootTime == 0 ||
		!uidOK || !gidOK {
		return decisionDetails{}, fmt.Errorf("invalid decision details")
	}
	authority := AdminAuthority{
		UID:                uint32(uid),
		GID:                uint32(gid),
		AuthorizationBasis: authorization,
	}
	if err := authority.validate(); err != nil {
		return decisionDetails{}, err
	}
	return decisionDetails{
		previousActionRecordSHA256: previous,
		decisionBootID:             bootID,
		decisionBootTimeNS:         bootTime,
		adminUID:                   uint32(uid),
		adminGID:                   uint32(gid),
		authorizationBasis:         authorization,
		decisionBasis:              basis,
	}, nil
}

func validateRecoveredDecisionRecord(
	payload []byte,
	record contracts.ActionRecordV1,
	publicKey ed25519.PublicKey,
	expectedPrevious string,
	prepared preparedState,
) (PlanOutcome, error) {
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil || !bytes.Equal(canonical, payload) {
		return PlanOutcome{}, fmt.Errorf("decision action record is not canonical")
	}
	if err := contracts.VerifyActionRecord(record, publicKey); err != nil {
		return PlanOutcome{}, err
	}
	if record.ActionID == nil || record.PreviousRecordSHA256 != expectedPrevious ||
		record.PlanID != prepared.Plan.PlanID ||
		record.PlanHashValue != prepared.Plan.PlanHashValue {
		return PlanOutcome{}, fmt.Errorf("decision action does not bind PREPARED plan")
	}
	details, err := decodeDecisionDetails(record.Details)
	if err != nil || details.previousActionRecordSHA256 != prepared.PreparedRecordSHA256 {
		return PlanOutcome{}, fmt.Errorf("decision action lacks PREPARED record binding: %w", err)
	}
	expectedReason, ok := decisionReason(record.State, details.decisionBasis)
	if !ok || record.ReasonCode != expectedReason {
		return PlanOutcome{}, fmt.Errorf("invalid decision state or reason")
	}
	preparedAt, _ := time.Parse(time.RFC3339Nano, prepared.Plan.PreparedAt)
	expiresAt, _ := time.Parse(time.RFC3339Nano, prepared.Plan.ApprovalExpiresAt)
	observedAt, err := time.Parse(time.RFC3339Nano, record.ObservedAt)
	if err != nil || prepared.ApprovalDeadlineBootTimeNS <= uint64(ApprovalTTL) {
		return PlanOutcome{}, fmt.Errorf("invalid decision clock binding")
	}
	preparedBootTime := prepared.ApprovalDeadlineBootTimeNS - uint64(ApprovalTTL)
	switch record.State {
	case "APPROVED", "REJECTED":
		if details.authorizationBasis == "system_expiry" ||
			details.decisionBootID != prepared.Plan.BootID ||
			observedAt.Before(preparedAt) || !observedAt.Before(expiresAt) ||
			details.decisionBootTimeNS < preparedBootTime ||
			details.decisionBootTimeNS >= prepared.ApprovalDeadlineBootTimeNS {
			return PlanOutcome{}, fmt.Errorf("decision was outside approval window")
		}
	case "EXPIRED_UNAPPLIED":
		switch details.decisionBasis {
		case "wall_deadline":
			if details.decisionBootID != prepared.Plan.BootID ||
				observedAt.Before(expiresAt) {
				return PlanOutcome{}, fmt.Errorf("wall expiry was not reached")
			}
		case "boottime_deadline":
			if details.decisionBootID != prepared.Plan.BootID ||
				details.decisionBootTimeNS < prepared.ApprovalDeadlineBootTimeNS {
				return PlanOutcome{}, fmt.Errorf("monotonic expiry was not reached")
			}
		case "host_boot_changed":
			if details.decisionBootID == prepared.Plan.BootID {
				return PlanOutcome{}, fmt.Errorf("host boot did not change")
			}
		}
	}
	return PlanOutcome{
		State:        record.State,
		RecordID:     record.RecordID,
		RecordSHA256: record.RecordSHA256,
		ObservedAt:   record.ObservedAt,
	}, nil
}

func (journal *actionJournal) appendDecision(
	prepared preparedState,
	authority AdminAuthority,
	sample ClockSample,
	state string,
	reason string,
	basis string,
) (contracts.ActionRecordV1, error) {
	if journal.closed {
		return contracts.ActionRecordV1{}, durablefile.ErrJournalClosed
	}
	if journal.failed() {
		return contracts.ActionRecordV1{}, durablefile.ErrJournalFailed
	}
	if _, exists := journal.outcomes[prepared.Plan.PlanID]; exists {
		return contracts.ActionRecordV1{}, ErrApprovalReplay
	}
	if expected, ok := decisionReason(state, basis); !ok || expected != reason {
		return contracts.ActionRecordV1{}, fmt.Errorf("invalid plan decision")
	}
	if authority.AuthorizationBasis == "system_expiry" &&
		state != "EXPIRED_UNAPPLIED" {
		return contracts.ActionRecordV1{}, fmt.Errorf("system authority cannot decide a plan")
	}
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
		Details: map[string]any{
			"previous_action_record_sha256": prepared.PreparedRecordSHA256,
			"decision_boot_id":              sample.BootID,
			"decision_boottime_ns":          sample.BootTimeNS,
			"admin_uid":                     authority.UID,
			"admin_gid":                     authority.GID,
			"authorization_basis":           authority.AuthorizationBasis,
			"decision_basis":                basis,
		},
		ActuatorKeyID: journal.keyID,
	}
	recordHash, err := contracts.ActionRecordHash(record)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	record.RecordSHA256 = recordHash
	record.RecordID = contracts.ActionRecordID(recordHash)
	message, err := contracts.ActionRecordSigningMessage(record)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	record.ActuatorSignature = hex.EncodeToString(
		ed25519.Sign(journal.privateKey, message),
	)
	if err := contracts.VerifyActionRecord(record, journal.publicKey); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	payload, err := contracts.CanonicalJSON(record)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	frameSize := int64(len(payload)) + actionFrameOverhead
	newBudget := lifecycleFutureFrames(state, false)
	if err := journal.ensureTransitionCapacity(
		prepared.Plan.PlanID,
		frameSize,
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
	journal.recordCount++
	journal.byteCount += int64(meta.Size)
	return record, nil
}

func (service *Service) GetPlan(
	planID string,
) (contracts.PreparedTemporaryEgressDenyPlanV1, error) {
	if service == nil || !planIDPattern.MatchString(planID) {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, ErrPlanNotFound
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.closed {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, durablefile.ErrJournalClosed
	}
	state, ok := service.journal.byPlan[planID]
	if !ok {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, ErrPlanNotFound
	}
	return clonePlan(state.Plan), nil
}

func (service *Service) Outcome(planID string) (PlanOutcome, bool) {
	if service == nil || !planIDPattern.MatchString(planID) {
		return PlanOutcome{}, false
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.journal == nil {
		return PlanOutcome{}, false
	}
	outcome, ok := service.journal.outcomes[planID]
	return outcome, ok
}

func (service *Service) Approve(
	ctx context.Context,
	authority AdminAuthority,
	reference ExactPlanRef,
) (contracts.ActionRecordV1, error) {
	return service.decide(ctx, authority, reference, "APPROVED")
}

func (service *Service) Reject(
	ctx context.Context,
	authority AdminAuthority,
	reference ExactPlanRef,
) (contracts.ActionRecordV1, error) {
	return service.decide(ctx, authority, reference, "REJECTED")
}

func planExpiryBasis(
	prepared preparedState,
	sample ClockSample,
) (string, error) {
	preparedAt, _ := time.Parse(time.RFC3339Nano, prepared.Plan.PreparedAt)
	expiresAt, _ := time.Parse(time.RFC3339Nano, prepared.Plan.ApprovalExpiresAt)
	if prepared.ApprovalDeadlineBootTimeNS <= uint64(ApprovalTTL) {
		return "", ErrApprovalClock
	}
	preparedBootTime := prepared.ApprovalDeadlineBootTimeNS - uint64(ApprovalTTL)
	switch {
	case sample.BootID != prepared.Plan.BootID:
		return "host_boot_changed", nil
	case !sample.Wall.Before(expiresAt):
		return "wall_deadline", nil
	case sample.BootTimeNS >= prepared.ApprovalDeadlineBootTimeNS:
		return "boottime_deadline", nil
	case sample.Wall.Before(preparedAt), sample.BootTimeNS < preparedBootTime:
		return "", ErrApprovalClock
	default:
		return "", nil
	}
}

func (service *Service) ExpireDue(ctx context.Context) (int, error) {
	if service == nil {
		return 0, fmt.Errorf("nil actuator service")
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
	hasPendingApprovals := service.journal.openOutcomeCount() != 0
	hasVerifiedActions := service.journal.hasVerifiedActions()
	if !hasPendingApprovals && !hasVerifiedActions {
		return 0, nil
	}
	sample, err := service.dependencies.clock()
	if err != nil {
		return 0, err
	}
	if err := sample.validate(); err != nil {
		return 0, err
	}
	planIDs := make([]string, 0, service.journal.openOutcomeCount())
	if hasPendingApprovals {
		for planID := range service.journal.byPlan {
			if _, decided := service.journal.outcomes[planID]; !decided {
				planIDs = append(planIDs, planID)
			}
		}
	}
	slices.Sort(planIDs)
	expired := 0
	for _, planID := range planIDs {
		if err := ctx.Err(); err != nil {
			return expired, err
		}
		prepared := service.journal.byPlan[planID]
		basis, err := planExpiryBasis(prepared, sample)
		if err != nil {
			return expired, err
		}
		if basis == "" {
			continue
		}
		reason, _ := decisionReason("EXPIRED_UNAPPLIED", basis)
		if _, err := service.journal.appendDecision(
			prepared,
			systemExpiryAuthority,
			sample,
			"EXPIRED_UNAPPLIED",
			reason,
			basis,
		); err != nil {
			return expired, err
		}
		expired++
	}
	audited, err := service.auditDueLocked(ctx, sample)
	return expired + audited, err
}

func (service *Service) decide(
	ctx context.Context,
	authority AdminAuthority,
	reference ExactPlanRef,
	desiredState string,
) (contracts.ActionRecordV1, error) {
	if service == nil {
		return contracts.ActionRecordV1{}, fmt.Errorf("nil actuator service")
	}
	if err := ctx.Err(); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	if err := authority.validate(); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	if authority.AuthorizationBasis == "system_expiry" {
		return contracts.ActionRecordV1{}, fmt.Errorf("system expiry is not an admin decision")
	}
	if err := reference.validate(); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	if desiredState != "APPROVED" && desiredState != "REJECTED" {
		return contracts.ActionRecordV1{}, fmt.Errorf("invalid requested plan decision")
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.closed {
		return contracts.ActionRecordV1{}, durablefile.ErrJournalClosed
	}
	if service.journal.failed() {
		return contracts.ActionRecordV1{}, durablefile.ErrJournalFailed
	}
	prepared, ok := service.journal.byPlan[reference.PlanID]
	if !ok {
		return contracts.ActionRecordV1{}, ErrPlanNotFound
	}
	if err := prepared.Plan.Validate(); err != nil ||
		prepared.Plan.PlanHashValue != reference.PlanHashValue ||
		prepared.Plan.Nonce != reference.Nonce {
		return contracts.ActionRecordV1{}, ErrApprovalMismatch
	}
	if outcome, exists := service.journal.outcomes[reference.PlanID]; exists {
		if outcome.State == "EXPIRED_UNAPPLIED" {
			return contracts.ActionRecordV1{}, ErrApprovalExpired
		}
		return contracts.ActionRecordV1{}, ErrApprovalReplay
	}
	sample, err := service.dependencies.clock()
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	if err := sample.validate(); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	state, basis := desiredState, "local_admin_approval"
	if desiredState == "REJECTED" {
		basis = "local_admin_rejection"
	}
	expiryBasis, err := planExpiryBasis(prepared, sample)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	if expiryBasis != "" {
		state, basis = "EXPIRED_UNAPPLIED", expiryBasis
	}
	if err := ctx.Err(); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	reason, ok := decisionReason(state, basis)
	if !ok {
		return contracts.ActionRecordV1{}, fmt.Errorf("invalid plan decision mapping")
	}
	record, err := service.journal.appendDecision(
		prepared,
		authority,
		sample,
		state,
		reason,
		basis,
	)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	if state == "EXPIRED_UNAPPLIED" {
		return record, ErrApprovalExpired
	}
	return record, nil
}
