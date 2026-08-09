package actuatord

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const (
	actionJournalName       = "actions.agf"
	actionJournalMaxFrame   = uint32(65_536)
	actionJournalMaxBytes   = int64(64 * 1024 * 1024)
	actionJournalMaxRecords = 65_536
	intentHashDomain        = "AGMIND_ACTUATOR_INTENT_V1\x00"
	rateRecordHashDomain    = "AGMIND_RATE_RESERVATION_HASH_V1\x00"
	rateRecordSigningDomain = "AGMIND_RATE_RESERVATION_V1\x00"
	actionFrameOverhead     = int64(76)
)

var ErrActionJournalCorrupt = errors.New("actuator action journal corrupt")

var (
	rateReservationIDPattern        = regexp.MustCompile(`^rr_[0-9a-f]{32}$`)
	rateReservationKeyIDPattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	rateReservationSignaturePattern = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

type rateReservationV1 struct {
	SchemaVersion        string `json:"schema_version"`
	ReservationID        string `json:"reservation_id"`
	IntentID             string `json:"intent_id"`
	IntentSHA256         string `json:"intent_sha256"`
	ReservedAt           string `json:"reserved_at"`
	PreviousRecordSHA256 string `json:"previous_record_sha256"`
	RecordSHA256         string `json:"record_sha256"`
	ActuatorKeyID        string `json:"actuator_key_id"`
	ActuatorSignature    string `json:"actuator_signature"`
}

func (record rateReservationV1) Validate() error {
	if record.SchemaVersion != "agmind.intent-rate-reservation.v1" ||
		!rateReservationIDPattern.MatchString(record.ReservationID) ||
		!intentIDPattern.MatchString(record.IntentID) ||
		!digestPattern.MatchString(record.IntentSHA256) ||
		!digestPattern.MatchString(record.PreviousRecordSHA256) ||
		!digestPattern.MatchString(record.RecordSHA256) ||
		!rateReservationKeyIDPattern.MatchString(record.ActuatorKeyID) ||
		!rateReservationSignaturePattern.MatchString(record.ActuatorSignature) {
		return fmt.Errorf("invalid intent rate reservation")
	}
	reservedAt, err := time.Parse(time.RFC3339Nano, record.ReservedAt)
	if err != nil || record.ReservedAt != reservedAt.UTC().Format(time.RFC3339Nano) {
		return fmt.Errorf("invalid reservation timestamp")
	}
	expectedHash, err := rateReservationHash(record)
	if err != nil || expectedHash != record.RecordSHA256 ||
		"rr_"+expectedHash[:32] != record.ReservationID {
		return fmt.Errorf("rate reservation self-binding mismatch")
	}
	return nil
}

func rateReservationHash(record rateReservationV1) (string, error) {
	document, err := objectFromCanonical(record)
	if err != nil {
		return "", err
	}
	delete(document, "reservation_id")
	delete(document, "record_sha256")
	delete(document, "actuator_signature")
	canonical, err := contracts.CanonicalJSON(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(rateRecordHashDomain), canonical...))
	return hex.EncodeToString(sum[:]), nil
}

func rateReservationSigningMessage(record rateReservationV1) ([]byte, error) {
	document, err := objectFromCanonical(record)
	if err != nil {
		return nil, err
	}
	delete(document, "actuator_signature")
	canonical, err := contracts.CanonicalJSON(document)
	if err != nil {
		return nil, err
	}
	return append([]byte(rateRecordSigningDomain), canonical...), nil
}

func verifyRateReservation(
	record rateReservationV1,
	publicKey ed25519.PublicKey,
) error {
	if err := record.Validate(); err != nil {
		return err
	}
	keyID, err := contracts.KeyID(publicKey)
	if err != nil || keyID != record.ActuatorKeyID {
		return fmt.Errorf("reservation key binding mismatch")
	}
	signature, err := hex.DecodeString(record.ActuatorSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid reservation signature")
	}
	message, err := rateReservationSigningMessage(record)
	if err != nil || !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("invalid reservation signature")
	}
	return nil
}

func journalRecordSchema(payload []byte) (string, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope == nil {
		return "", fmt.Errorf("invalid journal record envelope: %w", err)
	}
	raw, ok := envelope["schema_version"]
	if !ok {
		return "", fmt.Errorf("journal record schema is missing")
	}
	var schema string
	if err := json.Unmarshal(raw, &schema); err != nil || schema == "" {
		return "", fmt.Errorf("invalid journal record schema")
	}
	return schema, nil
}

func validateRecoveredRateReservation(
	payload []byte,
	record rateReservationV1,
	publicKey ed25519.PublicKey,
	expectedPrevious string,
) (rateReservationState, error) {
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil || !bytes.Equal(canonical, payload) {
		return rateReservationState{}, fmt.Errorf("rate reservation is not canonical")
	}
	if err := verifyRateReservation(record, publicKey); err != nil {
		return rateReservationState{}, err
	}
	if record.PreviousRecordSHA256 != expectedPrevious {
		return rateReservationState{}, fmt.Errorf("invalid rate reservation transition")
	}
	return rateReservationState{
		IntentSHA256: record.IntentSHA256,
		ReservedAt:   record.ReservedAt,
		RecordSHA256: record.RecordSHA256,
	}, nil
}

type rateReservationState struct {
	IntentSHA256 string
	ReservedAt   string
	RecordSHA256 string
}

type preparedState struct {
	Plan                       contracts.PreparedTemporaryEgressDenyPlanV1
	IntentSHA256               string
	ApprovalDeadlineBootTimeNS uint64
	PreparedRecordSHA256       string
}

type actionJournal struct {
	mutex        sync.Mutex
	stream       *durablefile.Journal
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	keyID        string
	previous     string
	byIntent     map[string]preparedState
	byPlan       map[string]preparedState
	reservations map[string]rateReservationState
	rateHistory  []rateReservationState
	outcomes     map[string]PlanOutcome
	attempts     map[string]applyAttemptState
	applied      map[string]appliedActionState
	verified     map[string]verifiedActionState
	recordCount  int
	byteCount    int64
	closed       bool
}

type recoveredActionState struct {
	previous     string
	byIntent     map[string]preparedState
	byPlan       map[string]preparedState
	reservations map[string]rateReservationState
	rateHistory  []rateReservationState
	outcomes     map[string]PlanOutcome
	attempts     map[string]applyAttemptState
	applied      map[string]appliedActionState
	verified     map[string]verifiedActionState
	recordCount  int
}

func actionJournalPath(stateDir string) string {
	return filepath.Join(stateDir, actionJournalName)
}

func canonicalIntentSHA256(
	intent contracts.TemporaryEgressDenyIntentV1,
) (string, error) {
	if err := intent.Validate(); err != nil {
		return "", err
	}
	canonical, err := contracts.CanonicalJSON(intent)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(intentHashDomain), canonical...))
	return hex.EncodeToString(sum[:]), nil
}

func intentFromPlan(
	plan contracts.PreparedTemporaryEgressDenyPlanV1,
) contracts.TemporaryEgressDenyIntentV1 {
	fields := plan.EgressDenyFields
	fields.SchemaVersion = "agmind.temporary-egress-deny-intent.v1"
	return contracts.TemporaryEgressDenyIntentV1{EgressDenyFields: fields}
}

func objectFromCanonical(value any) (map[string]any, error) {
	canonical, err := contracts.CanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, fmt.Errorf("canonical object decode failed: %w", err)
	}
	return object, nil
}

func decodePreparedDetails(
	details map[string]any,
) (preparedState, error) {
	if len(details) != 3 {
		return preparedState{}, fmt.Errorf("unexpected PREPARED detail fields")
	}
	planValue, planOK := details["prepared_plan"]
	intentHash, hashOK := details["intent_sha256"].(string)
	deadlineNumber, deadlineOK := details["approval_deadline_boottime_ns"].(json.Number)
	if !planOK || !hashOK || !deadlineOK || !digestPattern.MatchString(intentHash) {
		return preparedState{}, fmt.Errorf("invalid PREPARED details")
	}
	planCanonical, err := contracts.CanonicalJSON(planValue)
	if err != nil {
		return preparedState{}, err
	}
	plan, err := contracts.DecodeStrict[contracts.PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(planCanonical),
		65_536,
	)
	if err != nil {
		return preparedState{}, err
	}
	deadline, err := strconv.ParseUint(deadlineNumber.String(), 10, 64)
	if err != nil || deadline == 0 {
		return preparedState{}, fmt.Errorf("invalid boot-time approval deadline")
	}
	expectedIntentHash, err := canonicalIntentSHA256(intentFromPlan(plan))
	if err != nil || expectedIntentHash != intentHash {
		return preparedState{}, fmt.Errorf("PREPARED intent hash mismatch")
	}
	return preparedState{
		Plan:                       plan,
		IntentSHA256:               intentHash,
		ApprovalDeadlineBootTimeNS: deadline,
	}, nil
}

func validateRecoveredPreparedRecord(
	payload []byte,
	record contracts.ActionRecordV1,
	publicKey ed25519.PublicKey,
	expectedPrevious string,
) (preparedState, error) {
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil || !bytes.Equal(canonical, payload) {
		return preparedState{}, fmt.Errorf("action record is not canonical")
	}
	if err := contracts.VerifyActionRecord(record, publicKey); err != nil {
		return preparedState{}, err
	}
	if record.State != "PREPARED" || record.ReasonCode != "intent_prepared" ||
		record.ActionID == nil || record.PreviousRecordSHA256 != expectedPrevious {
		return preparedState{}, fmt.Errorf("invalid PREPARED action transition")
	}
	state, err := decodePreparedDetails(record.Details)
	if err != nil {
		return preparedState{}, err
	}
	if record.PlanID != state.Plan.PlanID ||
		record.PlanHashValue != state.Plan.PlanHashValue ||
		record.ObservedAt != state.Plan.PreparedAt {
		return preparedState{}, fmt.Errorf("action record does not bind prepared plan")
	}
	return state, nil
}

func recoverPreparedStates(
	records []durablefile.Record,
	publicKey ed25519.PublicKey,
) (recoveredActionState, error) {
	if len(records) > actionJournalMaxRecords {
		return recoveredActionState{}, fmt.Errorf("action record count exceeds bound")
	}
	recovered := recoveredActionState{
		previous:     strings.Repeat("0", 64),
		byIntent:     make(map[string]preparedState),
		byPlan:       make(map[string]preparedState),
		reservations: make(map[string]rateReservationState),
		rateHistory:  make([]rateReservationState, 0, len(records)),
		outcomes:     make(map[string]PlanOutcome),
		attempts:     make(map[string]applyAttemptState),
		applied:      make(map[string]appliedActionState),
		verified:     make(map[string]verifiedActionState),
	}
	for _, framed := range records {
		schema, err := journalRecordSchema(framed.Payload)
		if err != nil {
			return recoveredActionState{}, err
		}
		switch schema {
		case "agmind.intent-rate-reservation.v1":
			record, err := contracts.DecodeStrict[rateReservationV1](
				bytes.NewReader(framed.Payload),
				int64(actionJournalMaxFrame),
			)
			if err != nil {
				return recoveredActionState{}, err
			}
			state, err := validateRecoveredRateReservation(
				framed.Payload,
				record,
				publicKey,
				recovered.previous,
			)
			if err != nil {
				return recoveredActionState{}, err
			}
			if _, prepared := recovered.byIntent[record.IntentID]; prepared {
				return recoveredActionState{}, fmt.Errorf("rate reservation follows PREPARED")
			}
			if prior, repeated := recovered.reservations[record.IntentID]; repeated && prior.IntentSHA256 != state.IntentSHA256 {
				return recoveredActionState{}, fmt.Errorf("rate reservation intent equivocation")
			}
			recovered.reservations[record.IntentID] = state
			recovered.rateHistory = append(recovered.rateHistory, state)
			recovered.previous = record.RecordSHA256

		case "agmind.apply-attempt.v1":
			record, err := contracts.DecodeStrict[applyAttemptV1](
				bytes.NewReader(framed.Payload),
				int64(actionJournalMaxFrame),
			)
			if err != nil {
				return recoveredActionState{}, err
			}
			prepared, preparedOK := recovered.byPlan[record.PlanID]
			approved, approvedOK := recovered.outcomes[record.PlanID]
			if !preparedOK || !approvedOK {
				return recoveredActionState{}, fmt.Errorf("apply attempt lacks approved plan")
			}
			if _, duplicate := recovered.attempts[record.PlanID]; duplicate {
				return recoveredActionState{}, fmt.Errorf("duplicate apply attempt")
			}
			attempt, err := validateRecoveredApplyAttempt(
				framed.Payload,
				record,
				publicKey,
				recovered.previous,
				prepared,
				approved,
			)
			if err != nil {
				return recoveredActionState{}, err
			}
			recovered.attempts[record.PlanID] = attempt
			recovered.previous = record.RecordSHA256

		case "agmind.action-record.v1":
			record, err := contracts.DecodeStrict[contracts.ActionRecordV1](
				bytes.NewReader(framed.Payload),
				int64(actionJournalMaxFrame),
			)
			if err != nil {
				return recoveredActionState{}, err
			}
			switch record.State {
			case "PREPARED":
				state, err := validateRecoveredPreparedRecord(
					framed.Payload,
					record,
					publicKey,
					recovered.previous,
				)
				if err != nil {
					return recoveredActionState{}, err
				}
				reservation, ok := recovered.reservations[state.Plan.IntentID]
				if !ok || reservation.IntentSHA256 != state.IntentSHA256 ||
					reservation.RecordSHA256 != record.PreviousRecordSHA256 {
					return recoveredActionState{}, fmt.Errorf("PREPARED record lacks exact rate reservation")
				}
				reservedAt, _ := time.Parse(time.RFC3339Nano, reservation.ReservedAt)
				preparedAt, err := time.Parse(time.RFC3339Nano, state.Plan.PreparedAt)
				if err != nil || preparedAt.Before(reservedAt) {
					return recoveredActionState{}, fmt.Errorf("PREPARED predates rate reservation")
				}
				if _, duplicate := recovered.byIntent[state.Plan.IntentID]; duplicate {
					return recoveredActionState{}, fmt.Errorf("duplicate durable intent ID")
				}
				if _, duplicate := recovered.byPlan[state.Plan.PlanID]; duplicate {
					return recoveredActionState{}, fmt.Errorf("duplicate durable plan ID")
				}
				state.Plan = clonePlan(state.Plan)
				state.PreparedRecordSHA256 = record.RecordSHA256
				recovered.byIntent[state.Plan.IntentID] = state
				recovered.byPlan[state.Plan.PlanID] = state

			case "APPROVED", "REJECTED", "EXPIRED_UNAPPLIED":
				prepared, ok := recovered.byPlan[record.PlanID]
				if !ok {
					return recoveredActionState{}, fmt.Errorf("decision lacks PREPARED plan")
				}
				prior, hasPrior := recovered.outcomes[record.PlanID]
				attempt, attempted := recovered.attempts[record.PlanID]
				var outcome PlanOutcome
				if !hasPrior {
					outcome, err = validateRecoveredDecisionRecord(
						framed.Payload,
						record,
						publicKey,
						recovered.previous,
						prepared,
					)
				} else {
					outcome, err = validateRecoveredLifecycleRecord(
						framed.Payload,
						record,
						publicKey,
						recovered.previous,
						prepared,
						prior,
						attempt,
						attempted,
					)
				}
				if err != nil {
					return recoveredActionState{}, err
				}
				recovered.outcomes[record.PlanID] = outcome

			case "APPLIED", "VERIFIED", "EXPIRED", "STALE_ABORT", "FAILED_DIRTY":
				prepared, ok := recovered.byPlan[record.PlanID]
				if !ok {
					return recoveredActionState{}, fmt.Errorf("lifecycle action lacks PREPARED plan")
				}
				prior, ok := recovered.outcomes[record.PlanID]
				if !ok {
					return recoveredActionState{}, fmt.Errorf("lifecycle action lacks prior state")
				}
				attempt, attempted := recovered.attempts[record.PlanID]
				outcome, err := validateRecoveredLifecycleRecord(
					framed.Payload,
					record,
					publicKey,
					recovered.previous,
					prepared,
					prior,
					attempt,
					attempted,
				)
				if err != nil {
					return recoveredActionState{}, err
				}
				recovered.outcomes[record.PlanID] = outcome
				if record.State == "APPLIED" {
					observation, observationErr := decodeAppliedObservation(record.Details)
					if observationErr != nil {
						return recoveredActionState{}, observationErr
					}
					recovered.applied[record.PlanID] = appliedActionState{
						Observation: observation,
					}
				}
				if record.State == "VERIFIED" {
					deadline, deadlineErr := decodeVerifiedAuditDeadline(record.Details)
					if deadlineErr != nil {
						return recoveredActionState{}, deadlineErr
					}
					recovered.verified[record.PlanID] = verifiedActionState{
						AuditDeadlineBootTimeNS: deadline,
					}
				}

			default:
				return recoveredActionState{}, fmt.Errorf("unsupported durable action state %q", record.State)
			}
			recovered.previous = record.RecordSHA256

		default:
			return recoveredActionState{}, fmt.Errorf("unsupported action journal schema %q", schema)
		}
		recovered.recordCount++
	}
	return recovered, nil
}

func validateRecoveredCapacity(
	recovered recoveredActionState,
	verifiedBytes int64,
) error {
	futureFrames := futureFrameBudget(
		recovered.byPlan,
		recovered.outcomes,
		recovered.attempts,
	)
	if futureFrames < 0 || verifiedBytes < 0 ||
		recovered.recordCount+futureFrames > actionJournalMaxRecords ||
		verifiedBytes+int64(futureFrames)*
			(int64(actionJournalMaxFrame)+actionFrameOverhead) > actionJournalMaxBytes {
		return fmt.Errorf("action journal lacks reserved lifecycle capacity")
	}
	return nil
}

func openActionJournal(
	stateDir string,
	privateKey ed25519.PrivateKey,
	options ...durablefile.Option,
) (*actionJournal, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid actuator private key")
	}
	privateKey = append(ed25519.PrivateKey(nil), privateKey...)
	if expected := ed25519.NewKeyFromSeed(privateKey.Seed()); !bytes.Equal(expected, privateKey) {
		return nil, fmt.Errorf("actuator private key is internally inconsistent")
	}
	if err := durablefile.EnsurePrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	path := actionJournalPath(stateDir)
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Size() < 0 || info.Size() > actionJournalMaxBytes {
			return nil, errors.Join(
				ErrActionJournalCorrupt,
				fmt.Errorf("action journal exceeds byte bound"),
			)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := contracts.KeyID(publicKey)
	if err != nil {
		return nil, err
	}
	streamOptions := append([]durablefile.Option{}, options...)
	streamOptions = append(
		streamOptions,
		durablefile.WithMaxFrame(actionJournalMaxFrame),
	)
	stream, recovery, err := durablefile.NewJournalWithTailIntent(
		path,
		func(intent durablefile.TornTailIntent) error {
			if intent.VerifiedBytes > actionJournalMaxBytes {
				return fmt.Errorf("action journal prefix exceeds byte bound")
			}
			recovered, validateErr := recoverPreparedStates(intent.Records, publicKey)
			if validateErr != nil {
				return validateErr
			}
			return validateRecoveredCapacity(recovered, intent.VerifiedBytes)
		},
		streamOptions...,
	)
	if err != nil {
		return nil, errors.Join(ErrActionJournalCorrupt, err)
	}
	recovered, err := recoverPreparedStates(recovery.Records, publicKey)
	if err != nil {
		_ = stream.Close()
		return nil, errors.Join(ErrActionJournalCorrupt, err)
	}
	if err := validateRecoveredCapacity(recovered, recovery.VerifiedBytes); err != nil {
		_ = stream.Close()
		return nil, errors.Join(ErrActionJournalCorrupt, err)
	}
	journal := &actionJournal{
		stream:       stream,
		privateKey:   privateKey,
		publicKey:    append(ed25519.PublicKey(nil), publicKey...),
		keyID:        keyID,
		previous:     recovered.previous,
		byIntent:     recovered.byIntent,
		byPlan:       recovered.byPlan,
		reservations: recovered.reservations,
		rateHistory:  recovered.rateHistory,
		outcomes:     recovered.outcomes,
		attempts:     recovered.attempts,
		applied:      recovered.applied,
		verified:     recovered.verified,
		recordCount:  recovered.recordCount,
		byteCount:    recovery.VerifiedBytes,
	}
	fail := func(cause error) (*actionJournal, error) {
		_ = stream.Close()
		return nil, errors.Join(ErrActionJournalCorrupt, cause)
	}
	if recovery.VerifiedBytes > actionJournalMaxBytes ||
		len(recovery.Records) > actionJournalMaxRecords {
		return fail(fmt.Errorf("action journal exceeds bounds"))
	}
	return journal, nil
}

func (journal *actionJournal) existing(
	intentID string,
	intentSHA256 string,
) (contracts.PreparedTemporaryEgressDenyPlanV1, bool, error) {
	state, ok := journal.byIntent[intentID]
	if !ok {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, false, nil
	}
	if state.IntentSHA256 != intentSHA256 {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, false, ErrIntentEquivocation
	}
	return clonePlan(state.Plan), true, nil
}

func (journal *actionJournal) reservation(
	intentID string,
	intentSHA256 string,
) (bool, error) {
	state, ok := journal.reservations[intentID]
	if !ok {
		return false, nil
	}
	if state.IntentSHA256 != intentSHA256 {
		return false, ErrIntentEquivocation
	}
	return true, nil
}

func (journal *actionJournal) rateAllowed(now time.Time) error {
	minuteCount := 0
	hourCount := 0
	for _, state := range journal.rateHistory {
		reservedAt, err := time.Parse(time.RFC3339Nano, state.ReservedAt)
		if err != nil || reservedAt.After(now) {
			return fmt.Errorf("%w: actuator clock moved backwards", ErrIntentRejected)
		}
		age := now.Sub(reservedAt)
		if age < time.Minute {
			minuteCount++
		}
		if age < time.Hour {
			hourCount++
		}
	}
	if minuteCount >= PerMinuteIntents || hourCount >= PerHourIntents {
		return ErrIntentRateLimited
	}
	return nil
}

func (journal *actionJournal) openOutcomeCount() int {
	return len(journal.byPlan) - len(journal.outcomes)
}

func (journal *actionJournal) reserveIntent(
	intentID string,
	intentSHA256 string,
	reservedAt time.Time,
) error {
	if journal.closed {
		return durablefile.ErrJournalClosed
	}
	if _, err := journal.reservation(intentID, intentSHA256); err != nil {
		return err
	}
	// Preserve PREPARED plus the complete worst-case lifecycle through native
	// expiry before accepting another intent.
	futureFrames := futureFrameBudget(journal.byPlan, journal.outcomes, journal.attempts)
	if futureFrames < 0 ||
		journal.recordCount+futureFrames+2+maxLifecycleFramesPerPlan > actionJournalMaxRecords ||
		journal.byteCount >= actionJournalMaxBytes {
		return ErrPendingLimit
	}
	record := rateReservationV1{
		SchemaVersion:        "agmind.intent-rate-reservation.v1",
		IntentID:             intentID,
		IntentSHA256:         intentSHA256,
		ReservedAt:           reservedAt.UTC().Format(time.RFC3339Nano),
		PreviousRecordSHA256: journal.previous,
		ActuatorKeyID:        journal.keyID,
	}
	recordHash, err := rateReservationHash(record)
	if err != nil {
		return err
	}
	record.RecordSHA256 = recordHash
	record.ReservationID = "rr_" + recordHash[:32]
	message, err := rateReservationSigningMessage(record)
	if err != nil {
		return err
	}
	record.ActuatorSignature = hex.EncodeToString(
		ed25519.Sign(journal.privateKey, message),
	)
	if err := verifyRateReservation(record, journal.publicKey); err != nil {
		return err
	}
	payload, err := contracts.CanonicalJSON(record)
	if err != nil {
		return err
	}
	reservationFrameSize := int64(len(payload)) + actionFrameOverhead
	futureFrameCapacity := int64(futureFrames+1+maxLifecycleFramesPerPlan) *
		(int64(actionJournalMaxFrame) + actionFrameOverhead)
	if reservationFrameSize+futureFrameCapacity >
		actionJournalMaxBytes-journal.byteCount {
		return ErrPendingLimit
	}
	meta, err := journal.stream.Append(payload, true)
	if err != nil {
		return err
	}
	journal.previous = record.RecordSHA256
	state := rateReservationState{
		IntentSHA256: intentSHA256,
		ReservedAt:   record.ReservedAt,
		RecordSHA256: record.RecordSHA256,
	}
	journal.reservations[intentID] = state
	journal.rateHistory = append(journal.rateHistory, state)
	journal.recordCount++
	journal.byteCount += int64(meta.Size)
	return nil
}

func (journal *actionJournal) pendingAt(now time.Time) int {
	count := 0
	for _, state := range journal.byIntent {
		if _, terminal := journal.outcomes[state.Plan.PlanID]; terminal {
			continue
		}
		expires, err := time.Parse(time.RFC3339Nano, state.Plan.ApprovalExpiresAt)
		if err == nil && now.Before(expires) {
			count++
		}
	}
	return count
}

func (journal *actionJournal) appendPrepared(
	state preparedState,
) error {
	if journal.closed {
		return durablefile.ErrJournalClosed
	}
	futureFrames := futureFrameBudget(journal.byPlan, journal.outcomes, journal.attempts)
	if futureFrames < 0 ||
		journal.recordCount+futureFrames+1+maxLifecycleFramesPerPlan > actionJournalMaxRecords ||
		journal.byteCount >= actionJournalMaxBytes {
		return ErrPendingLimit
	}
	state.Plan = clonePlan(state.Plan)
	reservation, ok := journal.reservations[state.Plan.IntentID]
	if !ok || reservation.IntentSHA256 != state.IntentSHA256 ||
		reservation.RecordSHA256 != journal.previous {
		return fmt.Errorf("PREPARED record lacks exact rate reservation")
	}
	reservedAt, err := time.Parse(time.RFC3339Nano, reservation.ReservedAt)
	if err != nil {
		return err
	}
	preparedAt, err := time.Parse(time.RFC3339Nano, state.Plan.PreparedAt)
	if err != nil || preparedAt.Before(reservedAt) {
		return fmt.Errorf("%w: actuator clock moved backwards", ErrIntentRejected)
	}
	planObject, err := objectFromCanonical(state.Plan)
	if err != nil {
		return err
	}
	details := map[string]any{
		"approval_deadline_boottime_ns": state.ApprovalDeadlineBootTimeNS,
		"intent_sha256":                 state.IntentSHA256,
		"prepared_plan":                 planObject,
	}
	actionID, err := contracts.ActionID(state.Plan.PlanHashValue)
	if err != nil {
		return err
	}
	record := contracts.ActionRecordV1{
		SchemaVersion:        "agmind.action-record.v1",
		ActionID:             &actionID,
		PlanID:               state.Plan.PlanID,
		PlanHashValue:        state.Plan.PlanHashValue,
		State:                "PREPARED",
		ReasonCode:           "intent_prepared",
		ObservedAt:           state.Plan.PreparedAt,
		PreviousRecordSHA256: journal.previous,
		Details:              details,
		ActuatorKeyID:        journal.keyID,
	}
	recordHash, err := contracts.ActionRecordHash(record)
	if err != nil {
		return err
	}
	record.RecordSHA256 = recordHash
	record.RecordID = contracts.ActionRecordID(recordHash)
	message, err := contracts.ActionRecordSigningMessage(record)
	if err != nil {
		return err
	}
	record.ActuatorSignature = hex.EncodeToString(
		ed25519.Sign(journal.privateKey, message),
	)
	if err := contracts.VerifyActionRecord(record, journal.publicKey); err != nil {
		return err
	}
	payload, err := contracts.CanonicalJSON(record)
	if err != nil {
		return err
	}
	frameSize := int64(len(payload)) + actionFrameOverhead
	reservedFrames := futureFrames + maxLifecycleFramesPerPlan
	if reservedFrames < maxLifecycleFramesPerPlan ||
		frameSize+int64(reservedFrames)*
			(int64(actionJournalMaxFrame)+actionFrameOverhead) >
			actionJournalMaxBytes-journal.byteCount {
		return ErrPendingLimit
	}
	meta, err := journal.stream.Append(payload, true)
	if err != nil {
		return err
	}
	journal.previous = record.RecordSHA256
	state.PreparedRecordSHA256 = record.RecordSHA256
	journal.byIntent[state.Plan.IntentID] = state
	journal.byPlan[state.Plan.PlanID] = state
	journal.recordCount++
	journal.byteCount += int64(meta.Size)
	return nil
}

func (journal *actionJournal) failed() bool {
	return journal.stream.Failed()
}

func (journal *actionJournal) close() error {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	if journal.closed {
		return nil
	}
	journal.closed = true
	return journal.stream.Close()
}
