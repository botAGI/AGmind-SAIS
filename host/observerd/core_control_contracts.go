package observerd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"

	"agmind.local/sais/internal/contracts"
)

const (
	evidenceRepairAuthorizeRequestMaxBytes int64  = 4_096
	evidenceRepairCompleteRequestMaxBytes  int64  = 4_096
	retentionTombstoneRequestMaxBytes      int64  = 16_384
	retentionBlockedRequestMaxBytes        int64  = 4_096
	maxEvidenceSegmentBytes                uint64 = 64 * 1024 * 1024
	maxRetentionManifestRun                       = 128
	emptySHA256                                   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var ErrCoreControlReceiptRequired = errors.New(
	"core control event requires atomic receipt publication",
)

func coreControlEventType(eventType string) bool {
	switch eventType {
	case "evidence_repair_authorized",
		"evidence_repair_completed",
		"retention_tombstone",
		"retention_blocked_priority_evidence":
		return true
	default:
		return false
	}
}

type CoreControlRequest interface {
	Validate() error
	EventType() string
	OperationKey() string
	RequestMaxBytes() int64
	NormalizedFields() map[string]any
}

type EvidenceRepairAuthorizeV1 struct {
	SchemaVersion           string `json:"schema_version"`
	RepairID                string `json:"repair_id"`
	SegmentID               string `json:"segment_id"`
	VerifiedBytes           uint64 `json:"verified_bytes"`
	DiscardedBytes          uint64 `json:"discarded_bytes"`
	DiscardedSHA256         string `json:"discarded_sha256"`
	LastVerifiedFrameSHA256 string `json:"last_verified_frame_sha256"`
	CurrentChainHeadSHA256  string `json:"current_chain_head_sha256"`
	Reason                  string `json:"reason"`
}

func (request EvidenceRepairAuthorizeV1) Validate() error {
	if request.SchemaVersion != "agmind.evidence-repair-authorize.v1" ||
		!uuid4Pattern.MatchString(request.RepairID) ||
		!uuid4Pattern.MatchString(request.SegmentID) ||
		request.VerifiedBytes > maxEvidenceSegmentBytes ||
		request.DiscardedBytes == 0 ||
		request.DiscardedBytes >
			maxEvidenceSegmentBytes-request.VerifiedBytes ||
		!hex64Pattern.MatchString(request.DiscardedSHA256) ||
		!hex64Pattern.MatchString(request.LastVerifiedFrameSHA256) ||
		!hex64Pattern.MatchString(request.CurrentChainHeadSHA256) ||
		request.Reason != "torn_open_tail" ||
		(request.VerifiedBytes == 0) !=
			(request.LastVerifiedFrameSHA256 == zeroControlReceiptHash) {
		return fmt.Errorf("invalid evidence repair authorization")
	}
	return nil
}

func (request EvidenceRepairAuthorizeV1) EventType() string {
	return "evidence_repair_authorized"
}

func (request EvidenceRepairAuthorizeV1) OperationKey() string {
	return request.EventType() + ":" + request.RepairID
}

func (EvidenceRepairAuthorizeV1) RequestMaxBytes() int64 {
	return evidenceRepairAuthorizeRequestMaxBytes
}

func (request EvidenceRepairAuthorizeV1) NormalizedFields() map[string]any {
	return map[string]any{
		"schema_version":             request.SchemaVersion,
		"repair_id":                  request.RepairID,
		"segment_id":                 request.SegmentID,
		"verified_bytes":             request.VerifiedBytes,
		"discarded_bytes":            request.DiscardedBytes,
		"discarded_sha256":           request.DiscardedSHA256,
		"last_verified_frame_sha256": request.LastVerifiedFrameSHA256,
		"current_chain_head_sha256":  request.CurrentChainHeadSHA256,
		"reason":                     request.Reason,
	}
}

type EvidenceRepairCompleteV1 struct {
	SchemaVersion              string `json:"schema_version"`
	RepairID                   string `json:"repair_id"`
	AuthorizationEventID       string `json:"authorization_event_id"`
	AuthorizationContentSHA256 string `json:"authorization_content_sha256"`
	SegmentID                  string `json:"segment_id"`
	VerifiedBytes              uint64 `json:"verified_bytes"`
	PostRepairPrefixSHA256     string `json:"post_repair_prefix_sha256"`
	LastVerifiedFrameSHA256    string `json:"last_verified_frame_sha256"`
	CurrentChainHeadSHA256     string `json:"current_chain_head_sha256"`
	Reason                     string `json:"reason"`
}

func (request EvidenceRepairCompleteV1) Validate() error {
	if request.SchemaVersion != "agmind.evidence-repair-complete.v1" ||
		!uuid4Pattern.MatchString(request.RepairID) ||
		!eventPattern.MatchString(request.AuthorizationEventID) ||
		!hex64Pattern.MatchString(request.AuthorizationContentSHA256) ||
		!uuid4Pattern.MatchString(request.SegmentID) ||
		request.VerifiedBytes > maxEvidenceSegmentBytes ||
		!hex64Pattern.MatchString(request.PostRepairPrefixSHA256) ||
		!hex64Pattern.MatchString(request.LastVerifiedFrameSHA256) ||
		!hex64Pattern.MatchString(request.CurrentChainHeadSHA256) ||
		request.Reason != "torn_open_tail_completed" ||
		(request.VerifiedBytes == 0) !=
			(request.LastVerifiedFrameSHA256 == zeroControlReceiptHash) ||
		request.VerifiedBytes == 0 &&
			request.PostRepairPrefixSHA256 != emptySHA256 {
		return fmt.Errorf("invalid evidence repair completion")
	}
	return nil
}

func (request EvidenceRepairCompleteV1) EventType() string {
	return "evidence_repair_completed"
}

func (request EvidenceRepairCompleteV1) OperationKey() string {
	return request.EventType() + ":" + request.RepairID
}

func (EvidenceRepairCompleteV1) RequestMaxBytes() int64 {
	return evidenceRepairCompleteRequestMaxBytes
}

func (request EvidenceRepairCompleteV1) NormalizedFields() map[string]any {
	return map[string]any{
		"schema_version":               request.SchemaVersion,
		"repair_id":                    request.RepairID,
		"authorization_event_id":       request.AuthorizationEventID,
		"authorization_content_sha256": request.AuthorizationContentSHA256,
		"segment_id":                   request.SegmentID,
		"verified_bytes":               request.VerifiedBytes,
		"post_repair_prefix_sha256":    request.PostRepairPrefixSHA256,
		"last_verified_frame_sha256":   request.LastVerifiedFrameSHA256,
		"current_chain_head_sha256":    request.CurrentChainHeadSHA256,
		"reason":                       request.Reason,
	}
}

type RetentionTombstoneV2 struct {
	SchemaVersion               string   `json:"schema_version"`
	TombstoneID                 string   `json:"tombstone_id"`
	RemovedManifestHashes       []string `json:"removed_manifest_hashes"`
	FirstRemovedManifestSHA256  string   `json:"first_removed_manifest_sha256"`
	LastRemovedManifestSHA256   string   `json:"last_removed_manifest_sha256"`
	FirstRetainedManifestSHA256 string   `json:"first_retained_manifest_sha256"`
	RemovedBytes                uint64   `json:"removed_bytes"`
	Reason                      string   `json:"reason"`
	PolicyVersion               string   `json:"policy_version"`
	CurrentChainHeadSHA256      string   `json:"current_chain_head_sha256"`
	ManifestRunSHA256           string   `json:"manifest_run_sha256"`
}

func RetentionManifestRunSHA256(hashes []string) (string, error) {
	canonical, err := contracts.CanonicalJSON(hashes)
	if err != nil {
		return "", err
	}
	preimage := append([]byte("AGMIND_RETENTION_RUN_V2\x00"), canonical...)
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

func (request RetentionTombstoneV2) Validate() error {
	if request.SchemaVersion != "agmind.retention-tombstone.v2" ||
		!uuid4Pattern.MatchString(request.TombstoneID) ||
		len(request.RemovedManifestHashes) < 1 ||
		len(request.RemovedManifestHashes) > maxRetentionManifestRun ||
		!hex64Pattern.MatchString(request.FirstRemovedManifestSHA256) ||
		!hex64Pattern.MatchString(request.LastRemovedManifestSHA256) ||
		!hex64Pattern.MatchString(request.FirstRetainedManifestSHA256) ||
		request.RemovedBytes == 0 ||
		request.PolicyVersion != "agmind-retention-v1" ||
		!hex64Pattern.MatchString(request.CurrentChainHeadSHA256) ||
		!hex64Pattern.MatchString(request.ManifestRunSHA256) {
		return fmt.Errorf("invalid retention tombstone")
	}
	switch request.Reason {
	case "retention_age_limit",
		"retention_size_limit",
		"retention_age_and_size_limit":
	default:
		return fmt.Errorf("invalid retention tombstone reason")
	}
	seen := make(map[string]struct{}, len(request.RemovedManifestHashes))
	for _, manifestHash := range request.RemovedManifestHashes {
		if !hex64Pattern.MatchString(manifestHash) {
			return fmt.Errorf("invalid removed manifest hash")
		}
		if _, exists := seen[manifestHash]; exists {
			return fmt.Errorf("duplicate removed manifest hash")
		}
		seen[manifestHash] = struct{}{}
	}
	if request.FirstRemovedManifestSHA256 != request.RemovedManifestHashes[0] ||
		request.LastRemovedManifestSHA256 !=
			request.RemovedManifestHashes[len(request.RemovedManifestHashes)-1] {
		return fmt.Errorf("retention run endpoint binding mismatch")
	}
	runHash, err := RetentionManifestRunSHA256(request.RemovedManifestHashes)
	if err != nil || runHash != request.ManifestRunSHA256 {
		return fmt.Errorf("retention manifest run hash mismatch")
	}
	return nil
}

func (request RetentionTombstoneV2) EventType() string {
	return "retention_tombstone"
}

func (request RetentionTombstoneV2) OperationKey() string {
	return request.EventType() + ":" + request.TombstoneID
}

func (RetentionTombstoneV2) RequestMaxBytes() int64 {
	return retentionTombstoneRequestMaxBytes
}

func (request RetentionTombstoneV2) NormalizedFields() map[string]any {
	return map[string]any{
		"schema_version":                 request.SchemaVersion,
		"tombstone_id":                   request.TombstoneID,
		"removed_manifest_hashes":        append([]string{}, request.RemovedManifestHashes...),
		"first_removed_manifest_sha256":  request.FirstRemovedManifestSHA256,
		"last_removed_manifest_sha256":   request.LastRemovedManifestSHA256,
		"first_retained_manifest_sha256": request.FirstRetainedManifestSHA256,
		"removed_bytes":                  request.RemovedBytes,
		"reason":                         request.Reason,
		"policy_version":                 request.PolicyVersion,
		"current_chain_head_sha256":      request.CurrentChainHeadSHA256,
		"manifest_run_sha256":            request.ManifestRunSHA256,
	}
}

type RetentionBlockedV1 struct {
	SchemaVersion          string `json:"schema_version"`
	BlockedID              string `json:"blocked_id"`
	TargetBytes            uint64 `json:"target_bytes"`
	RoutineBytes           uint64 `json:"routine_bytes"`
	ProtectedBytes         uint64 `json:"protected_bytes"`
	BlockedBytes           uint64 `json:"blocked_bytes"`
	Reason                 string `json:"reason"`
	CurrentChainHeadSHA256 string `json:"current_chain_head_sha256"`
}

func (request RetentionBlockedV1) Validate() error {
	if request.SchemaVersion != "agmind.retention-blocked.v1" ||
		!uuid4Pattern.MatchString(request.BlockedID) ||
		request.TargetBytes == 0 ||
		request.BlockedBytes == 0 ||
		!hex64Pattern.MatchString(request.CurrentChainHeadSHA256) ||
		request.Reason != "protected_evidence" &&
			request.Reason != "required_key_proof" ||
		request.RoutineBytes > math.MaxUint64-request.ProtectedBytes {
		return fmt.Errorf("invalid retention blocked event")
	}
	retained := request.RoutineBytes + request.ProtectedBytes
	if retained <= request.TargetBytes ||
		request.BlockedBytes != retained-request.TargetBytes {
		return fmt.Errorf("invalid retention blocked byte arithmetic")
	}
	return nil
}

func (request RetentionBlockedV1) EventType() string {
	return "retention_blocked_priority_evidence"
}

func (request RetentionBlockedV1) OperationKey() string {
	return request.EventType() + ":" + request.BlockedID
}

func (RetentionBlockedV1) RequestMaxBytes() int64 {
	return retentionBlockedRequestMaxBytes
}

func (request RetentionBlockedV1) NormalizedFields() map[string]any {
	return map[string]any{
		"schema_version":            request.SchemaVersion,
		"blocked_id":                request.BlockedID,
		"target_bytes":              request.TargetBytes,
		"routine_bytes":             request.RoutineBytes,
		"protected_bytes":           request.ProtectedBytes,
		"blocked_bytes":             request.BlockedBytes,
		"reason":                    request.Reason,
		"current_chain_head_sha256": request.CurrentChainHeadSHA256,
	}
}

func CanonicalCoreControlRequest(request CoreControlRequest) ([]byte, error) {
	if request == nil {
		return nil, fmt.Errorf("nil core control request")
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	canonical, err := contracts.CanonicalJSON(request)
	if err != nil {
		return nil, err
	}
	fields, err := contracts.CanonicalJSON(request.NormalizedFields())
	if err != nil || !bytes.Equal(canonical, fields) {
		return nil, fmt.Errorf("core control normalized fields differ from request")
	}
	return canonical, nil
}

func CoreControlRequestSHA256(request CoreControlRequest) (string, error) {
	canonical, err := CanonicalCoreControlRequest(request)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func DecodeCoreControlRequest[T CoreControlRequest](reader io.Reader) (T, error) {
	var zero T
	request, err := contracts.DecodeStrict[T](
		reader,
		zero.RequestMaxBytes(),
	)
	if err != nil {
		return zero, err
	}
	if err := request.Validate(); err != nil {
		return zero, err
	}
	return request, nil
}

func coreControlRequestFromEnvelope(
	event contracts.EventEnvelopeV1,
) (CoreControlRequest, error) {
	raw, err := contracts.CanonicalJSON(event.NormalizedFields)
	if err != nil {
		return nil, err
	}
	switch event.EventType {
	case "evidence_repair_authorized":
		value, err := contracts.DecodeStrict[EvidenceRepairAuthorizeV1](
			bytes.NewReader(raw),
			evidenceRepairAuthorizeRequestMaxBytes,
		)
		if err != nil || value.Validate() != nil {
			return nil, fmt.Errorf("invalid signed repair authorization")
		}
		return value, nil
	case "evidence_repair_completed":
		value, err := contracts.DecodeStrict[EvidenceRepairCompleteV1](
			bytes.NewReader(raw),
			evidenceRepairCompleteRequestMaxBytes,
		)
		if err != nil || value.Validate() != nil {
			return nil, fmt.Errorf("invalid signed repair completion")
		}
		return value, nil
	case "retention_tombstone":
		value, err := contracts.DecodeStrict[RetentionTombstoneV2](
			bytes.NewReader(raw),
			retentionTombstoneRequestMaxBytes,
		)
		if err != nil || value.Validate() != nil {
			return nil, fmt.Errorf("invalid signed retention tombstone")
		}
		return value, nil
	case "retention_blocked_priority_evidence":
		value, err := contracts.DecodeStrict[RetentionBlockedV1](
			bytes.NewReader(raw),
			retentionBlockedRequestMaxBytes,
		)
		if err != nil || value.Validate() != nil {
			return nil, fmt.Errorf("invalid signed retention blocked event")
		}
		return value, nil
	default:
		return nil, nil
	}
}
