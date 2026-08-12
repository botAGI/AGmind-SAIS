package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const observerStateSchemaV1 = "agmind.observer-state.v1"
const observerStateSchemaV2 = "agmind.observer-state.v2"
const observerStateSchemaV3 = "agmind.observer-state.v3"
const observerStateSchemaV4 = "agmind.observer-state.v4"
const observerStateSchemaV5 = "agmind.observer-state.v5"
const observerStateSchema = "agmind.observer-state.v6"
const sequenceGapProtocolC8 = "proof_carrying_containment_c8"
const sequenceGapProtocolLegacyUnproven = "legacy_unproven"
const zeroPublicationHash = "0000000000000000000000000000000000000000000000000000000000000000"
const zeroControlReceiptHash = "0000000000000000000000000000000000000000000000000000000000000000"
const zeroPCCJournalHash = "0000000000000000000000000000000000000000000000000000000000000000"

const (
	controlReceiptMaxCount uint64 = 4_096
	controlReceiptMaxBytes uint64 = 64 * 1024 * 1024
)

const (
	bootBoundaryPending        = "pending"
	bootBoundaryCommitted      = "committed"
	bootBoundaryLegacyUnproven = "legacy_unproven"
)

type BootBoundary struct {
	BootID            string `json:"boot_id"`
	FirstSequence     uint64 `json:"first_sequence"`
	BoundaryEventID   string `json:"boundary_event_id,omitempty"`
	BoundaryEventType string `json:"boundary_event_type,omitempty"`
}

type PendingBootBoundary struct {
	ReasonCode             string  `json:"reason_code"`
	PreviousBootID         *string `json:"previous_boot_id,omitempty"`
	PreviousSourceSequence uint64  `json:"previous_source_sequence"`
}

// PendingDockerReconcile is the one Docker reconcile window whose CRITICAL
// docker_reconcile_gap open has been signed and whose matching
// docker_reconcile_recovered close has not. The window is SINGULAR and OWNED:
// it is recorded durably the moment the open is signed and dropped in the
// commit that signs the close, so a failed reconcile — or an observer restart
// mid-window — resumes THIS window instead of signing a second open that
// nothing will ever close. Core pairs opens and closes on
// (opened_at, reconcile_generation) and latches "docker_reconcile_missing"
// forever on an unpaired open, so an abandoned window is unrepresentable here
// by construction rather than by convention.
type PendingDockerReconcile struct {
	OpenedAt   string `json:"opened_at"`
	Generation uint64 `json:"reconcile_generation"`
}

type ObserverState struct {
	SchemaVersion           string                  `json:"schema_version"`
	HostID                  string                  `json:"host_id"`
	BootID                  string                  `json:"boot_id"`
	KeyID                   string                  `json:"key_id"`
	KeyEpoch                uint64                  `json:"key_epoch"`
	LastSequence            uint64                  `json:"last_sequence"`
	MutationReadOnly        bool                    `json:"mutation_read_only"`
	ReadOnlyReason          string                  `json:"read_only_reason"`
	ReconcileRequired       bool                    `json:"reconcile_required"`
	RoutineDropped          uint64                  `json:"routine_dropped"`
	DropEventPending        bool                    `json:"drop_event_pending"`
	AckSequence             uint64                  `json:"ack_sequence"`
	AckEventID              string                  `json:"ack_event_id"`
	AckContentSHA256        string                  `json:"ack_content_sha256"`
	AckRecordHash           string                  `json:"ack_record_hash"`
	AckPayloadSHA256        string                  `json:"ack_payload_sha256"`
	LastCoveredGapEnd       uint64                  `json:"last_covered_gap_end"`
	SequenceGapProtocol     string                  `json:"sequence_gap_protocol"`
	BootHistory             []BootBoundary          `json:"boot_history,omitempty"`
	AckRepairPending        bool                    `json:"ack_repair_pending"`
	AckRepairReason         string                  `json:"ack_repair_reason"`
	PublicationBaseSequence uint64                  `json:"publication_base_sequence"`
	PublicationBaseHash     string                  `json:"publication_base_hash"`
	PublicationHeadSequence uint64                  `json:"publication_head_sequence"`
	PublicationHeadHash     string                  `json:"publication_head_hash"`
	ControlReceiptCount     uint64                  `json:"control_receipt_count"`
	ControlReceiptBytes     uint64                  `json:"control_receipt_bytes"`
	ControlReceiptHeadHash  string                  `json:"control_receipt_head_sha256"`
	PCCBoundaryCount        uint64                  `json:"pcc_boundary_count"`
	PCCBoundaryBytes        uint64                  `json:"pcc_boundary_bytes"`
	PCCBoundaryHeadHash     string                  `json:"pcc_boundary_head_sha256"`
	PCCReceiptCount         uint64                  `json:"pcc_receipt_count"`
	PCCReceiptBytes         uint64                  `json:"pcc_receipt_bytes"`
	PCCReceiptHeadHash      string                  `json:"pcc_receipt_head_sha256"`
	BootBoundaryState       string                  `json:"boot_boundary_state"`
	PendingBootBoundary     *PendingBootBoundary    `json:"pending_boot_boundary,omitempty"`
	PendingDockerReconcile  *PendingDockerReconcile `json:"pending_docker_reconcile,omitempty"`
}

// observerStateV5 is the exact pre-Docker-reconcile-window state contract. A V5
// state predates the durable window, so any Docker gap it left open is already
// unowned; migration records no pending window and the startup reconcile opens
// a fresh one.
type observerStateV5 struct {
	SchemaVersion           string               `json:"schema_version"`
	HostID                  string               `json:"host_id"`
	BootID                  string               `json:"boot_id"`
	KeyID                   string               `json:"key_id"`
	KeyEpoch                uint64               `json:"key_epoch"`
	LastSequence            uint64               `json:"last_sequence"`
	MutationReadOnly        bool                 `json:"mutation_read_only"`
	ReadOnlyReason          string               `json:"read_only_reason"`
	ReconcileRequired       bool                 `json:"reconcile_required"`
	RoutineDropped          uint64               `json:"routine_dropped"`
	DropEventPending        bool                 `json:"drop_event_pending"`
	AckSequence             uint64               `json:"ack_sequence"`
	AckEventID              string               `json:"ack_event_id"`
	AckContentSHA256        string               `json:"ack_content_sha256"`
	AckRecordHash           string               `json:"ack_record_hash"`
	AckPayloadSHA256        string               `json:"ack_payload_sha256"`
	LastCoveredGapEnd       uint64               `json:"last_covered_gap_end"`
	SequenceGapProtocol     string               `json:"sequence_gap_protocol"`
	BootHistory             []BootBoundary       `json:"boot_history,omitempty"`
	AckRepairPending        bool                 `json:"ack_repair_pending"`
	AckRepairReason         string               `json:"ack_repair_reason"`
	PublicationBaseSequence uint64               `json:"publication_base_sequence"`
	PublicationBaseHash     string               `json:"publication_base_hash"`
	PublicationHeadSequence uint64               `json:"publication_head_sequence"`
	PublicationHeadHash     string               `json:"publication_head_hash"`
	ControlReceiptCount     uint64               `json:"control_receipt_count"`
	ControlReceiptBytes     uint64               `json:"control_receipt_bytes"`
	ControlReceiptHeadHash  string               `json:"control_receipt_head_sha256"`
	PCCBoundaryCount        uint64               `json:"pcc_boundary_count"`
	PCCBoundaryBytes        uint64               `json:"pcc_boundary_bytes"`
	PCCBoundaryHeadHash     string               `json:"pcc_boundary_head_sha256"`
	PCCReceiptCount         uint64               `json:"pcc_receipt_count"`
	PCCReceiptBytes         uint64               `json:"pcc_receipt_bytes"`
	PCCReceiptHeadHash      string               `json:"pcc_receipt_head_sha256"`
	BootBoundaryState       string               `json:"boot_boundary_state"`
	PendingBootBoundary     *PendingBootBoundary `json:"pending_boot_boundary,omitempty"`
}

func observerStateFromV5(legacy observerStateV5) ObserverState {
	return ObserverState{
		SchemaVersion:           observerStateSchema,
		HostID:                  legacy.HostID,
		BootID:                  legacy.BootID,
		KeyID:                   legacy.KeyID,
		KeyEpoch:                legacy.KeyEpoch,
		LastSequence:            legacy.LastSequence,
		MutationReadOnly:        legacy.MutationReadOnly,
		ReadOnlyReason:          legacy.ReadOnlyReason,
		ReconcileRequired:       legacy.ReconcileRequired,
		RoutineDropped:          legacy.RoutineDropped,
		DropEventPending:        legacy.DropEventPending,
		AckSequence:             legacy.AckSequence,
		AckEventID:              legacy.AckEventID,
		AckContentSHA256:        legacy.AckContentSHA256,
		AckRecordHash:           legacy.AckRecordHash,
		AckPayloadSHA256:        legacy.AckPayloadSHA256,
		LastCoveredGapEnd:       legacy.LastCoveredGapEnd,
		SequenceGapProtocol:     legacy.SequenceGapProtocol,
		BootHistory:             append([]BootBoundary(nil), legacy.BootHistory...),
		AckRepairPending:        legacy.AckRepairPending,
		AckRepairReason:         legacy.AckRepairReason,
		PublicationBaseSequence: legacy.PublicationBaseSequence,
		PublicationBaseHash:     legacy.PublicationBaseHash,
		PublicationHeadSequence: legacy.PublicationHeadSequence,
		PublicationHeadHash:     legacy.PublicationHeadHash,
		ControlReceiptCount:     legacy.ControlReceiptCount,
		ControlReceiptBytes:     legacy.ControlReceiptBytes,
		ControlReceiptHeadHash:  legacy.ControlReceiptHeadHash,
		PCCBoundaryCount:        legacy.PCCBoundaryCount,
		PCCBoundaryBytes:        legacy.PCCBoundaryBytes,
		PCCBoundaryHeadHash:     legacy.PCCBoundaryHeadHash,
		PCCReceiptCount:         legacy.PCCReceiptCount,
		PCCReceiptBytes:         legacy.PCCReceiptBytes,
		PCCReceiptHeadHash:      legacy.PCCReceiptHeadHash,
		BootBoundaryState:       legacy.BootBoundaryState,
		PendingBootBoundary:     legacy.PendingBootBoundary,
	}
}

func (legacy observerStateV5) Validate() error {
	if legacy.SchemaVersion != observerStateSchemaV5 {
		return fmt.Errorf("invalid V5 observer state")
	}
	return observerStateFromV5(legacy).Validate()
}

// observerStateV4 is the exact pre-PCC-journal state contract. Migration is
// legal only when neither fixed PCC journal path exists.
type observerStateV4 struct {
	SchemaVersion           string               `json:"schema_version"`
	HostID                  string               `json:"host_id"`
	BootID                  string               `json:"boot_id"`
	KeyID                   string               `json:"key_id"`
	KeyEpoch                uint64               `json:"key_epoch"`
	LastSequence            uint64               `json:"last_sequence"`
	MutationReadOnly        bool                 `json:"mutation_read_only"`
	ReadOnlyReason          string               `json:"read_only_reason"`
	ReconcileRequired       bool                 `json:"reconcile_required"`
	RoutineDropped          uint64               `json:"routine_dropped"`
	DropEventPending        bool                 `json:"drop_event_pending"`
	AckSequence             uint64               `json:"ack_sequence"`
	AckEventID              string               `json:"ack_event_id"`
	AckContentSHA256        string               `json:"ack_content_sha256"`
	AckRecordHash           string               `json:"ack_record_hash"`
	AckPayloadSHA256        string               `json:"ack_payload_sha256"`
	LastCoveredGapEnd       uint64               `json:"last_covered_gap_end"`
	SequenceGapProtocol     string               `json:"sequence_gap_protocol"`
	BootHistory             []BootBoundary       `json:"boot_history,omitempty"`
	AckRepairPending        bool                 `json:"ack_repair_pending"`
	AckRepairReason         string               `json:"ack_repair_reason"`
	PublicationBaseSequence uint64               `json:"publication_base_sequence"`
	PublicationBaseHash     string               `json:"publication_base_hash"`
	PublicationHeadSequence uint64               `json:"publication_head_sequence"`
	PublicationHeadHash     string               `json:"publication_head_hash"`
	ControlReceiptCount     uint64               `json:"control_receipt_count"`
	ControlReceiptBytes     uint64               `json:"control_receipt_bytes"`
	ControlReceiptHeadHash  string               `json:"control_receipt_head_sha256"`
	BootBoundaryState       string               `json:"boot_boundary_state"`
	PendingBootBoundary     *PendingBootBoundary `json:"pending_boot_boundary,omitempty"`
}

func observerStateFromV4(legacy observerStateV4) ObserverState {
	return ObserverState{
		SchemaVersion:           observerStateSchema,
		HostID:                  legacy.HostID,
		BootID:                  legacy.BootID,
		KeyID:                   legacy.KeyID,
		KeyEpoch:                legacy.KeyEpoch,
		LastSequence:            legacy.LastSequence,
		MutationReadOnly:        legacy.MutationReadOnly,
		ReadOnlyReason:          legacy.ReadOnlyReason,
		ReconcileRequired:       legacy.ReconcileRequired,
		RoutineDropped:          legacy.RoutineDropped,
		DropEventPending:        legacy.DropEventPending,
		AckSequence:             legacy.AckSequence,
		AckEventID:              legacy.AckEventID,
		AckContentSHA256:        legacy.AckContentSHA256,
		AckRecordHash:           legacy.AckRecordHash,
		AckPayloadSHA256:        legacy.AckPayloadSHA256,
		LastCoveredGapEnd:       legacy.LastCoveredGapEnd,
		SequenceGapProtocol:     legacy.SequenceGapProtocol,
		BootHistory:             append([]BootBoundary(nil), legacy.BootHistory...),
		AckRepairPending:        legacy.AckRepairPending,
		AckRepairReason:         legacy.AckRepairReason,
		PublicationBaseSequence: legacy.PublicationBaseSequence,
		PublicationBaseHash:     legacy.PublicationBaseHash,
		PublicationHeadSequence: legacy.PublicationHeadSequence,
		PublicationHeadHash:     legacy.PublicationHeadHash,
		ControlReceiptCount:     legacy.ControlReceiptCount,
		ControlReceiptBytes:     legacy.ControlReceiptBytes,
		ControlReceiptHeadHash:  legacy.ControlReceiptHeadHash,
		PCCBoundaryHeadHash:     zeroPCCJournalHash,
		PCCReceiptHeadHash:      zeroPCCJournalHash,
		BootBoundaryState:       legacy.BootBoundaryState,
		PendingBootBoundary:     legacy.PendingBootBoundary,
	}
}

func (legacy observerStateV4) Validate() error {
	if legacy.SchemaVersion != observerStateSchemaV4 {
		return fmt.Errorf("invalid V4 observer state")
	}
	return observerStateFromV4(legacy).Validate()
}

// observerStateV3 is the pre-control-receipt state contract. C2A is a
// fresh-state producer boundary, so migration is valid only with an empty
// receipt anchor; OpenStateStore rejects any pre-existing receipt journal
// before persisting the V4 migration.
type observerStateV3 struct {
	SchemaVersion           string               `json:"schema_version"`
	HostID                  string               `json:"host_id"`
	BootID                  string               `json:"boot_id"`
	KeyID                   string               `json:"key_id"`
	KeyEpoch                uint64               `json:"key_epoch"`
	LastSequence            uint64               `json:"last_sequence"`
	MutationReadOnly        bool                 `json:"mutation_read_only"`
	ReadOnlyReason          string               `json:"read_only_reason"`
	ReconcileRequired       bool                 `json:"reconcile_required"`
	RoutineDropped          uint64               `json:"routine_dropped"`
	DropEventPending        bool                 `json:"drop_event_pending"`
	AckSequence             uint64               `json:"ack_sequence"`
	AckEventID              string               `json:"ack_event_id"`
	AckContentSHA256        string               `json:"ack_content_sha256"`
	AckRecordHash           string               `json:"ack_record_hash"`
	AckPayloadSHA256        string               `json:"ack_payload_sha256"`
	LastCoveredGapEnd       uint64               `json:"last_covered_gap_end"`
	SequenceGapProtocol     string               `json:"sequence_gap_protocol"`
	BootHistory             []BootBoundary       `json:"boot_history,omitempty"`
	AckRepairPending        bool                 `json:"ack_repair_pending"`
	AckRepairReason         string               `json:"ack_repair_reason"`
	PublicationBaseSequence uint64               `json:"publication_base_sequence"`
	PublicationBaseHash     string               `json:"publication_base_hash"`
	PublicationHeadSequence uint64               `json:"publication_head_sequence"`
	PublicationHeadHash     string               `json:"publication_head_hash"`
	BootBoundaryState       string               `json:"boot_boundary_state"`
	PendingBootBoundary     *PendingBootBoundary `json:"pending_boot_boundary,omitempty"`
}

func observerStateFromV3(legacy observerStateV3) ObserverState {
	return ObserverState{
		SchemaVersion:           observerStateSchema,
		HostID:                  legacy.HostID,
		BootID:                  legacy.BootID,
		KeyID:                   legacy.KeyID,
		KeyEpoch:                legacy.KeyEpoch,
		LastSequence:            legacy.LastSequence,
		MutationReadOnly:        legacy.MutationReadOnly,
		ReadOnlyReason:          legacy.ReadOnlyReason,
		ReconcileRequired:       legacy.ReconcileRequired,
		RoutineDropped:          legacy.RoutineDropped,
		DropEventPending:        legacy.DropEventPending,
		AckSequence:             legacy.AckSequence,
		AckEventID:              legacy.AckEventID,
		AckContentSHA256:        legacy.AckContentSHA256,
		AckRecordHash:           legacy.AckRecordHash,
		AckPayloadSHA256:        legacy.AckPayloadSHA256,
		LastCoveredGapEnd:       legacy.LastCoveredGapEnd,
		SequenceGapProtocol:     legacy.SequenceGapProtocol,
		BootHistory:             append([]BootBoundary(nil), legacy.BootHistory...),
		AckRepairPending:        legacy.AckRepairPending,
		AckRepairReason:         legacy.AckRepairReason,
		PublicationBaseSequence: legacy.PublicationBaseSequence,
		PublicationBaseHash:     legacy.PublicationBaseHash,
		PublicationHeadSequence: legacy.PublicationHeadSequence,
		PublicationHeadHash:     legacy.PublicationHeadHash,
		ControlReceiptHeadHash:  zeroControlReceiptHash,
		PCCBoundaryHeadHash:     zeroPCCJournalHash,
		PCCReceiptHeadHash:      zeroPCCJournalHash,
		BootBoundaryState:       legacy.BootBoundaryState,
		PendingBootBoundary:     legacy.PendingBootBoundary,
	}
}

func (legacy observerStateV3) Validate() error {
	if legacy.SchemaVersion != observerStateSchemaV3 {
		return fmt.Errorf("invalid V3 observer state")
	}
	return observerStateFromV3(legacy).Validate()
}

// observerStateV2 is the pre-C8 state contract. It is migrated only when no
// sequence-gap marker exists; marker-bearing V2 state is one-way fenced in V3.
type observerStateV2 struct {
	SchemaVersion           string               `json:"schema_version"`
	HostID                  string               `json:"host_id"`
	BootID                  string               `json:"boot_id"`
	KeyID                   string               `json:"key_id"`
	KeyEpoch                uint64               `json:"key_epoch"`
	LastSequence            uint64               `json:"last_sequence"`
	MutationReadOnly        bool                 `json:"mutation_read_only"`
	ReadOnlyReason          string               `json:"read_only_reason"`
	ReconcileRequired       bool                 `json:"reconcile_required"`
	RoutineDropped          uint64               `json:"routine_dropped"`
	DropEventPending        bool                 `json:"drop_event_pending"`
	AckSequence             uint64               `json:"ack_sequence"`
	AckEventID              string               `json:"ack_event_id"`
	AckContentSHA256        string               `json:"ack_content_sha256"`
	AckRecordHash           string               `json:"ack_record_hash"`
	AckPayloadSHA256        string               `json:"ack_payload_sha256"`
	LastCoveredGapEnd       uint64               `json:"last_covered_gap_end"`
	BootHistory             []BootBoundary       `json:"boot_history,omitempty"`
	AckRepairPending        bool                 `json:"ack_repair_pending"`
	AckRepairReason         string               `json:"ack_repair_reason"`
	PublicationBaseSequence uint64               `json:"publication_base_sequence"`
	PublicationBaseHash     string               `json:"publication_base_hash"`
	PublicationHeadSequence uint64               `json:"publication_head_sequence"`
	PublicationHeadHash     string               `json:"publication_head_hash"`
	BootBoundaryState       string               `json:"boot_boundary_state"`
	PendingBootBoundary     *PendingBootBoundary `json:"pending_boot_boundary,omitempty"`
}

func observerStateFromV2(legacy observerStateV2) ObserverState {
	return ObserverState{
		SchemaVersion:           observerStateSchema,
		HostID:                  legacy.HostID,
		BootID:                  legacy.BootID,
		KeyID:                   legacy.KeyID,
		KeyEpoch:                legacy.KeyEpoch,
		LastSequence:            legacy.LastSequence,
		MutationReadOnly:        legacy.MutationReadOnly,
		ReadOnlyReason:          legacy.ReadOnlyReason,
		ReconcileRequired:       legacy.ReconcileRequired,
		RoutineDropped:          legacy.RoutineDropped,
		DropEventPending:        legacy.DropEventPending,
		AckSequence:             legacy.AckSequence,
		AckEventID:              legacy.AckEventID,
		AckContentSHA256:        legacy.AckContentSHA256,
		AckRecordHash:           legacy.AckRecordHash,
		AckPayloadSHA256:        legacy.AckPayloadSHA256,
		LastCoveredGapEnd:       legacy.LastCoveredGapEnd,
		SequenceGapProtocol:     sequenceGapProtocolC8,
		BootHistory:             append([]BootBoundary(nil), legacy.BootHistory...),
		AckRepairPending:        legacy.AckRepairPending,
		AckRepairReason:         legacy.AckRepairReason,
		PublicationBaseSequence: legacy.PublicationBaseSequence,
		PublicationBaseHash:     legacy.PublicationBaseHash,
		PublicationHeadSequence: legacy.PublicationHeadSequence,
		PublicationHeadHash:     legacy.PublicationHeadHash,
		ControlReceiptHeadHash:  zeroControlReceiptHash,
		PCCBoundaryHeadHash:     zeroPCCJournalHash,
		PCCReceiptHeadHash:      zeroPCCJournalHash,
		BootBoundaryState:       legacy.BootBoundaryState,
		PendingBootBoundary:     legacy.PendingBootBoundary,
	}
}

func (legacy observerStateV2) Validate() error {
	if legacy.SchemaVersion != observerStateSchemaV2 {
		return fmt.Errorf("invalid V2 observer state")
	}
	return observerStateFromV2(legacy).Validate()
}

func migrateObserverStateV2(legacy observerStateV2) ObserverState {
	state := observerStateFromV2(legacy)
	if legacy.LastCoveredGapEnd > 0 {
		state.SequenceGapProtocol = sequenceGapProtocolLegacyUnproven
		if !state.MutationReadOnly {
			state.MutationReadOnly = true
			state.ReadOnlyReason = "observer_sequence_gap_enrollment_required"
		}
		state.ReconcileRequired = true
	}
	return state
}

// observerStateV1 exists only to make the one-way migration strict. It is
// never persisted after a successful read.
type observerStateV1 struct {
	SchemaVersion           string         `json:"schema_version"`
	HostID                  string         `json:"host_id"`
	BootID                  string         `json:"boot_id"`
	KeyID                   string         `json:"key_id"`
	KeyEpoch                uint64         `json:"key_epoch"`
	LastSequence            uint64         `json:"last_sequence"`
	MutationReadOnly        bool           `json:"mutation_read_only"`
	ReadOnlyReason          string         `json:"read_only_reason"`
	ReconcileRequired       bool           `json:"reconcile_required"`
	RoutineDropped          uint64         `json:"routine_dropped"`
	DropEventPending        bool           `json:"drop_event_pending"`
	AckSequence             uint64         `json:"ack_sequence"`
	AckEventID              string         `json:"ack_event_id"`
	AckContentSHA256        string         `json:"ack_content_sha256"`
	AckRecordHash           string         `json:"ack_record_hash"`
	AckPayloadSHA256        string         `json:"ack_payload_sha256"`
	LastCoveredGapEnd       uint64         `json:"last_covered_gap_end"`
	BootHistory             []BootBoundary `json:"boot_history,omitempty"`
	AckRepairPending        bool           `json:"ack_repair_pending"`
	AckRepairReason         string         `json:"ack_repair_reason"`
	PublicationBaseSequence uint64         `json:"publication_base_sequence"`
	PublicationBaseHash     string         `json:"publication_base_hash"`
	PublicationHeadSequence uint64         `json:"publication_head_sequence"`
	PublicationHeadHash     string         `json:"publication_head_hash"`
}

func observerStateFromV1(legacy observerStateV1) ObserverState {
	return ObserverState{
		SchemaVersion:           observerStateSchema,
		HostID:                  legacy.HostID,
		BootID:                  legacy.BootID,
		KeyID:                   legacy.KeyID,
		KeyEpoch:                legacy.KeyEpoch,
		LastSequence:            legacy.LastSequence,
		MutationReadOnly:        legacy.MutationReadOnly,
		ReadOnlyReason:          legacy.ReadOnlyReason,
		ReconcileRequired:       legacy.ReconcileRequired,
		RoutineDropped:          legacy.RoutineDropped,
		DropEventPending:        legacy.DropEventPending,
		AckSequence:             legacy.AckSequence,
		AckEventID:              legacy.AckEventID,
		AckContentSHA256:        legacy.AckContentSHA256,
		AckRecordHash:           legacy.AckRecordHash,
		AckPayloadSHA256:        legacy.AckPayloadSHA256,
		LastCoveredGapEnd:       legacy.LastCoveredGapEnd,
		SequenceGapProtocol:     sequenceGapProtocolC8,
		BootHistory:             append([]BootBoundary(nil), legacy.BootHistory...),
		AckRepairPending:        legacy.AckRepairPending,
		AckRepairReason:         legacy.AckRepairReason,
		PublicationBaseSequence: legacy.PublicationBaseSequence,
		PublicationBaseHash:     legacy.PublicationBaseHash,
		PublicationHeadSequence: legacy.PublicationHeadSequence,
		PublicationHeadHash:     legacy.PublicationHeadHash,
		ControlReceiptHeadHash:  zeroControlReceiptHash,
		PCCBoundaryHeadHash:     zeroPCCJournalHash,
		PCCReceiptHeadHash:      zeroPCCJournalHash,
	}
}

func (legacy observerStateV1) Validate() error {
	if legacy.SchemaVersion != observerStateSchemaV1 ||
		legacy.MutationReadOnly != (legacy.ReadOnlyReason != "") {
		return fmt.Errorf("invalid legacy observer state")
	}
	state := observerStateFromV1(legacy)
	state.MutationReadOnly = true
	if state.ReadOnlyReason == "" {
		state.ReadOnlyReason = "observer_legacy_boot_boundary_unproven"
	}
	state.ReconcileRequired = true
	state.BootBoundaryState = bootBoundaryLegacyUnproven
	return state.Validate()
}

func pristineObserverStateV1(legacy observerStateV1) bool {
	return legacy.KeyEpoch == 1 &&
		legacy.ReconcileRequired &&
		legacy.LastSequence == 0 &&
		!legacy.MutationReadOnly &&
		legacy.ReadOnlyReason == "" &&
		legacy.RoutineDropped == 0 &&
		!legacy.DropEventPending &&
		legacy.AckSequence == 0 &&
		legacy.AckEventID == "" &&
		legacy.AckContentSHA256 == "" &&
		legacy.AckRecordHash == "" &&
		legacy.AckPayloadSHA256 == "" &&
		legacy.LastCoveredGapEnd == 0 &&
		!legacy.AckRepairPending &&
		legacy.AckRepairReason == "" &&
		legacy.PublicationBaseSequence == 0 &&
		legacy.PublicationBaseHash == zeroPublicationHash &&
		legacy.PublicationHeadSequence == 0 &&
		legacy.PublicationHeadHash == zeroPublicationHash &&
		len(legacy.BootHistory) == 1 &&
		legacy.BootHistory[0].BootID == legacy.BootID &&
		legacy.BootHistory[0].FirstSequence == 1
}

func migrateObserverStateV1(legacy observerStateV1) ObserverState {
	state := observerStateFromV1(legacy)
	if pristineObserverStateV1(legacy) {
		state.BootBoundaryState = bootBoundaryPending
		state.PendingBootBoundary = &PendingBootBoundary{
			ReasonCode: "observer_genesis",
		}
		return state
	}
	state.MutationReadOnly = true
	if state.ReadOnlyReason == "" {
		state.ReadOnlyReason = "observer_legacy_boot_boundary_unproven"
	}
	state.ReconcileRequired = true
	state.BootBoundaryState = bootBoundaryLegacyUnproven
	state.PendingBootBoundary = nil
	if legacy.LastCoveredGapEnd > 0 {
		state.SequenceGapProtocol = sequenceGapProtocolLegacyUnproven
	}
	return state
}

func observerStateSchemaVersion(raw []byte) (string, error) {
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return "", err
	}
	return header.SchemaVersion, nil
}

func decodeObserverState(raw []byte) (ObserverState, bool, error) {
	schemaVersion, err := observerStateSchemaVersion(raw)
	if err != nil {
		return ObserverState{}, false, err
	}
	switch schemaVersion {
	case observerStateSchema:
		state, err := contracts.DecodeStrict[ObserverState](
			bytes.NewReader(raw),
			65_536,
		)
		return state, false, err
	case observerStateSchemaV5:
		legacy, err := contracts.DecodeStrict[observerStateV5](
			bytes.NewReader(raw),
			65_536,
		)
		if err != nil {
			return ObserverState{}, false, err
		}
		if err := legacy.Validate(); err != nil {
			return ObserverState{}, false, err
		}
		return observerStateFromV5(legacy), true, nil
	case observerStateSchemaV4:
		legacy, err := contracts.DecodeStrict[observerStateV4](
			bytes.NewReader(raw),
			65_536,
		)
		if err != nil {
			return ObserverState{}, false, err
		}
		if err := legacy.Validate(); err != nil {
			return ObserverState{}, false, err
		}
		return observerStateFromV4(legacy), true, nil
	case observerStateSchemaV3:
		legacy, err := contracts.DecodeStrict[observerStateV3](
			bytes.NewReader(raw),
			65_536,
		)
		if err != nil {
			return ObserverState{}, false, err
		}
		if err := legacy.Validate(); err != nil {
			return ObserverState{}, false, err
		}
		return observerStateFromV3(legacy), true, nil
	case observerStateSchemaV2:
		legacy, err := contracts.DecodeStrict[observerStateV2](
			bytes.NewReader(raw),
			65_536,
		)
		if err != nil {
			return ObserverState{}, false, err
		}
		if err := legacy.Validate(); err != nil {
			return ObserverState{}, false, err
		}
		state := migrateObserverStateV2(legacy)
		if err := state.Validate(); err != nil {
			return ObserverState{}, false, err
		}
		return state, true, nil
	case observerStateSchemaV1:
		legacy, err := contracts.DecodeStrict[observerStateV1](
			bytes.NewReader(raw),
			65_536,
		)
		if err != nil {
			return ObserverState{}, false, err
		}
		if err := legacy.Validate(); err != nil {
			return ObserverState{}, false, err
		}
		state := migrateObserverStateV1(legacy)
		if err := state.Validate(); err != nil {
			return ObserverState{}, false, err
		}
		return state, true, nil
	default:
		return ObserverState{}, false, fmt.Errorf(
			"unsupported observer state schema version",
		)
	}
}

// V1-V3 state predates control receipts, so no receipt journal can be
// authenticated during migration. The normal bootstrap holds the state lock
// across this check and the subsequent V4 state write.
func requireLegacyControlReceiptJournalAbsent(statePath string) error {
	spoolRoot := filepath.Join(filepath.Dir(statePath), "spool")
	info, err := os.Lstat(spoolRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrControlReceiptCorrupt, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.Join(
			ErrControlReceiptCorrupt,
			durablefile.ErrUnsafePath,
		)
	}
	if err := durablefile.EnsurePrivateDirectory(spoolRoot); err != nil {
		return errors.Join(ErrControlReceiptCorrupt, err)
	}
	_, err = durablefile.ReadRegular(
		filepath.Join(spoolRoot, "control-receipts.agf"),
		1,
	)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrControlReceiptCorrupt, err)
	}
	return ErrControlReceiptCorrupt
}

func requireControlReceiptMigrationBoundary(
	statePath string,
	sourceSchema string,
) error {
	switch sourceSchema {
	case observerStateSchemaV1, observerStateSchemaV2, observerStateSchemaV3:
		return requireLegacyControlReceiptJournalAbsent(statePath)
	default:
		return nil
	}
}

func requireLegacyPCCJournalsAbsent(statePath string) error {
	spoolRoot := filepath.Join(filepath.Dir(statePath), "spool")
	info, err := os.Lstat(spoolRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrPCCJournalCorrupt, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.Join(
			ErrPCCJournalCorrupt,
			durablefile.ErrUnsafePath,
		)
	}
	if err := durablefile.EnsurePrivateDirectory(spoolRoot); err != nil {
		return errors.Join(ErrPCCJournalCorrupt, err)
	}
	for _, name := range []string{
		"pcc-boundaries.agf",
		"pcc-receipts.agf",
	} {
		_, err := os.Lstat(filepath.Join(spoolRoot, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return errors.Join(ErrPCCJournalCorrupt, err)
		}
		return ErrPCCJournalCorrupt
	}
	return nil
}

func requirePCCMigrationBoundary(
	statePath string,
	sourceSchema string,
) error {
	switch sourceSchema {
	case observerStateSchemaV1,
		observerStateSchemaV2,
		observerStateSchemaV3,
		observerStateSchemaV4:
		return requireLegacyPCCJournalsAbsent(statePath)
	default:
		return nil
	}
}

var (
	uuid4Pattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	hex32Pattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	eventPattern = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
)

func (state ObserverState) Validate() error {
	if state.SchemaVersion != observerStateSchema ||
		state.SequenceGapProtocol != sequenceGapProtocolC8 &&
			state.SequenceGapProtocol !=
				sequenceGapProtocolLegacyUnproven ||
		!uuid4Pattern.MatchString(state.HostID) ||
		!uuid4Pattern.MatchString(state.BootID) ||
		!hex32Pattern.MatchString(state.KeyID) ||
		state.KeyEpoch == 0 {
		return fmt.Errorf("invalid observer state identity")
	}
	if state.SequenceGapProtocol == sequenceGapProtocolLegacyUnproven &&
		(state.LastCoveredGapEnd == 0 ||
			!state.MutationReadOnly ||
			!state.ReconcileRequired) {
		return fmt.Errorf("legacy sequence-gap protocol state must remain fenced")
	}
	if state.MutationReadOnly && state.ReadOnlyReason == "" {
		return fmt.Errorf("read-only state requires a reason")
	}
	if !state.MutationReadOnly && state.ReadOnlyReason != "" {
		return fmt.Errorf("healthy state cannot retain read-only reason")
	}
	if state.BootBoundaryState != bootBoundaryCommitted &&
		!state.ReconcileRequired {
		return fmt.Errorf("non-committed boot boundary requires reconcile fence")
	}
	if state.AckSequence == 0 {
		if state.AckEventID != "" ||
			state.AckContentSHA256 != "" ||
			state.AckRecordHash != "" ||
			state.AckPayloadSHA256 != "" {
			return fmt.Errorf("empty ack anchor must have empty identity")
		}
	} else if !eventPattern.MatchString(state.AckEventID) ||
		!hex64Pattern.MatchString(state.AckContentSHA256) ||
		!hex64Pattern.MatchString(state.AckRecordHash) ||
		!hex64Pattern.MatchString(state.AckPayloadSHA256) {
		return fmt.Errorf("invalid ack anchor")
	}
	if state.LastCoveredGapEnd > state.LastSequence {
		return fmt.Errorf("covered gap exceeds reserved sequence")
	}
	if state.AckSequence > state.LastSequence {
		return fmt.Errorf("acknowledgement exceeds reserved sequence")
	}
	if state.AckRepairPending != (state.AckRepairReason != "") {
		return fmt.Errorf("ack repair state is inconsistent")
	}
	if !hex64Pattern.MatchString(state.PublicationBaseHash) ||
		!hex64Pattern.MatchString(state.PublicationHeadHash) ||
		state.PublicationBaseSequence > state.PublicationHeadSequence ||
		state.PublicationHeadSequence > state.LastSequence ||
		state.PublicationBaseSequence != state.AckSequence ||
		(state.PublicationBaseSequence == 0) !=
			(state.PublicationBaseHash == zeroPublicationHash) ||
		(state.PublicationHeadSequence == 0) !=
			(state.PublicationHeadHash == zeroPublicationHash) ||
		state.PublicationBaseSequence == state.PublicationHeadSequence &&
			state.PublicationBaseHash != state.PublicationHeadHash {
		return fmt.Errorf("invalid observer publication anchor")
	}
	if !hex64Pattern.MatchString(state.ControlReceiptHeadHash) ||
		state.ControlReceiptCount > controlReceiptMaxCount ||
		state.ControlReceiptBytes > controlReceiptMaxBytes ||
		(state.ControlReceiptCount == 0) !=
			(state.ControlReceiptBytes == 0) ||
		(state.ControlReceiptCount == 0) !=
			(state.ControlReceiptHeadHash == zeroControlReceiptHash) {
		return fmt.Errorf("invalid control receipt anchor")
	}
	if !validPCCJournalAnchor(
		state.PCCBoundaryCount,
		state.PCCBoundaryBytes,
		state.PCCBoundaryHeadHash,
		pccBoundaryArchiveMaxCount,
		pccBoundaryArchiveMaxBytes,
	) {
		return fmt.Errorf("invalid PCC boundary archive anchor")
	}
	if !validPCCJournalAnchor(
		state.PCCReceiptCount,
		state.PCCReceiptBytes,
		state.PCCReceiptHeadHash,
		pccReceiptMaxCount,
		pccReceiptMaxBytes,
	) {
		return fmt.Errorf("invalid PCC receipt anchor")
	}
	if pending := state.PendingDockerReconcile; pending != nil {
		// An unclosed Docker gap window and an open admission fence are the same
		// fact. Persisting one without the other would let the observer answer
		// identity questions while Core still holds the gap open.
		if !state.ReconcileRequired ||
			pending.Generation == 0 ||
			!canonicalUTCTimestamp(pending.OpenedAt) {
			return fmt.Errorf("invalid pending Docker reconcile window")
		}
	}
	if len(state.BootHistory) == 0 ||
		len(state.BootHistory) > 1_024 ||
		state.BootHistory[0].FirstSequence != 1 ||
		state.BootHistory[len(state.BootHistory)-1].BootID != state.BootID {
		return fmt.Errorf("invalid observer boot history")
	}
	{
		seen := make(map[string]struct{}, len(state.BootHistory))
		var priorFirst uint64
		for index, boundary := range state.BootHistory {
			if !uuid4Pattern.MatchString(boundary.BootID) ||
				index > 0 && boundary.FirstSequence <= priorFirst ||
				boundary.FirstSequence > state.LastSequence &&
					(state.LastSequence == math.MaxUint64 ||
						boundary.FirstSequence != state.LastSequence+1) {
				return fmt.Errorf("invalid observer boot history")
			}
			proofPresent := eventPattern.MatchString(boundary.BoundaryEventID) &&
				isBootBoundaryEventType(boundary.BoundaryEventType)
			proofAbsent := boundary.BoundaryEventID == "" &&
				boundary.BoundaryEventType == ""
			switch state.BootBoundaryState {
			case bootBoundaryCommitted:
				if !proofPresent {
					return fmt.Errorf("committed boot boundary lacks event identity")
				}
			case bootBoundaryPending:
				if index == len(state.BootHistory)-1 {
					if !proofAbsent {
						return fmt.Errorf("pending boot boundary already has event identity")
					}
				} else if !proofPresent {
					return fmt.Errorf("historical boot boundary lacks event identity")
				}
			case bootBoundaryLegacyUnproven:
				if !proofAbsent {
					return fmt.Errorf("legacy boot history cannot claim event identity")
				}
			default:
				return fmt.Errorf("invalid observer boot boundary state")
			}
			if _, exists := seen[boundary.BootID]; exists {
				return fmt.Errorf("duplicate observer boot history")
			}
			seen[boundary.BootID] = struct{}{}
			priorFirst = boundary.FirstSequence
		}
	}
	switch state.BootBoundaryState {
	case bootBoundaryPending:
		if state.PendingBootBoundary == nil {
			return fmt.Errorf("pending boot boundary details are required")
		}
		pending := state.PendingBootBoundary
		switch pending.ReasonCode {
		case "observer_genesis":
			if len(state.BootHistory) != 1 ||
				pending.PreviousBootID != nil ||
				pending.PreviousSourceSequence != 0 {
				return fmt.Errorf("invalid pending genesis boundary")
			}
		case "kernel_boot_id_changed":
			if len(state.BootHistory) < 2 ||
				pending.PreviousBootID == nil ||
				*pending.PreviousBootID !=
					state.BootHistory[len(state.BootHistory)-2].BootID ||
				pending.PreviousSourceSequence == 0 ||
				pending.PreviousSourceSequence == math.MaxUint64 ||
				state.BootHistory[len(state.BootHistory)-1].FirstSequence !=
					pending.PreviousSourceSequence+1 {
				return fmt.Errorf("invalid pending changed-boot boundary")
			}
		default:
			return fmt.Errorf("invalid pending boot boundary reason")
		}
	case bootBoundaryCommitted:
		if state.PendingBootBoundary != nil {
			return fmt.Errorf("committed boot boundary cannot remain pending")
		}
	case bootBoundaryLegacyUnproven:
		if state.PendingBootBoundary != nil ||
			!state.MutationReadOnly {
			return fmt.Errorf("unproven legacy state must remain fenced")
		}
	default:
		return fmt.Errorf("invalid observer boot boundary state")
	}
	return nil
}

func validPCCJournalAnchor(
	count uint64,
	bytes uint64,
	headHash string,
	maxCount uint64,
	maxBytes uint64,
) bool {
	return hex64Pattern.MatchString(headHash) &&
		count <= maxCount &&
		bytes <= maxBytes &&
		(count == 0) == (bytes == 0) &&
		(count == 0) == (headHash == zeroPCCJournalHash)
}

func isBootBoundaryEventType(eventType string) bool {
	switch eventType {
	case "observer_boot_boundary",
		"observer_key_transition",
		"observer_key_epoch_start":
		return true
	default:
		return false
	}
}

type StateIdentity struct {
	HostID   string
	BootID   string
	KeyID    string
	KeyEpoch uint64
}

type StateStore struct {
	mutex            sync.Mutex
	publicationMutex sync.Mutex
	path             string
	state            ObserverState
	persist          func(string, ObserverState) error
}

func cloneObserverState(state ObserverState) ObserverState {
	cloned := state
	cloned.BootHistory = append(
		[]BootBoundary(nil),
		state.BootHistory...,
	)
	if state.PendingBootBoundary != nil {
		pending := *state.PendingBootBoundary
		if pending.PreviousBootID != nil {
			previous := *pending.PreviousBootID
			pending.PreviousBootID = &previous
		}
		cloned.PendingBootBoundary = &pending
	}
	if state.PendingDockerReconcile != nil {
		window := *state.PendingDockerReconcile
		cloned.PendingDockerReconcile = &window
	}
	return cloned
}

func persistState(path string, state ObserverState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := contracts.CanonicalJSON(state)
	if err != nil {
		return err
	}
	if len(raw) > 65_536 {
		return fmt.Errorf("observer state exceeds 64 KiB")
	}
	return durablefile.AtomicWrite(path, raw)
}

func OpenStateStore(path string, identity StateIdentity) (*StateStore, error) {
	if err := durablefile.EnsurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	initial := ObserverState{
		SchemaVersion:          observerStateSchema,
		SequenceGapProtocol:    sequenceGapProtocolC8,
		HostID:                 identity.HostID,
		BootID:                 identity.BootID,
		KeyID:                  identity.KeyID,
		KeyEpoch:               identity.KeyEpoch,
		ReconcileRequired:      true,
		PublicationBaseHash:    zeroPublicationHash,
		PublicationHeadHash:    zeroPublicationHash,
		ControlReceiptHeadHash: zeroControlReceiptHash,
		PCCBoundaryHeadHash:    zeroPCCJournalHash,
		PCCReceiptHeadHash:     zeroPCCJournalHash,
		BootHistory: []BootBoundary{{
			BootID:        identity.BootID,
			FirstSequence: 1,
		}},
		BootBoundaryState: bootBoundaryPending,
		PendingBootBoundary: &PendingBootBoundary{
			ReasonCode: "observer_genesis",
		},
	}
	raw, err := readSingleLinkRegular(path, 65_536)
	if errors.Is(err, os.ErrNotExist) {
		if err := persistState(path, initial); err != nil {
			return nil, err
		}
		return &StateStore{
			path:    path,
			state:   cloneObserverState(initial),
			persist: persistState,
		}, nil
	}
	if err != nil {
		return nil, err
	}
	sourceSchema, err := observerStateSchemaVersion(raw)
	if err != nil {
		return nil, err
	}
	state, migrated, err := decodeObserverState(raw)
	if err != nil {
		return nil, err
	}
	if state.HostID != identity.HostID ||
		state.KeyID != identity.KeyID ||
		state.KeyEpoch != identity.KeyEpoch {
		return nil, fmt.Errorf("observer state identity mismatch")
	}
	if err := requireControlReceiptMigrationBoundary(
		path,
		sourceSchema,
	); err != nil {
		return nil, err
	}
	if err := requirePCCMigrationBoundary(path, sourceSchema); err != nil {
		return nil, err
	}
	needsPersist := migrated
	if state.BootBoundaryState == bootBoundaryLegacyUnproven {
		if needsPersist {
			if err := persistState(path, state); err != nil {
				return nil, err
			}
		}
		return &StateStore{
			path:    path,
			state:   cloneObserverState(state),
			persist: persistState,
		}, nil
	}
	if state.BootID != identity.BootID {
		for _, boundary := range state.BootHistory {
			if boundary.BootID == identity.BootID {
				state.MutationReadOnly = true
				state.ReadOnlyReason = "observer_boot_id_rollback"
				state.ReconcileRequired = true
				_ = persistState(path, state)
				return nil, fmt.Errorf("observer boot ID rollback")
			}
		}
		if state.LastSequence == math.MaxUint64 {
			state.MutationReadOnly = true
			state.ReadOnlyReason = "observer_sequence_exhausted"
			state.ReconcileRequired = true
			_ = persistState(path, state)
			return nil, fmt.Errorf("observer sequence exhausted")
		}
		lastIndex := len(state.BootHistory) - 1
		if state.BootBoundaryState == bootBoundaryPending {
			if state.PublicationHeadSequence >=
				state.BootHistory[lastIndex].FirstSequence {
				state.MutationReadOnly = true
				state.ReadOnlyReason =
					"observer_pending_boot_boundary_recovery_unproven"
				state.ReconcileRequired = true
				_ = persistState(path, state)
				return nil, ErrBootBoundaryRecoveryUnproven
			}
			state.BootID = identity.BootID
			state.BootHistory[lastIndex].BootID = identity.BootID
		} else {
			previousBootID := state.BootID
			if len(state.BootHistory) >= 1_024 {
				state.MutationReadOnly = true
				state.ReadOnlyReason = "observer_boot_history_exhausted"
				state.ReconcileRequired = true
				_ = persistState(path, state)
				return nil, fmt.Errorf("observer boot history exhausted")
			}
			state.BootID = identity.BootID
			state.BootHistory = append(state.BootHistory, BootBoundary{
				BootID:        identity.BootID,
				FirstSequence: state.LastSequence + 1,
			})
			state.BootBoundaryState = bootBoundaryPending
			state.PendingBootBoundary = &PendingBootBoundary{
				ReasonCode:             "kernel_boot_id_changed",
				PreviousBootID:         &previousBootID,
				PreviousSourceSequence: state.LastSequence,
			}
		}
		state.ReconcileRequired = true
		needsPersist = true
	}
	if needsPersist {
		if err := persistState(path, state); err != nil {
			return nil, err
		}
	}
	return &StateStore{
		path:    path,
		state:   cloneObserverState(state),
		persist: persistState,
	}, nil
}

func recoverPendingBootBoundaryBeforeBootChange(
	path string,
	identity StateIdentity,
	config SpoolConfig,
	keys *Keyring,
) error {
	persisted, err := loadObserverState(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if persisted.BootID == identity.BootID ||
		persisted.BootBoundaryState != bootBoundaryPending {
		return nil
	}
	if persisted.HostID != identity.HostID ||
		persisted.KeyID != identity.KeyID ||
		persisted.KeyEpoch != identity.KeyEpoch ||
		len(persisted.BootHistory) == 0 {
		return fmt.Errorf("observer state identity mismatch")
	}
	firstSequence := persisted.BootHistory[len(persisted.BootHistory)-1].FirstSequence
	if persisted.PublicationHeadSequence < firstSequence {
		return nil
	}
	previous, err := OpenStateStore(path, StateIdentity{
		HostID:   persisted.HostID,
		BootID:   persisted.BootID,
		KeyID:    persisted.KeyID,
		KeyEpoch: persisted.KeyEpoch,
	})
	if err != nil {
		return err
	}
	spool, err := NewSpool(config, previous, keys)
	if err != nil {
		return err
	}
	if closeErr := spool.Close(); closeErr != nil {
		return closeErr
	}
	recovered := previous.Snapshot()
	if recovered.BootBoundaryState != bootBoundaryCommitted ||
		recovered.PendingBootBoundary != nil {
		return ErrBootBoundaryRecoveryUnproven
	}
	return nil
}

func (store *StateStore) Snapshot() ObserverState {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return cloneObserverState(store.state)
}

func (store *StateStore) replaceLocked(next ObserverState) error {
	next = cloneObserverState(next)
	if err := store.persistLocked(next); err != nil {
		if errors.Is(err, durablefile.ErrCommitUncertain) {
			// The rename may already have made next authoritative on disk.
			// Adopt the reserved state and fence further reservations so the
			// live process can never reuse a possibly committed sequence.
			next.MutationReadOnly = true
			if next.ReadOnlyReason == "" {
				next.ReadOnlyReason = "observer_state_commit_uncertain"
			}
			next.ReconcileRequired = true
			store.state = cloneObserverState(next)
			fenceErr := store.persistLocked(next)
			return errors.Join(err, fenceErr)
		}
		return err
	}
	store.state = cloneObserverState(next)
	return nil
}

func (store *StateStore) persistLocked(next ObserverState) error {
	persist := store.persist
	if persist == nil {
		persist = persistState
	}
	return persist(store.path, cloneObserverState(next))
}

func (store *StateStore) PersistReadOnly(reason string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	next := cloneObserverState(store.state)
	next.MutationReadOnly = true
	next.ReadOnlyReason = reason
	next.ReconcileRequired = true
	// Fail closed in the live process before attempting persistence. A disk
	// failure is returned but can never leave readiness true in memory.
	store.state = cloneObserverState(next)
	return store.persistLocked(next)
}

func (store *StateStore) persistRotationIncomplete() error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.MutationReadOnly {
		if store.state.ReadOnlyReason == "observer_rotation_incomplete" {
			return nil
		}
		return fmt.Errorf(
			"refusing to replace unrelated mutation read-only reason: %s",
			store.state.ReadOnlyReason,
		)
	}
	next := cloneObserverState(store.state)
	next.MutationReadOnly = true
	next.ReadOnlyReason = "observer_rotation_incomplete"
	next.ReconcileRequired = true
	store.state = cloneObserverState(next)
	return store.persistLocked(next)
}

func (store *StateStore) reserve(identity StateIdentity) (uint64, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.MutationReadOnly ||
		store.state.SequenceGapProtocol != sequenceGapProtocolC8 {
		return 0, fmt.Errorf("observer state is mutation read-only")
	}
	if store.state.HostID != identity.HostID ||
		store.state.BootID != identity.BootID ||
		store.state.KeyID != identity.KeyID ||
		store.state.KeyEpoch != identity.KeyEpoch {
		return 0, fmt.Errorf("observer signing identity mismatch")
	}
	if store.state.LastSequence == math.MaxUint64 {
		next := cloneObserverState(store.state)
		next.MutationReadOnly = true
		next.ReadOnlyReason = "observer_sequence_exhausted"
		next.ReconcileRequired = true
		store.state = cloneObserverState(next)
		persistErr := store.persistLocked(next)
		return 0, errors.Join(fmt.Errorf("observer sequence exhausted"), persistErr)
	}
	next := cloneObserverState(store.state)
	next.BootID = identity.BootID
	next.LastSequence++
	if err := store.replaceLocked(next); err != nil {
		return 0, err
	}
	return next.LastSequence, nil
}

func (store *StateStore) reserveExpected(
	identity StateIdentity,
	expected uint64,
) (uint64, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if expected == 0 ||
		store.state.MutationReadOnly ||
		store.state.SequenceGapProtocol != sequenceGapProtocolC8 {
		return 0, fmt.Errorf("observer state is mutation read-only")
	}
	if store.state.HostID != identity.HostID ||
		store.state.BootID != identity.BootID ||
		store.state.KeyID != identity.KeyID ||
		store.state.KeyEpoch != identity.KeyEpoch {
		return 0, fmt.Errorf("observer signing identity mismatch")
	}
	if store.state.LastSequence == math.MaxUint64 {
		next := cloneObserverState(store.state)
		next.MutationReadOnly = true
		next.ReadOnlyReason = "observer_sequence_exhausted"
		next.ReconcileRequired = true
		store.state = cloneObserverState(next)
		persistErr := store.persistLocked(next)
		return 0, errors.Join(
			fmt.Errorf("observer sequence exhausted"),
			persistErr,
		)
	}
	if expected != store.state.LastSequence+1 {
		return 0, fmt.Errorf("observer expected sequence changed")
	}
	next := cloneObserverState(store.state)
	next.LastSequence = expected
	if err := store.replaceLocked(next); err != nil {
		return 0, err
	}
	return expected, nil
}

func (store *StateStore) commitPendingBootBoundary(
	event contracts.EventEnvelopeV1,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.BootBoundaryState != bootBoundaryPending ||
		store.state.PendingBootBoundary == nil ||
		store.state.MutationReadOnly ||
		store.state.SequenceGapProtocol != sequenceGapProtocolC8 ||
		len(store.state.BootHistory) == 0 ||
		event.SourceSequence > store.state.LastSequence ||
		event.SourceSequence <
			store.state.BootHistory[len(store.state.BootHistory)-1].FirstSequence ||
		!dedicatedBootBoundaryMatchesState(event, store.state) {
		return fmt.Errorf("invalid pending boot boundary commit")
	}
	next := cloneObserverState(store.state)
	last := len(next.BootHistory) - 1
	next.BootHistory[last].BoundaryEventID = event.EventID
	next.BootHistory[last].BoundaryEventType = event.EventType
	next.BootBoundaryState = bootBoundaryCommitted
	next.PendingBootBoundary = nil
	return store.replaceLocked(next)
}

func (store *StateStore) reserveRotationEpochStart(
	authorization rotationPublicationAuthorization,
	identity StateIdentity,
) (uint64, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	marker := authorization.marker
	if authorization.role != rotationEpochStartPublication ||
		store.state.MutationReadOnly ||
		store.state.SequenceGapProtocol != sequenceGapProtocolC8 ||
		store.state.HostID != identity.HostID ||
		store.state.BootID != identity.BootID ||
		store.state.KeyID != marker.Transition.OldKeyID ||
		store.state.KeyEpoch != marker.Transition.OldEpoch ||
		identity.KeyID != marker.Transition.NewKeyID ||
		identity.KeyEpoch != marker.Transition.NewEpoch ||
		store.state.LastSequence != marker.TransitionSequence ||
		marker.StartSequence != marker.TransitionSequence+1 ||
		rotationModeForState(store.state, authorization) ==
			rotationBoundaryInvalid {
		return 0, ErrRotationPublicationMismatch
	}
	next := cloneObserverState(store.state)
	next.LastSequence = marker.StartSequence
	if err := store.replaceLocked(next); err != nil {
		return 0, err
	}
	return marker.StartSequence, nil
}

func (store *StateStore) commitRotationPublication(
	event contracts.EventEnvelopeV1,
	authorization rotationPublicationAuthorization,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	mode := rotationModeForState(store.state, authorization)
	if store.state.MutationReadOnly ||
		store.state.SequenceGapProtocol != sequenceGapProtocolC8 ||
		mode == rotationBoundaryInvalid ||
		event.SourceSequence > store.state.LastSequence ||
		!rotationEnvelopeMatches(
			event,
			store.state,
			authorization,
			mode,
		) {
		return ErrRotationPublicationMismatch
	}
	next := cloneObserverState(store.state)
	switch authorization.role {
	case rotationTransitionPublication:
		if mode != rotationBoundaryB {
			return ErrRotationPublicationMismatch
		}
		last := len(next.BootHistory) - 1
		next.BootHistory[last].BoundaryEventID = event.EventID
		next.BootHistory[last].BoundaryEventType = event.EventType
		next.BootBoundaryState = bootBoundaryCommitted
		next.PendingBootBoundary = nil
	case rotationEpochStartPublication:
		next.KeyID = authorization.marker.Transition.NewKeyID
		next.KeyEpoch = authorization.marker.Transition.NewEpoch
		next.ReconcileRequired = true
		if mode == rotationBoundaryC {
			last := len(next.BootHistory) - 1
			next.BootHistory[last].BoundaryEventID = event.EventID
			next.BootHistory[last].BoundaryEventType = event.EventType
			next.BootBoundaryState = bootBoundaryCommitted
			next.PendingBootBoundary = nil
		}
	default:
		return ErrRotationPublicationMismatch
	}
	return store.replaceLocked(next)
}

func (store *StateStore) applyAck(
	sequence uint64,
	eventID string,
	contentSHA256 string,
	recordHash string,
	payloadSHA256 string,
	publicationSequence uint64,
	publicationHash string,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	next := cloneObserverState(store.state)
	next.AckSequence = sequence
	next.AckEventID = eventID
	next.AckContentSHA256 = contentSHA256
	next.AckRecordHash = recordHash
	next.AckPayloadSHA256 = payloadSHA256
	if publicationSequence != sequence ||
		!hex64Pattern.MatchString(publicationHash) ||
		publicationSequence < next.PublicationBaseSequence ||
		publicationSequence > next.PublicationHeadSequence {
		return fmt.Errorf("invalid publication acknowledgement anchor")
	}
	next.PublicationBaseSequence = publicationSequence
	next.PublicationBaseHash = publicationHash
	// A synced journal record is authoritative even if the redundant
	// state-file anchor cannot be rewritten. Keep the live state forward so a
	// retry cannot append the same sequence twice.
	store.state = cloneObserverState(next)
	return store.persistLocked(next)
}

func (store *StateStore) anchorPublication(
	expectedPreviousHash string,
	sequence uint64,
	publicationHash string,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.MutationReadOnly ||
		store.state.SequenceGapProtocol != sequenceGapProtocolC8 ||
		store.state.PublicationHeadHash != expectedPreviousHash ||
		sequence <= store.state.PublicationHeadSequence ||
		sequence > store.state.LastSequence ||
		!hex64Pattern.MatchString(publicationHash) ||
		publicationHash == zeroPublicationHash {
		return fmt.Errorf("invalid publication head transition")
	}
	next := cloneObserverState(store.state)
	next.PublicationHeadSequence = sequence
	next.PublicationHeadHash = publicationHash
	return store.replaceLocked(next)
}

func (store *StateStore) recoverPublicationHead(
	expectedPreviousHash string,
	sequence uint64,
	publicationHash string,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.PublicationHeadHash != expectedPreviousHash ||
		sequence <= store.state.PublicationHeadSequence ||
		sequence != store.state.LastSequence ||
		!hex64Pattern.MatchString(publicationHash) ||
		publicationHash == zeroPublicationHash {
		return fmt.Errorf("invalid publication recovery transition")
	}
	next := cloneObserverState(store.state)
	next.PublicationHeadSequence = sequence
	next.PublicationHeadHash = publicationHash
	// Startup recovery may make the immutable publication anchor more exact,
	// but it must never clear or replace an existing mutation fence.
	return store.replaceLocked(next)
}

func (store *StateStore) anchorControlReceipt(
	expectedCount uint64,
	expectedBytes uint64,
	expectedHeadHash string,
	count uint64,
	bytes uint64,
	headHash string,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.MutationReadOnly ||
		store.state.ControlReceiptCount != expectedCount ||
		store.state.ControlReceiptBytes != expectedBytes ||
		store.state.ControlReceiptHeadHash != expectedHeadHash ||
		expectedCount >= controlReceiptMaxCount ||
		count != expectedCount+1 ||
		bytes <= expectedBytes ||
		count > controlReceiptMaxCount ||
		bytes > controlReceiptMaxBytes ||
		!hex64Pattern.MatchString(headHash) ||
		headHash == zeroControlReceiptHash {
		return fmt.Errorf("invalid control receipt head transition")
	}
	next := cloneObserverState(store.state)
	next.ControlReceiptCount = count
	next.ControlReceiptBytes = bytes
	next.ControlReceiptHeadHash = headHash
	return store.replaceLocked(next)
}

func (store *StateStore) recoverControlReceipt(
	expectedCount uint64,
	expectedBytes uint64,
	expectedHeadHash string,
	count uint64,
	bytes uint64,
	headHash string,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.ControlReceiptCount != expectedCount ||
		store.state.ControlReceiptBytes != expectedBytes ||
		store.state.ControlReceiptHeadHash != expectedHeadHash ||
		expectedCount >= controlReceiptMaxCount ||
		count != expectedCount+1 ||
		bytes <= expectedBytes ||
		count > controlReceiptMaxCount ||
		bytes > controlReceiptMaxBytes ||
		!hex64Pattern.MatchString(headHash) ||
		headHash == zeroControlReceiptHash {
		return fmt.Errorf("invalid control receipt recovery transition")
	}
	next := cloneObserverState(store.state)
	next.ControlReceiptCount = count
	next.ControlReceiptBytes = bytes
	next.ControlReceiptHeadHash = headHash
	// Recovery can make the redundant state anchor exact, but it never clears
	// an existing mutation fence.
	return store.replaceLocked(next)
}

func (store *StateStore) anchorPCCBoundary(
	expected PCCBoundaryArchiveAnchor,
	nextAnchor PCCBoundaryArchiveAnchor,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.MutationReadOnly ||
		store.state.PCCBoundaryCount != expected.Count ||
		store.state.PCCBoundaryBytes != expected.Bytes ||
		store.state.PCCBoundaryHeadHash != expected.HeadHash ||
		expected.Count >= pccBoundaryArchiveMaxCount ||
		nextAnchor.Count != expected.Count+1 ||
		nextAnchor.Bytes <= expected.Bytes ||
		nextAnchor.Count > pccBoundaryArchiveMaxCount ||
		nextAnchor.Bytes > pccBoundaryArchiveMaxBytes ||
		!hex64Pattern.MatchString(nextAnchor.HeadHash) ||
		nextAnchor.HeadHash == zeroPCCJournalHash {
		return fmt.Errorf("invalid PCC boundary archive head transition")
	}
	next := cloneObserverState(store.state)
	next.PCCBoundaryCount = nextAnchor.Count
	next.PCCBoundaryBytes = nextAnchor.Bytes
	next.PCCBoundaryHeadHash = nextAnchor.HeadHash
	return store.replaceLocked(next)
}

func (store *StateStore) anchorPCCReceipt(
	expected PCCReceiptAnchor,
	nextAnchor PCCReceiptAnchor,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.MutationReadOnly ||
		store.state.PCCReceiptCount != expected.Count ||
		store.state.PCCReceiptBytes != expected.Bytes ||
		store.state.PCCReceiptHeadHash != expected.HeadHash ||
		expected.Count >= pccReceiptMaxCount ||
		nextAnchor.Count != expected.Count+1 ||
		nextAnchor.Bytes <= expected.Bytes ||
		nextAnchor.Count > pccReceiptMaxCount ||
		nextAnchor.Bytes > pccReceiptMaxBytes ||
		!hex64Pattern.MatchString(nextAnchor.HeadHash) ||
		nextAnchor.HeadHash == zeroPCCJournalHash {
		return fmt.Errorf("invalid PCC receipt head transition")
	}
	next := cloneObserverState(store.state)
	next.PCCReceiptCount = nextAnchor.Count
	next.PCCReceiptBytes = nextAnchor.Bytes
	next.PCCReceiptHeadHash = nextAnchor.HeadHash
	return store.replaceLocked(next)
}

func (store *StateStore) switchKey(newKeyID string, newEpoch uint64) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if !hex32Pattern.MatchString(newKeyID) ||
		store.state.KeyEpoch == math.MaxUint64 ||
		newEpoch != store.state.KeyEpoch+1 {
		return fmt.Errorf("key epochs must be consecutive")
	}
	next := cloneObserverState(store.state)
	next.KeyID = newKeyID
	next.KeyEpoch = newEpoch
	next.ReconcileRequired = true
	return store.replaceLocked(next)
}

func (store *StateStore) incrementRoutineDrop() (bool, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.RoutineDropped == math.MaxUint64 {
		return false, fmt.Errorf("routine drop counter exhausted")
	}
	next := cloneObserverState(store.state)
	next.RoutineDropped++
	emit := !next.DropEventPending
	next.DropEventPending = true
	return emit, store.replaceLocked(next)
}

func (store *StateStore) markGapCovered(sequence uint64) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.MutationReadOnly ||
		store.state.SequenceGapProtocol != sequenceGapProtocolC8 ||
		sequence > store.state.LastSequence ||
		sequence < store.state.LastCoveredGapEnd {
		return fmt.Errorf("invalid covered gap sequence")
	}
	next := cloneObserverState(store.state)
	next.LastCoveredGapEnd = sequence
	return store.replaceLocked(next)
}

func (store *StateStore) markAckRepair(reason string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	next := cloneObserverState(store.state)
	next.AckRepairPending = true
	next.AckRepairReason = reason
	next.ReconcileRequired = true
	return store.replaceLocked(next)
}

func (store *StateStore) requireDockerReconcile() error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.ReconcileRequired {
		return nil
	}
	next := cloneObserverState(store.state)
	next.ReconcileRequired = true
	// Readiness is a live-process safety fence first and a durability record
	// second. A pre-rename persistence failure must never leave candidate
	// admission open until the next monitor retry.
	store.state = cloneObserverState(next)
	return store.persistLocked(next)
}

// beginDockerReconcile takes ownership of the one Docker gap window. It is
// called only after the CRITICAL open has been signed, because a durable window
// with no open frame behind it would make the next attempt sign a close that
// Core cannot pair with any open — a hard CoverageConflict — whereas the
// reverse residue is only an unpaired open.
func (store *StateStore) beginDockerReconcile(
	window PendingDockerReconcile,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.PendingDockerReconcile != nil {
		return fmt.Errorf("Docker reconcile window is already open")
	}
	next := cloneObserverState(store.state)
	next.PendingDockerReconcile = &window
	return store.replaceLocked(next)
}

// clearDockerReconcileWindow releases ownership of the window WITHOUT lifting
// the reconcile fence. It runs immediately before the close is signed: if the
// signature then fails the window is merely unpaired (Core latches and the next
// reconcile recovers), while releasing it after the signature would let a retry
// sign a second close for an open that is already matched.
func (store *StateStore) clearDockerReconcileWindow() error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.PendingDockerReconcile == nil {
		return nil
	}
	next := cloneObserverState(store.state)
	next.PendingDockerReconcile = nil
	return store.replaceLocked(next)
}

func (store *StateStore) completeDockerReconcile() error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.PendingDockerReconcile != nil {
		return fmt.Errorf("Docker reconcile window remains unclosed")
	}
	next := cloneObserverState(store.state)
	next.ReconcileRequired = next.MutationReadOnly ||
		next.AckRepairPending ||
		next.DropEventPending ||
		next.BootBoundaryState != bootBoundaryCommitted
	if next.ReconcileRequired == store.state.ReconcileRequired {
		return nil
	}
	return store.replaceLocked(next)
}

func (store *StateStore) clearRotationFence() error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if !store.state.MutationReadOnly {
		return nil
	}
	if store.state.ReadOnlyReason != "observer_rotation_incomplete" {
		return fmt.Errorf("observer remains mutation read-only")
	}
	next := cloneObserverState(store.state)
	next.MutationReadOnly = false
	next.ReadOnlyReason = ""
	next.ReconcileRequired = true
	return store.replaceLocked(next)
}

type keyEntry struct {
	epoch uint64
	key   ed25519.PublicKey
}

type epochBoundary struct {
	epoch      uint64
	keyID      string
	transition contracts.EventEnvelopeV1
	start      contracts.EventEnvelopeV1
}

type Keyring struct {
	mutex         sync.RWMutex
	keys          map[string]keyEntry
	hostID        string
	boundaries    map[uint64]epochBoundary
	metadataEpoch uint64
}

func NewKeyring() *Keyring {
	return &Keyring{
		keys:       make(map[string]keyEntry),
		boundaries: make(map[uint64]epochBoundary),
	}
}

func (keyring *Keyring) Add(epoch uint64, publicKey ed25519.PublicKey) error {
	if epoch == 0 || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid observer public key")
	}
	keyID, err := contracts.KeyID(publicKey)
	if err != nil {
		return err
	}
	keyring.mutex.Lock()
	defer keyring.mutex.Unlock()
	if existing, ok := keyring.keys[keyID]; ok &&
		(existing.epoch != epoch || !bytes.Equal(existing.key, publicKey)) {
		return fmt.Errorf("conflicting observer public key")
	}
	keyring.keys[keyID] = keyEntry{
		epoch: epoch,
		key:   append(ed25519.PublicKey(nil), publicKey...),
	}
	return nil
}

func (keyring *Keyring) Verify(event contracts.EventEnvelopeV1) error {
	keyring.mutex.RLock()
	entry, ok := keyring.keys[event.KeyID]
	keyring.mutex.RUnlock()
	if !ok || entry.epoch != event.KeyEpoch {
		return fmt.Errorf("untrusted observer key epoch")
	}
	return contracts.VerifyEventSignature(event, entry.key)
}

type SignerConfig struct {
	HostID        string
	BootID        string
	KeyEpoch      uint64
	SourceID      string
	SourceVersion string
	Now           func() time.Time
}

type EventMetadata struct {
	EventTime           time.Time
	ClockUncertaintyMS  uint64
	ContainerID         *string
	ContainerStartTime  *string
	ReleaseID           *string
	InventoryGeneration uint64
	InventoryRevision   *uint64
	RedactionFlags      []string
	CoverageFlags       []string
	SourcePayloadHash   string
}

type bootBoundaryPublicationAuthorization uint8

const (
	noBootBoundaryPublication bootBoundaryPublicationAuthorization = iota
	observerBootBoundaryPublication
)

type rotationPublicationRole uint8

const (
	rotationTransitionPublication rotationPublicationRole = iota + 1
	rotationEpochStartPublication
)

type rotationPublicationAuthorization struct {
	marker            rotationMarker
	role              rotationPublicationRole
	transitionBinding *rotationTransitionBinding
}

type rotationTransitionBinding struct {
	event               contracts.EventEnvelopeV1
	contentSHA256       string
	frameIdentity       durablefile.FileIdentity
	publicationIdentity durablefile.FileIdentity
	publicationHash     string
}

func exactFlags(actual []string, expected ...string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func (authorization bootBoundaryPublicationAuthorization) permits(
	eventType string,
	metadata EventMetadata,
) bool {
	switch authorization {
	case observerBootBoundaryPublication:
		return eventType == "observer_boot_boundary" &&
			exactFlags(
				metadata.CoverageFlags,
				"boot_transition",
				"reconcile_required",
			)
	default:
		return false
	}
}

func decodeBootBoundaryFields(
	normalizedFields map[string]any,
) (contracts.ObserverBootBoundaryV1, []byte, error) {
	raw, err := contracts.CanonicalJSON(normalizedFields)
	if err != nil {
		return contracts.ObserverBootBoundaryV1{}, nil, err
	}
	boundary, err := contracts.DecodeStrict[contracts.ObserverBootBoundaryV1](
		bytes.NewReader(raw),
		65_536,
	)
	return boundary, raw, err
}

func pendingBoundaryMatches(
	boundary contracts.ObserverBootBoundaryV1,
	pending *PendingBootBoundary,
) bool {
	if pending == nil ||
		boundary.ReasonCode != pending.ReasonCode ||
		boundary.PreviousSourceSequence != pending.PreviousSourceSequence ||
		(boundary.PreviousBootID == nil) != (pending.PreviousBootID == nil) {
		return false
	}
	return boundary.PreviousBootID == nil ||
		*boundary.PreviousBootID == *pending.PreviousBootID
}

func dedicatedBoundaryMetadataMatches(
	metadata EventMetadata,
	normalizedCanonical []byte,
) bool {
	digest := sha256.Sum256(normalizedCanonical)
	return metadata.ContainerID == nil &&
		metadata.ContainerStartTime == nil &&
		metadata.ReleaseID == nil &&
		metadata.InventoryGeneration == 0 &&
		metadata.InventoryRevision == nil &&
		len(metadata.RedactionFlags) == 0 &&
		exactFlags(
			metadata.CoverageFlags,
			"boot_transition",
			"reconcile_required",
		) &&
		metadata.SourcePayloadHash == hex.EncodeToString(digest[:])
}

func dedicatedBootBoundaryMatchesState(
	event contracts.EventEnvelopeV1,
	state ObserverState,
) bool {
	if state.BootBoundaryState != bootBoundaryPending ||
		state.PendingBootBoundary == nil ||
		event.EventType != "observer_boot_boundary" ||
		event.SourceID != "agmind-observerd" ||
		event.SourceVersion != "0.1.0" ||
		event.HostID != state.HostID ||
		event.BootID != state.BootID ||
		event.KeyID != state.KeyID ||
		event.KeyEpoch != state.KeyEpoch ||
		event.ContainerID != nil ||
		event.ContainerStartTime != nil ||
		event.ReleaseID != nil ||
		event.InventoryGeneration != 0 ||
		event.InventoryRevision != nil ||
		len(event.RedactionFlags) != 0 ||
		!exactFlags(
			event.CoverageFlags,
			"boot_transition",
			"reconcile_required",
		) ||
		event.SourcePayloadHash != event.NormalizedFieldsSHA256 {
		return false
	}
	boundary, _, err := decodeBootBoundaryFields(event.NormalizedFields)
	return err == nil &&
		pendingBoundaryMatches(boundary, state.PendingBootBoundary)
}

type EnvelopeSigner struct {
	config     SignerConfig
	state      *StateStore
	spool      *Spool
	privateKey ed25519.PrivateKey
	keyID      string
}

func NewEnvelopeSigner(
	config SignerConfig,
	state *StateStore,
	spool *Spool,
	privateKey ed25519.PrivateKey,
) (*EnvelopeSigner, error) {
	if state == nil || spool == nil || config.Now == nil ||
		len(privateKey) != ed25519.PrivateKeySize {
		if state != nil {
			_ = state.PersistReadOnly("observer_private_key_unavailable")
		}
		return nil, fmt.Errorf("observer private key unavailable")
	}
	if !validPrivateKey(privateKey) {
		_ = state.PersistReadOnly("observer_private_key_invalid")
		return nil, fmt.Errorf("observer private key seed/public mismatch")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := contracts.KeyID(publicKey)
	if err != nil {
		_ = state.PersistReadOnly("observer_private_key_invalid")
		return nil, err
	}
	snapshot := state.Snapshot()
	if keyID != snapshot.KeyID ||
		config.KeyEpoch != snapshot.KeyEpoch ||
		config.HostID != snapshot.HostID ||
		config.BootID != snapshot.BootID {
		return nil, fmt.Errorf("observer signer identity does not match state")
	}
	return &EnvelopeSigner{
		config:     config,
		state:      state,
		spool:      spool,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		keyID:      keyID,
	}, nil
}

func cloneNormalized(fields map[string]any) (map[string]any, []byte, error) {
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var copied map[string]any
	if err := decoder.Decode(&copied); err != nil {
		return nil, nil, err
	}
	reencoded, err := contracts.CanonicalJSON(copied)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(canonical, reencoded) {
		return nil, nil, fmt.Errorf("normalized fields are not canonical")
	}
	return copied, canonical, nil
}

func priorityEventType(eventType string) bool {
	switch eventType {
	case "coverage",
		"observer_boot_boundary",
		"observer_start",
		"observer_key_transition",
		"observer_key_epoch_start",
		"pcc_correlation_snapshot",
		"evidence_repair_authorized",
		"evidence_repair_completed",
		"retention_tombstone",
		"retention_blocked_priority_evidence",
		"incident_action_mirror",
		"corruption":
		return true
	default:
		return false
	}
}

func (signer *EnvelopeSigner) Wrap(
	ctx context.Context,
	eventType string,
	normalizedFields map[string]any,
	metadata EventMetadata,
) (contracts.EventEnvelopeV1, error) {
	if coreControlEventType(eventType) {
		return contracts.EventEnvelopeV1{}, ErrCoreControlReceiptRequired
	}
	if eventType == "pcc_correlation_snapshot" {
		return contracts.EventEnvelopeV1{}, ErrPCCReceiptRequired
	}
	return signer.wrap(
		ctx,
		noBootBoundaryPublication,
		nil,
		eventType,
		normalizedFields,
		metadata,
		false,
	)
}

func (signer *EnvelopeSigner) wrapAuthorizedBootBoundary(
	ctx context.Context,
	authorization bootBoundaryPublicationAuthorization,
	eventType string,
	normalizedFields map[string]any,
	metadata EventMetadata,
) (contracts.EventEnvelopeV1, error) {
	return signer.wrap(
		ctx,
		authorization,
		nil,
		eventType,
		normalizedFields,
		metadata,
		false,
	)
}

func (signer *EnvelopeSigner) wrapAuthorizedRotation(
	ctx context.Context,
	marker rotationMarker,
	role rotationPublicationRole,
	eventType string,
	normalizedFields map[string]any,
	metadata EventMetadata,
) (contracts.EventEnvelopeV1, error) {
	authorization := rotationPublicationAuthorization{
		marker: marker,
		role:   role,
	}
	return signer.wrap(
		ctx,
		noBootBoundaryPublication,
		&authorization,
		eventType,
		normalizedFields,
		metadata,
		false,
	)
}

// wrapAuthorizedRotationLocked publishes while its caller retains the
// publication mutex across the complete transition/epoch-start pair.
func (signer *EnvelopeSigner) wrapAuthorizedRotationLocked(
	ctx context.Context,
	marker rotationMarker,
	role rotationPublicationRole,
	eventType string,
	normalizedFields map[string]any,
	metadata EventMetadata,
) (contracts.EventEnvelopeV1, error) {
	authorization := rotationPublicationAuthorization{
		marker: marker,
		role:   role,
	}
	return signer.wrap(
		ctx,
		noBootBoundaryPublication,
		&authorization,
		eventType,
		normalizedFields,
		metadata,
		true,
	)
}

func (signer *EnvelopeSigner) wrap(
	ctx context.Context,
	authorization bootBoundaryPublicationAuthorization,
	rotationAuthorization *rotationPublicationAuthorization,
	eventType string,
	normalizedFields map[string]any,
	metadata EventMetadata,
	publicationAlreadyLocked bool,
) (contracts.EventEnvelopeV1, error) {
	select {
	case <-ctx.Done():
		return contracts.EventEnvelopeV1{}, ctx.Err()
	default:
	}
	locked := !publicationAlreadyLocked
	if locked {
		signer.state.publicationMutex.Lock()
	}
	defer func() {
		if locked {
			signer.state.publicationMutex.Unlock()
		}
	}()
	select {
	case <-ctx.Done():
		return contracts.EventEnvelopeV1{}, ctx.Err()
	default:
	}
	snapshot := signer.state.Snapshot()
	if rotationAuthorization != nil &&
		rotationAuthorization.role == rotationEpochStartPublication {
		binding, err := signer.spool.bindRotationTransition(
			rotationAuthorization.marker,
		)
		if err != nil {
			return contracts.EventEnvelopeV1{}, err
		}
		rotationAuthorization.transitionBinding = &binding
	}
	boundaryPending := snapshot.BootBoundaryState == bootBoundaryPending
	rotationAuthorized := rotationAuthorization != nil &&
		rotationAuthorization.matchesRequest(
			snapshot,
			signer,
			eventType,
			normalizedFields,
			metadata,
		)
	if rotationAuthorization != nil && !rotationAuthorized {
		return contracts.EventEnvelopeV1{}, ErrRotationPublicationMismatch
	}
	if boundaryPending &&
		!authorization.permits(eventType, metadata) &&
		!rotationAuthorized {
		return contracts.EventEnvelopeV1{}, ErrBootBoundaryPending
	}
	if authorization != noBootBoundaryPublication &&
		rotationAuthorization != nil {
		return contracts.EventEnvelopeV1{}, fmt.Errorf(
			"conflicting observer publication authorization",
		)
	}
	if authorization != noBootBoundaryPublication && !boundaryPending {
		return contracts.EventEnvelopeV1{}, ErrBootBoundaryNotPending
	}
	if authorization != noBootBoundaryPublication &&
		!authorization.permits(eventType, metadata) {
		return contracts.EventEnvelopeV1{}, fmt.Errorf(
			"boot boundary authorization does not match publication",
		)
	}
	if authorization == observerBootBoundaryPublication {
		boundary, raw, err := decodeBootBoundaryFields(normalizedFields)
		if err != nil {
			return contracts.EventEnvelopeV1{}, err
		}
		if !pendingBoundaryMatches(
			boundary,
			snapshot.PendingBootBoundary,
		) || !dedicatedBoundaryMetadataMatches(metadata, raw) {
			return contracts.EventEnvelopeV1{}, ErrBootBoundaryPayloadMismatch
		}
	}
	var sequence uint64
	var err error
	if rotationAuthorization != nil &&
		rotationAuthorization.role == rotationEpochStartPublication {
		sequence, err = signer.state.reserveRotationEpochStart(
			*rotationAuthorization,
			StateIdentity{
				HostID:   signer.config.HostID,
				BootID:   signer.config.BootID,
				KeyID:    signer.keyID,
				KeyEpoch: signer.config.KeyEpoch,
			},
		)
	} else {
		sequence, err = signer.state.reserve(StateIdentity{
			HostID:   signer.config.HostID,
			BootID:   signer.config.BootID,
			KeyID:    signer.keyID,
			KeyEpoch: signer.config.KeyEpoch,
		})
	}
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	copied, normalizedCanonical, err := cloneNormalized(normalizedFields)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	copyString := func(value *string) *string {
		if value == nil {
			return nil
		}
		copiedValue := *value
		return &copiedValue
	}
	copyUint64 := func(value *uint64) *uint64 {
		if value == nil {
			return nil
		}
		copiedValue := *value
		return &copiedValue
	}
	normalizedDigest := sha256.Sum256(normalizedCanonical)
	event := contracts.EventEnvelopeV1{
		SchemaVersion:          "agmind.event-envelope.v1",
		EventType:              eventType,
		SourceID:               signer.config.SourceID,
		SourceVersion:          signer.config.SourceVersion,
		KeyID:                  signer.keyID,
		KeyEpoch:               signer.config.KeyEpoch,
		HostID:                 signer.config.HostID,
		BootID:                 signer.config.BootID,
		SourceSequence:         sequence,
		EventTime:              metadata.EventTime.UTC().Format(time.RFC3339Nano),
		IngestTime:             signer.config.Now().UTC().Format(time.RFC3339Nano),
		ClockUncertaintyMS:     metadata.ClockUncertaintyMS,
		ContainerID:            copyString(metadata.ContainerID),
		ContainerStartTime:     copyString(metadata.ContainerStartTime),
		ReleaseID:              copyString(metadata.ReleaseID),
		InventoryGeneration:    metadata.InventoryGeneration,
		InventoryRevision:      copyUint64(metadata.InventoryRevision),
		NormalizedFields:       copied,
		NormalizedFieldsSHA256: hex.EncodeToString(normalizedDigest[:]),
		RedactionFlags:         append([]string{}, metadata.RedactionFlags...),
		CoverageFlags:          append([]string{}, metadata.CoverageFlags...),
		SourcePayloadHash:      metadata.SourcePayloadHash,
	}
	event.EventID, err = contracts.DeriveEventID(event)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	message, err := contracts.EventSigningMessage(event)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	event.SourceSignature = hex.EncodeToString(ed25519.Sign(signer.privateKey, message))
	if err := event.Validate(); err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	tier := RoutineTier
	if priorityEventType(eventType) {
		tier = PriorityTier
	}
	var appendErr error
	if rotationAuthorization != nil &&
		rotationAuthorization.role == rotationEpochStartPublication {
		_, appendErr = signer.spool.appendRotationEpochStart(
			event,
			tier,
			*rotationAuthorization,
		)
	} else {
		_, appendErr = signer.spool.Append(event, tier)
	}
	if appendErr != nil {
		err := appendErr
		if errors.Is(err, ErrRoutineQuota) {
			if publicationAlreadyLocked {
				// The only lock-aware caller publishes priority rotation
				// records, so routine quota is unreachable without a caller
				// contract violation.
				return contracts.EventEnvelopeV1{}, err
			}
			emit, dropErr := signer.state.incrementRoutineDrop()
			locked = false
			signer.state.publicationMutex.Unlock()
			var emitErr error
			if dropErr == nil && emit {
				emitErr = signer.emitRoutineDropCoverage()
			}
			return contracts.EventEnvelopeV1{}, routineQuotaError(
				err,
				errors.Join(dropErr, emitErr),
			)
		}
		return contracts.EventEnvelopeV1{}, err
	}
	if signer.spool.boundaryArchive == nil {
		return contracts.EventEnvelopeV1{}, ErrPCCJournalCorrupt
	}
	if authorization == observerBootBoundaryPublication {
		if err := signer.spool.boundaryArchive.RecordCommittedBoundary(
			event,
			nil,
		); err != nil {
			return contracts.EventEnvelopeV1{}, err
		}
	}
	if rotationAuthorization != nil &&
		rotationAuthorization.role == rotationEpochStartPublication {
		switch rotationArchiveModeForState(snapshot, *rotationAuthorization) {
		case rotationBoundaryB:
			if err := signer.spool.boundaryArchive.RecordCommittedBoundary(
				rotationAuthorization.transitionBinding.event,
				&event,
			); err != nil {
				return contracts.EventEnvelopeV1{}, err
			}
		case rotationBoundaryC:
			if err := signer.spool.boundaryArchive.RecordCommittedBoundary(
				event,
				&rotationAuthorization.transitionBinding.event,
			); err != nil {
				return contracts.EventEnvelopeV1{}, err
			}
		}
	}
	if boundaryPending {
		var commitErr error
		if rotationAuthorization != nil {
			commitErr = signer.state.commitRotationPublication(
				event,
				*rotationAuthorization,
			)
		} else {
			commitErr = signer.state.commitPendingBootBoundary(event)
		}
		if commitErr != nil {
			return contracts.EventEnvelopeV1{}, commitErr
		}
	} else if rotationAuthorization != nil &&
		rotationAuthorization.role == rotationEpochStartPublication {
		if err := signer.state.commitRotationPublication(
			event,
			*rotationAuthorization,
		); err != nil {
			return contracts.EventEnvelopeV1{}, err
		}
	}
	return event, nil
}

var (
	ErrRootRequired           = errors.New("root privileges required")
	ErrStateLocked            = errors.New("observer state is locked")
	ErrInjectedRotationStop   = errors.New("injected rotation stop")
	ErrPCCJournalCorrupt      = errors.New("PCC journal corrupt")
	ErrBootBoundaryPending    = errors.New("observer boot boundary publication pending")
	ErrBootBoundaryNotPending = errors.New(
		"observer boot boundary publication is not pending",
	)
	ErrBootBoundaryRecoveryUnproven = errors.New(
		"observer pending boot boundary recovery is unproven",
	)
	ErrBootBoundaryPayloadMismatch = errors.New(
		"observer boot boundary does not match pending state",
	)
	ErrRotationPublicationMismatch = errors.New(
		"observer rotation publication does not match durable marker",
	)
)

type StateLock struct {
	journal *durablefile.Journal
}

func AcquireStateLock(stateDir string) (*StateLock, error) {
	if err := durablefile.EnsurePrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	journal, err := durablefile.NewJournal(
		filepath.Join(stateDir, ".observer.lock"),
		durablefile.WithMaxFrame(1),
	)
	if errors.Is(err, durablefile.ErrJournalLocked) {
		return nil, ErrStateLocked
	}
	if err != nil {
		return nil, err
	}
	return &StateLock{journal: journal}, nil
}

func (lock *StateLock) Close() error {
	if lock == nil || lock.journal == nil {
		return nil
	}
	err := lock.journal.Close()
	lock.journal = nil
	return err
}

type PublicKeyEpoch struct {
	KeyID              string                     `json:"key_id"`
	Epoch              uint64                     `json:"epoch"`
	PublicKey          string                     `json:"public_key"`
	Transition         *contracts.KeyTransitionV1 `json:"transition,omitempty"`
	TransitionEnvelope *contracts.EventEnvelopeV1 `json:"transition_envelope,omitempty"`
	EpochStartEnvelope *contracts.EventEnvelopeV1 `json:"epoch_start_envelope,omitempty"`
}

type PublicKeyMetadata struct {
	SchemaVersion string           `json:"schema_version"`
	HostID        string           `json:"host_id"`
	CurrentKeyID  string           `json:"current_key_id"`
	CurrentEpoch  uint64           `json:"current_epoch"`
	Keys          []PublicKeyEpoch `json:"keys"`
}

func (metadata PublicKeyMetadata) Validate() error {
	if metadata.SchemaVersion != "agmind.observer-public-keys.v1" ||
		!uuid4Pattern.MatchString(metadata.HostID) ||
		!hex32Pattern.MatchString(metadata.CurrentKeyID) ||
		metadata.CurrentEpoch == 0 ||
		metadata.Keys == nil ||
		len(metadata.Keys) == 0 ||
		len(metadata.Keys) > 16 {
		return fmt.Errorf("invalid observer public-key metadata")
	}
	var prior uint64
	currentFound := false
	var priorPublic ed25519.PublicKey
	var priorEntry PublicKeyEpoch
	var priorStartSequence uint64
	for index, entry := range metadata.Keys {
		if entry.Epoch != prior+1 ||
			!hex32Pattern.MatchString(entry.KeyID) ||
			!hex64Pattern.MatchString(entry.PublicKey) {
			return fmt.Errorf("invalid observer public-key epoch")
		}
		publicKey, err := hex.DecodeString(entry.PublicKey)
		if err != nil {
			return err
		}
		derived, err := contracts.KeyID(publicKey)
		if err != nil || derived != entry.KeyID {
			return fmt.Errorf("observer key ID mismatch")
		}
		if index == 0 {
			if entry.Transition != nil ||
				entry.TransitionEnvelope != nil ||
				entry.EpochStartEnvelope != nil {
				return fmt.Errorf("initial observer key cannot have transition proof")
			}
		} else {
			if entry.Transition == nil ||
				entry.TransitionEnvelope == nil ||
				entry.EpochStartEnvelope == nil {
				return fmt.Errorf("observer key epoch lacks transition proof")
			}
			transition := *entry.Transition
			if transition.HostID != metadata.HostID ||
				transition.OldKeyID != priorEntry.KeyID ||
				transition.NewKeyID != entry.KeyID ||
				transition.OldEpoch != priorEntry.Epoch ||
				transition.NewEpoch != entry.Epoch ||
				transition.NewPublicKey != entry.PublicKey {
				return fmt.Errorf("observer key transition identity mismatch")
			}
			if err := contracts.VerifyKeyTransition(
				transition,
				priorPublic,
			); err != nil {
				return fmt.Errorf("invalid observer key transition: %w", err)
			}
			transitionFields, err := transitionMap(transition)
			if err != nil || !eventHasExactFields(
				*entry.TransitionEnvelope,
				transitionFields,
			) {
				return fmt.Errorf("observer transition envelope fields mismatch")
			}
			transitionEnvelope := *entry.TransitionEnvelope
			if transitionEnvelope.HostID != metadata.HostID ||
				transitionEnvelope.EventType != "observer_key_transition" ||
				transitionEnvelope.KeyID != priorEntry.KeyID ||
				transitionEnvelope.KeyEpoch != priorEntry.Epoch ||
				transitionEnvelope.SourceID != "agmind-observerd" ||
				transitionEnvelope.SourceSequence == 0 ||
				transitionEnvelope.SourcePayloadHash !=
					transitionEnvelope.NormalizedFieldsSHA256 {
				return fmt.Errorf("observer transition envelope identity mismatch")
			}
			if err := contracts.VerifyEventSignature(
				transitionEnvelope,
				priorPublic,
			); err != nil {
				return fmt.Errorf("invalid observer transition envelope: %w", err)
			}
			startFields := map[string]any{
				"kind":      "observer_key_epoch_start",
				"key_id":    entry.KeyID,
				"key_epoch": entry.Epoch,
			}
			startEnvelope := *entry.EpochStartEnvelope
			if !eventHasExactFields(startEnvelope, startFields) ||
				startEnvelope.HostID != metadata.HostID ||
				startEnvelope.EventType != "observer_key_epoch_start" ||
				startEnvelope.KeyID != entry.KeyID ||
				startEnvelope.KeyEpoch != entry.Epoch ||
				startEnvelope.SourceID != "agmind-observerd" ||
				startEnvelope.SourcePayloadHash !=
					startEnvelope.NormalizedFieldsSHA256 ||
				transitionEnvelope.SourceSequence == math.MaxUint64 ||
				startEnvelope.SourceSequence !=
					transitionEnvelope.SourceSequence+1 {
				return fmt.Errorf("observer epoch-start envelope identity mismatch")
			}
			if err := contracts.VerifyEventSignature(
				startEnvelope,
				ed25519.PublicKey(publicKey),
			); err != nil {
				return fmt.Errorf("invalid observer epoch-start envelope: %w", err)
			}
			exactEnvelopeShape := func(
				event contracts.EventEnvelopeV1,
			) bool {
				return event.ContainerID == nil &&
					event.ContainerStartTime == nil &&
					event.ReleaseID == nil &&
					event.InventoryGeneration == 0 &&
					event.InventoryRevision == nil &&
					len(event.RedactionFlags) == 0
			}
			sameBoot := transitionEnvelope.BootID == startEnvelope.BootID
			sameBootRotation := sameBoot &&
				exactFlags(
					transitionEnvelope.CoverageFlags,
					"key_rotation",
				) &&
				exactFlags(startEnvelope.CoverageFlags, "key_rotation")
			bBoundary := sameBoot &&
				exactFlags(
					transitionEnvelope.CoverageFlags,
					"boot_transition",
					"key_rotation",
				) &&
				exactFlags(startEnvelope.CoverageFlags, "key_rotation")
			cBoundary := !sameBoot &&
				exactFlags(
					transitionEnvelope.CoverageFlags,
					"key_rotation",
				) &&
				exactFlags(
					startEnvelope.CoverageFlags,
					"boot_transition",
					"key_rotation",
				)
			if !exactEnvelopeShape(transitionEnvelope) ||
				!exactEnvelopeShape(startEnvelope) ||
				!sameBootRotation && !bBoundary && !cBoundary {
				return fmt.Errorf("observer rotation boundary shape mismatch")
			}
			if priorStartSequence != 0 &&
				transitionEnvelope.SourceSequence <= priorStartSequence {
				return fmt.Errorf("observer key transition sequence rollback")
			}
			priorStartSequence = startEnvelope.SourceSequence
		}
		if entry.Epoch == metadata.CurrentEpoch &&
			entry.KeyID == metadata.CurrentKeyID {
			currentFound = true
		}
		prior = entry.Epoch
		priorPublic = append(ed25519.PublicKey(nil), publicKey...)
		priorEntry = entry
	}
	if !currentFound {
		return fmt.Errorf("current observer key missing")
	}
	last := metadata.Keys[len(metadata.Keys)-1]
	if metadata.CurrentEpoch != prior ||
		metadata.CurrentEpoch != last.Epoch ||
		metadata.CurrentKeyID != last.KeyID {
		return fmt.Errorf("current observer key is not the final epoch")
	}
	canonical, err := contracts.CanonicalJSON(metadata)
	if err != nil || len(canonical) > 65_536 {
		return fmt.Errorf("observer public-key metadata exceeds 64 KiB")
	}
	return nil
}

func eventHasExactFields(
	event contracts.EventEnvelopeV1,
	expected map[string]any,
) bool {
	actualCanonical, actualErr := contracts.CanonicalJSON(
		event.NormalizedFields,
	)
	expectedCanonical, expectedErr := contracts.CanonicalJSON(expected)
	return actualErr == nil &&
		expectedErr == nil &&
		bytes.Equal(actualCanonical, expectedCanonical)
}

func (metadata PublicKeyMetadata) Keyring() (*Keyring, error) {
	if err := metadata.Validate(); err != nil {
		return nil, err
	}
	keyring := NewKeyring()
	for _, entry := range metadata.Keys {
		publicKey, _ := hex.DecodeString(entry.PublicKey)
		if err := keyring.Add(entry.Epoch, ed25519.PublicKey(publicKey)); err != nil {
			return nil, err
		}
		if entry.Epoch > 1 {
			keyring.boundaries[entry.Epoch] = epochBoundary{
				epoch:      entry.Epoch,
				keyID:      entry.KeyID,
				transition: *entry.TransitionEnvelope,
				start:      *entry.EpochStartEnvelope,
			}
		}
	}
	keyring.hostID = metadata.HostID
	keyring.metadataEpoch = metadata.CurrentEpoch
	return keyring, nil
}

func publicMetadataPath(stateDir string) string {
	return filepath.Join(stateDir, "observer-public-keys.json")
}

func LoadPublicKeyMetadata(stateDir string) (PublicKeyMetadata, error) {
	raw, err := readSingleLinkRegular(publicMetadataPath(stateDir), 65_536)
	if err != nil {
		return PublicKeyMetadata{}, err
	}
	return contracts.DecodeStrict[PublicKeyMetadata](bytes.NewReader(raw), 65_536)
}

func savePublicKeyMetadata(stateDir string, metadata PublicKeyMetadata) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	raw, err := contracts.CanonicalJSON(metadata)
	if err != nil {
		return err
	}
	if len(raw) > 65_536 {
		return fmt.Errorf("observer public-key metadata exceeds 64 KiB")
	}
	return durablefile.AtomicWrite(publicMetadataPath(stateDir), raw)
}

type rotationMarker struct {
	SchemaVersion      string                    `json:"schema_version"`
	HostID             string                    `json:"host_id"`
	Stage              string                    `json:"stage"`
	NewPrivateSHA256   string                    `json:"new_private_sha256"`
	TransitionSequence uint64                    `json:"transition_sequence"`
	StartSequence      uint64                    `json:"start_sequence"`
	Transition         contracts.KeyTransitionV1 `json:"transition"`
}

func (marker rotationMarker) Validate() error {
	if marker.SchemaVersion != "agmind.observer-key-rotation.v1" ||
		!uuid4Pattern.MatchString(marker.HostID) ||
		!hex64Pattern.MatchString(marker.NewPrivateSHA256) ||
		marker.TransitionSequence == 0 ||
		marker.TransitionSequence == math.MaxUint64 ||
		marker.StartSequence != marker.TransitionSequence+1 {
		return fmt.Errorf("invalid rotation marker")
	}
	switch marker.Stage {
	case "prepared", "transition_spooled", "key_switched", "start_spooled":
	default:
		return fmt.Errorf("invalid rotation stage")
	}
	if marker.Transition.HostID != marker.HostID {
		return fmt.Errorf("rotation host mismatch")
	}
	return marker.Transition.Validate()
}

type rotationOptions struct {
	euid                  func() int
	bootID                func() (string, error)
	now                   func() time.Time
	generate              func() (ed25519.PublicKey, ed25519.PrivateKey, error)
	saveMetadata          func(string, PublicKeyMetadata) error
	syncMetadataDirectory func(string) error
	persist               func(string, ObserverState) error
	stopAfter             string
}

type RotationOption func(*rotationOptions)

func WithRotationEUID(value func() int) RotationOption {
	return func(options *rotationOptions) { options.euid = value }
}

func WithRotationBootID(value func() (string, error)) RotationOption {
	return func(options *rotationOptions) { options.bootID = value }
}

func WithRotationNow(value func() time.Time) RotationOption {
	return func(options *rotationOptions) { options.now = value }
}

func WithRotationKeyGenerator(
	value func() (ed25519.PublicKey, ed25519.PrivateKey, error),
) RotationOption {
	return func(options *rotationOptions) { options.generate = value }
}

func WithRotationStopAfter(stage string) RotationOption {
	return func(options *rotationOptions) { options.stopAfter = stage }
}

func withRotationPersist(
	value func(string, ObserverState) error,
) RotationOption {
	return func(options *rotationOptions) { options.persist = value }
}

func readKernelBootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if !uuid4Pattern.MatchString(value) {
		return "", fmt.Errorf("invalid kernel boot ID")
	}
	return value, nil
}

func readHostID(path string) (string, error) {
	raw, err := readInstalledSecret(path, 128)
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if !uuid4Pattern.MatchString(value) {
		return "", fmt.Errorf("invalid host ID")
	}
	return value, nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readInstalledSecret(path, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key must be raw 64-byte Ed25519")
	}
	if !validPrivateKey(ed25519.PrivateKey(raw)) {
		return nil, fmt.Errorf("private key seed/public mismatch")
	}
	return append(ed25519.PrivateKey(nil), raw...), nil
}

func validPrivateKey(privateKey ed25519.PrivateKey) bool {
	if len(privateKey) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	return subtle.ConstantTimeCompare(privateKey, derived) == 1
}

func markerPath(stateDir string) string {
	return filepath.Join(stateDir, "key-rotation.json")
}

func rotationKeyPath(stateDir string) string {
	return filepath.Join(stateDir, "key-rotation-new.key")
}

func saveRotationMarker(stateDir string, marker rotationMarker) error {
	if err := marker.Validate(); err != nil {
		return err
	}
	raw, err := contracts.CanonicalJSON(marker)
	if err != nil {
		return err
	}
	return durablefile.AtomicWrite(markerPath(stateDir), raw)
}

func loadRotationMarker(stateDir string) (rotationMarker, error) {
	raw, err := readSingleLinkRegular(markerPath(stateDir), 65_536)
	if err != nil {
		return rotationMarker{}, err
	}
	return contracts.DecodeStrict[rotationMarker](bytes.NewReader(raw), 65_536)
}

func removeExactRotationArtifact(
	path string,
	expected []byte,
	maxBytes int64,
) error {
	// Pinned: RemoveIfIdentity refuses unpinned identities, and the pin is
	// what proves the unlinked inode is the one whose bytes matched.
	raw, identity, err := durablefile.ReadRegularIdentityHandle(path, maxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !bytes.Equal(raw, expected) {
		_ = identity.Close()
		return fmt.Errorf("rotation artifact identity mismatch")
	}
	return removeIdentityDurably(
		path,
		identity,
		durablefile.RemoveIfIdentity,
	)
}

func loadObserverState(path string) (ObserverState, error) {
	raw, err := readSingleLinkRegular(path, 65_536)
	if err != nil {
		return ObserverState{}, err
	}
	sourceSchema, err := observerStateSchemaVersion(raw)
	if err != nil {
		return ObserverState{}, err
	}
	state, migrated, err := decodeObserverState(raw)
	if err != nil {
		return ObserverState{}, err
	}
	if migrated {
		if err := requireControlReceiptMigrationBoundary(
			path,
			sourceSchema,
		); err != nil {
			return ObserverState{}, err
		}
		if err := requirePCCMigrationBoundary(path, sourceSchema); err != nil {
			return ObserverState{}, err
		}
		if err := persistState(path, state); err != nil {
			return ObserverState{}, err
		}
	}
	return state, nil
}

func markExistingStateReadOnly(path, reason string) {
	state, err := loadObserverState(path)
	if err != nil {
		return
	}
	store := &StateStore{
		path:    path,
		state:   cloneObserverState(state),
		persist: persistState,
	}
	_ = store.PersistReadOnly(reason)
}

type rotationBoundaryMode uint8

const (
	rotationBoundaryInvalid rotationBoundaryMode = iota
	rotationBoundarySameBoot
	rotationBoundaryB
	rotationBoundaryC
)

func rotationModeForState(
	state ObserverState,
	authorization rotationPublicationAuthorization,
) rotationBoundaryMode {
	marker := authorization.marker
	if marker.Validate() != nil ||
		len(state.BootHistory) == 0 ||
		state.HostID != marker.HostID ||
		state.KeyID != marker.Transition.OldKeyID ||
		state.KeyEpoch != marker.Transition.OldEpoch ||
		marker.TransitionSequence == 0 ||
		marker.StartSequence != marker.TransitionSequence+1 {
		return rotationBoundaryInvalid
	}
	lastBoundary := state.BootHistory[len(state.BootHistory)-1]
	switch authorization.role {
	case rotationTransitionPublication:
		if authorization.transitionBinding != nil ||
			state.LastSequence < marker.TransitionSequence-1 ||
			state.LastSequence > marker.TransitionSequence {
			return rotationBoundaryInvalid
		}
		if state.BootBoundaryState == bootBoundaryPending &&
			state.PendingBootBoundary != nil &&
			lastBoundary.FirstSequence == marker.TransitionSequence &&
			state.PendingBootBoundary.PreviousSourceSequence ==
				marker.TransitionSequence-1 {
			return rotationBoundaryB
		}
		if state.BootBoundaryState == bootBoundaryCommitted {
			return rotationBoundarySameBoot
		}
	case rotationEpochStartPublication:
		if authorization.transitionBinding == nil ||
			state.LastSequence < marker.StartSequence-1 ||
			state.LastSequence > marker.StartSequence {
			return rotationBoundaryInvalid
		}
		transition := authorization.transitionBinding.event
		if state.BootBoundaryState == bootBoundaryPending &&
			state.PendingBootBoundary != nil &&
			state.PendingBootBoundary.PreviousBootID != nil &&
			*state.PendingBootBoundary.PreviousBootID == transition.BootID &&
			state.PendingBootBoundary.PreviousSourceSequence ==
				marker.TransitionSequence &&
			lastBoundary.FirstSequence == marker.StartSequence &&
			transition.BootID != state.BootID {
			return rotationBoundaryC
		}
		if state.BootBoundaryState == bootBoundaryCommitted &&
			transition.BootID == state.BootID {
			return rotationBoundarySameBoot
		}
	}
	return rotationBoundaryInvalid
}

func rotationEpochStartMode(
	state ObserverState,
	marker rotationMarker,
	transition contracts.EventEnvelopeV1,
) rotationBoundaryMode {
	return rotationModeForState(state, rotationPublicationAuthorization{
		marker: marker,
		role:   rotationEpochStartPublication,
		transitionBinding: &rotationTransitionBinding{
			event: transition,
		},
	})
}

func rotationArchiveModeForState(
	state ObserverState,
	authorization rotationPublicationAuthorization,
) rotationBoundaryMode {
	mode := rotationModeForState(state, authorization)
	if mode != rotationBoundarySameBoot ||
		authorization.role != rotationEpochStartPublication ||
		authorization.transitionBinding == nil ||
		len(state.BootHistory) == 0 {
		return mode
	}
	transition := authorization.transitionBinding.event
	last := state.BootHistory[len(state.BootHistory)-1]
	if last.BoundaryEventType == "observer_key_transition" &&
		last.BoundaryEventID == transition.EventID &&
		last.BootID == transition.BootID &&
		last.FirstSequence == transition.SourceSequence &&
		exactFlags(
			transition.CoverageFlags,
			"boot_transition",
			"key_rotation",
		) {
		return rotationBoundaryB
	}
	return mode
}

func rotationCoverageFlags(
	mode rotationBoundaryMode,
	role rotationPublicationRole,
) []string {
	if mode == rotationBoundaryB && role == rotationTransitionPublication ||
		mode == rotationBoundaryC && role == rotationEpochStartPublication {
		return []string{"boot_transition", "key_rotation"}
	}
	return []string{"key_rotation"}
}

func rotationFieldsForAuthorization(
	authorization rotationPublicationAuthorization,
) (map[string]any, error) {
	switch authorization.role {
	case rotationTransitionPublication:
		return transitionMap(authorization.marker.Transition)
	case rotationEpochStartPublication:
		return map[string]any{
			"kind":      "observer_key_epoch_start",
			"key_id":    authorization.marker.Transition.NewKeyID,
			"key_epoch": authorization.marker.Transition.NewEpoch,
		}, nil
	default:
		return nil, ErrRotationPublicationMismatch
	}
}

func rotationMetadataMatches(
	metadata EventMetadata,
	fields map[string]any,
	expectedFlags []string,
) bool {
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(canonical)
	return metadata.ContainerID == nil &&
		metadata.ContainerStartTime == nil &&
		metadata.ReleaseID == nil &&
		metadata.InventoryGeneration == 0 &&
		metadata.InventoryRevision == nil &&
		len(metadata.RedactionFlags) == 0 &&
		exactFlags(metadata.CoverageFlags, expectedFlags...) &&
		metadata.SourcePayloadHash == hex.EncodeToString(sum[:])
}

func transitionEnvelopeMatchesMarker(
	event contracts.EventEnvelopeV1,
	marker rotationMarker,
) bool {
	fields, err := transitionMap(marker.Transition)
	return err == nil &&
		event.EventType == "observer_key_transition" &&
		event.SourceID == "agmind-observerd" &&
		event.SourceVersion == "0.1.0" &&
		event.HostID == marker.HostID &&
		event.KeyID == marker.Transition.OldKeyID &&
		event.KeyEpoch == marker.Transition.OldEpoch &&
		event.SourceSequence == marker.TransitionSequence &&
		event.ContainerID == nil &&
		event.ContainerStartTime == nil &&
		event.ReleaseID == nil &&
		event.InventoryGeneration == 0 &&
		event.InventoryRevision == nil &&
		len(event.RedactionFlags) == 0 &&
		event.SourcePayloadHash == event.NormalizedFieldsSHA256 &&
		eventHasExactFields(event, fields)
}

func rotationTransitionCoverageMatches(
	state ObserverState,
	transition contracts.EventEnvelopeV1,
	mode rotationBoundaryMode,
) bool {
	expected := []string{"key_rotation"}
	if mode == rotationBoundarySameBoot &&
		len(state.BootHistory) > 0 {
		last := state.BootHistory[len(state.BootHistory)-1]
		if last.BoundaryEventType == "observer_key_transition" &&
			last.BoundaryEventID == transition.EventID {
			expected = []string{"boot_transition", "key_rotation"}
		}
	}
	return exactFlags(transition.CoverageFlags, expected...)
}

func rotationEnvelopeMatches(
	event contracts.EventEnvelopeV1,
	state ObserverState,
	authorization rotationPublicationAuthorization,
	mode rotationBoundaryMode,
) bool {
	fields, err := rotationFieldsForAuthorization(authorization)
	if err != nil ||
		event.SourceID != "agmind-observerd" ||
		event.SourceVersion != "0.1.0" ||
		event.HostID != state.HostID ||
		event.BootID != state.BootID ||
		event.ContainerID != nil ||
		event.ContainerStartTime != nil ||
		event.ReleaseID != nil ||
		event.InventoryGeneration != 0 ||
		event.InventoryRevision != nil ||
		len(event.RedactionFlags) != 0 ||
		event.SourcePayloadHash != event.NormalizedFieldsSHA256 ||
		!eventHasExactFields(event, fields) ||
		!exactFlags(
			event.CoverageFlags,
			rotationCoverageFlags(mode, authorization.role)...,
		) {
		return false
	}
	marker := authorization.marker
	switch authorization.role {
	case rotationTransitionPublication:
		return event.EventType == "observer_key_transition" &&
			event.KeyID == marker.Transition.OldKeyID &&
			event.KeyEpoch == marker.Transition.OldEpoch &&
			event.SourceSequence == marker.TransitionSequence
	case rotationEpochStartPublication:
		if authorization.transitionBinding == nil ||
			!transitionEnvelopeMatchesMarker(
				authorization.transitionBinding.event,
				marker,
			) ||
			authorization.transitionBinding.event.SourceSequence+1 !=
				event.SourceSequence {
			return false
		}
		return rotationTransitionCoverageMatches(
			state,
			authorization.transitionBinding.event,
			mode,
		) &&
			event.EventType == "observer_key_epoch_start" &&
			event.KeyID == marker.Transition.NewKeyID &&
			event.KeyEpoch == marker.Transition.NewEpoch &&
			event.SourceSequence == marker.StartSequence
	default:
		return false
	}
}

func (authorization rotationPublicationAuthorization) matchesRequest(
	state ObserverState,
	signer *EnvelopeSigner,
	eventType string,
	fields map[string]any,
	metadata EventMetadata,
) bool {
	mode := rotationModeForState(state, authorization)
	expectedFields, err := rotationFieldsForAuthorization(authorization)
	if mode == rotationBoundaryInvalid ||
		err != nil ||
		!canonicalEqual(fields, expectedFields) ||
		!rotationMetadataMatches(
			metadata,
			expectedFields,
			rotationCoverageFlags(mode, authorization.role),
		) ||
		signer.config.HostID != state.HostID ||
		signer.config.BootID != state.BootID {
		return false
	}
	marker := authorization.marker
	switch authorization.role {
	case rotationTransitionPublication:
		if state.LastSequence != marker.TransitionSequence-1 ||
			eventType != "observer_key_transition" ||
			signer.keyID != marker.Transition.OldKeyID ||
			signer.config.KeyEpoch != marker.Transition.OldEpoch ||
			contracts.VerifyKeyTransition(
				marker.Transition,
				signer.privateKey.Public().(ed25519.PublicKey),
			) != nil {
			return false
		}
	case rotationEpochStartPublication:
		publicKey, err := hex.DecodeString(marker.Transition.NewPublicKey)
		if err != nil ||
			state.LastSequence != marker.StartSequence-1 ||
			eventType != "observer_key_epoch_start" ||
			signer.keyID != marker.Transition.NewKeyID ||
			signer.config.KeyEpoch != marker.Transition.NewEpoch ||
			!bytes.Equal(
				signer.privateKey.Public().(ed25519.PublicKey),
				publicKey,
			) ||
			authorization.transitionBinding == nil ||
			!transitionEnvelopeMatchesMarker(
				authorization.transitionBinding.event,
				marker,
			) ||
			!rotationTransitionCoverageMatches(
				state,
				authorization.transitionBinding.event,
				mode,
			) {
			return false
		}
	default:
		return false
	}
	return true
}

func rotationMetadata(
	now time.Time,
	fields map[string]any,
	coverageFlags ...string,
) (EventMetadata, error) {
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		return EventMetadata{}, err
	}
	sum := sha256.Sum256(canonical)
	if len(coverageFlags) == 0 {
		coverageFlags = []string{"key_rotation"}
	}
	return EventMetadata{
		EventTime:         now.UTC(),
		RedactionFlags:    []string{},
		CoverageFlags:     append([]string(nil), coverageFlags...),
		SourcePayloadHash: hex.EncodeToString(sum[:]),
	}, nil
}

func (spool *Spool) findRotationEvent(
	eventType string,
	keyID string,
	sequence uint64,
	expectedFields map[string]any,
) (contracts.EventEnvelopeV1, bool, error) {
	expectedCanonical, err := contracts.CanonicalJSON(expectedFields)
	if err != nil {
		return contracts.EventEnvelopeV1{}, false, err
	}
	expectedHash := sha256.Sum256(expectedCanonical)
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	item, exists := spool.items[sequence]
	if !exists {
		return contracts.EventEnvelopeV1{}, false, nil
	}
	{
		event, _, _, _, _, readErr := readStandaloneFrame(item.path, spool.keys)
		if readErr != nil ||
			event.EventType != eventType ||
			event.KeyID != keyID ||
			event.SourceSequence != sequence ||
			event.NormalizedFieldsSHA256 != expectedHashHex ||
			event.SourcePayloadHash != expectedHashHex {
			return contracts.EventEnvelopeV1{}, false, ErrSpoolCorrupt
		}
		actualCanonical, canonicalErr := contracts.CanonicalJSON(
			event.NormalizedFields,
		)
		if canonicalErr == nil && bytes.Equal(actualCanonical, expectedCanonical) {
			return event, true, nil
		}
	}
	return contracts.EventEnvelopeV1{}, false, ErrSpoolCorrupt
}

func (spool *Spool) bindRotationTransition(
	marker rotationMarker,
) (rotationTransitionBinding, error) {
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	snapshot := spool.state.Snapshot()
	item, exists := spool.items[marker.TransitionSequence]
	if !exists ||
		item.Tier != PriorityTier ||
		item.Sequence != marker.TransitionSequence ||
		item.Sequence > snapshot.PublicationHeadSequence ||
		validatePublicationItem(item) != nil {
		return rotationTransitionBinding{}, ErrRotationPublicationMismatch
	}
	event, canonical, contentHash, frameBytes, identity, err :=
		readStandaloneFrame(item.path, spool.keys)
	if err != nil ||
		!transitionEnvelopeMatchesMarker(event, marker) ||
		event.EventID != item.EventID ||
		contentHash != item.ContentSHA256 ||
		frameBytes != item.frameBytes ||
		!identity.Same(item.identity) ||
		!bytes.Equal(canonical, item.Canonical) {
		return rotationTransitionBinding{}, ErrRotationPublicationMismatch
	}
	return rotationTransitionBinding{
		event:               event,
		contentSHA256:       contentHash,
		frameIdentity:       identity,
		publicationIdentity: item.publicationIdentity,
		publicationHash:     item.publicationHash,
	}, nil
}

func rotationBindingMatchesItem(
	binding rotationTransitionBinding,
	item SpoolItem,
	keys *Keyring,
) bool {
	event, canonical, contentHash, frameBytes, identity, err :=
		readStandaloneFrame(item.path, keys)
	return err == nil &&
		event.EventID == binding.event.EventID &&
		event.SourceSequence == binding.event.SourceSequence &&
		bytes.Equal(canonical, item.Canonical) &&
		contentHash == binding.contentSHA256 &&
		frameBytes == item.frameBytes &&
		identity.Same(binding.frameIdentity) &&
		binding.event.EventID == item.EventID &&
		binding.event.SourceSequence == item.Sequence &&
		binding.contentSHA256 == item.ContentSHA256 &&
		binding.frameIdentity.Same(item.identity) &&
		binding.publicationIdentity.Same(item.publicationIdentity) &&
		binding.publicationHash == item.publicationHash
}

func (spool *Spool) containsRotationEvent(
	eventType string,
	keyID string,
	expectedFields map[string]any,
) bool {
	spool.mutex.Lock()
	sequences := make([]uint64, 0, len(spool.items))
	for sequence := range spool.items {
		sequences = append(sequences, sequence)
	}
	spool.mutex.Unlock()
	for _, sequence := range sequences {
		_, found, err := spool.findRotationEvent(
			eventType,
			keyID,
			sequence,
			expectedFields,
		)
		if err == nil && found {
			return true
		}
	}
	return false
}

func transitionMap(transition contracts.KeyTransitionV1) (map[string]any, error) {
	raw, err := contracts.CanonicalJSON(transition)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func canonicalEqual(left, right any) bool {
	leftRaw, leftErr := contracts.CanonicalJSON(left)
	rightRaw, rightErr := contracts.CanonicalJSON(right)
	return leftErr == nil &&
		rightErr == nil &&
		bytes.Equal(leftRaw, rightRaw)
}

func reconcileUncertainPublicMetadataCommit(
	stateDir string,
	expected PublicKeyMetadata,
	syncDirectory func(string) error,
) error {
	expectedRaw, err := contracts.CanonicalJSON(expected)
	if err != nil {
		return err
	}
	actualRaw, err := readSingleLinkRegular(
		publicMetadataPath(stateDir),
		65_536,
	)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualRaw, expectedRaw) {
		return fmt.Errorf("uncertain observer public-key metadata mismatch")
	}
	if syncDirectory == nil {
		return fmt.Errorf("observer public-key metadata resync unavailable")
	}
	return syncDirectory(stateDir)
}

func defaultRotationOptions() rotationOptions {
	return rotationOptions{
		euid:                  os.Geteuid,
		bootID:                readKernelBootID,
		now:                   time.Now,
		saveMetadata:          savePublicKeyMetadata,
		syncMetadataDirectory: durablefile.SyncDirectory,
		persist:               persistState,
		generate: func() (ed25519.PublicKey, ed25519.PrivateKey, error) {
			return ed25519.GenerateKey(rand.Reader)
		},
	}
}

// RotateKeys performs root-only offline, resumable observer key rotation.
func RotateKeys(configPath string, supplied ...RotationOption) error {
	if err := requireLinuxPlatform(runtime.GOOS); err != nil {
		return err
	}
	options := defaultRotationOptions()
	for _, option := range supplied {
		option(&options)
	}
	if options.euid == nil || options.euid() != 0 {
		return ErrRootRequired
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	lock, err := AcquireStateLock(config.StateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	hostID, err := readHostID(config.HostIDFile)
	if err != nil {
		return err
	}
	bootID, err := options.bootID()
	if err != nil {
		return err
	}
	statePath := filepath.Join(config.StateDir, "observer-state.json")
	preflightState, preflightErr := loadObserverState(statePath)
	stateExists := preflightErr == nil
	if preflightErr != nil && !errors.Is(preflightErr, os.ErrNotExist) {
		return preflightErr
	}
	artifactsPresent := rotationArtifactsPresent(config.StateDir)
	if stateExists &&
		preflightState.MutationReadOnly &&
		(preflightState.ReadOnlyReason != "observer_rotation_incomplete" ||
			!artifactsPresent) {
		return fmt.Errorf(
			"observer key rotation blocked by mutation read-only state: %s",
			preflightState.ReadOnlyReason,
		)
	}
	activeKey, keyErr := readPrivateKey(config.PrivateKeyFile)
	if keyErr != nil {
		markExistingStateReadOnly(statePath, "observer_private_key_unavailable")
		return keyErr
	}
	activeKeyID, err := contracts.KeyID(activeKey.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}

	var marker rotationMarker
	marker, err = loadRotationMarker(config.StateDir)
	markerExists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		markExistingStateReadOnly(statePath, "observer_rotation_marker_invalid")
		return err
	}
	if stateExists &&
		preflightState.BootID != bootID &&
		preflightState.BootBoundaryState == bootBoundaryPending &&
		len(preflightState.BootHistory) > 0 &&
		preflightState.PublicationHeadSequence >=
			preflightState.BootHistory[len(preflightState.BootHistory)-1].FirstSequence {
		metadata, metadataErr := LoadPublicKeyMetadata(config.StateDir)
		if metadataErr != nil {
			return metadataErr
		}
		keyring, keyringErr := metadata.Keyring()
		if keyringErr != nil {
			return keyringErr
		}
		recoveryConfig := SpoolConfig{
			StateDir:             config.StateDir,
			MaxBytes:             config.SpoolMaxBytes,
			PriorityReserveBytes: config.SpoolPriorityReserveBytes,
			Now:                  options.now,
		}
		if markerExists {
			if validateErr := marker.Validate(); validateErr != nil {
				return validateErr
			}
			newPublic, decodeErr := hex.DecodeString(
				marker.Transition.NewPublicKey,
			)
			if decodeErr != nil {
				return decodeErr
			}
			if addErr := keyring.Add(
				marker.Transition.NewEpoch,
				ed25519.PublicKey(newPublic),
			); addErr != nil {
				return addErr
			}
			recoveryConfig.rotation = &marker
		}
		if recoverErr := recoverPendingBootBoundaryBeforeBootChange(
			statePath,
			StateIdentity{
				HostID:   hostID,
				BootID:   bootID,
				KeyID:    preflightState.KeyID,
				KeyEpoch: preflightState.KeyEpoch,
			},
			recoveryConfig,
			keyring,
		); recoverErr != nil {
			return recoverErr
		}
		preflightState, preflightErr = loadObserverState(statePath)
		if preflightErr != nil {
			return preflightErr
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		identity := StateIdentity{
			HostID:   hostID,
			BootID:   bootID,
			KeyID:    activeKeyID,
			KeyEpoch: 1,
		}
		existingState, loadErr := preflightState, preflightErr
		if stateExists {
			if existingState.HostID != hostID ||
				existingState.KeyID != activeKeyID {
				markExistingStateReadOnly(
					statePath,
					"observer_rotation_active_identity_mismatch",
				)
				return fmt.Errorf("observer rotation active identity mismatch")
			}
			identity.KeyEpoch = existingState.KeyEpoch
		} else if !errors.Is(loadErr, os.ErrNotExist) {
			return loadErr
		}
		state, stateErr := OpenStateStore(
			statePath,
			identity,
		)
		if stateErr != nil {
			return stateErr
		}
		state.persist = options.persist
		snapshot := state.Snapshot()
		if snapshot.KeyEpoch == math.MaxUint64 ||
			snapshot.LastSequence >= math.MaxUint64-1 {
			_ = state.PersistReadOnly("observer_key_epoch_exhausted")
			return fmt.Errorf("observer key rotation sequence exhausted")
		}
		preflightMetadata, metadataErr := LoadPublicKeyMetadata(config.StateDir)
		if errors.Is(metadataErr, os.ErrNotExist) {
			if snapshot.KeyEpoch != 1 || snapshot.LastSequence != 0 {
				_ = state.PersistReadOnly(
					"observer_public_key_metadata_missing",
				)
				return fmt.Errorf("observer public key metadata missing")
			}
			preflightMetadata = initialPublicMetadata(
				hostID,
				activeKeyID,
				snapshot.KeyEpoch,
				activeKey.Public().(ed25519.PublicKey),
			)
			if err := options.saveMetadata(
				config.StateDir,
				preflightMetadata,
			); err != nil {
				return err
			}
		} else if metadataErr != nil {
			_ = state.PersistReadOnly(
				"observer_public_key_metadata_invalid",
			)
			return metadataErr
		}
		if preflightMetadata.HostID != hostID ||
			preflightMetadata.CurrentKeyID != snapshot.KeyID ||
			preflightMetadata.CurrentEpoch != snapshot.KeyEpoch {
			_ = state.PersistReadOnly(
				"observer_public_key_metadata_mismatch",
			)
			return fmt.Errorf("observer public key metadata mismatch")
		}
		if len(preflightMetadata.Keys) >= 16 {
			_ = state.PersistReadOnly(
				"observer_key_history_exhausted",
			)
			return fmt.Errorf("observer key history exhausted")
		}
		var publicKey ed25519.PublicKey
		var newPrivate ed25519.PrivateKey
		newPrivate, orphanErr := readPrivateKey(
			rotationKeyPath(config.StateDir),
		)
		if errors.Is(orphanErr, os.ErrNotExist) {
			var generateErr error
			publicKey, newPrivate, generateErr = options.generate()
			if generateErr != nil {
				return generateErr
			}
			if len(newPrivate) != ed25519.PrivateKeySize ||
				!bytes.Equal(
					publicKey,
					newPrivate.Public().(ed25519.PublicKey),
				) {
				return fmt.Errorf("invalid generated observer key")
			}
			if err := durablefile.CreateOnly(
				rotationKeyPath(config.StateDir),
				newPrivate,
			); err != nil {
				return err
			}
			if options.stopAfter == "new_key_written" {
				return ErrInjectedRotationStop
			}
		} else if orphanErr != nil {
			_ = state.PersistReadOnly("observer_rotation_orphan_key_invalid")
			return orphanErr
		} else {
			publicKey = newPrivate.Public().(ed25519.PublicKey)
		}
		newKeyID, keyIDErr := contracts.KeyID(publicKey)
		if keyIDErr != nil {
			return fmt.Errorf("invalid generated observer key")
		}
		transition := contracts.KeyTransitionV1{
			SchemaVersion: "agmind.key-transition.v1",
			OldKeyID:      snapshot.KeyID,
			NewKeyID:      newKeyID,
			OldEpoch:      snapshot.KeyEpoch,
			NewEpoch:      snapshot.KeyEpoch + 1,
			NewPublicKey:  hex.EncodeToString(publicKey),
			HostID:        hostID,
			OccurredAt:    options.now().UTC().Format(time.RFC3339Nano),
			OldSignature:  strings.Repeat("0", ed25519.SignatureSize*2),
			NewSignature:  strings.Repeat("0", ed25519.SignatureSize*2),
		}
		message, messageErr := contracts.KeyTransitionSigningMessage(transition)
		if messageErr != nil {
			return messageErr
		}
		transition.OldSignature = hex.EncodeToString(ed25519.Sign(activeKey, message))
		transition.NewSignature = hex.EncodeToString(ed25519.Sign(newPrivate, message))
		sum := sha256.Sum256(newPrivate)
		marker = rotationMarker{
			SchemaVersion:      "agmind.observer-key-rotation.v1",
			HostID:             hostID,
			Stage:              "prepared",
			NewPrivateSHA256:   hex.EncodeToString(sum[:]),
			TransitionSequence: snapshot.LastSequence + 1,
			StartSequence:      snapshot.LastSequence + 2,
			Transition:         transition,
		}
		if err := saveRotationMarker(config.StateDir, marker); err != nil {
			return err
		}
		if options.stopAfter == "prepared" {
			return ErrInjectedRotationStop
		}
	}
	if marker.HostID != hostID {
		markExistingStateReadOnly(statePath, "observer_rotation_host_mismatch")
		return fmt.Errorf("rotation host mismatch")
	}
	newPrivate, err := readPrivateKey(rotationKeyPath(config.StateDir))
	if errors.Is(err, os.ErrNotExist) &&
		marker.Stage == "start_spooled" &&
		activeKeyID == marker.Transition.NewKeyID {
		// Cleanup durably removes the temporary key before removing the marker.
		// At that boundary the active key is the same verified key material.
		newPrivate = append(ed25519.PrivateKey(nil), activeKey...)
		err = nil
	}
	if err != nil {
		markExistingStateReadOnly(statePath, "observer_rotation_key_missing")
		return err
	}
	newPrivateHash := sha256.Sum256(newPrivate)
	if hex.EncodeToString(newPrivateHash[:]) != marker.NewPrivateSHA256 {
		markExistingStateReadOnly(statePath, "observer_rotation_key_mismatch")
		return fmt.Errorf("rotation key mismatch")
	}
	oldPublic := activeKey.Public().(ed25519.PublicKey)
	if activeKeyID == marker.Transition.NewKeyID {
		oldPublicBytes, decodeErr := hex.DecodeString(marker.Transition.NewPublicKey)
		if decodeErr != nil || bytes.Equal(oldPublic, oldPublicBytes) == false {
			return fmt.Errorf("active new key mismatch")
		}
		metadata, metadataErr := LoadPublicKeyMetadata(config.StateDir)
		if metadataErr != nil {
			return metadataErr
		}
		for _, entry := range metadata.Keys {
			if entry.KeyID == marker.Transition.OldKeyID {
				decoded, _ := hex.DecodeString(entry.PublicKey)
				oldPublic = ed25519.PublicKey(decoded)
			}
		}
	}
	if err := contracts.VerifyKeyTransition(marker.Transition, oldPublic); err != nil {
		markExistingStateReadOnly(statePath, "observer_rotation_transition_invalid")
		return err
	}
	currentState, err := loadObserverState(statePath)
	if err != nil {
		return err
	}
	stateIsOld := currentState.HostID == hostID &&
		currentState.KeyID == marker.Transition.OldKeyID &&
		currentState.KeyEpoch == marker.Transition.OldEpoch
	stateIsNew := currentState.HostID == hostID &&
		currentState.KeyID == marker.Transition.NewKeyID &&
		currentState.KeyEpoch == marker.Transition.NewEpoch
	if !stateIsOld && !stateIsNew {
		markExistingStateReadOnly(
			statePath,
			"observer_rotation_state_identity_invalid",
		)
		return fmt.Errorf("observer rotation state identity invalid")
	}
	state, err := OpenStateStore(
		statePath,
		StateIdentity{
			HostID:   hostID,
			BootID:   bootID,
			KeyID:    currentState.KeyID,
			KeyEpoch: currentState.KeyEpoch,
		},
	)
	if err != nil {
		return err
	}
	state.persist = options.persist
	if err := state.clearRotationFence(); err != nil {
		return err
	}
	metadata, err := LoadPublicKeyMetadata(config.StateDir)
	if errors.Is(err, os.ErrNotExist) {
		_ = state.PersistReadOnly("observer_public_key_metadata_missing")
		return fmt.Errorf("observer public key metadata missing")
	} else if err != nil {
		_ = state.PersistReadOnly("observer_public_key_metadata_invalid")
		return err
	}
	if metadata.HostID != hostID {
		_ = state.PersistReadOnly(
			"observer_public_key_metadata_host_mismatch",
		)
		return fmt.Errorf("observer public key metadata host mismatch")
	}
	keyring, err := metadata.Keyring()
	if err != nil {
		return err
	}
	newPublic, _ := hex.DecodeString(marker.Transition.NewPublicKey)
	if err := keyring.Add(
		marker.Transition.NewEpoch,
		ed25519.PublicKey(newPublic),
	); err != nil {
		return err
	}
	spool, err := NewSpool(
		SpoolConfig{
			StateDir:             config.StateDir,
			MaxBytes:             config.SpoolMaxBytes,
			PriorityReserveBytes: config.SpoolPriorityReserveBytes,
			Now:                  options.now,
			rotation:             &marker,
		},
		state,
		keyring,
	)
	if err != nil {
		return err
	}
	defer spool.Close()
	state.publicationMutex.Lock()
	rotationPublicationLocked := true
	defer func() {
		if rotationPublicationLocked {
			state.publicationMutex.Unlock()
		}
	}()
	transitionFields, err := transitionMap(marker.Transition)
	if err != nil {
		return err
	}
	transitionEvent, transitionFound, err := spool.findRotationEvent(
		"observer_key_transition",
		marker.Transition.OldKeyID,
		marker.TransitionSequence,
		transitionFields,
	)
	if err != nil {
		_ = state.PersistReadOnly("observer_rotation_transition_invalid")
		return err
	}
	if !transitionFound {
		if state.Snapshot().LastSequence != marker.TransitionSequence-1 {
			_ = state.PersistReadOnly("observer_rotation_transition_sequence_lost")
			return fmt.Errorf("observer rotation transition sequence lost")
		}
		if state.Snapshot().KeyID != marker.Transition.OldKeyID ||
			activeKeyID != marker.Transition.OldKeyID {
			_ = state.PersistReadOnly("observer_rotation_transition_missing")
			return fmt.Errorf("cannot reconstruct missing old-epoch transition")
		}
		signer, err := NewEnvelopeSigner(
			SignerConfig{
				HostID:        hostID,
				BootID:        bootID,
				KeyEpoch:      marker.Transition.OldEpoch,
				SourceID:      "agmind-observerd",
				SourceVersion: "0.1.0",
				Now:           options.now,
			},
			state,
			spool,
			activeKey,
		)
		if err != nil {
			return err
		}
		transitionAuthorization := rotationPublicationAuthorization{
			marker: marker,
			role:   rotationTransitionPublication,
		}
		mode := rotationModeForState(
			state.Snapshot(),
			transitionAuthorization,
		)
		if mode == rotationBoundaryInvalid {
			_ = state.PersistReadOnly(
				"observer_rotation_transition_authorization_invalid",
			)
			return ErrRotationPublicationMismatch
		}
		eventMetadata, err := rotationMetadata(
			options.now(),
			transitionFields,
			rotationCoverageFlags(
				mode,
				rotationTransitionPublication,
			)...,
		)
		if err != nil {
			return err
		}
		transitionEvent, err = signer.wrapAuthorizedRotationLocked(
			context.Background(),
			marker,
			rotationTransitionPublication,
			"observer_key_transition",
			transitionFields,
			eventMetadata,
		)
		if err != nil {
			if errors.Is(err, ErrRotationPublicationMismatch) {
				return errors.Join(
					err,
					state.PersistReadOnly(
						"observer_rotation_transition_authorization_invalid",
					),
				)
			}
			return err
		}
		if transitionEvent.SourceSequence != marker.TransitionSequence {
			_ = state.PersistReadOnly(
				"observer_rotation_transition_sequence_lost",
			)
			return fmt.Errorf("observer rotation transition sequence mismatch")
		}
	}
	marker.Stage = "transition_spooled"
	if err := saveRotationMarker(config.StateDir, marker); err != nil {
		return err
	}
	if options.stopAfter == marker.Stage {
		return ErrInjectedRotationStop
	}
	marker.Stage = "key_switched"
	if err := saveRotationMarker(config.StateDir, marker); err != nil {
		return err
	}
	if options.stopAfter == marker.Stage {
		return ErrInjectedRotationStop
	}
	startFields := map[string]any{
		"kind":      "observer_key_epoch_start",
		"key_id":    marker.Transition.NewKeyID,
		"key_epoch": marker.Transition.NewEpoch,
	}
	startEvent, startFound, err := spool.findRotationEvent(
		"observer_key_epoch_start",
		marker.Transition.NewKeyID,
		marker.StartSequence,
		startFields,
	)
	if err != nil {
		_ = state.PersistReadOnly("observer_rotation_epoch_start_invalid")
		return err
	}
	if !startFound {
		if state.Snapshot().LastSequence != marker.StartSequence-1 {
			_ = state.PersistReadOnly(
				"observer_rotation_epoch_start_sequence_lost",
			)
			return fmt.Errorf("observer rotation epoch-start sequence lost")
		}
		startSigner := &EnvelopeSigner{
			config: SignerConfig{
				HostID:        hostID,
				BootID:        bootID,
				KeyEpoch:      marker.Transition.NewEpoch,
				SourceID:      "agmind-observerd",
				SourceVersion: "0.1.0",
				Now:           options.now,
			},
			state:      state,
			spool:      spool,
			privateKey: append(ed25519.PrivateKey(nil), newPrivate...),
			keyID:      marker.Transition.NewKeyID,
		}
		mode := rotationEpochStartMode(
			state.Snapshot(),
			marker,
			transitionEvent,
		)
		if mode == rotationBoundaryInvalid {
			_ = state.PersistReadOnly(
				"observer_rotation_epoch_start_authorization_invalid",
			)
			return ErrRotationPublicationMismatch
		}
		eventMetadata, err := rotationMetadata(
			options.now(),
			startFields,
			rotationCoverageFlags(
				mode,
				rotationEpochStartPublication,
			)...,
		)
		if err != nil {
			return err
		}
		startEvent, err = startSigner.wrapAuthorizedRotationLocked(
			context.Background(),
			marker,
			rotationEpochStartPublication,
			"observer_key_epoch_start",
			startFields,
			eventMetadata,
		)
		if err != nil {
			if errors.Is(err, ErrRotationPublicationMismatch) {
				return errors.Join(
					err,
					state.PersistReadOnly(
						"observer_rotation_epoch_start_authorization_invalid",
					),
				)
			}
			return err
		}
		if startEvent.SourceSequence != marker.StartSequence {
			_ = state.PersistReadOnly(
				"observer_rotation_epoch_start_sequence_lost",
			)
			return fmt.Errorf("observer rotation epoch-start sequence mismatch")
		}
	}
	if options.stopAfter == "start_durable" ||
		options.stopAfter == "start_spooled_metadata_old" {
		return ErrInjectedRotationStop
	}
	if state.Snapshot().KeyID != marker.Transition.NewKeyID ||
		state.Snapshot().KeyEpoch != marker.Transition.NewEpoch {
		_ = state.PersistReadOnly(
			"observer_rotation_epoch_start_activation_missing",
		)
		return ErrRotationPublicationMismatch
	}
	state.publicationMutex.Unlock()
	rotationPublicationLocked = false
	if state.Snapshot().BootBoundaryState == bootBoundaryPending {
		currentSigner, signerErr := NewEnvelopeSigner(
			SignerConfig{
				HostID:        hostID,
				BootID:        bootID,
				KeyEpoch:      marker.Transition.NewEpoch,
				SourceID:      "agmind-observerd",
				SourceVersion: "0.1.0",
				Now:           options.now,
			},
			state,
			spool,
			newPrivate,
		)
		if signerErr != nil {
			return signerErr
		}
		if boundaryErr := ensureDedicatedBootBoundary(
			context.Background(),
			state,
			currentSigner,
			options.now(),
		); boundaryErr != nil {
			return boundaryErr
		}
	}
	if err := durablefile.AtomicWrite(config.PrivateKeyFile, newPrivate); err != nil {
		return err
	}
	newEntry := PublicKeyEpoch{
		KeyID:              marker.Transition.NewKeyID,
		Epoch:              marker.Transition.NewEpoch,
		PublicKey:          marker.Transition.NewPublicKey,
		Transition:         &marker.Transition,
		TransitionEnvelope: &transitionEvent,
		EpochStartEnvelope: &startEvent,
	}
	switch metadata.CurrentEpoch {
	case marker.Transition.OldEpoch:
		if metadata.CurrentKeyID != marker.Transition.OldKeyID ||
			len(metadata.Keys) != int(marker.Transition.OldEpoch) {
			_ = state.PersistReadOnly(
				"observer_public_key_metadata_mismatch",
			)
			return fmt.Errorf("observer public key metadata mismatch")
		}
		metadata.Keys = append(metadata.Keys, newEntry)
		metadata.CurrentKeyID = marker.Transition.NewKeyID
		metadata.CurrentEpoch = marker.Transition.NewEpoch
	case marker.Transition.NewEpoch:
		if metadata.CurrentKeyID != marker.Transition.NewKeyID ||
			len(metadata.Keys) != int(marker.Transition.NewEpoch) ||
			!canonicalEqual(
				metadata.Keys[len(metadata.Keys)-1],
				newEntry,
			) {
			_ = state.PersistReadOnly(
				"observer_public_key_metadata_mismatch",
			)
			return fmt.Errorf("observer public key metadata mismatch")
		}
	default:
		_ = state.PersistReadOnly("observer_public_key_metadata_mismatch")
		return fmt.Errorf("observer public key metadata mismatch")
	}
	metadataCommitErr := options.saveMetadata(config.StateDir, metadata)
	if metadataCommitErr != nil {
		if errors.Is(metadataCommitErr, durablefile.ErrCommitUncertain) {
			if reconcileErr := reconcileUncertainPublicMetadataCommit(
				config.StateDir,
				metadata,
				options.syncMetadataDirectory,
			); reconcileErr == nil {
				metadataCommitErr = nil
			} else {
				metadataCommitErr = errors.Join(
					metadataCommitErr,
					reconcileErr,
				)
			}
		}
		if metadataCommitErr != nil {
			return errors.Join(
				metadataCommitErr,
				state.persistRotationIncomplete(),
			)
		}
	}
	if options.stopAfter == "metadata_committed" {
		return ErrInjectedRotationStop
	}
	marker.Stage = "start_spooled"
	if err := saveRotationMarker(config.StateDir, marker); err != nil {
		return err
	}
	if options.stopAfter == marker.Stage {
		return ErrInjectedRotationStop
	}
	if err := removeExactRotationArtifact(
		rotationKeyPath(config.StateDir),
		newPrivate,
		ed25519.PrivateKeySize,
	); err != nil {
		return err
	}
	if options.stopAfter == "rotation_key_removed" {
		return ErrInjectedRotationStop
	}
	markerRaw, err := contracts.CanonicalJSON(marker)
	if err != nil {
		return err
	}
	if err := removeExactRotationArtifact(
		markerPath(config.StateDir),
		markerRaw,
		65_536,
	); err != nil {
		return err
	}
	if options.stopAfter == "marker_removed" {
		return ErrInjectedRotationStop
	}
	return nil
}
