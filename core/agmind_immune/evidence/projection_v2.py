"""Dormant Projection V2 schema identity and strict persisted-fact codecs."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
from _thread import LockType
from _thread import RLock as RLockType
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from threading import Condition, Lock, RLock
from typing import cast

from pydantic import ValidationError

from agmind_immune.canonicaljson import candidate_facts_sha256, canonical_json
from agmind_immune.contracts import (
    MAX_UINT64,
    CoverageEventV1,
    EventEnvelopeV1,
    FalcoConnectV1,
    decode_strict,
)
from agmind_immune.correlation.authority import (
    CorrelationProjectionAuthority,
    _advance_correlation_projection_authority,
    _capture_correlation_replay_locked,
    _close_correlation_projection_authority,
    _correlation_projection_snapshot_gate,
    _CorrelationReplaySnapshot,
    _create_correlation_projection_authority,
    _issue_correlation_context,
    _ProjectionPredecessor,
    _rebuild_correlation_projection_authority,
    _revalidate_correlation_replay_locked,
    _same_exact_pcc,
    _seal_projection_predecessor,
    _validate_correlation_projection_predecessor,
)
from agmind_immune.correlation.pcc import (
    ActiveCandidateObservation,
    CandidateCreated,
    CandidateDuplicateKey,
    CorrelationContext,
    CorrelationProjectionError,
    Duplicate,
    HistoricalCoverageAssessment,
    InvestigationOnly,
    Rejected,
    _correlate_frozen_pcc,
    _duplicate_key,
    _freeze_replay_pcc_seed,
    _FrozenPCCCorrelationInput,
    _incident_from_frozen_falco,
    _rebind_frozen_pcc_projection_context,
    _validate_frozen_pcc_correlation_input,
    correlate_pcc,
    incident_from_verified_falco,
)
from agmind_immune.correlation.primitives import SpecialUseRegistry
from agmind_immune.coverage.historical import (
    HistoricalCoverageConflict,
    HistoricalCoverageUnavailable,
    _build_frozen_replay_entries,
    _build_replay_memo_leaf,
    _build_replay_pcc_leaf,
    _derive_replay_historical_coverage,
    _FrozenReplayEntry,
    _HistoricalReductionResult,
    _issue_replay_historical_path_authority,
    _late_coverage_invalidates_candidate,
    _late_coverage_invalidates_candidate_values,
    _late_coverage_may_invalidate_candidate,
    _prepare_historical_record,
    _reduce_historical_coverage_result,
    _replay_compact_digest,
    _replay_exact_fact,
    _ReplayMemoLeaf,
    _ReplayPCCLeaf,
)
from agmind_immune.evidence.dedup import _logical_primary_identity_v2
from agmind_immune.evidence.frames import JournalCorrupt, decode_frames
from agmind_immune.evidence.projection import (
    ProjectionApplyResult,
    ProjectionAuthorityError,
    ProjectionConflict,
    ProjectionCursor,
    ProjectionStatus,
    ProjectionUnhealthy,
    ProjectionValidationError,
)
from agmind_immune.evidence.segments import (
    MAX_EVIDENCE_RECORD_BYTES,
    MAX_SEGMENT_BYTES,
    EvidencePriority,
    EvidenceRef,
    EvidenceStatus,
    EvidenceStoreError,
    SegmentStore,
    StoredEvidenceRecord,
    _AcceptedEnvelopeRecordV1,
    _close_replay_source_snapshot,
    _exact_coverage_record_key,
    _exact_coverage_ref_key,
    _ReplayRecordDescriptor,
    _ReplaySegmentDescriptor,
    _ReplaySourceSnapshot,
)
from agmind_immune.incidents.models import ContainmentCandidateV1, IncidentV1
from agmind_immune.ingest.ack_journal import (
    _ACK_UNPUBLISHED_ANCHOR_FACTORY,
    AckIdentity,
    AckJournal,
    AckJournalError,
    AckJournalSnapshot,
    _AckJournalRecordV1,
    _AckReplaySnapshot,
    _AckUnpublishedAnchor,
    _close_replay_ack_snapshot,
)
from agmind_immune.ingest.ack_journal import (
    _MAX_RECORD_BYTES as _MAX_ACK_RECORD_BYTES,
)
from agmind_immune.ingest.correlation_journal import (
    CorrelationRequestJournal,
    CorrelationRequestJournalError,
    _capture_correlation_journal_replay_locked,
    _correlation_journal_replay_gate,
    _CorrelationJournalReplaySnapshot,
    _evaluate_completed_snapshot_batch,
    _revalidate_completed_snapshot,
    _revalidate_correlation_journal_replay_locked,
)
from agmind_immune.ingest.envelope import AuthenticatedPCCInput

_SCHEMA_V2_PATH = Path(__file__).with_name("schema_v2.sql")
_SCHEMA_V2_SHA256 = "d4a5d563ca3964cbe4ed276882a4b4def95fb756fc67a6777fddf5de38b1619d"
_SCHEMA_META_V2 = {
    "schema_version": "agmind.projection-schema.v2",
    "reducer_version": "agmind.projection-reducer.v2",
    "dedup_version": "AGMIND_PROJECTION_DEDUP_V2",
    "snapshot_layout": "AGMIND_PROJECTION_SNAPSHOT_V2",
}
_SNAPSHOT_DOMAIN_V2 = b"AGMIND_PROJECTION_SNAPSHOT_V2\0"
_REPLAY_SCHEMA_DOMAIN_V2 = b"AGMIND_PROJECTION_SCHEMA_V2\0"
_REPLAY_TRANSCRIPT_DOMAIN_V2 = b"AGMIND_PROJECTION_REPLAY_TRANSCRIPT_V2\0"
_REPLAY_REPORT_DOMAIN_V2 = b"AGMIND_PROJECTION_REPLAY_REPORT_V2\0"
_UNPUBLISHED_REPLAY_FACTORY = object()
_UINT64_V2 = re.compile(r"^[0-9]{20}$")
_EVENT_ID_V2 = re.compile(r"^evt_[0-9a-f]{64}$")
_CANDIDATE_ID_V2 = re.compile(r"^cand_[0-9a-f]{64}$")
_HEX64_V2 = re.compile(r"^[0-9a-f]{64}$")
_UUID4_V2 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_ACCEPTED_AT_V2 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
_MAX_CANONICAL_ENVELOPE_BYTES_V2 = 64 * 1024
_RESULT_KINDS_V2 = frozenset({"candidate", "investigation", "duplicate", "rejected"})
_EVIDENCE_ROLES_V2 = frozenset(
    {
        "primary_trigger",
        "correlation_snapshot",
        "supporting_trigger",
        "supporting_snapshot",
    }
)
_INVALIDATION_REASON_V2 = "late_critical_coverage_gap"
_INVALIDATION_CANDIDATE_CAP_V2 = 4_096
_INCIDENT_UINT64_FIELDS = frozenset({"primary_source_sequence"})
_INCIDENT_BOOL_FIELDS = frozenset({"successful_connect", "investigation_only"})
_INCIDENT_TUPLE_FIELDS = frozenset(
    {"missing_required_fields", "coverage_flags", "evidence_ids", "reason_codes"}
)
_INCIDENT_OPTIONAL_FIELDS_V2 = frozenset(
    {
        "docker_container_id",
        "docker_started_at",
        "proc_name",
        "proc_exe_path",
        "proc_parent_name",
        "destination_ipv4",
        "destination_port",
        "l4_protocol",
    }
)
_CANDIDATE_UINT64_FIELDS = frozenset(
    {"primary_source_sequence", "inventory_generation", "inventory_revision"}
)
_CANDIDATE_TUPLE_FIELDS = frozenset({"repo_digests", "evidence_ids"})
_INCIDENT_COLUMNS = tuple(IncidentV1.model_fields) + ("result_kind",)
_CANDIDATE_COLUMNS = tuple(ContainmentCandidateV1.model_fields) + (
    "candidate_facts_sha256",
)
_TABLE_LAYOUT_V2: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("schema_meta", ("key", "value"), ("key",)),
    (
        "events",
        (
            "event_id",
            "host_id",
            "source_sequence",
            "event_type",
            "source_id",
            "source_version",
            "key_id",
            "key_epoch",
            "boot_id",
            "event_time",
            "ingest_time",
            "clock_uncertainty_ms",
            "container_id",
            "container_start_time",
            "release_id",
            "inventory_generation",
            "inventory_revision",
            "normalized_fields_json",
            "normalized_fields_sha256",
            "redaction_flags_json",
            "coverage_flags_json",
            "source_payload_hash",
            "source_signature",
            "segment_id",
            "segment_relative_path",
            "frame_offset",
            "frame_size",
            "frame_sha256",
            "canonical_sha256",
            "content_sha256",
            "duplicate_of_event_id",
        ),
        ("event_id",),
    ),
    (
        "projection_dedup",
        ("event_id", "dedup_kind", "logical_key_sha256", "primary_event_id", "is_primary"),
        ("event_id",),
    ),
    (
        "coverage_intervals",
        (
            "event_id",
            "host_id",
            "component",
            "kind",
            "severity",
            "opened_at",
            "closed_at",
            "affected_source_sequence_start",
            "affected_source_sequence_end",
            "dropped_count",
            "reason_code",
            "reconcile_generation",
            "source_sequence",
            "content_sha256",
        ),
        ("event_id",),
    ),
    (
        "containers",
        (
            "host_id",
            "container_id",
            "container_started_at",
            "image_id",
            "repo_digests_json",
            "immutable_spec_sha256",
            "inventory_revision",
            "first_event_id",
            "first_source_sequence",
            "first_content_sha256",
            "last_event_id",
            "last_source_sequence",
            "last_content_sha256",
        ),
        ("host_id", "container_id", "container_started_at"),
    ),
    (
        "process_observations",
        (
            "event_id",
            "host_id",
            "container_id",
            "container_started_at",
            "proc_name",
            "proc_exe_path",
            "proc_parent_name",
            "source_sequence",
            "content_sha256",
        ),
        ("event_id",),
    ),
    (
        "network_observations",
        (
            "event_id",
            "host_id",
            "container_id",
            "container_started_at",
            "successful_connect",
            "destination_ipv4",
            "destination_port",
            "l4_protocol",
            "investigation_only",
            "source_sequence",
            "content_sha256",
        ),
        ("event_id",),
    ),
    ("incidents", _INCIDENT_COLUMNS, ("incident_id",)),
    ("candidates", _CANDIDATE_COLUMNS, ("candidate_id",)),
    (
        "candidate_evidence",
        (
            "candidate_id",
            "evidence_event_id",
            "evidence_source_sequence",
            "evidence_content_sha256",
            "role",
            "authority_snapshot_event_id",
        ),
        ("candidate_id", "evidence_event_id", "role", "authority_snapshot_event_id"),
    ),
    (
        "candidate_invalidations",
        (
            "candidate_id",
            "coverage_event_id",
            "coverage_source_sequence",
            "coverage_content_sha256",
            "reason_code",
        ),
        ("candidate_id", "coverage_event_id"),
    ),
    (
        "ingest_cursors",
        (
            "host_id",
            "source_sequence",
            "event_id",
            "content_sha256",
            "segment_id",
            "segment_relative_path",
            "frame_offset",
            "frame_size",
            "frame_sha256",
        ),
        ("host_id",),
    ),
)
_TABLE_NAMES_V2 = frozenset(item[0] for item in _TABLE_LAYOUT_V2)
_APPLY_STEPS_V2 = ("event", "dedup", "reducer", "cursor")
_CANDIDATE_STEPS_V2 = (
    "incident",
    "candidate",
    "candidate_evidence_trigger",
    "candidate_evidence_snapshot",
)


@dataclass(frozen=True)
class _PreparedV2Record:
    record: StoredEvidenceRecord
    envelope: EventEnvelopeV1
    dedup_kind: str
    logical_key_sha256: str
    falco: FalcoConnectV1 | None
    coverage: CoverageEventV1 | None


@dataclass(frozen=True, slots=True)
class _LateCandidateV2:
    candidate: ContainmentCandidateV1
    snapshot_ref: EvidenceRef


@dataclass(frozen=True, slots=True)
class _UnpublishedV2ReplayReport:
    cursor: ProjectionCursor
    applied_count: int
    prefix_sha256: str


class _ReplayPhase(StrEnum):
    IDLE = "idle"
    FREEZING = "freezing"
    COMPUTING = "computing"
    VALIDATING = "validating"
    PUBLISHED = "published"
    FAILED = "failed"


class _ReplayFaultPhase(StrEnum):
    FREEZE = "freeze"
    COMPUTE = "compute"
    PUBLISH = "publish"


@dataclass(frozen=True, slots=True)
class _ReplayStatus:
    generation: int
    phase: _ReplayPhase
    reservation_present: bool


@dataclass(frozen=True, slots=True)
class _ReplayReservation:
    token: object
    base_generation: int
    publish_generation: int
    through_key: tuple[str, str, int, int, str, str, int, str]


@dataclass(slots=True)
class _ReplayTestBarrier:
    phase: _ReplayPhase
    released: bool = False


@dataclass(frozen=True, slots=True)
class _ReplayInputSnapshot:
    source: _ReplaySourceSnapshot
    ack: _AckReplaySnapshot
    correlation: _CorrelationReplaySnapshot
    pcc_inputs: tuple[_FrozenPCCCorrelationInput, ...]
    schema_domain: bytes
    base_projection_generation: int
    publish_generation: int


@dataclass(frozen=True, slots=True)
class _ReplayComputation:
    database_image: bytes
    transcript_count: int
    transcript_digest: bytes
    pcc_leaves: tuple[_ReplayPCCLeaf, ...]
    memo_leaves: tuple[_ReplayMemoLeaf, ...]
    late_invalidations: tuple[object, ...]
    terminal_predecessor: _ProjectionPredecessor
    administrative_visits: int
    semantic_prefix_visits: int
    report_bytes: bytes
    prefix_sha256: str


@dataclass(slots=True)
class _ReplayComputeCounters:
    administrative_visits: int = 0
    semantic_prefix_visits: int = 0


def _encode_uint64_v2(value: object) -> str:
    if type(value) is not int:
        raise TypeError("Projection V2 uint64 must be an exact integer")
    if not 0 <= value < 2**64:
        raise ValueError("Projection V2 uint64 is out of range")
    return f"{value:020d}"


def _decode_uint64_v2(value: object) -> int:
    if type(value) is not str or _UINT64_V2.fullmatch(value) is None:
        raise ProjectionConflict("Projection V2 row contains a non-canonical uint64")
    decoded = int(value)
    if decoded >= 2**64:
        raise ProjectionConflict("Projection V2 row contains an overflowing uint64")
    return decoded


def _decode_bool_v2(value: object) -> bool:
    if type(value) is not int or value not in (0, 1):
        raise ProjectionConflict("Projection V2 row contains a non-canonical Boolean")
    return bool(value)


def _encode_tuple_v2(value: object) -> str:
    if type(value) is not tuple:
        raise TypeError("Projection V2 tuple field must be an exact tuple")
    return canonical_json(value).decode("utf-8")


def _decode_tuple_v2(value: object) -> tuple[object, ...]:
    if type(value) is not str:
        raise ProjectionConflict("Projection V2 tuple JSON must be exact text")
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ProjectionConflict("Projection V2 tuple JSON is invalid") from error
    try:
        canonical = canonical_json(decoded).decode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ProjectionConflict("Projection V2 tuple JSON is invalid") from error
    if type(decoded) is not list or canonical != value:
        raise ProjectionConflict("Projection V2 tuple JSON is not canonical")
    return tuple(decoded)


def _row_values_v2(
    row: sqlite3.Row | Sequence[object],
    columns: tuple[str, ...],
) -> tuple[object, ...]:
    if isinstance(row, sqlite3.Row):
        if tuple(row.keys()) != columns:
            raise ProjectionConflict("Projection V2 row columns are not exact")
        values = tuple(row)
    elif type(row) is tuple:
        values = row
    else:
        raise ProjectionConflict("Projection V2 row type is not exact")
    if len(values) != len(columns):
        raise ProjectionConflict("Projection V2 row width is not exact")
    return values


def _validated_incident_for_encoding(incident: IncidentV1) -> IncidentV1:
    fields_set = incident.model_fields_set
    known_fields = frozenset(IncidentV1.model_fields)
    if type(fields_set) is not set or not fields_set <= known_fields:
        raise ValueError("Projection V2 incident fields-set is invalid")
    document = {field: getattr(incident, field) for field in fields_set}
    validated = IncidentV1.model_validate(document, strict=True)
    if validated.model_fields_set != fields_set:
        raise ValueError("Projection V2 incident fields-set changed during validation")
    for field in IncidentV1.model_fields:
        original_value = getattr(incident, field)
        validated_value = getattr(validated, field)
        if type(original_value) is not type(validated_value) or original_value != validated_value:
            raise ValueError("Projection V2 incident changed during strict reconstruction")
    return validated


def _validated_candidate_for_encoding(
    candidate: ContainmentCandidateV1,
) -> ContainmentCandidateV1:
    fields_set = candidate.model_fields_set
    known_fields = frozenset(ContainmentCandidateV1.model_fields)
    if type(fields_set) is not set or not fields_set <= known_fields:
        raise ValueError("Projection V2 candidate fields-set is invalid")
    document = {field: getattr(candidate, field) for field in fields_set}
    validated = ContainmentCandidateV1.model_validate(document, strict=True)
    if validated.model_fields_set != fields_set:
        raise ValueError("Projection V2 candidate fields-set changed during validation")
    for field in ContainmentCandidateV1.model_fields:
        original_value = getattr(candidate, field)
        validated_value = getattr(validated, field)
        if type(original_value) is not type(validated_value) or original_value != validated_value:
            raise ValueError("Projection V2 candidate changed during strict reconstruction")
    return validated


def _encode_incident(incident: IncidentV1, result_kind: str) -> tuple[object, ...]:
    if type(incident) is not IncidentV1:
        raise TypeError("Projection V2 incident must use the exact model type")
    if type(result_kind) is not str or result_kind not in _RESULT_KINDS_V2:
        raise ValueError("Projection V2 incident result kind is not closed")
    validated = _validated_incident_for_encoding(incident)
    document = validated.model_dump(mode="python", exclude_unset=True)
    encoded: list[object] = []
    for field in IncidentV1.model_fields:
        value = document.get(field)
        if field in _INCIDENT_UINT64_FIELDS:
            value = _encode_uint64_v2(value)
        elif field in _INCIDENT_BOOL_FIELDS:
            if type(value) is not bool:
                raise TypeError("Projection V2 incident Boolean is not exact")
            value = int(value)
        elif field in _INCIDENT_TUPLE_FIELDS:
            value = _encode_tuple_v2(value)
        encoded.append(value)
    encoded.append(result_kind)
    return tuple(encoded)


def _decode_incident(
    row: sqlite3.Row | Sequence[object],
) -> tuple[IncidentV1, str]:
    values = _row_values_v2(row, _INCIDENT_COLUMNS)
    result_kind = values[-1]
    if type(result_kind) is not str or result_kind not in _RESULT_KINDS_V2:
        raise ProjectionConflict("Projection V2 incident result kind is invalid")
    document: dict[str, object] = {}
    try:
        for field, value in zip(IncidentV1.model_fields, values[:-1], strict=True):
            if field in _INCIDENT_OPTIONAL_FIELDS_V2 and value is None:
                continue
            if value is None:
                raise ProjectionConflict("Projection V2 incident lost a required field")
            if field in _INCIDENT_UINT64_FIELDS:
                value = _decode_uint64_v2(value)
            elif field in _INCIDENT_BOOL_FIELDS:
                value = _decode_bool_v2(value)
            elif field in _INCIDENT_TUPLE_FIELDS:
                value = _decode_tuple_v2(value)
            document[field] = value
        incident = IncidentV1.model_validate(document, strict=True)
    except ProjectionConflict:
        raise
    except (TypeError, ValueError, ValidationError) as error:
        raise ProjectionConflict("Projection V2 incident row is invalid") from error
    return incident, result_kind


def _encode_candidate(candidate: ContainmentCandidateV1) -> tuple[object, ...]:
    if type(candidate) is not ContainmentCandidateV1:
        raise TypeError("Projection V2 candidate must use the exact model type")
    validated = _validated_candidate_for_encoding(candidate)
    document = validated.model_dump(mode="python")
    encoded: list[object] = []
    for field in ContainmentCandidateV1.model_fields:
        value = document[field]
        if field in _CANDIDATE_UINT64_FIELDS:
            value = _encode_uint64_v2(value)
        elif field in _CANDIDATE_TUPLE_FIELDS:
            value = _encode_tuple_v2(value)
        encoded.append(value)
    encoded.append(candidate_facts_sha256(validated))
    return tuple(encoded)


def _decode_candidate(row: sqlite3.Row | Sequence[object]) -> ContainmentCandidateV1:
    values = _row_values_v2(row, _CANDIDATE_COLUMNS)
    stored_hash = values[-1]
    if type(stored_hash) is not str or _HEX64_V2.fullmatch(stored_hash) is None:
        raise ProjectionConflict("Projection V2 candidate facts hash is invalid")
    document: dict[str, object] = {}
    try:
        for field, value in zip(ContainmentCandidateV1.model_fields, values[:-1], strict=True):
            if value is None:
                raise ProjectionConflict("Projection V2 candidate lost a required field")
            if field in _CANDIDATE_UINT64_FIELDS:
                value = _decode_uint64_v2(value)
            elif field in _CANDIDATE_TUPLE_FIELDS:
                value = _decode_tuple_v2(value)
            document[field] = value
        candidate = ContainmentCandidateV1.model_validate(document, strict=True)
    except ProjectionConflict:
        raise
    except (TypeError, ValueError, ValidationError) as error:
        raise ProjectionConflict("Projection V2 candidate row is invalid") from error
    if candidate_facts_sha256(candidate) != stored_hash:
        raise ProjectionConflict("Projection V2 candidate facts hash changed")
    return candidate


def _candidate_duplicate_key_from_row(
    row: sqlite3.Row | Sequence[object],
) -> tuple[str, str, str, str, str, str]:
    values = _row_values_v2(row, _CANDIDATE_COLUMNS)
    candidate = _decode_candidate(values)
    raw = dict(zip(_CANDIDATE_COLUMNS, values, strict=True))
    expected: tuple[tuple[str, object], ...] = (
        ("host_id", candidate.host_id),
        ("boot_id", candidate.boot_id),
        ("docker_container_id", candidate.docker_container_id),
        ("docker_started_at", candidate.docker_started_at),
        ("detector_bundle_sha256", candidate.detector_bundle_sha256),
        ("destination_ipv4", candidate.destination_ipv4),
        ("primary_source_sequence", _encode_uint64_v2(candidate.primary_source_sequence)),
        ("primary_event_id", candidate.primary_event_id),
        ("candidate_id", candidate.candidate_id),
    )
    if any(raw[field] != wanted for field, wanted in expected):
        raise ProjectionConflict("Projection V2 candidate lookup index values changed")
    return (
        candidate.host_id,
        candidate.boot_id,
        candidate.docker_container_id,
        candidate.docker_started_at,
        candidate.detector_bundle_sha256,
        candidate.destination_ipv4,
    )


def _validate_identity_v2(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str:
        raise TypeError(f"Projection V2 {label} must be exact text")
    if pattern.fullmatch(value) is None:
        raise ValueError(f"Projection V2 {label} is invalid")
    return value


def _encode_candidate_evidence(
    candidate_id: str,
    evidence_event_id: str,
    evidence_source_sequence: int,
    evidence_content_sha256: str,
    role: str,
    authority_snapshot_event_id: str,
) -> tuple[object, ...]:
    if type(role) is not str or role not in _EVIDENCE_ROLES_V2:
        raise ValueError("Projection V2 evidence role is not closed")
    return (
        _validate_identity_v2(candidate_id, _CANDIDATE_ID_V2, "candidate ID"),
        _validate_identity_v2(evidence_event_id, _EVENT_ID_V2, "evidence event ID"),
        _encode_uint64_v2(evidence_source_sequence),
        _validate_identity_v2(evidence_content_sha256, _HEX64_V2, "evidence hash"),
        role,
        _validate_identity_v2(
            authority_snapshot_event_id,
            _EVENT_ID_V2,
            "authority snapshot event ID",
        ),
    )


def _decode_candidate_evidence(
    row: sqlite3.Row | Sequence[object],
) -> tuple[str, str, int, str, str, str]:
    values = _row_values_v2(row, _TABLE_LAYOUT_V2[9][1])
    try:
        candidate_id = _validate_identity_v2(values[0], _CANDIDATE_ID_V2, "candidate ID")
        evidence_event_id = _validate_identity_v2(values[1], _EVENT_ID_V2, "evidence event ID")
        source_sequence = _decode_uint64_v2(values[2])
        content_hash = _validate_identity_v2(values[3], _HEX64_V2, "evidence hash")
        role = values[4]
        if type(role) is not str or role not in _EVIDENCE_ROLES_V2:
            raise ValueError("Projection V2 evidence role is invalid")
        authority_event_id = _validate_identity_v2(
            values[5], _EVENT_ID_V2, "authority snapshot event ID"
        )
    except ProjectionConflict:
        raise
    except (TypeError, ValueError) as error:
        raise ProjectionConflict("Projection V2 candidate evidence row is invalid") from error
    return (
        candidate_id,
        evidence_event_id,
        source_sequence,
        content_hash,
        role,
        authority_event_id,
    )


def _encode_candidate_invalidation(
    candidate_id: str,
    coverage_event_id: str,
    coverage_source_sequence: int,
    coverage_content_sha256: str,
    reason_code: str,
) -> tuple[object, ...]:
    if type(reason_code) is not str or reason_code != _INVALIDATION_REASON_V2:
        raise ValueError("Projection V2 invalidation reason is not closed")
    return (
        _validate_identity_v2(candidate_id, _CANDIDATE_ID_V2, "candidate ID"),
        _validate_identity_v2(coverage_event_id, _EVENT_ID_V2, "coverage event ID"),
        _encode_uint64_v2(coverage_source_sequence),
        _validate_identity_v2(coverage_content_sha256, _HEX64_V2, "coverage hash"),
        reason_code,
    )


def _decode_candidate_invalidation(
    row: sqlite3.Row | Sequence[object],
) -> tuple[str, str, int, str, str]:
    values = _row_values_v2(row, _TABLE_LAYOUT_V2[10][1])
    try:
        candidate_id = _validate_identity_v2(values[0], _CANDIDATE_ID_V2, "candidate ID")
        coverage_event_id = _validate_identity_v2(values[1], _EVENT_ID_V2, "coverage event ID")
        source_sequence = _decode_uint64_v2(values[2])
        content_hash = _validate_identity_v2(values[3], _HEX64_V2, "coverage hash")
        reason_code = values[4]
        if type(reason_code) is not str or reason_code != _INVALIDATION_REASON_V2:
            raise ValueError("Projection V2 invalidation reason is invalid")
    except ProjectionConflict:
        raise
    except (TypeError, ValueError) as error:
        raise ProjectionConflict("Projection V2 candidate invalidation row is invalid") from error
    return candidate_id, coverage_event_id, source_sequence, content_hash, reason_code


def _configure_v2_connection(connection: sqlite3.Connection, *, file_backed: bool) -> None:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
    connection.execute("PRAGMA synchronous=FULL")
    expected_mode = "wal" if file_backed else "memory"
    if mode != expected_mode:
        raise ProjectionConflict("Projection V2 did not enter its safe journal mode")


def _verify_v2_pragmas(connection: sqlite3.Connection) -> None:
    database_path = str(connection.execute("PRAGMA database_list").fetchone()[2])
    expected: tuple[tuple[str, object], ...] = (
        ("journal_mode", "wal" if database_path else "memory"),
        ("synchronous", 2),
        ("foreign_keys", 1),
        ("trusted_schema", 0),
        ("busy_timeout", 5000),
        ("ignore_check_constraints", 0),
    )
    for pragma, wanted in expected:
        actual = connection.execute(f"PRAGMA {pragma}").fetchone()[0]
        if isinstance(wanted, str):
            actual = str(actual).lower()
        if actual != wanted:
            raise ProjectionConflict(f"Projection V2 PRAGMA {pragma} is unsafe")


def _create_v2_schema(connection: sqlite3.Connection) -> None:
    try:
        raw = _SCHEMA_V2_PATH.read_bytes()
    except OSError as error:
        raise ProjectionConflict("Projection V2 trusted schema bytes are unavailable") from error
    if hashlib.sha256(raw).hexdigest() != _SCHEMA_V2_SHA256:
        raise ProjectionConflict("Projection V2 trusted schema bytes changed")
    try:
        script = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ProjectionConflict("Projection V2 trusted schema is not UTF-8") from error
    connection.executescript(script)


def _schema_rows(connection: sqlite3.Connection) -> list[tuple[object, ...]]:
    return [
        tuple(row)
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE sql IS NOT NULL ORDER BY type,name"
        )
    ]


def _verify_v2_schema(connection: sqlite3.Connection) -> None:
    try:
        actual_tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if actual_tables != _TABLE_NAMES_V2:
            raise ProjectionConflict("Projection V2 table set is not exact")
        expected = sqlite3.connect(":memory:", isolation_level=None)
        try:
            _configure_v2_connection(expected, file_backed=False)
            _create_v2_schema(expected)
            expected_schema = _schema_rows(expected)
        finally:
            expected.close()
        if _schema_rows(connection) != expected_schema:
            raise ProjectionConflict("Projection V2 schema definition is not exact")
        metadata = dict(connection.execute("SELECT key,value FROM schema_meta ORDER BY key"))
        if metadata != _SCHEMA_META_V2:
            raise ProjectionConflict("Projection V2 metadata is not exact")
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if [str(row[0]) for row in integrity] != ["ok"]:
            raise ProjectionConflict("Projection V2 integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ProjectionConflict("Projection V2 foreign-key check failed")
        _verify_v2_pragmas(connection)
    except ProjectionConflict:
        raise
    except (sqlite3.DatabaseError, TypeError, ValueError) as error:
        raise ProjectionConflict("Projection V2 schema verification failed") from error


def _v2_connection_for_test(path: Path | None = None) -> sqlite3.Connection:
    connection = sqlite3.connect(
        ":memory:" if path is None else path,
        isolation_level=None,
        check_same_thread=False,
    )
    try:
        _configure_v2_connection(connection, file_backed=path is not None)
        existing_tables = connection.execute(
            "SELECT count(*) FROM sqlite_schema "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()[0]
        if existing_tables == 0:
            _create_v2_schema(connection)
        _verify_v2_schema(connection)
    except BaseException:
        connection.close()
        raise
    return connection


def _ordered_v2_rows_unverified(
    connection: sqlite3.Connection,
    table: str,
) -> list[tuple[object, ...]]:
    try:
        layout = next(item for item in _TABLE_LAYOUT_V2 if item[0] == table)
    except StopIteration as error:
        raise ProjectionConflict("Projection V2 table selection is not frozen") from error
    _table, columns, primary_key = layout
    selected = ",".join(columns)
    order = ",".join(f"{column} COLLATE BINARY" for column in primary_key)
    try:
        rows = connection.execute(
            f"SELECT {selected} FROM {table} ORDER BY {order}"
        ).fetchall()
        for row in rows:
            if table == "incidents":
                _decode_incident(row)
            elif table == "candidates":
                _candidate_duplicate_key_from_row(row)
            elif table == "candidate_evidence":
                _decode_candidate_evidence(row)
            elif table == "candidate_invalidations":
                _decode_candidate_invalidation(row)
        return [tuple(row) for row in rows]
    except ProjectionConflict:
        raise
    except (sqlite3.DatabaseError, TypeError, ValueError) as error:
        raise ProjectionConflict(f"Projection V2 {table} rows are invalid") from error


def _v2_ordered_table_rows(
    connection: sqlite3.Connection,
    table: str,
) -> list[tuple[object, ...]]:
    if type(table) is not str:
        raise ProjectionConflict("Projection V2 table selection is not exact text")
    _verify_v2_schema(connection)
    return _ordered_v2_rows_unverified(connection, table)


def _v2_snapshot_hash(connection: sqlite3.Connection) -> str:
    _verify_v2_schema(connection)
    digest = hashlib.sha256()
    digest.update(_SNAPSHOT_DOMAIN_V2)
    owns_transaction = not connection.in_transaction
    try:
        if owns_transaction:
            connection.execute("BEGIN")
        for table, columns, _primary_key in _TABLE_LAYOUT_V2:
            digest.update(canonical_json({"table": table, "columns": columns}))
            digest.update(b"\n")
            for row in _ordered_v2_rows_unverified(connection, table):
                digest.update(canonical_json({"row": list(row)}))
                digest.update(b"\n")
        if owns_transaction:
            connection.execute("COMMIT")
    except ProjectionConflict:
        if owns_transaction and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except (sqlite3.DatabaseError, TypeError, ValueError, UnicodeError) as error:
        if owns_transaction and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ProjectionConflict("Projection V2 logical snapshot is invalid") from error
    return digest.hexdigest()


def _prepare_v2(record: StoredEvidenceRecord) -> _PreparedV2Record:
    if type(record) is not StoredEvidenceRecord or type(record.ref) is not EvidenceRef:
        raise ProjectionValidationError("Projection V2 record is not exact evidence")
    try:
        _exact_coverage_record_key(record)
        if _ACCEPTED_AT_V2.fullmatch(record.accepted_at) is None:
            raise ValueError("accepted_at is not exact UTC")
        datetime.fromisoformat(record.accepted_at)
        envelope = decode_strict(
            record.canonical_envelope,
            EventEnvelopeV1,
            _MAX_CANONICAL_ENVELOPE_BYTES_V2,
        )
        raw = envelope.model_dump(exclude_none=True)
        if raw != record.envelope:
            raise ValueError("typed envelope differs from stored envelope")
    except (TypeError, ValueError, ValidationError) as error:
        raise ProjectionValidationError("Projection V2 envelope cannot be reparsed") from error
    ref = record.ref
    if (
        type(record.envelope) is not dict
        or canonical_json(raw) != record.canonical_envelope
        or canonical_json(record.envelope) != record.canonical_envelope
        or envelope.event_id != ref.event_id
        or envelope.source_sequence != ref.source_sequence
        or hashlib.sha256(record.canonical_envelope).hexdigest() != ref.content_sha256
    ):
        raise ProjectionValidationError("Projection V2 record outer facts do not bind")
    falco: FalcoConnectV1 | None = None
    coverage: CoverageEventV1 | None = None
    if envelope.event_type == "falco_connect":
        if envelope.normalized_fields.get("raw_event_sha256") != envelope.source_payload_hash:
            raise ProjectionValidationError("Projection V2 Falco raw hash does not bind")
        try:
            falco = FalcoConnectV1.model_validate(envelope.normalized_fields, strict=True)
        except ValidationError as error:
            raise ProjectionValidationError("Projection V2 Falco input is invalid") from error
    elif envelope.event_type == "coverage":
        try:
            coverage = CoverageEventV1.model_validate(envelope.normalized_fields, strict=True)
        except ValidationError as error:
            raise ProjectionValidationError("Projection V2 coverage input is invalid") from error
    kind, identity = _logical_primary_identity_v2(envelope)
    return _PreparedV2Record(record, envelope, kind, identity, falco, coverage)


def _optional_uint64_v2(value: int | None) -> str | None:
    return None if value is None else _encode_uint64_v2(value)


def _event_values_v2(
    prepared: _PreparedV2Record,
    duplicate: str | None,
) -> tuple[object, ...]:
    envelope = prepared.envelope
    ref = prepared.record.ref
    canonical = prepared.record.canonical_envelope
    return (
        envelope.event_id,
        envelope.host_id,
        _encode_uint64_v2(envelope.source_sequence),
        envelope.event_type,
        envelope.source_id,
        envelope.source_version,
        envelope.key_id,
        _encode_uint64_v2(envelope.key_epoch),
        envelope.boot_id,
        envelope.event_time,
        envelope.ingest_time,
        envelope.clock_uncertainty_ms,
        envelope.container_id,
        envelope.container_start_time,
        envelope.release_id,
        _encode_uint64_v2(envelope.inventory_generation),
        _optional_uint64_v2(envelope.inventory_revision),
        canonical_json(envelope.normalized_fields).decode("utf-8"),
        envelope.normalized_fields_sha256,
        canonical_json(envelope.redaction_flags).decode("utf-8"),
        canonical_json(envelope.coverage_flags).decode("utf-8"),
        envelope.source_payload_hash,
        envelope.source_signature,
        ref.segment_id,
        ref.segment_relative_path,
        _encode_uint64_v2(ref.frame_offset),
        _encode_uint64_v2(ref.frame_size),
        ref.frame_sha256,
        hashlib.sha256(canonical).hexdigest(),
        ref.content_sha256,
        duplicate,
    )


def _v2_cursor_from_row(row: sqlite3.Row | None) -> ProjectionCursor | None:
    if row is None:
        return None
    if tuple(row.keys()) != (
        "host_id",
        "source_sequence",
        "event_id",
        "content_sha256",
        "frame_sha256",
    ):
        raise ProjectionConflict("Projection V2 cursor columns are not exact")
    host_id = row["host_id"]
    event_id = row["event_id"]
    content_sha256 = row["content_sha256"]
    frame_sha256 = row["frame_sha256"]
    if (
        type(host_id) is not str
        or _UUID4_V2.fullmatch(host_id) is None
        or type(event_id) is not str
        or _EVENT_ID_V2.fullmatch(event_id) is None
        or type(content_sha256) is not str
        or _HEX64_V2.fullmatch(content_sha256) is None
        or type(frame_sha256) is not str
        or _HEX64_V2.fullmatch(frame_sha256) is None
    ):
        raise ProjectionConflict("Projection V2 cursor identity is invalid")
    return ProjectionCursor(
        host_id=host_id,
        source_sequence=_decode_uint64_v2(row["source_sequence"]),
        event_id=event_id,
        content_sha256=content_sha256,
        frame_sha256=frame_sha256,
    )


def _current_v2_cursor(connection: sqlite3.Connection) -> ProjectionCursor | None:
    rows = connection.execute(
        "SELECT host_id,source_sequence,event_id,content_sha256,frame_sha256 "
        "FROM ingest_cursors ORDER BY host_id"
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict("Projection V2 has multiple single-host cursors")
    return _v2_cursor_from_row(rows[0] if rows else None)


def _current_v2_cursor_ref(connection: sqlite3.Connection) -> EvidenceRef | None:
    rows = connection.execute(
        "SELECT source_sequence,event_id,content_sha256,segment_id,"
        "segment_relative_path,frame_offset,frame_size,frame_sha256 "
        "FROM ingest_cursors ORDER BY host_id"
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict("Projection V2 has multiple single-host cursor refs")
    if not rows:
        return None
    row = rows[0]
    values = tuple(row)
    if len(values) != 8 or any(type(value) is not str for value in values):
        raise ProjectionConflict("Projection V2 cursor ref fields are not exact text")
    try:
        return EvidenceRef(
            segment_id=cast(str, row["segment_id"]),
            segment_relative_path=cast(str, row["segment_relative_path"]),
            frame_offset=_decode_uint64_v2(row["frame_offset"]),
            frame_size=_decode_uint64_v2(row["frame_size"]),
            frame_sha256=_validate_identity_v2(
                row["frame_sha256"], _HEX64_V2, "cursor frame hash"
            ),
            event_id=_validate_identity_v2(
                row["event_id"], _EVENT_ID_V2, "cursor event ID"
            ),
            source_sequence=_decode_uint64_v2(row["source_sequence"]),
            content_sha256=_validate_identity_v2(
                row["content_sha256"], _HEX64_V2, "cursor content hash"
            ),
        )
    except (TypeError, ValueError) as error:
        raise ProjectionConflict("Projection V2 cursor ref is invalid") from error


def _predecessor_v2(
    generation: int,
    cursor: ProjectionCursor | None,
) -> _ProjectionPredecessor:
    if type(generation) is not int or not 1 <= generation <= MAX_UINT64:
        raise ProjectionConflict("Projection V2 generation must be a positive uint64")
    if cursor is None:
        return _ProjectionPredecessor(
            generation=generation,
            host_id=None,
            source_sequence=0,
            event_id=None,
            content_sha256=None,
            frame_sha256=None,
        )
    return _ProjectionPredecessor(
        generation=generation,
        host_id=cursor.host_id,
        source_sequence=cursor.source_sequence,
        event_id=cursor.event_id,
        content_sha256=cursor.content_sha256,
        frame_sha256=cursor.frame_sha256,
    )


@dataclass(frozen=True)
class _ProjectionAckBoundaryV2:
    confirmed: AckIdentity | None
    pending: AckIdentity | None
    generation: int
    prefix_size: int
    prefix_sha256: str

    @property
    def confirmed_through(self) -> int:
        confirmed = self.confirmed
        return 0 if confirmed is None else confirmed.sequence


def _exact_ack_identity_v2(value: object) -> AckIdentity | None:
    if value is None:
        return None
    if (
        type(value) is not AckIdentity
        or type(value.sequence) is not int
        or not 1 <= value.sequence <= MAX_UINT64
        or type(value.event_id) is not str
        or _EVENT_ID_V2.fullmatch(value.event_id) is None
        or type(value.content_sha256) is not str
        or _HEX64_V2.fullmatch(value.content_sha256) is None
    ):
        raise ProjectionAuthorityError(
            "Projection V2 ACK identity is not exact"
        )
    return value


def _healthy_acceptance_cursor_v2(
    store: SegmentStore,
    lifecycle: object,
) -> int:
    try:
        status = store.status()
    except Exception as error:
        raise ProjectionAuthorityError(
            "Projection V2 evidence status is unavailable"
        ) from error
    if (
        type(status) is not EvidenceStatus
        or store._lifecycle_identity is not lifecycle
        or getattr(store, "_closed", True)
        or status.healthy is not True
        or status.repair_pending is not False
        or status.retention_pending is not False
        or type(status.acceptance_cursor) is not int
        or not 0 <= status.acceptance_cursor <= MAX_UINT64
    ):
        raise ProjectionAuthorityError(
            "Projection V2 evidence acceptance cursor is not exact and healthy"
        )
    return status.acceptance_cursor


def _same_stored_record_v2(
    left: StoredEvidenceRecord,
    right: StoredEvidenceRecord,
) -> bool:
    try:
        left_key = _exact_coverage_record_key(left)
        right_key = _exact_coverage_record_key(right)
        return left_key == right_key
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return False


def _insert_v2_incident(
    connection: sqlite3.Connection,
    incident: IncidentV1,
    result_kind: str,
) -> None:
    placeholders = ",".join("?" for _ in _INCIDENT_COLUMNS)
    connection.execute(
        f"INSERT INTO incidents({','.join(_INCIDENT_COLUMNS)}) VALUES({placeholders})",
        _encode_incident(incident, result_kind),
    )


def _insert_v2_candidate(
    connection: sqlite3.Connection,
    candidate: ContainmentCandidateV1,
) -> None:
    placeholders = ",".join("?" for _ in _CANDIDATE_COLUMNS)
    connection.execute(
        f"INSERT INTO candidates({','.join(_CANDIDATE_COLUMNS)}) VALUES({placeholders})",
        _encode_candidate(candidate),
    )


def _candidate_key_tuple_v2(
    key: CandidateDuplicateKey,
) -> tuple[str, str, str, str, str, str]:
    if type(key) is not CandidateDuplicateKey:
        raise CorrelationProjectionError("candidate duplicate key is not exact")
    return (
        key.host_id,
        key.boot_id,
        key.docker_container_id,
        key.docker_started_at,
        key.detector_bundle_sha256,
        key.destination_ipv4,
    )


def _active_duplicate_v2(
    connection: sqlite3.Connection,
    key: CandidateDuplicateKey,
    *,
    current_trigger_order: tuple[int, str],
) -> ActiveCandidateObservation | None:
    if (
        type(current_trigger_order) is not tuple
        or len(current_trigger_order) != 2
        or type(current_trigger_order[0]) is not int
        or type(current_trigger_order[1]) is not str
    ):
        raise CorrelationProjectionError("current trigger order is not exact")
    columns = ",".join(_CANDIDATE_COLUMNS)
    rows = connection.execute(
        f"SELECT {columns} FROM candidates WHERE "
        "host_id=? AND boot_id=? AND docker_container_id=? AND docker_started_at=? "
        "AND detector_bundle_sha256=? AND destination_ipv4=? "
        "ORDER BY primary_source_sequence COLLATE BINARY,"
        "primary_event_id COLLATE BINARY,candidate_id COLLATE BINARY LIMIT 2",
        _candidate_key_tuple_v2(key),
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict(
            "Projection V2 has multiple active candidates for one duplicate key"
        )
    if not rows:
        return None
    row = rows[0]
    if _candidate_duplicate_key_from_row(row) != _candidate_key_tuple_v2(key):
        raise ProjectionConflict("Projection V2 duplicate lookup returned another key")
    candidate = _decode_candidate(row)
    if (
        candidate.primary_source_sequence,
        candidate.primary_event_id,
    ) >= current_trigger_order:
        raise ProjectionConflict(
            "Projection V2 active primary is not before the current trigger"
        )
    return ActiveCandidateObservation(
        key=key,
        candidate_id=candidate.candidate_id,
        primary_source_sequence=candidate.primary_source_sequence,
        primary_event_id=candidate.primary_event_id,
    )


def _historical_active_duplicate_v2(
    connection: sqlite3.Connection,
    key: CandidateDuplicateKey,
    *,
    current_trigger_order: tuple[int, str],
) -> ActiveCandidateObservation | None:
    if (
        type(current_trigger_order) is not tuple
        or len(current_trigger_order) != 2
        or type(current_trigger_order[0]) is not int
        or type(current_trigger_order[1]) is not str
    ):
        raise CorrelationProjectionError("historical trigger order is not exact")
    sequence, event_id = current_trigger_order
    columns = ",".join(_CANDIDATE_COLUMNS)
    rows = connection.execute(
        f"SELECT {columns} FROM candidates WHERE "
        "host_id=? AND boot_id=? AND docker_container_id=? AND docker_started_at=? "
        "AND detector_bundle_sha256=? AND destination_ipv4=? AND "
        "(primary_source_sequence<? OR "
        "(primary_source_sequence=? AND primary_event_id<?)) "
        "ORDER BY primary_source_sequence COLLATE BINARY,"
        "primary_event_id COLLATE BINARY,candidate_id COLLATE BINARY LIMIT 2",
        (
            *_candidate_key_tuple_v2(key),
            _encode_uint64_v2(sequence),
            _encode_uint64_v2(sequence),
            event_id,
        ),
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict(
            "Projection V2 has multiple historical active candidates"
        )
    if not rows:
        return None
    row = rows[0]
    if _candidate_duplicate_key_from_row(row) != _candidate_key_tuple_v2(key):
        raise ProjectionConflict(
            "Projection V2 historical lookup returned another key"
        )
    candidate = _decode_candidate(row)
    if (
        candidate.primary_source_sequence,
        candidate.primary_event_id,
    ) >= current_trigger_order:
        raise ProjectionConflict(
            "Projection V2 historical active primary is not before its trigger"
        )
    return ActiveCandidateObservation(
        key=key,
        candidate_id=candidate.candidate_id,
        primary_source_sequence=candidate.primary_source_sequence,
        primary_event_id=candidate.primary_event_id,
    )


def _replay_pread_v2(
    descriptor: int,
    size: int,
    *,
    maximum: int,
    counters: _ReplayComputeCounters,
) -> bytes:
    if (
        type(descriptor) is not int
        or descriptor < 0
        or type(size) is not int
        or not 0 <= size <= maximum
        or type(maximum) is not int
        or maximum < 0
        or type(counters) is not _ReplayComputeCounters
    ):
        raise TypeError("Projection V2 replay descriptor bounds are not exact")
    parts: list[bytes] = []
    offset = 0
    while offset < size:
        counters.administrative_visits += 1
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise ProjectionConflict("Projection V2 replay descriptor shortened")
        parts.append(chunk)
        offset += len(chunk)
    return b"".join(parts)


def _validate_replay_snapshot_shape_v2(
    snapshot: _ReplayInputSnapshot,
) -> tuple[
    _ReplaySourceSnapshot,
    _AckReplaySnapshot,
    _CorrelationReplaySnapshot,
    tuple[_FrozenPCCCorrelationInput, ...],
    bytes,
    int,
    int,
]:
    if type(snapshot) is not _ReplayInputSnapshot:
        raise TypeError("Projection V2 compute requires an exact replay snapshot")
    source = snapshot.source
    ack = snapshot.ack
    correlation = snapshot.correlation
    pcc_inputs = snapshot.pcc_inputs
    schema_domain = snapshot.schema_domain
    base_generation = snapshot.base_projection_generation
    publish_generation = snapshot.publish_generation
    if (
        type(source) is not _ReplaySourceSnapshot
        or type(ack) is not _AckReplaySnapshot
        or type(correlation) is not _CorrelationReplaySnapshot
        or type(pcc_inputs) is not tuple
        or type(schema_domain) is not bytes
        or type(base_generation) is not int
        or not 1 <= base_generation < MAX_UINT64
        or type(publish_generation) is not int
        or publish_generation != base_generation + 1
        or not 1 <= publish_generation <= MAX_UINT64
    ):
        raise TypeError("Projection V2 replay snapshot fields are not exact")
    if any(type(item) is not _FrozenPCCCorrelationInput for item in pcc_inputs):
        raise TypeError("Projection V2 replay PCC inputs are not exact")
    if (
        type(source.lifecycle_token) is not bytes
        or len(source.lifecycle_token) != 32
        or type(source.source_revision) is not int
        or source.source_revision < 0
        or type(source.terminal_ref) is not EvidenceRef
        or type(source.retained_ranges) is not tuple
        or type(source.records) is not tuple
        or type(source.segments) is not tuple
        or any(type(item) is not _ReplayRecordDescriptor for item in source.records)
        or any(type(item) is not _ReplaySegmentDescriptor for item in source.segments)
    ):
        raise TypeError("Projection V2 replay source facts are not exact")
    if any(
        type(item) is not tuple
        or len(item) != 2
        or type(item[0]) is not int
        or type(item[1]) is not int
        or not 1 <= item[0] <= item[1] <= MAX_UINT64
        for item in source.retained_ranges
    ):
        raise TypeError("Projection V2 replay retained ranges are not exact")
    try:
        _exact_coverage_ref_key(source.terminal_ref)
    except ValueError as error:
        raise TypeError("Projection V2 replay terminal ref is malformed") from error
    if (
        type(ack.lifecycle_token) is not bytes
        or len(ack.lifecycle_token) != 32
        or type(ack.mutation_revision) is not int
        or ack.mutation_revision < 0
        or type(ack.generation) is not int
        or not 0 <= ack.generation <= MAX_UINT64
        or (ack.confirmed is not None and type(ack.confirmed) is not tuple)
        or (ack.pending is not None and type(ack.pending) is not tuple)
        or type(ack.committed_prefix_size) is not int
        or type(ack.committed_prefix_sha256) is not bytes
        or len(ack.committed_prefix_sha256) != 32
        or type(ack.retention_pending) is not bool
        or type(ack.descriptor) is not int
        or type(ack.device) is not int
        or type(ack.inode) is not int
        or type(ack.size) is not int
    ):
        raise TypeError("Projection V2 replay ACK facts are not exact")
    predecessor = correlation.predecessor
    if (
        type(correlation.lifecycle_token) is not bytes
        or len(correlation.lifecycle_token) != 32
        or callable(correlation.revision)
        or type(predecessor) is not _ProjectionPredecessor
        or type(correlation.predecessor_canonical) is not bytes
        or type(correlation.detector_bundle_sha256) is not str
        or _HEX64_V2.fullmatch(correlation.detector_bundle_sha256) is None
        or type(correlation.registry_facts_canonical) is not bytes
    ):
        raise TypeError("Projection V2 replay correlation facts are not exact")
    try:
        predecessor_seal = _seal_projection_predecessor(predecessor)
    except (AttributeError, TypeError, ValueError) as error:
        raise TypeError("Projection V2 replay predecessor is malformed") from error
    if (
        predecessor_seal.canonical != correlation.predecessor_canonical
        or predecessor
        != _ProjectionPredecessor(base_generation, None, 0, None, None, None)
    ):
        raise ProjectionConflict("Projection V2 replay predecessor is not empty")
    return (
        source,
        ack,
        correlation,
        pcc_inputs,
        schema_domain,
        base_generation,
        publish_generation,
    )


def _decode_replay_records_v2(
    source: _ReplaySourceSnapshot,
    counters: _ReplayComputeCounters,
) -> tuple[StoredEvidenceRecord, ...]:
    records_by_segment: list[list[_ReplayRecordDescriptor]] = [
        [] for _segment in source.segments
    ]
    for ordinal, record in enumerate(source.records, start=1):
        counters.administrative_visits += 1
        try:
            _exact_coverage_ref_key(record.ref)
        except ValueError as error:
            raise TypeError(
                "Projection V2 replay record ref is malformed"
            ) from error
        if (
            type(record.ref) is not EvidenceRef
            or type(record.accepted_at) is not str
            or type(record.canonical_record) is not bytes
            or type(record.segment_index) is not int
            or not 0 <= record.segment_index < len(source.segments)
            or record.ref.source_sequence != ordinal
        ):
            raise TypeError("Projection V2 replay record descriptor is not exact")
        records_by_segment[record.segment_index].append(record)
    for segment_index, segment in enumerate(source.segments):
        counters.administrative_visits += 1
        if (
            type(segment.descriptor) is not int
            or segment.descriptor < 0
            or type(segment.device) is not int
            or type(segment.inode) is not int
            or type(segment.size) is not int
            or not 0 < segment.size <= MAX_SEGMENT_BYTES
            or type(segment.maximum_prefix_bytes) is not int
            or not 0 < segment.maximum_prefix_bytes <= segment.size
            or type(segment.relative_path) is not str
        ):
            raise TypeError("Projection V2 replay segment descriptor is not exact")
        info = os.fstat(segment.descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino, info.st_size)
            != (segment.device, segment.inode, segment.size)
            or fcntl.fcntl(segment.descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            != os.O_RDONLY
        ):
            raise ProjectionConflict("Projection V2 replay segment binding changed")
        prefix = _replay_pread_v2(
            segment.descriptor,
            segment.maximum_prefix_bytes,
            maximum=MAX_SEGMENT_BYTES,
            counters=counters,
        )
        try:
            decoded = decode_frames(prefix, max_frame=MAX_EVIDENCE_RECORD_BYTES)
        except (JournalCorrupt, ValueError) as error:
            raise ProjectionConflict("Projection V2 replay segment is corrupt") from error
        expected = records_by_segment[segment_index]
        if (
            decoded.torn_tail
            or decoded.verified_bytes != segment.maximum_prefix_bytes
            or len(decoded.records) != len(expected)
        ):
            raise ProjectionConflict("Projection V2 replay frames differ from snapshot")
        for frame, descriptor in zip(decoded.records, expected, strict=True):
            counters.administrative_visits += 1
            if (
                frame.offset != descriptor.ref.frame_offset
                or frame.size != descriptor.ref.frame_size
                or frame.record_hash.hex() != descriptor.ref.frame_sha256
                or frame.payload != descriptor.canonical_record
            ):
                raise ProjectionConflict("Projection V2 replay frame binding changed")

    records: list[StoredEvidenceRecord] = []
    for descriptor in source.records:
        counters.administrative_visits += 1
        try:
            accepted = decode_strict(
                descriptor.canonical_record,
                _AcceptedEnvelopeRecordV1,
                MAX_EVIDENCE_RECORD_BYTES,
            )
            envelope = accepted.envelope
            canonical_envelope = canonical_json(envelope)
            priority = EvidencePriority(accepted.evidence_priority)
        except (TypeError, ValueError, ValidationError) as error:
            raise ProjectionValidationError(
                "Projection V2 replay accepted record is invalid"
            ) from error
        ref = descriptor.ref
        if (
            accepted.accepted_at != descriptor.accepted_at
            or accepted.outer.sequence != ref.source_sequence
            or accepted.outer.event_id != ref.event_id
            or accepted.outer.content_sha256 != ref.content_sha256
        ):
            raise ProjectionValidationError(
                "Projection V2 replay accepted outer facts changed"
            )
        records.append(
            StoredEvidenceRecord(
                envelope=envelope,
                canonical_envelope=canonical_envelope,
                priority=priority,
                accepted_at=descriptor.accepted_at,
                ref=ref,
            )
        )
    if (
        not records
        or records[-1].ref != source.terminal_ref
        or len(records) != source.terminal_ref.source_sequence
    ):
        raise ProjectionConflict("Projection V2 replay source is not contiguous")
    return tuple(records)


def _exact_replay_ack_identity_v2(
    value: object,
) -> tuple[int, str, str] | None:
    if value is None:
        return None
    if (
        type(value) is not tuple
        or len(value) != 3
        or type(value[0]) is not int
        or not 1 <= value[0] <= MAX_UINT64
        or type(value[1]) is not str
        or _EVENT_ID_V2.fullmatch(value[1]) is None
        or type(value[2]) is not str
        or _HEX64_V2.fullmatch(value[2]) is None
    ):
        raise TypeError("Projection V2 replay ACK identity is not exact")
    return value


def _verify_replay_ack_v2(
    ack: _AckReplaySnapshot,
    terminal: EvidenceRef,
    counters: _ReplayComputeCounters,
) -> None:
    try:
        terminal_key = _exact_coverage_ref_key(terminal)
    except ValueError as error:
        raise TypeError("Projection V2 replay ACK terminal is malformed") from error
    confirmed = _exact_replay_ack_identity_v2(ack.confirmed)
    pending = _exact_replay_ack_identity_v2(ack.pending)
    if (
        confirmed is None
        or confirmed
        != (terminal_key[6], terminal_key[5], terminal_key[7])
        or pending is not None
        or ack.retention_pending
        or not 0 <= ack.committed_prefix_size <= ack.size
    ):
        raise ProjectionAuthorityError("Projection V2 replay ACK boundary is not strict")
    info = os.fstat(ack.descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or (info.st_dev, info.st_ino, info.st_size)
        != (ack.device, ack.inode, ack.size)
        or fcntl.fcntl(ack.descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        != os.O_RDONLY
    ):
        raise ProjectionAuthorityError("Projection V2 replay ACK descriptor changed")
    prefix = _replay_pread_v2(
        ack.descriptor,
        ack.committed_prefix_size,
        maximum=ack.size,
        counters=counters,
    )
    if hashlib.sha256(prefix).digest() != ack.committed_prefix_sha256:
        raise ProjectionAuthorityError("Projection V2 replay ACK prefix changed")
    try:
        decoded = decode_frames(prefix, max_frame=_MAX_ACK_RECORD_BYTES)
    except (JournalCorrupt, ValueError) as error:
        raise ProjectionAuthorityError(
            "Projection V2 replay ACK prefix is corrupt"
        ) from error
    if decoded.torn_tail or decoded.verified_bytes != len(prefix):
        raise ProjectionAuthorityError(
            "Projection V2 replay ACK prefix is incomplete"
        )
    reduced_confirmed: tuple[int, str, str] | None = None
    reduced_pending: tuple[int, str, str] | None = None
    reduced_generation = 0
    for frame in decoded.records:
        counters.administrative_visits += 1
        try:
            record = decode_strict(
                frame.payload,
                _AckJournalRecordV1,
                _MAX_ACK_RECORD_BYTES,
            )
            if frame.payload != canonical_json(record):
                raise ValueError("ACK record is not canonical")
            identity = _exact_replay_ack_identity_v2(
                (record.sequence, record.event_id, record.content_sha256)
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise ProjectionAuthorityError(
                "Projection V2 replay ACK record is invalid"
            ) from error
        assert identity is not None
        if record.kind == "pending_ack":
            expected_sequence = (
                1 if reduced_confirmed is None else reduced_confirmed[0] + 1
            )
            if reduced_pending is not None or identity[0] != expected_sequence:
                raise ProjectionAuthorityError(
                    "Projection V2 replay ACK pending transition is invalid"
                )
            reduced_pending = identity
            continue
        if reduced_pending is None or identity != reduced_pending:
            raise ProjectionAuthorityError(
                "Projection V2 replay ACK confirmation is invalid"
            )
        reduced_confirmed = identity
        reduced_pending = None
        reduced_generation += 1
    if (
        reduced_confirmed != confirmed
        or reduced_pending != pending
        or reduced_generation != ack.generation
    ):
        raise ProjectionAuthorityError(
            "Projection V2 replay ACK prefix facts changed"
        )


def _replay_connection_v2(schema_domain: bytes) -> sqlite3.Connection:
    if (
        type(schema_domain) is not bytes
        or not schema_domain.startswith(_REPLAY_SCHEMA_DOMAIN_V2)
    ):
        raise TypeError("Projection V2 replay schema domain is not exact")
    raw = schema_domain[len(_REPLAY_SCHEMA_DOMAIN_V2) :]
    if hashlib.sha256(raw).hexdigest() != _SCHEMA_V2_SHA256:
        raise ProjectionConflict("Projection V2 frozen schema bytes changed")
    try:
        script = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ProjectionConflict("Projection V2 frozen schema is not UTF-8") from error
    connection = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        check_same_thread=False,
    )
    try:
        _configure_v2_connection(connection, file_backed=False)
        connection.executescript(script)
        actual_tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        }
        metadata = dict(
            connection.execute("SELECT key,value FROM schema_meta ORDER BY key")
        )
        if actual_tables != _TABLE_NAMES_V2 or metadata != _SCHEMA_META_V2:
            raise ProjectionConflict("Projection V2 frozen schema is not exact")
        if [
            str(row[0])
            for row in connection.execute("PRAGMA integrity_check").fetchall()
        ] != ["ok"]:
            raise ProjectionConflict("Projection V2 frozen schema integrity failed")
        _verify_v2_pragmas(connection)
    except BaseException:
        connection.close()
        raise
    return connection


def _compute_reduce_base_v2(
    connection: sqlite3.Connection,
    prepared: _PreparedV2Record,
) -> None:
    envelope = prepared.envelope
    ref = prepared.record.ref
    sequence = _encode_uint64_v2(ref.source_sequence)
    coverage = prepared.coverage
    if coverage is not None:
        connection.execute(
            "INSERT INTO coverage_intervals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                envelope.event_id,
                envelope.host_id,
                coverage.component,
                coverage.kind,
                coverage.severity,
                coverage.opened_at,
                coverage.closed_at,
                _optional_uint64_v2(coverage.affected_source_sequence_start),
                _optional_uint64_v2(coverage.affected_source_sequence_end),
                _optional_uint64_v2(coverage.dropped_count),
                coverage.reason_code,
                _optional_uint64_v2(coverage.reconcile_generation),
                sequence,
                ref.content_sha256,
            ),
        )
        return
    falco = prepared.falco
    if falco is None:
        return
    if falco.docker_container_id is not None and falco.docker_started_at is not None:
        connection.execute(
            "INSERT INTO containers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(host_id,container_id,container_started_at) DO UPDATE SET "
            "image_id=excluded.image_id,repo_digests_json=excluded.repo_digests_json,"
            "immutable_spec_sha256=excluded.immutable_spec_sha256,"
            "inventory_revision=excluded.inventory_revision,"
            "last_event_id=excluded.last_event_id,"
            "last_source_sequence=excluded.last_source_sequence,"
            "last_content_sha256=excluded.last_content_sha256 "
            "WHERE excluded.last_source_sequence > containers.last_source_sequence",
            (
                envelope.host_id,
                falco.docker_container_id,
                falco.docker_started_at,
                falco.image_id,
                canonical_json(falco.repo_digests).decode("utf-8"),
                falco.immutable_spec_sha256,
                _optional_uint64_v2(falco.inventory_revision),
                envelope.event_id,
                sequence,
                ref.content_sha256,
                envelope.event_id,
                sequence,
                ref.content_sha256,
            ),
        )
    connection.execute(
        "INSERT INTO process_observations VALUES(?,?,?,?,?,?,?,?,?)",
        (
            envelope.event_id,
            envelope.host_id,
            falco.docker_container_id,
            falco.docker_started_at,
            falco.proc_name,
            falco.proc_exe_path,
            falco.proc_parent_name,
            sequence,
            ref.content_sha256,
        ),
    )
    connection.execute(
        "INSERT INTO network_observations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            envelope.event_id,
            envelope.host_id,
            falco.docker_container_id,
            falco.docker_started_at,
            int(falco.successful_connect),
            falco.destination_ipv4,
            falco.destination_port,
            falco.l4_protocol,
            int(falco.investigation_only),
            sequence,
            ref.content_sha256,
        ),
    )
    if (
        not falco.successful_connect
        or falco.missing_required_fields
        or falco.investigation_only
    ):
        incident = _incident_from_frozen_falco(
            falco,
            event_id=envelope.event_id,
            source_sequence=envelope.source_sequence,
            host_id=envelope.host_id,
            boot_id=envelope.boot_id,
            event_time=envelope.event_time,
            ingest_time=envelope.ingest_time,
            coverage_flags=tuple(envelope.coverage_flags),
        )
        _insert_v2_incident(connection, incident, "investigation")


def _persist_compute_pcc_result_v2(
    connection: sqlite3.Connection,
    result: object,
    proof: AuthenticatedPCCInput,
    active: ActiveCandidateObservation | None,
) -> None:
    if isinstance(result, CandidateCreated):
        candidate = result.candidate
        _insert_v2_incident(connection, result.incident, "candidate")
        _insert_v2_candidate(connection, candidate)
        roles = (
            ("primary_trigger", proof.snapshot.trigger),
            ("correlation_snapshot", proof),
        )
        for role, evidence in roles:
            connection.execute(
                "INSERT INTO candidate_evidence VALUES(?,?,?,?,?,?)",
                _encode_candidate_evidence(
                    candidate.candidate_id,
                    evidence.event_id,
                    evidence.source_sequence,
                    evidence.content_sha256,
                    role,
                    proof.event_id,
                ),
            )
        return
    if isinstance(result, Duplicate):
        if active is None or result.existing_candidate_id != active.candidate_id:
            raise ProjectionConflict(
                "Projection V2 replay duplicate changed its active candidate"
            )
        _insert_v2_incident(connection, result.incident, "duplicate")
        roles = (
            ("supporting_trigger", proof.snapshot.trigger),
            ("supporting_snapshot", proof),
        )
        for role, evidence in roles:
            connection.execute(
                "INSERT INTO candidate_evidence VALUES(?,?,?,?,?,?)",
                _encode_candidate_evidence(
                    result.existing_candidate_id,
                    evidence.event_id,
                    evidence.source_sequence,
                    evidence.content_sha256,
                    role,
                    proof.event_id,
                ),
            )
        return
    if isinstance(result, InvestigationOnly):
        _insert_v2_incident(connection, result.incident, "investigation")
        return
    if isinstance(result, Rejected):
        _insert_v2_incident(connection, result.incident, "rejected")
        return
    raise ProjectionConflict("Projection V2 replay correlation result is not exact")


def _compute_history_reduction_v2(
    frozen: _FrozenPCCCorrelationInput,
    entries: tuple[_FrozenReplayEntry, ...],
    counters: _ReplayComputeCounters,
) -> tuple[_HistoricalReductionResult, _ReplayMemoLeaf]:
    proof = frozen.proof
    if type(proof) is not AuthenticatedPCCInput:
        raise TypeError("Projection V2 replay PCC proof is not exact")
    snapshot = proof.snapshot
    trigger = snapshot.trigger
    compact_records: list[StoredEvidenceRecord] = []
    for entry in entries:
        counters.administrative_visits += 1
        if (
            entry.compact_member
            and entry.record.ref.source_sequence
            <= snapshot.coverage_through_sequence
        ):
            compact_records.append(entry.record)
    compact = tuple(compact_records)
    compact_count, compact_digest = _replay_compact_digest(compact)
    reduction = _reduce_historical_coverage_result(
        compact,
        host_id=proof.host_id,
        boot_id=proof.boot_id,
        trigger_event_id=trigger.event_id,
        trigger_source_sequence=trigger.source_sequence,
        trigger_event_time=trigger.event_time,
        clock_uncertainty_ms=trigger.clock_uncertainty_ms,
        coverage_through_sequence=snapshot.coverage_through_sequence,
        window_end=snapshot.decision_time,
    )
    counters.semantic_prefix_visits += (
        reduction.diagnostics.semantic_prefix_visits
    )
    key = (proof.event_id, proof.content_sha256)
    return reduction, _build_replay_memo_leaf(
        key,
        reduction,
        compact_count,
        compact_digest,
    )


def _compute_late_invalidations_v2(
    connection: sqlite3.Connection,
    prepared: _PreparedV2Record,
    proofs_by_event: dict[str, AuthenticatedPCCInput],
    counters: _ReplayComputeCounters,
) -> None:
    if prepared.coverage is None or not _late_coverage_may_invalidate_candidate(
        prepared.record
    ):
        return
    rows = connection.execute(
        f"SELECT {','.join(_CANDIDATE_COLUMNS)} FROM candidates "
        "WHERE host_id=? ORDER BY candidate_id COLLATE BINARY LIMIT ?",
        (prepared.envelope.host_id, _INVALIDATION_CANDIDATE_CAP_V2 + 1),
    ).fetchall()
    if len(rows) > _INVALIDATION_CANDIDATE_CAP_V2:
        raise ProjectionConflict("Projection V2 replay invalidation cap exceeded")
    for row in rows:
        counters.administrative_visits += 1
        candidate = _decode_candidate(row)
        proof = proofs_by_event.get(candidate.correlation_snapshot_event_id)
        if type(proof) is not AuthenticatedPCCInput:
            raise ProjectionConflict("Projection V2 replay candidate lost PCC leaf")
        if _late_coverage_invalidates_candidate_values(proof, prepared.record):
            connection.execute(
                "INSERT INTO candidate_invalidations VALUES(?,?,?,?,?)",
                _encode_candidate_invalidation(
                    candidate.candidate_id,
                    prepared.envelope.event_id,
                    prepared.record.ref.source_sequence,
                    prepared.record.ref.content_sha256,
                    _INVALIDATION_REASON_V2,
                ),
            )


def _compute_replay(snapshot: _ReplayInputSnapshot) -> _ReplayComputation:
    """Project one immutable replay snapshot without consulting live authority."""
    (
        source,
        ack,
        correlation,
        frozen_inputs,
        schema_domain,
        _base_generation,
        publish_generation,
    ) = _validate_replay_snapshot_shape_v2(snapshot)
    counters = _ReplayComputeCounters()
    connection: sqlite3.Connection | None = None
    try:
        records = _decode_replay_records_v2(source, counters)
        _verify_replay_ack_v2(ack, source.terminal_ref, counters)
        prepared_records = tuple(_prepare_v2(record) for record in records)
        historical_prepared = tuple(
            _prepare_historical_record(record) for record in records
        )
        entries = _build_frozen_replay_entries(records, historical_prepared)

        frozen_by_event: dict[str, _FrozenPCCCorrelationInput] = {}
        pcc_leaves: list[_ReplayPCCLeaf] = []
        proofs_by_event: dict[str, AuthenticatedPCCInput] = {}
        for frozen_input in frozen_inputs:
            counters.administrative_visits += 1
            proof, _context = _validate_frozen_pcc_correlation_input(
                frozen_input
            )
            evidence_ref = proof.evidence_ref
            try:
                _exact_coverage_ref_key(evidence_ref)
            except ValueError as error:
                raise TypeError("Projection V2 replay PCC ref is malformed") from error
            key = (proof.event_id, proof.content_sha256)
            if proof.event_id in frozen_by_event:
                raise ProjectionConflict("Projection V2 replay PCC input is duplicated")
            frozen_by_event[proof.event_id] = frozen_input
            proofs_by_event[proof.event_id] = proof
            pcc_leaves.append(_build_replay_pcc_leaf(key, proof))

        connection = _replay_connection_v2(schema_domain)
        transcript = hashlib.sha256(_REPLAY_TRANSCRIPT_DOMAIN_V2)
        memo_leaves: list[_ReplayMemoLeaf] = []
        consumed_pcc: set[str] = set()
        connection.execute("BEGIN IMMEDIATE")
        for prepared in prepared_records:
            counters.administrative_visits += 1
            envelope = prepared.envelope
            ref = prepared.record.ref
            duplicate_row = connection.execute(
                "SELECT primary_event_id FROM projection_dedup "
                "WHERE dedup_kind=? AND logical_key_sha256=? AND is_primary=1",
                (prepared.dedup_kind, prepared.logical_key_sha256),
            ).fetchone()
            duplicate = None if duplicate_row is None else duplicate_row[0]
            if duplicate is not None and (
                type(duplicate) is not str
                or _EVENT_ID_V2.fullmatch(duplicate) is None
            ):
                raise ProjectionConflict(
                    "Projection V2 replay logical primary is invalid"
                )
            primary_event_id = envelope.event_id if duplicate is None else duplicate
            placeholders = ",".join("?" for _ in _TABLE_LAYOUT_V2[1][1])
            connection.execute(
                f"INSERT INTO events({','.join(_TABLE_LAYOUT_V2[1][1])}) "
                f"VALUES({placeholders})",
                _event_values_v2(prepared, duplicate),
            )
            connection.execute(
                "INSERT INTO projection_dedup("
                "event_id,dedup_kind,logical_key_sha256,primary_event_id,is_primary"
                ") VALUES(?,?,?,?,?)",
                (
                    envelope.event_id,
                    prepared.dedup_kind,
                    prepared.logical_key_sha256,
                    primary_event_id,
                    int(duplicate is None),
                ),
            )
            if duplicate is None:
                _compute_reduce_base_v2(connection, prepared)
                if prepared.coverage is not None:
                    _compute_late_invalidations_v2(
                        connection,
                        prepared,
                        proofs_by_event,
                        counters,
                    )
                elif envelope.event_type == "pcc_correlation_snapshot":
                    event_frozen = frozen_by_event.get(envelope.event_id)
                    if event_frozen is None:
                        raise ProjectionConflict(
                            "Projection V2 replay lacks frozen PCC facts"
                        )
                    proof = event_frozen.proof
                    if (
                        type(proof) is not AuthenticatedPCCInput
                        or type(proof.evidence_ref) is not EvidenceRef
                        or proof.evidence_ref != ref
                        or proof.source_sequence != ref.source_sequence
                        or proof.event_id != ref.event_id
                        or proof.content_sha256 != ref.content_sha256
                    ):
                        raise ProjectionConflict(
                            "Projection V2 replay PCC does not bind source"
                        )
                    active: ActiveCandidateObservation | None = None
                    coverage: HistoricalCoverageAssessment | None = None
                    if proof.snapshot.outcome == "complete":
                        reduction, memo = _compute_history_reduction_v2(
                            event_frozen,
                            entries,
                            counters,
                        )
                        context = event_frozen.context
                        expected_key = _duplicate_key(proof, proof.snapshot)
                        if (
                            context.pinned_detector_bundle_sha256
                            != correlation.detector_bundle_sha256
                            or context.lookup_key != expected_key
                        ):
                            raise ProjectionConflict(
                                "Projection V2 replay frozen PCC context changed"
                            )
                        active = _active_duplicate_v2(
                            connection,
                            expected_key,
                            current_trigger_order=(
                                proof.snapshot.trigger.source_sequence,
                                proof.snapshot.trigger.event_id,
                            ),
                        )
                        memo_leaves.append(memo)
                        coverage = reduction.timeline.assessment
                    rebound = _rebind_frozen_pcc_projection_context(
                        event_frozen,
                        coverage,
                        active,
                        None,
                    )
                    result = _correlate_frozen_pcc(rebound)
                    _persist_compute_pcc_result_v2(
                        connection,
                        result,
                        proof,
                        active,
                    )
                    consumed_pcc.add(envelope.event_id)
            connection.execute(
                "INSERT INTO ingest_cursors("
                "host_id,source_sequence,event_id,content_sha256,segment_id,"
                "segment_relative_path,frame_offset,frame_size,frame_sha256"
                ") VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET "
                "source_sequence=excluded.source_sequence,event_id=excluded.event_id,"
                "content_sha256=excluded.content_sha256,segment_id=excluded.segment_id,"
                "segment_relative_path=excluded.segment_relative_path,"
                "frame_offset=excluded.frame_offset,frame_size=excluded.frame_size,"
                "frame_sha256=excluded.frame_sha256",
                (
                    envelope.host_id,
                    _encode_uint64_v2(ref.source_sequence),
                    ref.event_id,
                    ref.content_sha256,
                    ref.segment_id,
                    ref.segment_relative_path,
                    _encode_uint64_v2(ref.frame_offset),
                    _encode_uint64_v2(ref.frame_size),
                    ref.frame_sha256,
                ),
            )
            transcript.update(
                canonical_json(
                    _replay_exact_fact(
                        (
                            ref,
                            prepared.record.canonical_envelope,
                            duplicate,
                            duplicate is None,
                        )
                    )
                )
            )
        if consumed_pcc != set(frozen_by_event):
            raise ProjectionConflict("Projection V2 replay has unused PCC facts")
        connection.execute("COMMIT")

        for validation_frozen, expected_memo in zip(
            (
                frozen_by_event[leaf.key[0]]
                for leaf in pcc_leaves
                if frozen_by_event[leaf.key[0]].proof.snapshot.outcome == "complete"
            ),
            memo_leaves,
            strict=True,
        ):
            counters.administrative_visits += 1
            _reduction, rebuilt = _compute_history_reduction_v2(
                validation_frozen,
                entries,
                counters,
            )
            if rebuilt != expected_memo:
                raise ProjectionConflict(
                    "Projection V2 replay independent history validation changed"
                )

        cursor = _current_v2_cursor(connection)
        if cursor is None or cursor.source_sequence != len(records):
            raise ProjectionConflict("Projection V2 replay terminal cursor changed")
        terminal_predecessor = _predecessor_v2(publish_generation, cursor)
        prefix_sha256 = _v2_snapshot_hash(connection)
        late_invalidations = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT candidate_id,coverage_event_id,coverage_source_sequence,"
                "coverage_content_sha256,reason_code FROM candidate_invalidations "
                "ORDER BY candidate_id,coverage_event_id"
            ).fetchall()
        )
        for _row in late_invalidations:
            counters.administrative_visits += 1
        database_image = connection.serialize()
        transcript_digest = transcript.digest()
        report_payload = (
            hashlib.sha256(database_image).digest(),
            hashlib.sha256(schema_domain).digest(),
            publish_generation,
            len(records),
            transcript_digest,
            tuple(leaf.facts_digest for leaf in pcc_leaves),
            tuple(leaf.facts_digest for leaf in memo_leaves),
            hashlib.sha256(
                canonical_json(_replay_exact_fact(late_invalidations))
            ).digest(),
            _seal_projection_predecessor(terminal_predecessor).canonical,
            counters.administrative_visits,
            counters.semantic_prefix_visits,
            prefix_sha256,
        )
        report_bytes = _REPLAY_REPORT_DOMAIN_V2 + canonical_json(
            _replay_exact_fact(report_payload)
        )
        return _ReplayComputation(
            database_image=database_image,
            transcript_count=len(records),
            transcript_digest=transcript_digest,
            pcc_leaves=tuple(pcc_leaves),
            memo_leaves=tuple(memo_leaves),
            late_invalidations=late_invalidations,
            terminal_predecessor=terminal_predecessor,
            administrative_visits=counters.administrative_visits,
            semantic_prefix_visits=counters.semantic_prefix_visits,
            report_bytes=report_bytes,
            prefix_sha256=prefix_sha256,
        )
    except (HistoricalCoverageConflict, HistoricalCoverageUnavailable) as error:
        raise ProjectionConflict(
            "Projection V2 replay historical facts conflict"
        ) from error
    except sqlite3.IntegrityError as error:
        raise ProjectionConflict("Projection V2 replay facts conflict") from error
    finally:
        if connection is not None:
            connection.close()


def _validate_and_hydrate_replay(
    snapshot: _ReplayInputSnapshot,
    computation: _ReplayComputation,
) -> tuple[sqlite3.Connection, _UnpublishedV2ReplayReport]:
    """Validate one sealed computation into an unpublished private image."""
    (
        source,
        _ack,
        _correlation,
        _pcc_inputs,
        schema_domain,
        _base_generation,
        publish_generation,
    ) = _validate_replay_snapshot_shape_v2(snapshot)
    if (
        type(computation) is not _ReplayComputation
        or type(computation.database_image) is not bytes
        or not computation.database_image
        or type(computation.transcript_count) is not int
        or computation.transcript_count != len(source.records)
        or type(computation.transcript_digest) is not bytes
        or len(computation.transcript_digest) != 32
        or type(computation.pcc_leaves) is not tuple
        or type(computation.memo_leaves) is not tuple
        or type(computation.late_invalidations) is not tuple
        or type(computation.terminal_predecessor) is not _ProjectionPredecessor
        or type(computation.administrative_visits) is not int
        or computation.administrative_visits < 0
        or type(computation.semantic_prefix_visits) is not int
        or computation.semantic_prefix_visits < 0
        or type(computation.report_bytes) is not bytes
        or type(computation.prefix_sha256) is not str
        or _HEX64_V2.fullmatch(computation.prefix_sha256) is None
    ):
        raise ProjectionConflict("Projection V2 replay computation is not exact")
    expected_report_payload = (
        hashlib.sha256(computation.database_image).digest(),
        hashlib.sha256(schema_domain).digest(),
        publish_generation,
        computation.transcript_count,
        computation.transcript_digest,
        tuple(leaf.facts_digest for leaf in computation.pcc_leaves),
        tuple(leaf.facts_digest for leaf in computation.memo_leaves),
        hashlib.sha256(
            canonical_json(_replay_exact_fact(computation.late_invalidations))
        ).digest(),
        _seal_projection_predecessor(
            computation.terminal_predecessor
        ).canonical,
        computation.administrative_visits,
        computation.semantic_prefix_visits,
        computation.prefix_sha256,
    )
    expected_report_bytes = _REPLAY_REPORT_DOMAIN_V2 + canonical_json(
        _replay_exact_fact(expected_report_payload)
    )
    if computation.report_bytes != expected_report_bytes:
        raise ProjectionConflict("Projection V2 replay report seal changed")

    connection: sqlite3.Connection | None = None
    try:
        connection = _replay_connection_v2(schema_domain)
        connection.deserialize(computation.database_image)
        _verify_v2_schema(connection)
        if [
            str(row[0])
            for row in connection.execute("PRAGMA integrity_check").fetchall()
        ] != ["ok"]:
            raise ProjectionConflict("Projection V2 replay image is not integral")
        cursor = _current_v2_cursor(connection)
        cursor_ref = _current_v2_cursor_ref(connection)
        if cursor is None or cursor_ref is None:
            raise ProjectionConflict("Projection V2 replay image lost its cursor")
        terminal_ref = source.terminal_ref
        expected_predecessor = _predecessor_v2(publish_generation, cursor)
        invalidations = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT candidate_id,coverage_event_id,coverage_source_sequence,"
                "coverage_content_sha256,reason_code FROM candidate_invalidations "
                "ORDER BY candidate_id,coverage_event_id"
            ).fetchall()
        )
        if (
            cursor.source_sequence != terminal_ref.source_sequence
            or cursor.event_id != terminal_ref.event_id
            or cursor.content_sha256 != terminal_ref.content_sha256
            or cursor_ref != terminal_ref
            or expected_predecessor != computation.terminal_predecessor
            or _seal_projection_predecessor(expected_predecessor).canonical
            != _seal_projection_predecessor(
                computation.terminal_predecessor
            ).canonical
            or invalidations != computation.late_invalidations
            or _v2_snapshot_hash(connection) != computation.prefix_sha256
            or connection.serialize() != computation.database_image
        ):
            raise ProjectionConflict("Projection V2 hydrated replay facts changed")
        report = _UnpublishedV2ReplayReport(
            cursor=cursor,
            applied_count=computation.transcript_count,
            prefix_sha256=computation.prefix_sha256,
        )
        hydrated = connection
        connection = None
        return hydrated, report
    finally:
        if connection is not None:
            connection.close()


class _V2ProjectionOwner:
    """Dormant single-owner reducer for exact authenticated V2 projection tests."""

    _connection: sqlite3.Connection | None
    _evidence: SegmentStore
    _acknowledgements: AckJournal
    _journal: CorrelationRequestJournal
    _registry: SpecialUseRegistry
    _evidence_lifecycle: object
    _ack_lifecycle: object
    _authority: CorrelationProjectionAuthority | None
    _generation: int
    _step_hook: Callable[[str], None]
    _mutex: RLockType
    _replay_state_lock: LockType
    _replay_state_condition: Condition
    _replay_reservation: _ReplayReservation | None
    _replay_status: _ReplayStatus
    _replay_test_barrier: _ReplayTestBarrier | None
    _healthy: bool
    _closed: bool

    def __init__(self) -> None:
        raise TypeError("use the module-private Projection V2 owner factory")

    @classmethod
    def _take_ownership(
        cls,
        connection: sqlite3.Connection,
        *,
        evidence: SegmentStore,
        acknowledgements: AckJournal,
        journal: CorrelationRequestJournal,
        registry: SpecialUseRegistry,
        step_hook: Callable[[str], None] | None,
    ) -> _V2ProjectionOwner:
        if (
            not isinstance(connection, sqlite3.Connection)
            or type(evidence) is not SegmentStore
            or type(acknowledgements) is not AckJournal
            or type(journal) is not CorrelationRequestJournal
            or type(registry) is not SpecialUseRegistry
            or getattr(acknowledgements, "_store", None) is not evidence
            or getattr(journal, "_store", None) is not evidence
            or (step_hook is not None and not callable(step_hook))
        ):
            raise ProjectionAuthorityError(
                "Projection V2 owner requires exact same-lifecycle resources"
            )
        try:
            journal_is_live = journal._is_bound_to(evidence)
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 journal lifecycle cannot be validated"
            ) from error
        if journal_is_live is not True:
            raise ProjectionAuthorityError(
                "Projection V2 journal is not live on the evidence lifecycle"
            )
        generation = 1
        owner = object.__new__(cls)
        owner._connection = connection
        owner._evidence = evidence
        owner._acknowledgements = acknowledgements
        owner._journal = journal
        owner._registry = registry
        owner._evidence_lifecycle = evidence._lifecycle_identity
        owner._ack_lifecycle = acknowledgements._lifecycle_identity
        owner._authority = None
        owner._generation = generation
        owner._step_hook = step_hook or (lambda _step: None)
        owner._mutex = RLock()
        owner._replay_state_lock = Lock()
        owner._replay_state_condition = Condition(owner._replay_state_lock)
        owner._replay_reservation = None
        owner._replay_status = _ReplayStatus(
            generation=generation,
            phase=_ReplayPhase.IDLE,
            reservation_present=False,
        )
        owner._replay_test_barrier = None
        owner._healthy = True
        owner._closed = False
        try:
            if connection.in_transaction:
                raise ProjectionConflict(
                    "Projection V2 owner cannot adopt an active transaction"
                )
            _verify_v2_schema(connection)
            cursor = _current_v2_cursor(connection)
            acceptance_cursor = owner._healthy_acceptance_cursor()
            ack_boundary = owner._freeze_ack_boundary(acceptance_cursor)
            if cursor is not None and cursor.source_sequence > acceptance_cursor:
                raise ProjectionConflict(
                    "Projection V2 cursor exceeds authenticated acceptance"
                )
            if cursor is not None and cursor.source_sequence > ack_boundary.confirmed_through:
                raise ProjectionConflict(
                    "Projection V2 cursor exceeds authenticated ACK confirmation"
                )
            owner._validate_cursor_evidence(connection, cursor)
            predecessor = _predecessor_v2(generation, cursor)
            created_authority = _create_correlation_projection_authority(
                evidence,
                registry,
                predecessor,
            )
            owner._authority = created_authority
            prefix_sha256 = owner._validate_persisted_prefix(
                connection,
                created_authority,
                predecessor,
                cursor,
            )
            owner._revalidate_reopen_authority(
                connection,
                created_authority,
                predecessor,
                cursor,
                acceptance_cursor,
                ack_boundary,
                prefix_sha256,
            )
        except ProjectionConflict as error:
            owner._healthy = False
            owner._close_after_factory_failure(error)
            raise
        except Exception as error:
            owner._healthy = False
            owner._close_after_factory_failure(error)
            raise ProjectionAuthorityError(
                "Projection V2 owner authority could not be created"
            ) from error
        except BaseException as error:
            owner._healthy = False
            owner._close_after_factory_failure(error)
            raise
        return owner

    def _revalidate_reopen_authority(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        cursor: ProjectionCursor | None,
        acceptance_cursor: int,
        ack_boundary: _ProjectionAckBoundaryV2,
        prefix_sha256: str,
    ) -> None:
        observed_ack_boundary = ack_boundary
        for _pass in range(2):
            if self._healthy_acceptance_cursor() != acceptance_cursor:
                raise ProjectionAuthorityError(
                    "Projection V2 acceptance changed during reopen"
                )
            current_cursor = _current_v2_cursor(connection)
            if current_cursor != cursor:
                raise ProjectionConflict(
                    "Projection V2 cursor changed during reopen"
                )
            self._validate_cursor_evidence(connection, current_cursor)
            if _v2_snapshot_hash(connection) != prefix_sha256:
                raise ProjectionConflict(
                    "Projection V2 persisted prefix changed during reopen"
                )
            _validate_correlation_projection_predecessor(
                authority,
                predecessor,
            )
            observed_ack_boundary = self._revalidate_ack_boundary(
                observed_ack_boundary,
                acceptance_cursor,
            )

    def _healthy_acceptance_cursor(self) -> int:
        return _healthy_acceptance_cursor_v2(
            self._evidence,
            self._evidence_lifecycle,
        )

    def _current_ack_boundary(self) -> _ProjectionAckBoundaryV2:
        acknowledgements = self._acknowledgements
        if (
            type(acknowledgements) is not AckJournal
            or acknowledgements._store is not self._evidence
            or acknowledgements._lifecycle_identity is not self._ack_lifecycle
            or self._ack_lifecycle is not self._evidence_lifecycle
            or getattr(self._evidence, "_ack_journal_owner", None)
            is not acknowledgements
        ):
            raise ProjectionAuthorityError(
                "Projection V2 ACK journal changed lifecycle"
            )
        try:
            snapshot = acknowledgements.snapshot()
            self._evidence._validate_ack_journal_owner(
                acknowledgements,
                self._ack_lifecycle,
            )
            commitment = self._evidence._validate_ack_commitment_binding()
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 ACK authority is unavailable"
            ) from error
        if type(snapshot) is not AckJournalSnapshot or snapshot.healthy is not True:
            raise ProjectionAuthorityError(
                "Projection V2 ACK snapshot is not exact and healthy"
            )
        confirmed = _exact_ack_identity_v2(snapshot.confirmed)
        pending = _exact_ack_identity_v2(snapshot.pending)
        private_confirmed = _exact_ack_identity_v2(
            getattr(acknowledgements, "_confirmed", None)
        )
        private_pending = _exact_ack_identity_v2(
            getattr(acknowledgements, "_pending", None)
        )
        generation = getattr(acknowledgements, "_confirmed_generation", None)
        prefix_size = getattr(acknowledgements, "_committed_prefix_size", None)
        prefix_sha256 = getattr(
            acknowledgements,
            "_committed_prefix_sha256",
            None,
        )
        if (
            confirmed != private_confirmed
            or pending != private_pending
            or type(generation) is not int
            or not 0 <= generation <= MAX_UINT64
            or type(prefix_size) is not int
            or prefix_size < 0
            or type(prefix_sha256) is not str
            or _HEX64_V2.fullmatch(prefix_sha256) is None
            or (confirmed is None) != (generation == 0)
        ):
            raise ProjectionAuthorityError(
                "Projection V2 ACK committed boundary is inconsistent"
            )
        durable_confirmed = getattr(commitment, "confirmed", None)
        if confirmed is None:
            durable_identity_matches = durable_confirmed is None
        else:
            durable_identity_matches = (
                durable_confirmed is not None
                and getattr(durable_confirmed, "sequence", None)
                == confirmed.sequence
                and getattr(durable_confirmed, "event_id", None)
                == confirmed.event_id
                and getattr(durable_confirmed, "content_sha256", None)
                == confirmed.content_sha256
            )
        if (
            getattr(commitment, "phase", None) != "ready"
            or getattr(commitment, "generation", None) != generation
            or getattr(commitment, "journal_prefix_size", None) != prefix_size
            or getattr(commitment, "journal_prefix_sha256", None)
            != prefix_sha256
            or not durable_identity_matches
        ):
            raise ProjectionAuthorityError(
                "Projection V2 ACK cache differs from durable commitment"
            )
        try:
            if acknowledgements._hash_held_prefix(prefix_size).hex() != prefix_sha256:
                raise ProjectionAuthorityError(
                    "Projection V2 ACK committed prefix changed"
                )
            if confirmed is not None:
                self._evidence._validate_ack_identity(
                    acknowledgements,
                    self._ack_lifecycle,
                    sequence=confirmed.sequence,
                    event_id=confirmed.event_id,
                    content_sha256=confirmed.content_sha256,
                )
            if pending is not None:
                next_record = next(
                    self._evidence.iter_authenticated_records(
                        after=0 if confirmed is None else confirmed.sequence,
                    ),
                    None,
                )
                if (
                    next_record is None
                    or AckIdentity.from_ref(next_record.ref) != pending
                ):
                    raise ProjectionAuthorityError(
                        "Projection V2 pending ACK is not the next evidence ref"
                    )
        except ProjectionAuthorityError:
            raise
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 ACK boundary does not bind evidence"
            ) from error
        return _ProjectionAckBoundaryV2(
            confirmed=confirmed,
            pending=pending,
            generation=generation,
            prefix_size=prefix_size,
            prefix_sha256=prefix_sha256,
        )

    def _freeze_ack_boundary(
        self,
        acceptance_cursor: int,
    ) -> _ProjectionAckBoundaryV2:
        boundary = self._current_ack_boundary()
        if boundary.confirmed_through > acceptance_cursor:
            raise ProjectionAuthorityError(
                "Projection V2 ACK confirmation exceeds authenticated acceptance"
            )
        return boundary

    def _freeze_unpublished_ack_anchor(
        self,
        acceptance_cursor: int,
    ) -> _AckUnpublishedAnchor:
        boundary = self._freeze_ack_boundary(acceptance_cursor)
        acknowledgements = self._acknowledgements
        try:
            anchor = acknowledgements._capture_unpublished_anchor(
                acceptance_cursor,
                _factory=_ACK_UNPUBLISHED_ANCHOR_FACTORY,
            )
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 unpublished ACK lost its authenticated anchor"
            ) from error
        if (
            anchor.lifecycle is not self._ack_lifecycle
            or anchor.confirmed != boundary.confirmed
            or anchor.pending != boundary.pending
            or anchor.generation != boundary.generation
            or anchor.prefix_size != boundary.prefix_size
            or anchor.prefix_sha256 != boundary.prefix_sha256
        ):
            raise ProjectionAuthorityError(
                "Projection V2 unpublished ACK boundary changed during capture"
            )
        return anchor

    def _revalidate_unpublished_ack_anchor(
        self,
        anchor: _AckUnpublishedAnchor,
        acceptance_cursor: int,
    ) -> None:
        acknowledgements = self._acknowledgements
        try:
            if (
                type(anchor) is not _AckUnpublishedAnchor
                or type(acceptance_cursor) is not int
                or acceptance_cursor != anchor.acceptance_cursor
                or self._healthy_acceptance_cursor() != acceptance_cursor
            ):
                raise ProjectionAuthorityError(
                    "Projection V2 unpublished ACK acceptance changed"
                )
            acknowledgements._revalidate_unpublished_anchor(anchor)
        except ProjectionAuthorityError:
            raise
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 unpublished ACK anchor changed"
            ) from error

    def _revalidate_ack_boundary(
        self,
        frozen: _ProjectionAckBoundaryV2,
        acceptance_cursor: int,
    ) -> _ProjectionAckBoundaryV2:
        if type(frozen) is not _ProjectionAckBoundaryV2:
            raise ProjectionAuthorityError(
                "Projection V2 frozen ACK boundary is not exact"
            )
        current = self._freeze_ack_boundary(acceptance_cursor)
        if (
            current.confirmed_through < frozen.confirmed_through
            or current.generation < frozen.generation
            or current.prefix_size < frozen.prefix_size
        ):
            raise ProjectionAuthorityError(
                "Projection V2 ACK boundary moved backwards"
            )
        if current.confirmed_through == frozen.confirmed_through:
            if (
                current.confirmed != frozen.confirmed
                or current.generation != frozen.generation
                or current.prefix_size != frozen.prefix_size
                or current.prefix_sha256 != frozen.prefix_sha256
            ):
                raise ProjectionAuthorityError(
                    "Projection V2 ACK boundary was substituted"
                )
            if frozen.pending is not None and current.pending != frozen.pending:
                raise ProjectionAuthorityError(
                    "Projection V2 frozen pending ACK was replaced"
                )
        try:
            if (
                self._acknowledgements._hash_held_prefix(
                    frozen.prefix_size
                ).hex()
                != frozen.prefix_sha256
            ):
                raise ProjectionAuthorityError(
                    "Projection V2 frozen ACK prefix changed"
                )
            if frozen.confirmed is not None:
                self._evidence._validate_ack_identity(
                    self._acknowledgements,
                    self._ack_lifecycle,
                    sequence=frozen.confirmed.sequence,
                    event_id=frozen.confirmed.event_id,
                    content_sha256=frozen.confirmed.content_sha256,
                )
        except ProjectionAuthorityError:
            raise
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 frozen ACK prefix is unavailable"
            ) from error
        return current

    def _require_usable(self) -> tuple[sqlite3.Connection, CorrelationProjectionAuthority]:
        with self._replay_state_lock:
            if self._replay_reservation is not None:
                raise ProjectionAuthorityError(
                    "Projection V2 replay reservation is active"
                )
        if self._closed:
            raise ProjectionUnhealthy("Projection V2 owner is closed")
        if not self._healthy:
            raise ProjectionUnhealthy("Projection V2 owner is unhealthy")
        connection = self._connection
        authority = self._authority
        if connection is None or authority is None:
            self._healthy = False
            raise ProjectionUnhealthy("Projection V2 owner lost its resources")
        return connection, authority

    def _replay_status_for_test(self) -> _ReplayStatus:
        with self._replay_state_lock:
            status = self._replay_status
            return _ReplayStatus(
                generation=status.generation,
                phase=status.phase,
                reservation_present=status.reservation_present,
            )

    def _register_replay_status_barrier_for_test(
        self,
        phase: _ReplayPhase,
    ) -> None:
        if type(phase) is not _ReplayPhase or phase not in (
            _ReplayPhase.COMPUTING,
            _ReplayPhase.VALIDATING,
        ):
            raise ProjectionAuthorityError(
                "Projection V2 replay barrier phase is invalid"
            )
        with self._replay_state_condition:
            if self._replay_test_barrier is not None:
                raise ProjectionAuthorityError(
                    "Projection V2 replay barrier is already registered"
                )
            self._replay_test_barrier = _ReplayTestBarrier(phase=phase)

    def _release_replay_status_barrier_for_test(
        self,
        phase: _ReplayPhase,
    ) -> None:
        with self._replay_state_condition:
            barrier = self._replay_test_barrier
            if barrier is None or barrier.phase is not phase:
                raise ProjectionAuthorityError(
                    "Projection V2 replay barrier does not match"
                )
            barrier.released = True
            self._replay_state_condition.notify_all()

    def _set_replay_status_locked(self, status: _ReplayStatus) -> None:
        self._replay_status = status
        barrier = self._replay_test_barrier
        if barrier is None or barrier.phase is not status.phase:
            return
        self._replay_state_condition.notify_all()
        self._replay_state_condition.wait_for(
            lambda: barrier.released,
            timeout=5.0,
        )
        if self._replay_test_barrier is barrier:
            self._replay_test_barrier = None

    def _validate_cursor_evidence(
        self,
        connection: sqlite3.Connection,
        cursor: ProjectionCursor | None,
    ) -> None:
        cursor_ref = _current_v2_cursor_ref(connection)
        if (cursor is None) != (cursor_ref is None):
            raise ProjectionConflict("Projection V2 cursor identity is incomplete")
        if cursor is None:
            return
        assert cursor_ref is not None
        if (
            cursor_ref.source_sequence != cursor.source_sequence
            or cursor_ref.event_id != cursor.event_id
            or cursor_ref.content_sha256 != cursor.content_sha256
            or cursor_ref.frame_sha256 != cursor.frame_sha256
        ):
            raise ProjectionConflict("Projection V2 cursor ref changed")
        try:
            resolved = self._evidence.resolve_authenticated_ref(cursor_ref)
        except EvidenceStoreError as error:
            raise ProjectionAuthorityError(
                "Projection V2 cursor is outside authenticated evidence"
            ) from error
        if resolved.ref != cursor_ref:
            raise ProjectionAuthorityError(
                "Projection V2 cursor does not bind exact authenticated evidence"
            )

    def _latch_unhealthy(self, primary: BaseException | None = None) -> None:
        self._healthy = False
        authority = self._authority
        if authority is None:
            return
        try:
            _close_correlation_projection_authority(authority)
        except BaseException as error:  # noqa: BLE001 - retain ambiguous handle
            if primary is not None:
                primary.add_note(
                    "secondary Projection V2 authority-close failure: "
                    f"{type(error).__name__}: {error}"
                )
        else:
            self._authority = None

    @staticmethod
    def _retry_rows_for_authority(
        connection: sqlite3.Connection,
        table: str,
        columns: tuple[str, ...],
        authority_column: str,
        authority_event_id: str,
        *,
        limit: int,
    ) -> list[sqlite3.Row]:
        selected = ",".join(columns)
        primary_key = next(
            item[2] for item in _TABLE_LAYOUT_V2 if item[0] == table
        )
        order = ",".join(
            f"{column} COLLATE BINARY" for column in primary_key
        )
        return connection.execute(
            f"SELECT {selected} FROM {table} WHERE {authority_column}=? "
            f"ORDER BY {order} LIMIT {limit}",
            (authority_event_id,),
        ).fetchall()

    def _validate_retry_base_closure(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedV2Record,
        *,
        is_primary: bool,
    ) -> None:
        event_id = prepared.envelope.event_id
        coverage_rows = connection.execute(
            "SELECT host_id,component,kind,severity,opened_at,closed_at,"
            "affected_source_sequence_start,affected_source_sequence_end,"
            "dropped_count,reason_code,reconcile_generation,source_sequence,"
            "content_sha256 FROM coverage_intervals WHERE event_id=? LIMIT 2",
            (event_id,),
        ).fetchall()
        process_rows = connection.execute(
            "SELECT host_id,container_id,container_started_at,proc_name,"
            "proc_exe_path,proc_parent_name,source_sequence,content_sha256 "
            "FROM process_observations WHERE event_id=? LIMIT 2",
            (event_id,),
        ).fetchall()
        network_rows = connection.execute(
            "SELECT host_id,container_id,container_started_at,successful_connect,"
            "destination_ipv4,destination_port,l4_protocol,investigation_only,"
            "source_sequence,content_sha256 FROM network_observations "
            "WHERE event_id=? LIMIT 2",
            (event_id,),
        ).fetchall()
        if not is_primary:
            if coverage_rows or process_rows or network_rows:
                raise ProjectionConflict(
                    "Projection V2 duplicate retry has reducer side effects"
                )
            return
        ref = prepared.record.ref
        sequence = _encode_uint64_v2(ref.source_sequence)
        if prepared.coverage is not None:
            coverage = prepared.coverage
            expected_coverage = (
                prepared.envelope.host_id,
                coverage.component,
                coverage.kind,
                coverage.severity,
                coverage.opened_at,
                coverage.closed_at,
                _optional_uint64_v2(coverage.affected_source_sequence_start),
                _optional_uint64_v2(coverage.affected_source_sequence_end),
                _optional_uint64_v2(coverage.dropped_count),
                coverage.reason_code,
                _optional_uint64_v2(coverage.reconcile_generation),
                sequence,
                ref.content_sha256,
            )
            if (
                len(coverage_rows) != 1
                or tuple(coverage_rows[0]) != expected_coverage
                or process_rows
                or network_rows
            ):
                raise ProjectionConflict(
                    "Projection V2 coverage retry closure changed"
                )
            return
        falco = prepared.falco
        if falco is None:
            if coverage_rows or process_rows or network_rows:
                raise ProjectionConflict(
                    "Projection V2 generic retry has reducer side effects"
                )
            return
        expected_process = (
            prepared.envelope.host_id,
            falco.docker_container_id,
            falco.docker_started_at,
            falco.proc_name,
            falco.proc_exe_path,
            falco.proc_parent_name,
            sequence,
            ref.content_sha256,
        )
        expected_network = (
            prepared.envelope.host_id,
            falco.docker_container_id,
            falco.docker_started_at,
            int(falco.successful_connect),
            falco.destination_ipv4,
            falco.destination_port,
            falco.l4_protocol,
            int(falco.investigation_only),
            sequence,
            ref.content_sha256,
        )
        if (
            coverage_rows
            or len(process_rows) != 1
            or tuple(process_rows[0]) != expected_process
            or len(network_rows) != 1
            or tuple(network_rows[0]) != expected_network
        ):
            raise ProjectionConflict(
                "Projection V2 Falco retry closure changed"
            )

    def _retry_pcc_result(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
    ) -> tuple[
        AuthenticatedPCCInput,
        CandidateCreated | Duplicate | InvestigationOnly | Rejected,
    ]:
        completed = self._journal.completed_for_snapshot(prepared.record.ref)
        proof = _revalidate_completed_snapshot(completed)
        if (
            type(proof) is not AuthenticatedPCCInput
            or not self._evidence._authenticated_pcc_input_is_exact(proof)
            or type(proof.evidence_ref) is not EvidenceRef
            or proof.evidence_ref != prepared.record.ref
        ):
            raise ProjectionAuthorityError(
                "Projection V2 retry lost completed PCC authority"
            )
        if proof.snapshot.outcome == "failed":
            result = correlate_pcc(proof, CorrelationContext.failed_snapshot())
        else:
            key = _duplicate_key(proof, proof.snapshot)
            trigger = proof.snapshot.trigger
            active = _historical_active_duplicate_v2(
                connection,
                key,
                current_trigger_order=(
                    trigger.source_sequence,
                    trigger.event_id,
                ),
            )
            issued_proof, context = _issue_correlation_context(
                authority,
                completed,
                expected_predecessor=predecessor,
                active_duplicate=active,
                historical_access=None,
            )
            if not _same_exact_pcc(proof, issued_proof):
                raise ProjectionAuthorityError(
                    "Projection V2 retry issued a changed PCC"
                )
            result = correlate_pcc(issued_proof, context)
        final = _revalidate_completed_snapshot(completed)
        if not _same_exact_pcc(proof, final):
            raise ProjectionAuthorityError(
                "Projection V2 completed PCC changed during retry"
            )
        if not isinstance(
            result,
            (CandidateCreated, Duplicate, InvestigationOnly, Rejected),
        ):
            raise ProjectionAuthorityError(
                "Projection V2 retry correlation result is not closed"
            )
        return proof, result

    def _validate_retry_security_closure(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        *,
        is_primary: bool,
    ) -> None:
        event_id = prepared.envelope.event_id
        self._validate_coverage_invalidation_closure(
            connection,
            prepared,
            is_primary=is_primary,
        )
        incident_rows = self._retry_rows_for_authority(
            connection,
            "incidents",
            _INCIDENT_COLUMNS,
            "authority_event_id",
            event_id,
            limit=2,
        )
        candidate_rows = self._retry_rows_for_authority(
            connection,
            "candidates",
            _CANDIDATE_COLUMNS,
            "correlation_snapshot_event_id",
            event_id,
            limit=2,
        )
        evidence_rows = self._retry_rows_for_authority(
            connection,
            "candidate_evidence",
            _TABLE_LAYOUT_V2[9][1],
            "authority_snapshot_event_id",
            event_id,
            limit=3,
        )
        if not is_primary:
            if incident_rows or candidate_rows or evidence_rows:
                raise ProjectionConflict(
                    "Projection V2 duplicate retry has security side effects"
                )
            return
        if prepared.envelope.event_type == "pcc_correlation_snapshot":
            proof, result = self._retry_pcc_result(
                connection,
                authority,
                predecessor,
                prepared,
            )
            if isinstance(result, CandidateCreated):
                result_kind = "candidate"
            elif isinstance(result, Duplicate):
                result_kind = "duplicate"
            elif isinstance(result, InvestigationOnly):
                result_kind = "investigation"
            else:
                result_kind = "rejected"
            if (
                len(incident_rows) != 1
                or tuple(incident_rows[0])
                != _encode_incident(result.incident, result_kind)
            ):
                raise ProjectionConflict(
                    "Projection V2 PCC retry incident closure changed"
                )
            if isinstance(result, CandidateCreated):
                candidate_id = result.candidate.candidate_id
                expected_roles = (
                    ("primary_trigger", proof.snapshot.trigger),
                    ("correlation_snapshot", proof),
                )
                if (
                    len(candidate_rows) != 1
                    or tuple(candidate_rows[0])
                    != _encode_candidate(result.candidate)
                ):
                    raise ProjectionConflict(
                        "Projection V2 PCC retry candidate closure changed"
                    )
            elif isinstance(result, Duplicate):
                candidate_id = result.existing_candidate_id
                expected_roles = (
                    ("supporting_trigger", proof.snapshot.trigger),
                    ("supporting_snapshot", proof),
                )
                if candidate_rows:
                    raise ProjectionConflict(
                        "Projection V2 duplicate retry created a candidate"
                    )
                retained = connection.execute(
                    f"SELECT {','.join(_CANDIDATE_COLUMNS)} FROM candidates "
                    "WHERE candidate_id=? LIMIT 2",
                    (candidate_id,),
                ).fetchall()
                if len(retained) != 1:
                    raise ProjectionConflict(
                        "Projection V2 duplicate retry lost its candidate"
                    )
                _decode_candidate(retained[0])
            else:
                if candidate_rows or evidence_rows:
                    raise ProjectionConflict(
                        "Projection V2 non-candidate retry has candidate facts"
                    )
                return
            expected_evidence = sorted(
                _encode_candidate_evidence(
                    candidate_id,
                    evidence.event_id,
                    evidence.source_sequence,
                    evidence.content_sha256,
                    role,
                    proof.event_id,
                )
                for role, evidence in expected_roles
            )
            actual_evidence = sorted(tuple(row) for row in evidence_rows)
            if actual_evidence != expected_evidence:
                raise ProjectionConflict(
                    "Projection V2 PCC retry evidence closure changed"
                )
            return
        if candidate_rows or evidence_rows:
            raise ProjectionConflict(
                "Projection V2 non-PCC retry has candidate facts"
            )
        falco = prepared.falco
        incident_expected = (
            falco is not None
            and (
                not falco.successful_connect
                or bool(falco.missing_required_fields)
                or falco.investigation_only
            )
        )
        if not incident_expected:
            if incident_rows:
                raise ProjectionConflict(
                    "Projection V2 retry has an unexpected incident"
                )
            return
        verifier = self._evidence._bound_verifier
        if verifier is None:
            raise ProjectionAuthorityError(
                "Projection V2 retry lost Falco verifier authority"
            )
        try:
            authenticated = self._evidence._authenticated_falco_input(
                verifier,
                prepared.record.ref,
            )
            incident = incident_from_verified_falco(authenticated)
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 retry Falco authority is unavailable"
            ) from error
        if (
            len(incident_rows) != 1
            or tuple(incident_rows[0])
            != _encode_incident(incident, "investigation")
        ):
            raise ProjectionConflict(
                "Projection V2 direct-incident retry closure changed"
            )

    def _validate_retry_closure(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        *,
        is_primary: bool,
    ) -> None:
        self._validate_retry_base_closure(
            connection,
            prepared,
            is_primary=is_primary,
        )
        self._validate_retry_security_closure(
            connection,
            authority,
            predecessor,
            prepared,
            is_primary=is_primary,
        )

    def _validate_persisted_prefix(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        cursor: ProjectionCursor | None,
    ) -> str:
        prefix_sha256 = _v2_snapshot_hash(connection)
        if cursor is None:
            nonempty = tuple(
                table
                for table, _columns, _primary_key in _TABLE_LAYOUT_V2[1:]
                if connection.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                != 0
            )
            if nonempty:
                raise ProjectionConflict(
                    "Projection V2 has facts without a cursor"
                )
            return prefix_sha256
        try:
            records = tuple(
                self._evidence.iter_authenticated_records(
                    after=0,
                    through=cursor.source_sequence,
                )
            )
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 persisted prefix is unavailable"
            ) from error
        if (
            not records
            or records[-1].ref.source_sequence != cursor.source_sequence
            or records[-1].ref.event_id != cursor.event_id
            or records[-1].ref.content_sha256 != cursor.content_sha256
            or records[-1].ref.frame_sha256 != cursor.frame_sha256
            or connection.execute("SELECT count(*) FROM events").fetchone()[0]
            != len(records)
            or connection.execute(
                "SELECT count(*) FROM projection_dedup"
            ).fetchone()[0]
            != len(records)
        ):
            raise ProjectionConflict(
                "Projection V2 persisted prefix does not match its cursor"
            )
        expected_containers: dict[
            tuple[str, str, str],
            tuple[_PreparedV2Record, _PreparedV2Record],
        ] = {}
        logical_primaries: dict[tuple[str, str], str] = {}
        selected = ",".join(_TABLE_LAYOUT_V2[1][1])
        for record in records:
            prepared = _prepare_v2(record)
            logical_key = (
                prepared.dedup_kind,
                prepared.logical_key_sha256,
            )
            source_primary = logical_primaries.setdefault(
                logical_key,
                prepared.envelope.event_id,
            )
            expected_duplicate = (
                None
                if source_primary == prepared.envelope.event_id
                else source_primary
            )
            row = connection.execute(
                f"SELECT {selected} FROM events WHERE event_id=?",
                (prepared.envelope.event_id,),
            ).fetchone()
            if row is None:
                raise ProjectionConflict(
                    "Projection V2 persisted prefix lost an event"
                )
            duplicate = row["duplicate_of_event_id"]
            if duplicate is not None and (
                type(duplicate) is not str
                or _EVENT_ID_V2.fullmatch(duplicate) is None
            ):
                raise ProjectionConflict(
                    "Projection V2 persisted duplicate identity is invalid"
                )
            if duplicate != expected_duplicate:
                raise ProjectionConflict(
                    "Projection V2 persisted logical primary differs from "
                    "authenticated source order"
                )
            if tuple(row) != _event_values_v2(prepared, expected_duplicate):
                raise ProjectionConflict(
                    "Projection V2 persisted event facts changed"
                )
            is_primary = expected_duplicate is None
            dedup = connection.execute(
                "SELECT dedup_kind,logical_key_sha256,primary_event_id,is_primary "
                "FROM projection_dedup WHERE event_id=?",
                (prepared.envelope.event_id,),
            ).fetchone()
            if dedup is None or tuple(dedup) != (
                prepared.dedup_kind,
                prepared.logical_key_sha256,
                source_primary,
                int(is_primary),
            ):
                raise ProjectionConflict(
                    "Projection V2 persisted dedup facts changed"
                )
            if expected_duplicate is not None:
                primary = connection.execute(
                    "SELECT dedup_kind,logical_key_sha256,primary_event_id,is_primary "
                    "FROM projection_dedup WHERE event_id=?",
                    (source_primary,),
                ).fetchone()
                if primary is None or tuple(primary) != (
                    prepared.dedup_kind,
                    prepared.logical_key_sha256,
                    source_primary,
                    1,
                ):
                    raise ProjectionConflict(
                        "Projection V2 persisted logical primary changed"
                    )
            self._validate_retry_closure(
                connection,
                authority,
                predecessor,
                prepared,
                is_primary=is_primary,
            )
            falco = prepared.falco
            if (
                is_primary
                and falco is not None
                and falco.docker_container_id is not None
                and falco.docker_started_at is not None
            ):
                key = (
                    prepared.envelope.host_id,
                    falco.docker_container_id,
                    falco.docker_started_at,
                )
                first = expected_containers.get(key, (prepared, prepared))[0]
                expected_containers[key] = (first, prepared)
        actual_containers = _ordered_v2_rows_unverified(
            connection,
            "containers",
        )
        expected_rows: list[tuple[object, ...]] = []
        for key, (first, last) in expected_containers.items():
            first_falco = first.falco
            last_falco = last.falco
            if first_falco is None or last_falco is None:
                raise AssertionError("Projection V2 container facts lost Falco input")
            expected_rows.append(
                (
                    *key,
                    last_falco.image_id,
                    canonical_json(last_falco.repo_digests).decode("utf-8"),
                    last_falco.immutable_spec_sha256,
                    _optional_uint64_v2(last_falco.inventory_revision),
                    first.envelope.event_id,
                    _encode_uint64_v2(first.record.ref.source_sequence),
                    first.record.ref.content_sha256,
                    last.envelope.event_id,
                    _encode_uint64_v2(last.record.ref.source_sequence),
                    last.record.ref.content_sha256,
                )
            )
        if actual_containers != sorted(expected_rows):
            raise ProjectionConflict(
                "Projection V2 persisted container closure changed"
            )
        return prefix_sha256

    def _exact_retry(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
    ) -> ProjectionApplyResult | None:
        selected = ",".join(_TABLE_LAYOUT_V2[1][1])
        row = connection.execute(
            f"SELECT {selected} FROM events WHERE event_id=?",
            (prepared.envelope.event_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            _v2_snapshot_hash(connection)
        except ProjectionConflict:
            self._latch_unhealthy()
            raise
        duplicate = row["duplicate_of_event_id"]
        if duplicate is not None and (
            type(duplicate) is not str or _EVENT_ID_V2.fullmatch(duplicate) is None
        ):
            self._latch_unhealthy()
            raise ProjectionConflict("Projection V2 retry duplicate identity is invalid")
        if tuple(row) != _event_values_v2(prepared, duplicate):
            self._latch_unhealthy()
            raise ProjectionConflict("Projection V2 event retry facts changed")
        dedup = connection.execute(
            "SELECT dedup_kind,logical_key_sha256,primary_event_id,is_primary "
            "FROM projection_dedup WHERE event_id=?",
            (prepared.envelope.event_id,),
        ).fetchone()
        expected_primary = prepared.envelope.event_id if duplicate is None else duplicate
        if dedup is None or tuple(dedup) != (
            prepared.dedup_kind,
            prepared.logical_key_sha256,
            expected_primary,
            int(duplicate is None),
        ):
            self._latch_unhealthy()
            raise ProjectionConflict("Projection V2 retry dedup facts changed")
        cursor = _current_v2_cursor(connection)
        if cursor is None or cursor.source_sequence < prepared.envelope.source_sequence:
            self._latch_unhealthy()
            raise ProjectionConflict("Projection V2 retry is ahead of its cursor")
        try:
            prefix_sha256 = self._validate_persisted_prefix(
                connection,
                authority,
                predecessor,
                cursor,
            )
            if (
                _current_v2_cursor(connection) != cursor
                or _v2_snapshot_hash(connection) != prefix_sha256
            ):
                raise ProjectionConflict(
                    "Projection V2 persisted prefix changed during retry"
                )
            self._validate_cursor_evidence(connection, cursor)
            _validate_correlation_projection_predecessor(
                authority,
                predecessor,
            )
        except ProjectionConflict:
            self._latch_unhealthy()
            raise
        except (
            ProjectionAuthorityError,
            CorrelationProjectionError,
            CorrelationRequestJournalError,
            EvidenceStoreError,
            HistoricalCoverageConflict,
            HistoricalCoverageUnavailable,
            AttributeError,
            TypeError,
            ValueError,
        ) as error:
            self._latch_unhealthy(error)
            raise ProjectionAuthorityError(
                "Projection V2 retry authority could not be revalidated"
            ) from error
        return ProjectionApplyResult(
            event_id=prepared.envelope.event_id,
            duplicate_of_event_id=duplicate,
            reducer_applied=False,
            cursor=cursor,
        )

    def apply(self, ref: EvidenceRef) -> ProjectionApplyResult:
        with self._mutex:
            connection, authority = self._require_usable()
            if type(ref) is not EvidenceRef:
                raise ProjectionAuthorityError(
                    "Projection V2 apply requires an exact evidence ref"
                )
            try:
                _verify_v2_schema(connection)
                record = self._evidence.resolve_authenticated_ref(ref)
            except ProjectionConflict:
                self._latch_unhealthy()
                raise
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 ref is not exact authenticated evidence"
                ) from error
            prepared = _prepare_v2(record)
            acceptance_cursor = self._healthy_acceptance_cursor()
            ack_boundary = self._freeze_ack_boundary(acceptance_cursor)
            if prepared.record.ref.source_sequence > acceptance_cursor:
                raise ProjectionAuthorityError(
                    "Projection V2 ref exceeds contiguous authenticated acceptance"
                )
            if prepared.record.ref.source_sequence > ack_boundary.confirmed_through:
                raise ProjectionAuthorityError(
                    "Projection V2 ref exceeds authenticated ACK confirmation"
                )
            cursor = _current_v2_cursor(connection)
            self._validate_cursor_evidence(connection, cursor)
            if cursor is not None and cursor.host_id != prepared.envelope.host_id:
                self._latch_unhealthy()
                raise ProjectionConflict("Projection V2 cursor host changed")
            predecessor = _predecessor_v2(self._generation, cursor)
            _validate_correlation_projection_predecessor(authority, predecessor)
            retry = self._exact_retry(
                connection,
                authority,
                predecessor,
                prepared,
            )
            if retry is not None:
                self._revalidate_ack_boundary(ack_boundary, acceptance_cursor)
                _validate_correlation_projection_predecessor(authority, predecessor)
                return retry
            after = 0 if cursor is None else cursor.source_sequence
            try:
                records = self._evidence.iter_authenticated_records(
                    after=after,
                    through=ack_boundary.confirmed_through,
                )
                next_record = next(records, None)
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 source-order authority is unavailable"
                ) from error
            if next_record is None or next_record.ref != prepared.record.ref:
                raise ProjectionAuthorityError(
                    "Projection V2 ref is not the next authenticated record"
                )
            return self._apply_prepared(
                connection,
                authority,
                predecessor,
                prepared,
                acceptance_cursor,
                ack_boundary,
            )

    def _replay_unpublished_prefix(
        self,
        through: EvidenceRef,
        *,
        _factory: object,
        _fault_phase: _ReplayFaultPhase | None = None,
    ) -> _UnpublishedV2ReplayReport:
        if (
            _factory is not _UNPUBLISHED_REPLAY_FACTORY
            or type(through) is not EvidenceRef
            or (
                _fault_phase is not None
                and type(_fault_phase) is not _ReplayFaultPhase
            )
        ):
            raise ProjectionAuthorityError(
                "Projection V2 unpublished replay is factory-only"
            )
        try:
            through_key = _exact_coverage_ref_key(through)
        except ValueError as error:
            raise ProjectionAuthorityError(
                "Projection V2 unpublished terminal is not exact"
            ) from error

        reservation: _ReplayReservation | None = None
        source_snapshot: _ReplaySourceSnapshot | None = None
        ack_snapshot: _AckReplaySnapshot | None = None
        journal_snapshot: _CorrelationJournalReplaySnapshot | None = None
        hydrated_connection: sqlite3.Connection | None = None
        primary_error: BaseException | None = None
        published = False
        base_generation = self._generation
        try:
            with self._mutex:
                connection, authority = self._require_usable()
                if self._generation >= MAX_UINT64:
                    raise ProjectionAuthorityError(
                        "Projection V2 replay generation is exhausted"
                    )
                _verify_v2_schema(connection)
                if _current_v2_cursor(connection) is not None or any(
                    connection.execute(
                        f"SELECT count(*) FROM {table}"
                    ).fetchone()[0]
                    for table, _columns, _primary_key in _TABLE_LAYOUT_V2[1:]
                ):
                    raise ProjectionConflict(
                        "Projection V2 unpublished replay requires an empty database"
                    )
                base_generation = self._generation
                reservation = _ReplayReservation(
                    token=object(),
                    base_generation=base_generation,
                    publish_generation=base_generation + 1,
                    through_key=through_key,
                )
                with self._replay_state_lock:
                    if self._replay_reservation is not None:
                        raise ProjectionAuthorityError(
                            "Projection V2 replay reservation is already active"
                        )
                    self._replay_reservation = reservation
                    self._set_replay_status_locked(
                        _ReplayStatus(
                            generation=base_generation,
                            phase=_ReplayPhase.FREEZING,
                            reservation_present=True,
                        )
                    )

                expected_predecessor = _predecessor_v2(
                    base_generation,
                    None,
                )
                with (
                    self._evidence._replay_source_snapshot_gate(),
                    self._acknowledgements._replay_ack_snapshot_gate(),
                    _correlation_projection_snapshot_gate(
                        authority
                    ) as correlation_binding,
                    _correlation_journal_replay_gate(self._journal),
                ):
                    if (
                        self._connection is not connection
                        or self._authority is not authority
                        or self._generation != base_generation
                    ):
                        raise ProjectionAuthorityError(
                            "Projection V2 replay owner changed during freeze"
                        )
                    source_snapshot = (
                        self._evidence._capture_replay_source_locked(
                            through
                        )
                    )
                    ack_snapshot = (
                        self._acknowledgements._capture_replay_ack_locked(
                            through.source_sequence
                        )
                    )
                    expected_ack = (
                        through.source_sequence,
                        through.event_id,
                        through.content_sha256,
                    )
                    if (
                        ack_snapshot.confirmed != expected_ack
                        or ack_snapshot.pending is not None
                        or ack_snapshot.retention_pending
                    ):
                        raise ProjectionAuthorityError(
                            "Projection V2 replay requires strict ACK equality"
                        )
                    correlation_snapshot = (
                        _capture_correlation_replay_locked(
                            authority,
                            correlation_binding,
                            expected_predecessor,
                        )
                    )
                    journal_snapshot, issued_proofs = (
                        _capture_correlation_journal_replay_locked(
                            self._journal,
                            through_sequence=through.source_sequence,
                        )
                    )
                    pcc_inputs = tuple(
                        _freeze_replay_pcc_seed(
                            proof,
                            detector_bundle_sha256=(
                                correlation_snapshot.detector_bundle_sha256
                            ),
                            registry=correlation_binding.registry,
                            registry_facts_canonical=(
                                correlation_snapshot.registry_facts_canonical
                            ),
                        )
                        for proof in issued_proofs
                    )
                    issued_proofs = ()
                    snapshot = _ReplayInputSnapshot(
                        source=source_snapshot,
                        ack=ack_snapshot,
                        correlation=correlation_snapshot,
                        pcc_inputs=pcc_inputs,
                        schema_domain=(
                            _REPLAY_SCHEMA_DOMAIN_V2
                            + _SCHEMA_V2_PATH.read_bytes()
                        ),
                        base_projection_generation=base_generation,
                        publish_generation=base_generation + 1,
                    )
                    if _fault_phase is _ReplayFaultPhase.FREEZE:
                        raise KeyboardInterrupt(
                            "injected replay freeze failure"
                        )

            assert reservation is not None
            with self._replay_state_lock:
                if self._replay_reservation is not reservation:
                    raise ProjectionAuthorityError(
                        "Projection V2 replay reservation changed after freeze"
                    )
                self._set_replay_status_locked(
                    _ReplayStatus(
                        generation=base_generation,
                        phase=_ReplayPhase.COMPUTING,
                        reservation_present=True,
                    )
                )
            if _fault_phase is _ReplayFaultPhase.COMPUTE:
                raise KeyboardInterrupt("injected replay compute failure")
            try:
                computation = _compute_replay(snapshot)
                hydrated_connection, report = _validate_and_hydrate_replay(
                    snapshot,
                    computation,
                )
            except ProjectionConflict as error:
                raise ProjectionAuthorityError(
                    "Projection V2 replay frozen authority changed"
                ) from error

            with self._mutex:
                if (
                    self._closed
                    or not self._healthy
                    or self._connection is not connection
                    or self._authority is not authority
                    or self._generation != base_generation
                ):
                    raise ProjectionAuthorityError(
                        "Projection V2 replay owner changed before publication"
                    )
                with (
                    self._evidence._replay_source_snapshot_gate(),
                    self._acknowledgements._replay_ack_snapshot_gate(),
                    _correlation_projection_snapshot_gate(
                        authority
                    ) as correlation_binding,
                    _correlation_journal_replay_gate(self._journal),
                ):
                    with self._replay_state_lock:
                        if (
                            self._replay_reservation is not reservation
                            or reservation.base_generation
                            != base_generation
                            or reservation.publish_generation
                            != base_generation + 1
                            or reservation.through_key != through_key
                        ):
                            raise ProjectionAuthorityError(
                                "Projection V2 replay reservation changed"
                            )
                        self._set_replay_status_locked(
                            _ReplayStatus(
                                generation=base_generation,
                                phase=_ReplayPhase.VALIDATING,
                                reservation_present=True,
                            )
                        )
                    self._evidence._revalidate_replay_source_locked(
                        source_snapshot
                    )
                    self._acknowledgements._revalidate_replay_ack_locked(
                        ack_snapshot
                    )
                    _revalidate_correlation_replay_locked(
                        authority,
                        correlation_binding,
                        snapshot.correlation,
                    )
                    if journal_snapshot is None:
                        raise ProjectionAuthorityError(
                            "Projection V2 replay lost journal facts"
                        )
                    _revalidate_correlation_journal_replay_locked(
                        self._journal,
                        journal_snapshot,
                    )
                    if (
                        computation.terminal_predecessor.generation
                        != base_generation + 1
                        or report.cursor.source_sequence
                        != through.source_sequence
                        or report.cursor.event_id != through.event_id
                        or report.cursor.content_sha256
                        != through.content_sha256
                    ):
                        raise ProjectionConflict(
                            "Projection V2 replay publication seal changed"
                        )
                    if _fault_phase is _ReplayFaultPhase.PUBLISH:
                        raise KeyboardInterrupt(
                            "injected replay publish failure"
                        )

                    _close_replay_ack_snapshot(ack_snapshot)
                    ack_snapshot = None
                    _close_replay_source_snapshot(source_snapshot)
                    source_snapshot = None
                    connection.close()
                    _rebuild_correlation_projection_authority(
                        authority,
                        computation.terminal_predecessor,
                    )
                    self._connection = hydrated_connection
                    hydrated_connection = None
                    self._generation = base_generation + 1
                    with self._replay_state_lock:
                        self._replay_reservation = None
                        self._set_replay_status_locked(
                            _ReplayStatus(
                                generation=base_generation + 1,
                                phase=_ReplayPhase.PUBLISHED,
                                reservation_present=False,
                            )
                        )
                    published = True
                    return report
        except (
            AckJournalError,
            CorrelationProjectionError,
            CorrelationRequestJournalError,
            EvidenceStoreError,
        ) as error:
            converted = ProjectionAuthorityError(
                "Projection V2 replay authority changed"
            )
            primary_error = converted
            raise converted from error
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_errors: list[BaseException] = []
            if hydrated_connection is not None:
                try:
                    hydrated_connection.close()
                except BaseException as error:  # noqa: BLE001
                    cleanup_errors.append(error)
            if ack_snapshot is not None:
                try:
                    _close_replay_ack_snapshot(ack_snapshot)
                except BaseException as error:  # noqa: BLE001
                    cleanup_errors.append(error)
            if source_snapshot is not None:
                try:
                    _close_replay_source_snapshot(source_snapshot)
                except BaseException as error:  # noqa: BLE001
                    cleanup_errors.append(error)
            if not published:
                with self._replay_state_lock:
                    if reservation is not None:
                        if self._replay_reservation is reservation:
                            self._replay_reservation = None
                        self._set_replay_status_locked(
                            _ReplayStatus(
                                generation=base_generation,
                                phase=_ReplayPhase.FAILED,
                                reservation_present=False,
                            )
                        )
                    if self._replay_test_barrier is not None:
                        self._replay_test_barrier = None
                        self._replay_state_condition.notify_all()
            if cleanup_errors:
                if primary_error is not None:
                    for cleanup_error in cleanup_errors:
                        primary_error.add_note(
                            "Projection V2 replay cleanup failure: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                else:
                    raise BaseExceptionGroup(
                        "Projection V2 replay cleanup failed",
                        cleanup_errors,
                    )

    def _revalidate_transaction_predecessor(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        acceptance_cursor: int,
        ack_boundary: _ProjectionAckBoundaryV2,
        unpublished_ack: _AckUnpublishedAnchor | None = None,
    ) -> None:
        if self._healthy_acceptance_cursor() != acceptance_cursor:
            raise ProjectionAuthorityError(
                "Projection V2 acceptance cursor changed inside transaction"
            )
        if unpublished_ack is None:
            self._revalidate_ack_boundary(ack_boundary, acceptance_cursor)
        else:
            self._revalidate_unpublished_ack_anchor(
                unpublished_ack,
                acceptance_cursor,
            )
        current = _current_v2_cursor(connection)
        if _predecessor_v2(self._generation, current) != predecessor:
            raise ProjectionConflict(
                "Projection V2 predecessor changed inside its transaction"
            )
        self._validate_cursor_evidence(connection, current)
        _validate_correlation_projection_predecessor(authority, predecessor)
        if unpublished_ack is None:
            self._revalidate_ack_boundary(ack_boundary, acceptance_cursor)
        else:
            self._revalidate_unpublished_ack_anchor(
                unpublished_ack,
                acceptance_cursor,
            )
        if self._healthy_acceptance_cursor() != acceptance_cursor:
            raise ProjectionAuthorityError(
                "Projection V2 acceptance cursor changed during validation"
            )
        try:
            current_record = self._evidence.resolve_authenticated_ref(
                prepared.record.ref
            )
        except EvidenceStoreError as error:
            raise ProjectionAuthorityError(
                "Projection V2 input lost authenticated evidence authority"
            ) from error
        if not _same_stored_record_v2(current_record, prepared.record):
            raise ProjectionAuthorityError(
                "Projection V2 authenticated input changed during transaction"
            )
        _validate_correlation_projection_predecessor(authority, predecessor)

    def _apply_prepared(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        acceptance_cursor: int,
        ack_boundary: _ProjectionAckBoundaryV2,
        unpublished_ack: _AckUnpublishedAnchor | None = None,
    ) -> ProjectionApplyResult:
        envelope = prepared.envelope
        ref = prepared.record.ref
        duplicate: str | None = None
        is_primary = False
        transaction_started = False
        commit_attempted = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction_started = True
            self._revalidate_transaction_predecessor(
                connection,
                authority,
                predecessor,
                prepared,
                acceptance_cursor,
                ack_boundary,
                unpublished_ack,
            )
            duplicate_row = connection.execute(
                "SELECT primary_event_id FROM projection_dedup "
                "WHERE dedup_kind=? AND logical_key_sha256=? AND is_primary=1",
                (prepared.dedup_kind, prepared.logical_key_sha256),
            ).fetchone()
            if duplicate_row is not None:
                duplicate_value = duplicate_row["primary_event_id"]
                if (
                    type(duplicate_value) is not str
                    or _EVENT_ID_V2.fullmatch(duplicate_value) is None
                ):
                    raise ProjectionConflict(
                        "Projection V2 logical primary identity is invalid"
                    )
                duplicate = duplicate_value
            is_primary = duplicate is None
            primary_event_id = envelope.event_id if is_primary else duplicate
            placeholders = ",".join("?" for _ in _TABLE_LAYOUT_V2[1][1])
            connection.execute(
                f"INSERT INTO events({','.join(_TABLE_LAYOUT_V2[1][1])}) "
                f"VALUES({placeholders})",
                _event_values_v2(prepared, duplicate),
            )
            self._step_hook(_APPLY_STEPS_V2[0])
            connection.execute(
                "INSERT INTO projection_dedup("
                "event_id,dedup_kind,logical_key_sha256,primary_event_id,is_primary"
                ") VALUES(?,?,?,?,?)",
                (
                    envelope.event_id,
                    prepared.dedup_kind,
                    prepared.logical_key_sha256,
                    primary_event_id,
                    int(is_primary),
                ),
            )
            self._step_hook(_APPLY_STEPS_V2[1])
            final_authority_check: Callable[[], None] | None = None
            if is_primary:
                final_authority_check = self._reduce_primary(
                    connection,
                    authority,
                    predecessor,
                    prepared,
                    acceptance_cursor,
                )
            self._step_hook(_APPLY_STEPS_V2[2])
            self._revalidate_transaction_predecessor(
                connection,
                authority,
                predecessor,
                prepared,
                acceptance_cursor,
                ack_boundary,
                unpublished_ack,
            )
            connection.execute(
                "INSERT INTO ingest_cursors("
                "host_id,source_sequence,event_id,content_sha256,segment_id,"
                "segment_relative_path,frame_offset,frame_size,frame_sha256"
                ") VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(host_id) DO UPDATE SET "
                "source_sequence=excluded.source_sequence,event_id=excluded.event_id,"
                "content_sha256=excluded.content_sha256,segment_id=excluded.segment_id,"
                "segment_relative_path=excluded.segment_relative_path,"
                "frame_offset=excluded.frame_offset,frame_size=excluded.frame_size,"
                "frame_sha256=excluded.frame_sha256",
                (
                    envelope.host_id,
                    _encode_uint64_v2(ref.source_sequence),
                    ref.event_id,
                    ref.content_sha256,
                    ref.segment_id,
                    ref.segment_relative_path,
                    _encode_uint64_v2(ref.frame_offset),
                    _encode_uint64_v2(ref.frame_size),
                    ref.frame_sha256,
                ),
            )
            self._step_hook(_APPLY_STEPS_V2[3])
            if final_authority_check is not None:
                final_authority_check()
            try:
                final_record = self._evidence.resolve_authenticated_ref(ref)
            except EvidenceStoreError as error:
                raise ProjectionAuthorityError(
                    "Projection V2 input authority disappeared before commit"
                ) from error
            if not _same_stored_record_v2(final_record, prepared.record):
                raise ProjectionAuthorityError(
                    "Projection V2 input changed before commit"
                )
            if self._healthy_acceptance_cursor() != acceptance_cursor:
                raise ProjectionAuthorityError(
                    "Projection V2 acceptance cursor changed before commit"
                )
            if unpublished_ack is None:
                self._revalidate_ack_boundary(ack_boundary, acceptance_cursor)
            else:
                self._revalidate_unpublished_ack_anchor(
                    unpublished_ack,
                    acceptance_cursor,
                )
            _validate_correlation_projection_predecessor(
                authority,
                predecessor,
            )
            commit_attempted = True
            connection.execute("COMMIT")
            transaction_started = False
            self._step_hook("commit")
            successor = _ProjectionPredecessor(
                generation=self._generation,
                host_id=envelope.host_id,
                source_sequence=ref.source_sequence,
                event_id=ref.event_id,
                content_sha256=ref.content_sha256,
                frame_sha256=ref.frame_sha256,
            )
            _advance_correlation_projection_authority(
                authority,
                predecessor,
                successor,
            )
        except sqlite3.IntegrityError as error:
            self._settle_failed_transaction(
                connection,
                error,
                transaction_started=transaction_started,
                commit_attempted=commit_attempted,
            )
            self._latch_unhealthy(error)
            raise ProjectionConflict(
                "Projection V2 facts conflict with authenticated evidence"
            ) from error
        except BaseException as error:
            rollback_proven = self._settle_failed_transaction(
                connection,
                error,
                transaction_started=transaction_started,
                commit_attempted=commit_attempted,
            )
            if not rollback_proven:
                self._latch_unhealthy(error)
            else:
                try:
                    _validate_correlation_projection_predecessor(
                        authority,
                        predecessor,
                    )
                except Exception:  # noqa: BLE001 - any authority drift is fatal
                    self._latch_unhealthy(error)
            raise
        cursor = ProjectionCursor(
            host_id=envelope.host_id,
            source_sequence=ref.source_sequence,
            event_id=ref.event_id,
            content_sha256=ref.content_sha256,
            frame_sha256=ref.frame_sha256,
        )
        return ProjectionApplyResult(
            event_id=envelope.event_id,
            duplicate_of_event_id=duplicate,
            reducer_applied=is_primary,
            cursor=cursor,
        )

    def _settle_failed_transaction(
        self,
        connection: sqlite3.Connection,
        primary: BaseException,
        *,
        transaction_started: bool,
        commit_attempted: bool,
    ) -> bool:
        try:
            in_transaction = connection.in_transaction
        except BaseException as error:  # noqa: BLE001 - health ambiguity
            self._latch_unhealthy(primary)
            primary.add_note(f"transaction state could not be read: {error!r}")
            return False
        if commit_attempted and not in_transaction:
            self._latch_unhealthy(primary)
            primary.add_note("Projection V2 COMMIT may have completed")
            return False
        if not transaction_started and not in_transaction:
            return True
        if not in_transaction:
            self._latch_unhealthy(primary)
            primary.add_note("Projection V2 transaction ended without proven rollback")
            return False
        try:
            connection.execute("ROLLBACK")
            self._step_hook("rollback")
            return True
        except BaseException as error:  # noqa: BLE001 - preserve primary
            self._latch_unhealthy(primary)
            primary.add_note(f"Projection V2 rollback could not be proven: {error!r}")
            return False

    def _reduce_primary(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        acceptance_cursor: int,
    ) -> Callable[[], None] | None:
        self._reduce_base(connection, prepared)
        if prepared.coverage is not None:
            try:
                expected = self._expected_coverage_invalidations(
                    connection,
                    prepared,
                )
                for row in expected:
                    connection.execute(
                        "INSERT INTO candidate_invalidations VALUES(?,?,?,?,?)",
                        row,
                    )
                    self._step_hook("candidate_invalidation")
            except ProjectionConflict:
                raise
            except (
                CorrelationRequestJournalError,
                EvidenceStoreError,
                HistoricalCoverageConflict,
                HistoricalCoverageUnavailable,
                AttributeError,
                TypeError,
                ValueError,
            ) as error:
                raise ProjectionAuthorityError(
                    "Projection V2 late coverage authority is unavailable"
                ) from error

            def final_coverage_authority_check() -> None:
                try:
                    self._validate_coverage_invalidation_closure(
                        connection,
                        prepared,
                        is_primary=True,
                    )
                except (ProjectionConflict, ProjectionAuthorityError):
                    raise
                except (
                    CorrelationRequestJournalError,
                    EvidenceStoreError,
                    HistoricalCoverageConflict,
                    HistoricalCoverageUnavailable,
                    AttributeError,
                    TypeError,
                    ValueError,
                ) as error:
                    raise ProjectionAuthorityError(
                        "Projection V2 late coverage authority changed after persistence"
                    ) from error

            return final_coverage_authority_check
        if prepared.envelope.event_type != "pcc_correlation_snapshot":
            return None
        try:
            return self._reduce_pcc(
                connection,
                authority,
                predecessor,
                prepared,
                acceptance_cursor,
            )
        except ProjectionConflict:
            raise
        except ProjectionAuthorityError:
            raise
        except (
            CorrelationProjectionError,
            CorrelationRequestJournalError,
            EvidenceStoreError,
            HistoricalCoverageConflict,
            HistoricalCoverageUnavailable,
            AttributeError,
            TypeError,
            ValueError,
        ) as error:
            raise ProjectionAuthorityError(
                "Projection V2 PCC authority could not be revalidated"
            ) from error

    def _expected_coverage_invalidations(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedV2Record,
    ) -> list[tuple[object, ...]]:
        if prepared.coverage is None:
            return []
        candidate_columns = ",".join(f"c.{column}" for column in _CANDIDATE_COLUMNS)
        rows = connection.execute(
            f"SELECT {candidate_columns} FROM candidates AS c "
            "JOIN events AS snapshot "
            "ON snapshot.event_id=c.correlation_snapshot_event_id "
            "WHERE c.host_id=? AND snapshot.source_sequence<? "
            "ORDER BY c.candidate_id COLLATE BINARY LIMIT ?",
            (
                prepared.envelope.host_id,
                _encode_uint64_v2(prepared.record.ref.source_sequence),
                _INVALIDATION_CANDIDATE_CAP_V2 + 1,
            ),
        ).fetchall()
        if len(rows) > _INVALIDATION_CANDIDATE_CAP_V2:
            raise HistoricalCoverageUnavailable(
                "late coverage candidate matches exceed 4096"
            )
        if not _late_coverage_may_invalidate_candidate(prepared.record):
            return []
        verifier = self._evidence._bound_verifier
        if verifier is None:
            raise ProjectionAuthorityError(
                "Projection V2 late coverage lost verifier authority"
            )
        candidates: list[_LateCandidateV2] = []
        for row in rows:
            _candidate_duplicate_key_from_row(row)
            candidate = _decode_candidate(row)
            snapshot_rows = connection.execute(
                "SELECT candidate_id,evidence_event_id,evidence_source_sequence,"
                "evidence_content_sha256,role,authority_snapshot_event_id "
                "FROM candidate_evidence WHERE candidate_id=? AND "
                "evidence_event_id=? AND role='correlation_snapshot' AND "
                "authority_snapshot_event_id=? LIMIT 2",
                (
                    candidate.candidate_id,
                    candidate.correlation_snapshot_event_id,
                    candidate.correlation_snapshot_event_id,
                ),
            ).fetchall()
            if len(snapshot_rows) != 1:
                raise ProjectionConflict(
                    "Projection V2 late candidate lost snapshot evidence"
                )
            (
                evidence_candidate_id,
                evidence_event_id,
                snapshot_sequence,
                evidence_hash,
                role,
                authority_event_id,
            ) = _decode_candidate_evidence(snapshot_rows[0])
            if (
                evidence_candidate_id != candidate.candidate_id
                or evidence_event_id != candidate.correlation_snapshot_event_id
                or authority_event_id != candidate.correlation_snapshot_event_id
                or role != "correlation_snapshot"
                or snapshot_sequence >= prepared.record.ref.source_sequence
            ):
                raise ProjectionConflict(
                    "Projection V2 late candidate snapshot binding changed"
                )
            snapshot_ref = verifier.accepted_ref(snapshot_sequence)
            if (
                type(snapshot_ref) is not EvidenceRef
                or snapshot_ref.event_id != evidence_event_id
                or snapshot_ref.content_sha256 != evidence_hash
            ):
                raise ProjectionAuthorityError(
                    "Projection V2 late candidate snapshot is not authenticated"
                )
            candidates.append(_LateCandidateV2(candidate, snapshot_ref))
        if not candidates:
            return []

        def evaluate(
            proofs: tuple[AuthenticatedPCCInput, ...],
        ) -> tuple[tuple[object, ...], ...]:
            if len(proofs) != len(candidates):
                raise ProjectionAuthorityError(
                    "Projection V2 late candidate batch length changed"
                )
            expected: list[tuple[object, ...]] = []
            for selected, proof in zip(candidates, proofs, strict=True):
                candidate = selected.candidate
                trigger = proof.snapshot.trigger
                if (
                    type(proof) is not AuthenticatedPCCInput
                    or type(proof.evidence_ref) is not EvidenceRef
                    or proof.evidence_ref != selected.snapshot_ref
                    or proof.event_id != candidate.correlation_snapshot_event_id
                    or proof.host_id != candidate.host_id
                    or proof.boot_id != candidate.boot_id
                    or trigger.event_id != candidate.primary_event_id
                    or trigger.source_sequence != candidate.primary_source_sequence
                ):
                    raise ProjectionAuthorityError(
                        "Projection V2 late candidate PCC binding changed"
                    )
                if _late_coverage_invalidates_candidate(proof, prepared.record):
                    expected.append(
                        _encode_candidate_invalidation(
                            candidate.candidate_id,
                            prepared.envelope.event_id,
                            prepared.record.ref.source_sequence,
                            prepared.record.ref.content_sha256,
                            _INVALIDATION_REASON_V2,
                        )
                    )
            return tuple(expected)

        return list(
            _evaluate_completed_snapshot_batch(
                self._journal,
                tuple(selected.snapshot_ref for selected in candidates),
                evaluate,
            )
        )

    def _validate_coverage_invalidation_closure(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedV2Record,
        *,
        is_primary: bool,
    ) -> None:
        rows = connection.execute(
            "SELECT candidate_id,coverage_event_id,coverage_source_sequence,"
            "coverage_content_sha256,reason_code FROM candidate_invalidations "
            "WHERE coverage_event_id=? ORDER BY candidate_id COLLATE BINARY LIMIT ?",
            (
                prepared.envelope.event_id,
                _INVALIDATION_CANDIDATE_CAP_V2 + 1,
            ),
        ).fetchall()
        if len(rows) > _INVALIDATION_CANDIDATE_CAP_V2:
            raise ProjectionConflict(
                "Projection V2 coverage invalidation closure exceeds 4096"
            )
        for row in rows:
            _decode_candidate_invalidation(row)
        actual = [tuple(row) for row in rows]
        expected = (
            self._expected_coverage_invalidations(connection, prepared)
            if is_primary and prepared.coverage is not None
            else []
        )
        if actual != expected:
            raise ProjectionConflict(
                "Projection V2 coverage invalidation closure changed"
            )

    def _reduce_base(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedV2Record,
    ) -> None:
        envelope = prepared.envelope
        ref = prepared.record.ref
        sequence = _encode_uint64_v2(ref.source_sequence)
        if prepared.coverage is not None:
            coverage = prepared.coverage
            connection.execute(
                "INSERT INTO coverage_intervals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    envelope.event_id,
                    envelope.host_id,
                    coverage.component,
                    coverage.kind,
                    coverage.severity,
                    coverage.opened_at,
                    coverage.closed_at,
                    _optional_uint64_v2(coverage.affected_source_sequence_start),
                    _optional_uint64_v2(coverage.affected_source_sequence_end),
                    _optional_uint64_v2(coverage.dropped_count),
                    coverage.reason_code,
                    _optional_uint64_v2(coverage.reconcile_generation),
                    sequence,
                    ref.content_sha256,
                ),
            )
            return
        falco = prepared.falco
        if falco is None:
            return
        if falco.docker_container_id is not None and falco.docker_started_at is not None:
            connection.execute(
                "INSERT INTO containers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(host_id,container_id,container_started_at) DO UPDATE SET "
                "image_id=excluded.image_id,repo_digests_json=excluded.repo_digests_json,"
                "immutable_spec_sha256=excluded.immutable_spec_sha256,"
                "inventory_revision=excluded.inventory_revision,"
                "last_event_id=excluded.last_event_id,"
                "last_source_sequence=excluded.last_source_sequence,"
                "last_content_sha256=excluded.last_content_sha256 "
                "WHERE excluded.last_source_sequence > containers.last_source_sequence",
                (
                    envelope.host_id,
                    falco.docker_container_id,
                    falco.docker_started_at,
                    falco.image_id,
                    canonical_json(falco.repo_digests).decode("utf-8"),
                    falco.immutable_spec_sha256,
                    _optional_uint64_v2(falco.inventory_revision),
                    envelope.event_id,
                    sequence,
                    ref.content_sha256,
                    envelope.event_id,
                    sequence,
                    ref.content_sha256,
                ),
            )
        connection.execute(
            "INSERT INTO process_observations VALUES(?,?,?,?,?,?,?,?,?)",
            (
                envelope.event_id,
                envelope.host_id,
                falco.docker_container_id,
                falco.docker_started_at,
                falco.proc_name,
                falco.proc_exe_path,
                falco.proc_parent_name,
                sequence,
                ref.content_sha256,
            ),
        )
        connection.execute(
            "INSERT INTO network_observations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                envelope.event_id,
                envelope.host_id,
                falco.docker_container_id,
                falco.docker_started_at,
                int(falco.successful_connect),
                falco.destination_ipv4,
                falco.destination_port,
                falco.l4_protocol,
                int(falco.investigation_only),
                sequence,
                ref.content_sha256,
            ),
        )
        if (
            not falco.successful_connect
            or falco.missing_required_fields
            or falco.investigation_only
        ):
            verifier = self._evidence._bound_verifier
            if verifier is None:
                raise ProjectionAuthorityError(
                    "Projection V2 direct incident lacks verifier authority"
                )
            try:
                authenticated = self._evidence._authenticated_falco_input(
                    verifier,
                    ref,
                )
                incident = incident_from_verified_falco(authenticated)
                revalidated = self._evidence.resolve_authenticated_ref(ref)
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 direct incident lost Falco authority"
                ) from error
            if not _same_stored_record_v2(revalidated, prepared.record):
                raise ProjectionAuthorityError(
                    "Projection V2 direct Falco evidence changed"
                )
            _insert_v2_incident(connection, incident, "investigation")

    def _reduce_pcc(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        acceptance_cursor: int,
    ) -> Callable[[], None]:
        if self._healthy_acceptance_cursor() != acceptance_cursor:
            raise ProjectionAuthorityError(
                "Projection V2 acceptance changed before PCC history"
            )
        ref = prepared.record.ref
        completed = self._journal.completed_for_snapshot(ref)
        initial = _revalidate_completed_snapshot(completed)
        if (
            type(initial) is not AuthenticatedPCCInput
            or not self._evidence._authenticated_pcc_input_is_exact(initial)
            or type(initial.evidence_ref) is not EvidenceRef
            or initial.evidence_ref != ref
            or initial.event_id != ref.event_id
            or initial.source_sequence != ref.source_sequence
            or initial.content_sha256 != ref.content_sha256
        ):
            raise CorrelationProjectionError(
                "completed PCC is not exact same-store authority"
            )
        active: ActiveCandidateObservation | None = None
        if initial.snapshot.outcome == "failed":
            result = correlate_pcc(initial, CorrelationContext.failed_snapshot())
        else:
            path = _issue_replay_historical_path_authority(
                self._evidence,
                initial,
                None,
            )
            coverage_before = _derive_replay_historical_coverage(
                initial,
                path,
                None,
            )
            if (
                _derive_replay_historical_coverage(
                    initial,
                    path,
                    None,
                )
                != coverage_before
            ):
                raise CorrelationProjectionError(
                    "historical coverage changed before duplicate lookup"
                )
            revalidated = _revalidate_completed_snapshot(completed)
            if not _same_exact_pcc(initial, revalidated):
                raise CorrelationProjectionError(
                    "completed PCC changed before duplicate lookup"
                )
            key = _duplicate_key(initial, initial.snapshot)
            if self._healthy_acceptance_cursor() != acceptance_cursor:
                raise ProjectionAuthorityError(
                    "Projection V2 acceptance changed before duplicate lookup"
                )
            _validate_correlation_projection_predecessor(
                authority,
                predecessor,
            )
            trigger = initial.snapshot.trigger
            active = _active_duplicate_v2(
                connection,
                key,
                current_trigger_order=(
                    trigger.source_sequence,
                    trigger.event_id,
                ),
            )
            proof, context = _issue_correlation_context(
                authority,
                completed,
                expected_predecessor=predecessor,
                active_duplicate=active,
                historical_access=None,
            )
            if not _same_exact_pcc(initial, proof):
                raise CorrelationProjectionError(
                    "issued PCC changed after duplicate lookup"
                )
            result = correlate_pcc(proof, context)
            if self._healthy_acceptance_cursor() != acceptance_cursor:
                raise ProjectionAuthorityError(
                    "Projection V2 acceptance changed during correlation"
                )
        final = _revalidate_completed_snapshot(completed)
        if not _same_exact_pcc(initial, final):
            raise CorrelationProjectionError(
                "completed PCC changed during correlation"
            )

        def final_authority_check() -> None:
            try:
                persisted = _revalidate_completed_snapshot(completed)
                if not _same_exact_pcc(initial, persisted):
                    raise CorrelationProjectionError(
                        "completed PCC changed after result persistence"
                    )
                if self._healthy_acceptance_cursor() != acceptance_cursor:
                    raise CorrelationProjectionError(
                        "evidence acceptance changed after result persistence"
                    )
                if initial.snapshot.outcome == "complete":
                    fresh_proof, _fresh_context = _issue_correlation_context(
                        authority,
                        completed,
                        expected_predecessor=predecessor,
                        active_duplicate=active,
                        historical_access=None,
                    )
                    if not _same_exact_pcc(initial, fresh_proof):
                        raise CorrelationProjectionError(
                            "PCC authority changed during final live validation"
                        )
            except ProjectionAuthorityError:
                raise
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 PCC authority changed after persistence"
                ) from error

        if isinstance(result, CandidateCreated):
            self._persist_candidate_created(connection, result, initial)
            return final_authority_check
        if isinstance(result, Duplicate):
            if active is None or result.existing_candidate_id != active.candidate_id:
                raise ProjectionConflict(
                    "Projection V2 duplicate result changed its active primary"
            )
            self._persist_duplicate(connection, result, initial)
            return final_authority_check
        if isinstance(result, InvestigationOnly):
            _insert_v2_incident(connection, result.incident, "investigation")
            self._step_hook(_CANDIDATE_STEPS_V2[0])
            return final_authority_check
        if isinstance(result, Rejected):
            _insert_v2_incident(connection, result.incident, "rejected")
            self._step_hook(_CANDIDATE_STEPS_V2[0])
            return final_authority_check
        raise CorrelationProjectionError("correlation returned an unknown result type")

    def _persist_candidate_created(
        self,
        connection: sqlite3.Connection,
        result: CandidateCreated,
        proof: AuthenticatedPCCInput,
    ) -> None:
        candidate = result.candidate
        _insert_v2_incident(connection, result.incident, "candidate")
        self._step_hook(_CANDIDATE_STEPS_V2[0])
        _insert_v2_candidate(connection, candidate)
        self._step_hook(_CANDIDATE_STEPS_V2[1])
        self._insert_candidate_evidence(
            connection,
            candidate.candidate_id,
            proof,
            trigger_role="primary_trigger",
            snapshot_role="correlation_snapshot",
        )

    def _persist_duplicate(
        self,
        connection: sqlite3.Connection,
        result: Duplicate,
        proof: AuthenticatedPCCInput,
    ) -> None:
        _insert_v2_incident(connection, result.incident, "duplicate")
        self._step_hook(_CANDIDATE_STEPS_V2[0])
        self._insert_candidate_evidence(
            connection,
            result.existing_candidate_id,
            proof,
            trigger_role="supporting_trigger",
            snapshot_role="supporting_snapshot",
        )

    def _insert_candidate_evidence(
        self,
        connection: sqlite3.Connection,
        candidate_id: str,
        proof: AuthenticatedPCCInput,
        *,
        trigger_role: str,
        snapshot_role: str,
    ) -> None:
        trigger = proof.snapshot.trigger
        connection.execute(
            "INSERT INTO candidate_evidence VALUES(?,?,?,?,?,?)",
            _encode_candidate_evidence(
                candidate_id,
                trigger.event_id,
                trigger.source_sequence,
                trigger.content_sha256,
                trigger_role,
                proof.event_id,
            ),
        )
        self._step_hook(_CANDIDATE_STEPS_V2[2])
        connection.execute(
            "INSERT INTO candidate_evidence VALUES(?,?,?,?,?,?)",
            _encode_candidate_evidence(
                candidate_id,
                proof.event_id,
                proof.source_sequence,
                proof.content_sha256,
                snapshot_role,
                proof.event_id,
            ),
        )
        self._step_hook(_CANDIDATE_STEPS_V2[3])

    def status(self) -> ProjectionStatus:
        with self._mutex:
            with self._replay_state_lock:
                if self._replay_reservation is not None:
                    raise ProjectionAuthorityError(
                        "Projection V2 replay reservation is active"
                    )
            connection = self._connection
            cursor: ProjectionCursor | None = None
            if connection is not None:
                try:
                    cursor = _current_v2_cursor(connection)
                except (ProjectionConflict, sqlite3.DatabaseError):
                    self._latch_unhealthy()
            return ProjectionStatus(healthy=self._healthy and not self._closed, cursor=cursor)

    def snapshot_hash(self) -> str:
        with self._mutex:
            connection, _authority = self._require_usable()
            return _v2_snapshot_hash(connection)

    def _close_resources(self) -> list[BaseException]:
        errors: list[BaseException] = []
        authority = self._authority
        if authority is not None:
            try:
                _close_correlation_projection_authority(authority)
            except BaseException as error:  # noqa: BLE001 - close all owned resources
                errors.append(error)
            else:
                self._authority = None
        connection = self._connection
        if connection is not None:
            try:
                connection.close()
            except BaseException as error:  # noqa: BLE001 - close all owned resources
                errors.append(error)
            else:
                self._connection = None
        if not getattr(self._journal, "_closed", True):
            try:
                self._journal.close()
            except BaseException as error:  # noqa: BLE001 - close all owned resources
                errors.append(error)
        if not getattr(self._acknowledgements, "_closed", True):
            try:
                self._acknowledgements.close()
            except BaseException as error:  # noqa: BLE001 - close all owned resources
                errors.append(error)
        if not getattr(self._evidence, "_closed", True):
            try:
                self._evidence.close()
            except BaseException as error:  # noqa: BLE001 - close all owned resources
                errors.append(error)
        return errors

    def _resources_released(self) -> bool:
        return (
            self._authority is None
            and self._connection is None
            and getattr(self._journal, "_closed", False) is True
            and getattr(self._acknowledgements, "_closed", False) is True
            and getattr(self._evidence, "_closed", False) is True
        )

    def _close_after_factory_failure(self, primary: BaseException) -> None:
        errors = self._close_resources()
        for error in errors:
            primary.add_note(
                "Projection V2 factory cleanup failure (attempt 1): "
                f"{type(error).__name__}: {error}"
            )
        if not errors:
            return
        retry_errors = self._close_resources()
        for error in retry_errors:
            primary.add_note(
                "Projection V2 factory cleanup failure (attempt 2): "
                f"{type(error).__name__}: {error}"
            )

    def close(self) -> None:
        with self._mutex:
            with self._replay_state_lock:
                if self._replay_reservation is not None:
                    raise ProjectionAuthorityError(
                        "Projection V2 replay reservation is active"
                    )
            if self._closed and self._resources_released():
                return
            self._closed = True
            errors = self._close_resources()
            if errors:
                self._healthy = False
                primary = errors[0]
                for error in errors[1:]:
                    primary.add_note(
                        "secondary Projection V2 close failure: "
                        f"{type(error).__name__}: {error}"
                    )
                raise ProjectionUnhealthy(
                    "Projection V2 owner close could not be proven"
                ) from primary


def _v2_projection_owner_for_test(
    connection: sqlite3.Connection,
    *,
    evidence: SegmentStore,
    acknowledgements: AckJournal,
    journal: CorrelationRequestJournal,
    registry: SpecialUseRegistry,
    step_hook: Callable[[str], None] | None = None,
) -> _V2ProjectionOwner:
    """Transfer exact test resources into one dormant V2 projection owner."""
    return _V2ProjectionOwner._take_ownership(
        connection,
        evidence=evidence,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=registry,
        step_hook=step_hook,
    )


def _v2_unpublished_projection_from_prefix_for_test(
    *,
    evidence: SegmentStore,
    acknowledgements: AckJournal,
    journal: CorrelationRequestJournal,
    registry: SpecialUseRegistry,
    through: EvidenceRef,
    step_hook: Callable[[str], None] | None = None,
) -> tuple[_V2ProjectionOwner, sqlite3.Connection, _UnpublishedV2ReplayReport]:
    """Build one fresh dormant V2 projection from an exact ACKed source prefix."""
    if (
        type(evidence) is not SegmentStore
        or type(acknowledgements) is not AckJournal
        or type(journal) is not CorrelationRequestJournal
        or type(registry) is not SpecialUseRegistry
        or type(through) is not EvidenceRef
    ):
        raise ProjectionAuthorityError(
            "unpublished Projection V2 replay requires exact resources"
        )
    connection = _v2_connection_for_test()
    owner = _V2ProjectionOwner._take_ownership(
        connection,
        evidence=evidence,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=registry,
        step_hook=step_hook,
    )
    try:
        report = owner._replay_unpublished_prefix(
            through,
            _factory=_UNPUBLISHED_REPLAY_FACTORY,
        )
        published_connection = owner._connection
        if not isinstance(published_connection, sqlite3.Connection):
            raise ProjectionAuthorityError(
                "unpublished Projection V2 replay lost its published database"
            )
        return owner, published_connection, report
    except BaseException as error:
        owner._close_after_factory_failure(error)
        raise


__all__: list[str] = []
