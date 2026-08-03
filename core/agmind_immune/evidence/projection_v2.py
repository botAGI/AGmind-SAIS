"""Dormant Projection V2 schema identity and strict persisted-fact codecs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from _thread import RLock as RLockType
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import RLock
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
    _close_correlation_projection_authority,
    _create_correlation_projection_authority,
    _issue_correlation_context,
    _ProjectionPredecessor,
    _same_exact_pcc,
    _validate_correlation_projection_pins,
    _validate_correlation_projection_predecessor,
)
from agmind_immune.correlation.pcc import (
    ActiveCandidateObservation,
    CandidateCreated,
    CandidateDuplicateKey,
    CorrelationContext,
    CorrelationProjectionError,
    Duplicate,
    InvestigationOnly,
    Rejected,
    _duplicate_key,
    correlate_pcc,
    incident_from_verified_falco,
)
from agmind_immune.correlation.primitives import (
    SpecialUseRegistry,
    special_use_registry_is_issued,
)
from agmind_immune.coverage.historical import (
    HistoricalCoverageConflict,
    HistoricalCoverageUnavailable,
    _activate_replay_historical_session,
    _begin_replay_historical_commit,
    _begin_replay_historical_event,
    _begin_replay_historical_validation,
    _close_replay_historical_session,
    _compare_replay_historical_primary,
    _complete_replay_historical_event,
    _derive_replay_historical_coverage,
    _final_seal_replay_historical_session,
    _issue_replay_historical_path_authority,
    _late_coverage_invalidates_candidate,
    _late_coverage_may_invalidate_candidate,
    _open_replay_historical_access,
    _ReplayAccess,
    _ReplayHandle,
    _revalidate_replay_historical_source,
    _take_replay_historical_handle,
    _validate_replay_historical_event,
)
from agmind_immune.evidence.dedup import _logical_primary_identity_v2
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
    EvidenceRef,
    EvidenceStatus,
    EvidenceStoreError,
    SegmentStore,
    StoredEvidenceRecord,
    _exact_coverage_record_key,
)
from agmind_immune.incidents.models import ContainmentCandidateV1, IncidentV1
from agmind_immune.ingest.ack_journal import (
    AckIdentity,
    AckJournal,
    AckJournalSnapshot,
)
from agmind_immune.ingest.correlation_journal import (
    _MAX_COMPLETED_BATCH,
    CorrelationRequestJournal,
    CorrelationRequestJournalError,
    _completed_snapshot_batch_items,
    _CompletedSnapshotBatchAuthority,
    _evaluate_completed_snapshot_batch,
    _issue_completed_snapshot_batch,
    _revalidate_completed_snapshot,
    _revoke_completed_snapshot_batch,
    _seal_completed_snapshot_batch,
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
_UNPUBLISHED_REPLAY_FACTORY = object()
_UNPUBLISHED_PCC_CHUNK = _MAX_COMPLETED_BATCH
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


@dataclass(frozen=True, slots=True)
class _UnpublishedAckAnchor:
    boundary: _ProjectionAckBoundaryV2
    lifecycle: object
    descriptor: int
    journal_stat: os.stat_result
    authenticated_digest: bytes
    size: int
    previous_hash: bytes


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
    connection = sqlite3.connect(":memory:" if path is None else path, isolation_level=None)
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
    _healthy: bool
    _closed: bool
    _historical_replay_handle: _ReplayHandle | None

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
        owner._healthy = True
        owner._closed = False
        owner._historical_replay_handle = None
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

    def _open_historical_replay_access(
        self,
        proof: AuthenticatedPCCInput,
    ) -> _ReplayAccess | None:
        handle = self._historical_replay_handle
        if handle is None:
            return None
        return _open_replay_historical_access(handle, proof)

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
    ) -> _UnpublishedAckAnchor:
        boundary = self._freeze_ack_boundary(acceptance_cursor)
        acknowledgements = self._acknowledgements
        authenticated_stat = acknowledgements._authenticated_stat
        authenticated_hasher = acknowledgements._authenticated_hasher
        if authenticated_stat is None or authenticated_hasher is None:
            raise ProjectionAuthorityError(
                "Projection V2 unpublished ACK lost its authenticated anchor"
            )
        return _UnpublishedAckAnchor(
            boundary=boundary,
            lifecycle=self._ack_lifecycle,
            descriptor=acknowledgements._descriptor,
            journal_stat=authenticated_stat,
            authenticated_digest=authenticated_hasher.digest(),
            size=acknowledgements._size,
            previous_hash=acknowledgements._previous_hash,
        )

    def _revalidate_unpublished_ack_anchor(
        self,
        anchor: _UnpublishedAckAnchor,
        acceptance_cursor: int,
    ) -> None:
        acknowledgements = self._acknowledgements
        authenticated_stat = acknowledgements._authenticated_stat
        authenticated_hasher = acknowledgements._authenticated_hasher
        try:
            descriptor_stat = os.fstat(acknowledgements._descriptor)
        except OSError as error:
            raise ProjectionAuthorityError(
                "Projection V2 unpublished ACK descriptor is unavailable"
            ) from error
        if (
            type(anchor) is not _UnpublishedAckAnchor
            or self._healthy_acceptance_cursor() != acceptance_cursor
            or acknowledgements._lifecycle_identity is not anchor.lifecycle
            or acknowledgements._descriptor != anchor.descriptor
            or acknowledgements._healthy is not True
            or acknowledgements._closed is not False
            or acknowledgements._closing is not False
            or authenticated_stat is None
            or authenticated_hasher is None
            or descriptor_stat != anchor.journal_stat
            or authenticated_stat != anchor.journal_stat
            or authenticated_hasher.digest() != anchor.authenticated_digest
            or acknowledgements._size != anchor.size
            or acknowledgements._previous_hash != anchor.previous_hash
            or _exact_ack_identity_v2(acknowledgements._confirmed)
            != anchor.boundary.confirmed
            or _exact_ack_identity_v2(acknowledgements._pending)
            != anchor.boundary.pending
            or acknowledgements._confirmed_generation
            != anchor.boundary.generation
            or acknowledgements._committed_prefix_size
            != anchor.boundary.prefix_size
            or acknowledgements._committed_prefix_sha256
            != anchor.boundary.prefix_sha256
        ):
            raise ProjectionAuthorityError(
                "Projection V2 unpublished ACK anchor changed"
            )

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
        completed_authority: object | None = None,
    ) -> tuple[
        AuthenticatedPCCInput,
        CandidateCreated | Duplicate | InvestigationOnly | Rejected,
    ]:
        completed = (
            self._journal.completed_for_snapshot(prepared.record.ref)
            if completed_authority is None
            else completed_authority
        )
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
            historical_access = self._open_historical_replay_access(proof)
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
                historical_access=historical_access,
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
        completed_authority: object | None = None,
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
                completed_authority,
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
        completed_authority: object | None = None,
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
            completed_authority=completed_authority,
        )

    def _validate_persisted_prefix(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        cursor: ProjectionCursor | None,
        completed_by_event: dict[str, object] | None = None,
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
            completed_authority: object | None = None
            if (
                completed_by_event is not None
                and prepared.envelope.event_type == "pcc_correlation_snapshot"
            ):
                try:
                    completed_authority = completed_by_event[
                        prepared.envelope.event_id
                    ]
                except KeyError as error:
                    raise ProjectionAuthorityError(
                        "Projection V2 unpublished prefix is missing completed "
                        "PCC batch authority"
                    ) from error
            self._validate_retry_closure(
                connection,
                authority,
                predecessor,
                prepared,
                is_primary=is_primary,
                completed_authority=completed_authority,
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
    ) -> _UnpublishedV2ReplayReport:
        with self._mutex:
            connection, authority = self._require_usable()
            if _factory is not _UNPUBLISHED_REPLAY_FACTORY or type(through) is not EvidenceRef:
                raise ProjectionAuthorityError(
                    "Projection V2 unpublished replay is factory-only"
                )
            _verify_v2_schema(connection)
            if _current_v2_cursor(connection) is not None or any(
                connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table, _columns, _primary_key in _TABLE_LAYOUT_V2[1:]
            ):
                raise ProjectionConflict(
                    "Projection V2 unpublished replay requires an empty database"
                )
            acceptance_cursor = self._healthy_acceptance_cursor()
            ack_anchor = self._freeze_unpublished_ack_anchor(acceptance_cursor)
            ack_boundary = ack_anchor.boundary
            if (
                acceptance_cursor != through.source_sequence
                or ack_boundary.pending is not None
                or ack_boundary.confirmed != AckIdentity.from_ref(through)
            ):
                raise ProjectionAuthorityError(
                    "Projection V2 unpublished replay requires strict ACK equality"
                )
            try:
                records = tuple(
                    self._evidence.iter_authenticated_records(
                        through=through.source_sequence,
                    )
                )
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 unpublished source prefix is unavailable"
                ) from error
            if (
                not records
                or records[-1].ref != through
                or len(records) != through.source_sequence
                or any(
                    record.ref.source_sequence != index
                    for index, record in enumerate(records, start=1)
                )
            ):
                raise ProjectionAuthorityError(
                    "Projection V2 unpublished source prefix is not exact and contiguous"
                )
            prepared_records = tuple(_prepare_v2(record) for record in records)
            snapshot_refs = tuple(
                prepared.record.ref
                for prepared in prepared_records
                if prepared.envelope.event_type == "pcc_correlation_snapshot"
            )

            try:
                historical_session, historical_token = (
                    _activate_replay_historical_session(
                        self._evidence,
                        through,
                    )
                )
                self._historical_replay_handle = _take_replay_historical_handle(
                    historical_session
                )
            except HistoricalCoverageUnavailable as error:
                raise ProjectionAuthorityError(
                    "Projection V2 unpublished historical session is unavailable"
                ) from error
            batches: list[_CompletedSnapshotBatchAuthority] = []
            completed_by_event: dict[str, object] = {}
            try:
                for offset in range(0, len(snapshot_refs), _UNPUBLISHED_PCC_CHUNK):
                    refs = snapshot_refs[offset : offset + _UNPUBLISHED_PCC_CHUNK]
                    batch = _issue_completed_snapshot_batch(self._journal, refs)
                    items = _completed_snapshot_batch_items(batch)
                    batches.append(batch)
                    for ref, item in zip(refs, items, strict=True):
                        completed_by_event[ref.event_id] = item
                result: ProjectionApplyResult | None = None
                for prepared in prepared_records:
                    replay_event_token = _begin_replay_historical_event(
                        historical_session,
                        prepared.record.ref,
                    )
                    cursor = _current_v2_cursor(connection)
                    predecessor = _predecessor_v2(self._generation, cursor)
                    _validate_correlation_projection_predecessor(
                        authority,
                        predecessor,
                    )
                    completed = completed_by_event.get(
                        prepared.envelope.event_id
                    )
                    result = self._apply_prepared(
                        connection,
                        authority,
                        predecessor,
                        prepared,
                        acceptance_cursor,
                        ack_boundary,
                        completed,
                        ack_anchor,
                        replay_event_token,
                    )
                    _complete_replay_historical_event(replay_event_token)
                if result is None or result.cursor.source_sequence != through.source_sequence:
                    raise ProjectionAuthorityError(
                        "Projection V2 unpublished replay did not reach its exact boundary"
                    )
                current_ack = self._current_ack_boundary()
                if (
                    self._healthy_acceptance_cursor() != acceptance_cursor
                    or current_ack != ack_boundary
                    or self._evidence.resolve_authenticated_ref(through).ref != through
                ):
                    raise ProjectionAuthorityError(
                        "Projection V2 unpublished source or ACK authority changed"
                    )
                cursor = _current_v2_cursor(connection)
                predecessor = _predecessor_v2(self._generation, cursor)
                _validate_correlation_projection_predecessor(
                    authority,
                    predecessor,
                )
                try:
                    _begin_replay_historical_validation(historical_session)
                except (
                    HistoricalCoverageConflict,
                    HistoricalCoverageUnavailable,
                ) as error:
                    raise ProjectionAuthorityError(
                        "Projection V2 unpublished final historical authority changed"
                    ) from error
                try:
                    sealed_cursor = _current_v2_cursor(connection)
                    if (
                        not special_use_registry_is_issued(self._registry)
                        or cursor != result.cursor
                        or sealed_cursor != result.cursor
                    ):
                        raise ProjectionAuthorityError(
                            "Projection V2 unpublished final seal changed"
                        )
                    self._revalidate_unpublished_ack_anchor(
                        ack_anchor,
                        acceptance_cursor,
                    )
                    if (
                        self._healthy_acceptance_cursor() != acceptance_cursor
                        or self._evidence.resolve_authenticated_ref(through).ref
                        != through
                    ):
                        raise ProjectionAuthorityError(
                            "Projection V2 unpublished final source changed"
                        )
                    _validate_correlation_projection_predecessor(
                        authority,
                        _predecessor_v2(self._generation, sealed_cursor),
                    )
                except ProjectionAuthorityError:
                    raise
                except Exception as error:
                    raise ProjectionAuthorityError(
                        "Projection V2 unpublished final seal authority changed"
                    ) from error
                prefix_sha256 = self._validate_persisted_prefix(
                    connection,
                    authority,
                    predecessor,
                    cursor,
                    completed_by_event,
                )
                if (
                    cursor != result.cursor
                    or _current_v2_cursor(connection) != cursor
                    or _v2_snapshot_hash(connection) != prefix_sha256
                ):
                    raise ProjectionConflict(
                        "Projection V2 unpublished final prefix changed"
                    )
                try:
                    _revalidate_replay_historical_source(historical_session)
                except HistoricalCoverageUnavailable as error:
                    raise ProjectionAuthorityError(
                        "Projection V2 unpublished source changed after prefix seal"
                    ) from error
                for batch in tuple(batches):
                    _seal_completed_snapshot_batch(batch)
                    batches.remove(batch)
                final_ack = self._current_ack_boundary()
                final_cursor = _current_v2_cursor(connection)
                if (
                    self._healthy_acceptance_cursor() != acceptance_cursor
                    or final_ack != ack_boundary
                    or final_cursor != result.cursor
                    or self._evidence.resolve_authenticated_ref(through).ref
                    != through
                    or _v2_snapshot_hash(connection) != prefix_sha256
                ):
                    raise ProjectionAuthorityError(
                        "Projection V2 unpublished authority changed after final seal"
                    )
                _validate_correlation_projection_predecessor(
                    authority,
                    _predecessor_v2(self._generation, final_cursor),
                )

                def terminal_external_authority_check() -> None:
                    terminal_cursor = _current_v2_cursor(connection)
                    if (
                        self._healthy_acceptance_cursor() != acceptance_cursor
                        or self._current_ack_boundary() != ack_boundary
                        or terminal_cursor != result.cursor
                        or self._evidence.resolve_authenticated_ref(through).ref
                        != through
                        or _v2_snapshot_hash(connection) != prefix_sha256
                    ):
                        raise ProjectionAuthorityError(
                            "Projection V2 terminal external authority changed"
                        )
                    _validate_correlation_projection_predecessor(
                        authority,
                        _predecessor_v2(self._generation, terminal_cursor),
                    )
                    _validate_correlation_projection_pins(authority)

                try:
                    _final_seal_replay_historical_session(
                        historical_session,
                        terminal_external_authority_check,
                    )
                except (
                    CorrelationProjectionError,
                    HistoricalCoverageConflict,
                    HistoricalCoverageUnavailable,
                ) as error:
                    raise ProjectionAuthorityError(
                        "Projection V2 unpublished terminal authority changed"
                    ) from error
                return _UnpublishedV2ReplayReport(
                    cursor=result.cursor,
                    applied_count=len(prepared_records),
                    prefix_sha256=prefix_sha256,
                )
            finally:
                self._historical_replay_handle = None
                for batch in batches:
                    _revoke_completed_snapshot_batch(batch)
                _close_replay_historical_session(
                    historical_session,
                    historical_token,
                )

    def _revalidate_transaction_predecessor(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        acceptance_cursor: int,
        ack_boundary: _ProjectionAckBoundaryV2,
        unpublished_ack: _UnpublishedAckAnchor | None = None,
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
        completed_authority: object | None = None,
        unpublished_ack: _UnpublishedAckAnchor | None = None,
        replay_event_token: object | None = None,
    ) -> ProjectionApplyResult:
        envelope = prepared.envelope
        ref = prepared.record.ref
        duplicate: str | None = None
        is_primary = False
        transaction_started = False
        commit_attempted = False
        try:
            if replay_event_token is not None:
                _validate_replay_historical_event(
                    replay_event_token,
                    ref,
                )
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
            if replay_event_token is not None:
                _compare_replay_historical_primary(
                    replay_event_token,
                    ref,
                    is_primary,
                )
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
                    completed_authority,
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
            if replay_event_token is not None:
                _begin_replay_historical_commit(
                    replay_event_token,
                    ref,
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
        completed_authority: object | None = None,
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
                completed_authority,
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
        completed_authority: object | None = None,
    ) -> Callable[[], None]:
        if self._healthy_acceptance_cursor() != acceptance_cursor:
            raise ProjectionAuthorityError(
                "Projection V2 acceptance changed before PCC history"
            )
        ref = prepared.record.ref
        completed = (
            self._journal.completed_for_snapshot(ref)
            if completed_authority is None
            else completed_authority
        )
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
        historical_access: _ReplayAccess | None = None
        if initial.snapshot.outcome == "failed":
            result = correlate_pcc(initial, CorrelationContext.failed_snapshot())
        else:
            historical_access = self._open_historical_replay_access(initial)
            path = _issue_replay_historical_path_authority(
                self._evidence,
                initial,
                historical_access,
            )
            coverage_before = _derive_replay_historical_coverage(
                initial,
                path,
                historical_access,
            )
            if (
                _derive_replay_historical_coverage(
                    initial,
                    path,
                    historical_access,
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
                historical_access=historical_access,
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
                        historical_access=historical_access,
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
        return owner, connection, report
    except BaseException as error:
        owner._close_after_factory_failure(error)
        raise


__all__: list[str] = []
