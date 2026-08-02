"""Dormant Projection V2 schema identity and strict persisted-fact codecs."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from agmind_immune.canonicaljson import candidate_facts_sha256, canonical_json
from agmind_immune.contracts import (
    CoverageEventV1,
    EventEnvelopeV1,
    FalcoConnectV1,
    decode_strict,
)
from agmind_immune.evidence.dedup import _logical_primary_identity_v2
from agmind_immune.evidence.projection import ProjectionConflict, ProjectionValidationError
from agmind_immune.evidence.segments import (
    EvidenceRef,
    StoredEvidenceRecord,
    _exact_coverage_record_key,
)
from agmind_immune.incidents.models import ContainmentCandidateV1, IncidentV1

_SCHEMA_V2_PATH = Path(__file__).with_name("schema_v2.sql")
_SCHEMA_V2_SHA256 = "d4a5d563ca3964cbe4ed276882a4b4def95fb756fc67a6777fddf5de38b1619d"
_SCHEMA_META_V2 = {
    "schema_version": "agmind.projection-schema.v2",
    "reducer_version": "agmind.projection-reducer.v2",
    "dedup_version": "AGMIND_PROJECTION_DEDUP_V2",
    "snapshot_layout": "AGMIND_PROJECTION_SNAPSHOT_V2",
}
_SNAPSHOT_DOMAIN_V2 = b"AGMIND_PROJECTION_SNAPSHOT_V2\0"
_UINT64_V2 = re.compile(r"^[0-9]{20}$")
_EVENT_ID_V2 = re.compile(r"^evt_[0-9a-f]{64}$")
_CANDIDATE_ID_V2 = re.compile(r"^cand_[0-9a-f]{64}$")
_HEX64_V2 = re.compile(r"^[0-9a-f]{64}$")
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


@dataclass(frozen=True)
class _PreparedV2Record:
    record: StoredEvidenceRecord
    envelope: EventEnvelopeV1
    dedup_kind: str
    logical_key_sha256: str
    falco: FalcoConnectV1 | None
    coverage: CoverageEventV1 | None


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


__all__: list[str] = []
