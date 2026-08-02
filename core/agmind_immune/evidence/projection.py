"""Authenticated, ACK-capped SQLite projection of authoritative evidence.

The Python sqlite3 API cannot bind a connection to a directory descriptor on
both Darwin and Linux. C1C therefore combines dir-fd-relative namespace
operations with before/after inode checks and assumes the dedicated Core UID
does not perform adversarial rename-and-restore races inside its mode-0700
projection directory.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from _thread import RLock as RLockType
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

from agmind_immune.canonicaljson import canonical_json, verify_event_signature
from agmind_immune.contracts import (
    HEX64,
    UUID4,
    CoverageEventV1,
    EventEnvelopeV1,
    FalcoConnectV1,
)
from agmind_immune.evidence.dedup import _logical_primary_identity_v1
from agmind_immune.evidence.segments import (
    EvidenceCorrupt,
    EvidencePriority,
    EvidenceRef,
    SegmentStore,
    StoredEvidenceRecord,
)
from agmind_immune.ingest.ack_journal import AckJournal, AckJournalSnapshot
from agmind_immune.ingest.envelope import EnvelopeVerifier, KeyMetadataError

_UINT64 = re.compile(r"^[0-9]{20}$")
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_SCHEMA_PATH = Path(__file__).with_name("schema.sql")
_SNAPSHOT_DOMAIN = b"AGMIND_PROJECTION_SNAPSHOT_V1\0"
_SCHEMA_META = {
    "schema_version": "agmind.projection-schema.v1",
    "reducer_version": "agmind.projection-reducer.v1",
    "snapshot_layout": "AGMIND_PROJECTION_SNAPSHOT_V1",
}
_TABLE_LAYOUT: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
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
_TABLE_NAMES = frozenset(item[0] for item in _TABLE_LAYOUT)
_APPLY_STEPS = ("event", "dedup", "reducer", "cursor")
_REBUILD_STEPS = (
    "temp_create",
    "schema",
    "apply",
    "checkpoint",
    "temp_fsync",
    "old_sidecar_cleanup",
    "rename",
    "parent_fsync",
    "reopen_verify",
)
_RETENTION_REBUILD_FACTORY = object()


class ProjectionError(RuntimeError):
    """Base class for projection failures."""


class ProjectionAuthorityError(ProjectionError):
    """Evidence or ACK authority does not permit the requested projection."""


class ProjectionValidationError(ProjectionError):
    """Authenticated evidence is not a valid C1C reducer input."""


class ProjectionConflict(ProjectionError):
    """Existing projection facts conflict with immutable authenticated evidence."""


class ProjectionUnhealthy(ProjectionError):
    """The projection has latched an ambiguous or conflicting state."""


class ProjectionBusy(ProjectionError):
    """Another process owns the stable projection lock."""


@dataclass(frozen=True)
class ProjectionCursor:
    host_id: str
    source_sequence: int
    event_id: str
    content_sha256: str
    frame_sha256: str


@dataclass(frozen=True)
class ProjectionStatus:
    healthy: bool
    cursor: ProjectionCursor | None


@dataclass(frozen=True)
class ProjectionApplyResult:
    event_id: str
    duplicate_of_event_id: str | None
    reducer_applied: bool
    cursor: ProjectionCursor


@dataclass(frozen=True)
class RebuildReport:
    snapshot_hash: str
    table_counts: tuple[tuple[str, int], ...]
    source_record_count: int
    duplicate_count: int
    cursor: ProjectionCursor | None


@dataclass(frozen=True)
class _PreparedRecord:
    record: StoredEvidenceRecord
    envelope: EventEnvelopeV1
    dedup_kind: str
    logical_key_sha256: str
    falco: FalcoConnectV1 | None
    coverage: CoverageEventV1 | None


@dataclass(frozen=True)
class _FileBinding:
    device: int
    inode: int


def _uint64(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
        raise ProjectionValidationError("projection uint64 is out of range")
    return f"{value:020d}"


def _decode_uint64(value: object) -> int:
    if not isinstance(value, str) or _UINT64.fullmatch(value) is None:
        raise ProjectionConflict("projection contains a non-canonical uint64")
    decoded = int(value)
    if decoded >= 2**64:
        raise ProjectionConflict("projection uint64 exceeds its contract")
    return decoded


def _optional_uint64(value: int | None) -> str | None:
    return None if value is None else _uint64(value)


def _validated_retired_ranges(
    value: object,
) -> tuple[tuple[int, int], ...]:
    if type(value) is not tuple or not value:
        raise ProjectionConflict("authenticated retired ranges are unavailable")
    validated: list[tuple[int, int]] = []
    prior_end = 0
    for item in value:
        if type(item) is not tuple or len(item) != 2:
            raise ProjectionConflict("authenticated retired range is invalid")
        start, end = item
        if (
            type(start) is not int
            or type(end) is not int
            or not 1 <= start <= end < 2**64
            or start <= prior_end
        ):
            raise ProjectionConflict("authenticated retired range is invalid")
        validated.append((start, end))
        prior_end = end
    return tuple(validated)


def _validate_regular(info: os.stat_result, *, label: str) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ProjectionConflict(f"unsafe {label} artifact")


def _validate_parent(path: Path) -> int:
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError as error:
        raise ProjectionConflict("projection parent must already exist") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ProjectionConflict("unsafe projection parent directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
        os.close(descriptor)
        raise ProjectionConflict("projection parent changed during open")
    return descriptor


def _binding(info: os.stat_result) -> _FileBinding:
    return _FileBinding(info.st_dev, info.st_ino)


def _lstat_at(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _bind_regular_at(parent_fd: int, name: str, *, label: str) -> _FileBinding:
    before = _lstat_at(parent_fd, name)
    if before is None:
        raise ProjectionConflict(f"{label} disappeared")
    _validate_regular(before, label=label)
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    try:
        opened = os.fstat(descriptor)
        _validate_regular(opened, label=label)
        if _binding(opened) != _binding(before):
            raise ProjectionConflict(f"{label} changed during binding")
        return _binding(opened)
    finally:
        os.close(descriptor)


def _require_entry_binding(
    parent_fd: int,
    name: str,
    expected: _FileBinding,
    *,
    label: str,
) -> None:
    actual = _lstat_at(parent_fd, name)
    if actual is None:
        raise ProjectionConflict(f"{label} disappeared")
    _validate_regular(actual, label=label)
    if _binding(actual) != expected:
        raise ProjectionConflict(f"{label} identity changed")


def _open_stable_lock(parent_fd: int, name: str) -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    try:
        _validate_regular(os.fstat(descriptor), label="projection lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ProjectionBusy("projection lock is already held") from error
        entry = _lstat_at(parent_fd, name)
        if entry is None or _binding(entry) != _binding(os.fstat(descriptor)):
            raise ProjectionConflict("projection lock entry changed during open")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _precreate_file(parent_fd: int, name: str) -> _FileBinding:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    try:
        info = os.fstat(descriptor)
        _validate_regular(info, label="new projection")
        return _binding(info)
    finally:
        os.close(descriptor)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    connection.execute("PRAGMA synchronous=FULL")
    if str(mode).lower() != "wal":
        connection.close()
        raise ProjectionConflict("projection did not enter WAL mode")
    return connection


def _verify_pragmas(connection: sqlite3.Connection) -> None:
    expected: tuple[tuple[str, object], ...] = (
        ("journal_mode", "wal"),
        ("synchronous", 2),
        ("foreign_keys", 1),
        ("trusted_schema", 0),
        ("busy_timeout", 5000),
    )
    for pragma, wanted in expected:
        actual = connection.execute(f"PRAGMA {pragma}").fetchone()[0]
        if isinstance(wanted, str):
            actual = str(actual).lower()
        if actual != wanted:
            raise ProjectionConflict(f"projection PRAGMA {pragma} is unsafe")


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _verify_schema(connection: sqlite3.Connection) -> None:
    actual_tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if actual_tables != _TABLE_NAMES:
        raise ProjectionConflict("projection schema table set is not exact")
    expected_connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        expected_connection.execute("PRAGMA foreign_keys=ON")
        expected_connection.execute("PRAGMA trusted_schema=OFF")
        _create_schema(expected_connection)
        expected_schema = expected_connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            "WHERE sql IS NOT NULL ORDER BY type, name"
        ).fetchall()
    finally:
        expected_connection.close()
    actual_schema = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema "
        "WHERE sql IS NOT NULL ORDER BY type, name"
    ).fetchall()
    if [tuple(row) for row in actual_schema] != [
        tuple(row) for row in expected_schema
    ]:
        raise ProjectionConflict("projection schema definition is not exact")
    meta = dict(connection.execute("SELECT key, value FROM schema_meta ORDER BY key"))
    if meta != _SCHEMA_META:
        raise ProjectionConflict("projection schema metadata is not exact")
    integrity = connection.execute("PRAGMA integrity_check").fetchall()
    if [str(row[0]) for row in integrity] != ["ok"]:
        raise ProjectionConflict("projection integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise ProjectionConflict("projection foreign-key check failed")
    _verify_pragmas(connection)


def _cursor_from_row(row: sqlite3.Row | None) -> ProjectionCursor | None:
    if row is None:
        return None
    host_id = row["host_id"]
    event_id = row["event_id"]
    content_sha256 = row["content_sha256"]
    frame_sha256 = row["frame_sha256"]
    if (
        type(host_id) is not str
        or UUID4.fullmatch(host_id) is None
        or type(event_id) is not str
        or _EVENT_ID.fullmatch(event_id) is None
        or type(content_sha256) is not str
        or HEX64.fullmatch(content_sha256) is None
        or type(frame_sha256) is not str
        or HEX64.fullmatch(frame_sha256) is None
    ):
        raise ProjectionConflict("projection cursor identity is invalid")
    return ProjectionCursor(
        host_id=host_id,
        source_sequence=_decode_uint64(row["source_sequence"]),
        event_id=event_id,
        content_sha256=content_sha256,
        frame_sha256=frame_sha256,
    )


def _current_cursor(connection: sqlite3.Connection) -> ProjectionCursor | None:
    rows = connection.execute(
        "SELECT host_id, source_sequence, event_id, content_sha256, frame_sha256 "
        "FROM ingest_cursors ORDER BY host_id"
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict("single-host projection has multiple cursors")
    return _cursor_from_row(rows[0] if rows else None)


def _current_cursor_ref(connection: sqlite3.Connection) -> EvidenceRef | None:
    rows = connection.execute(
        "SELECT source_sequence,event_id,content_sha256,segment_id,"
        "segment_relative_path,frame_offset,frame_size,frame_sha256 "
        "FROM ingest_cursors ORDER BY host_id"
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict("single-host projection has multiple cursors")
    if not rows:
        return None
    row = rows[0]
    return EvidenceRef(
        segment_id=str(row["segment_id"]),
        segment_relative_path=str(row["segment_relative_path"]),
        frame_offset=_decode_uint64(row["frame_offset"]),
        frame_size=_decode_uint64(row["frame_size"]),
        frame_sha256=str(row["frame_sha256"]),
        event_id=str(row["event_id"]),
        source_sequence=_decode_uint64(row["source_sequence"]),
        content_sha256=str(row["content_sha256"]),
    )


def _event_values(prepared: _PreparedRecord, duplicate: str | None) -> tuple[object, ...]:
    envelope = prepared.envelope
    ref = prepared.record.ref
    canonical = prepared.record.canonical_envelope
    return (
        envelope.event_id,
        envelope.host_id,
        _uint64(envelope.source_sequence),
        envelope.event_type,
        envelope.source_id,
        envelope.source_version,
        envelope.key_id,
        _uint64(envelope.key_epoch),
        envelope.boot_id,
        envelope.event_time,
        envelope.ingest_time,
        envelope.clock_uncertainty_ms,
        envelope.container_id,
        envelope.container_start_time,
        envelope.release_id,
        _uint64(envelope.inventory_generation),
        _optional_uint64(envelope.inventory_revision),
        canonical_json(envelope.normalized_fields).decode("utf-8"),
        envelope.normalized_fields_sha256,
        canonical_json(envelope.redaction_flags).decode("utf-8"),
        canonical_json(envelope.coverage_flags).decode("utf-8"),
        envelope.source_payload_hash,
        envelope.source_signature,
        ref.segment_id,
        ref.segment_relative_path,
        _uint64(ref.frame_offset),
        _uint64(ref.frame_size),
        ref.frame_sha256,
        hashlib.sha256(canonical).hexdigest(),
        ref.content_sha256,
        duplicate,
    )


def _prepare(record: StoredEvidenceRecord) -> _PreparedRecord:
    try:
        raw = json.loads(record.canonical_envelope)
        envelope = EventEnvelopeV1.model_validate(raw, strict=True)
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError) as error:
        raise ProjectionValidationError("authenticated envelope cannot be reparsed") from error
    ref = record.ref
    if (
        envelope.event_id != ref.event_id
        or envelope.source_sequence != ref.source_sequence
        or hashlib.sha256(record.canonical_envelope).hexdigest() != ref.content_sha256
        or canonical_json(raw) != record.canonical_envelope
    ):
        raise ProjectionValidationError("authenticated record outer facts do not bind")
    falco: FalcoConnectV1 | None = None
    coverage: CoverageEventV1 | None = None
    if envelope.event_type == "falco_connect":
        if envelope.normalized_fields.get("raw_event_sha256") != envelope.source_payload_hash:
            raise ProjectionValidationError("Falco raw hash does not bind source payload")
        try:
            falco = FalcoConnectV1.model_validate(envelope.normalized_fields, strict=True)
        except ValidationError as error:
            raise ProjectionValidationError("Falco reducer input is invalid") from error
    elif envelope.event_type == "coverage":
        try:
            coverage = CoverageEventV1.model_validate(envelope.normalized_fields, strict=True)
        except ValidationError as error:
            raise ProjectionValidationError("coverage reducer input is invalid") from error
    kind, logical_hash = _logical_primary_identity_v1(envelope)
    return _PreparedRecord(record, envelope, kind, logical_hash, falco, coverage)


def _retired_record_from_projection_event(
    row: tuple[object, ...],
    verifier: EnvelopeVerifier,
) -> StoredEvidenceRecord:
    columns = _TABLE_LAYOUT[1][1]
    if len(row) != len(columns):
        raise ProjectionConflict("retired projection event shape is invalid")
    values = dict(zip(columns, row, strict=True))

    def required_text(name: str) -> str:
        value = values[name]
        if type(value) is not str:
            raise ProjectionConflict(
                f"retired projection event {name} is not exact text"
            )
        return value

    def optional_text(name: str) -> str | None:
        value = values[name]
        if value is not None and type(value) is not str:
            raise ProjectionConflict(
                f"retired projection event {name} is not exact optional text"
            )
        return value

    def canonical_json_value(
        name: str,
    ) -> object:
        encoded = required_text(name)
        try:
            decoded = json.loads(encoded)
            rebuilt = canonical_json(decoded).decode("utf-8")
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise ProjectionConflict(
                f"retired projection event {name} is not canonical JSON"
            ) from error
        if rebuilt != encoded:
            raise ProjectionConflict(
                f"retired projection event {name} is not exact canonical JSON"
            )
        return decoded

    normalized_fields = canonical_json_value("normalized_fields_json")
    redaction_flags = canonical_json_value("redaction_flags_json")
    coverage_flags = canonical_json_value("coverage_flags_json")
    if (
        type(normalized_fields) is not dict
        or type(redaction_flags) is not list
        or type(coverage_flags) is not list
    ):
        raise ProjectionConflict(
            "retired projection event canonical JSON types are invalid"
        )
    clock_uncertainty_ms = values["clock_uncertainty_ms"]
    if type(clock_uncertainty_ms) is not int:
        raise ProjectionConflict(
            "retired projection event clock uncertainty is invalid"
        )
    envelope_value: dict[str, object] = {
        "schema_version": "agmind.event-envelope.v1",
        "event_id": required_text("event_id"),
        "event_type": required_text("event_type"),
        "source_id": required_text("source_id"),
        "source_version": required_text("source_version"),
        "key_id": required_text("key_id"),
        "key_epoch": _decode_uint64(values["key_epoch"]),
        "host_id": required_text("host_id"),
        "boot_id": required_text("boot_id"),
        "source_sequence": _decode_uint64(values["source_sequence"]),
        "event_time": required_text("event_time"),
        "ingest_time": required_text("ingest_time"),
        "clock_uncertainty_ms": clock_uncertainty_ms,
        "inventory_generation": _decode_uint64(
            values["inventory_generation"]
        ),
        "normalized_fields": normalized_fields,
        "normalized_fields_sha256": required_text(
            "normalized_fields_sha256"
        ),
        "redaction_flags": redaction_flags,
        "coverage_flags": coverage_flags,
        "source_payload_hash": required_text("source_payload_hash"),
        "source_signature": required_text("source_signature"),
    }
    for name in (
        "container_id",
        "container_start_time",
        "release_id",
    ):
        value = optional_text(name)
        if value is not None:
            envelope_value[name] = value
    inventory_revision = values["inventory_revision"]
    if inventory_revision is not None:
        envelope_value["inventory_revision"] = _decode_uint64(
            inventory_revision
        )
    try:
        EnvelopeVerifier._precheck_signed_content(envelope_value)
        envelope = EventEnvelopeV1.model_validate(
            envelope_value,
            strict=True,
        )
        FalcoConnectV1.model_validate(
            envelope.normalized_fields,
            strict=True,
        )
        verifier._validate_special_semantics(envelope)
    except (TypeError, ValueError, ValidationError) as error:
        raise ProjectionConflict(
            "retired projection event is not an exact routine Falco envelope"
        ) from error
    if (
        envelope.event_type != "falco_connect"
        or envelope.host_id != verifier.root.host_id
        or envelope.source_id != "agmind-observerd"
    ):
        raise ProjectionConflict(
            "retired projection event is outside routine Falco authority"
        )
    canonical = canonical_json(envelope)
    digest = hashlib.sha256(canonical).hexdigest()
    if (
        required_text("canonical_sha256") != digest
        or required_text("content_sha256") != digest
    ):
        raise ProjectionConflict(
            "retired projection event does not bind its canonical digest"
        )
    try:
        public_key = verifier.key_chain.key(
            envelope.key_epoch,
            envelope.key_id,
        )
        verify_event_signature(envelope, public_key)
    except (
        InvalidSignature,
        KeyMetadataError,
        TypeError,
        ValueError,
    ) as error:
        raise ProjectionConflict(
            "retired projection event signature is not anchored"
        ) from error

    segment_id = required_text("segment_id")
    segment_relative_path = required_text("segment_relative_path")
    frame_sha256 = required_text("frame_sha256")
    if (
        UUID4.fullmatch(segment_id) is None
        or not segment_relative_path.startswith("segments/")
        or not segment_relative_path.endswith(f"-{segment_id}.agseg")
        or HEX64.fullmatch(frame_sha256) is None
    ):
        raise ProjectionConflict(
            "retired projection event frame reference is invalid"
        )
    ref = EvidenceRef(
        segment_id=segment_id,
        segment_relative_path=segment_relative_path,
        frame_offset=_decode_uint64(values["frame_offset"]),
        frame_size=_decode_uint64(values["frame_size"]),
        frame_sha256=frame_sha256,
        event_id=envelope.event_id,
        source_sequence=envelope.source_sequence,
        content_sha256=digest,
    )
    record = StoredEvidenceRecord(
        envelope=envelope.model_dump(exclude_none=True),
        canonical_envelope=canonical,
        priority=EvidencePriority.ROUTINE,
        accepted_at=envelope.ingest_time,
        ref=ref,
    )
    try:
        prepared = _prepare(record)
    except ProjectionValidationError as error:
        raise ProjectionConflict(
            "retired projection event cannot be replayed exactly"
        ) from error
    if prepared.falco is None or prepared.coverage is not None:
        raise ProjectionConflict(
            "retired projection event is not routine Falco reducer input"
        )
    return record


class ProjectionStore:
    """Factory-opened projection bound to one recovered evidence/ACK lifecycle."""

    _path: Path
    _evidence: SegmentStore
    _acknowledgements: AckJournal
    _step_hook: Callable[[str], None]
    _mutex: RLockType
    _healthy: bool
    _closed: bool
    _parent_fd: int
    _parent_binding: _FileBinding
    _lock_fd: int
    _lock_name: str
    _main_binding: _FileBinding
    _connection: sqlite3.Connection | None

    def __init__(self) -> None:
        raise TypeError("use ProjectionStore.open()")

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        evidence: SegmentStore,
        acknowledgements: AckJournal,
        step_hook: Callable[[str], None] | None = None,
    ) -> ProjectionStore:
        if (
            not path.is_absolute()
            or Path(os.path.normpath(path)) != path
            or not path.name
            or path.name in {".", ".."}
        ):
            raise ProjectionConflict("projection database name is invalid")
        store = object.__new__(cls)
        store._path = path
        store._evidence = evidence
        store._acknowledgements = acknowledgements
        store._step_hook = step_hook or (lambda _step: None)
        store._mutex = RLock()
        store._healthy = True
        store._closed = False
        store._parent_fd = _validate_parent(path.parent)
        store._parent_binding = _binding(os.fstat(store._parent_fd))
        store._lock_fd = -1
        store._lock_name = f".{path.name}.projection.lock"
        store._connection = None
        reconciliation_handoff: bytes | None = None
        try:
            if getattr(acknowledgements, "_store", None) is not evidence:
                raise ProjectionAuthorityError(
                    "ACK journal is not bound to the retained evidence store"
                )
            _ = evidence.acceptance_cursor
            handoff_value = getattr(
                evidence,
                "_projection_reconciliation_completed_state_raw",
                None,
            )
            if handoff_value is not None:
                if (
                    type(evidence) is not SegmentStore
                    or type(handoff_value) is not bytes
                ):
                    raise ProjectionAuthorityError(
                        "projection reconciliation handoff is invalid"
                    )
                reconciliation_handoff = handoff_value
            snapshot = acknowledgements.snapshot()
            if not snapshot.healthy:
                raise ProjectionAuthorityError("ACK journal is unhealthy at projection open")
            store._lock_fd = _open_stable_lock(store._parent_fd, store._lock_name)
            store._recover_temp_artifacts()
            existing = _lstat_at(store._parent_fd, path.name)
            new = existing is None
            if new:
                store._main_binding = _precreate_file(store._parent_fd, path.name)
            else:
                store._main_binding = _bind_regular_at(
                    store._parent_fd,
                    path.name,
                    label="projection database",
                )
            store._validate_sidecars(permit_nonempty=True)
            store._verify_namespace_bindings()
            store._connection = _connect(path)
            store._verify_connected_entry(
                store._connection,
                store._path.name,
                store._main_binding,
            )
            if new:
                _create_schema(store._connection)
            _verify_schema(store._connection)
            store._validate_sidecars(permit_nonempty=True)
            store._verify_namespace_bindings()
            if not new:
                try:
                    records = store._records_for_current_cursor(
                        store._connection,
                        snapshot,
                    )
                    store._validate_logical_prefix(
                        store._connection,
                        records,
                    )
                except ProjectionConflict:
                    if (
                        type(evidence) is not SegmentStore
                        or not getattr(
                            evidence,
                            "_authenticated_retired_ranges",
                            (),
                        )
                    ):
                        raise
                    retired_ranges = _validated_retired_ranges(
                        evidence._authenticated_retired_ranges,
                    )
                    store._validate_retention_rebuild_source(
                        store._connection,
                        snapshot,
                        retired_ranges,
                    )
                    store._rebuild(
                        require_existing_prefix=False,
                    )
            if (
                getattr(
                    evidence,
                    "_projection_reconciliation_completed_state_raw",
                    None,
                )
                is not reconciliation_handoff
            ):
                raise ProjectionConflict(
                    "projection reconciliation handoff changed during open"
                )
            if reconciliation_handoff is not None:
                evidence._projection_reconciliation_completed_state_raw = (
                    None
                )
        except BaseException:
            store.close()
            raise
        return store

    @property
    def path(self) -> Path:
        return self._path

    def _is_bound_to(
        self,
        evidence: SegmentStore,
        acknowledgements: AckJournal,
    ) -> bool:
        with self._mutex:
            return (
                self._evidence is evidence
                and self._acknowledgements is acknowledgements
            )

    def status(self) -> ProjectionStatus:
        with self._mutex:
            if self._closed or not self._healthy or self._connection is None:
                return ProjectionStatus(False, None)
            connection = self._connection
            try:
                self._verify_live_connection(connection)
                cursor = _current_cursor(connection)
                self._verify_live_connection(connection)
            except (ProjectionError, sqlite3.Error, OSError):
                self._healthy = False
                return ProjectionStatus(False, None)
            return ProjectionStatus(True, cursor)

    def _require_usable(self) -> sqlite3.Connection:
        if self._closed:
            raise ProjectionUnhealthy("projection is closed")
        if not self._healthy:
            raise ProjectionUnhealthy("projection state is unhealthy")
        if self._connection is None:
            raise ProjectionUnhealthy("projection connection is unavailable")
        return self._connection

    def _temp_prefix(self) -> str:
        return f".{self._path.name}.projection."

    def _verify_parent_path_binding(self) -> None:
        try:
            actual = os.stat(self._path.parent, follow_symlinks=False)
        except OSError as error:
            raise ProjectionConflict("projection parent path changed") from error
        if _binding(actual) != self._parent_binding:
            raise ProjectionConflict("projection parent path identity changed")

    def _verify_namespace_bindings(self) -> None:
        self._verify_parent_path_binding()
        if self._lock_fd >= 0:
            lock_info = os.fstat(self._lock_fd)
            _validate_regular(lock_info, label="projection lock")
            _require_entry_binding(
                self._parent_fd,
                self._lock_name,
                _binding(lock_info),
                label="projection lock",
            )
        _require_entry_binding(
            self._parent_fd,
            self._path.name,
            self._main_binding,
            label="projection database",
        )

    def _verify_live_connection(self, connection: sqlite3.Connection) -> None:
        try:
            self._verify_namespace_bindings()
            self._verify_connected_entry(
                connection,
                self._path.name,
                self._main_binding,
            )
        except ProjectionConflict:
            self._healthy = False
            raise

    def _verify_connected_entry(
        self,
        connection: sqlite3.Connection,
        name: str,
        expected: _FileBinding,
    ) -> None:
        rows = connection.execute("PRAGMA database_list").fetchall()
        main_rows = [row for row in rows if str(row[1]) == "main"]
        if len(main_rows) != 1:
            raise ProjectionConflict("SQLite main database binding is ambiguous")
        sqlite_path = Path(str(main_rows[0][2]))
        try:
            sqlite_info = os.stat(sqlite_path, follow_symlinks=False)
        except OSError as error:
            raise ProjectionConflict("SQLite main database path is unavailable") from error
        _validate_regular(sqlite_info, label="SQLite main database")
        if _binding(sqlite_info) != expected:
            raise ProjectionConflict("SQLite opened a substituted main database")
        _require_entry_binding(
            self._parent_fd,
            name,
            expected,
            label="SQLite database",
        )
        self._verify_parent_path_binding()

    def _recover_temp_artifacts(self) -> None:
        prefix = self._temp_prefix()
        recognized = re.compile(
            rf"^{re.escape(prefix)}[0-9a-f]{{8}}-[0-9a-f]{{4}}-4[0-9a-f]{{3}}-"
            rf"[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}\.tmp(?:-(?:wal|shm))?$"
        )
        directory_fd = os.open(
            ".",
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            dir_fd=self._parent_fd,
        )
        try:
            names = os.listdir(directory_fd)
        finally:
            os.close(directory_fd)
        for name in names:
            if name == f".{self._path.name}.projection.lock":
                continue
            if not name.startswith(prefix):
                continue
            if recognized.fullmatch(name) is None:
                raise ProjectionConflict("unrecognised projection temp artifact")
            info = _lstat_at(self._parent_fd, name)
            if info is None:
                raise ProjectionConflict("projection temp disappeared")
            _validate_regular(info, label="projection temp")
            os.unlink(name, dir_fd=self._parent_fd)
        os.fsync(self._parent_fd)

    def _validate_sidecars(
        self,
        *,
        base_name: str | None = None,
        permit_nonempty: bool,
    ) -> tuple[str, ...]:
        base_name = self._path.name if base_name is None else base_name
        found: list[str] = []
        for suffix in ("-wal", "-shm"):
            sidecar = f"{base_name}{suffix}"
            info = _lstat_at(self._parent_fd, sidecar)
            if info is None:
                continue
            _validate_regular(info, label="SQLite sidecar")
            descriptor = os.open(
                sidecar,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._parent_fd,
            )
            try:
                opened = os.fstat(descriptor)
                _validate_regular(opened, label="SQLite sidecar")
                if _binding(opened) != _binding(info):
                    raise ProjectionConflict("SQLite sidecar changed during validation")
            finally:
                os.close(descriptor)
            if not permit_nonempty and info.st_size != 0:
                raise ProjectionConflict("checkpoint left a nonempty SQLite sidecar")
            found.append(sidecar)
        return tuple(found)

    def _confirmed_boundary(self, snapshot: AckJournalSnapshot) -> StoredEvidenceRecord:
        if not snapshot.healthy or snapshot.confirmed is None:
            raise ProjectionAuthorityError("a healthy confirmed ACK is required")
        confirmed = snapshot.confirmed
        if confirmed.sequence > self._evidence.acceptance_cursor:
            raise ProjectionAuthorityError("confirmed ACK exceeds evidence acceptance")
        records = tuple(
            self._evidence.iter_authenticated_records(
                after=confirmed.sequence - 1,
                through=confirmed.sequence,
            )
        )
        if len(records) != 1:
            raise ProjectionAuthorityError("confirmed ACK is not a real evidence record")
        record = records[0]
        if (
            record.ref.source_sequence != confirmed.sequence
            or record.ref.event_id != confirmed.event_id
            or record.ref.content_sha256 != confirmed.content_sha256
        ):
            raise ProjectionAuthorityError("confirmed ACK identity is not authenticated")
        return record

    def _records_for_snapshot(
        self,
        snapshot: AckJournalSnapshot,
    ) -> tuple[StoredEvidenceRecord, ...]:
        if not snapshot.healthy:
            raise ProjectionAuthorityError("projection requires a healthy ACK snapshot")
        if snapshot.confirmed is None:
            return ()
        self._confirmed_boundary(snapshot)
        records = tuple(
            self._evidence.iter_authenticated_records(
                after=0,
                through=snapshot.confirmed.sequence,
            )
        )
        if not records or records[-1].ref.source_sequence != snapshot.confirmed.sequence:
            raise ProjectionAuthorityError("confirmed prefix has no authenticated terminal")
        return records

    def _records_for_current_cursor(
        self,
        connection: sqlite3.Connection,
        snapshot: AckJournalSnapshot,
    ) -> tuple[StoredEvidenceRecord, ...]:
        cursor_ref = _current_cursor_ref(connection)
        if cursor_ref is None:
            return ()
        if snapshot.confirmed is None or cursor_ref.source_sequence > snapshot.confirmed.sequence:
            raise ProjectionConflict("projection cursor exceeds frozen confirmed ACK")
        try:
            self._evidence.resolve_authenticated_ref(cursor_ref)
        except Exception as error:
            raise ProjectionConflict(
                "projection cursor is not a complete authenticated EvidenceRef"
            ) from error
        records = tuple(
            self._evidence.iter_authenticated_records(
                after=0,
                through=cursor_ref.source_sequence,
            )
        )
        if not records or records[-1].ref != cursor_ref:
            raise ProjectionConflict("projection cursor does not end a complete real prefix")
        return records

    def _validate_logical_prefix(
        self,
        connection: sqlite3.Connection,
        records: tuple[StoredEvidenceRecord, ...],
    ) -> None:
        expected = sqlite3.connect(":memory:", isolation_level=None)
        expected.row_factory = sqlite3.Row
        try:
            expected.execute("PRAGMA foreign_keys=ON")
            expected.execute("PRAGMA trusted_schema=OFF")
            _create_schema(expected)
            for record in records:
                self._apply_prepared(expected, _prepare(record), invoke_hook=False)
            for table, columns, primary_key in _TABLE_LAYOUT:
                selected = ",".join(columns)
                order = ",".join(f"{column} COLLATE BINARY" for column in primary_key)
                actual_rows = [
                    tuple(row)
                    for row in connection.execute(
                        f"SELECT {selected} FROM {table} ORDER BY {order}"
                    )
                ]
                expected_rows = [
                    tuple(row)
                    for row in expected.execute(
                        f"SELECT {selected} FROM {table} ORDER BY {order}"
                    )
                ]
                if actual_rows != expected_rows:
                    raise ProjectionConflict(
                        f"projection {table} does not match authenticated prefix"
                    )
        finally:
            expected.close()

    def _validate_retention_rebuild_source(
        self,
        connection: sqlite3.Connection,
        snapshot: AckJournalSnapshot,
        retired_ranges: tuple[tuple[int, int], ...],
    ) -> None:
        from agmind_immune.evidence.retention import (
            RetentionStateCorrupt,
            RetentionStateV1,
            decode_retention_state,
        )

        state_binding = self._evidence._retention_state_binding
        reconciliation_handoff = (
            self._evidence
            ._projection_reconciliation_completed_state_raw
        )
        if (
            self._evidence._retention_state_temporary is not None
            or self._evidence._retention_state_namespace_uncertain
        ):
            raise ProjectionConflict(
                "projection reconciliation lacks exact completed retention state"
            )
        if state_binding is None:
            if type(reconciliation_handoff) is not bytes:
                raise ProjectionConflict(
                    "projection reconciliation lacks completed-state handoff"
                )
            state_raw = reconciliation_handoff
        else:
            if (
                state_binding.name != "retention-state.json"
                or type(state_binding.raw) is not bytes
                or (
                    reconciliation_handoff is not None
                    and reconciliation_handoff is not state_binding.raw
                )
            ):
                raise ProjectionConflict(
                    "projection reconciliation completed state is ambiguous"
                )
            state_raw = state_binding.raw
        try:
            state = decode_retention_state(state_raw)
            manifests = (
                self._evidence
                ._retention_state_selected_manifests(state)
            )
        except (
            EvidenceCorrupt,
            RetentionStateCorrupt,
            TypeError,
            ValueError,
        ) as error:
            raise ProjectionConflict(
                "projection reconciliation retention state is invalid"
            ) from error
        if (
            type(state) is not RetentionStateV1
            or state.operation != "tombstone"
            or state.phase != "completed"
            or not manifests
            or (
                state_binding is not None
                and self._evidence._retention_state_binding
                is not state_binding
            )
            or (
                state_binding is None
                and (
                    self._evidence._retention_state_binding is not None
                    or self._evidence
                    ._projection_reconciliation_completed_state_raw
                    is not state_raw
                )
            )
            or self._evidence._retention_state_temporary is not None
            or self._evidence._retention_state_namespace_uncertain
        ):
            raise ProjectionConflict(
                "projection reconciliation retention state is not completed"
            )
        current_retired_ranges = tuple(
            (
                manifest.first_source_sequence,
                manifest.last_source_sequence,
            )
            for manifest in manifests
        )
        if any(
            not any(
                retired_start <= start
                and end <= retired_end
                for retired_start, retired_end in retired_ranges
            )
            for start, end in current_retired_ranges
        ):
            raise ProjectionConflict(
                "completed retention ranges lack authenticated retirement"
            )
        cursor_ref = _current_cursor_ref(connection)
        cursor_sequence = (
            0
            if cursor_ref is None
            else cursor_ref.source_sequence
        )
        if (
            cursor_ref is not None
            and (
                snapshot.confirmed is None
                or cursor_sequence > snapshot.confirmed.sequence
            )
        ):
            raise ProjectionConflict(
                "projection cursor exceeds frozen confirmed ACK"
            )
        confirmed_records = self._records_for_snapshot(snapshot)
        surviving_records = tuple(
            record
            for record in confirmed_records
            if record.ref.source_sequence <= cursor_sequence
        )
        retired_prefix_ranges = tuple(
            (start, min(end, cursor_sequence))
            for start, end in retired_ranges
            if start <= cursor_sequence
        )
        required_retired_prefix_ranges = tuple(
            (start, min(end, cursor_sequence))
            for start, end in current_retired_ranges
            if start <= cursor_sequence
        )
        if any(
            start <= record.ref.source_sequence <= end
            for record in surviving_records
            for start, end in retired_prefix_ranges
        ):
            raise ProjectionConflict(
                "authenticated retired ranges overlap surviving evidence"
            )
        verifier = self._evidence._bound_verifier
        if (
            type(verifier) is not EnvelopeVerifier
            or not self._evidence._is_bound_verifier(verifier)
        ):
            raise ProjectionConflict(
                "retired projection reconstruction lacks verifier authority"
            )
        event_columns = _TABLE_LAYOUT[1][1]
        sequence_index = event_columns.index("source_sequence")
        retired_records = tuple(
            _retired_record_from_projection_event(row, verifier)
            for row in self._ordered_table_rows(connection, "events")
            if any(
                start <= _decode_uint64(row[sequence_index]) <= end
                for start, end in retired_prefix_ranges
            )
        )
        required_retired_sequences = tuple(
            sorted(
                record.ref.source_sequence
                for record in retired_records
                if any(
                    start <= record.ref.source_sequence <= end
                    for start, end in required_retired_prefix_ranges
                )
            )
        )
        retired_record_count = sum(
            end - start + 1
            for start, end in required_retired_prefix_ranges
        )
        if len(required_retired_sequences) != retired_record_count:
            raise ProjectionConflict(
                "retired projection reconstruction is not dense"
            )
        position = 0
        for start, end in required_retired_prefix_ranges:
            for expected_sequence in range(start, end + 1):
                if required_retired_sequences[position] != expected_sequence:
                    raise ProjectionConflict(
                        "retired projection reconstruction has a sequence gap"
                    )
                position += 1
        replay_records = tuple(
            sorted(
                (*surviving_records, *retired_records),
                key=lambda record: record.ref.source_sequence,
            )
        )
        terminal_ref = (
            None
            if not replay_records
            else replay_records[-1].ref
        )
        if terminal_ref != cursor_ref:
            raise ProjectionConflict(
                "signed pre-retention replay does not bind old cursor"
            )
        sequences = tuple(
            record.ref.source_sequence
            for record in replay_records
        )
        if len(sequences) != len(set(sequences)):
            raise ProjectionConflict(
                "retired projection reconstruction has duplicate sequences"
            )

        expected = sqlite3.connect(":memory:", isolation_level=None)
        expected.row_factory = sqlite3.Row
        try:
            expected.execute("PRAGMA foreign_keys=ON")
            expected.execute("PRAGMA trusted_schema=OFF")
            _create_schema(expected)
            for record in replay_records:
                self._apply_prepared(
                    expected,
                    _prepare(record),
                    invoke_hook=False,
                )
            for table, _columns, _primary_key in _TABLE_LAYOUT:
                actual_rows = self._ordered_table_rows(
                    connection,
                    table,
                )
                replayed_rows = self._ordered_table_rows(
                    expected,
                    table,
                )
                if actual_rows != replayed_rows:
                    raise ProjectionConflict(
                        f"projection {table} does not match authenticated "
                        "surviving evidence under exact signed "
                        "pre-retention replay"
                    )
        finally:
            expected.close()

    @staticmethod
    def _ordered_table_rows(
        connection: sqlite3.Connection,
        table: str,
    ) -> list[tuple[object, ...]]:
        layout = next(
            item
            for item in _TABLE_LAYOUT
            if item[0] == table
        )
        _table, columns, primary_key = layout
        selected = ",".join(columns)
        order = ",".join(
            f"{column} COLLATE BINARY"
            for column in primary_key
        )
        return [
            tuple(row)
            for row in connection.execute(
                f"SELECT {selected} FROM {table} ORDER BY {order}"
            )
        ]

    def _exact_retry(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedRecord,
    ) -> ProjectionApplyResult | None:
        row = connection.execute("SELECT * FROM events WHERE event_id=?", (prepared.envelope.event_id,)).fetchone()
        if row is None:
            return None
        dedup = connection.execute(
            "SELECT primary_event_id, is_primary FROM projection_dedup WHERE event_id=?",
            (prepared.envelope.event_id,),
        ).fetchone()
        if dedup is None:
            self._healthy = False
            raise ProjectionConflict("event exists without dedup provenance")
        cursor = _current_cursor(connection)
        if cursor is None:
            self._healthy = False
            raise ProjectionConflict("event exists without a projection cursor")
        return ProjectionApplyResult(
            event_id=prepared.envelope.event_id,
            duplicate_of_event_id=row["duplicate_of_event_id"],
            reducer_applied=False,
            cursor=cursor,
        )

    def apply(self, ref: EvidenceRef) -> ProjectionApplyResult:
        with self._mutex:
            connection = self._require_usable()
            self._verify_live_connection(connection)
            snapshot = self._acknowledgements.snapshot()
            self._confirmed_boundary(snapshot)
            try:
                current_records = self._records_for_current_cursor(connection, snapshot)
                self._validate_logical_prefix(connection, current_records)
            except ProjectionConflict:
                self._healthy = False
                raise
            try:
                record = self._evidence.resolve_authenticated_ref(ref)
            except Exception as error:
                raise ProjectionAuthorityError("ref is not exact authenticated evidence") from error
            if snapshot.confirmed is None or ref.source_sequence > snapshot.confirmed.sequence:
                raise ProjectionAuthorityError("ref exceeds the frozen confirmed ACK")
            prepared = _prepare(record)
            retry = self._exact_retry(connection, prepared)
            if retry is not None:
                self._verify_live_connection(connection)
                return retry
            cursor = _current_cursor(connection)
            after = 0 if cursor is None else cursor.source_sequence
            candidates = self._evidence.iter_authenticated_records(
                after=after,
                through=snapshot.confirmed.sequence,
            )
            next_record = next(candidates, None)
            if next_record is None or next_record.ref != ref:
                raise ProjectionAuthorityError("ref is not the next real authenticated record")
            if cursor is not None and cursor.host_id != prepared.envelope.host_id:
                self._healthy = False
                raise ProjectionConflict("projection cursor host changed")
            result = self._apply_prepared(connection, prepared, invoke_hook=True)
            self._verify_live_connection(connection)
            return result

    def _apply_prepared(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedRecord,
        *,
        invoke_hook: bool,
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
            duplicate_row = connection.execute(
                "SELECT primary_event_id FROM projection_dedup "
                "WHERE dedup_kind=? AND logical_key_sha256=? AND is_primary=1",
                (prepared.dedup_kind, prepared.logical_key_sha256),
            ).fetchone()
            duplicate = (
                None
                if duplicate_row is None
                else str(duplicate_row["primary_event_id"])
            )
            is_primary = duplicate is None
            primary_event_id = envelope.event_id if is_primary else duplicate
            placeholders = ",".join("?" for _ in _TABLE_LAYOUT[1][1])
            connection.execute(
                f"INSERT INTO events({','.join(_TABLE_LAYOUT[1][1])}) VALUES({placeholders})",
                _event_values(prepared, duplicate),
            )
            if invoke_hook:
                self._step_hook(_APPLY_STEPS[0])
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
            if invoke_hook:
                self._step_hook(_APPLY_STEPS[1])
            if is_primary:
                self._reduce(connection, prepared)
            if invoke_hook:
                self._step_hook(_APPLY_STEPS[2])
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
                    _uint64(ref.source_sequence),
                    ref.event_id,
                    ref.content_sha256,
                    ref.segment_id,
                    ref.segment_relative_path,
                    _uint64(ref.frame_offset),
                    _uint64(ref.frame_size),
                    ref.frame_sha256,
                ),
            )
            if invoke_hook:
                self._step_hook(_APPLY_STEPS[3])
            commit_attempted = True
            connection.execute("COMMIT")
            transaction_started = False
            if invoke_hook:
                self._step_hook("commit")
        except sqlite3.IntegrityError as error:
            self._settle_failed_transaction(
                connection,
                error,
                transaction_started=transaction_started,
                commit_attempted=commit_attempted,
                invoke_hook=invoke_hook,
            )
            if connection is self._connection:
                self._healthy = False
            raise ProjectionConflict(
                "projection facts conflict with authenticated evidence"
            ) from error
        except BaseException as error:
            self._settle_failed_transaction(
                connection,
                error,
                transaction_started=transaction_started,
                commit_attempted=commit_attempted,
                invoke_hook=invoke_hook,
            )
            raise
        cursor = ProjectionCursor(
            envelope.host_id,
            ref.source_sequence,
            ref.event_id,
            ref.content_sha256,
            ref.frame_sha256,
        )
        return ProjectionApplyResult(envelope.event_id, duplicate, is_primary, cursor)

    def _settle_failed_transaction(
        self,
        connection: sqlite3.Connection,
        primary: BaseException,
        *,
        transaction_started: bool,
        commit_attempted: bool,
        invoke_hook: bool,
    ) -> None:
        try:
            in_transaction = connection.in_transaction
        except BaseException as state_error:  # noqa: BLE001 - health ambiguity
            if connection is self._connection:
                self._healthy = False
            primary.add_note(
                f"transaction state could not be read: {state_error!r}"
            )
            return
        if commit_attempted and not in_transaction:
            if connection is self._connection:
                self._healthy = False
            primary.add_note("COMMIT may have completed before its failure was observed")
            return
        if not transaction_started and not in_transaction:
            return
        if not in_transaction:
            if connection is self._connection:
                self._healthy = False
            primary.add_note("write transaction ended without a proven rollback")
            return
        try:
            connection.execute("ROLLBACK")
            if invoke_hook:
                self._step_hook("rollback")
        except BaseException as rollback_error:  # noqa: BLE001 - preserve primary
            if connection is self._connection:
                self._healthy = False
            primary.add_note(f"ROLLBACK could not be proven: {rollback_error!r}")

    def _reduce(self, connection: sqlite3.Connection, prepared: _PreparedRecord) -> None:
        envelope = prepared.envelope
        ref = prepared.record.ref
        sequence = _uint64(ref.source_sequence)
        if prepared.coverage is not None:
            coverage_item = prepared.coverage
            connection.execute(
                "INSERT INTO coverage_intervals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    envelope.event_id,
                    envelope.host_id,
                    coverage_item.component,
                    coverage_item.kind,
                    coverage_item.severity,
                    coverage_item.opened_at,
                    coverage_item.closed_at,
                    _optional_uint64(coverage_item.affected_source_sequence_start),
                    _optional_uint64(coverage_item.affected_source_sequence_end),
                    _optional_uint64(coverage_item.dropped_count),
                    coverage_item.reason_code,
                    _optional_uint64(coverage_item.reconcile_generation),
                    sequence,
                    ref.content_sha256,
                ),
            )
            return
        if prepared.falco is None:
            return
        falco_item = prepared.falco
        if (
            falco_item.docker_container_id is not None
            and falco_item.docker_started_at is not None
        ):
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
                    falco_item.docker_container_id,
                    falco_item.docker_started_at,
                    falco_item.image_id,
                    canonical_json(falco_item.repo_digests).decode("utf-8"),
                    falco_item.immutable_spec_sha256,
                    _optional_uint64(falco_item.inventory_revision),
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
                falco_item.docker_container_id,
                falco_item.docker_started_at,
                falco_item.proc_name,
                falco_item.proc_exe_path,
                falco_item.proc_parent_name,
                sequence,
                ref.content_sha256,
            ),
        )
        connection.execute(
            "INSERT INTO network_observations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                envelope.event_id,
                envelope.host_id,
                falco_item.docker_container_id,
                falco_item.docker_started_at,
                int(falco_item.successful_connect),
                falco_item.destination_ipv4,
                falco_item.destination_port,
                falco_item.l4_protocol,
                int(falco_item.investigation_only),
                sequence,
                ref.content_sha256,
            ),
        )

    def snapshot_hash(self) -> str:
        with self._mutex:
            connection = self._require_usable()
            self._verify_live_connection(connection)
            snapshot = self._snapshot_hash(connection)
            self._verify_live_connection(connection)
            return snapshot

    @staticmethod
    def _snapshot_hash(connection: sqlite3.Connection) -> str:
        digest = hashlib.sha256()
        digest.update(_SNAPSHOT_DOMAIN)
        connection.execute("BEGIN")
        try:
            for table, columns, primary_key in _TABLE_LAYOUT:
                digest.update(canonical_json({"table": table, "columns": columns}))
                digest.update(b"\n")
                order = ",".join(f"{column} COLLATE BINARY" for column in primary_key)
                selected = ",".join(columns)
                for row in connection.execute(
                    f"SELECT {selected} FROM {table} ORDER BY {order}"
                ):
                    digest.update(canonical_json({"row": list(row)}))
                    digest.update(b"\n")
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        return digest.hexdigest()

    @staticmethod
    def _counts(connection: sqlite3.Connection) -> tuple[tuple[str, int], ...]:
        return tuple(
            (table, int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]))
            for table, _columns, _primary_key in _TABLE_LAYOUT
        )

    def _rebuild_records(
        self,
    ) -> tuple[tuple[StoredEvidenceRecord, ...], AckJournalSnapshot]:
        snapshot = self._acknowledgements.snapshot()
        return self._records_for_snapshot(snapshot), snapshot

    def rebuild(self) -> RebuildReport:
        return self._rebuild(require_existing_prefix=True)

    def _rebuild_after_authenticated_retention(
        self,
        completion: object,
        *,
        _factory: object,
    ) -> RebuildReport:
        if (
            _factory is not _RETENTION_REBUILD_FACTORY
            or type(self) is not ProjectionStore
        ):
            raise TypeError(
                "retention projection rebuild requires its exact factory"
            )
        with self._mutex:
            binding = (
                self._evidence
                ._authenticated_retention_unlink_completion
            )
            if binding is None or binding.capability is not completion:
                raise ProjectionAuthorityError(
                    "retention projection rebuild lacks exact completion authority"
                )
            self._evidence._validate_authenticated_retention_completion(
                completion,
                binding,
            )
            report = self._rebuild(require_existing_prefix=False)
            current = (
                self._evidence
                ._authenticated_retention_unlink_completion
            )
            if current is not binding:
                self._healthy = False
                raise ProjectionAuthorityError(
                    "retention completion changed during projection rebuild"
                )
            self._evidence._validate_authenticated_retention_completion(
                completion,
                binding,
            )
            return report

    def _rebuild(
        self,
        *,
        require_existing_prefix: bool,
    ) -> RebuildReport:
        with self._mutex:
            old_connection = self._require_usable()
            self._verify_live_connection(old_connection)
            records, snapshot = self._rebuild_records()
            old_records: tuple[StoredEvidenceRecord, ...] | None = None
            if require_existing_prefix:
                old_records = self._records_for_current_cursor(
                    old_connection,
                    snapshot,
                )
                self._validate_logical_prefix(
                    old_connection,
                    old_records,
                )
            temp_name = f"{self._temp_prefix()}{uuid.uuid4()}.tmp"
            temp_path = self._path.parent / temp_name
            temp_connection: sqlite3.Connection | None = None
            reopened_connection: sqlite3.Connection | None = None
            renamed = False
            report: RebuildReport | None = None
            try:
                self._verify_namespace_bindings()
                temp_binding = _precreate_file(self._parent_fd, temp_name)
                self._step_hook(_REBUILD_STEPS[0])
                temp_connection = _connect(temp_path)
                self._verify_connected_entry(
                    temp_connection,
                    temp_name,
                    temp_binding,
                )
                _create_schema(temp_connection)
                _verify_schema(temp_connection)
                self._step_hook(_REBUILD_STEPS[1])
                duplicates = 0
                for record in records:
                    result = self._apply_prepared(
                        temp_connection,
                        _prepare(record),
                        invoke_hook=False,
                    )
                    duplicates += int(result.duplicate_of_event_id is not None)
                self._step_hook(_REBUILD_STEPS[2])
                logical_hash = self._snapshot_hash(temp_connection)
                counts = self._counts(temp_connection)
                cursor = _current_cursor(temp_connection)
                report = RebuildReport(
                    logical_hash,
                    counts,
                    len(records),
                    duplicates,
                    cursor,
                )
                self._verify_parent_path_binding()
                _require_entry_binding(
                    self._parent_fd,
                    temp_name,
                    temp_binding,
                    label="temporary projection",
                )
                checkpoint = temp_connection.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
                if checkpoint is None or int(checkpoint[0]) != 0:
                    raise ProjectionConflict("temporary projection checkpoint is busy")
                self._verify_parent_path_binding()
                _require_entry_binding(
                    self._parent_fd,
                    temp_name,
                    temp_binding,
                    label="temporary projection",
                )
                self._step_hook(_REBUILD_STEPS[3])
                temp_connection.close()
                temp_connection = None
                _require_entry_binding(
                    self._parent_fd,
                    temp_name,
                    temp_binding,
                    label="temporary projection",
                )
                descriptor = os.open(
                    temp_name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=self._parent_fd,
                )
                try:
                    temp_fsync_info = os.fstat(descriptor)
                    _validate_regular(temp_fsync_info, label="temporary projection")
                    if _binding(temp_fsync_info) != temp_binding:
                        raise ProjectionConflict(
                            "temporary projection changed before fsync"
                        )
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                for sidecar in self._validate_sidecars(
                    base_name=temp_name,
                    permit_nonempty=False,
                ):
                    os.unlink(sidecar, dir_fd=self._parent_fd)
                os.fsync(self._parent_fd)
                self._step_hook(_REBUILD_STEPS[4])

                self._verify_namespace_bindings()
                checkpoint = old_connection.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
                if checkpoint is None or int(checkpoint[0]) != 0:
                    raise ProjectionConflict("old projection checkpoint is busy")
                self._verify_namespace_bindings()
                old_connection.close()
                self._connection = None
                for sidecar in self._validate_sidecars(permit_nonempty=False):
                    os.unlink(sidecar, dir_fd=self._parent_fd)
                os.fsync(self._parent_fd)
                self._step_hook(_REBUILD_STEPS[5])
                _require_entry_binding(
                    self._parent_fd,
                    self._path.name,
                    self._main_binding,
                    label="projection database before rename",
                )
                _require_entry_binding(
                    self._parent_fd,
                    temp_name,
                    temp_binding,
                    label="temporary projection before rename",
                )
                os.replace(
                    temp_name,
                    self._path.name,
                    src_dir_fd=self._parent_fd,
                    dst_dir_fd=self._parent_fd,
                )
                renamed = True
                self._main_binding = _bind_regular_at(
                    self._parent_fd,
                    self._path.name,
                    label="rebuilt projection",
                )
                self._step_hook(_REBUILD_STEPS[6])
                os.fsync(self._parent_fd)
                self._step_hook(_REBUILD_STEPS[7])
                self._verify_namespace_bindings()
                reopened_connection = _connect(self._path)
                self._verify_connected_entry(
                    reopened_connection,
                    self._path.name,
                    self._main_binding,
                )
                _verify_schema(reopened_connection)
                self._validate_sidecars(permit_nonempty=True)
                self._validate_logical_prefix(reopened_connection, records)
                reopened_hash = self._snapshot_hash(reopened_connection)
                reopened_counts = self._counts(reopened_connection)
                reopened_cursor = _current_cursor(reopened_connection)
                if (
                    reopened_hash != report.snapshot_hash
                    or reopened_counts != report.table_counts
                    or reopened_cursor != report.cursor
                    or self._acknowledgements.snapshot() != snapshot
                ):
                    reopened_connection.close()
                    reopened_connection = None
                    raise ProjectionConflict("reopened projection differs from rebuild")
                self._connection = reopened_connection
                reopened_connection = None
                self._step_hook(_REBUILD_STEPS[8])
                return report
            except BaseException as primary:
                if temp_connection is not None:
                    try:
                        temp_connection.close()
                    except BaseException as close_error:  # noqa: BLE001 - preserve primary
                        primary.add_note(
                            f"temporary projection close failed: {close_error!r}"
                        )
                if reopened_connection is not None:
                    try:
                        reopened_connection.close()
                    except BaseException as close_error:  # noqa: BLE001 - preserve primary
                        primary.add_note(
                            f"reopened projection close failed: {close_error!r}"
                        )
                if renamed:
                    self._healthy = False
                    if self._connection is not None:
                        try:
                            self._connection.close()
                        except BaseException as close_error:  # noqa: BLE001
                            primary.add_note(
                                f"live projection close failed: {close_error!r}"
                            )
                        self._connection = None
                else:
                    for suffix in ("", "-wal", "-shm"):
                        artifact = f"{temp_name}{suffix}"
                        info = _lstat_at(self._parent_fd, artifact)
                        if info is not None:
                            try:
                                _validate_regular(info, label="temporary projection")
                                os.unlink(artifact, dir_fd=self._parent_fd)
                            except BaseException as cleanup_error:  # noqa: BLE001
                                primary.add_note(
                                    f"temporary cleanup failed: {cleanup_error!r}"
                                )
                    if self._connection is None:
                        reopened_old: sqlite3.Connection | None = None
                        try:
                            self._verify_namespace_bindings()
                            reopened_old = _connect(self._path)
                            self._verify_connected_entry(
                                reopened_old,
                                self._path.name,
                                self._main_binding,
                            )
                            _verify_schema(reopened_old)
                            self._validate_sidecars(permit_nonempty=True)
                            if old_records is not None:
                                self._validate_logical_prefix(
                                    reopened_old,
                                    old_records,
                                )
                        except BaseException as recovery_error:  # noqa: BLE001
                            self._healthy = False
                            if reopened_old is not None:
                                try:
                                    reopened_old.close()
                                except BaseException as close_error:  # noqa: BLE001
                                    primary.add_note(
                                        "failed recovered connection close: "
                                        f"{close_error!r}"
                                    )
                            primary.add_note(
                                f"old projection recovery failed: {recovery_error!r}"
                            )
                        else:
                            self._connection = reopened_old
                raise

    def close(self) -> None:
        with getattr(self, "_mutex", RLock()):
            if getattr(self, "_closed", False):
                return
            self._closed = True
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
                self._connection = None
            lock_fd = getattr(self, "_lock_fd", -1)
            if lock_fd >= 0:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
                self._lock_fd = -1
            parent_fd = getattr(self, "_parent_fd", -1)
            if parent_fd >= 0:
                os.close(parent_fd)
                self._parent_fd = -1
