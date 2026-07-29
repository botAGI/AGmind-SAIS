"""Authenticated, ACK-capped SQLite projection of authoritative evidence."""

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
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from pydantic import ValidationError

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import CoverageEventV1, EventEnvelopeV1, FalcoConnectV1
from agmind_immune.evidence.segments import (
    EvidenceRef,
    SegmentStore,
    StoredEvidenceRecord,
)
from agmind_immune.ingest.ack_journal import AckJournal, AckJournalSnapshot

_UINT64 = re.compile(r"^[0-9]{20}$")
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


def _open_stable_lock(parent_fd: int, name: str) -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    try:
        _validate_regular(os.fstat(descriptor), label="projection lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ProjectionBusy("projection lock is already held") from error
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _precreate_file(parent_fd: int, name: str) -> None:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
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
    return ProjectionCursor(
        host_id=str(row["host_id"]),
        source_sequence=_decode_uint64(row["source_sequence"]),
        event_id=str(row["event_id"]),
        content_sha256=str(row["content_sha256"]),
        frame_sha256=str(row["frame_sha256"]),
    )


def _current_cursor(connection: sqlite3.Connection) -> ProjectionCursor | None:
    rows = connection.execute(
        "SELECT host_id, source_sequence, event_id, content_sha256, frame_sha256 "
        "FROM ingest_cursors ORDER BY host_id"
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict("single-host projection has multiple cursors")
    return _cursor_from_row(rows[0] if rows else None)


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
        kind = "falco_connect"
        key: tuple[str, ...] = (
            envelope.host_id,
            envelope.event_type,
            envelope.source_payload_hash,
        )
    elif envelope.event_type == "coverage":
        try:
            coverage = CoverageEventV1.model_validate(envelope.normalized_fields, strict=True)
        except ValidationError as error:
            raise ProjectionValidationError("coverage reducer input is invalid") from error
        kind = "coverage"
        key = (
            envelope.host_id,
            envelope.event_type,
            envelope.normalized_fields_sha256,
            envelope.source_payload_hash,
        )
    else:
        kind = "other"
        key = (envelope.event_id,)
    logical_hash = hashlib.sha256(
        b"AGMIND_PROJECTION_DEDUP_V1\0"
        + kind.encode("ascii")
        + b"\0"
        + canonical_json(key)
    ).hexdigest()
    return _PreparedRecord(record, envelope, kind, logical_hash, falco, coverage)


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
    _lock_fd: int
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
        if not path.name or path.name in {".", ".."}:
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
        store._lock_fd = -1
        store._connection = None
        try:
            if getattr(acknowledgements, "_store", None) is not evidence:
                raise ProjectionAuthorityError(
                    "ACK journal is not bound to the retained evidence store"
                )
            _ = evidence.acceptance_cursor
            if not acknowledgements.snapshot().healthy:
                raise ProjectionAuthorityError("ACK journal is unhealthy at projection open")
            lock_name = f".{path.name}.projection.lock"
            store._lock_fd = _open_stable_lock(store._parent_fd, lock_name)
            store._recover_temp_artifacts()
            new = not path.exists()
            if new:
                _precreate_file(store._parent_fd, path.name)
            else:
                _validate_regular(path.stat(follow_symlinks=False), label="projection database")
            store._validate_sidecars(permit_nonempty=True)
            store._connection = _connect(path)
            if new:
                _create_schema(store._connection)
            _verify_schema(store._connection)
            store._validate_sidecars(permit_nonempty=True)
        except BaseException:
            store.close()
            raise
        return store

    @property
    def path(self) -> Path:
        return self._path

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

    def _recover_temp_artifacts(self) -> None:
        prefix = self._temp_prefix()
        recognized = re.compile(
            rf"^{re.escape(prefix)}[0-9a-f]{{8}}-[0-9a-f]{{4}}-4[0-9a-f]{{3}}-"
            rf"[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}\.tmp(?:-(?:wal|shm))?$"
        )
        for name in os.listdir(self._path.parent):
            if name == f".{self._path.name}.projection.lock":
                continue
            if not name.startswith(prefix):
                continue
            if recognized.fullmatch(name) is None:
                raise ProjectionConflict("unrecognised projection temp artifact")
            artifact = self._path.parent / name
            _validate_regular(artifact.stat(follow_symlinks=False), label="projection temp")
            artifact.unlink()
        os.fsync(self._parent_fd)

    def _validate_sidecars(
        self,
        *,
        base: Path | None = None,
        permit_nonempty: bool,
    ) -> tuple[Path, ...]:
        base = self._path if base is None else base
        found: list[Path] = []
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{base}{suffix}")
            if not sidecar.exists():
                continue
            _validate_regular(sidecar.stat(follow_symlinks=False), label="SQLite sidecar")
            if not permit_nonempty and sidecar.stat().st_size != 0:
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

    def _exact_retry(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedRecord,
    ) -> ProjectionApplyResult | None:
        row = connection.execute("SELECT * FROM events WHERE event_id=?", (prepared.envelope.event_id,)).fetchone()
        if row is None:
            return None
        expected = _event_values(prepared, row["duplicate_of_event_id"])
        columns = _TABLE_LAYOUT[1][1]
        actual = tuple(row[column] for column in columns)
        if actual != expected:
            self._healthy = False
            raise ProjectionConflict("event ID conflicts with immutable evidence facts")
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
            snapshot = self._acknowledgements.snapshot()
            self._confirmed_boundary(snapshot)
            try:
                record = self._evidence.resolve_authenticated_ref(ref)
            except Exception as error:
                raise ProjectionAuthorityError("ref is not exact authenticated evidence") from error
            if snapshot.confirmed is None or ref.source_sequence > snapshot.confirmed.sequence:
                raise ProjectionAuthorityError("ref exceeds the frozen confirmed ACK")
            prepared = _prepare(record)
            retry = self._exact_retry(connection, prepared)
            if retry is not None:
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
            return self._apply_prepared(connection, prepared, invoke_hook=True)

    def _apply_prepared(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedRecord,
        *,
        invoke_hook: bool,
    ) -> ProjectionApplyResult:
        envelope = prepared.envelope
        ref = prepared.record.ref
        duplicate_row = connection.execute(
            "SELECT primary_event_id FROM projection_dedup "
            "WHERE dedup_kind=? AND logical_key_sha256=? AND is_primary=1",
            (prepared.dedup_kind, prepared.logical_key_sha256),
        ).fetchone()
        duplicate = None if duplicate_row is None else str(duplicate_row["primary_event_id"])
        is_primary = duplicate is None
        primary_event_id = envelope.event_id if is_primary else duplicate
        try:
            connection.execute("BEGIN IMMEDIATE")
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
            connection.execute("COMMIT")
        except sqlite3.IntegrityError as error:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            if connection is self._connection:
                self._healthy = False
            raise ProjectionConflict(
                "projection facts conflict with authenticated evidence"
            ) from error
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        cursor = ProjectionCursor(
            envelope.host_id,
            ref.source_sequence,
            ref.event_id,
            ref.content_sha256,
            ref.frame_sha256,
        )
        return ProjectionApplyResult(envelope.event_id, duplicate, is_primary, cursor)

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
            return self._snapshot_hash(self._require_usable())

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
        if not snapshot.healthy:
            raise ProjectionAuthorityError("rebuild requires a healthy ACK snapshot")
        if snapshot.confirmed is None:
            return (), snapshot
        self._confirmed_boundary(snapshot)
        records = tuple(
            self._evidence.iter_authenticated_records(
                after=0,
                through=snapshot.confirmed.sequence,
            )
        )
        if not records or records[-1].ref.source_sequence != snapshot.confirmed.sequence:
            raise ProjectionAuthorityError("rebuild prefix does not end at confirmed ACK")
        return records, snapshot

    def rebuild(self) -> RebuildReport:
        with self._mutex:
            old_connection = self._require_usable()
            records, _snapshot = self._rebuild_records()
            temp_name = f"{self._temp_prefix()}{uuid.uuid4()}.tmp"
            temp_path = self._path.parent / temp_name
            temp_connection: sqlite3.Connection | None = None
            renamed = False
            report: RebuildReport | None = None
            try:
                _precreate_file(self._parent_fd, temp_name)
                self._step_hook(_REBUILD_STEPS[0])
                temp_connection = _connect(temp_path)
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
                checkpoint = temp_connection.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
                if checkpoint is None or int(checkpoint[0]) != 0:
                    raise ProjectionConflict("temporary projection checkpoint is busy")
                self._step_hook(_REBUILD_STEPS[3])
                temp_connection.close()
                temp_connection = None
                descriptor = os.open(
                    temp_name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=self._parent_fd,
                )
                try:
                    _validate_regular(os.fstat(descriptor), label="temporary projection")
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                for sidecar in self._validate_sidecars(
                    base=temp_path,
                    permit_nonempty=False,
                ):
                    sidecar.unlink()
                os.fsync(self._parent_fd)
                self._step_hook(_REBUILD_STEPS[4])

                checkpoint = old_connection.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
                if checkpoint is None or int(checkpoint[0]) != 0:
                    raise ProjectionConflict("old projection checkpoint is busy")
                old_connection.close()
                self._connection = None
                for sidecar in self._validate_sidecars(permit_nonempty=False):
                    sidecar.unlink()
                os.fsync(self._parent_fd)
                self._step_hook(_REBUILD_STEPS[5])
                os.replace(
                    temp_name,
                    self._path.name,
                    src_dir_fd=self._parent_fd,
                    dst_dir_fd=self._parent_fd,
                )
                renamed = True
                self._step_hook(_REBUILD_STEPS[6])
                os.fsync(self._parent_fd)
                self._step_hook(_REBUILD_STEPS[7])
                self._connection = _connect(self._path)
                _verify_schema(self._connection)
                self._validate_sidecars(permit_nonempty=True)
                reopened_hash = self._snapshot_hash(self._connection)
                reopened_counts = self._counts(self._connection)
                reopened_cursor = _current_cursor(self._connection)
                if (
                    reopened_hash != report.snapshot_hash
                    or reopened_counts != report.table_counts
                    or reopened_cursor != report.cursor
                ):
                    raise ProjectionConflict("reopened projection differs from rebuild")
                self._step_hook(_REBUILD_STEPS[8])
                return report
            except BaseException:
                if temp_connection is not None:
                    temp_connection.close()
                if renamed:
                    self._healthy = False
                    if self._connection is not None:
                        self._connection.close()
                        self._connection = None
                else:
                    for suffix in ("", "-wal", "-shm"):
                        artifact = Path(f"{temp_path}{suffix}")
                        if artifact.exists():
                            try:
                                _validate_regular(
                                    artifact.stat(follow_symlinks=False),
                                    label="temporary projection",
                                )
                                artifact.unlink()
                            except OSError:
                                pass
                    if self._connection is None:
                        self._connection = _connect(self._path)
                        _verify_schema(self._connection)
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


def _iter_authenticated_prefix(
    evidence: SegmentStore,
    confirmed_through: int,
) -> Iterator[StoredEvidenceRecord]:
    """Narrow replay helper kept ref-authenticated and explicitly bounded."""
    yield from evidence.iter_authenticated_records(after=0, through=confirmed_through)
