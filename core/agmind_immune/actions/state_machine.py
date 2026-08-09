"""Crash-safe outbox from durable policy intent to durable prepared-plan receipt."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast, final

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import PreparedTemporaryEgressDenyPlanV1

from .client import (
    ActuatorIntentClient,
    IntentDeliveryFatal,
    IntentDeliveryRejected,
    _decode_exact_intent,
    _decode_exact_plan,
    _require_plan_binds_intent,
)
from .models import (
    DecisionIntentCommit,
    _commit_observation,
    _decode_decision_intent_record,
)

_DATABASE_NAME = "intent-delivery.sqlite3"
_READ_ONLY_MARKER_NAME = "intent-delivery.read-only"
_READ_ONLY_MARKER = b"agmind.intent-delivery-read-only.v1\n"
_SCHEMA_VERSION = "agmind.intent-delivery-state.v2"
_RECEIPT_SCHEMA_VERSION = "agmind.prepared-plan-receipt.v1"
_QUARANTINE_SCHEMA_VERSION = "agmind.terminal-intent-quarantine.v1"
_INTENT_HASH_DOMAIN = b"AGMIND_ACTUATOR_INTENT_V1\0"
_RECEIPT_HASH_DOMAIN = b"AGMIND_PREPARED_PLAN_RECEIPT_V1\0"
_QUARANTINE_HASH_DOMAIN = b"AGMIND_TERMINAL_INTENT_QUARANTINE_V1\0"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CANDIDATE_ID = re.compile(r"^cand_[0-9a-f]{64}$")
_INTENT_ID = re.compile(r"^int_[0-9a-f]{32}$")
_PLAN_ID = re.compile(r"^plan_[0-9a-f]{32}$")
_TERMINAL_REASON_STATUS = {
    "intent_conflict": 409,
    "target_stale": 409,
    "intent_rejected": 422,
}
_STATE_MACHINE_FACTORY = object()
_TEST_STATE_MACHINE_FACTORY = object()

_DELIVERY_METADATA_SCHEMA = """
CREATE TABLE delivery_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT, WITHOUT ROWID
""".strip()
_PREPARED_PLAN_RECEIPTS_SCHEMA = """
CREATE TABLE prepared_plan_receipts (
    intent_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL UNIQUE,
    decision_record_sha256 TEXT NOT NULL,
    intent_sha256 TEXT NOT NULL,
    intent_canonical BLOB NOT NULL,
    plan_id TEXT NOT NULL UNIQUE,
    plan_hash TEXT NOT NULL,
    plan_canonical BLOB NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE
) STRICT, WITHOUT ROWID
""".strip()
_TERMINAL_INTENT_QUARANTINES_SCHEMA = """
CREATE TABLE terminal_intent_quarantines (
    intent_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL UNIQUE,
    decision_record_sha256 TEXT NOT NULL,
    intent_sha256 TEXT NOT NULL,
    intent_canonical BLOB NOT NULL,
    status_code INTEGER NOT NULL,
    reason_code TEXT NOT NULL,
    quarantine_sha256 TEXT NOT NULL UNIQUE
) STRICT, WITHOUT ROWID
""".strip()
_SCHEMA = (
    f"{_DELIVERY_METADATA_SCHEMA};\n"
    f"{_PREPARED_PLAN_RECEIPTS_SCHEMA};\n"
    f"{_TERMINAL_INTENT_QUARANTINES_SCHEMA};"
)
_EXACT_SCHEMA = (
    (
        "table",
        "delivery_metadata",
        "delivery_metadata",
        _DELIVERY_METADATA_SCHEMA,
    ),
    (
        "table",
        "prepared_plan_receipts",
        "prepared_plan_receipts",
        _PREPARED_PLAN_RECEIPTS_SCHEMA,
    ),
    (
        "table",
        "terminal_intent_quarantines",
        "terminal_intent_quarantines",
        _TERMINAL_INTENT_QUARANTINES_SCHEMA,
    ),
)
_RECEIPT_SELECT = (
    "SELECT intent_id,candidate_id,decision_record_sha256,intent_sha256,"
    "intent_canonical,plan_id,plan_hash,plan_canonical,receipt_sha256 "
    "FROM prepared_plan_receipts"
)
_QUARANTINE_SELECT = (
    "SELECT intent_id,candidate_id,decision_record_sha256,intent_sha256,"
    "intent_canonical,status_code,reason_code,quarantine_sha256 "
    "FROM terminal_intent_quarantines"
)


def _intent_sha256(raw: bytes) -> str:
    return hashlib.sha256(_INTENT_HASH_DOMAIN + raw).hexdigest()


def _receipt_sha256(document: dict[str, object]) -> str:
    return hashlib.sha256(_RECEIPT_HASH_DOMAIN + canonical_json(document)).hexdigest()


def _quarantine_sha256(document: dict[str, object]) -> str:
    return hashlib.sha256(
        _QUARANTINE_HASH_DOMAIN + canonical_json(document)
    ).hexdigest()


def _validated_commit(commit: object) -> tuple[DecisionIntentCommit, bytes]:
    if type(commit) is not DecisionIntentCommit:
        raise IntentDeliveryFatal("delivery requires one exact durable commit")
    try:
        record = _decode_decision_intent_record(commit.record_canonical)
        observed = _commit_observation(record, commit.record_canonical)
    except Exception as error:
        raise IntentDeliveryFatal("decision-intent commit is invalid") from error
    if observed != commit or commit.effect != "manual_approval_required":
        raise IntentDeliveryFatal("decision-intent commit cannot authorize delivery")
    raw = commit.intent_canonical
    if raw is None or commit.intent_id is None:
        raise IntentDeliveryFatal("manual decision has no exact intent")
    intent = _decode_exact_intent(raw)
    if intent.intent_id != commit.intent_id:
        raise IntentDeliveryFatal("decision-intent commit changed intent identity")
    return commit, raw


@dataclass(frozen=True, slots=True)
class PreparedPlanReceipt:
    """Detached observation of one exact durably stored actuator response."""

    candidate_id: str
    decision_record_sha256: str
    intent_id: str
    intent_sha256: str
    intent_canonical: bytes
    plan_id: str
    plan_hash: str
    plan_canonical: bytes
    receipt_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.candidate_id) is not str
            or _CANDIDATE_ID.fullmatch(self.candidate_id) is None
            or type(self.decision_record_sha256) is not str
            or _HEX64.fullmatch(self.decision_record_sha256) is None
            or type(self.intent_id) is not str
            or _INTENT_ID.fullmatch(self.intent_id) is None
            or type(self.intent_sha256) is not str
            or _HEX64.fullmatch(self.intent_sha256) is None
            or type(self.intent_canonical) is not bytes
            or type(self.plan_id) is not str
            or _PLAN_ID.fullmatch(self.plan_id) is None
            or type(self.plan_hash) is not str
            or _HEX64.fullmatch(self.plan_hash) is None
            or type(self.plan_canonical) is not bytes
            or type(self.receipt_sha256) is not str
            or _HEX64.fullmatch(self.receipt_sha256) is None
        ):
            raise ValueError("prepared-plan receipt fields are invalid")
        intent = _decode_exact_intent(self.intent_canonical)
        plan = _decode_exact_plan(self.plan_canonical)
        _require_plan_binds_intent(plan, intent)
        document = self._hash_document()
        if (
            intent.intent_id != self.intent_id
            or plan.intent_id != self.intent_id
            or plan.plan_id != self.plan_id
            or plan.plan_hash != self.plan_hash
            or not hmac.compare_digest(
                self.intent_sha256,
                _intent_sha256(self.intent_canonical),
            )
            or not hmac.compare_digest(
                self.receipt_sha256,
                _receipt_sha256(document),
            )
        ):
            raise ValueError("prepared-plan receipt bindings are invalid")

    def _hash_document(self) -> dict[str, object]:
        return {
            "schema_version": _RECEIPT_SCHEMA_VERSION,
            "candidate_id": self.candidate_id,
            "decision_record_sha256": self.decision_record_sha256,
            "intent_id": self.intent_id,
            "intent_sha256": self.intent_sha256,
            "intent": _decode_exact_intent(self.intent_canonical),
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "plan": _decode_exact_plan(self.plan_canonical),
        }

    def plan(self) -> PreparedTemporaryEgressDenyPlanV1:
        return _decode_exact_plan(self.plan_canonical)


@dataclass(frozen=True, slots=True)
class QuarantinedIntentReceipt:
    """Durable terminal outcome for one exact actuator intent rejection."""

    candidate_id: str
    decision_record_sha256: str
    intent_id: str
    intent_sha256: str
    intent_canonical: bytes
    status_code: int
    reason_code: str
    quarantine_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.candidate_id) is not str
            or _CANDIDATE_ID.fullmatch(self.candidate_id) is None
            or type(self.decision_record_sha256) is not str
            or _HEX64.fullmatch(self.decision_record_sha256) is None
            or type(self.intent_id) is not str
            or _INTENT_ID.fullmatch(self.intent_id) is None
            or type(self.intent_sha256) is not str
            or _HEX64.fullmatch(self.intent_sha256) is None
            or type(self.intent_canonical) is not bytes
            or type(self.status_code) is not int
            or type(self.reason_code) is not str
            or _TERMINAL_REASON_STATUS.get(self.reason_code) != self.status_code
            or type(self.quarantine_sha256) is not str
            or _HEX64.fullmatch(self.quarantine_sha256) is None
        ):
            raise ValueError("quarantined-intent receipt fields are invalid")
        intent = _decode_exact_intent(self.intent_canonical)
        document = self._hash_document()
        if (
            intent.intent_id != self.intent_id
            or not hmac.compare_digest(
                self.intent_sha256,
                _intent_sha256(self.intent_canonical),
            )
            or not hmac.compare_digest(
                self.quarantine_sha256,
                _quarantine_sha256(document),
            )
        ):
            raise ValueError("quarantined-intent receipt bindings are invalid")

    def _hash_document(self) -> dict[str, object]:
        return {
            "schema_version": _QUARANTINE_SCHEMA_VERSION,
            "candidate_id": self.candidate_id,
            "decision_record_sha256": self.decision_record_sha256,
            "intent_id": self.intent_id,
            "intent_sha256": self.intent_sha256,
            "intent": _decode_exact_intent(self.intent_canonical),
            "status_code": self.status_code,
            "reason_code": self.reason_code,
        }


def _build_receipt(
    commit: DecisionIntentCommit,
    intent_canonical: bytes,
    plan: PreparedTemporaryEgressDenyPlanV1,
) -> PreparedPlanReceipt:
    plan_canonical = canonical_json(plan)
    intent = _decode_exact_intent(intent_canonical)
    exact_plan = _decode_exact_plan(plan_canonical)
    _require_plan_binds_intent(exact_plan, intent)
    base: dict[str, object] = {
        "schema_version": _RECEIPT_SCHEMA_VERSION,
        "candidate_id": commit.candidate_id,
        "decision_record_sha256": commit.record_sha256,
        "intent_id": intent.intent_id,
        "intent_sha256": _intent_sha256(intent_canonical),
        "intent": intent,
        "plan_id": exact_plan.plan_id,
        "plan_hash": exact_plan.plan_hash,
        "plan": exact_plan,
    }
    return PreparedPlanReceipt(
        candidate_id=commit.candidate_id,
        decision_record_sha256=commit.record_sha256,
        intent_id=intent.intent_id,
        intent_sha256=str(base["intent_sha256"]),
        intent_canonical=bytes(intent_canonical),
        plan_id=exact_plan.plan_id,
        plan_hash=exact_plan.plan_hash,
        plan_canonical=plan_canonical,
        receipt_sha256=_receipt_sha256(base),
    )


def _build_quarantine(
    commit: DecisionIntentCommit,
    intent_canonical: bytes,
    rejection: IntentDeliveryRejected,
) -> QuarantinedIntentReceipt:
    intent = _decode_exact_intent(intent_canonical)
    base: dict[str, object] = {
        "schema_version": _QUARANTINE_SCHEMA_VERSION,
        "candidate_id": commit.candidate_id,
        "decision_record_sha256": commit.record_sha256,
        "intent_id": intent.intent_id,
        "intent_sha256": _intent_sha256(intent_canonical),
        "intent": intent,
        "status_code": rejection.status_code,
        "reason_code": rejection.reason_code,
    }
    return QuarantinedIntentReceipt(
        candidate_id=commit.candidate_id,
        decision_record_sha256=commit.record_sha256,
        intent_id=intent.intent_id,
        intent_sha256=str(base["intent_sha256"]),
        intent_canonical=bytes(intent_canonical),
        status_code=rejection.status_code,
        reason_code=rejection.reason_code,
        quarantine_sha256=_quarantine_sha256(base),
    )


def _receipt_from_row(row: sqlite3.Row) -> PreparedPlanReceipt:
    try:
        values = tuple(row)
        if len(values) != 9:
            raise ValueError("receipt row width is invalid")
        return PreparedPlanReceipt(
            intent_id=values[0],
            candidate_id=values[1],
            decision_record_sha256=values[2],
            intent_sha256=values[3],
            intent_canonical=bytes(values[4]),
            plan_id=values[5],
            plan_hash=values[6],
            plan_canonical=bytes(values[7]),
            receipt_sha256=values[8],
        )
    except (IntentDeliveryFatal, TypeError, ValueError) as error:
        raise IntentDeliveryFatal("stored prepared-plan receipt is invalid") from error


def _quarantine_from_row(row: sqlite3.Row) -> QuarantinedIntentReceipt:
    try:
        values = tuple(row)
        if len(values) != 8:
            raise ValueError("quarantine row width is invalid")
        return QuarantinedIntentReceipt(
            intent_id=values[0],
            candidate_id=values[1],
            decision_record_sha256=values[2],
            intent_sha256=values[3],
            intent_canonical=bytes(values[4]),
            status_code=values[5],
            reason_code=values[6],
            quarantine_sha256=values[7],
        )
    except (IntentDeliveryFatal, TypeError, ValueError) as error:
        raise IntentDeliveryFatal(
            "stored quarantined-intent receipt is invalid"
        ) from error


def _receipt_matches(
    receipt: PreparedPlanReceipt,
    commit: DecisionIntentCommit,
    intent_canonical: bytes,
) -> bool:
    return (
        receipt.candidate_id == commit.candidate_id
        and receipt.decision_record_sha256 == commit.record_sha256
        and receipt.intent_id == commit.intent_id
        and hmac.compare_digest(
            receipt.intent_sha256,
            _intent_sha256(intent_canonical),
        )
        and hmac.compare_digest(receipt.intent_canonical, intent_canonical)
    )


def _quarantine_matches(
    quarantine: QuarantinedIntentReceipt,
    commit: DecisionIntentCommit,
    intent_canonical: bytes,
) -> bool:
    return (
        quarantine.candidate_id == commit.candidate_id
        and quarantine.decision_record_sha256 == commit.record_sha256
        and quarantine.intent_id == commit.intent_id
        and hmac.compare_digest(
            quarantine.intent_sha256,
            _intent_sha256(intent_canonical),
        )
        and hmac.compare_digest(quarantine.intent_canonical, intent_canonical)
    )


def _validate_state_path(path: Path) -> tuple[int, bool]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or Path(os.path.normpath(path)) != path
        or path.name != _DATABASE_NAME
        or "\x00" in str(path)
    ):
        raise IntentDeliveryFatal("intent-delivery database path is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if nofollow == 0 or directory == 0:
        raise IntentDeliveryFatal("intent-delivery state requires nofollow support")
    parent = path.parent
    parent_info = os.stat(parent, follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or stat.S_IMODE(parent_info.st_mode) != 0o700
    ):
        raise IntentDeliveryFatal("intent-delivery parent is not owner-only")
    parent_fd = os.open(
        parent,
        os.O_RDONLY | os.O_CLOEXEC | nofollow | directory,
    )
    created = False
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDWR | os.O_CLOEXEC | nofollow,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            descriptor = os.open(
                path.name,
                os.O_RDWR | os.O_CLOEXEC | nofollow | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            created = True
        try:
            info = os.fstat(descriptor)
            named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_dev != named.st_dev
                or info.st_ino != named.st_ino
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise IntentDeliveryFatal("intent-delivery database artifact is unsafe")
            if created:
                os.fsync(descriptor)
                os.fsync(parent_fd)
        finally:
            os.close(descriptor)
    except BaseException:
        os.close(parent_fd)
        raise
    return parent_fd, created


def _validate_marker_descriptor(descriptor: int, parent_fd: int) -> None:
    info = os.fstat(descriptor)
    named = os.stat(
        _READ_ONLY_MARKER_NAME,
        dir_fd=parent_fd,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_dev != named.st_dev
        or info.st_ino != named.st_ino
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise IntentDeliveryFatal("intent-delivery read-only marker is unsafe")


def _read_only_marker_exists(parent_fd: int) -> bool:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            _READ_ONLY_MARKER_NAME,
            os.O_RDONLY | os.O_CLOEXEC | nofollow,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return False
    except OSError as error:
        raise IntentDeliveryFatal("intent-delivery read-only marker cannot be opened") from error
    try:
        _validate_marker_descriptor(descriptor, parent_fd)
        if os.read(descriptor, len(_READ_ONLY_MARKER) + 1) != _READ_ONLY_MARKER:
            raise IntentDeliveryFatal("intent-delivery read-only marker is invalid")
    except OSError as error:
        raise IntentDeliveryFatal("intent-delivery read-only marker cannot be read") from error
    finally:
        os.close(descriptor)
    return True


def _create_read_only_marker(parent_fd: int) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            _READ_ONLY_MARKER_NAME,
            os.O_WRONLY | os.O_CLOEXEC | nofollow | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=parent_fd,
        )
    except FileExistsError:
        if not _read_only_marker_exists(parent_fd):
            raise IntentDeliveryFatal("intent-delivery read-only marker disappeared")
        return
    try:
        remaining = memoryview(_READ_ONLY_MARKER)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short read-only marker write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        _validate_marker_descriptor(descriptor, parent_fd)
        os.fsync(parent_fd)
    except OSError as error:
        raise IntentDeliveryFatal("intent-delivery read-only marker is not durable") from error
    finally:
        os.close(descriptor)


def _set_database_read_only(connection: sqlite3.Connection) -> None:
    try:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        connection.execute("BEGIN IMMEDIATE")
        updated = connection.execute("UPDATE delivery_metadata SET value='1' WHERE key='read_only'")
        if updated.rowcount != 1:
            raise IntentDeliveryFatal("intent-delivery read-only metadata is absent")
        connection.execute("COMMIT")
    except (IntentDeliveryFatal, sqlite3.Error):
        try:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise


def _durably_latch_read_only(connection: sqlite3.Connection, parent_fd: int) -> None:
    try:
        _set_database_read_only(connection)
        return
    except (IntentDeliveryFatal, sqlite3.Error) as database_error:
        try:
            _create_read_only_marker(parent_fd)
        except (IntentDeliveryFatal, OSError) as marker_error:
            marker_error.add_note(f"database latch also failed: {database_error!r}")
            raise IntentDeliveryFatal(
                "intent-delivery read-only latch is not durable"
            ) from marker_error


def _validate_exact_schema(connection: sqlite3.Connection) -> None:
    observed = tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        )
    )
    if observed != _EXACT_SCHEMA:
        raise IntentDeliveryFatal("intent-delivery schema is not exact")


def _validate_metadata(connection: sqlite3.Connection) -> dict[str, str]:
    metadata = dict(connection.execute("SELECT key,value FROM delivery_metadata"))
    if (
        set(metadata) != {"schema_version", "read_only"}
        or metadata["schema_version"] != _SCHEMA_VERSION
        or metadata["read_only"] not in {"0", "1"}
    ):
        raise IntentDeliveryFatal("intent-delivery metadata is not exact")
    return metadata


def _validate_all_outcomes(connection: sqlite3.Connection) -> None:
    for row in connection.execute(f"{_RECEIPT_SELECT} ORDER BY intent_id"):
        _receipt_from_row(row)
    for row in connection.execute(f"{_QUARANTINE_SELECT} ORDER BY intent_id"):
        _quarantine_from_row(row)
    overlap = connection.execute(
        "SELECT intent_id,candidate_id FROM prepared_plan_receipts "
        "WHERE intent_id IN (SELECT intent_id FROM terminal_intent_quarantines) "
        "OR candidate_id IN (SELECT candidate_id FROM terminal_intent_quarantines) "
        "LIMIT 1"
    ).fetchone()
    if overlap is not None:
        raise IntentDeliveryFatal("intent has multiple terminal delivery outcomes")


def _configure_database(connection: sqlite3.Connection, *, created: bool) -> None:
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA busy_timeout=0")
    connection.execute("PRAGMA foreign_keys=ON")
    if created:
        journal_mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
    else:
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    if journal_mode != "delete":
        raise IntentDeliveryFatal("intent-delivery journal mode is not DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA fullfsync=ON")
    if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
        raise IntentDeliveryFatal("intent-delivery synchronous mode is not FULL")


def _initialize_database(connection: sqlite3.Connection, parent_fd: int) -> None:
    connection.executescript(_SCHEMA)
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "INSERT INTO delivery_metadata(key,value) VALUES(?,?)",
            ("schema_version", _SCHEMA_VERSION),
        )
        connection.execute(
            "INSERT INTO delivery_metadata(key,value) VALUES(?,?)",
            ("read_only", "0"),
        )
        connection.execute("COMMIT")
        os.fsync(parent_fd)
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _open_database(path: Path) -> tuple[sqlite3.Connection, int, bool]:
    parent_fd, created = _validate_state_path(path)
    connection: sqlite3.Connection | None = None
    try:
        marker_exists = _read_only_marker_exists(parent_fd)
        if created and marker_exists:
            raise IntentDeliveryFatal("read-only marker cannot initialize a new database")
        connection = sqlite3.connect(
            path,
            isolation_level=None,
            timeout=0.0,
        )
        connection.row_factory = sqlite3.Row
        _configure_database(connection, created=created)
        if created:
            _initialize_database(connection, parent_fd)
        _validate_exact_schema(connection)
        metadata = _validate_metadata(connection)
        if connection.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok":
            raise IntentDeliveryFatal("intent-delivery database is inconsistent")
        semantic_corruption = False
        try:
            _validate_all_outcomes(connection)
        except IntentDeliveryFatal:
            semantic_corruption = True
            if not marker_exists and metadata["read_only"] != "1":
                _durably_latch_read_only(connection, parent_fd)
        marker_exists = marker_exists or _read_only_marker_exists(parent_fd)
        read_only = semantic_corruption or marker_exists or metadata["read_only"] == "1"
        if read_only:
            connection.execute("PRAGMA query_only=ON")
            if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
                raise IntentDeliveryFatal("intent-delivery connection is not read-only")
        current = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.geteuid()
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            raise IntentDeliveryFatal("intent-delivery database binding changed")
        return connection, parent_fd, read_only
    except BaseException:
        if connection is not None:
            connection.close()
        os.close(parent_fd)
        raise


@final
class IntentDeliveryStateMachine:
    """Serialize exact retries and fsync one prepared-plan receipt per intent."""

    __slots__ = (
        "_after_prepare",
        "_client",
        "_closed",
        "_connection",
        "_lock",
        "_parent_fd",
        "_read_only",
    )

    def __init__(
        self,
        connection: sqlite3.Connection,
        parent_fd: int,
        client: ActuatorIntentClient,
        after_prepare: Callable[[], None],
        read_only: bool,
        *,
        _factory: object,
    ) -> None:
        if _factory not in {_STATE_MACHINE_FACTORY, _TEST_STATE_MACHINE_FACTORY}:
            raise TypeError("use IntentDeliveryStateMachine.open()")
        if (
            type(connection) is not sqlite3.Connection
            or type(parent_fd) is not int
            or parent_fd < 0
            or type(client) is not ActuatorIntentClient
            or not callable(after_prepare)
            or type(read_only) is not bool
        ):
            raise IntentDeliveryFatal("intent-delivery authorities are invalid")
        self._connection = connection
        self._parent_fd = parent_fd
        self._client = client
        self._after_prepare = after_prepare
        self._read_only = read_only
        self._closed = False
        self._lock = asyncio.Lock()

    @classmethod
    def open(
        cls,
        path: Path,
        client: ActuatorIntentClient,
    ) -> IntentDeliveryStateMachine:
        connection, parent_fd, read_only = _open_database(path)
        try:
            return cls(
                connection,
                parent_fd,
                client,
                lambda: None,
                read_only,
                _factory=_STATE_MACHINE_FACTORY,
            )
        except BaseException:
            connection.close()
            os.close(parent_fd)
            raise

    @property
    def read_only(self) -> bool:
        return self._read_only or self._closed

    def _existing_outcome(
        self,
        intent_id: str,
        candidate_id: str,
    ) -> PreparedPlanReceipt | QuarantinedIntentReceipt | None:
        receipt_rows = self._connection.execute(
            "SELECT intent_id,candidate_id,decision_record_sha256,intent_sha256,"
            "intent_canonical,plan_id,plan_hash,plan_canonical,receipt_sha256 "
            "FROM prepared_plan_receipts "
            "WHERE intent_id=? OR candidate_id=? LIMIT 2",
            (intent_id, candidate_id),
        ).fetchall()
        quarantine_rows = self._connection.execute(
            f"{_QUARANTINE_SELECT} "
            "WHERE intent_id=? OR candidate_id=? LIMIT 2",
            (intent_id, candidate_id),
        ).fetchall()
        if len(receipt_rows) + len(quarantine_rows) > 1:
            raise IntentDeliveryFatal("intent has multiple terminal delivery outcomes")
        if receipt_rows:
            return _receipt_from_row(receipt_rows[0])
        if quarantine_rows:
            return _quarantine_from_row(quarantine_rows[0])
        return None

    def _latch_read_only(self) -> None:
        self._read_only = True
        try:
            _durably_latch_read_only(self._connection, self._parent_fd)
        finally:
            try:
                self._connection.execute("PRAGMA query_only=ON")
            except sqlite3.Error:
                pass

    def _require_matching_outcome(
        self,
        outcome: PreparedPlanReceipt | QuarantinedIntentReceipt,
        commit: DecisionIntentCommit,
        intent_canonical: bytes,
    ) -> PreparedTemporaryEgressDenyPlanV1 | QuarantinedIntentReceipt:
        if type(outcome) is PreparedPlanReceipt and _receipt_matches(
            outcome,
            commit,
            intent_canonical,
        ):
            return outcome.plan()
        if type(outcome) is QuarantinedIntentReceipt and _quarantine_matches(
            outcome,
            commit,
            intent_canonical,
        ):
            return outcome
        self._latch_read_only()
        raise IntentDeliveryFatal(
            "stored outcome conflicts with the durable decision intent"
        )

    def _persist(
        self,
        outcome: PreparedPlanReceipt | QuarantinedIntentReceipt,
        commit: DecisionIntentCommit,
        intent_canonical: bytes,
    ) -> PreparedTemporaryEgressDenyPlanV1 | QuarantinedIntentReceipt:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            existing = self._existing_outcome(
                outcome.intent_id,
                outcome.candidate_id,
            )
            if existing is not None:
                result = self._require_matching_outcome(
                    existing,
                    commit,
                    intent_canonical,
                )
                self._connection.execute("COMMIT")
                return result
            if type(outcome) is PreparedPlanReceipt:
                self._connection.execute(
                    "INSERT INTO prepared_plan_receipts("
                    "intent_id,candidate_id,decision_record_sha256,intent_sha256,"
                    "intent_canonical,plan_id,plan_hash,plan_canonical,receipt_sha256"
                    ") VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        outcome.intent_id,
                        outcome.candidate_id,
                        outcome.decision_record_sha256,
                        outcome.intent_sha256,
                        outcome.intent_canonical,
                        outcome.plan_id,
                        outcome.plan_hash,
                        outcome.plan_canonical,
                        outcome.receipt_sha256,
                    ),
                )
            elif type(outcome) is QuarantinedIntentReceipt:
                self._connection.execute(
                    "INSERT INTO terminal_intent_quarantines("
                    "intent_id,candidate_id,decision_record_sha256,intent_sha256,"
                    "intent_canonical,status_code,reason_code,quarantine_sha256"
                    ") VALUES(?,?,?,?,?,?,?,?)",
                    (
                        outcome.intent_id,
                        outcome.candidate_id,
                        outcome.decision_record_sha256,
                        outcome.intent_sha256,
                        outcome.intent_canonical,
                        outcome.status_code,
                        outcome.reason_code,
                        outcome.quarantine_sha256,
                    ),
                )
            else:
                raise IntentDeliveryFatal("delivery outcome has an inexact type")
            self._connection.execute("COMMIT")
            os.fsync(self._parent_fd)
            if type(outcome) is PreparedPlanReceipt:
                return outcome.plan()
            return cast(QuarantinedIntentReceipt, outcome)
        except IntentDeliveryFatal:
            if not self._read_only:
                self._latch_read_only()
            raise
        except (OSError, sqlite3.Error) as error:
            self._latch_read_only()
            raise IntentDeliveryFatal("delivery outcome durability is uncertain") from error

    async def deliver(
        self,
        commit: object,
    ) -> PreparedTemporaryEgressDenyPlanV1 | QuarantinedIntentReceipt:
        async with self._lock:
            if self._closed:
                raise IntentDeliveryFatal("intent-delivery state machine is closed")
            if self._read_only:
                raise IntentDeliveryFatal("intent-delivery state is read-only")
            exact_commit, intent_canonical = _validated_commit(commit)
            try:
                existing = self._existing_outcome(
                    exact_commit.intent_id or "",
                    exact_commit.candidate_id,
                )
            except (IntentDeliveryFatal, sqlite3.Error) as error:
                self._latch_read_only()
                raise IntentDeliveryFatal("delivery outcome lookup failed") from error
            if existing is not None:
                return self._require_matching_outcome(
                    existing,
                    exact_commit,
                    intent_canonical,
                )
            try:
                plan = await self._client.prepare(intent_canonical)
            except IntentDeliveryRejected as rejection:
                outcome: PreparedPlanReceipt | QuarantinedIntentReceipt = (
                    _build_quarantine(
                        exact_commit,
                        intent_canonical,
                        rejection,
                    )
                )
            else:
                outcome = _build_receipt(exact_commit, intent_canonical, plan)
            self._after_prepare()
            return self._persist(outcome, exact_commit, intent_canonical)

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            primary: BaseException | None = None
            try:
                self._connection.close()
            except BaseException as error:  # noqa: BLE001 - close both resources
                primary = error
            try:
                os.close(self._parent_fd)
            except BaseException as error:  # noqa: BLE001 - preserve first failure
                if primary is None:
                    primary = error
                else:
                    primary.add_note("secondary intent-delivery parent close failure")
            if primary is not None:
                raise IntentDeliveryFatal("intent-delivery state close failed") from primary


def _intent_delivery_state_machine_for_test(
    path: Path,
    client: ActuatorIntentClient,
    *,
    after_prepare: Callable[[], None] | None = None,
) -> IntentDeliveryStateMachine:
    connection, parent_fd, read_only = _open_database(path)
    try:
        return IntentDeliveryStateMachine(
            connection,
            parent_fd,
            client,
            (lambda: None) if after_prepare is None else after_prepare,
            read_only,
            _factory=_TEST_STATE_MACHINE_FACTORY,
        )
    except BaseException:
        connection.close()
        os.close(parent_fd)
        raise


__all__ = [
    "IntentDeliveryStateMachine",
    "PreparedPlanReceipt",
    "QuarantinedIntentReceipt",
]
