"""Bounded durable observations produced by the non-authoritative Hunter."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import final

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import HunterOutputV1, decode_strict

from .output import MAX_HUNTER_OUTPUT_BYTES, HunterResult

_DATABASE_NAME = "hunter-investigations.sqlite3"
_SCHEMA_VERSION = "agmind.hunter-investigation-state.v1"
_RECORD_SCHEMA_VERSION = "agmind.hunter-investigation.v1"
_RECORD_HASH_DOMAIN = b"AGMIND_HUNTER_INVESTIGATION_V1\0"
_CANDIDATE_ID = re.compile(r"^cand_[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_STATUSES = frozenset({"available", "unavailable", "invalid", "expired", "queue_full"})
_PAGE_SIZE = 4_096
_MAX_PAGES = 16_384
_MAX_RECORDS = 65_536
_MAX_PAGE_RESULTS = 100

_METADATA_SCHEMA = """
CREATE TABLE hunter_investigation_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT, WITHOUT ROWID
""".strip()
_INVESTIGATIONS_SCHEMA = """
CREATE TABLE hunter_investigations (
    candidate_id TEXT PRIMARY KEY,
    bundle_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    output_canonical BLOB,
    record_sha256 TEXT NOT NULL UNIQUE
) STRICT, WITHOUT ROWID
""".strip()
_SCHEMA = f"{_METADATA_SCHEMA};\n{_INVESTIGATIONS_SCHEMA};"
_EXACT_SCHEMA = (
    (
        "table",
        "hunter_investigation_metadata",
        "hunter_investigation_metadata",
        _METADATA_SCHEMA,
    ),
    (
        "table",
        "hunter_investigations",
        "hunter_investigations",
        _INVESTIGATIONS_SCHEMA,
    ),
)
_RECORD_SELECT = (
    "SELECT candidate_id,bundle_sha256,status,reason_code,"
    "output_canonical,record_sha256 FROM hunter_investigations"
)


class HunterInvestigationStoreError(RuntimeError):
    """Hunter persistence failed outside containment authority."""


class HunterInvestigationEquivocation(HunterInvestigationStoreError):
    """One candidate was assigned two different terminal Hunter results."""


def _decode_output(raw: bytes) -> HunterOutputV1:
    try:
        output = decode_strict(raw, HunterOutputV1, MAX_HUNTER_OUTPUT_BYTES)
    except (TypeError, ValueError) as error:
        raise ValueError("stored Hunter output is not one strict object") from error
    if type(output) is not HunterOutputV1 or canonical_json(output) != raw:
        raise ValueError("stored Hunter output is not canonical")
    return output


def _record_hash(
    candidate_id: str,
    bundle_sha256: str,
    status: str,
    reason_code: str,
    output_canonical: bytes | None,
) -> str:
    output = None if output_canonical is None else _decode_output(output_canonical)
    document = {
        "schema_version": _RECORD_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "bundle_sha256": bundle_sha256,
        "status": status,
        "reason_code": reason_code,
        "output": output,
    }
    return hashlib.sha256(_RECORD_HASH_DOMAIN + canonical_json(document)).hexdigest()


@dataclass(frozen=True, slots=True)
class HunterInvestigationRecord:
    """Detached, hash-bound terminal result safe for later read-only APIs."""

    candidate_id: str
    bundle_sha256: str
    status: str
    reason_code: str
    output_canonical: bytes | None
    record_sha256: str

    def __post_init__(self) -> None:
        output_is_valid = (
            type(self.output_canonical) is bytes
            and 1 <= len(self.output_canonical) <= MAX_HUNTER_OUTPUT_BYTES
        )
        if (
            type(self.candidate_id) is not str
            or _CANDIDATE_ID.fullmatch(self.candidate_id) is None
            or type(self.bundle_sha256) is not str
            or _HEX64.fullmatch(self.bundle_sha256) is None
            or type(self.status) is not str
            or self.status not in _STATUSES
            or type(self.reason_code) is not str
            or not 1 <= len(self.reason_code) <= 64
            or not self.reason_code.isascii()
            or type(self.record_sha256) is not str
            or _HEX64.fullmatch(self.record_sha256) is None
            or (self.status == "available") != output_is_valid
            or (self.status != "available" and self.output_canonical is not None)
        ):
            raise ValueError("Hunter investigation record fields are invalid")
        expected = _record_hash(
            self.candidate_id,
            self.bundle_sha256,
            self.status,
            self.reason_code,
            self.output_canonical,
        )
        if not hmac.compare_digest(self.record_sha256, expected):
            raise ValueError("Hunter investigation record binding is invalid")

    def output(self) -> HunterOutputV1 | None:
        if self.output_canonical is None:
            return None
        return _decode_output(self.output_canonical)


def _record_from_result(candidate_id: str, result: HunterResult) -> HunterInvestigationRecord:
    if (
        type(candidate_id) is not str
        or _CANDIDATE_ID.fullmatch(candidate_id) is None
        or type(result) is not HunterResult
    ):
        raise HunterInvestigationStoreError("Hunter investigation identity is invalid")
    try:
        output_canonical = None
        if result.output is not None:
            output_canonical = canonical_json(result.output)
            _decode_output(output_canonical)
        return HunterInvestigationRecord(
            candidate_id=candidate_id,
            bundle_sha256=result.bundle_sha256,
            status=result.status,
            reason_code=result.reason_code,
            output_canonical=output_canonical,
            record_sha256=_record_hash(
                candidate_id,
                result.bundle_sha256,
                result.status,
                result.reason_code,
                output_canonical,
            ),
        )
    except (TypeError, ValueError) as error:
        raise HunterInvestigationStoreError("Hunter terminal result is invalid") from error


def _record_from_row(row: sqlite3.Row) -> HunterInvestigationRecord:
    try:
        values = tuple(row)
        if len(values) != 6:
            raise ValueError("Hunter investigation row width is invalid")
        output = values[4]
        if output is not None and type(output) is not bytes:
            raise ValueError("Hunter investigation output storage class is invalid")
        return HunterInvestigationRecord(
            candidate_id=values[0],
            bundle_sha256=values[1],
            status=values[2],
            reason_code=values[3],
            output_canonical=output,
            record_sha256=values[5],
        )
    except (TypeError, ValueError) as error:
        raise HunterInvestigationStoreError("stored Hunter investigation is invalid") from error


def _validate_path(path: Path) -> tuple[int, bool]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or Path(os.path.normpath(path)) != path
        or path.name != _DATABASE_NAME
        or "\x00" in str(path)
    ):
        raise HunterInvestigationStoreError("Hunter investigation database path is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if nofollow == 0 or directory == 0:
        raise HunterInvestigationStoreError("Hunter persistence requires nofollow support")
    try:
        parent_info = os.stat(path.parent, follow_symlinks=False)
    except OSError as error:
        raise HunterInvestigationStoreError("Hunter state parent is unavailable") from error
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or stat.S_IMODE(parent_info.st_mode) != 0o700
    ):
        raise HunterInvestigationStoreError("Hunter state parent is not owner-only")
    parent_fd = os.open(
        path.parent,
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
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise HunterInvestigationStoreError(
                    "Hunter investigation database artifact is unsafe"
                )
            if created:
                os.fsync(descriptor)
                os.fsync(parent_fd)
        finally:
            os.close(descriptor)
        return parent_fd, created
    except BaseException:
        os.close(parent_fd)
        raise


def _configure_database(connection: sqlite3.Connection, *, created: bool) -> None:
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA busy_timeout=0")
    connection.execute("PRAGMA foreign_keys=ON")
    if created:
        connection.execute(f"PRAGMA page_size={_PAGE_SIZE}")
        journal_mode = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0])
    else:
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
    if journal_mode.lower() != "delete":
        raise HunterInvestigationStoreError("Hunter journal mode is not DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA fullfsync=ON")
    if (
        int(connection.execute("PRAGMA page_size").fetchone()[0]) != _PAGE_SIZE
        or int(connection.execute(f"PRAGMA max_page_count={_MAX_PAGES}").fetchone()[0])
        != _MAX_PAGES
        or int(connection.execute("PRAGMA synchronous").fetchone()[0]) != 2
    ):
        raise HunterInvestigationStoreError("Hunter database bounds are not exact")


def _initialize_database(connection: sqlite3.Connection, parent_fd: int) -> None:
    connection.executescript(_SCHEMA)
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "INSERT INTO hunter_investigation_metadata(key,value) VALUES(?,?)",
            ("schema_version", _SCHEMA_VERSION),
        )
        connection.execute("COMMIT")
        os.fsync(parent_fd)
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _validate_database(connection: sqlite3.Connection) -> None:
    observed_schema = tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        )
    )
    if observed_schema != _EXACT_SCHEMA:
        raise HunterInvestigationStoreError("Hunter investigation schema is not exact")
    metadata = dict(connection.execute("SELECT key,value FROM hunter_investigation_metadata"))
    if metadata != {"schema_version": _SCHEMA_VERSION}:
        raise HunterInvestigationStoreError("Hunter investigation metadata is not exact")
    if connection.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok":
        raise HunterInvestigationStoreError("Hunter investigation database is inconsistent")
    count = int(connection.execute("SELECT count(*) FROM hunter_investigations").fetchone()[0])
    if count > _MAX_RECORDS:
        raise HunterInvestigationStoreError("Hunter investigation record bound is exceeded")
    for row in connection.execute(f"{_RECORD_SELECT} ORDER BY candidate_id"):
        _record_from_row(row)


def _open_database(path: Path) -> tuple[sqlite3.Connection, int]:
    try:
        parent_fd, created = _validate_path(path)
    except HunterInvestigationStoreError:
        raise
    except OSError as error:
        raise HunterInvestigationStoreError("Hunter database path cannot be opened") from error
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, isolation_level=None, timeout=0.0)
        connection.row_factory = sqlite3.Row
        _configure_database(connection, created=created)
        if created:
            _initialize_database(connection, parent_fd)
        _validate_database(connection)
        current = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.geteuid()
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            raise HunterInvestigationStoreError("Hunter database binding changed")
        return connection, parent_fd
    except HunterInvestigationStoreError:
        if connection is not None:
            connection.close()
        os.close(parent_fd)
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as error:
        if connection is not None:
            connection.close()
        os.close(parent_fd)
        raise HunterInvestigationStoreError("Hunter database cannot be opened") from error


def _rollback(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        return
    try:
        connection.execute("ROLLBACK")
    except sqlite3.Error:
        pass


@final
class HunterInvestigationStore:
    """Persist one immutable terminal enrichment result per candidate."""

    __slots__ = ("_closed", "_connection", "_parent_fd")

    def __init__(
        self,
        connection: sqlite3.Connection,
        parent_fd: int,
        *,
        _factory: object,
    ) -> None:
        if (
            _factory is not _STORE_FACTORY
            or type(connection) is not sqlite3.Connection
            or type(parent_fd) is not int
            or parent_fd < 0
        ):
            raise TypeError("use HunterInvestigationStore.open()")
        self._connection = connection
        self._parent_fd = parent_fd
        self._closed = False

    @classmethod
    def open(cls, path: Path) -> HunterInvestigationStore:
        connection, parent_fd = _open_database(path)
        try:
            return cls(connection, parent_fd, _factory=_STORE_FACTORY)
        except BaseException:
            connection.close()
            os.close(parent_fd)
            raise

    def _require_open(self) -> None:
        if self._closed:
            raise HunterInvestigationStoreError("Hunter investigation store is closed")

    def get(self, candidate_id: str) -> HunterInvestigationRecord | None:
        self._require_open()
        if type(candidate_id) is not str or _CANDIDATE_ID.fullmatch(candidate_id) is None:
            raise HunterInvestigationStoreError("Hunter candidate ID is invalid")
        try:
            row = self._connection.execute(
                f"{_RECORD_SELECT} WHERE candidate_id=?",
                (candidate_id,),
            ).fetchone()
        except sqlite3.Error as error:
            raise HunterInvestigationStoreError("Hunter investigation lookup failed") from error
        return None if row is None else _record_from_row(row)

    def page(
        self,
        *,
        after: str | None,
        limit: int,
    ) -> tuple[HunterInvestigationRecord, ...]:
        self._require_open()
        if (
            (
                after is not None
                and (type(after) is not str or _CANDIDATE_ID.fullmatch(after) is None)
            )
            or type(limit) is not int
            or not 1 <= limit <= _MAX_PAGE_RESULTS
        ):
            raise HunterInvestigationStoreError("Hunter investigation page is invalid")
        try:
            if after is None:
                rows = self._connection.execute(
                    f"{_RECORD_SELECT} ORDER BY candidate_id LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = self._connection.execute(
                    f"{_RECORD_SELECT} WHERE candidate_id>? ORDER BY candidate_id LIMIT ?",
                    (after, limit),
                ).fetchall()
        except sqlite3.Error as error:
            raise HunterInvestigationStoreError("Hunter investigation page failed") from error
        return tuple(_record_from_row(row) for row in rows)

    def persist(
        self,
        candidate_id: str,
        result: HunterResult,
    ) -> HunterInvestigationRecord:
        self._require_open()
        record = _record_from_result(candidate_id, result)
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._connection.execute(
                f"{_RECORD_SELECT} WHERE candidate_id=?",
                (record.candidate_id,),
            ).fetchone()
            if row is not None:
                existing = _record_from_row(row)
                if existing != record:
                    raise HunterInvestigationEquivocation(
                        "Hunter candidate has a different durable terminal result"
                    )
                self._connection.execute("COMMIT")
                return existing
            count = int(
                self._connection.execute("SELECT count(*) FROM hunter_investigations").fetchone()[0]
            )
            if count >= _MAX_RECORDS:
                raise HunterInvestigationStoreError("Hunter investigation store is full")
            self._connection.execute(
                "INSERT INTO hunter_investigations("
                "candidate_id,bundle_sha256,status,reason_code,output_canonical,record_sha256"
                ") VALUES(?,?,?,?,?,?)",
                (
                    record.candidate_id,
                    record.bundle_sha256,
                    record.status,
                    record.reason_code,
                    record.output_canonical,
                    record.record_sha256,
                ),
            )
            self._connection.execute("COMMIT")
            os.fsync(self._parent_fd)
            return record
        except HunterInvestigationEquivocation:
            _rollback(self._connection)
            raise
        except HunterInvestigationStoreError:
            _rollback(self._connection)
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as error:
            _rollback(self._connection)
            raise HunterInvestigationStoreError(
                "Hunter investigation durability is uncertain"
            ) from error

    def close(self) -> None:
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
        except BaseException as error:  # noqa: BLE001 - preserve first close failure
            if primary is None:
                primary = error
            else:
                primary.add_note("secondary Hunter state parent close failure")
        if primary is not None:
            raise HunterInvestigationStoreError("Hunter investigation close failed") from primary


_STORE_FACTORY = object()


__all__ = [
    "HunterInvestigationEquivocation",
    "HunterInvestigationRecord",
    "HunterInvestigationStore",
    "HunterInvestigationStoreError",
]
