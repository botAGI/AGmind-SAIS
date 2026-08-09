"""Durable append-only Core mirror of the actuator's verified mixed journal."""

from __future__ import annotations

import asyncio
import fcntl
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import final

from agmind_immune.contracts import ActionRecordV1
from agmind_immune.evidence.frames import JournalCorrupt, decode_frames

from .actuator_protocol import (
    ActuatorJournalClient,
    ActuatorJournalConflict,
    ActuatorJournalFatal,
    ActuatorJournalRetryable,
    ActuatorJournalSnapshot,
    VerifiedActuatorJournalExtension,
    VerifiedActuatorJournalRecord,
)
from .actuator_records import ActuatorRecordError, ActuatorRecordProjection, MirroredIntentState

ACTUATOR_MIRROR_PATH = Path("/var/lib/agmind-sais/core/actuator-actions.agf")
ACTUATOR_PUBLIC_KEY_PATH = Path("/etc/agmind-sais/public/actuator-ed25519.pub")
_MAX_FRAME_PAYLOAD = 65_536
_MAX_MIRROR_BYTES = 64 * 1024 * 1024
_MAX_MIRROR_RECORDS = 65_536
_INTENT_ID = re.compile(r"^int_[0-9a-f]{32}$")
_ACTION_ID = re.compile(r"^act_[0-9a-f]{32}$")
_TEST_FACTORY = object()


class ActuatorMirrorError(RuntimeError):
    """Base class for local actuator-mirror failures."""


class ActuatorMirrorFatal(ActuatorMirrorError):
    """The mutation path must remain read-only until operator recovery."""


class ActuatorMirrorConflict(ActuatorMirrorFatal):
    """The actuator snapshot does not extend the already durable prefix."""


class ActuatorMirrorBusy(ActuatorMirrorFatal):
    """Another Core process exclusively owns the mirror."""


@dataclass(frozen=True, slots=True)
class ActuatorMirrorSnapshot:
    record_count: int
    verified_bytes: int
    head_sha256: str
    records: tuple[VerifiedActuatorJournalRecord, ...]
    intents: tuple[MirroredIntentState, ...]
    action_records: tuple[ActionRecordV1, ...]


def _read_actuator_public_key(path: Path = ACTUATOR_PUBLIC_KEY_PATH) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if path != ACTUATOR_PUBLIC_KEY_PATH or nofollow == 0:
        raise ActuatorMirrorFatal("actuator public-key path is not the fixed safe path")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size != 32
        ):
            raise ActuatorMirrorFatal("actuator public key is not protected raw Ed25519")
        public_key = os.read(descriptor, 33)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        if (
            len(public_key) != 32
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise ActuatorMirrorFatal("actuator public key changed while loading")
        return public_key
    except ActuatorMirrorError:
        raise
    except OSError as error:
        raise ActuatorMirrorFatal("actuator public key is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _safe_parent(path: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        nofollow == 0
        or directory == 0
        or not isinstance(path, Path)
        or not path.is_absolute()
        or Path(os.path.normpath(path)) != path
        or "\x00" in str(path)
    ):
        raise ActuatorMirrorFatal("actuator mirror path is unsafe")
    try:
        descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_CLOEXEC | nofollow | directory,
        )
    except OSError as error:
        raise ActuatorMirrorFatal("actuator mirror parent is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        named = os.stat(path.parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise ActuatorMirrorFatal("actuator mirror parent is not owner-only")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_mirror_file(parent_fd: int, name: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDWR | os.O_APPEND | os.O_CLOEXEC | nofollow
    created = False
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            descriptor = os.open(
                name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise ActuatorMirrorFatal("actuator mirror file is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not 0 <= opened.st_size <= _MAX_MIRROR_BYTES
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise ActuatorMirrorFatal("actuator mirror file is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ActuatorMirrorBusy("actuator mirror is already locked") from error
        if created:
            os.fsync(descriptor)
            os.fsync(parent_fd)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _full_read(descriptor: int) -> bytes:
    info = os.fstat(descriptor)
    if not 0 <= info.st_size <= _MAX_MIRROR_BYTES:
        raise ActuatorMirrorFatal("actuator mirror exceeds its byte bound")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = info.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1024 * 1024))
        if not chunk:
            raise ActuatorMirrorFatal("actuator mirror was truncated while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    after = os.fstat(descriptor)
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ActuatorMirrorFatal("actuator mirror changed while replaying")
    return raw


def _snapshot_from_local(
    descriptor: int,
    public_key: bytes,
) -> tuple[ActuatorMirrorSnapshot, ActuatorRecordProjection]:
    raw = _full_read(descriptor)
    try:
        decoded = decode_frames(raw, max_frame=_MAX_FRAME_PAYLOAD)
    except (JournalCorrupt, ValueError) as error:
        raise ActuatorMirrorFatal("actuator mirror AGF1 chain is corrupt") from error
    if len(decoded.records) > _MAX_MIRROR_RECORDS:
        raise ActuatorMirrorFatal("actuator mirror exceeds its record bound")
    if decoded.torn_tail:
        try:
            os.ftruncate(descriptor, decoded.verified_bytes)
            os.fsync(descriptor)
        except OSError as error:
            raise ActuatorMirrorFatal("actuator mirror torn-tail repair is uncertain") from error
        raw = raw[: decoded.verified_bytes]
    projection = ActuatorRecordProjection(public_key)
    records: list[VerifiedActuatorJournalRecord] = []
    try:
        for index, frame_record in enumerate(decoded.records, start=1):
            inner = projection.append(frame_record.payload)
            frame = raw[frame_record.offset : frame_record.offset + frame_record.size]
            records.append(
                VerifiedActuatorJournalRecord(
                    index,
                    frame_record.offset,
                    frame_record.size,
                    len(frame_record.payload),
                    frame_record.previous_hash.hex(),
                    frame_record.record_hash.hex(),
                    frame_record.payload,
                    frame,
                    inner,
                )
            )
    except ActuatorRecordError as error:
        raise ActuatorMirrorFatal("actuator mirror signed payload chain is corrupt") from error
    verified_bytes = decoded.verified_bytes
    head = records[-1].frame_sha256 if records else "0" * 64
    return (
        ActuatorMirrorSnapshot(
            len(records),
            verified_bytes,
            head,
            tuple(records),
            projection.intents(),
            projection.action_records(),
        ),
        projection,
    )


def _write_all(descriptor: int, value: bytes) -> None:
    written = 0
    while written < len(value):
        count = os.write(descriptor, value[written:])
        if count <= 0:
            raise OSError("short actuator mirror write")
        written += count


@final
class ActuatorMirror:
    """Exclusive durable mirror that accepts only exact remote prefix extension."""

    __slots__ = (
        "_client",
        "_closed",
        "_descriptor",
        "_fatal_error",
        "_lock",
        "_name",
        "_parent_descriptor",
        "_projection",
        "_public_key",
        "_read_only",
        "_snapshot",
    )

    _client: ActuatorJournalClient
    _closed: bool
    _descriptor: int
    _fatal_error: str | None
    _lock: asyncio.Lock
    _name: str
    _parent_descriptor: int
    _projection: ActuatorRecordProjection
    _public_key: bytes
    _read_only: bool
    _snapshot: ActuatorMirrorSnapshot

    def __init__(self) -> None:
        raise TypeError("use ActuatorMirror.open()")

    @classmethod
    def open(cls, client: ActuatorJournalClient) -> ActuatorMirror:
        return cls._open(
            ACTUATOR_MIRROR_PATH,
            _read_actuator_public_key(),
            client,
            factory=None,
        )

    @classmethod
    def _open(
        cls,
        path: Path,
        public_key: bytes,
        client: ActuatorJournalClient,
        *,
        factory: object | None,
    ) -> ActuatorMirror:
        if (
            type(client) is not ActuatorJournalClient
            or type(public_key) is not bytes
            or len(public_key) != 32
            or (factory is None and path != ACTUATOR_MIRROR_PATH)
            or (factory is not None and factory is not _TEST_FACTORY)
        ):
            raise ActuatorMirrorFatal("actuator mirror inputs are invalid")
        mirror = object.__new__(cls)
        mirror._client = client
        mirror._public_key = public_key
        mirror._parent_descriptor = -1
        mirror._descriptor = -1
        mirror._name = path.name
        mirror._read_only = False
        mirror._fatal_error = None
        mirror._closed = False
        mirror._lock = asyncio.Lock()
        try:
            mirror._parent_descriptor = _safe_parent(path)
            mirror._descriptor = _open_mirror_file(
                mirror._parent_descriptor,
                mirror._name,
            )
            mirror._snapshot, mirror._projection = _snapshot_from_local(
                mirror._descriptor,
                mirror._public_key,
            )
            return mirror
        except BaseException:
            mirror._close_descriptors()
            raise

    @property
    def read_only(self) -> bool:
        return self._read_only or self._closed

    @property
    def fatal_error(self) -> str | None:
        return self._fatal_error

    def snapshot(self) -> ActuatorMirrorSnapshot:
        return self._snapshot

    def latest_for_intent(self, intent_id: str) -> MirroredIntentState | None:
        if type(intent_id) is not str or _INTENT_ID.fullmatch(intent_id) is None:
            raise ValueError("intent ID is invalid")
        return next(
            (state for state in self._snapshot.intents if state.intent_id == intent_id),
            None,
        )

    def action_records(self, *, after: int = 0, limit: int = 100) -> tuple[ActionRecordV1, ...]:
        records = self._snapshot.action_records
        if (
            type(after) is not int
            or type(limit) is not int
            or not 0 <= after <= len(records)
            or not 1 <= limit <= 100
        ):
            raise ValueError("action record page is invalid")
        return records[after : after + limit]

    def latest_for_action(self, action_id_value: str) -> ActionRecordV1 | None:
        if type(action_id_value) is not str or _ACTION_ID.fullmatch(action_id_value) is None:
            raise ValueError("action ID is invalid")
        return next(
            (
                record
                for record in reversed(self._snapshot.action_records)
                if record.action_id == action_id_value
            ),
            None,
        )

    def _latch_fatal(self, message: str) -> None:
        self._read_only = True
        if self._fatal_error is None:
            self._fatal_error = message

    def _prefix_conflict(self) -> ActuatorMirrorConflict:
        message = "actuator journal prefix conflicts with durable mirror"
        self._latch_fatal(message)
        return ActuatorMirrorConflict(message)

    def _binding_is_current(self, expected_size: int) -> bool:
        try:
            opened = os.fstat(self._descriptor)
            named = os.stat(
                self._name,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            return False
        return (
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and opened.st_uid == os.geteuid()
            and stat.S_IMODE(opened.st_mode) == 0o600
            and opened.st_size == expected_size
            and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)
        )

    async def sync_once(self, *, page_limit: int = 100) -> ActuatorMirrorSnapshot:
        async with self._lock:
            if self._closed:
                raise ActuatorMirrorFatal("actuator mirror is closed")
            if self._read_only:
                raise ActuatorMirrorFatal(self._fatal_error or "actuator mirror is read-only")
            local = self._snapshot
            transaction = self._projection.begin_extension()
            try:
                remote = await self._client.fetch_verified_extension(
                    self._projection,
                    ActuatorJournalSnapshot(
                        local.record_count,
                        local.verified_bytes,
                        local.head_sha256,
                    ),
                    local_first=local.records[0] if local.records else None,
                    local_last=local.records[-1] if local.records else None,
                    page_limit=page_limit,
                )
            except asyncio.CancelledError:
                self._projection.rollback_extension(transaction)
                raise
            except ActuatorJournalRetryable:
                self._projection.rollback_extension(transaction)
                raise
            except ActuatorJournalConflict as error:
                self._projection.rollback_extension(transaction)
                raise self._prefix_conflict() from error
            except ActuatorJournalFatal as error:
                self._projection.rollback_extension(transaction)
                self._latch_fatal("actuator journal verification failed")
                raise ActuatorMirrorFatal("actuator journal verification failed") from error
            except BaseException as error:
                self._projection.rollback_extension(transaction)
                self._latch_fatal("actuator journal sync failed outside its contract")
                raise ActuatorMirrorFatal(
                    "actuator journal sync failed outside its contract"
                ) from error
            if remote.snapshot.record_count != local.record_count + len(remote.records):
                self._projection.rollback_extension(transaction)
                self._latch_fatal("actuator extension count is inconsistent")
                raise ActuatorMirrorFatal("actuator extension count is inconsistent")
            if not remote.records:
                self._projection.commit_extension(transaction)
                return local
            if not self._binding_is_current(local.verified_bytes):
                self._projection.rollback_extension(transaction)
                self._latch_fatal("actuator mirror file binding changed")
                raise ActuatorMirrorFatal("actuator mirror file binding changed")
            try:
                os.lseek(self._descriptor, 0, os.SEEK_END)
                for record in remote.records:
                    _write_all(self._descriptor, record.frame)
                os.fsync(self._descriptor)
            except OSError as error:
                self._projection.rollback_extension(transaction)
                self._latch_fatal("actuator mirror durability is uncertain")
                raise ActuatorMirrorFatal("actuator mirror durability is uncertain") from error
            if not self._binding_is_current(remote.snapshot.verified_bytes):
                self._projection.rollback_extension(transaction)
                self._latch_fatal("actuator mirror durable size or binding is invalid")
                raise ActuatorMirrorFatal("actuator mirror durable size or binding is invalid")
            self._projection.commit_extension(transaction)
            self._snapshot = _mirror_snapshot(local, remote)
            return self._snapshot

    def _close_descriptors(self) -> None:
        if self._descriptor >= 0:
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self._descriptor)
            except OSError:
                pass
            self._descriptor = -1
        if self._parent_descriptor >= 0:
            try:
                os.close(self._parent_descriptor)
            except OSError:
                pass
            self._parent_descriptor = -1

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._close_descriptors()


def _mirror_snapshot(
    local: ActuatorMirrorSnapshot,
    remote: VerifiedActuatorJournalExtension,
) -> ActuatorMirrorSnapshot:
    return ActuatorMirrorSnapshot(
        remote.snapshot.record_count,
        remote.snapshot.verified_bytes,
        remote.snapshot.head_sha256,
        local.records + remote.records,
        remote.intents,
        remote.action_records,
    )


def _actuator_mirror_for_test(
    path: Path,
    public_key: bytes,
    client: ActuatorJournalClient,
) -> ActuatorMirror:
    return ActuatorMirror._open(
        path,
        public_key,
        client,
        factory=_TEST_FACTORY,
    )


__all__ = [
    "ACTUATOR_MIRROR_PATH",
    "ACTUATOR_PUBLIC_KEY_PATH",
    "ActuatorMirror",
    "ActuatorMirrorBusy",
    "ActuatorMirrorConflict",
    "ActuatorMirrorError",
    "ActuatorMirrorFatal",
    "ActuatorMirrorSnapshot",
]
