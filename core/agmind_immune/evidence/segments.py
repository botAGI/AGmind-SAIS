"""Authoritative single-host AGF1 evidence segments and immutable manifest chain."""

from __future__ import annotations

import copy
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import time
import uuid
from bisect import bisect_right
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, BinaryIO, Literal, cast

from pydantic import Field, ValidationError, field_validator, model_validator

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import (
    MAX_UINT64,
    ContractModel,
    EventEnvelopeV1,
    decode_strict,
)
from agmind_immune.evidence.frames import (
    FrameRecord,
    JournalCorrupt,
    TornTail,
    encode_frame,
    iter_frames,
)
from agmind_immune.evidence.manifest import (
    GENESIS_MANIFEST_SHA256,
    SegmentChainHeadV1,
    SegmentManifestV1,
    chain_head_for,
    segment_manifest_hash,
)
from agmind_immune.ingest.envelope import (
    EnvelopeVerifier,
    IngestVerificationError,
    VerifiedEnvelope,
    VerifierCommitError,
    _AppendAuthorization,
)

MAX_EVIDENCE_RECORD_BYTES = 128 * 1024
MAX_SEGMENT_BYTES = 64 * 1024 * 1024
MAX_SEGMENT_AGE_SECONDS = 600.0
MAX_CONTRACT_FILE_BYTES = 256 * 1024
_EVENT = re.compile(r"^evt_[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OPEN_NAME = re.compile(
    r"^(?P<sequence>[0-9]{20})-(?P<segment>[0-9a-f]{8}-[0-9a-f]{4}-"
    r"4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.open$"
)
_DATE_NAME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_CREATE_TEMP_NAME = re.compile(
    r"^\.agmind-create-(?P<sequence>[0-9]{20})-"
    r"(?P<segment>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.tmp$"
)
_UUID4_TEXT = (
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_EVIDENCE_REF_SEGMENT_ID = re.compile(rf"^{_UUID4_TEXT}$")
_EVIDENCE_REF_SEGMENT_PATH = re.compile(
    rf"^segments/(?P<date>[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})/"
    rf"(?P<first_sequence>[0-9]{{20}})-(?P<segment>{_UUID4_TEXT})\.agseg$"
)
_MANIFEST_NAME = re.compile(rf"^(?P<segment>{_UUID4_TEXT})\.json$")
_MANIFEST_TEMP_NAME = re.compile(
    rf"^\.(?P<segment>{_UUID4_TEXT})\.json\.{_UUID4_TEXT}\.tmp$"
)
_ROOT_TEMP_NAME = re.compile(rf"^\.chain-head\.json\.{_UUID4_TEXT}\.tmp$")
_HEALTH_FINAL_TEMP_NAME = re.compile(
    rf"^\.health\.json\.{_UUID4_TEXT}\.tmp$"
)
_ACK_COMMITMENT_NAME = "ack-commitment.json"
_ACK_COMMITMENT_TEMP_NAME = re.compile(
    rf"^\.ack-commitment\.json\.{_UUID4_TEXT}\.tmp$"
)
_MAX_ACK_COMMITMENT_BYTES = 4096
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
_ATOMIC_RENAME_UNAVAILABLE = frozenset(
    {
        errno.EINVAL,
        errno.ENOSYS,
        errno.ENOTSUP,
        errno.EOPNOTSUPP,
    }
)


class EvidenceStoreError(RuntimeError):
    """Base class for evidence-store failures."""


class EvidenceSealError(EvidenceStoreError):
    """An unsealed caller-created value reached the evidence boundary."""


class EvidenceStoreBusy(EvidenceStoreError):
    """Another process already owns this evidence root."""


class EvidenceConflict(EvidenceStoreError):
    """One host-global sequence maps to different canonical evidence."""


class EvidenceCorrupt(EvidenceStoreError):
    """Evidence bytes, facts, or immutable chain structure are corrupt."""


class EvidenceReadOnly(EvidenceStoreError):
    """A persistent health marker prevents evidence mutation."""


class _AckAuthorityError(EvidenceStoreError):
    """An ACK identity is not the next authenticated contiguous evidence ref."""


class _AckLifecycleStateError(EvidenceStoreError):
    """The requested ACK-journal operation is illegal in this store lifecycle."""


class _AckLifecycleCorrupt(EvidenceStoreError):
    """An expected ACK-journal artifact disappeared or was substituted."""


class _AckLifecycleIoUncertain(EvidenceStoreError):
    """ACK authority I/O may have completed but could not be authenticated."""


class TornTailRepairRequired(EvidenceStoreError):
    """An active segment ends in an incomplete frame and requires signed repair."""

    def __init__(self, path: Path, verified_bytes: int, actual_bytes: int) -> None:
        super().__init__(f"torn active tail requires signed repair: {path}")
        self.path = path
        self.verified_bytes = verified_bytes
        self.actual_bytes = actual_bytes


@contextmanager
def _post_authentication_namespace(display_path: Path) -> Iterator[None]:
    try:
        yield
    except EvidenceCorrupt:
        raise
    except EvidenceStoreError:
        raise
    except OSError as error:
        raise EvidenceCorrupt(
            f"authenticated evidence namespace became uncertain: {display_path}"
        ) from error


class EvidencePriority(StrEnum):
    ROUTINE = "routine"
    PROTECTED = "protected"


@dataclass(frozen=True)
class EvidenceRef:
    segment_id: str
    segment_relative_path: str
    frame_offset: int
    frame_size: int
    frame_sha256: str
    event_id: str
    source_sequence: int
    content_sha256: str


@dataclass(frozen=True)
class EvidenceStatus:
    healthy: bool
    host_id: str | None
    evidence_head: int
    acceptance_cursor: int
    key_healthy: bool


def _exact_coverage_ref_key(
    value: object,
) -> tuple[str, str, int, int, str, str, int, str]:
    if type(value) is not EvidenceRef:
        raise ValueError("coverage evidence ref must use the exact runtime type")
    if (
        type(value.segment_id) is not str
        or _EVIDENCE_REF_SEGMENT_ID.fullmatch(value.segment_id) is None
    ):
        raise ValueError("coverage evidence ref segment_id is invalid")
    if type(value.segment_relative_path) is not str:
        raise ValueError("coverage evidence ref path is not an exact string")
    path_match = _EVIDENCE_REF_SEGMENT_PATH.fullmatch(value.segment_relative_path)
    if path_match is None or path_match.group("segment") != value.segment_id:
        raise ValueError("coverage evidence ref path is invalid")
    date_text = path_match.group("date")
    try:
        path_date = date.fromisoformat(date_text)
    except ValueError as error:
        raise ValueError("coverage evidence ref path date is invalid") from error
    if path_date.isoformat() != date_text:
        raise ValueError("coverage evidence ref path date is not canonical")
    if (
        type(value.frame_offset) is not int
        or type(value.frame_size) is not int
        or type(value.source_sequence) is not int
    ):
        raise ValueError("coverage evidence ref numeric fields are not exact integers")
    first_sequence = int(path_match.group("first_sequence"))
    if (
        not 1 <= first_sequence <= value.source_sequence <= MAX_UINT64
        or value.frame_offset < 0
        or not 76 < value.frame_size <= MAX_EVIDENCE_RECORD_BYTES + 76
        or value.frame_offset + value.frame_size > MAX_SEGMENT_BYTES
    ):
        raise ValueError("coverage evidence ref numeric bounds are invalid")
    if (
        type(value.frame_sha256) is not str
        or _HEX64.fullmatch(value.frame_sha256) is None
        or type(value.event_id) is not str
        or _EVENT.fullmatch(value.event_id) is None
        or type(value.content_sha256) is not str
        or _HEX64.fullmatch(value.content_sha256) is None
    ):
        raise ValueError("coverage evidence ref identity fields are invalid")
    return (
        value.segment_id,
        value.segment_relative_path,
        value.frame_offset,
        value.frame_size,
        value.frame_sha256,
        value.event_id,
        value.source_sequence,
        value.content_sha256,
    )


def _same_exact_coverage_ref(left: object, right: object) -> bool:
    return _exact_coverage_ref_key(left) == _exact_coverage_ref_key(right)


@dataclass(frozen=True)
class StoredEvidenceRecord:
    envelope: dict[str, Any]
    canonical_envelope: bytes
    priority: EvidencePriority
    accepted_at: str
    ref: EvidenceRef


def _exact_coverage_record_key(
    value: object,
) -> tuple[
    bytes,
    EvidencePriority,
    str,
    tuple[str, str, int, int, str, str, int, str],
]:
    if type(value) is not StoredEvidenceRecord:
        raise ValueError("coverage record must use the exact runtime type")
    if (
        type(value.envelope) is not dict
        or type(value.canonical_envelope) is not bytes
        or type(value.priority) is not EvidencePriority
        or type(value.accepted_at) is not str
    ):
        raise ValueError("coverage record fields do not use exact runtime types")
    try:
        encoded_envelope = canonical_json(value.envelope)
    except (TypeError, ValueError) as error:
        raise ValueError("coverage record envelope is not canonicalizable") from error
    if encoded_envelope != value.canonical_envelope:
        raise ValueError("coverage record envelope differs from its canonical bytes")
    return (
        value.canonical_envelope,
        value.priority,
        value.accepted_at,
        _exact_coverage_ref_key(value.ref),
    )


def _same_exact_coverage_record(left: object, right: object) -> bool:
    return _exact_coverage_record_key(left) == _exact_coverage_record_key(right)


class _AcceptedOuterV1(ContractModel):
    sequence: int = Field(ge=1, le=MAX_UINT64)
    event_id: str
    content_sha256: str

    @field_validator("event_id")
    @classmethod
    def event_is_exact(cls, value: str) -> str:
        if not _EVENT.fullmatch(value):
            raise ValueError("accepted outer event_id is invalid")
        return value

    @field_validator("content_sha256")
    @classmethod
    def digest_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("accepted outer digest is invalid")
        return value


class _AcceptedEnvelopeRecordV1(ContractModel):
    schema_version: Literal["agmind.accepted-envelope.v1"]
    evidence_priority: Literal["routine", "protected"]
    accepted_at: str
    outer: _AcceptedOuterV1
    envelope: dict[str, Any]

    @model_validator(mode="after")
    def outer_binds_envelope(self) -> _AcceptedEnvelopeRecordV1:
        canonical = canonical_json(self.envelope)
        if len(canonical) > 64 * 1024:
            raise ValueError("stored canonical envelope exceeds 64 KiB")
        try:
            envelope = EventEnvelopeV1.model_validate(self.envelope, strict=True)
        except ValidationError as error:
            raise ValueError("stored envelope contract is invalid") from error
        if (
            self.outer.sequence != envelope.source_sequence
            or self.outer.event_id != envelope.event_id
            or self.outer.content_sha256 != hashlib.sha256(canonical).hexdigest()
        ):
            raise ValueError("stored outer facts do not bind envelope")
        if not _UTC_TIMESTAMP.fullmatch(self.accepted_at):
            raise ValueError("accepted_at must be UTC")
        datetime.fromisoformat(self.accepted_at)
        return self


class _EvidenceHealthV1(ContractModel):
    schema_version: Literal["agmind.evidence-health.v1"]
    mode: Literal["read_only"]
    reason: Literal["segment_corrupt", "evidence_conflict"]


class _EvidenceHealthIntentV1(ContractModel):
    schema_version: Literal["agmind.evidence-health-intent.v1"]
    mode: Literal["read_only_pending"]
    reason: Literal["segment_corrupt", "evidence_conflict"]


class _AckCommitmentIdentityV1(ContractModel):
    sequence: int = Field(ge=1, le=MAX_UINT64)
    event_id: str
    content_sha256: str

    @field_validator("event_id")
    @classmethod
    def event_id_is_exact(cls, value: str) -> str:
        if not _EVENT.fullmatch(value):
            raise ValueError("ACK commitment event_id is invalid")
        return value

    @field_validator("content_sha256")
    @classmethod
    def content_hash_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("ACK commitment content hash is invalid")
        return value


class _AckCommitmentV1(ContractModel):
    schema_version: Literal["agmind.core-ack-commitment.v1"]
    phase: Literal["initializing", "ready"]
    generation: int = Field(ge=0, le=MAX_UINT64)
    confirmed: _AckCommitmentIdentityV1 | None
    journal_prefix_size: int = Field(ge=0, le=MAX_UINT64)
    journal_prefix_sha256: str

    @field_validator("journal_prefix_sha256")
    @classmethod
    def prefix_hash_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("ACK commitment prefix hash is invalid")
        return value

    @model_validator(mode="after")
    def state_is_coherent(self) -> _AckCommitmentV1:
        genesis = (
            self.generation == 0
            and self.confirmed is None
            and self.journal_prefix_size == 0
            and self.journal_prefix_sha256 == _EMPTY_SHA256
        )
        if self.phase == "initializing":
            if not genesis:
                raise ValueError("initializing ACK commitment must be exact genesis")
        elif not genesis and (
            self.generation == 0
            or self.confirmed is None
            or self.journal_prefix_size == 0
        ):
            raise ValueError("ready ACK commitment state is incoherent")
        return self


@dataclass(frozen=True)
class _AckCommitmentRecoveryView:
    commitment: _AckCommitmentV1 | None
    journal_present: bool
    temporary_name: str | None


@dataclass(frozen=True)
class _AckCommitmentTemporaryBinding:
    name: str
    commitment: _AckCommitmentV1
    raw: bytes
    identity: _FileIdentity


def _canonical_ack_commitment(commitment: _AckCommitmentV1) -> bytes:
    return canonical_json(commitment.model_dump(exclude_none=False))


def _decode_ack_commitment(raw: bytes) -> _AckCommitmentV1:
    if not raw or len(raw) > _MAX_ACK_COMMITMENT_BYTES:
        raise ValueError("ACK commitment exceeds its explicit byte limit")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate ACK commitment property: {key}")
            value[key] = item
        return value

    def reject_number(value: str) -> object:
        raise ValueError(f"invalid ACK commitment number: {value}")

    value = json.loads(
        raw.decode("utf-8", "strict"),
        object_pairs_hook=unique_object,
        parse_float=reject_number,
        parse_constant=reject_number,
    )
    if not isinstance(value, dict):
        raise TypeError("ACK commitment must be one JSON object")
    return _AckCommitmentV1.model_validate(value)


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    mode: int
    owner: int
    link_count: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class _SegmentScan:
    records: tuple[StoredEvidenceRecord, ...]
    frames: tuple[FrameRecord, ...]
    torn_verified: int | None
    size: int
    sha256: str
    identity: _FileIdentity


@dataclass(frozen=True)
class _Promotion:
    date_name: str
    open_name: str
    closed_name: str
    identity: _FileIdentity
    sha256: str


@dataclass(frozen=True)
class _PendingDurableCommit:
    canonical: bytes
    content_sha256: str
    event_id: str
    evidence_priority: Literal["routine", "protected"]
    host_id: str
    source_sequence: int
    ref: EvidenceRef


@dataclass(frozen=True)
class _RecoveryPlan:
    promotions: tuple[_Promotion, ...] = ()
    delete_private_temporaries: tuple[tuple[str, str], ...] = ()
    delete_manifest_temporaries: tuple[str, ...] = ()
    delete_root_temporaries: tuple[str, ...] = ()
    head_raw: bytes | None = None


@dataclass
class _ActiveSegment:
    segment_id: str
    open_path: Path
    open_name: str
    closed_name: str
    closed_relative_path: str
    directory_descriptor: int
    priority: EvidencePriority
    host_id: str
    first_source_sequence: int
    opened_at: str
    opened_monotonic: float
    descriptor: int
    size: int = 0
    record_count: int = 0
    previous_frame_hash: bytes = bytes(32)


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("evidence wall clock must be timezone-aware")
    current = value.astimezone(UTC)
    text = current.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return text.replace(".000000Z", "Z")


def _full_write(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("short evidence write")
        written += count


class _HashingReader:
    def __init__(
        self,
        stream: BinaryIO,
        *,
        maximum: int,
        expected_size: int,
    ) -> None:
        if maximum < 0 or expected_size < 0 or expected_size > maximum:
            raise ValueError("invalid bounded evidence stream size")
        self._stream = stream
        self._digest = hashlib.sha256()
        self._limit = expected_size
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self._limit - self.total
        if remaining <= 0:
            return b""
        if size < 0 or size > remaining:
            size = remaining
        raw = self._stream.read(size)
        if len(raw) > remaining:
            raise EvidenceCorrupt("bounded evidence reader exceeded its hard limit")
        self._digest.update(raw)
        self.total += len(raw)
        return raw

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _validate_directory(
    descriptor: int,
    display_path: Path,
    *,
    exact_mode: bool,
) -> os.stat_result:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or (
            exact_mode
            and (
                info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            )
        )
    ):
        raise EvidenceCorrupt(f"unsafe evidence directory: {display_path}")
    return info


def _open_root_directory(path: Path) -> int:
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise EvidenceCorrupt("evidence root must be an absolute clean path")
    descriptor = os.open("/", _directory_flags())
    try:
        for index, component in enumerate(path.parts[1:]):
            last = index == len(path.parts[1:]) - 1
            try:
                child = os.open(component, _directory_flags(), dir_fd=descriptor)
            except FileNotFoundError:
                if not last:
                    raise EvidenceCorrupt(
                        f"evidence root parent is missing: {path}"
                    ) from None
                os.mkdir(component, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(component, _directory_flags(), dir_fd=descriptor)
            except OSError as error:
                raise EvidenceCorrupt(
                    f"unsafe evidence root path component: {component}"
                ) from error
            _validate_directory(
                child,
                Path(*path.parts[: index + 2]),
                exact_mode=last,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_or_create_directory_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
) -> int:
    if "/" in name or name in {"", ".", ".."}:
        raise EvidenceCorrupt(f"unsafe evidence directory name: {name}")
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    except FileNotFoundError:
        os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    try:
        _validate_directory(descriptor, display_path, exact_mode=True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_directory_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
) -> int:
    if "/" in name or name in {"", ".", ".."}:
        raise EvidenceCorrupt(f"unsafe evidence directory name: {name}")
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    except FileNotFoundError as error:
        raise EvidenceCorrupt(f"managed evidence directory is missing: {display_path}") from error
    try:
        _validate_directory(descriptor, display_path, exact_mode=True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _entry_stat_at(parent_descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _regular_stat_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
) -> os.stat_result:
    info = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise EvidenceCorrupt(f"unsafe evidence file: {display_path}")
    return info


def _file_identity(info: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=info.st_dev,
        inode=info.st_ino,
        size=info.st_size,
        mode=info.st_mode,
        owner=info.st_uid,
        link_count=info.st_nlink,
        modified_ns=info.st_mtime_ns,
        changed_ns=info.st_ctime_ns,
    )


def _validate_identity(
    actual: os.stat_result,
    expected: _FileIdentity,
    display_path: Path,
) -> None:
    if _file_identity(actual) != expected:
        raise EvidenceCorrupt(f"evidence source identity changed: {display_path}")


def _validate_post_rename_identity(
    actual: _FileIdentity,
    authenticated: _FileIdentity,
    display_path: Path,
) -> None:
    stable_facts = (
        actual.device == authenticated.device,
        actual.inode == authenticated.inode,
        actual.size == authenticated.size,
        actual.mode == authenticated.mode,
        actual.owner == authenticated.owner,
        actual.link_count == authenticated.link_count,
        actual.modified_ns == authenticated.modified_ns,
        actual.changed_ns >= authenticated.changed_ns,
    )
    if not all(stable_facts):
        raise EvidenceCorrupt(
            f"published evidence drifted from authenticated facts: {display_path}"
        )


def _hash_held_descriptor(
    descriptor: int,
    identity: _FileIdentity,
    display_path: Path,
) -> tuple[str, _FileIdentity]:
    if identity.size > MAX_SEGMENT_BYTES:
        raise EvidenceCorrupt(f"published evidence exceeds hard bound: {display_path}")
    before = _file_identity(os.fstat(descriptor))
    digest = hashlib.sha256()
    offset = 0
    while offset < identity.size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, identity.size - offset),
            offset,
        )
        if not chunk:
            raise EvidenceCorrupt(
                f"published evidence shortened during verification: {display_path}"
            )
        digest.update(chunk)
        offset += len(chunk)
    after = _file_identity(os.fstat(descriptor))
    if after != before:
        raise EvidenceCorrupt(
            f"published evidence changed during digest verification: {display_path}"
        )
    return digest.hexdigest(), after


def _open_regular_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    maximum: int | None = None,
) -> tuple[int, os.stat_result]:
    expected = _regular_stat_at(parent_descriptor, name, display_path)
    if maximum is not None and expected.st_size > maximum:
        raise EvidenceCorrupt(f"evidence file exceeds bound: {display_path}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_ino != expected.st_ino
            or opened.st_dev != expected.st_dev
            or opened.st_size != expected.st_size
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise EvidenceCorrupt(f"evidence file changed during open: {display_path}")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    maximum: int,
) -> bytes:
    descriptor, expected = _open_regular_at(
        parent_descriptor,
        name,
        display_path,
        maximum=maximum,
    )
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise EvidenceCorrupt(f"evidence contract exceeds bound: {display_path}")
        if total != expected.st_size:
            raise EvidenceCorrupt(f"evidence file size changed while reading: {display_path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _rename_noreplace(
    source_name: str,
    destination_name: str,
    *,
    source_dir_fd: int,
    destination_dir_fd: int,
) -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int
            result = renameat2(
                source_dir_fd,
                os.fsencode(source_name),
                destination_dir_fd,
                os.fsencode(destination_name),
                1,
            )
            if result == 0:
                return
            error_number = ctypes.get_errno()
            if error_number in _ATOMIC_RENAME_UNAVAILABLE:
                raise EvidenceStoreError(
                    "atomic no-replace rename is unavailable on Linux"
                )
            raise OSError(
                error_number,
                os.strerror(error_number),
                destination_name,
            )
        raise EvidenceStoreError(
            "atomic no-replace rename is unavailable on Linux"
        )
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renameatx_np = getattr(libc, "renameatx_np", None)
        if renameatx_np is not None:
            renameatx_np.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameatx_np.restype = ctypes.c_int
            result = renameatx_np(
                source_dir_fd,
                os.fsencode(source_name),
                destination_dir_fd,
                os.fsencode(destination_name),
                4,
            )
            if result == 0:
                return
            error_number = ctypes.get_errno()
            if error_number in _ATOMIC_RENAME_UNAVAILABLE:
                raise EvidenceStoreError(
                    "atomic no-replace rename is unavailable on Darwin"
                )
            raise OSError(error_number, os.strerror(error_number), destination_name)
        raise EvidenceStoreError("atomic no-replace rename is unavailable on Darwin")
    raise EvidenceStoreError(
        f"atomic no-replace rename is unavailable on {sys.platform}"
    )


def _bind_held_source(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    descriptor: int,
    identity: _FileIdentity,
) -> None:
    _validate_identity(os.fstat(descriptor), identity, display_path)
    _validate_identity(
        _regular_stat_at(parent_descriptor, name, display_path),
        identity,
        display_path,
    )


def _validate_published_from_held(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    descriptor: int,
    identity: _FileIdentity,
    expected_sha256: str,
) -> None:
    held_before = _file_identity(os.fstat(descriptor))
    _validate_post_rename_identity(held_before, identity, display_path)
    published_before = _file_identity(
        _regular_stat_at(parent_descriptor, name, display_path)
    )
    if published_before != held_before:
        raise EvidenceCorrupt(
            f"published evidence is not the authenticated source: {display_path}"
        )
    actual_sha256, held_after = _hash_held_descriptor(
        descriptor,
        held_before,
        display_path,
    )
    published_after = _file_identity(
        _regular_stat_at(parent_descriptor, name, display_path)
    )
    if (
        actual_sha256 != expected_sha256
        or held_after != held_before
        or published_after != held_after
    ):
        raise EvidenceCorrupt(
            f"published evidence bytes changed after authentication: {display_path}"
        )


def _publish_held_without_replacement(
    source_parent_descriptor: int,
    source_name: str,
    destination_parent_descriptor: int,
    destination_name: str,
    display_path: Path,
    *,
    descriptor: int,
    identity: _FileIdentity,
    expected_sha256: str,
) -> None:
    with _post_authentication_namespace(display_path):
        _bind_held_source(
            source_parent_descriptor,
            source_name,
            display_path,
            descriptor=descriptor,
            identity=identity,
        )
        _rename_noreplace(
            source_name,
            destination_name,
            source_dir_fd=source_parent_descriptor,
            destination_dir_fd=destination_parent_descriptor,
        )
        _validate_published_from_held(
            destination_parent_descriptor,
            destination_name,
            display_path,
            descriptor=descriptor,
            identity=identity,
            expected_sha256=expected_sha256,
        )
        os.fsync(destination_parent_descriptor)


def _promote_authenticated_source(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
    display_path: Path,
    *,
    identity: _FileIdentity,
    expected_sha256: str,
) -> None:
    source_path = display_path.with_name(source_name)
    with _post_authentication_namespace(source_path):
        descriptor, opened = _open_regular_at(
            parent_descriptor,
            source_name,
            source_path,
            maximum=MAX_SEGMENT_BYTES,
        )
    try:
        _validate_identity(opened, identity, source_path)
        _publish_held_without_replacement(
            parent_descriptor,
            source_name,
            parent_descriptor,
            destination_name,
            display_path,
            descriptor=descriptor,
            identity=identity,
            expected_sha256=expected_sha256,
        )
    finally:
        os.close(descriptor)


def _write_temporary_at(
    parent_descriptor: int,
    temporary_name: str,
    raw: bytes,
) -> tuple[int, _FileIdentity]:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_descriptor)
    try:
        os.fchmod(descriptor, 0o600)
        _full_write(descriptor, raw)
        os.fsync(descriptor)
        return descriptor, _file_identity(os.fstat(descriptor))
    except BaseException:
        os.close(descriptor)
        raise


def _cleanup_private_publication(
    parent_descriptor: int,
    temporary_name: str | None,
    display_path: Path,
    *,
    descriptor: int,
    preserve_primary: bool,
) -> None:
    cleanup_error: OSError | None = None
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except OSError as error:
            cleanup_error = error
    if temporary_name is not None:
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        except OSError as error:
            if cleanup_error is None:
                cleanup_error = error
    if cleanup_error is not None and not preserve_primary:
        raise EvidenceCorrupt(
            f"authenticated evidence cleanup became uncertain: {display_path}"
        ) from cleanup_error


def _atomic_replace_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    raw: bytes,
    *,
    step_hook: Callable[[str], None] | None = None,
) -> None:
    hook = step_hook or (lambda _step: None)
    temporary_name = f".{name}.{uuid.uuid4()}.tmp"
    expected_sha256 = hashlib.sha256(raw).hexdigest()
    descriptor = -1
    try:
        descriptor, identity = _write_temporary_at(
            parent_descriptor,
            temporary_name,
            raw,
        )
        hook("commitment_temp_fsync")
        with _post_authentication_namespace(display_path):
            _bind_held_source(
                parent_descriptor,
                temporary_name,
                display_path,
                descriptor=descriptor,
                identity=identity,
            )
            os.replace(
                temporary_name,
                name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            hook("commitment_atomic_replace")
            _validate_published_from_held(
                parent_descriptor,
                name,
                display_path,
                descriptor=descriptor,
                identity=identity,
                expected_sha256=expected_sha256,
            )
            os.fsync(parent_descriptor)
            hook("commitment_directory_fsync")
    except BaseException:
        _cleanup_private_publication(
            parent_descriptor,
            temporary_name,
            display_path,
            descriptor=descriptor,
            preserve_primary=True,
        )
        raise
    else:
        _cleanup_private_publication(
            parent_descriptor,
            temporary_name,
            display_path,
            descriptor=descriptor,
            preserve_primary=False,
        )


def _publish_without_replacement_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    raw: bytes,
) -> None:
    temporary_name = f".{name}.{uuid.uuid4()}.tmp"
    expected_sha256 = hashlib.sha256(raw).hexdigest()
    descriptor = -1
    try:
        descriptor, identity = _write_temporary_at(
            parent_descriptor,
            temporary_name,
            raw,
        )
        _publish_held_without_replacement(
            parent_descriptor,
            temporary_name,
            parent_descriptor,
            name,
            display_path,
            descriptor=descriptor,
            identity=identity,
            expected_sha256=expected_sha256,
        )
    except BaseException:
        _cleanup_private_publication(
            parent_descriptor,
            temporary_name,
            display_path,
            descriptor=descriptor,
            preserve_primary=True,
        )
        raise
    else:
        _cleanup_private_publication(
            parent_descriptor,
            temporary_name,
            display_path,
            descriptor=descriptor,
            preserve_primary=False,
        )


class SegmentStore:
    """One lifetime-locked authoritative AGF1 evidence root."""

    def __init__(
        self,
        root: Path,
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        health_step_hook: Callable[[str], None] | None = None,
        segment_create_step_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.root = root
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic_clock or time.monotonic
        self._health_step_hook = health_step_hook or (lambda _step: None)
        self._segment_create_step_hook = (
            segment_create_step_hook or (lambda _step: None)
        )
        self._closed = False
        self._active: _ActiveSegment | None = None
        self._manifests: list[SegmentManifestV1] = []
        self._chain_head: SegmentChainHeadV1 | None = None
        self._records: list[StoredEvidenceRecord] = []
        self._index: dict[tuple[str, int], tuple[bytes, EvidenceRef]] = {}
        self._record_positions: dict[tuple[str, int], int] = {}
        self._sequences_by_host: dict[str, list[int]] = {}
        self._last_sequence_by_host: dict[str, int] = {}
        self._read_only_reason: str | None = None
        self._append_uncertain = False
        self._pending_durable_commit: _PendingDurableCommit | None = None
        self._date_descriptors: dict[str, int] = {}
        self._lifecycle_identity = object()
        self._bound_verifier: EnvelopeVerifier | None = None
        self._authority_state: Literal["unbound", "recovering", "ready"] = "unbound"
        self._coverage_state_owner: object | None = None
        self._ack_journal_owner: object | None = None
        self._ack_journal_state: Literal[
            "unknown",
            "fresh",
            "present",
            "bootstrap",
            "creating",
            "recovering",
            "initialization_uncertain",
            "initialized",
            "append_uncertain",
            "commitment_uncertain",
            "io_uncertain",
        ] = "unknown"
        self._ack_journal_operation: Literal["create", "recover"] | None = None
        self._ack_journal_identity: _FileIdentity | None = None
        self._ack_journal_digest: bytes | None = None
        self._ack_commitment: _AckCommitmentV1 | None = None
        self._ack_commitment_raw: bytes | None = None
        self._ack_commitment_identity: _FileIdentity | None = None
        self._ack_commitment_temporary: _AckCommitmentTemporaryBinding | None = None
        self.fail_next_append: BaseException | None = None
        self._segments_path = root / "segments"
        self._manifests_path = root / "manifests"
        self._root_descriptor = _open_root_directory(root)
        try:
            fcntl.flock(self._root_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(self._root_descriptor)
            raise EvidenceStoreBusy(f"evidence root is already locked: {root}") from error
        try:
            self._load_health_state()
            root_names = set(os.listdir(self._root_descriptor))
            managed_names = {"segments", "manifests"}
            present_managed = root_names & managed_names
            if present_managed == managed_names:
                self._segments_descriptor = _open_directory_at(
                    self._root_descriptor,
                    "segments",
                    self._segments_path,
                )
                self._manifests_descriptor = _open_directory_at(
                    self._root_descriptor,
                    "manifests",
                    self._manifests_path,
                )
            elif not root_names and self._read_only_reason is None:
                self._segments_descriptor = _open_or_create_directory_at(
                    self._root_descriptor,
                    "segments",
                    self._segments_path,
                )
                self._manifests_descriptor = _open_or_create_directory_at(
                    self._root_descriptor,
                    "manifests",
                    self._manifests_path,
                )
            else:
                raise EvidenceCorrupt(
                    "nonpristine evidence root is missing a managed directory"
                )
            self._startup()
        except BaseException:
            for descriptor in self._date_descriptors.values():
                os.close(descriptor)
            if hasattr(self, "_manifests_descriptor"):
                os.close(self._manifests_descriptor)
            if hasattr(self, "_segments_descriptor"):
                os.close(self._segments_descriptor)
            fcntl.flock(self._root_descriptor, fcntl.LOCK_UN)
            os.close(self._root_descriptor)
            self._closed = True
            raise

    @property
    def manifests(self) -> tuple[SegmentManifestV1, ...]:
        return tuple(manifest.model_copy(deep=True) for manifest in self._manifests)

    @property
    def chain_head(self) -> SegmentChainHeadV1 | None:
        return (
            None
            if self._chain_head is None
            else self._chain_head.model_copy(deep=True)
        )

    @property
    def active_path(self) -> Path | None:
        return None if self._active is None else self._active.open_path

    @property
    def read_only_reason(self) -> str | None:
        return self._read_only_reason

    def _is_bound_verifier(self, verifier: EnvelopeVerifier) -> bool:
        return (
            not self._closed
            and self._authority_state == "ready"
            and self._bound_verifier is verifier
            and verifier._bound_lifecycle is self._lifecycle_identity
        )

    def status(self) -> EvidenceStatus:
        if self._closed:
            return EvidenceStatus(False, None, 0, 0, False)
        verifier = self._bound_verifier
        if verifier is None:
            return EvidenceStatus(False, None, 0, 0, False)
        fsm = verifier.fsm
        evidence_head = fsm.last_sequence
        holes = fsm.unresolved_holes
        acceptance_cursor = holes[0][0] - 1 if holes else evidence_head
        if (
            type(fsm.host_id) is not str
            or type(evidence_head) is not int
            or type(acceptance_cursor) is not int
            or not 0 <= acceptance_cursor <= evidence_head <= MAX_UINT64
        ):
            return EvidenceStatus(False, None, 0, 0, False)
        active = self._active
        active_descriptor = None if active is None else active.descriptor
        base_healthy = (
            self._read_only_reason is None
            and not self._append_uncertain
            and self._pending_durable_commit is None
            and (
                active is None
                or (
                    type(active_descriptor) is int
                    and active_descriptor >= 0
                )
            )
        )
        stable = (
            self._is_bound_verifier(verifier)
            and self._bound_verifier is verifier
            and verifier.fsm is fsm
            and self._active is active
            and (
                active is None
                or active.descriptor == active_descriptor
            )
        )
        healthy = base_healthy and stable
        key_healthy = (
            type(fsm.mutation_read_only) is bool
            and not fsm.mutation_read_only
            and fsm.pending_rotation is None
        )
        return EvidenceStatus(
            healthy,
            fsm.host_id,
            evidence_head,
            acceptance_cursor,
            key_healthy,
        )

    def _require_authenticated_recovered(self) -> EnvelopeVerifier:
        if self._closed:
            raise EvidenceStoreError("evidence store is closed")
        verifier = self._bound_verifier
        if verifier is None or self._authority_state != "ready":
            raise EvidenceSealError(
                "authenticated evidence is unavailable before verifier recovery"
            )
        return verifier

    def _require_ack_mutation_ready(self) -> EnvelopeVerifier:
        verifier = self._require_authenticated_recovered()
        if self._read_only_reason is not None:
            raise EvidenceReadOnly(
                f"evidence root is read-only: {self._read_only_reason}"
            )
        if self._append_uncertain or self._pending_durable_commit is not None:
            raise EvidenceReadOnly("evidence durability is not settled")
        return verifier

    @property
    def acceptance_cursor(self) -> int:
        """Highest source cursor made contiguous by signed-or-covered evidence."""
        verifier = self._require_authenticated_recovered()
        holes = verifier.fsm.unresolved_holes
        return holes[0][0] - 1 if holes else verifier.fsm.last_sequence

    def resolve_authenticated_ref(self, ref: EvidenceRef) -> StoredEvidenceRecord:
        """Resolve one complete ref only after verifier-authenticated recovery."""
        verifier = self._require_authenticated_recovered()
        key = (verifier.fsm.host_id, ref.source_sequence)
        indexed = self._index.get(key)
        if (
            indexed is None
            or indexed[1] != ref
            or verifier.accepted_ref(ref.source_sequence) != ref
        ):
            raise _AckAuthorityError(
                "ACK ref does not match one complete authenticated evidence ref"
            )
        position = self._record_positions.get(key)
        if position is None:
            raise EvidenceCorrupt("authenticated evidence index has no record position")
        record = self._records[position]
        if record.ref != ref:
            raise EvidenceCorrupt("authenticated evidence position changed")
        return StoredEvidenceRecord(
            envelope=copy.deepcopy(record.envelope),
            canonical_envelope=record.canonical_envelope,
            priority=record.priority,
            accepted_at=record.accepted_at,
            ref=record.ref,
        )

    def iter_authenticated_records(
        self,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Iterator[StoredEvidenceRecord]:
        """Iterate authenticated records in evidence order within explicit bounds."""
        verifier = self._require_authenticated_recovered()
        if not 0 <= after <= MAX_UINT64:
            raise ValueError("authenticated evidence lower bound is invalid")
        if through is not None and not 0 <= through <= MAX_UINT64:
            raise ValueError("authenticated evidence upper bound is invalid")
        host_id = verifier.fsm.host_id
        sequences = self._sequences_by_host.get(host_id, [])
        start = bisect_right(sequences, after)
        stop = len(sequences) if through is None else bisect_right(sequences, through)
        for position in range(start, stop):
            sequence = sequences[position]
            indexed = self._index.get((host_id, sequence))
            if indexed is None:
                raise EvidenceCorrupt("authenticated evidence sequence index changed")
            yield self.resolve_authenticated_ref(indexed[1])

    def _acquire_coverage_state(self, owner: object) -> object:
        self._require_authenticated_recovered()
        if self._coverage_state_owner is not None:
            raise EvidenceStoreBusy("evidence root already has one coverage-state owner")
        self._coverage_state_owner = owner
        return self._lifecycle_identity

    def _resolve_next_coverage_record(
        self,
        owner: object,
        lifecycle_identity: object,
        record: StoredEvidenceRecord,
        *,
        after_ref: EvidenceRef | None,
    ) -> StoredEvidenceRecord:
        verifier = self._require_authenticated_recovered()
        if (
            owner is not self._coverage_state_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise EvidenceSealError("coverage state is outside this evidence lifecycle")
        try:
            _exact_coverage_record_key(record)
            if after_ref is not None:
                _exact_coverage_ref_key(after_ref)
        except ValueError as error:
            raise EvidenceSealError("coverage apply record is not exact") from error
        host_id = verifier.fsm.host_id
        sequences = self._sequences_by_host.get(host_id, [])
        if after_ref is None:
            position = 0
        else:
            self.resolve_authenticated_ref(after_ref)
            position = bisect_right(sequences, after_ref.source_sequence)
        if position >= len(sequences):
            raise EvidenceSealError(
                "coverage apply has no next authenticated real evidence ref"
            )
        next_ref = self._index[(host_id, sequences[position])][1]
        try:
            _exact_coverage_ref_key(next_ref)
        except ValueError as error:
            raise EvidenceCorrupt(
                "next authenticated coverage ref is invalid"
            ) from error
        if not _same_exact_coverage_ref(record.ref, next_ref):
            raise EvidenceSealError(
                "coverage apply skipped the next authenticated real evidence ref"
            )
        resolved = self.resolve_authenticated_ref(next_ref)
        try:
            same_resolved_record = _same_exact_coverage_record(resolved, record)
        except ValueError as error:
            raise EvidenceCorrupt(
                "resolved authenticated coverage record is invalid"
            ) from error
        if not same_resolved_record:
            raise EvidenceSealError(
                "coverage apply record differs from authenticated evidence"
            )
        return resolved

    def _validate_coverage_state_owner(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        reducer_head: EvidenceRef | None,
    ) -> EvidenceRef | None:
        verifier = self._require_authenticated_recovered()
        if (
            owner is not self._coverage_state_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise EvidenceSealError("coverage state is outside this evidence lifecycle")
        sequence = verifier.fsm.last_sequence
        authenticated_head: EvidenceRef | None = None
        if reducer_head is not None:
            try:
                _exact_coverage_ref_key(reducer_head)
            except ValueError as error:
                raise EvidenceSealError("coverage reducer head is invalid") from error
        if sequence != 0:
            ref = verifier.accepted_ref(sequence)
            if type(ref) is not EvidenceRef:
                raise EvidenceCorrupt(
                    "authenticated evidence head has no exact ref"
                )
            try:
                _exact_coverage_ref_key(ref)
            except ValueError as error:
                raise EvidenceCorrupt(
                    "authenticated evidence head has no exact ref"
                ) from error
            self.resolve_authenticated_ref(ref)
            authenticated_head = ref
        same_head = authenticated_head is reducer_head
        if authenticated_head is not None and reducer_head is not None:
            same_head = _same_exact_coverage_ref(authenticated_head, reducer_head)
        if not same_head:
            raise EvidenceSealError(
                "coverage reducer head differs from authenticated evidence head"
            )
        return authenticated_head

    def _release_coverage_state(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._coverage_state_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise EvidenceSealError("coverage state release has the wrong lifecycle")
        self._coverage_state_owner = None

    def authenticated_refs(
        self,
        *,
        after_sequence: int,
        through_sequence: int,
        limit: int,
    ) -> tuple[EvidenceRef, ...]:
        """Return one mutation-safe bounded batch of exact committed refs."""
        verifier = self._require_ack_mutation_ready()
        if (
            isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or not 0 <= after_sequence <= MAX_UINT64
            or isinstance(through_sequence, bool)
            or not isinstance(through_sequence, int)
            or not 0 <= through_sequence <= MAX_UINT64
            or through_sequence < after_sequence
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("authenticated ref bounds are invalid")

        host_id = verifier.fsm.host_id
        sequences = self._sequences_by_host.get(host_id, [])
        start = bisect_right(sequences, after_sequence)
        stop = bisect_right(sequences, through_sequence)
        refs: list[EvidenceRef] = []
        previous = after_sequence
        for position in range(start, stop):
            sequence = sequences[position]
            if sequence <= previous:
                raise EvidenceCorrupt(
                    "authenticated evidence refs are not strictly ascending"
                )
            indexed = self._index.get((host_id, sequence))
            if indexed is None:
                raise EvidenceCorrupt(
                    "authenticated evidence sequence index changed"
                )
            ref = indexed[1]
            self.resolve_authenticated_ref(ref)
            refs.append(ref)
            previous = sequence
            if len(refs) == limit:
                break
        return tuple(refs)

    def _ack_journal_artifact_identity(self) -> _FileIdentity | None:
        name = "ack-journal.agf"
        try:
            if _entry_stat_at(self._root_descriptor, name) is None:
                return None
            return _file_identity(
                _regular_stat_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                )
            )
        except EvidenceCorrupt as error:
            raise _AckLifecycleCorrupt(
                "ACK-journal root artifact is unsafe or unstable"
            ) from error
        except OSError as error:
            raise _AckLifecycleIoUncertain(
                "ACK-journal root artifact I/O is uncertain"
            ) from error

    def _ack_journal_prefix_digest(
        self,
        prefix_size: int,
    ) -> tuple[_FileIdentity, bytes]:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                "ack-journal.agf",
                flags,
                dir_fd=self._root_descriptor,
            )
        except FileNotFoundError as error:
            raise _AckLifecycleCorrupt(
                "ACK-journal authority disappeared during content binding"
            ) from error
        except OSError as error:
            raise _AckLifecycleIoUncertain(
                "ACK-journal content binding I/O is uncertain"
            ) from error
        primary_error: BaseException | None = None
        try:
            try:
                opened_identity = _file_identity(os.fstat(descriptor))
                published_identity = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        "ack-journal.agf",
                        self.root / "ack-journal.agf",
                    )
                )
                if (
                    opened_identity != published_identity
                    or opened_identity.size < prefix_size
                ):
                    raise _AckLifecycleCorrupt(
                        "ACK-journal prefix identity changed"
                    )
                digest = hashlib.sha256()
                offset = 0
                while offset < prefix_size:
                    chunk = os.pread(
                        descriptor,
                        min(1024 * 1024, prefix_size - offset),
                        offset,
                    )
                    if not chunk:
                        raise _AckLifecycleCorrupt(
                            "ACK-journal prefix shortened during hashing"
                        )
                    digest.update(chunk)
                    offset += len(chunk)
                after_identity = _file_identity(os.fstat(descriptor))
                published_after = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        "ack-journal.agf",
                        self.root / "ack-journal.agf",
                    )
                )
                if (
                    after_identity != opened_identity
                    or published_after != opened_identity
                ):
                    raise _AckLifecycleCorrupt(
                        "ACK-journal identity changed during prefix hashing"
                    )
                return opened_identity, digest.digest()
            except FileNotFoundError as error:
                raise _AckLifecycleCorrupt(
                    "ACK-journal prefix disappeared during binding"
                ) from error
            except EvidenceCorrupt as error:
                raise _AckLifecycleCorrupt(
                    "ACK-journal prefix is unsafe or unstable"
                ) from error
            except OSError as error:
                raise _AckLifecycleIoUncertain(
                    "ACK-journal prefix I/O is uncertain"
                ) from error
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                os.close(descriptor)
            except OSError as close_error:
                if primary_error is None:
                    raise _AckLifecycleIoUncertain(
                        "ACK-journal prefix descriptor close became uncertain"
                    ) from close_error
                primary_error.add_note(
                    "secondary ACK-journal prefix descriptor close failure: "
                    f"{type(close_error).__name__}: {close_error}"
                )

    @staticmethod
    def _same_ack_journal_inode(
        actual: _FileIdentity,
        expected: _FileIdentity,
    ) -> bool:
        return (
            actual.device == expected.device
            and actual.inode == expected.inode
        )

    @staticmethod
    def _ack_genesis_commitment(
        phase: Literal["initializing", "ready"],
    ) -> _AckCommitmentV1:
        return _AckCommitmentV1(
            schema_version="agmind.core-ack-commitment.v1",
            phase=phase,
            generation=0,
            confirmed=None,
            journal_prefix_size=0,
            journal_prefix_sha256=_EMPTY_SHA256,
        )

    def _read_ack_commitment(
        self,
    ) -> tuple[_AckCommitmentV1, bytes, _FileIdentity]:
        try:
            raw = _read_regular_at(
                self._root_descriptor,
                _ACK_COMMITMENT_NAME,
                self.root / _ACK_COMMITMENT_NAME,
                _MAX_ACK_COMMITMENT_BYTES,
            )
            commitment = _decode_ack_commitment(raw)
            if raw != _canonical_ack_commitment(commitment):
                raise EvidenceCorrupt("ACK commitment is not canonical JSON")
            identity = _file_identity(
                _regular_stat_at(
                    self._root_descriptor,
                    _ACK_COMMITMENT_NAME,
                    self.root / _ACK_COMMITMENT_NAME,
                )
            )
            return commitment, raw, identity
        except FileNotFoundError as error:
            raise _AckLifecycleCorrupt(
                "ACK commitment artifact disappeared"
            ) from error
        except OSError as error:
            raise _AckLifecycleIoUncertain(
                "ACK commitment artifact I/O is uncertain"
            ) from error
        except (
            EvidenceCorrupt,
            RecursionError,
            TypeError,
            ValueError,
            ValidationError,
        ) as error:
            raise _AckLifecycleCorrupt(
                "ACK commitment artifact is invalid or unstable"
            ) from error

    def _rebind_ack_commitment(
        self,
        *,
        expected: _AckCommitmentV1 | None = None,
    ) -> _AckCommitmentV1:
        commitment, raw, identity = self._read_ack_commitment()
        if expected is not None and commitment != expected:
            raise _AckLifecycleCorrupt(
                "published ACK commitment differs from the requested state"
            )
        self._ack_commitment = commitment
        self._ack_commitment_raw = raw
        self._ack_commitment_identity = identity
        return commitment

    def _validate_ack_commitment_binding(self) -> _AckCommitmentV1:
        expected = self._ack_commitment
        expected_raw = self._ack_commitment_raw
        expected_identity = self._ack_commitment_identity
        if (
            expected is None
            or expected_raw is None
            or expected_identity is None
        ):
            raise _AckLifecycleCorrupt("ACK commitment binding is absent")
        actual, raw, identity = self._read_ack_commitment()
        if (
            actual != expected
            or raw != expected_raw
            or identity != expected_identity
        ):
            raise _AckLifecycleCorrupt(
                "ACK commitment changed outside its durable publisher"
            )
        return actual

    def _ack_commitment_recovery_view(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> _AckCommitmentRecoveryView:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {
                "creating",
                "recovering",
                "initialization_uncertain",
                "initialized",
            }
        ):
            raise _AckLifecycleStateError(
                "ACK commitment recovery has the wrong lifecycle"
            )
        commitment = (
            None
            if self._ack_commitment is None
            else self._validate_ack_commitment_binding()
        )
        return _AckCommitmentRecoveryView(
            commitment=(
                None if commitment is None else commitment.model_copy(deep=True)
            ),
            journal_present=self._ack_journal_identity is not None,
            temporary_name=(
                None
                if self._ack_commitment_temporary is None
                else self._ack_commitment_temporary.name
            ),
        )

    def _remove_ack_commitment_temporary(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {
                "creating",
                "recovering",
                "initialization_uncertain",
                "initialized",
            }
        ):
            raise _AckLifecycleStateError(
                "ACK commitment temporary cleanup has the wrong lifecycle"
            )
        binding = self._ack_commitment_temporary
        if binding is None:
            return
        try:
            raw = _read_regular_at(
                self._root_descriptor,
                binding.name,
                self.root / binding.name,
                _MAX_ACK_COMMITMENT_BYTES,
            )
            commitment = _decode_ack_commitment(raw)
            identity = _file_identity(
                _regular_stat_at(
                    self._root_descriptor,
                    binding.name,
                    self.root / binding.name,
                )
            )
            if (
                raw != binding.raw
                or commitment != binding.commitment
                or identity != binding.identity
                or raw != _canonical_ack_commitment(commitment)
            ):
                raise _AckLifecycleCorrupt(
                    "ACK commitment temporary changed after startup"
                )
            os.unlink(binding.name, dir_fd=self._root_descriptor)
            os.fsync(self._root_descriptor)
        except (_AckLifecycleCorrupt, _AckLifecycleIoUncertain):
            raise
        except (
            EvidenceCorrupt,
            RecursionError,
            TypeError,
            ValueError,
            ValidationError,
        ) as error:
            raise _AckLifecycleCorrupt(
                "ACK commitment temporary is no longer authenticated"
            ) from error
        except FileNotFoundError as error:
            raise _AckLifecycleCorrupt(
                "ACK commitment temporary disappeared after startup"
            ) from error
        except OSError as error:
            raise _AckLifecycleIoUncertain(
                "ACK commitment temporary cleanup I/O is uncertain"
            ) from error
        self._ack_commitment_temporary = None

    def _publish_ack_initializing_genesis(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_operation != "create"
            or self._ack_journal_state != "creating"
            or self._ack_commitment is not None
            or self._ack_journal_identity is not None
        ):
            raise _AckLifecycleStateError(
                "ACK initializing commitment has the wrong lifecycle"
            )
        self._remove_ack_commitment_temporary(owner, lifecycle_identity)
        commitment = self._ack_genesis_commitment("initializing")
        try:
            _publish_without_replacement_at(
                self._root_descriptor,
                _ACK_COMMITMENT_NAME,
                self.root / _ACK_COMMITMENT_NAME,
                _canonical_ack_commitment(commitment),
            )
        except (EvidenceCorrupt, OSError) as error:
            raise _AckLifecycleCorrupt(
                "ACK initializing commitment publication failed"
            ) from error
        self._rebind_ack_commitment(expected=commitment)
        self._ack_journal_state = "initialization_uncertain"

    def _publish_ack_ready_genesis(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        step_hook: Callable[[str], None] | None = None,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {"initialization_uncertain", "recovering"}
        ):
            raise _AckLifecycleStateError(
                "ACK ready-genesis publication has the wrong lifecycle"
            )
        current = self._validate_ack_commitment_binding()
        if current != self._ack_genesis_commitment("initializing"):
            raise _AckLifecycleCorrupt(
                "ACK ready genesis does not follow initializing genesis"
            )
        journal_identity, digest = self._ack_journal_prefix_digest(0)
        if journal_identity.size != 0 or digest.hex() != _EMPTY_SHA256:
            raise _AckLifecycleCorrupt(
                "ACK initializing commitment does not bind an empty journal"
            )
        self._remove_ack_commitment_temporary(owner, lifecycle_identity)
        commitment = self._ack_genesis_commitment("ready")
        try:
            _atomic_replace_at(
                self._root_descriptor,
                _ACK_COMMITMENT_NAME,
                self.root / _ACK_COMMITMENT_NAME,
                _canonical_ack_commitment(commitment),
                step_hook=step_hook,
            )
        except EvidenceCorrupt as error:
            if isinstance(error.__cause__, OSError):
                raise error.__cause__
            raise _AckLifecycleCorrupt(
                "ACK ready-genesis publication failed"
            ) from error
        self._rebind_ack_commitment(expected=commitment)

    def _publish_ack_ready_generation(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        generation: int,
        sequence: int,
        event_id: str,
        content_sha256: str,
        journal_prefix_size: int,
        journal_prefix_sha256: str,
        step_hook: Callable[[str], None] | None = None,
    ) -> _AckCommitmentV1:
        self._validate_ack_journal_owner(owner, lifecycle_identity)
        current = self._validate_ack_commitment_binding()
        if (
            current.phase != "ready"
            or generation != current.generation + 1
        ):
            raise _AckLifecycleCorrupt(
                "ACK commitment generation is not one exact transition ahead"
            )
        try:
            ref = self._validate_ack_identity(
                owner,
                lifecycle_identity,
                sequence=sequence,
                event_id=event_id,
                content_sha256=content_sha256,
            )
        except _AckAuthorityError as error:
            raise _AckLifecycleCorrupt(
                "ACK commitment does not bind authenticated evidence"
            ) from error
        if (
            ref.source_sequence != sequence
            or ref.event_id != event_id
            or ref.content_sha256 != content_sha256
        ):
            raise _AckLifecycleCorrupt(
                "ACK commitment evidence identity changed"
            )
        journal_identity, digest = self._ack_journal_prefix_digest(
            journal_prefix_size
        )
        if (
            journal_identity.size < journal_prefix_size
            or digest.hex() != journal_prefix_sha256
        ):
            raise _AckLifecycleCorrupt(
                "ACK commitment prefix differs from the held journal"
            )
        self._remove_ack_commitment_temporary(owner, lifecycle_identity)
        commitment = _AckCommitmentV1(
            schema_version="agmind.core-ack-commitment.v1",
            phase="ready",
            generation=generation,
            confirmed=_AckCommitmentIdentityV1(
                sequence=sequence,
                event_id=event_id,
                content_sha256=content_sha256,
            ),
            journal_prefix_size=journal_prefix_size,
            journal_prefix_sha256=journal_prefix_sha256,
        )
        try:
            _atomic_replace_at(
                self._root_descriptor,
                _ACK_COMMITMENT_NAME,
                self.root / _ACK_COMMITMENT_NAME,
                _canonical_ack_commitment(commitment),
                step_hook=step_hook,
            )
        except EvidenceCorrupt as error:
            if isinstance(error.__cause__, OSError):
                raise error.__cause__
            raise _AckLifecycleCorrupt(
                "ACK commitment publication failed"
            ) from error
        self._rebind_ack_commitment(expected=commitment)
        rebound_identity, rebound_digest = self._ack_journal_prefix_digest(
            journal_prefix_size
        )
        if (
            rebound_identity != journal_identity
            or rebound_digest.hex() != journal_prefix_sha256
        ):
            raise _AckLifecycleCorrupt(
                "ACK journal changed after commitment publication"
            )
        return commitment.model_copy(deep=True)

    def _mark_ack_commitment_uncertain(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {"initialized", "append_uncertain", "commitment_uncertain"}
        ):
            raise _AckLifecycleStateError(
                "ACK commitment uncertainty has the wrong lifecycle"
            )
        self._ack_journal_state = "commitment_uncertain"

    def _mark_ack_io_uncertain(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated: os.stat_result | None,
        authenticated_digest: bytes | None,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {
                "recovering",
                "initialization_uncertain",
                "initialized",
                "io_uncertain",
            }
        ):
            raise _AckLifecycleStateError(
                "ACK I/O uncertainty has the wrong lifecycle"
            )
        if (authenticated is None) != (authenticated_digest is None):
            raise _AckLifecycleCorrupt(
                "ACK I/O uncertainty has an incomplete content anchor"
            )
        if authenticated is not None and authenticated_digest is not None:
            retained_identity = _file_identity(authenticated)
            expected_identity = self._ack_journal_identity
            if (
                len(authenticated_digest) != hashlib.sha256().digest_size
                or expected_identity is None
                or not self._same_ack_journal_inode(
                    retained_identity,
                    expected_identity,
                )
            ):
                raise _AckLifecycleCorrupt(
                    "ACK I/O uncertainty has an invalid content anchor"
                )
            self._ack_journal_identity = retained_identity
            self._ack_journal_digest = authenticated_digest
        if self._ack_journal_state != "initialization_uncertain":
            self._ack_journal_state = "io_uncertain"

    def _acquire_ack_journal(
        self,
        owner: object,
        *,
        operation: Literal["create", "recover"],
    ) -> tuple[int, object]:
        self._require_ack_mutation_ready()
        if self._ack_journal_owner is not None:
            raise EvidenceStoreBusy("evidence root already has one ACK-journal owner")
        state = self._ack_journal_state
        if state == "unknown":
            raise _AckLifecycleStateError(
                "ACK-journal startup presence was not authenticated"
            )
        if state == "initialization_uncertain":
            raise _AckLifecycleStateError(
                "ACK-journal initialization is uncertain until store restart"
            )
        if state in {
            "append_uncertain",
            "commitment_uncertain",
            "io_uncertain",
        }:
            raise _AckLifecycleStateError(
                "ACK authority publication is uncertain until store restart"
            )
        if state in {"creating", "recovering"}:
            raise _AckLifecycleStateError(
                "ACK-journal initialization did not settle"
            )

        actual_identity = self._ack_journal_artifact_identity()
        if state in {"present", "initialized"}:
            expected_identity = self._ack_journal_identity
            if actual_identity is None:
                raise _AckLifecycleCorrupt(
                    "expected ACK-journal authority disappeared"
                )
            if (
                expected_identity is None
                or actual_identity != expected_identity
            ):
                raise _AckLifecycleCorrupt(
                    "expected ACK-journal authority changed identity"
                )
        if state == "bootstrap":
            expected_identity = self._ack_journal_identity
            if (
                (expected_identity is None) != (actual_identity is None)
                or (
                    expected_identity is not None
                    and actual_identity != expected_identity
                )
            ):
                raise _AckLifecycleCorrupt(
                    "bootstrap ACK journal changed after startup"
                )
        if state == "fresh" and actual_identity is not None:
            raise _AckLifecycleCorrupt(
                "unexpected ACK journal appeared in a fresh store lifecycle"
            )
        if operation == "create":
            if state != "fresh":
                raise _AckLifecycleStateError(
                    "ACK journal may be created only in a fresh store lifecycle"
                )
            next_state: Literal["creating", "recovering"] = "creating"
        else:
            if state not in {"present", "bootstrap"}:
                raise _AckLifecycleStateError(
                    "ACK journal may be recovered only once from startup presence"
                )
            next_state = "recovering"

        duplicate_command = getattr(fcntl, "F_DUPFD_CLOEXEC", None)
        if duplicate_command is None:
            root_descriptor = os.dup(self._root_descriptor)
            os.set_inheritable(root_descriptor, False)
        else:
            root_descriptor = fcntl.fcntl(
                self._root_descriptor,
                duplicate_command,
                0,
            )
        self._ack_journal_owner = owner
        self._ack_journal_operation = operation
        self._ack_journal_state = next_state
        return root_descriptor, self._lifecycle_identity

    def _ack_journal_final_name_created(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or not (
                (
                    self._ack_journal_operation == "create"
                    and self._ack_journal_state
                    in {"creating", "initialization_uncertain"}
                )
                or (
                    self._ack_journal_operation == "recover"
                    and self._ack_journal_state == "recovering"
                    and self._ack_journal_identity is None
                )
            )
        ):
            raise _AckLifecycleStateError(
                "ACK-journal create publication has the wrong lifecycle"
            )
        self._ack_journal_state = "initialization_uncertain"

    def _complete_ack_journal_initialization(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated: os.stat_result,
        authenticated_digest: bytes,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise _AckLifecycleStateError(
                "ACK-journal completion has the wrong lifecycle"
            )
        operation = self._ack_journal_operation
        state = self._ack_journal_state
        if not (
            (operation == "create" and state == "initialization_uncertain")
            or (
                operation == "recover"
                and state in {"recovering", "initialization_uncertain"}
            )
        ):
            raise _AckLifecycleStateError(
                "ACK-journal completion did not follow create or recovery"
            )
        actual_identity = self._ack_journal_artifact_identity()
        authenticated_identity = _file_identity(authenticated)
        if actual_identity is None:
            raise _AckLifecycleCorrupt(
                "ACK-journal authority disappeared before initialization completed"
            )
        if actual_identity != authenticated_identity:
            raise _AckLifecycleCorrupt(
                "ACK-journal authority changed before initialization completed"
            )
        if len(authenticated_digest) != hashlib.sha256().digest_size:
            raise _AckLifecycleCorrupt(
                "ACK-journal authenticated digest is invalid"
            )
        commitment = self._validate_ack_commitment_binding()
        if commitment.phase != "ready":
            raise _AckLifecycleCorrupt(
                "ACK journal cannot initialize under a non-ready commitment"
            )
        expected_identity = self._ack_journal_identity
        if (
            operation == "recover"
            and (
                (
                    expected_identity is not None
                    and not self._same_ack_journal_inode(
                        authenticated_identity,
                        expected_identity,
                    )
                )
                or (
                    expected_identity is None
                    and self._ack_commitment is not None
                    and self._ack_commitment.phase != "ready"
                    and authenticated_identity.size != 0
                )
            )
        ):
            raise _AckLifecycleCorrupt(
                "recovered ACK journal differs from startup identity"
            )
        self._ack_journal_identity = authenticated_identity
        self._ack_journal_digest = authenticated_digest
        self._ack_journal_state = "initialized"

    def _seal_ack_journal_identity(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated: os.stat_result,
        authenticated_digest: bytes,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state != "initialized"
        ):
            raise _AckLifecycleStateError(
                "ACK-journal close has the wrong lifecycle"
            )
        authenticated_identity = _file_identity(authenticated)
        if len(authenticated_digest) != hashlib.sha256().digest_size:
            raise _AckLifecycleCorrupt(
                "ACK-journal close digest is invalid"
            )
        commitment = self._validate_ack_commitment_binding()
        if commitment.phase != "ready":
            raise _AckLifecycleCorrupt(
                "ACK journal cannot close under a non-ready commitment"
            )
        actual_identity = self._ack_journal_artifact_identity()
        expected_identity = self._ack_journal_identity
        if (
            actual_identity is None
            or actual_identity != authenticated_identity
            or expected_identity is None
            or not self._same_ack_journal_inode(
                authenticated_identity,
                expected_identity,
            )
        ):
            raise _AckLifecycleCorrupt(
                "ACK-journal authority changed before healthy close"
            )
        self._ack_journal_identity = authenticated_identity
        self._ack_journal_digest = authenticated_digest

    def _mark_ack_journal_append_uncertain(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated_before: os.stat_result,
        authenticated_digest_before: bytes,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {"initialized", "append_uncertain"}
        ):
            raise _AckLifecycleStateError(
                "ACK-journal uncertainty has the wrong lifecycle"
            )
        retained_identity = _file_identity(authenticated_before)
        if len(authenticated_digest_before) != hashlib.sha256().digest_size:
            raise _AckLifecycleCorrupt(
                "ACK-journal pre-append digest is invalid"
            )
        expected_identity = self._ack_journal_identity
        if (
            expected_identity is None
            or not self._same_ack_journal_inode(
                retained_identity,
                expected_identity,
            )
        ):
            raise _AckLifecycleCorrupt(
                "ACK-journal pre-append identity changed"
            )
        self._ack_journal_identity = retained_identity
        self._ack_journal_digest = authenticated_digest_before
        self._ack_journal_state = "append_uncertain"

    def _validate_ack_journal_owner(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        self._require_ack_mutation_ready()
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {"recovering", "initialization_uncertain", "initialized"}
        ):
            raise EvidenceSealError("ACK journal is outside this evidence lifecycle")
        if self._ack_journal_state == "initialized":
            commitment = self._validate_ack_commitment_binding()
            if commitment.phase != "ready":
                raise _AckLifecycleCorrupt(
                    "initialized ACK journal has no ready commitment"
                )

    def _release_ack_journal(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise EvidenceSealError("ACK journal release has the wrong lifecycle")
        state = self._ack_journal_state
        if state == "creating":
            self._ack_journal_state = "fresh"
        elif state == "recovering":
            self._ack_journal_state = "present"
        self._ack_journal_owner = None
        self._ack_journal_operation = None

    def _validate_ack_identity(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        sequence: int,
        event_id: str,
        content_sha256: str,
    ) -> EvidenceRef:
        self._validate_ack_journal_owner(owner, lifecycle_identity)
        verifier = self._require_authenticated_recovered()
        indexed = self._index.get((verifier.fsm.host_id, sequence))
        if indexed is None:
            raise _AckAuthorityError("ACK identity has no authenticated evidence")
        ref = indexed[1]
        if ref.event_id != event_id or ref.content_sha256 != content_sha256:
            raise _AckAuthorityError("ACK identity differs from authenticated evidence")
        self.resolve_authenticated_ref(ref)
        return ref

    def _validate_next_ack_ref(
        self,
        owner: object,
        lifecycle_identity: object,
        ref: EvidenceRef,
        *,
        confirmed_through: int,
    ) -> None:
        self._validate_ack_journal_owner(owner, lifecycle_identity)
        self.resolve_authenticated_ref(ref)
        verifier = self._require_authenticated_recovered()
        host_id = verifier.fsm.host_id
        sequences = self._sequences_by_host.get(host_id, [])
        position = bisect_right(sequences, confirmed_through)
        if position >= len(sequences):
            raise _AckAuthorityError(
                "pending ACK has no next authenticated evidence ref"
            )
        next_ref = self._index[(host_id, sequences[position])][1]
        if next_ref != ref:
            raise _AckAuthorityError(
                "pending ACK is not the next authenticated evidence ref"
            )
        if ref.source_sequence > self.acceptance_cursor:
            raise _AckAuthorityError(
                "pending ACK exceeds the signed-or-covered acceptance cursor"
            )

    def _date_descriptor(self, date_name: str, *, create: bool = False) -> int:
        if (
            not _DATE_NAME.fullmatch(date_name)
            or date.fromisoformat(date_name).isoformat() != date_name
        ):
            raise EvidenceCorrupt(f"invalid evidence UTC date directory: {date_name}")
        retained = self._date_descriptors.get(date_name)
        if retained is not None:
            return retained
        display_path = self._segments_path / date_name
        if create:
            descriptor = _open_or_create_directory_at(
                self._segments_descriptor,
                date_name,
                display_path,
            )
        else:
            try:
                descriptor = os.open(
                    date_name,
                    _directory_flags(),
                    dir_fd=self._segments_descriptor,
                )
            except FileNotFoundError as error:
                raise EvidenceCorrupt(
                    f"evidence date directory disappeared: {display_path}"
                ) from error
            try:
                _validate_directory(descriptor, display_path, exact_mode=True)
            except BaseException:
                os.close(descriptor)
                raise
        self._date_descriptors[date_name] = descriptor
        return descriptor

    def _startup(self) -> None:
        try:
            plan, manifested_open = self._scan_manifests_and_segments()
            active_cleanup = self._scan_unsettled_open(manifested_open)
            plan = _RecoveryPlan(
                promotions=plan.promotions,
                delete_private_temporaries=(
                    plan.delete_private_temporaries + active_cleanup
                ),
                delete_manifest_temporaries=plan.delete_manifest_temporaries,
                delete_root_temporaries=plan.delete_root_temporaries,
                head_raw=plan.head_raw,
            )
            if self._read_only_reason is None:
                self._apply_recovery_plan(plan)
        except TornTailRepairRequired:
            raise
        except EvidenceCorrupt:
            if self._read_only_reason is None:
                self._trip_read_only("segment_corrupt")
            raise
        except (JournalCorrupt, OSError, ValidationError, ValueError) as error:
            if self._read_only_reason is None:
                self._trip_read_only("segment_corrupt")
            raise EvidenceCorrupt("evidence startup verification failed") from error

    def _load_health_state(self) -> None:
        names = set(os.listdir(self._root_descriptor))
        pending_names = {
            name
            for name in names
            if (
                name.startswith(".health-intent.")
                and name.endswith(".pending")
            )
            or _HEALTH_FINAL_TEMP_NAME.fullmatch(name)
        }
        if pending_names:
            for name in pending_names:
                _regular_stat_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                )
            self._read_only_reason = "segment_corrupt"
        if "health.intent.json" in names:
            raw = _read_regular_at(
                self._root_descriptor,
                "health.intent.json",
                self.root / "health.intent.json",
                MAX_CONTRACT_FILE_BYTES,
            )
            try:
                intent = decode_strict(
                    raw,
                    _EvidenceHealthIntentV1,
                    MAX_CONTRACT_FILE_BYTES,
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise EvidenceCorrupt("evidence health intent is malformed") from error
            if raw != canonical_json(intent):
                raise EvidenceCorrupt("evidence health intent is not canonical")
            self._read_only_reason = intent.reason
        if "health.json" in names:
            raw = _read_regular_at(
                self._root_descriptor,
                "health.json",
                self.root / "health.json",
                MAX_CONTRACT_FILE_BYTES,
            )
            try:
                marker = decode_strict(
                    raw,
                    _EvidenceHealthV1,
                    MAX_CONTRACT_FILE_BYTES,
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise EvidenceCorrupt("evidence health marker is malformed") from error
            if raw != canonical_json(marker):
                raise EvidenceCorrupt("evidence health marker is not canonical")
            if (
                self._read_only_reason is not None
                and self._read_only_reason != marker.reason
            ):
                raise EvidenceCorrupt("health intent and final marker disagree")
            self._read_only_reason = marker.reason

    def _trip_read_only(self, reason: str) -> None:
        if reason not in {"segment_corrupt", "evidence_conflict"}:
            raise ValueError("unsupported evidence read-only reason")
        self._read_only_reason = reason
        final_raw = canonical_json(
            {
                "schema_version": "agmind.evidence-health.v1",
                "mode": "read_only",
                "reason": reason,
            }
        )
        final_stat = _entry_stat_at(self._root_descriptor, "health.json")
        if final_stat is not None:
            raw = _read_regular_at(
                self._root_descriptor,
                "health.json",
                self.root / "health.json",
                MAX_CONTRACT_FILE_BYTES,
            )
            marker = decode_strict(raw, _EvidenceHealthV1, MAX_CONTRACT_FILE_BYTES)
            if raw != canonical_json(marker) or marker.reason != reason:
                raise EvidenceCorrupt("existing health marker conflicts with trip reason")
            return

        intent_raw = canonical_json(
            {
                "schema_version": "agmind.evidence-health-intent.v1",
                "mode": "read_only_pending",
                "reason": reason,
            }
        )
        intent_sha256 = hashlib.sha256(intent_raw).hexdigest()
        if _entry_stat_at(self._root_descriptor, "health.intent.json") is None:
            temporary_name = f".health-intent.{uuid.uuid4()}.pending"
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=self._root_descriptor,
            )
            try:
                self._health_step_hook("create")
                os.fchmod(descriptor, 0o600)
                os.fsync(self._root_descriptor)
                self._health_step_hook("create_directory_fsync")
                _full_write(descriptor, intent_raw)
                self._health_step_hook("write")
                os.fsync(descriptor)
                self._health_step_hook("file_fsync")
                identity = _file_identity(os.fstat(descriptor))
                _bind_held_source(
                    self._root_descriptor,
                    temporary_name,
                    self.root / "health.intent.json",
                    descriptor=descriptor,
                    identity=identity,
                )
                _rename_noreplace(
                    temporary_name,
                    "health.intent.json",
                    source_dir_fd=self._root_descriptor,
                    destination_dir_fd=self._root_descriptor,
                )
                self._health_step_hook("rename")
                _validate_published_from_held(
                    self._root_descriptor,
                    "health.intent.json",
                    self.root / "health.intent.json",
                    descriptor=descriptor,
                    identity=identity,
                    expected_sha256=intent_sha256,
                )
                os.fsync(self._root_descriptor)
                self._health_step_hook("rename_directory_fsync")
            finally:
                os.close(descriptor)
        else:
            raw = _read_regular_at(
                self._root_descriptor,
                "health.intent.json",
                self.root / "health.intent.json",
                MAX_CONTRACT_FILE_BYTES,
            )
            intent = decode_strict(
                raw,
                _EvidenceHealthIntentV1,
                MAX_CONTRACT_FILE_BYTES,
            )
            if raw != canonical_json(intent) or intent.reason != reason:
                raise EvidenceCorrupt("existing health intent conflicts with trip reason")
        _atomic_replace_at(
            self._root_descriptor,
            "health.json",
            self.root / "health.json",
            final_raw,
        )
        os.unlink("health.intent.json", dir_fd=self._root_descriptor)
        for name in os.listdir(self._root_descriptor):
            if name.startswith(".health-intent.") and name.endswith(".pending"):
                os.unlink(name, dir_fd=self._root_descriptor)
        os.fsync(self._root_descriptor)

    def enter_read_only(self, reason: Literal["evidence_conflict"]) -> None:
        """Persist a verifier-detected critical conflict before returning it."""
        self._trip_read_only(reason)

    def _trip_ack_journal_corrupt(self) -> None:
        """Persist a root-wide fence without rewriting corrupt ACK bytes."""
        self._trip_read_only("segment_corrupt")

    def _fence_missing_expected_ack_journal(self) -> None:
        state = self._ack_journal_state
        if state not in {
            "present",
            "initialized",
            "append_uncertain",
            "commitment_uncertain",
            "io_uncertain",
        }:
            return
        try:
            actual_identity = self._ack_journal_artifact_identity()
        except _AckLifecycleCorrupt:
            actual_identity = None
        expected_identity = self._ack_journal_identity
        identity_changed = actual_identity is None or expected_identity is None
        if not identity_changed and actual_identity is not None:
            if state in {"append_uncertain", "commitment_uncertain"}:
                identity_changed = (
                    expected_identity is None
                    or not self._same_ack_journal_inode(
                        actual_identity,
                        expected_identity,
                    )
                    or actual_identity.size < expected_identity.size
                )
            else:
                identity_changed = actual_identity != expected_identity

        content_changed = False
        if (
            not identity_changed
            and state in {
                "initialized",
                "append_uncertain",
                "commitment_uncertain",
                "io_uncertain",
            }
            and expected_identity is not None
        ):
            expected_digest = self._ack_journal_digest
            if expected_digest is None:
                content_changed = state != "io_uncertain"
            else:
                try:
                    hashed_identity, actual_digest = (
                        self._ack_journal_prefix_digest(
                            expected_identity.size
                        )
                    )
                except (_AckLifecycleCorrupt, _AckLifecycleIoUncertain):
                    content_changed = True
                else:
                    content_changed = (
                        actual_identity is None
                        or not self._same_ack_journal_inode(
                            hashed_identity,
                            actual_identity,
                        )
                        or actual_digest != expected_digest
                    )
        commitment_changed = False
        if state in {"present", "initialized", "append_uncertain"}:
            try:
                self._validate_ack_commitment_binding()
            except (_AckLifecycleCorrupt, _AckLifecycleIoUncertain):
                commitment_changed = True
        elif state == "io_uncertain":
            try:
                self._validate_ack_commitment_binding()
            except _AckLifecycleCorrupt:
                commitment_changed = True
            except _AckLifecycleIoUncertain:
                commitment_changed = False
        elif state == "commitment_uncertain":
            expected_commitment = self._ack_commitment
            try:
                actual_commitment, _raw, _identity = self._read_ack_commitment()
            except _AckLifecycleCorrupt:
                commitment_changed = True
            except _AckLifecycleIoUncertain:
                commitment_changed = False
            else:
                commitment_changed = (
                    expected_commitment is None
                    or actual_commitment.phase != "ready"
                    or actual_commitment.generation
                    not in {
                        expected_commitment.generation,
                        expected_commitment.generation + 1,
                    }
                )
        if identity_changed or content_changed or commitment_changed:
            self._trip_read_only("segment_corrupt")

    def _scan_manifests_and_segments(
        self,
    ) -> tuple[_RecoveryPlan, set[tuple[str, str]]]:
        manifests: list[SegmentManifestV1] = []
        manifest_temporaries: list[str] = []
        for name in sorted(os.listdir(self._manifests_descriptor)):
            if _MANIFEST_TEMP_NAME.fullmatch(name):
                _regular_stat_at(
                    self._manifests_descriptor,
                    name,
                    self._manifests_path / name,
                )
                manifest_temporaries.append(name)
                continue
            match = _MANIFEST_NAME.fullmatch(name)
            if match is None:
                raise EvidenceCorrupt(f"unexpected manifest artifact: {name}")
            raw = _read_regular_at(
                self._manifests_descriptor,
                name,
                self._manifests_path / name,
                MAX_CONTRACT_FILE_BYTES,
            )
            manifest = decode_strict(raw, SegmentManifestV1, MAX_CONTRACT_FILE_BYTES)
            if raw != canonical_json(manifest):
                raise EvidenceCorrupt("immutable manifest is not canonical JSON")
            if name != f"{manifest.segment_id}.json":
                raise EvidenceCorrupt("manifest filename does not match segment_id")
            manifests.append(manifest)
        chain = self._order_manifest_chain(manifests)
        referenced_closed: set[tuple[str, str]] = set()
        manifested_open: set[tuple[str, str]] = set()
        promotions: list[_Promotion] = []
        for manifest in chain:
            _, date_name, closed_name = manifest.segment_relative_path.split("/")
            open_name = closed_name.removesuffix(".agseg") + ".open"
            date_descriptor = self._date_descriptor(date_name)
            closed_stat = _entry_stat_at(date_descriptor, closed_name)
            open_stat = _entry_stat_at(date_descriptor, open_name)
            if closed_stat is not None and open_stat is not None:
                raise EvidenceCorrupt("manifest segment has both open and closed payloads")
            if open_stat is not None:
                scan = self._verify_segment_against_manifest(
                    date_descriptor,
                    open_name,
                    self._segments_path / date_name / open_name,
                    manifest,
                )
                promotions.append(
                    _Promotion(
                        date_name=date_name,
                        open_name=open_name,
                        closed_name=closed_name,
                        identity=scan.identity,
                        sha256=scan.sha256,
                    )
                )
                manifested_open.add((date_name, open_name))
            elif closed_stat is None:
                raise EvidenceCorrupt("manifest payload is missing without retention authority")
            else:
                scan = self._verify_segment_against_manifest(
                    date_descriptor,
                    closed_name,
                    self._segments_path / date_name / closed_name,
                    manifest,
                )
            self._add_records(list(scan.records))
            referenced_closed.add((date_name, closed_name))
        if promotions:
            final_closed_name = chain[-1].segment_relative_path.rsplit(
                "/",
                1,
            )[-1]
            if (
                len(promotions) != 1
                or promotions[0].closed_name != final_closed_name
            ):
                raise EvidenceCorrupt(
                    "only one final manifested-open promotion is recoverable"
                )

        private_temporaries: list[tuple[str, str]] = []
        for date_name in sorted(os.listdir(self._segments_descriptor)):
            date_descriptor = self._date_descriptor(date_name)
            for name in sorted(os.listdir(date_descriptor)):
                if name.endswith(".agseg"):
                    if (date_name, name) not in referenced_closed:
                        raise EvidenceCorrupt("closed segment has no immutable manifest")
                elif name.endswith(".open"):
                    continue
                elif _CREATE_TEMP_NAME.fullmatch(name):
                    info = _regular_stat_at(
                        date_descriptor,
                        name,
                        self._segments_path / date_name / name,
                    )
                    if info.st_size > MAX_EVIDENCE_RECORD_BYTES + 76:
                        raise EvidenceCorrupt("private create temporary exceeds bound")
                    if info.st_size:
                        temporary_scan = self._read_segment(
                            date_descriptor,
                            name,
                            self._segments_path / date_name / name,
                            allow_torn=True,
                        )
                        if (
                            temporary_scan.torn_verified not in {None, 0}
                            or (
                                temporary_scan.torn_verified is None
                                and (
                                    len(temporary_scan.frames) != 1
                                    or len(temporary_scan.records) != 1
                                )
                            )
                        ):
                            raise EvidenceCorrupt(
                                "private create temporary has impossible contents"
                            )
                    private_temporaries.append((date_name, name))
                else:
                    raise EvidenceCorrupt(f"unexpected segment artifact: {name}")
        self._manifests = chain
        head_raw = self._scan_chain_head()

        root_temporaries: list[str] = []
        allowed_root = {
            "ack-journal.agf",
            _ACK_COMMITMENT_NAME,
            "chain-head.json",
            "health.intent.json",
            "health.json",
            "manifests",
            "segments",
        }
        root_entries = tuple(os.listdir(self._root_descriptor))
        ack_journal_identity: _FileIdentity | None = None
        ack_commitment: _AckCommitmentV1 | None = None
        ack_commitment_raw: bytes | None = None
        ack_commitment_identity: _FileIdentity | None = None
        ack_commitment_temporaries: list[_AckCommitmentTemporaryBinding] = []
        for name in root_entries:
            if name == "ack-journal.agf":
                ack_journal_identity = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        name,
                        self.root / name,
                    )
                )
                continue
            if name == _ACK_COMMITMENT_NAME:
                try:
                    (
                        ack_commitment,
                        ack_commitment_raw,
                        ack_commitment_identity,
                    ) = self._read_ack_commitment()
                except _AckLifecycleCorrupt as error:
                    raise EvidenceCorrupt(
                        "ACK commitment is invalid at startup"
                    ) from error
                continue
            if _ACK_COMMITMENT_TEMP_NAME.fullmatch(name):
                info = _regular_stat_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                )
                if info.st_size > _MAX_ACK_COMMITMENT_BYTES:
                    raise EvidenceCorrupt(
                        "ACK commitment temporary exceeds its bound"
                    )
                raw = _read_regular_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                    _MAX_ACK_COMMITMENT_BYTES,
                )
                try:
                    temporary = _decode_ack_commitment(raw)
                except (
                    RecursionError,
                    TypeError,
                    ValueError,
                    ValidationError,
                ) as error:
                    raise EvidenceCorrupt(
                        "ACK commitment temporary schema is invalid"
                    ) from error
                if raw != _canonical_ack_commitment(temporary):
                    raise EvidenceCorrupt(
                        "ACK commitment temporary is not canonical JSON"
                    )
                after = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        name,
                        self.root / name,
                    )
                )
                before = _file_identity(info)
                if after != before:
                    raise EvidenceCorrupt(
                        "ACK commitment temporary changed during startup scan"
                    )
                ack_commitment_temporaries.append(
                    _AckCommitmentTemporaryBinding(
                        name=name,
                        commitment=temporary,
                        raw=raw,
                        identity=after,
                    )
                )
                continue
            if name in allowed_root or (
                name.startswith(".health-intent.") and name.endswith(".pending")
            ) or _HEALTH_FINAL_TEMP_NAME.fullmatch(name):
                continue
            if _ROOT_TEMP_NAME.fullmatch(name):
                _regular_stat_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                )
                root_temporaries.append(name)
                continue
            raise EvidenceCorrupt(f"unexpected evidence-root artifact: {name}")
        if len(ack_commitment_temporaries) > 1:
            raise EvidenceCorrupt("multiple ACK commitment temporaries exist")
        self._ack_journal_identity = ack_journal_identity
        self._ack_commitment = ack_commitment
        self._ack_commitment_raw = ack_commitment_raw
        self._ack_commitment_identity = ack_commitment_identity
        self._ack_commitment_temporary = (
            ack_commitment_temporaries[0]
            if ack_commitment_temporaries
            else None
        )
        if ack_commitment is not None and ack_commitment.phase == "initializing":
            self._ack_journal_state = "bootstrap"
        elif ack_journal_identity is None and ack_commitment is None:
            self._ack_journal_state = "fresh"
        else:
            self._ack_journal_state = "present"
        return (
            _RecoveryPlan(
                promotions=tuple(promotions),
                delete_private_temporaries=tuple(private_temporaries),
                delete_manifest_temporaries=tuple(manifest_temporaries),
                delete_root_temporaries=tuple(root_temporaries),
                head_raw=head_raw,
            ),
            manifested_open,
        )

    @staticmethod
    def _order_manifest_chain(
        manifests: list[SegmentManifestV1],
    ) -> list[SegmentManifestV1]:
        if not manifests:
            return []
        by_previous: dict[str, SegmentManifestV1] = {}
        for manifest in manifests:
            if manifest.previous_manifest_sha256 in by_previous:
                raise EvidenceCorrupt("manifest chain fork detected")
            by_previous[manifest.previous_manifest_sha256] = manifest
        ordered: list[SegmentManifestV1] = []
        cursor = GENESIS_MANIFEST_SHA256
        seen: set[str] = set()
        while cursor in by_previous:
            manifest = by_previous[cursor]
            if manifest.manifest_sha256 in seen:
                raise EvidenceCorrupt("manifest chain cycle detected")
            ordered.append(manifest)
            seen.add(manifest.manifest_sha256)
            cursor = manifest.manifest_sha256
        if len(ordered) != len(manifests):
            raise EvidenceCorrupt("manifest chain is disconnected or lacks genesis")
        return ordered

    def _scan_chain_head(self) -> bytes | None:
        head_name = "chain-head.json"
        head_path = self.root / head_name
        if not self._manifests:
            if _entry_stat_at(self._root_descriptor, head_name) is not None:
                raise EvidenceCorrupt("chain head exists without manifests")
            self._chain_head = None
            return None
        expected = chain_head_for(self._manifests[-1])
        if _entry_stat_at(self._root_descriptor, head_name) is None:
            self._chain_head = expected
            return canonical_json(expected)
        raw = _read_regular_at(
            self._root_descriptor,
            head_name,
            head_path,
            MAX_CONTRACT_FILE_BYTES,
        )
        actual = decode_strict(
            raw,
            SegmentChainHeadV1,
            MAX_CONTRACT_FILE_BYTES,
        )
        if raw != canonical_json(actual):
            raise EvidenceCorrupt("chain-head cache is not canonical JSON")
        if actual == expected:
            self._chain_head = actual
            return None
        immediate_prior = (
            len(self._manifests) >= 2
            and actual == chain_head_for(self._manifests[-2])
        )
        if not immediate_prior:
            raise EvidenceCorrupt("chain-head cache references unknown or conflicting facts")
        self._chain_head = expected
        return canonical_json(expected)

    def _scan_unsettled_open(
        self,
        manifested_open: set[tuple[str, str]],
    ) -> tuple[tuple[str, str], ...]:
        open_entries: list[tuple[str, str]] = []
        for date_name in sorted(os.listdir(self._segments_descriptor)):
            date_descriptor = self._date_descriptor(date_name)
            for name in sorted(os.listdir(date_descriptor)):
                if name.endswith(".open") and (date_name, name) not in manifested_open:
                    open_entries.append((date_name, name))
        if len(open_entries) > 1:
            raise EvidenceCorrupt("multiple active evidence segments exist")
        if not open_entries:
            return ()
        date_name, open_name = open_entries[0]
        path = self._segments_path / date_name / open_name
        match = _OPEN_NAME.fullmatch(open_name)
        if match is None:
            raise EvidenceCorrupt("active segment filename is not canonical")
        date_descriptor = self._date_descriptor(date_name)
        scan = self._read_segment(
            date_descriptor,
            open_name,
            path,
            allow_torn=True,
        )
        if scan.size == 0:
            raise EvidenceCorrupt("zero-byte active segment is impossible")
        if scan.torn_verified is not None:
            raise TornTailRepairRequired(path, scan.torn_verified, scan.size)
        records = list(scan.records)
        frames = list(scan.frames)
        if not records or not frames:
            raise EvidenceCorrupt("empty active segment cannot establish facts")
        priorities = {record.priority for record in records}
        hosts = {str(record.envelope["host_id"]) for record in records}
        if len(priorities) != 1 or len(hosts) != 1:
            raise EvidenceCorrupt("active segment mixes host or priority")
        if int(match.group("sequence")) != records[0].ref.source_sequence:
            raise EvidenceCorrupt("active filename first sequence mismatch")
        if records[0].accepted_at[:10] != date_name:
            raise EvidenceCorrupt("active segment date differs from opened_at UTC date")
        segment_id = match.group("segment")
        closed_name = open_name.removesuffix(".open") + ".agseg"
        closed_relative = f"segments/{date_name}/{closed_name}"
        rebuilt: list[StoredEvidenceRecord] = []
        for record, frame in zip(records, frames, strict=True):
            ref = replace_ref(
                record.ref,
                segment_id=segment_id,
                segment_relative_path=closed_relative,
                frame=frame,
            )
            rebuilt.append(
                StoredEvidenceRecord(
                    envelope=record.envelope,
                    canonical_envelope=record.canonical_envelope,
                    priority=record.priority,
                    accepted_at=record.accepted_at,
                    ref=ref,
                )
            )
        self._add_records(rebuilt)
        descriptor = -1
        if self._read_only_reason is None:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(open_name, flags, dir_fd=date_descriptor)
            try:
                _bind_held_source(
                    date_descriptor,
                    open_name,
                    path,
                    descriptor=descriptor,
                    identity=scan.identity,
                )
            except BaseException:
                os.close(descriptor)
                raise
        self._active = _ActiveSegment(
            segment_id=segment_id,
            open_path=path,
            open_name=open_name,
            closed_name=closed_name,
            closed_relative_path=closed_relative,
            directory_descriptor=date_descriptor,
            priority=records[0].priority,
            host_id=str(records[0].envelope["host_id"]),
            first_source_sequence=records[0].ref.source_sequence,
            opened_at=records[0].accepted_at,
            opened_monotonic=self._monotonic() - MAX_SEGMENT_AGE_SECONDS,
            descriptor=descriptor,
            size=scan.size,
            record_count=len(records),
            previous_frame_hash=frames[-1].record_hash,
        )
        return ()

    def _apply_recovery_plan(self, plan: _RecoveryPlan) -> None:
        for promotion in plan.promotions:
            date_descriptor = self._date_descriptor(promotion.date_name)
            try:
                _promote_authenticated_source(
                    date_descriptor,
                    promotion.open_name,
                    promotion.closed_name,
                    self._segments_path
                    / promotion.date_name
                    / promotion.closed_name,
                    identity=promotion.identity,
                    expected_sha256=promotion.sha256,
                )
            except FileExistsError as error:
                raise EvidenceCorrupt(
                    "segment recovery promotion target already exists"
                ) from error
        if plan.head_raw is not None:
            _atomic_replace_at(
                self._root_descriptor,
                "chain-head.json",
                self.root / "chain-head.json",
                plan.head_raw,
            )
        for date_name, name in plan.delete_private_temporaries:
            os.unlink(name, dir_fd=self._date_descriptor(date_name))
            os.fsync(self._date_descriptor(date_name))
        for name in plan.delete_manifest_temporaries:
            os.unlink(name, dir_fd=self._manifests_descriptor)
        if plan.delete_manifest_temporaries:
            os.fsync(self._manifests_descriptor)
        for name in plan.delete_root_temporaries:
            os.unlink(name, dir_fd=self._root_descriptor)
        if plan.delete_root_temporaries:
            os.fsync(self._root_descriptor)

    def _read_segment(
        self,
        parent_descriptor: int,
        name: str,
        path: Path,
        *,
        allow_torn: bool,
    ) -> _SegmentScan:
        descriptor, expected = _open_regular_at(
            parent_descriptor,
            name,
            path,
            maximum=MAX_SEGMENT_BYTES,
        )
        frames: list[FrameRecord] = []
        torn_verified: int | None = None
        digest = ""
        total = 0
        after: os.stat_result | None = None
        try:
            with os.fdopen(
                descriptor,
                "rb",
                buffering=0,
                closefd=True,
            ) as stream:
                hashing_stream = _HashingReader(
                    cast(BinaryIO, stream),
                    maximum=MAX_SEGMENT_BYTES,
                    expected_size=expected.st_size,
                )
                try:
                    frames.extend(
                        iter_frames(
                            cast(BinaryIO, hashing_stream),
                            max_frame=MAX_EVIDENCE_RECORD_BYTES,
                        )
                    )
                except TornTail as error:
                    if not allow_torn:
                        raise EvidenceCorrupt("closed segment has a torn frame") from error
                    torn_verified = error.verified_bytes
                digest = hashing_stream.hexdigest()
                total = hashing_stream.total
                after = os.fstat(stream.fileno())
        except JournalCorrupt as error:
            raise EvidenceCorrupt("complete AGF1 frame is corrupt") from error
        if total != expected.st_size:
            raise EvidenceCorrupt("segment size changed during streaming verification")
        current = _regular_stat_at(parent_descriptor, name, path)
        assert after is not None
        if after.st_size > MAX_SEGMENT_BYTES or current.st_size > MAX_SEGMENT_BYTES:
            raise EvidenceCorrupt("segment growth exceeded cumulative scan bound")
        identity = _file_identity(expected)
        if _file_identity(after) != identity or _file_identity(current) != identity:
            raise EvidenceCorrupt("segment changed during held-descriptor verification")
        records: list[StoredEvidenceRecord] = []
        for frame in frames:
            try:
                value = decode_strict(
                    frame.payload,
                    _AcceptedEnvelopeRecordV1,
                    MAX_EVIDENCE_RECORD_BYTES,
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise EvidenceCorrupt("evidence frame payload is invalid") from error
            if frame.payload != canonical_json(value):
                raise EvidenceCorrupt("evidence frame payload is not canonical JSON")
            canonical_envelope = canonical_json(value.envelope)
            records.append(
                StoredEvidenceRecord(
                    envelope=value.envelope,
                    canonical_envelope=canonical_envelope,
                    priority=EvidencePriority(value.evidence_priority),
                    accepted_at=value.accepted_at,
                    ref=EvidenceRef(
                        segment_id="00000000-0000-4000-8000-000000000000",
                        segment_relative_path="",
                        frame_offset=frame.offset,
                        frame_size=frame.size,
                        frame_sha256=frame.record_hash.hex(),
                        event_id=value.outer.event_id,
                        source_sequence=value.outer.sequence,
                        content_sha256=value.outer.content_sha256,
                    ),
                )
            )
        return _SegmentScan(
            records=tuple(records),
            frames=tuple(frames),
            torn_verified=torn_verified,
            size=total,
            sha256=digest,
            identity=identity,
        )

    def _verify_segment_against_manifest(
        self,
        parent_descriptor: int,
        name: str,
        path: Path,
        manifest: SegmentManifestV1,
    ) -> _SegmentScan:
        scan = self._read_segment(
            parent_descriptor,
            name,
            path,
            allow_torn=False,
        )
        records = list(scan.records)
        frames = list(scan.frames)
        if scan.torn_verified is not None or not records or not frames:
            raise EvidenceCorrupt("settled segment is empty or torn")
        priorities = {record.priority.value for record in records}
        hosts = {str(record.envelope["host_id"]) for record in records}
        logical_name = (
            name.removesuffix(".open") + ".agseg"
            if name.endswith(".open")
            else name
        )
        logical_path = path.with_name(logical_name)
        facts_match = (
            len(priorities) == 1
            and priorities == {manifest.evidence_priority}
            and hosts == {manifest.host_id}
            and len(records) == manifest.record_count
            and scan.size == manifest.segment_size_bytes
            and scan.sha256 == manifest.segment_sha256
            and records[0].ref.event_id == manifest.first_event_id
            and records[-1].ref.event_id == manifest.last_event_id
            and records[0].ref.source_sequence == manifest.first_source_sequence
            and records[-1].ref.source_sequence == manifest.last_source_sequence
            and frames[0].record_hash.hex() == manifest.first_frame_sha256
            and frames[-1].record_hash.hex() == manifest.last_frame_sha256
            and logical_path.relative_to(self.root).as_posix()
            == manifest.segment_relative_path
        )
        if not facts_match:
            raise EvidenceCorrupt("segment facts do not match immutable manifest")
        rebuilt: list[StoredEvidenceRecord] = []
        for record, frame in zip(records, frames, strict=True):
            ref = replace_ref(
                record.ref,
                segment_id=manifest.segment_id,
                segment_relative_path=manifest.segment_relative_path,
                frame=frame,
            )
            rebuilt.append(
                StoredEvidenceRecord(
                    envelope=record.envelope,
                    canonical_envelope=record.canonical_envelope,
                    priority=record.priority,
                    accepted_at=record.accepted_at,
                    ref=ref,
                )
            )
        return _SegmentScan(
            records=tuple(rebuilt),
            frames=scan.frames,
            torn_verified=None,
            size=scan.size,
            sha256=scan.sha256,
            identity=scan.identity,
        )

    def _add_records(self, records: list[StoredEvidenceRecord]) -> None:
        for record in records:
            host_id = str(record.envelope["host_id"])
            key = (host_id, record.ref.source_sequence)
            prior = self._index.get(key)
            if prior is not None:
                if prior[0] != record.canonical_envelope:
                    raise EvidenceCorrupt("stored same-sequence evidence conflict")
                raise EvidenceCorrupt("stored duplicate evidence frame")
            prior_sequence = self._last_sequence_by_host.get(host_id, 0)
            if record.ref.source_sequence <= prior_sequence:
                raise EvidenceCorrupt("stored evidence is not in host-global sequence order")
            self._record_positions[key] = len(self._records)
            self._sequences_by_host.setdefault(host_id, []).append(
                record.ref.source_sequence
            )
            self._index[key] = (record.canonical_envelope, record.ref)
            self._last_sequence_by_host[host_id] = record.ref.source_sequence
            self._records.append(record)

    def _bind_empty(self, verifier: EnvelopeVerifier) -> None:
        if self._closed:
            raise EvidenceStoreError("evidence store is closed")
        if self._bound_verifier is not None or self._authority_state != "unbound":
            raise EvidenceSealError("evidence store already has verifier authority")
        if (
            self._records
            or self._manifests
            or self._chain_head is not None
            or self._active is not None
        ):
            raise EvidenceReadOnly(
                "nonempty evidence requires authenticated open-and-recover"
            )
        try:
            verifier._bind_lifecycle(self._lifecycle_identity)
        except VerifierCommitError as error:
            raise EvidenceSealError("verifier belongs to another store lifecycle") from error
        self._bound_verifier = verifier
        self._authority_state = "ready"

    def _bind_and_recover(self, verifier: EnvelopeVerifier) -> None:
        if self._closed:
            raise EvidenceStoreError("evidence store is closed")
        if self._bound_verifier is not None or self._authority_state != "unbound":
            raise EvidenceSealError("evidence store already has verifier authority")
        try:
            verifier._bind_lifecycle(self._lifecycle_identity)
        except VerifierCommitError as error:
            raise EvidenceSealError("verifier belongs to another store lifecycle") from error
        self._bound_verifier = verifier
        self._authority_state = "recovering"
        try:
            for record in self.iter_records():
                ref = record.ref
                verified = verifier.verify(
                    record.envelope,
                    sequence=ref.source_sequence,
                    event_id=ref.event_id,
                    content_sha256=ref.content_sha256,
                )
                authorization = verifier._authorize_append(
                    verified,
                    self._lifecycle_identity,
                    record.priority.value,
                )
                if authorization.canonical != record.canonical_envelope:
                    raise EvidenceCorrupt("replay canonical bytes changed")
                verifier._commit_durable(
                    authorization,
                    self._lifecycle_identity,
                    ref,
                )
        except (EvidenceCorrupt, IngestVerificationError, VerifierCommitError):
            self._trip_read_only("segment_corrupt")
            raise
        self._authority_state = "ready"

    def append(
        self,
        envelope: VerifiedEnvelope,
        priority: EvidencePriority,
    ) -> EvidenceRef:
        if self._closed:
            raise EvidenceStoreError("evidence store is closed")
        verifier = self._bound_verifier
        if verifier is None or self._authority_state != "ready":
            raise EvidenceSealError(
                "append requires one factory-bound recovered verifier lifecycle"
            )
        if self._read_only_reason is not None:
            raise EvidenceReadOnly(
                f"evidence root is read-only: {self._read_only_reason}"
            )
        if self._append_uncertain:
            raise EvidenceReadOnly("prior evidence append has uncertain durability")
        if not isinstance(priority, EvidencePriority):
            raise EvidenceSealError("evidence priority must be verifier-derived")
        pending = self._pending_durable_commit
        if pending is not None:
            presented = (
                getattr(envelope, "canonical", None),
                getattr(envelope, "content_sha256", None),
                getattr(envelope, "event_id", None),
                getattr(envelope, "evidence_priority", None),
                getattr(envelope, "source_sequence", None),
                priority.value,
            )
            expected = (
                pending.canonical,
                pending.content_sha256,
                pending.event_id,
                pending.evidence_priority,
                pending.source_sequence,
                pending.evidence_priority,
            )
            if presented != expected:
                raise EvidenceReadOnly(
                    "exact durable verifier commit must be repaired before append"
                )
            try:
                authorization = verifier._authorize_append(
                    envelope,
                    self._lifecycle_identity,
                    priority.value,
                )
            except (AttributeError, TypeError, VerifierCommitError) as error:
                raise EvidenceSealError(
                    "pending commit requires one exact verifier-staged envelope"
                ) from error
            if (
                authorization.canonical != pending.canonical
                or authorization.content_sha256 != pending.content_sha256
                or authorization.event_id != pending.event_id
                or authorization.evidence_priority != pending.evidence_priority
                or authorization.host_id != pending.host_id
                or authorization.source_sequence != pending.source_sequence
                or self._index.get((pending.host_id, pending.source_sequence))
                != (pending.canonical, pending.ref)
            ):
                raise EvidenceReadOnly(
                    "pending durable commit no longer matches exact stored facts"
                )
            verifier._commit_durable(
                authorization,
                self._lifecycle_identity,
                pending.ref,
            )
            self._pending_durable_commit = None
            return pending.ref
        try:
            authorization = verifier._authorize_append(
                envelope,
                self._lifecycle_identity,
                priority.value,
            )
        except (AttributeError, TypeError, VerifierCommitError) as error:
            raise EvidenceSealError(
                "SegmentStore accepts one exact verifier-staged envelope only"
            ) from error
        if self.fail_next_append is not None:
            failure = self.fail_next_append
            self.fail_next_append = None
            raise failure
        host_id = authorization.host_id
        key = (host_id, authorization.source_sequence)
        prior = self._index.get(key)
        if prior is not None:
            if prior[0] == authorization.canonical:
                verifier._commit_durable(
                    authorization,
                    self._lifecycle_identity,
                    prior[1],
                )
                return prior[1]
            self._trip_read_only("segment_corrupt")
            raise EvidenceConflict("different canonical evidence reused a host sequence")
        if authorization.source_sequence <= self._last_sequence_by_host.get(host_id, 0):
            self._trip_read_only("segment_corrupt")
            raise EvidenceConflict("sealed evidence is not in host-global sequence order")
        try:
            envelope_value = EventEnvelopeV1.model_validate_json(
                authorization.canonical,
                strict=True,
            )
        except ValidationError as error:
            raise EvidenceSealError("authorized canonical envelope no longer decodes") from error
        accepted_at = _utc_timestamp(self._wall_clock())
        payload = canonical_json(
            {
                "schema_version": "agmind.accepted-envelope.v1",
                "evidence_priority": priority.value,
                "accepted_at": accepted_at,
                "outer": {
                    "sequence": authorization.source_sequence,
                    "event_id": authorization.event_id,
                    "content_sha256": authorization.content_sha256,
                },
                "envelope": envelope_value.model_dump(exclude_none=True),
            }
        )
        if len(payload) > MAX_EVIDENCE_RECORD_BYTES:
            raise EvidenceStoreError("canonical evidence record exceeds frame bound")
        if self._must_rotate(authorization, priority, len(payload)):
            self.flush_security_boundary()
        if self._active is None:
            try:
                active, frame = self._create_active_with_first_frame(
                    authorization,
                    priority,
                    accepted_at,
                    payload,
                )
            except EvidenceCorrupt:
                self._trip_read_only("segment_corrupt")
                raise
            offset = 0
        else:
            active = self._active
            frame = encode_frame(
                payload,
                previous_hash=active.previous_frame_hash,
                max_frame=MAX_EVIDENCE_RECORD_BYTES,
            )
            offset = active.size
            try:
                _full_write(active.descriptor, frame)
                os.fsync(active.descriptor)
            except BaseException:
                self._append_uncertain = True
                os.close(active.descriptor)
                active.descriptor = -1
                raise
            active.size += len(frame)
            active.record_count += 1
            active.previous_frame_hash = frame[-32:]
        ref = EvidenceRef(
            segment_id=active.segment_id,
            segment_relative_path=active.closed_relative_path,
            frame_offset=offset,
            frame_size=len(frame),
            frame_sha256=frame[-32:].hex(),
            event_id=authorization.event_id,
            source_sequence=authorization.source_sequence,
            content_sha256=authorization.content_sha256,
        )
        record = StoredEvidenceRecord(
            envelope=envelope_value.model_dump(exclude_none=True),
            canonical_envelope=authorization.canonical,
            priority=priority,
            accepted_at=accepted_at,
            ref=ref,
        )
        self._record_positions[key] = len(self._records)
        self._sequences_by_host.setdefault(host_id, []).append(
            authorization.source_sequence
        )
        self._index[key] = (authorization.canonical, ref)
        self._last_sequence_by_host[host_id] = authorization.source_sequence
        self._records.append(record)
        self._pending_durable_commit = _PendingDurableCommit(
            canonical=authorization.canonical,
            content_sha256=authorization.content_sha256,
            event_id=authorization.event_id,
            evidence_priority=authorization.evidence_priority,
            host_id=authorization.host_id,
            source_sequence=authorization.source_sequence,
            ref=ref,
        )
        verifier._commit_durable(
            authorization,
            self._lifecycle_identity,
            ref,
        )
        self._pending_durable_commit = None
        return ref

    def _must_rotate(
        self,
        envelope: _AppendAuthorization,
        priority: EvidencePriority,
        payload_size: int,
    ) -> bool:
        active = self._active
        if active is None:
            return False
        projected_frame = payload_size + 76
        return (
            active.priority != priority
            or active.host_id != envelope.host_id
            or active.size + projected_frame > MAX_SEGMENT_BYTES
            or self._monotonic() - active.opened_monotonic >= MAX_SEGMENT_AGE_SECONDS
        )

    def _create_active_with_first_frame(
        self,
        envelope: _AppendAuthorization,
        priority: EvidencePriority,
        accepted_at: str,
        payload: bytes,
    ) -> tuple[_ActiveSegment, bytes]:
        opened_at = datetime.fromisoformat(accepted_at)
        date_name = opened_at.date().isoformat()
        date_path = self._segments_path / date_name
        date_descriptor = self._date_descriptor(date_name, create=True)
        segment_id = str(uuid.uuid4())
        basename = f"{envelope.source_sequence:020d}-{segment_id}"
        open_name = f"{basename}.open"
        closed_name = f"{basename}.agseg"
        temporary_name = (
            f".agmind-create-{envelope.source_sequence:020d}-{segment_id}.tmp"
        )
        open_path = date_path / open_name
        frame = encode_frame(
            payload,
            previous_hash=bytes(32),
            max_frame=MAX_EVIDENCE_RECORD_BYTES,
        )
        frame_sha256 = hashlib.sha256(frame).hexdigest()
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_APPEND
            | os.O_CLOEXEC
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        published = False
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=date_descriptor,
            )
            self._segment_create_step_hook("create")
            os.fchmod(descriptor, 0o600)
            _full_write(descriptor, frame)
            self._segment_create_step_hook("write")
            os.fsync(descriptor)
            self._segment_create_step_hook("file_fsync")
            self._segment_create_step_hook("before_publish")
            identity = _file_identity(os.fstat(descriptor))
            with _post_authentication_namespace(open_path):
                _bind_held_source(
                    date_descriptor,
                    temporary_name,
                    open_path,
                    descriptor=descriptor,
                    identity=identity,
                )
                _rename_noreplace(
                    temporary_name,
                    open_name,
                    source_dir_fd=date_descriptor,
                    destination_dir_fd=date_descriptor,
                )
            published = True
            self._segment_create_step_hook("publish")
            with _post_authentication_namespace(open_path):
                _validate_published_from_held(
                    date_descriptor,
                    open_name,
                    open_path,
                    descriptor=descriptor,
                    identity=identity,
                    expected_sha256=frame_sha256,
                )
                os.fsync(date_descriptor)
        except BaseException:
            _cleanup_private_publication(
                date_descriptor,
                None if published else temporary_name,
                open_path,
                descriptor=descriptor,
                preserve_primary=True,
            )
            if published:
                self._append_uncertain = True
            raise
        closed_relative = f"segments/{date_name}/{closed_name}"
        active = _ActiveSegment(
            segment_id=segment_id,
            open_path=open_path,
            open_name=open_name,
            closed_name=closed_name,
            closed_relative_path=closed_relative,
            directory_descriptor=date_descriptor,
            priority=priority,
            host_id=envelope.host_id,
            first_source_sequence=envelope.source_sequence,
            opened_at=accepted_at,
            opened_monotonic=self._monotonic(),
            descriptor=descriptor,
            size=len(frame),
            record_count=1,
            previous_frame_hash=frame[-32:],
        )
        self._active = active
        return active, frame

    def flush_security_boundary(self) -> None:
        if self._read_only_reason is not None:
            raise EvidenceReadOnly(
                f"evidence root is read-only: {self._read_only_reason}"
            )
        if self._pending_durable_commit is not None:
            raise EvidenceReadOnly(
                "pending durable verifier commit must be repaired before flush"
            )
        active = self._active
        if active is None:
            return
        if self._append_uncertain or active.descriptor < 0:
            raise EvidenceReadOnly("uncertain active tail cannot be settled automatically")
        if active.record_count == 0:
            raise EvidenceStoreError("cannot settle an empty active segment")
        os.fsync(active.descriptor)
        os.close(active.descriptor)
        active.descriptor = -1
        try:
            scan = self._read_segment(
                active.directory_descriptor,
                active.open_name,
                active.open_path,
                allow_torn=False,
            )
            records = list(scan.records)
            frames = list(scan.frames)
            if (
                scan.torn_verified is not None
                or not records
                or not frames
                or len(records) != active.record_count
                or scan.size != active.size
                or frames[-1].record_hash != active.previous_frame_hash
                or records[0].ref.source_sequence != active.first_source_sequence
                or {record.priority for record in records} != {active.priority}
                or {str(record.envelope["host_id"]) for record in records}
                != {active.host_id}
            ):
                raise EvidenceCorrupt("active segment facts changed before close")
        except (EvidenceCorrupt, JournalCorrupt, OSError, ValidationError, ValueError):
            self._trip_read_only("segment_corrupt")
            raise
        closed_at = _utc_timestamp(self._wall_clock())
        previous_hash = (
            self._manifests[-1].manifest_sha256
            if self._manifests
            else GENESIS_MANIFEST_SHA256
        )
        document: dict[str, object] = {
            "schema_version": "agmind.segment-manifest.v1",
            "segment_id": active.segment_id,
            "segment_relative_path": active.closed_relative_path,
            "host_id": active.host_id,
            "evidence_priority": active.priority.value,
            "first_event_id": records[0].ref.event_id,
            "last_event_id": records[-1].ref.event_id,
            "first_source_sequence": records[0].ref.source_sequence,
            "last_source_sequence": records[-1].ref.source_sequence,
            "record_count": len(records),
            "opened_at": active.opened_at,
            "closed_at": closed_at,
            "segment_size_bytes": scan.size,
            "segment_sha256": scan.sha256,
            "first_frame_sha256": frames[0].record_hash.hex(),
            "last_frame_sha256": frames[-1].record_hash.hex(),
            "previous_manifest_sha256": previous_hash,
        }
        document["manifest_sha256"] = segment_manifest_hash(document)
        manifest = SegmentManifestV1.model_validate(document, strict=True)
        manifest_name = f"{active.segment_id}.json"
        manifest_path = self._manifests_path / manifest_name
        try:
            _publish_without_replacement_at(
                self._manifests_descriptor,
                manifest_name,
                manifest_path,
                canonical_json(manifest),
            )
            _promote_authenticated_source(
                active.directory_descriptor,
                active.open_name,
                active.closed_name,
                self.root / active.closed_relative_path,
                identity=scan.identity,
                expected_sha256=scan.sha256,
            )
        except FileExistsError as error:
            self._trip_read_only("segment_corrupt")
            raise EvidenceCorrupt(
                "immutable close destination already exists"
            ) from error
        except EvidenceCorrupt:
            self._trip_read_only("segment_corrupt")
            raise
        head = chain_head_for(manifest)
        try:
            _atomic_replace_at(
                self._root_descriptor,
                "chain-head.json",
                self.root / "chain-head.json",
                canonical_json(head),
            )
        except EvidenceCorrupt:
            self._trip_read_only("segment_corrupt")
            raise
        self._manifests.append(manifest)
        self._chain_head = head
        self._active = None

    def iter_records(self) -> Iterator[StoredEvidenceRecord]:
        for record in tuple(self._records):
            yield StoredEvidenceRecord(
                envelope=copy.deepcopy(record.envelope),
                canonical_envelope=record.canonical_envelope,
                priority=record.priority,
                accepted_at=record.accepted_at,
                ref=record.ref,
            )

    def close(self, *, flush: bool = True) -> None:
        if self._closed:
            return
        try:
            if (
                flush
                and self._active is not None
                and self._read_only_reason is None
                and not self._append_uncertain
                and self._pending_durable_commit is None
            ):
                self.flush_security_boundary()
            elif self._active is not None and self._active.descriptor >= 0:
                os.close(self._active.descriptor)
                self._active.descriptor = -1
        finally:
            try:
                try:
                    coverage_close_error: BaseException | None = None
                    coverage_owner = self._coverage_state_owner
                    if coverage_owner is not None:
                        try:
                            close_from_store = getattr(
                                coverage_owner,
                                "_close_from_segment_store",
                                None,
                            )
                            if not callable(close_from_store):
                                raise EvidenceStoreError(
                                    "coverage-state owner cannot close "
                                    "before evidence unlock"
                                )
                            cast(Callable[[object], None], close_from_store)(
                                self._lifecycle_identity
                            )
                        except BaseException as error:  # noqa: BLE001
                            coverage_close_error = error
                    if self._coverage_state_owner is not None:
                        self._coverage_state_owner = None
                        survivor_error = EvidenceStoreError(
                            "coverage-state owner survived evidence shutdown"
                        )
                        if coverage_close_error is not None:
                            raise survivor_error from coverage_close_error
                        raise survivor_error
                    if coverage_close_error is not None:
                        raise coverage_close_error
                finally:
                    owner = self._ack_journal_owner
                    if owner is not None:
                        close_from_store = getattr(
                            owner,
                            "_close_from_segment_store",
                            None,
                        )
                        if not callable(close_from_store):
                            raise EvidenceStoreError(
                                "ACK-journal owner cannot close before evidence unlock"
                            )
                        cast(Callable[[object], None], close_from_store)(
                            self._lifecycle_identity
                        )
                    if self._ack_journal_owner is not None:
                        raise EvidenceStoreError(
                            "ACK-journal owner survived evidence shutdown"
                        )
                    self._fence_missing_expected_ack_journal()
            finally:
                for descriptor in self._date_descriptors.values():
                    os.close(descriptor)
                os.close(self._manifests_descriptor)
                os.close(self._segments_descriptor)
                fcntl.flock(self._root_descriptor, fcntl.LOCK_UN)
                os.close(self._root_descriptor)
                self._closed = True


def replace_ref(
    ref: EvidenceRef,
    *,
    segment_id: str,
    segment_relative_path: str,
    frame: FrameRecord,
) -> EvidenceRef:
    return EvidenceRef(
        segment_id=segment_id,
        segment_relative_path=segment_relative_path,
        frame_offset=frame.offset,
        frame_size=frame.size,
        frame_sha256=frame.record_hash.hex(),
        event_id=ref.event_id,
        source_sequence=ref.source_sequence,
        content_sha256=ref.content_sha256,
    )
