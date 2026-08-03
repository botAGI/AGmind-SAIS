"""Durable Core correlation-request phases bound to one evidence lifecycle."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import weakref
from _thread import LockType
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Lock
from typing import (
    BinaryIO,
    Literal,
    Never,
    Protocol,
    Self,
    SupportsIndex,
    cast,
    final,
)

from pydantic import ConfigDict, ValidationError, field_validator, model_validator

from agmind_immune.canonicaljson import (
    canonical_json,
    pcc_correlation_request_sha256,
)
from agmind_immune.contracts import (
    MAX_UINT64,
    ContractModel,
    PCCCorrelationSnapshotRequestV1,
    PCCCorrelationSnapshotV1,
    decode_strict,
)
from agmind_immune.evidence.frames import (
    FrameRecord,
    JournalCorrupt,
    TornTail,
    encode_frame,
    iter_frames,
)
from agmind_immune.evidence.segments import (
    EvidenceCorrupt,
    EvidenceRef,
    EvidenceSealError,
    SegmentStore,
    _AckAuthorityError,
    _CorrelationJournalLifecycleCorrupt,
    _CorrelationJournalLifecycleIoUncertain,
    _CorrelationJournalLifecycleStateError,
    _exact_coverage_ref_key,
    _full_write,
)
from agmind_immune.ingest.envelope import (
    AuthenticatedPCCInput,
    authenticated_pcc_input_is_issued,
)

_JOURNAL_NAME = "correlation-requests.agf"
_MAX_RECORDS = 12_291
_MAX_VERIFIED_BYTES = 16 * 1024 * 1024
_MAX_FRAME_PAYLOAD = 64 * 1024
_MAX_COMPLETED_BATCH = 4_096
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_PREFIX = "pcc_correlation_snapshot:"


class _DigestState(Protocol):
    def update(self, value: bytes, /) -> None: ...

    def digest(self) -> bytes: ...

    def copy(self) -> _DigestState: ...


class CorrelationRequestJournalError(RuntimeError):
    """Base class for durable correlation-request failures."""


class CorrelationRequestJournalCorrupt(CorrelationRequestJournalError):
    """The journal, its chain, or its evidence-root binding is corrupt."""


class CorrelationRequestJournalStateError(CorrelationRequestJournalError):
    """A caller requested an illegal or conflicting phase transition."""


class CorrelationRequestJournalAuthorityError(CorrelationRequestJournalError):
    """A caller supplied evidence outside this journal's store authority."""


class CorrelationRequestJournalUnhealthy(CorrelationRequestJournalError):
    """A prior write has ambiguous durability and requires restart recovery."""


class _CorrelationRequestStateV1(ContractModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal["agmind.correlation-request-state.v1"]
    operation_key: str
    request_sha256: str
    request: PCCCorrelationSnapshotRequestV1
    phase: Literal["selected", "proof_observed", "completed"]
    snapshot_event_id: str | None = None
    snapshot_content_sha256: str | None = None

    @field_validator("request_sha256", "snapshot_content_sha256")
    @classmethod
    def digest_is_exact(cls, value: str | None) -> str | None:
        if value is not None and not _HEX64.fullmatch(value):
            raise ValueError("correlation-request digest is invalid")
        return value

    @field_validator("snapshot_event_id")
    @classmethod
    def snapshot_event_is_exact(cls, value: str | None) -> str | None:
        if value is not None and not _EVENT_ID.fullmatch(value):
            raise ValueError("correlation snapshot event ID is invalid")
        return value

    @model_validator(mode="after")
    def bindings_and_phase_shape_are_exact(self) -> _CorrelationRequestStateV1:
        request = self.request
        expected_operation = _operation_key(request.trigger_event_id)
        if self.operation_key != expected_operation:
            raise ValueError("operation_key does not bind the exact trigger")
        if request.requested_ttl_seconds != 120:
            raise ValueError("correlation request TTL must be exactly 120 seconds")
        if self.request_sha256 != pcc_correlation_request_sha256(request):
            raise ValueError("request_sha256 does not bind the exact request")

        snapshot_fields = {
            "snapshot_event_id",
            "snapshot_content_sha256",
        }
        if self.phase == "selected":
            if (
                self.snapshot_event_id is not None
                or self.snapshot_content_sha256 is not None
                or bool(snapshot_fields & self.model_fields_set)
            ):
                raise ValueError("selected phase must omit snapshot identity")
        elif (
            self.snapshot_event_id is None
            or self.snapshot_content_sha256 is None
            or not snapshot_fields.issubset(self.model_fields_set)
        ):
            raise ValueError("observed phases require the complete snapshot identity")
        return self


def _operation_key(trigger_event_id: str) -> str:
    return f"{_OPERATION_PREFIX}{trigger_event_id}"


def _validate_journal_stat(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise CorrelationRequestJournalCorrupt(
            "unsafe correlation-request journal artifact"
        )


def _same_file(actual: os.stat_result, expected: os.stat_result) -> bool:
    return (
        actual.st_dev == expected.st_dev
        and actual.st_ino == expected.st_ino
        and actual.st_size == expected.st_size
        and actual.st_mode == expected.st_mode
        and actual.st_uid == expected.st_uid
        and actual.st_nlink == expected.st_nlink
        and actual.st_mtime_ns == expected.st_mtime_ns
        and actual.st_ctime_ns == expected.st_ctime_ns
    )


type _SnapshotKey = tuple[str, str]
type _EvidenceRefFingerprint = tuple[str, str, int, int, str, str, int, str]


def _evidence_ref_fingerprint(ref: object) -> _EvidenceRefFingerprint:
    try:
        return _exact_coverage_ref_key(ref)
    except (TypeError, ValueError) as error:
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation authority requires an exact EvidenceRef"
        ) from error


@dataclass(frozen=True, slots=True)
class _AuthenticatedJournalReplay:
    states_by_operation: dict[str, _CorrelationRequestStateV1]
    operation_by_request: dict[str, str]
    operation_by_snapshot: dict[_SnapshotKey, str]
    journal_stat: os.stat_result
    journal_digest: bytes
    journal_size: int
    journal_record_count: int
    journal_chain_head: bytes


@dataclass(frozen=True, slots=True)
class _CompletedPCCReplayFacts:
    ref_key: _EvidenceRefFingerprint
    state_canonical: bytes
    state_fields_set: frozenset[str]
    operation_key: str
    request_sha256: str
    proof_canonical: bytes
    request_canonical: bytes
    request_fields_set: frozenset[str]
    snapshot_canonical: bytes
    snapshot_fields_set: frozenset[str]


@dataclass(frozen=True, slots=True)
class _CorrelationJournalReplaySnapshot:
    journal_lifecycle: object
    store_lifecycle: object
    mutation_revision: object
    verifier_generation: int
    journal_device: int
    journal_inode: int
    journal_size: int
    journal_digest: bytes
    journal_record_count: int
    journal_chain_head: bytes
    completed_facts: tuple[_CompletedPCCReplayFacts, ...]


@dataclass(frozen=True, slots=True)
class _CompletedSnapshotBinding:
    journal: CorrelationRequestJournal
    store: SegmentStore
    journal_lifecycle: object
    store_lifecycle: object
    verifier: object
    verifier_authority: object
    verifier_generation: int
    state_canonical: bytes
    state_fields_set: frozenset[str]
    operation_key: str
    request_sha256: str
    request_canonical: bytes
    request_fields_set: frozenset[str]
    trigger_event_id: str
    trigger_content_sha256: str
    trigger_source_sequence: int
    snapshot_ref: _EvidenceRefFingerprint
    pcc: AuthenticatedPCCInput
    pcc_canonical: bytes
    pcc_request_canonical: bytes
    pcc_request_fields_set: frozenset[str]
    pcc_snapshot_canonical: bytes
    pcc_snapshot_fields_set: frozenset[str]
    journal_states: tuple[tuple[str, bytes, frozenset[str]], ...]
    journal_request_index: tuple[tuple[str, str], ...]
    journal_snapshot_index: tuple[tuple[_SnapshotKey, str], ...]
    journal_stat: os.stat_result
    journal_digest: bytes
    journal_size: int
    journal_record_count: int
    journal_chain_head: bytes
    token: object


@final
class _CompletedSnapshotAuthority:
    """Opaque authority for one exact durable completed PCC delivery."""

    __slots__ = ("__weakref__", "_token")
    _token: object

    def __new__(cls, *args: object, **kwargs: object) -> Self:
        del cls, args, kwargs
        raise TypeError("completed snapshot authorities are factory-only")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("completed snapshot authorities are immutable")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("completed snapshot authorities are final")

    def __copy__(self) -> Never:
        raise TypeError("completed snapshot authorities cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        del memo
        raise TypeError("completed snapshot authorities cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("completed snapshot authorities cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("completed snapshot authorities cannot be serialized")


@dataclass(frozen=True, slots=True)
class _CompletedSnapshotBatchItemFacts:
    fingerprint: _EvidenceRefFingerprint
    state_canonical: bytes
    state_fields_set: frozenset[str]
    operation_key: str
    request_sha256: str
    proof: AuthenticatedPCCInput
    proof_canonical: bytes
    request_canonical: bytes
    request_fields_set: frozenset[str]
    snapshot_canonical: bytes
    snapshot_fields_set: frozenset[str]


@dataclass(frozen=True, slots=True)
class _CompletedSnapshotBatchBinding:
    journal: CorrelationRequestJournal
    store: SegmentStore
    journal_lifecycle: object
    store_lifecycle: object
    verifier: object
    verifier_authority: object
    verifier_generation: int
    mutation_revision: object
    replay: _AuthenticatedJournalReplay
    facts: tuple[_CompletedSnapshotBatchItemFacts, ...]
    token: object


@final
class _CompletedSnapshotBatchAuthority:
    """Opaque shared authority for one exact bounded completed-PCC batch."""

    __slots__ = ("__weakref__", "_token")
    _token: object

    def __new__(cls, *args: object, **kwargs: object) -> Self:
        del cls, args, kwargs
        raise TypeError("completed snapshot batch authorities are factory-only")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("completed snapshot batch authorities are immutable")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("completed snapshot batch authorities are final")


@final
class _CompletedSnapshotBatchItem:
    """Opaque O(1)-checkable item issued from one shared batch anchor."""

    __slots__ = ("__weakref__", "_token")
    _token: object

    def __new__(cls, *args: object, **kwargs: object) -> Self:
        del cls, args, kwargs
        raise TypeError("completed snapshot batch items are factory-only")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("completed snapshot batch items are immutable")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("completed snapshot batch items are final")


class _BoundedReader:
    def __init__(self, stream: BinaryIO, limit: int) -> None:
        self._stream = stream
        self._remaining = limit

    def read(self, size: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if size < 0 or size > self._remaining:
            size = self._remaining
        raw = self._stream.read(size)
        self._remaining -= len(raw)
        return raw


class CorrelationRequestJournal:
    """One sequential correlation-request authority leased from a SegmentStore."""

    _store: SegmentStore
    _root_descriptor: int
    _descriptor: int
    _lifecycle_identity: object
    _previous_hash: bytes
    _states_by_operation: dict[str, _CorrelationRequestStateV1]
    _operation_by_request: dict[str, str]
    _operation_by_snapshot: dict[_SnapshotKey, str]
    _healthy: bool
    _closed: bool
    _closing: bool
    _size: int
    _record_count: int
    _authenticated_stat: os.stat_result | None
    _authenticated_hasher: _DigestState | None
    _mutation_revision: object
    _lock: LockType

    def __init__(self) -> None:
        raise TypeError(
            "use CorrelationRequestJournal.create_new() or open_and_recover()"
        )

    @classmethod
    def create_new(cls, store: SegmentStore) -> CorrelationRequestJournal:
        """Create one absent journal under the store's authenticated root."""
        return cls._open_bound(store, create=True)

    @classmethod
    def open_and_recover(cls, store: SegmentStore) -> CorrelationRequestJournal:
        """Strictly recover one existing complete journal without tail repair."""
        return cls._open_bound(store, create=False)

    @classmethod
    def _open_bound(
        cls,
        store: SegmentStore,
        *,
        create: bool,
    ) -> CorrelationRequestJournal:
        journal = object.__new__(cls)
        journal._store = store
        journal._root_descriptor = -1
        journal._descriptor = -1
        journal._lifecycle_identity = object()
        journal._previous_hash = bytes(32)
        journal._states_by_operation = {}
        journal._operation_by_request = {}
        journal._operation_by_snapshot = {}
        journal._healthy = True
        journal._closed = False
        journal._closing = False
        journal._size = 0
        journal._record_count = 0
        journal._authenticated_stat = None
        journal._authenticated_hasher = None
        journal._mutation_revision = object()
        journal._lock = Lock()
        try:
            root_descriptor, lifecycle_identity = (
                store._acquire_correlation_journal(
                    journal,
                    operation="create" if create else "recover",
                )
            )
            journal._root_descriptor = root_descriptor
            journal._lifecycle_identity = lifecycle_identity
            journal._descriptor = (
                journal._create_new() if create else journal._open_existing()
            )
            journal._recover()
            authenticated = journal._bind_published_or_latch()
            store._complete_correlation_journal_initialization(
                journal,
                lifecycle_identity,
                authenticated,
                journal._authenticated_digest(),
            )
            return journal
        except _CorrelationJournalLifecycleCorrupt as error:
            corrupt = CorrelationRequestJournalCorrupt(str(error))
            journal._healthy = False
            journal._attempt_corruption_fence(corrupt)
            journal._close_after_failed_open(corrupt)
            raise corrupt from error
        except _CorrelationJournalLifecycleStateError as error:
            state_error = CorrelationRequestJournalStateError(str(error))
            journal._close_after_failed_open(state_error)
            raise state_error from error
        except _CorrelationJournalLifecycleIoUncertain as error:
            journal._healthy = False
            journal._attempt_io_uncertain(
                error,
                journal._authenticated_stat,
                journal._authenticated_digest_or_none(),
            )
            journal._close_after_failed_open(error)
            raise
        except CorrelationRequestJournalCorrupt as error:
            journal._healthy = False
            journal._attempt_corruption_fence(error)
            journal._close_after_failed_open(error)
            raise
        except BaseException as error:
            journal._healthy = False
            if (
                getattr(store, "_correlation_journal_owner", None)
                is journal
            ):
                journal._attempt_io_uncertain(
                    error,
                    journal._authenticated_stat,
                    journal._authenticated_digest_or_none(),
                )
            journal._close_after_failed_open(error)
            raise

    def _create_new(self) -> int:
        flags = os.O_RDWR | os.O_APPEND | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                _JOURNAL_NAME,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=self._root_descriptor,
            )
        except FileExistsError as error:
            raise CorrelationRequestJournalCorrupt(
                "correlation-request journal appeared during fresh initialization"
            ) from error
        try:
            self._store._correlation_journal_final_name_created(
                self,
                self._lifecycle_identity,
            )
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            published = os.stat(
                _JOURNAL_NAME,
                dir_fd=self._root_descriptor,
                follow_symlinks=False,
            )
            _validate_journal_stat(opened)
            if not _same_file(opened, published):
                raise CorrelationRequestJournalCorrupt(
                    "created correlation-request journal changed before root sync"
                )
            os.fsync(descriptor)
            os.fsync(self._root_descriptor)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _open_existing(self) -> int:
        flags = os.O_RDWR | os.O_APPEND | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            expected = os.stat(
                _JOURNAL_NAME,
                dir_fd=self._root_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise CorrelationRequestJournalCorrupt(
                "expected correlation-request journal disappeared before recovery"
            ) from error
        _validate_journal_stat(expected)
        try:
            descriptor = os.open(
                _JOURNAL_NAME,
                flags,
                dir_fd=self._root_descriptor,
            )
        except OSError as error:
            raise CorrelationRequestJournalCorrupt(
                "correlation-request journal became unavailable during open"
            ) from error
        try:
            opened = os.fstat(descriptor)
            _validate_journal_stat(opened)
            if not _same_file(opened, expected):
                raise CorrelationRequestJournalCorrupt(
                    "correlation-request journal changed during authenticated open"
                )
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _recover(self) -> None:
        expected = os.fstat(self._descriptor)
        _validate_journal_stat(expected)
        if expected.st_size > _MAX_VERIFIED_BYTES:
            raise CorrelationRequestJournalCorrupt(
                "correlation-request journal exceeds its verified-byte bound"
            )

        read_descriptor = os.dup(self._descriptor)
        try:
            os.set_inheritable(read_descriptor, False)
            os.lseek(read_descriptor, 0, os.SEEK_SET)
            stream = os.fdopen(read_descriptor, "rb", buffering=0, closefd=True)
        except BaseException:
            os.close(read_descriptor)
            raise

        states: dict[str, _CorrelationRequestStateV1] = {}
        request_index: dict[str, str] = {}
        snapshot_index: dict[_SnapshotKey, str] = {}
        previous_hash = bytes(32)
        verified_size = 0
        record_count = 0
        hasher = hashlib.sha256()
        try:
            with stream:
                bounded = _BoundedReader(cast(BinaryIO, stream), expected.st_size)
                try:
                    for frame in iter_frames(
                        cast(BinaryIO, bounded),
                        max_frame=_MAX_FRAME_PAYLOAD,
                    ):
                        record_count += 1
                        if record_count > _MAX_RECORDS:
                            raise CorrelationRequestJournalCorrupt(
                                "correlation-request journal exceeds its record bound"
                            )
                        state = self._decode_frame_state(frame)
                        self._replay_state(
                            state,
                            states,
                            request_index,
                            snapshot_index,
                        )
                        authenticated_frame = encode_frame(
                            frame.payload,
                            previous_hash=frame.previous_hash,
                            max_frame=_MAX_FRAME_PAYLOAD,
                        )
                        if (
                            len(authenticated_frame) != frame.size
                            or authenticated_frame[-32:] != frame.record_hash
                        ):
                            raise CorrelationRequestJournalCorrupt(
                                "verified correlation frame cannot be reconstructed"
                            )
                        hasher.update(authenticated_frame)
                        verified_size += len(authenticated_frame)
                        if verified_size > _MAX_VERIFIED_BYTES:
                            raise CorrelationRequestJournalCorrupt(
                                "verified correlation bytes exceed their bound"
                            )
                        previous_hash = frame.record_hash
                except TornTail as error:
                    raise CorrelationRequestJournalCorrupt(
                        "correlation-request journal has an unproven torn tail"
                    ) from error
        except JournalCorrupt as error:
            raise CorrelationRequestJournalCorrupt(
                "correlation-request frame chain is corrupt"
            ) from error

        published = self._bind_published()
        after = os.fstat(self._descriptor)
        if (
            verified_size != expected.st_size
            or not _same_file(after, expected)
            or not _same_file(published, expected)
        ):
            raise CorrelationRequestJournalCorrupt(
                "correlation-request journal changed during held-descriptor recovery"
            )
        self._states_by_operation = states
        self._operation_by_request = request_index
        self._operation_by_snapshot = snapshot_index
        self._previous_hash = previous_hash
        self._size = verified_size
        self._record_count = record_count
        self._authenticated_stat = published
        self._authenticated_hasher = hasher

    @staticmethod
    def _decode_frame_state(frame: FrameRecord) -> _CorrelationRequestStateV1:
        try:
            state = decode_strict(
                frame.payload,
                _CorrelationRequestStateV1,
                _MAX_FRAME_PAYLOAD,
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise CorrelationRequestJournalCorrupt(
                "correlation-request record schema is invalid"
            ) from error
        if frame.payload != canonical_json(state):
            raise CorrelationRequestJournalCorrupt(
                "correlation-request record is not canonical JSON"
            )
        return state

    @staticmethod
    def _replay_state(
        state: _CorrelationRequestStateV1,
        states: dict[str, _CorrelationRequestStateV1],
        request_index: dict[str, str],
        snapshot_index: dict[_SnapshotKey, str],
    ) -> None:
        existing = states.get(state.operation_key)
        indexed_operation = request_index.get(state.request_sha256)
        if state.phase == "selected":
            if existing is not None or indexed_operation is not None:
                raise CorrelationRequestJournalCorrupt(
                    "correlation-request journal repeats a selection"
                )
            states[state.operation_key] = state
            request_index[state.request_sha256] = state.operation_key
            return
        if (
            existing is None
            or indexed_operation != state.operation_key
            or existing.request_sha256 != state.request_sha256
            or existing.request != state.request
        ):
            raise CorrelationRequestJournalCorrupt(
                "correlation phase does not bind one selected request"
            )
        if state.phase == "proof_observed":
            if existing.phase != "selected":
                raise CorrelationRequestJournalCorrupt(
                    "correlation proof phase skips or repeats a transition"
                )
            snapshot_key = CorrelationRequestJournal._snapshot_key(state)
            indexed_snapshot = snapshot_index.get(snapshot_key)
            if (
                indexed_snapshot is not None
                and indexed_snapshot != state.operation_key
            ):
                raise CorrelationRequestJournalCorrupt(
                    "correlation snapshot identity has multiple operations"
                )
            snapshot_index[snapshot_key] = state.operation_key
        elif (
            existing.phase != "proof_observed"
            or state.snapshot_event_id != existing.snapshot_event_id
            or state.snapshot_content_sha256
            != existing.snapshot_content_sha256
        ):
            raise CorrelationRequestJournalCorrupt(
                "correlation completion does not match its observed proof"
            )
        else:
            snapshot_key = CorrelationRequestJournal._snapshot_key(state)
            if snapshot_index.get(snapshot_key) != state.operation_key:
                raise CorrelationRequestJournalCorrupt(
                    "correlation completion lost its unique snapshot owner"
                )
        states[state.operation_key] = state

    @staticmethod
    def _snapshot_key(state: _CorrelationRequestStateV1) -> _SnapshotKey:
        event_id = state.snapshot_event_id
        content_sha256 = state.snapshot_content_sha256
        if event_id is None or content_sha256 is None:
            raise CorrelationRequestJournalCorrupt(
                "observed correlation state lost snapshot identity"
            )
        return event_id, content_sha256

    def _bind_published(self) -> os.stat_result:
        opened = os.fstat(self._descriptor)
        _validate_journal_stat(opened)
        try:
            published = os.stat(
                _JOURNAL_NAME,
                dir_fd=self._root_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise CorrelationRequestJournalCorrupt(
                "correlation-request journal disappeared from its root"
            ) from error
        _validate_journal_stat(published)
        if not _same_file(opened, published):
            raise CorrelationRequestJournalCorrupt(
                "journal root name no longer binds the retained inode"
            )
        return published

    def _bind_published_or_latch(self) -> os.stat_result:
        try:
            published = self._bind_published()
            retained = self._authenticated_stat
            if retained is None or not _same_file(published, retained):
                raise CorrelationRequestJournalCorrupt(
                    "correlation journal identity changed outside its writer"
                )
            return published
        except CorrelationRequestJournalCorrupt as error:
            self._healthy = False
            self._attempt_corruption_fence(error)
            raise

    def _authenticated_digest_or_none(self) -> bytes | None:
        hasher = self._authenticated_hasher
        if hasher is None:
            return None
        return hasher.digest()

    def _authenticated_digest(self) -> bytes:
        digest = self._authenticated_digest_or_none()
        if digest is None:
            raise CorrelationRequestJournalCorrupt(
                "correlation journal has no authenticated content anchor"
            )
        return digest

    def _hash_held_prefix(self) -> bytes:
        digest = hashlib.sha256()
        offset = 0
        while offset < self._size:
            raw = os.pread(
                self._descriptor,
                min(1024 * 1024, self._size - offset),
                offset,
            )
            if not raw:
                raise CorrelationRequestJournalCorrupt(
                    "correlation journal shortened during verification"
                )
            digest.update(raw)
            offset += len(raw)
        return digest.digest()

    def _verify_authenticated_content(self) -> os.stat_result:
        before = self._bind_published_or_latch()
        digest = self._hash_held_prefix()
        after = self._bind_published_or_latch()
        if not _same_file(before, after) or digest != self._authenticated_digest():
            raise CorrelationRequestJournalCorrupt(
                "correlation journal content differs from its authenticated anchor"
            )
        return after

    def _require_open(self) -> None:
        if self._closed or self._closing:
            raise CorrelationRequestJournalStateError(
                "correlation-request journal is closed"
            )

    def _require_usable(self) -> None:
        self._require_open()
        if not self._healthy:
            raise CorrelationRequestJournalUnhealthy(
                "correlation journal durability is ambiguous until recovery"
            )
        try:
            self._store._validate_correlation_journal_owner(
                self,
                self._lifecycle_identity,
            )
        except _CorrelationJournalLifecycleCorrupt as error:
            corrupt = CorrelationRequestJournalCorrupt(str(error))
            self._healthy = False
            self._attempt_corruption_fence(corrupt)
            raise corrupt from error
        except _CorrelationJournalLifecycleStateError as error:
            raise CorrelationRequestJournalStateError(str(error)) from error
        except EvidenceSealError as error:
            raise CorrelationRequestJournalStateError(str(error)) from error
        self._bind_published_or_latch()

    def _append(self, state: _CorrelationRequestStateV1) -> None:
        payload = canonical_json(state)
        if len(payload) > _MAX_FRAME_PAYLOAD:
            raise CorrelationRequestJournalStateError(
                "correlation-request record exceeds its payload bound"
            )
        if self._record_count >= _MAX_RECORDS:
            raise CorrelationRequestJournalStateError(
                "correlation-request journal record quota is exhausted"
            )
        frame = encode_frame(
            payload,
            previous_hash=self._previous_hash,
            max_frame=_MAX_FRAME_PAYLOAD,
        )
        if self._size + len(frame) > _MAX_VERIFIED_BYTES:
            raise CorrelationRequestJournalStateError(
                "correlation-request journal byte quota is exhausted"
            )

        authenticated_before: os.stat_result | None = None
        digest_before: bytes | None = None
        authenticated_after: os.stat_result | None = None
        hasher_after: _DigestState | None = None
        try:
            authenticated_before = self._bind_published_or_latch()
            digest_before = self._authenticated_digest()
            before = os.fstat(self._descriptor)
            if not _same_file(before, authenticated_before):
                raise CorrelationRequestJournalCorrupt(
                    "correlation append did not start at its authenticated identity"
                )
            _full_write(self._descriptor, frame)
            os.fsync(self._descriptor)
            after = self._bind_published()
            expected_size = before.st_size + len(frame)
            if after.st_size != expected_size:
                raise CorrelationRequestJournalCorrupt(
                    "correlation append includes an unexpected concurrent write"
                )
            if os.pread(self._descriptor, len(frame), before.st_size) != frame:
                raise CorrelationRequestJournalCorrupt(
                    "durable correlation frame differs from appended bytes"
                )
            authenticated_after = self._bind_published()
            if not _same_file(authenticated_after, after):
                raise CorrelationRequestJournalCorrupt(
                    "correlation journal identity changed during append"
                )
            hasher = self._authenticated_hasher
            if hasher is None:
                raise CorrelationRequestJournalCorrupt(
                    "correlation journal lost its content anchor"
                )
            hasher_after = hasher.copy()
            hasher_after.update(frame)
        except CorrelationRequestJournalCorrupt as error:
            self._healthy = False
            self._attempt_corruption_fence(error)
            raise
        except BaseException as error:
            self._healthy = False
            if authenticated_before is not None and digest_before is not None:
                self._attempt_append_uncertain(
                    error,
                    authenticated_before,
                    digest_before,
                )
            raise
        if authenticated_after is None or hasher_after is None:
            raise AssertionError("successful correlation append lost its anchor")
        self._size = expected_size
        self._record_count += 1
        self._previous_hash = frame[-32:]
        self._authenticated_stat = authenticated_after
        self._authenticated_hasher = hasher_after
        self._mutation_revision = object()

    def select(
        self,
        trigger_ref: EvidenceRef,
        canonical_request: bytes,
    ) -> _CorrelationRequestStateV1:
        """Durably select one exact narrow request for an authenticated trigger."""
        with self._lock:
            self._require_usable()
            if type(canonical_request) is not bytes:
                raise CorrelationRequestJournalStateError(
                    "canonical request must be exact bytes"
                )
            try:
                request = decode_strict(
                    canonical_request,
                    PCCCorrelationSnapshotRequestV1,
                    _MAX_FRAME_PAYLOAD,
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise CorrelationRequestJournalStateError(
                    "correlation request schema is invalid"
                ) from error
            if canonical_request != canonical_json(request):
                raise CorrelationRequestJournalStateError(
                    "correlation request is not canonical JSON"
                )
            if request.requested_ttl_seconds != 120:
                raise CorrelationRequestJournalStateError(
                    "correlation request TTL must be exactly 120 seconds"
                )
            request_sha256 = pcc_correlation_request_sha256(request)
            self._resolve_authenticated_ref(trigger_ref)
            operation_key = _operation_key(trigger_ref.event_id)
            existing = self._states_by_operation.get(operation_key)
            if existing is not None:
                if (
                    existing.request_sha256 != request_sha256
                    or canonical_json(existing.request) != canonical_request
                ):
                    self._raise_conflict(
                        "a correlation operation was reselected differently"
                    )
                if not self._trigger_matches(trigger_ref, request):
                    raise CorrelationRequestJournalAuthorityError(
                        "correlation request does not match its trigger ref"
                    )
                return existing.model_copy(deep=True)

            if not self._trigger_matches(trigger_ref, request):
                raise CorrelationRequestJournalAuthorityError(
                    "correlation request does not match its trigger ref"
                )
            if request_sha256 in self._operation_by_request:
                self._raise_conflict(
                    "one correlation request hash names another operation"
                )
            selected = _CorrelationRequestStateV1(
                schema_version="agmind.correlation-request-state.v1",
                operation_key=operation_key,
                request_sha256=request_sha256,
                request=request,
                phase="selected",
            )
            self._append(selected)
            self._states_by_operation[operation_key] = selected
            self._operation_by_request[request_sha256] = operation_key
            return selected.model_copy(deep=True)

    @staticmethod
    def _trigger_matches(
        trigger_ref: EvidenceRef,
        request: PCCCorrelationSnapshotRequestV1,
    ) -> bool:
        return (
            type(trigger_ref) is EvidenceRef
            and trigger_ref.event_id == request.trigger_event_id
            and trigger_ref.content_sha256 == request.trigger_content_sha256
            and trigger_ref.source_sequence == request.trigger_source_sequence
        )

    def _resolve_authenticated_ref(self, ref: EvidenceRef) -> None:
        if type(ref) is not EvidenceRef:
            raise CorrelationRequestJournalAuthorityError(
                "correlation evidence must be an exact EvidenceRef"
            )
        try:
            self._store.resolve_authenticated_ref(ref)
        except _AckAuthorityError as error:
            raise CorrelationRequestJournalAuthorityError(
                "correlation evidence is outside the authenticated store"
            ) from error
        except EvidenceCorrupt as error:
            self._raise_internal_evidence_corruption(
                "authenticated trigger evidence is internally corrupt",
                error,
            )

    def mark_proof_observed(
        self,
        request_sha256: str,
        snapshot_ref: EvidenceRef,
    ) -> _CorrelationRequestStateV1:
        """Durably bind one protected PCC proof to its selected request."""
        with self._lock:
            self._require_usable()
            state = self._state_for_request(request_sha256)
            if type(snapshot_ref) is not EvidenceRef:
                raise CorrelationRequestJournalAuthorityError(
                    "correlation proof must be an exact EvidenceRef"
                )
            if state.phase != "selected":
                self._authenticate_snapshot(state, snapshot_ref)
                if (
                    state.snapshot_event_id != snapshot_ref.event_id
                    or state.snapshot_content_sha256
                    != snapshot_ref.content_sha256
                ):
                    self._raise_conflict(
                        "correlation request was rebound to a different proof"
                    )
                self._require_unique_snapshot_owner(state)
                return state.model_copy(deep=True)

            self._authenticate_snapshot(state, snapshot_ref)
            observed = _CorrelationRequestStateV1(
                schema_version="agmind.correlation-request-state.v1",
                operation_key=state.operation_key,
                request_sha256=state.request_sha256,
                request=state.request,
                phase="proof_observed",
                snapshot_event_id=snapshot_ref.event_id,
                snapshot_content_sha256=snapshot_ref.content_sha256,
            )
            snapshot_key = self._snapshot_key(observed)
            indexed_operation = self._operation_by_snapshot.get(snapshot_key)
            if (
                indexed_operation is not None
                and indexed_operation != state.operation_key
            ):
                self._raise_journal_corruption(
                    "correlation snapshot identity has multiple live operations"
                )
            self._append(observed)
            self._states_by_operation[state.operation_key] = observed
            self._operation_by_snapshot[snapshot_key] = state.operation_key
            return observed.model_copy(deep=True)

    def _authenticate_snapshot(
        self,
        state: _CorrelationRequestStateV1,
        snapshot_ref: EvidenceRef,
    ) -> None:
        if snapshot_ref.source_sequence <= state.request.trigger_source_sequence:
            raise CorrelationRequestJournalAuthorityError(
                "correlation proof must follow its trigger"
            )
        verifier = getattr(self._store, "_bound_verifier", None)
        if verifier is None:
            raise CorrelationRequestJournalAuthorityError(
                "correlation store has no authenticated verifier"
            )
        try:
            authenticated = self._store._authenticated_pcc_input(
                verifier,
                snapshot_ref,
                state.request,
            )
        except (_AckAuthorityError, EvidenceSealError) as error:
            raise CorrelationRequestJournalAuthorityError(
                "correlation proof lacks exact protected PCC authority"
            ) from error
        except EvidenceCorrupt as error:
            self._raise_internal_evidence_corruption(
                "authenticated PCC evidence is internally corrupt",
                error,
            )
        snapshot = authenticated.snapshot
        if (
            authenticated.evidence_ref != snapshot_ref
            or authenticated.source_sequence != snapshot_ref.source_sequence
            or authenticated.event_id != snapshot_ref.event_id
            or authenticated.content_sha256 != snapshot_ref.content_sha256
            or snapshot.request_sha256 != state.request_sha256
            or snapshot.trigger.event_id != state.request.trigger_event_id
            or snapshot.trigger.content_sha256
            != state.request.trigger_content_sha256
            or snapshot.trigger.source_sequence
            != state.request.trigger_source_sequence
            or snapshot.requested_ttl_seconds
            != state.request.requested_ttl_seconds
        ):
            raise CorrelationRequestJournalAuthorityError(
                "correlation proof does not bind the exact selected request"
            )

    def mark_completed(
        self,
        request_sha256: str,
    ) -> _CorrelationRequestStateV1:
        """Durably complete only one request whose exact proof was observed."""
        with self._lock:
            self._require_usable()
            state = self._state_for_request(request_sha256)
            if state.phase == "completed":
                self._require_unique_snapshot_owner(state)
                return state.model_copy(deep=True)
            if state.phase != "proof_observed":
                raise CorrelationRequestJournalStateError(
                    "correlation request has no observed proof"
                )
            self._require_unique_snapshot_owner(state)
            completed = _CorrelationRequestStateV1(
                schema_version="agmind.correlation-request-state.v1",
                operation_key=state.operation_key,
                request_sha256=state.request_sha256,
                request=state.request,
                phase="completed",
                snapshot_event_id=state.snapshot_event_id,
                snapshot_content_sha256=state.snapshot_content_sha256,
            )
            self._append(completed)
            self._states_by_operation[state.operation_key] = completed
            return completed.model_copy(deep=True)

    def completed_for_snapshot(
        self,
        snapshot_ref: EvidenceRef,
    ) -> _CompletedSnapshotAuthority:
        """Issue authority only for one exact durably completed PCC snapshot."""
        with self._lock:
            binding = self._completed_snapshot_binding(snapshot_ref)
            return _issue_completed_snapshot_authority(binding)

    @staticmethod
    def _state_canonical_is_exact(
        state: _CorrelationRequestStateV1,
    ) -> bool:
        try:
            canonical = canonical_json(state)
            reparsed = decode_strict(
                canonical,
                _CorrelationRequestStateV1,
                _MAX_FRAME_PAYLOAD,
            )
            return (
                type(state) is _CorrelationRequestStateV1
                and type(reparsed) is _CorrelationRequestStateV1
                and type(state.request) is PCCCorrelationSnapshotRequestV1
                and type(reparsed.request) is PCCCorrelationSnapshotRequestV1
                and canonical_json(reparsed) == canonical
                and reparsed == state
                and reparsed.model_fields_set == state.model_fields_set
                and reparsed.request.model_fields_set
                == state.request.model_fields_set
            )
        except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
            return False

    @staticmethod
    def _journal_states_binding(
        states: dict[str, _CorrelationRequestStateV1],
    ) -> tuple[tuple[str, bytes, frozenset[str]], ...]:
        return tuple(
            (
                operation,
                canonical_json(state),
                frozenset(state.model_fields_set),
            )
            for operation, state in states.items()
        )

    def _require_live_cache_matches_replay(
        self,
        replay: _AuthenticatedJournalReplay,
    ) -> None:
        try:
            state_keys_match = tuple(self._states_by_operation) == tuple(
                replay.states_by_operation
            )
            states_match = state_keys_match and all(
                (live := self._states_by_operation.get(operation)) is not None
                and self._state_canonical_is_exact(live)
                and canonical_json(live) == canonical_json(replayed)
                and live.model_fields_set == replayed.model_fields_set
                for operation, replayed in replay.states_by_operation.items()
            )
            request_index_matches = tuple(
                self._operation_by_request.items()
            ) == tuple(replay.operation_by_request.items())
            snapshot_index_matches = tuple(
                self._operation_by_snapshot.items()
            ) == tuple(replay.operation_by_snapshot.items())
        except (AttributeError, TypeError, UnicodeError, ValueError):
            states_match = False
            request_index_matches = False
            snapshot_index_matches = False
        if not (
            states_match
            and request_index_matches
            and snapshot_index_matches
        ):
            self._raise_journal_corruption(
                "correlation journal caches differ from durable replay"
            )

    def _authenticated_journal_replay(
        self,
    ) -> _AuthenticatedJournalReplay:
        try:
            expected = self._bind_published_or_latch()
            if expected.st_size > _MAX_VERIFIED_BYTES:
                raise CorrelationRequestJournalCorrupt(
                    "correlation-request journal exceeds its verified-byte bound"
                )
            read_descriptor = os.dup(self._descriptor)
            try:
                os.set_inheritable(read_descriptor, False)
                os.lseek(read_descriptor, 0, os.SEEK_SET)
                stream = os.fdopen(
                    read_descriptor,
                    "rb",
                    buffering=0,
                    closefd=True,
                )
            except BaseException:
                os.close(read_descriptor)
                raise

            states: dict[str, _CorrelationRequestStateV1] = {}
            request_index: dict[str, str] = {}
            snapshot_index: dict[_SnapshotKey, str] = {}
            previous_hash = bytes(32)
            verified_size = 0
            record_count = 0
            hasher = hashlib.sha256()
            try:
                with stream:
                    bounded = _BoundedReader(
                        cast(BinaryIO, stream),
                        expected.st_size,
                    )
                    try:
                        for frame in iter_frames(
                            cast(BinaryIO, bounded),
                            max_frame=_MAX_FRAME_PAYLOAD,
                        ):
                            record_count += 1
                            if record_count > _MAX_RECORDS:
                                raise CorrelationRequestJournalCorrupt(
                                    "correlation-request journal exceeds its record bound"
                                )
                            state = self._decode_frame_state(frame)
                            self._replay_state(
                                state,
                                states,
                                request_index,
                                snapshot_index,
                            )
                            authenticated_frame = encode_frame(
                                frame.payload,
                                previous_hash=frame.previous_hash,
                                max_frame=_MAX_FRAME_PAYLOAD,
                            )
                            if (
                                len(authenticated_frame) != frame.size
                                or authenticated_frame[-32:]
                                != frame.record_hash
                            ):
                                raise CorrelationRequestJournalCorrupt(
                                    "verified correlation frame cannot be reconstructed"
                                )
                            hasher.update(authenticated_frame)
                            verified_size += len(authenticated_frame)
                            if verified_size > _MAX_VERIFIED_BYTES:
                                raise CorrelationRequestJournalCorrupt(
                                    "verified correlation bytes exceed their bound"
                                )
                            previous_hash = frame.record_hash
                    except TornTail as error:
                        raise CorrelationRequestJournalCorrupt(
                            "correlation-request journal has an unproven torn tail"
                        ) from error
            except JournalCorrupt as error:
                raise CorrelationRequestJournalCorrupt(
                    "correlation-request frame chain is corrupt"
                ) from error

            published = self._bind_published()
            after = os.fstat(self._descriptor)
            digest = hasher.digest()
            retained = self._authenticated_stat
            if (
                verified_size != expected.st_size
                or not _same_file(after, expected)
                or not _same_file(published, expected)
                or retained is None
                or not _same_file(published, retained)
                or digest != self._authenticated_digest()
                or verified_size != self._size
                or record_count != self._record_count
                or previous_hash != self._previous_hash
            ):
                raise CorrelationRequestJournalCorrupt(
                    "correlation journal replay differs from authenticated bytes"
                )
            replay = _AuthenticatedJournalReplay(
                states_by_operation=states,
                operation_by_request=request_index,
                operation_by_snapshot=snapshot_index,
                journal_stat=published,
                journal_digest=digest,
                journal_size=verified_size,
                journal_record_count=record_count,
                journal_chain_head=previous_hash,
            )
            self._require_live_cache_matches_replay(replay)
            return replay
        except CorrelationRequestJournalCorrupt as error:
            if self._healthy:
                self._healthy = False
                self._attempt_corruption_fence(error)
            raise

    def _completed_state_from_replay(
        self,
        replay: _AuthenticatedJournalReplay,
        snapshot_ref: EvidenceRef,
    ) -> _CorrelationRequestStateV1:
        fingerprint = _evidence_ref_fingerprint(snapshot_ref)
        snapshot_key = (fingerprint[5], fingerprint[7])
        operation = replay.operation_by_snapshot.get(snapshot_key)
        state = (
            None
            if operation is None
            else replay.states_by_operation.get(operation)
        )
        if state is None or state.phase != "completed":
            raise CorrelationRequestJournalAuthorityError(
                "correlation snapshot has no unique completed journal state"
            )
        if (
            replay.operation_by_request.get(state.request_sha256)
            != operation
            or state.snapshot_event_id != fingerprint[5]
            or state.snapshot_content_sha256 != fingerprint[7]
        ):
            self._raise_journal_corruption(
                "completed correlation replay indexes are inconsistent"
            )
        return state

    @classmethod
    def _replays_match(
        cls,
        first: _AuthenticatedJournalReplay,
        second: _AuthenticatedJournalReplay,
    ) -> bool:
        return (
            _same_file(first.journal_stat, second.journal_stat)
            and first.journal_digest == second.journal_digest
            and first.journal_size == second.journal_size
            and first.journal_record_count == second.journal_record_count
            and first.journal_chain_head == second.journal_chain_head
            and cls._journal_states_binding(first.states_by_operation)
            == cls._journal_states_binding(second.states_by_operation)
            and tuple(first.operation_by_request.items())
            == tuple(second.operation_by_request.items())
            and tuple(first.operation_by_snapshot.items())
            == tuple(second.operation_by_snapshot.items())
        )

    def _authenticated_pcc_for_completed_state(
        self,
        state: _CorrelationRequestStateV1,
        snapshot_ref: EvidenceRef,
    ) -> AuthenticatedPCCInput:
        verifier = self._store._bound_verifier
        if verifier is None or not self._store._is_bound_verifier(verifier):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation store has no exact verifier authority"
            )
        try:
            authenticated = self._store._authenticated_pcc_input(
                verifier,
                snapshot_ref,
                state.request,
            )
        except (_AckAuthorityError, EvidenceSealError) as error:
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation proof lacks exact store authority"
            ) from error
        except EvidenceCorrupt as error:
            self._raise_internal_evidence_corruption(
                "completed PCC evidence is internally corrupt",
                error,
            )
        if not self._pcc_matches_completed_state(
            authenticated,
            state,
            _evidence_ref_fingerprint(snapshot_ref),
        ):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation proof changed during reauthentication"
            )
        return authenticated

    def _pcc_matches_completed_state(
        self,
        authenticated: object,
        state: _CorrelationRequestStateV1,
        snapshot_ref: _EvidenceRefFingerprint,
    ) -> bool:
        if type(authenticated) is not AuthenticatedPCCInput:
            return False
        try:
            request = authenticated.request
            snapshot = authenticated.snapshot
            trigger = snapshot.trigger
            return (
                authenticated_pcc_input_is_issued(authenticated)
                and self._store._authenticated_pcc_input_is_exact(authenticated)
                and type(request) is PCCCorrelationSnapshotRequestV1
                and type(snapshot) is PCCCorrelationSnapshotV1
                and _evidence_ref_fingerprint(authenticated.evidence_ref)
                == snapshot_ref
                and authenticated.event_id == snapshot_ref[5]
                and authenticated.source_sequence == snapshot_ref[6]
                and authenticated.content_sha256 == snapshot_ref[7]
                and canonical_json(request) == canonical_json(state.request)
                and request.model_fields_set == state.request.model_fields_set
                and snapshot.request_sha256 == state.request_sha256
                and snapshot.requested_ttl_seconds
                == state.request.requested_ttl_seconds
                and trigger.event_id == state.request.trigger_event_id
                and trigger.content_sha256
                == state.request.trigger_content_sha256
                and trigger.source_sequence
                == state.request.trigger_source_sequence
                and state.snapshot_event_id == snapshot_ref[5]
                and state.snapshot_content_sha256 == snapshot_ref[7]
            )
        except (
            AttributeError,
            RecursionError,
            TypeError,
            UnicodeError,
            ValueError,
        ):
            return False

    def _completed_snapshot_binding(
        self,
        snapshot_ref: EvidenceRef,
    ) -> _CompletedSnapshotBinding:
        self._require_usable()
        if type(snapshot_ref) is not EvidenceRef:
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation proof must be an exact EvidenceRef"
            )
        replay_before = self._authenticated_journal_replay()
        state = self._completed_state_from_replay(
            replay_before,
            snapshot_ref,
        )
        if not self._state_canonical_is_exact(state):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation state is no longer canonical"
            )
        verifier = self._store._bound_verifier
        if verifier is None or not self._store._is_bound_verifier(verifier):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation store lost verifier authority"
            )
        verifier_authority = verifier._authority
        verifier_generation = verifier_authority.generation
        if type(verifier_generation) is not int or verifier_generation < 0:
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation verifier generation is invalid"
            )
        authenticated = self._authenticated_pcc_for_completed_state(
            state,
            snapshot_ref,
        )
        replay_after = self._authenticated_journal_replay()
        state_after = self._completed_state_from_replay(
            replay_after,
            snapshot_ref,
        )
        if (
            not self._replays_match(replay_before, replay_after)
            or canonical_json(state_after) != canonical_json(state)
            or state_after.model_fields_set != state.model_fields_set
            or not self._state_canonical_is_exact(state_after)
            or not self._pcc_matches_completed_state(
                authenticated,
                state_after,
                _evidence_ref_fingerprint(snapshot_ref),
            )
            or self._store._bound_verifier is not verifier
            or not self._store._is_bound_verifier(verifier)
            or verifier._authority is not verifier_authority
            or verifier._authority.generation != verifier_generation
        ):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation authority changed during issue"
            )
        request = state_after.request
        snapshot = authenticated.snapshot
        trigger = request
        return _CompletedSnapshotBinding(
            journal=self,
            store=self._store,
            journal_lifecycle=self._lifecycle_identity,
            store_lifecycle=self._store._lifecycle_identity,
            verifier=verifier,
            verifier_authority=verifier_authority,
            verifier_generation=verifier_generation,
            state_canonical=canonical_json(state_after),
            state_fields_set=frozenset(state_after.model_fields_set),
            operation_key=state_after.operation_key,
            request_sha256=state_after.request_sha256,
            request_canonical=canonical_json(request),
            request_fields_set=frozenset(request.model_fields_set),
            trigger_event_id=trigger.trigger_event_id,
            trigger_content_sha256=trigger.trigger_content_sha256,
            trigger_source_sequence=trigger.trigger_source_sequence,
            snapshot_ref=_evidence_ref_fingerprint(snapshot_ref),
            pcc=authenticated,
            pcc_canonical=authenticated.canonical,
            pcc_request_canonical=canonical_json(authenticated.request),
            pcc_request_fields_set=frozenset(
                authenticated.request.model_fields_set
            ),
            pcc_snapshot_canonical=canonical_json(snapshot),
            pcc_snapshot_fields_set=frozenset(snapshot.model_fields_set),
            journal_states=self._journal_states_binding(
                replay_after.states_by_operation
            ),
            journal_request_index=tuple(
                replay_after.operation_by_request.items()
            ),
            journal_snapshot_index=tuple(
                replay_after.operation_by_snapshot.items()
            ),
            journal_stat=replay_after.journal_stat,
            journal_digest=replay_after.journal_digest,
            journal_size=replay_after.journal_size,
            journal_record_count=replay_after.journal_record_count,
            journal_chain_head=replay_after.journal_chain_head,
            token=object(),
        )

    def _completed_binding_matches_replay(
        self,
        binding: _CompletedSnapshotBinding,
        replay: _AuthenticatedJournalReplay,
        state: _CorrelationRequestStateV1,
    ) -> bool:
        try:
            snapshot_ref = cast(EvidenceRef, binding.pcc.evidence_ref)
            verifier = self._store._bound_verifier
            request = state.request
            snapshot = binding.pcc.snapshot
            return (
                binding.journal is self
                and binding.store is self._store
                and binding.journal_lifecycle is self._lifecycle_identity
                and binding.store_lifecycle is self._store._lifecycle_identity
                and verifier is binding.verifier
                and verifier is not None
                and self._store._is_bound_verifier(verifier)
                and verifier._authority is binding.verifier_authority
                and verifier._authority.generation
                == binding.verifier_generation
                and self._state_canonical_is_exact(state)
                and canonical_json(state) == binding.state_canonical
                and frozenset(state.model_fields_set)
                == binding.state_fields_set
                and state.operation_key == binding.operation_key
                and state.request_sha256 == binding.request_sha256
                and canonical_json(request) == binding.request_canonical
                and frozenset(request.model_fields_set)
                == binding.request_fields_set
                and request.trigger_event_id == binding.trigger_event_id
                and request.trigger_content_sha256
                == binding.trigger_content_sha256
                and request.trigger_source_sequence
                == binding.trigger_source_sequence
                and _evidence_ref_fingerprint(snapshot_ref)
                == binding.snapshot_ref
                and self._pcc_matches_completed_state(
                    binding.pcc,
                    state,
                    binding.snapshot_ref,
                )
                and binding.pcc.canonical == binding.pcc_canonical
                and canonical_json(binding.pcc.request)
                == binding.pcc_request_canonical
                and frozenset(binding.pcc.request.model_fields_set)
                == binding.pcc_request_fields_set
                and canonical_json(snapshot)
                == binding.pcc_snapshot_canonical
                and frozenset(snapshot.model_fields_set)
                == binding.pcc_snapshot_fields_set
                and _same_file(replay.journal_stat, binding.journal_stat)
                and replay.journal_digest == binding.journal_digest
                and replay.journal_size == binding.journal_size
                and replay.journal_record_count
                == binding.journal_record_count
                and replay.journal_chain_head
                == binding.journal_chain_head
                and self._journal_states_binding(
                    replay.states_by_operation
                )
                == binding.journal_states
                and tuple(replay.operation_by_request.items())
                == binding.journal_request_index
                and tuple(replay.operation_by_snapshot.items())
                == binding.journal_snapshot_index
            )
        except CorrelationRequestJournalCorrupt:
            raise
        except (
            AttributeError,
            RecursionError,
            TypeError,
            UnicodeError,
            ValueError,
        ):
            return False

    def _revalidate_completed_binding(
        self,
        binding: _CompletedSnapshotBinding,
    ) -> AuthenticatedPCCInput:
        self._require_usable()
        replay_before = self._authenticated_journal_replay()
        snapshot_ref = cast(EvidenceRef, binding.pcc.evidence_ref)
        state = self._completed_state_from_replay(
            replay_before,
            snapshot_ref,
        )
        if not self._completed_binding_matches_replay(
            binding,
            replay_before,
            state,
        ):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation authority was revoked"
            )
        current = self._authenticated_pcc_for_completed_state(
            state,
            snapshot_ref,
        )
        if (
            current.canonical != binding.pcc_canonical
            or _evidence_ref_fingerprint(current.evidence_ref)
            != binding.snapshot_ref
            or canonical_json(current.request)
            != binding.pcc_request_canonical
            or frozenset(current.request.model_fields_set)
            != binding.pcc_request_fields_set
            or canonical_json(current.snapshot)
            != binding.pcc_snapshot_canonical
            or frozenset(current.snapshot.model_fields_set)
            != binding.pcc_snapshot_fields_set
        ):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation PCC changed during validation"
            )
        replay_after = self._authenticated_journal_replay()
        state_after = self._completed_state_from_replay(
            replay_after,
            snapshot_ref,
        )
        if (
            not self._replays_match(replay_before, replay_after)
            or not self._completed_binding_matches_replay(
                binding,
                replay_after,
                state_after,
            )
        ):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation authority changed during validation"
            )
        return binding.pcc

    def _require_unique_snapshot_owner(
        self,
        state: _CorrelationRequestStateV1,
    ) -> None:
        snapshot_key = self._snapshot_key(state)
        if self._operation_by_snapshot.get(snapshot_key) != state.operation_key:
            self._raise_journal_corruption(
                "correlation snapshot index lost its unique operation"
            )

    def _raise_journal_corruption(self, message: str) -> Never:
        self._healthy = False
        corrupt = CorrelationRequestJournalCorrupt(message)
        self._attempt_corruption_fence(corrupt)
        raise corrupt

    def _state_for_request(
        self,
        request_sha256: str,
    ) -> _CorrelationRequestStateV1:
        if type(request_sha256) is not str or not _HEX64.fullmatch(request_sha256):
            raise CorrelationRequestJournalStateError(
                "request_sha256 must be 64 lowercase hex"
            )
        operation = self._operation_by_request.get(request_sha256)
        if operation is None:
            raise CorrelationRequestJournalStateError(
                "correlation request is not selected"
            )
        state = self._states_by_operation.get(operation)
        if state is None or state.request_sha256 != request_sha256:
            raise CorrelationRequestJournalCorrupt(
                "correlation request index no longer binds its state"
            )
        return state

    def _raise_conflict(self, message: str) -> None:
        failures: list[Exception] = []
        for _attempt in range(2):
            try:
                self._store.enter_read_only("evidence_conflict")
                if self._store.read_only_reason != "evidence_conflict":
                    raise RuntimeError(
                        "evidence-conflict fence did not bind the exact reason"
                    )
            except BaseException as error:
                if not isinstance(error, Exception):
                    self._latch_operational_failure(error)
                    raise
                failures.append(error)
                continue
            self._latch_verifier_after_conflict_fence()
            raise CorrelationRequestJournalStateError(message)

        self._healthy = False
        unhealthy = CorrelationRequestJournalUnhealthy(
            "evidence-conflict fence durability is uncertain"
        )
        for failure in failures[:-1]:
            unhealthy.add_note(
                "prior evidence-conflict persistence failure: "
                f"{type(failure).__name__}: {failure}"
            )
        self._latch_operational_failure(unhealthy)
        raise unhealthy from failures[-1]

    def _latch_verifier_after_conflict_fence(self) -> None:
        verifier = getattr(self._store, "_bound_verifier", None)
        latch = getattr(verifier, "_enter_read_only_after_durable_fence", None)
        if verifier is None or not callable(latch):
            unhealthy = CorrelationRequestJournalUnhealthy(
                "durable evidence-conflict fence has no exact verifier latch"
            )
            self._latch_operational_failure(unhealthy)
            raise unhealthy
        try:
            latch()
        except BaseException as error:
            if not isinstance(error, Exception):
                self._latch_operational_failure(error)
                raise
            unhealthy = CorrelationRequestJournalUnhealthy(
                "durable evidence-conflict verifier latch failed"
            )
            self._latch_operational_failure(unhealthy)
            raise unhealthy from error
        if getattr(verifier.fsm, "mutation_read_only", None) is not True:
            unhealthy = CorrelationRequestJournalUnhealthy(
                "durable evidence-conflict verifier latch did not settle"
            )
            self._latch_operational_failure(unhealthy)
            raise unhealthy

    def _latch_operational_failure(self, primary: BaseException) -> None:
        retained = self._authenticated_stat
        digest = self._authenticated_digest_or_none()
        try:
            if retained is None or digest is None:
                raise CorrelationRequestJournalCorrupt(
                    "operational failure has no authenticated journal anchor"
                )
            before = self._bind_published()
            if not _same_file(before, retained):
                raise CorrelationRequestJournalCorrupt(
                    "operational failure journal identity changed"
                )
            if self._hash_held_prefix() != digest:
                raise CorrelationRequestJournalCorrupt(
                    "operational failure journal content changed"
                )
            after = self._bind_published()
            if not _same_file(after, before):
                raise CorrelationRequestJournalCorrupt(
                    "operational failure journal changed during verification"
                )
            self._store._seal_correlation_journal_identity(
                self,
                self._lifecycle_identity,
                after,
                digest,
            )
        except BaseException as error:  # noqa: BLE001
            primary.add_note(
                "secondary operational-failure anchor seal failure: "
                f"{type(error).__name__}: {error}"
            )
            self._attempt_io_uncertain(primary, retained, digest)
        self._healthy = False

    def _raise_internal_evidence_corruption(
        self,
        message: str,
        cause: EvidenceCorrupt,
    ) -> Never:
        self._healthy = False
        corrupt = CorrelationRequestJournalCorrupt(message)
        self._attempt_corruption_fence(corrupt)
        raise corrupt from cause

    def pending(self) -> tuple[_CorrelationRequestStateV1, ...]:
        """Return selected/observed requests in stable selection order."""
        with self._lock:
            self._require_usable()
            return tuple(
                state.model_copy(deep=True)
                for state in self._states_by_operation.values()
                if state.phase != "completed"
            )

    def _is_bound_to(self, store: SegmentStore) -> bool:
        """Report whether this live journal owns the exact supplied store."""
        with self._lock:
            if (
                store is not self._store
                or self._closed
                or self._closing
                or not self._healthy
            ):
                return False
            try:
                self._store._validate_correlation_journal_owner(
                    self,
                    self._lifecycle_identity,
                )
                self._bind_published_or_latch()
            except CorrelationRequestJournalError:
                return False
            except (
                _CorrelationJournalLifecycleCorrupt,
                _CorrelationJournalLifecycleStateError,
                EvidenceSealError,
            ):
                return False
            return True

    def _attempt_corruption_fence(
        self,
        primary: CorrelationRequestJournalCorrupt,
    ) -> None:
        try:
            self._store._trip_correlation_journal_corrupt()
        except Exception as error:  # noqa: BLE001
            primary.add_note(
                "secondary correlation corruption-fence failure: "
                f"{type(error).__name__}: {error}"
            )

    def _attempt_append_uncertain(
        self,
        primary: BaseException,
        authenticated_before: os.stat_result,
        digest_before: bytes,
    ) -> None:
        try:
            self._store._mark_correlation_journal_append_uncertain(
                self,
                self._lifecycle_identity,
                authenticated_before,
                digest_before,
            )
        except Exception as error:  # noqa: BLE001
            primary.add_note(
                "secondary correlation append-uncertainty failure: "
                f"{type(error).__name__}: {error}"
            )

    def _attempt_io_uncertain(
        self,
        primary: BaseException,
        authenticated: os.stat_result | None,
        digest: bytes | None,
    ) -> None:
        try:
            self._store._mark_correlation_journal_io_uncertain(
                self,
                self._lifecycle_identity,
                authenticated,
                digest,
            )
        except Exception as error:  # noqa: BLE001
            primary.add_note(
                "secondary correlation I/O-uncertainty failure: "
                f"{type(error).__name__}: {error}"
            )

    def _close_resources(self) -> list[Exception]:
        errors: list[Exception] = []
        if self._descriptor >= 0:
            try:
                os.close(self._descriptor)
            except OSError as error:
                errors.append(error)
            finally:
                self._descriptor = -1
        if self._root_descriptor >= 0:
            try:
                os.close(self._root_descriptor)
            except OSError as error:
                errors.append(error)
            finally:
                self._root_descriptor = -1
        if getattr(self._store, "_correlation_journal_owner", None) is self:
            try:
                self._store._release_correlation_journal(
                    self,
                    self._lifecycle_identity,
                )
            except Exception as error:  # noqa: BLE001
                errors.append(error)
        retained = getattr(self._store, "_correlation_journal_owner", None) is self
        self._closed = not retained
        if retained:
            self._closing = True
        return errors

    def _close_after_failed_open(self, primary: BaseException) -> None:
        for error in self._close_resources():
            primary.add_note(
                "secondary correlation cleanup failure: "
                f"{type(error).__name__}: {error}"
            )

    def _close_from_segment_store(self, lifecycle_identity: object) -> None:
        if lifecycle_identity is not self._lifecycle_identity:
            raise CorrelationRequestJournalStateError(
                "store supplied the wrong correlation lifecycle"
            )
        self.close()

    def close(self) -> None:
        """Seal the authenticated journal identity and release its root lease."""
        with self._lock:
            if self._closed:
                return
            if self._closing:
                errors = self._close_resources()
                if errors:
                    raise CorrelationRequestJournalUnhealthy(
                        "correlation journal close remains uncertain"
                    ) from errors[0]
                return
            self._closing = True
            primary: BaseException | None = None
            if self._healthy:
                authenticated: os.stat_result | None = None
                try:
                    authenticated = self._verify_authenticated_content()
                    self._store._seal_correlation_journal_identity(
                        self,
                        self._lifecycle_identity,
                        authenticated,
                        self._authenticated_digest(),
                    )
                except _CorrelationJournalLifecycleCorrupt as error:
                    corrupt = CorrelationRequestJournalCorrupt(str(error))
                    self._healthy = False
                    self._attempt_corruption_fence(corrupt)
                    primary = corrupt
                except _CorrelationJournalLifecycleIoUncertain as error:
                    self._healthy = False
                    self._attempt_io_uncertain(
                        error,
                        authenticated,
                        self._authenticated_digest_or_none(),
                    )
                    primary = error
                except CorrelationRequestJournalCorrupt as error:
                    self._healthy = False
                    self._attempt_corruption_fence(error)
                    primary = error
                except BaseException as error:  # noqa: BLE001
                    self._healthy = False
                    self._attempt_io_uncertain(
                        error,
                        authenticated,
                        self._authenticated_digest_or_none(),
                    )
                    primary = error
            cleanup_errors = self._close_resources()
            if primary is not None:
                for cleanup_error in cleanup_errors:
                    primary.add_note(
                        "secondary correlation close failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
                raise primary
            if cleanup_errors:
                raise CorrelationRequestJournalUnhealthy(
                    "correlation journal close cleanup failed"
                ) from cleanup_errors[0]


@contextmanager
def _correlation_journal_replay_gate(
    journal: CorrelationRequestJournal,
) -> Iterator[None]:
    """Hold the completed-PCC journal as the deepest replay authority."""
    if type(journal) is not CorrelationRequestJournal:
        raise CorrelationRequestJournalAuthorityError(
            "correlation replay requires exact journal authority"
        )
    with journal._lock:
        journal._require_usable()
        yield


def _completed_replay_facts_locked(
    journal: CorrelationRequestJournal,
    replay: _AuthenticatedJournalReplay,
    *,
    through_sequence: int,
) -> tuple[tuple[_CompletedPCCReplayFacts, ...], tuple[AuthenticatedPCCInput, ...]]:
    records = tuple(
        journal._store.iter_authenticated_records(through=through_sequence)
    )
    if (
        not records
        or records[-1].ref.source_sequence != through_sequence
        or any(
            record.ref.source_sequence != ordinal
            for ordinal, record in enumerate(records, start=1)
        )
    ):
        raise CorrelationRequestJournalAuthorityError(
            "correlation replay terminal is not exact and contiguous"
        )
    facts: list[_CompletedPCCReplayFacts] = []
    proofs: list[AuthenticatedPCCInput] = []
    for record in records:
        ref = record.ref
        ref_key = _evidence_ref_fingerprint(ref)
        operation = replay.operation_by_snapshot.get((ref_key[5], ref_key[7]))
        if operation is None:
            continue
        state = replay.states_by_operation.get(operation)
        if state is None:
            journal._raise_journal_corruption(
                "correlation replay snapshot index lost its state"
            )
        if state.phase != "completed":
            continue
        if (
            replay.operation_by_request.get(state.request_sha256) != operation
            or state.snapshot_event_id != ref_key[5]
            or state.snapshot_content_sha256 != ref_key[7]
            or not journal._state_canonical_is_exact(state)
        ):
            journal._raise_journal_corruption(
                "correlation replay completed indexes changed"
            )
        proof = journal._authenticated_pcc_for_completed_state(state, ref)
        facts.append(
            _CompletedPCCReplayFacts(
                ref_key=ref_key,
                state_canonical=canonical_json(state),
                state_fields_set=frozenset(state.model_fields_set),
                operation_key=state.operation_key,
                request_sha256=state.request_sha256,
                proof_canonical=proof.canonical,
                request_canonical=canonical_json(proof.request),
                request_fields_set=frozenset(proof.request.model_fields_set),
                snapshot_canonical=canonical_json(proof.snapshot),
                snapshot_fields_set=frozenset(proof.snapshot.model_fields_set),
            )
        )
        proofs.append(proof)
    return tuple(facts), tuple(proofs)


def _capture_correlation_journal_replay_locked(
    journal: CorrelationRequestJournal,
    *,
    through_sequence: int,
) -> tuple[_CorrelationJournalReplaySnapshot, tuple[AuthenticatedPCCInput, ...]]:
    """Capture immutable durable journal facts and ephemeral issued PCC proofs."""
    if (
        type(journal) is not CorrelationRequestJournal
        or type(through_sequence) is not int
        or not 1 <= through_sequence <= MAX_UINT64
    ):
        raise CorrelationRequestJournalAuthorityError(
            "correlation replay capture fields are not exact"
        )
    journal._require_usable()
    journal_lifecycle = journal._lifecycle_identity
    mutation_revision = journal._mutation_revision
    store = journal._store
    store_lifecycle = store._lifecycle_identity
    verifier = store._bound_verifier
    if verifier is None or not store._is_bound_verifier(verifier):
        raise CorrelationRequestJournalAuthorityError(
            "correlation replay lost verifier authority"
        )
    verifier_generation = verifier._authority.generation
    if type(verifier_generation) is not int or verifier_generation < 0:
        raise CorrelationRequestJournalAuthorityError(
            "correlation replay verifier generation is invalid"
        )
    replay = journal._authenticated_journal_replay()
    facts, proofs = _completed_replay_facts_locked(
        journal,
        replay,
        through_sequence=through_sequence,
    )
    replay_after = journal._authenticated_journal_replay()
    if (
        not journal._replays_match(replay, replay_after)
        or journal._lifecycle_identity is not journal_lifecycle
        or journal._mutation_revision is not mutation_revision
        or journal._store is not store
        or store._lifecycle_identity is not store_lifecycle
        or store._bound_verifier is not verifier
        or not store._is_bound_verifier(verifier)
        or verifier._authority.generation != verifier_generation
    ):
        raise CorrelationRequestJournalAuthorityError(
            "correlation replay authority changed during capture"
        )
    info = replay_after.journal_stat
    snapshot = _CorrelationJournalReplaySnapshot(
        journal_lifecycle=journal_lifecycle,
        store_lifecycle=store_lifecycle,
        mutation_revision=mutation_revision,
        verifier_generation=verifier_generation,
        journal_device=info.st_dev,
        journal_inode=info.st_ino,
        journal_size=replay_after.journal_size,
        journal_digest=replay_after.journal_digest,
        journal_record_count=replay_after.journal_record_count,
        journal_chain_head=replay_after.journal_chain_head,
        completed_facts=facts,
    )
    return snapshot, proofs


def _revalidate_correlation_journal_replay_locked(
    journal: CorrelationRequestJournal,
    snapshot: _CorrelationJournalReplaySnapshot,
) -> None:
    """Reject publication unless every frozen journal fact remains exact."""
    if (
        type(journal) is not CorrelationRequestJournal
        or type(snapshot) is not _CorrelationJournalReplaySnapshot
        or type(snapshot.verifier_generation) is not int
        or snapshot.verifier_generation < 0
        or type(snapshot.journal_device) is not int
        or type(snapshot.journal_inode) is not int
        or type(snapshot.journal_size) is not int
        or snapshot.journal_size < 0
        or type(snapshot.journal_digest) is not bytes
        or len(snapshot.journal_digest) != 32
        or type(snapshot.journal_record_count) is not int
        or snapshot.journal_record_count < 0
        or type(snapshot.journal_chain_head) is not bytes
        or len(snapshot.journal_chain_head) != 32
        or type(snapshot.completed_facts) is not tuple
        or any(
            type(fact) is not _CompletedPCCReplayFacts
            for fact in snapshot.completed_facts
        )
    ):
        raise CorrelationRequestJournalAuthorityError(
            "correlation replay snapshot is not exact"
        )
    journal._require_usable()
    store = journal._store
    verifier = store._bound_verifier
    replay = journal._authenticated_journal_replay()
    info = replay.journal_stat
    if (
        journal._lifecycle_identity is not snapshot.journal_lifecycle
        or journal._mutation_revision is not snapshot.mutation_revision
        or store._lifecycle_identity is not snapshot.store_lifecycle
        or verifier is None
        or not store._is_bound_verifier(verifier)
        or verifier._authority.generation != snapshot.verifier_generation
        or info.st_dev != snapshot.journal_device
        or info.st_ino != snapshot.journal_inode
        or replay.journal_size != snapshot.journal_size
        or replay.journal_digest != snapshot.journal_digest
        or replay.journal_record_count != snapshot.journal_record_count
        or replay.journal_chain_head != snapshot.journal_chain_head
    ):
        raise CorrelationRequestJournalAuthorityError(
            "correlation replay journal revision or durable facts changed"
        )
    for fact in snapshot.completed_facts:
        try:
            ref = EvidenceRef(
                segment_id=fact.ref_key[0],
                segment_relative_path=fact.ref_key[1],
                frame_offset=fact.ref_key[2],
                frame_size=fact.ref_key[3],
                frame_sha256=fact.ref_key[4],
                event_id=fact.ref_key[5],
                source_sequence=fact.ref_key[6],
                content_sha256=fact.ref_key[7],
            )
            state = replay.states_by_operation.get(fact.operation_key)
            if state is None:
                raise ValueError("completed replay state disappeared")
            proof = journal._authenticated_pcc_for_completed_state(state, ref)
            if (
                canonical_json(state) != fact.state_canonical
                or frozenset(state.model_fields_set) != fact.state_fields_set
                or state.operation_key != fact.operation_key
                or state.request_sha256 != fact.request_sha256
                or replay.operation_by_request.get(fact.request_sha256)
                != fact.operation_key
                or replay.operation_by_snapshot.get(
                    (fact.ref_key[5], fact.ref_key[7])
                )
                != fact.operation_key
                or proof.canonical != fact.proof_canonical
                or canonical_json(proof.request) != fact.request_canonical
                or frozenset(proof.request.model_fields_set)
                != fact.request_fields_set
                or canonical_json(proof.snapshot) != fact.snapshot_canonical
                or frozenset(proof.snapshot.model_fields_set)
                != fact.snapshot_fields_set
                or not journal._pcc_matches_completed_state(
                    proof,
                    state,
                    fact.ref_key,
                )
            ):
                raise ValueError("completed replay facts changed")
        except CorrelationRequestJournalError:
            raise
        except (AttributeError, IndexError, TypeError, ValueError) as error:
            raise CorrelationRequestJournalAuthorityError(
                "correlation replay completed PCC facts changed"
            ) from error


def _evaluate_completed_snapshot_batch[T](
    journal: CorrelationRequestJournal,
    snapshot_refs: tuple[EvidenceRef, ...],
    evaluator: Callable[[tuple[AuthenticatedPCCInput, ...]], T],
) -> T:
    """Evaluate one bounded pure callback over an authenticated completed batch."""
    if type(journal) is not CorrelationRequestJournal or not callable(evaluator):
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch requires exact journal authority"
        )
    if (
        type(snapshot_refs) is not tuple
        or not snapshot_refs
        or len(snapshot_refs) > _MAX_COMPLETED_BATCH
        or any(type(ref) is not EvidenceRef for ref in snapshot_refs)
    ):
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch refs are not exact and bounded"
        )
    fingerprints = tuple(_evidence_ref_fingerprint(ref) for ref in snapshot_refs)
    if len(set(fingerprints)) != len(fingerprints):
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch refs are not unique"
        )
    with journal._lock:
        journal._require_usable()
        journal_lifecycle = journal._lifecycle_identity
        store = journal._store
        store_lifecycle = store._lifecycle_identity
        verifier = store._bound_verifier
        if verifier is None or not store._is_bound_verifier(verifier):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation batch lost verifier authority"
            )
        verifier_authority = verifier._authority
        verifier_generation = verifier_authority.generation
        if type(verifier_generation) is not int or verifier_generation < 0:
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation batch verifier generation is invalid"
            )
        replay_before = journal._authenticated_journal_replay()
        entries: list[
            tuple[
                EvidenceRef,
                _EvidenceRefFingerprint,
                bytes,
                frozenset[str],
                AuthenticatedPCCInput,
                bytes,
                bytes,
                frozenset[str],
                bytes,
                frozenset[str],
            ]
        ] = []
        proofs: list[AuthenticatedPCCInput] = []
        for ref, fingerprint in zip(snapshot_refs, fingerprints, strict=True):
            state = journal._completed_state_from_replay(replay_before, ref)
            if not journal._state_canonical_is_exact(state):
                raise CorrelationRequestJournalAuthorityError(
                    "completed correlation batch state is not canonical"
                )
            proof = journal._authenticated_pcc_for_completed_state(state, ref)
            snapshot = proof.snapshot
            entries.append(
                (
                    ref,
                    fingerprint,
                    canonical_json(state),
                    frozenset(state.model_fields_set),
                    proof,
                    proof.canonical,
                    canonical_json(proof.request),
                    frozenset(proof.request.model_fields_set),
                    canonical_json(snapshot),
                    frozenset(snapshot.model_fields_set),
                )
            )
            proofs.append(proof)
        result = evaluator(tuple(proofs))
        reauthenticated: list[AuthenticatedPCCInput] = []
        for (
            ref,
            fingerprint,
            state_canonical,
            state_fields_set,
            proof,
            proof_canonical,
            request_canonical,
            request_fields_set,
            snapshot_canonical,
            snapshot_fields_set,
        ) in entries:
            state = journal._completed_state_from_replay(replay_before, ref)
            current = journal._authenticated_pcc_for_completed_state(state, ref)
            if (
                canonical_json(state) != state_canonical
                or frozenset(state.model_fields_set) != state_fields_set
                or not journal._state_canonical_is_exact(state)
                or current.canonical != proof_canonical
                or _evidence_ref_fingerprint(current.evidence_ref) != fingerprint
                or canonical_json(current.request) != request_canonical
                or frozenset(current.request.model_fields_set)
                != request_fields_set
                or canonical_json(current.snapshot) != snapshot_canonical
                or frozenset(current.snapshot.model_fields_set)
                != snapshot_fields_set
                or not journal._pcc_matches_completed_state(
                    proof,
                    state,
                    fingerprint,
                )
            ):
                raise CorrelationRequestJournalAuthorityError(
                    "completed correlation batch changed during evaluation"
                )
            reauthenticated.append(current)
        replay_after = journal._authenticated_journal_replay()
        if (
            not journal._replays_match(replay_before, replay_after)
            or journal._lifecycle_identity is not journal_lifecycle
            or journal._store is not store
            or store._lifecycle_identity is not store_lifecycle
            or store._bound_verifier is not verifier
            or not store._is_bound_verifier(verifier)
            or verifier._authority is not verifier_authority
            or verifier._authority.generation != verifier_generation
        ):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation batch authority changed"
            )
        for entry, current in zip(entries, reauthenticated, strict=True):
            (
                ref,
                fingerprint,
                state_canonical,
                state_fields_set,
                proof,
                proof_canonical,
                request_canonical,
                request_fields_set,
                snapshot_canonical,
                snapshot_fields_set,
            ) = entry
            state_after = journal._completed_state_from_replay(replay_after, ref)
            if (
                canonical_json(state_after) != state_canonical
                or frozenset(state_after.model_fields_set) != state_fields_set
                or not journal._state_canonical_is_exact(state_after)
                or current.canonical != proof_canonical
                or proof.canonical != proof_canonical
                or canonical_json(current.request) != request_canonical
                or frozenset(current.request.model_fields_set)
                != request_fields_set
                or canonical_json(current.snapshot) != snapshot_canonical
                or frozenset(current.snapshot.model_fields_set)
                != snapshot_fields_set
                or not journal._pcc_matches_completed_state(
                    current,
                    state_after,
                    fingerprint,
                )
                or not journal._pcc_matches_completed_state(
                    proof,
                    state_after,
                    fingerprint,
                )
            ):
                raise CorrelationRequestJournalAuthorityError(
                    "completed correlation batch changed during final proof"
                )
        return result


_COMPLETED_BATCH_AUTHORITIES_LOCK = Lock()
_ISSUED_COMPLETED_BATCHES: weakref.WeakKeyDictionary[
    _CompletedSnapshotBatchAuthority,
    tuple[
        _CompletedSnapshotBatchBinding,
        tuple[_CompletedSnapshotBatchItem, ...],
    ],
] = weakref.WeakKeyDictionary()
_ISSUED_COMPLETED_BATCH_ITEMS: weakref.WeakKeyDictionary[
    _CompletedSnapshotBatchItem,
    tuple[_CompletedSnapshotBatchBinding, int, object],
] = weakref.WeakKeyDictionary()
_CLAIMED_COMPLETED_BATCHES: weakref.WeakSet[
    _CompletedSnapshotBatchAuthority
] = weakref.WeakSet()


def _exact_completed_batch_refs(
    snapshot_refs: tuple[EvidenceRef, ...],
) -> tuple[_EvidenceRefFingerprint, ...]:
    if (
        type(snapshot_refs) is not tuple
        or not snapshot_refs
        or len(snapshot_refs) > _MAX_COMPLETED_BATCH
        or any(type(ref) is not EvidenceRef for ref in snapshot_refs)
    ):
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch refs are not exact and bounded"
        )
    fingerprints = tuple(_evidence_ref_fingerprint(ref) for ref in snapshot_refs)
    if len(set(fingerprints)) != len(fingerprints):
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch refs are not unique"
        )
    return fingerprints


def _issue_completed_snapshot_batch(
    journal: CorrelationRequestJournal,
    snapshot_refs: tuple[EvidenceRef, ...],
) -> _CompletedSnapshotBatchAuthority:
    """Issue one shared exact anchor with O(1)-checkable completed items."""
    if type(journal) is not CorrelationRequestJournal:
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch requires exact journal authority"
        )
    fingerprints = _exact_completed_batch_refs(snapshot_refs)
    with journal._lock:
        journal._require_usable()
        journal_lifecycle = journal._lifecycle_identity
        store = journal._store
        store_lifecycle = store._lifecycle_identity
        verifier = store._bound_verifier
        if verifier is None or not store._is_bound_verifier(verifier):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation batch lost verifier authority"
            )
        verifier_authority = verifier._authority
        verifier_generation = verifier_authority.generation
        if type(verifier_generation) is not int or verifier_generation < 0:
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation batch verifier generation is invalid"
            )
        mutation_revision = journal._mutation_revision
        replay_before = journal._authenticated_journal_replay()
        facts: list[_CompletedSnapshotBatchItemFacts] = []
        for ref, fingerprint in zip(snapshot_refs, fingerprints, strict=True):
            state = journal._completed_state_from_replay(replay_before, ref)
            if not journal._state_canonical_is_exact(state):
                raise CorrelationRequestJournalAuthorityError(
                    "completed correlation batch state is not canonical"
                )
            proof = journal._authenticated_pcc_for_completed_state(state, ref)
            facts.append(
                _CompletedSnapshotBatchItemFacts(
                    fingerprint=fingerprint,
                    state_canonical=canonical_json(state),
                    state_fields_set=frozenset(state.model_fields_set),
                    operation_key=state.operation_key,
                    request_sha256=state.request_sha256,
                    proof=proof,
                    proof_canonical=proof.canonical,
                    request_canonical=canonical_json(proof.request),
                    request_fields_set=frozenset(proof.request.model_fields_set),
                    snapshot_canonical=canonical_json(proof.snapshot),
                    snapshot_fields_set=frozenset(proof.snapshot.model_fields_set),
                )
            )
        replay_after = journal._authenticated_journal_replay()
        if (
            not journal._replays_match(replay_before, replay_after)
            or journal._mutation_revision is not mutation_revision
            or journal._lifecycle_identity is not journal_lifecycle
            or journal._store is not store
            or store._lifecycle_identity is not store_lifecycle
            or store._bound_verifier is not verifier
            or not store._is_bound_verifier(verifier)
            or verifier._authority is not verifier_authority
            or verifier._authority.generation != verifier_generation
        ):
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation batch authority changed during issue"
            )
        for fact, ref in zip(facts, snapshot_refs, strict=True):
            state = journal._completed_state_from_replay(replay_after, ref)
            if (
                canonical_json(state) != fact.state_canonical
                or frozenset(state.model_fields_set) != fact.state_fields_set
                or not journal._pcc_matches_completed_state(
                    fact.proof,
                    state,
                    fact.fingerprint,
                )
            ):
                raise CorrelationRequestJournalAuthorityError(
                    "completed correlation batch item changed during issue"
                )
        binding = _CompletedSnapshotBatchBinding(
            journal=journal,
            store=store,
            journal_lifecycle=journal_lifecycle,
            store_lifecycle=store_lifecycle,
            verifier=verifier,
            verifier_authority=verifier_authority,
            verifier_generation=verifier_generation,
            mutation_revision=mutation_revision,
            replay=replay_after,
            facts=tuple(facts),
            token=object(),
        )
        authority: _CompletedSnapshotBatchAuthority = object.__new__(
            _CompletedSnapshotBatchAuthority
        )
        object.__setattr__(authority, "_token", binding.token)
        items: list[_CompletedSnapshotBatchItem] = []
        with _COMPLETED_BATCH_AUTHORITIES_LOCK:
            for index in range(len(facts)):
                item: _CompletedSnapshotBatchItem = object.__new__(
                    _CompletedSnapshotBatchItem
                )
                token = object()
                object.__setattr__(item, "_token", token)
                _ISSUED_COMPLETED_BATCH_ITEMS[item] = (binding, index, token)
                items.append(item)
            _ISSUED_COMPLETED_BATCHES[authority] = (binding, tuple(items))
        return authority


def _completed_snapshot_batch_items(
    authority: object,
) -> tuple[_CompletedSnapshotBatchItem, ...]:
    if type(authority) is not _CompletedSnapshotBatchAuthority:
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch authority is not exact"
        )
    with _COMPLETED_BATCH_AUTHORITIES_LOCK:
        issued = _ISSUED_COMPLETED_BATCHES.get(authority)
        if issued is None or authority._token is not issued[0].token:
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation batch authority was not issued"
            )
        if authority in _CLAIMED_COMPLETED_BATCHES:
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation batch items were already claimed"
            )
        _CLAIMED_COMPLETED_BATCHES.add(authority)
        return issued[1]


def _completed_batch_binding(
    authority: object,
) -> _CompletedSnapshotBatchBinding:
    if type(authority) is not _CompletedSnapshotBatchAuthority:
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch authority is not exact"
        )
    with _COMPLETED_BATCH_AUTHORITIES_LOCK:
        issued = _ISSUED_COMPLETED_BATCHES.get(authority)
    if issued is None or authority._token is not issued[0].token:
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch authority was not issued"
        )
    return issued[0]


def _batch_item_binding(
    authority: object,
) -> tuple[_CompletedSnapshotBatchBinding, int]:
    if type(authority) is not _CompletedSnapshotBatchItem:
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch item is not exact"
        )
    with _COMPLETED_BATCH_AUTHORITIES_LOCK:
        issued = _ISSUED_COMPLETED_BATCH_ITEMS.get(authority)
    if issued is None or authority._token is not issued[2]:
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch item was not issued"
        )
    return issued[0], issued[1]


def _revoke_completed_snapshot_batch(authority: object) -> None:
    if type(authority) is not _CompletedSnapshotBatchAuthority:
        raise CorrelationRequestJournalAuthorityError(
            "completed correlation batch authority is not exact"
        )
    with _COMPLETED_BATCH_AUTHORITIES_LOCK:
        issued = _ISSUED_COMPLETED_BATCHES.pop(authority, None)
        _CLAIMED_COMPLETED_BATCHES.discard(authority)
        if issued is not None:
            for item in issued[1]:
                _ISSUED_COMPLETED_BATCH_ITEMS.pop(item, None)


def _revalidate_completed_snapshot_batch_item(
    authority: object,
) -> AuthenticatedPCCInput:
    binding, index = _batch_item_binding(authority)
    exact_authority = cast(_CompletedSnapshotBatchItem, authority)
    journal = binding.journal
    facts = binding.facts[index]
    with journal._lock:
        journal._require_usable()
        if journal._mutation_revision is not binding.mutation_revision:
            raise CorrelationRequestJournalAuthorityError(
                "append-only extension revokes completed batch authority"
            )
        verifier = binding.store._bound_verifier
        if (
            journal._lifecycle_identity is not binding.journal_lifecycle
            or journal._store is not binding.store
            or binding.store._lifecycle_identity is not binding.store_lifecycle
            or verifier is not binding.verifier
            or verifier is None
            or not binding.store._is_bound_verifier(verifier)
            or verifier._authority is not binding.verifier_authority
            or verifier._authority.generation != binding.verifier_generation
            or journal._authenticated_stat is None
            or not _same_file(journal._authenticated_stat, binding.replay.journal_stat)
            or journal._authenticated_digest() != binding.replay.journal_digest
            or journal._size != binding.replay.journal_size
            or journal._record_count != binding.replay.journal_record_count
            or journal._previous_hash != binding.replay.journal_chain_head
        ):
            journal._raise_journal_corruption(
                "completed correlation batch shared anchor changed"
            )
        state = journal._states_by_operation.get(facts.operation_key)
        if (
            state is None
            or canonical_json(state) != facts.state_canonical
            or frozenset(state.model_fields_set) != facts.state_fields_set
            or journal._operation_by_request.get(facts.request_sha256)
            != facts.operation_key
            or journal._operation_by_snapshot.get(
                (facts.fingerprint[5], facts.fingerprint[7])
            )
            != facts.operation_key
            or facts.proof.canonical != facts.proof_canonical
            or canonical_json(facts.proof.request) != facts.request_canonical
            or frozenset(facts.proof.request.model_fields_set)
            != facts.request_fields_set
            or canonical_json(facts.proof.snapshot) != facts.snapshot_canonical
            or frozenset(facts.proof.snapshot.model_fields_set)
            != facts.snapshot_fields_set
            or not binding.store._authenticated_pcc_input_is_exact(facts.proof)
            or not journal._pcc_matches_completed_state(
                facts.proof,
                state,
                facts.fingerprint,
            )
        ):
            journal._raise_journal_corruption(
                "completed correlation batch item cache changed"
            )
        with _COMPLETED_BATCH_AUTHORITIES_LOCK:
            issued = _ISSUED_COMPLETED_BATCH_ITEMS.get(exact_authority)
            if (
                issued is None
                or exact_authority._token is not issued[2]
                or issued[0] is not binding
                or issued[1] != index
            ):
                raise CorrelationRequestJournalAuthorityError(
                    "completed correlation batch item was revoked"
                )
        return facts.proof


def _seal_completed_snapshot_batch(authority: object) -> None:
    binding = _completed_batch_binding(authority)
    journal = binding.journal
    exact_authority = cast(_CompletedSnapshotBatchAuthority, authority)
    with _COMPLETED_BATCH_AUTHORITIES_LOCK:
        issued = _ISSUED_COMPLETED_BATCHES.get(exact_authority)
        if issued is None:
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation batch authority was not issued"
            )
        items = issued[1]
    try:
        for item in items:
            _revalidate_completed_snapshot_batch_item(item)
        with journal._lock:
            replay = journal._authenticated_journal_replay()
            if (
                journal._mutation_revision is not binding.mutation_revision
                or not journal._replays_match(binding.replay, replay)
            ):
                raise CorrelationRequestJournalAuthorityError(
                    "completed correlation batch changed before final seal"
                )
            with _COMPLETED_BATCH_AUTHORITIES_LOCK:
                final_issued = _ISSUED_COMPLETED_BATCHES.get(exact_authority)
                if (
                    final_issued is None
                    or exact_authority._token is not binding.token
                    or final_issued[0] is not binding
                    or final_issued[1] is not items
                    or exact_authority not in _CLAIMED_COMPLETED_BATCHES
                ):
                    raise CorrelationRequestJournalAuthorityError(
                        "completed correlation batch was revoked during final seal"
                    )
    finally:
        _revoke_completed_snapshot_batch(authority)


def _completed_snapshot_authority_protocol() -> tuple[
    Callable[[_CompletedSnapshotBinding], _CompletedSnapshotAuthority],
    Callable[[object], AuthenticatedPCCInput],
]:
    issued: weakref.WeakKeyDictionary[
        _CompletedSnapshotAuthority,
        _CompletedSnapshotBinding,
    ] = weakref.WeakKeyDictionary()

    def issue(
        binding: _CompletedSnapshotBinding,
    ) -> _CompletedSnapshotAuthority:
        authority: _CompletedSnapshotAuthority = object.__new__(
            _CompletedSnapshotAuthority
        )
        object.__setattr__(authority, "_token", binding.token)
        issued[authority] = binding
        return authority

    def revalidate(authority: object) -> AuthenticatedPCCInput:
        if type(authority) is not _CompletedSnapshotAuthority:
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation authority is not exact"
            )
        try:
            binding = issued.get(authority)
            token = authority._token
        except (AttributeError, TypeError):
            binding = None
            token = None
        if binding is None or token is not binding.token:
            raise CorrelationRequestJournalAuthorityError(
                "completed correlation authority was not issued"
            )
        journal = binding.journal
        with journal._lock:
            if (
                issued.get(authority) is not binding
                or authority._token is not binding.token
            ):
                raise CorrelationRequestJournalAuthorityError(
                    "completed correlation authority changed before validation"
                )
            try:
                authenticated = journal._revalidate_completed_binding(binding)
            except CorrelationRequestJournalCorrupt:
                raise
            except CorrelationRequestJournalError as error:
                raise CorrelationRequestJournalAuthorityError(
                    "completed correlation authority is no longer live"
                ) from error
            if (
                issued.get(authority) is not binding
                or authority._token is not binding.token
            ):
                raise CorrelationRequestJournalAuthorityError(
                    "completed correlation authority changed during validation"
                )
            return authenticated

    return issue, revalidate


(
    _issue_completed_snapshot_authority,
    _revalidate_single_completed_snapshot,
) = _completed_snapshot_authority_protocol()
del _completed_snapshot_authority_protocol


def _revalidate_completed_snapshot(authority: object) -> AuthenticatedPCCInput:
    if type(authority) is _CompletedSnapshotBatchItem:
        return _revalidate_completed_snapshot_batch_item(authority)
    return _revalidate_single_completed_snapshot(authority)


__all__ = [
    "CorrelationRequestJournal",
    "CorrelationRequestJournalAuthorityError",
    "CorrelationRequestJournalCorrupt",
    "CorrelationRequestJournalError",
    "CorrelationRequestJournalStateError",
    "CorrelationRequestJournalUnhealthy",
]
