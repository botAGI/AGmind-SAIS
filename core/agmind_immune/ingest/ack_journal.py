"""Core-owned durable observer ACK authority bound to one evidence lifecycle."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from _thread import LockType
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import BinaryIO, Literal, Protocol, cast

from pydantic import Field, ValidationError, field_validator

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import MAX_UINT64, ContractModel, decode_strict
from agmind_immune.evidence.frames import (
    FrameRecord,
    JournalCorrupt,
    TornTail,
    encode_frame,
    iter_frames,
)
from agmind_immune.evidence.segments import (
    EvidenceRef,
    SegmentStore,
    _AckAuthorityError,
    _AckCommitmentV1,
    _AckLifecycleCorrupt,
    _AckLifecycleIoUncertain,
    _AckLifecycleStateError,
    _full_write,
)

_JOURNAL_NAME = "ack-journal.agf"
_MAX_RECORD_BYTES = 1024
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DELIVERY_LEASE_FACTORY = object()


class _DigestState(Protocol):
    def update(self, value: bytes, /) -> None: ...

    def digest(self) -> bytes: ...

    def copy(self) -> _DigestState: ...


class AckJournalError(RuntimeError):
    """Base class for Core ACK-journal failures."""


class AckJournalCorrupt(AckJournalError):
    """A complete frame, record, transition, or evidence binding is corrupt."""


class AckJournalStateError(AckJournalError):
    """A caller requested an illegal ACK state transition."""


class AckJournalAuthorityError(AckJournalError):
    """A caller presented evidence outside the authenticated ACK prefix."""


class AckJournalUnhealthy(AckJournalError):
    """A prior append has ambiguous durability and requires restart recovery."""


class AckDeliveryLease:
    """Opaque exclusive delivery ownership for one live ACK-journal lifecycle."""

    _journal: AckJournal | None
    _lifecycle_identity: object
    _released: bool

    def __init__(
        self,
        journal: AckJournal,
        lifecycle_identity: object,
        *,
        _factory: object | None = None,
    ) -> None:
        if _factory is not _DELIVERY_LEASE_FACTORY:
            raise TypeError("use AckJournal.claim_delivery()")
        self._journal = journal
        self._lifecycle_identity = lifecycle_identity
        self._released = False

    def release(self) -> None:
        """Idempotently surrender delivery ownership to the bound journal."""
        journal = self._journal
        if journal is None or self._released:
            return
        journal._release_delivery_claim(self, self._lifecycle_identity)


class _AckJournalRecordV1(ContractModel):
    schema_version: Literal["agmind.core-ack-journal-record.v1"]
    kind: Literal["pending_ack", "confirmed_ack"]
    sequence: int = Field(ge=1, le=MAX_UINT64)
    event_id: str
    content_sha256: str

    @field_validator("event_id")
    @classmethod
    def event_id_is_exact(cls, value: str) -> str:
        if not _EVENT_ID.fullmatch(value):
            raise ValueError("ACK event_id is invalid")
        return value

    @field_validator("content_sha256")
    @classmethod
    def content_hash_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("ACK content hash is invalid")
        return value


@dataclass(frozen=True)
class AckIdentity:
    sequence: int
    event_id: str
    content_sha256: str

    @classmethod
    def from_ref(cls, ref: EvidenceRef) -> AckIdentity:
        return cls(
            sequence=ref.source_sequence,
            event_id=ref.event_id,
            content_sha256=ref.content_sha256,
        )


@dataclass(frozen=True)
class AckJournalSnapshot:
    confirmed: AckIdentity | None
    pending: AckIdentity | None
    healthy: bool

    @property
    def confirmed_through(self) -> int:
        return 0 if self.confirmed is None else self.confirmed.sequence


@dataclass(frozen=True)
class _ConfirmedBoundary:
    generation: int
    confirmed: AckIdentity | None
    prefix_size: int
    prefix_sha256: str


def _validate_journal_stat(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise AckJournalCorrupt("unsafe ACK-journal artifact")


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


def _primary_io_error(error: _AckLifecycleIoUncertain) -> BaseException:
    cause: BaseException | None = error.__cause__
    while cause is not None:
        if isinstance(cause, OSError):
            return cause
        cause = cause.__cause__
    return error


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


class AckJournal:
    """One sequential AGF1 ACK authority leased from a ready SegmentStore."""

    _store: SegmentStore
    _step_hook: Callable[[str], None]
    _root_descriptor: int
    _descriptor: int
    _lifecycle_identity: object
    _previous_hash: bytes
    _confirmed: AckIdentity | None
    _pending: AckIdentity | None
    _healthy: bool
    _closed: bool
    _closing: bool
    _size: int
    _authenticated_stat: os.stat_result | None
    _authenticated_hasher: _DigestState | None
    _confirmed_generation: int
    _committed_prefix_size: int
    _committed_prefix_sha256: str
    _delivery_lock: LockType
    _delivery_lease: AckDeliveryLease | None

    def __init__(self) -> None:
        raise TypeError("use AckJournal.create_new() or open_and_recover()")

    @classmethod
    def create_new(
        cls,
        segment_store: SegmentStore,
        *,
        step_hook: Callable[[str], None] | None = None,
    ) -> AckJournal:
        """Explicitly initialize one absent journal on an authenticated store."""
        return cls._open_bound(
            segment_store,
            create=True,
            step_hook=step_hook,
        )

    @classmethod
    def open_and_recover(
        cls,
        segment_store: SegmentStore,
        *,
        step_hook: Callable[[str], None] | None = None,
    ) -> AckJournal:
        """Recover one existing journal without ever recreating lost authority."""
        return cls._open_bound(
            segment_store,
            create=False,
            step_hook=step_hook,
        )

    @classmethod
    def _open_bound(
        cls,
        segment_store: SegmentStore,
        *,
        create: bool,
        step_hook: Callable[[str], None] | None,
    ) -> AckJournal:
        journal = object.__new__(cls)
        journal._store = segment_store
        journal._step_hook = step_hook or (lambda _step: None)
        journal._root_descriptor = -1
        journal._descriptor = -1
        journal._lifecycle_identity = object()
        journal._previous_hash = bytes(32)
        journal._confirmed = None
        journal._pending = None
        journal._healthy = True
        journal._closed = False
        journal._closing = False
        journal._size = 0
        journal._authenticated_stat = None
        journal._authenticated_hasher = None
        journal._confirmed_generation = 0
        journal._committed_prefix_size = 0
        journal._committed_prefix_sha256 = hashlib.sha256(b"").hexdigest()
        journal._delivery_lock = Lock()
        journal._delivery_lease = None
        try:
            root_descriptor, lifecycle_identity = (
                segment_store._acquire_ack_journal(
                    journal,
                    operation="create" if create else "recover",
                )
            )
            journal._root_descriptor = root_descriptor
            journal._lifecycle_identity = lifecycle_identity
            view = segment_store._ack_commitment_recovery_view(
                journal,
                journal._lifecycle_identity,
            )
            if create:
                if view.commitment is not None or view.journal_present:
                    raise AckJournalCorrupt(
                        "fresh ACK initialization found existing authority"
                    )
                segment_store._publish_ack_initializing_genesis(
                    journal,
                    journal._lifecycle_identity,
                )
                journal._descriptor = journal._create_new()
                journal._recover(
                    segment_store._ack_genesis_commitment("initializing")
                )
                segment_store._publish_ack_ready_genesis(
                    journal,
                    journal._lifecycle_identity,
                )
            else:
                commitment = view.commitment
                if commitment is None:
                    raise AckJournalCorrupt(
                        "ACK journal has no final commitment"
                    )
                if commitment.phase == "initializing":
                    journal._descriptor = (
                        journal._open_existing()
                        if view.journal_present
                        else journal._create_new()
                    )
                else:
                    if not view.journal_present:
                        raise AckJournalCorrupt(
                            "ready ACK commitment has no journal"
                        )
                    journal._descriptor = journal._open_existing()
                journal._recover(commitment)
                if commitment.phase == "initializing":
                    segment_store._publish_ack_ready_genesis(
                        journal,
                        journal._lifecycle_identity,
                    )
            authenticated = journal._bind_published_or_latch()
            segment_store._complete_ack_journal_initialization(
                journal,
                journal._lifecycle_identity,
                authenticated,
                journal._authenticated_digest(),
            )
            return journal
        except _AckLifecycleIoUncertain as error:
            journal._healthy = False
            primary = _primary_io_error(error)
            journal._close_after_failed_open(primary)
            raise primary from error
        except _AckLifecycleCorrupt as error:
            corrupt_error = AckJournalCorrupt(str(error))
            journal._healthy = False
            journal._attempt_corruption_fence(corrupt_error)
            journal._close_after_failed_open(corrupt_error)
            raise corrupt_error from error
        except _AckLifecycleStateError as error:
            state_error = AckJournalStateError(str(error))
            journal._close_after_failed_open(state_error)
            raise state_error from error
        except AckJournalCorrupt as corrupt_error:
            journal._healthy = False
            journal._attempt_corruption_fence(corrupt_error)
            journal._close_after_failed_open(corrupt_error)
            raise
        except BaseException as open_error:
            journal._close_after_failed_open(open_error)
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
            raise AckJournalCorrupt(
                "ACK journal appeared during explicit fresh initialization"
            ) from error
        try:
            self._store._ack_journal_final_name_created(
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
                raise AckJournalCorrupt(
                    "created ACK journal changed before root sync"
                )
            os.fsync(descriptor)
            self._step_hook("create_file_fsync")
            os.fsync(self._root_descriptor)
            self._step_hook("create_directory_fsync")
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
        except FileNotFoundError as error:
            raise AckJournalCorrupt(
                "startup-observed ACK journal disappeared before recovery"
            ) from error
        except OSError as error:
            raise AckJournalCorrupt(
                "startup-observed ACK journal became unavailable before recovery"
            ) from error
        _validate_journal_stat(expected)
        try:
            descriptor = os.open(
                _JOURNAL_NAME,
                flags,
                dir_fd=self._root_descriptor,
            )
        except OSError as error:
            raise AckJournalCorrupt(
                "startup-observed ACK journal disappeared during recovery open"
            ) from error
        try:
            opened = os.fstat(descriptor)
            _validate_journal_stat(opened)
            if not _same_file(opened, expected):
                raise AckJournalCorrupt("ACK journal changed during authenticated open")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _recover(self, commitment: _AckCommitmentV1) -> None:
        expected = os.fstat(self._descriptor)
        _validate_journal_stat(expected)
        read_descriptor = os.dup(self._descriptor)
        os.set_inheritable(read_descriptor, False)
        os.lseek(read_descriptor, 0, os.SEEK_SET)
        confirmed: AckIdentity | None = None
        pending: AckIdentity | None = None
        previous_hash = bytes(32)
        torn_verified: int | None = None
        authenticated_hasher: _DigestState = hashlib.sha256()
        generation = 0
        verified_size = 0
        boundaries = [
            _ConfirmedBoundary(
                generation=0,
                confirmed=None,
                prefix_size=0,
                prefix_sha256=hashlib.sha256(b"").hexdigest(),
            )
        ]
        try:
            with os.fdopen(
                read_descriptor,
                "rb",
                buffering=0,
                closefd=True,
            ) as stream:
                bounded_stream = _BoundedReader(
                    cast(BinaryIO, stream),
                    expected.st_size,
                )
                try:
                    for frame in iter_frames(
                        cast(BinaryIO, bounded_stream),
                        max_frame=_MAX_RECORD_BYTES,
                    ):
                        record, identity = self._decode_frame_record(frame)
                        confirmed, pending = self._recover_frame(
                            record,
                            identity,
                            confirmed=confirmed,
                            pending=pending,
                        )
                        authenticated_frame = encode_frame(
                            frame.payload,
                            previous_hash=frame.previous_hash,
                            max_frame=_MAX_RECORD_BYTES,
                        )
                        if (
                            len(authenticated_frame) != frame.size
                            or authenticated_frame[-32:] != frame.record_hash
                        ):
                            raise AckJournalCorrupt(
                                "verified ACK frame cannot be reconstructed"
                            )
                        authenticated_hasher.update(authenticated_frame)
                        verified_size += len(authenticated_frame)
                        previous_hash = frame.record_hash
                        if record.kind == "confirmed_ack":
                            generation += 1
                            boundaries.append(
                                _ConfirmedBoundary(
                                    generation=generation,
                                    confirmed=identity,
                                    prefix_size=verified_size,
                                    prefix_sha256=authenticated_hasher.digest().hex(),
                                )
                            )
                except TornTail as error:
                    torn_verified = error.verified_bytes
        except JournalCorrupt as error:
            raise AckJournalCorrupt("complete ACK-journal frame is corrupt") from error

        after = os.fstat(self._descriptor)
        published = self._bind_published()
        if not _same_file(after, expected) or not _same_file(published, expected):
            raise AckJournalCorrupt(
                "ACK journal changed during held-descriptor recovery"
            )

        committed_boundary: _ConfirmedBoundary | None
        if commitment.phase == "initializing":
            if (
                commitment
                != self._store._ack_genesis_commitment("initializing")
                or expected.st_size != 0
                or generation != 0
                or pending is not None
                or torn_verified is not None
            ):
                raise AckJournalCorrupt(
                    "initializing ACK commitment does not bind an empty journal"
                )
            committed_boundary = boundaries[0]
        else:
            committed_boundary = next(
                (
                    boundary
                    for boundary in boundaries
                    if self._commitment_matches_boundary(
                        commitment,
                        boundary,
                    )
                ),
                None,
            )
            if committed_boundary is None:
                raise AckJournalCorrupt(
                    "ACK commitment does not match a complete journal prefix"
                )
            ahead = generation - commitment.generation
            if ahead < 0 or ahead > 1:
                raise AckJournalCorrupt(
                    "ACK journal confirmation count violates commitment floor"
                )
            if ahead == 1:
                if pending is not None or torn_verified is not None:
                    raise AckJournalCorrupt(
                        "one-ahead ACK confirmation has trailing journal state"
                    )
                next_boundary = boundaries[-1]
                next_confirmed = next_boundary.confirmed
                if (
                    next_boundary.generation != commitment.generation + 1
                    or next_confirmed is None
                ):
                    raise AckJournalCorrupt(
                        "one-ahead ACK confirmation is not one exact transition"
                    )
                commitment = self._store._publish_ack_ready_generation(
                    self,
                    self._lifecycle_identity,
                    generation=next_boundary.generation,
                    sequence=next_confirmed.sequence,
                    event_id=next_confirmed.event_id,
                    content_sha256=next_confirmed.content_sha256,
                    journal_prefix_size=next_boundary.prefix_size,
                    journal_prefix_sha256=next_boundary.prefix_sha256,
                    step_hook=self._step_hook,
                )
                committed_boundary = next_boundary
            else:
                self._store._remove_ack_commitment_temporary(
                    self,
                    self._lifecycle_identity,
                )

        authenticated_stat = published
        if torn_verified is not None:
            os.ftruncate(self._descriptor, torn_verified)
            self._step_hook("repair_truncate")
            os.fsync(self._descriptor)
            self._step_hook("repair_file_fsync")
            repaired = os.fstat(self._descriptor)
            _validate_journal_stat(repaired)
            published_repaired = self._bind_published()
            if (
                repaired.st_size != torn_verified
                or not _same_file(repaired, published_repaired)
            ):
                raise AckJournalCorrupt("ACK torn-tail repair size is uncertain")
            authenticated_stat = published_repaired
        self._previous_hash = previous_hash
        self._confirmed = confirmed
        self._pending = pending
        self._size = (
            torn_verified
            if torn_verified is not None
            else expected.st_size
        )
        self._authenticated_stat = authenticated_stat
        self._authenticated_hasher = authenticated_hasher
        self._confirmed_generation = committed_boundary.generation
        self._committed_prefix_size = committed_boundary.prefix_size
        self._committed_prefix_sha256 = committed_boundary.prefix_sha256

    @staticmethod
    def _commitment_matches_boundary(
        commitment: _AckCommitmentV1,
        boundary: _ConfirmedBoundary,
    ) -> bool:
        confirmed = commitment.confirmed
        identity = boundary.confirmed
        return (
            commitment.generation == boundary.generation
            and commitment.journal_prefix_size == boundary.prefix_size
            and commitment.journal_prefix_sha256 == boundary.prefix_sha256
            and (
                (confirmed is None and identity is None)
                or (
                    confirmed is not None
                    and identity is not None
                    and confirmed.sequence == identity.sequence
                    and confirmed.event_id == identity.event_id
                    and confirmed.content_sha256 == identity.content_sha256
                )
            )
        )

    @staticmethod
    def _decode_frame_record(
        frame: FrameRecord,
    ) -> tuple[_AckJournalRecordV1, AckIdentity]:
        try:
            record = decode_strict(
                frame.payload,
                _AckJournalRecordV1,
                _MAX_RECORD_BYTES,
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise AckJournalCorrupt("ACK-journal record schema is invalid") from error
        if frame.payload != canonical_json(record):
            raise AckJournalCorrupt("ACK-journal record is not canonical JSON")
        return record, AckIdentity(
            sequence=record.sequence,
            event_id=record.event_id,
            content_sha256=record.content_sha256,
        )

    def _recover_frame(
        self,
        record: _AckJournalRecordV1,
        identity: AckIdentity,
        *,
        confirmed: AckIdentity | None,
        pending: AckIdentity | None,
    ) -> tuple[AckIdentity | None, AckIdentity | None]:
        if record.kind == "pending_ack":
            if pending is not None:
                raise AckJournalCorrupt(
                    "ACK journal contains more than one unmatched pending record"
                )
            confirmed_through = 0 if confirmed is None else confirmed.sequence
            try:
                ref = self._store._validate_ack_identity(
                    self,
                    self._lifecycle_identity,
                    sequence=identity.sequence,
                    event_id=identity.event_id,
                    content_sha256=identity.content_sha256,
                )
                self._store._validate_next_ack_ref(
                    self,
                    self._lifecycle_identity,
                    ref,
                    confirmed_through=confirmed_through,
                )
            except _AckAuthorityError as error:
                raise AckJournalCorrupt(
                    "pending ACK does not bind the next authenticated ref"
                ) from error
            return confirmed, identity
        if pending is None or identity != pending:
            raise AckJournalCorrupt(
                "confirmed ACK does not exactly match one pending record"
            )
        try:
            self._store._validate_ack_identity(
                self,
                self._lifecycle_identity,
                sequence=identity.sequence,
                event_id=identity.event_id,
                content_sha256=identity.content_sha256,
            )
        except _AckAuthorityError as error:
            raise AckJournalCorrupt(
                "confirmed ACK does not bind authenticated evidence"
            ) from error
        return identity, None

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
            raise AckJournalCorrupt(
                "ACK journal disappeared from its authenticated root"
            ) from error
        _validate_journal_stat(published)
        if not _same_file(opened, published):
            raise AckJournalCorrupt(
                "ACK journal root name no longer binds the retained inode"
            )
        return published

    def _bind_published_or_latch(self) -> os.stat_result:
        try:
            published = self._bind_published()
            retained = self._authenticated_stat
            if retained is None or not _same_file(published, retained):
                raise AckJournalCorrupt(
                    "ACK-journal identity changed outside its durable writer"
                )
        except AckJournalCorrupt as primary:
            self._healthy = False
            self._attempt_corruption_fence(primary)
            raise
        except OSError as error:
            retained_error = AckJournalCorrupt(
                "ACK-journal retained inode became unavailable"
            )
            self._healthy = False
            self._attempt_corruption_fence(retained_error)
            raise retained_error from error
        return published

    def _authenticated_digest(self) -> bytes:
        authenticated_hasher = self._authenticated_hasher
        if authenticated_hasher is None:
            raise AckJournalCorrupt(
                "ACK journal has no authenticated content anchor"
            )
        return authenticated_hasher.digest()

    def _hash_held_prefix(self, size: int) -> bytes:
        digest = hashlib.sha256()
        offset = 0
        while offset < size:
            chunk = os.pread(
                self._descriptor,
                min(1024 * 1024, size - offset),
                offset,
            )
            if not chunk:
                raise AckJournalCorrupt(
                    "ACK journal shortened during content verification"
                )
            digest.update(chunk)
            offset += len(chunk)
        return digest.digest()

    def _verify_authenticated_content(self) -> os.stat_result:
        before = self._bind_published_or_latch()
        actual_digest = self._hash_held_prefix(self._size)
        after = self._bind_published_or_latch()
        if (
            not _same_file(after, before)
            or actual_digest != self._authenticated_digest()
        ):
            raise AckJournalCorrupt(
                "ACK-journal content differs from its authenticated anchor"
            )
        return after

    def _require_open(self) -> None:
        if self._closed or self._closing:
            raise AckJournalStateError("ACK journal is closed")

    def _require_usable(self) -> None:
        self._require_open()
        if not self._healthy:
            raise AckJournalUnhealthy(
                "ACK-journal durability is ambiguous until restart recovery"
            )
        try:
            self._store._validate_ack_journal_owner(
                self,
                self._lifecycle_identity,
            )
        except _AckLifecycleIoUncertain as error:
            self._healthy = False
            primary = _primary_io_error(error)
            self._attempt_commitment_uncertain(primary)
            raise primary from error
        except _AckLifecycleCorrupt as error:
            corrupt_error = AckJournalCorrupt(str(error))
            self._healthy = False
            self._attempt_corruption_fence(corrupt_error)
            raise corrupt_error from error
        except _AckLifecycleStateError as error:
            raise AckJournalStateError(str(error)) from error
        self._bind_published_or_latch()

    def _append(
        self,
        kind: Literal["pending_ack", "confirmed_ack"],
        identity: AckIdentity,
    ) -> None:
        payload = canonical_json(
            {
                "schema_version": "agmind.core-ack-journal-record.v1",
                "kind": kind,
                "sequence": identity.sequence,
                "event_id": identity.event_id,
                "content_sha256": identity.content_sha256,
            }
        )
        frame = encode_frame(
            payload,
            previous_hash=self._previous_hash,
            max_frame=_MAX_RECORD_BYTES,
        )
        authenticated_before: os.stat_result | None = None
        authenticated_digest_before: bytes | None = None
        authenticated_after: os.stat_result | None = None
        authenticated_hasher_after: _DigestState | None = None
        try:
            authenticated_before = self._bind_published_or_latch()
            authenticated_digest_before = self._authenticated_digest()
            before = os.fstat(self._descriptor)
            if not _same_file(before, authenticated_before):
                raise AckJournalCorrupt(
                    "ACK-journal append did not start at its authenticated identity"
                )
            _full_write(self._descriptor, frame)
            self._step_hook("record_write")
            os.fsync(self._descriptor)
            self._step_hook("record_file_fsync")
            after = self._bind_published()
            expected_size = before.st_size + len(frame)
            if after.st_size != expected_size:
                raise AckJournalCorrupt(
                    "ACK-journal append size includes an unexpected concurrent write"
                )
            if os.pread(self._descriptor, len(frame), before.st_size) != frame:
                raise AckJournalCorrupt(
                    "ACK-journal appended bytes differ from the durable frame"
                )
            authenticated_after = self._bind_published()
            if not _same_file(authenticated_after, after):
                raise AckJournalCorrupt(
                    "ACK-journal identity changed during append verification"
                )
            authenticated_hasher = self._authenticated_hasher
            if authenticated_hasher is None:
                raise AckJournalCorrupt(
                    "ACK journal lost its authenticated content anchor"
                )
            authenticated_hasher_after = authenticated_hasher.copy()
            authenticated_hasher_after.update(frame)
        except AckJournalCorrupt as primary:
            self._healthy = False
            self._attempt_corruption_fence(primary)
            raise
        except BaseException as primary:
            self._healthy = False
            if (
                authenticated_before is None
                or authenticated_digest_before is None
            ):
                primary.add_note(
                    "ACK append failed before its retained pre-append "
                    "identity could be latched"
                )
            else:
                self._attempt_append_uncertain(
                    primary,
                    authenticated_before,
                    authenticated_digest_before,
                )
            raise
        if (
            authenticated_after is None
            or authenticated_hasher_after is None
        ):
            raise AssertionError("successful ACK append lost its anchor")
        self._size = expected_size
        self._previous_hash = frame[-32:]
        self._authenticated_stat = authenticated_after
        self._authenticated_hasher = authenticated_hasher_after

    def record_pending(self, ref: EvidenceRef) -> None:
        """Durably establish the one exact observer ACK permitted in flight."""
        self._require_usable()
        identity = AckIdentity.from_ref(ref)
        if self._pending is not None:
            if identity == self._pending:
                try:
                    self._store.resolve_authenticated_ref(ref)
                except _AckAuthorityError as error:
                    raise AckJournalAuthorityError(str(error)) from error
                return
            raise AckJournalStateError("a different ACK is already pending")
        confirmed_through = (
            0 if self._confirmed is None else self._confirmed.sequence
        )
        try:
            self._store._validate_next_ack_ref(
                self,
                self._lifecycle_identity,
                ref,
                confirmed_through=confirmed_through,
            )
        except _AckAuthorityError as error:
            raise AckJournalAuthorityError(str(error)) from error
        self._append("pending_ack", identity)
        self._pending = identity

    def record_confirmed(self, ref: EvidenceRef) -> None:
        """Durably confirm only the exact currently pending ACK identity."""
        self._require_usable()
        identity = AckIdentity.from_ref(ref)
        if self._pending is None:
            if identity == self._confirmed:
                try:
                    self._store.resolve_authenticated_ref(ref)
                except _AckAuthorityError as error:
                    raise AckJournalAuthorityError(str(error)) from error
                return
            raise AckJournalStateError("no matching ACK is pending")
        if identity != self._pending:
            raise AckJournalStateError("confirmed ACK differs from pending identity")
        try:
            self._store._validate_ack_identity(
                self,
                self._lifecycle_identity,
                sequence=identity.sequence,
                event_id=identity.event_id,
                content_sha256=identity.content_sha256,
            )
            self._store.resolve_authenticated_ref(ref)
        except _AckAuthorityError as error:
            raise AckJournalAuthorityError(str(error)) from error
        self._append("confirmed_ack", identity)
        next_generation = self._confirmed_generation + 1
        next_prefix_size = self._size
        next_prefix_sha256 = self._authenticated_digest().hex()
        try:
            self._store._publish_ack_ready_generation(
                self,
                self._lifecycle_identity,
                generation=next_generation,
                sequence=identity.sequence,
                event_id=identity.event_id,
                content_sha256=identity.content_sha256,
                journal_prefix_size=next_prefix_size,
                journal_prefix_sha256=next_prefix_sha256,
                step_hook=self._step_hook,
            )
        except _AckLifecycleIoUncertain as error:
            self._healthy = False
            primary = _primary_io_error(error)
            self._attempt_commitment_uncertain(primary)
            raise primary from error
        except _AckLifecycleCorrupt as error:
            corrupt_error = AckJournalCorrupt(str(error))
            self._healthy = False
            self._attempt_corruption_fence(corrupt_error)
            raise corrupt_error from error
        except BaseException as primary:
            self._healthy = False
            self._attempt_commitment_uncertain(primary)
            raise
        self._confirmed_generation = next_generation
        self._committed_prefix_size = next_prefix_size
        self._committed_prefix_sha256 = next_prefix_sha256
        self._confirmed = identity
        self._pending = None

    def snapshot(self) -> AckJournalSnapshot:
        self._require_open()
        if self._healthy:
            try:
                self._store._validate_ack_commitment_binding()
            except _AckLifecycleIoUncertain as error:
                self._healthy = False
                primary = _primary_io_error(error)
                self._attempt_commitment_uncertain(primary)
                raise primary from error
            except _AckLifecycleCorrupt as error:
                corrupt_error = AckJournalCorrupt(str(error))
                self._healthy = False
                self._attempt_corruption_fence(corrupt_error)
                raise corrupt_error from error
            self._bind_published_or_latch()
        return AckJournalSnapshot(
            confirmed=self._confirmed,
            pending=self._pending,
            healthy=self._healthy,
        )

    def pending_request_body(self) -> bytes | None:
        """Return byte-stable canonical observer ACK JSON for restart retry."""
        self._require_usable()
        pending = self._pending
        if pending is None:
            return None
        return canonical_json(
            {
                "schema_version": "agmind.observer-ack.v1",
                "sequence": pending.sequence,
                "event_id": pending.event_id,
                "content_sha256": pending.content_sha256,
            }
        )

    def claim_delivery(self, segment_store: SegmentStore) -> AckDeliveryLease:
        """Claim the one delivery writer bound to this exact live store."""
        with self._delivery_lock:
            self._require_usable()
            if segment_store is not self._store:
                raise AckJournalAuthorityError(
                    "delivery store differs from the ACK-journal authority"
                )
            if self._delivery_lease is not None:
                raise AckJournalStateError(
                    "ACK journal already has one delivery owner"
                )
            lease = AckDeliveryLease(
                self,
                self._lifecycle_identity,
                _factory=_DELIVERY_LEASE_FACTORY,
            )
            self._delivery_lease = lease
            return lease

    def _release_delivery_claim(
        self,
        lease: AckDeliveryLease,
        lifecycle_identity: object,
    ) -> None:
        with self._delivery_lock:
            if lease._released:
                return
            if (
                lease._journal is not self
                or lifecycle_identity is not self._lifecycle_identity
                or self._delivery_lease is not lease
            ):
                raise AckJournalStateError(
                    "delivery lease is outside this ACK-journal lifecycle"
                )
            self._delivery_lease = None
            lease._released = True
            lease._journal = None

    def _invalidate_delivery_claim_locked(self) -> None:
        lease = self._delivery_lease
        self._delivery_lease = None
        if lease is not None:
            lease._released = True
            lease._journal = None

    def _attempt_corruption_fence(self, primary: AckJournalCorrupt) -> None:
        try:
            self._store._trip_ack_journal_corrupt()
        except Exception as error:  # noqa: BLE001
            primary.add_note(
                "secondary ACK corruption-fence failure: "
                f"{type(error).__name__}: {error}"
            )

    def _attempt_append_uncertain(
        self,
        primary: BaseException,
        authenticated_before: os.stat_result,
        authenticated_digest_before: bytes,
    ) -> None:
        try:
            self._store._mark_ack_journal_append_uncertain(
                self,
                self._lifecycle_identity,
                authenticated_before,
                authenticated_digest_before,
            )
        except Exception as error:  # noqa: BLE001
            primary.add_note(
                "secondary ACK append-uncertainty latch failure: "
                f"{type(error).__name__}: {error}"
            )

    def _attempt_commitment_uncertain(self, primary: BaseException) -> None:
        try:
            self._store._mark_ack_commitment_uncertain(
                self,
                self._lifecycle_identity,
            )
        except Exception as error:  # noqa: BLE001
            primary.add_note(
                "secondary ACK commitment-uncertainty latch failure: "
                f"{type(error).__name__}: {error}"
            )

    def _close_resources(self) -> list[Exception]:
        cleanup_errors: list[Exception] = []
        if self._descriptor >= 0:
            try:
                os.close(self._descriptor)
            except OSError as error:
                cleanup_errors.append(error)
            finally:
                self._descriptor = -1
        if self._root_descriptor >= 0:
            try:
                os.close(self._root_descriptor)
            except OSError as error:
                cleanup_errors.append(error)
            finally:
                self._root_descriptor = -1
        if getattr(self._store, "_ack_journal_owner", None) is self:
            try:
                self._store._release_ack_journal(
                    self,
                    self._lifecycle_identity,
                )
            except Exception as error:  # noqa: BLE001
                cleanup_errors.append(error)
        self._closed = True
        return cleanup_errors

    def _close_after_failed_open(self, primary: BaseException) -> None:
        cleanup_errors = self._close_resources()
        for cleanup_error in cleanup_errors:
            primary.add_note(
                "secondary ACK failed-open cleanup failure: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )

    def _close_from_segment_store(self, lifecycle_identity: object) -> None:
        if lifecycle_identity is not self._lifecycle_identity:
            raise AckJournalStateError("store supplied the wrong ACK lifecycle")
        self.close()

    def close(self) -> None:
        with self._delivery_lock:
            if self._closed:
                return
            if self._closing:
                raise AckJournalStateError("ACK journal close is already in progress")
            self._closing = True
            self._invalidate_delivery_claim_locked()
        if self._healthy:
            try:
                authenticated = self._verify_authenticated_content()
                self._store._seal_ack_journal_identity(
                    self,
                    self._lifecycle_identity,
                    authenticated,
                    self._authenticated_digest(),
                )
            except _AckLifecycleCorrupt as error:
                corrupt_error = AckJournalCorrupt(str(error))
                self._healthy = False
                self._attempt_corruption_fence(corrupt_error)
                self._close_after_failed_open(corrupt_error)
                raise corrupt_error from error
            except _AckLifecycleStateError as error:
                state_error = AckJournalStateError(str(error))
                self._close_after_failed_open(state_error)
                raise state_error from error
            except AckJournalCorrupt as corrupt_error:
                self._healthy = False
                self._attempt_corruption_fence(corrupt_error)
                self._close_after_failed_open(corrupt_error)
                raise
            except OSError as error:
                retained_error = AckJournalCorrupt(
                    "ACK-journal retained inode became unavailable during close"
                )
                self._healthy = False
                self._attempt_corruption_fence(retained_error)
                self._close_after_failed_open(retained_error)
                raise retained_error from error
            except BaseException as primary_close_error:
                self._close_after_failed_open(primary_close_error)
                raise

        cleanup_errors = self._close_resources()
        if cleanup_errors:
            unhealthy_error = AckJournalUnhealthy(
                "ACK-journal close became uncertain"
            )
            for secondary in cleanup_errors[1:]:
                unhealthy_error.add_note(
                    "secondary ACK close cleanup failure: "
                    f"{type(secondary).__name__}: {secondary}"
                )
            raise unhealthy_error from cleanup_errors[0]
