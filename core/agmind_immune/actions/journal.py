"""Bounded append-only journal for atomic policy decision plus intent records."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import stat
from dataclasses import dataclass
from threading import Lock
from typing import Any

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.evidence.frames import (
    JournalCorrupt,
    TornTail,
    encode_frame,
    iter_frames,
)
from agmind_immune.evidence.segments import (
    SegmentStore,
    _DecisionIntentJournalLifecycleCorrupt,
    _DecisionIntentJournalLifecycleIoUncertain,
    _DecisionIntentJournalLifecycleStateError,
    _full_write,
)
from agmind_immune.policy.client import _timestamp_ns

from .models import (
    DecisionIntentCommit,
    DecisionIntentError,
    DecisionIntentValidationError,
    _commit_observation,
    _DecisionIntentRecordV1,
    _decode_decision_intent_record,
)

_JOURNAL_NAME = "decision-intents.agf"
_MAX_FRAME_PAYLOAD = 131_072
_MAX_VERIFIED_BYTES = 67_108_864
_MAX_RECORDS = 65_536
_JOURNAL_COMMIT_FACTORY = object()


class DecisionIntentJournalCorrupt(DecisionIntentError):
    """The durable frame chain, file binding, or record semantics are corrupt."""


class DecisionIntentJournalConflict(DecisionIntentError):
    """One candidate already has a different terminal decision record."""


class DecisionIntentJournalUnhealthy(DecisionIntentError):
    """A write outcome is ambiguous and requires strict reopen recovery."""


class DecisionIntentJournalBusy(DecisionIntentError):
    """Another process owns the fixed decision-intent journal."""


@dataclass(frozen=True, slots=True)
class _FileBinding:
    device: int
    inode: int
    size: int
    mode: int
    owner: int
    links: int
    modified_ns: int
    changed_ns: int


def _root_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise DecisionIntentJournalCorrupt(
            "decision-intent root is not an owner-only directory"
        )
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid)


def _file_binding(info: os.stat_result) -> _FileBinding:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or not 0 <= info.st_size <= _MAX_VERIFIED_BYTES
    ):
        raise DecisionIntentJournalCorrupt(
            "decision-intent journal artifact is unsafe or oversized"
        )
    return _FileBinding(
        device=info.st_dev,
        inode=info.st_ino,
        size=info.st_size,
        mode=info.st_mode,
        owner=info.st_uid,
        links=info.st_nlink,
        modified_ns=info.st_mtime_ns,
        changed_ns=info.st_ctime_ns,
    )


class DecisionIntentJournal:
    """One lifetime-locked, controller-owned decision/intent outbox."""

    __slots__ = (
        "_binding",
        "_closed",
        "_descriptor",
        "_hasher",
        "_healthy",
        "_last_committed_at_ns",
        "_lifecycle_identity",
        "_lock",
        "_previous_hash",
        "_raw_by_candidate",
        "_raw_in_order",
        "_root_descriptor",
        "_store",
    )

    _binding: _FileBinding | None
    _closed: bool
    _descriptor: int
    _hasher: Any
    _healthy: bool
    _last_committed_at_ns: int | None
    _lifecycle_identity: object
    _lock: Lock
    _previous_hash: bytes
    _raw_by_candidate: dict[str, bytes]
    _raw_in_order: list[bytes]
    _root_descriptor: int
    _store: SegmentStore

    def __init__(self) -> None:
        raise TypeError("use DecisionIntentJournal.open()")

    @classmethod
    def open(cls, store: SegmentStore) -> DecisionIntentJournal:
        if (
            type(store) is not SegmentStore
            or store._closed
            or type(store._root_descriptor) is not int
            or store._root_descriptor < 0
        ):
            raise DecisionIntentJournalCorrupt(
                "decision-intent journal requires one live exact evidence store"
            )
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow == 0:
            raise DecisionIntentJournalCorrupt(
                "decision-intent journal requires O_NOFOLLOW"
            )
        journal = object.__new__(cls)
        journal._store = store
        journal._lifecycle_identity = None
        journal._root_descriptor = -1
        journal._descriptor = -1
        journal._binding = None
        journal._hasher = hashlib.sha256()
        journal._last_committed_at_ns = None
        journal._previous_hash = bytes(32)
        journal._raw_by_candidate = {}
        journal._raw_in_order = []
        journal._healthy = True
        journal._closed = False
        journal._lock = Lock()
        try:
            (
                journal._root_descriptor,
                journal._lifecycle_identity,
                operation,
            ) = store._acquire_decision_intent_journal(journal)
            if _root_identity(os.fstat(journal._root_descriptor)) != _root_identity(
                os.fstat(store._root_descriptor)
            ):
                raise DecisionIntentJournalCorrupt(
                    "decision-intent root descriptor changed"
                )
            common = os.O_RDWR | os.O_APPEND | os.O_CLOEXEC | nofollow
            if operation == "recover":
                descriptor = os.open(
                    _JOURNAL_NAME,
                    common,
                    dir_fd=journal._root_descriptor,
                )
            else:
                descriptor = os.open(
                    _JOURNAL_NAME,
                    common | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=journal._root_descriptor,
                )
            journal._descriptor = descriptor
            if operation == "create":
                store._decision_intent_journal_final_name_created(
                    journal,
                    journal._lifecycle_identity,
                )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise DecisionIntentJournalBusy(
                    "decision-intent journal is already locked"
                ) from error
            if operation == "create":
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.fsync(journal._root_descriptor)
            opened_info = os.fstat(descriptor)
            opened = _file_binding(opened_info)
            named = _file_binding(
                os.stat(
                    _JOURNAL_NAME,
                    dir_fd=journal._root_descriptor,
                    follow_symlinks=False,
                )
            )
            if opened != named:
                raise DecisionIntentJournalCorrupt(
                    "decision-intent path changed while opening"
                )
            store._validate_decision_intent_journal_opened(
                journal,
                journal._lifecycle_identity,
                opened_info,
            )
            journal._binding = opened
            repaired_torn_tail = journal._recover()
            store._complete_decision_intent_journal_initialization(
                journal,
                journal._lifecycle_identity,
                os.fstat(descriptor),
                journal._hasher.digest(),
                repaired_torn_tail=repaired_torn_tail,
            )
            journal._require_bound()
            return journal
        except BaseException as error:
            journal._healthy = False
            if isinstance(
                error,
                (
                    DecisionIntentJournalCorrupt,
                    _DecisionIntentJournalLifecycleCorrupt,
                ),
            ):
                journal._attempt_corruption_fence(error)
            for cleanup_error in journal._close_resources():
                error.add_note(
                    "secondary decision-intent cleanup failure: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise

    def _close_resources(self) -> list[Exception]:
        errors: list[Exception] = []
        if self._descriptor >= 0:
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            except OSError as error:
                errors.append(error)
            try:
                os.close(self._descriptor)
            except OSError as error:
                errors.append(error)
            self._descriptor = -1
        if self._root_descriptor >= 0:
            try:
                os.close(self._root_descriptor)
            except OSError as error:
                errors.append(error)
            self._root_descriptor = -1
        if getattr(self._store, "_decision_intent_journal_owner", None) is self:
            try:
                self._store._release_decision_intent_journal(
                    self,
                    self._lifecycle_identity,
                )
            except Exception as error:  # noqa: BLE001
                errors.append(error)
        retained = (
            getattr(self._store, "_decision_intent_journal_owner", None) is self
        )
        self._closed = not retained
        return errors

    def _named_binding(self) -> _FileBinding:
        try:
            return _file_binding(
                os.stat(
                    _JOURNAL_NAME,
                    dir_fd=self._root_descriptor,
                    follow_symlinks=False,
                )
            )
        except OSError as error:
            raise DecisionIntentJournalCorrupt(
                "decision-intent journal path is unavailable"
            ) from error

    def _require_bound(self) -> None:
        if (
            self._closed
            or not self._healthy
            or self._descriptor < 0
            or self._root_descriptor < 0
            or type(self._store) is not SegmentStore
            or self._store._closed
            or self._store._lifecycle_identity is not self._lifecycle_identity
            or _root_identity(os.fstat(self._root_descriptor))
            != _root_identity(os.fstat(self._store._root_descriptor))
        ):
            raise DecisionIntentJournalUnhealthy(
                "decision-intent journal lost its evidence lifecycle"
            )
        try:
            self._store._validate_decision_intent_journal_owner(
                self,
                self._lifecycle_identity,
            )
        except (
            _DecisionIntentJournalLifecycleCorrupt,
            _DecisionIntentJournalLifecycleIoUncertain,
            _DecisionIntentJournalLifecycleStateError,
        ) as error:
            self._healthy = False
            raise DecisionIntentJournalUnhealthy(
                "decision-intent journal lost its store authority"
            ) from error
        retained = self._binding
        try:
            opened = _file_binding(os.fstat(self._descriptor))
            named = self._named_binding()
        except OSError as error:
            self._healthy = False
            raise DecisionIntentJournalUnhealthy(
                "decision-intent binding I/O is uncertain"
            ) from error
        if retained is None or opened != retained or named != retained:
            self._healthy = False
            raise DecisionIntentJournalCorrupt(
                "decision-intent journal binding changed"
            )

    def _recover(self) -> bool:
        retained = self._binding
        if retained is None:
            raise DecisionIntentJournalCorrupt(
                "decision-intent journal has no opened binding"
            )
        raw_by_candidate: dict[str, bytes] = {}
        raw_in_order: list[bytes] = []
        previous_hash = bytes(32)
        authenticated_hasher = hashlib.sha256()
        last_committed_at_ns: int | None = None
        verified_bytes = 0
        record_count = 0
        torn_verified_bytes: int | None = None
        read_descriptor = os.dup(self._descriptor)
        try:
            os.lseek(read_descriptor, 0, os.SEEK_SET)
            with os.fdopen(read_descriptor, "rb", closefd=True) as stream:
                read_descriptor = -1
                try:
                    for frame in iter_frames(
                        stream,
                        max_frame=_MAX_FRAME_PAYLOAD,
                    ):
                        record_count += 1
                        verified_bytes += frame.size
                        if (
                            record_count > _MAX_RECORDS
                            or verified_bytes > _MAX_VERIFIED_BYTES
                        ):
                            raise DecisionIntentJournalCorrupt(
                                "decision-intent journal exceeds recovery bounds"
                            )
                        try:
                            record = _decode_decision_intent_record(frame.payload)
                        except DecisionIntentValidationError as error:
                            raise DecisionIntentJournalCorrupt(
                                "decision-intent frame payload is invalid"
                            ) from error
                        if record.candidate_id in raw_by_candidate:
                            raise DecisionIntentJournalCorrupt(
                                "decision-intent journal repeats a candidate"
                            )
                        committed_at_ns = _timestamp_ns(record.committed_at)
                        if (
                            last_committed_at_ns is not None
                            and committed_at_ns < last_committed_at_ns
                        ):
                            raise DecisionIntentJournalCorrupt(
                                "decision-intent journal UTC chain rolls back"
                            )
                        encoded = encode_frame(
                            frame.payload,
                            previous_hash=frame.previous_hash,
                            max_frame=_MAX_FRAME_PAYLOAD,
                        )
                        if (
                            len(encoded) != frame.size
                            or not hmac.compare_digest(
                                encoded[-32:],
                                frame.record_hash,
                            )
                        ):
                            raise DecisionIntentJournalCorrupt(
                                "decision-intent frame bytes are not reproducible"
                            )
                        raw = bytes(frame.payload)
                        raw_by_candidate[record.candidate_id] = raw
                        raw_in_order.append(raw)
                        authenticated_hasher.update(encoded)
                        last_committed_at_ns = committed_at_ns
                        previous_hash = frame.record_hash
                except TornTail as error:
                    torn_verified_bytes = error.verified_bytes
                except JournalCorrupt as error:
                    raise DecisionIntentJournalCorrupt(
                        "decision-intent AGF1 chain is corrupt"
                    ) from error
        finally:
            if read_descriptor >= 0:
                os.close(read_descriptor)
        if torn_verified_bytes is not None:
            if torn_verified_bytes != verified_bytes:
                raise DecisionIntentJournalCorrupt(
                    "decision-intent torn-tail boundary is inconsistent"
                )
            before_repair = _file_binding(os.fstat(self._descriptor))
            named_before_repair = self._named_binding()
            if before_repair != retained or named_before_repair != retained:
                raise DecisionIntentJournalCorrupt(
                    "decision-intent changed during torn-tail verification"
                )
            try:
                os.ftruncate(self._descriptor, verified_bytes)
                os.fsync(self._descriptor)
                os.fsync(self._root_descriptor)
            except BaseException as error:
                self._healthy = False
                self._attempt_io_uncertain(error, None, None)
                if not isinstance(error, Exception):
                    raise
                raise DecisionIntentJournalUnhealthy(
                    "decision-intent torn-tail repair is uncertain"
                ) from error
        current_info = os.fstat(self._descriptor)
        current = _file_binding(current_info)
        named = self._named_binding()
        if (
            current != named
            or current.size != verified_bytes
            or (torn_verified_bytes is None and current != retained)
        ):
            raise DecisionIntentJournalCorrupt(
                "decision-intent recovery differs from authenticated bytes"
            )
        authenticated_digest = authenticated_hasher.digest()
        try:
            os.fsync(self._descriptor)
        except BaseException as error:
            self._healthy = False
            self._attempt_io_uncertain(
                error,
                current_info,
                authenticated_digest,
            )
            if not isinstance(error, Exception):
                raise
            raise DecisionIntentJournalUnhealthy(
                "decision-intent recovered prefix durability is uncertain"
            ) from error
        self._binding = current
        self._hasher = authenticated_hasher
        self._last_committed_at_ns = last_committed_at_ns
        self._previous_hash = previous_hash
        self._raw_by_candidate = raw_by_candidate
        self._raw_in_order = raw_in_order
        return torn_verified_bytes is not None

    def _attempt_corruption_fence(self, primary: BaseException) -> None:
        try:
            self._store._trip_decision_intent_journal_corrupt()
        except Exception as error:  # noqa: BLE001
            primary.add_note(
                "secondary decision-intent corruption-fence failure: "
                f"{type(error).__name__}: {error}"
            )

    def _attempt_append_uncertain(
        self,
        primary: BaseException,
        authenticated_before: os.stat_result,
        digest_before: bytes,
    ) -> None:
        try:
            self._store._mark_decision_intent_journal_append_uncertain(
                self,
                self._lifecycle_identity,
                authenticated_before,
                digest_before,
            )
        except Exception as error:  # noqa: BLE001
            primary.add_note(
                "secondary decision-intent append-uncertainty failure: "
                f"{type(error).__name__}: {error}"
            )

    def _attempt_io_uncertain(
        self,
        primary: BaseException,
        authenticated: os.stat_result | None,
        digest: bytes | None,
    ) -> None:
        try:
            self._store._mark_decision_intent_journal_io_uncertain(
                self,
                self._lifecycle_identity,
                authenticated,
                digest,
            )
        except Exception as error:  # noqa: BLE001
            primary.add_note(
                "secondary decision-intent I/O-uncertainty failure: "
                f"{type(error).__name__}: {error}"
            )

    def _is_bound_to(self, store: SegmentStore) -> bool:
        with self._lock:
            try:
                self._require_bound()
            except DecisionIntentError:
                return False
            return store is self._store

    def _commit(
        self,
        record: _DecisionIntentRecordV1,
        *,
        _factory: object,
    ) -> DecisionIntentCommit:
        if _factory is not _JOURNAL_COMMIT_FACTORY:
            raise TypeError("decision-intent append is controller-owned")
        if type(record) is not _DecisionIntentRecordV1:
            raise DecisionIntentValidationError(
                "decision-intent append requires one exact record"
            )
        raw = canonical_json(record)
        if not 1 <= len(raw) <= _MAX_FRAME_PAYLOAD:
            raise DecisionIntentValidationError(
                "decision-intent record exceeds the frame bound"
            )
        decoded = _decode_decision_intent_record(raw)
        with self._lock:
            self._require_bound()
            existing = self._raw_by_candidate.get(decoded.candidate_id)
            if existing is not None:
                if not hmac.compare_digest(existing, raw):
                    raise DecisionIntentJournalConflict(
                        "candidate already has a different durable decision"
                    )
                return _commit_observation(decoded, existing)
            committed_at_ns = _timestamp_ns(decoded.committed_at)
            if (
                self._last_committed_at_ns is not None
                and committed_at_ns < self._last_committed_at_ns
            ):
                raise DecisionIntentValidationError(
                    "decision-intent committed_at rolls back the journal clock"
                )
            if len(self._raw_in_order) >= _MAX_RECORDS:
                raise DecisionIntentJournalUnhealthy(
                    "decision-intent journal record bound is exhausted"
                )
            frame = encode_frame(
                raw,
                previous_hash=self._previous_hash,
                max_frame=_MAX_FRAME_PAYLOAD,
            )
            retained = self._binding
            if (
                retained is None
                or retained.size + len(frame) > _MAX_VERIFIED_BYTES
            ):
                raise DecisionIntentJournalUnhealthy(
                    "decision-intent journal byte bound is exhausted"
                )
            authenticated_before = os.fstat(self._descriptor)
            if _file_binding(authenticated_before) != retained:
                self._healthy = False
                raise DecisionIntentJournalCorrupt(
                    "decision-intent pre-append binding changed"
                )
            digest_before = self._hasher.digest()
            next_hasher = self._hasher.copy()
            next_hasher.update(frame)
            append_started = False
            try:
                append_started = True
                _full_write(self._descriptor, frame)
                os.fsync(self._descriptor)
                written = os.pread(
                    self._descriptor,
                    len(frame),
                    retained.size,
                )
                if not hmac.compare_digest(written, frame):
                    raise DecisionIntentJournalCorrupt(
                        "decision-intent append suffix differs from issued frame"
                    )
                current_info = os.fstat(self._descriptor)
                current = _file_binding(current_info)
                named = self._named_binding()
                if (
                    current != named
                    or current.device != retained.device
                    or current.inode != retained.inode
                    or current.size != retained.size + len(frame)
                ):
                    raise DecisionIntentJournalCorrupt(
                        "decision-intent append changed file identity"
                    )
                self._store._seal_decision_intent_journal_identity(
                    self,
                    self._lifecycle_identity,
                    current_info,
                    next_hasher.digest(),
                )
            except BaseException as error:
                self._healthy = False
                if append_started:
                    self._attempt_append_uncertain(
                        error,
                        authenticated_before,
                        digest_before,
                    )
                if not isinstance(error, Exception):
                    raise
                raise DecisionIntentJournalUnhealthy(
                    "decision-intent append durability is uncertain"
                ) from error
            self._binding = current
            self._hasher = next_hasher
            self._last_committed_at_ns = committed_at_ns
            self._previous_hash = frame[-32:]
            self._raw_by_candidate[decoded.candidate_id] = raw
            self._raw_in_order.append(raw)
            return _commit_observation(decoded, raw)

    def records(self) -> tuple[DecisionIntentCommit, ...]:
        """Return detached observations of the verified durable prefix."""
        with self._lock:
            self._require_bound()
            return tuple(
                _commit_observation(_decode_decision_intent_record(raw), raw)
                for raw in self._raw_in_order
            )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            primary: BaseException | None = None
            if self._healthy:
                authenticated: os.stat_result | None = None
                try:
                    self._require_bound()
                    authenticated = os.fstat(self._descriptor)
                    self._store._seal_decision_intent_journal_identity(
                        self,
                        self._lifecycle_identity,
                        authenticated,
                        self._hasher.digest(),
                    )
                except BaseException as error:  # noqa: BLE001
                    self._healthy = False
                    self._attempt_io_uncertain(
                        error,
                        authenticated,
                        None if authenticated is None else self._hasher.digest(),
                    )
                    primary = error
            errors = self._close_resources()
            if primary is not None:
                for cleanup_error in errors:
                    primary.add_note(
                        "secondary decision-intent close failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
                raise primary
            if primary is None and errors:
                primary = DecisionIntentJournalUnhealthy(
                    "decision-intent journal close is uncertain"
                )
                primary.__cause__ = errors[0]
            if primary is not None:
                raise primary

    def _close_from_segment_store(self, lifecycle_identity: object) -> None:
        if lifecycle_identity is not self._lifecycle_identity:
            raise DecisionIntentJournalUnhealthy(
                "store supplied the wrong decision-intent lifecycle"
            )
        self.close()


__all__ = [
    "DecisionIntentJournal",
    "DecisionIntentJournalBusy",
    "DecisionIntentJournalConflict",
    "DecisionIntentJournalCorrupt",
    "DecisionIntentJournalUnhealthy",
]
