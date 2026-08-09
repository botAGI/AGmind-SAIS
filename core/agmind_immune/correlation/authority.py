"""Fail-closed loading of the Core-visible PCC detector bundle."""

from __future__ import annotations

import os
import stat
import weakref
from _thread import RLock as RLockType
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Never, Protocol, Self, SupportsIndex, cast, final

from agmind_immune.canonicaljson import canonical_json, pcc_detector_bundle_sha256
from agmind_immune.contracts import MAX_UINT64
from agmind_immune.correlation.pcc import (
    ActiveCandidateObservation,
    CandidateDuplicateKey,
    CorrelationContext,
    CorrelationProjectionError,
    HistoricalCoverageAssessment,
    _duplicate_key,
    _exact_event_id,
    _exact_hex64,
    _exact_uuid4,
    _register_correlation_context,
)
from agmind_immune.correlation.primitives import (
    SpecialUseRegistry,
    _canonical_registry_binding,
    special_use_registry_is_issued,
)
from agmind_immune.coverage.historical import (
    HistoricalPathAuthority,
    _issue_historical_path_authority,
    derive_historical_coverage,
)
from agmind_immune.evidence.segments import EvidenceRef, SegmentStore
from agmind_immune.ingest.correlation_journal import (
    _revalidate_completed_snapshot,
)
from agmind_immune.ingest.envelope import AuthenticatedPCCInput

__all__ = ("CorrelationProjectionAuthority",)

_MAX_DETECTOR_BUNDLE_BYTES = 65_536
_DIRECTORY_COMPONENTS = ("etc", "falco", "rules.d")
_RULE_NAME = "agmind-pcc.yaml"


class _DetectorBundleUnavailable(RuntimeError):
    pass


class _Stat(Protocol):
    st_dev: int
    st_ino: int
    st_mode: int
    st_nlink: int
    st_uid: int
    st_gid: int
    st_size: int
    st_mtime_ns: int
    st_ctime_ns: int


class _Filesystem(Protocol):
    def stat(
        self,
        path: str,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> _Stat: ...

    def open(
        self,
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int: ...

    def fstat(self, descriptor: int) -> _Stat: ...

    def read(self, descriptor: int, count: int) -> bytes: ...

    def close(self, descriptor: int) -> None: ...


class _OSFilesystem:
    @staticmethod
    def stat(
        path: str,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> _Stat:
        return cast(
            _Stat,
            os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks),
        )

    @staticmethod
    def open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        return os.open(path, flags, mode, dir_fd=dir_fd)

    @staticmethod
    def fstat(descriptor: int) -> _Stat:
        return cast(_Stat, os.fstat(descriptor))

    @staticmethod
    def read(descriptor: int, count: int) -> bytes:
        return os.read(descriptor, count)

    @staticmethod
    def close(descriptor: int) -> None:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _StatBinding:
    device: int
    inode: int
    mode: int
    link_count: int
    owner: int
    group: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _DirectoryBinding:
    parent_descriptor: int | None
    name: str
    descriptor: int
    stat: _StatBinding


def _binding(info: _Stat) -> _StatBinding:
    return _StatBinding(
        device=info.st_dev,
        inode=info.st_ino,
        mode=info.st_mode,
        link_count=info.st_nlink,
        owner=info.st_uid,
        group=info.st_gid,
        size=info.st_size,
        modified_ns=info.st_mtime_ns,
        changed_ns=info.st_ctime_ns,
    )


def _validate_directory(info: _Stat) -> _StatBinding:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink < 1
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise _DetectorBundleUnavailable(
            "detector bundle parent is not a protected root-owned directory"
        )
    return _binding(info)


def _validate_rule(info: _Stat) -> _StatBinding:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o444
        or not 1 <= info.st_size <= _MAX_DETECTOR_BUNDLE_BYTES
    ):
        raise _DetectorBundleUnavailable(
            "detector bundle is not a protected root-owned read-only file"
        )
    return _binding(info)


def _require_same(actual: _StatBinding, expected: _StatBinding) -> None:
    if actual != expected:
        raise _DetectorBundleUnavailable("detector bundle path changed while loading")


def _load_from_filesystem(filesystem: _Filesystem) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if nofollow == 0 or directory == 0:
        raise _DetectorBundleUnavailable(
            "detector bundle loading requires O_NOFOLLOW and O_DIRECTORY"
        )
    common_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    directory_flags = common_flags | directory

    descriptors: list[int] = []
    directories: list[_DirectoryBinding] = []
    result: str | None = None
    failure: BaseException | None = None
    try:
        named_root = _validate_directory(filesystem.stat("/", follow_symlinks=False))
        root_descriptor = filesystem.open("/", directory_flags)
        descriptors.append(root_descriptor)
        opened_root = _validate_directory(filesystem.fstat(root_descriptor))
        _require_same(opened_root, named_root)
        directories.append(
            _DirectoryBinding(None, "/", root_descriptor, opened_root)
        )

        parent_descriptor = root_descriptor
        for component in _DIRECTORY_COMPONENTS:
            named = _validate_directory(
                filesystem.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            )
            child_descriptor = filesystem.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            descriptors.append(child_descriptor)
            opened = _validate_directory(filesystem.fstat(child_descriptor))
            _require_same(opened, named)
            directories.append(
                _DirectoryBinding(
                    parent_descriptor,
                    component,
                    child_descriptor,
                    opened,
                )
            )
            parent_descriptor = child_descriptor

        named_rule = _validate_rule(
            filesystem.stat(
                _RULE_NAME,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        )
        rule_descriptor = filesystem.open(
            _RULE_NAME,
            common_flags,
            dir_fd=parent_descriptor,
        )
        descriptors.append(rule_descriptor)
        opened_rule = _validate_rule(filesystem.fstat(rule_descriptor))
        _require_same(opened_rule, named_rule)

        raw = filesystem.read(rule_descriptor, _MAX_DETECTOR_BUNDLE_BYTES + 1)
        if type(raw) is not bytes:
            raise _DetectorBundleUnavailable("detector bundle read did not return exact bytes")
        if len(raw) != opened_rule.size or not 1 <= len(raw) <= _MAX_DETECTOR_BUNDLE_BYTES:
            raise _DetectorBundleUnavailable(
                "detector bundle read was short, extra, empty, or oversized"
            )

        post_read_rule = _validate_rule(filesystem.fstat(rule_descriptor))
        _require_same(post_read_rule, opened_rule)

        for held in directories:
            if held.parent_descriptor is None:
                final_named = filesystem.stat("/", follow_symlinks=False)
            else:
                final_named = filesystem.stat(
                    held.name,
                    dir_fd=held.parent_descriptor,
                    follow_symlinks=False,
                )
            _require_same(_validate_directory(final_named), held.stat)
            _require_same(
                _validate_directory(filesystem.fstat(held.descriptor)),
                held.stat,
            )

        final_named_rule = _validate_rule(
            filesystem.stat(
                _RULE_NAME,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        )
        _require_same(final_named_rule, opened_rule)
        result = pcc_detector_bundle_sha256(raw)
    except BaseException as error:  # noqa: BLE001 - descriptors close before cancellation.
        failure = error

    close_failure: OSError | None = None
    for descriptor in reversed(descriptors):
        try:
            filesystem.close(descriptor)
        except OSError as error:
            if close_failure is None:
                close_failure = error

    if failure is not None:
        if isinstance(failure, _DetectorBundleUnavailable):
            raise failure
        if isinstance(failure, (OSError, OverflowError, TypeError, ValueError)):
            raise _DetectorBundleUnavailable("detector bundle loading failed") from failure
        raise failure
    if close_failure is not None:
        raise _DetectorBundleUnavailable("detector bundle descriptor close failed") from close_failure
    if result is None:
        raise _DetectorBundleUnavailable("detector bundle loading produced no result")
    return result


def _detector_bundle_loader(filesystem: _Filesystem) -> Callable[[], str]:
    """Create the private no-argument loader around one filesystem boundary."""

    def load() -> str:
        return _load_from_filesystem(filesystem)

    return load


_load_pinned_detector_bundle = _detector_bundle_loader(_OSFilesystem())


@final
@dataclass(frozen=True, slots=True)
class _ProjectionPredecessor:
    generation: int
    host_id: str | None
    source_sequence: int
    event_id: str | None
    content_sha256: str | None
    frame_sha256: str | None

    def __post_init__(self) -> None:
        if (
            type(self.generation) is not int
            or not 0 <= self.generation <= MAX_UINT64
        ):
            raise ValueError("projection generation must be an exact uint64")
        if type(self.source_sequence) is not int:
            raise TypeError("projection source sequence must be an exact integer")
        optional = (
            self.host_id,
            self.event_id,
            self.content_sha256,
            self.frame_sha256,
        )
        if self.source_sequence == 0:
            if any(value is not None for value in optional):
                raise ValueError("empty projection cursor must have no identity facts")
            return
        if self.source_sequence < 0 or self.source_sequence > MAX_UINT64:
            raise ValueError("projection source sequence must be a positive uint64")
        _exact_uuid4(self.host_id, "projection host_id")
        _exact_event_id(self.event_id, "projection event_id")
        _exact_hex64(self.content_sha256, "projection content_sha256")
        _exact_hex64(self.frame_sha256, "projection frame_sha256")


_PROJECTION_PREDECESSOR_SEAL_DOMAIN = (
    b"AGMIND_CORRELATION_PROJECTION_PREDECESSOR_SEAL_V1\0"
)


@dataclass(frozen=True, slots=True)
class _ProjectionPredecessorSeal:
    predecessor: _ProjectionPredecessor
    generation: int
    host_id: str | None
    source_sequence: int
    event_id: str | None
    content_sha256: str | None
    frame_sha256: str | None
    canonical: bytes


def _seal_projection_predecessor(
    value: _ProjectionPredecessor,
) -> _ProjectionPredecessorSeal:
    if type(value) is not _ProjectionPredecessor:
        raise TypeError("projection predecessor is not exact")
    generation = value.generation
    source_sequence = value.source_sequence
    optional = (
        value.host_id,
        value.event_id,
        value.content_sha256,
        value.frame_sha256,
    )
    if (
        type(generation) is not int
        or not 0 <= generation <= MAX_UINT64
        or type(source_sequence) is not int
        or not 0 <= source_sequence <= MAX_UINT64
    ):
        raise ValueError("projection predecessor scalar facts are invalid")
    if source_sequence == 0:
        if any(item is not None for item in optional):
            raise ValueError("empty projection predecessor has identity facts")
    else:
        _exact_uuid4(value.host_id, "projection host_id")
        _exact_event_id(value.event_id, "projection event_id")
        _exact_hex64(value.content_sha256, "projection content_sha256")
        _exact_hex64(value.frame_sha256, "projection frame_sha256")
    tagged_optional = tuple(
        ("none",) if item is None else ("str", item)
        for item in optional
    )
    canonical = _PROJECTION_PREDECESSOR_SEAL_DOMAIN + canonical_json(
        (
            ("generation", "int", str(generation)),
            ("host_id", tagged_optional[0]),
            ("source_sequence", "int", str(source_sequence)),
            ("event_id", tagged_optional[1]),
            ("content_sha256", tagged_optional[2]),
            ("frame_sha256", tagged_optional[3]),
        )
    )
    return _ProjectionPredecessorSeal(
        predecessor=value,
        generation=generation,
        host_id=value.host_id,
        source_sequence=source_sequence,
        event_id=value.event_id,
        content_sha256=value.content_sha256,
        frame_sha256=value.frame_sha256,
        canonical=canonical,
    )


def _projection_predecessor_seal_is_current(
    expected: _ProjectionPredecessorSeal,
    current: _ProjectionPredecessor,
) -> bool:
    if type(expected) is not _ProjectionPredecessorSeal or current is not expected.predecessor:
        return False
    try:
        actual = _seal_projection_predecessor(current)
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        actual.predecessor is expected.predecessor
        and actual.generation is expected.generation
        and actual.host_id is expected.host_id
        and actual.source_sequence is expected.source_sequence
        and actual.event_id is expected.event_id
        and actual.content_sha256 is expected.content_sha256
        and actual.frame_sha256 is expected.frame_sha256
        and actual.canonical == expected.canonical
    )


def _clone_predecessor(
    value: _ProjectionPredecessor,
) -> _ProjectionPredecessor:
    if type(value) is not _ProjectionPredecessor:
        raise TypeError("projection predecessor is not exact")
    return _ProjectionPredecessor(
        generation=value.generation,
        host_id=value.host_id,
        source_sequence=value.source_sequence,
        event_id=value.event_id,
        content_sha256=value.content_sha256,
        frame_sha256=value.frame_sha256,
    )


@final
class CorrelationProjectionAuthority:
    """Opaque owner of one evidence lifecycle's correlation pin clock."""

    __slots__ = ("__weakref__", "_token")
    _token: object

    def __new__(cls, *args: object, **kwargs: object) -> Self:
        del cls, args, kwargs
        raise TypeError("correlation projection authorities are factory-only")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("correlation projection authorities are immutable")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("CorrelationProjectionAuthority is final")

    def __copy__(self) -> Never:
        raise TypeError("correlation projection authorities cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        del memo
        raise TypeError("correlation projection authorities cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("correlation projection authorities cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("correlation projection authorities cannot be serialized")


@dataclass(slots=True)
class _ProjectionAuthorityBinding:
    token: object
    lifecycle_token: bytes
    store: SegmentStore
    store_lifecycle: object
    registry: SpecialUseRegistry
    registry_facts: object
    detector_bundle_sha256: str
    predecessor: _ProjectionPredecessor
    revision: object
    closed: bool
    lock: RLockType


_CORRELATION_REPLAY_REGISTRY_DOMAIN = (
    b"AGMIND_CORRELATION_REPLAY_REGISTRY_FACTS_V1\0"
)


@dataclass(frozen=True, slots=True)
class _CorrelationReplaySnapshot:
    lifecycle_token: bytes
    revision: object
    predecessor: _ProjectionPredecessor
    predecessor_canonical: bytes
    detector_bundle_sha256: str
    registry_facts_canonical: bytes


@dataclass(frozen=True, slots=True)
class _IssuedContextBinding:
    completed: object
    public_proof: AuthenticatedPCCInput
    trusted_proof: AuthenticatedPCCInput
    path: HistoricalPathAuthority
    coverage: HistoricalCoverageAssessment
    acceptance_cursor: int
    predecessor: _ProjectionPredecessor
    revision: object
    detector_bundle_sha256: str
    registry_facts: object


@dataclass(frozen=True, slots=True)
class _StoreLifecycleOwner:
    store_ref: weakref.ReferenceType[SegmentStore]
    lifecycle: object
    authority_ref: weakref.ReferenceType[CorrelationProjectionAuthority]


@final
class _PreparedProjectionAuthorityReplacement:
    """Identity-only handle for one sealed authority replacement plan."""

    __slots__ = ("__weakref__",)

    def __init__(self) -> None:
        raise TypeError("projection authority replacements are factory-issued")

    def __copy__(self) -> Never:
        raise TypeError("projection authority replacements cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("projection authority replacements cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("projection authority replacements cannot be serialized")


@dataclass(slots=True)
class _ProjectionAuthorityReplacementState:
    old_authority: CorrelationProjectionAuthority
    old_binding: _ProjectionAuthorityBinding
    old_revision: object
    old_owner: _StoreLifecycleOwner
    fresh_authority: CorrelationProjectionAuthority
    fresh_reference: weakref.ReferenceType[CorrelationProjectionAuthority]
    fresh_binding: _ProjectionAuthorityBinding
    fresh_revision: object
    fresh_revocation_revision: object
    fresh_identity: int
    fresh_issued_entry: tuple[
        weakref.ReferenceType[CorrelationProjectionAuthority],
        _ProjectionAuthorityBinding,
    ]
    owner_identity: tuple[int, int]
    fresh_owner: _StoreLifecycleOwner
    old_predecessor: _ProjectionPredecessor
    old_revocation_revision: object
    success_successor: _ProjectionPredecessor
    fallback_successor: _ProjectionPredecessor
    committed: bool = False


_ISSUED_AUTHORITIES: dict[
    int,
    tuple[
        weakref.ReferenceType[CorrelationProjectionAuthority],
        _ProjectionAuthorityBinding,
    ],
] = {}
_STORE_LIFECYCLE_OWNERS: dict[
    tuple[int, int],
    _StoreLifecycleOwner,
] = {}
_PREPARED_AUTHORITY_REPLACEMENTS: weakref.WeakKeyDictionary[
    _PreparedProjectionAuthorityReplacement,
    _ProjectionAuthorityReplacementState,
] = weakref.WeakKeyDictionary()
_ISSUED_AUTHORITIES_LOCK = RLockType()
_AUTHORITY_REPLACEMENT_FACTORY = object()


def _safe_detector_bundle_sha256() -> str:
    value = _load_pinned_detector_bundle()
    _exact_hex64(value, "detector_bundle_sha256")
    return value


def _healthy_store_cursor(store: SegmentStore, lifecycle: object) -> int:
    status = store.status()
    if (
        store._lifecycle_identity is not lifecycle
        or store._closed
        or not status.healthy
        or status.repair_pending
        or status.retention_pending
        or type(status.acceptance_cursor) is not int
        or status.acceptance_cursor < 0
    ):
        raise CorrelationProjectionError(
            "correlation projection evidence lifecycle is unavailable"
        )
    return status.acceptance_cursor


def _registry_facts(registry: SpecialUseRegistry) -> object:
    if (
        type(registry) is not SpecialUseRegistry
        or not special_use_registry_is_issued(registry)
    ):
        raise CorrelationProjectionError(
            "correlation projection special-use registry is unavailable"
        )
    try:
        return _canonical_registry_binding(registry)
    except (AttributeError, RecursionError, TypeError, ValueError) as error:
        raise CorrelationProjectionError(
            "correlation projection special-use registry changed"
        ) from error


def _authority_binding(
    authority: object,
) -> _ProjectionAuthorityBinding:
    if type(authority) is not CorrelationProjectionAuthority:
        raise CorrelationProjectionError(
            "correlation projection authority is not exact"
        )
    with _ISSUED_AUTHORITIES_LOCK:
        registered = _ISSUED_AUTHORITIES.get(id(authority))
    try:
        token = authority._token
    except AttributeError:
        token = None
    if (
        registered is None
        or registered[0]() is not authority
        or token is not registered[1].token
    ):
        raise CorrelationProjectionError(
            "correlation projection authority was not issued"
        )
    return registered[1]


def _require_authority_locked(
    authority: CorrelationProjectionAuthority,
    binding: _ProjectionAuthorityBinding,
    *,
    allow_closed: bool = False,
) -> None:
    with _ISSUED_AUTHORITIES_LOCK:
        registered = _ISSUED_AUTHORITIES.get(id(authority))
        owner = _STORE_LIFECYCLE_OWNERS.get(
            (id(binding.store), id(binding.store_lifecycle))
        )
        current_owner = (
            owner is not None
            and owner.store_ref() is binding.store
            and owner.lifecycle is binding.store_lifecycle
            and owner.authority_ref() is authority
        )
    if (
        registered is None
        or registered[0]() is not authority
        or registered[1] is not binding
        or authority._token is not binding.token
        or (binding.closed and not allow_closed)
        or (not binding.closed and not current_owner)
    ):
        raise CorrelationProjectionError(
            "correlation projection authority is no longer live"
        )
    try:
        _clone_predecessor(binding.predecessor)
    except (AttributeError, TypeError, ValueError) as error:
        raise CorrelationProjectionError(
            "correlation projection predecessor facts are invalid"
        ) from error


def _registry_facts_canonical(registry_facts: object) -> bytes:
    if (
        type(registry_facts) is not tuple
        or len(registry_facts) != 2
        or type(registry_facts[0]) is not tuple
        or type(registry_facts[1]) is not tuple
    ):
        raise TypeError("correlation registry facts are not exact tuples")
    entries = registry_facts[0]
    index = registry_facts[1]
    if any(
        type(entry) is not tuple
        or len(entry) != 2
        or any(type(value) is not str for value in entry)
        for entry in entries
    ) or any(
        type(item) is not tuple
        or len(item) != 3
        or type(item[0]) is not int
        or type(item[1]) is not int
        or type(item[2]) is not str
        for item in index
    ):
        raise TypeError("correlation registry scalar facts are not exact")
    return _CORRELATION_REPLAY_REGISTRY_DOMAIN + canonical_json(
        (
            (
                "entries",
                tuple(
                    (("str", prefix), ("str", reachability))
                    for prefix, reachability in entries
                ),
            ),
            (
                "index",
                tuple(
                    (
                        ("int", str(network)),
                        ("int", str(prefix_length)),
                        ("str", reachability),
                    )
                    for network, prefix_length, reachability in index
                ),
            ),
        )
    )


@contextmanager
def _correlation_projection_snapshot_gate(
    authority: CorrelationProjectionAuthority,
) -> Iterator[_ProjectionAuthorityBinding]:
    binding = _authority_binding(authority)
    with binding.lock, _ISSUED_AUTHORITIES_LOCK:
        _require_authority_locked(authority, binding)
        yield binding


def _capture_correlation_replay_locked(
    authority: CorrelationProjectionAuthority,
    binding: _ProjectionAuthorityBinding,
    expected: _ProjectionPredecessor,
) -> _CorrelationReplaySnapshot:
    if type(binding) is not _ProjectionAuthorityBinding:
        raise CorrelationProjectionError(
            "correlation replay binding is not exact"
        )
    try:
        _require_authority_locked(authority, binding)
        expected_seal = _seal_projection_predecessor(expected)
        bound_predecessor = binding.predecessor
        bound_seal = _seal_projection_predecessor(bound_predecessor)
        registry_facts = _registry_facts(binding.registry)
        registry_canonical = _registry_facts_canonical(registry_facts)
        lifecycle_token = binding.lifecycle_token
        detector = binding.detector_bundle_sha256
        if (
            expected_seal.canonical != bound_seal.canonical
            or registry_facts != binding.registry_facts
            or not special_use_registry_is_issued(binding.registry)
            or type(lifecycle_token) is not bytes
            or len(lifecycle_token) != 32
            or type(detector) is not str
        ):
            raise CorrelationProjectionError(
                "correlation replay predecessor or pins changed"
            )
        _exact_hex64(detector, "detector_bundle_sha256")
    except CorrelationProjectionError:
        raise
    except (AttributeError, RecursionError, TypeError, ValueError) as error:
        raise CorrelationProjectionError(
            "correlation replay snapshot facts are invalid"
        ) from error
    return _CorrelationReplaySnapshot(
        lifecycle_token=lifecycle_token,
        revision=binding.revision,
        predecessor=bound_predecessor,
        predecessor_canonical=bound_seal.canonical,
        detector_bundle_sha256=detector,
        registry_facts_canonical=registry_canonical,
    )


def _revalidate_correlation_replay_locked(
    authority: CorrelationProjectionAuthority,
    binding: _ProjectionAuthorityBinding,
    snapshot: _CorrelationReplaySnapshot,
) -> None:
    if (
        type(binding) is not _ProjectionAuthorityBinding
        or type(snapshot) is not _CorrelationReplaySnapshot
    ):
        raise CorrelationProjectionError(
            "correlation replay snapshot is not exact"
        )
    try:
        _require_authority_locked(authority, binding)
        predecessor = binding.predecessor
        predecessor_seal = _seal_projection_predecessor(predecessor)
        registry_facts = _registry_facts(binding.registry)
        registry_canonical = _registry_facts_canonical(registry_facts)
        if (
            binding.lifecycle_token != snapshot.lifecycle_token
            or binding.revision is not snapshot.revision
            or predecessor is not snapshot.predecessor
            or predecessor_seal.canonical != snapshot.predecessor_canonical
            or binding.detector_bundle_sha256
            != snapshot.detector_bundle_sha256
            or registry_facts != binding.registry_facts
            or registry_canonical != snapshot.registry_facts_canonical
            or not special_use_registry_is_issued(binding.registry)
        ):
            raise CorrelationProjectionError(
                "correlation replay predecessor, revision, or pins changed"
            )
    except CorrelationProjectionError:
        raise
    except (AttributeError, RecursionError, TypeError, ValueError) as error:
        raise CorrelationProjectionError(
            "correlation replay revalidation failed"
        ) from error


def _validate_correlation_projection_predecessor(
    authority: CorrelationProjectionAuthority,
    expected: _ProjectionPredecessor,
) -> None:
    try:
        expected_before = _clone_predecessor(expected)
        binding = _authority_binding(authority)
        with binding.lock:
            _require_authority_locked(authority, binding)
            expected_after = _clone_predecessor(expected)
            binding_predecessor = _clone_predecessor(binding.predecessor)
            if (
                expected_after != expected_before
                or binding_predecessor != expected_before
            ):
                raise CorrelationProjectionError(
                    "correlation projection predecessor is stale or changed"
                )
    except CorrelationProjectionError:
        raise
    except Exception as error:
        raise CorrelationProjectionError(
            "correlation projection predecessor validation failed"
        ) from error


def _validate_correlation_projection_pins(
    authority: CorrelationProjectionAuthority,
) -> None:
    try:
        binding = _authority_binding(authority)
        with binding.lock:
            _require_authority_locked(authority, binding)
            if (
                not special_use_registry_is_issued(binding.registry)
                or _registry_facts(binding.registry) != binding.registry_facts
                or _safe_detector_bundle_sha256()
                != binding.detector_bundle_sha256
            ):
                raise CorrelationProjectionError(
                    "correlation projection pins changed"
                )
    except CorrelationProjectionError:
        raise
    except Exception as error:
        raise CorrelationProjectionError(
            "correlation projection pin validation failed"
        ) from error


def _validate_correlation_projection_terminal_authority(
    authority: CorrelationProjectionAuthority,
    expected: _ProjectionPredecessor,
) -> None:
    try:
        expected_seal = _seal_projection_predecessor(expected)
        binding = _authority_binding(authority)
    except CorrelationProjectionError:
        raise
    except Exception as error:
        raise CorrelationProjectionError(
            "correlation terminal authority validation failed"
        ) from error
    with binding.lock:
        revision = binding.revision
        registry = binding.registry
        registry_facts = binding.registry_facts
        detector_bundle_sha256 = binding.detector_bundle_sha256
        bound_predecessor = binding.predecessor
        try:
            bound_seal = _seal_projection_predecessor(bound_predecessor)
            _require_authority_locked(authority, binding)
            current_registry_facts = _registry_facts(binding.registry)
            current_detector = _safe_detector_bundle_sha256()
            registry_facts_after = _registry_facts(binding.registry)
            if (
                not _projection_predecessor_seal_is_current(
                    expected_seal,
                    expected,
                )
                or binding.predecessor is not bound_predecessor
                or not _projection_predecessor_seal_is_current(
                    bound_seal,
                    binding.predecessor,
                )
                or bound_seal.canonical != expected_seal.canonical
                or binding.revision is not revision
                or binding.registry is not registry
                or binding.registry_facts is not registry_facts
                or type(current_registry_facts) is not type(registry_facts)
                or current_registry_facts != registry_facts
                or type(registry_facts_after) is not type(registry_facts)
                or registry_facts_after != registry_facts
                or binding.detector_bundle_sha256 is not detector_bundle_sha256
                or type(current_detector) is not str
                or current_detector != detector_bundle_sha256
                or not special_use_registry_is_issued(binding.registry)
            ):
                raise CorrelationProjectionError(
                    "correlation terminal predecessor or pins changed"
                )
        except CorrelationProjectionError:
            raise
        except Exception as error:
            raise CorrelationProjectionError(
                "correlation terminal authority validation failed"
            ) from error

def _create_correlation_projection_authority(
    store: SegmentStore,
    registry: SpecialUseRegistry,
    predecessor: _ProjectionPredecessor,
) -> CorrelationProjectionAuthority:
    if (
        type(store) is not SegmentStore
        or type(registry) is not SpecialUseRegistry
        or type(predecessor) is not _ProjectionPredecessor
    ):
        raise TypeError(
            "correlation projection authority requires exact store, registry, and cursor"
        )
    lifecycle = store._lifecycle_identity
    try:
        predecessor_before = _clone_predecessor(predecessor)
        detector_before = _safe_detector_bundle_sha256()
        cursor_before = _healthy_store_cursor(store, lifecycle)
        registry_before = _registry_facts(registry)
        detector_after = _safe_detector_bundle_sha256()
        cursor_after = _healthy_store_cursor(store, lifecycle)
        registry_after = _registry_facts(registry)
        predecessor_after = _clone_predecessor(predecessor)
    except CorrelationProjectionError:
        raise
    except Exception as error:
        raise CorrelationProjectionError(
            "correlation projection pin authority is unavailable"
        ) from error
    if (
        detector_before != detector_after
        or cursor_before != cursor_after
        or registry_before != registry_after
        or predecessor_before != predecessor_after
    ):
        raise CorrelationProjectionError(
            "correlation projection pins changed during creation"
        )
    return _issue_correlation_projection_authority(
        store,
        registry,
        predecessor_after,
        detector_after,
        registry_after,
    )


def _issue_correlation_projection_authority(
    store: SegmentStore,
    registry: SpecialUseRegistry,
    predecessor: _ProjectionPredecessor,
    detector_bundle_sha256: str,
    registry_facts: object,
) -> CorrelationProjectionAuthority:
    """Issue from already captured exact pins after validating live ownership."""
    if (
        type(store) is not SegmentStore
        or type(registry) is not SpecialUseRegistry
        or type(predecessor) is not _ProjectionPredecessor
        or type(detector_bundle_sha256) is not str
        or not special_use_registry_is_issued(registry)
    ):
        raise TypeError("correlation projection captured pins are not exact")
    lifecycle = store._lifecycle_identity
    try:
        _exact_hex64(detector_bundle_sha256, "detector_bundle_sha256")
        predecessor_facts = _clone_predecessor(predecessor)
        current_registry_facts = _registry_facts(registry)
        _registry_facts_canonical(registry_facts)
        _healthy_store_cursor(store, lifecycle)
    except CorrelationProjectionError:
        raise
    except (AttributeError, RecursionError, TypeError, ValueError) as error:
        raise CorrelationProjectionError(
            "correlation projection captured pins are invalid"
        ) from error
    if (
        type(current_registry_facts) is not type(registry_facts)
        or current_registry_facts != registry_facts
    ):
        raise CorrelationProjectionError(
            "correlation projection captured registry facts changed"
        )
    authority = object.__new__(CorrelationProjectionAuthority)
    token = object()
    object.__setattr__(authority, "_token", token)
    binding = _ProjectionAuthorityBinding(
        token=token,
        lifecycle_token=os.urandom(32),
        store=store,
        store_lifecycle=lifecycle,
        registry=registry,
        registry_facts=registry_facts,
        detector_bundle_sha256=detector_bundle_sha256,
        predecessor=predecessor_facts,
        revision=object(),
        closed=False,
        lock=RLockType(),
    )
    identity = id(authority)
    owner_identity = (id(store), id(lifecycle))

    def cleanup(
        reference: weakref.ReferenceType[CorrelationProjectionAuthority],
    ) -> None:
        with _ISSUED_AUTHORITIES_LOCK:
            current = _ISSUED_AUTHORITIES.get(identity)
            if current is not None and current[0] is reference:
                _ISSUED_AUTHORITIES.pop(identity, None)
            owner = _STORE_LIFECYCLE_OWNERS.get(owner_identity)
            if owner is not None and owner.authority_ref is reference:
                _STORE_LIFECYCLE_OWNERS.pop(owner_identity, None)

    reference = weakref.ref(authority, cleanup)
    store_reference = weakref.ref(store)
    with _ISSUED_AUTHORITIES_LOCK:
        current_owner = _STORE_LIFECYCLE_OWNERS.get(owner_identity)
        if (
            current_owner is not None
            and current_owner.store_ref() is store
            and current_owner.lifecycle is lifecycle
            and current_owner.authority_ref() is not None
        ):
            raise CorrelationProjectionError(
                "correlation projection store lifecycle already has a live owner"
            )
        if current_owner is not None:
            _STORE_LIFECYCLE_OWNERS.pop(owner_identity, None)
        _ISSUED_AUTHORITIES[identity] = (reference, binding)
        _STORE_LIFECYCLE_OWNERS[owner_identity] = _StoreLifecycleOwner(
            store_ref=store_reference,
            lifecycle=lifecycle,
            authority_ref=reference,
        )
    return authority


def _same_exact_pcc(
    left: AuthenticatedPCCInput,
    right: AuthenticatedPCCInput,
) -> bool:
    try:
        return (
            left is right
            and left.canonical == right.canonical
            and left.evidence_ref == right.evidence_ref
            and left.request is right.request
            and left.snapshot is right.snapshot
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _issue_hidden_pcc(
    store: SegmentStore,
    public_proof: AuthenticatedPCCInput,
) -> AuthenticatedPCCInput:
    verifier = store._bound_verifier
    if verifier is None or not store._is_bound_verifier(verifier):
        raise CorrelationProjectionError(
            "correlation projection store lost verifier authority"
        )
    try:
        public_ref = public_proof.evidence_ref
        if type(public_ref) is not EvidenceRef:
            raise TypeError("public PCC evidence ref is not exact")
        detached_ref = EvidenceRef(
            segment_id=public_ref.segment_id,
            segment_relative_path=public_ref.segment_relative_path,
            frame_offset=public_ref.frame_offset,
            frame_size=public_ref.frame_size,
            frame_sha256=public_ref.frame_sha256,
            event_id=public_ref.event_id,
            source_sequence=public_ref.source_sequence,
            content_sha256=public_ref.content_sha256,
        )
        hidden = store._authenticated_pcc_input(
            verifier,
            detached_ref,
            public_proof.request,
        )
        object.__setattr__(hidden, "_evidence_ref", detached_ref)
    except Exception as error:
        raise CorrelationProjectionError(
            "correlation projection could not reissue private PCC facts"
        ) from error
    if (
        hidden is public_proof
        or hidden.canonical != public_proof.canonical
        or hidden.evidence_ref != public_proof.evidence_ref
        or hidden.evidence_ref is public_proof.evidence_ref
        or not store._authenticated_pcc_input_is_exact(hidden)
    ):
        raise CorrelationProjectionError(
            "private PCC reissue changed authenticated facts"
        )
    return hidden


def _clone_coverage(
    value: HistoricalCoverageAssessment,
) -> HistoricalCoverageAssessment:
    if type(value) is not HistoricalCoverageAssessment:
        raise TypeError("historical coverage assessment is not exact")
    return HistoricalCoverageAssessment(
        host_id=value.host_id,
        boot_id=value.boot_id,
        trigger_event_id=value.trigger_event_id,
        trigger_source_sequence=value.trigger_source_sequence,
        coverage_through_sequence=value.coverage_through_sequence,
        window_start=value.window_start,
        window_end=value.window_end,
        complete=value.complete,
        critical_gap=value.critical_gap,
        coverage_snapshot_sha256=value.coverage_snapshot_sha256,
    )


def _clone_duplicate_key(value: CandidateDuplicateKey) -> CandidateDuplicateKey:
    if type(value) is not CandidateDuplicateKey:
        raise TypeError("candidate duplicate key is not exact")
    return CandidateDuplicateKey(
        host_id=value.host_id,
        boot_id=value.boot_id,
        docker_container_id=value.docker_container_id,
        docker_started_at=value.docker_started_at,
        detector_bundle_sha256=value.detector_bundle_sha256,
        destination_ipv4=value.destination_ipv4,
    )


def _clone_active_duplicate(
    value: ActiveCandidateObservation | None,
) -> ActiveCandidateObservation | None:
    if value is None:
        return None
    if type(value) is not ActiveCandidateObservation:
        raise TypeError("active duplicate observation is not exact")
    return ActiveCandidateObservation(
        key=_clone_duplicate_key(value.key),
        candidate_id=value.candidate_id,
        primary_source_sequence=value.primary_source_sequence,
        primary_event_id=value.primary_event_id,
    )


def _context_issue_facts(
    binding: _ProjectionAuthorityBinding,
    completed: object,
    expected_predecessor: _ProjectionPredecessor,
    active_duplicate: ActiveCandidateObservation | None,
) -> tuple[
    AuthenticatedPCCInput,
    AuthenticatedPCCInput,
    HistoricalPathAuthority,
    HistoricalCoverageAssessment,
    CandidateDuplicateKey,
    ActiveCandidateObservation | None,
    int,
]:
    store = binding.store
    public_proof = _revalidate_completed_snapshot(completed)
    if (
        type(public_proof) is not AuthenticatedPCCInput
        or not store._authenticated_pcc_input_is_exact(public_proof)
        or public_proof.snapshot.outcome != "complete"
    ):
        raise CorrelationProjectionError(
            "completed correlation authority is not an exact same-store complete PCC"
        )
    if binding.predecessor != expected_predecessor:
        raise CorrelationProjectionError(
            "correlation predecessor changed before context issuance"
        )
    cursor_before = _healthy_store_cursor(store, binding.store_lifecycle)
    registry_before = _registry_facts(binding.registry)
    detector_before = _safe_detector_bundle_sha256()
    path = _issue_historical_path_authority(
        store,
        public_proof,
    )
    coverage = derive_historical_coverage(
        public_proof,
        path,
    )
    lookup_key = _duplicate_key(public_proof, public_proof.snapshot)
    active_before = _clone_active_duplicate(active_duplicate)
    if (
        active_before is not None
        and (
            active_before.key != lookup_key
        )
    ):
        raise CorrelationProjectionError(
            "active duplicate does not bind the exact PCC lookup key"
        )
    trusted_proof = _issue_hidden_pcc(store, public_proof)

    revalidated = _revalidate_completed_snapshot(completed)
    coverage_after = derive_historical_coverage(
        public_proof,
        path,
    )
    detector_after = _safe_detector_bundle_sha256()
    registry_after = _registry_facts(binding.registry)
    cursor_after = _healthy_store_cursor(store, binding.store_lifecycle)
    active_after = _clone_active_duplicate(active_duplicate)
    if (
        not _same_exact_pcc(revalidated, public_proof)
        or coverage_after != coverage
        or detector_before != detector_after
        or detector_after != binding.detector_bundle_sha256
        or registry_before != registry_after
        or registry_after != binding.registry_facts
        or cursor_before != cursor_after
        or not store._authenticated_pcc_input_is_exact(trusted_proof)
        or binding.predecessor != expected_predecessor
        or active_after != active_before
    ):
        raise CorrelationProjectionError(
            "correlation context authority changed during issuance"
        )
    return (
        public_proof,
        trusted_proof,
        path,
        coverage,
        lookup_key,
        active_after,
        cursor_after,
    )


def _validate_issued_context_locked(
    authority: CorrelationProjectionAuthority,
    authority_binding: _ProjectionAuthorityBinding,
    context_binding: _IssuedContextBinding,
) -> None:
    _require_authority_locked(authority, authority_binding)
    if (
        authority_binding.revision is not context_binding.revision
        or authority_binding.predecessor != context_binding.predecessor
        or authority_binding.detector_bundle_sha256
        != context_binding.detector_bundle_sha256
        or authority_binding.registry_facts != context_binding.registry_facts
    ):
        raise CorrelationProjectionError(
            "correlation context projection clock was revoked"
        )
    public_proof = _revalidate_completed_snapshot(context_binding.completed)
    if (
        not _same_exact_pcc(public_proof, context_binding.public_proof)
        or not authority_binding.store._authenticated_pcc_input_is_exact(
            context_binding.public_proof
        )
        or not authority_binding.store._authenticated_pcc_input_is_exact(
            context_binding.trusted_proof
        )
        or _healthy_store_cursor(
            authority_binding.store,
            authority_binding.store_lifecycle,
        )
        != context_binding.acceptance_cursor
        or _registry_facts(authority_binding.registry)
        != context_binding.registry_facts
        or _safe_detector_bundle_sha256()
        != context_binding.detector_bundle_sha256
        or derive_historical_coverage(
            context_binding.public_proof,
            context_binding.path,
        )
        != context_binding.coverage
    ):
        raise CorrelationProjectionError(
            "correlation context live authority was revoked"
        )


def _evaluate_issued_context(
    authority: CorrelationProjectionAuthority,
    authority_binding: _ProjectionAuthorityBinding,
    context_binding: _IssuedContextBinding,
    callback: Callable[[], object],
) -> object:
    with authority_binding.lock:
        try:
            _validate_issued_context_locked(
                authority,
                authority_binding,
                context_binding,
            )
        except CorrelationProjectionError:
            raise
        except Exception as error:
            raise CorrelationProjectionError(
                "correlation context live validation failed"
            ) from error
        result = callback()
        try:
            _validate_issued_context_locked(
                authority,
                authority_binding,
                context_binding,
            )
        except CorrelationProjectionError:
            raise
        except Exception as error:
            raise CorrelationProjectionError(
                "correlation context changed during evaluation"
            ) from error
        return result


def _issue_correlation_context(
    authority: CorrelationProjectionAuthority,
    completed: object,
    *,
    expected_predecessor: _ProjectionPredecessor,
    active_duplicate: ActiveCandidateObservation | None,
) -> tuple[AuthenticatedPCCInput, CorrelationContext]:
    expected_before = _clone_predecessor(expected_predecessor)
    authority_binding = _authority_binding(authority)
    with authority_binding.lock:
        _require_authority_locked(authority, authority_binding)
        if _clone_predecessor(expected_predecessor) != expected_before:
            raise CorrelationProjectionError(
                "expected projection predecessor changed before issuance"
            )
        authority_binding.revision = object()
        revision = authority_binding.revision
        try:
            (
                public_proof,
                trusted_proof,
                path,
                coverage,
                lookup_key,
                issued_active_duplicate,
                acceptance_cursor,
            ) = _context_issue_facts(
                authority_binding,
                completed,
                expected_before,
                active_duplicate,
            )
        except CorrelationProjectionError:
            raise
        except Exception as error:
            raise CorrelationProjectionError(
                "correlation context issuance lost authority"
            ) from error
        if authority_binding.revision is not revision:
            raise CorrelationProjectionError(
                "correlation projection revision changed during issuance"
            )
        public_coverage = _clone_coverage(coverage)
        context = CorrelationContext(
            pinned_detector_bundle_sha256=(
                authority_binding.detector_bundle_sha256
            ),
            special_use_registry=authority_binding.registry,
            coverage=public_coverage,
            lookup_key=_clone_duplicate_key(lookup_key),
            active_duplicate=issued_active_duplicate,
            terminal_observation=None,
        )
        issued_binding = _IssuedContextBinding(
            completed=completed,
            public_proof=public_proof,
            trusted_proof=trusted_proof,
            path=path,
            coverage=_clone_coverage(coverage),
            acceptance_cursor=acceptance_cursor,
            predecessor=_clone_predecessor(expected_before),
            revision=revision,
            detector_bundle_sha256=authority_binding.detector_bundle_sha256,
            registry_facts=authority_binding.registry_facts,
        )

        def evaluate(callback: Callable[[], object]) -> object:
            return _evaluate_issued_context(
                authority,
                authority_binding,
                issued_binding,
                callback,
            )

        try:
            _register_correlation_context(
                context,
                public_proof,
                trusted_proof,
                evaluate,
            )
        except Exception as error:
            raise CorrelationProjectionError(
                "correlation context registration lost exact facts"
            ) from error
        return public_proof, context


def _lawful_forward(
    current: _ProjectionPredecessor,
    successor: _ProjectionPredecessor,
) -> bool:
    if current.generation != successor.generation:
        return False
    if successor.source_sequence == 0:
        return False
    if current.source_sequence == 0:
        return True
    return (
        successor.host_id == current.host_id
        and successor.source_sequence > current.source_sequence
    )


def _advance_correlation_projection_authority(
    authority: CorrelationProjectionAuthority,
    expected: _ProjectionPredecessor,
    successor: _ProjectionPredecessor,
) -> None:
    expected_before = _clone_predecessor(expected)
    successor_before = _clone_predecessor(successor)
    binding = _authority_binding(authority)
    with binding.lock:
        _require_authority_locked(authority, binding)
        if (
            _clone_predecessor(expected) != expected_before
            or _clone_predecessor(successor) != successor_before
            or binding.predecessor != expected_before
            or not _lawful_forward(
                expected_before,
                successor_before,
            )
        ):
            raise CorrelationProjectionError(
                "projection predecessor advance is stale or non-forward"
            )
        binding.predecessor = _clone_predecessor(successor_before)
        binding.revision = object()


def _rebuild_correlation_projection_authority(
    authority: CorrelationProjectionAuthority,
    successor: _ProjectionPredecessor,
) -> None:
    successor_before = _clone_predecessor(successor)
    binding = _authority_binding(authority)
    with binding.lock:
        _require_authority_locked(authority, binding)
        if _clone_predecessor(successor) != successor_before:
            raise CorrelationProjectionError(
                "projection rebuild successor changed before use"
            )
        current = binding.predecessor
        if (
            current.generation == MAX_UINT64
            or successor_before.generation != current.generation + 1
        ):
            raise CorrelationProjectionError(
                "projection rebuild generation is not fresh"
            )
        binding.predecessor = _clone_predecessor(successor_before)
        binding.revision = object()


def _prepare_correlation_projection_authority_replacement(
    authority: CorrelationProjectionAuthority,
    success_successor: _ProjectionPredecessor,
    fallback_successor: _ProjectionPredecessor,
    *,
    _factory: object,
) -> _PreparedProjectionAuthorityReplacement:
    """Preallocate an unregistered, two-outcome successor for one live owner."""
    if _factory is not _AUTHORITY_REPLACEMENT_FACTORY:
        raise CorrelationProjectionError(
            "projection authority replacement preparation is factory-only"
        )
    success_before = _clone_predecessor(success_successor)
    fallback_before = _clone_predecessor(fallback_successor)
    binding = _authority_binding(authority)
    with binding.lock, _ISSUED_AUTHORITIES_LOCK:
        _require_authority_locked(authority, binding)
        current = _clone_predecessor(binding.predecessor)
        if (
            current.generation == MAX_UINT64
            or success_before.generation != current.generation + 1
            or fallback_before.generation != current.generation + 1
            or fallback_before.host_id != current.host_id
            or fallback_before.source_sequence != current.source_sequence
            or fallback_before.event_id != current.event_id
            or fallback_before.content_sha256 != current.content_sha256
            or fallback_before.frame_sha256 != current.frame_sha256
            or success_before.source_sequence < current.source_sequence
            or (
                current.source_sequence != 0
                and success_before.host_id != current.host_id
            )
            or _clone_predecessor(success_successor) != success_before
            or _clone_predecessor(fallback_successor) != fallback_before
            or _registry_facts(binding.registry) != binding.registry_facts
            or _safe_detector_bundle_sha256()
            != binding.detector_bundle_sha256
        ):
            raise CorrelationProjectionError(
                "projection authority replacement successors are invalid"
            )
        owner_identity = (id(binding.store), id(binding.store_lifecycle))
        current_owner = _STORE_LIFECYCLE_OWNERS.get(owner_identity)
        if (
            current_owner is None
            or current_owner.store_ref() is not binding.store
            or current_owner.lifecycle is not binding.store_lifecycle
            or current_owner.authority_ref() is not authority
        ):
            raise CorrelationProjectionError(
                "projection authority replacement lost its sole owner"
            )
        fresh = object.__new__(CorrelationProjectionAuthority)
        fresh_token = object()
        object.__setattr__(fresh, "_token", fresh_token)
        fresh_revision = object()
        fresh_binding = _ProjectionAuthorityBinding(
            token=fresh_token,
            lifecycle_token=os.urandom(32),
            store=binding.store,
            store_lifecycle=binding.store_lifecycle,
            registry=binding.registry,
            registry_facts=binding.registry_facts,
            detector_bundle_sha256=binding.detector_bundle_sha256,
            predecessor=fallback_before,
            revision=fresh_revision,
            closed=False,
            lock=RLockType(),
        )
        fresh_identity = id(fresh)
        store_reference = weakref.ref(binding.store)

        def cleanup(
            reference: weakref.ReferenceType[CorrelationProjectionAuthority],
        ) -> None:
            with _ISSUED_AUTHORITIES_LOCK:
                registered = _ISSUED_AUTHORITIES.get(fresh_identity)
                if registered is not None and registered[0] is reference:
                    _ISSUED_AUTHORITIES.pop(fresh_identity, None)
                owner = _STORE_LIFECYCLE_OWNERS.get(owner_identity)
                if owner is not None and owner.authority_ref is reference:
                    _STORE_LIFECYCLE_OWNERS.pop(owner_identity, None)

        fresh_reference = weakref.ref(fresh, cleanup)
        fresh_issued_entry = (fresh_reference, fresh_binding)
        fresh_owner = _StoreLifecycleOwner(
            store_ref=store_reference,
            lifecycle=binding.store_lifecycle,
            authority_ref=fresh_reference,
        )
        prepared = object.__new__(_PreparedProjectionAuthorityReplacement)
        state = _ProjectionAuthorityReplacementState(
            old_authority=authority,
            old_binding=binding,
            old_revision=binding.revision,
            old_owner=current_owner,
            fresh_authority=fresh,
            fresh_reference=fresh_reference,
            fresh_binding=fresh_binding,
            fresh_revision=fresh_revision,
            fresh_revocation_revision=object(),
            fresh_identity=fresh_identity,
            fresh_issued_entry=fresh_issued_entry,
            owner_identity=owner_identity,
            fresh_owner=fresh_owner,
            old_predecessor=current,
            old_revocation_revision=object(),
            success_successor=success_before,
            fallback_successor=fallback_before,
        )
        if (
            _clone_predecessor(success_successor) != success_before
            or _clone_predecessor(fallback_successor) != fallback_before
            or _STORE_LIFECYCLE_OWNERS.get(owner_identity) is not current_owner
        ):
            raise CorrelationProjectionError(
                "projection authority replacement changed during prepare"
            )
        _PREPARED_AUTHORITY_REPLACEMENTS[prepared] = state
        return prepared


def _commit_correlation_projection_authority_replacement(
    prepared: _PreparedProjectionAuthorityReplacement,
    *,
    success: bool,
    _factory: object,
) -> CorrelationProjectionAuthority:
    """Atomically revoke the old owner and install one prepared successor."""
    if (
        type(prepared) is not _PreparedProjectionAuthorityReplacement
        or type(success) is not bool
        or _factory is not _AUTHORITY_REPLACEMENT_FACTORY
    ):
        raise CorrelationProjectionError(
            "projection authority replacement commit is not exact"
        )
    with _ISSUED_AUTHORITIES_LOCK:
        state = _PREPARED_AUTHORITY_REPLACEMENTS.get(prepared)
    if state is None:
        raise CorrelationProjectionError(
            "projection authority replacement was not prepared"
        )
    binding = state.old_binding
    fresh_binding = state.fresh_binding
    with binding.lock, fresh_binding.lock, _ISSUED_AUTHORITIES_LOCK:
        _require_authority_locked(state.old_authority, binding)
        owner = _STORE_LIFECYCLE_OWNERS.get(state.owner_identity)
        if (
            state.committed
            or _PREPARED_AUTHORITY_REPLACEMENTS.get(prepared) is not state
            or binding.revision is not state.old_revision
            or _clone_predecessor(binding.predecessor)
            != state.old_predecessor
            or owner is not state.old_owner
            or owner.store_ref() is not binding.store
            or owner.lifecycle is not binding.store_lifecycle
            or owner.authority_ref() is not state.old_authority
            or _ISSUED_AUTHORITIES.get(state.fresh_identity) is not None
            or state.fresh_reference() is not state.fresh_authority
            or state.fresh_authority._token is not fresh_binding.token
            or state.fresh_issued_entry
            != (state.fresh_reference, fresh_binding)
            or state.fresh_owner.store_ref() is not binding.store
            or state.fresh_owner.lifecycle is not binding.store_lifecycle
            or state.fresh_owner.authority_ref is not state.fresh_reference
            or fresh_binding.store is not binding.store
            or fresh_binding.store_lifecycle is not binding.store_lifecycle
            or fresh_binding.registry is not binding.registry
            or fresh_binding.registry_facts != binding.registry_facts
            or fresh_binding.detector_bundle_sha256
            != binding.detector_bundle_sha256
            or fresh_binding.revision is not state.fresh_revision
            or fresh_binding.closed
            or _clone_predecessor(fresh_binding.predecessor)
            != state.fallback_successor
            or state.fallback_successor.generation
            != state.old_predecessor.generation + 1
            or state.fallback_successor.host_id
            != state.old_predecessor.host_id
            or state.fallback_successor.source_sequence
            != state.old_predecessor.source_sequence
            or state.fallback_successor.event_id
            != state.old_predecessor.event_id
            or state.fallback_successor.content_sha256
            != state.old_predecessor.content_sha256
            or state.fallback_successor.frame_sha256
            != state.old_predecessor.frame_sha256
            or state.success_successor.generation
            != state.old_predecessor.generation + 1
            or state.success_successor.source_sequence
            < state.old_predecessor.source_sequence
            or (
                state.old_predecessor.source_sequence != 0
                and state.success_successor.host_id
                != state.old_predecessor.host_id
            )
        ):
            raise CorrelationProjectionError(
                "projection authority replacement is stale"
            )
        selected_successor = (
            state.success_successor
            if success
            else state.fallback_successor
        )
        fresh_binding.predecessor = selected_successor
        try:
            # Registration is not liveness: while the old lifecycle owner is
            # current, the prepared successor cannot authorize work.
            _ISSUED_AUTHORITIES[state.fresh_identity] = state.fresh_issued_entry
            # This single replacement is the visibility/ownership commit edge.
            _STORE_LIFECYCLE_OWNERS[state.owner_identity] = state.fresh_owner
            binding.closed = True
            binding.revision = state.old_revocation_revision
            state.committed = True
        except BaseException:
            current = _STORE_LIFECYCLE_OWNERS.get(state.owner_identity)
            if current is state.fresh_owner:
                # The edge happened. Normalize the committed lane; the caller
                # can recover and explicitly fail-shut the fresh handle.
                binding.closed = True
                binding.revision = state.old_revocation_revision
                state.committed = True
            else:
                registered = _ISSUED_AUTHORITIES.get(state.fresh_identity)
                if registered is state.fresh_issued_entry:
                    _ISSUED_AUTHORITIES.pop(state.fresh_identity, None)
                fresh_binding.predecessor = state.fallback_successor
            raise
        return state.fresh_authority


def _fail_closed_correlation_projection_authority_replacement(
    prepared: _PreparedProjectionAuthorityReplacement,
    primary: BaseException,
    *,
    _factory: object,
) -> bool:
    """Close a visible prepared successor without relying on caller adoption."""
    if (
        type(prepared) is not _PreparedProjectionAuthorityReplacement
        or not isinstance(primary, BaseException)
        or _factory is not _AUTHORITY_REPLACEMENT_FACTORY
    ):
        raise CorrelationProjectionError(
            "projection authority replacement fail-shut is not exact"
        )
    with _ISSUED_AUTHORITIES_LOCK:
        state = _PREPARED_AUTHORITY_REPLACEMENTS.get(prepared)
    if state is None:
        raise CorrelationProjectionError(
            "projection authority replacement was not prepared"
        )
    with (
        state.old_binding.lock,
        state.fresh_binding.lock,
        _ISSUED_AUTHORITIES_LOCK,
    ):
        current = _STORE_LIFECYCLE_OWNERS.get(state.owner_identity)
        fresh_is_current = (
            current is state.fresh_owner
            and current.store_ref() is state.fresh_binding.store
            and current.lifecycle is state.fresh_binding.store_lifecycle
            and current.authority_ref() is state.fresh_authority
        )
        if fresh_is_current:
            state.old_binding.closed = True
            state.old_binding.revision = state.old_revocation_revision
            state.committed = True
            state.fresh_binding.closed = True
            state.fresh_binding.revision = state.fresh_revocation_revision
            if _STORE_LIFECYCLE_OWNERS.get(state.owner_identity) is current:
                _STORE_LIFECYCLE_OWNERS.pop(state.owner_identity, None)
            return True
        old_is_current = (
            current is state.old_owner
            and current.store_ref() is state.old_binding.store
            and current.lifecycle is state.old_binding.store_lifecycle
            and current.authority_ref() is state.old_authority
        )
        registered = _ISSUED_AUTHORITIES.get(state.fresh_identity)
        if old_is_current and registered is state.fresh_issued_entry:
            _ISSUED_AUTHORITIES.pop(state.fresh_identity, None)
        state.fresh_binding.closed = True
        state.fresh_binding.revision = state.fresh_revocation_revision
        if not old_is_current:
            primary.add_note(
                "correlation projection authority replacement lost its owner lane"
            )
        return False


def _close_correlation_projection_authority(
    authority: CorrelationProjectionAuthority,
) -> None:
    binding = _authority_binding(authority)
    with binding.lock:
        _require_authority_locked(authority, binding, allow_closed=True)
        if binding.closed:
            return
        binding.closed = True
        binding.revision = object()
        owner_identity = (id(binding.store), id(binding.store_lifecycle))
        with _ISSUED_AUTHORITIES_LOCK:
            owner = _STORE_LIFECYCLE_OWNERS.get(owner_identity)
            if (
                owner is not None
                and owner.store_ref() is binding.store
                and owner.lifecycle is binding.store_lifecycle
                and owner.authority_ref() is authority
            ):
                _STORE_LIFECYCLE_OWNERS.pop(owner_identity, None)
