"""Dormant durable filesystem publication for an owner-prepared Projection V2 image.

This module deliberately owns namespace names and descriptors only. Replay,
evidence, ACK, correlation, and journal authority remain inside the V2 owner.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import sqlite3
import stat
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from agmind_immune.evidence import projection, projection_v2

_PUBLICATION_FACTORY = object()
_TEMP_UUID = (
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


@dataclass(frozen=True, slots=True)
class _InodeBinding:
    device: int
    inode: int


@dataclass(slots=True)
class _HeldArtifact:
    name: str
    descriptor: int
    binding: _InodeBinding


@dataclass(frozen=True, slots=True)
class _V1Baseline:
    artifact: _HeldArtifact
    size: int
    sha256: str


@dataclass(slots=True)
class _StableProjectionNamespace:
    path: Path
    parent_path: Path
    main_name: str
    lock_name: str
    parent_descriptor: int
    parent_binding: _InodeBinding
    lock_descriptor: int
    lock_binding: _InodeBinding
    image_kind: projection._ProjectionImageKind
    original_main_binding: _InodeBinding | None


@dataclass(slots=True)
class _PublicationAcquisition:
    namespace: _StableProjectionNamespace | None = None
    temp: _HeldArtifact | None = None
    v1_artifact: _HeldArtifact | None = None
    v1_baseline: _V1Baseline | None = None
    v1_connection: sqlite3.Connection | None = None


@dataclass(slots=True)
class _PublicationState:
    namespace: _StableProjectionNamespace
    temp: _HeldArtifact
    v1_baseline: _V1Baseline | None
    namespace_attempted: bool = False


class _RecoveryDisposition(StrEnum):
    ABSENT = "absent"
    MAIN_ONLY = "main_only"
    TEMP_REMOVED = "temp_removed"
    LINK_COMPLETED = "link_completed"


@dataclass(frozen=True, slots=True)
class _PublicationRecoveryResult:
    main_binding: _InodeBinding | None
    disposition: _RecoveryDisposition


class _FilesystemNamespacePublisher:
    """One-shot callback whose only captured object is filesystem state."""

    def __init__(self, state: _PublicationState) -> None:
        self.state = state

    def __call__(
        self,
        latch: projection_v2._NamespacePublicationLatch,
    ) -> sqlite3.Connection:
        return _publish_namespace(self.state, latch)


def _inode(info: os.stat_result) -> _InodeBinding:
    return _InodeBinding(info.st_dev, info.st_ino)


def _projection_binding(value: projection._FileBinding) -> _InodeBinding:
    return _InodeBinding(value.device, value.inode)


def _validate_core_artifact(
    info: os.stat_result,
    *,
    label: str,
    links: frozenset[int],
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink not in links
    ):
        raise projection.ProjectionConflict(f"unsafe {label} artifact")


def _lstat(parent_descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _dup_cloexec(descriptor: int) -> int:
    if hasattr(fcntl, "F_DUPFD_CLOEXEC"):
        return fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 0)
    duplicated = os.dup(descriptor)
    os.set_inheritable(duplicated, False)
    return duplicated


def _close_descriptor(descriptor: int) -> None:
    os.close(descriptor)


def _close_held(artifact: _HeldArtifact) -> None:
    if artifact.descriptor < 0:
        return
    descriptor = artifact.descriptor
    artifact.descriptor = -1
    _close_descriptor(descriptor)


def _drain_close_held(
    artifacts: list[_HeldArtifact],
) -> list[BaseException]:
    errors: list[BaseException] = []
    for artifact in artifacts:
        try:
            _close_held(artifact)
        except BaseException as error:  # noqa: BLE001 - drain every owned fd
            errors.append(error)
    return errors


def _drain_close_namespace(
    namespace: _StableProjectionNamespace,
) -> list[BaseException]:
    errors: list[BaseException] = []
    for attribute in ("lock_descriptor", "parent_descriptor"):
        descriptor = getattr(namespace, attribute)
        if descriptor < 0:
            continue
        setattr(namespace, attribute, -1)
        try:
            _close_descriptor(descriptor)
        except BaseException as error:  # noqa: BLE001 - drain every owned fd
            errors.append(error)
    return errors


def _finish_cleanup(
    errors: list[BaseException],
    *,
    primary: BaseException | None,
    label: str,
) -> None:
    if not errors:
        return
    if primary is not None:
        for cleanup_issue in errors:
            primary.add_note(
                f"{label}: {type(cleanup_issue).__name__}: {cleanup_issue}"
            )
        return
    raise BaseExceptionGroup(label, errors)


def _open_held_artifact(
    parent_descriptor: int,
    name: str,
    *,
    label: str,
    links: frozenset[int],
) -> _HeldArtifact:
    before = _lstat(parent_descriptor, name)
    if before is None:
        raise projection.ProjectionConflict(f"{label} disappeared")
    _validate_core_artifact(before, label=label, links=links)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        _validate_core_artifact(opened, label=label, links=links)
        if _inode(opened) != _inode(before):
            raise projection.ProjectionConflict(f"{label} changed during binding")
        artifact = _HeldArtifact(name, descriptor, _inode(opened))
        descriptor = -1
        return artifact
    except projection.ProjectionConflict:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise projection.ProjectionConflict(f"{label} could not be bound") from error
    finally:
        if descriptor >= 0:
            _close_descriptor(descriptor)


def _require_held_artifact(
    parent_descriptor: int,
    artifact: _HeldArtifact,
    *,
    label: str,
    links: frozenset[int],
) -> os.stat_result:
    if artifact.descriptor < 0:
        raise projection.ProjectionConflict(f"{label} descriptor was detached")
    try:
        opened = os.fstat(artifact.descriptor)
    except OSError as error:
        raise projection.ProjectionConflict(f"{label} descriptor was lost") from error
    named = _lstat(parent_descriptor, artifact.name)
    if named is None:
        raise projection.ProjectionConflict(f"{label} disappeared")
    _validate_core_artifact(opened, label=label, links=links)
    _validate_core_artifact(named, label=label, links=links)
    if _inode(opened) != artifact.binding or _inode(named) != artifact.binding:
        raise projection.ProjectionConflict(f"{label} identity changed")
    return opened


def _unlink_held_artifact(
    parent_descriptor: int,
    artifact: _HeldArtifact,
    *,
    label: str,
    links_before: frozenset[int],
    links_after: int,
) -> None:
    _require_held_artifact(
        parent_descriptor,
        artifact,
        label=label,
        links=links_before,
    )
    unlink_error: BaseException | None = None
    try:
        os.unlink(artifact.name, dir_fd=parent_descriptor)
    except BaseException as error:  # noqa: BLE001 - classify a mutated syscall
        unlink_error = error
    named = _lstat(parent_descriptor, artifact.name)
    try:
        opened = os.fstat(artifact.descriptor)
    except OSError as error:
        if unlink_error is not None:
            unlink_error.add_note(f"post-unlink descriptor check failed: {error!r}")
            raise unlink_error
        raise projection.ProjectionConflict(
            f"{label} descriptor could not prove unlink"
        ) from error
    if (
        named is not None
        or _inode(opened) != artifact.binding
        or opened.st_nlink != links_after
    ):
        if unlink_error is not None:
            raise unlink_error
        raise projection.ProjectionConflict(f"{label} unlink was not exact")
    _close_held(artifact)


def _validate_namespace(namespace: _StableProjectionNamespace) -> None:
    if namespace.parent_descriptor < 0 or namespace.lock_descriptor < 0:
        raise projection.ProjectionConflict("projection namespace descriptors were detached")
    try:
        parent_opened = os.fstat(namespace.parent_descriptor)
        parent_named = os.stat(namespace.parent_path, follow_symlinks=False)
        lock_opened = os.fstat(namespace.lock_descriptor)
    except OSError as error:
        raise projection.ProjectionConflict(
            "projection namespace binding is unavailable"
        ) from error
    lock_named = _lstat(namespace.parent_descriptor, namespace.lock_name)
    if (
        not stat.S_ISDIR(parent_opened.st_mode)
        or not stat.S_ISDIR(parent_named.st_mode)
        or parent_opened.st_uid != os.geteuid()
        or parent_named.st_uid != os.geteuid()
        or stat.S_IMODE(parent_opened.st_mode) != 0o700
        or stat.S_IMODE(parent_named.st_mode) != 0o700
        or _inode(parent_opened) != namespace.parent_binding
        or _inode(parent_named) != namespace.parent_binding
        or lock_named is None
    ):
        raise projection.ProjectionConflict("projection parent binding changed")
    _validate_core_artifact(
        lock_opened,
        label="projection lock",
        links=frozenset({1}),
    )
    _validate_core_artifact(
        lock_named,
        label="projection lock",
        links=frozenset({1}),
    )
    if (
        _inode(lock_opened) != namespace.lock_binding
        or _inode(lock_named) != namespace.lock_binding
        or fcntl.fcntl(namespace.lock_descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        != os.O_RDWR
    ):
        raise projection.ProjectionConflict("projection stable lock changed")
    try:
        fcntl.flock(
            namespace.lock_descriptor,
            fcntl.LOCK_EX | fcntl.LOCK_NB,
        )
    except OSError as error:
        raise projection.ProjectionConflict("projection stable lock was lost") from error


def _stable_namespace(
    path: Path,
    *,
    parent_fd: int,
    lock_fd: int,
    image_kind: projection._ProjectionImageKind,
    main_binding: projection._FileBinding | None,
    acquisition: _PublicationAcquisition,
) -> _StableProjectionNamespace:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or Path(os.path.normpath(path)) != path
        or image_kind not in (
            projection._ProjectionImageKind.NEW,
            projection._ProjectionImageKind.V1,
        )
        or (image_kind is projection._ProjectionImageKind.NEW and main_binding is not None)
        or (
            image_kind is projection._ProjectionImageKind.V1
            and type(main_binding) is not projection._FileBinding
        )
    ):
        raise projection.ProjectionConflict("invalid durable publication namespace")
    owned_parent = -1
    owned_lock = -1
    namespace: _StableProjectionNamespace | None = None
    primary: BaseException | None = None
    try:
        owned_parent = _dup_cloexec(parent_fd)
        owned_lock = _dup_cloexec(lock_fd)
        parent_info = os.fstat(owned_parent)
        lock_info = os.fstat(owned_lock)
        namespace = _StableProjectionNamespace(
            path=path,
            parent_path=path.parent,
            main_name=path.name,
            lock_name=f".{path.name}.projection.lock",
            parent_descriptor=owned_parent,
            parent_binding=_inode(parent_info),
            lock_descriptor=owned_lock,
            lock_binding=_inode(lock_info),
            image_kind=image_kind,
            original_main_binding=(
                None
                if main_binding is None
                else _projection_binding(main_binding)
            ),
        )
        acquisition.namespace = namespace
        _validate_namespace(namespace)
        current = _lstat(owned_parent, path.name)
        if image_kind is projection._ProjectionImageKind.NEW:
            if current is not None or _any_sidecar(owned_parent, path.name):
                raise projection.ProjectionConflict(
                    "NEW projection destination is not absent"
                )
        else:
            assert namespace.original_main_binding is not None
            if current is None:
                raise projection.ProjectionConflict("V1 projection disappeared")
            _validate_core_artifact(
                current,
                label="V1 projection",
                links=frozenset({1}),
            )
            if _inode(current) != namespace.original_main_binding:
                raise projection.ProjectionConflict("V1 projection identity changed")
            if _any_sidecar(owned_parent, path.name):
                raise projection.ProjectionConflict(
                    "V1 projection sidecar exists before publication"
                )
        owned_parent = -1
        owned_lock = -1
        return namespace
    except BaseException as error:
        primary = error
        raise
    finally:
        close_errors: list[BaseException] = []
        if namespace is not None and acquisition.namespace is namespace:
            owned_lock = -1
            owned_parent = -1
        if owned_lock >= 0:
            descriptor = owned_lock
            owned_lock = -1
            try:
                _close_descriptor(descriptor)
            except BaseException as error:  # noqa: BLE001 - drain both duplicates
                close_errors.append(error)
        if owned_parent >= 0:
            descriptor = owned_parent
            owned_parent = -1
            try:
                _close_descriptor(descriptor)
            except BaseException as error:  # noqa: BLE001 - drain both duplicates
                close_errors.append(error)
        _finish_cleanup(
            close_errors,
            primary=primary,
            label="stable namespace acquisition cleanup failure",
        )


def _create_temp(
    namespace: _StableProjectionNamespace,
    *,
    acquisition: _PublicationAcquisition,
) -> _HeldArtifact:
    name = f".{namespace.main_name}.projection.{uuid.uuid4()}.tmp"
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            flags,
            0o600,
            dir_fd=namespace.parent_descriptor,
        )
        info = os.fstat(descriptor)
        artifact = _HeldArtifact(name, descriptor, _inode(info))
        acquisition.temp = artifact
        descriptor = -1
        _validate_core_artifact(
            info,
            label="temporary projection",
            links=frozenset({1}),
        )
        named = _lstat(namespace.parent_descriptor, name)
        if named is None or _inode(named) != _inode(info):
            raise projection.ProjectionConflict(
                "temporary projection changed during creation"
            )
        return artifact
    finally:
        if descriptor >= 0:
            _close_descriptor(descriptor)


def _open_existing_sqlite(path: Path, *, configure_v2: bool) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"{path.as_uri()}?mode=rw",
        uri=True,
        isolation_level=None,
        check_same_thread=False,
    )
    try:
        connection.row_factory = sqlite3.Row if configure_v2 else None
        if configure_v2:
            projection_v2._configure_v2_connection(
                connection,
                file_backed=True,
            )
        return connection
    except BaseException:
        connection.close()
        raise


def _hash_descriptor(descriptor: int) -> tuple[int, str]:
    info = os.fstat(descriptor)
    digest = hashlib.sha256()
    offset = 0
    while offset < info.st_size:
        block = os.pread(descriptor, min(1024 * 1024, info.st_size - offset), offset)
        if not block:
            raise projection.ProjectionConflict("projection bytes changed during hashing")
        digest.update(block)
        offset += len(block)
    if os.fstat(descriptor).st_size != info.st_size:
        raise projection.ProjectionConflict("projection size changed during hashing")
    return info.st_size, digest.hexdigest()


def _open_held_v1_read_only(artifact: _HeldArtifact) -> sqlite3.Connection:
    """Open the exact held V1 inode without resolving its namespace entry again."""
    if artifact.descriptor < 0:
        raise projection.ProjectionConflict("V1 projection descriptor was detached")
    held_path = Path("/dev/fd") / str(artifact.descriptor)
    try:
        descriptor_info = os.fstat(artifact.descriptor)
        descriptor_flags = fcntl.fcntl(artifact.descriptor, fcntl.F_GETFL)
        held_path_info = os.stat(held_path)
    except (OSError, TypeError, ValueError) as error:
        raise projection.ProjectionConflict(
            "held V1 projection descriptor is unavailable"
        ) from error
    _validate_core_artifact(
        descriptor_info,
        label="V1 projection",
        links=frozenset({1}),
    )
    if (
        _inode(descriptor_info) != artifact.binding
        or held_path_info.st_ino != descriptor_info.st_ino
        or descriptor_flags & os.O_ACCMODE != os.O_RDONLY
    ):
        raise projection.ProjectionConflict(
            "held V1 projection descriptor identity changed"
        )

    connection = sqlite3.connect(
        f"{held_path.as_uri()}?mode=ro&immutable=1",
        uri=True,
        isolation_level=None,
    )
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        expected_pragmas: tuple[tuple[str, int], ...] = (
            ("busy_timeout", 5000),
            ("foreign_keys", 1),
            ("trusted_schema", 0),
            ("query_only", 1),
        )
        for pragma, expected in expected_pragmas:
            if connection.execute(f"PRAGMA {pragma}").fetchone()[0] != expected:
                raise projection.ProjectionConflict(
                    f"held V1 projection PRAGMA {pragma} is unsafe"
                )
        main_rows = [
            row
            for row in connection.execute("PRAGMA database_list").fetchall()
            if str(row[1]) == "main"
        ]
        if len(main_rows) != 1 or Path(str(main_rows[0][2])) != held_path:
            raise projection.ProjectionConflict(
                "SQLite did not open the held V1 projection descriptor"
            )
        current_descriptor_info = os.fstat(artifact.descriptor)
        current_held_path_info = os.stat(held_path)
        if (
            _inode(current_descriptor_info) != artifact.binding
            or current_held_path_info.st_ino != current_descriptor_info.st_ino
        ):
            raise projection.ProjectionConflict(
                "held V1 projection descriptor changed during open"
            )
    except BaseException:
        connection.close()
        raise
    return connection


def _bind_v1_baseline(
    namespace: _StableProjectionNamespace,
    *,
    acquisition: _PublicationAcquisition,
) -> tuple[_V1Baseline, sqlite3.Connection]:
    artifact = _open_held_artifact(
        namespace.parent_descriptor,
        namespace.main_name,
        label="V1 projection",
        links=frozenset({1}),
    )
    acquisition.v1_artifact = artifact
    if artifact.binding != namespace.original_main_binding:
        raise projection.ProjectionConflict("V1 projection identity changed")
    if _any_sidecar(namespace.parent_descriptor, namespace.main_name):
        raise projection.ProjectionConflict(
            "V1 projection sidecar exists before immutable open"
        )
    size, digest = _hash_descriptor(artifact.descriptor)
    baseline = _V1Baseline(artifact, size, digest)
    acquisition.v1_baseline = baseline
    acquisition.v1_artifact = None
    connection = _open_held_v1_read_only(artifact)
    acquisition.v1_connection = connection
    projection._verify_v1_schema(connection, immutable_read_only=True)
    serialized = connection.serialize()
    _require_held_artifact(
        namespace.parent_descriptor,
        artifact,
        label="V1 projection",
        links=frozenset({1}),
    )
    current_size, current_digest = _hash_descriptor(artifact.descriptor)
    if (
        type(serialized) is not bytes
        or len(serialized) != size
        or hashlib.sha256(serialized).hexdigest() != digest
        or current_size != size
        or current_digest != digest
        or _any_sidecar(namespace.parent_descriptor, namespace.main_name)
    ):
        raise projection.ProjectionConflict(
            "immutable V1 connection is not the held baseline inode"
        )
    return baseline, connection


def _any_sidecar(parent_descriptor: int, name: str) -> bool:
    return any(
        _lstat(parent_descriptor, f"{name}{suffix}") is not None
        for suffix in projection._SQLITE_SIDECAR_SUFFIXES
    )


def _bind_sidecars(
    namespace: _StableProjectionNamespace,
    name: str,
    *,
    require_empty: bool,
) -> list[_HeldArtifact]:
    artifacts: list[_HeldArtifact] = []
    try:
        for suffix in projection._SQLITE_SIDECAR_SUFFIXES:
            sidecar_name = f"{name}{suffix}"
            if _lstat(namespace.parent_descriptor, sidecar_name) is None:
                continue
            artifact = _open_held_artifact(
                namespace.parent_descriptor,
                sidecar_name,
                label="temporary projection sidecar",
                links=frozenset({1}),
            )
            artifacts.append(artifact)
            if require_empty and os.fstat(artifact.descriptor).st_size != 0:
                raise projection.ProjectionConflict(
                    "temporary projection sidecar is not empty"
                )
        return artifacts
    except BaseException as primary:
        _finish_cleanup(
            _drain_close_held(artifacts),
            primary=primary,
            label="temporary sidecar binding cleanup failure",
        )
        raise


def _remove_bound_sidecars(
    namespace: _StableProjectionNamespace,
    artifacts: list[_HeldArtifact],
) -> None:
    errors: list[BaseException] = []
    for artifact in artifacts:
        try:
            _unlink_held_artifact(
                namespace.parent_descriptor,
                artifact,
                label="temporary projection sidecar",
                links_before=frozenset({1}),
                links_after=0,
            )
        except BaseException as error:  # noqa: BLE001 - drain remaining sidecars
            errors.append(error)
            errors.extend(_drain_close_held([artifact]))
    _finish_cleanup(
        errors,
        primary=None,
        label="temporary sidecar removal failed",
    )


def _sync_file(descriptor: int) -> None:
    fdatasync = getattr(os, "fdatasync", None)
    if fdatasync is None:
        os.fsync(descriptor)
    else:
        fdatasync(descriptor)


def _fsync_parent(namespace: _StableProjectionNamespace) -> None:
    _validate_namespace(namespace)
    os.fsync(namespace.parent_descriptor)


def _require_v1_unchanged(
    namespace: _StableProjectionNamespace,
    baseline: _V1Baseline | None,
) -> None:
    if baseline is None:
        raise projection.ProjectionConflict("V1 baseline was lost")
    _require_held_artifact(
        namespace.parent_descriptor,
        baseline.artifact,
        label="V1 projection",
        links=frozenset({1}),
    )
    named = _lstat(namespace.parent_descriptor, namespace.main_name)
    size, digest = _hash_descriptor(baseline.artifact.descriptor)
    if (
        named is None
        or _inode(named) != baseline.artifact.binding
        or size != baseline.size
        or digest != baseline.sha256
    ):
        raise projection.ProjectionConflict("V1 projection changed before publication")


def _prepublish_validate(state: _PublicationState) -> None:
    namespace = state.namespace
    _validate_namespace(namespace)
    _require_held_artifact(
        namespace.parent_descriptor,
        state.temp,
        label="temporary projection",
        links=frozenset({1}),
    )
    if _any_sidecar(namespace.parent_descriptor, state.temp.name):
        raise projection.ProjectionConflict(
            "temporary projection sidecar appeared before publication"
        )
    if namespace.image_kind is projection._ProjectionImageKind.V1:
        _require_v1_unchanged(namespace, state.v1_baseline)
        if _any_sidecar(namespace.parent_descriptor, namespace.main_name):
            raise projection.ProjectionConflict(
                "V1 projection sidecar appeared before publication"
            )
    elif (
        _lstat(namespace.parent_descriptor, namespace.main_name) is not None
        or _any_sidecar(namespace.parent_descriptor, namespace.main_name)
    ):
        raise projection.ProjectionConflict("NEW projection destination is not absent")


def _replace_completed(state: _PublicationState) -> bool:
    namespace = state.namespace
    baseline = state.v1_baseline
    if baseline is None:
        return False
    final = _lstat(namespace.parent_descriptor, namespace.main_name)
    temp = _lstat(namespace.parent_descriptor, state.temp.name)
    try:
        old = os.fstat(baseline.artifact.descriptor)
        staged = os.fstat(state.temp.descriptor)
    except OSError:
        return False
    return (
        final is not None
        and _inode(final) == state.temp.binding
        and _inode(staged) == state.temp.binding
        and staged.st_nlink == 1
        and temp is None
        and _inode(old) == baseline.artifact.binding
        and old.st_nlink == 0
    )


def _link_completed(state: _PublicationState) -> bool:
    namespace = state.namespace
    final = _lstat(namespace.parent_descriptor, namespace.main_name)
    temp = _lstat(namespace.parent_descriptor, state.temp.name)
    try:
        opened = os.fstat(state.temp.descriptor)
    except OSError:
        return False
    return (
        final is not None
        and temp is not None
        and _inode(final) == state.temp.binding
        and _inode(temp) == state.temp.binding
        and _inode(opened) == state.temp.binding
        and final.st_nlink == temp.st_nlink == opened.st_nlink == 2
    )


def _publish_replace(state: _PublicationState) -> None:
    namespace = state.namespace
    syscall_error: BaseException | None = None
    try:
        os.replace(
            state.temp.name,
            namespace.main_name,
            src_dir_fd=namespace.parent_descriptor,
            dst_dir_fd=namespace.parent_descriptor,
        )
    except BaseException as error:  # noqa: BLE001 - resolve an exact namespace edge
        syscall_error = error
    if not _replace_completed(state):
        if syscall_error is not None:
            raise syscall_error
        raise projection.ProjectionConflict("V1 replacement state is ambiguous")


def _publish_link(state: _PublicationState) -> None:
    namespace = state.namespace
    syscall_error: BaseException | None = None
    try:
        os.link(
            state.temp.name,
            namespace.main_name,
            src_dir_fd=namespace.parent_descriptor,
            dst_dir_fd=namespace.parent_descriptor,
            follow_symlinks=False,
        )
    except BaseException as error:  # noqa: BLE001 - resolve an exact namespace edge
        syscall_error = error
    if not _link_completed(state):
        if syscall_error is not None:
            raise syscall_error
        raise projection.ProjectionConflict("NEW publication link state is ambiguous")
    _unlink_held_artifact(
        namespace.parent_descriptor,
        state.temp,
        label="temporary projection link",
        links_before=frozenset({2}),
        links_after=1,
    )


def _publish_namespace(
    state: _PublicationState,
    latch: projection_v2._NamespacePublicationLatch,
) -> sqlite3.Connection:
    if type(latch) is not projection_v2._NamespacePublicationLatch:
        raise projection.ProjectionAuthorityError(
            "durable publisher received a substituted namespace latch"
        )
    _prepublish_validate(state)
    try:
        state.namespace_attempted = True
        latch._arm_namespace_publication()
        if state.namespace.image_kind is projection._ProjectionImageKind.V1:
            _publish_replace(state)
        else:
            _publish_link(state)
    except BaseException:
        if state.namespace_attempted:
            latch._arm_namespace_publication()
        raise
    _fsync_parent(state.namespace)
    reopened = _open_existing_sqlite(state.namespace.path, configure_v2=True)
    return reopened


def _cleanup_prearm_temp(
    namespace: _StableProjectionNamespace,
    temp: _HeldArtifact,
) -> None:
    current = _lstat(namespace.parent_descriptor, temp.name)
    if current is None:
        return
    try:
        _require_held_artifact(
            namespace.parent_descriptor,
            temp,
            label="temporary projection",
            links=frozenset({1}),
        )
        sidecars = _bind_sidecars(
            namespace,
            temp.name,
            require_empty=True,
        )
    except BaseException:  # noqa: BLE001 - unsafe artifacts must remain untouched
        return
    _remove_bound_sidecars(namespace, sidecars)
    _unlink_held_artifact(
        namespace.parent_descriptor,
        temp,
        label="temporary projection",
        links_before=frozenset({1}),
        links_after=0,
    )
    _fsync_parent(namespace)


def _prove_prearm_destination(
    namespace: _StableProjectionNamespace,
    temp: _HeldArtifact,
    baseline: _V1Baseline | None,
) -> None:
    if namespace.image_kind is projection._ProjectionImageKind.V1:
        _require_v1_unchanged(namespace, baseline)
        return
    current = _lstat(namespace.parent_descriptor, namespace.main_name)
    if current is None:
        return
    _validate_core_artifact(
        current,
        label="raced projection destination",
        links=frozenset({1}),
    )
    if _inode(current) == temp.binding:
        raise projection.ProjectionConflict(
            "NEW projection destination publication state is ambiguous"
        )


def _publish_staged_v2_filesystem(
    owner: projection_v2._V2ProjectionOwner,
    stage: projection_v2._StagedV2Replay,
    path: Path,
    *,
    parent_fd: int,
    lock_fd: int,
    image_kind: projection._ProjectionImageKind,
    main_binding: projection._FileBinding | None,
    _factory: object,
) -> projection_v2._UnpublishedV2ReplayReport:
    """Materialize and durably publish one already-staged V2 replay."""
    if _factory is not _PUBLICATION_FACTORY:
        raise projection.ProjectionAuthorityError(
            "durable Projection V2 publication is factory-only"
        )
    acquisition = _PublicationAcquisition()
    state: _PublicationState | None = None
    primary: BaseException | None = None
    try:
        namespace = _stable_namespace(
            path,
            parent_fd=parent_fd,
            lock_fd=lock_fd,
            image_kind=image_kind,
            main_binding=main_binding,
            acquisition=acquisition,
        )
        baseline: _V1Baseline | None = None
        if image_kind is projection._ProjectionImageKind.V1:
            baseline, _v1_connection = _bind_v1_baseline(
                namespace,
                acquisition=acquisition,
            )
        temp = _create_temp(namespace, acquisition=acquisition)
        state = _PublicationState(namespace, temp, baseline)
        target: sqlite3.Connection | None = _open_existing_sqlite(
            namespace.parent_path / temp.name,
            configure_v2=False,
        )
        try:
            assert target is not None
            seal = owner._copy_staged_replay_into(
                stage,
                target,
                _factory=projection_v2._STAGED_REPLAY_FACTORY,
            )
        finally:
            # The copy call transfers the exact raw target to owner state.
            target = None
        owner._prepare_staged_replay_for_publication(
            stage,
            seal,
            _factory=projection_v2._STAGED_REPLAY_FACTORY,
        )
        _require_held_artifact(
            namespace.parent_descriptor,
            temp,
            label="temporary projection",
            links=frozenset({1}),
        )
        _sync_file(temp.descriptor)
        _require_held_artifact(
            namespace.parent_descriptor,
            temp,
            label="temporary projection",
            links=frozenset({1}),
        )
        sidecars = _bind_sidecars(namespace, temp.name, require_empty=True)
        _remove_bound_sidecars(namespace, sidecars)
        if _any_sidecar(namespace.parent_descriptor, temp.name):
            raise projection.ProjectionConflict(
                "temporary projection sidecar removal was incomplete"
            )
        _fsync_parent(namespace)
        publisher = _FilesystemNamespacePublisher(state)
        return owner._publish_staged_replay(
            stage,
            seal,
            publisher,
            _factory=projection_v2._STAGED_REPLAY_FACTORY,
        )
    except BaseException as error:
        primary = error
        if state is not None and state.namespace_attempted:
            owner._latch_unhealthy(error)
        else:
            binding = owner._staged_replay
            if binding is not None and binding.capability is stage:
                try:
                    owner._abort_staged_replay(
                        stage,
                        _factory=projection_v2._STAGED_REPLAY_FACTORY,
                    )
                except BaseException as cleanup_error:  # noqa: BLE001
                    error.add_note(
                        "durable publication stage cleanup failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            owned_namespace = acquisition.namespace
            owned_temp = acquisition.temp
            if owned_namespace is not None and owned_temp is not None:
                try:
                    _cleanup_prearm_temp(owned_namespace, owned_temp)
                    _prove_prearm_destination(
                        owned_namespace,
                        owned_temp,
                        acquisition.v1_baseline,
                    )
                except BaseException as cleanup_error:  # noqa: BLE001
                    error.add_note(
                        "durable publication pre-arm proof failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            elif (
                owned_namespace is not None
                and owned_namespace.image_kind is projection._ProjectionImageKind.V1
                and acquisition.v1_baseline is not None
            ):
                try:
                    _require_v1_unchanged(
                        owned_namespace,
                        acquisition.v1_baseline,
                    )
                except BaseException as cleanup_error:  # noqa: BLE001
                    error.add_note(
                        "durable publication V1 pre-arm proof failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
        raise
    finally:
        close_errors: list[BaseException] = []
        v1_connection = acquisition.v1_connection
        acquisition.v1_connection = None
        if v1_connection is not None:
            try:
                v1_connection.close()
            except BaseException as error:  # noqa: BLE001 - held immutable reader
                close_errors.append(error)
        owned_temp = acquisition.temp
        acquisition.temp = None
        if owned_temp is not None:
            close_errors.extend(_drain_close_held([owned_temp]))
        baseline = acquisition.v1_baseline
        acquisition.v1_baseline = None
        if baseline is not None:
            close_errors.extend(_drain_close_held([baseline.artifact]))
        v1_artifact = acquisition.v1_artifact
        acquisition.v1_artifact = None
        if v1_artifact is not None:
            close_errors.extend(_drain_close_held([v1_artifact]))
        owned_namespace = acquisition.namespace
        acquisition.namespace = None
        if owned_namespace is not None:
            close_errors.extend(_drain_close_namespace(owned_namespace))
        if close_errors:
            if primary is None and state is not None and state.namespace_attempted:
                owner._latch_unhealthy(close_errors[0])
            _finish_cleanup(
                close_errors,
                primary=primary,
                label="durable publication final cleanup failure",
            )


def _temp_groups(namespace: _StableProjectionNamespace) -> dict[str, set[str]]:
    prefix = f".{namespace.main_name}.projection."
    main_pattern = re.compile(rf"^{re.escape(prefix)}{_TEMP_UUID}\.tmp$")
    sidecar_pattern = re.compile(
        rf"^({re.escape(prefix)}{_TEMP_UUID}\.tmp)(-(?:wal|shm|journal))$"
    )
    groups: dict[str, set[str]] = {}
    for name in os.listdir(namespace.parent_descriptor):
        if name == namespace.lock_name or not name.startswith(prefix):
            continue
        if main_pattern.fullmatch(name) is not None:
            groups.setdefault(name, set()).add(name)
            continue
        match = sidecar_pattern.fullmatch(name)
        if match is None:
            raise projection.ProjectionConflict(
                "unexpected Projection V2 publication artifact"
            )
        temp_name = match.group(1)
        groups.setdefault(temp_name, set()).add(name)
    if any(temp_name not in names for temp_name, names in groups.items()):
        raise projection.ProjectionConflict("orphan Projection V2 temp sidecar")
    if len(groups) > 1:
        raise projection.ProjectionConflict("multiple Projection V2 temp groups")
    return groups


def _remove_recovery_group(
    namespace: _StableProjectionNamespace,
    temp: _HeldArtifact,
) -> None:
    sidecars = _bind_sidecars(namespace, temp.name, require_empty=False)
    _remove_bound_sidecars(namespace, sidecars)
    _unlink_held_artifact(
        namespace.parent_descriptor,
        temp,
        label="recoverable temporary projection",
        links_before=frozenset({1}),
        links_after=0,
    )
    _fsync_parent(namespace)


def _recovery_namespace(
    path: Path,
    *,
    parent_fd: int,
    lock_fd: int,
    acquisition: _PublicationAcquisition,
) -> _StableProjectionNamespace:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or Path(os.path.normpath(path)) != path
    ):
        raise projection.ProjectionConflict("invalid recovery namespace")
    owned_parent = _dup_cloexec(parent_fd)
    owned_lock = -1
    namespace: _StableProjectionNamespace | None = None
    primary: BaseException | None = None
    try:
        owned_lock = _dup_cloexec(lock_fd)
        namespace = _StableProjectionNamespace(
            path=path,
            parent_path=path.parent,
            main_name=path.name,
            lock_name=f".{path.name}.projection.lock",
            parent_descriptor=owned_parent,
            parent_binding=_inode(os.fstat(owned_parent)),
            lock_descriptor=owned_lock,
            lock_binding=_inode(os.fstat(owned_lock)),
            image_kind=projection._ProjectionImageKind.NEW,
            original_main_binding=None,
        )
        acquisition.namespace = namespace
        _validate_namespace(namespace)
        owned_parent = -1
        owned_lock = -1
        return namespace
    except BaseException as error:
        primary = error
        raise
    finally:
        close_errors: list[BaseException] = []
        if namespace is not None and acquisition.namespace is namespace:
            owned_lock = -1
            owned_parent = -1
        if owned_lock >= 0:
            descriptor = owned_lock
            owned_lock = -1
            try:
                _close_descriptor(descriptor)
            except BaseException as error:  # noqa: BLE001 - drain both duplicates
                close_errors.append(error)
        if owned_parent >= 0:
            descriptor = owned_parent
            owned_parent = -1
            try:
                _close_descriptor(descriptor)
            except BaseException as error:  # noqa: BLE001 - drain both duplicates
                close_errors.append(error)
        _finish_cleanup(
            close_errors,
            primary=primary,
            label="recovery namespace acquisition cleanup failure",
        )


def _recover_v2_publication_locked(
    path: Path,
    *,
    parent_fd: int,
    lock_fd: int,
    _factory: object,
) -> _PublicationRecoveryResult:
    """Recover one exact temp/link state without classifying the final schema."""
    if _factory is not _PUBLICATION_FACTORY:
        raise projection.ProjectionAuthorityError(
            "Projection V2 publication recovery is factory-only"
        )
    acquisition = _PublicationAcquisition()
    namespace: _StableProjectionNamespace | None = None
    temp: _HeldArtifact | None = None
    main: _HeldArtifact | None = None
    primary: BaseException | None = None
    try:
        namespace = _recovery_namespace(
            path,
            parent_fd=parent_fd,
            lock_fd=lock_fd,
            acquisition=acquisition,
        )
        groups = _temp_groups(namespace)
        main_info = _lstat(namespace.parent_descriptor, namespace.main_name)
        if not groups:
            if main_info is None:
                return _PublicationRecoveryResult(None, _RecoveryDisposition.ABSENT)
            main = _open_held_artifact(
                namespace.parent_descriptor,
                namespace.main_name,
                label="projection main",
                links=frozenset({1}),
            )
            return _PublicationRecoveryResult(
                main.binding,
                _RecoveryDisposition.MAIN_ONLY,
            )

        temp_name = next(iter(groups))
        temp_info = _lstat(namespace.parent_descriptor, temp_name)
        if temp_info is None:
            raise projection.ProjectionConflict("Projection V2 temp disappeared")
        if main_info is not None and _inode(main_info) == _inode(temp_info):
            if _any_sidecar(namespace.parent_descriptor, temp_name) or _any_sidecar(
                namespace.parent_descriptor,
                namespace.main_name,
            ):
                raise projection.ProjectionConflict(
                    "linked Projection V2 publication has sidecars"
                )
            temp = _open_held_artifact(
                namespace.parent_descriptor,
                temp_name,
                label="linked temporary projection",
                links=frozenset({2}),
            )
            main = _open_held_artifact(
                namespace.parent_descriptor,
                namespace.main_name,
                label="linked projection main",
                links=frozenset({2}),
            )
            if main.binding != temp.binding:
                raise projection.ProjectionConflict(
                    "linked Projection V2 publication identity changed"
                )
            _unlink_held_artifact(
                namespace.parent_descriptor,
                temp,
                label="linked temporary projection",
                links_before=frozenset({2}),
                links_after=1,
            )
            _require_held_artifact(
                namespace.parent_descriptor,
                main,
                label="linked projection main",
                links=frozenset({1}),
            )
            _fsync_parent(namespace)
            return _PublicationRecoveryResult(
                main.binding,
                _RecoveryDisposition.LINK_COMPLETED,
            )

        temp = _open_held_artifact(
            namespace.parent_descriptor,
            temp_name,
            label="recoverable temporary projection",
            links=frozenset({1}),
        )
        if main_info is not None:
            main = _open_held_artifact(
                namespace.parent_descriptor,
                namespace.main_name,
                label="raced projection main",
                links=frozenset({1}),
            )
            if main.binding == temp.binding:
                raise projection.ProjectionConflict(
                    "Projection V2 recovery link state is ambiguous"
                )
        _remove_recovery_group(namespace, temp)
        return _PublicationRecoveryResult(
            None if main is None else main.binding,
            _RecoveryDisposition.TEMP_REMOVED,
        )
    except BaseException as error:
        primary = error
        raise
    finally:
        close_errors = _drain_close_held(
            [artifact for artifact in (temp, main) if artifact is not None]
        )
        owned_namespace = acquisition.namespace
        acquisition.namespace = None
        if owned_namespace is not None:
            close_errors.extend(_drain_close_namespace(owned_namespace))
        _finish_cleanup(
            close_errors,
            primary=primary,
            label="Projection V2 recovery cleanup failure",
        )
