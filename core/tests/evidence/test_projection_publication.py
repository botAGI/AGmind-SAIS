from __future__ import annotations

# The loop-local closures are installed and invoked before their iteration advances.
# ruff: noqa: B023
import hashlib
import importlib
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest
from tests.evidence.test_projection_pcc import (
    _DETECTOR_HASH,
    _durable_unpublished_case,
)


def _subjects(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Any, Any]:
    active = importlib.import_module("agmind_immune.evidence.projection")
    v2 = importlib.import_module("agmind_immune.evidence.projection_v2")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    try:
        publication = importlib.import_module(
            "agmind_immune.evidence.projection_publication"
        )
    except ModuleNotFoundError:
        pytest.fail("dormant durable Projection V2 publisher is not implemented")
    return active, v2, publication


def _namespace(active: Any, path: Path) -> tuple[int, int, Any | None]:
    parent_fd = active._validate_parent(path.parent)
    lock_fd = active._open_stable_lock(
        parent_fd,
        f".{path.name}.projection.lock",
    )
    info = active._lstat_at(parent_fd, path.name)
    binding = None if info is None else active._binding(info)
    return parent_fd, lock_fd, binding


def _close_namespace(parent_fd: int, lock_fd: int) -> None:
    os.close(lock_fd)
    os.close(parent_fd)


def _close_owner(owner: Any) -> None:
    try:
        owner.close()
    except Exception:
        if owner._healthy:
            raise


def _v1_image(active: Any, path: Path) -> None:
    connection = active._connect(path)
    try:
        active._create_schema(connection)
    finally:
        connection.close()
    path.chmod(0o600)


def _temp_name(path: Path, token: uuid.UUID) -> str:
    return f".{path.name}.projection.{token}.tmp"


class _CheckpointCursor:
    def fetchone(self) -> tuple[int, int, int]:
        return (1, 0, 0)


class _TargetProxy:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        checkpoint_busy: bool = False,
        interrupt_close: bool = False,
    ) -> None:
        self.connection = connection
        self.checkpoint_busy = checkpoint_busy
        self.interrupt_close = interrupt_close
        self.close_attempts = 0

    def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> Any:
        if self.checkpoint_busy and sql == "PRAGMA wal_checkpoint(TRUNCATE)":
            return _CheckpointCursor()
        return self.connection.execute(sql, parameters)

    @property
    def in_transaction(self) -> bool:
        return self.connection.in_transaction

    def close(self) -> None:
        self.close_attempts += 1
        self.connection.close()
        if self.interrupt_close:
            raise KeyboardInterrupt("injected ambiguous target close")

    def __getattr__(self, name: str) -> Any:
        return getattr(self.connection, name)


def test_staged_v2_prepare_checkpoints_closes_and_never_exposes_target_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _active, v2, _publication = _subjects(monkeypatch)

    for case in (
        "detach_interrupt",
        "success",
        "checkpoint_busy",
        "ambiguous_close",
        "unprepared",
    ):
        root = tmp_path / case
        root.mkdir(mode=0o700)
        owner, _live, _store, through = _durable_unpublished_case(
            v2,
            root / "evidence",
        )
        stage = owner._stage_unpublished_prefix(
            through,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        target_path = root / "candidate.sqlite3"
        target = sqlite3.connect(
            target_path,
            isolation_level=None,
            check_same_thread=False,
        )
        target_path.chmod(0o600)
        seal = owner._copy_staged_replay_into(
            stage,
            target,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        assert not hasattr(stage, "connection")
        assert not hasattr(seal, "connection")
        binding = owner._staged_replay
        assert binding is not None

        try:
            if case == "detach_interrupt":
                proxy = _TargetProxy(target)
                binding.materialized_connection = proxy
                original_setattr = v2._StagedReplayBinding.__setattr__
                injected = False

                def interrupt_after_detach(
                    selected: Any,
                    name: str,
                    value: object,
                ) -> None:
                    nonlocal injected
                    original_setattr(selected, name, value)
                    if (
                        selected is binding
                        and name == "materialized_connection"
                        and value is None
                        and not injected
                    ):
                        injected = True
                        raise KeyboardInterrupt("injected immediately after detach")

                with pytest.MonkeyPatch.context() as patch:
                    patch.setattr(
                        v2._StagedReplayBinding,
                        "__setattr__",
                        interrupt_after_detach,
                    )
                    with pytest.raises(KeyboardInterrupt, match="after detach"):
                        owner._prepare_staged_replay_for_publication(
                            stage,
                            seal,
                            _factory=v2._STAGED_REPLAY_FACTORY,
                        )
                assert proxy.close_attempts == 1
                assert binding.materialized_connection is None
                assert owner._staged_replay is None
                assert owner._healthy is False
            elif case == "success":
                owner._prepare_staged_replay_for_publication(
                    stage,
                    seal,
                    _factory=v2._STAGED_REPLAY_FACTORY,
                )
                assert binding.materialized_connection is None
                assert binding.materialized_seal is seal
                assert binding.materialized_physical is not None
                assert binding.materialized_physical.descriptor >= 0
                with pytest.raises(sqlite3.ProgrammingError):
                    target.execute("SELECT 1")
                owner._abort_staged_replay(
                    stage,
                    _factory=v2._STAGED_REPLAY_FACTORY,
                )
                assert owner._healthy is True
            elif case == "checkpoint_busy":
                proxy = _TargetProxy(target, checkpoint_busy=True)
                binding.materialized_connection = proxy
                with pytest.raises(v2.ProjectionConflict, match="checkpoint"):
                    owner._prepare_staged_replay_for_publication(
                        stage,
                        seal,
                        _factory=v2._STAGED_REPLAY_FACTORY,
                    )
                assert proxy.close_attempts == 1
                assert owner._staged_replay is None
                assert owner._healthy is True
            elif case == "ambiguous_close":
                proxy = _TargetProxy(target, interrupt_close=True)
                binding.materialized_connection = proxy
                with pytest.raises(KeyboardInterrupt, match="ambiguous target close"):
                    owner._prepare_staged_replay_for_publication(
                        stage,
                        seal,
                        _factory=v2._STAGED_REPLAY_FACTORY,
                    )
                assert proxy.close_attempts == 1
                assert binding.materialized_connection is None
                assert owner._staged_replay is None
                assert owner._healthy is False
            else:
                called = False

                def must_not_publish(_latch: Any) -> sqlite3.Connection:
                    nonlocal called
                    called = True
                    raise AssertionError("unprepared target reached publisher")

                with pytest.raises(v2.ProjectionAuthorityError, match="prepared"):
                    owner._publish_staged_replay(
                        stage,
                        seal,
                        must_not_publish,
                        _factory=v2._STAGED_REPLAY_FACTORY,
                    )
                assert called is False
                assert owner._healthy is True
        finally:
            _close_owner(owner)


def test_v2_publisher_binds_and_removes_only_exact_empty_temp_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active, v2, publication = _subjects(monkeypatch)

    for case in ("stable_namespace", "create_temp", "state_handoff"):
        root = tmp_path / f"acquire-{case}"
        root.mkdir(mode=0o700)
        path = root / "projection.sqlite3"
        token = uuid.UUID(f"01000000-0000-4000-8000-{len(case):012d}")
        temp_path = root / _temp_name(path, token)
        owner, _live, _store, through = _durable_unpublished_case(
            v2,
            root / "evidence",
        )
        stage = owner._stage_unpublished_prefix(
            through,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        parent_fd, lock_fd, main_binding = _namespace(active, path)
        leaked_artifacts: list[Any] = []
        original_create = publication._create_temp
        original_state = publication._PublicationState

        def fail_stable(*_args: Any, **_kwargs: Any) -> Any:
            raise KeyboardInterrupt("injected stable namespace failure")

        def fail_after_create(namespace: Any, *, acquisition: Any) -> Any:
            artifact = original_create(namespace, acquisition=acquisition)
            leaked_artifacts.append(artifact)
            raise KeyboardInterrupt("injected post-create failure")

        def fail_state_handoff(namespace: Any, temp: Any, baseline: Any) -> Any:
            leaked_artifacts.append(temp)
            original_state(namespace, temp, baseline)
            raise KeyboardInterrupt("injected state handoff failure")

        try:
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(publication.uuid, "uuid4", lambda: token)
                if case == "stable_namespace":
                    patch.setattr(publication, "_stable_namespace", fail_stable)
                elif case == "create_temp":
                    patch.setattr(publication, "_create_temp", fail_after_create)
                else:
                    patch.setattr(publication, "_PublicationState", fail_state_handoff)
                with pytest.raises(KeyboardInterrupt, match="injected"):
                    publication._publish_staged_v2_filesystem(
                        owner,
                        stage,
                        path,
                        parent_fd=parent_fd,
                        lock_fd=lock_fd,
                        image_kind=active._ProjectionImageKind.NEW,
                        main_binding=main_binding,
                        _factory=publication._PUBLICATION_FACTORY,
                    )
            assert owner._staged_replay is None
            assert owner._healthy is True
            assert not temp_path.exists()
            assert all(artifact.descriptor == -1 for artifact in leaked_artifacts)
        finally:
            binding = owner._staged_replay
            if binding is not None and binding.capability is stage:
                owner._abort_staged_replay(
                    stage,
                    _factory=v2._STAGED_REPLAY_FACTORY,
                )
            for artifact in leaked_artifacts:
                if artifact.descriptor >= 0:
                    publication._close_held(artifact)
            temp_path.unlink(missing_ok=True)
            _close_namespace(parent_fd, lock_fd)
            _close_owner(owner)

    for case in ("empty", "nonempty", "symlink", "unlink_failure", "close_failure"):
        root = tmp_path / case
        root.mkdir(mode=0o700)
        path = root / "projection.sqlite3"
        token = uuid.UUID(f"00000000-0000-4000-8000-{len(case):012d}")
        temp_path = root / _temp_name(path, token)
        owner, _live, _store, through = _durable_unpublished_case(
            v2,
            root / "evidence",
        )
        stage = owner._stage_unpublished_prefix(
            through,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        parent_fd, lock_fd, main_binding = _namespace(active, path)
        callback_values: list[object] = []
        published_seals: list[object] = []
        sidecar_artifacts: list[Any] = []
        sidecar_descriptors: list[int] = []
        original_prepare = type(owner)._prepare_staged_replay_for_publication
        original_publish = type(owner)._publish_staged_replay
        original_open_held = publication._open_held_artifact
        original_close_descriptor = publication._close_descriptor
        original_unlink = publication.os.unlink
        injected_cleanup_failure = False

        def prepare_with_sidecars(
            selected: Any,
            capability: Any,
            seal: Any,
            *,
            _factory: object,
        ) -> None:
            original_prepare(
                selected,
                capability,
                seal,
                _factory=_factory,
            )
            if case in ("empty", "unlink_failure", "close_failure"):
                for suffix in ("-wal", "-shm", "-journal"):
                    sidecar = Path(f"{temp_path}{suffix}")
                    sidecar.touch(mode=0o600)
                    sidecar.chmod(0o600)
            elif case == "nonempty":
                sidecar = Path(f"{temp_path}-wal")
                sidecar.write_bytes(b"not-empty")
                sidecar.chmod(0o600)
            else:
                foreign = root / "foreign"
                foreign.write_bytes(b"")
                foreign.chmod(0o600)
                Path(f"{temp_path}-shm").symlink_to(foreign.name)

        def track_sidecar(
            parent_descriptor: int,
            name: str,
            *,
            label: str,
            links: frozenset[int],
        ) -> Any:
            artifact = original_open_held(
                parent_descriptor,
                name,
                label=label,
                links=links,
            )
            if name.endswith(("-wal", "-shm", "-journal")):
                sidecar_artifacts.append(artifact)
                sidecar_descriptors.append(artifact.descriptor)
            return artifact

        def fail_one_sidecar_unlink(
            name: str,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal injected_cleanup_failure
            if name.endswith("-wal") and not injected_cleanup_failure:
                injected_cleanup_failure = True
                raise OSError("injected sidecar unlink failure")
            original_unlink(name, dir_fd=dir_fd)

        def fail_one_sidecar_close(descriptor: int) -> None:
            nonlocal injected_cleanup_failure
            if (
                descriptor in sidecar_descriptors
                and not injected_cleanup_failure
            ):
                injected_cleanup_failure = True
                original_close_descriptor(descriptor)
                raise KeyboardInterrupt("injected sidecar close failure")
            original_close_descriptor(descriptor)

        def inspect_callback(
            selected: Any,
            capability: Any,
            seal: Any,
            publisher: Any,
            *,
            _factory: object,
            _fault_phase: Any | None = None,
        ) -> Any:
            del selected
            closure = getattr(publisher, "__closure__", None) or ()
            callback_values.extend(cell.cell_contents for cell in closure)
            callback_values.extend(vars(publisher).values())
            published_seals.append(seal)
            return original_publish(
                owner,
                capability,
                seal,
                publisher,
                _factory=_factory,
                _fault_phase=_fault_phase,
            )

        try:
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(publication.uuid, "uuid4", lambda: token)
                patch.setattr(type(owner), "_prepare_staged_replay_for_publication", prepare_with_sidecars)
                patch.setattr(type(owner), "_publish_staged_replay", inspect_callback)
                patch.setattr(publication, "_open_held_artifact", track_sidecar)
                if case == "unlink_failure":
                    patch.setattr(publication.os, "unlink", fail_one_sidecar_unlink)
                elif case == "close_failure":
                    patch.setattr(publication, "_close_descriptor", fail_one_sidecar_close)
                if case == "empty":
                    report = publication._publish_staged_v2_filesystem(
                        owner,
                        stage,
                        path,
                        parent_fd=parent_fd,
                        lock_fd=lock_fd,
                        image_kind=active._ProjectionImageKind.NEW,
                        main_binding=main_binding,
                        _factory=publication._PUBLICATION_FACTORY,
                    )
                    assert report.cursor is not None
                    assert path.exists()
                    assert not temp_path.exists()
                    assert all(
                        not Path(f"{temp_path}{suffix}").exists()
                        for suffix in ("-wal", "-shm", "-journal")
                    )
                    assert owner not in callback_values
                    assert stage not in callback_values
                    assert published_seals[0] not in callback_values
                    assert not any(
                        isinstance(value, sqlite3.Connection)
                        for value in callback_values
                    )
                elif case in ("nonempty", "symlink"):
                    with pytest.raises(v2.ProjectionConflict, match="sidecar"):
                        publication._publish_staged_v2_filesystem(
                            owner,
                            stage,
                            path,
                            parent_fd=parent_fd,
                            lock_fd=lock_fd,
                            image_kind=active._ProjectionImageKind.NEW,
                            main_binding=main_binding,
                            _factory=publication._PUBLICATION_FACTORY,
                        )
                    assert not path.exists()
                    assert owner._healthy is True
                    assert (
                        Path(f"{temp_path}-wal").exists()
                        if case == "nonempty"
                        else Path(f"{temp_path}-shm").is_symlink()
                    )
                else:
                    with pytest.raises((OSError, KeyboardInterrupt, BaseExceptionGroup)):
                        publication._publish_staged_v2_filesystem(
                            owner,
                            stage,
                            path,
                            parent_fd=parent_fd,
                            lock_fd=lock_fd,
                            image_kind=active._ProjectionImageKind.NEW,
                            main_binding=main_binding,
                            _factory=publication._PUBLICATION_FACTORY,
                        )
                    assert injected_cleanup_failure is True
                    assert sidecar_artifacts
                    assert all(
                        artifact.descriptor == -1
                        for artifact in sidecar_artifacts
                    )
                    assert owner._healthy is True
        finally:
            for artifact in sidecar_artifacts:
                if artifact.descriptor >= 0:
                    try:
                        publication._close_held(artifact)
                    except BaseException:  # noqa: BLE001,S110 - best-effort test cleanup
                        pass
            _close_namespace(parent_fd, lock_fd)
            _close_owner(owner)


def test_v1_replace_crash_matrix_preserves_prearm_inode_and_latches_postarm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active, v2, publication = _subjects(monkeypatch)

    for case in (
        "connection_swap",
        "initial_main_sidecar",
        "late_main_sidecar",
        "prearm",
        "replace_then_raise",
        "replace_without_mutation",
    ):
        root = tmp_path / case
        root.mkdir(mode=0o700)
        path = root / "projection.sqlite3"
        _v1_image(active, path)
        before = path.stat(follow_symlinks=False)
        before_bytes = path.read_bytes()
        token = uuid.UUID(f"10000000-0000-4000-8000-{len(case):012d}")
        temp_path = root / _temp_name(path, token)
        owner, _live, _store, through = _durable_unpublished_case(
            v2,
            root / "evidence",
        )
        stage = owner._stage_unpublished_prefix(
            through,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        parent_fd, lock_fd, main_binding = _namespace(active, path)
        assert main_binding is not None
        original_prepare = type(owner)._prepare_staged_replay_for_publication
        original_publish = type(owner)._publish_staged_replay
        original_replace = publication.os.replace
        original_connect = publication.sqlite3.connect
        main_sidecar = Path(f"{path}-journal")
        alternate = root / "alternate-v1.sqlite3"
        hidden = root / "held-original.sqlite3"
        immutable_open_targets: list[str] = []
        immutable_open_bindings: list[tuple[int, int]] = []

        if case == "connection_swap":
            alternate.write_bytes(before_bytes)
            alternate.chmod(0o600)

        def connect_substituted_v1(
            database: Any,
            *args: Any,
            **kwargs: Any,
        ) -> sqlite3.Connection:
            if type(database) is not str or not database.startswith("file:///dev/fd/"):
                return original_connect(database, *args, **kwargs)
            raw_path, separator, query = database.partition("?")
            assert separator == "?"
            assert query == "mode=ro&immutable=1"
            descriptor = int(Path(raw_path.removeprefix("file://")).name)
            opened = os.fstat(descriptor)
            immutable_open_targets.append(database)
            immutable_open_bindings.append((opened.st_dev, opened.st_ino))
            os.replace(path, hidden)
            os.replace(alternate, path)
            try:
                result = original_connect(database, *args, **kwargs)
            finally:
                os.replace(path, alternate)
                os.replace(hidden, path)
            return result

        def late_v1_sidecar(
            selected: Any,
            capability: Any,
            seal: Any,
            publisher: Any,
            *,
            _factory: object,
            _fault_phase: Any | None = None,
        ) -> Any:
            main_sidecar.write_bytes(b"late-v1-sidecar")
            main_sidecar.chmod(0o600)
            return original_publish(
                selected,
                capability,
                seal,
                publisher,
                _factory=_factory,
                _fault_phase=_fault_phase,
            )

        def prearm_failure(
            selected: Any,
            capability: Any,
            seal: Any,
            *,
            _factory: object,
        ) -> None:
            original_prepare(selected, capability, seal, _factory=_factory)
            hostile = Path(f"{temp_path}-journal")
            hostile.write_bytes(b"unsafe")
            hostile.chmod(0o600)

        def replace_then_raise(*args: Any, **kwargs: Any) -> None:
            original_replace(*args, **kwargs)
            raise KeyboardInterrupt("replace completed then interrupted")

        def replace_without_mutation(*_args: Any, **_kwargs: Any) -> None:
            raise KeyboardInterrupt("replace interrupted before mutation")

        try:
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(publication.uuid, "uuid4", lambda: token)
                if case == "connection_swap":
                    patch.setattr(
                        publication.sqlite3,
                        "connect",
                        connect_substituted_v1,
                    )
                elif case == "initial_main_sidecar":
                    main_sidecar.write_bytes(b"initial-v1-sidecar")
                    main_sidecar.chmod(0o600)
                elif case == "late_main_sidecar":
                    patch.setattr(type(owner), "_publish_staged_replay", late_v1_sidecar)
                elif case == "prearm":
                    patch.setattr(type(owner), "_prepare_staged_replay_for_publication", prearm_failure)
                if case == "connection_swap":
                    report = publication._publish_staged_v2_filesystem(
                        owner,
                        stage,
                        path,
                        parent_fd=parent_fd,
                        lock_fd=lock_fd,
                        image_kind=active._ProjectionImageKind.V1,
                        main_binding=main_binding,
                        _factory=publication._PUBLICATION_FACTORY,
                    )
                    assert report.cursor is not None
                    assert len(immutable_open_targets) == 1
                    assert immutable_open_bindings == [(before.st_dev, before.st_ino)]
                elif case in (
                    "initial_main_sidecar",
                    "late_main_sidecar",
                    "prearm",
                ):
                    with pytest.raises(v2.ProjectionConflict):
                        publication._publish_staged_v2_filesystem(
                            owner,
                            stage,
                            path,
                            parent_fd=parent_fd,
                            lock_fd=lock_fd,
                            image_kind=active._ProjectionImageKind.V1,
                            main_binding=main_binding,
                            _factory=publication._PUBLICATION_FACTORY,
                        )
                    after = path.stat(follow_symlinks=False)
                    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
                    assert path.read_bytes() == before_bytes
                    assert owner._healthy is True
                elif case == "replace_then_raise":
                    patch.setattr(publication.os, "replace", replace_then_raise)
                    report = publication._publish_staged_v2_filesystem(
                        owner,
                        stage,
                        path,
                        parent_fd=parent_fd,
                        lock_fd=lock_fd,
                        image_kind=active._ProjectionImageKind.V1,
                        main_binding=main_binding,
                        _factory=publication._PUBLICATION_FACTORY,
                    )
                    assert report.cursor is not None
                    assert owner._connection is not None
                    v2._verify_v2_schema(owner._connection)
                else:
                    patch.setattr(publication.os, "replace", replace_without_mutation)
                    with pytest.raises(KeyboardInterrupt, match="before mutation"):
                        publication._publish_staged_v2_filesystem(
                            owner,
                            stage,
                            path,
                            parent_fd=parent_fd,
                            lock_fd=lock_fd,
                            image_kind=active._ProjectionImageKind.V1,
                            main_binding=main_binding,
                            _factory=publication._PUBLICATION_FACTORY,
                        )
                    after = path.stat(follow_symlinks=False)
                    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
                    assert path.read_bytes() == before_bytes
                    assert owner._healthy is False
                    assert temp_path.exists()
        finally:
            _close_namespace(parent_fd, lock_fd)
            _close_owner(owner)


def test_new_link_no_overwrite_and_crash_recovery_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active, v2, publication = _subjects(monkeypatch)

    for case in (
        "link_no_mutation",
        "link_eexist",
        "unlink_failure",
        "success",
        "link_then_raise",
        "raced_final",
    ):
        root = tmp_path / f"publish-{case}"
        root.mkdir(mode=0o700)
        path = root / "projection.sqlite3"
        token = uuid.UUID(f"20000000-0000-4000-8000-{len(case):012d}")
        temp_path = root / _temp_name(path, token)
        owner, _live, _store, through = _durable_unpublished_case(
            v2,
            root / "evidence",
        )
        stage = owner._stage_unpublished_prefix(
            through,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        parent_fd, lock_fd, main_binding = _namespace(active, path)
        original_link = publication.os.link
        original_unlink = publication.os.unlink
        original_publish = type(owner)._publish_staged_replay
        namespace_calls = 0

        def link_then_raise(*args: Any, **kwargs: Any) -> None:
            original_link(*args, **kwargs)
            raise KeyboardInterrupt("link completed then interrupted")

        def link_without_mutation(*_args: Any, **_kwargs: Any) -> None:
            nonlocal namespace_calls
            namespace_calls += 1
            raise OSError("injected link failure before mutation")

        def link_with_eexist(*args: Any, **kwargs: Any) -> None:
            nonlocal namespace_calls
            namespace_calls += 1
            path.write_bytes(b"post-arm-raced-main")
            path.chmod(0o600)
            original_link(*args, **kwargs)

        def fail_temp_unlink(
            name: str,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal namespace_calls
            if name == temp_path.name:
                namespace_calls += 1
                raise OSError("injected temp unlink failure")
            original_unlink(name, dir_fd=dir_fd)

        def race_before_callback(
            selected: Any,
            capability: Any,
            seal: Any,
            publisher: Any,
            *,
            _factory: object,
            _fault_phase: Any | None = None,
        ) -> Any:
            path.write_bytes(b"raced-main")
            path.chmod(0o600)
            return original_publish(
                selected,
                capability,
                seal,
                publisher,
                _factory=_factory,
                _fault_phase=_fault_phase,
            )

        try:
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(publication.uuid, "uuid4", lambda: token)
                if case == "link_no_mutation":
                    patch.setattr(publication.os, "link", link_without_mutation)
                elif case == "link_eexist":
                    patch.setattr(publication.os, "link", link_with_eexist)
                elif case == "unlink_failure":
                    patch.setattr(publication.os, "unlink", fail_temp_unlink)
                elif case == "link_then_raise":
                    patch.setattr(publication.os, "link", link_then_raise)
                elif case == "raced_final":
                    patch.setattr(type(owner), "_publish_staged_replay", race_before_callback)
                if case in ("link_no_mutation", "link_eexist", "unlink_failure"):
                    with pytest.raises((OSError, KeyboardInterrupt, BaseExceptionGroup)):
                        publication._publish_staged_v2_filesystem(
                            owner,
                            stage,
                            path,
                            parent_fd=parent_fd,
                            lock_fd=lock_fd,
                            image_kind=active._ProjectionImageKind.NEW,
                            main_binding=main_binding,
                            _factory=publication._PUBLICATION_FACTORY,
                        )
                    assert namespace_calls == 1
                    assert owner._healthy is False
                    assert temp_path.exists()
                    if case == "link_no_mutation":
                        assert not path.exists()
                    elif case == "link_eexist":
                        assert path.read_bytes() == b"post-arm-raced-main"
                    else:
                        assert path.exists()
                        assert (
                            path.stat(follow_symlinks=False).st_ino
                            == temp_path.stat(follow_symlinks=False).st_ino
                        )
                        assert path.stat(follow_symlinks=False).st_nlink == 2
                elif case == "raced_final":
                    with pytest.raises(v2.ProjectionConflict, match="destination"):
                        publication._publish_staged_v2_filesystem(
                            owner,
                            stage,
                            path,
                            parent_fd=parent_fd,
                            lock_fd=lock_fd,
                            image_kind=active._ProjectionImageKind.NEW,
                            main_binding=main_binding,
                            _factory=publication._PUBLICATION_FACTORY,
                        )
                    assert path.read_bytes() == b"raced-main"
                    assert owner._healthy is True
                else:
                    report = publication._publish_staged_v2_filesystem(
                        owner,
                        stage,
                        path,
                        parent_fd=parent_fd,
                        lock_fd=lock_fd,
                        image_kind=active._ProjectionImageKind.NEW,
                        main_binding=main_binding,
                        _factory=publication._PUBLICATION_FACTORY,
                    )
                    assert report.cursor is not None
                    assert path.stat(follow_symlinks=False).st_nlink == 1
        finally:
            _close_namespace(parent_fd, lock_fd)
            _close_owner(owner)

    for case in (
        "prelink",
        "linked",
        "main_only",
        "raced_main",
        "foreign_hardlink",
        "multiple_temps",
        "linked_sidecar",
    ):
        root = tmp_path / f"recover-{case}"
        root.mkdir(mode=0o700)
        path = root / "projection.sqlite3"
        temp = root / _temp_name(
            path,
            uuid.UUID(f"30000000-0000-4000-8000-{len(case):012d}"),
        )
        temp.write_bytes(b"staged-v2")
        temp.chmod(0o600)
        if case in ("linked", "linked_sidecar"):
            os.link(temp, path)
        elif case == "main_only":
            os.replace(temp, path)
        elif case == "raced_main":
            path.write_bytes(b"raced-main")
            path.chmod(0o600)
        elif case == "foreign_hardlink":
            os.link(temp, root / "foreign")
        elif case == "multiple_temps":
            second = root / _temp_name(
                path,
                uuid.UUID("30000000-0000-4000-8000-999999999999"),
            )
            second.write_bytes(b"other")
            second.chmod(0o600)
        if case == "prelink":
            sidecar = Path(f"{temp}-wal")
            sidecar.write_bytes(b"recoverable")
            sidecar.chmod(0o600)
        elif case == "linked_sidecar":
            sidecar = Path(f"{temp}-shm")
            sidecar.touch(mode=0o600)
            sidecar.chmod(0o600)

        before = {
            candidate.name: hashlib.sha256(candidate.read_bytes()).hexdigest()
            for candidate in root.iterdir()
            if candidate.is_file() and not candidate.name.endswith(".projection.lock")
        }
        parent_fd, lock_fd, _main_binding = _namespace(active, path)
        try:
            if case in ("foreign_hardlink", "multiple_temps", "linked_sidecar"):
                with pytest.raises(v2.ProjectionConflict):
                    publication._recover_v2_publication_locked(
                        path,
                        parent_fd=parent_fd,
                        lock_fd=lock_fd,
                        _factory=publication._PUBLICATION_FACTORY,
                    )
                after = {
                    candidate.name: hashlib.sha256(candidate.read_bytes()).hexdigest()
                    for candidate in root.iterdir()
                    if candidate.is_file()
                    and not candidate.name.endswith(".projection.lock")
                }
                assert after == before
            else:
                publication._recover_v2_publication_locked(
                    path,
                    parent_fd=parent_fd,
                    lock_fd=lock_fd,
                    _factory=publication._PUBLICATION_FACTORY,
                )
                if case == "prelink":
                    assert not temp.exists()
                    assert not Path(f"{temp}-wal").exists()
                    assert not path.exists()
                elif case == "linked":
                    assert not temp.exists()
                    assert path.exists()
                    assert path.stat(follow_symlinks=False).st_nlink == 1
                elif case == "main_only":
                    assert path.read_bytes() == b"staged-v2"
                else:
                    assert path.read_bytes() == b"raced-main"
                    assert not temp.exists()
        finally:
            _close_namespace(parent_fd, lock_fd)

    root = tmp_path / "recover-drain-all"
    root.mkdir(mode=0o700)
    path = root / "projection.sqlite3"
    path.write_bytes(b"raced-main")
    path.chmod(0o600)
    temp = root / _temp_name(
        path,
        uuid.UUID("40000000-0000-4000-8000-000000000001"),
    )
    temp.write_bytes(b"staged-v2")
    temp.chmod(0o600)
    parent_fd, lock_fd, _main_binding = _namespace(active, path)
    original_recovery_namespace = publication._recovery_namespace
    original_open_held = publication._open_held_artifact
    original_close_descriptor = publication._close_descriptor
    captured_namespace: list[Any] = []
    captured_namespace_descriptors: list[tuple[int, int]] = []
    main_artifact: list[Any] = []
    main_descriptors: list[int] = []
    close_attempts: list[int] = []
    injected = False

    def capture_recovery_namespace(*args: Any, **kwargs: Any) -> Any:
        namespace = original_recovery_namespace(*args, **kwargs)
        captured_namespace.append(namespace)
        captured_namespace_descriptors.append(
            (namespace.lock_descriptor, namespace.parent_descriptor)
        )
        return namespace

    def capture_main_artifact(
        parent_descriptor: int,
        name: str,
        *,
        label: str,
        links: frozenset[int],
    ) -> Any:
        artifact = original_open_held(
            parent_descriptor,
            name,
            label=label,
            links=links,
        )
        if name == path.name:
            main_artifact.append(artifact)
            main_descriptors.append(artifact.descriptor)
        return artifact

    def interrupt_main_close(descriptor: int) -> None:
        nonlocal injected
        close_attempts.append(descriptor)
        if (
            main_artifact
            and descriptor == main_descriptors[0]
            and not injected
        ):
            injected = True
            original_close_descriptor(descriptor)
            raise KeyboardInterrupt("injected recovery main close failure")
        original_close_descriptor(descriptor)

    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(publication, "_recovery_namespace", capture_recovery_namespace)
            patch.setattr(publication, "_open_held_artifact", capture_main_artifact)
            patch.setattr(publication, "_close_descriptor", interrupt_main_close)
            with pytest.raises((OSError, KeyboardInterrupt, BaseExceptionGroup)):
                publication._recover_v2_publication_locked(
                    path,
                    parent_fd=parent_fd,
                    lock_fd=lock_fd,
                    _factory=publication._PUBLICATION_FACTORY,
                )
        assert injected is True
        assert captured_namespace
        assert captured_namespace[0].lock_descriptor == -1
        assert captured_namespace[0].parent_descriptor == -1
        assert main_artifact[0].descriptor == -1
        assert all(
            descriptor in close_attempts
            for descriptor in captured_namespace_descriptors[0]
        )
    finally:
        _close_namespace(parent_fd, lock_fd)
