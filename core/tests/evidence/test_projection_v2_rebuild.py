from __future__ import annotations

# ruff: noqa: B023
import importlib
import os
from pathlib import Path
from typing import Any

import pytest
from agmind_immune.contracts import MAX_UINT64
from agmind_immune.evidence import segments as segments_module
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from tests.evidence import test_projection_pcc as pcc_helpers
from tests.evidence.test_projection_pcc import _durable_unpublished_case
from tests.evidence.test_projection_publication import (
    _close_namespace,
    _close_owner,
    _namespace,
    _subjects,
)
from tests.phase5b_helpers import envelope_value


def _publish_new(
    active: Any,
    v2: Any,
    publication: Any,
    owner: Any,
    path: Path,
    through: Any,
) -> Any:
    parent_fd, lock_fd, main_binding = _namespace(active, path)
    assert main_binding is None
    try:
        stage = owner._stage_unpublished_prefix(
            through,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        return publication._publish_staged_v2_filesystem(
            owner,
            stage,
            path,
            parent_fd=parent_fd,
            lock_fd=lock_fd,
            image_kind=active._ProjectionImageKind.NEW,
            main_binding=None,
            _factory=publication._PUBLICATION_FACTORY,
        )
    finally:
        _close_namespace(parent_fd, lock_fd)


def _live_v2_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Any, Any, Any, Any, Any, Path, Any]:
    active, v2, publication = _subjects(monkeypatch)
    owner, _initial, store, through = _durable_unpublished_case(
        v2,
        tmp_path / "evidence",
    )
    path = tmp_path / "projection.sqlite3"
    report = _publish_new(active, v2, publication, owner, path, through)
    assert report.cursor is not None
    assert report.cursor.source_sequence == through.source_sequence
    assert report.cursor.event_id == through.event_id
    assert report.cursor.content_sha256 == through.content_sha256
    assert owner._generation == 2
    assert owner._connection is not None
    return active, v2, publication, owner, store, path, through


def _live_retention_v2_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    active, v2, publication = _subjects(monkeypatch)
    retention = importlib.import_module("tests.evidence.test_retention")
    key, acceptance, store, coverage = retention._live_store_with_active_routine(
        tmp_path / "evidence"
    )
    journal = CorrelationRequestJournal.create_new(store)
    acknowledgements = store._ack_journal_owner
    assert type(acknowledgements) is AckJournal
    connection = v2._v2_connection_for_test()
    owner = v2._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=pcc_helpers.load_pinned_special_use_registry(
            pcc_helpers._REGISTRY_PATH
        ),
    )
    old_through = tuple(store.iter_authenticated_records())[-1].ref
    path = tmp_path / "projection.sqlite3"
    _publish_new(active, v2, publication, owner, path, old_through)

    selected_snapshot = store._freeze_retention_snapshot(
        retention._proof_clock(),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    decision = retention.select_retention(
        selected_snapshot,
        request_id=retention.REQUEST_ID,
    )
    request = decision.request
    assert request is not None
    retention_journal = retention.retention_module._open_retention_state_journal(
        store
    )
    retention_journal.prepare_publication(decision)
    target_item = retention._item(
        envelope_value(
            key,
            sequence=3,
            event_type="retention_tombstone",
            normalized_fields=request.model_dump(mode="python"),
        )
    )
    target_ref = acceptance.accept(target_item)
    coverage._apply_live_accepted(store, target_ref, None)
    acknowledgements.record_pending(target_ref)
    acknowledgements.record_confirmed(target_ref)
    target = retention.retention_module.RetentionTargetV1(
        sequence=target_item.sequence,
        event_id=target_item.event_id,
        content_sha256=target_item.content_sha256,
    )
    retention_journal.bind_target(target)
    retention_journal.advance_evidence_appended(target)
    final_snapshot = store._freeze_retention_snapshot(
        retention._proof_clock(seconds=1),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    tombstone = store._authenticate_retention_tombstone(
        retention_journal,
        final_snapshot,
        target_ref,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    completion = store._execute_authenticated_retention_unlink(
        tombstone,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    return {
        "active": active,
        "v2": v2,
        "publication": publication,
        "owner": owner,
        "store": store,
        "coverage": coverage,
        "path": path,
        "through": target_ref,
        "completion": completion,
    }


def test_nonempty_v2_rebuild_stage_binds_live_owner_without_early_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active, v2, _publication, owner, _store, path, through = _live_v2_case(
        tmp_path,
        monkeypatch,
    )
    old_connection = owner._connection
    old_authority = owner._authority
    before = path.stat(follow_symlinks=False)
    before_bytes = path.read_bytes()
    try:
        stage = owner._stage_v2_rebuild_prefix(
            through,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        binding = owner._staged_replay
        assert binding is not None
        assert binding.capability is stage
        assert binding.live_connection is old_connection
        assert binding.authority is old_authority
        assert binding.reservation.base_generation == 2
        assert binding.reservation.publish_generation == 3
        assert owner._replay_status_for_test().phase is v2._ReplayPhase.STAGED
        assert owner._connection is old_connection
        assert owner._authority is old_authority
        assert path.read_bytes() == before_bytes
        after = path.stat(follow_symlinks=False)
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
        parent_fd, lock_fd, main_binding = _namespace(active, path)
        assert main_binding is not None
        try:
            with pytest.raises(v2.ProjectionConflict, match="inode was substituted"):
                owner._bind_staged_v2_rebuild_namespace(
                    stage,
                    device=main_binding.device,
                    inode=main_binding.inode + 1,
                    _factory=v2._STAGED_REPLAY_FACTORY,
                )
            assert owner._staged_replay is binding
            assert binding.rebuild is None
            guard = owner._bind_staged_v2_rebuild_namespace(
                stage,
                device=main_binding.device,
                inode=main_binding.inode,
                _factory=v2._STAGED_REPLAY_FACTORY,
            )
        finally:
            _close_namespace(parent_fd, lock_fd)
        assert not hasattr(guard, "connection")
        assert not hasattr(guard, "descriptor")
        assert not hasattr(guard, "snapshot")
        assert not hasattr(guard, "authority")
        with pytest.raises(v2.ProjectionAuthorityError):
            owner._bind_staged_v2_rebuild_namespace(
                stage,
                device=main_binding.device,
                inode=main_binding.inode,
                _factory=v2._STAGED_REPLAY_FACTORY,
            )
    finally:
        binding = owner._staged_replay
        if binding is not None:
            if binding.rebuild is None:
                owner._abort_staged_replay(
                    binding.capability,
                    _factory=v2._STAGED_REPLAY_FACTORY,
                )
            else:
                owner._rebase_failed_staged_v2_rebuild(
                    binding.capability,
                    binding.rebuild.guard,
                    primary=RuntimeError("test teardown fallback"),
                    _factory=v2._STAGED_REPLAY_FACTORY,
                )
        _close_owner(owner)

    for case in ("max_generation", "corrupt_base", "cross_owner"):
        root = tmp_path / case
        root.mkdir(mode=0o700)
        active, v2, _publication, owner, _store, path, through = _live_v2_case(
            root,
            monkeypatch,
        )
        other_owner = None
        try:
            if case == "max_generation":
                owner._generation = MAX_UINT64
                before_names = tuple(sorted(os.listdir(root)))
                with pytest.raises(v2.ProjectionAuthorityError, match="exhausted"):
                    owner._stage_v2_rebuild_prefix(
                        through,
                        _factory=v2._STAGED_REPLAY_FACTORY,
                    )
                assert owner._staged_replay is None
                assert owner._replay_status_for_test().reservation_present is False
                assert tuple(sorted(os.listdir(root))) == before_names
                owner._generation = 2
            elif case == "corrupt_base":
                assert owner._connection is not None
                owner._connection.execute("DELETE FROM ingest_cursors")
                with pytest.raises(v2.ProjectionConflict):
                    owner._stage_v2_rebuild_prefix(
                        through,
                        _factory=v2._STAGED_REPLAY_FACTORY,
                    )
                assert owner._staged_replay is None
                assert owner._replay_status_for_test().reservation_present is False
            else:
                stage = owner._stage_v2_rebuild_prefix(
                    through,
                    _factory=v2._STAGED_REPLAY_FACTORY,
                )
                second_root = root / "other"
                second_root.mkdir(mode=0o700)
                (
                    _other_active,
                    _other_v2,
                    _other_publication,
                    other_owner,
                    _other_store,
                    _other_path,
                    _other_through,
                ) = _live_v2_case(second_root, monkeypatch)
                with pytest.raises(v2.ProjectionAuthorityError):
                    other_owner._bind_staged_v2_rebuild_namespace(
                        stage,
                        device=path.stat().st_dev,
                        inode=path.stat().st_ino,
                        _factory=v2._STAGED_REPLAY_FACTORY,
                    )
        finally:
            binding = owner._staged_replay
            if binding is not None:
                owner._abort_staged_replay(
                    binding.capability,
                    _factory=v2._STAGED_REPLAY_FACTORY,
                )
            _close_owner(owner)
            if other_owner is not None:
                _close_owner(other_owner)


def test_v2_rebuild_prearm_failure_rebases_exact_old_inode_and_fresh_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for failure in (
        "temp",
        "materialize",
        "checkpoint",
        "prepublish",
        "suspended_reopen",
    ):
        root = tmp_path / failure
        root.mkdir(mode=0o700)
        active, v2, publication, owner, _store, path, through = _live_v2_case(
            root,
            monkeypatch,
        )
        authority_module = importlib.import_module(
            "agmind_immune.correlation.authority"
        )
        old_authority = owner._authority
        old_connection = owner._connection
        old_binding = path.stat(follow_symlinks=False)
        old_hash = owner.snapshot_hash()
        old_cursor = owner.status().cursor
        assert old_cursor is not None
        parent_fd, lock_fd, main_binding = _namespace(active, path)
        assert main_binding is not None
        stage = owner._stage_v2_rebuild_prefix(
            through,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        fault_phase = None

        def fail_temp(*_args: Any, **_kwargs: Any) -> Any:
            raise KeyboardInterrupt("pre-arm temp")

        original_fsync_parent = publication._fsync_parent
        fsync_calls = 0

        def fail_prepublish_once(namespace: Any) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 1:
                raise KeyboardInterrupt("pre-arm prepublish")
            original_fsync_parent(namespace)

        try:
            with pytest.MonkeyPatch.context() as patch:
                if failure == "temp":
                    patch.setattr(publication, "_create_temp", fail_temp)
                elif failure == "materialize":
                    fault_phase = v2._ReplayFaultPhase.REBUILD_MATERIALIZE
                elif failure == "checkpoint":
                    fault_phase = v2._ReplayFaultPhase.REBUILD_STAGED_CHECKPOINT
                elif failure == "prepublish":
                    patch.setattr(
                        publication,
                        "_fsync_parent",
                        fail_prepublish_once,
                    )
                else:
                    fault_phase = v2._ReplayFaultPhase.PRE_COMMIT
                with pytest.raises(
                    KeyboardInterrupt,
                    match="pre-arm|materialization|checkpoint|pre-commit",
                ):
                    publication._publish_staged_v2_rebuild_filesystem(
                        owner,
                        stage,
                        path,
                        parent_fd=parent_fd,
                        lock_fd=lock_fd,
                        main_binding=main_binding,
                        _factory=publication._PUBLICATION_FACTORY,
                        _fault_phase=fault_phase,
                    )
            after = path.stat(follow_symlinks=False)
            assert (after.st_dev, after.st_ino) == (
                old_binding.st_dev,
                old_binding.st_ino,
            )
            assert owner._healthy is True
            assert owner._generation == 3
            if failure == "suspended_reopen":
                assert owner._connection is not old_connection
            else:
                assert owner._connection is old_connection
            assert owner._authority is not old_authority
            assert owner.snapshot_hash() == old_hash
            status = owner._replay_status_for_test()
            assert status.phase is v2._ReplayPhase.FAILED
            assert status.generation == 3
            assert status.reservation_present is False
            with pytest.raises(v2.CorrelationProjectionError):
                v2._validate_correlation_projection_predecessor(
                    old_authority,
                    v2._predecessor_v2(2, old_cursor),
                )
            fresh_authority = owner._authority
            assert fresh_authority is not None
            fresh_binding = authority_module._authority_binding(fresh_authority)
            with authority_module._ISSUED_AUTHORITIES_LOCK:
                live_for_store = [
                    registered
                    for reference, registered in authority_module._ISSUED_AUTHORITIES.values()
                    if reference() is not None
                    and registered.store is fresh_binding.store
                    and registered.store_lifecycle is fresh_binding.store_lifecycle
                    and not registered.closed
                ]
            assert live_for_store == [fresh_binding]
            v2._validate_correlation_projection_predecessor(
                fresh_authority,
                v2._predecessor_v2(3, old_cursor),
            )

            retry = owner._stage_v2_rebuild_prefix(
                through,
                _factory=v2._STAGED_REPLAY_FACTORY,
            )
            retry_report = publication._publish_staged_v2_rebuild_filesystem(
                owner,
                retry,
                path,
                parent_fd=parent_fd,
                lock_fd=lock_fd,
                main_binding=active._binding(path.stat(follow_symlinks=False)),
                _factory=publication._PUBLICATION_FACTORY,
            )
            assert retry_report.cursor is not None
            assert owner._generation == 4
            assert owner._replay_status_for_test().phase is v2._ReplayPhase.PUBLISHED
        finally:
            _close_namespace(parent_fd, lock_fd)
            binding = owner._staged_replay
            if binding is not None:
                owner._abort_staged_replay(
                    binding.capability,
                    _factory=v2._STAGED_REPLAY_FACTORY,
                )
            _close_owner(owner)


def test_v2_rebuild_suspend_replace_crash_matrix_fails_conservatively(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for failure in (
        "staged_close_ambiguous",
        "close_ambiguous",
        "old_journal",
        "old_wal",
        "old_shm",
        "old_hardlink",
        "replace_no_mutation",
        "replace_then_raise",
        "parent_fsync",
        "reopen",
    ):
        root = tmp_path / failure
        root.mkdir(mode=0o700)
        active, v2, publication, owner, _store, path, through = _live_v2_case(
            root,
            monkeypatch,
        )
        old_binding = path.stat(follow_symlinks=False)
        old_descriptor = os.open(path, os.O_RDONLY)
        parent_fd, lock_fd, main_binding = _namespace(active, path)
        assert main_binding is not None
        stage = owner._stage_v2_rebuild_prefix(
            through,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        original_replace = publication.os.replace
        original_prepublish = publication._prepublish_validate_v2_rebuild
        original_fsync_parent = publication._fsync_parent
        original_open = publication._open_existing_sqlite
        suspended_observations: list[tuple[Any, Any]] = []
        sidecar_suffix = {
            "old_journal": "-journal",
            "old_wal": "-wal",
            "old_shm": "-shm",
        }.get(failure, "-journal")
        sidecar = Path(f"{path}{sidecar_suffix}")
        hardlink = root / "old-hardlink.sqlite3"
        fsync_calls = 0

        def observe_suspended(state: Any) -> None:
            status = owner._replay_status_for_test()
            suspended_observations.append((status.phase, owner._connection))
            if failure in ("old_journal", "old_wal", "old_shm"):
                sidecar.write_bytes(b"ambiguous-old-sidecar")
                sidecar.chmod(0o600)
            elif failure == "old_hardlink":
                os.link(path, hardlink)
            original_prepublish(state)

        def replace_no_mutation(*_args: Any, **_kwargs: Any) -> None:
            raise KeyboardInterrupt("replace no mutation")

        def replace_then_raise(*args: Any, **kwargs: Any) -> None:
            original_replace(*args, **kwargs)
            raise KeyboardInterrupt("replace mutated then raised")

        def fail_parent_fsync(namespace: Any) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 2:
                raise KeyboardInterrupt("parent fsync after replace")
            original_fsync_parent(namespace)

        def fail_reopen(
            selected: Path,
            *,
            configure_v2: bool,
        ) -> Any:
            if configure_v2 and selected == path:
                raise KeyboardInterrupt("reopen after replace")
            return original_open(selected, configure_v2=configure_v2)

        fault_phase = (
            v2._ReplayFaultPhase.REBUILD_STAGED_CLOSE
            if failure == "staged_close_ambiguous"
            else (
                v2._ReplayFaultPhase.REBUILD_CLOSE
                if failure == "close_ambiguous"
                else None
            )
        )
        try:
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(
                    publication,
                    "_prepublish_validate_v2_rebuild",
                    observe_suspended,
                )
                if failure == "replace_no_mutation":
                    patch.setattr(publication.os, "replace", replace_no_mutation)
                elif failure == "replace_then_raise":
                    patch.setattr(publication.os, "replace", replace_then_raise)
                elif failure == "parent_fsync":
                    patch.setattr(publication, "_fsync_parent", fail_parent_fsync)
                elif failure == "reopen":
                    patch.setattr(publication, "_open_existing_sqlite", fail_reopen)
                with pytest.raises(
                    (KeyboardInterrupt, v2.ProjectionConflict),
                ):
                    publication._publish_staged_v2_rebuild_filesystem(
                        owner,
                        stage,
                        path,
                        parent_fd=parent_fd,
                        lock_fd=lock_fd,
                        main_binding=main_binding,
                        _factory=publication._PUBLICATION_FACTORY,
                        _fault_phase=fault_phase,
                    )
            assert owner._healthy is False
            assert owner._authority is None
            assert owner._replay_status_for_test().reservation_present is False
            assert owner.status().healthy is False
            if failure in ("staged_close_ambiguous", "close_ambiguous"):
                assert suspended_observations == []
            else:
                assert suspended_observations == [
                    (v2._ReplayPhase.SUSPENDED, None)
                ]
            if failure == "old_hardlink":
                assert os.fstat(old_descriptor).st_nlink == 2
                hardlink.unlink()
            old_links = os.fstat(old_descriptor).st_nlink
            current = path.stat(follow_symlinks=False)
            if failure in ("replace_then_raise", "parent_fsync", "reopen"):
                assert old_links == 0
                assert (current.st_dev, current.st_ino) != (
                    old_binding.st_dev,
                    old_binding.st_ino,
                )
            else:
                assert old_links == 1
                assert (current.st_dev, current.st_ino) == (
                    old_binding.st_dev,
                    old_binding.st_ino,
                )
            assert current.st_nlink == 1
        finally:
            sidecar.unlink(missing_ok=True)
            hardlink.unlink(missing_ok=True)
            os.close(old_descriptor)
            _close_namespace(parent_fd, lock_fd)
            _close_owner(owner)


def test_v2_rebuild_success_adopts_reopened_g_plus_one_and_consumes_retention_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tampered_root = tmp_path / "tampered"
    tampered_root.mkdir(mode=0o700)
    tampered = _live_retention_v2_case(tampered_root, monkeypatch)
    tampered_owner = tampered["owner"]
    tampered_store = tampered["store"]
    try:
        assert tampered_owner._connection is not None
        tampered_owner._connection.execute(
            "UPDATE projection_dedup SET logical_key_sha256=? "
            "WHERE event_id=(SELECT event_id FROM events "
            "ORDER BY source_sequence LIMIT 1)",
            ("0" * 64,),
        )
        with pytest.raises(tampered["v2"].ProjectionConflict):
            tampered_owner._stage_v2_rebuild_prefix(
                tampered["through"],
                retention_completion=tampered["completion"],
                _factory=tampered["v2"]._STAGED_REPLAY_FACTORY,
            )
        assert tampered_owner._staged_replay is None
        assert tampered_store._authenticated_retention_replay_scope is None
        assert tampered_store._authenticated_retention_replay_consumed is None
        tampered_store._finalize_authenticated_retention_completion(
            tampered["completion"],
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
    finally:
        tampered["coverage"].close()
        _close_owner(tampered_owner)

    success_root = tmp_path / "fallback-success"
    success_root.mkdir(mode=0o700)
    case = _live_retention_v2_case(success_root, monkeypatch)
    active = case["active"]
    v2 = case["v2"]
    publication = case["publication"]
    owner = case["owner"]
    store = case["store"]
    path = case["path"]
    through = case["through"]
    completion = case["completion"]
    old_connection = owner._connection
    old_authority = owner._authority
    old_cursor = owner.status().cursor
    assert old_cursor is not None
    old_binding = path.stat(follow_symlinks=False)
    old_descriptor = os.open(path, os.O_RDONLY)
    parent_fd, lock_fd, main_binding = _namespace(active, path)
    assert main_binding is not None
    try:
        stage = owner._stage_v2_rebuild_prefix(
            through,
            retention_completion=completion,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        with pytest.raises(KeyboardInterrupt, match="pre-arm"):
            publication._publish_staged_v2_rebuild_filesystem(
                owner,
                stage,
                path,
                parent_fd=parent_fd,
                lock_fd=lock_fd,
                main_binding=main_binding,
                _factory=publication._PUBLICATION_FACTORY,
                _fault_phase=v2._ReplayFaultPhase.PRE_COMMIT,
            )
        assert owner._healthy is True
        assert owner._generation == 3
        assert owner._connection is not old_connection
        assert owner._replay_status_for_test().phase is v2._ReplayPhase.FAILED
        assert store._authenticated_retention_replay_scope is None
        assert store._authenticated_retention_replay_consumed is None
        assert os.fstat(old_descriptor).st_nlink == 1
        with pytest.raises(v2.CorrelationProjectionError):
            v2._validate_correlation_projection_predecessor(
                old_authority,
                v2._predecessor_v2(2, old_cursor),
            )
        fallback_authority = owner._authority
        assert fallback_authority is not None
        v2._validate_correlation_projection_predecessor(
            fallback_authority,
            v2._predecessor_v2(3, old_cursor),
        )

        final_edge_phases: list[Any] = []
        original_consume = (
            type(store)._commit_prevalidated_retention_replay_consumption_locked
        )

        def observe_consumption(selected_store: Any, consumed: Any) -> None:
            if selected_store is store:
                final_edge_phases.append(owner._replay_status.phase)
            original_consume(selected_store, consumed)

        retry = owner._stage_v2_rebuild_prefix(
            through,
            retention_completion=completion,
            _factory=v2._STAGED_REPLAY_FACTORY,
        )
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(
                type(store),
                "_commit_prevalidated_retention_replay_consumption_locked",
                observe_consumption,
            )
            report = publication._publish_staged_v2_rebuild_filesystem(
                owner,
                retry,
                path,
                parent_fd=parent_fd,
                lock_fd=lock_fd,
                main_binding=active._binding(path.stat(follow_symlinks=False)),
                _factory=publication._PUBLICATION_FACTORY,
            )
        new_binding = path.stat(follow_symlinks=False)
        assert report.cursor is not None
        assert report.cursor.source_sequence == through.source_sequence
        assert (new_binding.st_dev, new_binding.st_ino) != (
            old_binding.st_dev,
            old_binding.st_ino,
        )
        assert owner._generation == 4
        assert owner._authority is not fallback_authority
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == through.source_sequence
        assert owner._replay_status_for_test().phase is v2._ReplayPhase.PUBLISHED
        assert final_edge_phases == [v2._ReplayPhase.SUSPENDED]
        assert owner._replay_status_for_test().reservation_present is False
        assert store._authenticated_retention_replay_scope is None
        assert store._authenticated_retention_replay_consumed is not None
        assert os.fstat(old_descriptor).st_nlink == 0
        assert new_binding.st_nlink == 1
        assert owner._authority is not None
        with pytest.raises(v2.CorrelationProjectionError):
            v2._validate_correlation_projection_predecessor(
                fallback_authority,
                v2._predecessor_v2(3, old_cursor),
            )
        authority_module = importlib.import_module(
            "agmind_immune.correlation.authority"
        )
        final_authority = owner._authority
        final_authority_binding = authority_module._authority_binding(
            final_authority
        )
        with authority_module._ISSUED_AUTHORITIES_LOCK:
            live_for_store = [
                registered
                for reference, registered in authority_module._ISSUED_AUTHORITIES.values()
                if reference() is not None
                and registered.store is final_authority_binding.store
                and registered.store_lifecycle
                is final_authority_binding.store_lifecycle
                and not registered.closed
            ]
        assert live_for_store == [final_authority_binding]
        with pytest.raises(v2.ProjectionAuthorityError):
            owner._stage_v2_rebuild_prefix(
                through,
                retention_completion=completion,
                _factory=v2._STAGED_REPLAY_FACTORY,
            )
        store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        assert store._authenticated_retention_replay_consumed is None
    finally:
        os.close(old_descriptor)
        _close_namespace(parent_fd, lock_fd)
        case["coverage"].close()
        _close_owner(owner)
