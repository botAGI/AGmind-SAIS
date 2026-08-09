from __future__ import annotations

import importlib
import json
import os
import shutil
import sqlite3
import stat
from pathlib import Path
from typing import Any, cast

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.correlation.primitives import (
    SpecialUseRegistry,
    load_pinned_special_use_registry,
)
from agmind_immune.evidence.segments import EvidenceRef, SegmentStore
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeVerifier,
    PinnedObserverRoot,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.phase5b_helpers import (
    BOOT_A,
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
)


def _projection() -> Any:
    try:
        return importlib.import_module("agmind_immune.evidence.projection")
    except ModuleNotFoundError:
        pytest.fail("projection/rebuild slice is not implemented")


@pytest.fixture(autouse=True)
def _fixed_detector_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: "1" * 64)


def _system(
    path: Path,
) -> tuple[
    AcceptanceCoordinator,
    SegmentStore,
    AckJournal,
    CorrelationRequestJournal,
    SpecialUseRegistry,
]:
    path.parent.mkdir(parents=True, mode=0o700)
    path.parent.chmod(0o700)
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(EnvelopeVerifier(root, chain), store)
    acknowledgements = AckJournal.create_new(store)
    correlation_requests = CorrelationRequestJournal.create_new(store)
    registry = load_pinned_special_use_registry(
        Path(__file__).resolve().parents[2] / "contracts/v1/ipv4-special-use.csv"
    )
    return coordinator, store, acknowledgements, correlation_requests, registry


def _accept(coordinator: AcceptanceCoordinator, value: dict[str, object]) -> EvidenceRef:
    item = decode_events_page(canonical_json(page_value(value))).events[0]
    return coordinator.accept(item)


def _confirm(journal: AckJournal, *refs: EvidenceRef) -> None:
    for ref in refs:
        journal.record_pending(ref)
        journal.record_confirmed(ref)


def _fixture_refs(coordinator: AcceptanceCoordinator) -> list[EvidenceRef]:
    fixture = Path(__file__).with_name("fixtures") / "m1-evidence.jsonl"
    return [
        _accept(coordinator, json.loads(line))
        for line in fixture.read_text(encoding="utf-8").splitlines()
    ]


def test_public_rebuild_projection_persists_completed_pcc_and_requires_fixed_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replay = importlib.import_module("agmind_immune.replay")
    pcc = importlib.import_module("tests.correlation.test_pcc")
    pcc_projection = importlib.import_module("tests.evidence.test_projection_pcc")
    correlation_module = importlib.import_module(
        "agmind_immune.ingest.correlation_journal"
    )
    evidence_dir = tmp_path / "evidence"
    coordinator, proof = pcc._accepted_complete(evidence_dir, ttl_seconds=120)
    store = coordinator.segment_store
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm(acknowledgements, *[record.ref for record in records])
    correlation_requests = correlation_module.CorrelationRequestJournal.create_new(store)
    pcc_projection._complete_journal(correlation_requests, proof)
    correlation_requests.close()
    acknowledgements.close()
    store.close()

    registry = Path(__file__).resolve().parents[2] / "contracts/v1/ipv4-special-use.csv"

    def recovered_verifier() -> EnvelopeVerifier:
        key = private_key(11)
        root = PinnedObserverRoot.from_validated_contract_for_test(
            ObserverTrustRootV1.model_validate(root_value(key))
        )
        return EnvelopeVerifier(
            root,
            AnchoredPublicKeyChain.from_value(root, metadata_value(key)),
        )

    monkeypatch.setattr(replay, "_verifier", recovered_verifier)
    monkeypatch.setattr(
        replay,
        "_DEFAULT_SPECIAL_USE_REGISTRY",
        tmp_path / "missing-fixed-registry.csv",
        raising=False,
    )
    missing_projection = tmp_path / "missing.sqlite3"
    with pytest.raises(FileNotFoundError):
        replay.rebuild_projection(evidence_dir, missing_projection)
    assert not missing_projection.exists()
    assert not any(
        Path(f"{missing_projection}{suffix}").exists()
        for suffix in ("-wal", "-shm", "-journal")
    )

    monkeypatch.setattr(replay, "_DEFAULT_SPECIAL_USE_REGISTRY", registry, raising=False)
    authority = importlib.import_module("agmind_immune.correlation.authority")

    legacy_projection = tmp_path / "legacy.sqlite3"
    projection = _projection()
    with sqlite3.connect(legacy_projection, isolation_level=None) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        projection._create_v1_schema(connection)
    legacy_projection.chmod(0o600)
    legacy_before = legacy_projection.read_bytes()
    legacy_info = legacy_projection.stat()
    legacy_identity = legacy_info.st_dev, legacy_info.st_ino
    detector_calls = 0

    def changing_detector() -> str:
        nonlocal detector_calls
        detector_calls += 1
        return ("1" if detector_calls % 2 else "2") * 64

    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", changing_detector)
    with pytest.raises(projection.ProjectionAuthorityError):
        replay.rebuild_projection(evidence_dir, legacy_projection)
    legacy_after = legacy_projection.stat()
    assert (legacy_after.st_dev, legacy_after.st_ino) == legacy_identity
    assert legacy_projection.read_bytes() == legacy_before
    assert not any(
        Path(f"{legacy_projection}{suffix}").exists()
        for suffix in ("-wal", "-shm", "-journal")
    )
    assert not tuple(tmp_path.glob(f".{legacy_projection.name}.projection.*.tmp*"))

    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: "1" * 64)
    report = replay.rebuild_projection(evidence_dir, tmp_path / "projection.sqlite3")
    assert report.cursor is not None
    assert report.cursor.source_sequence == records[-1].ref.source_sequence
    with sqlite3.connect(tmp_path / "projection.sqlite3") as connection:
        assert connection.execute("SELECT result_kind FROM incidents").fetchall() == [
            ("candidate",)
        ]
        assert connection.execute("SELECT count(*) FROM candidates").fetchone() == (1,)


@pytest.mark.parametrize("recovery", ["apply", "rebuild"])
def test_existing_legal_projection_lag_opens_and_catches_up(
    tmp_path: Path,
    recovery: str,
) -> None:
    projection = _projection()
    coordinator, store, journal, correlation, registry = _system(tmp_path / recovery / "evidence")
    key = private_key(11)
    refs = [
        _accept(coordinator, boot_boundary(key)),
        _accept(
            coordinator,
            envelope_value(
                key,
                sequence=2,
                boot_id=BOOT_A,
                normalized_fields={"kind": "confirmed_after_projection"},
            ),
        ),
    ]
    _confirm(journal, refs[0])
    path = tmp_path / recovery / "projection.sqlite3"
    cache = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    cache.apply(refs[0])
    cache.close()
    _confirm(journal, refs[1])

    reopened = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    if recovery == "apply":
        assert reopened.apply(refs[1]).cursor.source_sequence == 2
    else:
        report = reopened.rebuild()
        assert report.cursor is not None
        assert report.cursor.source_sequence == 2
    reopened.close()
    store.close()


@pytest.mark.parametrize("substitution", ["main", "temp"])
def test_persistent_pre_rename_substitution_never_crosses_replace(
    tmp_path: Path,
    substitution: str,
) -> None:
    projection = _projection()
    coordinator, store, journal, correlation, registry = _system(tmp_path / substitution / "evidence")
    refs = _fixture_refs(coordinator)
    _confirm(journal, *refs)
    path = tmp_path / substitution / "projection.sqlite3"
    baseline = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    baseline.rebuild()
    baseline.close()
    original_main_inode = path.stat().st_ino
    source_bytes = {
        child.relative_to(store.root): child.read_bytes()
        for child in store.root.rglob("*")
        if child.is_file()
    }
    substituted_inode: int | None = None
    fired = False

    def substitute_at_last_pre_rename_seam(step: str) -> None:
        nonlocal fired, substituted_inode
        if step != "old_sidecar_cleanup" or fired:
            return
        fired = True
        if substitution == "main":
            authentic = path.with_name("authentic-main.saved")
            path.rename(authentic)
            shutil.copyfile(authentic, path)
            path.chmod(0o600)
            substituted_inode = path.stat().st_ino
        else:
            temp = next(path.parent.glob(f".{path.name}.projection.*.tmp"))
            authentic = path.with_name("authentic-temp.saved")
            temp.rename(authentic)
            shutil.copyfile(authentic, temp)
            temp.chmod(0o600)
            substituted_inode = temp.stat().st_ino

    cache = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
        step_hook=substitute_at_last_pre_rename_seam,
    )
    with pytest.raises(projection.ProjectionConflict):
        cache.rebuild()
    assert fired is True
    assert substituted_inode is not None
    if substitution == "main":
        assert path.stat().st_ino == substituted_inode
        assert cache._healthy is False
    else:
        assert path.stat().st_ino == original_main_inode
        assert cache.snapshot_hash()
    assert source_bytes == {
        child.relative_to(store.root): child.read_bytes()
        for child in store.root.rglob("*")
        if child.is_file()
    }
    cache.close()
    store.close()


@pytest.mark.parametrize(
    "forgery",
    ["skipped_prefix", "cursor_ref", "duplicate_marker", "reducer_row"],
)
def test_existing_cache_must_match_authenticated_confirmed_prefix(
    tmp_path: Path,
    forgery: str,
) -> None:
    projection = _projection()
    coordinator, store, journal, correlation, registry = _system(tmp_path / forgery / "evidence")
    refs = _fixture_refs(coordinator)
    _confirm(journal, *refs)
    path = tmp_path / forgery / "projection.sqlite3"
    cache = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    cache.rebuild()
    cache.close()
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        if forgery == "skipped_prefix":
            connection.execute(
                "DELETE FROM projection_dedup WHERE event_id=?",
                (refs[0].event_id,),
            )
            connection.execute("DELETE FROM events WHERE event_id=?", (refs[0].event_id,))
        elif forgery == "cursor_ref":
            connection.execute(
                "UPDATE ingest_cursors SET segment_id=?",
                ("00000000-0000-4000-8000-000000000099",),
            )
        elif forgery == "duplicate_marker":
            connection.execute(
                "UPDATE events SET duplicate_of_event_id=NULL WHERE event_id=?",
                (refs[2].event_id,),
            )
        else:
            connection.execute(
                "DELETE FROM network_observations WHERE event_id=?",
                (refs[1].event_id,),
            )
    with pytest.raises(projection.ProjectionConflict):
        projection.ProjectionStore.open(
            path,
            evidence=store,
            acknowledgements=journal,
            correlation_requests=correlation,
            registry=registry,
        )
    store.close()


@pytest.mark.parametrize(
    "namespace_case",
    ["relative", "dangling_sidecar", "live_parent_swap", "parent_swap", "main_swap"],
)
def test_projection_namespace_is_bound_and_no_follow(
    tmp_path: Path,
    namespace_case: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = _projection()
    coordinator, store, journal, correlation, registry = _system(tmp_path / namespace_case / "evidence")
    ref = _accept(coordinator, boot_boundary(private_key(11)))
    _confirm(journal, ref)
    parent = tmp_path / namespace_case
    path = parent / "projection.sqlite3"
    if namespace_case == "relative":
        relative = Path(os.path.relpath(path, Path.cwd()))
        with pytest.raises(projection.ProjectionConflict):
            projection.ProjectionStore.open(
                relative,
                evidence=store,
                acknowledgements=journal,
                correlation_requests=correlation,
                registry=registry,
            )
        store.close()
        return
    if namespace_case == "dangling_sidecar":
        os.symlink(parent / "missing", Path(f"{path}-wal"))
        with pytest.raises(projection.ProjectionConflict):
            projection.ProjectionStore.open(
                path,
                evidence=store,
                acknowledgements=journal,
                correlation_requests=correlation,
                registry=registry,
            )
        store.close()
        return
    if namespace_case == "live_parent_swap":
        cache = projection.ProjectionStore.open(
            path,
            evidence=store,
            acknowledgements=journal,
            correlation_requests=correlation,
            registry=registry,
        )
        moved = parent.with_name(f"{parent.name}-moved")
        parent.rename(moved)
        try:
            with pytest.raises(projection.ProjectionConflict):
                cache.apply(ref)
        finally:
            cache.close()
            moved.rename(parent)
        store.close()
        return
    baseline = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    baseline.rebuild()
    baseline.close()
    original_connect = projection._connect
    moved = parent.with_name(f"{parent.name}-moved")

    def substitute_before_connect(connect_path: Path) -> sqlite3.Connection:
        if connect_path == path:
            if namespace_case == "parent_swap":
                parent.rename(moved)
                parent.mkdir(mode=0o700)
                shutil.copyfile(moved / path.name, path)
                path.chmod(0o600)
            else:
                replacement = parent / "replacement.sqlite3"
                shutil.copyfile(path, replacement)
                replacement.chmod(0o600)
                os.replace(replacement, path)
        return cast(sqlite3.Connection, original_connect(connect_path))

    monkeypatch.setattr(projection, "_connect", substitute_before_connect)
    try:
        with pytest.raises(projection.ProjectionConflict):
            projection.ProjectionStore.open(
                path,
                evidence=store,
                acknowledgements=journal,
                correlation_requests=correlation,
                registry=registry,
            )
    finally:
        if namespace_case == "parent_swap" and moved.exists():
            shutil.rmtree(parent)
            moved.rename(parent)
    store.close()


@pytest.mark.parametrize("confirmed_count", [1, 3])
def test_rebuild_is_capped_by_frozen_ack_authority(
    tmp_path: Path, confirmed_count: int
) -> None:
    projection = _projection()
    coordinator, store, journal, correlation, registry = _system(tmp_path / str(confirmed_count) / "evidence")
    refs = _fixture_refs(coordinator)
    _confirm(journal, *refs[:confirmed_count])
    hook = None
    if confirmed_count == 1:
        journal.record_pending(refs[1])
        fired = False

        def confirm_during_rebuild(step: str) -> None:
            nonlocal fired
            if step == "apply" and not fired:
                fired = True
                journal.record_confirmed(refs[1])

        hook = confirm_during_rebuild
    cache = projection.ProjectionStore.open(
        tmp_path / str(confirmed_count) / "projection.sqlite3",
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
        step_hook=hook,
    )
    report = cache.rebuild()
    assert report.source_record_count == confirmed_count
    assert report.cursor is not None
    assert report.cursor.source_sequence == confirmed_count
    assert (
        store.acceptance_cursor
        >= journal.snapshot().confirmed_through
        >= report.cursor.source_sequence
    )
    if confirmed_count == 1:
        assert journal.snapshot().confirmed_through == 2
    cache.close()
    store.close()


@pytest.mark.parametrize("history", ["two_rebuilds", "delete_rebuild"])
def test_logical_snapshot_hash_ignores_sqlite_history(tmp_path: Path, history: str) -> None:
    projection = _projection()
    coordinator, store, journal, correlation, registry = _system(tmp_path / history / "evidence")
    key = private_key(11)
    refs = [
        _accept(coordinator, boot_boundary(key)),
        _accept(
            coordinator,
            envelope_value(key, sequence=2, boot_id=BOOT_A, normalized_fields={"kind": "two"}),
        ),
    ]
    _confirm(journal, *refs)
    path = tmp_path / history / "projection.sqlite3"
    cache = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    first = cache.rebuild()
    ack_before = journal.snapshot()
    if history == "delete_rebuild":
        cache.close()
        path.unlink()
        cache = projection.ProjectionStore.open(
            path,
            evidence=store,
            acknowledgements=journal,
            correlation_requests=correlation,
            registry=registry,
        )
    second = cache.rebuild()
    assert (second.snapshot_hash, second.table_counts) == (
        first.snapshot_hash,
        first.table_counts,
    )
    assert journal.snapshot() == ack_before
    cache.close()
    store.close()


@pytest.mark.parametrize(
    ("failure_step", "post_rename"),
    [
        ("temp_create", False),
        ("schema", False),
        ("apply", False),
        ("checkpoint", False),
        ("temp_fsync", False),
        ("old_sidecar_cleanup", False),
        ("rename", True),
        ("parent_fsync", True),
        ("reopen_verify", True),
    ],
)
def test_swap_failures_preserve_authority_and_fence_ambiguity(
    tmp_path: Path, failure_step: str, post_rename: bool
) -> None:
    projection = _projection()
    coordinator, store, journal, correlation, registry = _system(tmp_path / failure_step / "evidence")
    ref = _accept(coordinator, boot_boundary(private_key(11)))
    _confirm(journal, ref)
    path = tmp_path / failure_step / "projection.sqlite3"
    baseline = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    baseline.rebuild()
    old_hash = baseline.snapshot_hash()
    source_bytes = {
        child.relative_to(store.root): child.read_bytes()
        for child in store.root.rglob("*")
        if child.is_file()
    }
    baseline.close()
    fired = False

    def hook(step: str) -> None:
        nonlocal fired
        if step == failure_step and not fired:
            fired = True
            raise OSError(f"injected {step}")

    cache = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
        step_hook=hook,
    )
    with pytest.raises(OSError, match="injected"):
        cache.rebuild()
    if post_rename:
        with pytest.raises(projection.ProjectionUnhealthy):
            cache.snapshot_hash()
    else:
        assert cache.snapshot_hash() == old_hash
    assert source_bytes == {
        child.relative_to(store.root): child.read_bytes()
        for child in store.root.rglob("*")
        if child.is_file()
    }
    assert journal.snapshot().healthy is True
    cache.close()
    store.close()


@pytest.mark.parametrize(
    ("operation", "post_rename"),
    [
        ("checkpoint", False),
        ("close", False),
        ("fsync", False),
        ("rename", False),
        ("reopen", True),
        ("verify", True),
        ("pre_rename_reopen", False),
    ],
)
def test_operation_failures_recover_or_latch_without_touching_source(
    tmp_path: Path,
    operation: str,
    post_rename: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = _projection()
    coordinator, store, journal, correlation, registry = _system(tmp_path / operation / "evidence")
    ref = _accept(coordinator, boot_boundary(private_key(11)))
    _confirm(journal, ref)
    path = tmp_path / operation / "projection.sqlite3"
    baseline = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    baseline.rebuild()
    expected_hash = baseline.snapshot_hash()
    baseline.close()
    source_bytes = {
        child.relative_to(store.root): child.read_bytes()
        for child in store.root.rglob("*")
        if child.is_file()
    }
    cache = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    original_connect = projection._connect
    original_verify = projection._verify_schema
    original_fsync = projection.os.fsync
    original_replace = projection.os.replace
    connect_fail = False
    verify_calls = 0
    fsync_fail = False
    replace_fail = False

    class ConnectionProxy:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection
            self.failed = False

        def __getattr__(self, name: str) -> Any:
            return getattr(self.connection, name)

        def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> Any:
            if (
                operation == "checkpoint"
                and "wal_checkpoint" in sql
                and not self.failed
            ):
                self.failed = True
                raise OSError("injected checkpoint")
            return self.connection.execute(sql, parameters)

        def close(self) -> None:
            if operation == "close" and not self.failed:
                self.failed = True
                raise OSError("injected close")
            self.connection.close()

    def connect_fault(connect_path: Path) -> Any:
        nonlocal connect_fail
        if (
            operation in {"reopen", "pre_rename_reopen"}
            and connect_path == path
            and not connect_fail
        ):
            connect_fail = True
            raise OSError("injected reopen")
        connection = original_connect(connect_path)
        return ConnectionProxy(connection) if operation in {"checkpoint", "close"} else connection

    def verify_fault(connection: sqlite3.Connection) -> None:
        nonlocal verify_calls
        verify_calls += 1
        if operation == "verify" and verify_calls == 2:
            raise OSError("injected verify")
        original_verify(connection)

    def fsync_fault(descriptor: int) -> None:
        nonlocal fsync_fail
        if operation == "fsync" and stat.S_ISREG(os.fstat(descriptor).st_mode) and not fsync_fail:
            fsync_fail = True
            raise OSError("injected fsync")
        original_fsync(descriptor)

    def replace_fault(*args: Any, **kwargs: Any) -> None:
        nonlocal replace_fail
        if operation == "rename" and not replace_fail:
            replace_fail = True
            raise OSError("injected rename")
        original_replace(*args, **kwargs)

    if operation in {"checkpoint", "close", "reopen", "pre_rename_reopen"}:
        monkeypatch.setattr(projection, "_connect", connect_fault)
    if operation == "verify":
        monkeypatch.setattr(projection, "_verify_schema", verify_fault)
    if operation == "fsync":
        monkeypatch.setattr(projection.os, "fsync", fsync_fault)
    if operation == "rename":
        monkeypatch.setattr(projection.os, "replace", replace_fault)
    if operation == "pre_rename_reopen":
        fired = False

        def fail_after_old_close(step: str) -> None:
            nonlocal fired
            if step == "old_sidecar_cleanup" and not fired:
                fired = True
                raise OSError("injected primary")

        cache._step_hook = fail_after_old_close
    with pytest.raises(OSError, match="injected"):
        cache.rebuild()
    if post_rename or operation == "pre_rename_reopen":
        assert cache._healthy is False
        with pytest.raises(projection.ProjectionUnhealthy):
            cache.snapshot_hash()
    else:
        assert cache.snapshot_hash() == expected_hash
    assert source_bytes == {
        child.relative_to(store.root): child.read_bytes()
        for child in store.root.rglob("*")
        if child.is_file()
    }
    cache.close()
    store.close()
