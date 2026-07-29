from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.evidence.segments import EvidenceRef, SegmentStore
from agmind_immune.ingest.ack_journal import AckJournal
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


def _system(path: Path) -> tuple[AcceptanceCoordinator, SegmentStore, AckJournal]:
    path.parent.mkdir(parents=True, mode=0o700)
    path.parent.chmod(0o700)
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(EnvelopeVerifier(root, chain), store)
    return coordinator, store, AckJournal.create_new(store)


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


@pytest.mark.parametrize("confirmed_count", [1, 3])
def test_rebuild_is_capped_by_frozen_ack_authority(
    tmp_path: Path, confirmed_count: int
) -> None:
    projection = _projection()
    coordinator, store, journal = _system(tmp_path / str(confirmed_count) / "evidence")
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
    coordinator, store, journal = _system(tmp_path / history / "evidence")
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
        path, evidence=store, acknowledgements=journal
    )
    first = cache.rebuild()
    ack_before = journal.snapshot()
    if history == "delete_rebuild":
        cache.close()
        path.unlink()
        cache = projection.ProjectionStore.open(
            path, evidence=store, acknowledgements=journal
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
    coordinator, store, journal = _system(tmp_path / failure_step / "evidence")
    ref = _accept(coordinator, boot_boundary(private_key(11)))
    _confirm(journal, ref)
    path = tmp_path / failure_step / "projection.sqlite3"
    baseline = projection.ProjectionStore.open(
        path, evidence=store, acknowledgements=journal
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
        path, evidence=store, acknowledgements=journal, step_hook=hook
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
