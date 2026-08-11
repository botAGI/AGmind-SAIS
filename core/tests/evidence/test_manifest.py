from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import agmind_immune.evidence.segments as segments_module
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.evidence.frames import decode_frames, encode_frame
from agmind_immune.evidence.manifest import (
    SegmentManifestV1,
    chain_head_for,
    segment_manifest_hash,
)
from agmind_immune.evidence.segments import (
    EvidenceCorrupt,
    EvidenceReadOnly,
    EvidenceStoreError,
    SegmentStore,
    TornTailRepairRequired,
)
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    CoreEventV1,
    EnvelopeConflict,
    EnvelopeVerifier,
    PinnedObserverRoot,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from pydantic import ValidationError
from tests.phase5b_helpers import (
    BOOT_A,
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
)


def _tree_snapshot(path: Path) -> dict[str, tuple[str, int, bytes]]:
    snapshot: dict[str, tuple[str, int, bytes]] = {}
    for entry in sorted(path.rglob("*")):
        relative = entry.relative_to(path).as_posix()
        info = entry.lstat()
        if entry.is_dir():
            snapshot[relative] = ("directory", stat.S_IMODE(info.st_mode), b"")
        else:
            snapshot[relative] = (
                "file",
                stat.S_IMODE(info.st_mode),
                entry.read_bytes(),
            )
    return snapshot


def _one_record_store(path: Path, *, flush: bool) -> SegmentStore:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    item = decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    coordinator.accept(item)
    if flush:
        store.flush_security_boundary()
    return store


def _store_with_prior_head_and_active_record(
    path: Path,
) -> tuple[AcceptanceCoordinator, SegmentStore, bytes, CoreEventV1]:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    coordinator.accept(decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0])
    store.flush_security_boundary()
    prior_head = (path / "chain-head.json").read_bytes()
    coordinator.accept(
        decode_events_page(
            canonical_json(
                page_value(
                    envelope_value(
                        key,
                        sequence=2,
                        boot_id=BOOT_A,
                        normalized_fields={"kind": "second"},
                    )
                )
            )
        ).events[0]
    )
    later = decode_events_page(
        canonical_json(
            page_value(
                envelope_value(
                    key,
                    sequence=3,
                    boot_id=BOOT_A,
                    normalized_fields={"kind": "third"},
                )
            )
        )
    ).events[0]
    return coordinator, store, prior_head, later


@pytest.mark.parametrize("window", ["manifest_open", "promoted_head", "missing_head"])
def test_documented_publication_windows_reconcile(tmp_path: Path, window: str) -> None:
    path = tmp_path / "evidence"
    store = _one_record_store(path, flush=True)
    manifest = store.manifests[0]
    closed = path / manifest.segment_relative_path
    opened = closed.with_suffix(".open")
    store.close()
    if window == "manifest_open":
        os.rename(closed, opened)
        (path / "chain-head.json").unlink()
    elif window == "promoted_head":
        (path / "chain-head.json").write_text(
            json.dumps(
                {
                    "schema_version": "agmind.segment-chain-head.v1",
                    "head_segment_id": "00000000-0000-4000-8000-000000000000",
                    "head_manifest_sha256": "0" * 64,
                    "last_event_id": "evt_" + "0" * 64,
                    "last_source_sequence": 0,
                }
            ),
            encoding="utf-8",
        )
    else:
        (path / "chain-head.json").unlink()

    if window == "promoted_head":
        with pytest.raises(EvidenceCorrupt):
            SegmentStore(path)
        return
    recovered = SegmentStore(path)
    assert closed.exists()
    assert not opened.exists()
    assert recovered.chain_head is not None
    assert recovered.chain_head.head_manifest_sha256 == manifest.manifest_sha256
    recovered.close()


def test_active_torn_tail_is_typed_and_never_truncated(tmp_path: Path) -> None:
    path = tmp_path / "evidence"
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    first = decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    coordinator.accept(first)
    store.flush_security_boundary()
    second = decode_events_page(
        canonical_json(
            page_value(
                envelope_value(
                    key,
                    sequence=2,
                    boot_id=BOOT_A,
                    normalized_fields={"kind": "second"},
                )
            )
        )
    ).events[0]
    coordinator.accept(second)
    opened = store.active_path
    assert opened is not None
    store.close(flush=False)
    with opened.open("ab") as handle:
        handle.write(b"AG")
        handle.flush()
        os.fsync(handle.fileno())
    (path / "chain-head.json").unlink()
    before = _tree_snapshot(path)
    with pytest.raises(TornTailRepairRequired) as captured:
        SegmentStore(path)
    assert captured.value.verified_bytes < len(opened.read_bytes())
    assert _tree_snapshot(path) == before


def test_zero_byte_open_is_corruption_and_never_deleted(tmp_path: Path) -> None:
    path = tmp_path / "zero-open"
    store = SegmentStore(path)
    store.close()
    date_path = path / "segments" / "2026-07-28"
    date_path.mkdir(mode=0o700)
    empty_open = date_path / "00000000000000000001-00000000-0000-4000-8000-000000000001.open"
    empty_open.touch(mode=0o600)
    before = empty_open.stat()
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(path)
    after = empty_open.stat()
    assert empty_open.read_bytes() == b""
    assert (after.st_dev, after.st_ino, after.st_mode) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    )


@pytest.mark.parametrize("missing_child", ["segments", "manifests"])
def test_fenced_root_missing_managed_child_is_never_bootstrapped(
    tmp_path: Path,
    missing_child: str,
) -> None:
    path = tmp_path / missing_child
    path.mkdir(mode=0o700)
    health = path / "health.json"
    health.write_bytes(
        canonical_json(
            {
                "schema_version": "agmind.evidence-health.v1",
                "mode": "read_only",
                "reason": "segment_corrupt",
            }
        )
    )
    health.chmod(0o600)
    present_child = "manifests" if missing_child == "segments" else "segments"
    (path / present_child).mkdir(mode=0o700)
    before = _tree_snapshot(path)
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(path)
    assert _tree_snapshot(path) == before


def test_closed_complete_frame_corruption_persists_read_only(tmp_path: Path) -> None:
    path = tmp_path / "evidence"
    store = _one_record_store(path, flush=True)
    closed = path / store.manifests[0].segment_relative_path
    store.close()
    raw = bytearray(closed.read_bytes())
    raw[len(raw) // 2] ^= 1
    closed.write_bytes(raw)
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(path)
    marker = json.loads((path / "health.json").read_text(encoding="utf-8"))
    assert marker == {
        "schema_version": "agmind.evidence-health.v1",
        "mode": "read_only",
        "reason": "segment_corrupt",
    }


def test_health_fence_makes_startup_recovery_plan_nonmutating(
    tmp_path: Path,
) -> None:
    path = tmp_path / "evidence"
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    item = decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    coordinator.accept(item)
    store.flush_security_boundary()
    manifest = store.manifests[0]
    conflict = decode_events_page(
        canonical_json(
            page_value(
                envelope_value(
                    key,
                    sequence=1,
                    boot_id=BOOT_A,
                    normalized_fields={"kind": "conflict"},
                )
            )
        )
    ).events[0]
    with pytest.raises(EnvelopeConflict):
        coordinator.accept(conflict)
    store.close(flush=False)

    closed = path / manifest.segment_relative_path
    opened = closed.with_suffix(".open")
    os.rename(closed, opened)
    (path / "chain-head.json").unlink()
    before = _tree_snapshot(path)
    fenced = SegmentStore(path)
    assert fenced.read_only_reason == "evidence_conflict"
    assert _tree_snapshot(path) == before
    fenced.close(flush=False)


def test_deep_chain_head_rollback_is_persistent_corruption(
    tmp_path: Path,
) -> None:
    path = tmp_path / "evidence"
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    coordinator.accept(decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0])
    store.flush_security_boundary()
    for sequence in (2, 3):
        coordinator.accept(
            decode_events_page(
                canonical_json(
                    page_value(
                        envelope_value(
                            key,
                            sequence=sequence,
                            boot_id=BOOT_A,
                            normalized_fields={"kind": f"event-{sequence}"},
                        )
                    )
                )
            ).events[0]
        )
        store.flush_security_boundary()
    manifests = store.manifests
    assert len(manifests) == 3
    store.close()

    head_path = path / "chain-head.json"
    rolled_back = canonical_json(chain_head_for(manifests[0]))
    head_path.write_bytes(rolled_back)
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(path)
    assert head_path.read_bytes() == rolled_back
    assert json.loads((path / "health.json").read_bytes())["reason"] == "segment_corrupt"


@pytest.mark.parametrize("target_kind", ["manifest", "segment"])
def test_no_replace_publication_never_overwrites_racing_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_kind: str,
) -> None:
    path = tmp_path / target_kind
    store = _one_record_store(path, flush=False)
    active = store.active_path
    assert active is not None
    immutable_race = b"preexisting-race-target"
    rename_noreplace = segments_module._rename_noreplace
    inserted: tuple[int, str] | None = None

    def inject_target(
        source_name: str,
        destination_name: str,
        *,
        source_dir_fd: int,
        destination_dir_fd: int,
    ) -> None:
        nonlocal inserted
        is_manifest = destination_name.endswith(".json") and destination_name not in {
            "chain-head.json",
            "health.intent.json",
            "health.json",
        }
        should_insert = (target_kind == "manifest" and is_manifest) or (
            target_kind == "segment" and destination_name.endswith(".agseg")
        )
        if should_insert and inserted is None:
            descriptor = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=destination_dir_fd,
            )
            try:
                os.write(descriptor, immutable_race)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            inserted = (destination_dir_fd, destination_name)
        rename_noreplace(
            source_name,
            destination_name,
            source_dir_fd=source_dir_fd,
            destination_dir_fd=destination_dir_fd,
        )

    monkeypatch.setattr(segments_module, "_rename_noreplace", inject_target)
    with pytest.raises(EvidenceCorrupt):
        store.flush_security_boundary()
    assert inserted is not None
    inserted_fd, inserted_name = inserted
    descriptor = os.open(inserted_name, os.O_RDONLY, dir_fd=inserted_fd)
    try:
        assert os.read(descriptor, len(immutable_race) + 1) == immutable_race
    finally:
        os.close(descriptor)
    store.close(flush=False)


@pytest.mark.parametrize("publication", ["manifest", "segment"])
def test_atomic_no_replace_unavailable_changes_no_source_or_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
) -> None:
    path = tmp_path / publication
    store = _one_record_store(path, flush=False)
    source = store.active_path
    assert source is not None
    source_before = source.stat()
    source_bytes = source.read_bytes()
    segment_id = source.stem.split("-", 1)[1]
    destination = (
        path / "manifests" / f"{segment_id}.json"
        if publication == "manifest"
        else source.with_suffix(".agseg")
    )
    rename_noreplace = segments_module._rename_noreplace
    actual_platform = segments_module.sys.platform

    def force_unavailable(
        source_name: str,
        destination_name: str,
        *,
        source_dir_fd: int,
        destination_dir_fd: int,
    ) -> None:
        is_manifest = destination_name == f"{segment_id}.json" and publication == "manifest"
        is_segment = destination_name.endswith(".agseg") and publication == "segment"
        if not (is_manifest or is_segment):
            rename_noreplace(
                source_name,
                destination_name,
                source_dir_fd=source_dir_fd,
                destination_dir_fd=destination_dir_fd,
            )
            return
        segments_module.sys.platform = "atomic-no-replace-unavailable"
        try:
            rename_noreplace(
                source_name,
                destination_name,
                source_dir_fd=source_dir_fd,
                destination_dir_fd=destination_dir_fd,
            )
        finally:
            segments_module.sys.platform = actual_platform

    monkeypatch.setattr(segments_module, "_rename_noreplace", force_unavailable)
    with pytest.raises(EvidenceStoreError):
        store.flush_security_boundary()
    source_after = source.stat()
    assert source.read_bytes() == source_bytes
    assert (source_after.st_dev, source_after.st_ino) == (
        source_before.st_dev,
        source_before.st_ino,
    )
    assert not destination.exists()
    assert not (path / "chain-head.json").exists()
    store.close(flush=False)


@pytest.mark.parametrize(
    ("publication", "attack"),
    [
        ("recovery", "path_swap"),
        ("runtime", "path_swap"),
        ("runtime", "in_place"),
    ],
)
def test_post_scan_source_mutation_is_rejected_before_chain_head_advances(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
    attack: str,
) -> None:
    path = tmp_path / publication
    store = _one_record_store(path, flush=publication == "recovery")
    if publication == "recovery":
        manifest = store.manifests[0]
        closed = path / manifest.segment_relative_path
        source = closed.with_suffix(".open")
        store.close()
        os.rename(closed, source)
        (path / "chain-head.json").unlink()
    else:
        source = store.active_path
        assert source is not None
    replacement = b"X" * len(source.read_bytes())
    rename_noreplace = segments_module._rename_noreplace
    attacked = False

    def mutate_after_scan(
        source_name: str,
        destination_name: str,
        *,
        source_dir_fd: int,
        destination_dir_fd: int,
    ) -> None:
        nonlocal attacked
        if source_name == source.name and destination_name.endswith(".agseg"):
            if attack == "path_swap":
                authenticated_name = f"{source_name}.authenticated"
                os.rename(
                    source_name,
                    authenticated_name,
                    src_dir_fd=source_dir_fd,
                    dst_dir_fd=source_dir_fd,
                )
                descriptor = os.open(
                    source_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=source_dir_fd,
                )
            else:
                descriptor = os.open(
                    source_name,
                    os.O_WRONLY,
                    dir_fd=source_dir_fd,
                )
            try:
                os.pwrite(descriptor, replacement, 0)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            attacked = True
        rename_noreplace(
            source_name,
            destination_name,
            source_dir_fd=source_dir_fd,
            destination_dir_fd=destination_dir_fd,
        )

    monkeypatch.setattr(segments_module, "_rename_noreplace", mutate_after_scan)
    with pytest.raises(EvidenceCorrupt):
        if publication == "recovery":
            SegmentStore(path)
        else:
            store.flush_security_boundary()
    assert attacked is True
    assert not (path / "chain-head.json").exists()
    if publication == "runtime":
        store.close(flush=False)


def test_runtime_segment_source_disappearance_after_manifest_fences_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime-segment-disappearance"
    coordinator, store, prior_head, later = _store_with_prior_head_and_active_record(path)
    promote_authenticated_source = segments_module._promote_authenticated_source
    disappeared = False

    def disappear_before_promotion(
        parent_descriptor: int,
        source_name: str,
        destination_name: str,
        display_path: Path,
        *,
        identity: object,
        expected_sha256: str,
    ) -> None:
        nonlocal disappeared
        os.unlink(source_name, dir_fd=parent_descriptor)
        disappeared = True
        promote_authenticated_source(
            parent_descriptor,
            source_name,
            destination_name,
            display_path,
            identity=identity,
            expected_sha256=expected_sha256,
        )

    monkeypatch.setattr(
        segments_module,
        "_promote_authenticated_source",
        disappear_before_promotion,
    )
    with pytest.raises(EvidenceCorrupt):
        store.flush_security_boundary()
    assert disappeared is True
    assert len(list((path / "manifests").glob("*.json"))) == 2
    assert json.loads((path / "health.json").read_bytes())["reason"] == ("segment_corrupt")
    assert (path / "chain-head.json").read_bytes() == prior_head
    with pytest.raises(EvidenceReadOnly):
        coordinator.accept(later)
    store.close(flush=False)


def test_chain_head_private_source_disappearance_fences_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "chain-head-disappearance"
    coordinator, store, prior_head, later = _store_with_prior_head_and_active_record(path)
    replace = segments_module.os.replace
    disappeared = False

    def disappear_before_replace(
        source_name: str,
        destination_name: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
    ) -> None:
        nonlocal disappeared
        if destination_name == "chain-head.json":
            os.unlink(source_name, dir_fd=src_dir_fd)
            disappeared = True
        replace(
            source_name,
            destination_name,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(
        segments_module.os,
        "replace",
        disappear_before_replace,
    )
    with pytest.raises(EvidenceCorrupt):
        store.flush_security_boundary()
    assert disappeared is True
    assert json.loads((path / "health.json").read_bytes())["reason"] == ("segment_corrupt")
    assert (path / "chain-head.json").read_bytes() == prior_head
    with pytest.raises(EvidenceReadOnly):
        coordinator.accept(later)
    store.close(flush=False)


@pytest.mark.parametrize("publication", ["first_frame", "manifest", "chain_head"])
def test_private_source_replacement_cleanup_preserves_corruption_fence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
) -> None:
    path = tmp_path / publication
    coordinator, store, prior_head, later = _store_with_prior_head_and_active_record(path)
    if publication == "first_frame":
        store.flush_security_boundary()
        prior_head = (path / "chain-head.json").read_bytes()

    bind_held_source = segments_module._bind_held_source
    replaced = False

    def replace_private_source_with_directory(
        parent_descriptor: int,
        name: str,
        display_path: Path,
        *,
        descriptor: int,
        identity: object,
    ) -> None:
        nonlocal replaced
        is_target = (
            (publication == "first_frame" and name.startswith(".agmind-create-"))
            or (publication == "manifest" and display_path.parent == path / "manifests")
            or (publication == "chain_head" and display_path == path / "chain-head.json")
        )
        if is_target and not replaced:
            os.rename(
                name,
                f"{name}.authenticated",
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
            replaced = True
        bind_held_source(
            parent_descriptor,
            name,
            display_path,
            descriptor=descriptor,
            identity=identity,
        )

    monkeypatch.setattr(
        segments_module,
        "_bind_held_source",
        replace_private_source_with_directory,
    )
    with pytest.raises(EvidenceCorrupt):
        if publication == "first_frame":
            coordinator.accept(later)
        else:
            store.flush_security_boundary()
    assert replaced is True
    assert json.loads((path / "health.json").read_bytes())["reason"] == ("segment_corrupt")
    assert (path / "chain-head.json").read_bytes() == prior_head
    with pytest.raises(EvidenceReadOnly):
        coordinator.accept(later)
    store.close(flush=False)


def test_segment_growth_after_initial_fstat_never_consumes_past_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "growth"
    store = _one_record_store(path, flush=False)
    opened = store.active_path
    assert opened is not None
    store.close(flush=False)
    initial = opened.read_bytes()
    decoded = decode_frames(
        initial,
        max_frame=segments_module.MAX_EVIDENCE_RECORD_BYTES,
    )
    first = decoded.records[0]
    appended = encode_frame(
        first.payload,
        previous_hash=first.record_hash,
        max_frame=segments_module.MAX_EVIDENCE_RECORD_BYTES,
    )
    bound = len(initial) + len(appended) - 1
    open_regular = segments_module._open_regular_at
    hashing_reader = segments_module._HashingReader
    tracked: list[object] = []
    grown = False

    class TrackingHashingReader(hashing_reader):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)
            tracked.append(self)

    def grow_after_fstat(
        parent_descriptor: int,
        name: str,
        display_path: Path,
        *,
        maximum: int | None = None,
    ) -> tuple[int, os.stat_result]:
        nonlocal grown
        descriptor, info = open_regular(
            parent_descriptor,
            name,
            display_path,
            maximum=maximum,
        )
        if name == opened.name and not grown:
            writer = os.open(name, os.O_WRONLY | os.O_APPEND, dir_fd=parent_descriptor)
            try:
                os.write(writer, appended)
                os.fsync(writer)
            finally:
                os.close(writer)
            grown = True
        return descriptor, info

    monkeypatch.setattr(segments_module, "MAX_SEGMENT_BYTES", bound)
    monkeypatch.setattr(segments_module, "_HashingReader", TrackingHashingReader)
    monkeypatch.setattr(segments_module, "_open_regular_at", grow_after_fstat)
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(path)
    assert grown is True
    assert tracked
    assert max(reader.total for reader in tracked) <= bound


def test_segment_scan_rejects_oversize_and_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversize_path = tmp_path / "oversize"
    oversize_store = _one_record_store(oversize_path, flush=False)
    opened = oversize_store.active_path
    assert opened is not None
    oversize_store.close(flush=False)
    os.truncate(opened, 64 * 1024 * 1024 + 1)
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(oversize_path)

    swap_path = tmp_path / "swap"
    swap_store = _one_record_store(swap_path, flush=True)
    closed = swap_path / swap_store.manifests[0].segment_relative_path
    replacement = closed.read_bytes()
    swap_store.close()
    open_regular = segments_module._open_regular_at
    swapped = False

    def swap_after_open(
        parent_descriptor: int,
        name: str,
        display_path: Path,
        *,
        maximum: int | None = None,
    ) -> tuple[int, os.stat_result]:
        nonlocal swapped
        descriptor, info = open_regular(
            parent_descriptor,
            name,
            display_path,
            maximum=maximum,
        )
        if name.endswith(".agseg") and not swapped:
            swapped = True
            os.rename(
                name,
                f"{name}.swapped",
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            replacement_descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_descriptor,
            )
            try:
                os.write(replacement_descriptor, replacement)
                os.fsync(replacement_descriptor)
            finally:
                os.close(replacement_descriptor)
        return descriptor, info

    monkeypatch.setattr(segments_module, "_open_regular_at", swap_after_open)
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(swap_path)
    assert swapped is True


@pytest.mark.parametrize(
    "relative_path",
    [
        "segments/2026-99-99/{name}",
        "segments/2026-07-27/{name}",
        "segments/2026-07-28/nested/{name}",
    ],
)
def test_manifest_path_date_is_exact(
    tmp_path: Path,
    relative_path: str,
) -> None:
    store = _one_record_store(tmp_path / "manifest-date", flush=True)
    manifest = store.manifests[0]
    store.close()
    value = manifest.model_dump()
    name = manifest.segment_relative_path.rsplit("/", 1)[-1]
    value["segment_relative_path"] = relative_path.format(name=name)
    value["manifest_sha256"] = segment_manifest_hash(value)
    with pytest.raises(ValidationError):
        SegmentManifestV1.model_validate(value, strict=True)


@pytest.mark.parametrize("placement", ["wrong-date", "nested"])
def test_active_segment_path_date_is_exact(
    tmp_path: Path,
    placement: str,
) -> None:
    path = tmp_path / placement
    store = _one_record_store(path, flush=False)
    opened = store.active_path
    assert opened is not None
    store.close(flush=False)
    if placement == "wrong-date":
        destination_parent = opened.parent.parent / "2026-07-27"
    else:
        destination_parent = opened.parent / "nested"
    destination_parent.mkdir(mode=0o700)
    os.rename(opened, destination_parent / opened.name)
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(path)


@pytest.mark.parametrize("unsafe_fact", ["mode", "hardlink"])
def test_active_segment_rejects_unsafe_file_facts(
    tmp_path: Path,
    unsafe_fact: str,
) -> None:
    path = tmp_path / unsafe_fact
    store = _one_record_store(path, flush=False)
    opened = store.active_path
    assert opened is not None
    store.close(flush=False)
    if unsafe_fact == "mode":
        opened.chmod(0o640)
    else:
        os.link(opened, opened.with_suffix(".alias"))
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(path)
