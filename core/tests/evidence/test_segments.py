from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import agmind_immune.evidence.segments as segments_module
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.evidence.frames import decode_frames
from agmind_immune.evidence.segments import (
    EvidenceCorrupt,
    EvidencePriority,
    EvidenceReadOnly,
    EvidenceSealError,
    SegmentStore,
)
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeVerifier,
    PinnedObserverRoot,
    VerifiedEnvelope,
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


def _system(path: Path) -> tuple[AcceptanceCoordinator, SegmentStore]:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    return AcceptanceCoordinator.create_empty(EnvelopeVerifier(root, chain), store), store


def _item(envelope: dict[str, object]) -> object:
    return decode_events_page(canonical_json(page_value(envelope))).events[0]


def test_unsealed_value_cannot_enter_authoritative_store(tmp_path: Path) -> None:
    store = SegmentStore(tmp_path / "evidence")
    forged = object.__new__(VerifiedEnvelope)
    with pytest.raises(EvidenceSealError):
        store.append(forged, EvidencePriority.ROUTINE)
    store.close()

    coordinator, sealed_store = _system(tmp_path / "sealed-evidence")
    item = _item(boot_boundary(private_key(11)))
    verified = coordinator.verifier.verify(
        item.envelope,
        sequence=item.sequence,
        event_id=item.event_id,
        content_sha256=item.content_sha256,
    )
    with pytest.raises(AttributeError):
        verified.content_sha256 = "0" * 64
    object.__setattr__(verified, "_content_sha256", "0" * 64)
    with pytest.raises(EvidenceSealError):
        sealed_store.append(verified, EvidencePriority.PROTECTED)
    assert tuple(sealed_store.iter_records()) == ()
    assert sealed_store.active_path is None
    sealed_store.close()


def test_staged_authority_is_exact_object_and_store_lifecycle_bound(
    tmp_path: Path,
) -> None:
    coordinator, store = _system(tmp_path / "authority")
    item = _item(boot_boundary(private_key(11)))
    verified = coordinator.verifier.verify(
        item.envelope,
        sequence=item.sequence,
        event_id=item.event_id,
        content_sha256=item.content_sha256,
    )

    clone = object.__new__(VerifiedEnvelope)
    for name in VerifiedEnvelope.__slots__:
        if name != "__weakref__":
            object.__setattr__(clone, name, getattr(verified, name))
    with pytest.raises(EvidenceSealError):
        store.append(clone, EvidencePriority.PROTECTED)
    assert not hasattr(verified, "_next_fsm")
    assert not hasattr(verified, "envelope")
    assert not hasattr(coordinator.verifier, "commit")

    _other_coordinator, other = _system(tmp_path / "other")
    with pytest.raises(EvidenceSealError):
        other.append(verified, EvidencePriority.PROTECTED)
    assert tuple(other.iter_records()) == ()

    third = SegmentStore(tmp_path / "third")
    with pytest.raises(EvidenceSealError):
        AcceptanceCoordinator.create_empty(coordinator.verifier, third)
    third.close()
    other.close()
    store.close()


def test_priority_rotation_manifest_frame_facts_and_clean_restart(tmp_path: Path) -> None:
    path = tmp_path / "evidence"
    coordinator, store = _system(path)
    key = private_key(11)
    first = coordinator.accept(_item(boot_boundary(key)))
    second_envelope = envelope_value(
        key,
        sequence=2,
        boot_id=BOOT_A,
        normalized_fields={"kind": "second"},
    )
    second = coordinator.accept(_item(second_envelope))
    store.flush_security_boundary()

    manifests = store.manifests
    assert [manifest.evidence_priority for manifest in manifests] == ["protected", "routine"]
    assert manifests[0].previous_manifest_sha256 == "0" * 64
    assert manifests[1].previous_manifest_sha256 == manifests[0].manifest_sha256
    assert manifests[0].first_source_sequence == manifests[0].last_source_sequence == 1
    assert manifests[1].first_source_sequence == manifests[1].last_source_sequence == 2
    assert store.chain_head is not None
    assert store.chain_head.head_manifest_sha256 == manifests[-1].manifest_sha256
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    for relative in (first.segment_relative_path, second.segment_relative_path):
        assert stat.S_IMODE((path / relative).stat().st_mode) == 0o600
    store.close()

    restarted = SegmentStore(path)
    assert [record.ref.source_sequence for record in restarted.iter_records()] == [1, 2]
    assert restarted.chain_head == store.chain_head
    restarted.close()


@pytest.mark.parametrize(
    "failure_step",
    ["create", "write", "file_fsync", "before_publish"],
)
def test_first_frame_publication_never_exposes_empty_open(
    tmp_path: Path,
    failure_step: str,
) -> None:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    injected = False

    def create_hook(step: str) -> None:
        nonlocal injected
        if step == failure_step and not injected:
            injected = True
            raise OSError(f"injected create {step}")

    path = tmp_path / failure_step
    store = SegmentStore(path, segment_create_step_hook=create_hook)
    verifier = EnvelopeVerifier(root, chain)
    coordinator = AcceptanceCoordinator.create_empty(verifier, store)
    item = _item(boot_boundary(key))
    with pytest.raises(OSError, match="injected create"):
        coordinator.accept(item)
    assert verifier.fsm.last_sequence == 0
    assert tuple(store.iter_records()) == ()
    assert list((path / "segments").rglob("*.open")) == []
    assert list((path / "segments").rglob(".agmind-create-*.tmp")) == []

    coordinator.accept(item)
    assert verifier.fsm.last_sequence == 1
    opened = store.active_path
    assert opened is not None and opened.stat().st_size > 0
    store.close()


def test_authenticated_first_frame_source_disappearance_fences_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "disappeared-first-frame"
    coordinator, store = _system(path)
    item = _item(boot_boundary(private_key(11)))
    rename_noreplace = segments_module._rename_noreplace
    disappeared = False

    def disappear_before_rename(
        source_name: str,
        destination_name: str,
        *,
        source_dir_fd: int,
        destination_dir_fd: int,
    ) -> None:
        nonlocal disappeared
        if source_name.startswith(".agmind-create-") and destination_name.endswith(
            ".open"
        ):
            os.unlink(source_name, dir_fd=source_dir_fd)
            disappeared = True
        rename_noreplace(
            source_name,
            destination_name,
            source_dir_fd=source_dir_fd,
            destination_dir_fd=destination_dir_fd,
        )

    monkeypatch.setattr(
        segments_module,
        "_rename_noreplace",
        disappear_before_rename,
    )
    with pytest.raises(EvidenceCorrupt):
        coordinator.accept(item)
    assert disappeared is True
    assert json.loads((path / "health.json").read_bytes())["reason"] == (
        "segment_corrupt"
    )
    assert not (path / "chain-head.json").exists()
    with pytest.raises(EvidenceReadOnly):
        coordinator.accept(item)
    store.close(flush=False)


def test_published_first_frame_recovers_after_pre_return_failure(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    injected = False

    def create_hook(step: str) -> None:
        nonlocal injected
        if step == "publish" and not injected:
            injected = True
            raise OSError("injected after publish")

    path = tmp_path / "published"
    store = SegmentStore(path, segment_create_step_hook=create_hook)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    item = _item(boot_boundary(key))
    with pytest.raises(OSError, match="after publish"):
        coordinator.accept(item)
    opened = list((path / "segments").rglob("*.open"))
    assert len(opened) == 1 and opened[0].stat().st_size > 0
    with pytest.raises(EvidenceReadOnly):
        coordinator.accept(item)
    store.close(flush=False)

    restarted_store = SegmentStore(path)
    restarted = AcceptanceCoordinator.open_and_recover(
        EnvelopeVerifier(root, chain),
        restarted_store,
    )
    assert restarted.verifier.fsm.last_sequence == 1
    assert restarted.accept(item).source_sequence == 1
    assert len(tuple(restarted_store.iter_records())) == 1
    restarted_store.close()


def test_root_is_component_safe_and_live_operations_stay_on_locked_inode(
    tmp_path: Path,
) -> None:
    actual_parent = tmp_path / "actual"
    actual_parent.mkdir(mode=0o700)
    symlink_parent = tmp_path / "linked"
    symlink_parent.symlink_to(actual_parent, target_is_directory=True)
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(symlink_parent / "evidence")

    original_parent = tmp_path / "original"
    original_root = original_parent / "evidence"
    original_parent.mkdir(mode=0o700)
    coordinator, store = _system(original_root)
    key = private_key(11)
    coordinator.accept(_item(boot_boundary(key)))
    active = store.active_path
    assert active is not None
    relative_active = active.relative_to(original_root)
    moved_parent = tmp_path / "moved"
    os.rename(original_parent, moved_parent)
    original_root.mkdir(parents=True, mode=0o700)
    decoy = original_root / "decoy"
    decoy.write_bytes(b"do-not-touch")

    coordinator.accept(
        _item(
            envelope_value(
                key,
                sequence=2,
                boot_id=BOOT_A,
                event_type="observer_start",
                normalized_fields={
                    "kind": "observer_start",
                    "reconcile_required": True,
                },
                coverage_flags=["reconcile_required"],
            )
        )
    )
    moved_active = moved_parent / "evidence" / relative_active
    assert len(
        decode_frames(moved_active.read_bytes(), max_frame=128 * 1024).records
    ) == 2
    assert decoy.read_bytes() == b"do-not-touch"
    store.close()
    assert list((moved_parent / "evidence" / "manifests").iterdir())
    assert list(original_root.iterdir()) == [decoy]
