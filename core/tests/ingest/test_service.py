from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

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
    SegmentStore,
)
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeConflict,
    EnvelopeSignatureError,
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


def _coordinator(path: Path) -> tuple[AcceptanceCoordinator, SegmentStore, EnvelopeVerifier]:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    verifier = EnvelopeVerifier(root, chain)
    store = SegmentStore(path)
    return AcceptanceCoordinator.create_empty(verifier, store), store, verifier


def test_factories_enforce_replay_and_single_store_lifecycle(tmp_path: Path) -> None:
    path = tmp_path / "evidence"
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    raw_store = SegmentStore(path)
    with pytest.raises(TypeError):
        AcceptanceCoordinator(EnvelopeVerifier(root, chain), raw_store)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        raw_store,
    )
    item = decode_events_page(
        canonical_json(page_value(boot_boundary(key)))
    ).events[0]
    coordinator.accept(item)
    raw_store.flush_security_boundary()
    raw_store.close()

    reopened = SegmentStore(path)
    with pytest.raises(EvidenceReadOnly):
        AcceptanceCoordinator.create_empty(EnvelopeVerifier(root, chain), reopened)
    recovered = AcceptanceCoordinator.open_and_recover(
        EnvelopeVerifier(root, chain),
        reopened,
    )
    assert recovered.verifier.fsm.last_sequence == 1
    assert recovered.accept(item).source_sequence == 1
    assert len(tuple(reopened.iter_records())) == 1
    reopened.close()


def test_append_failure_leaves_fsm_uncommitted_and_retry_is_exact(tmp_path: Path) -> None:
    coordinator, store, verifier = _coordinator(tmp_path / "evidence")
    key = private_key(11)
    item = decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    store.fail_next_append = OSError("injected append failure")
    with pytest.raises(OSError, match="injected"):
        coordinator.accept(item)
    assert verifier.fsm.last_sequence == 0

    first = coordinator.accept(item)
    retry = coordinator.accept(item)
    assert retry == first
    assert next(store.iter_records()).ref == first
    conflict = decode_events_page(
        canonical_json(
            page_value(
                envelope_value(
                    key,
                    sequence=1,
                    boot_id=BOOT_A,
                    normalized_fields={"kind": "signed-conflict"},
                )
            )
        )
    ).events[0]
    with pytest.raises(EnvelopeConflict):
        coordinator.accept(conflict)
    assert json.loads((tmp_path / "evidence" / "health.json").read_bytes())[
        "reason"
    ] == "evidence_conflict"
    store.close(flush=False)
    read_only = SegmentStore(tmp_path / "evidence")
    assert read_only.read_only_reason == "evidence_conflict"
    with pytest.raises(EvidenceReadOnly):
        read_only.flush_security_boundary()
    read_only.close(flush=False)


@pytest.mark.parametrize(
    "failure_step",
    [
        "create",
        "create_directory_fsync",
        "write",
        "file_fsync",
        "rename",
        "rename_directory_fsync",
    ],
)
def test_health_intent_keeps_marker_failure_fail_closed(
    tmp_path: Path,
    failure_step: str,
) -> None:
    path = tmp_path / failure_step
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    injected = False

    def health_hook(step: str) -> None:
        nonlocal injected
        if step == failure_step and not injected:
            injected = True
            raise OSError(f"injected health {step}")

    store = SegmentStore(path, health_step_hook=health_hook)
    verifier = EnvelopeVerifier(root, chain)
    coordinator = AcceptanceCoordinator.create_empty(verifier, store)
    coordinator.accept(
        decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    )
    active = store.active_path
    assert active is not None
    triggering_bytes = active.read_bytes()
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
    with pytest.raises(OSError, match="injected health"):
        coordinator.accept(conflict)
    assert store.read_only_reason == "evidence_conflict"
    assert verifier.fsm.mutation_read_only is False
    assert active.read_bytes() == triggering_bytes
    store.close(flush=False)

    restarted = SegmentStore(path)
    assert restarted.read_only_reason in {"evidence_conflict", "segment_corrupt"}
    assert active.read_bytes() == triggering_bytes
    restarted.close(flush=False)


def test_runtime_close_reread_failure_trips_persistent_fence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runtime-corruption"
    coordinator, store, _verifier = _coordinator(path)
    key = private_key(11)
    coordinator.accept(
        decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    )
    active = store.active_path
    assert active is not None
    changed = bytearray(active.read_bytes())
    changed[len(changed) // 2] ^= 1
    active.write_bytes(changed)
    triggering_bytes = active.read_bytes()
    with pytest.raises(EvidenceCorrupt):
        store.flush_security_boundary()
    assert active.read_bytes() == triggering_bytes
    assert json.loads((path / "health.json").read_bytes())["reason"] == "segment_corrupt"
    store.close(flush=False)


def test_durable_append_before_commit_retries_without_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, store, verifier = _coordinator(tmp_path / "evidence")
    key = private_key(11)
    item = decode_events_page(
        canonical_json(page_value(boot_boundary(key)))
    ).events[0]
    commit_durable = verifier._commit_durable
    failed = False

    def fail_once(authorization: Any, lifecycle: object, ref: object) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise RuntimeError("injected crash after durable append")
        commit_durable(authorization, lifecycle, ref)

    monkeypatch.setattr(verifier, "_commit_durable", fail_once)
    with pytest.raises(RuntimeError, match="after durable"):
        coordinator.accept(item)
    records = tuple(store.iter_records())
    assert len(records) == 1
    assert verifier.fsm.last_sequence == 0
    active = store.active_path
    assert active is not None
    durable_bytes = active.read_bytes()

    different = decode_events_page(
        canonical_json(page_value(boot_boundary(key, sequence=2)))
    ).events[0]
    with pytest.raises(EvidenceReadOnly):
        coordinator.accept(different)
    assert active.read_bytes() == durable_bytes
    assert len(tuple(store.iter_records())) == 1

    retried = coordinator.accept(item)
    assert retried == records[0].ref
    assert verifier.fsm.last_sequence == 1
    assert len(tuple(store.iter_records())) == 1
    expected_fsm = verifier.fsm
    store.flush_security_boundary()
    store.close()

    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    reopened_store = SegmentStore(tmp_path / "evidence")
    reopened = AcceptanceCoordinator.open_and_recover(
        EnvelopeVerifier(root, chain),
        reopened_store,
    )
    assert reopened.verifier.fsm == expected_fsm
    assert reopened.accept(item) == retried
    reopened_store.close()


def test_restart_rebuilds_verifier_authority_from_evidence(tmp_path: Path) -> None:
    path = tmp_path / "evidence"
    coordinator_before_restart, store, verifier_before_restart = _coordinator(path)
    key = private_key(11)
    item = decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    expected = coordinator_before_restart.accept(item)
    assert verifier_before_restart.fsm.last_sequence == 1
    store.flush_security_boundary()
    store.close()

    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    restarted_store = SegmentStore(path)
    restarted = AcceptanceCoordinator.recover(
        EnvelopeVerifier(root, chain),
        restarted_store,
    )
    assert restarted.accept(item) == expected
    assert restarted.verifier.fsm.last_sequence == 1
    assert len(tuple(restarted_store.iter_records())) == 1
    restarted_store.close()

    authenticity_path = tmp_path / "structurally-valid-but-unauthenticated"
    authentic_coordinator, authentic_store, _ = _coordinator(authenticity_path)
    authentic_coordinator.accept(item)
    authentic_store.flush_security_boundary()
    manifest = authentic_store.manifests[0]
    authentic_store.close()
    segment_path = authenticity_path / manifest.segment_relative_path
    frame_record = decode_frames(
        segment_path.read_bytes(),
        max_frame=128 * 1024,
    ).records[0]
    stored = json.loads(frame_record.payload)
    stored["envelope"]["source_signature"] = "0" * 128
    stored["outer"]["content_sha256"] = hashlib.sha256(
        canonical_json(stored["envelope"])
    ).hexdigest()
    rewritten = encode_frame(
        canonical_json(stored),
        previous_hash=bytes(32),
        max_frame=128 * 1024,
    )
    segment_path.write_bytes(rewritten)
    manifest_value = manifest.model_dump()
    manifest_value.update(
        {
            "segment_size_bytes": len(rewritten),
            "segment_sha256": hashlib.sha256(rewritten).hexdigest(),
            "first_frame_sha256": rewritten[-32:].hex(),
            "last_frame_sha256": rewritten[-32:].hex(),
        }
    )
    manifest_value["manifest_sha256"] = segment_manifest_hash(manifest_value)
    rewritten_manifest = SegmentManifestV1.model_validate(manifest_value, strict=True)
    (authenticity_path / "manifests" / f"{manifest.segment_id}.json").write_bytes(
        canonical_json(rewritten_manifest)
    )
    (authenticity_path / "chain-head.json").write_bytes(
        canonical_json(chain_head_for(rewritten_manifest))
    )
    triggering_bytes = segment_path.read_bytes()
    structurally_valid = SegmentStore(authenticity_path)
    with pytest.raises(EnvelopeSignatureError):
        AcceptanceCoordinator.recover(
            EnvelopeVerifier(root, chain),
            structurally_valid,
        )
    assert segment_path.read_bytes() == triggering_bytes
    assert json.loads((authenticity_path / "health.json").read_bytes())[
        "reason"
    ] == "segment_corrupt"
    structurally_valid.close()
