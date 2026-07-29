from __future__ import annotations

import copy
from pathlib import Path

import pytest
from agmind_immune.canonicaljson import canonical_json, event_signing_message
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    BootBoundaryError,
    EnvelopeConflict,
    EnvelopeIdentityError,
    EnvelopeSignatureError,
    EnvelopeVerifier,
    KeyMetadataError,
    OuterBindingError,
    PageDecodeError,
    PinnedObserverRoot,
    SequenceError,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.phase5b_helpers import (
    BOOT_A,
    BOOT_B,
    NOW,
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    public_bytes,
    root_value,
    rotation_pair,
)


def _identity(root_key_seed: int = 11) -> tuple[PinnedObserverRoot, AnchoredPublicKeyChain]:
    key = private_key(root_key_seed)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    return root, AnchoredPublicKeyChain.from_value(root, metadata_value(key))


def _outer(envelope: dict[str, object]) -> dict[str, object]:
    raw = canonical_json(page_value(envelope))
    return decode_events_page(raw).events[0].model_dump()


def _coordinator(
    path: Path,
    root: PinnedObserverRoot,
    chain: AnchoredPublicKeyChain,
) -> AcceptanceCoordinator:
    return AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        SegmentStore(path),
    )


def _accept(
    coordinator: AcceptanceCoordinator,
    envelope: dict[str, object],
) -> object:
    item = decode_events_page(canonical_json(page_value(envelope))).events[0]
    return coordinator.accept(item)


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (lambda raw: raw[:-1] + b" trailing", PageDecodeError),
        (
            lambda _raw: (
                b'{"schema_version":"agmind.observer-events-page.v1",'
                b'"schema_version":"agmind.observer-events-page.v1","events":[],'
                b'"uncovered_gaps":[],"gaps_truncated":false,"acked_through":0,'
                b'"reserved_through":0}'
            ),
            PageDecodeError,
        ),
        (
            lambda raw: raw.replace(b'"acked_through":0', b'"acked_through":-0'),
            PageDecodeError,
        ),
        (
            lambda raw: raw.replace(b'"sequence":1', b'"sequence":0', 1),
            PageDecodeError,
        ),
    ],
)
def test_strict_page_matrix(mutate: object, error: type[Exception]) -> None:
    key = private_key(11)
    raw = canonical_json(page_value(boot_boundary(key)))
    with pytest.raises(error):
        decode_events_page(mutate(raw))


def test_outer_binding_signature_and_falco_source_hash_matrix(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    root, chain = _identity()
    valid = boot_boundary(key)
    item = _outer(valid)
    coordinator = _coordinator(tmp_path / "outer", root, chain)
    verifier = coordinator.verifier

    bad_outer = dict(item)
    bad_outer["sequence"] = 2
    with pytest.raises(OuterBindingError):
        verifier.verify(
            bad_outer["envelope"],
            sequence=bad_outer["sequence"],
            event_id=bad_outer["event_id"],
            content_sha256=bad_outer["content_sha256"],
        )

    bad_signature = copy.deepcopy(valid)
    bad_signature["source_signature"] = "0" * 128
    bad_item = _outer(bad_signature)
    with pytest.raises(EnvelopeSignatureError):
        verifier.verify(
            bad_item["envelope"],
            sequence=bad_item["sequence"],
            event_id=bad_item["event_id"],
            content_sha256=bad_item["content_sha256"],
        )

    _accept(coordinator, valid)
    falco_fields = {
        "detector_rule": "Outbound connect",
        "detector_rule_version": "1",
        "falco_version": "0.42.1",
        "event_time": NOW,
        "evt_type": "connect",
        "evt_rawres": -1,
        "evt_res": "EINPROGRESS",
        "successful_connect": True,
        "investigation_only": True,
        "repo_digests": [],
        "missing_required_fields": [
            "destination_ipv4",
            "destination_port",
            "falco_container_id_prefix",
            "falco_container_start_ts",
            "l4_protocol",
            "proc_exe_path",
            "proc_name",
            "proc_parent_name",
        ],
        "raw_event_sha256": "1" * 64,
    }
    bad_falco = envelope_value(
        key,
        sequence=2,
        event_type="falco_connect",
        normalized_fields=falco_fields,
        source_payload_hash="2" * 64,
    )
    with pytest.raises(OuterBindingError):
        _accept(coordinator, bad_falco)
    coordinator.segment_store.close()


def test_immutable_root_and_metadata_proof_matrix() -> None:
    old_key = private_key(11)
    new_key = private_key(12)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(old_key))
    )
    rotation = rotation_pair(
        old_key,
        new_key,
        transition_sequence=2,
        transition_boot=BOOT_A,
        start_boot=BOOT_A,
        mode="same",
    )
    valid = metadata_value(old_key, rotation=rotation)
    assert AnchoredPublicKeyChain.from_value(root, valid).current_epoch == 2

    substituted = copy.deepcopy(valid)
    substituted["keys"][0]["public_key"] = public_bytes(private_key(13)).hex()
    with pytest.raises(KeyMetadataError):
        AnchoredPublicKeyChain.from_value(root, substituted)

    removed_prefix = copy.deepcopy(valid)
    removed_prefix["keys"] = removed_prefix["keys"][1:]
    with pytest.raises(KeyMetadataError):
        AnchoredPublicKeyChain.from_value(root, removed_prefix)

    proof_mismatch = copy.deepcopy(valid)
    proof_mismatch["keys"][1]["transition_envelope"]["event_id"] = "evt_" + "0" * 64
    with pytest.raises(KeyMetadataError):
        AnchoredPublicKeyChain.from_value(root, proof_mismatch)

    with pytest.raises(KeyMetadataError):
        AnchoredPublicKeyChain.from_value(root, metadata_value(old_key), minimum_epoch=2)


@pytest.mark.parametrize(
    ("mode", "transition_boot", "start_boot"),
    [
        ("same", BOOT_A, BOOT_A),
        ("b", BOOT_B, BOOT_B),
        ("c", BOOT_A, BOOT_B),
    ],
)
def test_closed_rotation_fsm_and_candidate_activation(
    mode: str,
    transition_boot: str,
    start_boot: str,
    tmp_path: Path,
) -> None:
    old_key = private_key(11)
    new_key = private_key(12)
    first = boot_boundary(old_key)
    rotation = rotation_pair(
        old_key,
        new_key,
        transition_sequence=2,
        transition_boot=transition_boot,
        start_boot=start_boot,
        mode=mode,
    )
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(old_key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(old_key, rotation=rotation))
    coordinator = _coordinator(tmp_path / "main", root, chain)
    verifier = coordinator.verifier
    if mode != "b":
        _accept(coordinator, first)
    transition_ref = _accept(coordinator, rotation[1])
    assert verifier.fsm.active_epoch == 1
    assert transition_ref.source_sequence == 2
    assert tuple(coordinator.segment_store.iter_records())[-1].envelope["key_epoch"] == 1
    _accept(coordinator, rotation[2])
    assert verifier.fsm.active_epoch == 2
    assert verifier.fsm.current_boot_id == start_boot

    intervening_coordinator = _coordinator(tmp_path / "intervening", root, chain)
    if mode != "b":
        _accept(intervening_coordinator, first)
    _accept(intervening_coordinator, rotation[1])
    gap = envelope_value(
        old_key,
        sequence=3,
        boot_id=transition_boot,
        normalized_fields={"kind": "intervening"},
    )
    with pytest.raises((SequenceError, BootBoundaryError)):
        _accept(intervening_coordinator, gap)

    mismatch_coordinator = _coordinator(tmp_path / "mismatch", root, chain)
    if mode != "b":
        _accept(mismatch_coordinator, first)
    different_transition_envelope = copy.deepcopy(rotation[1])
    different_transition_envelope["ingest_time"] = "2026-07-28T10:00:01Z"
    different_transition_envelope["source_signature"] = old_key.sign(
        event_signing_message(different_transition_envelope)
    ).hex()
    with pytest.raises(KeyMetadataError):
        _accept(mismatch_coordinator, different_transition_envelope)
    coordinator.segment_store.close()
    intervening_coordinator.segment_store.close()
    mismatch_coordinator.segment_store.close()


def test_hole_requires_signed_exact_gap_and_retry_conflict_is_persistent(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    root, chain = _identity()
    coordinator = _coordinator(tmp_path / "holes", root, chain)
    verifier = coordinator.verifier
    _accept(coordinator, boot_boundary(key))
    later = envelope_value(key, sequence=4, normalized_fields={"kind": "later"})
    _accept(coordinator, later)
    assert verifier.fsm.unresolved_holes == ((2, 3),)

    gap_fields = {
        "component": "observer",
        "kind": "observer_sequence_gap",
        "severity": "CRITICAL",
        "opened_at": NOW,
        "affected_source_sequence_start": 2,
        "affected_source_sequence_end": 3,
        "reason_code": "reserved_sequence_not_published",
    }
    gap = envelope_value(
        key,
        sequence=5,
        event_type="coverage",
        normalized_fields=gap_fields,
        coverage_flags=["reconcile_required", "sequence_gap"],
    )
    _accept(coordinator, gap)
    assert verifier.fsm.unresolved_holes == ()

    retry = _outer(gap)
    retry_verified = verifier.verify(
        retry["envelope"],
        sequence=retry["sequence"],
        event_id=retry["event_id"],
        content_sha256=retry["content_sha256"],
    )
    assert retry_verified.is_retry is True

    conflict = envelope_value(
        key,
        sequence=5,
        normalized_fields={"kind": "valid-signed-conflict"},
    )
    with pytest.raises(EnvelopeConflict):
        coordinator.accept(decode_events_page(canonical_json(page_value(conflict))).events[0])
    assert verifier.fsm.mutation_read_only is True
    coordinator.segment_store.close(flush=False)


def test_sequence_gap_open_and_close_have_disjoint_exact_semantics(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    root, chain = _identity()
    coordinator = _coordinator(tmp_path / "sequence-gap-close", root, chain)
    verifier = coordinator.verifier
    _accept(coordinator, boot_boundary(key))
    _accept(
        coordinator,
        envelope_value(key, sequence=4, normalized_fields={"kind": "later"}),
    )
    assert verifier.fsm.unresolved_holes == ((2, 3),)

    opened_at = NOW
    open_fields = {
        "component": "observer",
        "kind": "observer_sequence_gap",
        "severity": "CRITICAL",
        "opened_at": opened_at,
        "affected_source_sequence_start": 2,
        "affected_source_sequence_end": 3,
        "reason_code": "reserved_sequence_not_published",
    }
    _accept(
        coordinator,
        envelope_value(
            key,
            sequence=5,
            event_type="coverage",
            normalized_fields=open_fields,
            coverage_flags=["reconcile_required", "sequence_gap"],
        ),
    )
    assert verifier.fsm.unresolved_holes == ()

    close_fields = {
        "component": "observer",
        "kind": "observer_sequence_gap",
        "severity": "INFO",
        "opened_at": opened_at,
        "closed_at": NOW,
        "affected_source_sequence_start": 2,
        "affected_source_sequence_end": 3,
        "reason_code": "reserved_sequence_reconciled",
        "reconcile_generation": 1,
    }
    _accept(
        coordinator,
        envelope_value(
            key,
            sequence=6,
            event_type="coverage",
            normalized_fields=close_fields,
            coverage_flags=["reconcile_required", "sequence_gap"],
            inventory_generation=1,
        ),
    )
    assert verifier.fsm.unresolved_holes == ()
    coordinator.segment_store.close()


@pytest.mark.parametrize(
    ("mutate_fields", "envelope_kwargs"),
    [
        (
            lambda fields: {**fields, "severity": "WARNING"},
            {},
        ),
        (
            lambda fields: {**fields, "extra": "forbidden"},
            {},
        ),
        (
            lambda fields: {
                **fields,
                "reason_code": "reserved_sequence_not_published",
            },
            {},
        ),
        (
            lambda fields: fields,
            {"inventory_generation": 0},
        ),
        (
            lambda fields: {**fields, "reconcile_generation": 0},
            {"inventory_generation": 0},
        ),
        (
            lambda fields: fields,
            {"coverage_flags": ["sequence_gap"]},
        ),
        (
            lambda fields: fields,
            {"container_id": "a" * 64},
        ),
        (
            lambda fields: {**fields, "closed_at": "2026-07-28T10:00:01Z"},
            {},
        ),
    ],
)
def test_sequence_gap_close_rejects_inexact_form(
    tmp_path: Path,
    mutate_fields: object,
    envelope_kwargs: dict[str, object],
) -> None:
    key = private_key(11)
    root, chain = _identity()
    coordinator = _coordinator(tmp_path, root, chain)
    _accept(coordinator, boot_boundary(key))
    close_fields = mutate_fields(
        {
            "component": "observer",
            "kind": "observer_sequence_gap",
            "severity": "INFO",
            "opened_at": NOW,
            "closed_at": NOW,
            "affected_source_sequence_start": 2,
            "affected_source_sequence_end": 3,
            "reason_code": "reserved_sequence_reconciled",
            "reconcile_generation": 1,
        }
    )
    with pytest.raises(OuterBindingError):
        close_kwargs = {
            "coverage_flags": ["reconcile_required", "sequence_gap"],
            "inventory_generation": 1,
            **envelope_kwargs,
        }
        _accept(
            coordinator,
            envelope_value(
                key,
                sequence=2,
                event_type="coverage",
                normalized_fields=close_fields,
                **close_kwargs,
            ),
        )
    coordinator.segment_store.close(flush=False)


def test_changed_boot_cursor_and_all_coverage_contracts(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    root, chain = _identity()
    coordinator = _coordinator(tmp_path / "coverage", root, chain)
    _accept(coordinator, boot_boundary(key))
    changed = boot_boundary(
        key,
        sequence=4,
        boot_id=BOOT_B,
        previous_boot_id=BOOT_A,
        previous_source_sequence=3,
    )
    _accept(coordinator, changed)
    assert coordinator.verifier.fsm.unresolved_holes == ((2, 3),)

    adapter_coverage = envelope_value(
        key,
        sequence=5,
        boot_id=BOOT_B,
        event_type="coverage",
        normalized_fields={
            "component": "falco-adapter",
            "kind": "detector_lag",
            "severity": "WARNING",
            "opened_at": NOW,
            "reason_code": "socket_backpressure",
        },
        source_payload_hash="1" * 64,
        inventory_generation=7,
        inventory_revision=4,
    )
    _accept(coordinator, adapter_coverage)
    invalid = envelope_value(
        key,
        sequence=6,
        boot_id=BOOT_B,
        event_type="coverage",
        normalized_fields={
            "component": "falco-adapter",
            "kind": "detector_lag",
            "severity": "WARNING",
            "opened_at": NOW,
        },
    )
    with pytest.raises(OuterBindingError):
        _accept(coordinator, invalid)
    coordinator.segment_store.close()


def test_wrong_era_key_cannot_manufacture_historical_conflict(
    tmp_path: Path,
) -> None:
    old_key = private_key(11)
    new_key = private_key(12)
    rotation = rotation_pair(
        old_key,
        new_key,
        transition_sequence=2,
        transition_boot=BOOT_A,
        start_boot=BOOT_A,
        mode="same",
    )
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(old_key))
    )
    chain = AnchoredPublicKeyChain.from_value(
        root,
        metadata_value(old_key, rotation=rotation),
    )
    coordinator = _coordinator(tmp_path / "historical-key", root, chain)
    _accept(coordinator, boot_boundary(old_key))

    future_key_conflict = envelope_value(
        new_key,
        sequence=1,
        key_epoch=2,
        normalized_fields={"kind": "future-key-conflict"},
    )
    with pytest.raises(EnvelopeIdentityError):
        _accept(coordinator, future_key_conflict)
    assert not (tmp_path / "historical-key" / "health.json").exists()

    _accept(coordinator, rotation[1])
    _accept(coordinator, rotation[2])
    retired_key_conflict = envelope_value(
        old_key,
        sequence=3,
        key_epoch=1,
        normalized_fields={"kind": "retired-key-conflict"},
    )
    with pytest.raises(EnvelopeIdentityError):
        _accept(coordinator, retired_key_conflict)
    assert not (tmp_path / "historical-key" / "health.json").exists()
    coordinator.segment_store.close()
