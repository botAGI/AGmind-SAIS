from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import pytest
from agmind_immune.canonicaljson import (
    canonical_json,
    pcc_correlation_request_sha256,
    pcc_management_denylist_sha256,
    pcc_operator_denylist_sha256,
    release_id,
)
from agmind_immune.contracts import (
    ObserverTrustRootV1,
    PCCCorrelationSnapshotRequestV1,
)
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeConflict,
    EnvelopeVerifier,
    OuterBindingError,
    PCCCorrelationVerificationContext,
    PCCSnapshotVerificationError,
    PinnedObserverRoot,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.phase5b_helpers import (
    BOOT_A,
    BOOT_B,
    NOW,
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
    rotation_pair,
)

_CONTAINER_ID = "a" * 64
_IMAGE_ID = "sha256:" + "b" * 64
_IMMUTABLE_SPEC_SHA256 = "c" * 64
_RAW_EVENT_SHA256 = "d" * 64


def _identity(
    key: Ed25519PrivateKey,
    *,
    rotation: tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object],
    ]
    | None = None,
) -> tuple[PinnedObserverRoot, AnchoredPublicKeyChain]:
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key)),
    )
    return root, AnchoredPublicKeyChain.from_value(
        root,
        metadata_value(key, rotation=rotation),
    )


def _coordinator(
    path: Path,
    key: Ed25519PrivateKey,
    *,
    rotation: tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object],
    ]
    | None = None,
) -> AcceptanceCoordinator:
    root, chain = _identity(key, rotation=rotation)
    return AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        SegmentStore(path),
    )


def _accept(
    coordinator: AcceptanceCoordinator,
    envelope: dict[str, object],
) -> object:
    return coordinator.accept(_item(envelope))


def _item(envelope: dict[str, object]) -> object:
    return decode_events_page(canonical_json(page_value(envelope))).events[0]


def _candidate_trigger(
    key: Ed25519PrivateKey,
    *,
    sequence: int = 2,
    boot_id: str = BOOT_A,
    key_epoch: int = 1,
) -> dict[str, object]:
    fields = {
        "detector_rule": "AGmind PCC Suspicious Process Outbound Connect",
        "detector_rule_version": "agmind-pcc-rules-v1",
        "falco_version": "0.44.1",
        "event_time": NOW,
        "evt_type": "connect",
        "evt_rawres": 0,
        "evt_res": "SUCCESS",
        "successful_connect": True,
        "investigation_only": False,
        "falco_container_id_prefix": _CONTAINER_ID[:12],
        "falco_container_full_id": _CONTAINER_ID,
        "falco_container_start_ts": NOW,
        "docker_container_id": _CONTAINER_ID,
        "docker_started_at": NOW,
        "image_id": _IMAGE_ID,
        "repo_digests": [],
        "immutable_spec_sha256": _IMMUTABLE_SPEC_SHA256,
        "inventory_revision": 7,
        "proc_name": "curl",
        "proc_exe_path": "/usr/bin/curl",
        "proc_parent_name": "sh",
        "destination_ipv4": "8.8.8.8",
        "destination_port": 443,
        "l4_protocol": "tcp",
        "missing_required_fields": [],
        "raw_event_sha256": _RAW_EVENT_SHA256,
    }
    return envelope_value(
        key,
        sequence=sequence,
        boot_id=boot_id,
        key_epoch=key_epoch,
        event_type="falco_connect",
        normalized_fields=fields,
        source_payload_hash=_RAW_EVENT_SHA256,
        container_id=_CONTAINER_ID,
        container_start_time=NOW,
        release_id=release_id(_IMAGE_ID, _IMMUTABLE_SPEC_SHA256),
        inventory_generation=9,
        inventory_revision=7,
    )


def _trigger_projection(trigger: dict[str, object]) -> dict[str, object]:
    fields = trigger["normalized_fields"]
    assert isinstance(fields, dict)
    projection = {
        "schema_version": "agmind.pcc-falco-trigger-projection.v1",
        "event_id": trigger["event_id"],
        "content_sha256": hashlib.sha256(canonical_json(trigger)).hexdigest(),
        "normalized_fields_sha256": trigger["normalized_fields_sha256"],
        "source_sequence": trigger["source_sequence"],
        "source_id": trigger["source_id"],
        "source_version": trigger["source_version"],
        "host_id": trigger["host_id"],
        "boot_id": trigger["boot_id"],
        "event_time": trigger["event_time"],
        "ingest_time": trigger["ingest_time"],
        "clock_uncertainty_ms": trigger["clock_uncertainty_ms"],
        "inventory_generation": trigger["inventory_generation"],
        "inventory_revision": trigger["inventory_revision"],
        "container_id": trigger["container_id"],
        "container_start_time": trigger["container_start_time"],
        "release_id": trigger["release_id"],
        "detector_rule": fields["detector_rule"],
        "detector_rule_version": fields["detector_rule_version"],
        "falco_version": fields["falco_version"],
        "evt_rawres": fields["evt_rawres"],
        "evt_res": fields["evt_res"],
        "successful_connect": fields["successful_connect"],
        "investigation_only": fields["investigation_only"],
        "image_id": fields["image_id"],
        "repo_digests": fields["repo_digests"],
        "immutable_spec_sha256": fields["immutable_spec_sha256"],
        "proc_name": fields["proc_name"],
        "proc_exe_path": fields["proc_exe_path"],
        "proc_parent_name": fields["proc_parent_name"],
        "destination_ipv4": fields["destination_ipv4"],
        "destination_port": fields["destination_port"],
        "l4_protocol": fields["l4_protocol"],
        "missing_required_fields": fields["missing_required_fields"],
        "coverage_flags": trigger["coverage_flags"],
        "raw_event_sha256": fields["raw_event_sha256"],
    }
    return projection


def _request(
    trigger: dict[str, object],
    *,
    ttl_seconds: int = 60,
) -> PCCCorrelationSnapshotRequestV1:
    return PCCCorrelationSnapshotRequestV1.model_validate(
        {
            "schema_version": "agmind.pcc-correlation-snapshot-request.v1",
            "trigger_event_id": trigger["event_id"],
            "trigger_content_sha256": hashlib.sha256(
                canonical_json(trigger)
            ).hexdigest(),
            "trigger_source_sequence": trigger["source_sequence"],
            "requested_ttl_seconds": ttl_seconds,
        },
        strict=True,
    )


def _failed_snapshot(
    trigger: dict[str, object],
    request: PCCCorrelationSnapshotRequestV1,
    *,
    reason: Literal["inventory_stale", "observer_boot_changed"] = "inventory_stale",
    snapshot_sequence: int = 3,
    boundary_chain: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    fields: dict[str, object] = {
        "schema_version": "agmind.pcc-correlation-snapshot.v1",
        "outcome": "failed",
        "request_sha256": pcc_correlation_request_sha256(request),
        "trigger": _trigger_projection(trigger),
        "decision_time": NOW,
        "requested_ttl_seconds": request.requested_ttl_seconds,
        "failure_reasons": [reason],
        "coverage_through_sequence": snapshot_sequence - 1,
        "hard_limits_version": "pcc-hard-limits-v1",
    }
    if boundary_chain is not None:
        fields["boot_transition_hop_count"] = len(boundary_chain)
        fields["boot_transition_chain_sha256"] = hashlib.sha256(
            b"AGMIND_BOOT_TRANSITION_CHAIN_V1\0"
            + canonical_json(boundary_chain)
        ).hexdigest()
    return fields


def _complete_snapshot(
    trigger: dict[str, object],
    request: PCCCorrelationSnapshotRequestV1,
) -> dict[str, object]:
    docker_networks = [
        {
            "network_id": "e" * 64,
            "driver": "bridge",
            "subnet_cidrs": ["172.20.0.0/16"],
            "gateway_addresses": ["172.20.0.1"],
        }
    ]
    operator_networks = ["10.0.0.0/8"]
    operator_addresses = ["203.0.113.10"]
    management_networks = ["192.0.2.0/24"]
    management_addresses = ["198.51.100.10"]
    return {
        "schema_version": "agmind.pcc-correlation-snapshot.v1",
        "outcome": "complete",
        "request_sha256": pcc_correlation_request_sha256(request),
        "trigger": _trigger_projection(trigger),
        "decision_time": NOW,
        "detector_bundle_sha256": "1" * 64,
        "requested_ttl_seconds": request.requested_ttl_seconds,
        "special_use_registry_sha256": (
            "e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73"
        ),
        "operator_denied_networks": operator_networks,
        "operator_denied_addresses": operator_addresses,
        "operator_denylist_sha256": pcc_operator_denylist_sha256(
            operator_networks,
            operator_addresses,
        ),
        "management_denied_networks": management_networks,
        "management_denied_addresses": management_addresses,
        "management_denylist_sha256": pcc_management_denylist_sha256(
            management_networks,
            management_addresses,
        ),
        "docker_networks": docker_networks,
        "docker_network_snapshot_sha256": hashlib.sha256(
            b"AGMIND_DOCKER_NETWORK_SNAPSHOT_V1\0"
            + canonical_json(docker_networks)
        ).hexdigest(),
        "docker_container_id": _CONTAINER_ID,
        "docker_started_at": NOW,
        "image_id": _IMAGE_ID,
        "repo_digests": [],
        "immutable_spec_sha256": _IMMUTABLE_SPEC_SHA256,
        "inventory_generation": 9,
        "inventory_revision": 7,
        "inventory_observed_at": NOW,
        "network_mode": "default",
        "network_driver": "bridge",
        "privileged": False,
        "configured_cap_add": [],
        "configured_cap_drop": [],
        "effective_cap_net_admin": False,
        "running": True,
        "coverage_through_sequence": 2,
        "hard_limits_version": "pcc-hard-limits-v1",
    }


def _snapshot_envelope(
    key: Ed25519PrivateKey,
    fields: dict[str, object],
    *,
    sequence: int = 3,
    boot_id: str = BOOT_A,
    key_epoch: int = 1,
) -> dict[str, object]:
    complete = fields.get("outcome") == "complete"
    return envelope_value(
        key,
        sequence=sequence,
        boot_id=boot_id,
        key_epoch=key_epoch,
        event_type="pcc_correlation_snapshot",
        normalized_fields=fields,
        container_id=_CONTAINER_ID if complete else None,
        container_start_time=NOW if complete else None,
        release_id=(
            release_id(_IMAGE_ID, _IMMUTABLE_SPEC_SHA256)
            if complete
            else None
        ),
        inventory_generation=9 if complete else 0,
        inventory_revision=7 if complete else None,
    )


def _verify(
    verifier: EnvelopeVerifier,
    envelope: dict[str, object],
    *,
    context: PCCCorrelationVerificationContext | None = None,
) -> object:
    return verifier.verify(
        envelope,
        sequence=int(envelope["source_sequence"]),
        event_id=str(envelope["event_id"]),
        content_sha256=hashlib.sha256(canonical_json(envelope)).hexdigest(),
        pcc_context=context,
    )


def test_pcc_snapshot_requires_typed_context_and_is_protected(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / "required-context", key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    snapshot = _snapshot_envelope(key, _failed_snapshot(trigger, request))

    with pytest.raises(PCCSnapshotVerificationError):
        _verify(coordinator.verifier, snapshot)

    verified = _verify(
        coordinator.verifier,
        snapshot,
        context=PCCCorrelationVerificationContext(
            request=request,
        ),
    )
    assert verified.evidence_priority == "protected"
    coordinator.segment_store.close()


def test_pcc_context_is_rejected_for_every_other_event_type(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / "context-scope", key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    ordinary = envelope_value(
        key,
        sequence=3,
        normalized_fields={"kind": "ordinary"},
    )

    with pytest.raises(PCCSnapshotVerificationError):
        _verify(
            coordinator.verifier,
            ordinary,
            context=PCCCorrelationVerificationContext(
                request=request,
            ),
        )
    coordinator.segment_store.close()


def test_complete_pcc_snapshot_binds_envelope_identity_and_is_protected(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / "complete", key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    snapshot = _snapshot_envelope(key, _complete_snapshot(trigger, request))

    verified = _verify(
        coordinator.verifier,
        snapshot,
        context=PCCCorrelationVerificationContext(request=request),
    )

    assert verified.evidence_priority == "protected"
    coordinator.segment_store.close()


@pytest.mark.parametrize(
    "request_mutation",
    ["ttl", "event_id", "content_sha256", "source_sequence"],
)
def test_pcc_snapshot_rejects_a_different_typed_request(
    tmp_path: Path,
    request_mutation: str,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / f"request-{request_mutation}", key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    snapshot = _snapshot_envelope(key, _failed_snapshot(trigger, request))
    context_value = request.model_dump(mode="json")
    if request_mutation == "ttl":
        context_value["requested_ttl_seconds"] = 61
    elif request_mutation == "event_id":
        context_value["trigger_event_id"] = "evt_" + "0" * 64
    elif request_mutation == "content_sha256":
        context_value["trigger_content_sha256"] = "0" * 64
    else:
        context_value["trigger_source_sequence"] = 1
    different = PCCCorrelationSnapshotRequestV1.model_validate(
        context_value,
        strict=True,
    )

    with pytest.raises(PCCSnapshotVerificationError):
        _verify(
            coordinator.verifier,
            snapshot,
            context=PCCCorrelationVerificationContext(request=different),
        )
    coordinator.segment_store.close()


@pytest.mark.parametrize(
    ("projection_field", "wrong_value"),
    [
        ("destination_ipv4", "1.1.1.1"),
        ("source_version", "9.9.9"),
        ("raw_event_sha256", "0" * 64),
    ],
)
def test_pcc_projection_must_equal_the_exact_accepted_trigger(
    tmp_path: Path,
    projection_field: str,
    wrong_value: object,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / f"projection-{projection_field}", key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    fields = _failed_snapshot(trigger, request)
    projection = dict(fields["trigger"])
    projection[projection_field] = wrong_value
    fields["trigger"] = projection

    with pytest.raises(PCCSnapshotVerificationError):
        _verify(
            coordinator.verifier,
            _snapshot_envelope(key, fields),
            context=PCCCorrelationVerificationContext(request=request),
        )
    coordinator.segment_store.close()


@pytest.mark.parametrize(
    "metadata_break",
    [
        "decision_time",
        "ordinary_cross_boot",
        "failed_container_authority",
        "complete_generation",
    ],
)
def test_pcc_snapshot_rejects_inexact_envelope_metadata(
    tmp_path: Path,
    metadata_break: str,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / f"metadata-{metadata_break}", key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    fields = (
        _complete_snapshot(trigger, request)
        if metadata_break == "complete_generation"
        else _failed_snapshot(trigger, request)
    )
    if metadata_break == "decision_time":
        fields["decision_time"] = "2026-07-28T10:00:01Z"
        snapshot = _snapshot_envelope(key, fields)
    elif metadata_break == "ordinary_cross_boot":
        snapshot = _snapshot_envelope(key, fields, boot_id=BOOT_B)
    elif metadata_break == "failed_container_authority":
        snapshot = envelope_value(
            key,
            sequence=3,
            event_type="pcc_correlation_snapshot",
            normalized_fields=fields,
            container_id=_CONTAINER_ID,
        )
    else:
        snapshot = envelope_value(
            key,
            sequence=3,
            event_type="pcc_correlation_snapshot",
            normalized_fields=fields,
            container_id=_CONTAINER_ID,
            container_start_time=NOW,
            release_id=release_id(_IMAGE_ID, _IMMUTABLE_SPEC_SHA256),
            inventory_generation=8,
            inventory_revision=7,
        )

    with pytest.raises(PCCSnapshotVerificationError):
        _verify(
            coordinator.verifier,
            snapshot,
            context=PCCCorrelationVerificationContext(request=request),
        )
    coordinator.segment_store.close()


def test_pcc_schema_cannot_hide_under_another_event_type(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / "hidden-schema", key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    hidden = envelope_value(
        key,
        sequence=3,
        event_type="test_event",
        normalized_fields=_failed_snapshot(trigger, request),
    )

    with pytest.raises(OuterBindingError):
        _verify(coordinator.verifier, hidden)
    coordinator.segment_store.close()


def test_trigger_absence_fails_closed_without_authenticated_retired_range(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / "historical-missing", key)
    _accept(coordinator, boot_boundary(key))
    absent_trigger = _candidate_trigger(key)
    request = _request(absent_trigger)
    snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(absent_trigger, request),
    )

    with pytest.raises(PCCSnapshotVerificationError, match="retired-range"):
        _verify(
            coordinator.verifier,
            snapshot,
            context=PCCCorrelationVerificationContext(
                request=request,
            ),
        )
    coordinator.segment_store.close()


def test_coordinator_has_a_narrow_pcc_append_and_exact_retry(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / "coordinator", key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    item = _item(
        _snapshot_envelope(
            key,
            _failed_snapshot(trigger, request),
        )
    )

    with pytest.raises(PCCSnapshotVerificationError, match="context"):
        coordinator.accept(item)
    first = coordinator.accept_pcc(item, request)
    changed_request = PCCCorrelationSnapshotRequestV1.model_validate(
        {
            **request.model_dump(mode="python"),
            "requested_ttl_seconds": request.requested_ttl_seconds + 1,
        },
        strict=True,
    )
    with pytest.raises(PCCSnapshotVerificationError, match="request"):
        coordinator.accept_pcc(item, changed_request)
    retry = coordinator.accept_pcc(item, request)

    assert retry == first
    assert coordinator.verifier.accepted_ref(item.sequence) == first
    coordinator.segment_store.close()


def test_signed_same_sequence_pcc_conflict_persists_fence_before_context_mismatch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "signed-conflict"
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    persisted_request = _request(trigger, ttl_seconds=60)
    accepted = _item(
        _snapshot_envelope(
            key,
            _failed_snapshot(trigger, persisted_request),
        )
    )
    coordinator.accept_pcc(accepted, persisted_request)

    conflicting_request = _request(trigger, ttl_seconds=61)
    conflicting_fields = _failed_snapshot(trigger, conflicting_request)
    conflicting_projection = dict(conflicting_fields["trigger"])
    conflicting_projection["destination_ipv4"] = "1.1.1.1"
    conflicting_fields["trigger"] = conflicting_projection
    conflict = _item(
        _snapshot_envelope(
            key,
            conflicting_fields,
        )
    )
    with pytest.raises(EnvelopeConflict):
        coordinator.accept_pcc(conflict, persisted_request)

    assert coordinator.verifier.fsm.mutation_read_only is True
    assert coordinator.segment_store.read_only_reason == "evidence_conflict"
    coordinator.segment_store.close(flush=False)

    reopened = SegmentStore(path)
    assert reopened.read_only_reason == "evidence_conflict"
    reopened.close(flush=False)


def test_simulation_cannot_admit_a_new_pcc_snapshot_without_context(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / "simulation", key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(trigger, request),
    )
    item = decode_events_page(canonical_json(page_value(snapshot))).events[0]

    with pytest.raises(PCCSnapshotVerificationError, match="context"):
        coordinator.verifier._new_control_simulation().advance(item)
    coordinator.segment_store.close()


def _cross_boot_case(
    path: Path,
    mode: Literal["a", "b", "c"],
) -> tuple[
    AcceptanceCoordinator,
    PCCCorrelationSnapshotRequestV1,
    dict[str, object],
]:
    old_key = private_key(11)
    new_key = private_key(12)
    if mode == "a":
        coordinator = _coordinator(path, old_key)
        _accept(coordinator, boot_boundary(old_key))
        trigger = _candidate_trigger(old_key)
        _accept(coordinator, trigger)
        boundary = boot_boundary(
            old_key,
            sequence=3,
            boot_id=BOOT_B,
            previous_boot_id=BOOT_A,
            previous_source_sequence=2,
        )
        _accept(coordinator, boundary)
        hop = {
            "boundary_event_type": "observer_boot_boundary",
            "event_id": boundary["event_id"],
            "content_sha256": hashlib.sha256(canonical_json(boundary)).hexdigest(),
            "source_sequence": 3,
            "boot_id": BOOT_B,
            "previous_boot_id": BOOT_A,
            "previous_source_sequence": 2,
        }
        signing_key = old_key
        key_epoch = 1
        snapshot_sequence = 4
    else:
        rotation = rotation_pair(
            old_key,
            new_key,
            transition_sequence=3,
            transition_boot=BOOT_B if mode == "b" else BOOT_A,
            start_boot=BOOT_B,
            mode=mode,
        )
        coordinator = _coordinator(path, old_key, rotation=rotation)
        _accept(coordinator, boot_boundary(old_key))
        trigger = _candidate_trigger(old_key)
        _accept(coordinator, trigger)
        transition = rotation[1]
        start = rotation[2]
        _accept(coordinator, transition)
        _accept(coordinator, start)
        boundary = transition if mode == "b" else start
        companion = start if mode == "b" else transition
        hop = {
            "boundary_event_type": boundary["event_type"],
            "event_id": boundary["event_id"],
            "content_sha256": hashlib.sha256(canonical_json(boundary)).hexdigest(),
            "source_sequence": boundary["source_sequence"],
            "boot_id": BOOT_B,
            "previous_boot_id": BOOT_A,
            "previous_source_sequence": 2 if mode == "b" else 3,
            "rotation_companion_event_type": companion["event_type"],
            "rotation_companion_event_id": companion["event_id"],
            "rotation_companion_content_sha256": hashlib.sha256(
                canonical_json(companion)
            ).hexdigest(),
            "rotation_companion_source_sequence": companion["source_sequence"],
            "rotation_companion_boot_id": companion["boot_id"],
        }
        signing_key = new_key
        key_epoch = 2
        snapshot_sequence = 5
    request = _request(trigger)
    fields = _failed_snapshot(
        trigger,
        request,
        reason="observer_boot_changed",
        snapshot_sequence=snapshot_sequence,
        boundary_chain=[hop],
    )
    snapshot = _snapshot_envelope(
        signing_key,
        fields,
        sequence=snapshot_sequence,
        boot_id=BOOT_B,
        key_epoch=key_epoch,
    )
    return coordinator, request, snapshot


@pytest.mark.parametrize("mode", ["a", "b", "c"])
def test_cross_boot_terminal_snapshot_recomputes_protected_abc_chain(
    tmp_path: Path,
    mode: Literal["a", "b", "c"],
) -> None:
    coordinator, request, snapshot = _cross_boot_case(tmp_path / mode, mode)

    verified = _verify(
        coordinator.verifier,
        snapshot,
        context=PCCCorrelationVerificationContext(request=request),
    )

    assert verified.evidence_priority == "protected"
    coordinator.segment_store.close()


def test_cross_boot_terminal_snapshot_rejects_a_forged_chain_hash(
    tmp_path: Path,
) -> None:
    coordinator, request, snapshot = _cross_boot_case(tmp_path / "forged", "b")
    fields = dict(snapshot["normalized_fields"])
    fields["boot_transition_chain_sha256"] = "0" * 64
    forged = _snapshot_envelope(
        private_key(12),
        fields,
        sequence=5,
        boot_id=BOOT_B,
        key_epoch=2,
    )

    with pytest.raises(PCCSnapshotVerificationError):
        _verify(
            coordinator.verifier,
            forged,
            context=PCCCorrelationVerificationContext(request=request),
        )
    coordinator.segment_store.close()


def test_cross_boot_b_snapshot_and_hop_ledger_survive_recovery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "recovery-b"
    coordinator, request, snapshot = _cross_boot_case(path, "b")
    item = _item(snapshot)
    expected_ref = coordinator.accept_pcc(item, request)
    expected_ledger = coordinator.verifier.fsm.pcc_boot_transition_hops
    assert len(expected_ledger) == 1
    assert expected_ledger[0].boundary_event_type == "observer_key_transition"
    assert expected_ledger[0].previous_source_sequence == 2
    coordinator.segment_store.flush_security_boundary()
    coordinator.segment_store.close()

    old_key = private_key(11)
    rotation = rotation_pair(
        old_key,
        private_key(12),
        transition_sequence=3,
        transition_boot=BOOT_B,
        start_boot=BOOT_B,
        mode="b",
    )
    root, chain = _identity(old_key, rotation=rotation)
    recovered_store = SegmentStore(path)
    recovered = AcceptanceCoordinator.open_and_recover(
        EnvelopeVerifier(root, chain),
        recovered_store,
    )

    assert recovered.verifier.fsm.pcc_boot_transition_hops == expected_ledger
    assert recovered.verifier.accepted_ref(item.sequence) == expected_ref
    assert recovered.accept_pcc(item, request) == expected_ref
    recovered_store.close()
