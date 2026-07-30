from __future__ import annotations

import copy
import importlib
import pickle
from pathlib import Path

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import EventEnvelopeV1
from agmind_immune.correlation.pcc import (
    CorrelationContext,
    correlate_pcc,
    incident_from_retained_trigger,
    incident_from_verified_falco,
)
from agmind_immune.evidence.segments import EvidenceRef
from agmind_immune.ingest.envelope import (
    AuthenticatedFalcoInput,
    AuthenticatedPCCInput,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.evidence.test_retention_restart import _fresh_verifier
from tests.ingest.test_pcc_correlation_snapshot import (
    _accept,
    _candidate_trigger,
    _complete_snapshot,
    _coordinator,
    _item,
    _request,
    _snapshot_envelope,
)
from tests.phase5b_helpers import boot_boundary, private_key


def _accepted_pcc(
    path: Path,
) -> tuple[AcceptanceCoordinator, object, object]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    item = _item(
        _snapshot_envelope(
            key,
            _complete_snapshot(trigger, request),
        )
    )
    return coordinator, item, request


def _accepted_falco(
    path: Path,
) -> tuple[AcceptanceCoordinator, EvidenceRef]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    ref = _accept(coordinator, _candidate_trigger(key))
    assert type(ref) is EvidenceRef
    return coordinator, ref


def test_authenticated_pcc_input_has_no_public_constructor(
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError):
        AuthenticatedPCCInput()  # type: ignore[call-arg]

    coordinator, item, request = _accepted_pcc(tmp_path)
    try:
        capability = coordinator.accept_pcc_for_correlation(
            item,
            request,
        )

        assert type(capability) is AuthenticatedPCCInput
        assert capability.snapshot.outcome == "complete"
        assert capability.event_type == "pcc_correlation_snapshot"
        assert capability.request == request
        assert capability.evidence_ref == coordinator.verifier.accepted_ref(
            item.sequence
        )
        coordinator.segment_store.resolve_authenticated_ref(
            capability.evidence_ref
        )
    finally:
        coordinator.segment_store.close()


def test_imported_factory_marker_cannot_forge_reducer_authority(
    tmp_path: Path,
) -> None:
    del tmp_path
    envelope_module = importlib.import_module(
        "agmind_immune.ingest.envelope"
    )

    assert not hasattr(
        envelope_module,
        "_AUTHENTICATED_PCC_INPUT_FACTORY",
    )
    assert not hasattr(
        envelope_module,
        "_AUTHENTICATED_FALCO_INPUT_FACTORY",
    )


def test_unissued_exact_instance_cannot_enter_the_reducer() -> None:
    forged = object.__new__(AuthenticatedPCCInput)

    with pytest.raises(TypeError, match="issued"):
        correlate_pcc(forged, CorrelationContext.failed_snapshot())


@pytest.mark.parametrize("copier", [copy.copy, copy.deepcopy])
def test_copy_of_issued_capability_cannot_gain_reducer_authority(
    tmp_path: Path,
    copier: object,
) -> None:
    coordinator, item, request = _accepted_pcc(tmp_path)
    try:
        issued = coordinator.accept_pcc_for_correlation(item, request)
        with pytest.raises(TypeError):
            copied = copier(issued)  # type: ignore[operator]
            correlate_pcc(copied, CorrelationContext.failed_snapshot())
    finally:
        coordinator.segment_store.close()


def test_pickled_capability_cannot_gain_reducer_authority(
    tmp_path: Path,
) -> None:
    coordinator, item, request = _accepted_pcc(tmp_path)
    try:
        issued = coordinator.accept_pcc_for_correlation(item, request)

        with pytest.raises(TypeError):
            restored = pickle.loads(pickle.dumps(issued))
            correlate_pcc(restored, CorrelationContext.failed_snapshot())
    finally:
        coordinator.segment_store.close()


def test_issued_capability_binds_strict_canonical_envelope(
    tmp_path: Path,
) -> None:
    coordinator, item, request = _accepted_pcc(tmp_path)
    try:
        issued = coordinator.accept_pcc_for_correlation(item, request)

        assert issued.canonical == canonical_json(
            EventEnvelopeV1.model_validate_json(
                issued.canonical,
                strict=True,
            )
        )
    finally:
        coordinator.segment_store.close()


def test_mutating_an_issued_pcc_capability_invalidates_its_authority(
    tmp_path: Path,
) -> None:
    coordinator, item, request = _accepted_pcc(tmp_path)
    try:
        issued = coordinator.accept_pcc_for_correlation(item, request)
        object.__setattr__(issued, "_event_id", "evt_" + "0" * 64)

        with pytest.raises(TypeError, match="binding"):
            incident_from_retained_trigger(issued)
    finally:
        coordinator.segment_store.close()


@pytest.mark.parametrize(
    "mutation",
    [
        "boot_id",
        "canonical",
        "content_sha256",
        "event_type",
        "evidence_ref",
        "host_id",
        "request",
        "snapshot_trigger",
        "source_sequence",
    ],
)
def test_every_pcc_authority_binding_is_rechecked_at_use(
    tmp_path: Path,
    mutation: str,
) -> None:
    coordinator, item, request = _accepted_pcc(tmp_path / mutation)
    try:
        issued = coordinator.accept_pcc_for_correlation(item, request)
        if mutation == "boot_id":
            object.__setattr__(issued, "_boot_id", "0" * 36)
        elif mutation == "canonical":
            object.__setattr__(issued, "_canonical", b"{}")
        elif mutation == "content_sha256":
            object.__setattr__(issued, "_content_sha256", "0" * 64)
        elif mutation == "event_type":
            object.__setattr__(issued, "_event_type", "falco_connect")
        elif mutation == "evidence_ref":
            object.__setattr__(issued, "_evidence_ref", object())
        elif mutation == "host_id":
            object.__setattr__(issued, "_host_id", "0" * 36)
        elif mutation == "request":
            object.__setattr__(
                issued.request,
                "requested_ttl_seconds",
                30,
            )
        elif mutation == "snapshot_trigger":
            object.__setattr__(
                issued.snapshot.trigger,
                "destination_port",
                8443,
            )
        else:
            object.__setattr__(issued, "_source_sequence", 1)

        with pytest.raises(TypeError, match="binding"):
            incident_from_retained_trigger(issued)
    finally:
        coordinator.segment_store.close()


def test_exact_retry_and_recovery_export_the_same_committed_pcc(
    tmp_path: Path,
) -> None:
    coordinator, item, request = _accepted_pcc(tmp_path)
    first = coordinator.accept_pcc_for_correlation(item, request)
    retry = coordinator.accept_pcc_for_correlation(item, request)
    coordinator.segment_store.close()

    recovered = AcceptanceCoordinator.open_and_recover(
        _fresh_verifier(),
        coordinator.segment_store.__class__(tmp_path),
    )
    try:
        replay = recovered.authenticated_pcc_input(
            first.evidence_ref,
            request,
        )

        assert retry.evidence_ref == first.evidence_ref
        assert retry.canonical == first.canonical
        assert replay.evidence_ref == first.evidence_ref
        assert replay.canonical == first.canonical
    finally:
        recovered.segment_store.close(flush=False)


def test_falco_capability_is_issued_only_from_its_committed_record(
    tmp_path: Path,
) -> None:
    coordinator, ref = _accepted_falco(tmp_path)
    try:
        capability = coordinator.authenticated_falco_input(ref)

        assert type(capability) is AuthenticatedFalcoInput
        assert capability.evidence_ref == ref
        assert capability.event_type == "falco_connect"
        assert capability.canonical == canonical_json(
            EventEnvelopeV1.model_validate_json(
                capability.canonical,
                strict=True,
            )
        )
    finally:
        coordinator.segment_store.close()


def test_unissued_or_copied_falco_capability_has_no_incident_authority(
    tmp_path: Path,
) -> None:
    forged = object.__new__(AuthenticatedFalcoInput)
    with pytest.raises(TypeError, match="issued"):
        incident_from_verified_falco(forged)

    coordinator, ref = _accepted_falco(tmp_path)
    try:
        issued = coordinator.authenticated_falco_input(ref)
        for copier in (copy.copy, copy.deepcopy):
            with pytest.raises(TypeError):
                copied = copier(issued)
                incident_from_verified_falco(copied)
        with pytest.raises(TypeError):
            restored = pickle.loads(pickle.dumps(issued))
            incident_from_verified_falco(restored)
    finally:
        coordinator.segment_store.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("_boot_id", "0" * 36),
        ("_canonical", b"{}"),
        ("_content_sha256", "0" * 64),
        ("_coverage_flags", ("forged",)),
        ("_event_id", "evt_" + "0" * 64),
        ("_event_time", "2026-07-28T10:00:01Z"),
        ("_evidence_ref", object()),
        ("_falco_canonical", b"{}"),
        ("_host_id", "0" * 36),
        ("_ingest_time", "2026-07-28T10:00:01Z"),
        ("_source_sequence", 1),
    ],
)
def test_every_falco_authority_binding_is_rechecked_at_use(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    coordinator, ref = _accepted_falco(tmp_path / field)
    try:
        issued = coordinator.authenticated_falco_input(ref)
        object.__setattr__(issued, field, value)

        with pytest.raises(TypeError, match="issued"):
            incident_from_verified_falco(issued)
    finally:
        coordinator.segment_store.close()


def test_recovered_falco_record_reissues_the_same_exact_capability_facts(
    tmp_path: Path,
) -> None:
    coordinator, ref = _accepted_falco(tmp_path)
    first = coordinator.authenticated_falco_input(ref)
    coordinator.segment_store.close()
    recovered = AcceptanceCoordinator.open_and_recover(
        _fresh_verifier(),
        coordinator.segment_store.__class__(tmp_path),
    )
    try:
        replay = recovered.authenticated_falco_input(ref)

        assert replay.evidence_ref == first.evidence_ref
        assert replay.canonical == first.canonical
        assert replay.falco == first.falco
    finally:
        recovered.segment_store.close(flush=False)
