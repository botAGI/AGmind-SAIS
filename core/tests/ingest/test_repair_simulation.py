from __future__ import annotations

import copy
from pathlib import Path

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import (
    EvidenceRepairAuthorizeV1,
    EvidenceRepairCompleteV1,
    ObserverTrustRootV1,
)
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceSealError,
    SegmentStore,
)
from agmind_immune.ingest import envelope as ingest_envelope
from agmind_immune.ingest.envelope import (
    CoreEventV1,
    EnvelopeSignatureError,
    EnvelopeVerifier,
    VerifierCommitError,
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
    rotation_pair,
)


def _item(envelope: dict[str, object]) -> CoreEventV1:
    return ingest_envelope.decode_events_page(
        canonical_json(page_value(envelope))
    ).events[0]


def _authorization_request() -> EvidenceRepairAuthorizeV1:
    return EvidenceRepairAuthorizeV1.model_validate(
        {
            "schema_version": "agmind.evidence-repair-authorize.v1",
            "repair_id": "11111111-1111-4111-8111-111111111111",
            "segment_id": "22222222-2222-4222-8222-222222222222",
            "verified_bytes": 4096,
            "discarded_bytes": 512,
            "discarded_sha256": "1" * 64,
            "last_verified_frame_sha256": "2" * 64,
            "current_chain_head_sha256": "3" * 64,
            "reason": "torn_open_tail",
        },
        strict=True,
    )


def _completion_request(
    authorization: CoreEventV1,
    *,
    authorization_event_id: str | None = None,
    authorization_content_sha256: str | None = None,
) -> EvidenceRepairCompleteV1:
    return EvidenceRepairCompleteV1.model_validate(
        {
            "schema_version": "agmind.evidence-repair-complete.v1",
            "repair_id": "11111111-1111-4111-8111-111111111111",
            "authorization_event_id": (
                authorization.event_id
                if authorization_event_id is None
                else authorization_event_id
            ),
            "authorization_content_sha256": (
                authorization.content_sha256
                if authorization_content_sha256 is None
                else authorization_content_sha256
            ),
            "segment_id": "22222222-2222-4222-8222-222222222222",
            "verified_bytes": 4096,
            "post_repair_prefix_sha256": "4" * 64,
            "last_verified_frame_sha256": "2" * 64,
            "current_chain_head_sha256": "3" * 64,
            "reason": "torn_open_tail_completed",
        },
        strict=True,
    )


def _bound_verifier(
    path: Path,
) -> tuple[AcceptanceCoordinator, SegmentStore, EnvelopeVerifier]:
    key = private_key(11)
    root = ingest_envelope.PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key), strict=True)
    )
    chain = ingest_envelope.AnchoredPublicKeyChain.from_value(
        root,
        metadata_value(key),
    )
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    coordinator.accept(_item(boot_boundary(key)))
    return coordinator, store, coordinator.verifier


def _bound_rotating_verifier(
    path: Path,
) -> tuple[
    AcceptanceCoordinator,
    SegmentStore,
    EnvelopeVerifier,
    tuple[dict[str, object], dict[str, object], dict[str, object]],
]:
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
    root = ingest_envelope.PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(old_key), strict=True)
    )
    chain = ingest_envelope.AnchoredPublicKeyChain.from_value(
        root,
        metadata_value(old_key, rotation=rotation),
    )
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    coordinator.accept(_item(boot_boundary(old_key)))
    return coordinator, store, coordinator.verifier, rotation


def test_exact_authorization_simulation_cannot_append_or_mutate_live_verifier(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    _coordinator, store, verifier = _bound_verifier(tmp_path)
    request = _authorization_request()
    direct = _item(
        envelope_value(
            key,
            sequence=2,
            event_type="evidence_repair_authorized",
            normalized_fields=request.model_dump(),
        )
    )
    authority_before = verifier._authority
    stages_before = dict(verifier._staged)
    authorizations_before = dict(verifier._authorizations)

    assert hasattr(verifier, "_new_repair_simulation")
    simulation = verifier._new_repair_simulation()
    proof = simulation.verify_exact_authorization(request, direct, (direct,))

    assert type(proof) is ingest_envelope.SimulatedRepairAuthorization
    assert type(proof.target) is ingest_envelope.SimulatedEvent
    assert proof.request == request
    assert proof.base_generation == authority_before.generation
    assert verifier._validate_repair_authorization_proof(proof) is proof
    assert verifier._authority is authority_before
    assert verifier._staged == stages_before
    assert verifier._authorizations == authorizations_before
    with pytest.raises(EvidenceSealError, match="verifier-staged"):
        store.append(proof.target, EvidencePriority.PROTECTED)  # type: ignore[arg-type]
    store.close(flush=False)


def test_exact_completion_requires_the_simulated_authorization_identity(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    _coordinator, store, verifier = _bound_verifier(tmp_path)
    authorization_request = _authorization_request()
    authorization = _item(
        envelope_value(
            key,
            sequence=2,
            event_type="evidence_repair_authorized",
            normalized_fields=authorization_request.model_dump(),
        )
    )
    wrong_request = _completion_request(
        authorization,
        authorization_event_id="evt_" + "5" * 64,
        authorization_content_sha256="6" * 64,
    )
    completion = _item(
        envelope_value(
            key,
            sequence=3,
            event_type="evidence_repair_completed",
            normalized_fields=wrong_request.model_dump(),
        )
    )

    simulation = verifier._new_repair_simulation()
    with pytest.raises(
        ingest_envelope.RepairSimulationError,
        match="authorization",
    ):
        simulation.verify_exact_completion(
            wrong_request,
            completion,
            (authorization, completion),
        )
    store.close(flush=False)


def test_repair_proof_validator_rejects_a_caller_created_lookalike(
    tmp_path: Path,
) -> None:
    _coordinator, store, verifier = _bound_verifier(tmp_path)
    with pytest.raises(VerifierCommitError, match="foreign"):
        verifier._validate_repair_authorization_proof(object())  # type: ignore[arg-type]
    store.close(flush=False)


def test_repair_proof_validator_detects_mutated_target_presentation(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    _coordinator, store, verifier = _bound_verifier(tmp_path)
    request = _authorization_request()
    direct = _item(
        envelope_value(
            key,
            sequence=2,
            event_type="evidence_repair_authorized",
            normalized_fields=request.model_dump(),
        )
    )
    proof = verifier._new_repair_simulation().verify_exact_authorization(
        request,
        direct,
        (direct,),
    )

    object.__setattr__(proof.target, "_event_id", "evt_" + "0" * 64)
    with pytest.raises(VerifierCommitError, match="inexact"):
        verifier._validate_repair_authorization_proof(proof)
    store.close(flush=False)


def test_exact_completion_returns_a_separate_non_appendable_proof(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    _coordinator, store, verifier = _bound_verifier(tmp_path)
    authorization_request = _authorization_request()
    authorization = _item(
        envelope_value(
            key,
            sequence=2,
            event_type="evidence_repair_authorized",
            normalized_fields=authorization_request.model_dump(),
        )
    )
    completion_request = _completion_request(authorization)
    completion = _item(
        envelope_value(
            key,
            sequence=3,
            event_type="evidence_repair_completed",
            normalized_fields=completion_request.model_dump(),
        )
    )
    authority_before = verifier._authority

    proof = verifier._new_repair_simulation().verify_exact_completion(
        completion_request,
        completion,
        (authorization, completion),
    )

    assert type(proof) is ingest_envelope.SimulatedRepairCompletion
    assert proof.request == completion_request
    assert proof.target.event_id == completion.event_id
    assert verifier._validate_repair_completion_proof(proof) is proof
    assert verifier._authority is authority_before
    with pytest.raises(EvidenceSealError, match="verifier-staged"):
        store.append(proof.target, EvidencePriority.PROTECTED)  # type: ignore[arg-type]
    store.close(flush=False)


def test_simulation_privately_advances_an_anchored_key_rotation(
    tmp_path: Path,
) -> None:
    new_key = private_key(12)
    _coordinator, store, verifier, rotation = _bound_rotating_verifier(
        tmp_path
    )
    request = _authorization_request()
    direct = _item(
        envelope_value(
            new_key,
            sequence=4,
            key_epoch=2,
            event_type="evidence_repair_authorized",
            normalized_fields=request.model_dump(),
        )
    )
    transition = _item(rotation[1])
    epoch_start = _item(rotation[2])
    authority_before = verifier._authority

    proof = verifier._new_repair_simulation().verify_exact_authorization(
        request,
        direct,
        (transition, epoch_start, direct),
    )

    assert proof.target.key_epoch == 2
    assert verifier.fsm.active_epoch == 1
    assert verifier._authority is authority_before
    assert verifier._staged == {}
    assert verifier._authorizations == {}
    store.close(flush=False)


def test_simulation_rejects_a_bad_signature_without_partial_live_state(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    _coordinator, store, verifier = _bound_verifier(tmp_path)
    request = _authorization_request()
    envelope = envelope_value(
        key,
        sequence=2,
        event_type="evidence_repair_authorized",
        normalized_fields=request.model_dump(),
    )
    bad_envelope = copy.deepcopy(envelope)
    bad_envelope["source_signature"] = "0" * 128
    direct = _item(bad_envelope)
    authority_before = verifier._authority

    with pytest.raises(EnvelopeSignatureError):
        verifier._new_repair_simulation().verify_exact_authorization(
            request,
            direct,
            (direct,),
        )
    assert verifier._authority is authority_before
    assert verifier._staged == {}
    assert verifier._authorizations == {}
    store.close(flush=False)


def test_authorization_proof_is_stale_after_live_authority_advances(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    coordinator, store, verifier = _bound_verifier(tmp_path)
    request = _authorization_request()
    direct = _item(
        envelope_value(
            key,
            sequence=2,
            event_type="evidence_repair_authorized",
            normalized_fields=request.model_dump(),
        )
    )
    proof = verifier._new_repair_simulation().verify_exact_authorization(
        request,
        direct,
        (direct,),
    )
    coordinator.accept(
        _item(
            envelope_value(
                key,
                sequence=2,
                normalized_fields={"kind": "live-authority-advanced"},
            )
        )
    )

    with pytest.raises(VerifierCommitError, match="stale"):
        verifier._validate_repair_authorization_proof(proof)
    store.close(flush=False)


def test_restricted_historical_replay_never_calls_live_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = private_key(11)
    coordinator, store, verifier = _bound_verifier(tmp_path)
    authorization_request = _authorization_request()
    authorization = _item(
        envelope_value(
            key,
            sequence=2,
            event_type="evidence_repair_authorized",
            normalized_fields=authorization_request.model_dump(),
        )
    )
    authorization_ref = coordinator.accept(authorization)
    completion_request = _completion_request(authorization)
    completion = _item(
        envelope_value(
            key,
            sequence=3,
            event_type="evidence_repair_completed",
            normalized_fields=completion_request.model_dump(),
        )
    )
    completion_ref = coordinator.accept(completion)
    authority_before = verifier._authority
    stages_before = dict(verifier._staged)

    def live_verify_is_forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("restricted replay invoked live verify")

    monkeypatch.setattr(verifier, "verify", live_verify_is_forbidden)
    replayed = verifier._restricted_historical_replay(
        (
            (authorization, authorization_ref),
            (completion, completion_ref),
        )
    )

    assert [event.event_type for event in replayed] == [
        "evidence_repair_authorized",
        "evidence_repair_completed",
    ]
    assert all(event.is_retry for event in replayed)
    assert verifier._authority is authority_before
    assert verifier._staged == stages_before
    assert verifier._authorizations == {}
    with pytest.raises(
        ingest_envelope.RepairSimulationError,
        match="strictly increasing",
    ):
        verifier._restricted_historical_replay(
            (
                (completion, completion_ref),
                (authorization, authorization_ref),
            )
        )
    store.close(flush=False)


def test_simulation_has_no_reference_back_to_live_verifier_or_store(
    tmp_path: Path,
) -> None:
    _coordinator, store, verifier = _bound_verifier(tmp_path)
    simulation = verifier._new_repair_simulation()

    assert not hasattr(simulation, "_verifier_ref")
    assert not hasattr(simulation, "_bound_lifecycle")
    assert not hasattr(simulation, "__dict__")
    store.close(flush=False)


def test_live_stage_created_after_simulation_invalidates_authorization_proof(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    _coordinator, store, verifier = _bound_verifier(tmp_path)
    request = _authorization_request()
    direct = _item(
        envelope_value(
            key,
            sequence=2,
            event_type="evidence_repair_authorized",
            normalized_fields=request.model_dump(),
        )
    )
    proof = verifier._new_repair_simulation().verify_exact_authorization(
        request,
        direct,
        (direct,),
    )
    staged = verifier.verify(
        direct.envelope,
        sequence=direct.sequence,
        event_id=direct.event_id,
        content_sha256=direct.content_sha256,
    )
    assert staged.source_sequence == direct.sequence
    assert verifier._authority.generation == proof.base_generation

    with pytest.raises(VerifierCommitError, match="stale"):
        verifier._validate_repair_authorization_proof(proof)
    store.close(flush=False)
