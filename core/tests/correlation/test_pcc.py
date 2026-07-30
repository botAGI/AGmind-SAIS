from __future__ import annotations

import hashlib
import importlib
import inspect
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from agmind_immune.canonicaljson import (
    candidate_id,
    canonical_json,
    event_id,
    event_signing_message,
    pcc_docker_network_snapshot_sha256,
    pcc_management_denylist_sha256,
    pcc_operator_denylist_sha256,
)
from agmind_immune.contracts import PCCDockerNetworkV1
from agmind_immune.correlation.pcc import (
    ActiveCandidateObservation,
    CandidateCreated,
    CandidateDuplicateKey,
    CorrelationContext,
    CorrelationProjectionError,
    Duplicate,
    HistoricalCoverageAssessment,
    Rejected,
    TerminalCandidateObservation,
    correlate_pcc,
    correlate_pcc_facts,
)
from agmind_immune.correlation.primitives import (
    load_pinned_special_use_registry,
)
from agmind_immune.ingest.envelope import (
    AuthenticatedFalcoInput,
    AuthenticatedPCCInput,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.ingest.test_pcc_correlation_snapshot import (
    _accept,
    _candidate_trigger,
    _complete_snapshot,
    _coordinator,
    _failed_snapshot,
    _item,
    _request,
    _snapshot_envelope,
)
from tests.phase5b_helpers import NOW, boot_boundary, private_key

_REGISTRY_PATH = Path("contracts/v1/ipv4-special-use.csv")
_PINNED_DETECTOR = "1" * 64
_COVERAGE_SHA256 = "2" * 64


def _resign(
    envelope: dict[str, object],
    key: Ed25519PrivateKey,
) -> None:
    normalized = envelope["normalized_fields"]
    assert isinstance(normalized, dict)
    normalized_sha256 = hashlib.sha256(
        canonical_json(normalized)
    ).hexdigest()
    envelope["normalized_fields_sha256"] = normalized_sha256
    envelope["event_id"] = event_id(
        SimpleNamespace(
            host_id=envelope["host_id"],
            boot_id=envelope["boot_id"],
            key_epoch=envelope["key_epoch"],
            source_sequence=envelope["source_sequence"],
            normalized_fields_sha256=normalized_sha256,
        )
    )
    envelope["source_signature"] = key.sign(
        event_signing_message(envelope)
    ).hex()


def _rehash_snapshot(fields: dict[str, object]) -> None:
    raw_networks = fields["docker_networks"]
    assert isinstance(raw_networks, list)
    networks = tuple(
        PCCDockerNetworkV1.model_validate(value, strict=True)
        for value in raw_networks
    )
    fields["docker_network_snapshot_sha256"] = (
        pcc_docker_network_snapshot_sha256(
            networks,
        )
    )
    fields["operator_denylist_sha256"] = pcc_operator_denylist_sha256(
        fields["operator_denied_networks"],
        fields["operator_denied_addresses"],
    )
    fields["management_denylist_sha256"] = (
        pcc_management_denylist_sha256(
            fields["management_denied_networks"],
            fields["management_denied_addresses"],
        )
    )


def _accepted_complete(
    path: Path,
    *,
    destination_ipv4: str = "8.8.8.8",
    destination_port: int = 443,
    l4_protocol: str = "tcp",
    ttl_seconds: int = 60,
    trigger_event_time: str = NOW,
    snapshot_change: Callable[[dict[str, object]], None] | None = None,
) -> tuple[AcceptanceCoordinator, AuthenticatedPCCInput]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    trigger_fields = trigger["normalized_fields"]
    assert isinstance(trigger_fields, dict)
    trigger_fields["destination_ipv4"] = destination_ipv4
    trigger_fields["destination_port"] = destination_port
    trigger_fields["l4_protocol"] = l4_protocol
    trigger_fields["event_time"] = trigger_event_time
    trigger["event_time"] = trigger_event_time
    trigger["ingest_time"] = trigger_event_time
    _resign(trigger, key)
    _accept(coordinator, trigger)

    request = _request(trigger, ttl_seconds=ttl_seconds)
    fields = _complete_snapshot(trigger, request)
    if snapshot_change is not None:
        snapshot_change(fields)
    _rehash_snapshot(fields)
    snapshot = _snapshot_envelope(key, fields)
    decision_time = cast(str, fields["decision_time"])
    snapshot["event_time"] = decision_time
    snapshot["ingest_time"] = decision_time
    _resign(snapshot, key)
    capability = coordinator.accept_pcc_for_correlation(
        _item(snapshot),
        request,
    )
    return coordinator, capability


def _accepted_failed(
    path: Path,
) -> tuple[AcceptanceCoordinator, AuthenticatedPCCInput]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger)
    snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(trigger, request),
    )
    return (
        coordinator,
        coordinator.accept_pcc_for_correlation(
            _item(snapshot),
            request,
        ),
    )


def _accepted_direct_falco(
    path: Path,
    *,
    investigation_only: bool,
) -> tuple[AcceptanceCoordinator, AuthenticatedFalcoInput]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    fields = trigger["normalized_fields"]
    assert isinstance(fields, dict)
    fields["investigation_only"] = investigation_only
    _resign(trigger, key)
    ref = _accept(coordinator, trigger)
    return coordinator, coordinator.authenticated_falco_input(ref)


def _duplicate_key(
    authenticated: AuthenticatedPCCInput,
) -> CandidateDuplicateKey:
    snapshot = authenticated.snapshot
    assert snapshot.outcome == "complete"
    assert snapshot.docker_container_id is not None
    assert snapshot.docker_started_at is not None
    assert snapshot.detector_bundle_sha256 is not None
    return CandidateDuplicateKey(
        host_id=authenticated.host_id,
        boot_id=authenticated.boot_id,
        docker_container_id=snapshot.docker_container_id,
        docker_started_at=snapshot.docker_started_at,
        detector_bundle_sha256=snapshot.detector_bundle_sha256,
        destination_ipv4=snapshot.trigger.destination_ipv4,
    )


def _context(
    authenticated: AuthenticatedPCCInput,
    *,
    detector_pin: str = _PINNED_DETECTOR,
    coverage_complete: bool = True,
    critical_gap: bool = False,
    lookup_key: CandidateDuplicateKey | None = None,
    active_duplicate: ActiveCandidateObservation | None = None,
    terminal_observation: TerminalCandidateObservation | None = None,
) -> CorrelationContext:
    snapshot = authenticated.snapshot
    trigger = snapshot.trigger
    coverage = HistoricalCoverageAssessment(
        host_id=authenticated.host_id,
        boot_id=authenticated.boot_id,
        trigger_event_id=trigger.event_id,
        trigger_source_sequence=trigger.source_sequence,
        coverage_through_sequence=snapshot.coverage_through_sequence,
        window_start=trigger.event_time,
        window_end=snapshot.decision_time,
        complete=coverage_complete,
        critical_gap=critical_gap,
        coverage_snapshot_sha256=(
            _COVERAGE_SHA256 if coverage_complete else None
        ),
    )
    return CorrelationContext(
        pinned_detector_bundle_sha256=detector_pin,
        special_use_registry=load_pinned_special_use_registry(
            _REGISTRY_PATH
        ),
        coverage=coverage,
        lookup_key=(
            _duplicate_key(authenticated)
            if lookup_key is None
            else lookup_key
        ),
        active_duplicate=active_duplicate,
        terminal_observation=terminal_observation,
    )


def _reason(result: object) -> tuple[str, ...]:
    assert isinstance(result, Rejected)
    return cast(tuple[str, ...], result.reason_codes)


def _correlate_facts(
    authenticated: AuthenticatedPCCInput,
    context: CorrelationContext,
) -> object:
    return correlate_pcc_facts(
        authenticated.snapshot.trigger,
        authenticated,
        context,
    )


def test_public_reducer_has_no_now_or_model_input_and_raw_kernel_builds_facts(
    tmp_path: Path,
) -> None:
    assert tuple(inspect.signature(correlate_pcc).parameters) == (
        "authenticated",
        "context",
    )
    assert "model" not in CorrelationContext.__dataclass_fields__
    with pytest.raises((TypeError, ValueError)):
        CorrelationContext()
    assert not hasattr(
        importlib.import_module("agmind_immune.correlation.pcc"),
        "_CORRELATION_CONTEXT_FACTORY",
    )

    coordinator, authenticated = _accepted_complete(tmp_path)
    try:
        public_result = correlate_pcc(
            authenticated,
            _context(authenticated),
        )
        result = _correlate_facts(
            authenticated,
            _context(authenticated),
        )

        assert _reason(public_result) == ("correlation_proof_mismatch",)
        assert isinstance(result, CandidateCreated)
        assert result.incident.reason_codes == ()
        assert result.candidate.primary_event_id == (
            authenticated.snapshot.trigger.event_id
        )
        assert result.candidate.correlation_snapshot_event_id == (
            authenticated.event_id
        )
        assert result.candidate.evidence_ids == tuple(
            sorted(
                (
                    authenticated.event_id,
                    authenticated.snapshot.trigger.event_id,
                )
            )
        )
        assert result.candidate.created_at == (
            authenticated.snapshot.decision_time
        )
    finally:
        coordinator.segment_store.close()

    with pytest.raises(TypeError):
        correlate_pcc(object(), object())  # type: ignore[arg-type]


def test_raw_context_cannot_mint_a_public_candidate(
    tmp_path: Path,
) -> None:
    coordinator, authenticated = _accepted_complete(tmp_path)
    try:
        result = correlate_pcc(authenticated, _context(authenticated))

        assert _reason(result) == ("correlation_proof_mismatch",)
    finally:
        coordinator.segment_store.close()


def test_direct_verified_falco_is_trigger_only_and_candidate_success_waits_for_pcc(
    tmp_path: Path,
) -> None:
    direct_store, direct = _accepted_direct_falco(
        tmp_path / "direct",
        investigation_only=True,
    )
    candidate_store, candidate = _accepted_direct_falco(
        tmp_path / "candidate",
        investigation_only=False,
    )
    function = importlib.import_module(
        "agmind_immune.correlation.pcc"
    ).incident_from_verified_falco
    try:
        incident = function(direct)

        assert incident.evidence_ids == (direct.event_id,)
        assert incident.authority_event_id == direct.event_id
        assert incident.reason_codes == ("investigation_only",)
        with pytest.raises(ValueError, match="PCC"):
            function(candidate)
    finally:
        direct_store.segment_store.close()
        candidate_store.segment_store.close()


def test_retained_trigger_incident_keeps_proof_authority_and_facts_binding(
    tmp_path: Path,
) -> None:
    coordinator, authenticated = _accepted_complete(tmp_path / "primary")
    other_store, other = _accepted_complete(
        tmp_path / "other",
        destination_ipv4="1.1.1.1",
    )
    module = importlib.import_module("agmind_immune.correlation.pcc")
    try:
        incident = module.incident_from_retained_trigger(authenticated)

        assert incident.evidence_ids == tuple(
            sorted(
                (
                    authenticated.event_id,
                    authenticated.snapshot.trigger.event_id,
                )
            )
        )
        assert incident.authority_event_id == authenticated.event_id
        with pytest.raises(ValueError, match="bind"):
            correlate_pcc_facts(
                other.snapshot.trigger,
                authenticated,
                _context(authenticated),
            )
    finally:
        coordinator.segment_store.close()
        other_store.segment_store.close()


def test_failed_snapshot_preserves_exact_rejection_reasons(
    tmp_path: Path,
) -> None:
    coordinator, authenticated = _accepted_failed(tmp_path)
    try:
        result = correlate_pcc(
            authenticated,
            CorrelationContext.failed_snapshot(),
        )
        assert _reason(result) == ("inventory_stale",)
        assert result.incident.authority_event_id == authenticated.event_id
    finally:
        coordinator.segment_store.close()


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("detector-pin", "detector_bundle_not_pinned"),
        ("inventory-stale", "inventory_stale"),
        ("coverage-incomplete", "historical_coverage_incomplete"),
        ("coverage-gap", "critical_coverage_gap"),
        ("not-public", "destination_not_public"),
        ("docker", "docker_destination"),
        ("operator", "operator_destination"),
        ("management", "management_destination"),
        ("not-running", "target_not_running"),
        ("shared-netns", "shared_network_namespace"),
        ("host-network", "unsupported_network_mode"),
        ("driver", "unsupported_network_driver"),
        ("privileged", "privileged_target"),
        ("cap-add", "target_cap_net_admin"),
        ("cap-all", "target_cap_net_admin"),
        ("effective-cap", "target_cap_net_admin"),
    ],
)
def test_ordered_security_gates_fail_closed(
    tmp_path: Path,
    case: str,
    expected: str,
) -> None:
    destination = "192.0.2.1" if case == "not-public" else "8.8.8.8"

    def mutate(fields: dict[str, object]) -> None:
        if case == "inventory-stale":
            fields["inventory_observed_at"] = (
                "2026-07-28T09:59:49Z"
            )
        elif case == "docker":
            fields["docker_networks"] = [
                {
                    "network_id": "e" * 64,
                    "driver": "bridge",
                    "subnet_cidrs": ["8.8.8.0/24"],
                    "gateway_addresses": ["8.8.8.1"],
                }
            ]
        elif case == "operator":
            fields["operator_denied_networks"] = []
            fields["operator_denied_addresses"] = ["8.8.8.8"]
        elif case == "management":
            fields["management_denied_networks"] = []
            fields["management_denied_addresses"] = ["8.8.8.8"]
        elif case == "not-running":
            fields["running"] = False
        elif case == "shared-netns":
            fields["network_mode"] = "container:peer"
        elif case == "host-network":
            fields["network_mode"] = "host"
        elif case == "driver":
            fields["network_driver"] = "macvlan"
        elif case == "privileged":
            fields["privileged"] = True
        elif case == "cap-add":
            fields["configured_cap_add"] = ["cap_net_admin"]
        elif case == "cap-all":
            fields["configured_cap_add"] = ["all"]
        elif case == "effective-cap":
            fields["effective_cap_net_admin"] = True

    coordinator, authenticated = _accepted_complete(
        tmp_path / case,
        destination_ipv4=destination,
        snapshot_change=mutate,
    )
    try:
        context = _context(
            authenticated,
            detector_pin=("0" * 64 if case == "detector-pin" else _PINNED_DETECTOR),
            coverage_complete=case != "coverage-incomplete",
            critical_gap=case == "coverage-gap",
        )
        assert _reason(_correlate_facts(authenticated, context)) == (
            expected,
        )
    finally:
        coordinator.segment_store.close()


def test_exact_integer_nanosecond_freshness_gate(
    tmp_path: Path,
) -> None:
    at_limit, exact = _accepted_complete(
        tmp_path / "at-limit",
        trigger_event_time="2026-07-28T09:59:30Z",
    )
    stale_store, stale = _accepted_complete(
        tmp_path / "stale",
        trigger_event_time="2026-07-28T09:59:29.999999999Z",
    )
    try:
        assert isinstance(
            _correlate_facts(exact, _context(exact)),
            CandidateCreated,
        )
        assert _reason(_correlate_facts(stale, _context(stale))) == (
            "event_stale",
        )
    finally:
        at_limit.segment_store.close()
        stale_store.segment_store.close()


def test_context_binding_mismatch_fails_before_duplicate_queries(
    tmp_path: Path,
) -> None:
    coordinator, authenticated = _accepted_complete(tmp_path)
    key = _duplicate_key(authenticated)
    mismatched = CandidateDuplicateKey(
        host_id=key.host_id,
        boot_id="323e4567-e89b-42d3-a456-426614174000",
        docker_container_id=key.docker_container_id,
        docker_started_at=key.docker_started_at,
        detector_bundle_sha256=key.detector_bundle_sha256,
        destination_ipv4=key.destination_ipv4,
    )
    try:
        assert _reason(
            _correlate_facts(
                authenticated,
                _context(authenticated, lookup_key=mismatched),
            )
        ) == ("correlation_proof_mismatch",)
    finally:
        coordinator.segment_store.close()


def test_active_duplicate_wins_over_cooldown_and_keeps_first_values(
    tmp_path: Path,
) -> None:
    coordinator, authenticated = _accepted_complete(
        tmp_path,
        destination_port=8443,
        l4_protocol="udp",
        ttl_seconds=120,
    )
    snapshot = authenticated.snapshot
    key = _duplicate_key(authenticated)
    existing_id = candidate_id(
        snapshot.trigger.event_id,
        cast(str, snapshot.docker_container_id),
        cast(str, snapshot.docker_started_at),
        snapshot.trigger.destination_ipv4,
        cast(str, snapshot.detector_bundle_sha256),
    )
    active = ActiveCandidateObservation(
        key=key,
        candidate_id=existing_id,
        primary_source_sequence=snapshot.trigger.source_sequence,
        primary_event_id=snapshot.trigger.event_id,
    )
    terminal = TerminalCandidateObservation(
        key=key,
        candidate_id=existing_id,
        state="VERIFIED",
        terminal_at="2026-07-28T09:59:59.999999999Z",
    )
    try:
        result = _correlate_facts(
            authenticated,
            _context(
                authenticated,
                active_duplicate=active,
                terminal_observation=terminal,
            ),
        )
        assert isinstance(result, Duplicate)
        assert result.existing_candidate_id == existing_id
        assert result.incident.evidence_ids == tuple(
            sorted((snapshot.trigger.event_id, authenticated.event_id))
        )
    finally:
        coordinator.segment_store.close()


def test_out_of_order_duplicate_is_projection_corruption(
    tmp_path: Path,
) -> None:
    coordinator, authenticated = _accepted_complete(tmp_path)
    key = _duplicate_key(authenticated)
    active = ActiveCandidateObservation(
        key=key,
        candidate_id="cand_" + "a" * 64,
        primary_source_sequence=authenticated.source_sequence + 1,
        primary_event_id="evt_" + "f" * 64,
    )
    try:
        with pytest.raises(CorrelationProjectionError):
            _correlate_facts(
                authenticated,
                _context(authenticated, active_duplicate=active),
            )
    finally:
        coordinator.segment_store.close()


@pytest.mark.parametrize(
    ("terminal_at", "expected_type"),
    [
        (
            "2026-07-28T09:50:00.000000001Z",
            Rejected,
        ),
        (
            "2026-07-28T09:50:00Z",
            CandidateCreated,
        ),
    ],
)
def test_terminal_cooldown_is_half_open_at_exact_nanoseconds(
    tmp_path: Path,
    terminal_at: str,
    expected_type: type[object],
) -> None:
    coordinator, authenticated = _accepted_complete(tmp_path)
    key = _duplicate_key(authenticated)
    terminal = TerminalCandidateObservation(
        key=key,
        candidate_id="cand_" + "a" * 64,
        state="EXPIRED_UNAPPLIED",
        terminal_at=terminal_at,
    )
    try:
        result = _correlate_facts(
            authenticated,
            _context(
                authenticated,
                terminal_observation=terminal,
            ),
        )
        assert isinstance(result, expected_type)
        if isinstance(result, Rejected):
            assert result.reason_codes == ("candidate_cooldown",)
    finally:
        coordinator.segment_store.close()
