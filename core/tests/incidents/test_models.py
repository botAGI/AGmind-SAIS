from __future__ import annotations

from typing import Any, get_args

import pytest
from agmind_immune.canonicaljson import candidate_id, incident_id
from agmind_immune.incidents.models import (
    CORRELATION_REASON_CODES,
    ContainmentCandidateV1,
    CorrelationReasonCode,
    IncidentV1,
)
from pydantic import ValidationError

PRIMARY_EVENT_ID = "evt_" + "a" * 64
SNAPSHOT_EVENT_ID = "evt_" + "b" * 64
INCIDENT_ID = "inc_b6a20642d932fed5b59e1d7221f7dacc8824a244fce8fcd85f5139b837ba5f52"
CONTAINER_ID = "f" * 64
DETECTOR_BUNDLE_SHA256 = (
    "f6189db90ea61fefe991672b20316f1693f723de28ab37800029a40545af7b15"
)
CANDIDATE_ID = "cand_e2a860ac90463466aa8052b923eb0a8887a566173603a56837050eb9e3030cbd"
HOST_ID = "11111111-1111-4111-8111-111111111111"
BOOT_ID = "22222222-2222-4222-8222-222222222222"
STARTED_AT = "2026-07-27T12:00:00Z"
DECISION_TIME = "2026-07-27T12:00:05.123456789Z"
RULE = "AGmind PCC Suspicious Process Outbound Connect"
RULE_VERSION = "agmind-pcc-rules-v1"

EXPECTED_REASON_CODES = frozenset(
    {
        "detector_not_pinned",
        "connect_not_successful",
        "sensor_fields_incomplete",
        "authoritative_identity_incomplete",
        "investigation_only",
        "detector_bundle_not_pinned",
        "mutation_read_only",
        "reconcile_required",
        "docker_reconcile_gap",
        "routine_drop_pending",
        "inventory_stale",
        "docker_network_snapshot_unavailable",
        "docker_network_snapshot_overflow",
        "detector_bundle_unavailable",
        "special_use_registry_unavailable",
        "operator_denylist_unavailable",
        "management_denylist_unavailable",
        "container_not_running",
        "container_identity_changed",
        "observer_boot_changed",
        "event_stale",
        "clock_uncertain",
        "historical_coverage_incomplete",
        "critical_coverage_gap",
        "correlation_proof_mismatch",
        "destination_not_public",
        "docker_destination",
        "operator_destination",
        "management_destination",
        "target_not_running",
        "shared_network_namespace",
        "unsupported_network_mode",
        "unsupported_network_driver",
        "privileged_target",
        "target_cap_net_admin",
        "ttl_out_of_bounds",
        "candidate_cooldown",
    }
)


def _incident(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "agmind.incident.v1",
        "incident_id": INCIDENT_ID,
        "primary_event_id": PRIMARY_EVENT_ID,
        "primary_source_sequence": 7,
        "host_id": HOST_ID,
        "boot_id": BOOT_ID,
        "detector_rule": RULE,
        "detector_rule_version": RULE_VERSION,
        "event_time": "2026-07-27T12:00:00.000000001Z",
        "ingest_time": "2026-07-27T12:00:00.000000002Z",
        "successful_connect": True,
        "investigation_only": False,
        "docker_container_id": CONTAINER_ID,
        "docker_started_at": STARTED_AT,
        "proc_name": "curl",
        "proc_exe_path": "/usr/bin/curl",
        "proc_parent_name": "sh",
        "destination_ipv4": "1.1.1.1",
        "destination_port": 443,
        "l4_protocol": "tcp",
        "missing_required_fields": (),
        "coverage_flags": (),
        "evidence_ids": (PRIMARY_EVENT_ID, SNAPSHOT_EVENT_ID),
        "reason_codes": (),
        "authority_event_id": SNAPSHOT_EVENT_ID,
    }
    value.update(changes)
    return value


def _direct_incident(**changes: object) -> dict[str, object]:
    value = _incident(
        investigation_only=True,
        evidence_ids=(PRIMARY_EVENT_ID,),
        reason_codes=("investigation_only",),
        authority_event_id=PRIMARY_EVENT_ID,
    )
    for field in (
        "docker_container_id",
        "docker_started_at",
        "proc_name",
        "proc_exe_path",
        "proc_parent_name",
        "destination_ipv4",
        "destination_port",
        "l4_protocol",
    ):
        value.pop(field)
    value.update(changes)
    return value


def _candidate(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "agmind.containment-candidate.v1",
        "candidate_id": CANDIDATE_ID,
        "incident_id": INCIDENT_ID,
        "host_id": HOST_ID,
        "boot_id": BOOT_ID,
        "primary_event_id": PRIMARY_EVENT_ID,
        "primary_source_sequence": 7,
        "correlation_snapshot_event_id": SNAPSHOT_EVENT_ID,
        "docker_container_id": CONTAINER_ID,
        "docker_started_at": STARTED_AT,
        "image_id": "sha256:" + "e" * 64,
        "repo_digests": ("registry.example/agmind@sha256:" + "d" * 64,),
        "immutable_spec_sha256": "c" * 64,
        "inventory_generation": 11,
        "inventory_revision": 12,
        "destination_ipv4": "1.1.1.1",
        "destination_port": 443,
        "l4_protocol": "tcp",
        "ttl_seconds": 120,
        "detector_rule": RULE,
        "detector_rule_version": RULE_VERSION,
        "detector_bundle_sha256": DETECTOR_BUNDLE_SHA256,
        "coverage_snapshot_sha256": "1" * 64,
        "docker_network_snapshot_sha256": "2" * 64,
        "special_use_registry_sha256": "3" * 64,
        "operator_denylist_sha256": "4" * 64,
        "management_denylist_sha256": "5" * 64,
        "evidence_ids": (PRIMARY_EVENT_ID, SNAPSHOT_EVENT_ID),
        "created_at": DECISION_TIME,
    }
    value.update(changes)
    return value


def _validate_incident(value: dict[str, object]) -> IncidentV1:
    return IncidentV1.model_validate(value, strict=True)


def _validate_candidate(value: dict[str, object]) -> ContainmentCandidateV1:
    return ContainmentCandidateV1.model_validate(value, strict=True)


def test_locked_incident_and_candidate_id_vectors() -> None:
    assert incident_id(PRIMARY_EVENT_ID) == INCIDENT_ID
    assert (
        candidate_id(
            PRIMARY_EVENT_ID,
            CONTAINER_ID,
            STARTED_AT,
            "1.1.1.1",
            DETECTOR_BUNDLE_SHA256,
        )
        == CANDIDATE_ID
    )
    assert _validate_incident(_incident()).incident_id == INCIDENT_ID
    assert _validate_candidate(_candidate()).candidate_id == CANDIDATE_ID


def test_model_field_order_is_the_frozen_wire_order() -> None:
    assert tuple(IncidentV1.model_fields) == (
        "schema_version",
        "incident_id",
        "primary_event_id",
        "primary_source_sequence",
        "host_id",
        "boot_id",
        "detector_rule",
        "detector_rule_version",
        "event_time",
        "ingest_time",
        "successful_connect",
        "investigation_only",
        "docker_container_id",
        "docker_started_at",
        "proc_name",
        "proc_exe_path",
        "proc_parent_name",
        "destination_ipv4",
        "destination_port",
        "l4_protocol",
        "missing_required_fields",
        "coverage_flags",
        "evidence_ids",
        "reason_codes",
        "authority_event_id",
    )
    assert tuple(ContainmentCandidateV1.model_fields) == (
        "schema_version",
        "candidate_id",
        "incident_id",
        "host_id",
        "boot_id",
        "primary_event_id",
        "primary_source_sequence",
        "correlation_snapshot_event_id",
        "docker_container_id",
        "docker_started_at",
        "image_id",
        "repo_digests",
        "immutable_spec_sha256",
        "inventory_generation",
        "inventory_revision",
        "destination_ipv4",
        "destination_port",
        "l4_protocol",
        "ttl_seconds",
        "detector_rule",
        "detector_rule_version",
        "detector_bundle_sha256",
        "coverage_snapshot_sha256",
        "docker_network_snapshot_sha256",
        "special_use_registry_sha256",
        "operator_denylist_sha256",
        "management_denylist_sha256",
        "evidence_ids",
        "created_at",
    )


def test_reason_code_contract_is_closed_and_unknown_values_fail() -> None:
    assert frozenset(get_args(CorrelationReasonCode)) == EXPECTED_REASON_CODES
    assert CORRELATION_REASON_CODES == EXPECTED_REASON_CODES

    with pytest.raises(ValidationError):
        _validate_incident(_direct_incident(reason_codes=("make_it_so",)))


@pytest.mark.parametrize(
    ("factory", "field", "bad"),
    [
        (_incident, "incident_id", "inc_" + "A" * 64),
        (_incident, "primary_event_id", "evt_" + "A" * 64),
        (_incident, "host_id", "11111111-1111-1111-8111-111111111111"),
        (_incident, "boot_id", "22222222-2222-4222-c222-222222222222"),
        (_incident, "event_time", "2026-07-27T12:00:00.1234567890Z"),
        (_incident, "ingest_time", "2026-07-27T12:00:00+00:00"),
        (_incident, "docker_container_id", "F" * 64),
        (_incident, "docker_started_at", "2026-02-30T00:00:00Z"),
        (_incident, "destination_ipv4", "01.1.1.1"),
        (_incident, "destination_port", 0),
        (_incident, "l4_protocol", "\n"),
        (_candidate, "candidate_id", "cand_" + "A" * 64),
        (_candidate, "image_id", "e" * 64),
        (_candidate, "immutable_spec_sha256", "C" * 64),
        (_candidate, "inventory_generation", 0),
        (_candidate, "inventory_revision", 2**64),
        (_candidate, "destination_port", 65_536),
        (_candidate, "ttl_seconds", 29),
        (_candidate, "created_at", "2026-07-27 12:00:05Z"),
    ],
)
def test_exact_identifiers_bounds_and_timestamp_contracts(
    factory: Any,
    field: str,
    bad: object,
) -> None:
    with pytest.raises(ValidationError):
        if factory is _incident:
            _validate_incident(factory(**{field: bad}))
        else:
            _validate_candidate(factory(**{field: bad}))


@pytest.mark.parametrize(
    ("factory", "field", "bad"),
    [
        (_incident, "primary_source_sequence", "7"),
        (_incident, "successful_connect", 1),
        (_incident, "investigation_only", 0),
        (_incident, "missing_required_fields", []),
        (_candidate, "primary_source_sequence", True),
        (_candidate, "inventory_generation", "11"),
        (_candidate, "repo_digests", ["registry.example/app@sha256:" + "d" * 64]),
        (_candidate, "ttl_seconds", 120.0),
    ],
)
def test_models_do_not_coerce_scalar_or_array_types(
    factory: Any,
    field: str,
    bad: object,
) -> None:
    with pytest.raises(ValidationError):
        if factory is _incident:
            _validate_incident(factory(**{field: bad}))
        else:
            _validate_candidate(factory(**{field: bad}))


@pytest.mark.parametrize(
    ("factory", "field", "bad"),
    [
        (_incident, "missing_required_fields", ("proc_name", "proc_name")),
        (_incident, "coverage_flags", ("z", "a")),
        (_incident, "evidence_ids", (SNAPSHOT_EVENT_ID, PRIMARY_EVENT_ID)),
        (_incident, "reason_codes", ("event_stale", "clock_uncertain")),
        (
            _candidate,
            "repo_digests",
            (
                "registry.example/z@sha256:" + "d" * 64,
                "registry.example/a@sha256:" + "e" * 64,
            ),
        ),
        (_candidate, "evidence_ids", (SNAPSHOT_EVENT_ID, PRIMARY_EVENT_ID)),
    ],
)
def test_tuple_fields_are_unique_and_canonically_sorted(
    factory: Any,
    field: str,
    bad: object,
) -> None:
    with pytest.raises(ValidationError):
        if factory is _incident:
            _validate_incident(factory(**{field: bad}))
        else:
            _validate_candidate(factory(**{field: bad}))


def test_models_are_deeply_immutable() -> None:
    incident = _validate_incident(_incident())
    candidate = _validate_candidate(_candidate())

    with pytest.raises(ValidationError):
        incident.reason_codes = ("event_stale",)
    with pytest.raises(ValidationError):
        candidate.ttl_seconds = 30
    with pytest.raises(TypeError):
        candidate.evidence_ids[0] = SNAPSHOT_EVENT_ID  # type: ignore[index]


def test_optional_incident_fields_must_be_absent_instead_of_null() -> None:
    assert _validate_incident(_direct_incident()).docker_container_id is None

    with pytest.raises(ValidationError):
        _validate_incident(_direct_incident(docker_container_id=None))


def test_incident_derivation_and_authority_evidence_semantics_are_self_checked() -> None:
    direct = _validate_incident(_direct_incident())
    assert direct.evidence_ids == (PRIMARY_EVENT_ID,)
    assert direct.authority_event_id == PRIMARY_EVENT_ID

    for changes in (
        {"incident_id": "inc_" + "0" * 64},
        {"authority_event_id": "evt_" + "c" * 64},
        {"evidence_ids": (PRIMARY_EVENT_ID,)},
        {
            "authority_event_id": PRIMARY_EVENT_ID,
            "evidence_ids": (PRIMARY_EVENT_ID, SNAPSHOT_EVENT_ID),
        },
    ):
        with pytest.raises(ValidationError):
            _validate_incident(_incident(**changes))


def test_candidate_derivation_and_exact_evidence_pair_are_self_checked() -> None:
    for changes in (
        {"candidate_id": "cand_" + "0" * 64},
        {"incident_id": "inc_" + "0" * 64},
        {"correlation_snapshot_event_id": PRIMARY_EVENT_ID},
        {"evidence_ids": (PRIMARY_EVENT_ID,)},
        {
            "evidence_ids": (
                PRIMARY_EVENT_ID,
                SNAPSHOT_EVENT_ID,
                "evt_" + "c" * 64,
            )
        },
    ):
        with pytest.raises(ValidationError):
            _validate_candidate(_candidate(**changes))


@pytest.mark.parametrize(
    "field",
    [
        "raw_falco_line",
        "docker_inspect",
        "model_output",
        "policy_decision",
        "command",
        "pid",
        "namespace_handle",
        "approval",
        "mutation_authority",
    ],
)
def test_models_forbid_untrusted_or_authority_bearing_extra_fields(field: str) -> None:
    with pytest.raises(ValidationError):
        _validate_incident(_incident(**{field: "forbidden"}))
    with pytest.raises(ValidationError):
        _validate_candidate(_candidate(**{field: "forbidden"}))
