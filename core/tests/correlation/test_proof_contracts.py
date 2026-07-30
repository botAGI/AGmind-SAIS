from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from typing import Any

import pytest
from agmind_immune import canonicaljson, contracts
from pydantic import ValidationError

_EVENT_ID = "evt_" + "a" * 64
_CONTENT_SHA256 = "b" * 64
_REQUEST_SHA256 = "4bc87347010d86cbeca0d11c1dc1e45dfd6dedc018d65bdbd246af659d48e2d5"
_DETECTOR_SHA256 = "f6189db90ea61fefe991672b20316f1693f723de28ab37800029a40545af7b15"
_DOCKER_SHA256 = "36ad699bd9f227d9ec3b1158556a89fe19bb939fd8533ce53d3dc9b905b170a8"
_OPERATOR_SHA256 = "c5e904a2c27cc1ad3f01a9cb6cf0a6dee20fa4c842f9a1448052ff143fd2eba5"
_MANAGEMENT_SHA256 = "a9751844b944ce899506632969d875e36a5049dfb5c6ef7543295f3ae9bd5c71"
_BOOT_CHAIN_SHA256 = "84d7b640b5b0fa842ce99f646658832bbf538d663052eb4183d5402a7b83585c"
_EMPTY_DOCKER_SHA256 = "6748f6e775bc393276f0e78faeb4aa167bc69b0b90a012076d1f0a103feb3ac8"
_SPECIAL_USE_SHA256 = "e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73"
_OLD_BOOT_ID = "123e4567-e89b-42d3-a456-426614174000"
_NEW_BOOT_ID = "223e4567-e89b-42d3-a456-426614174001"
_THIRD_BOOT_ID = "323e4567-e89b-42d3-a456-426614174002"
_NETWORK_ID = "c" * 64


def _request() -> dict[str, Any]:
    return {
        "schema_version": "agmind.pcc-correlation-snapshot-request.v1",
        "trigger_event_id": _EVENT_ID,
        "trigger_content_sha256": _CONTENT_SHA256,
        "trigger_source_sequence": 41,
        "requested_ttl_seconds": 120,
    }


def _trigger() -> dict[str, Any]:
    return {
        "schema_version": "agmind.pcc-falco-trigger-projection.v1",
        "event_id": _EVENT_ID,
        "content_sha256": _CONTENT_SHA256,
        "normalized_fields_sha256": "6" * 64,
        "source_sequence": 41,
        "source_id": "agmind-observerd",
        "source_version": "1.0.0",
        "host_id": "323e4567-e89b-42d3-a456-426614174002",
        "boot_id": _OLD_BOOT_ID,
        "event_time": "2026-07-27T12:00:05.123456789Z",
        "ingest_time": "2026-07-27T12:00:05.223456789Z",
        "clock_uncertainty_ms": 2_000,
        "inventory_generation": 7,
        "inventory_revision": 3,
        "container_id": "f" * 64,
        "container_start_time": "2026-07-27T12:00:00Z",
        "release_id": "rel_d1e5600f5f569da1cf8b7461fb5ada89",
        "detector_rule": "AGmind PCC Suspicious Process Outbound Connect",
        "detector_rule_version": "agmind-pcc-rules-v1",
        "falco_version": "0.44.1",
        "evt_rawres": 0,
        "evt_res": "SUCCESS",
        "successful_connect": True,
        "investigation_only": False,
        "image_id": "sha256:" + "1" * 64,
        "repo_digests": ["example.invalid/app@sha256:" + "2" * 64],
        "immutable_spec_sha256": "3" * 64,
        "proc_name": "curl",
        "proc_exe_path": "/usr/bin/curl",
        "proc_parent_name": "sh",
        "destination_ipv4": "1.1.1.1",
        "destination_port": 443,
        "l4_protocol": "tcp",
        "missing_required_fields": [],
        "coverage_flags": [],
        "raw_event_sha256": "7" * 64,
    }


def _network() -> dict[str, Any]:
    return {
        "network_id": _NETWORK_ID,
        "driver": "bridge",
        "subnet_cidrs": ["172.18.0.0/16"],
        "gateway_addresses": ["172.18.0.1"],
    }


def _boot_hop() -> dict[str, Any]:
    return {
        "boundary_event_type": "observer_boot_boundary",
        "event_id": "evt_" + "4" * 64,
        "content_sha256": "5" * 64,
        "source_sequence": 100,
        "boot_id": _NEW_BOOT_ID,
        "previous_boot_id": _OLD_BOOT_ID,
        "previous_source_sequence": 99,
    }


def _boot_hop_b() -> dict[str, Any]:
    return {
        **_boot_hop(),
        "boundary_event_type": "observer_key_transition",
        "rotation_companion_event_type": "observer_key_epoch_start",
        "rotation_companion_event_id": "evt_" + "6" * 64,
        "rotation_companion_content_sha256": "7" * 64,
        "rotation_companion_source_sequence": 101,
        "rotation_companion_boot_id": _NEW_BOOT_ID,
    }


def _boot_hop_c() -> dict[str, Any]:
    return {
        **_boot_hop(),
        "boundary_event_type": "observer_key_epoch_start",
        "rotation_companion_event_type": "observer_key_transition",
        "rotation_companion_event_id": "evt_" + "6" * 64,
        "rotation_companion_content_sha256": "7" * 64,
        "rotation_companion_source_sequence": 99,
        "rotation_companion_boot_id": _OLD_BOOT_ID,
    }


def _complete_snapshot() -> dict[str, Any]:
    trigger = _trigger()
    return {
        "schema_version": "agmind.pcc-correlation-snapshot.v1",
        "outcome": "complete",
        "request_sha256": _REQUEST_SHA256,
        "trigger": trigger,
        "decision_time": "2026-07-27T12:00:06.123456Z",
        "detector_bundle_sha256": _DETECTOR_SHA256,
        "requested_ttl_seconds": 120,
        "special_use_registry_sha256": _SPECIAL_USE_SHA256,
        "operator_denied_networks": ["10.0.0.0/24"],
        "operator_denied_addresses": ["10.0.0.2"],
        "operator_denylist_sha256": _OPERATOR_SHA256,
        "management_denied_networks": ["10.0.0.0/24"],
        "management_denied_addresses": ["10.0.0.2"],
        "management_denylist_sha256": _MANAGEMENT_SHA256,
        "docker_networks": [_network()],
        "docker_network_snapshot_sha256": _DOCKER_SHA256,
        "docker_container_id": trigger["container_id"],
        "docker_started_at": trigger["container_start_time"],
        "image_id": trigger["image_id"],
        "repo_digests": trigger["repo_digests"],
        "immutable_spec_sha256": trigger["immutable_spec_sha256"],
        "inventory_generation": trigger["inventory_generation"],
        "inventory_revision": trigger["inventory_revision"],
        "inventory_observed_at": "2026-07-27T12:00:05.923456789Z",
        "network_mode": "bridge",
        "network_driver": "bridge",
        "privileged": False,
        "configured_cap_add": ["CHOWN", "SETUID"],
        "configured_cap_drop": ["NET_RAW"],
        "effective_cap_net_admin": False,
        "running": True,
        "coverage_through_sequence": 41,
        "hard_limits_version": "pcc-hard-limits-v1",
    }


def _failed_snapshot(*, cross_boot: bool = False) -> dict[str, Any]:
    document = {
        "schema_version": "agmind.pcc-correlation-snapshot.v1",
        "outcome": "failed",
        "request_sha256": _REQUEST_SHA256,
        "trigger": _trigger(),
        "decision_time": "2026-07-27T12:00:06.123456Z",
        "requested_ttl_seconds": 120,
        "failure_reasons": ["observer_boot_changed"] if cross_boot else ["inventory_stale"],
        "coverage_through_sequence": 41,
        "hard_limits_version": "pcc-hard-limits-v1",
    }
    if cross_boot:
        document["boot_transition_hop_count"] = 1
        document["boot_transition_chain_sha256"] = _BOOT_CHAIN_SHA256
    return document


def test_locked_pcc_hash_vectors_have_exact_domains_and_length_prefixes() -> None:
    request = contracts.PCCCorrelationSnapshotRequestV1.model_validate(
        _request(), strict=True
    )
    network = contracts.PCCDockerNetworkV1.model_validate(_network(), strict=True)
    hop = contracts.PCCBootTransitionHopV1.model_validate(_boot_hop(), strict=True)

    assert canonicaljson.pcc_correlation_request_sha256(request) == _REQUEST_SHA256
    assert (
        canonicaljson.pcc_detector_bundle_sha256(b"- rule: outbound\n")
        == _DETECTOR_SHA256
    )
    assert canonicaljson.pcc_docker_network_snapshot_sha256((network,)) == _DOCKER_SHA256
    assert (
        canonicaljson.pcc_operator_denylist_sha256(
            ("10.0.0.0/24",), ("10.0.0.2",)
        )
        == _OPERATOR_SHA256
    )
    assert (
        canonicaljson.pcc_management_denylist_sha256(
            ("10.0.0.0/24",), ("10.0.0.2",)
        )
        == _MANAGEMENT_SHA256
    )
    assert canonicaljson.pcc_boot_transition_chain_sha256((hop,)) == _BOOT_CHAIN_SHA256
    assert canonicaljson.pcc_docker_network_snapshot_sha256(()) == _EMPTY_DOCKER_SHA256


def test_pcc_hash_helpers_reject_noncanonical_or_unknown_inputs() -> None:
    request = contracts.PCCCorrelationSnapshotRequestV1.model_validate(
        _request(), strict=True
    )
    network = contracts.PCCDockerNetworkV1.model_validate(_network(), strict=True)
    hop = contracts.PCCBootTransitionHopV1.model_validate(_boot_hop(), strict=True)

    with pytest.raises(TypeError):
        canonicaljson.pcc_correlation_request_sha256(
            {**request.model_dump(), "model_output": "BLOCK"}
        )
    with pytest.raises(ValueError):
        canonicaljson.pcc_operator_denylist_sha256(
            ("10.1.0.0/24", "10.0.0.0/24"),
            (),
        )
    with pytest.raises(ValueError):
        canonicaljson.pcc_management_denylist_sha256(
            ("10.0.0.0/24", "10.0.0.0/24"),
            (),
        )
    with pytest.raises(ValueError):
        canonicaljson.pcc_operator_denylist_sha256(
            ("10.0.0.1/24",),
            (),
        )
    with pytest.raises(ValueError):
        canonicaljson.pcc_management_denylist_sha256(
            (),
            ("2001:db8::1",),
        )
    with pytest.raises(TypeError):
        canonicaljson.pcc_docker_network_snapshot_sha256(
            ({**network.model_dump(), "unknown": True},)
        )
    with pytest.raises(TypeError):
        canonicaljson.pcc_boot_transition_chain_sha256((hop.model_dump(),))
    with pytest.raises(ValueError):
        canonicaljson.pcc_boot_transition_chain_sha256(())
    with pytest.raises(ValueError):
        canonicaljson.pcc_boot_transition_chain_sha256((hop,) * 1_025)

    disconnected = contracts.PCCBootTransitionHopV1.model_validate(
        {
            **_boot_hop(),
            "event_id": "evt_" + "8" * 64,
            "content_sha256": "9" * 64,
            "source_sequence": 200,
            "boot_id": _THIRD_BOOT_ID,
            "previous_source_sequence": 199,
        },
        strict=True,
    )
    with pytest.raises(ValueError):
        canonicaljson.pcc_boot_transition_chain_sha256((hop, disconnected))


def test_docker_network_hash_enforces_global_count_total_and_byte_bounds() -> None:
    empty_networks = tuple(
        contracts.PCCDockerNetworkV1.model_validate(
            {
                "network_id": f"{index:064x}",
                "driver": "bridge",
                "subnet_cidrs": [],
                "gateway_addresses": [],
            },
            strict=True,
        )
        for index in range(1, 66)
    )
    canonicaljson.pcc_docker_network_snapshot_sha256(empty_networks[:64])
    with pytest.raises(ValueError):
        canonicaljson.pcc_docker_network_snapshot_sha256(empty_networks)

    total_overflow = tuple(
        contracts.PCCDockerNetworkV1.model_validate(
            {
                "network_id": f"{index + 1:064x}",
                "driver": "bridge",
                "subnet_cidrs": sorted(
                    f"10.{index}.{item}.0/24" for item in range(32)
                ),
                "gateway_addresses": [],
            },
            strict=True,
        )
        for index in range(5)
    )
    with pytest.raises(ValueError):
        canonicaljson.pcc_docker_network_snapshot_sha256(total_overflow)

    byte_overflow = tuple(
        contracts.PCCDockerNetworkV1.model_validate(
            {
                "network_id": f"{index + 1:064x}",
                    "driver": "d" * 64,
                    "subnet_cidrs": sorted(
                        (
                            f"2001:db8:{index * 2 + 1:x}::/64",
                            f"2001:db8:{index * 2 + 2:x}::/64",
                        )
                    ),
                    "gateway_addresses": sorted(
                        (
                            f"2001:db8:{index * 2 + 1:x}::1",
                            f"2001:db8:{index * 2 + 2:x}::1",
                        )
                    ),
            },
            strict=True,
        )
        for index in range(64)
    )
    assert len(canonicaljson.canonical_json(byte_overflow)) > 16 * 1024
    with pytest.raises(ValueError):
        canonicaljson.pcc_docker_network_snapshot_sha256(byte_overflow)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("trigger_event_id", "evt_" + "A" * 64),
        ("trigger_content_sha256", "b" * 63),
        ("trigger_source_sequence", 0),
        ("trigger_source_sequence", 2**64),
        ("requested_ttl_seconds", 29),
        ("requested_ttl_seconds", 301),
        ("requested_ttl_seconds", "120"),
        ("model_output", {"action": "block"}),
    ],
)
def test_request_is_closed_strict_frozen_and_bounded(field: str, invalid: object) -> None:
    valid = contracts.PCCCorrelationSnapshotRequestV1.model_validate(
        _request(), strict=True
    )
    with pytest.raises(ValidationError, match="frozen"):
        valid.requested_ttl_seconds = 30

    document = _request()
    document[field] = invalid
    with pytest.raises(ValidationError):
        contracts.PCCCorrelationSnapshotRequestV1.model_validate(
            document, strict=True
        )


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda value: value.__setitem__("source_id", "falco"),
            id="wrong-source",
        ),
        pytest.param(
            lambda value: value.__setitem__("release_id", "rel_" + "0" * 32),
            id="release-mismatch",
        ),
        pytest.param(
            lambda value: value.__setitem__("evt_rawres", -1),
            id="result-tuple",
        ),
        pytest.param(
            lambda value: value.__setitem__("investigation_only", True),
            id="investigation-only",
        ),
        pytest.param(
            lambda value: value.__setitem__("proc_name", None),
            id="missing-sensor-fact",
        ),
        pytest.param(
            lambda value: value.__setitem__(
                "missing_required_fields", ["proc_name"]
            ),
            id="reported-missing-field",
        ),
        pytest.param(
            lambda value: value.__setitem__(
                "repo_digests", ["z.invalid/x", "a.invalid/x"]
            ),
            id="repo-order",
        ),
        pytest.param(
            lambda value: value.__setitem__("detector_rule_version", "other"),
            id="wrong-rule-version",
        ),
        pytest.param(
            lambda value: value.__setitem__("successful_connect", 1),
            id="strict-bool",
        ),
    ],
)
def test_retained_trigger_is_candidate_capable_and_deeply_immutable(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    trigger = contracts.PCCFalcoTriggerProjectionV1.model_validate(
        _trigger(), strict=True
    )
    assert trigger.repo_digests == ("example.invalid/app@sha256:" + "2" * 64,)
    with pytest.raises(ValidationError, match="frozen"):
        trigger.destination_port = 80
    with pytest.raises(TypeError):
        trigger.repo_digests[0] = "changed"

    document = _trigger()
    mutate(document)
    with pytest.raises(ValidationError):
        contracts.PCCFalcoTriggerProjectionV1.model_validate(
            document, strict=True
        )


@pytest.mark.parametrize(
    ("model_name", "document"),
    [
        pytest.param(
            "PCCDockerNetworkV1",
            {
                **_network(),
                "subnet_cidrs": ["172.19.0.0/16", "172.18.0.0/16"],
            },
            id="network-set-order",
        ),
        pytest.param(
            "PCCDockerNetworkV1",
            {**_network(), "subnet_cidrs": ["172.18.0.1/16"]},
            id="noncanonical-subnet",
        ),
        pytest.param(
            "PCCDockerNetworkV1",
            {**_network(), "gateway_addresses": ["172.018.0.1"]},
            id="noncanonical-gateway",
        ),
        pytest.param(
            "PCCBootTransitionHopV1",
            {
                **_boot_hop(),
                "rotation_companion_event_type": None,
            },
            id="absent-not-null",
        ),
        pytest.param(
            "PCCBootTransitionHopV1",
            {
                **_boot_hop(),
                "boundary_event_type": "observer_key_transition",
            },
            id="missing-rotation-companion",
        ),
    ],
)
def test_network_and_boot_hop_reject_noncanonical_or_partial_forms(
    model_name: str,
    document: dict[str, Any],
) -> None:
    network = contracts.PCCDockerNetworkV1.model_validate(_network(), strict=True)
    hop = contracts.PCCBootTransitionHopV1.model_validate(_boot_hop(), strict=True)
    assert network.subnet_cidrs == ("172.18.0.0/16",)
    with pytest.raises(ValidationError, match="frozen"):
        hop.source_sequence = 101

    with pytest.raises(ValidationError):
        model = getattr(contracts, model_name)
        model.model_validate(document, strict=True)


@pytest.mark.parametrize(
    ("field", "mapped_value"),
    [
        pytest.param(
            "gateway_addresses",
            "::ffff:c000:201",
            id="hex-mapped-address",
        ),
        pytest.param(
            "gateway_addresses",
            "::ffff:192.0.2.1",
            id="canonical-mapped-address",
        ),
        pytest.param(
            "subnet_cidrs",
            "::ffff:c000:200/120",
            id="hex-mapped-prefix",
        ),
        pytest.param(
            "subnet_cidrs",
            "::ffff:192.0.2.0/120",
            id="canonical-mapped-prefix",
        ),
    ],
)
def test_docker_network_rejects_ipv4_mapped_ipv6(
    field: str,
    mapped_value: str,
) -> None:
    document = _network()
    document[field] = [mapped_value]

    with pytest.raises(ValidationError, match="IPv4-mapped IPv6"):
        contracts.PCCDockerNetworkV1.model_validate(document, strict=True)


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(
            {
                **_boot_hop_b(),
                "rotation_companion_source_sequence": 102,
            },
            id="b-nonadjacent",
        ),
        pytest.param(
            {
                **_boot_hop_b(),
                "rotation_companion_boot_id": _OLD_BOOT_ID,
            },
            id="b-wrong-companion-boot",
        ),
        pytest.param(
            {
                **_boot_hop_c(),
                "rotation_companion_source_sequence": 98,
            },
            id="c-nonadjacent",
        ),
        pytest.param(
            {
                **_boot_hop_c(),
                "rotation_companion_source_sequence": 0,
            },
            id="c-zero-companion-sequence",
        ),
        pytest.param(
            {
                **_boot_hop_c(),
                "rotation_companion_boot_id": _NEW_BOOT_ID,
            },
            id="c-wrong-companion-boot",
        ),
        pytest.param(
            {
                **_boot_hop_b(),
                "rotation_companion_event_id": _boot_hop_b()["event_id"],
            },
            id="same-boundary-and-companion-event",
        ),
    ],
)
def test_boot_transition_rotation_variants_are_closed_and_adjacent(
    document: dict[str, Any],
) -> None:
    variant_b = contracts.PCCBootTransitionHopV1.model_validate(
        _boot_hop_b(), strict=True
    )
    variant_c = contracts.PCCBootTransitionHopV1.model_validate(
        _boot_hop_c(), strict=True
    )
    assert variant_b.rotation_companion_boot_id == variant_b.boot_id
    assert variant_c.rotation_companion_boot_id == variant_c.previous_boot_id

    with pytest.raises(ValidationError):
        contracts.PCCBootTransitionHopV1.model_validate(document, strict=True)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda value: value.__setitem__("request_sha256", "0" * 64),
            id="request-hash",
        ),
        pytest.param(
            lambda value: value.__setitem__(
                "docker_network_snapshot_sha256", "0" * 64
            ),
            id="network-hash",
        ),
        pytest.param(
            lambda value: value.__setitem__("operator_denylist_sha256", "0" * 64),
            id="operator-hash",
        ),
        pytest.param(
            lambda value: value.__setitem__(
                "management_denylist_sha256", "0" * 64
            ),
            id="management-hash",
        ),
        pytest.param(
            lambda value: value.__setitem__("docker_container_id", "0" * 64),
            id="trigger-identity",
        ),
        pytest.param(
            lambda value: value.__setitem__("coverage_through_sequence", 40),
            id="coverage-prefix",
        ),
        pytest.param(
            lambda value: value.__setitem__(
                "decision_time", "2026-07-27T12:00:06.123456789Z"
            ),
            id="decision-not-microsecond",
        ),
        pytest.param(
            lambda value: value.__setitem__(
                "special_use_registry_sha256", "e" * 64
            ),
            id="special-use-registry-pin",
        ),
        pytest.param(
            lambda value: value.__setitem__("failure_reasons", None),
            id="complete-field-null",
        ),
    ],
)
def test_complete_snapshot_binds_request_trigger_inventory_and_safety(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    snapshot = contracts.PCCCorrelationSnapshotV1.model_validate(
        _complete_snapshot(), strict=True
    )
    assert snapshot.outcome == "complete"
    assert snapshot.docker_networks is not None
    assert snapshot.docker_networks[0].subnet_cidrs == ("172.18.0.0/16",)
    with pytest.raises(ValidationError, match="frozen"):
        snapshot.running = False
    with pytest.raises(TypeError):
        snapshot.docker_networks[0].subnet_cidrs[0] = "changed"

    document = _complete_snapshot()
    mutate(document)
    with pytest.raises(ValidationError):
        contracts.PCCCorrelationSnapshotV1.model_validate(document, strict=True)


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(
            {**_failed_snapshot(), "image_id": "sha256:" + "1" * 64},
            id="complete-field-present",
        ),
        pytest.param(
            {**_failed_snapshot(), "boot_transition_hop_count": 1},
            id="ordinary-boot-proof",
        ),
        pytest.param(
            {
                **_failed_snapshot(cross_boot=True),
                "failure_reasons": ["inventory_stale", "observer_boot_changed"],
            },
            id="cross-boot-extra-reason",
        ),
        pytest.param(
            {
                key: value
                for key, value in _failed_snapshot(cross_boot=True).items()
                if key != "boot_transition_chain_sha256"
            },
            id="cross-boot-missing-hash",
        ),
        pytest.param(
            {**_failed_snapshot(cross_boot=True), "boot_transition_hop_count": 0},
            id="cross-boot-zero-hops",
        ),
        pytest.param(
            {**_failed_snapshot(), "failure_reasons": None},
            id="failed-field-null",
        ),
    ],
)
def test_failed_snapshot_discriminates_ordinary_and_cross_boot_forms(
    document: dict[str, Any],
) -> None:
    ordinary = contracts.PCCCorrelationSnapshotV1.model_validate(
        _failed_snapshot(), strict=True
    )
    cross_boot = contracts.PCCCorrelationSnapshotV1.model_validate(
        _failed_snapshot(cross_boot=True), strict=True
    )
    assert ordinary.failure_reasons == ("inventory_stale",)
    assert ordinary.boot_transition_hop_count is None
    assert cross_boot.failure_reasons == ("observer_boot_changed",)
    assert cross_boot.boot_transition_hop_count == 1

    with pytest.raises(ValidationError):
        contracts.PCCCorrelationSnapshotV1.model_validate(document, strict=True)


def test_complete_snapshot_rejects_global_network_and_normalized_size_overflow() -> None:
    too_many_networks = _complete_snapshot()
    too_many_networks["docker_networks"] = [
        {**_network(), "network_id": f"{index:064x}"} for index in range(65)
    ]
    too_many_networks["docker_network_snapshot_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        contracts.PCCCorrelationSnapshotV1.model_validate(
            too_many_networks, strict=True
        )

    oversized = _complete_snapshot()
    oversized["configured_cap_add"] = [
        f"CAP_{index:03d}_" + "X" * 56 for index in range(128)
    ]
    oversized["configured_cap_drop"] = [
        f"DROP_{index:03d}_" + "Y" * 55 for index in range(128)
    ]
    oversized["repo_digests"] = [
        f"registry-{index:02d}.invalid/" + "z" * 165 + f"@sha256:{index:064x}"
        for index in range(16)
    ]
    oversized["trigger"]["repo_digests"] = copy.deepcopy(oversized["repo_digests"])
    assert len(
        json.dumps(oversized, sort_keys=True, separators=(",", ":")).encode()
    ) > 24 * 1024
    with pytest.raises(ValidationError):
        contracts.PCCCorrelationSnapshotV1.model_validate(oversized, strict=True)


def test_detector_hash_rejects_non_bytes_without_coercion() -> None:
    with pytest.raises(TypeError):
        canonicaljson.pcc_detector_bundle_sha256("- rule: outbound\n")  # type: ignore[arg-type]

    # Independent guard that the parity literal is not plain concatenation.
    plain = hashlib.sha256(
        b"AGMIND_DETECTOR_BUNDLE_V1\0"
        b"- rule: outbound\n"
        b"agmind.falco-connect.v1"
        b"0.44.1"
    ).hexdigest()
    assert plain != _DETECTOR_SHA256
