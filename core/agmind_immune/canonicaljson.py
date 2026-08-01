"""AGmind Canonical JSON v1 and locked cryptographic derivations."""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel

if TYPE_CHECKING:
    from .contracts import (
        PCCBootTransitionHopV1,
        PCCCorrelationSnapshotRequestV1,
        PCCDockerNetworkV1,
    )
    from .incidents.models import ContainmentCandidateV1

MIN_CANONICAL_INTEGER = -(2**63)
MAX_CANONICAL_INTEGER = 2**64 - 1
MAX_JSON_NESTING_DEPTH = 64
_PCC_ADAPTER_SCHEMA_VERSION = b"agmind.falco-connect.v1"
_PCC_FALCO_VERSION = b"0.44.1"
_PCC_DETECTOR_BUNDLE_DOMAIN = b"AGMIND_DETECTOR_BUNDLE_V1\0"
_PCC_DOCKER_NETWORK_DOMAIN = b"AGMIND_DOCKER_NETWORK_SNAPSHOT_V1\0"
_PCC_OPERATOR_DENYLIST_DOMAIN = b"AGMIND_OPERATOR_DENYLIST_V1\0"
_PCC_MANAGEMENT_DENYLIST_DOMAIN = b"AGMIND_MANAGEMENT_DENYLIST_V1\0"
_PCC_BOOT_TRANSITION_CHAIN_DOMAIN = b"AGMIND_BOOT_TRANSITION_CHAIN_V1\0"
_CANDIDATE_FACTS_DOMAIN = b"AGMIND_CANDIDATE_FACTS_V1\0"
_PCC_MAX_DENYLIST_ITEMS = 128
_PCC_MAX_DOCKER_NETWORKS = 64
_PCC_MAX_DOCKER_SUBNETS = 128
_PCC_MAX_DOCKER_GATEWAYS = 128
_PCC_MAX_DOCKER_NETWORK_BYTES = 16 * 1024
_PCC_MAX_BOOT_TRANSITION_HOPS = 1_024


def _quote(value: str) -> str:
    try:
        value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise ValueError("invalid UTF-8 string") from error
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError("surrogate code points are forbidden")
    out: list[str] = ['"']
    escapes = {
        "\b": "\\b",
        "\f": "\\f",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
        '"': '\\"',
        "\\": "\\\\",
    }
    for char in value:
        if char in escapes:
            out.append(escapes[char])
        elif ord(char) < 0x20:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _encode(value: object, container_depth: int = 0) -> str:
    if isinstance(value, BaseModel):
        return _encode(value.model_dump(exclude_none=True), container_depth)
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not MIN_CANONICAL_INTEGER <= value <= MAX_CANONICAL_INTEGER:
            raise ValueError("integer exceeds canonical range")
        return str(value)
    if isinstance(value, float):
        raise ValueError("floating-point JSON is forbidden")  # noqa: TRY004
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, (list, tuple)):
        depth = container_depth + 1
        if depth > MAX_JSON_NESTING_DEPTH:
            raise ValueError("JSON nesting depth exceeds 64")
        return "[" + ",".join(_encode(item, depth) for item in value) + "]"
    if isinstance(value, Mapping):
        depth = container_depth + 1
        if depth > MAX_JSON_NESTING_DEPTH:
            raise ValueError("JSON nesting depth exceeds 64")
        if not all(isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        document = dict(value)
        return (
            "{"
            + ",".join(
                _quote(key) + ":" + _encode(document[key], depth)
                for key in sorted(document)
            )
            + "}"
        )
    raise ValueError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json(value: object) -> bytes:
    return _encode(value).encode("utf-8")


def pcc_correlation_request_sha256(
    request: PCCCorrelationSnapshotRequestV1,
) -> str:
    """Hash the exact canonical narrow correlation request."""
    from .contracts import PCCCorrelationSnapshotRequestV1

    if type(request) is not PCCCorrelationSnapshotRequestV1:
        raise TypeError("request must be an exact PCCCorrelationSnapshotRequestV1")
    normalized = PCCCorrelationSnapshotRequestV1.model_validate(
        request.model_dump(mode="python"),
        strict=True,
    )
    return hashlib.sha256(canonical_json(normalized)).hexdigest()


def pcc_detector_bundle_sha256(rule_file_bytes: bytes) -> str:
    """Hash the exact rule bytes with fixed, length-prefixed deployment pins."""
    if type(rule_file_bytes) is not bytes:
        raise TypeError("PCC rule bundle must be exact bytes")

    preimage = bytearray(_PCC_DETECTOR_BUNDLE_DOMAIN)
    for value in (
        rule_file_bytes,
        _PCC_ADAPTER_SCHEMA_VERSION,
        _PCC_FALCO_VERSION,
    ):
        preimage.extend(len(value).to_bytes(8, "big", signed=False))
        preimage.extend(value)
    return hashlib.sha256(preimage).hexdigest()


def _pcc_exact_sequence[T](values: Sequence[T], field: str) -> tuple[T, ...]:
    if type(values) not in (list, tuple):
        raise TypeError(f"{field} must be an exact list or tuple")
    result = tuple(values)
    return result


def _pcc_ipv4_tuple(
    values: Sequence[str],
    field: str,
    *,
    network: bool,
) -> tuple[str, ...]:
    result = _pcc_exact_sequence(values, field)
    if any(type(value) is not str for value in result):
        raise TypeError(f"{field} must contain exact strings")
    if len(result) > _PCC_MAX_DENYLIST_ITEMS:
        raise ValueError(f"{field} exceeds {_PCC_MAX_DENYLIST_ITEMS} entries")
    if result != tuple(sorted(set(result))):
        raise ValueError(f"{field} must be unique and sorted")
    for value in result:
        try:
            parsed = (
                ipaddress.ip_network(value, strict=True)
                if network
                else ipaddress.ip_address(value)
            )
        except ValueError as error:
            raise ValueError(f"{field} contains an invalid IPv4 value") from error
        expected_type = ipaddress.IPv4Network if network else ipaddress.IPv4Address
        if type(parsed) is not expected_type or str(parsed) != value:
            raise ValueError(f"{field} must contain canonical IPv4 values")
    return result


def _pcc_denylist_sha256(
    domain: bytes,
    denied_networks: Sequence[str],
    denied_addresses: Sequence[str],
) -> str:
    payload = {
        "denied_addresses": _pcc_ipv4_tuple(
            denied_addresses,
            "denied_addresses",
            network=False,
        ),
        "denied_networks": _pcc_ipv4_tuple(
            denied_networks,
            "denied_networks",
            network=True,
        ),
    }
    return hashlib.sha256(domain + canonical_json(payload)).hexdigest()


def pcc_operator_denylist_sha256(
    denied_networks: Sequence[str],
    denied_addresses: Sequence[str],
) -> str:
    """Hash the canonical operator denylist under its dedicated domain."""
    return _pcc_denylist_sha256(
        _PCC_OPERATOR_DENYLIST_DOMAIN,
        denied_networks,
        denied_addresses,
    )


def pcc_management_denylist_sha256(
    denied_networks: Sequence[str],
    denied_addresses: Sequence[str],
) -> str:
    """Hash the canonical management denylist under its dedicated domain."""
    return _pcc_denylist_sha256(
        _PCC_MANAGEMENT_DENYLIST_DOMAIN,
        denied_networks,
        denied_addresses,
    )


def pcc_docker_network_snapshot_sha256(
    docker_networks: Sequence[PCCDockerNetworkV1],
) -> str:
    """Hash the complete canonical Docker-network snapshot."""
    from .contracts import PCCDockerNetworkV1

    raw_networks = _pcc_exact_sequence(docker_networks, "docker_networks")
    if len(raw_networks) > _PCC_MAX_DOCKER_NETWORKS:
        raise ValueError(
            f"docker_networks exceeds {_PCC_MAX_DOCKER_NETWORKS} networks"
        )
    normalized: list[PCCDockerNetworkV1] = []
    for network in raw_networks:
        if type(network) is not PCCDockerNetworkV1:
            raise TypeError("docker_networks must contain exact PCCDockerNetworkV1 models")
        normalized.append(
            PCCDockerNetworkV1.model_validate(
                network.model_dump(mode="python"),
                strict=True,
            )
        )
    payload = tuple(normalized)
    network_ids = tuple(network.network_id for network in payload)
    if network_ids != tuple(sorted(set(network_ids))):
        raise ValueError("docker_networks must have unique sorted network IDs")
    if sum(len(network.subnet_cidrs) for network in payload) > _PCC_MAX_DOCKER_SUBNETS:
        raise ValueError("docker_networks exceeds the global subnet limit")
    if (
        sum(len(network.gateway_addresses) for network in payload)
        > _PCC_MAX_DOCKER_GATEWAYS
    ):
        raise ValueError("docker_networks exceeds the global gateway limit")
    canonical = canonical_json(payload)
    if len(canonical) > _PCC_MAX_DOCKER_NETWORK_BYTES:
        raise ValueError("docker_networks exceeds 16 KiB")
    return hashlib.sha256(
        _PCC_DOCKER_NETWORK_DOMAIN + canonical
    ).hexdigest()


def pcc_boot_transition_chain_sha256(
    boundary_chain: Sequence[PCCBootTransitionHopV1],
) -> str:
    """Hash the complete canonical protected boot-transition hop chain."""
    from .contracts import PCCBootTransitionHopV1

    raw_hops = _pcc_exact_sequence(boundary_chain, "boundary_chain")
    if not 1 <= len(raw_hops) <= _PCC_MAX_BOOT_TRANSITION_HOPS:
        raise ValueError("boundary_chain must contain 1..1024 hops")
    normalized: list[PCCBootTransitionHopV1] = []
    for hop in raw_hops:
        if type(hop) is not PCCBootTransitionHopV1:
            raise TypeError(
                "boundary_chain must contain exact PCCBootTransitionHopV1 models"
            )
        normalized.append(
            PCCBootTransitionHopV1.model_validate(
                hop.model_dump(mode="python", exclude_none=True),
                strict=True,
            )
        )
    payload = tuple(normalized)
    event_ids: set[str] = set()
    seen_boot_ids = {payload[0].previous_boot_id}
    prior_hop: PCCBootTransitionHopV1 | None = None
    prior_end_sequence = 0
    for hop in payload:
        hop_event_ids: tuple[str, ...] = (hop.event_id,)
        if hop.rotation_companion_event_id is not None:
            hop_event_ids += (hop.rotation_companion_event_id,)
        if event_ids.intersection(hop_event_ids):
            raise ValueError("boundary_chain contains a duplicate event ID")
        event_ids.update(hop_event_ids)
        if hop.boot_id in seen_boot_ids:
            raise ValueError("boundary_chain contains a repeated boot ID")
        seen_boot_ids.add(hop.boot_id)
        if prior_hop is not None and (
            hop.previous_boot_id != prior_hop.boot_id
            or hop.source_sequence <= prior_end_sequence
            or hop.previous_source_sequence < prior_end_sequence
        ):
            raise ValueError("boundary_chain is reordered or disconnected")
        prior_hop = hop
        prior_end_sequence = max(
            hop.source_sequence,
            hop.rotation_companion_source_sequence or 0,
        )
    return hashlib.sha256(
        _PCC_BOOT_TRANSITION_CHAIN_DOMAIN + canonical_json(payload)
    ).hexdigest()


def _document(value: BaseModel | Mapping[str, object]) -> dict[str, Any]:
    if isinstance(value, BaseModel):
        return value.model_dump(exclude_none=True)
    return dict(value)


def _ascii(value: str, field: str) -> bytes:
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field} must be ASCII") from error


def key_id(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must contain 32 bytes")
    return hashlib.sha256(public_key).hexdigest()[:32]


def event_id(envelope: Any) -> str:
    try:
        normalized_digest = bytes.fromhex(str(envelope.normalized_fields_sha256))
    except ValueError as error:
        raise ValueError("invalid normalized_fields_sha256") from error
    if len(normalized_digest) != 32:
        raise ValueError("normalized_fields_sha256 must contain 32 bytes")
    try:
        numbers = int(envelope.key_epoch).to_bytes(8, "big", signed=False)
        numbers += int(envelope.source_sequence).to_bytes(8, "big", signed=False)
    except OverflowError as error:
        raise ValueError("event counters must be uint64") from error
    preimage = b"AGMIND_EVENT_ID_V1\0"
    preimage += _ascii(str(envelope.host_id), "host_id") + b"\0"
    preimage += _ascii(str(envelope.boot_id), "boot_id") + b"\0"
    preimage += numbers + normalized_digest
    return "evt_" + hashlib.sha256(preimage).hexdigest()


def release_id(image_id: str, immutable_spec_sha256: str) -> str:
    preimage = b"AGMIND_RELEASE_ID_V1\0"
    preimage += _ascii(image_id, "image_id") + b"\0"
    preimage += _ascii(immutable_spec_sha256, "immutable_spec_sha256")
    return "rel_" + hashlib.sha256(preimage).hexdigest()[:32]


def incident_id(primary_event_id: str) -> str:
    preimage = b"AGMIND_INCIDENT_ID_V1\0"
    preimage += _ascii(primary_event_id, "primary_event_id")
    return "inc_" + hashlib.sha256(preimage).hexdigest()


def candidate_id(
    event_id_value: str,
    docker_container_id: str,
    docker_started_at: str,
    destination_ipv4: str,
    detector_bundle_sha256: str,
) -> str:
    fields = (
        event_id_value,
        docker_container_id,
        docker_started_at,
        destination_ipv4,
        detector_bundle_sha256,
    )
    preimage = b"AGMIND_CANDIDATE_ID_V1\0" + b"\0".join(
        _ascii(value, "candidate field") for value in fields
    )
    return "cand_" + hashlib.sha256(preimage).hexdigest()


def candidate_facts_sha256(candidate: ContainmentCandidateV1) -> str:
    """Hash every canonical containment-candidate fact under its fixed domain."""
    from .incidents.models import ContainmentCandidateV1

    if type(candidate) is not ContainmentCandidateV1:
        raise TypeError("candidate must be an exact ContainmentCandidateV1")
    return hashlib.sha256(
        _CANDIDATE_FACTS_DOMAIN + canonical_json(candidate)
    ).hexdigest()


def intent_id(candidate_id_value: str, policy_bundle_sha256: str, ttl_seconds: int) -> str:
    if not 0 <= ttl_seconds <= 2**64 - 1:
        raise ValueError("ttl_seconds must be uint64")
    preimage = b"AGMIND_INTENT_ID_V1\0"
    preimage += _ascii(candidate_id_value, "candidate_id") + b"\0"
    preimage += _ascii(policy_bundle_sha256, "policy_bundle_sha256") + b"\0"
    preimage += str(ttl_seconds).encode("ascii")
    return "int_" + hashlib.sha256(preimage).hexdigest()[:32]


def plan_id(intent_id_value: str, nonce: bytes) -> str:
    if len(nonce) != 32:
        raise ValueError("nonce must contain exactly 32 bytes")
    preimage = b"AGMIND_PLAN_ID_V1\0"
    preimage += _ascii(intent_id_value, "intent_id") + b"\0" + nonce
    return "plan_" + hashlib.sha256(preimage).hexdigest()[:32]


def plan_hash(plan: BaseModel | Mapping[str, object]) -> str:
    document = _document(plan)
    document.pop("plan_hash", None)
    return hashlib.sha256(
        b"AGMIND_PLAN_HASH_V1\0" + canonical_json(document)
    ).hexdigest()


def action_id(plan_hash_value: str) -> str:
    try:
        digest = bytes.fromhex(plan_hash_value)
    except ValueError as error:
        raise ValueError("invalid plan_hash") from error
    if len(digest) != 32:
        raise ValueError("plan_hash must contain 32 bytes")
    return "act_" + hashlib.sha256(b"AGMIND_ACTION_ID_V1\0" + digest).hexdigest()[:32]


def action_record_hash(record: BaseModel | Mapping[str, object]) -> str:
    document = _document(record)
    document.pop("record_id", None)
    document.pop("record_sha256", None)
    document.pop("actuator_signature", None)
    return hashlib.sha256(
        b"AGMIND_ACTION_RECORD_HASH_V1\0" + canonical_json(document)
    ).hexdigest()


def action_record_id(record_sha256: str) -> str:
    if len(record_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in record_sha256
    ):
        raise ValueError("record_sha256 must be exactly 64 lowercase hex characters")
    return "ar_" + record_sha256[:32]


def event_signing_message(envelope: BaseModel | Mapping[str, object]) -> bytes:
    document = _document(envelope)
    document.pop("source_signature", None)
    return b"AGMIND_EVENT_ENVELOPE_V1\0" + canonical_json(document)


def action_record_signing_message(record: BaseModel | Mapping[str, object]) -> bytes:
    document = _document(record)
    document.pop("actuator_signature", None)
    return b"AGMIND_ACTION_RECORD_V1\0" + canonical_json(document)


def key_transition_signing_message(
    transition: BaseModel | Mapping[str, object],
) -> bytes:
    """Return the dual-signature preimage.

    The approved plan requires one shared, domain-separated canonical
    transition signed by both keys but does not spell the domain bytes. M1
    fixes that ambiguity as ``AGMIND_KEY_TRANSITION_V1\\0``.
    """
    document = _document(transition)
    document.pop("old_signature", None)
    document.pop("new_signature", None)
    return b"AGMIND_KEY_TRANSITION_V1\0" + canonical_json(document)


def verify_event_signature(
    envelope: BaseModel | Mapping[str, object], public_key: bytes
) -> None:
    document = _document(envelope)
    if document.get("key_id") != key_id(public_key):
        raise ValueError("event key_id does not bind the supplied public key")
    signature_text = document.get("source_signature")
    if not isinstance(signature_text, str):
        raise TypeError("invalid event signature")
    try:
        signature = bytes.fromhex(signature_text)
    except ValueError as error:
        raise ValueError("invalid event signature") from error
    Ed25519PublicKey.from_public_bytes(public_key).verify(
        signature, event_signing_message(document)
    )


def verify_action_record(
    record: BaseModel | Mapping[str, object], public_key: bytes
) -> None:
    document = _document(record)
    if document.get("actuator_key_id") != key_id(public_key):
        raise ValueError("actuator_key_id does not bind the supplied public key")
    expected_hash = action_record_hash(document)
    if document.get("record_sha256") != expected_hash:
        raise ValueError("record_sha256 does not match record content")
    if document.get("record_id") != action_record_id(expected_hash):
        raise ValueError("record_id does not match record_sha256")
    signature_text = document.get("actuator_signature")
    if not isinstance(signature_text, str):
        raise TypeError("invalid actuator signature")
    try:
        signature = bytes.fromhex(signature_text)
    except ValueError as error:
        raise ValueError("invalid actuator signature") from error
    Ed25519PublicKey.from_public_bytes(public_key).verify(
        signature, action_record_signing_message(document)
    )


def verify_key_transition(
    transition: BaseModel | Mapping[str, object], old_public_key: bytes
) -> None:
    document = _document(transition)
    if document.get("old_key_id") != key_id(old_public_key):
        raise ValueError("old_key_id does not bind the supplied public key")
    new_public_text = document.get("new_public_key")
    if not isinstance(new_public_text, str):
        raise TypeError("invalid new_public_key")
    try:
        new_public_key = bytes.fromhex(new_public_text)
    except ValueError as error:
        raise ValueError("invalid new_public_key") from error
    if document.get("new_key_id") != key_id(new_public_key):
        raise ValueError("new_key_id does not bind new_public_key")
    old_signature_text = document.get("old_signature")
    new_signature_text = document.get("new_signature")
    if not isinstance(old_signature_text, str) or not isinstance(new_signature_text, str):
        raise TypeError("transition requires both signatures")
    try:
        old_signature = bytes.fromhex(old_signature_text)
        new_signature = bytes.fromhex(new_signature_text)
    except ValueError as error:
        raise ValueError("invalid transition signature") from error
    message = key_transition_signing_message(document)
    Ed25519PublicKey.from_public_bytes(old_public_key).verify(old_signature, message)
    Ed25519PublicKey.from_public_bytes(new_public_key).verify(new_signature, message)
