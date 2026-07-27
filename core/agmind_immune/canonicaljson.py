"""AGmind Canonical JSON v1 and locked cryptographic derivations."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel


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


def _encode(value: object) -> str:
    if isinstance(value, BaseModel):
        return _encode(value.model_dump(exclude_none=True))
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("floating-point JSON is forbidden")  # noqa: TRY004
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        document = dict(value)
        return (
            "{"
            + ",".join(
                _quote(key) + ":" + _encode(document[key]) for key in sorted(document)
            )
            + "}"
        )
    raise ValueError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json(value: object) -> bytes:
    return _encode(value).encode("utf-8")


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


def intent_id(candidate_id_value: str, policy_bundle_sha256: str, ttl_seconds: int) -> str:
    if not 0 <= ttl_seconds <= 2**64 - 1:
        raise ValueError("ttl_seconds must be uint64")
    preimage = b"AGMIND_INTENT_ID_V1\0"
    preimage += _ascii(candidate_id_value, "candidate_id") + b"\0"
    preimage += _ascii(policy_bundle_sha256, "policy_bundle_sha256") + b"\0"
    preimage += str(ttl_seconds).encode("ascii")
    return "int_" + hashlib.sha256(preimage).hexdigest()[:32]


def plan_id(intent_id_value: str, nonce: bytes) -> str:
    if not nonce:
        raise ValueError("nonce bytes must not be empty")
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
    try:
        digest = bytes.fromhex(record_sha256)
    except ValueError as error:
        raise ValueError("invalid record_sha256") from error
    if len(digest) != 32:
        raise ValueError("record_sha256 must contain 32 bytes")
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
