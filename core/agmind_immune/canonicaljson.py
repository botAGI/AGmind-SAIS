"""AGmind Canonical JSON v1 and deterministic contract identifiers."""

from __future__ import annotations

import hashlib
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
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        return (
            "{" + ",".join(_quote(key) + ":" + _encode(value[key]) for key in sorted(value)) + "}"
        )
    raise ValueError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json(value: object) -> bytes:
    return _encode(value).encode("utf-8")


def event_id(envelope: Any) -> str:
    try:
        normalized_digest = bytes.fromhex(envelope.normalized_fields_sha256)
    except ValueError as error:
        raise ValueError("invalid normalized_fields_sha256") from error
    if len(normalized_digest) != 32:
        raise ValueError("normalized_fields_sha256 must contain 32 bytes")
    preimage = b"AGMIND_EVENT_ID_V1\0" + envelope.host_id.encode("ascii") + b"\0"
    preimage += envelope.boot_id.encode("ascii") + b"\0"
    preimage += int(envelope.key_epoch).to_bytes(8, "big", signed=False)
    preimage += int(envelope.source_sequence).to_bytes(8, "big", signed=False) + normalized_digest
    return "evt_" + hashlib.sha256(preimage).hexdigest()


def plan_hash(plan: BaseModel) -> str:
    document = plan.model_dump(exclude_none=True)
    document.pop("plan_hash", None)
    return hashlib.sha256(b"AGMIND_PLAN_HASH_V1\0" + canonical_json(document)).hexdigest()


def event_signing_message(envelope: BaseModel) -> bytes:
    document = envelope.model_dump(exclude_none=True)
    document.pop("source_signature", None)
    return b"AGMIND_EVENT_ENVELOPE_V1\0" + canonical_json(document)


def verify_event_signature(envelope: BaseModel, public_key: bytes) -> None:
    try:
        signature = bytes.fromhex(str(envelope.model_dump()["source_signature"]))
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, event_signing_message(envelope)
        )
    except ValueError as error:
        raise ValueError("invalid event signature") from error
