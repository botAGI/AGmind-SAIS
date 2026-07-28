from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any

from agmind_immune.canonicaljson import (
    canonical_json,
    event_id,
    event_signing_message,
    key_id,
    key_transition_signing_message,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HOST_ID = "123e4567-e89b-42d3-a456-426614174000"
BOOT_A = "223e4567-e89b-42d3-a456-426614174000"
BOOT_B = "323e4567-e89b-42d3-a456-426614174000"
NOW = "2026-07-28T10:00:00Z"


def private_key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def root_value(key: Ed25519PrivateKey, *, host_id: str = HOST_ID) -> dict[str, object]:
    public = public_bytes(key)
    return {
        "schema_version": "agmind.observer-trust-root.v1",
        "host_id": host_id,
        "key_id": key_id(public),
        "key_epoch": 1,
        "public_key": public.hex(),
    }


def transition_value(
    old_key: Ed25519PrivateKey,
    new_key: Ed25519PrivateKey,
    *,
    old_epoch: int = 1,
    host_id: str = HOST_ID,
) -> dict[str, object]:
    old_public = public_bytes(old_key)
    new_public = public_bytes(new_key)
    value: dict[str, object] = {
        "schema_version": "agmind.key-transition.v1",
        "old_key_id": key_id(old_public),
        "new_key_id": key_id(new_public),
        "old_epoch": old_epoch,
        "new_epoch": old_epoch + 1,
        "new_public_key": new_public.hex(),
        "host_id": host_id,
        "occurred_at": NOW,
    }
    message = key_transition_signing_message(value)
    value["old_signature"] = old_key.sign(message).hex()
    value["new_signature"] = new_key.sign(message).hex()
    return value


def envelope_value(
    signing_key: Ed25519PrivateKey,
    *,
    sequence: int,
    boot_id: str = BOOT_A,
    key_epoch: int = 1,
    event_type: str = "test_event",
    normalized_fields: dict[str, Any] | None = None,
    coverage_flags: list[str] | None = None,
    source_payload_hash: str | None = None,
    container_id: str | None = None,
    container_start_time: str | None = None,
    release_id: str | None = None,
    inventory_generation: int = 0,
    inventory_revision: int | None = None,
    host_id: str = HOST_ID,
) -> dict[str, object]:
    fields = normalized_fields or {"kind": "test_event"}
    normalized_hash = hashlib.sha256(canonical_json(fields)).hexdigest()
    public = public_bytes(signing_key)
    identity = SimpleNamespace(
        host_id=host_id,
        boot_id=boot_id,
        key_epoch=key_epoch,
        source_sequence=sequence,
        normalized_fields_sha256=normalized_hash,
    )
    value: dict[str, object] = {
        "schema_version": "agmind.event-envelope.v1",
        "event_id": event_id(identity),
        "event_type": event_type,
        "source_id": "agmind-observerd",
        "source_version": "0.1.0",
        "key_id": key_id(public),
        "key_epoch": key_epoch,
        "host_id": host_id,
        "boot_id": boot_id,
        "source_sequence": sequence,
        "event_time": NOW,
        "ingest_time": NOW,
        "clock_uncertainty_ms": 0,
        "inventory_generation": inventory_generation,
        "normalized_fields": fields,
        "normalized_fields_sha256": normalized_hash,
        "redaction_flags": [],
        "coverage_flags": sorted(coverage_flags or []),
        "source_payload_hash": source_payload_hash or normalized_hash,
    }
    if container_id is not None:
        value["container_id"] = container_id
    if container_start_time is not None:
        value["container_start_time"] = container_start_time
    if release_id is not None:
        value["release_id"] = release_id
    if inventory_revision is not None:
        value["inventory_revision"] = inventory_revision
    value["source_signature"] = signing_key.sign(event_signing_message(value)).hex()
    return value


def boot_boundary(
    key: Ed25519PrivateKey,
    *,
    sequence: int = 1,
    boot_id: str = BOOT_A,
    previous_boot_id: str | None = None,
    previous_source_sequence: int = 0,
) -> dict[str, object]:
    fields: dict[str, Any] = {
        "schema_version": "agmind.observer-boot-boundary.v1",
        "kind": "observer_boot_boundary",
        "reason_code": "observer_genesis"
        if previous_boot_id is None
        else "kernel_boot_id_changed",
        "previous_source_sequence": previous_source_sequence,
    }
    if previous_boot_id is not None:
        fields["previous_boot_id"] = previous_boot_id
    return envelope_value(
        key,
        sequence=sequence,
        boot_id=boot_id,
        event_type="observer_boot_boundary",
        normalized_fields=fields,
        coverage_flags=["boot_transition", "reconcile_required"],
    )


def rotation_pair(
    old_key: Ed25519PrivateKey,
    new_key: Ed25519PrivateKey,
    *,
    transition_sequence: int,
    transition_boot: str,
    start_boot: str,
    mode: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    transition = transition_value(old_key, new_key)
    if mode == "b":
        transition_flags = ["boot_transition", "key_rotation"]
        start_flags = ["key_rotation"]
    elif mode == "c":
        transition_flags = ["key_rotation"]
        start_flags = ["boot_transition", "key_rotation"]
    else:
        transition_flags = ["key_rotation"]
        start_flags = ["key_rotation"]
    transition_envelope = envelope_value(
        old_key,
        sequence=transition_sequence,
        boot_id=transition_boot,
        event_type="observer_key_transition",
        normalized_fields=transition,
        coverage_flags=transition_flags,
    )
    new_public = public_bytes(new_key)
    start_envelope = envelope_value(
        new_key,
        sequence=transition_sequence + 1,
        boot_id=start_boot,
        key_epoch=2,
        event_type="observer_key_epoch_start",
        normalized_fields={
            "kind": "observer_key_epoch_start",
            "key_id": key_id(new_public),
            "key_epoch": 2,
        },
        coverage_flags=start_flags,
    )
    return transition, transition_envelope, start_envelope


def metadata_value(
    root_key: Ed25519PrivateKey,
    *,
    rotation: tuple[dict[str, object], dict[str, object], dict[str, object]] | None = None,
) -> dict[str, object]:
    root_public = public_bytes(root_key)
    keys: list[dict[str, object]] = [
        {
            "key_id": key_id(root_public),
            "epoch": 1,
            "public_key": root_public.hex(),
        }
    ]
    if rotation is not None:
        transition, transition_envelope, start_envelope = rotation
        keys.append(
            {
                "key_id": transition["new_key_id"],
                "epoch": 2,
                "public_key": transition["new_public_key"],
                "transition": transition,
                "transition_envelope": transition_envelope,
                "epoch_start_envelope": start_envelope,
            }
        )
    last = keys[-1]
    return {
        "schema_version": "agmind.observer-public-keys.v1",
        "host_id": HOST_ID,
        "current_key_id": last["key_id"],
        "current_epoch": last["epoch"],
        "keys": keys,
    }


def page_value(*envelopes: dict[str, object]) -> dict[str, object]:
    events = []
    for envelope in envelopes:
        canonical = canonical_json(envelope)
        events.append(
            {
                "sequence": envelope["source_sequence"],
                "event_id": envelope["event_id"],
                "content_sha256": hashlib.sha256(canonical).hexdigest(),
                "envelope": envelope,
            }
        )
    reserved = max((int(item["sequence"]) for item in events), default=0)
    return {
        "schema_version": "agmind.observer-events-page.v1",
        "events": events,
        "uncovered_gaps": [],
        "gaps_truncated": False,
        "acked_through": 0,
        "reserved_through": reserved,
    }
