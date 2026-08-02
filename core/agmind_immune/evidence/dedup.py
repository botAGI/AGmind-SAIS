"""Frozen logical-primary identities shared by projection reducers."""

from __future__ import annotations

import hashlib
from typing import Literal

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import EventEnvelopeV1

_DEDUP_V1_DOMAIN = b"AGMIND_PROJECTION_DEDUP_V1\0"
_DEDUP_V2_DOMAIN = b"AGMIND_PROJECTION_DEDUP_V2\0"

type _DedupKind = Literal["falco_connect", "coverage", "other"]


def _logical_primary_key(
    envelope: EventEnvelopeV1,
    *,
    bind_boot: bool,
) -> tuple[_DedupKind, tuple[str, ...]]:
    if type(envelope) is not EventEnvelopeV1:
        raise TypeError("logical-primary identity requires an exact envelope")
    boot = (envelope.boot_id,) if bind_boot else ()
    if envelope.event_type == "falco_connect":
        return (
            "falco_connect",
            (
                envelope.host_id,
                *boot,
                envelope.event_type,
                envelope.source_payload_hash,
            ),
        )
    if envelope.event_type == "coverage":
        return (
            "coverage",
            (
                envelope.host_id,
                *boot,
                envelope.event_type,
                envelope.normalized_fields_sha256,
                envelope.source_payload_hash,
            ),
        )
    return "other", (envelope.event_id,)


def _logical_primary_identity(
    envelope: EventEnvelopeV1,
    *,
    version: Literal[1, 2],
) -> tuple[_DedupKind, str]:
    if version == 1:
        domain = _DEDUP_V1_DOMAIN
        bind_boot = False
    elif version == 2:
        domain = _DEDUP_V2_DOMAIN
        bind_boot = True
    else:
        raise ValueError("logical-primary version is not frozen")
    kind, key = _logical_primary_key(envelope, bind_boot=bind_boot)
    digest = hashlib.sha256(
        domain + kind.encode("ascii") + b"\0" + canonical_json(key)
    ).hexdigest()
    return kind, digest


def _logical_primary_identity_v1(
    envelope: EventEnvelopeV1,
) -> tuple[_DedupKind, str]:
    return _logical_primary_identity(envelope, version=1)


def _logical_primary_identity_v2(
    envelope: EventEnvelopeV1,
) -> tuple[_DedupKind, str]:
    return _logical_primary_identity(envelope, version=2)


__all__: list[str] = []
