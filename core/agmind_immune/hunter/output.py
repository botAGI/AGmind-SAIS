"""Strict non-authoritative output validation for hostile model bytes."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Literal

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import HunterOutputV1, decode_strict

MAX_HUNTER_OUTPUT_BYTES = 16_384
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

HunterStatus = Literal["available", "unavailable", "invalid", "expired", "queue_full"]


class HunterOutputInvalid(ValueError):
    """The untrusted model returned bytes outside the annotation contract."""


def _contains_control(value: str) -> bool:
    return any(
        ord(char) < 0x20
        or 0x7F <= ord(char) <= 0x9F
        or unicodedata.category(char) == "Cf"
        or unicodedata.bidirectional(char)
        in {"BN", "LRE", "LRI", "LRO", "PDF", "PDI", "RLE", "RLI", "RLO"}
        for char in value
    )


def decode_hunter_output(
    raw: bytes,
    allowed_evidence_ids: frozenset[str],
) -> HunterOutputV1:
    """Decode exactly one bounded annotation and bind every cited evidence ID."""
    if type(raw) is not bytes:
        raise HunterOutputInvalid("hunter output must be exact bytes")
    if type(allowed_evidence_ids) is not frozenset:
        raise HunterOutputInvalid("allowed evidence IDs must be an exact frozen set")
    try:
        output = decode_strict(raw, HunterOutputV1, MAX_HUNTER_OUTPUT_BYTES)
    except (TypeError, ValueError) as error:
        raise HunterOutputInvalid("hunter output is not one strict v1 object") from error
    if type(output) is not HunterOutputV1:
        raise HunterOutputInvalid("hunter output has an inexact runtime type")
    if not set(output.supporting_evidence_ids).issubset(allowed_evidence_ids):
        raise HunterOutputInvalid("hunter output cites evidence outside the supplied bundle")
    text = (
        *output.hypotheses,
        *output.refuting_questions,
        output.narrative,
        *output.limitations,
    )
    if any(_contains_control(value) for value in text):
        raise HunterOutputInvalid("hunter output contains terminal control characters")
    try:
        detached = HunterOutputV1.model_validate(output.model_dump(mode="python"), strict=True)
    except (TypeError, ValueError) as error:
        raise HunterOutputInvalid("hunter output cannot be detached") from error
    if canonical_json(detached) != canonical_json(output):
        raise HunterOutputInvalid("hunter output changed while detaching")
    return detached


@dataclass(frozen=True, slots=True)
class HunterResult:
    """Typed enrichment outcome; every non-available result carries no model text."""

    status: HunterStatus
    output: HunterOutputV1 | None
    bundle_sha256: str
    reason_code: str

    def __post_init__(self) -> None:
        if (
            type(self.status) is not str
            or self.status not in {"available", "unavailable", "invalid", "expired", "queue_full"}
            or type(self.bundle_sha256) is not str
            or _HEX64.fullmatch(self.bundle_sha256) is None
            or type(self.reason_code) is not str
            or not 1 <= len(self.reason_code) <= 64
            or not self.reason_code.isascii()
        ):
            raise ValueError("hunter result metadata is invalid")
        if self.status == "available":
            if type(self.output) is not HunterOutputV1:
                raise ValueError("available hunter result requires exact output")
        elif self.output is not None:
            raise ValueError("non-available hunter result cannot expose model output")
