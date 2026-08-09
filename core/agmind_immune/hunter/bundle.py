"""Bounded field-allowlisted evidence views for the untrusted AI hunter."""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.incidents.models import IncidentV1

MAX_HUNTER_INPUT_BYTES = 32_768
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)


def _utf8(value: str, field: str, maximum: int) -> str:
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError as error:
        raise ValueError(f"{field} must be valid UTF-8") from error
    if not 1 <= size <= maximum or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError(f"{field} must be 1..{maximum} valid UTF-8 bytes")
    return value


def _ascii(value: str, field: str, maximum: int = 64) -> str:
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field} must be ASCII") from error
    if (
        not 1 <= len(encoded) <= maximum
        or any(byte < 0x20 or byte > 0x7E for byte in encoded)
    ):
        raise ValueError(f"{field} must be bounded printable ASCII")
    return value


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class HunterEvidenceFactV1(_FrozenModel):
    """The complete and only evidence shape allowed to cross into DeepSeek."""

    evidence_id: str
    detector_rule: str
    detector_rule_version: str
    event_time: str
    proc_name: str | None = None
    proc_exe_basename: str | None = None
    proc_parent_basename: str | None = None
    destination_ipv4: str | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65_535)
    l4_protocol: str | None = None
    image_id: str | None = None
    coverage_flags: tuple[str, ...] = Field(max_length=32)

    @field_validator("evidence_id")
    @classmethod
    def evidence_identifier_is_exact(cls, value: str) -> str:
        if _EVENT_ID.fullmatch(value) is None:
            raise ValueError("evidence_id must be an exact event ID")
        return value

    @field_validator("detector_rule", "proc_name")
    @classmethod
    def text_is_bounded(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _utf8(value, info.field_name, 512)

    @field_validator("proc_exe_basename", "proc_parent_basename")
    @classmethod
    def basename_is_bounded(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        _utf8(value, info.field_name, 512)
        if value in {".", ".."} or "/" in value or "\x00" in value:
            raise ValueError(f"{info.field_name} must be a lexical basename")
        return value

    @field_validator("detector_rule_version", "l4_protocol")
    @classmethod
    def enum_is_bounded(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _ascii(value, info.field_name)

    @field_validator("event_time")
    @classmethod
    def event_time_is_exact(cls, value: str) -> str:
        if _TIMESTAMP.fullmatch(value) is None:
            raise ValueError("event_time must be canonical RFC3339Nano UTC")
        try:
            parsed = dt.datetime.fromisoformat(value)
        except ValueError as error:
            raise ValueError("event_time is invalid") from error
        if parsed.tzinfo != dt.UTC:
            raise ValueError("event_time must use UTC")
        return value

    @field_validator("destination_ipv4")
    @classmethod
    def destination_is_exact(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError as error:
            raise ValueError("destination_ipv4 must be canonical IPv4") from error
        if str(parsed) != value:
            raise ValueError("destination_ipv4 must be canonical IPv4")
        return value

    @field_validator("image_id")
    @classmethod
    def image_is_exact(cls, value: str | None) -> str | None:
        if value is not None and _IMAGE_ID.fullmatch(value) is None:
            raise ValueError("image_id must be an immutable Docker image ID")
        return value

    @field_validator("coverage_flags", mode="before")
    @classmethod
    def flags_are_exact_tuple(cls, value: object) -> object:
        if type(value) is not tuple:
            raise ValueError("coverage_flags must be an exact immutable tuple")
        return value

    @field_validator("coverage_flags")
    @classmethod
    def flags_are_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("coverage_flags must be unique and sorted")
        for value in values:
            _ascii(value, "coverage_flags")
        return values


class HunterBundleV1(_FrozenModel):
    """Canonical model input with no target, policy, approval, or action facts."""

    schema_version: Literal["agmind.hunter-bundle.v1"]
    evidence: tuple[HunterEvidenceFactV1, ...] = Field(min_length=1, max_length=8)
    omitted_evidence_ids: tuple[str, ...] = Field(max_length=8)
    limitations: tuple[str, ...] = Field(max_length=8)

    @field_validator("evidence", "omitted_evidence_ids", "limitations", mode="before")
    @classmethod
    def arrays_are_exact_tuples(cls, value: object, info: Any) -> object:
        if type(value) is not tuple:
            raise ValueError(f"{info.field_name} must be an exact immutable tuple")
        return value

    @field_validator("evidence")
    @classmethod
    def evidence_is_canonical(
        cls,
        values: tuple[HunterEvidenceFactV1, ...],
    ) -> tuple[HunterEvidenceFactV1, ...]:
        identifiers = tuple(value.evidence_id for value in values)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("hunter evidence must be unique and sorted")
        return values

    @field_validator("omitted_evidence_ids")
    @classmethod
    def omitted_ids_are_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))) or any(
            _EVENT_ID.fullmatch(value) is None for value in values
        ):
            raise ValueError("omitted evidence IDs must be exact, unique, and sorted")
        return values

    @field_validator("limitations")
    @classmethod
    def limitations_are_bounded(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _utf8(value, "limitations", 1_024)
        return values


def _detached_fact(value: object) -> HunterEvidenceFactV1:
    if type(value) is not HunterEvidenceFactV1:
        raise TypeError("hunter evidence must use the exact fact type")
    detached = HunterEvidenceFactV1.model_validate(
        value.model_dump(mode="python"),
        strict=True,
    )
    if canonical_json(detached) != canonical_json(value):
        raise ValueError("hunter evidence changed while detaching")
    return detached


def build_hunter_bundle(
    incident: IncidentV1,
    evidence: tuple[HunterEvidenceFactV1, ...],
) -> HunterBundleV1:
    """Build one deterministic incident-bound view without copying incident text."""
    if type(incident) is not IncidentV1:
        raise TypeError("hunter bundle requires an exact immutable incident")
    if type(evidence) is not tuple or not 1 <= len(evidence) <= 8:
        raise ValueError("hunter evidence must be an exact tuple of 1..8 facts")
    detached = tuple(sorted((_detached_fact(value) for value in evidence), key=lambda x: x.evidence_id))
    identifiers = tuple(value.evidence_id for value in detached)
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("hunter evidence IDs must be unique")
    incident_ids = frozenset(incident.evidence_ids)
    if any(identifier not in incident_ids for identifier in identifiers):
        raise ValueError("hunter fact is not bound to incident evidence")

    retained = detached
    omitted: tuple[str, ...] = ()
    while retained:
        limitations = (
            ()
            if not omitted
            else (f"{len(omitted)} evidence record(s) omitted by input byte limit",)
        )
        candidate = HunterBundleV1(
            schema_version="agmind.hunter-bundle.v1",
            evidence=retained,
            omitted_evidence_ids=omitted,
            limitations=limitations,
        )
        if len(canonical_json(candidate)) <= MAX_HUNTER_INPUT_BYTES:
            return candidate
        dropped = retained[-1]
        retained = retained[:-1]
        omitted = tuple(sorted((*omitted, dropped.evidence_id)))
    raise ValueError("one hunter evidence record exceeds the fixed input byte limit")
