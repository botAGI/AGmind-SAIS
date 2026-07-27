"""Strict, bounded mirrors of the versioned AGmind wire contracts."""

from __future__ import annotations

import csv
import datetime as dt
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$")
_IPV4 = re.compile(r"^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$")
_MAX_UINT64 = 2**64 - 1


def _reject_float(_: str) -> object:
    raise ValueError("floating-point JSON is forbidden")


def _reject_constant(_: str) -> object:
    raise ValueError("non-finite JSON number is forbidden")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_strict[T: BaseModel](raw: bytes, model: type[T], max_bytes: int) -> T:
    """Decode exactly one bounded JSON value before Pydantic validation."""
    if max_bytes < 1 or len(raw) > max_bytes:
        raise ValueError("JSON input exceeds explicit byte limit")
    text = raw.decode("utf-8", "strict")
    decoder = json.JSONDecoder(
        object_pairs_hook=_unique_object, parse_float=_reject_float, parse_constant=_reject_constant
    )
    try:
        value, end = decoder.raw_decode(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON: {error.msg}") from error
    if text[end:].strip():
        raise ValueError("trailing JSON data is forbidden")
    if not isinstance(value, dict):
        raise ValueError("contract JSON must be an object")  # noqa: TRY004
    return model.model_validate(value, strict=True)


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _valid_ipv4(value: str) -> str:
    if not _IPV4.fullmatch(value):
        raise ValueError("IPv4 must be canonical dotted decimal")
    try:
        parsed = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError("invalid IPv4 address") from error
    if str(parsed) != value:
        raise ValueError("IPv4 must not contain leading zeroes")
    return value


def _valid_timestamp(value: str) -> str:
    if not _TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be RFC3339 UTC ending in Z")
    try:
        dt.datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("invalid RFC3339 timestamp") from error
    return value


class EventEnvelopeV1(ContractModel):
    schema_version: str
    event_id: str
    event_type: str = Field(max_length=64)
    source_id: str = Field(max_length=512)
    source_version: str = Field(max_length=64)
    key_id: str
    key_epoch: int = Field(ge=1, le=_MAX_UINT64)
    host_id: str
    boot_id: str
    source_sequence: int = Field(ge=0, le=_MAX_UINT64)
    event_time: str
    ingest_time: str
    clock_uncertainty_ms: int = Field(ge=0, le=2_000)
    container_id: str | None = None
    container_start_time: str | None = None
    release_id: str | None = None
    inventory_generation: int = Field(ge=0, le=_MAX_UINT64)
    inventory_revision: int | None = Field(default=None, ge=0, le=_MAX_UINT64)
    normalized_fields: dict[str, Any]
    normalized_fields_sha256: str
    redaction_flags: list[str] = Field(max_length=64)
    coverage_flags: list[str] = Field(max_length=64)
    source_payload_hash: str
    source_signature: str

    @field_validator("schema_version")
    @classmethod
    def schema_is_supported(cls, value: str) -> str:
        if value != "agmind.event-envelope.v1":
            raise ValueError("unsupported event schema version")
        return value

    @field_validator("event_id")
    @classmethod
    def event_id_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"evt_[0-9a-f]{64}", value):
            raise ValueError("invalid event_id")
        return value

    @field_validator("key_id")
    @classmethod
    def key_id_is_valid(cls, value: str) -> str:
        if not _HEX32.fullmatch(value):
            raise ValueError("invalid key_id")
        return value

    @field_validator("host_id", "boot_id")
    @classmethod
    def uuid_is_valid(cls, value: str) -> str:
        if not _UUID4.fullmatch(value):
            raise ValueError("identity must be a lowercase UUIDv4")
        return value

    @field_validator("event_time", "ingest_time", "container_start_time")
    @classmethod
    def timestamp_is_valid(cls, value: str | None) -> str | None:
        return None if value is None else _valid_timestamp(value)

    @field_validator("normalized_fields_sha256", "source_payload_hash")
    @classmethod
    def digest_is_valid(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("invalid sha256 digest")
        return value

    @field_validator("source_signature")
    @classmethod
    def signature_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{128}", value):
            raise ValueError("invalid Ed25519 signature")
        return value

    @model_validator(mode="after")
    def normalized_fields_are_bounded(self) -> EventEnvelopeV1:
        from .canonicaljson import canonical_json

        if len(canonical_json(self.normalized_fields)) > 32 * 1024:
            raise ValueError("normalized fields exceed 32 KiB")
        return self


class HunterOutputV1(ContractModel):
    schema_version: str
    hypotheses: list[str] = Field(max_length=8)
    supporting_evidence_ids: list[str] = Field(max_length=8)
    refuting_questions: list[str] = Field(max_length=8)
    narrative: str = Field(max_length=8_192)
    limitations: list[str] = Field(max_length=8)

    @field_validator("schema_version")
    @classmethod
    def schema_is_supported(cls, value: str) -> str:
        if value != "agmind.hunter-output.v1":
            raise ValueError("unsupported hunter schema version")
        return value

    @field_validator("hypotheses", "supporting_evidence_ids", "refuting_questions", "limitations")
    @classmethod
    def entries_are_bounded(cls, value: list[str]) -> list[str]:
        if any(len(item.encode("utf-8")) > 1_024 for item in value):
            raise ValueError("hunter entry exceeds 1,024 bytes")
        return value


class TemporaryEgressDenyIntentV1(ContractModel):
    schema_version: str
    intent_id: str
    verb: str
    host_id: str
    docker_container_id: str
    docker_started_at: str
    image_id: str
    repo_digests: list[str] = Field(max_length=16)
    immutable_spec_sha256: str
    inventory_generation: int = Field(ge=0, le=_MAX_UINT64)
    inventory_revision: int = Field(ge=0, le=_MAX_UINT64)
    destination_ipv4: str
    ttl_seconds: int = Field(ge=30, le=300)
    evidence_ids: list[str] = Field(min_length=1, max_length=32)
    detector_bundle_sha256: str
    policy_bundle_version: str = Field(max_length=64)
    policy_bundle_sha256: str
    coverage_snapshot_sha256: str
    created_at: str

    @field_validator("schema_version")
    @classmethod
    def schema_is_supported(cls, value: str) -> str:
        if value != "agmind.temporary-egress-deny-intent.v1":
            raise ValueError("unsupported intent schema version")
        return value

    @field_validator("intent_id")
    @classmethod
    def intent_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"int_[0-9a-f]{32}", value):
            raise ValueError("invalid intent_id")
        return value

    @field_validator("verb")
    @classmethod
    def only_deny_verb(cls, value: str) -> str:
        if value != "temporary_egress_deny":
            raise ValueError("unsupported intent verb")
        return value

    @field_validator("host_id")
    @classmethod
    def host_is_uuid(cls, value: str) -> str:
        if not _UUID4.fullmatch(value):
            raise ValueError("host_id must be lowercase UUIDv4")
        return value

    @field_validator("docker_container_id")
    @classmethod
    def container_is_valid(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("docker_container_id must be 64 lowercase hex")
        return value

    @field_validator("docker_started_at", "created_at")
    @classmethod
    def time_is_valid(cls, value: str) -> str:
        return _valid_timestamp(value)

    @field_validator("image_id")
    @classmethod
    def image_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("invalid immutable image ID")
        return value

    @field_validator(
        "immutable_spec_sha256",
        "detector_bundle_sha256",
        "policy_bundle_sha256",
        "coverage_snapshot_sha256",
    )
    @classmethod
    def digest_is_valid(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("invalid sha256 digest")
        return value

    @field_validator("destination_ipv4")
    @classmethod
    def destination_is_valid(cls, value: str) -> str:
        return _valid_ipv4(value)

    @model_validator(mode="after")
    def sorted_collections(self) -> TemporaryEgressDenyIntentV1:
        if self.evidence_ids != sorted(set(self.evidence_ids)):
            raise ValueError("evidence_ids must be unique and sorted")
        if self.repo_digests != sorted(set(self.repo_digests)):
            raise ValueError("repo_digests must be unique and sorted")
        if any(len(item.encode("utf-8")) > 256 for item in self.repo_digests):
            raise ValueError("repo digest exceeds 256 bytes")
        return self


class PreparedTemporaryEgressDenyPlanV1(TemporaryEgressDenyIntentV1):
    plan_id: str
    boot_id: str
    init_pid: int = Field(gt=0, le=_MAX_UINT64)
    pid_start_ticks: int = Field(gt=0, le=_MAX_UINT64)
    cgroup_path_sha256: str
    network_namespace_inode: int = Field(gt=0, le=_MAX_UINT64)
    docker_network_snapshot_sha256: str
    special_use_registry_sha256: str
    management_denylist_sha256: str
    hard_limits_version: str
    prepared_at: str
    approval_expires_at: str
    nonce: str
    plan_hash: str


@dataclass(frozen=True)
class SpecialUseEntry:
    network: ipaddress.IPv4Network
    globally_reachable: bool


def load_special_use_registry(path: Path) -> list[SpecialUseEntry]:
    entries: list[SpecialUseEntry] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            block = row["Address Block"].split()[0]
            try:
                network = ipaddress.ip_network(block, strict=False)
            except ValueError:
                continue
            if isinstance(network, ipaddress.IPv4Network):
                entries.append(SpecialUseEntry(network, row["Globally Reachable"] == "True"))
    return entries


def is_permitted_public_ipv4(
    address: str,
    registry: list[SpecialUseEntry],
    denied_networks: list[str],
    denied_addresses: list[str],
) -> bool:
    try:
        value = ipaddress.IPv4Address(_valid_ipv4(address))
    except ValueError:
        return False
    if value.is_multicast or value == ipaddress.IPv4Address("255.255.255.255"):
        return False
    try:
        if any(value in ipaddress.ip_network(network, strict=False) for network in denied_networks):
            return False
        if any(value == ipaddress.IPv4Address(denied) for denied in denied_addresses):
            return False
    except ValueError:
        return False
    matches = [entry for entry in registry if value in entry.network]
    # Addresses absent from the special-use registry are ordinary public IPv4.
    return not matches or max(matches, key=lambda entry: entry.network.prefixlen).globally_reachable
