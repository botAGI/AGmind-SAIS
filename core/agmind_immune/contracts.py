"""Strict, bounded mirrors of every versioned AGmind wire contract."""

from __future__ import annotations

import csv
import datetime as dt
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
IPV4 = re.compile(
    r"^(?:0|[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])"
    r"(?:\.(?:0|[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])){3}$"
)
MAX_UINT64 = 2**64 - 1
MIN_INT64 = -(2**63)
MAX_INT64 = 2**63 - 1
SUCCESS_RESULTS = {"EINPROGRESS", "EINPROGRESS(115)"}
FALCO_SENSOR_REQUIRED_FIELDS = {
    "destination_ipv4",
    "destination_port",
    "falco_container_id_prefix",
    "falco_container_start_ts",
    "l4_protocol",
    "proc_exe_path",
    "proc_name",
    "proc_parent_name",
}
MAX_JSON_NESTING_DEPTH = 64
ACTION_STATES = {
    "PROPOSED",
    "POLICY_ADMITTED",
    "PREPARED",
    "APPROVED",
    "APPLIED",
    "VERIFIED",
    "EXPIRED",
    "STALE_ABORT",
    "REJECTED",
    "FAILED_DIRTY",
    "EXPIRED_UNAPPLIED",
}


def _reject_float(_: str) -> object:
    raise ValueError("floating-point JSON is forbidden")


def _reject_constant(_: str) -> object:
    raise ValueError("non-finite JSON number is forbidden")


def _parse_integer(token: str) -> int:
    if token == "-0":
        raise ValueError("lexical negative zero is forbidden")
    if token.startswith("-"):
        magnitude = token[1:]
        limit = str(-MIN_INT64)
    else:
        magnitude = token
        limit = str(MAX_UINT64)
    if len(magnitude) > len(limit) or (
        len(magnitude) == len(limit) and magnitude > limit
    ):
        raise ValueError("integer exceeds canonical range")
    return int(token)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_json_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                raise ValueError("JSON nesting depth exceeds 64")
        elif char in "]}":
            depth -= 1


def _validate_unicode(value: object) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("surrogate code points are forbidden")
        value.encode("utf-8", "strict")
    elif isinstance(value, list):
        for item in value:
            _validate_unicode(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_unicode(key)
            _validate_unicode(item)


def decode_strict[T: BaseModel](raw: bytes, model: type[T], max_bytes: int) -> T:
    """Decode exactly one bounded JSON object before model validation."""
    if max_bytes < 1 or len(raw) > max_bytes:
        raise ValueError("JSON input exceeds explicit byte limit")
    text = raw.decode("utf-8", "strict")
    _validate_json_depth(text)
    decoder = json.JSONDecoder(
        object_pairs_hook=_unique_object,
        parse_int=_parse_integer,
        parse_float=_reject_float,
        parse_constant=_reject_constant,
    )
    start = 0
    while start < len(text) and text[start] in " \t\r\n":
        start += 1
    try:
        value, end = decoder.raw_decode(text, start)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON: {error.msg}") from error
    while end < len(text) and text[end] in " \t\r\n":
        end += 1
    if end != len(text):
        raise ValueError("trailing JSON data is forbidden")
    if not isinstance(value, dict):
        raise ValueError("contract JSON must be an object")  # noqa: TRY004
    _validate_unicode(value)
    for field_name, field in model.model_fields.items():
        wire_name = field.alias or field_name
        if field.is_required() and wire_name not in value:
            raise ValueError(f"missing required property: {wire_name}")
    for field_name, field_value in value.items():
        if field_value is None:
            raise ValueError(f"top-level null is forbidden: {field_name}")
    return model.model_validate(value, strict=True)


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _utf8(value: str, field: str, maximum: int, *, minimum: int = 1) -> str:
    size = len(value.encode("utf-8", "strict"))
    if size < minimum or size > maximum:
        raise ValueError(f"{field} must be {minimum}..{maximum} UTF-8 bytes")
    return value


def _ascii(value: str, field: str, maximum: int = 64, *, minimum: int = 1) -> str:
    try:
        size = len(value.encode("ascii"))
    except UnicodeEncodeError as error:
        raise ValueError(f"{field} must be ASCII") from error
    if size < minimum or size > maximum:
        raise ValueError(f"{field} must be {minimum}..{maximum} ASCII bytes")
    if any(not 0x20 <= ord(char) <= 0x7E for char in value):
        raise ValueError(f"{field} must contain printable ASCII")
    return value


def _valid_ipv4(value: str) -> str:
    if not IPV4.fullmatch(value):
        raise ValueError("IPv4 must be canonical dotted decimal")
    try:
        parsed = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError("invalid IPv4 address") from error
    if str(parsed) != value:
        raise ValueError("IPv4 must not contain leading zeroes")
    return value


def _valid_timestamp(value: str) -> str:
    if not TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be RFC3339Nano UTC ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("invalid RFC3339 timestamp") from error
    if parsed.tzinfo != dt.UTC:
        raise ValueError("timestamp must use UTC")
    return value


def _sorted_unique(values: list[str], field: str) -> list[str]:
    if values != sorted(set(values)):
        raise ValueError(f"{field} must be unique and sorted")
    return values


def _repo_digests(values: list[str]) -> list[str]:
    _sorted_unique(values, "repo_digests")
    for item in values:
        _utf8(item, "repo digest", 256)
    return values


def _validate_bounded_nested(
    value: object,
    *,
    maximum_string_characters: int,
    maximum_array_items: int,
    maximum_object_properties: int,
    maximum_property_name_characters: int,
    container_depth: int = 1,
) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not MIN_INT64 <= value <= MAX_UINT64:
            raise ValueError("nested integer exceeds canonical range")
        return
    if isinstance(value, float):
        raise ValueError("nested floating-point value is forbidden")  # noqa: TRY004
    if isinstance(value, str):
        _validate_unicode(value)
        if len(value) > maximum_string_characters:
            raise ValueError("nested string exceeds schema bound")
        return
    if isinstance(value, list):
        if container_depth > MAX_JSON_NESTING_DEPTH:
            raise ValueError("JSON nesting depth exceeds 64")
        if len(value) > maximum_array_items:
            raise ValueError("nested array exceeds schema bound")
        for item in value:
            _validate_bounded_nested(
                item,
                maximum_string_characters=maximum_string_characters,
                maximum_array_items=maximum_array_items,
                maximum_object_properties=maximum_object_properties,
                maximum_property_name_characters=maximum_property_name_characters,
                container_depth=container_depth + 1,
            )
        return
    if isinstance(value, dict):
        if container_depth > MAX_JSON_NESTING_DEPTH:
            raise ValueError("JSON nesting depth exceeds 64")
        if len(value) > maximum_object_properties:
            raise ValueError("nested object exceeds schema bound")
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("nested object keys must be strings")
            _validate_unicode(key)
            if len(key) > maximum_property_name_characters:
                raise ValueError("nested property name exceeds schema bound")
            _validate_bounded_nested(
                item,
                maximum_string_characters=maximum_string_characters,
                maximum_array_items=maximum_array_items,
                maximum_object_properties=maximum_object_properties,
                maximum_property_name_characters=maximum_property_name_characters,
                container_depth=container_depth + 1,
            )
        return
    raise ValueError(f"unsupported nested JSON type: {type(value).__name__}")


class EventEnvelopeV1(ContractModel):
    schema_version: Literal["agmind.event-envelope.v1"]
    event_id: str
    event_type: str
    source_id: str
    source_version: str
    key_id: str
    key_epoch: int = Field(ge=1, le=MAX_UINT64)
    host_id: str
    boot_id: str
    source_sequence: int = Field(ge=0, le=MAX_UINT64)
    event_time: str
    ingest_time: str
    clock_uncertainty_ms: int = Field(ge=0, le=2_000)
    container_id: str | None = None
    container_start_time: str | None = None
    release_id: str | None = None
    inventory_generation: int = Field(ge=0, le=MAX_UINT64)
    inventory_revision: int | None = Field(default=None, ge=0, le=MAX_UINT64)
    normalized_fields: dict[str, Any]
    normalized_fields_sha256: str
    redaction_flags: list[str] = Field(max_length=64)
    coverage_flags: list[str] = Field(max_length=64)
    source_payload_hash: str
    source_signature: str

    @field_validator("event_id")
    @classmethod
    def event_id_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"evt_[0-9a-f]{64}", value):
            raise ValueError("invalid event_id")
        return value

    @field_validator("event_type", "source_version")
    @classmethod
    def short_ascii(cls, value: str, info: Any) -> str:
        return _ascii(value, info.field_name)

    @field_validator("source_id")
    @classmethod
    def source_is_bounded(cls, value: str) -> str:
        return _utf8(value, "source_id", 512)

    @field_validator("key_id")
    @classmethod
    def key_id_is_valid(cls, value: str) -> str:
        if not HEX32.fullmatch(value):
            raise ValueError("invalid key_id")
        return value

    @field_validator("host_id", "boot_id")
    @classmethod
    def uuid_is_valid(cls, value: str) -> str:
        if not UUID4.fullmatch(value):
            raise ValueError("identity must be a lowercase UUIDv4")
        return value

    @field_validator("event_time", "ingest_time", "container_start_time")
    @classmethod
    def timestamp_is_valid(cls, value: str | None) -> str | None:
        return None if value is None else _valid_timestamp(value)

    @field_validator("container_id")
    @classmethod
    def container_is_valid(cls, value: str | None) -> str | None:
        if value is not None and not HEX64.fullmatch(value):
            raise ValueError("container_id must be 64 lowercase hex")
        return value

    @field_validator("release_id")
    @classmethod
    def release_is_valid(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"rel_[0-9a-f]{32}", value):
            raise ValueError("invalid release_id")
        return value

    @field_validator("normalized_fields_sha256", "source_payload_hash")
    @classmethod
    def digest_is_valid(cls, value: str) -> str:
        if not HEX64.fullmatch(value):
            raise ValueError("invalid sha256 digest")
        return value

    @field_validator("source_signature")
    @classmethod
    def signature_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{128}", value):
            raise ValueError("invalid Ed25519 signature")
        return value

    @field_validator("redaction_flags", "coverage_flags")
    @classmethod
    def flags_are_bounded(cls, values: list[str], info: Any) -> list[str]:
        _sorted_unique(values, info.field_name)
        for value in values:
            _ascii(value, info.field_name)
        return values

    @model_validator(mode="after")
    def normalized_fields_are_bounded(self) -> EventEnvelopeV1:
        import hashlib

        from .canonicaljson import canonical_json
        from .canonicaljson import event_id as derive_event_id

        canonical = canonical_json(self.normalized_fields)
        if len(canonical) > 32 * 1024:
            raise ValueError("normalized fields exceed 32 KiB")
        _validate_bounded_nested(
            self.normalized_fields,
            maximum_string_characters=8_192,
            maximum_array_items=128,
            maximum_object_properties=128,
            maximum_property_name_characters=512,
        )
        digest = hashlib.sha256(canonical).hexdigest()
        if digest != self.normalized_fields_sha256:
            raise ValueError("normalized_fields_sha256 does not match normalized_fields")
        if derive_event_id(self) != self.event_id:
            raise ValueError("event_id does not match locked derivation")
        return self


class FalcoConnectV1(ContractModel):
    detector_rule: str
    detector_rule_version: str
    falco_version: str
    event_time: str
    evt_type: Literal["connect"]
    evt_rawres: int | None = Field(default=None, ge=MIN_INT64, le=MAX_INT64)
    evt_res: str
    successful_connect: bool
    investigation_only: bool
    falco_container_id_prefix: str | None = None
    falco_container_full_id: str | None = None
    falco_container_start_ts: int | str | None = None
    docker_container_id: str | None = None
    docker_started_at: str | None = None
    image_id: str | None = None
    repo_digests: list[str] = Field(max_length=16)
    immutable_spec_sha256: str | None = None
    inventory_revision: int | None = Field(default=None, ge=0, le=MAX_UINT64)
    proc_name: str | None = None
    proc_exe_path: str | None = None
    proc_parent_name: str | None = None
    destination_ipv4: str | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65_535)
    l4_protocol: str | None = None
    missing_required_fields: list[str] = Field(max_length=32)
    raw_event_sha256: str

    @field_validator("detector_rule", "proc_name", "proc_exe_path", "proc_parent_name")
    @classmethod
    def safe_fragment(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _utf8(value, info.field_name, 512)

    @field_validator("detector_rule_version", "falco_version", "evt_res", "l4_protocol")
    @classmethod
    def enum_ascii(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _ascii(value, info.field_name)

    @field_validator("falco_container_id_prefix")
    @classmethod
    def prefix_is_valid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"[0-9a-f]{12,64}", value):
            raise ValueError("invalid Falco container ID prefix")
        return value

    @field_validator("falco_container_full_id", "docker_container_id")
    @classmethod
    def full_id_is_valid(cls, value: str | None) -> str | None:
        if value is not None and not HEX64.fullmatch(value):
            raise ValueError("Docker full ID must be 64 lowercase hex")
        return value

    @field_validator("docker_started_at")
    @classmethod
    def docker_time_is_valid(cls, value: str | None) -> str | None:
        return None if value is None else _valid_timestamp(value)

    @field_validator("event_time")
    @classmethod
    def event_time_is_valid(cls, value: str) -> str:
        return _valid_timestamp(value)

    @field_validator("image_id")
    @classmethod
    def image_is_valid(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("invalid immutable image ID")
        return value

    @field_validator("immutable_spec_sha256", "raw_event_sha256")
    @classmethod
    def digest_is_valid(cls, value: str | None) -> str | None:
        if value is not None and not HEX64.fullmatch(value):
            raise ValueError("invalid sha256 digest")
        return value

    @field_validator("destination_ipv4")
    @classmethod
    def destination_is_valid(cls, value: str | None) -> str | None:
        return None if value is None else _valid_ipv4(value)

    @field_validator("repo_digests")
    @classmethod
    def repos_are_bounded(cls, values: list[str]) -> list[str]:
        return _repo_digests(values)

    @field_validator("missing_required_fields")
    @classmethod
    def missing_fields_are_bounded(cls, values: list[str]) -> list[str]:
        _sorted_unique(values, "missing_required_fields")
        for value in values:
            _ascii(value, "missing_required_fields")
        return values

    @model_validator(mode="after")
    def result_and_candidate_semantics(self) -> FalcoConnectV1:
        if isinstance(self.falco_container_start_ts, int):
            if not MIN_INT64 <= self.falco_container_start_ts <= MAX_INT64:
                raise ValueError("falco_container_start_ts integer exceeds int64")
        elif isinstance(self.falco_container_start_ts, str):
            _ascii(self.falco_container_start_ts, "falco_container_start_ts")
        completed_success = (
            self.evt_res == "SUCCESS"
            and self.evt_rawres is not None
            and self.evt_rawres >= 0
        )
        nonblocking_success = (
            self.evt_res in SUCCESS_RESULTS
            and (self.evt_rawres is None or self.evt_rawres < 0)
        )
        hard_error = self.evt_res not in {"SUCCESS", *SUCCESS_RESULTS}
        if self.evt_res == "SUCCESS" and not completed_success:
            raise ValueError("invalid completed Falco result tuple")
        if self.evt_res in SUCCESS_RESULTS and not nonblocking_success:
            raise ValueError("invalid nonblocking Falco result tuple")
        if hard_error and self.evt_rawres is not None and self.evt_rawres >= 0:
            raise ValueError("invalid hard-error Falco result tuple")
        computed_success = completed_success or nonblocking_success
        if self.successful_connect != computed_success:
            raise ValueError("successful_connect contradicts Falco result")
        sensor_facts = {
            "falco_container_id_prefix": self.falco_container_id_prefix,
            "falco_container_start_ts": self.falco_container_start_ts,
            "proc_name": self.proc_name,
            "proc_exe_path": self.proc_exe_path,
            "proc_parent_name": self.proc_parent_name,
            "destination_ipv4": self.destination_ipv4,
            "destination_port": self.destination_port,
            "l4_protocol": self.l4_protocol,
        }
        omitted_sensor = {name for name, value in sensor_facts.items() if value is None}
        reported_missing = set(self.missing_required_fields)
        if reported_missing - FALCO_SENSOR_REQUIRED_FIELDS:
            raise ValueError("unknown missing_required_fields entry")
        if reported_missing & FALCO_SENSOR_REQUIRED_FIELDS != omitted_sensor:
            raise ValueError("missing_required_fields does not match sensor omissions")
        if omitted_sensor and not self.investigation_only:
            raise ValueError("sensor omissions must be investigation-only")
        authoritative = (
            self.docker_container_id,
            self.docker_started_at,
            self.image_id,
            self.immutable_spec_sha256,
            self.inventory_revision,
        )
        if not self.investigation_only:
            if (
                not self.successful_connect
                or omitted_sensor
                or any(item is None for item in authoritative)
            ):
                raise ValueError("candidate-capable event lacks authoritative identity")
            if self.missing_required_fields:
                raise ValueError("candidate-capable event cannot report missing fields")
        if not self.successful_connect and not self.investigation_only:
            raise ValueError("hard errors must be investigation-only")
        return self


class CoverageEventV1(ContractModel):
    component: str
    kind: str
    severity: Literal["INFO", "WARNING", "CRITICAL"]
    opened_at: str
    closed_at: str | None = None
    affected_source_sequence_start: int | None = Field(
        default=None, ge=0, le=MAX_UINT64
    )
    affected_source_sequence_end: int | None = Field(
        default=None, ge=0, le=MAX_UINT64
    )
    dropped_count: int | None = Field(default=None, ge=0, le=MAX_UINT64)
    reason_code: str
    reconcile_generation: int | None = Field(default=None, ge=0, le=MAX_UINT64)

    @field_validator("component", "kind", "reason_code")
    @classmethod
    def reason_ascii(cls, value: str, info: Any) -> str:
        return _ascii(value, info.field_name)

    @field_validator("opened_at", "closed_at")
    @classmethod
    def timestamp_is_valid(cls, value: str | None) -> str | None:
        return None if value is None else _valid_timestamp(value)

    @model_validator(mode="after")
    def intervals_are_ordered(self) -> CoverageEventV1:
        if self.closed_at is not None:
            opened = dt.datetime.fromisoformat(self.opened_at)
            closed = dt.datetime.fromisoformat(self.closed_at)
            if closed < opened:
                raise ValueError("closed_at precedes opened_at")
        if (
            self.affected_source_sequence_start is not None
            and self.affected_source_sequence_end is not None
            and self.affected_source_sequence_end < self.affected_source_sequence_start
        ):
            raise ValueError("coverage sequence interval is reversed")
        return self


class _EgressDenyFields(ContractModel):
    intent_id: str
    verb: Literal["temporary_egress_deny"]
    host_id: str
    docker_container_id: str
    docker_started_at: str
    image_id: str
    repo_digests: list[str] = Field(max_length=16)
    immutable_spec_sha256: str
    inventory_generation: int = Field(ge=0, le=MAX_UINT64)
    inventory_revision: int = Field(ge=0, le=MAX_UINT64)
    destination_ipv4: str
    ttl_seconds: int = Field(ge=30, le=300)
    evidence_ids: list[str] = Field(min_length=1, max_length=32)
    detector_bundle_sha256: str
    policy_bundle_version: str
    policy_bundle_sha256: str
    coverage_snapshot_sha256: str
    created_at: str

    @field_validator("intent_id")
    @classmethod
    def intent_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"int_[0-9a-f]{32}", value):
            raise ValueError("invalid intent_id")
        return value

    @field_validator("host_id")
    @classmethod
    def host_is_uuid(cls, value: str) -> str:
        if not UUID4.fullmatch(value):
            raise ValueError("host_id must be lowercase UUIDv4")
        return value

    @field_validator("docker_container_id")
    @classmethod
    def container_is_valid(cls, value: str) -> str:
        if not HEX64.fullmatch(value):
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
        if not HEX64.fullmatch(value):
            raise ValueError("invalid sha256 digest")
        return value

    @field_validator("destination_ipv4")
    @classmethod
    def destination_is_valid(cls, value: str) -> str:
        return _valid_ipv4(value)

    @field_validator("policy_bundle_version")
    @classmethod
    def policy_version_is_ascii(cls, value: str) -> str:
        return _ascii(value, "policy_bundle_version")

    @field_validator("repo_digests")
    @classmethod
    def repos_are_bounded(cls, values: list[str]) -> list[str]:
        return _repo_digests(values)

    @field_validator("evidence_ids")
    @classmethod
    def evidence_is_valid(cls, values: list[str]) -> list[str]:
        _sorted_unique(values, "evidence_ids")
        if any(not re.fullmatch(r"evt_[0-9a-f]{64}", value) for value in values):
            raise ValueError("invalid evidence ID")
        return values


class TemporaryEgressDenyIntentV1(_EgressDenyFields):
    schema_version: Literal["agmind.temporary-egress-deny-intent.v1"]


class PreparedTemporaryEgressDenyPlanV1(_EgressDenyFields):
    schema_version: Literal["agmind.prepared-temporary-egress-deny-plan.v1"]
    plan_id: str
    boot_id: str
    init_pid: int = Field(gt=0, le=MAX_UINT64)
    pid_start_ticks: int = Field(gt=0, le=MAX_UINT64)
    cgroup_path_sha256: str
    network_namespace_inode: int = Field(gt=0, le=MAX_UINT64)
    docker_network_snapshot_sha256: str
    special_use_registry_sha256: str
    management_denylist_sha256: str
    hard_limits_version: Literal["pcc-hard-limits-v1"]
    prepared_at: str
    approval_expires_at: str
    nonce: str
    plan_hash: str

    @field_validator("plan_id")
    @classmethod
    def plan_id_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"plan_[0-9a-f]{32}", value):
            raise ValueError("invalid plan_id")
        return value

    @field_validator("boot_id")
    @classmethod
    def boot_is_uuid(cls, value: str) -> str:
        if not UUID4.fullmatch(value):
            raise ValueError("boot_id must be lowercase UUIDv4")
        return value

    @field_validator(
        "cgroup_path_sha256",
        "docker_network_snapshot_sha256",
        "special_use_registry_sha256",
        "management_denylist_sha256",
        "plan_hash",
    )
    @classmethod
    def plan_digest_is_valid(cls, value: str) -> str:
        if not HEX64.fullmatch(value):
            raise ValueError("invalid sha256 digest")
        return value

    @field_validator("prepared_at", "approval_expires_at")
    @classmethod
    def plan_time_is_valid(cls, value: str) -> str:
        return _valid_timestamp(value)

    @field_validator("nonce")
    @classmethod
    def nonce_is_valid(cls, value: str) -> str:
        if not HEX64.fullmatch(value):
            raise ValueError("nonce must encode exactly 32 bytes as lowercase hex")
        return value

    @model_validator(mode="after")
    def identifiers_and_expiry_match(self) -> PreparedTemporaryEgressDenyPlanV1:
        from .canonicaljson import plan_hash, plan_id

        if plan_id(self.intent_id, bytes.fromhex(self.nonce)) != self.plan_id:
            raise ValueError("plan_id does not match locked derivation")
        if plan_hash(self) != self.plan_hash:
            raise ValueError("plan_hash does not match locked derivation")
        prepared = dt.datetime.fromisoformat(self.prepared_at)
        expires = dt.datetime.fromisoformat(self.approval_expires_at)
        if expires - prepared != dt.timedelta(minutes=5):
            raise ValueError("approval_expires_at must be exactly five minutes after prepared_at")
        return self


class HunterOutputV1(ContractModel):
    schema_version: Literal["agmind.hunter-output.v1"]
    hypotheses: list[str] = Field(max_length=8)
    supporting_evidence_ids: list[str] = Field(max_length=8)
    refuting_questions: list[str] = Field(max_length=8)
    narrative: str
    limitations: list[str] = Field(max_length=8)

    @field_validator("hypotheses", "refuting_questions", "limitations")
    @classmethod
    def entries_are_bounded(cls, values: list[str], info: Any) -> list[str]:
        for value in values:
            _utf8(value, info.field_name, 1_024)
        return values

    @field_validator("supporting_evidence_ids")
    @classmethod
    def supporting_evidence_is_valid(cls, values: list[str]) -> list[str]:
        _sorted_unique(values, "supporting_evidence_ids")
        if any(not re.fullmatch(r"evt_[0-9a-f]{64}", value) for value in values):
            raise ValueError("invalid supporting evidence ID")
        return values

    @field_validator("narrative")
    @classmethod
    def narrative_is_bounded(cls, value: str) -> str:
        return _utf8(value, "narrative", 8_192, minimum=0)


class ActionRecordV1(ContractModel):
    schema_version: Literal["agmind.action-record.v1"]
    record_id: str
    action_id: str | None = None
    plan_id: str
    plan_hash: str
    state: str
    reason_code: str
    observed_at: str
    previous_record_sha256: str
    record_sha256: str
    details: dict[str, Any]
    actuator_key_id: str
    actuator_signature: str

    @field_validator("record_id")
    @classmethod
    def record_id_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"ar_[0-9a-f]{32}", value):
            raise ValueError("invalid record_id")
        return value

    @field_validator("action_id")
    @classmethod
    def action_id_is_valid(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"act_[0-9a-f]{32}", value):
            raise ValueError("invalid action_id")
        return value

    @field_validator("plan_id")
    @classmethod
    def plan_id_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"plan_[0-9a-f]{32}", value):
            raise ValueError("invalid plan_id")
        return value

    @field_validator("plan_hash", "previous_record_sha256", "record_sha256")
    @classmethod
    def digest_is_valid(cls, value: str) -> str:
        if not HEX64.fullmatch(value):
            raise ValueError("invalid sha256 digest")
        return value

    @field_validator("state")
    @classmethod
    def state_is_valid(cls, value: str) -> str:
        if value not in ACTION_STATES:
            raise ValueError("invalid action state")
        return value

    @field_validator("reason_code")
    @classmethod
    def reason_is_ascii(cls, value: str) -> str:
        return _ascii(value, "reason_code")

    @field_validator("observed_at")
    @classmethod
    def observed_is_valid(cls, value: str) -> str:
        return _valid_timestamp(value)

    @field_validator("actuator_key_id")
    @classmethod
    def key_id_is_valid(cls, value: str) -> str:
        if not HEX32.fullmatch(value):
            raise ValueError("invalid actuator_key_id")
        return value

    @field_validator("actuator_signature")
    @classmethod
    def signature_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{128}", value):
            raise ValueError("invalid actuator signature")
        return value

    @model_validator(mode="after")
    def record_hashes_match(self) -> ActionRecordV1:
        from .canonicaljson import (
            action_id,
            action_record_hash,
            action_record_id,
            canonical_json,
        )

        _validate_bounded_nested(
            self.details,
            maximum_string_characters=1_024,
            maximum_array_items=64,
            maximum_object_properties=64,
            maximum_property_name_characters=64,
        )
        if len(canonical_json(self.details)) > 32 * 1024:
            raise ValueError("action details exceed 32 KiB")
        if self.action_id is not None and self.action_id != action_id(self.plan_hash):
            raise ValueError("action_id does not match plan_hash")
        expected = action_record_hash(self)
        if self.record_sha256 != expected:
            raise ValueError("record_sha256 does not match locked derivation")
        if self.record_id != action_record_id(expected):
            raise ValueError("record_id does not match record_sha256")
        return self


class KeyTransitionV1(ContractModel):
    schema_version: Literal["agmind.key-transition.v1"]
    old_key_id: str
    new_key_id: str
    old_epoch: int = Field(ge=1, le=MAX_UINT64)
    new_epoch: int = Field(ge=2, le=MAX_UINT64)
    new_public_key: str
    host_id: str
    occurred_at: str
    old_signature: str
    new_signature: str

    @field_validator("old_key_id", "new_key_id")
    @classmethod
    def key_id_is_valid(cls, value: str) -> str:
        if not HEX32.fullmatch(value):
            raise ValueError("invalid key_id")
        return value

    @field_validator("new_public_key")
    @classmethod
    def public_key_is_valid(cls, value: str) -> str:
        if not HEX64.fullmatch(value):
            raise ValueError("new_public_key must contain 32 bytes")
        return value

    @field_validator("host_id")
    @classmethod
    def host_is_valid(cls, value: str) -> str:
        if not UUID4.fullmatch(value):
            raise ValueError("host_id must be lowercase UUIDv4")
        return value

    @field_validator("occurred_at")
    @classmethod
    def occurred_is_valid(cls, value: str) -> str:
        return _valid_timestamp(value)

    @field_validator("old_signature", "new_signature")
    @classmethod
    def signature_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{128}", value):
            raise ValueError("invalid Ed25519 signature")
        return value

    @model_validator(mode="after")
    def epochs_and_new_key_match(self) -> KeyTransitionV1:
        from .canonicaljson import key_id

        if self.new_epoch != self.old_epoch + 1:
            raise ValueError("key epochs must be consecutive")
        if self.new_key_id != key_id(bytes.fromhex(self.new_public_key)):
            raise ValueError("new_key_id does not bind new_public_key")
        if self.old_key_id == self.new_key_id:
            raise ValueError("key transition must change keys")
        return self


@dataclass(frozen=True)
class SpecialUseEntry:
    network: ipaddress.IPv4Network
    globally_reachable: bool


def load_special_use_registry(path: Path) -> list[SpecialUseEntry]:
    entries: list[SpecialUseEntry] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            for raw_block in row["Address Block"].split(","):
                block = re.sub(r"\s+\[\d+\]\s*$", "", raw_block.strip())
                try:
                    network = ipaddress.ip_network(block, strict=False)
                except ValueError:
                    continue
                if isinstance(network, ipaddress.IPv4Network):
                    entries.append(
                        SpecialUseEntry(
                            network, row["Globally Reachable"] == "True"
                        )
                    )
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
    return not matches or max(
        matches, key=lambda entry: entry.network.prefixlen
    ).globally_reachable
