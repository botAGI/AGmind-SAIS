"""Strict immutable incident and containment-candidate facts."""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..canonicaljson import candidate_id as derive_candidate_id
from ..canonicaljson import incident_id as derive_incident_id

MAX_UINT64 = 2**64 - 1
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_INCIDENT_ID = re.compile(r"^inc_[0-9a-f]{64}$")
_CANDIDATE_ID = re.compile(r"^cand_[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_INCIDENT_OPTIONAL_FIELDS = (
    "docker_container_id",
    "docker_started_at",
    "proc_name",
    "proc_exe_path",
    "proc_parent_name",
    "destination_ipv4",
    "destination_port",
    "l4_protocol",
)

CorrelationReasonCode = Literal[
    "detector_not_pinned",
    "connect_not_successful",
    "sensor_fields_incomplete",
    "authoritative_identity_incomplete",
    "investigation_only",
    "detector_bundle_not_pinned",
    "mutation_read_only",
    "reconcile_required",
    "docker_reconcile_gap",
    "routine_drop_pending",
    "inventory_stale",
    "docker_network_snapshot_unavailable",
    "docker_network_snapshot_overflow",
    "detector_bundle_unavailable",
    "special_use_registry_unavailable",
    "operator_denylist_unavailable",
    "management_denylist_unavailable",
    "container_not_running",
    "container_identity_changed",
    "observer_boot_changed",
    "event_stale",
    "clock_uncertain",
    "historical_coverage_incomplete",
    "critical_coverage_gap",
    "correlation_proof_mismatch",
    "destination_not_public",
    "docker_destination",
    "operator_destination",
    "management_destination",
    "target_not_running",
    "shared_network_namespace",
    "unsupported_network_mode",
    "unsupported_network_driver",
    "privileged_target",
    "target_cap_net_admin",
    "ttl_out_of_bounds",
    "candidate_cooldown",
]
CORRELATION_REASON_CODES: frozenset[str] = frozenset(
    str(value) for value in get_args(CorrelationReasonCode)
)


def _utf8(value: str, field: str, maximum: int) -> str:
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError as error:
        raise ValueError(f"{field} must be valid UTF-8") from error
    if not 1 <= size <= maximum:
        raise ValueError(f"{field} must be 1..{maximum} UTF-8 bytes")
    return value


def _ascii(value: str, field: str, maximum: int = 64) -> str:
    try:
        size = len(value.encode("ascii"))
    except UnicodeEncodeError as error:
        raise ValueError(f"{field} must be ASCII") from error
    if not 1 <= size <= maximum:
        raise ValueError(f"{field} must be 1..{maximum} ASCII bytes")
    if any(not 0x20 <= ord(character) <= 0x7E for character in value):
        raise ValueError(f"{field} must contain printable ASCII")
    return value


def _timestamp(value: str, field: str) -> str:
    if not _TIMESTAMP.fullmatch(value):
        raise ValueError(f"{field} must be RFC3339Nano UTC ending in Z")
    try:
        dt.datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{field} must be a valid RFC3339Nano timestamp") from error
    return value


def _ipv4(value: str) -> str:
    try:
        parsed = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError("destination_ipv4 must be canonical dotted decimal") from error
    if str(parsed) != value:
        raise ValueError("destination_ipv4 must be canonical dotted decimal")
    return value


def _exact_tuple(value: object, field: str) -> object:
    if type(value) is not tuple:
        raise ValueError(f"{field} must be an immutable tuple")
    return value


def _canonical_strings(
    values: tuple[str, ...],
    field: str,
    *,
    maximum_items: int,
    maximum_item_bytes: int = 64,
    ascii_only: bool,
) -> tuple[str, ...]:
    if len(values) > maximum_items:
        raise ValueError(f"{field} exceeds {maximum_items} entries")
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{field} must be unique and sorted")
    for value in values:
        if ascii_only:
            _ascii(value, field, maximum_item_bytes)
        else:
            _utf8(value, field, maximum_item_bytes)
    return values


def _event_ids(
    values: tuple[str, ...],
    field: str,
    *,
    maximum_items: int,
) -> tuple[str, ...]:
    if not 1 <= len(values) <= maximum_items:
        raise ValueError(f"{field} must contain 1..{maximum_items} event IDs")
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{field} must be unique and sorted")
    if any(not _EVENT_ID.fullmatch(value) for value in values):
        raise ValueError(f"{field} must contain exact event IDs")
    return values


class _ImmutableFact(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class IncidentV1(_ImmutableFact):
    schema_version: Literal["agmind.incident.v1"]
    incident_id: str
    primary_event_id: str
    primary_source_sequence: int = Field(ge=1, le=MAX_UINT64)
    host_id: str
    boot_id: str
    detector_rule: str
    detector_rule_version: str
    event_time: str
    ingest_time: str
    successful_connect: bool
    investigation_only: bool
    docker_container_id: str | None = None
    docker_started_at: str | None = None
    proc_name: str | None = None
    proc_exe_path: str | None = None
    proc_parent_name: str | None = None
    destination_ipv4: str | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65_535)
    l4_protocol: str | None = None
    missing_required_fields: tuple[str, ...]
    coverage_flags: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    reason_codes: tuple[CorrelationReasonCode, ...]
    authority_event_id: str

    @field_validator(
        "missing_required_fields",
        "coverage_flags",
        "evidence_ids",
        "reason_codes",
        mode="before",
    )
    @classmethod
    def arrays_are_exact_tuples(cls, value: object, info: Any) -> object:
        return _exact_tuple(value, info.field_name)

    @field_validator("incident_id")
    @classmethod
    def incident_identifier_is_exact(cls, value: str) -> str:
        if not _INCIDENT_ID.fullmatch(value):
            raise ValueError("incident_id must be an exact incident ID")
        return value

    @field_validator("primary_event_id", "authority_event_id")
    @classmethod
    def event_identifier_is_exact(cls, value: str, info: Any) -> str:
        if not _EVENT_ID.fullmatch(value):
            raise ValueError(f"{info.field_name} must be an exact event ID")
        return value

    @field_validator("host_id", "boot_id")
    @classmethod
    def host_identity_is_exact(cls, value: str, info: Any) -> str:
        if not _UUID4.fullmatch(value):
            raise ValueError(f"{info.field_name} must be a lowercase UUIDv4")
        return value

    @field_validator("detector_rule", "proc_name", "proc_exe_path", "proc_parent_name")
    @classmethod
    def untrusted_fragment_is_bounded(
        cls,
        value: str | None,
        info: Any,
    ) -> str | None:
        return None if value is None else _utf8(value, info.field_name, 512)

    @field_validator("detector_rule_version", "l4_protocol")
    @classmethod
    def enum_is_bounded_ascii(
        cls,
        value: str | None,
        info: Any,
    ) -> str | None:
        return None if value is None else _ascii(value, info.field_name)

    @field_validator("event_time", "ingest_time", "docker_started_at")
    @classmethod
    def time_is_exact(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, info.field_name)

    @field_validator("docker_container_id")
    @classmethod
    def container_is_exact(cls, value: str | None) -> str | None:
        if value is not None and not _HEX64.fullmatch(value):
            raise ValueError("docker_container_id must be 64 lowercase hex")
        return value

    @field_validator("destination_ipv4")
    @classmethod
    def destination_is_exact(cls, value: str | None) -> str | None:
        return None if value is None else _ipv4(value)

    @field_validator("missing_required_fields")
    @classmethod
    def missing_fields_are_canonical(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _canonical_strings(
            values,
            "missing_required_fields",
            maximum_items=32,
            ascii_only=True,
        )

    @field_validator("coverage_flags")
    @classmethod
    def coverage_flags_are_canonical(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _canonical_strings(
            values,
            "coverage_flags",
            maximum_items=64,
            ascii_only=True,
        )

    @field_validator("evidence_ids")
    @classmethod
    def evidence_is_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _event_ids(values, "evidence_ids", maximum_items=2)

    @field_validator("reason_codes")
    @classmethod
    def reasons_are_canonical(
        cls,
        values: tuple[CorrelationReasonCode, ...],
    ) -> tuple[CorrelationReasonCode, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("reason_codes must be unique and sorted")
        return values

    @model_validator(mode="after")
    def identity_and_authority_are_exact(self) -> IncidentV1:
        for field in _INCIDENT_OPTIONAL_FIELDS:
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} must be absent rather than null")
        if derive_incident_id(self.primary_event_id) != self.incident_id:
            raise ValueError("incident_id does not bind primary_event_id")
        expected_evidence = (
            (self.primary_event_id,)
            if self.authority_event_id == self.primary_event_id
            else tuple(sorted((self.primary_event_id, self.authority_event_id)))
        )
        if self.evidence_ids != expected_evidence:
            raise ValueError("evidence_ids do not bind the exact incident authority")
        return self


class ContainmentCandidateV1(_ImmutableFact):
    schema_version: Literal["agmind.containment-candidate.v1"]
    candidate_id: str
    incident_id: str
    host_id: str
    boot_id: str
    primary_event_id: str
    primary_source_sequence: int = Field(ge=1, le=MAX_UINT64)
    correlation_snapshot_event_id: str
    docker_container_id: str
    docker_started_at: str
    image_id: str
    repo_digests: tuple[str, ...]
    immutable_spec_sha256: str
    inventory_generation: int = Field(ge=1, le=MAX_UINT64)
    inventory_revision: int = Field(ge=1, le=MAX_UINT64)
    destination_ipv4: str
    destination_port: int = Field(ge=1, le=65_535)
    l4_protocol: str
    ttl_seconds: int = Field(ge=30, le=300)
    detector_rule: Literal["AGmind PCC Suspicious Process Outbound Connect"]
    detector_rule_version: Literal["agmind-pcc-rules-v1"]
    detector_bundle_sha256: str
    coverage_snapshot_sha256: str
    docker_network_snapshot_sha256: str
    special_use_registry_sha256: str
    operator_denylist_sha256: str
    management_denylist_sha256: str
    evidence_ids: tuple[str, ...]
    created_at: str

    @field_validator("repo_digests", "evidence_ids", mode="before")
    @classmethod
    def arrays_are_exact_tuples(cls, value: object, info: Any) -> object:
        return _exact_tuple(value, info.field_name)

    @field_validator("candidate_id")
    @classmethod
    def candidate_identifier_is_exact(cls, value: str) -> str:
        if not _CANDIDATE_ID.fullmatch(value):
            raise ValueError("candidate_id must be an exact candidate ID")
        return value

    @field_validator("incident_id")
    @classmethod
    def incident_identifier_is_exact(cls, value: str) -> str:
        if not _INCIDENT_ID.fullmatch(value):
            raise ValueError("incident_id must be an exact incident ID")
        return value

    @field_validator("primary_event_id", "correlation_snapshot_event_id")
    @classmethod
    def event_identifier_is_exact(cls, value: str, info: Any) -> str:
        if not _EVENT_ID.fullmatch(value):
            raise ValueError(f"{info.field_name} must be an exact event ID")
        return value

    @field_validator("host_id", "boot_id")
    @classmethod
    def host_identity_is_exact(cls, value: str, info: Any) -> str:
        if not _UUID4.fullmatch(value):
            raise ValueError(f"{info.field_name} must be a lowercase UUIDv4")
        return value

    @field_validator("docker_container_id")
    @classmethod
    def container_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("docker_container_id must be 64 lowercase hex")
        return value

    @field_validator("docker_started_at", "created_at")
    @classmethod
    def time_is_exact(cls, value: str, info: Any) -> str:
        return _timestamp(value, info.field_name)

    @field_validator("image_id")
    @classmethod
    def image_is_exact(cls, value: str) -> str:
        if not _IMAGE_ID.fullmatch(value):
            raise ValueError("image_id must be an immutable Docker image ID")
        return value

    @field_validator("repo_digests")
    @classmethod
    def repositories_are_canonical(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _canonical_strings(
            values,
            "repo_digests",
            maximum_items=16,
            maximum_item_bytes=256,
            ascii_only=False,
        )

    @field_validator(
        "immutable_spec_sha256",
        "detector_bundle_sha256",
        "coverage_snapshot_sha256",
        "docker_network_snapshot_sha256",
        "special_use_registry_sha256",
        "operator_denylist_sha256",
        "management_denylist_sha256",
    )
    @classmethod
    def digest_is_exact(cls, value: str, info: Any) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError(f"{info.field_name} must be 64 lowercase hex")
        return value

    @field_validator("destination_ipv4")
    @classmethod
    def destination_is_exact(cls, value: str) -> str:
        return _ipv4(value)

    @field_validator("l4_protocol")
    @classmethod
    def protocol_is_bounded_ascii(cls, value: str) -> str:
        return _ascii(value, "l4_protocol")

    @field_validator("evidence_ids")
    @classmethod
    def evidence_is_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _event_ids(values, "evidence_ids", maximum_items=2)

    @model_validator(mode="after")
    def identity_and_evidence_are_exact(self) -> ContainmentCandidateV1:
        if derive_incident_id(self.primary_event_id) != self.incident_id:
            raise ValueError("incident_id does not bind primary_event_id")
        if (
            derive_candidate_id(
                self.primary_event_id,
                self.docker_container_id,
                self.docker_started_at,
                self.destination_ipv4,
                self.detector_bundle_sha256,
            )
            != self.candidate_id
        ):
            raise ValueError("candidate_id does not bind immutable candidate identity")
        if self.correlation_snapshot_event_id == self.primary_event_id:
            raise ValueError("correlation snapshot cannot be the primary event")
        expected_evidence = tuple(
            sorted((self.primary_event_id, self.correlation_snapshot_event_id))
        )
        if self.evidence_ids != expected_evidence:
            raise ValueError("evidence_ids must be the exact trigger/snapshot pair")
        return self
