"""Strict, non-authoritative policy boundary values."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Literal, cast, final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agmind_immune.canonicaljson import canonical_json

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CANDIDATE_ID = re.compile(r"^cand_[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_REPO_DIGEST = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$"
)
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
_MAX_UINT64 = 2**64 - 1
POLICY_INPUT_HASH_DOMAIN = b"AGMIND_POLICY_INPUT_V1\0"
POLICY_DECISION_HASH_DOMAIN = b"AGMIND_POLICY_DECISION_V1\0"


class PolicyError(RuntimeError):
    """Base class for fail-closed policy-boundary failures."""


class PolicyUnavailable(PolicyError):
    """The fixed local policy service could not return a bounded response."""


class PolicyResponseInvalid(PolicyError):
    """The untrusted policy response failed strict local validation."""


@final
@dataclass(frozen=True, slots=True)
class PolicyBundleIdentity:
    version: str
    sha256: str

    def __post_init__(self) -> None:
        if self.version != "pcc-policy-v1" or _HEX64.fullmatch(self.sha256) is None:
            raise ValueError("policy bundle identity is invalid")


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class PolicyInputV1(_StrictFrozenModel):
    """Exact detached input sent to the non-authoritative OPA service."""

    schema_version: Literal["agmind.policy-input.v1"]
    candidate_id: str
    candidate_facts_sha256: str
    host_id: str
    boot_id: str
    docker_container_id: str
    docker_started_at: str
    image_id: str
    repo_digests: tuple[str, ...]
    immutable_spec_sha256: str
    inventory_generation: int = Field(ge=1, le=_MAX_UINT64)
    inventory_revision: int = Field(ge=1, le=_MAX_UINT64)
    destination_ipv4: str
    destination_port: int = Field(ge=1, le=65_535)
    l4_protocol: str
    requested_ttl_seconds: int = Field(ge=30, le=300)
    detector_rule: str
    detector_rule_version: str
    detector_bundle_sha256: str
    coverage_ready: Literal[True]
    coverage_snapshot_sha256: str
    docker_network_snapshot_sha256: str
    special_use_registry_sha256: str
    operator_denylist_sha256: str
    management_denylist_sha256: str
    evidence_ids: tuple[str, ...]
    evidence_age_ms: int = Field(ge=0, le=_MAX_UINT64)
    policy_bundle_version: Literal["pcc-policy-v1"]
    policy_bundle_sha256: str
    policy_input_sha256: str

    @field_validator("repo_digests", "evidence_ids", mode="before")
    @classmethod
    def arrays_are_exact_tuples(cls, value: object, info: Any) -> object:
        if type(value) not in (list, tuple):
            raise ValueError(f"{info.field_name} must be an exact array")
        return tuple(cast(list[object] | tuple[object, ...], value))

    @field_validator(
        "candidate_facts_sha256",
        "immutable_spec_sha256",
        "detector_bundle_sha256",
        "coverage_snapshot_sha256",
        "docker_network_snapshot_sha256",
        "special_use_registry_sha256",
        "operator_denylist_sha256",
        "management_denylist_sha256",
        "policy_bundle_sha256",
        "policy_input_sha256",
    )
    @classmethod
    def hashes_are_exact(cls, value: str, info: Any) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be 64 lowercase hex")
        return value

    @field_validator("candidate_id")
    @classmethod
    def candidate_is_exact(cls, value: str) -> str:
        if _CANDIDATE_ID.fullmatch(value) is None:
            raise ValueError("candidate_id must be exact")
        return value

    @field_validator("host_id", "boot_id")
    @classmethod
    def lifecycle_is_exact(cls, value: str, info: Any) -> str:
        if _UUID4.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be a lowercase UUIDv4")
        return value

    @field_validator("docker_started_at")
    @classmethod
    def timestamp_is_exact(cls, value: str) -> str:
        if _TIMESTAMP.fullmatch(value) is None:
            raise ValueError("docker_started_at must be canonical RFC3339Nano UTC")
        return value

    @field_validator("destination_ipv4")
    @classmethod
    def destination_is_exact(cls, value: str) -> str:
        try:
            parsed = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError as error:
            raise ValueError("destination_ipv4 must be canonical IPv4") from error
        if str(parsed) != value:
            raise ValueError("destination_ipv4 must be canonical IPv4")
        return value

    @field_validator("evidence_ids")
    @classmethod
    def evidence_is_exact(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            len(value) != 2
            or value != tuple(sorted(set(value)))
            or any(_EVENT_ID.fullmatch(item) is None for item in value)
        ):
            raise ValueError("evidence_ids must be the exact sorted proof pair")
        return value

    @field_validator("repo_digests")
    @classmethod
    def repositories_are_exact(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            len(value) > 16
            or value != tuple(sorted(set(value)))
            or any(
                type(item) is not str
                or not 1 <= len(item) <= 256
                or _REPO_DIGEST.fullmatch(item) is None
                for item in value
            )
        ):
            raise ValueError("repo_digests must be canonical ASCII Docker digests")
        return value

    @model_validator(mode="after")
    def input_hash_is_exact(self) -> PolicyInputV1:
        if not hmac.compare_digest(
            self.policy_input_sha256,
            _policy_input_sha256(self),
        ):
            raise ValueError("policy_input_sha256 does not bind the exact input")
        return self


class PolicyDecisionV1(_StrictFrozenModel):
    """Locally narrowed deny-or-manual decision; never an action authority."""

    schema_version: Literal["agmind.policy-decision.v1"]
    effect: Literal["deny", "manual_approval_required"]
    reason_codes: tuple[Literal["policy_default_deny", "manual_approval_required"], ...]
    max_ttl_seconds: int = Field(ge=0, le=120)
    allowed_evidence_ids: tuple[str, ...]
    candidate_id: str
    candidate_facts_sha256: str
    policy_input_sha256: str
    policy_bundle_version: Literal["pcc-policy-v1"]
    policy_bundle_sha256: str

    @field_validator("reason_codes", "allowed_evidence_ids", mode="before")
    @classmethod
    def arrays_are_exact_tuples(cls, value: object, info: Any) -> object:
        if type(value) not in (list, tuple):
            raise ValueError(f"{info.field_name} must be an exact array")
        return tuple(cast(list[object] | tuple[object, ...], value))

    @field_validator(
        "candidate_facts_sha256",
        "policy_input_sha256",
        "policy_bundle_sha256",
    )
    @classmethod
    def hashes_are_exact(cls, value: str, info: Any) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be 64 lowercase hex")
        return value

    @field_validator("candidate_id")
    @classmethod
    def candidate_is_exact(cls, value: str) -> str:
        if _CANDIDATE_ID.fullmatch(value) is None:
            raise ValueError("candidate_id must be exact")
        return value

    @field_validator("allowed_evidence_ids")
    @classmethod
    def allowed_evidence_is_exact(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if (
            len(value) > 2
            or value != tuple(sorted(set(value)))
            or any(_EVENT_ID.fullmatch(item) is None for item in value)
        ):
            raise ValueError("allowed evidence IDs are not canonical")
        return value

    @model_validator(mode="after")
    def effect_shape_is_closed(self) -> PolicyDecisionV1:
        if self.effect == "deny":
            if (
                self.reason_codes != ("policy_default_deny",)
                or self.max_ttl_seconds != 0
                or self.allowed_evidence_ids
            ):
                raise ValueError("deny decision shape is invalid")
        elif self.reason_codes != ("manual_approval_required",):
            raise ValueError("manual decision reason is invalid")
        return self


class PolicyEvaluation(_StrictFrozenModel):
    """Replayable observation only; it contains no admission authority."""

    policy_input: PolicyInputV1
    decision: PolicyDecisionV1
    candidate_id: str
    candidate_facts_sha256: str
    policy_input_sha256: str
    policy_decision_sha256: str
    policy_bundle: PolicyBundleIdentity
    evaluated_at: str
    evidence_age_ms: int = Field(ge=0, le=_MAX_UINT64)

    @field_validator(
        "candidate_facts_sha256",
        "policy_input_sha256",
        "policy_decision_sha256",
    )
    @classmethod
    def hashes_are_exact(cls, value: str, info: Any) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be 64 lowercase hex")
        return value

    @field_validator("candidate_id")
    @classmethod
    def candidate_is_exact(cls, value: str) -> str:
        if _CANDIDATE_ID.fullmatch(value) is None:
            raise ValueError("candidate_id must be exact")
        return value

    @field_validator("evaluated_at")
    @classmethod
    def evaluated_time_is_exact(cls, value: str) -> str:
        if _TIMESTAMP.fullmatch(value) is None:
            raise ValueError("evaluated_at must be canonical RFC3339Nano UTC")
        return value

    @model_validator(mode="after")
    def bindings_are_exact(self) -> PolicyEvaluation:
        if (
            self.candidate_id != self.policy_input.candidate_id
            or self.candidate_id != self.decision.candidate_id
            or self.candidate_facts_sha256
            != self.policy_input.candidate_facts_sha256
            or self.candidate_facts_sha256
            != self.decision.candidate_facts_sha256
            or self.policy_input_sha256
            != self.policy_input.policy_input_sha256
            or self.policy_input_sha256 != self.decision.policy_input_sha256
            or self.policy_bundle.version
            != self.policy_input.policy_bundle_version
            or self.policy_bundle.version
            != self.decision.policy_bundle_version
            or self.policy_bundle.sha256
            != self.policy_input.policy_bundle_sha256
            or self.policy_bundle.sha256
            != self.decision.policy_bundle_sha256
            or self.evidence_age_ms != self.policy_input.evidence_age_ms
            or not hmac.compare_digest(
                self.policy_decision_sha256,
                _policy_decision_sha256(self.decision),
            )
        ):
            raise ValueError("policy evaluation bindings are inconsistent")
        return self


class _OPAResponseV1(_StrictFrozenModel):
    result: PolicyDecisionV1


def _policy_input_sha256(value: PolicyInputV1 | dict[str, object]) -> str:
    if type(value) is PolicyInputV1:
        document = value.model_dump(mode="python")
    elif type(value) is dict:
        document = dict(value)
    else:
        raise TypeError("policy input hash requires an exact input object")
    claimed = document.pop("policy_input_sha256", None)
    if claimed is not None and (
        type(claimed) is not str or _HEX64.fullmatch(claimed) is None
    ):
        raise ValueError("policy input claimed hash is invalid")
    return hashlib.sha256(
        POLICY_INPUT_HASH_DOMAIN + canonical_json(document)
    ).hexdigest()


def _policy_decision_sha256(decision: PolicyDecisionV1) -> str:
    if type(decision) is not PolicyDecisionV1:
        raise TypeError("policy decision hash requires an exact decision")
    return hashlib.sha256(
        POLICY_DECISION_HASH_DOMAIN + canonical_json(decision)
    ).hexdigest()
