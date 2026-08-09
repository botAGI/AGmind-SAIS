"""Strict durable decision/intent values with no approval authority."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal
from typing import TYPE_CHECKING, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agmind_immune.canonicaljson import canonical_json, intent_id
from agmind_immune.clock import CoreClockSample, _validate_core_clock_sample
from agmind_immune.contracts import (
    MAX_UINT64,
    TemporaryEgressDenyIntentV1,
    decode_strict,
)
from agmind_immune.policy.client import (
    POLICY_BUNDLE,
    _datetime_ns,
    _evidence_age_ms,
    _narrow_decision,
    _timestamp_ns,
    _utc_text,
    _validate_policy_evaluation_for_candidate,
)
from agmind_immune.policy.models import (
    PolicyDecisionV1,
    PolicyEvaluation,
    PolicyInputV1,
    _policy_decision_sha256,
)

if TYPE_CHECKING:
    from agmind_immune.coverage import MutationReadiness
    from agmind_immune.evidence.projection import ProjectionCursor
    from agmind_immune.evidence.segments import EvidenceRef
    from agmind_immune.incidents.models import ContainmentCandidateV1

_RECORD_HASH_DOMAIN = b"AGMIND_DECISION_INTENT_RECORD_V1\0"
_MAX_RECORD_BYTES = 131_072
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_CANDIDATE_ID = re.compile(r"^cand_[0-9a-f]{64}$")
_INTENT_ID = re.compile(r"^int_[0-9a-f]{32}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)


class DecisionIntentError(RuntimeError):
    """Base class for durable policy-decision and intent failures."""


class DecisionIntentValidationError(DecisionIntentError):
    """A decision/intent value failed exact local validation."""


@dataclass(frozen=True, slots=True)
class DecisionIntentCommit:
    """Immutable observation of one durably committed composite record."""

    candidate_id: str
    record_sha256: str
    effect: Literal["deny", "manual_approval_required"]
    intent_id: str | None
    record_canonical: bytes
    intent_canonical: bytes | None

    def __post_init__(self) -> None:
        if (
            type(self.candidate_id) is not str
            or _CANDIDATE_ID.fullmatch(self.candidate_id) is None
            or type(self.record_sha256) is not str
            or _HEX64.fullmatch(self.record_sha256) is None
            or type(self.record_canonical) is not bytes
            or not 1 <= len(self.record_canonical) <= _MAX_RECORD_BYTES
        ):
            raise ValueError("decision-intent commit observation is invalid")
        if self.effect == "deny":
            if self.intent_id is not None or self.intent_canonical is not None:
                raise ValueError("deny observation cannot contain an intent")
        elif (
            self.effect != "manual_approval_required"
            or type(self.intent_id) is not str
            or _INTENT_ID.fullmatch(self.intent_id) is None
            or type(self.intent_canonical) is not bytes
            or not 1 <= len(self.intent_canonical) <= 65_536
        ):
            raise ValueError("manual observation requires one exact intent")


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class _ProjectionCursorV1(_StrictFrozenModel):
    host_id: str
    source_sequence: int = Field(ge=1, le=MAX_UINT64)
    event_id: str
    content_sha256: str
    frame_sha256: str

    @field_validator("host_id")
    @classmethod
    def host_is_exact(cls, value: str) -> str:
        if _UUID4.fullmatch(value) is None:
            raise ValueError("projection cursor host is invalid")
        return value

    @field_validator("event_id")
    @classmethod
    def event_is_exact(cls, value: str) -> str:
        if _EVENT_ID.fullmatch(value) is None:
            raise ValueError("projection cursor event is invalid")
        return value

    @field_validator("content_sha256", "frame_sha256")
    @classmethod
    def hash_is_exact(cls, value: str) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError("projection cursor hash is invalid")
        return value


class _EvidenceRefV1(_StrictFrozenModel):
    segment_id: str
    segment_relative_path: str
    frame_offset: int
    frame_size: int
    frame_sha256: str
    event_id: str
    source_sequence: int
    content_sha256: str

    @model_validator(mode="after")
    def reference_is_exact(self) -> _EvidenceRefV1:
        from agmind_immune.evidence.segments import (
            EvidenceRef,
            _exact_coverage_ref_key,
        )

        reference = EvidenceRef(
            segment_id=self.segment_id,
            segment_relative_path=self.segment_relative_path,
            frame_offset=self.frame_offset,
            frame_size=self.frame_size,
            frame_sha256=self.frame_sha256,
            event_id=self.event_id,
            source_sequence=self.source_sequence,
            content_sha256=self.content_sha256,
        )
        try:
            _exact_coverage_ref_key(reference)
        except (TypeError, ValueError) as error:
            raise ValueError("durable terminal reference is invalid") from error
        return self


class _DurableTemporaryEgressDenyIntentV1(_StrictFrozenModel):
    schema_version: Literal["agmind.temporary-egress-deny-intent.v1"]
    intent_id: str
    verb: Literal["temporary_egress_deny"]
    host_id: str
    docker_container_id: str
    docker_started_at: str
    image_id: str
    repo_digests: tuple[str, ...]
    immutable_spec_sha256: str
    inventory_generation: int
    inventory_revision: int
    destination_ipv4: str
    ttl_seconds: int
    evidence_ids: tuple[str, ...]
    detector_bundle_sha256: str
    policy_bundle_version: str
    policy_bundle_sha256: str
    coverage_snapshot_sha256: str
    created_at: str

    @field_validator("repo_digests", "evidence_ids", mode="before")
    @classmethod
    def arrays_are_tuples(cls, value: object, info: Any) -> object:
        if type(value) not in (list, tuple):
            raise ValueError(f"{info.field_name} must be an exact array")
        return tuple(cast(list[object] | tuple[object, ...], value))

    @model_validator(mode="after")
    def wire_contract_is_exact(self) -> _DurableTemporaryEgressDenyIntentV1:
        raw = canonical_json(self)
        try:
            decoded = decode_strict(raw, TemporaryEgressDenyIntentV1, 65_536)
        except (TypeError, ValueError) as error:
            raise ValueError("durable intent violates the wire contract") from error
        if not hmac.compare_digest(canonical_json(decoded), raw):
            raise ValueError("durable intent wire bytes are not canonical")
        return self


class _DecisionIntentRecordV1(_StrictFrozenModel):
    schema_version: Literal["agmind.decision-intent-record.v1"]
    candidate_id: str
    candidate_facts_sha256: str
    candidate_created_at: str
    authority_snapshot_event_id: str
    projection_cursor: _ProjectionCursorV1
    terminal_ref: _EvidenceRefV1
    observer_reconcile_generation: int = Field(ge=1, le=MAX_UINT64)
    coverage_snapshot_sha256: str
    policy_input: PolicyInputV1
    policy_decision: PolicyDecisionV1
    policy_decision_sha256: str
    evaluated_at: str
    fresh_evidence_age_ms: int = Field(ge=0, le=MAX_UINT64)
    committed_at: str
    intent: _DurableTemporaryEgressDenyIntentV1 | None = None
    record_sha256: str

    @field_validator("candidate_id")
    @classmethod
    def candidate_is_exact(cls, value: str) -> str:
        if _CANDIDATE_ID.fullmatch(value) is None:
            raise ValueError("durable candidate ID is invalid")
        return value

    @field_validator("authority_snapshot_event_id")
    @classmethod
    def authority_event_is_exact(cls, value: str) -> str:
        if _EVENT_ID.fullmatch(value) is None:
            raise ValueError("durable authority event is invalid")
        return value

    @field_validator(
        "candidate_facts_sha256",
        "coverage_snapshot_sha256",
        "policy_decision_sha256",
        "record_sha256",
    )
    @classmethod
    def hash_is_exact(cls, value: str) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError("durable record hash is invalid")
        return value

    @field_validator("candidate_created_at", "evaluated_at", "committed_at")
    @classmethod
    def time_is_exact(cls, value: str) -> str:
        if _TIMESTAMP.fullmatch(value) is None:
            raise ValueError("durable record timestamp is invalid")
        _timestamp_ns(value)
        return value

    @model_validator(mode="after")
    def bindings_are_exact(self) -> _DecisionIntentRecordV1:
        policy_input = self.policy_input
        decision = self.policy_decision
        cursor = self.projection_cursor
        terminal = self.terminal_ref
        if (
            self.candidate_id != policy_input.candidate_id
            or self.candidate_id != decision.candidate_id
            or self.candidate_facts_sha256
            != policy_input.candidate_facts_sha256
            or self.candidate_facts_sha256
            != decision.candidate_facts_sha256
            or self.coverage_snapshot_sha256
            != policy_input.coverage_snapshot_sha256
            or self.authority_snapshot_event_id not in policy_input.evidence_ids
            or cursor.source_sequence != terminal.source_sequence
            or cursor.event_id != terminal.event_id
            or cursor.content_sha256 != terminal.content_sha256
            or cursor.frame_sha256 != terminal.frame_sha256
            or cursor.host_id != policy_input.host_id
            or not hmac.compare_digest(
                self.policy_decision_sha256,
                _policy_decision_sha256(decision),
            )
            or policy_input.policy_bundle_version != POLICY_BUNDLE.version
            or policy_input.policy_bundle_sha256 != POLICY_BUNDLE.sha256
            or _timestamp_ns(self.candidate_created_at)
            > _timestamp_ns(self.evaluated_at)
            or _timestamp_ns(self.evaluated_at) > _timestamp_ns(self.committed_at)
            or self.fresh_evidence_age_ms < policy_input.evidence_age_ms
        ):
            raise ValueError("durable decision bindings are inconsistent")
        try:
            _narrow_decision(decision, policy_input)
        except Exception as error:
            raise ValueError("durable policy decision is not locally narrowed") from error
        if decision.effect == "deny":
            if self.intent is not None or "intent" in self.model_fields_set:
                raise ValueError("deny record must omit intent")
        else:
            expected_intent = self.intent
            if (
                expected_intent is None
                or "intent" not in self.model_fields_set
                or self.fresh_evidence_age_ms > 120_000
                or expected_intent.intent_id
                != intent_id(
                    self.candidate_id,
                    POLICY_BUNDLE.sha256,
                    decision.max_ttl_seconds,
                )
                or expected_intent.host_id != policy_input.host_id
                or expected_intent.docker_container_id
                != policy_input.docker_container_id
                or expected_intent.docker_started_at
                != policy_input.docker_started_at
                or expected_intent.image_id != policy_input.image_id
                or expected_intent.repo_digests != policy_input.repo_digests
                or expected_intent.immutable_spec_sha256
                != policy_input.immutable_spec_sha256
                or expected_intent.inventory_generation
                != policy_input.inventory_generation
                or expected_intent.inventory_revision
                != policy_input.inventory_revision
                or expected_intent.destination_ipv4
                != policy_input.destination_ipv4
                or expected_intent.ttl_seconds != decision.max_ttl_seconds
                or expected_intent.evidence_ids
                != decision.allowed_evidence_ids
                or expected_intent.detector_bundle_sha256
                != policy_input.detector_bundle_sha256
                or expected_intent.policy_bundle_version
                != POLICY_BUNDLE.version
                or expected_intent.policy_bundle_sha256 != POLICY_BUNDLE.sha256
                or expected_intent.coverage_snapshot_sha256
                != policy_input.coverage_snapshot_sha256
                or expected_intent.created_at != self.committed_at
            ):
                raise ValueError("manual record intent is not exactly narrowed")
        if not hmac.compare_digest(
            self.record_sha256,
            _decision_intent_record_sha256(self),
        ):
            raise ValueError("durable record self-hash is invalid")
        return self


def _decision_intent_record_sha256(
    value: _DecisionIntentRecordV1 | dict[str, object],
) -> str:
    if type(value) is _DecisionIntentRecordV1:
        document = value.model_dump(
            mode="python",
            exclude={"record_sha256"},
            exclude_none=True,
        )
    elif type(value) is dict:
        document = dict(value)
        document.pop("record_sha256", None)
        document = {key: item for key, item in document.items() if item is not None}
    else:
        raise TypeError("record hash requires an exact decision record")
    return hashlib.sha256(_RECORD_HASH_DOMAIN + canonical_json(document)).hexdigest()


def _minimum_age_ms(created_at: str, evaluated_at: str) -> int:
    created_ns = _timestamp_ns(created_at)
    evaluated_ns = _timestamp_ns(evaluated_at)
    if evaluated_ns < created_ns:
        raise DecisionIntentValidationError(
            "policy evaluation predates candidate creation"
        )
    return (evaluated_ns - created_ns + 999_999) // 1_000_000


def _intent_for(
    candidate: ContainmentCandidateV1,
    evaluation: PolicyEvaluation,
    committed_at: str,
) -> _DurableTemporaryEgressDenyIntentV1 | None:
    decision = evaluation.decision
    if decision.effect == "deny":
        return None
    try:
        return _DurableTemporaryEgressDenyIntentV1.model_validate(
            {
                "schema_version": "agmind.temporary-egress-deny-intent.v1",
                "intent_id": intent_id(
                    candidate.candidate_id,
                    POLICY_BUNDLE.sha256,
                    decision.max_ttl_seconds,
                ),
                "verb": "temporary_egress_deny",
                "host_id": candidate.host_id,
                "docker_container_id": candidate.docker_container_id,
                "docker_started_at": candidate.docker_started_at,
                "image_id": candidate.image_id,
                "repo_digests": candidate.repo_digests,
                "immutable_spec_sha256": candidate.immutable_spec_sha256,
                "inventory_generation": candidate.inventory_generation,
                "inventory_revision": candidate.inventory_revision,
                "destination_ipv4": candidate.destination_ipv4,
                "ttl_seconds": decision.max_ttl_seconds,
                "evidence_ids": decision.allowed_evidence_ids,
                "detector_bundle_sha256": candidate.detector_bundle_sha256,
                "policy_bundle_version": POLICY_BUNDLE.version,
                "policy_bundle_sha256": POLICY_BUNDLE.sha256,
                "coverage_snapshot_sha256": candidate.coverage_snapshot_sha256,
                "created_at": committed_at,
            },
            strict=True,
        )
    except Exception as error:
        raise DecisionIntentValidationError(
            "manual intent could not be constructed exactly"
        ) from error


def _build_decision_intent_record(
    *,
    candidate: ContainmentCandidateV1,
    evaluation: object,
    sample: CoreClockSample,
    uncertainty_ns: int,
    authority_snapshot_event_id: str,
    projection_cursor: ProjectionCursor,
    terminal_ref: EvidenceRef,
    readiness: MutationReadiness,
) -> _DecisionIntentRecordV1:
    from agmind_immune.coverage import MutationReadiness
    from agmind_immune.evidence.projection import ProjectionCursor
    from agmind_immune.evidence.segments import (
        EvidenceRef,
        _exact_coverage_ref_key,
    )
    from agmind_immune.incidents.models import ContainmentCandidateV1

    try:
        if (
            type(candidate) is not ContainmentCandidateV1
            or type(projection_cursor) is not ProjectionCursor
            or type(terminal_ref) is not EvidenceRef
        ):
            raise DecisionIntentValidationError(
                "commit authority facts are not exact"
            )
        if type(sample) is not CoreClockSample:
            raise DecisionIntentValidationError(
                "commit clock sample is not exact"
            )
        _validate_core_clock_sample(sample)
        uncertainty = sample.uncertainty_seconds
        if (
            sample.healthy is not True
            or type(uncertainty) is not Decimal
            or uncertainty > sample.max_uncertainty_seconds
            or type(uncertainty_ns) is not int
            or not 0 <= uncertainty_ns <= MAX_UINT64
            or uncertainty_ns
            != int(
                (uncertainty * Decimal(1_000_000_000)).to_integral_value(
                    rounding=ROUND_CEILING
                )
            )
        ):
            raise DecisionIntentValidationError(
                "commit clock uncertainty is not exact"
            )
        detached = _validate_policy_evaluation_for_candidate(
            evaluation,
            candidate,
        )
        fresh_age_ms = _evidence_age_ms(
            candidate.created_at,
            sample,
            uncertainty_ns,
        )
        committed_at = _utc_text(sample.decision_utc)
        minimum_age_ms = _minimum_age_ms(
            candidate.created_at,
            detached.evaluated_at,
        )
        if (
            _timestamp_ns(detached.evaluated_at)
            > _datetime_ns(sample.decision_utc)
            or detached.evidence_age_ms < minimum_age_ms
            or fresh_age_ms < detached.evidence_age_ms
        ):
            raise DecisionIntentValidationError(
                "policy evaluation clock binding is stale or rolled back"
            )
        if type(readiness) is not MutationReadiness:
            raise DecisionIntentValidationError("commit readiness is not exact")
        terminal_key = _exact_coverage_ref_key(terminal_ref)
        base: dict[str, object] = {
            "schema_version": "agmind.decision-intent-record.v1",
            "candidate_id": candidate.candidate_id,
            "candidate_facts_sha256": detached.candidate_facts_sha256,
            "candidate_created_at": candidate.created_at,
            "authority_snapshot_event_id": authority_snapshot_event_id,
            "projection_cursor": {
                "host_id": projection_cursor.host_id,
                "source_sequence": projection_cursor.source_sequence,
                "event_id": projection_cursor.event_id,
                "content_sha256": projection_cursor.content_sha256,
                "frame_sha256": projection_cursor.frame_sha256,
            },
            "terminal_ref": {
                "segment_id": terminal_key[0],
                "segment_relative_path": terminal_key[1],
                "frame_offset": terminal_key[2],
                "frame_size": terminal_key[3],
                "frame_sha256": terminal_key[4],
                "event_id": terminal_key[5],
                "source_sequence": terminal_key[6],
                "content_sha256": terminal_key[7],
            },
            "observer_reconcile_generation": (
                readiness.observer_reconcile_generation
            ),
            "coverage_snapshot_sha256": candidate.coverage_snapshot_sha256,
            "policy_input": detached.policy_input,
            "policy_decision": detached.decision,
            "policy_decision_sha256": detached.policy_decision_sha256,
            "evaluated_at": detached.evaluated_at,
            "fresh_evidence_age_ms": fresh_age_ms,
            "committed_at": committed_at,
        }
        durable_intent = _intent_for(candidate, detached, committed_at)
        if durable_intent is not None:
            base["intent"] = durable_intent
        base["record_sha256"] = _decision_intent_record_sha256(base)
        record = _DecisionIntentRecordV1.model_validate(base, strict=True)
    except DecisionIntentError:
        raise
    except Exception as error:
        raise DecisionIntentValidationError(
            "decision-intent record construction failed"
        ) from error
    if type(record) is not _DecisionIntentRecordV1:
        raise DecisionIntentValidationError("decision-intent record is not exact")
    return record


def _decode_decision_intent_record(raw: bytes) -> _DecisionIntentRecordV1:
    try:
        record = decode_strict(raw, _DecisionIntentRecordV1, _MAX_RECORD_BYTES)
    except (TypeError, ValueError) as error:
        raise DecisionIntentValidationError(
            "decision-intent record is not strict canonical JSON"
        ) from error
    if (
        type(record) is not _DecisionIntentRecordV1
        or not hmac.compare_digest(canonical_json(record), raw)
    ):
        raise DecisionIntentValidationError(
            "decision-intent record bytes are not canonical"
        )
    return record


def _commit_observation(
    record: _DecisionIntentRecordV1,
    raw: bytes,
) -> DecisionIntentCommit:
    intent = record.intent
    return DecisionIntentCommit(
        candidate_id=record.candidate_id,
        record_sha256=record.record_sha256,
        effect=record.policy_decision.effect,
        intent_id=None if intent is None else intent.intent_id,
        record_canonical=bytes(raw),
        intent_canonical=None if intent is None else canonical_json(intent),
    )


__all__ = [
    "DecisionIntentCommit",
    "DecisionIntentError",
    "DecisionIntentValidationError",
]
