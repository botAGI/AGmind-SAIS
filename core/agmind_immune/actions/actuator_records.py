"""Cryptographic verification and deterministic projection of actuator records."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agmind_immune.canonicaljson import (
    action_id,
    canonical_json,
    key_id,
    verify_action_record,
)
from agmind_immune.contracts import (
    MAX_UINT64,
    ActionRecordV1,
    PreparedTemporaryEgressDenyPlanV1,
    TemporaryEgressDenyIntentV1,
    decode_strict,
)

_ZERO_SHA256 = "0" * 64
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_INTENT_ID = re.compile(r"^int_[0-9a-f]{32}$")
_PLAN_ID = re.compile(r"^plan_[0-9a-f]{32}$")
_RESERVATION_ID = re.compile(r"^rr_[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^aa_[0-9a-f]{32}$")
_UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TIMESTAMP = re.compile(
    r"^(?P<whole>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?Z$"
)
_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")

_INTENT_HASH_DOMAIN = b"AGMIND_ACTUATOR_INTENT_V1\0"
_RATE_HASH_DOMAIN = b"AGMIND_RATE_RESERVATION_HASH_V1\0"
_RATE_SIGNING_DOMAIN = b"AGMIND_RATE_RESERVATION_V1\0"
_ATTEMPT_HASH_DOMAIN = b"AGMIND_APPLY_ATTEMPT_HASH_V1\0"
_ATTEMPT_SIGNING_DOMAIN = b"AGMIND_APPLY_ATTEMPT_V1\0"
_MAX_PAYLOAD_BYTES = 65_536
_APPROVAL_TTL_NS = 300_000_000_000


class ActuatorRecordError(ValueError):
    """One signed mixed-journal payload or transition is invalid."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _valid_timestamp(value: str) -> str:
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise ValueError("timestamp is not canonical RFC3339Nano UTC")
    fraction = match.group("fraction")
    if fraction is not None and fraction.endswith("0"):
        raise ValueError("timestamp fraction is not RFC3339Nano-minimal")
    try:
        dt.datetime.strptime(match.group("whole"), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.UTC)
    except ValueError as error:
        raise ValueError("timestamp calendar value is invalid") from error
    return value


class _RateReservationV1(_FrozenModel):
    schema_version: Literal["agmind.intent-rate-reservation.v1"]
    reservation_id: str
    intent_id: str
    intent_sha256: str
    reserved_at: str
    previous_record_sha256: str
    record_sha256: str
    actuator_key_id: str
    actuator_signature: str

    @field_validator("reservation_id")
    @classmethod
    def reservation_is_exact(cls, value: str) -> str:
        if _RESERVATION_ID.fullmatch(value) is None:
            raise ValueError("invalid reservation ID")
        return value

    @field_validator("intent_id")
    @classmethod
    def intent_is_exact(cls, value: str) -> str:
        if _INTENT_ID.fullmatch(value) is None:
            raise ValueError("invalid intent ID")
        return value

    @field_validator("intent_sha256", "previous_record_sha256", "record_sha256")
    @classmethod
    def digest_is_exact(cls, value: str) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError("invalid reservation digest")
        return value

    @field_validator("reserved_at")
    @classmethod
    def time_is_exact(cls, value: str) -> str:
        return _valid_timestamp(value)

    @field_validator("actuator_key_id")
    @classmethod
    def key_is_exact(cls, value: str) -> str:
        if _HEX32.fullmatch(value) is None:
            raise ValueError("invalid actuator key ID")
        return value

    @field_validator("actuator_signature")
    @classmethod
    def signature_is_exact(cls, value: str) -> str:
        if _SIGNATURE.fullmatch(value) is None:
            raise ValueError("invalid actuator signature")
        return value


class _ApplyAttemptV1(_FrozenModel):
    schema_version: Literal["agmind.apply-attempt.v1"]
    attempt_id: str
    plan_id: str
    plan_hash: str
    started_at: str
    boot_id: str
    boottime_ns: int = Field(ge=1, le=MAX_UINT64)
    target_netns_inode: int = Field(ge=1, le=MAX_UINT64)
    destination_ipv4: str
    ttl_seconds: int = Field(ge=30, le=300)
    expected_ruleset_sha256: str
    previous_action_record_sha256: str
    previous_record_sha256: str
    record_sha256: str
    actuator_key_id: str
    actuator_signature: str

    @field_validator("attempt_id")
    @classmethod
    def attempt_is_exact(cls, value: str) -> str:
        if _ATTEMPT_ID.fullmatch(value) is None:
            raise ValueError("invalid apply-attempt ID")
        return value

    @field_validator("plan_id")
    @classmethod
    def plan_is_exact(cls, value: str) -> str:
        if _PLAN_ID.fullmatch(value) is None:
            raise ValueError("invalid plan ID")
        return value

    @field_validator(
        "plan_hash",
        "expected_ruleset_sha256",
        "previous_action_record_sha256",
        "previous_record_sha256",
        "record_sha256",
    )
    @classmethod
    def digest_is_exact(cls, value: str) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError("invalid apply-attempt digest")
        return value

    @field_validator("started_at")
    @classmethod
    def time_is_exact(cls, value: str) -> str:
        return _valid_timestamp(value)

    @field_validator("boot_id")
    @classmethod
    def boot_is_exact(cls, value: str) -> str:
        if _UUID4.fullmatch(value) is None:
            raise ValueError("invalid boot ID")
        return value

    @field_validator("destination_ipv4")
    @classmethod
    def destination_is_exact(cls, value: str) -> str:
        parsed = ipaddress.ip_address(value)
        if type(parsed) is not ipaddress.IPv4Address or str(parsed) != value:
            raise ValueError("destination is not canonical IPv4")
        return value

    @field_validator("actuator_key_id")
    @classmethod
    def key_is_exact(cls, value: str) -> str:
        if _HEX32.fullmatch(value) is None:
            raise ValueError("invalid actuator key ID")
        return value

    @field_validator("actuator_signature")
    @classmethod
    def signature_is_exact(cls, value: str) -> str:
        if _SIGNATURE.fullmatch(value) is None:
            raise ValueError("invalid actuator signature")
        return value


@dataclass(frozen=True, slots=True)
class VerifiedActuatorPayload:
    schema_version: str
    record_sha256: str
    payload: bytes
    intent_id: str | None
    plan_id: str | None


@dataclass(frozen=True, slots=True)
class MirroredIntentState:
    intent_id: str
    intent_sha256: str
    state: str
    prepared_plan: PreparedTemporaryEgressDenyPlanV1 | None
    latest_record_id: str | None
    latest_record_sha256: str | None
    observed_at: str | None


@dataclass(frozen=True, slots=True)
class _ReservationState:
    intent_sha256: str
    reserved_at: str
    record_sha256: str


@dataclass(frozen=True, slots=True)
class _PreparedState:
    plan: PreparedTemporaryEgressDenyPlanV1
    intent_sha256: str
    approval_deadline_boottime_ns: int
    record_id: str
    record_sha256: str


@dataclass(frozen=True, slots=True)
class _OutcomeState:
    state: str
    record_id: str
    record_sha256: str
    observed_at: str


@dataclass(frozen=True, slots=True)
class _AttemptState:
    record_sha256: str
    expected_ruleset_sha256: str


@dataclass(slots=True)
class _ProjectionTransaction:
    previous: str
    action_count: int
    changes: list[tuple[dict[str, Any], str, bool, object]]
    seen: set[tuple[int, str]]


def _canonical_model(raw: bytes, model: type[_RateReservationV1]) -> _RateReservationV1:
    decoded = decode_strict(raw, model, _MAX_PAYLOAD_BYTES)
    if not hmac.compare_digest(canonical_json(decoded), raw):
        raise ActuatorRecordError("actuator payload is not canonical")
    return decoded


def _canonical_attempt(raw: bytes) -> _ApplyAttemptV1:
    decoded = decode_strict(raw, _ApplyAttemptV1, _MAX_PAYLOAD_BYTES)
    if not hmac.compare_digest(canonical_json(decoded), raw):
        raise ActuatorRecordError("actuator payload is not canonical")
    return decoded


def _canonical_action(raw: bytes) -> ActionRecordV1:
    decoded = decode_strict(raw, ActionRecordV1, _MAX_PAYLOAD_BYTES)
    if not hmac.compare_digest(canonical_json(decoded), raw):
        raise ActuatorRecordError("actuator payload is not canonical")
    return decoded


def _hash_without(document: dict[str, object], domain: bytes, *fields: str) -> str:
    value = dict(document)
    for field in fields:
        value.pop(field, None)
    return hashlib.sha256(domain + canonical_json(value)).hexdigest()


def _verify_ed25519(
    public_key: bytes,
    signature_text: str,
    domain: bytes,
    document: dict[str, object],
) -> None:
    signed = dict(document)
    signed.pop("actuator_signature", None)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(signature_text),
            domain + canonical_json(signed),
        )
    except (InvalidSignature, ValueError) as error:
        raise ActuatorRecordError("actuator payload signature is invalid") from error


def _uint(value: object, bits: int, field: str) -> int:
    if type(value) is not int or not 0 <= value < 2**bits:
        raise ActuatorRecordError(f"{field} is not an unsigned {bits}-bit integer")
    return value


def _timestamp(value: str) -> tuple[dt.datetime, int]:
    try:
        _valid_timestamp(value)
        match = _TIMESTAMP.fullmatch(value)
        if match is None:
            raise ValueError("timestamp grammar changed")
        whole = dt.datetime.strptime(
            match.group("whole"),
            "%Y-%m-%dT%H:%M:%S",
        ).replace(tzinfo=dt.UTC)
        fraction = match.group("fraction") or ""
        return whole, int(fraction.ljust(9, "0") or "0")
    except ValueError as error:
        raise ActuatorRecordError("actuator transition timestamp is invalid") from error


def _intent_from_plan(
    plan: PreparedTemporaryEgressDenyPlanV1,
) -> TemporaryEgressDenyIntentV1:
    fields = plan.model_dump(mode="python")
    for name in (
        "plan_id",
        "boot_id",
        "init_pid",
        "pid_start_ticks",
        "cgroup_path_sha256",
        "network_namespace_inode",
        "docker_network_snapshot_sha256",
        "special_use_registry_sha256",
        "management_denylist_sha256",
        "hard_limits_version",
        "prepared_at",
        "approval_expires_at",
        "nonce",
        "plan_hash",
    ):
        fields.pop(name)
    fields["schema_version"] = "agmind.temporary-egress-deny-intent.v1"
    return TemporaryEgressDenyIntentV1.model_validate(fields, strict=True)


def actuator_intent_sha256(plan: PreparedTemporaryEgressDenyPlanV1) -> str:
    if type(plan) is not PreparedTemporaryEgressDenyPlanV1:
        raise ActuatorRecordError("prepared plan type is inexact")
    return hashlib.sha256(_INTENT_HASH_DOMAIN + canonical_json(_intent_from_plan(plan))).hexdigest()


class ActuatorRecordProjection:
    """Verify one complete mixed inner chain and project per-intent state."""

    __slots__ = (
        "_actions",
        "_attempts",
        "_by_intent",
        "_by_plan",
        "_outcomes",
        "_previous",
        "_public_key",
        "_reservations",
        "_transaction",
    )

    def __init__(self, public_key: bytes) -> None:
        if type(public_key) is not bytes or len(public_key) != 32:
            raise ActuatorRecordError("actuator public key must contain 32 raw bytes")
        self._public_key = public_key
        self._previous = _ZERO_SHA256
        self._actions: list[ActionRecordV1] = []
        self._reservations: dict[str, _ReservationState] = {}
        self._by_intent: dict[str, _PreparedState] = {}
        self._by_plan: dict[str, _PreparedState] = {}
        self._outcomes: dict[str, _OutcomeState] = {}
        self._attempts: dict[str, _AttemptState] = {}
        self._transaction: _ProjectionTransaction | None = None

    @property
    def previous_record_sha256(self) -> str:
        return self._previous

    def begin_extension(self) -> _ProjectionTransaction:
        if self._transaction is not None:
            raise ActuatorRecordError("actuator projection transaction is already active")
        transaction = _ProjectionTransaction(
            self._previous,
            len(self._actions),
            [],
            set(),
        )
        self._transaction = transaction
        return transaction

    def rollback_extension(self, transaction: _ProjectionTransaction) -> None:
        if self._transaction is not transaction:
            raise ActuatorRecordError("actuator projection rollback token is invalid")
        for mapping, item_key, existed, prior in reversed(transaction.changes):
            if existed:
                mapping[item_key] = prior
            else:
                mapping.pop(item_key, None)
        del self._actions[transaction.action_count :]
        self._previous = transaction.previous
        self._transaction = None

    def commit_extension(self, transaction: _ProjectionTransaction) -> None:
        if self._transaction is not transaction:
            raise ActuatorRecordError("actuator projection commit token is invalid")
        self._transaction = None

    def _set_state(self, mapping: dict[str, Any], item_key: str, value: object) -> None:
        transaction = self._transaction
        if transaction is not None:
            identity = (id(mapping), item_key)
            if identity not in transaction.seen:
                transaction.seen.add(identity)
                transaction.changes.append(
                    (mapping, item_key, item_key in mapping, mapping.get(item_key))
                )
        mapping[item_key] = value

    def append(self, payload: bytes) -> VerifiedActuatorPayload:
        if type(payload) is not bytes or not 1 <= len(payload) <= _MAX_PAYLOAD_BYTES:
            raise ActuatorRecordError("actuator payload is absent or exceeds 64 KiB")
        try:
            envelope = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ActuatorRecordError("actuator payload is not JSON") from error
        if type(envelope) is not dict or type(envelope.get("schema_version")) is not str:
            raise ActuatorRecordError("actuator payload schema is absent")
        schema = envelope["schema_version"]
        try:
            if schema == "agmind.intent-rate-reservation.v1":
                rate_record = _canonical_model(payload, _RateReservationV1)
                verified = self._append_reservation(rate_record, payload)
            elif schema == "agmind.apply-attempt.v1":
                attempt_record = _canonical_attempt(payload)
                verified = self._append_attempt(attempt_record, payload)
            elif schema == "agmind.action-record.v1":
                action_record = _canonical_action(payload)
                verified = self._append_action(action_record)
            else:
                raise ActuatorRecordError("unsupported actuator journal schema")
        except ActuatorRecordError:
            raise
        except (InvalidSignature, TypeError, ValueError) as error:
            raise ActuatorRecordError("actuator payload verification failed") from error
        self._previous = verified.record_sha256
        return verified

    def _append_reservation(
        self,
        record: _RateReservationV1,
        payload: bytes,
    ) -> VerifiedActuatorPayload:
        document = record.model_dump(mode="python")
        expected = _hash_without(
            document,
            _RATE_HASH_DOMAIN,
            "reservation_id",
            "record_sha256",
            "actuator_signature",
        )
        if (
            record.previous_record_sha256 != self._previous
            or record.record_sha256 != expected
            or record.reservation_id != "rr_" + expected[:32]
            or record.actuator_key_id != key_id(self._public_key)
        ):
            raise ActuatorRecordError("rate reservation hash chain is invalid")
        _verify_ed25519(
            self._public_key,
            record.actuator_signature,
            _RATE_SIGNING_DOMAIN,
            document,
        )
        if record.intent_id in self._by_intent:
            raise ActuatorRecordError("rate reservation follows PREPARED")
        prior = self._reservations.get(record.intent_id)
        if prior is not None and prior.intent_sha256 != record.intent_sha256:
            raise ActuatorRecordError("rate reservation intent equivocation")
        self._set_state(
            self._reservations,
            record.intent_id,
            _ReservationState(
                record.intent_sha256,
                record.reserved_at,
                record.record_sha256,
            ),
        )
        return VerifiedActuatorPayload(
            record.schema_version,
            record.record_sha256,
            payload,
            record.intent_id,
            None,
        )

    def _append_attempt(
        self,
        record: _ApplyAttemptV1,
        payload: bytes,
    ) -> VerifiedActuatorPayload:
        document = record.model_dump(mode="python")
        expected = _hash_without(
            document,
            _ATTEMPT_HASH_DOMAIN,
            "attempt_id",
            "record_sha256",
            "actuator_signature",
        )
        if (
            record.previous_record_sha256 != self._previous
            or record.record_sha256 != expected
            or record.attempt_id != "aa_" + expected[:32]
            or record.actuator_key_id != key_id(self._public_key)
        ):
            raise ActuatorRecordError("apply attempt hash chain is invalid")
        _verify_ed25519(
            self._public_key,
            record.actuator_signature,
            _ATTEMPT_SIGNING_DOMAIN,
            document,
        )
        prepared = self._by_plan.get(record.plan_id)
        outcome = self._outcomes.get(record.plan_id)
        if (
            prepared is None
            or outcome is None
            or outcome.state != "APPROVED"
            or record.plan_id in self._attempts
            or record.previous_action_record_sha256 != outcome.record_sha256
            or record.plan_hash != prepared.plan.plan_hash
            or record.boot_id != prepared.plan.boot_id
            or record.target_netns_inode != prepared.plan.network_namespace_inode
            or record.destination_ipv4 != prepared.plan.destination_ipv4
            or record.ttl_seconds != prepared.plan.ttl_seconds
        ):
            raise ActuatorRecordError("apply attempt does not bind one approved plan")
        self._set_state(
            self._attempts,
            record.plan_id,
            _AttemptState(
                record.record_sha256,
                record.expected_ruleset_sha256,
            ),
        )
        return VerifiedActuatorPayload(
            record.schema_version,
            record.record_sha256,
            payload,
            prepared.plan.intent_id,
            record.plan_id,
        )

    def _append_action(self, record: ActionRecordV1) -> VerifiedActuatorPayload:
        try:
            verify_action_record(record, self._public_key)
        except (InvalidSignature, TypeError, ValueError) as error:
            raise ActuatorRecordError("action record signature is invalid") from error
        if record.previous_record_sha256 != self._previous:
            raise ActuatorRecordError("action record global chain is discontinuous")
        if record.state == "PREPARED":
            intent_id = self._append_prepared(record)
        elif record.state in {"APPROVED", "REJECTED", "EXPIRED_UNAPPLIED"}:
            if record.plan_id in self._outcomes:
                intent_id = self._append_lifecycle(record)
            else:
                intent_id = self._append_decision(record)
        elif record.state in {"APPLIED", "VERIFIED", "EXPIRED", "STALE_ABORT", "FAILED_DIRTY"}:
            intent_id = self._append_lifecycle(record)
        else:
            raise ActuatorRecordError("unsupported durable actuator state")
        self._actions.append(record)
        return VerifiedActuatorPayload(
            record.schema_version,
            record.record_sha256,
            canonical_json(record),
            intent_id,
            record.plan_id,
        )

    def _append_prepared(self, record: ActionRecordV1) -> str:
        details = record.details
        if (
            record.action_id is None
            or record.reason_code != "intent_prepared"
            or set(details)
            != {
                "approval_deadline_boottime_ns",
                "intent_sha256",
                "prepared_plan",
            }
        ):
            raise ActuatorRecordError("PREPARED record shape is invalid")
        deadline = _uint(
            details["approval_deadline_boottime_ns"],
            64,
            "approval deadline",
        )
        if deadline == 0 or type(details["intent_sha256"]) is not str:
            raise ActuatorRecordError("PREPARED authority details are invalid")
        plan = decode_strict(
            canonical_json(details["prepared_plan"]),
            PreparedTemporaryEgressDenyPlanV1,
            _MAX_PAYLOAD_BYTES,
        )
        intent_sha256 = actuator_intent_sha256(plan)
        reservation = self._reservations.get(plan.intent_id)
        if (
            details["intent_sha256"] != intent_sha256
            or reservation is None
            or reservation.intent_sha256 != intent_sha256
            or reservation.record_sha256 != record.previous_record_sha256
            or record.plan_id != plan.plan_id
            or record.plan_hash != plan.plan_hash
            or record.observed_at != plan.prepared_at
            or record.action_id != action_id(plan.plan_hash)
            or plan.intent_id in self._by_intent
            or plan.plan_id in self._by_plan
            or _timestamp(plan.prepared_at) < _timestamp(reservation.reserved_at)
        ):
            raise ActuatorRecordError("PREPARED record does not bind its reservation and plan")
        prepared = _PreparedState(
            plan,
            intent_sha256,
            deadline,
            record.record_id,
            record.record_sha256,
        )
        self._set_state(self._by_intent, plan.intent_id, prepared)
        self._set_state(self._by_plan, plan.plan_id, prepared)
        return plan.intent_id

    def _append_decision(self, record: ActionRecordV1) -> str:
        prepared = self._by_plan.get(record.plan_id)
        details = record.details
        if prepared is None or record.action_id is None or len(details) != 7:
            raise ActuatorRecordError("decision lacks one PREPARED plan")
        required = {
            "previous_action_record_sha256",
            "decision_boot_id",
            "decision_boottime_ns",
            "admin_uid",
            "admin_gid",
            "authorization_basis",
            "decision_basis",
        }
        if set(details) != required:
            raise ActuatorRecordError("decision details are not exact")
        previous = details["previous_action_record_sha256"]
        boot_id = details["decision_boot_id"]
        authorization = details["authorization_basis"]
        basis = details["decision_basis"]
        boot_time = _uint(details["decision_boottime_ns"], 64, "decision boottime")
        uid = _uint(details["admin_uid"], 32, "admin UID")
        gid = _uint(details["admin_gid"], 32, "admin GID")
        if (
            type(previous) is not str
            or type(boot_id) is not str
            or _UUID4.fullmatch(boot_id) is None
            or type(authorization) is not str
            or type(basis) is not str
            or boot_time == 0
            or record.plan_hash != prepared.plan.plan_hash
            or previous != prepared.record_sha256
        ):
            raise ActuatorRecordError("decision does not bind PREPARED")
        authority_valid = (
            (authorization == "root" and uid == 0)
            or (authorization in {"primary_group", "supplementary_group"} and uid != 0)
            or (authorization == "system_expiry" and uid == 0 and gid == 0)
        )
        mapping = {
            ("APPROVED", "local_admin_approval"): "local_admin_approved",
            ("REJECTED", "local_admin_rejection"): "local_admin_rejected",
            ("EXPIRED_UNAPPLIED", "wall_deadline"): "approval_deadline_elapsed",
            ("EXPIRED_UNAPPLIED", "boottime_deadline"): "approval_deadline_elapsed",
            ("EXPIRED_UNAPPLIED", "host_boot_changed"): "host_boot_changed",
        }
        if not authority_valid or mapping.get((record.state, basis)) != record.reason_code:
            raise ActuatorRecordError("decision authority, state, or reason is invalid")
        plan = prepared.plan
        observed = _timestamp(record.observed_at)
        prepared_at = _timestamp(plan.prepared_at)
        expires_at = _timestamp(plan.approval_expires_at)
        if prepared.approval_deadline_boottime_ns <= _APPROVAL_TTL_NS:
            raise ActuatorRecordError("decision monotonic deadline is invalid")
        prepared_boot = prepared.approval_deadline_boottime_ns - _APPROVAL_TTL_NS
        if record.state in {"APPROVED", "REJECTED"}:
            valid_clock = (
                authorization != "system_expiry"
                and boot_id == plan.boot_id
                and prepared_at <= observed < expires_at
                and prepared_boot <= boot_time < prepared.approval_deadline_boottime_ns
            )
        elif basis == "wall_deadline":
            valid_clock = boot_id == plan.boot_id and observed >= expires_at
        elif basis == "boottime_deadline":
            valid_clock = (
                boot_id == plan.boot_id and boot_time >= prepared.approval_deadline_boottime_ns
            )
        else:
            valid_clock = boot_id != plan.boot_id
        if not valid_clock:
            raise ActuatorRecordError("decision is outside its approval boundary")
        self._set_state(
            self._outcomes,
            record.plan_id,
            _OutcomeState(
                record.state,
                record.record_id,
                record.record_sha256,
                record.observed_at,
            ),
        )
        return plan.intent_id

    def _append_lifecycle(self, record: ActionRecordV1) -> str:
        prepared = self._by_plan.get(record.plan_id)
        prior = self._outcomes.get(record.plan_id)
        attempt = self._attempts.get(record.plan_id)
        if prepared is None or prior is None or record.action_id is None:
            raise ActuatorRecordError("lifecycle record lacks prior state")
        allowed = {
            ("APPROVED", False): {"STALE_ABORT", "REJECTED"},
            ("APPROVED", True): {"APPLIED", "REJECTED", "FAILED_DIRTY"},
            ("APPLIED", True): {"VERIFIED", "EXPIRED", "FAILED_DIRTY"},
            ("VERIFIED", True): {"EXPIRED", "FAILED_DIRTY"},
        }
        if record.state not in allowed.get((prior.state, attempt is not None), set()):
            raise ActuatorRecordError("invalid actuator lifecycle transition")
        details = record.details
        common = {
            "previous_action_record_sha256",
            "transition_boot_id",
            "transition_boottime_ns",
            "transition_basis",
        }
        expected_fields = {
            "STALE_ABORT": common,
            "REJECTED": common,
            "FAILED_DIRTY": common,
            "APPLIED": common
            | {
                "apply_attempt_sha256",
                "target_netns_inode",
                "ruleset_sha256",
                "configured_timeout_ms",
                "remaining_timeout_ms",
                "counter_packets",
                "counter_bytes",
                "host_netns_before",
                "host_netns_after",
            },
            "VERIFIED": common | {"applied_record_sha256", "audit_deadline_boottime_ns"},
            "EXPIRED": common,
        }
        if set(details) != expected_fields[record.state]:
            raise ActuatorRecordError("lifecycle details are not exact")
        per_plan_previous = (
            attempt.record_sha256
            if prior.state == "APPROVED" and attempt is not None
            else prior.record_sha256
        )
        boot_id = details["transition_boot_id"]
        basis = details["transition_basis"]
        boot_time = _uint(details["transition_boottime_ns"], 64, "transition boottime")
        reason_valid = {
            "STALE_ABORT": record.reason_code == "target_revalidation_failed" and bool(basis),
            "REJECTED": record.reason_code in {"nft_preflight_rejected", "nft_apply_proven_absent"}
            and bool(basis),
            "FAILED_DIRTY": record.reason_code == "nft_result_uncertain" and bool(basis),
            "APPLIED": record.reason_code == "nft_apply_observed"
            and basis == "exact_kernel_readback",
            "VERIFIED": record.reason_code == "nft_apply_verified" and basis == "proof_committed",
            "EXPIRED": record.reason_code == "native_timeout_expired"
            and basis in {"kernel_timeout_observed", "namespace_destroyed", "host_boot_changed"},
        }[record.state]
        if (
            details["previous_action_record_sha256"] != per_plan_previous
            or type(boot_id) is not str
            or _UUID4.fullmatch(boot_id) is None
            or type(basis) is not str
            or boot_time == 0
            or not reason_valid
            or record.plan_hash != prepared.plan.plan_hash
            or (
                record.state not in {"EXPIRED", "STALE_ABORT", "REJECTED"}
                and boot_id != prepared.plan.boot_id
            )
        ):
            raise ActuatorRecordError("lifecycle record bindings are invalid")
        if record.state == "APPLIED":
            if attempt is None:
                raise ActuatorRecordError("APPLIED lacks an apply attempt")
            numeric = (
                "target_netns_inode",
                "configured_timeout_ms",
                "remaining_timeout_ms",
                "counter_packets",
                "counter_bytes",
                "host_netns_before",
                "host_netns_after",
            )
            values = {name: _uint(details[name], 64, name) for name in numeric}
            if (
                details.get("apply_attempt_sha256") != attempt.record_sha256
                or details.get("ruleset_sha256") != attempt.expected_ruleset_sha256
                or values["target_netns_inode"] != prepared.plan.network_namespace_inode
                or values["configured_timeout_ms"] != prepared.plan.ttl_seconds * 1000
                or not 0 < values["remaining_timeout_ms"] <= values["configured_timeout_ms"]
                or values["host_netns_before"] == 0
                or values["host_netns_before"] != values["host_netns_after"]
            ):
                raise ActuatorRecordError("APPLIED observation does not bind its attempt")
        elif record.state == "VERIFIED":
            deadline = _uint(details["audit_deadline_boottime_ns"], 64, "audit deadline")
            if details.get("applied_record_sha256") != per_plan_previous or deadline <= boot_time:
                raise ActuatorRecordError("VERIFIED record does not bind APPLIED")
        self._set_state(
            self._outcomes,
            record.plan_id,
            _OutcomeState(
                record.state,
                record.record_id,
                record.record_sha256,
                record.observed_at,
            ),
        )
        return prepared.plan.intent_id

    def intents(self) -> tuple[MirroredIntentState, ...]:
        projected: list[MirroredIntentState] = []
        for intent_id in sorted(self._reservations):
            reservation = self._reservations[intent_id]
            prepared = self._by_intent.get(intent_id)
            outcome = None if prepared is None else self._outcomes.get(prepared.plan.plan_id)
            if prepared is None:
                state = "RESERVED"
                record_id = record_sha256 = observed_at = None
                plan = None
            elif outcome is None:
                state = "PREPARED"
                record_id = prepared.record_id
                record_sha256 = prepared.record_sha256
                observed_at = prepared.plan.prepared_at
                plan = prepared.plan
            else:
                state = outcome.state
                record_id = outcome.record_id
                record_sha256 = outcome.record_sha256
                observed_at = outcome.observed_at
                plan = prepared.plan
            projected.append(
                MirroredIntentState(
                    intent_id,
                    reservation.intent_sha256,
                    state,
                    plan,
                    record_id,
                    record_sha256,
                    observed_at,
                )
            )
        return tuple(projected)

    def action_records(self) -> tuple[ActionRecordV1, ...]:
        return tuple(self._actions)


__all__ = [
    "ActuatorRecordError",
    "ActuatorRecordProjection",
    "MirroredIntentState",
    "VerifiedActuatorPayload",
    "actuator_intent_sha256",
]
