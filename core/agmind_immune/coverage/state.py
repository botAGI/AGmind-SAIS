"""Deterministic coverage reduction and same-evidence ACK barrier authority."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import final

from pydantic import ValidationError

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import (
    CoverageEventV1,
    EventEnvelopeV1,
    KeyTransitionV1,
    ObserverBootBoundaryV1,
    decode_strict,
)
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    EvidenceStoreError,
    SegmentStore,
    StoredEvidenceRecord,
)

_MAX_CANONICAL_ENVELOPE_BYTES = 64 * 1024
_LEASE_WINDOW = timedelta(seconds=15)
_STATE_FACTORY = object()
_BARRIER_FACTORY = object()


class CoverageError(RuntimeError):
    """Base class for deterministic coverage failures."""


class CoverageValidationError(CoverageError):
    """A presented record or reserved wire form is invalid."""


class CoverageConflict(CoverageError):
    """Authenticated coverage facts cannot form one deterministic history."""


class CoverageAuthorityError(CoverageError):
    """The requested operation is outside the exact evidence lifecycle."""


class CoverageUnhealthy(CoverageError):
    """A prior failed apply permanently fenced this reducer instance."""


@dataclass(frozen=True)
class _DockerOpen:
    source_sequence: int
    opened_at: str
    generation: int


@dataclass(frozen=True)
class _DockerRecovery:
    source_sequence: int
    opened_at: str
    closed_at: str
    generation: int


@dataclass(frozen=True)
class _CriticalInterval:
    component: str
    kind: str
    opened_at: str
    source_sequence: int


@dataclass(frozen=True)
class _SequenceGap:
    affected_start: int
    affected_end: int
    opened_at: str
    open_source_sequence: int
    baseline_recovery_generation: int
    close_source_sequence: int | None = None
    close_recovery_generation: int | None = None
    close_recovery_time: str | None = None


@dataclass(frozen=True)
class _FalcoLease:
    source_sequence: int
    event_id: str
    opened_at: str
    ingest_time: str


@dataclass(frozen=True)
class _CoverageSnapshot:
    host_id: str | None = None
    head_sequence: int = 0
    head_ref: EvidenceRef | None = None
    boot_transition_sequence: int | None = None
    observer_started: bool = False
    docker_generation: int | None = None
    docker_opens: tuple[_DockerOpen, ...] = ()
    docker_recoveries: tuple[_DockerRecovery, ...] = ()
    open_critical_intervals: tuple[_CriticalInterval, ...] = ()
    sequence_gaps: tuple[_SequenceGap, ...] = ()
    falco_lease: _FalcoLease | None = None
    live_lease_deadline: float | None = None
    latest_falco_stop_sequence: int | None = None


@dataclass(frozen=True)
class _PreparedRecord:
    record: StoredEvidenceRecord
    envelope: EventEnvelopeV1
    coverage: CoverageEventV1 | None


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _prepare(record: StoredEvidenceRecord) -> _PreparedRecord:
    if type(record) is not StoredEvidenceRecord:
        raise CoverageValidationError("coverage accepts only exact StoredEvidenceRecord")
    if type(record.envelope) is not dict:
        raise CoverageValidationError("stored coverage envelope is not an exact object")
    if type(record.canonical_envelope) is not bytes:
        raise CoverageValidationError("stored coverage canonical envelope is not bytes")
    if type(record.ref) is not EvidenceRef:
        raise CoverageValidationError("stored coverage ref is not exact")
    if type(record.priority) is not EvidencePriority:
        raise CoverageValidationError("stored coverage priority is not exact")
    try:
        envelope = decode_strict(
            record.canonical_envelope,
            EventEnvelopeV1,
            _MAX_CANONICAL_ENVELOPE_BYTES,
        )
        decoded_value = envelope.model_dump(exclude_none=True)
        if (
            canonical_json(decoded_value) != record.canonical_envelope
            or canonical_json(record.envelope) != record.canonical_envelope
            or decoded_value != record.envelope
        ):
            raise ValueError("stored envelope and canonical bytes differ")
    except (TypeError, ValueError, ValidationError) as error:
        raise CoverageValidationError(
            "stored coverage envelope is not exact canonical evidence"
        ) from error
    digest = hashlib.sha256(record.canonical_envelope).hexdigest()
    if (
        record.ref.source_sequence != envelope.source_sequence
        or record.ref.event_id != envelope.event_id
        or record.ref.content_sha256 != digest
    ):
        raise CoverageValidationError("stored coverage ref does not bind its envelope")
    coverage: CoverageEventV1 | None = None
    if envelope.event_type == "coverage":
        try:
            coverage = CoverageEventV1.model_validate(
                envelope.normalized_fields,
                strict=True,
            )
            if coverage.model_dump(exclude_none=True) != envelope.normalized_fields:
                raise ValueError("coverage fields are not an exact typed form")
        except (TypeError, ValueError, ValidationError) as error:
            raise CoverageValidationError("coverage fields are invalid") from error
    return _PreparedRecord(record=record, envelope=envelope, coverage=coverage)


def _empty_security_context(envelope: EventEnvelopeV1) -> bool:
    return (
        envelope.container_id is None
        and envelope.container_start_time is None
        and envelope.release_id is None
        and envelope.inventory_generation == 0
        and envelope.inventory_revision is None
        and envelope.redaction_flags == []
        and envelope.source_payload_hash == envelope.normalized_fields_sha256
    )


def _is_boot_transition(envelope: EventEnvelopeV1) -> bool:
    if "boot_transition" not in envelope.coverage_flags:
        return False
    try:
        if envelope.event_type == "observer_boot_boundary":
            ObserverBootBoundaryV1.model_validate(
                envelope.normalized_fields,
                strict=True,
            )
            exact = envelope.coverage_flags == [
                "boot_transition",
                "reconcile_required",
            ]
        elif envelope.event_type == "observer_key_transition":
            KeyTransitionV1.model_validate(envelope.normalized_fields, strict=True)
            exact = envelope.coverage_flags == ["boot_transition", "key_rotation"]
        elif envelope.event_type == "observer_key_epoch_start":
            exact = (
                set(envelope.normalized_fields) == {"kind", "key_id", "key_epoch"}
                and envelope.normalized_fields.get("kind") == "observer_key_epoch_start"
                and envelope.normalized_fields.get("key_id") == envelope.key_id
                and envelope.normalized_fields.get("key_epoch") == envelope.key_epoch
                and envelope.coverage_flags == ["boot_transition", "key_rotation"]
            )
        else:
            exact = False
    except (TypeError, ValueError, ValidationError) as error:
        raise CoverageValidationError("boot transition form is invalid") from error
    if not exact or not _empty_security_context(envelope):
        raise CoverageValidationError("boot transition context is invalid")
    return True


def _is_observer_start(envelope: EventEnvelopeV1) -> bool:
    if envelope.event_type != "observer_start":
        return False
    if (
        envelope.normalized_fields != {"kind": "observer_start", "reconcile_required": True}
        or envelope.coverage_flags != ["reconcile_required"]
        or not _empty_security_context(envelope)
    ):
        raise CoverageValidationError("observer-start form is invalid")
    return True


def _coverage_context_is_empty(envelope: EventEnvelopeV1) -> bool:
    return (
        envelope.container_id is None
        and envelope.container_start_time is None
        and envelope.release_id is None
        and envelope.inventory_revision is None
        and envelope.redaction_flags == []
    )


def _exact_docker_open(
    prepared: _PreparedRecord,
    coverage: CoverageEventV1,
) -> _DockerOpen:
    envelope = prepared.envelope
    fields = envelope.normalized_fields
    required = {
        "component",
        "kind",
        "severity",
        "opened_at",
        "reason_code",
        "reconcile_generation",
    }
    generation = coverage.reconcile_generation
    if (
        set(fields) != required
        or coverage.component != "observer"
        or coverage.severity != "CRITICAL"
        or coverage.closed_at is not None
        or generation is None
        or generation == 0
        or envelope.event_time != coverage.opened_at
        or envelope.inventory_generation != generation
        or not _coverage_context_is_empty(envelope)
        or envelope.coverage_flags != ["docker_event_gap", "reconcile_required"]
        or envelope.source_payload_hash != envelope.normalized_fields_sha256
    ):
        raise CoverageValidationError("Docker reconcile open form is invalid")
    return _DockerOpen(
        source_sequence=envelope.source_sequence,
        opened_at=coverage.opened_at,
        generation=generation,
    )


def _exact_docker_recovery(
    prepared: _PreparedRecord,
    coverage: CoverageEventV1,
) -> _DockerRecovery:
    envelope = prepared.envelope
    fields = envelope.normalized_fields
    required = {
        "component",
        "kind",
        "severity",
        "opened_at",
        "closed_at",
        "reason_code",
        "reconcile_generation",
    }
    generation = coverage.reconcile_generation
    closed_at = coverage.closed_at
    if (
        set(fields) != required
        or coverage.component != "observer"
        or coverage.severity != "INFO"
        or coverage.reason_code != "docker_full_reconcile_succeeded"
        or closed_at is None
        or generation is None
        or generation == 0
        or _timestamp(closed_at) < _timestamp(coverage.opened_at)
        or envelope.event_time != closed_at
        or envelope.inventory_generation != generation
        or not _coverage_context_is_empty(envelope)
        or envelope.coverage_flags != ["docker_event_gap", "reconcile_required"]
        or envelope.source_payload_hash != envelope.normalized_fields_sha256
    ):
        raise CoverageValidationError("Docker reconcile recovery form is invalid")
    return _DockerRecovery(
        source_sequence=envelope.source_sequence,
        opened_at=coverage.opened_at,
        closed_at=closed_at,
        generation=generation,
    )


def _exact_falco_point(
    prepared: _PreparedRecord,
    coverage: CoverageEventV1,
) -> str | None:
    expected = {
        "falco_adapter_start": ("INFO", "adapter_started"),
        "falco_adapter_stop": ("CRITICAL", "adapter_stopping"),
        "falco_heartbeat_lease": ("INFO", "valid_heartbeat"),
    }
    selected = expected.get(coverage.kind)
    if selected is None:
        return None
    envelope = prepared.envelope
    if (
        set(envelope.normalized_fields)
        != {
            "component",
            "kind",
            "severity",
            "opened_at",
            "closed_at",
            "reason_code",
        }
        or coverage.component != "falco-adapter"
        or (coverage.severity, coverage.reason_code) != selected
        or coverage.closed_at != coverage.opened_at
        or envelope.event_time != coverage.opened_at
        or not _coverage_context_is_empty(envelope)
        or envelope.coverage_flags != []
    ):
        raise CoverageValidationError("Falco lifecycle coverage form is invalid")
    return coverage.kind


def _exact_sequence_gap(
    prepared: _PreparedRecord,
    coverage: CoverageEventV1,
) -> str:
    envelope = prepared.envelope
    start = coverage.affected_source_sequence_start
    end = coverage.affected_source_sequence_end
    common = (
        coverage.component == "observer"
        and start is not None
        and end is not None
        and start > 0
        and end >= start
        and _coverage_context_is_empty(envelope)
        and envelope.coverage_flags == ["reconcile_required", "sequence_gap"]
        and envelope.source_payload_hash == envelope.normalized_fields_sha256
    )
    open_fields = {
        "component",
        "kind",
        "severity",
        "opened_at",
        "affected_source_sequence_start",
        "affected_source_sequence_end",
        "reason_code",
    }
    close_fields = open_fields | {"closed_at", "reconcile_generation"}
    exact_open = (
        set(envelope.normalized_fields) == open_fields
        and coverage.severity == "CRITICAL"
        and coverage.reason_code == "reserved_sequence_not_published"
        and coverage.closed_at is None
        and coverage.reconcile_generation is None
        and envelope.event_time == coverage.opened_at
        and envelope.inventory_generation == 0
    )
    exact_close = (
        set(envelope.normalized_fields) == close_fields
        and coverage.severity == "INFO"
        and coverage.reason_code == "reserved_sequence_reconciled"
        and coverage.closed_at is not None
        and coverage.reconcile_generation is not None
        and coverage.reconcile_generation > 0
        and envelope.event_time == coverage.closed_at
        and envelope.inventory_generation == coverage.reconcile_generation
    )
    if not common or not (exact_open or exact_close):
        raise CoverageValidationError("sequence-gap coverage form is invalid")
    return "open" if exact_open else "close"


def _validate_receipt(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise CoverageValidationError("live monotonic receipt is invalid")
    return float(value)


def _apply_docker_open(
    snapshot: _CoverageSnapshot,
    opened: _DockerOpen,
) -> _CoverageSnapshot:
    if any(
        item.opened_at == opened.opened_at and item.generation == opened.generation
        for item in snapshot.docker_opens
    ):
        raise CoverageConflict("Docker reconcile open is duplicated")
    return replace(
        snapshot,
        docker_generation=None,
        docker_opens=(*snapshot.docker_opens, opened),
    )


def _apply_docker_recovery(
    snapshot: _CoverageSnapshot,
    recovery: _DockerRecovery,
) -> _CoverageSnapshot:
    matches = tuple(
        item
        for item in snapshot.docker_opens
        if item.opened_at == recovery.opened_at
        and item.generation == recovery.generation
        and item.source_sequence < recovery.source_sequence
    )
    if len(matches) != 1:
        raise CoverageConflict("Docker recovery has no one exact unmatched open")
    prior_generation = max(
        (item.generation for item in snapshot.docker_recoveries),
        default=0,
    )
    if recovery.generation <= prior_generation:
        raise CoverageConflict("Docker recovery generation did not advance")
    matched = matches[0]
    remaining = tuple(item for item in snapshot.docker_opens if item != matched)
    return replace(
        snapshot,
        docker_generation=recovery.generation if not remaining else None,
        docker_opens=remaining,
        docker_recoveries=(*snapshot.docker_recoveries, recovery),
    )


def _apply_sequence_gap_open(
    snapshot: _CoverageSnapshot,
    prepared: _PreparedRecord,
    coverage: CoverageEventV1,
) -> _CoverageSnapshot:
    start = coverage.affected_source_sequence_start
    end = coverage.affected_source_sequence_end
    if start is None or end is None:
        raise CoverageValidationError("sequence-gap range is absent")
    for historical in snapshot.sequence_gaps:
        if not (end < historical.affected_start or start > historical.affected_end):
            raise CoverageConflict("sequence-gap range duplicates or overlaps history")
    baseline = max(
        (item.generation for item in snapshot.docker_recoveries),
        default=0,
    )
    opened = _SequenceGap(
        affected_start=start,
        affected_end=end,
        opened_at=coverage.opened_at,
        open_source_sequence=prepared.envelope.source_sequence,
        baseline_recovery_generation=baseline,
    )
    return replace(snapshot, sequence_gaps=(*snapshot.sequence_gaps, opened))


def _apply_sequence_gap_close(
    snapshot: _CoverageSnapshot,
    prepared: _PreparedRecord,
    coverage: CoverageEventV1,
) -> _CoverageSnapshot:
    start = coverage.affected_source_sequence_start
    end = coverage.affected_source_sequence_end
    generation = coverage.reconcile_generation
    closed_at = coverage.closed_at
    matches = tuple(
        (position, item)
        for position, item in enumerate(snapshot.sequence_gaps)
        if item.affected_start == start
        and item.affected_end == end
        and item.opened_at == coverage.opened_at
        and item.close_source_sequence is None
    )
    if len(matches) != 1 or generation is None or closed_at is None:
        raise CoverageConflict("sequence-gap close has no one exact open")
    position, opened = matches[0]
    recoveries = tuple(
        recovery
        for recovery in snapshot.docker_recoveries
        if opened.open_source_sequence
        < recovery.source_sequence
        < prepared.envelope.source_sequence
        and recovery.generation == generation
        and recovery.closed_at == closed_at
    )
    if (
        len(recoveries) != 1
        or generation <= opened.baseline_recovery_generation
        or _timestamp(closed_at) < _timestamp(opened.opened_at)
    ):
        raise CoverageConflict("sequence-gap close lacks one later baseline-advancing recovery")
    closed = replace(
        opened,
        close_source_sequence=prepared.envelope.source_sequence,
        close_recovery_generation=generation,
        close_recovery_time=closed_at,
    )
    gaps = tuple(
        closed if index == position else item for index, item in enumerate(snapshot.sequence_gaps)
    )
    return replace(snapshot, sequence_gaps=gaps)


def _apply_generic_critical(
    snapshot: _CoverageSnapshot,
    prepared: _PreparedRecord,
    coverage: CoverageEventV1,
) -> _CoverageSnapshot:
    if coverage.severity != "CRITICAL":
        return snapshot
    key = (coverage.component, coverage.kind, coverage.opened_at)
    intervals = snapshot.open_critical_intervals
    if coverage.closed_at is None:
        if any((item.component, item.kind, item.opened_at) == key for item in intervals):
            raise CoverageConflict("generic critical interval is duplicated")
        return replace(
            snapshot,
            open_critical_intervals=(
                *intervals,
                _CriticalInterval(
                    component=coverage.component,
                    kind=coverage.kind,
                    opened_at=coverage.opened_at,
                    source_sequence=prepared.envelope.source_sequence,
                ),
            ),
        )
    matching = tuple(
        item for item in intervals if (item.component, item.kind, item.opened_at) == key
    )
    if not matching:
        return snapshot
    if len(matching) != 1:
        raise CoverageConflict("generic critical close is ambiguous")
    return replace(
        snapshot,
        open_critical_intervals=tuple(item for item in intervals if item != matching[0]),
    )


def _transition(
    snapshot: _CoverageSnapshot,
    prepared: _PreparedRecord,
    *,
    live_receipt_monotonic: float | None,
    live_receipt_allowed: bool,
) -> _CoverageSnapshot:
    envelope = prepared.envelope
    if snapshot.host_id is not None and envelope.host_id != snapshot.host_id:
        raise CoverageConflict("coverage records span more than one host")
    if envelope.source_sequence <= snapshot.head_sequence:
        raise CoverageConflict("coverage records are not in strict source order")
    if live_receipt_monotonic is not None and not live_receipt_allowed:
        raise CoverageValidationError("live monotonic receipt requires a bound live evidence apply")

    candidate = snapshot
    if _is_boot_transition(envelope):
        candidate = replace(
            candidate,
            boot_transition_sequence=envelope.source_sequence,
            observer_started=False,
            docker_generation=None,
            falco_lease=None,
            live_lease_deadline=None,
        )
    elif _is_observer_start(envelope):
        candidate = replace(
            candidate,
            observer_started=True,
            docker_generation=None,
            falco_lease=None,
            live_lease_deadline=None,
        )
    elif envelope.event_type == "coverage":
        coverage = prepared.coverage
        if coverage is None:
            raise CoverageValidationError("coverage event has no typed fields")
        if coverage.kind == "docker_reconcile_gap":
            if live_receipt_monotonic is not None:
                raise CoverageValidationError("receipt is legal only on a Falco lease")
            candidate = _apply_docker_open(
                candidate,
                _exact_docker_open(prepared, coverage),
            )
        elif coverage.kind == "docker_reconcile_recovered":
            if live_receipt_monotonic is not None:
                raise CoverageValidationError("receipt is legal only on a Falco lease")
            candidate = _apply_docker_recovery(
                candidate,
                _exact_docker_recovery(prepared, coverage),
            )
        elif coverage.kind == "observer_sequence_gap":
            if live_receipt_monotonic is not None:
                raise CoverageValidationError("receipt is legal only on a Falco lease")
            form = _exact_sequence_gap(prepared, coverage)
            if form == "open":
                candidate = _apply_sequence_gap_open(candidate, prepared, coverage)
            else:
                candidate = _apply_sequence_gap_close(candidate, prepared, coverage)
        else:
            falco_form = _exact_falco_point(prepared, coverage)
            if falco_form == "falco_adapter_start":
                if live_receipt_monotonic is not None:
                    raise CoverageValidationError("receipt is legal only on a Falco lease")
            elif falco_form == "falco_adapter_stop":
                if live_receipt_monotonic is not None:
                    raise CoverageValidationError("receipt is legal only on a Falco lease")
                candidate = replace(
                    candidate,
                    falco_lease=None,
                    live_lease_deadline=None,
                    latest_falco_stop_sequence=envelope.source_sequence,
                )
            elif falco_form == "falco_heartbeat_lease":
                opened = _timestamp(coverage.opened_at)
                ingest = _timestamp(envelope.ingest_time)
                lease_age = ingest - opened
                if lease_age < timedelta(0) or lease_age > _LEASE_WINDOW:
                    raise CoverageValidationError("Falco lease ingest is outside its signed window")
                deadline = None
                if live_receipt_monotonic is not None:
                    receipt = _validate_receipt(live_receipt_monotonic)
                    deadline = receipt + (_LEASE_WINDOW - lease_age).total_seconds()
                candidate = replace(
                    candidate,
                    falco_lease=_FalcoLease(
                        source_sequence=envelope.source_sequence,
                        event_id=envelope.event_id,
                        opened_at=coverage.opened_at,
                        ingest_time=envelope.ingest_time,
                    ),
                    live_lease_deadline=deadline,
                )
            else:
                if live_receipt_monotonic is not None:
                    raise CoverageValidationError("receipt is legal only on a Falco lease")
                candidate = _apply_generic_critical(
                    candidate,
                    prepared,
                    coverage,
                )
    elif live_receipt_monotonic is not None:
        raise CoverageValidationError("receipt is legal only on a Falco lease")

    return replace(
        candidate,
        host_id=envelope.host_id,
        head_sequence=envelope.source_sequence,
        head_ref=prepared.record.ref,
    )


@final
class CoverageAckBarrier:
    """Opaque non-callable capability bound to one live coverage/store owner."""

    __slots__ = (
        "_capability_token",
        "_evidence",
        "_lifecycle_identity",
        "_state",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("CoverageAckBarrier is final")

    def __init__(
        self,
        factory: object,
        state: CoverageState,
        evidence: SegmentStore,
        lifecycle_identity: object,
        capability_token: object,
    ) -> None:
        if factory is not _BARRIER_FACTORY:
            raise TypeError("CoverageAckBarrier is issued only by CoverageState")
        self._state = state
        self._evidence = evidence
        self._lifecycle_identity = lifecycle_identity
        self._capability_token = capability_token

    def _first_unclosed_sequence_gap(
        self,
        evidence: SegmentStore,
    ) -> int | None:
        return self._state._first_unclosed_sequence_gap(
            evidence,
            lifecycle_identity=self._lifecycle_identity,
            capability_token=self._capability_token,
        )


class CoverageState:
    """Frozen-snapshot reducer with an optional exact SegmentStore owner."""

    def __init__(
        self,
        *,
        factory: object,
        snapshot: _CoverageSnapshot | None = None,
    ) -> None:
        if factory is not _STATE_FACTORY:
            raise TypeError("use CoverageState.rebuild() or open_and_recover()")
        self._snapshot = snapshot or _CoverageSnapshot()
        self._healthy = True
        self._closed = False
        self._evidence: SegmentStore | None = None
        self._lifecycle_identity: object | None = None
        self._capability_token: object | None = None

    @classmethod
    def rebuild(
        cls,
        records: Iterable[StoredEvidenceRecord],
    ) -> CoverageState:
        state = cls(factory=_STATE_FACTORY)
        snapshot = state._snapshot
        try:
            for record in records:
                prepared = _prepare(record)
                snapshot = _transition(
                    snapshot,
                    prepared,
                    live_receipt_monotonic=None,
                    live_receipt_allowed=False,
                )
        except CoverageError:
            raise
        except (TypeError, ValueError, OverflowError) as error:
            raise CoverageValidationError("coverage replay input is invalid") from error
        state._snapshot = snapshot
        return state

    @classmethod
    def open_and_recover(
        cls,
        evidence: SegmentStore,
    ) -> CoverageState:
        if type(evidence) is not SegmentStore:
            raise CoverageAuthorityError("coverage requires one exact SegmentStore")
        state = cls(factory=_STATE_FACTORY)
        lifecycle_identity: object | None = None
        recovery_complete = False
        try:
            lifecycle_identity = evidence._acquire_coverage_state(state)
            snapshot = state._snapshot
            for record in evidence.iter_authenticated_records():
                snapshot = _transition(
                    snapshot,
                    _prepare(record),
                    live_receipt_monotonic=None,
                    live_receipt_allowed=False,
                )
            evidence._validate_coverage_state_owner(
                state,
                lifecycle_identity,
                reducer_head=snapshot.head_ref,
            )
            state._snapshot = snapshot
            state._evidence = evidence
            state._lifecycle_identity = lifecycle_identity
            state._capability_token = object()
            recovery_complete = True
        except CoverageError:
            raise
        except EvidenceStoreError as error:
            raise CoverageAuthorityError(
                "coverage recovery is outside authenticated evidence"
            ) from error
        except (TypeError, ValueError, OverflowError) as error:
            raise CoverageValidationError("coverage recovery input is invalid") from error
        finally:
            if lifecycle_identity is not None and not recovery_complete:
                evidence._release_coverage_state(state, lifecycle_identity)
        return state

    def _require_usable(self) -> None:
        if not self._healthy:
            raise CoverageUnhealthy("coverage reducer is unhealthy")
        if self._closed:
            raise CoverageAuthorityError("coverage reducer is closed")

    def apply(
        self,
        record: StoredEvidenceRecord,
        *,
        live_receipt_monotonic: float | None = None,
    ) -> None:
        self._require_usable()
        preceding = self._snapshot
        apply_complete = False
        try:
            if type(record) is not StoredEvidenceRecord:
                raise CoverageValidationError("coverage accepts only exact StoredEvidenceRecord")
            selected = record
            if self._evidence is not None:
                lifecycle_identity = self._lifecycle_identity
                if lifecycle_identity is None:
                    raise CoverageAuthorityError("bound coverage state has no lifecycle token")
                try:
                    selected = self._evidence._resolve_next_coverage_record(
                        self,
                        lifecycle_identity,
                        record,
                        after_ref=preceding.head_ref,
                    )
                except EvidenceStoreError as error:
                    raise CoverageAuthorityError(
                        "coverage apply is not the next same-store real record"
                    ) from error
            prepared = _prepare(selected)
            candidate = _transition(
                preceding,
                prepared,
                live_receipt_monotonic=live_receipt_monotonic,
                live_receipt_allowed=self._evidence is not None,
            )
        except CoverageError:
            raise
        except (TypeError, ValueError, OverflowError) as error:
            raise CoverageValidationError("coverage apply failed validation") from error
        else:
            self._snapshot = candidate
            apply_complete = True
        finally:
            if not apply_complete:
                self._healthy = False

    def ack_barrier_capability(self) -> CoverageAckBarrier:
        self._require_usable()
        evidence = self._evidence
        lifecycle_identity = self._lifecycle_identity
        capability_token = self._capability_token
        if evidence is None or lifecycle_identity is None or capability_token is None:
            raise CoverageAuthorityError("unbound coverage state cannot issue an ACK barrier")
        try:
            evidence._validate_coverage_state_owner(
                self,
                lifecycle_identity,
                reducer_head=self._snapshot.head_ref,
            )
        except EvidenceStoreError as error:
            raise CoverageAuthorityError(
                "coverage barrier issuance failed same-store validation"
            ) from error
        return CoverageAckBarrier(
            _BARRIER_FACTORY,
            self,
            evidence,
            lifecycle_identity,
            capability_token,
        )

    def _first_unclosed_sequence_gap(
        self,
        evidence: SegmentStore,
        *,
        lifecycle_identity: object,
        capability_token: object,
    ) -> int | None:
        if not self._healthy:
            raise CoverageUnhealthy("coverage reducer is unhealthy")
        if (
            self._closed
            or evidence is not self._evidence
            or lifecycle_identity is not self._lifecycle_identity
            or capability_token is not self._capability_token
        ):
            raise CoverageAuthorityError("coverage ACK barrier is stale or foreign")
        try:
            evidence._validate_coverage_state_owner(
                self,
                lifecycle_identity,
                reducer_head=self._snapshot.head_ref,
            )
        except EvidenceStoreError as error:
            raise CoverageAuthorityError(
                "coverage ACK barrier failed same-store head validation"
            ) from error
        return min(
            (
                item.open_source_sequence
                for item in self._snapshot.sequence_gaps
                if item.close_source_sequence is None
            ),
            default=None,
        )

    def _invalidate(self) -> None:
        self._closed = True
        self._capability_token = None
        self._evidence = None
        self._lifecycle_identity = None

    def close(self) -> None:
        if self._closed:
            return
        evidence = self._evidence
        lifecycle_identity = self._lifecycle_identity
        try:
            if evidence is not None and lifecycle_identity is not None:
                try:
                    evidence._release_coverage_state(self, lifecycle_identity)
                except EvidenceStoreError as error:
                    raise CoverageAuthorityError("coverage owner release failed") from error
        finally:
            self._invalidate()

    def _close_from_segment_store(self, lifecycle_identity: object) -> None:
        if self._closed:
            return
        evidence = self._evidence
        if evidence is None or lifecycle_identity is not self._lifecycle_identity:
            raise CoverageAuthorityError("coverage store-close callback has the wrong lifecycle")
        evidence._release_coverage_state(self, lifecycle_identity)
        self._invalidate()
