"""Bounded historical coverage reduction over authenticated evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import weakref
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
from threading import RLock, get_ident
from types import MappingProxyType
from typing import Never, SupportsIndex, cast, final, overload

from pydantic import BaseModel, ValidationError

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import (
    MAX_UINT64,
    CoverageEventV1,
    EventEnvelopeV1,
    PCCCorrelationSnapshotRequestV1,
    PCCCorrelationSnapshotV1,
)
from agmind_immune.correlation.pcc import HistoricalCoverageAssessment
from agmind_immune.coverage.grammar import (
    _classify_coverage_record,
    _CoverageClassification,
    _historical_coverage_window,
    _interval_intersects_window,
)
from agmind_immune.evidence.dedup import _logical_primary_identity_v2
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    EvidenceStatus,
    EvidenceStoreError,
    SegmentStore,
    StoredEvidenceRecord,
    _exact_coverage_record_key,
)
from agmind_immune.ingest.envelope import (
    AuthenticatedPCCInput,
    EnvelopeVerifier,
    authenticated_pcc_input_is_issued,
)

_COVERAGE_HASH_DOMAIN = b"AGMIND_CORRELATION_COVERAGE_V1\0"
_REPLAY_COMPACT_HASH_DOMAIN = b"AGMIND_HISTORICAL_REPLAY_COMPACT_V1\0"
_REPLAY_SEAL_HASH_DOMAIN = b"AGMIND_HISTORICAL_REPLAY_STATE_SEAL_V1\0"
_COLLECTION_CAP = 4_096
_PATH_FACTORY = object()
_ISSUED_PATHS: weakref.WeakKeyDictionary[
    HistoricalPathAuthority,
    _PathBinding | _ReplayPathBinding,
]


class HistoricalCoverageUnavailable(RuntimeError):
    """Historical authority or bounded construction resources are unavailable."""


class HistoricalCoverageConflict(RuntimeError):
    """Authenticated historical facts cannot form one deterministic history."""


@dataclass(frozen=True, slots=True)
class HistoricalCoverageRecord:
    canonical_envelope: bytes
    priority: EvidencePriority
    accepted_at: str
    ref: EvidenceRef
    classification: _CoverageClassification
    dedup_kind: str
    logical_key_sha256: str


@dataclass(frozen=True, slots=True)
class _PreparedHistoricalRecord:
    fact: HistoricalCoverageRecord
    envelope: EventEnvelopeV1
    coverage: CoverageEventV1 | None


@dataclass(frozen=True, slots=True)
class HistoricalCriticalEpisode:
    component: str
    kind: str
    opened_at: str
    open_event_id: str
    closed_at: str | None = None
    close_event_id: str | None = None

    def __post_init__(self) -> None:
        if (self.closed_at is None) != (self.close_event_id is None):
            raise ValueError("historical close time and identity must be both present")


@dataclass(frozen=True, slots=True)
class HistoricalCoverageTimeline:
    assessment: HistoricalCoverageAssessment
    intersecting_intervals: tuple[HistoricalCriticalEpisode, ...]
    coverage_event_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _OpenEpisode:
    scope_boot_id: str | None
    component: str
    kind: str
    opened_at: str
    open_event_id: str
    open_sequence: int
    latest_event_id: str
    latest_sequence: int
    reason_code: str
    dropped_count: int | None
    normalized_fields_sha256: str
    source_payload_hash: str


@dataclass(frozen=True, slots=True)
class _DockerRecovery:
    generation: int
    opened_at: str
    closed_at: str
    open_event_id: str
    recovery_event_id: str
    recovery_sequence: int


@dataclass(frozen=True, slots=True)
class _SequenceEpisode:
    affected_start: int
    affected_end: int
    opened_at: str
    open_event_id: str
    open_sequence: int
    baseline_recovery: _DockerRecovery | None


@dataclass(frozen=True, slots=True)
class _ClosedSummary:
    episode: HistoricalCriticalEpisode
    dependency_ids: tuple[str, ...]


def _late_coverage_may_invalidate_candidate(record: StoredEvidenceRecord) -> bool:
    if type(record) is not StoredEvidenceRecord:
        raise HistoricalCoverageUnavailable(
            "late coverage classification requires exact evidence"
        )
    prepared = _prepare_historical_record(record)
    return prepared.coverage is not None and prepared.fact.classification.action in {
        "docker_open",
        "docker_close",
        "sequence_open",
        "sequence_close",
        "generic_open",
        "generic_close",
        "falco_stop",
    }


def _late_coverage_invalidates_candidate(
    authenticated: AuthenticatedPCCInput,
    record: StoredEvidenceRecord,
) -> bool:
    """Derive late coverage impact from an issued PCC and exact evidence bytes."""
    if (
        type(authenticated) is not AuthenticatedPCCInput
        or not authenticated_pcc_input_is_issued(authenticated)
        or type(record) is not StoredEvidenceRecord
    ):
        raise HistoricalCoverageUnavailable(
            "late coverage requires exact issued evidence authority"
        )
    return _late_coverage_invalidates_candidate_values(authenticated, record)


def _late_coverage_invalidates_candidate_values(
    authenticated: AuthenticatedPCCInput,
    record: StoredEvidenceRecord,
) -> bool:
    """Derive late coverage impact from exact detached proof values."""
    if (
        type(authenticated) is not AuthenticatedPCCInput
        or type(record) is not StoredEvidenceRecord
    ):
        raise HistoricalCoverageUnavailable(
            "late coverage requires exact detached evidence values"
        )
    prepared = _prepare_historical_record(record)
    coverage = prepared.coverage
    if coverage is None:
        return False
    envelope = prepared.envelope
    snapshot = authenticated.snapshot
    trigger = snapshot.trigger
    if (
        snapshot.outcome != "complete"
        or authenticated.host_id != trigger.host_id
        or authenticated.boot_id != trigger.boot_id
        or authenticated.source_sequence <= trigger.source_sequence
        or snapshot.coverage_through_sequence != authenticated.source_sequence - 1
        or envelope.host_id != authenticated.host_id
        or envelope.source_sequence <= authenticated.source_sequence
    ):
        raise HistoricalCoverageConflict(
            "late coverage candidate authority is inconsistent"
        )
    action = prepared.fact.classification.action
    sequence_intersects = False
    if action in {"sequence_open", "sequence_close"}:
        affected_start = coverage.affected_source_sequence_start
        affected_end = coverage.affected_source_sequence_end
        if affected_start is None or affected_end is None:
            raise HistoricalCoverageConflict("late sequence coverage lost its range")
        sequence_intersects = not (
            affected_end < trigger.source_sequence
            or affected_start > snapshot.coverage_through_sequence
        )
    time_intersects = False
    if action in {
        "docker_open",
        "docker_close",
        "sequence_open",
        "sequence_close",
        "generic_open",
        "generic_close",
        "falco_stop",
    } and (
        prepared.fact.classification.scope != "process"
        or envelope.boot_id == authenticated.boot_id
    ):
        window = _historical_coverage_window(
            trigger.event_time,
            trigger.clock_uncertainty_ms,
            snapshot.decision_time,
        )
        time_intersects = _interval_intersects_window(
            coverage.opened_at,
            coverage.closed_at,
            window,
        )
    return time_intersects or sequence_intersects


def _bounded_for_test(label: str, values: Iterable[object]) -> tuple[object, ...]:
    selected: list[object] = []
    for value in values:
        if len(selected) == _COLLECTION_CAP:
            raise HistoricalCoverageUnavailable(f"{label} exceed 4096")
        selected.append(value)
    return tuple(selected)


def _append_bounded[T](collection: list[T], value: T, label: str) -> None:
    if len(collection) == _COLLECTION_CAP:
        raise HistoricalCoverageUnavailable(f"{label} exceed 4096")
    collection.append(value)


def _retain_closed_summary(
    pretrigger: list[_ClosedSummary],
    recent: list[_ClosedSummary],
    summary: _ClosedSummary,
    *,
    source_sequence: int,
    trigger_source_sequence: int,
) -> None:
    if source_sequence <= trigger_source_sequence:
        _append_bounded(pretrigger, summary, "pre-trigger summaries")
    else:
        _append_bounded(recent, summary, "recent path events")


def _prepare_historical_record(record: StoredEvidenceRecord) -> _PreparedHistoricalRecord:
    if type(record) is not StoredEvidenceRecord or type(record.ref) is not EvidenceRef:
        raise HistoricalCoverageConflict("historical record is not exact evidence")
    try:
        raw = json.loads(record.canonical_envelope)
        envelope = EventEnvelopeV1.model_validate(raw, strict=True)
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError) as error:
        raise HistoricalCoverageConflict("historical envelope is invalid") from error
    if (
        canonical_json(raw) != record.canonical_envelope
        or canonical_json(record.envelope) != record.canonical_envelope
        or envelope.event_id != record.ref.event_id
        or envelope.source_sequence != record.ref.source_sequence
        or hashlib.sha256(record.canonical_envelope).hexdigest()
        != record.ref.content_sha256
    ):
        raise HistoricalCoverageConflict("historical record outer binding changed")
    coverage: CoverageEventV1 | None = None
    if envelope.event_type == "coverage":
        try:
            coverage = CoverageEventV1.model_validate(
                envelope.normalized_fields,
                strict=True,
            )
        except ValidationError as error:
            raise HistoricalCoverageConflict("historical coverage fields are invalid") from error
    try:
        classification = _classify_coverage_record(envelope, coverage)
    except (TypeError, ValueError) as error:
        raise HistoricalCoverageConflict("historical coverage grammar rejected a record") from error
    kind, identity = _logical_primary_identity_v2(envelope)
    return _PreparedHistoricalRecord(
        fact=HistoricalCoverageRecord(
            canonical_envelope=record.canonical_envelope,
            priority=record.priority,
            accepted_at=record.accepted_at,
            ref=record.ref,
            classification=classification,
            dedup_kind=kind,
            logical_key_sha256=identity,
        ),
        envelope=envelope,
        coverage=coverage,
    )


@dataclass(frozen=True, slots=True)
class _HistoricalPreparedPrefix:
    prepared: tuple[_PreparedHistoricalRecord, ...]
    primary: tuple[bool, ...]
    ordinal_by_sequence: Mapping[int, int]

    def before(self, source_sequence: int) -> tuple[_PreparedHistoricalRecord, ...]:
        return tuple(
            item
            for item in self.prepared
            if item.envelope.source_sequence < source_sequence
        )


@dataclass(frozen=True, slots=True)
class _HistoricalReductionDiagnostics:
    prepared_records: int
    primary_checks: int
    interval_materializations: int
    event_materializations: int
    leaf_materializations: int
    semantic_prefix_visits: int


@dataclass(frozen=True, slots=True)
class _HistoricalReductionResult:
    timeline: HistoricalCoverageTimeline
    assessment_digest: bytes
    interval_count: int
    interval_digest: bytes
    event_count: int
    event_digest: bytes
    semantic_digest: bytes
    diagnostics: _HistoricalReductionDiagnostics


@dataclass(slots=True)
class _HistoricalReductionCounters:
    primary_checks: int = 0
    semantic_prefix_visits: int = 0


def _prepared_prefix_primary(
    prefix: _HistoricalPreparedPrefix,
    candidate: _PreparedHistoricalRecord,
    counters: _HistoricalReductionCounters,
) -> bool:
    counters.primary_checks += 1
    ordinal = prefix.ordinal_by_sequence.get(candidate.envelope.source_sequence)
    if ordinal is None or prefix.prepared[ordinal] is not candidate:
        raise HistoricalCoverageConflict("historical record is outside the prepared prefix")
    return prefix.primary[ordinal]


def _episode_was_closed(
    prefix: _HistoricalPreparedPrefix,
    counters: _HistoricalReductionCounters,
    before_sequence: int,
    key: tuple[str | None, str, str, str],
) -> bool:
    closed = False
    for candidate in prefix.before(before_sequence):
        counters.semantic_prefix_visits += 1
        if not _prepared_prefix_primary(prefix, candidate, counters):
            continue
        if (
            candidate.coverage is None
            or candidate.fact.classification.action
            not in {"generic_open", "generic_close"}
            or _episode_key(candidate) != key
        ):
            continue
        if candidate.fact.classification.action == "generic_close":
            closed = True
        elif closed:
            return True
    return closed


def _sequence_range_was_seen(
    prefix: _HistoricalPreparedPrefix,
    counters: _HistoricalReductionCounters,
    before_sequence: int,
    start: int,
    end: int,
) -> bool:
    for candidate in prefix.before(before_sequence):
        counters.semantic_prefix_visits += 1
        coverage = candidate.coverage
        if (
            coverage is None
            or candidate.fact.classification.action != "sequence_open"
            or not _prepared_prefix_primary(prefix, candidate, counters)
        ):
            continue
        prior_start = coverage.affected_source_sequence_start
        prior_end = coverage.affected_source_sequence_end
        if (
            prior_start is not None
            and prior_end is not None
            and not (end < prior_start or start > prior_end)
        ):
            return True
    return False


def _docker_episode_was_seen(
    prefix: _HistoricalPreparedPrefix,
    counters: _HistoricalReductionCounters,
    before_sequence: int,
    opened_at: str,
    generation: int,
) -> bool:
    for candidate in prefix.before(before_sequence):
        counters.semantic_prefix_visits += 1
        coverage = candidate.coverage
        if (
            coverage is not None
            and candidate.fact.classification.action == "docker_open"
            and coverage.opened_at == opened_at
            and coverage.reconcile_generation == generation
            and _prepared_prefix_primary(prefix, candidate, counters)
        ):
            return True
    return False


def _episode_key(
    prepared: _PreparedHistoricalRecord,
) -> tuple[str | None, str, str, str]:
    coverage = prepared.coverage
    if coverage is None:
        raise HistoricalCoverageConflict("episode record lost coverage fields")
    return (
        prepared.envelope.boot_id
        if prepared.fact.classification.scope == "process"
        else None,
        coverage.component,
        coverage.kind,
        coverage.opened_at,
    )


def _coverage_snapshot_sha256(
    *,
    host_id: str,
    boot_id: str,
    trigger_event_id: str,
    trigger_source_sequence: int,
    coverage_through_sequence: int,
    window_start: str,
    window_end: str,
    intersecting_intervals: Iterable[HistoricalCriticalEpisode],
    coverage_event_ids: Iterable[str],
) -> str:
    intervals = sorted(
        intersecting_intervals,
        key=lambda item: (
            item.opened_at,
            item.component,
            item.kind,
            item.open_event_id,
            item.close_event_id or "",
        ),
    )
    _bounded_for_test("final intervals", intervals)
    identifiers = tuple(sorted(set(coverage_event_ids)))
    _bounded_for_test("final coverage IDs", identifiers)
    rendered: list[dict[str, object]] = []
    for interval in intervals:
        value: dict[str, object] = {
            "component": interval.component,
            "kind": interval.kind,
            "opened_at": interval.opened_at,
            "open_event_id": interval.open_event_id,
        }
        if interval.closed_at is not None:
            value["closed_at"] = interval.closed_at
        if interval.close_event_id is not None:
            value["close_event_id"] = interval.close_event_id
        rendered.append(value)
    payload = {
        "host_id": host_id,
        "boot_id": boot_id,
        "trigger_event_id": trigger_event_id,
        "trigger_source_sequence": trigger_source_sequence,
        "coverage_through_sequence": coverage_through_sequence,
        "window_start": window_start,
        "window_end": window_end,
        "intersecting_intervals": rendered,
        "coverage_event_ids": identifiers,
    }
    return hashlib.sha256(
        _COVERAGE_HASH_DOMAIN + canonical_json(payload)
    ).hexdigest()


def _reduce_historical_coverage_result(
    records: tuple[StoredEvidenceRecord, ...],
    *,
    host_id: str,
    boot_id: str,
    trigger_event_id: str,
    trigger_source_sequence: int,
    trigger_event_time: str,
    clock_uncertainty_ms: int,
    coverage_through_sequence: int,
    window_end: str,
) -> _HistoricalReductionResult:
    if type(records) is not tuple or any(
        type(record) is not StoredEvidenceRecord for record in records
    ):
        raise HistoricalCoverageUnavailable(
            "historical reduction requires exact ordered evidence records"
        )
    selected_prepared = tuple(_prepare_historical_record(stored) for stored in records)
    seen_primary_keys: set[tuple[str, str]] = set()
    primary_mask: list[bool] = []
    for prepared in selected_prepared:
        primary_key = (
            prepared.fact.dedup_kind,
            prepared.fact.logical_key_sha256,
        )
        primary = primary_key not in seen_primary_keys
        primary_mask.append(primary)
        if primary:
            seen_primary_keys.add(primary_key)
    prefix = _HistoricalPreparedPrefix(
        selected_prepared,
        tuple(primary_mask),
        MappingProxyType(
            {
                prepared.envelope.source_sequence: ordinal
                for ordinal, prepared in enumerate(selected_prepared)
            }
        ),
    )
    counters = _HistoricalReductionCounters()
    window = _historical_coverage_window(
        trigger_event_time,
        clock_uncertainty_ms,
        window_end,
    )
    active: dict[tuple[object, ...], _OpenEpisode] = {}
    pretrigger: list[_ClosedSummary] = []
    recent_summaries: list[_ClosedSummary] = []
    recent_primary_ids: list[str] = []
    docker_active: dict[tuple[str, int], _OpenEpisode] = {}
    latest_recovery: _DockerRecovery | None = None
    sequence_active: dict[tuple[int, int, str], _SequenceEpisode] = {}
    last_sequence = 0
    current_boot: str | None = None

    for prepared in selected_prepared:
        counters.semantic_prefix_visits += 1
        envelope = prepared.envelope
        if envelope.host_id != host_id or envelope.source_sequence <= last_sequence:
            raise HistoricalCoverageConflict("historical records are not one host in order")
        last_sequence = envelope.source_sequence
        if envelope.source_sequence > coverage_through_sequence:
            continue
        if not _prepared_prefix_primary(prefix, prepared, counters):
            continue
        if current_boot is not None and envelope.boot_id != current_boot:
            active = {
                key: value
                for key, value in active.items()
                if value.scope_boot_id is None
            }
        current_boot = envelope.boot_id
        action = prepared.fact.classification.action
        coverage = prepared.coverage
        if (
            coverage is not None
            and trigger_source_sequence < envelope.source_sequence
            <= coverage_through_sequence
        ):
            _append_bounded(
                recent_primary_ids,
                envelope.event_id,
                "recent primary IDs",
            )

        if action == "docker_open" and coverage is not None:
            generation = coverage.reconcile_generation
            if generation is None:
                raise HistoricalCoverageConflict("Docker open lost generation")
            docker_key = (coverage.opened_at, generation)
            if docker_key in docker_active or _docker_episode_was_seen(
                prefix,
                counters,
                envelope.source_sequence,
                coverage.opened_at,
                generation,
            ):
                raise HistoricalCoverageConflict("Docker open is duplicated")
            opened = _OpenEpisode(
                None,
                coverage.component,
                coverage.kind,
                coverage.opened_at,
                envelope.event_id,
                envelope.source_sequence,
                envelope.event_id,
                envelope.source_sequence,
                coverage.reason_code,
                None,
                envelope.normalized_fields_sha256,
                envelope.source_payload_hash,
            )
            if len(active) + len(docker_active) + len(sequence_active) == _COLLECTION_CAP:
                raise HistoricalCoverageUnavailable("active episodes exceed 4096")
            docker_active[docker_key] = opened
        elif action == "docker_close" and coverage is not None:
            generation = coverage.reconcile_generation
            if generation is None or coverage.closed_at is None:
                raise HistoricalCoverageConflict("Docker recovery lost exact fields")
            docker_key = (coverage.opened_at, generation)
            docker_opened = docker_active.get(docker_key)
            if docker_opened is None or (
                latest_recovery is not None
                and generation <= latest_recovery.generation
            ):
                raise HistoricalCoverageConflict("Docker recovery lacks one advancing open")
            del docker_active[docker_key]
            episode = HistoricalCriticalEpisode(
                docker_opened.component,
                docker_opened.kind,
                docker_opened.opened_at,
                docker_opened.open_event_id,
                coverage.closed_at,
                envelope.event_id,
            )
            if _interval_intersects_window(episode.opened_at, episode.closed_at, window):
                _retain_closed_summary(
                    pretrigger,
                    recent_summaries,
                    _ClosedSummary(
                        episode,
                        (docker_opened.open_event_id, envelope.event_id),
                    ),
                    source_sequence=envelope.source_sequence,
                    trigger_source_sequence=trigger_source_sequence,
                )
            latest_recovery = _DockerRecovery(
                generation,
                docker_opened.opened_at,
                coverage.closed_at,
                docker_opened.open_event_id,
                envelope.event_id,
                envelope.source_sequence,
            )
        elif action == "sequence_open" and coverage is not None:
            start = coverage.affected_source_sequence_start
            end = coverage.affected_source_sequence_end
            if start is None or end is None:
                raise HistoricalCoverageConflict("sequence open lost range")
            sequence_key = (start, end, coverage.opened_at)
            if sequence_key in sequence_active or _sequence_range_was_seen(
                prefix,
                counters,
                envelope.source_sequence,
                start,
                end,
            ):
                raise HistoricalCoverageConflict("sequence gap duplicated")
            if len(active) + len(docker_active) + len(sequence_active) == _COLLECTION_CAP:
                raise HistoricalCoverageUnavailable("active episodes exceed 4096")
            sequence_active[sequence_key] = _SequenceEpisode(
                start,
                end,
                coverage.opened_at,
                envelope.event_id,
                envelope.source_sequence,
                latest_recovery,
            )
        elif action == "sequence_close" and coverage is not None:
            start = coverage.affected_source_sequence_start
            end = coverage.affected_source_sequence_end
            generation = coverage.reconcile_generation
            if start is None or end is None or generation is None or coverage.closed_at is None:
                raise HistoricalCoverageConflict("sequence close lost exact fields")
            sequence_key = (start, end, coverage.opened_at)
            sequence_opened = sequence_active.get(sequence_key)
            if (
                sequence_opened is None
                or latest_recovery is None
                or latest_recovery.recovery_sequence >= envelope.source_sequence
                or latest_recovery.recovery_sequence <= sequence_opened.open_sequence
                or latest_recovery.generation != generation
                or latest_recovery.closed_at != coverage.closed_at
                or (
                    sequence_opened.baseline_recovery is not None
                    and generation <= sequence_opened.baseline_recovery.generation
                )
            ):
                raise HistoricalCoverageConflict("sequence close lacks baseline recovery")
            del sequence_active[sequence_key]
            dependency_ids = [
                sequence_opened.open_event_id,
                envelope.event_id,
                latest_recovery.open_event_id,
                latest_recovery.recovery_event_id,
            ]
            if sequence_opened.baseline_recovery is not None:
                dependency_ids.extend(
                    (
                        sequence_opened.baseline_recovery.open_event_id,
                        sequence_opened.baseline_recovery.recovery_event_id,
                    )
                )
            if (
                _interval_intersects_window(
                    sequence_opened.opened_at,
                    coverage.closed_at,
                    window,
                )
                or not (
                    sequence_opened.affected_end < trigger_source_sequence
                    or sequence_opened.affected_start > coverage_through_sequence
                )
            ):
                _retain_closed_summary(
                    pretrigger,
                    recent_summaries,
                    _ClosedSummary(
                        HistoricalCriticalEpisode(
                            "observer",
                            "observer_sequence_gap",
                            sequence_opened.opened_at,
                            sequence_opened.open_event_id,
                            coverage.closed_at,
                            envelope.event_id,
                        ),
                        tuple(dependency_ids),
                    ),
                    source_sequence=envelope.source_sequence,
                    trigger_source_sequence=trigger_source_sequence,
                )
        elif action in {"generic_open", "generic_close"} and coverage is not None:
            episode_key = _episode_key(prepared)
            active_opened = active.get(episode_key)
            if action == "generic_open":
                if active_opened is None:
                    if _episode_was_closed(
                        prefix,
                        counters,
                        envelope.source_sequence,
                        episode_key,
                    ):
                        raise HistoricalCoverageConflict(
                            "closed critical episode cannot reopen"
                        )
                    if (
                        len(active) + len(docker_active) + len(sequence_active)
                        == _COLLECTION_CAP
                    ):
                        raise HistoricalCoverageUnavailable("active episodes exceed 4096")
                    active[episode_key] = _OpenEpisode(
                        episode_key[0],
                        coverage.component,
                        coverage.kind,
                        coverage.opened_at,
                        envelope.event_id,
                        envelope.source_sequence,
                        envelope.event_id,
                        envelope.source_sequence,
                        coverage.reason_code,
                        coverage.dropped_count,
                        envelope.normalized_fields_sha256,
                        envelope.source_payload_hash,
                    )
                else:
                    prior_count = active_opened.dropped_count
                    next_count = coverage.dropped_count
                    if prepared.fact.classification.counter_required:
                        if prior_count is None or next_count is None or (
                            next_count <= prior_count
                            and not (prior_count == MAX_UINT64 and next_count == MAX_UINT64)
                        ):
                            raise HistoricalCoverageConflict("critical counter did not advance")
                    elif prior_count is not None or next_count is not None:
                        raise HistoricalCoverageConflict("uncounted critical gained a counter")
                    if (
                        episode_key[0] is None
                        and coverage.reason_code != active_opened.reason_code
                    ):
                        raise HistoricalCoverageConflict("critical opening reason changed")
                    active[episode_key] = replace(
                        active_opened,
                        latest_event_id=envelope.event_id,
                        latest_sequence=envelope.source_sequence,
                        reason_code=coverage.reason_code,
                        dropped_count=next_count,
                        normalized_fields_sha256=envelope.normalized_fields_sha256,
                        source_payload_hash=envelope.source_payload_hash,
                    )
            elif active_opened is not None:
                if prepared.fact.classification.counter_required:
                    if coverage.dropped_count != active_opened.dropped_count:
                        raise HistoricalCoverageConflict("critical close changed counter")
                elif (
                    active_opened.dropped_count is not None
                    or coverage.dropped_count is not None
                ):
                    raise HistoricalCoverageConflict("uncounted critical gained a counter")
                del active[episode_key]
                episode = HistoricalCriticalEpisode(
                    active_opened.component,
                    active_opened.kind,
                    active_opened.opened_at,
                    active_opened.open_event_id,
                    coverage.closed_at,
                    envelope.event_id,
                )
                if _interval_intersects_window(episode.opened_at, episode.closed_at, window):
                    _retain_closed_summary(
                        pretrigger,
                        recent_summaries,
                        _ClosedSummary(
                            episode,
                            (
                                active_opened.open_event_id,
                                active_opened.latest_event_id,
                                envelope.event_id,
                            ),
                        ),
                        source_sequence=envelope.source_sequence,
                        trigger_source_sequence=trigger_source_sequence,
                    )
            else:
                # A self-contained close is legal only when no earlier primary used the key.
                for prior in prefix.before(
                    envelope.source_sequence
                ):
                    counters.semantic_prefix_visits += 1
                    if (
                        _prepared_prefix_primary(prefix, prior, counters)
                        and prior.coverage is not None
                        and prior.fact.classification.action
                        in {"generic_open", "generic_close"}
                        and _episode_key(prior) == episode_key
                    ):
                        raise HistoricalCoverageConflict("critical episode was already closed")
                episode = HistoricalCriticalEpisode(
                    coverage.component,
                    coverage.kind,
                    coverage.opened_at,
                    envelope.event_id,
                    coverage.closed_at,
                    envelope.event_id,
                )
                if _interval_intersects_window(episode.opened_at, episode.closed_at, window):
                    _retain_closed_summary(
                        pretrigger,
                        recent_summaries,
                        _ClosedSummary(
                            episode,
                            (envelope.event_id,),
                        ),
                        source_sequence=envelope.source_sequence,
                        trigger_source_sequence=trigger_source_sequence,
                    )

        elif action == "falco_stop" and coverage is not None:
            point = HistoricalCriticalEpisode(
                component=coverage.component,
                kind=coverage.kind,
                opened_at=coverage.opened_at,
                closed_at=coverage.closed_at,
                open_event_id=envelope.event_id,
                close_event_id=envelope.event_id,
            )
            if _interval_intersects_window(point.opened_at, point.closed_at, window):
                _retain_closed_summary(
                    pretrigger,
                    recent_summaries,
                    _ClosedSummary(point, (envelope.event_id,)),
                    source_sequence=envelope.source_sequence,
                    trigger_source_sequence=trigger_source_sequence,
                )

    intervals: list[HistoricalCriticalEpisode] = [
        summary.episode for summary in (*pretrigger, *recent_summaries)
    ]
    final_ids = list(recent_primary_ids)
    for summary in (*pretrigger, *recent_summaries):
        for identifier in summary.dependency_ids:
            if identifier not in final_ids:
                _append_bounded(final_ids, identifier, "final coverage IDs")
    for remaining_opened in (*docker_active.values(), *active.values()):
        episode = HistoricalCriticalEpisode(
            remaining_opened.component,
            remaining_opened.kind,
            remaining_opened.opened_at,
            remaining_opened.open_event_id,
        )
        if _interval_intersects_window(episode.opened_at, None, window):
            _append_bounded(intervals, episode, "final intervals")
            for identifier in (
                remaining_opened.open_event_id,
                remaining_opened.latest_event_id,
            ):
                if identifier not in final_ids:
                    _append_bounded(final_ids, identifier, "final coverage IDs")

    structural_incomplete = False
    for open_sequence in sequence_active.values():
        if _interval_intersects_window(
            open_sequence.opened_at,
            None,
            window,
        ) or not (
            open_sequence.affected_end < trigger_source_sequence
            or open_sequence.affected_start > coverage_through_sequence
        ):
            structural_incomplete = True
    ordered_intervals: list[HistoricalCriticalEpisode] = []
    interval_hasher = hashlib.sha256()
    interval_hasher.update(_REPLAY_MEMO_INTERVAL_HASH_DOMAIN + b"[")
    for interval in sorted(
        intervals,
        key=lambda item: (
            item.opened_at,
            item.component,
            item.kind,
            item.open_event_id,
            item.close_event_id or "",
        ),
    ):
        if type(interval) is not HistoricalCriticalEpisode:
            raise HistoricalCoverageUnavailable(
                "historical replay memo interval type changed"
            )
        if ordered_intervals:
            interval_hasher.update(b",")
        ordered_intervals.append(interval)
        interval_hasher.update(canonical_json(_replay_exact_fact(interval)))
    sorted_intervals = tuple(ordered_intervals)
    interval_hasher.update(b"]")
    _bounded_for_test("final intervals", sorted_intervals)
    ordered_event_ids: list[str] = []
    event_hasher = hashlib.sha256()
    event_hasher.update(_REPLAY_MEMO_EVENT_HASH_DOMAIN + b"[")
    for event_id in sorted(set(final_ids)):
        if type(event_id) is not str:
            raise HistoricalCoverageUnavailable(
                "historical replay memo event type changed"
            )
        if ordered_event_ids:
            event_hasher.update(b",")
        ordered_event_ids.append(event_id)
        event_hasher.update(canonical_json(_replay_exact_fact(event_id)))
    coverage_ids = tuple(ordered_event_ids)
    event_hasher.update(b"]")
    _bounded_for_test("final coverage IDs", coverage_ids)
    complete = window.complete and not structural_incomplete
    digest = None
    if complete:
        if window.window_start is None:
            raise HistoricalCoverageConflict("complete window lost its start")
        digest = _coverage_snapshot_sha256(
            host_id=host_id,
            boot_id=boot_id,
            trigger_event_id=trigger_event_id,
            trigger_source_sequence=trigger_source_sequence,
            coverage_through_sequence=coverage_through_sequence,
            window_start=window.window_start,
            window_end=window.window_end,
            intersecting_intervals=sorted_intervals,
            coverage_event_ids=coverage_ids,
        )
    assessment = HistoricalCoverageAssessment(
        host_id=host_id,
        boot_id=boot_id,
        trigger_event_id=trigger_event_id,
        trigger_source_sequence=trigger_source_sequence,
        coverage_through_sequence=coverage_through_sequence,
        window_start=window.window_start,
        window_end=window.window_end,
        complete=complete,
        critical_gap=bool(sorted_intervals) if complete else False,
        coverage_snapshot_sha256=digest,
    )
    assessment_digest = _replay_fact_digest(
        _REPLAY_MEMO_ASSESSMENT_HASH_DOMAIN,
        assessment,
    )
    interval_digest = interval_hasher.digest()
    event_digest = event_hasher.digest()
    semantic_digest = _replay_fact_digest(
        _REPLAY_MEMO_SEMANTIC_HASH_DOMAIN,
        (
            assessment_digest,
            len(sorted_intervals),
            interval_digest,
            len(coverage_ids),
            event_digest,
        ),
    )
    timeline = HistoricalCoverageTimeline(assessment, sorted_intervals, coverage_ids)
    return _HistoricalReductionResult(
        timeline=timeline,
        assessment_digest=assessment_digest,
        interval_count=len(sorted_intervals),
        interval_digest=interval_digest,
        event_count=len(coverage_ids),
        event_digest=event_digest,
        semantic_digest=semantic_digest,
        diagnostics=_HistoricalReductionDiagnostics(
            prepared_records=len(selected_prepared),
            primary_checks=counters.primary_checks,
            interval_materializations=len(sorted_intervals),
            event_materializations=len(coverage_ids),
            leaf_materializations=len(sorted_intervals) + len(coverage_ids),
            semantic_prefix_visits=counters.semantic_prefix_visits,
        ),
    )


def _reduce_historical_coverage(
    records: Iterable[StoredEvidenceRecord],
    *,
    host_id: str,
    boot_id: str,
    trigger_event_id: str,
    trigger_source_sequence: int,
    trigger_event_time: str,
    clock_uncertainty_ms: int,
    coverage_through_sequence: int,
    window_end: str,
) -> HistoricalCoverageTimeline:
    return _reduce_historical_coverage_result(
        tuple(records),
        host_id=host_id,
        boot_id=boot_id,
        trigger_event_id=trigger_event_id,
        trigger_source_sequence=trigger_source_sequence,
        trigger_event_time=trigger_event_time,
        clock_uncertainty_ms=clock_uncertainty_ms,
        coverage_through_sequence=coverage_through_sequence,
        window_end=window_end,
    ).timeline


type _RefFingerprint = tuple[object, ...]


def _ref_fingerprint(ref: object) -> _RefFingerprint:
    if type(ref) is not EvidenceRef:
        raise HistoricalCoverageUnavailable("historical PCC ref is not exact")
    return (
        ref.segment_id,
        ref.segment_relative_path,
        ref.frame_offset,
        ref.frame_size,
        ref.frame_sha256,
        ref.event_id,
        ref.source_sequence,
        ref.content_sha256,
    )


@dataclass(frozen=True, slots=True)
class _PathBinding:
    lifecycle: object
    verifier: object
    verifier_authority: object
    verifier_generation: int
    pcc: AuthenticatedPCCInput
    pcc_ref: _RefFingerprint
    pcc_canonical: bytes
    request_canonical: bytes
    snapshot_canonical: bytes
    host_id: str
    boot_id: str
    trigger_event_id: str
    trigger_content_sha256: str
    trigger_source_sequence: int
    terminal_sequence: int
    coverage_through_sequence: int
    acceptance_cursor: int
    surviving_path_refs: tuple[_RefFingerprint, ...]
    retired_ranges: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class _ReplayPathBinding:
    """Non-authorizing marker distinguishing replay paths from ordinary paths."""


@dataclass(frozen=True, slots=True)
class _ReplayPathRecord:
    pcc: AuthenticatedPCCInput
    compact_records: _BoundedView[StoredEvidenceRecord]
    compact_prepared: _BoundedView[_PreparedHistoricalRecord]
    compact_count: int
    compact_digest: str
    event_token: _ReplayEventToken | None
    phase: str


@final
class _ReplayHandle:
    __slots__ = ("__dispatch",)
    __dispatch: Callable[..., object]

    def __init__(
        self,
        dispatch: Callable[..., object],
    ) -> None:
        del dispatch
        raise TypeError("historical replay handles are broker-issued")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("historical replay handles are immutable")

    def _invoke(self, operation: str, *arguments: object) -> object:
        return self.__dispatch(self, operation, *arguments)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("historical replay handles cannot be subclassed")

    def __copy__(self) -> Never:
        raise TypeError("historical replay handles cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        del memo
        raise TypeError("historical replay handles cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("historical replay handles cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("historical replay handles cannot be serialized")


@final
class _ReplayAccess:
    __slots__ = ("__dispatch",)
    __dispatch: Callable[..., object]

    def __init__(
        self,
        dispatch: Callable[..., object],
    ) -> None:
        del dispatch
        raise TypeError("historical replay accesses are broker-issued")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("historical replay accesses are immutable")

    def _invoke(self, operation: str, *arguments: object) -> object:
        return self.__dispatch(self, operation, *arguments)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("historical replay accesses cannot be subclassed")

    def __copy__(self) -> Never:
        raise TypeError("historical replay accesses cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        del memo
        raise TypeError("historical replay accesses cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("historical replay accesses cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("historical replay accesses cannot be serialized")


@dataclass(frozen=True, slots=True)
class _ReplayAccessRecord:
    pcc: AuthenticatedPCCInput
    phase: str
    event_token: _ReplayEventToken | None


@dataclass(frozen=True, slots=True)
class _BoundedView[T]:
    ledger: Sequence[T]
    count: int

    def __len__(self) -> int:
        return self.count

    def __getitem__(self, index: int | slice) -> T | Sequence[T]:
        if isinstance(index, slice):
            return self.ledger[: self.count][index]
        normalized = index if index >= 0 else self.count + index
        if not 0 <= normalized < self.count:
            raise IndexError(index)
        return self.ledger[normalized]

    def __iter__(self) -> Iterator[T]:
        for index in range(self.count):
            yield self.ledger[index]


@final
class _ReplayLedger[T](Sequence[T]):
    __slots__ = ("_items",)

    def __init__(self) -> None:
        self._items: list[T] = []

    def append(self, value: T) -> None:
        self._items.append(value)

    def clear(self) -> None:
        self._items.clear()

    def freeze(self) -> tuple[T, ...]:
        return tuple(self._items)

    def __len__(self) -> int:
        return len(self._items)

    @overload
    def __getitem__(self, index: SupportsIndex) -> T: ...

    @overload
    def __getitem__(self, index: slice) -> list[T]: ...

    def __getitem__(self, index: SupportsIndex | slice) -> T | list[T]:
        return self._items[index]

    def __iter__(self) -> Iterator[T]:
        return iter(self._items)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _ReplayLedger):
            return self._items == other._items
        if isinstance(other, (list, tuple)):
            return self._items == list(other)
        return NotImplemented


@dataclass(frozen=True, slots=True)
class _ReplayPCCLeaf:
    key: tuple[str, str]
    pcc: AuthenticatedPCCInput
    request: PCCCorrelationSnapshotRequestV1
    snapshot: PCCCorrelationSnapshotV1
    evidence_ref: EvidenceRef
    facts_digest: bytes


@dataclass(frozen=True, slots=True)
class _ReplayMemoLeaf:
    key: tuple[str, str]
    assessment: HistoricalCoverageAssessment
    compact_count: int
    compact_digest: str
    assessment_digest: bytes
    interval_count: int
    interval_digest: bytes
    event_count: int
    event_digest: bytes
    semantic_digest: bytes
    facts_digest: bytes


@dataclass(frozen=True, slots=True)
class _ReplayStateSeal:
    """Linear strict expectation over closure-owned replay leaves."""

    state: str
    version: int
    store: SegmentStore
    lifecycle: object
    verifier: object
    verifier_authority: object
    creator_thread: int
    terminal_ref: EvidenceRef
    frozen_status: EvidenceStatus
    entries: tuple[_FrozenReplayEntry, ...]
    entry_records: tuple[StoredEvidenceRecord, ...]
    entry_prepared: tuple[_PreparedHistoricalRecord, ...]
    frozen_record_keys: tuple[object, ...]
    frozen_retired_ranges: tuple[tuple[int, int], ...]
    verifier_generation: int
    projected_head: int
    compact_container: object
    compact_prepared_container: object
    compact_records: tuple[StoredEvidenceRecord, ...]
    compact_prepared: tuple[_PreparedHistoricalRecord, ...]
    used_pcc_container: object
    used_pcc: tuple[_ReplayPCCLeaf, ...]
    used_pcc_identities: tuple[
        tuple[
            _ReplayPCCLeaf,
            AuthenticatedPCCInput,
            object,
            object,
            EvidenceRef,
        ],
        ...,
    ]
    memo_container: object
    memos: tuple[_ReplayMemoLeaf, ...]
    memo_identities: tuple[
        tuple[_ReplayMemoLeaf, HistoricalCoverageAssessment],
        ...,
    ]
    access: _ReplayAccess | None
    access_record: _ReplayAccessRecord | None
    path_container: object
    paths: tuple[tuple[HistoricalPathAuthority, _ReplayPathRecord], ...]
    probe_ticket: object | None
    canonical_digest: bytes


def _replay_exact_fact(value: object) -> object:
    """Render exact runtime types and ordered values for the replay seal."""
    value_type = type(value)
    type_name = f"{value_type.__module__}.{value_type.__qualname__}"
    if value is None:
        return ["none"]
    if value_type is bool:
        return ["bool", value]
    if value_type is int:
        return ["int", str(value)]
    if value_type is float:
        return ["float", cast(float, value).hex()]
    if value_type is str:
        return ["str", value]
    if value_type is bytes:
        return ["bytes", cast(bytes, value).hex()]
    if value_type is tuple:
        tuple_value = cast(tuple[object, ...], value)
        return ["tuple", [_replay_exact_fact(item) for item in tuple_value]]
    if value_type is list:
        list_value = cast(list[object], value)
        return ["list", [_replay_exact_fact(item) for item in list_value]]
    if value_type is dict:
        dict_value = cast(dict[object, object], value)
        return [
            "dict",
            [
                [_replay_exact_fact(key), _replay_exact_fact(item)]
                for key, item in dict_value.items()
            ],
        ]
    if value_type is set:
        set_value = cast(set[object], value)
        rendered = [_replay_exact_fact(item) for item in set_value]
        rendered.sort(key=canonical_json)
        return ["set", rendered]
    if value_type is frozenset:
        frozen_value = cast(frozenset[object], value)
        rendered = [_replay_exact_fact(item) for item in frozen_value]
        rendered.sort(key=canonical_json)
        return ["frozenset", rendered]
    if isinstance(value, Enum):
        return ["enum", type_name, _replay_exact_fact(value.value)]
    if value_type is AuthenticatedPCCInput:
        pcc_value = cast(AuthenticatedPCCInput, value)
        return [
            "authenticated_pcc",
            _replay_exact_fact(pcc_value.canonical),
            _replay_exact_fact(pcc_value.evidence_ref),
            _replay_exact_fact(pcc_value.request),
            _replay_exact_fact(pcc_value.snapshot),
            _replay_exact_fact(pcc_value.host_id),
            _replay_exact_fact(pcc_value.boot_id),
            _replay_exact_fact(pcc_value.event_id),
            _replay_exact_fact(pcc_value.source_sequence),
            _replay_exact_fact(pcc_value.content_sha256),
        ]
    if isinstance(value, BaseModel):
        if type(value.model_fields_set) is not set:
            raise TypeError("replay seal model fields-set is not exact")
        return [
            "model",
            type_name,
            _replay_exact_fact(value.model_fields_set),
            [
                [field_name, _replay_exact_fact(getattr(value, field_name))]
                for field_name in type(value).model_fields
            ],
        ]
    if is_dataclass(value) and not isinstance(value, type):
        return [
            "dataclass",
            type_name,
            [
                [field.name, _replay_exact_fact(getattr(value, field.name))]
                for field in fields(value)
            ],
        ]
    raise TypeError(f"replay seal cannot encode exact {type_name}")


@dataclass(frozen=True, slots=True)
class _FrozenReplayEntry:
    record: StoredEvidenceRecord
    prepared: _PreparedHistoricalRecord
    expected_primary: bool
    compact_member: bool


@final
class _ReplayEventToken:
    __slots__ = ("_entry_index", "_state")
    _entry_index: int
    _state: str

    def __init__(self, entry_index: int) -> None:
        del entry_index
        raise TypeError("historical replay event tokens are broker-issued")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("historical replay event tokens are immutable")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("historical replay event tokens are final")

    def __copy__(self) -> Never:
        raise TypeError("historical replay event tokens cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        del memo
        raise TypeError("historical replay event tokens cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("historical replay event tokens cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("historical replay event tokens cannot be serialized")


def _build_frozen_replay_entries(
    records: tuple[StoredEvidenceRecord, ...],
    prepared_records: tuple[_PreparedHistoricalRecord, ...],
) -> tuple[_FrozenReplayEntry, ...]:
    seen: set[tuple[str, str]] = set()
    last_primary_boot: str | None = None
    entries: list[_FrozenReplayEntry] = []
    for record, prepared in zip(records, prepared_records, strict=True):
        logical_key = (
            prepared.fact.dedup_kind,
            prepared.fact.logical_key_sha256,
        )
        expected_primary = logical_key not in seen
        if expected_primary:
            seen.add(logical_key)
        boot_transition = expected_primary and (
            last_primary_boot is None
            or prepared.envelope.boot_id != last_primary_boot
        )
        compact_member = expected_primary and (
            boot_transition or prepared.coverage is not None
        )
        if expected_primary:
            last_primary_boot = prepared.envelope.boot_id
        entries.append(
            _FrozenReplayEntry(
                record,
                prepared,
                expected_primary,
                compact_member,
            )
        )
    return tuple(entries)


def _initial_replay_compact_digest() -> str:
    return hashlib.sha256(_REPLAY_COMPACT_HASH_DOMAIN + b"EMPTY").hexdigest()


def _update_replay_compact_digest(
    previous: str,
    record: StoredEvidenceRecord,
) -> str:
    return _advance_replay_compact_digest(previous, record)


def _advance_replay_compact_digest(
    previous: str,
    record: StoredEvidenceRecord,
) -> str:
    identity = canonical_json(
        {
            "ref": list(_ref_fingerprint(record.ref)),
            "canonical_envelope_sha256": hashlib.sha256(
                record.canonical_envelope
            ).hexdigest(),
        }
    )
    return hashlib.sha256(
        _REPLAY_COMPACT_HASH_DOMAIN + bytes.fromhex(previous) + identity
    ).hexdigest()


def _replay_compact_digest(
    records: Iterable[StoredEvidenceRecord],
) -> tuple[int, str]:
    count = 0
    digest = _initial_replay_compact_digest()
    for record in records:
        count += 1
        digest = _update_replay_compact_digest(digest, record)
    return count, digest


def _validate_replay_compact_boundary(
    records: Sequence[StoredEvidenceRecord],
    prefix_digests: Sequence[str],
    *,
    selected_count: int,
    coverage_through: int,
    expected_digest: str,
) -> None:
    if (
        not 0 <= selected_count <= len(records)
        or (
            selected_count > 0
            and records[selected_count - 1].ref.source_sequence > coverage_through
        )
        or (
            selected_count < len(records)
            and records[selected_count].ref.source_sequence <= coverage_through
        )
        or prefix_digests[selected_count] != expected_digest
    ):
        raise HistoricalCoverageUnavailable(
            "historical replay compact prefix changed"
        )


_REPLAY_PCC_LEAF_HASH_DOMAIN = b"AGMIND_HISTORICAL_REPLAY_PCC_LEAF_V1\0"
_REPLAY_MEMO_ASSESSMENT_HASH_DOMAIN = (
    b"AGMIND_HISTORICAL_REPLAY_MEMO_ASSESSMENT_V1\0"
)
_REPLAY_MEMO_INTERVAL_HASH_DOMAIN = b"AGMIND_HISTORICAL_REPLAY_MEMO_INTERVAL_V1\0"
_REPLAY_MEMO_EVENT_HASH_DOMAIN = b"AGMIND_HISTORICAL_REPLAY_MEMO_EVENT_V1\0"
_REPLAY_MEMO_SEMANTIC_HASH_DOMAIN = b"AGMIND_HISTORICAL_REPLAY_MEMO_SEMANTIC_V1\0"
_REPLAY_MEMO_LEAF_HASH_DOMAIN = b"AGMIND_HISTORICAL_REPLAY_MEMO_LEAF_V1\0"


def _replay_fact_digest(domain: bytes, value: object) -> bytes:
    return hashlib.sha256(domain + canonical_json(_replay_exact_fact(value))).digest()


def _build_replay_pcc_leaf(
    key: tuple[str, str],
    authenticated: AuthenticatedPCCInput,
) -> _ReplayPCCLeaf:
    if (
        type(key) is not tuple
        or len(key) != 2
        or any(type(part) is not str for part in key)
        or type(authenticated) is not AuthenticatedPCCInput
        or type(authenticated.evidence_ref) is not EvidenceRef
        or key != (authenticated.event_id, authenticated.content_sha256)
    ):
        raise HistoricalCoverageUnavailable(
            "historical replay PCC leaf facts are not exact"
        )
    facts_digest = _replay_fact_digest(
        _REPLAY_PCC_LEAF_HASH_DOMAIN,
        (
            key,
            authenticated.canonical,
            authenticated.evidence_ref,
            authenticated.request,
            authenticated.snapshot,
            authenticated.host_id,
            authenticated.boot_id,
            authenticated.event_id,
            authenticated.source_sequence,
            authenticated.content_sha256,
        ),
    )
    return _ReplayPCCLeaf(
        key,
        authenticated,
        authenticated.request,
        authenticated.snapshot,
        authenticated.evidence_ref,
        facts_digest,
    )


def _replay_pcc_leaf_is_current(leaf: _ReplayPCCLeaf) -> bool:
    if (
        type(leaf) is not _ReplayPCCLeaf
        or leaf.pcc.request is not leaf.request
        or leaf.pcc.snapshot is not leaf.snapshot
        or leaf.pcc.evidence_ref is not leaf.evidence_ref
    ):
        return False
    try:
        current = _build_replay_pcc_leaf(leaf.key, leaf.pcc)
    except (AttributeError, TypeError, ValueError, HistoricalCoverageUnavailable):
        return False
    return hmac.compare_digest(current.facts_digest, leaf.facts_digest)


def _build_replay_memo_leaf(
    key: tuple[str, str],
    reduction: _HistoricalReductionResult,
    compact_count: int,
    compact_digest: str,
) -> _ReplayMemoLeaf:
    if (
        type(key) is not tuple
        or len(key) != 2
        or any(type(part) is not str for part in key)
        or type(reduction) is not _HistoricalReductionResult
        or type(reduction.timeline) is not HistoricalCoverageTimeline
        or type(reduction.timeline.assessment) is not HistoricalCoverageAssessment
        or type(compact_count) is not int
        or compact_count < 0
        or type(compact_digest) is not str
        or len(compact_digest) != 64
    ):
        raise HistoricalCoverageUnavailable(
            "historical replay memo leaf facts are not exact"
        )
    facts_digest = _replay_fact_digest(
        _REPLAY_MEMO_LEAF_HASH_DOMAIN,
        (
            key,
            compact_count,
            compact_digest,
            reduction.assessment_digest,
            reduction.interval_count,
            reduction.interval_digest,
            reduction.event_count,
            reduction.event_digest,
            reduction.semantic_digest,
        ),
    )
    return _ReplayMemoLeaf(
        key=key,
        assessment=reduction.timeline.assessment,
        compact_count=compact_count,
        compact_digest=compact_digest,
        assessment_digest=reduction.assessment_digest,
        interval_count=reduction.interval_count,
        interval_digest=reduction.interval_digest,
        event_count=reduction.event_count,
        event_digest=reduction.event_digest,
        semantic_digest=reduction.semantic_digest,
        facts_digest=facts_digest,
    )


def _replay_memo_leaf_is_current(leaf: _ReplayMemoLeaf) -> bool:
    if type(leaf) is not _ReplayMemoLeaf:
        return False
    try:
        assessment_digest = _replay_fact_digest(
            _REPLAY_MEMO_ASSESSMENT_HASH_DOMAIN,
            leaf.assessment,
        )
        facts_digest = _replay_fact_digest(
            _REPLAY_MEMO_LEAF_HASH_DOMAIN,
            (
                leaf.key,
                leaf.compact_count,
                leaf.compact_digest,
                leaf.assessment_digest,
                leaf.interval_count,
                leaf.interval_digest,
                leaf.event_count,
                leaf.event_digest,
                leaf.semantic_digest,
            ),
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return hmac.compare_digest(assessment_digest, leaf.assessment_digest) and hmac.compare_digest(
        facts_digest,
        leaf.facts_digest,
    )


def _replay_memo_leaf_semantics_match(
    expected: _ReplayMemoLeaf,
    rebuilt: _ReplayMemoLeaf,
) -> bool:
    return (
        type(expected) is _ReplayMemoLeaf
        and type(rebuilt) is _ReplayMemoLeaf
        and hmac.compare_digest(expected.facts_digest, rebuilt.facts_digest)
    )


def _capture_replay_broker_seal(
    *,
    state: str,
    version: int,
    store: SegmentStore,
    lifecycle: object,
    verifier: EnvelopeVerifier,
    verifier_authority: object,
    creator_thread: int,
    terminal_ref: EvidenceRef,
    frozen_status: EvidenceStatus,
    entries: tuple[_FrozenReplayEntry, ...],
    frozen_record_keys: tuple[object, ...],
    frozen_retired_ranges: tuple[tuple[int, int], ...],
    verifier_generation: int,
    projected_head: int,
    compact_records: Sequence[StoredEvidenceRecord],
    compact_prepared: Sequence[_PreparedHistoricalRecord],
    compact_count: int,
    compact_digest: str,
    used_pcc: dict[tuple[str, str], _ReplayPCCLeaf],
    memo: dict[tuple[str, str], _ReplayMemoLeaf],
    access: _ReplayAccess | None,
    access_record: _ReplayAccessRecord | None,
    paths: dict[HistoricalPathAuthority, _ReplayPathRecord],
    probe_ticket: object | None,
    pcc_leaf_is_current: Callable[[_ReplayPCCLeaf], bool],
    memo_leaf_is_current: Callable[[_ReplayMemoLeaf], bool],
) -> _ReplayStateSeal:
    if (
        type(state) is not str
        or state not in {"VALIDATION_PROBING", "VALIDATING", "FINAL_PROBING"}
        or type(version) is not int
        or version < 0
        or type(store) is not SegmentStore
        or type(creator_thread) is not int
        or type(terminal_ref) is not EvidenceRef
        or type(frozen_status) is not EvidenceStatus
        or type(entries) is not tuple
        or type(frozen_record_keys) is not tuple
        or type(frozen_retired_ranges) is not tuple
        or type(verifier_generation) is not int
        or verifier_generation < 0
        or type(projected_head) is not int
        or projected_head != terminal_ref.source_sequence
        or type(compact_count) is not int
        or type(compact_digest) is not str
        or type(used_pcc) is not dict
        or type(memo) is not dict
        or type(paths) is not dict
        or access is not None
        or access_record is not None
        or paths
        or (
            state in {"VALIDATION_PROBING", "FINAL_PROBING"}
            and probe_ticket is None
        )
        or (state == "VALIDATING" and probe_ticket is not None)
        or store._lifecycle_identity is not lifecycle
        or store._bound_verifier is not verifier
        or verifier._authority is not verifier_authority
        or verifier._authority.generation != verifier_generation
    ):
        raise HistoricalCoverageUnavailable(
            "historical replay broker authority is not strictly sealed"
        )
    if type(compact_records) not in {_ReplayLedger, tuple} or type(
        compact_prepared
    ) not in {_ReplayLedger, tuple}:
        raise HistoricalCoverageUnavailable(
            "historical replay compact containers are not exact"
        )
    records = tuple(compact_records)
    prepared_records = tuple(compact_prepared)
    if len(records) != len(prepared_records) or compact_count != len(records):
        raise HistoricalCoverageUnavailable(
            "historical replay compact closure changed"
        )
    entry_records: list[StoredEvidenceRecord] = []
    entry_prepared: list[_PreparedHistoricalRecord] = []
    for entry in entries:
        if (
            type(entry) is not _FrozenReplayEntry
            or type(entry.record) is not StoredEvidenceRecord
            or type(entry.record.ref) is not EvidenceRef
            or type(entry.prepared) is not _PreparedHistoricalRecord
            or type(entry.expected_primary) is not bool
            or type(entry.compact_member) is not bool
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay entry leaf changed"
            )
        entry_records.append(entry.record)
        entry_prepared.append(entry.prepared)
    if (
        not entries
        or entries[-1].record.ref is not terminal_ref
        or len(entries) != terminal_ref.source_sequence
        or tuple(_exact_coverage_record_key(record) for record in entry_records)
        != frozen_record_keys
        or any(
            type(item) is not tuple
            or len(item) != 2
            or any(type(boundary) is not int for boundary in item)
            for item in frozen_retired_ranges
        )
    ):
        raise HistoricalCoverageUnavailable(
            "historical replay frozen transcript changed"
        )
    running_digest = _initial_replay_compact_digest()
    for record, prepared in zip(records, prepared_records, strict=True):
        if (
            type(record) is not StoredEvidenceRecord
            or type(record.ref) is not EvidenceRef
            or type(prepared) is not _PreparedHistoricalRecord
            or type(prepared.fact) is not HistoricalCoverageRecord
            or type(prepared.envelope) is not EventEnvelopeV1
            or (prepared.coverage is not None and type(prepared.coverage) is not CoverageEventV1)
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay compact leaf changed"
            )
        running_digest = _advance_replay_compact_digest(running_digest, record)
    if not hmac.compare_digest(running_digest, compact_digest):
        raise HistoricalCoverageUnavailable(
            "historical replay compact digest changed"
        )
    pcc_leaves: list[_ReplayPCCLeaf] = []
    pcc_identities: list[
        tuple[
            _ReplayPCCLeaf,
            AuthenticatedPCCInput,
            object,
            object,
            EvidenceRef,
        ]
    ] = []
    for key, leaf in used_pcc.items():
        if key is not leaf.key or not pcc_leaf_is_current(leaf):
            raise HistoricalCoverageUnavailable(
                "historical replay PCC leaf changed"
        )
        pcc_leaves.append(leaf)
        pcc_identities.append(
            (
                leaf,
                leaf.pcc,
                leaf.request,
                leaf.snapshot,
                leaf.evidence_ref,
            )
        )
    memo_leaves: list[_ReplayMemoLeaf] = []
    memo_identities: list[
        tuple[_ReplayMemoLeaf, HistoricalCoverageAssessment]
    ] = []
    for key, memo_leaf in memo.items():
        if (
            key is not memo_leaf.key
            or not 0 <= memo_leaf.compact_count <= compact_count
            or not memo_leaf_is_current(memo_leaf)
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay memo leaf changed"
            )
        memo_leaves.append(memo_leaf)
        memo_identities.append((memo_leaf, memo_leaf.assessment))
    if tuple(used_pcc) != tuple(memo):
        raise HistoricalCoverageUnavailable(
            "historical replay leaf closure changed"
        )
    canonical_digest = _replay_fact_digest(
        _REPLAY_SEAL_HASH_DOMAIN,
        (
            state,
            version,
            creator_thread,
            terminal_ref,
            frozen_status,
            frozen_record_keys,
            frozen_retired_ranges,
            verifier_generation,
            projected_head,
            tuple(
                (
                    _exact_coverage_record_key(entry.record),
                    entry.prepared,
                    entry.expected_primary,
                    entry.compact_member,
                )
                for entry in entries
            ),
            compact_count,
            compact_digest,
            tuple(
                (_exact_coverage_record_key(record), prepared)
                for record, prepared in zip(records, prepared_records, strict=True)
            ),
            tuple((leaf.key, leaf.facts_digest) for leaf in pcc_leaves),
            tuple((leaf.key, leaf.facts_digest) for leaf in memo_leaves),
        ),
    )
    return _ReplayStateSeal(
        state=state,
        version=version,
        store=store,
        lifecycle=lifecycle,
        verifier=verifier,
        verifier_authority=verifier_authority,
        creator_thread=creator_thread,
        terminal_ref=terminal_ref,
        frozen_status=frozen_status,
        entries=entries,
        entry_records=tuple(entry_records),
        entry_prepared=tuple(entry_prepared),
        frozen_record_keys=frozen_record_keys,
        frozen_retired_ranges=frozen_retired_ranges,
        verifier_generation=verifier_generation,
        projected_head=projected_head,
        compact_container=compact_records,
        compact_prepared_container=compact_prepared,
        compact_records=records,
        compact_prepared=prepared_records,
        used_pcc_container=used_pcc,
        used_pcc=tuple(pcc_leaves),
        used_pcc_identities=tuple(pcc_identities),
        memo_container=memo,
        memos=tuple(memo_leaves),
        memo_identities=tuple(memo_identities),
        access=access,
        access_record=access_record,
        path_container=paths,
        paths=tuple(paths.items()),
        probe_ticket=probe_ticket,
        canonical_digest=canonical_digest,
    )


def _replay_broker_state_matches_seal(
    expected: _ReplayStateSeal,
    current: _ReplayStateSeal,
) -> bool:
    if type(expected) is not _ReplayStateSeal or type(current) is not _ReplayStateSeal:
        return False
    scalar_equal = (
        expected.state == current.state
        and expected.version == current.version
        and expected.creator_thread == current.creator_thread
        and expected.verifier_generation == current.verifier_generation
        and expected.projected_head == current.projected_head
    )
    identity_equal = (
        expected.store is current.store
        and expected.lifecycle is current.lifecycle
        and expected.verifier is current.verifier
        and expected.verifier_authority is current.verifier_authority
        and expected.terminal_ref is current.terminal_ref
        and expected.frozen_status is current.frozen_status
        and expected.entries is current.entries
        and expected.frozen_record_keys is current.frozen_record_keys
        and expected.frozen_retired_ranges is current.frozen_retired_ranges
        and expected.compact_container is current.compact_container
        and expected.compact_prepared_container is current.compact_prepared_container
        and expected.used_pcc_container is current.used_pcc_container
        and expected.memo_container is current.memo_container
        and expected.access is current.access
        and expected.access_record is current.access_record
        and expected.path_container is current.path_container
        and expected.probe_ticket is current.probe_ticket
    )
    identity_groups: tuple[tuple[tuple[object, ...], tuple[object, ...]], ...] = (
        (expected.entry_records, current.entry_records),
        (expected.entry_prepared, current.entry_prepared),
        (expected.compact_records, current.compact_records),
        (expected.compact_prepared, current.compact_prepared),
        (expected.used_pcc, current.used_pcc),
        (expected.memos, current.memos),
    )
    ordered_identities_equal = all(
        len(left) == len(right)
        and all(left_item is right_item for left_item, right_item in zip(left, right, strict=True))
        for left, right in identity_groups
    )
    path_identities_equal = len(expected.paths) == len(current.paths) and all(
        expected_path is current_path and expected_record is current_record
        for (expected_path, expected_record), (current_path, current_record) in zip(
            expected.paths,
            current.paths,
            strict=True,
        )
    )
    pcc_inner_identities_equal = (
        len(expected.used_pcc_identities) == len(current.used_pcc_identities)
        and all(
            all(
                expected_item is current_item
                for expected_item, current_item in zip(
                    expected_identity,
                    current_identity,
                    strict=True,
                )
            )
            for expected_identity, current_identity in zip(
                expected.used_pcc_identities,
                current.used_pcc_identities,
                strict=True,
            )
        )
    )
    memo_inner_identities_equal = (
        len(expected.memo_identities) == len(current.memo_identities)
        and all(
            expected_leaf is current_leaf
            and expected_assessment is current_assessment
            for (expected_leaf, expected_assessment), (
                current_leaf,
                current_assessment,
            ) in zip(
                expected.memo_identities,
                current.memo_identities,
                strict=True,
            )
        )
    )
    return (
        scalar_equal
        and identity_equal
        and ordered_identities_equal
        and path_identities_equal
        and pcc_inner_identities_equal
        and memo_inner_identities_equal
        and hmac.compare_digest(expected.canonical_digest, current.canonical_digest)
    )


_ACTIVE_REPLAY_MARKER: ContextVar[object | None] = ContextVar(
    "agmind_historical_replay_marker",
    default=None,
)
_REPLAY_RESERVATION_LOCK = RLock()
_REPLAY_STORE_RESERVATIONS: weakref.WeakKeyDictionary[SegmentStore, object] = (
    weakref.WeakKeyDictionary()
)
_REPLAY_STORE_GATES: weakref.WeakKeyDictionary[SegmentStore, RLock] = (
    weakref.WeakKeyDictionary()
)


def _store_replay_gate(store: SegmentStore) -> RLock:
    with _REPLAY_RESERVATION_LOCK:
        gate = _REPLAY_STORE_GATES.get(store)
        if gate is None:
            gate = RLock()
            _REPLAY_STORE_GATES[store] = gate
        return gate


def _replay_setup_checkpoint(stage: str) -> None:
    del stage


def _replay_path_cleanup_visit(path: HistoricalPathAuthority) -> None:
    del path


def _replay_probe_checkpoint(stage: str) -> None:
    del stage


def _replay_cleanup_checkpoint(stage: str) -> None:
    del stage


@contextmanager
def _replay_historical_session(
    store: SegmentStore,
    terminal_ref: EvidenceRef,
) -> Iterator[_ReplayHandle]:
    """Create one lexical replay broker with no enumerable session authority."""
    capture_broker_seal = _capture_replay_broker_seal
    broker_state_matches_seal = _replay_broker_state_matches_seal
    build_pcc_leaf = _build_replay_pcc_leaf
    build_memo_leaf = _build_replay_memo_leaf
    pcc_leaf_is_current = _replay_pcc_leaf_is_current
    memo_leaf_is_current = _replay_memo_leaf_is_current
    memo_leaf_semantics_match = _replay_memo_leaf_semantics_match
    reservation = object()
    activation_marker = object()
    context_token: object | None = None
    creator_thread: int | None = None
    cleanup_lock = RLock()
    cleanup_complete = False
    cleanup_errors: tuple[BaseException, ...] = ()
    primary: BaseException | None = None
    broker_dispatch: Callable[..., object] | None = None
    broker_revoke: Callable[[], None] = lambda: None
    handle: _ReplayHandle | None = None

    def remove_exact_reservation() -> None:
        gate = _store_replay_gate(store)
        with gate, _REPLAY_RESERVATION_LOCK:
            if _REPLAY_STORE_RESERVATIONS.get(store) is reservation:
                _REPLAY_STORE_RESERVATIONS.pop(store, None)

    def cleanup_scope() -> tuple[BaseException, ...]:
        nonlocal cleanup_complete, cleanup_errors, context_token
        with cleanup_lock:
            if cleanup_complete:
                return cleanup_errors
            errors: list[BaseException] = []
            try:
                broker_revoke()
                _replay_cleanup_checkpoint("broker-revoked")
            except BaseException as error:  # noqa: BLE001 - fail-safe cleanup
                errors.append(error)
            if context_token is not None:
                try:
                    _ACTIVE_REPLAY_MARKER.reset(context_token)  # type: ignore[arg-type]
                    _replay_cleanup_checkpoint("context-reset")
                except BaseException as error:  # noqa: BLE001 - fail-safe cleanup
                    errors.append(error)
                    try:
                        _ACTIVE_REPLAY_MARKER.set(None)
                    except BaseException as fallback_error:  # noqa: BLE001
                        errors.append(fallback_error)
                context_token = None
            try:
                remove_exact_reservation()
                _replay_cleanup_checkpoint("reservation-removed")
            except BaseException as error:  # noqa: BLE001 - fail-safe cleanup
                errors.append(error)
                try:
                    with _REPLAY_RESERVATION_LOCK:
                        if _REPLAY_STORE_RESERVATIONS.get(store) is reservation:
                            _REPLAY_STORE_RESERVATIONS.pop(store, None)
                except BaseException as fallback_error:  # noqa: BLE001
                    errors.append(fallback_error)
            cleanup_errors = tuple(errors)
            cleanup_complete = True
            return cleanup_errors

    def handle_dispatch(
        caller: _ReplayHandle,
        operation: str,
        *arguments: object,
    ) -> object:
        if operation == "close_scope":
            if caller is not handle:
                raise HistoricalCoverageUnavailable(
                    "historical replay handle close is outside its lexical context"
                )
            if cleanup_complete:
                if cleanup_errors:
                    raise BaseExceptionGroup(
                        "historical replay cleanup failed",
                        list(cleanup_errors),
                    )
                return None
            if (
                creator_thread is None
                or get_ident() != creator_thread
                or _ACTIVE_REPLAY_MARKER.get() is not activation_marker
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay handle close is outside its lexical context"
                )
            errors = cleanup_scope()
            if errors:
                raise BaseExceptionGroup("historical replay cleanup failed", errors)
            return None
        dispatch = broker_dispatch
        if dispatch is None:
            raise HistoricalCoverageUnavailable(
                "historical replay handle is dormant or revoked"
            )
        return dispatch(caller, operation, *arguments)

    try:
        handle = object.__new__(_ReplayHandle)
        object.__setattr__(handle, "_ReplayHandle__dispatch", handle_dispatch)
        _replay_setup_checkpoint("handle-created")
        if _ACTIVE_REPLAY_MARKER.get() is not None:
            raise HistoricalCoverageUnavailable(
                "nested historical replay sessions are forbidden"
            )
        gate = _store_replay_gate(store)
        with gate, _REPLAY_RESERVATION_LOCK:
            if store in _REPLAY_STORE_RESERVATIONS:
                raise HistoricalCoverageUnavailable(
                    "historical replay store already has an active session"
                )
            _REPLAY_STORE_RESERVATIONS[store] = reservation
        _replay_setup_checkpoint("store-reserved")
        if type(store) is not SegmentStore or type(terminal_ref) is not EvidenceRef:
            raise HistoricalCoverageUnavailable(
                "historical replay broker requires exact source authority"
            )
        supplied_terminal_ref = terminal_ref
        try:
            terminal_record = store.resolve_authenticated_ref(
                supplied_terminal_ref
            )
        except EvidenceStoreError as error:
            raise HistoricalCoverageUnavailable(
                "historical replay terminal is not authenticated"
            ) from error
        if (
            type(terminal_record) is not StoredEvidenceRecord
            or type(terminal_record.ref) is not EvidenceRef
            or terminal_record.ref != supplied_terminal_ref
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay terminal binding changed"
            )
        terminal_ref = terminal_record.ref
        status_before = store.status()
        verifier = store._bound_verifier
        lifecycle = store._lifecycle_identity
        if (
            not status_before.healthy
            or status_before.repair_pending
            or status_before.retention_pending
            or verifier is None
            or not store._is_bound_verifier(verifier)
            or status_before.evidence_head != terminal_ref.source_sequence
            or status_before.acceptance_cursor != terminal_ref.source_sequence
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay source is not exact, terminal, and healthy"
            )
        try:
            frozen_records = tuple(
                store.iter_authenticated_records(
                    after=0,
                    through=terminal_ref.source_sequence,
                )
            )
            frozen_prepared = tuple(
                _prepare_historical_record(record) for record in frozen_records
            )
        except (EvidenceStoreError, TypeError, ValueError) as error:
            raise HistoricalCoverageUnavailable(
                "historical replay source could not be frozen"
            ) from error
        status_after = store.status()
        if (
            status_after != status_before
            or store._lifecycle_identity is not lifecycle
            or store._bound_verifier is not verifier
            or verifier._authority.generation != store.verifier_generation
            or not frozen_records
            or frozen_records[-1].ref is not terminal_ref
            or len(frozen_records) != terminal_ref.source_sequence
            or any(
                record.ref.source_sequence != index
                for index, record in enumerate(frozen_records, start=1)
            )
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay frozen source transcript changed"
            )
        entries = _build_frozen_replay_entries(frozen_records, frozen_prepared)
        creator_thread = get_ident()
        verifier_authority = verifier._authority
        verifier_generation = verifier_authority.generation
        frozen_status = status_before
        frozen_record_keys = tuple(
            _exact_coverage_record_key(record) for record in frozen_records
        )
        frozen_retired_ranges = tuple(store._authenticated_retired_ranges)
        state = "PROJECTING"
        version = 0
        projected_head = 0
        compact_records: Sequence[StoredEvidenceRecord] = _ReplayLedger()
        compact_prepared: Sequence[_PreparedHistoricalRecord] = _ReplayLedger()
        compact_count = 0
        compact_digest = _initial_replay_compact_digest()
        used_pcc: dict[tuple[str, str], _ReplayPCCLeaf] = {}
        memo: dict[tuple[str, str], _ReplayMemoLeaf] = {}
        pending_event: _ReplayEventToken | None = None
        current_access: _ReplayAccess | None = None
        current_access_record: _ReplayAccessRecord | None = None
        paths: dict[HistoricalPathAuthority, _ReplayPathRecord] = {}
        expected_seal: _ReplayStateSeal | None = None
        probe_ticket: object | None = None
        broker_live = True
        broker_lock = RLock()
        _replay_setup_checkpoint("broker-created")

        def source_authority_is_exact() -> bool:
            try:
                status = store.status()
                return (
                    type(status) is EvidenceStatus
                    and status == frozen_status
                    and store._lifecycle_identity is lifecycle
                    and store._bound_verifier is verifier
                    and verifier._authority is verifier_authority
                    and verifier._authority.generation == verifier_generation
                    and store._is_bound_verifier(verifier)
                )
            except (AttributeError, EvidenceStoreError, TypeError, ValueError):
                return False

        def require_broker_context() -> None:
            if (
                not broker_live
                or _ACTIVE_REPLAY_MARKER.get() is not activation_marker
                or get_ident() != creator_thread
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay broker is not live in its lexical context"
                )

        def require_source_authority() -> None:
            if not source_authority_is_exact():
                raise HistoricalCoverageUnavailable(
                    "historical replay frozen source authority changed"
                )

        def revoke_current_access() -> None:
            nonlocal current_access, current_access_record
            revoked_paths = tuple(paths)
            paths.clear()
            current_access = None
            current_access_record = None
            errors: list[BaseException] = []
            for revoked_path in revoked_paths:
                try:
                    _replay_path_cleanup_visit(revoked_path)
                except BaseException as error:  # noqa: BLE001 - complete revocation
                    errors.append(error)
            if errors:
                raise BaseExceptionGroup(
                    "historical replay path cleanup failed",
                    errors,
                )

        def capture_seal() -> _ReplayStateSeal:
            return capture_broker_seal(
                state=state,
                version=version,
                store=store,
                lifecycle=lifecycle,
                verifier=verifier,
                verifier_authority=verifier_authority,
                creator_thread=creator_thread,
                terminal_ref=terminal_ref,
                frozen_status=frozen_status,
                entries=entries,
                frozen_record_keys=frozen_record_keys,
                frozen_retired_ranges=frozen_retired_ranges,
                verifier_generation=verifier_generation,
                projected_head=projected_head,
                compact_records=compact_records,
                compact_prepared=compact_prepared,
                compact_count=compact_count,
                compact_digest=compact_digest,
                used_pcc=used_pcc,
                memo=memo,
                access=current_access,
                access_record=current_access_record,
                paths=paths,
                probe_ticket=probe_ticket,
                pcc_leaf_is_current=pcc_leaf_is_current,
                memo_leaf_is_current=memo_leaf_is_current,
            )

        def validate_event_token(
            token: _ReplayEventToken,
            ref: EvidenceRef,
        ) -> None:
            require_broker_context()
            require_source_authority()
            if (
                state != "EVENT_OPEN"
                or type(token) is not _ReplayEventToken
                or token._state not in {"issued", "observed"}
                or pending_event is not token
                or token._entry_index != projected_head
                or type(ref) is not EvidenceRef
                or entries[token._entry_index].record.ref is not ref
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay event token is not exact and pending"
                )

        def require_access(
            access: _ReplayAccess,
            authenticated: AuthenticatedPCCInput,
        ) -> _ReplayAccessRecord:
            require_broker_context()
            record = current_access_record
            if (
                state in {"VALIDATION_PROBING", "FINAL_PROBING", "SEALED", "REVOKED"}
                or type(access) is not _ReplayAccess
                or access is not current_access
                or record is None
                or record.pcc is not authenticated
                or record.phase != state
                or (
                    state == "EVENT_OPEN"
                    and (
                        record.event_token is not pending_event
                        or record.event_token is None
                        or record.event_token._state not in {"issued", "observed"}
                    )
                )
                or (state == "VALIDATING" and record.event_token is not None)
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay access was revoked or substituted"
                )
            return record

        def issue_path_record(
            authenticated: AuthenticatedPCCInput,
        ) -> _ReplayPathRecord:
            nonlocal used_pcc
            require_source_authority()
            if not store._authenticated_pcc_input_is_exact(authenticated):
                raise HistoricalCoverageUnavailable(
                    "historical replay PCC is not exact at the projected head"
                )
            key = (authenticated.event_id, authenticated.content_sha256)
            used = used_pcc.get(key)
            if used is None:
                if state != "EVENT_OPEN":
                    raise HistoricalCoverageUnavailable(
                        "validating replay cannot add a PCC binding"
                    )
                used = build_pcc_leaf(key, authenticated)
                used_pcc[key] = used
            elif used.pcc is not authenticated or not _replay_pcc_leaf_is_current(used):
                raise HistoricalCoverageUnavailable(
                    "historical replay PCC binding changed"
                )
            cached = memo.get(key)
            if cached is not None:
                selected_count = cached.compact_count
                selected_digest = cached.compact_digest
            elif (
                state == "EVENT_OPEN"
                and authenticated.source_sequence == projected_head + 1
                and authenticated.snapshot.coverage_through_sequence == projected_head
                and pending_event is not None
                and pending_event._entry_index == projected_head
                and pending_event._state in {"issued", "observed"}
            ):
                selected_count = compact_count
                selected_digest = compact_digest
            else:
                raise HistoricalCoverageUnavailable(
                    "historical replay PCC is not exact at the projected head"
                )
            return _ReplayPathRecord(
                pcc=authenticated,
                compact_records=_BoundedView(compact_records, selected_count),
                compact_prepared=_BoundedView(compact_prepared, selected_count),
                compact_count=selected_count,
                compact_digest=selected_digest,
                event_token=pending_event,
                phase=state,
            )

        def validate_path_record(binding: _ReplayPathRecord) -> None:
            require_source_authority()
            authenticated = binding.pcc
            key = (authenticated.event_id, authenticated.content_sha256)
            used = used_pcc.get(key)
            cached = memo.get(key)
            if cached is None:
                exact_compact = (
                    binding.compact_count == compact_count
                    and binding.compact_digest == compact_digest
                    and binding.compact_count == len(binding.compact_records)
                )
            else:
                exact_compact = (
                    binding.compact_records.ledger is compact_records
                    and binding.compact_prepared.ledger is compact_prepared
                    and binding.compact_count == cached.compact_count
                    and binding.compact_digest == cached.compact_digest
                )
            exact_phase = (
                binding.phase == "EVENT_OPEN"
                and state == "EVENT_OPEN"
                and binding.event_token is pending_event
                and binding.event_token is not None
                and binding.event_token._state in {"issued", "observed"}
            ) or (
                binding.phase == "VALIDATING"
                and state == "VALIDATING"
                and binding.event_token is None
            )
            if (
                used is None
                or used.pcc is not authenticated
                or not _replay_pcc_leaf_is_current(used)
                or not store._authenticated_pcc_input_is_exact(authenticated)
                or not exact_compact
                or not exact_phase
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay path binding changed"
                )

        def reduce_path_record(
            binding: _ReplayPathRecord,
        ) -> HistoricalCoverageAssessment:
            authenticated = binding.pcc
            key = (authenticated.event_id, authenticated.content_sha256)
            cached = memo.get(key)
            if cached is not None:
                return cached.assessment
            if state != "EVENT_OPEN":
                raise HistoricalCoverageUnavailable(
                    "validating replay cannot add a historical memo"
                )
            trigger = authenticated.snapshot.trigger
            selected_records = binding.compact_records
            reduction = _reduce_historical_coverage_result(
                tuple(selected_records),
                host_id=authenticated.host_id,
                boot_id=authenticated.boot_id,
                trigger_event_id=trigger.event_id,
                trigger_source_sequence=trigger.source_sequence,
                trigger_event_time=trigger.event_time,
                clock_uncertainty_ms=trigger.clock_uncertainty_ms,
                coverage_through_sequence=(
                    authenticated.snapshot.coverage_through_sequence
                ),
                window_end=authenticated.snapshot.decision_time,
            )
            leaf = build_memo_leaf(
                key,
                reduction,
                binding.compact_count,
                binding.compact_digest,
            )
            if leaf.assessment is not reduction.timeline.assessment:
                raise HistoricalCoverageUnavailable(
                    "historical replay reducer leaf assessment changed"
                )
            memo[key] = leaf
            return leaf.assessment

        def run_independent_validation(
            used_snapshot: tuple[_ReplayPCCLeaf, ...],
            memo_snapshot: tuple[_ReplayMemoLeaf, ...],
        ) -> tuple[
            tuple[StoredEvidenceRecord, ...],
            tuple[_PreparedHistoricalRecord, ...],
        ]:
            _replay_probe_checkpoint("validation-before-source")
            rebuilt_records = tuple(
                store.iter_authenticated_records(
                    after=0,
                    through=terminal_ref.source_sequence,
                )
            )
            rebuilt_prepared = tuple(
                _prepare_historical_record(record) for record in rebuilt_records
            )
            rebuilt_entries = _build_frozen_replay_entries(
                rebuilt_records,
                rebuilt_prepared,
            )
            if (
                len(rebuilt_entries) != len(entries)
                or not rebuilt_entries
                or rebuilt_entries[-1].record.ref != terminal_ref
                or any(
                    _replay_fact_digest(
                        _REPLAY_SEAL_HASH_DOMAIN,
                        (
                            _exact_coverage_record_key(rebuilt.record),
                            rebuilt.prepared,
                            rebuilt.expected_primary,
                            rebuilt.compact_member,
                        ),
                    )
                    != _replay_fact_digest(
                        _REPLAY_SEAL_HASH_DOMAIN,
                        (
                            _exact_coverage_record_key(frozen.record),
                            frozen.prepared,
                            frozen.expected_primary,
                            frozen.compact_member,
                        ),
                    )
                    for rebuilt, frozen in zip(
                        rebuilt_entries,
                        entries,
                        strict=True,
                    )
                )
                or tuple(store._authenticated_retired_ranges)
                != frozen_retired_ranges
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay independent source rebuild changed"
                )
            rebuilt_compact_records: list[StoredEvidenceRecord] = []
            rebuilt_compact_prepared: list[_PreparedHistoricalRecord] = []
            rebuilt_prefix_digests = [_initial_replay_compact_digest()]
            for entry in rebuilt_entries:
                if not entry.compact_member:
                    continue
                rebuilt_compact_records.append(entry.record)
                rebuilt_compact_prepared.append(entry.prepared)
                rebuilt_prefix_digests.append(
                    _update_replay_compact_digest(
                        rebuilt_prefix_digests[-1],
                        entry.record,
                    )
                )
            if (
                len(rebuilt_compact_records) != compact_count
                or not hmac.compare_digest(
                    rebuilt_prefix_digests[-1],
                    compact_digest,
                )
                or any(
                    _exact_coverage_record_key(rebuilt)
                    != _exact_coverage_record_key(accumulated)
                    for rebuilt, accumulated in zip(
                        rebuilt_compact_records,
                        compact_records,
                        strict=True,
                    )
                )
                or len(used_snapshot) != len(memo_snapshot)
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay accumulated compact transcript changed"
                )
            memo_by_key = {leaf.key: leaf for leaf in memo_snapshot}
            if tuple(leaf.key for leaf in used_snapshot) != tuple(memo_by_key):
                raise HistoricalCoverageUnavailable(
                    "historical replay validation leaf closure changed"
                )
            for pcc_leaf in used_snapshot:
                cached = memo_by_key[pcc_leaf.key]
                fresh = store._authenticated_pcc_input(
                    verifier,
                    pcc_leaf.evidence_ref,
                    pcc_leaf.request,
                )
                fresh_pcc_leaf = build_pcc_leaf(pcc_leaf.key, fresh)
                if not hmac.compare_digest(
                    fresh_pcc_leaf.facts_digest,
                    pcc_leaf.facts_digest,
                ):
                    raise HistoricalCoverageUnavailable(
                        "historical replay PCC changed during final rebuild"
                    )
                coverage_through = fresh.snapshot.coverage_through_sequence
                selected_count = cached.compact_count
                _validate_replay_compact_boundary(
                    rebuilt_compact_records,
                    rebuilt_prefix_digests,
                    selected_count=selected_count,
                    coverage_through=coverage_through,
                    expected_digest=cached.compact_digest,
                )
                selected_records = _BoundedView(
                    rebuilt_compact_records,
                    selected_count,
                )
                trigger = fresh.snapshot.trigger
                reduction = _reduce_historical_coverage_result(
                    tuple(selected_records),
                    host_id=fresh.host_id,
                    boot_id=fresh.boot_id,
                    trigger_event_id=trigger.event_id,
                    trigger_source_sequence=trigger.source_sequence,
                    trigger_event_time=trigger.event_time,
                    clock_uncertainty_ms=trigger.clock_uncertainty_ms,
                    coverage_through_sequence=coverage_through,
                    window_end=fresh.snapshot.decision_time,
                )
                rebuilt_leaf = build_memo_leaf(
                    cached.key,
                    reduction,
                    selected_count,
                    cached.compact_digest,
                )
                if rebuilt_leaf.assessment is not reduction.timeline.assessment:
                    raise HistoricalCoverageUnavailable(
                        "historical replay validation leaf assessment changed"
                    )
                if not memo_leaf_semantics_match(cached, rebuilt_leaf):
                    raise HistoricalCoverageUnavailable(
                        "historical replay memo changed in final rebuild"
                    )
            _replay_probe_checkpoint("validation-after-source")
            return tuple(rebuilt_compact_records), tuple(rebuilt_compact_prepared)

        def run_validation_probe(caller: _ReplayHandle) -> None:
            nonlocal state, version, compact_records, compact_prepared
            nonlocal expected_seal, probe_ticket
            with broker_lock:
                require_broker_context()
                require_source_authority()
                if (
                    caller is not handle
                    or state != "PROJECTING"
                    or pending_event is not None
                    or projected_head != terminal_ref.source_sequence
                    or probe_ticket is not None
                ):
                    raise HistoricalCoverageUnavailable(
                        "historical replay validation probe is out of phase"
                    )
                revoke_current_access()
                state = "VALIDATION_PROBING"
                version += 1
                ticket = object()
                probe_ticket = ticket
                expected_version = version
                probe_expectation = capture_seal()
                used_snapshot = tuple(used_pcc.values())
                memo_snapshot = tuple(memo.values())
            try:
                rebuilt_records, rebuilt_prepared = run_independent_validation(
                    used_snapshot,
                    memo_snapshot,
                )
            except BaseException:
                with broker_lock:
                    if probe_ticket is ticket:
                        probe_ticket = None
                        version += 1
                        state = "REVOKED"
                raise
            with broker_lock:
                if (
                    not broker_live
                    or caller is not handle
                    or state != "VALIDATION_PROBING"
                    or probe_ticket is not ticket
                    or version != expected_version
                    or not source_authority_is_exact()
                    or not broker_state_matches_seal(
                        probe_expectation,
                        capture_seal(),
                    )
                    or len(rebuilt_records) != compact_count
                    or len(rebuilt_prepared) != compact_count
                ):
                    if probe_ticket is ticket:
                        probe_ticket = None
                    version += 1
                    state = "REVOKED"
                    raise HistoricalCoverageUnavailable(
                        "historical replay validation probe became stale"
                    )
                compact_records = tuple(compact_records)
                compact_prepared = tuple(compact_prepared)
                probe_ticket = None
                version += 1
                state = "VALIDATING"
                expected_seal = capture_seal()

        def validate_final_transcript() -> None:
            _replay_probe_checkpoint("final-before-source")
            try:
                record_keys = tuple(
                    _exact_coverage_record_key(record)
                    for record in store.iter_authenticated_records(
                        after=0,
                        through=terminal_ref.source_sequence,
                    )
                )
                resolved_keys = tuple(
                    _exact_coverage_record_key(
                        store.resolve_authenticated_ref(entry.record.ref)
                    )
                    for entry in entries
                )
                resident_keys = tuple(
                    _exact_coverage_record_key(record) for record in store._records
                )
                retired_ranges = tuple(store._authenticated_retired_ranges)
            except (EvidenceStoreError, TypeError, ValueError) as error:
                raise HistoricalCoverageUnavailable(
                    "historical replay final transcript is unavailable"
                ) from error
            if (
                record_keys != frozen_record_keys
                or resolved_keys != frozen_record_keys
                or resident_keys != frozen_record_keys
                or retired_ranges != frozen_retired_ranges
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay final transcript changed"
                )
            _replay_probe_checkpoint("final-after-source")

        def run_final_probe(
            caller: _ReplayHandle,
            authority_check: Callable[[], None],
        ) -> None:
            nonlocal state, version, expected_seal, probe_ticket
            if not callable(authority_check):
                raise HistoricalCoverageUnavailable(
                    "historical replay final callback is invalid"
                )
            with broker_lock:
                require_broker_context()
                require_source_authority()
                if caller is handle and state == "VALIDATING":
                    revoke_current_access()
                if (
                    caller is not handle
                    or state != "VALIDATING"
                    or expected_seal is None
                    or probe_ticket is not None
                    or not broker_state_matches_seal(
                        expected_seal,
                        capture_seal(),
                    )
                ):
                    raise HistoricalCoverageUnavailable(
                        "historical replay final probe is out of phase"
                    )
                state = "FINAL_PROBING"
                version += 1
                ticket = object()
                probe_ticket = ticket
                expected_version = version
                probe_expectation = capture_seal()
            try:
                validate_final_transcript()
                authority_check()
            except BaseException:
                with broker_lock:
                    if probe_ticket is ticket:
                        probe_ticket = None
                        version += 1
                        state = "REVOKED"
                raise
            with broker_lock:
                if (
                    not broker_live
                    or caller is not handle
                    or state != "FINAL_PROBING"
                    or probe_ticket is not ticket
                    or version != expected_version
                    or not source_authority_is_exact()
                    or not broker_state_matches_seal(
                        probe_expectation,
                        capture_seal(),
                    )
                ):
                    if probe_ticket is ticket:
                        probe_ticket = None
                    version += 1
                    state = "REVOKED"
                    raise HistoricalCoverageUnavailable(
                        "historical replay final probe became stale"
                    )
                probe_ticket = None
                expected_seal = None
                version += 1
                state = "SEALED"

        def access_dispatch(
            access: _ReplayAccess,
            operation: str,
            *arguments: object,
        ) -> object:
            with broker_lock:
                if operation == "close":
                    if access is current_access:
                        revoke_current_access()
                    return None
                if operation == "issue_path":
                    if len(arguments) != 2:
                        raise HistoricalCoverageUnavailable(
                            "historical replay issue arguments changed"
                        )
                    requested_store, authenticated = arguments
                    if type(authenticated) is not AuthenticatedPCCInput:
                        raise HistoricalCoverageUnavailable(
                            "historical replay issue PCC type changed"
                        )
                    require_access(access, authenticated)
                    if requested_store is not store:
                        raise HistoricalCoverageUnavailable(
                            "historical replay issue store changed"
                        )
                    issued_record = issue_path_record(authenticated)
                    path = HistoricalPathAuthority(
                        store,
                        _ReplayPathBinding(),
                        _factory=_PATH_FACTORY,
                    )
                    paths[path] = issued_record
                    return path
                if operation == "derive":
                    if len(arguments) != 2:
                        raise HistoricalCoverageUnavailable(
                            "historical replay derive arguments changed"
                        )
                    authenticated_value, path_value = arguments
                    if (
                        type(authenticated_value) is not AuthenticatedPCCInput
                        or type(path_value) is not HistoricalPathAuthority
                    ):
                        raise HistoricalCoverageUnavailable(
                            "historical replay derive types changed"
                        )
                    authenticated = authenticated_value
                    path = path_value
                    require_access(access, authenticated)
                    path_record = paths.get(path)
                    if (
                        path_record is None
                        or path._store_ref() is not store
                        or type(path._binding) is not _ReplayPathBinding
                        or path_record.pcc is not authenticated
                    ):
                        raise HistoricalCoverageUnavailable(
                            "historical replay path was revoked or substituted"
                        )
                    validate_path_record(path_record)
                    assessment = reduce_path_record(path_record)
                    if paths.get(path) is not path_record:
                        raise HistoricalCoverageUnavailable(
                            "historical replay path changed during reduction"
                        )
                    validate_path_record(path_record)
                    return assessment
                raise HistoricalCoverageUnavailable(
                    "historical replay access operation is invalid"
                )

        def dispatch(
            caller: _ReplayHandle,
            operation: str,
            *arguments: object,
        ) -> object:
            nonlocal state, version, projected_head, compact_count
            nonlocal compact_digest, pending_event, current_access
            nonlocal current_access_record
            if operation == "begin_validation":
                run_validation_probe(caller)
                return None
            if operation == "final_probe":
                if len(arguments) != 1:
                    raise HistoricalCoverageUnavailable(
                        "historical replay final probe arguments changed"
                    )
                run_final_probe(caller, cast(Callable[[], None], arguments[0]))
                return None
            with broker_lock:
                require_broker_context()
                if caller is not handle:
                    raise HistoricalCoverageUnavailable(
                        "historical replay handle was substituted"
                    )
                if state in {"VALIDATION_PROBING", "FINAL_PROBING", "SEALED", "REVOKED"}:
                    raise HistoricalCoverageUnavailable(
                        "historical replay operation is out of phase"
                    )
                if operation == "open_access":
                    if len(arguments) != 1 or type(arguments[0]) is not AuthenticatedPCCInput:
                        raise HistoricalCoverageUnavailable(
                            "historical replay access PCC type changed"
                        )
                    authenticated = arguments[0]
                    require_source_authority()
                    if not store._authenticated_pcc_input_is_exact(authenticated):
                        raise HistoricalCoverageUnavailable(
                            "historical replay access requires an exact PCC"
                        )
                    key = (authenticated.event_id, authenticated.content_sha256)
                    event_token: _ReplayEventToken | None
                    if state == "EVENT_OPEN":
                        event_token = pending_event
                        used = used_pcc.get(key)
                        if (
                            event_token is None
                            or event_token._state not in {"issued", "observed"}
                            or authenticated.source_sequence != projected_head + 1
                            or (used is not None and used.pcc is not authenticated)
                        ):
                            raise HistoricalCoverageUnavailable(
                                "projecting replay access is outside its exact event"
                            )
                    elif state == "VALIDATING":
                        event_token = None
                        used = used_pcc.get(key)
                        if (
                            used is None
                            or used.pcc is not authenticated
                            or key not in memo
                        ):
                            raise HistoricalCoverageUnavailable(
                                "validation replay access lacks a sealed memo"
                            )
                    else:
                        raise HistoricalCoverageUnavailable(
                            "historical replay access is out of phase"
                        )
                    revoke_current_access()
                    issued = object.__new__(_ReplayAccess)
                    object.__setattr__(issued, "_ReplayAccess__dispatch", access_dispatch)
                    current_access = issued
                    current_access_record = _ReplayAccessRecord(
                        authenticated,
                        state,
                        event_token,
                    )
                    return issued
                if operation == "begin_event":
                    require_source_authority()
                    revoke_current_access()
                    if (
                        state != "PROJECTING"
                        or pending_event is not None
                        or len(arguments) != 1
                        or type(arguments[0]) is not EvidenceRef
                    ):
                        raise HistoricalCoverageUnavailable(
                            "historical replay event is out of phase"
                        )
                    ref = arguments[0]
                    if (
                        ref.source_sequence != projected_head + 1
                        or entries[projected_head].record.ref is not ref
                    ):
                        raise HistoricalCoverageUnavailable(
                            "historical replay event is not the exact frozen next entry"
                        )
                    token = object.__new__(_ReplayEventToken)
                    object.__setattr__(token, "_entry_index", projected_head)
                    object.__setattr__(token, "_state", "issued")
                    pending_event = token
                    state = "EVENT_OPEN"
                    version += 1
                    return token
                if operation == "validate_event":
                    if len(arguments) != 2:
                        raise HistoricalCoverageUnavailable(
                            "historical replay event validation arguments changed"
                        )
                    validate_event_token(
                        cast(_ReplayEventToken, arguments[0]),
                        cast(EvidenceRef, arguments[1]),
                    )
                    return None
                if operation == "compare_primary":
                    if len(arguments) != 3:
                        raise HistoricalCoverageUnavailable(
                            "historical replay primary arguments changed"
                        )
                    token = cast(_ReplayEventToken, arguments[0])
                    ref = cast(EvidenceRef, arguments[1])
                    observed_primary = arguments[2]
                    validate_event_token(token, ref)
                    entry = entries[token._entry_index]
                    if (
                        type(observed_primary) is not bool
                        or observed_primary is not entry.expected_primary
                    ):
                        state = "REVOKED"
                        version += 1
                        raise HistoricalCoverageConflict(
                            "projection primary differs from frozen replay authority"
                        )
                    object.__setattr__(token, "_state", "observed")
                    return None
                if operation == "begin_commit":
                    if len(arguments) != 2:
                        raise HistoricalCoverageUnavailable(
                            "historical replay commit arguments changed"
                        )
                    token = cast(_ReplayEventToken, arguments[0])
                    ref = cast(EvidenceRef, arguments[1])
                    validate_event_token(token, ref)
                    if token._state != "observed":
                        raise HistoricalCoverageUnavailable(
                            "historical replay event lacks primary equality"
                        )
                    revoke_current_access()
                    object.__setattr__(token, "_state", "committing")
                    state = "COMMITTING"
                    version += 1
                    return None
                if operation == "complete_event":
                    if len(arguments) != 1:
                        raise HistoricalCoverageUnavailable(
                            "historical replay completion arguments changed"
                        )
                    token = cast(_ReplayEventToken, arguments[0])
                    if (
                        state != "COMMITTING"
                        or type(token) is not _ReplayEventToken
                        or token._state != "committing"
                        or pending_event is not token
                        or token._entry_index != projected_head
                        or not source_authority_is_exact()
                    ):
                        state = "REVOKED"
                        version += 1
                        raise HistoricalCoverageUnavailable(
                            "historical replay committing event cannot complete"
                        )
                    entry = entries[token._entry_index]
                    if entry.compact_member:
                        if (
                            type(compact_records) is not _ReplayLedger
                            or type(compact_prepared) is not _ReplayLedger
                        ):
                            state = "REVOKED"
                            version += 1
                            raise HistoricalCoverageUnavailable(
                                "historical replay compact ledger was sealed early"
                            )
                        compact_records.append(entry.record)
                        compact_prepared.append(entry.prepared)
                        compact_count += 1
                        compact_digest = _update_replay_compact_digest(
                            compact_digest,
                            entry.record,
                        )
                    projected_head = entry.record.ref.source_sequence
                    object.__setattr__(token, "_state", "completed")
                    pending_event = None
                    state = "PROJECTING"
                    version += 1
                    return None
                raise HistoricalCoverageUnavailable(
                    "historical replay handle operation is invalid"
                )

        def revoke_broker() -> None:
            nonlocal broker_live, broker_dispatch, state, version
            nonlocal compact_records, compact_prepared, compact_count
            nonlocal compact_digest, pending_event, expected_seal, probe_ticket
            errors: list[BaseException] = []
            with broker_lock:
                if not broker_live:
                    return
                broker_live = False
                broker_dispatch = None
                state = "REVOKED"
                version += 1
                probe_ticket = None
                expected_seal = None
                try:
                    revoke_current_access()
                except BaseException as error:  # noqa: BLE001 - complete cleanup
                    errors.append(error)
                if type(pending_event) is _ReplayEventToken:
                    object.__setattr__(pending_event, "_state", "revoked")
                pending_event = None
                used_pcc.clear()
                memo.clear()
                if type(compact_records) is _ReplayLedger:
                    compact_records.clear()
                if type(compact_prepared) is _ReplayLedger:
                    compact_prepared.clear()
                compact_records = ()
                compact_prepared = ()
                compact_count = 0
                compact_digest = _initial_replay_compact_digest()
            if errors:
                raise BaseExceptionGroup(
                    "historical replay broker revocation failed",
                    errors,
                )

        broker_dispatch = dispatch
        broker_revoke = revoke_broker
        context_token = _ACTIVE_REPLAY_MARKER.set(activation_marker)
        _replay_setup_checkpoint("context-set")
        _replay_setup_checkpoint("before-handle-yield")
        yield handle
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = cleanup_scope()
        if errors:
            if primary is not None:
                for cleanup_error in errors:
                    primary.add_note(
                        "historical replay cleanup failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            else:
                raise BaseExceptionGroup(
                    "historical replay cleanup failed",
                    errors,
                )


def _open_replay_historical_access(
    handle: _ReplayHandle,
    authenticated: AuthenticatedPCCInput,
) -> _ReplayAccess:
    if type(handle) is not _ReplayHandle:
        raise HistoricalCoverageUnavailable(
            "historical replay handle is not issued and live"
        )
    access = handle._invoke("open_access", authenticated)
    if type(access) is not _ReplayAccess:
        raise HistoricalCoverageUnavailable(
            "historical replay broker returned an invalid access"
        )
    return access


def _close_replay_historical_access(access: _ReplayAccess | None) -> None:
    if access is None:
        return
    if type(access) is _ReplayAccess:
        access._invoke("close")


def _begin_replay_historical_event(
    handle: _ReplayHandle,
    ref: EvidenceRef,
) -> _ReplayEventToken:
    token = handle._invoke("begin_event", ref)
    if type(token) is not _ReplayEventToken:
        raise HistoricalCoverageUnavailable(
            "historical replay broker returned an invalid event token"
        )
    return token


def _validate_replay_historical_event(
    handle: _ReplayHandle,
    token: object,
    ref: EvidenceRef,
) -> None:
    if type(token) is not _ReplayEventToken:
        raise HistoricalCoverageUnavailable(
            "historical replay requires an exact event token"
        )
    handle._invoke("validate_event", token, ref)


def _compare_replay_historical_primary(
    handle: _ReplayHandle,
    token: object,
    ref: EvidenceRef,
    observed_primary: bool,
) -> None:
    if type(token) is not _ReplayEventToken:
        raise HistoricalCoverageUnavailable(
            "historical replay requires an exact event token"
        )
    handle._invoke("compare_primary", token, ref, observed_primary)


def _begin_replay_historical_commit(
    handle: _ReplayHandle,
    token: object,
    ref: EvidenceRef,
) -> None:
    if type(token) is not _ReplayEventToken:
        raise HistoricalCoverageUnavailable(
            "historical replay requires an exact event token"
        )
    handle._invoke("begin_commit", token, ref)


def _complete_replay_historical_event(
    handle: _ReplayHandle,
    token: object,
) -> None:
    if type(token) is not _ReplayEventToken:
        raise HistoricalCoverageUnavailable(
            "historical replay requires an exact event token"
        )
    handle._invoke("complete_event", token)


def _begin_replay_historical_validation(
    handle: _ReplayHandle,
) -> None:
    handle._invoke("begin_validation")


def _final_seal_replay_historical_session(
    handle: _ReplayHandle,
    authority_check: Callable[[], None],
) -> None:
    handle._invoke("final_probe", authority_check)


def _complete_replay_historical_session(
    handle: _ReplayHandle,
) -> None:
    handle._invoke("close_scope")


@final
class HistoricalPathAuthority:
    """Opaque capability for one store's exact authenticated PCC path."""

    __slots__ = ("__weakref__", "_binding", "_store_ref")
    _binding: _PathBinding | _ReplayPathBinding
    _store_ref: weakref.ReferenceType[SegmentStore]

    def __init__(
        self,
        store: SegmentStore,
        binding: _PathBinding | _ReplayPathBinding,
        *,
        _factory: object,
    ) -> None:
        if _factory is not _PATH_FACTORY:
            raise TypeError("HistoricalPathAuthority is issued only by SegmentStore")
        object.__setattr__(self, "_store_ref", weakref.ref(store))
        object.__setattr__(self, "_binding", binding)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("historical path capabilities are immutable")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("HistoricalPathAuthority is final")

    def __copy__(self) -> Never:
        raise TypeError("historical path capabilities cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        del memo
        raise TypeError("historical path capabilities cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("historical path capabilities cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("historical path capabilities cannot be serialized")


def _clipped_retired_ranges(
    store: SegmentStore,
    start: int,
    end: int,
) -> tuple[tuple[int, int], ...]:
    clipped: list[tuple[int, int]] = []
    for retired_start, retired_end in store._authenticated_retired_ranges:
        left = max(start, retired_start)
        right = min(end, retired_end)
        if left <= right:
            clipped.append((left, right))
    return tuple(clipped)


def _path_records(
    store: SegmentStore,
    start: int,
    end: int,
) -> tuple[StoredEvidenceRecord, ...]:
    selected: list[StoredEvidenceRecord] = []
    for record in store.iter_authenticated_records(after=start - 1, through=end):
        if len(selected) == _COLLECTION_CAP:
            raise HistoricalCoverageUnavailable("recent path events exceed 4096")
        selected.append(record)
    return tuple(selected)


def _path_is_structurally_anchored(
    records: tuple[StoredEvidenceRecord, ...],
    retired_ranges: tuple[tuple[int, int], ...],
    start: int,
    terminal: int,
) -> bool:
    live_sequences = {record.ref.source_sequence for record in records}
    cursor = start
    while cursor <= terminal:
        if cursor in live_sequences:
            cursor += 1
            continue
        covered_through = cursor - 1
        for range_start, range_end in retired_ranges:
            if range_start <= cursor <= range_end:
                covered_through = max(covered_through, range_end)
        for record in records:
            prepared = _prepare_historical_record(record)
            coverage = prepared.coverage
            if coverage is None or prepared.fact.classification.action not in {
                "sequence_open",
                "sequence_close",
            }:
                continue
            affected_start = coverage.affected_source_sequence_start
            affected_end = coverage.affected_source_sequence_end
            if (
                affected_start is not None
                and affected_end is not None
                and affected_start <= cursor <= affected_end
            ):
                covered_through = max(covered_through, affected_end)
        if covered_through < cursor:
            return False
        cursor = covered_through + 1
    return True


def _new_path_binding(
    store: SegmentStore,
    authenticated: AuthenticatedPCCInput,
) -> _PathBinding:
    if (
        type(store) is not SegmentStore
        or type(authenticated) is not AuthenticatedPCCInput
        or not authenticated_pcc_input_is_issued(authenticated)
        or not store._authenticated_pcc_input_is_exact(authenticated)
    ):
        raise HistoricalCoverageUnavailable("historical path lacks issued PCC authority")
    status = store.status()
    verifier = store._bound_verifier
    snapshot = authenticated.snapshot
    request = authenticated.request
    trigger = snapshot.trigger
    terminal = authenticated.source_sequence
    coverage_through = snapshot.coverage_through_sequence
    if (
        not status.healthy
        or status.repair_pending
        or status.retention_pending
        or verifier is None
        or not store._is_bound_verifier(verifier)
        or coverage_through != terminal - 1
        or status.acceptance_cursor < terminal
        or authenticated.host_id != trigger.host_id
        or authenticated.boot_id != trigger.boot_id
        or request.trigger_event_id != trigger.event_id
        or request.trigger_content_sha256 != trigger.content_sha256
        or request.trigger_source_sequence != trigger.source_sequence
    ):
        raise HistoricalCoverageUnavailable("historical PCC path is not exact and healthy")
    try:
        pcc_record = store.resolve_authenticated_ref(
            cast(EvidenceRef, authenticated.evidence_ref)
        )
    except EvidenceStoreError as error:
        raise HistoricalCoverageUnavailable("protected PCC terminal is unavailable") from error
    if (
        pcc_record.priority is not EvidencePriority.PROTECTED
        or pcc_record.ref.source_sequence != terminal
        or pcc_record.ref.event_id != authenticated.event_id
        or pcc_record.ref.content_sha256 != authenticated.content_sha256
    ):
        raise HistoricalCoverageUnavailable("protected PCC terminal changed")
    records = _path_records(store, trigger.source_sequence, terminal)
    if not records or records[-1].ref != pcc_record.ref:
        raise HistoricalCoverageUnavailable("historical path lacks its live terminal")
    trigger_live = next(
        (item for item in records if item.ref.source_sequence == trigger.source_sequence),
        None,
    )
    retired = _clipped_retired_ranges(store, trigger.source_sequence, coverage_through)
    if not _path_is_structurally_anchored(
        records,
        retired,
        trigger.source_sequence,
        terminal,
    ):
        raise HistoricalCoverageUnavailable(
            "historical path is not covered by live refs and authenticated ranges"
        )
    if trigger_live is None:
        matches = sum(
            1 for start, end in retired if start <= trigger.source_sequence <= end
        )
        if matches != 1:
            raise HistoricalCoverageUnavailable("retired trigger lacks one routine range")
    elif (
        trigger_live.ref.event_id != trigger.event_id
        or trigger_live.ref.content_sha256 != trigger.content_sha256
        or trigger_live.priority is not EvidencePriority.ROUTINE
    ):
        raise HistoricalCoverageUnavailable("live trigger differs from retained PCC identity")
    return _PathBinding(
        lifecycle=store._lifecycle_identity,
        verifier=verifier,
        verifier_authority=verifier._authority,
        verifier_generation=store.verifier_generation,
        pcc=authenticated,
        pcc_ref=_ref_fingerprint(authenticated.evidence_ref),
        pcc_canonical=authenticated.canonical,
        request_canonical=canonical_json(request),
        snapshot_canonical=canonical_json(snapshot),
        host_id=authenticated.host_id,
        boot_id=authenticated.boot_id,
        trigger_event_id=trigger.event_id,
        trigger_content_sha256=trigger.content_sha256,
        trigger_source_sequence=trigger.source_sequence,
        terminal_sequence=terminal,
        coverage_through_sequence=coverage_through,
        acceptance_cursor=status.acceptance_cursor,
        surviving_path_refs=tuple(_ref_fingerprint(item.ref) for item in records),
        retired_ranges=retired,
    )


def _issue_historical_path_authority(
    store: SegmentStore,
    authenticated: AuthenticatedPCCInput,
) -> HistoricalPathAuthority:
    if _ACTIVE_REPLAY_MARKER.get() is not None:
        raise HistoricalCoverageUnavailable(
            "historical replay requires an explicit lexical access"
        )
    with _store_replay_gate(store):
        with _REPLAY_RESERVATION_LOCK:
            if store in _REPLAY_STORE_RESERVATIONS:
                raise HistoricalCoverageUnavailable(
                    "historical replay store is active in another context"
                )
        binding = _new_path_binding(store, authenticated)
    authority = HistoricalPathAuthority(
        store,
        binding,
        _factory=_PATH_FACTORY,
    )
    with _ISSUED_PATHS_LOCK:
        _ISSUED_PATHS[authority] = authority._binding
    return authority


def _issue_replay_historical_path_authority(
    store: SegmentStore,
    authenticated: AuthenticatedPCCInput,
    access: _ReplayAccess | None,
) -> HistoricalPathAuthority:
    if access is None:
        return _issue_historical_path_authority(store, authenticated)
    if type(access) is not _ReplayAccess:
        raise HistoricalCoverageUnavailable(
            "historical replay issue lacks its explicit lexical access"
        )
    path = access._invoke("issue_path", store, authenticated)
    if type(path) is not HistoricalPathAuthority:
        raise HistoricalCoverageUnavailable(
            "historical replay broker returned an invalid path"
        )
    return path


def _revalidate_authority(
    authenticated: AuthenticatedPCCInput,
    authority: HistoricalPathAuthority,
    access: _ReplayAccess | None = None,
) -> tuple[SegmentStore, _PathBinding | _ReplayPathBinding]:
    if type(authority) is not HistoricalPathAuthority:
        raise TypeError("historical coverage requires an exact path authority")
    store = authority._store_ref()
    binding = authority._binding
    if type(binding) is _ReplayPathBinding:
        raise HistoricalCoverageUnavailable(
            "historical replay path requires its closure-owned broker"
        )
    with _ISSUED_PATHS_LOCK:
        issued_binding = _ISSUED_PATHS.get(authority)
    if (
        type(binding) is not _PathBinding
        or issued_binding is not binding
        or store is None
        or authenticated is not binding.pcc
    ):
        raise HistoricalCoverageUnavailable("historical path belongs to another PCC or store")
    current = _new_path_binding(store, authenticated)
    if current != binding:
        raise HistoricalCoverageUnavailable("historical path authority was revoked")
    return store, binding


def derive_historical_coverage(
    authenticated: AuthenticatedPCCInput,
    authority: HistoricalPathAuthority,
) -> HistoricalCoverageAssessment:
    return _derive_historical_coverage_with_access(
        authenticated,
        authority,
        None,
    )


def _derive_historical_coverage_with_access(
    authenticated: AuthenticatedPCCInput,
    authority: HistoricalPathAuthority,
    access: _ReplayAccess | None,
) -> HistoricalCoverageAssessment:
    if type(authority) is not HistoricalPathAuthority:
        raise TypeError("historical coverage requires an exact path authority")
    store_ref = authority._store_ref()
    if store_ref is None:
        raise HistoricalCoverageUnavailable("historical path lost its store")
    binding_value = authority._binding
    if type(binding_value) is _ReplayPathBinding:
        if type(access) is not _ReplayAccess:
            raise HistoricalCoverageUnavailable(
                "historical replay requires explicit lexical access"
            )
        assessment = access._invoke("derive", authenticated, authority)
        if type(assessment) is not HistoricalCoverageAssessment:
            raise HistoricalCoverageUnavailable(
                "historical replay broker returned an invalid assessment"
            )
        return assessment
    with _store_replay_gate(store_ref):
        with _REPLAY_RESERVATION_LOCK:
            if store_ref in _REPLAY_STORE_RESERVATIONS:
                raise HistoricalCoverageUnavailable(
                    "historical replay revoked ordinary path authority"
                )
        store, replay_binding = _revalidate_authority(
            authenticated,
            authority,
            access,
        )
        if type(replay_binding) is not _PathBinding:
            raise HistoricalCoverageUnavailable(
                "historical path binding has an invalid runtime type"
            )
        binding = replay_binding
        try:
            records = store.iter_authenticated_records(
                after=0,
                through=binding.coverage_through_sequence,
            )
            trigger = authenticated.snapshot.trigger
            timeline = _reduce_historical_coverage(
                records,
                host_id=binding.host_id,
                boot_id=binding.boot_id,
                trigger_event_id=binding.trigger_event_id,
                trigger_source_sequence=binding.trigger_source_sequence,
                trigger_event_time=trigger.event_time,
                clock_uncertainty_ms=trigger.clock_uncertainty_ms,
                coverage_through_sequence=binding.coverage_through_sequence,
                window_end=authenticated.snapshot.decision_time,
            )
            _revalidate_authority(authenticated, authority)
            return timeline.assessment
        except HistoricalCoverageUnavailable:
            raise
        except (EvidenceStoreError, ValueError, TypeError) as error:
            raise HistoricalCoverageUnavailable(
                "historical reduction lost store authority"
            ) from error


def _derive_replay_historical_coverage(
    authenticated: AuthenticatedPCCInput,
    authority: HistoricalPathAuthority,
    access: _ReplayAccess | None,
) -> HistoricalCoverageAssessment:
    binding = authority._binding if type(authority) is HistoricalPathAuthority else None
    if type(binding) is not _ReplayPathBinding:
        if access is not None:
            raise HistoricalCoverageUnavailable(
                "ordinary historical derive rejects replay access"
            )
        return derive_historical_coverage(authenticated, authority)
    if access is None:
        raise HistoricalCoverageUnavailable(
            "historical replay derive lacks explicit lexical access"
        )
    return _derive_historical_coverage_with_access(
        authenticated,
        authority,
        access,
    )


__all__ = [
    "HistoricalCoverageConflict",
    "HistoricalCoverageRecord",
    "HistoricalCoverageTimeline",
    "HistoricalCoverageUnavailable",
    "HistoricalCriticalEpisode",
    "derive_historical_coverage",
]


_ISSUED_PATHS = weakref.WeakKeyDictionary()
_ISSUED_PATHS_LOCK = RLock()
