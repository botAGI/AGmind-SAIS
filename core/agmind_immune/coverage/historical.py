"""Bounded historical coverage reduction over authenticated evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import weakref
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import Never, SupportsIndex, cast, final

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
    EvidenceStoreError,
    SegmentStore,
    StoredEvidenceRecord,
)
from agmind_immune.ingest.envelope import (
    AuthenticatedPCCInput,
    authenticated_pcc_input_is_issued,
)

_COVERAGE_HASH_DOMAIN = b"AGMIND_CORRELATION_COVERAGE_V1\0"
_REPLAY_COMPACT_HASH_DOMAIN = b"AGMIND_HISTORICAL_REPLAY_COMPACT_V1\0"
_COLLECTION_CAP = 4_096
_PATH_FACTORY = object()
_ISSUED_PATHS: weakref.WeakKeyDictionary[
    HistoricalPathAuthority,
    _PathBinding,
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


@final
class HistoricalPathAuthority:
    """Opaque capability for one store's exact authenticated PCC path."""

    __slots__ = ("__weakref__", "_binding", "_store_ref")
    _binding: _PathBinding
    _store_ref: weakref.ReferenceType[SegmentStore]

    def __init__(
        self,
        store: SegmentStore,
        binding: _PathBinding,
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
    binding = _new_path_binding(store, authenticated)
    authority = HistoricalPathAuthority(
        store,
        binding,
        _factory=_PATH_FACTORY,
    )
    with _ISSUED_PATHS_LOCK:
        _ISSUED_PATHS[authority] = authority._binding
    return authority


def _revalidate_authority(
    authenticated: AuthenticatedPCCInput,
    authority: HistoricalPathAuthority,
) -> tuple[SegmentStore, _PathBinding]:
    if type(authority) is not HistoricalPathAuthority:
        raise TypeError("historical coverage requires an exact path authority")
    store = authority._store_ref()
    binding = authority._binding
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
    if type(authority) is not HistoricalPathAuthority:
        raise TypeError("historical coverage requires an exact path authority")
    store, binding = _revalidate_authority(authenticated, authority)
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
