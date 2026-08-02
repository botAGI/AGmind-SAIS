"""Bounded historical coverage reduction over authenticated evidence."""

from __future__ import annotations

import hashlib
import json
import weakref
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Never, SupportsIndex, cast, final

from pydantic import ValidationError

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import MAX_UINT64, CoverageEventV1, EventEnvelopeV1
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


def _is_primary(
    prefix: Iterable[StoredEvidenceRecord],
    prepared: _PreparedHistoricalRecord,
) -> bool:
    for earlier in prefix:
        candidate = _prepare_historical_record(earlier)
        if (
            candidate.fact.dedup_kind == prepared.fact.dedup_kind
            and candidate.fact.logical_key_sha256
            == prepared.fact.logical_key_sha256
        ):
            return False
    return True


def _episode_was_closed(
    prefix_records: Callable[[int], Iterable[StoredEvidenceRecord]],
    before_sequence: int,
    key: tuple[str | None, str, str, str],
) -> bool:
    closed = False
    for record in prefix_records(before_sequence):
        candidate = _prepare_historical_record(record)
        if not _is_primary(
            prefix_records(candidate.envelope.source_sequence),
            candidate,
        ):
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
    prefix_records: Callable[[int], Iterable[StoredEvidenceRecord]],
    before_sequence: int,
    start: int,
    end: int,
) -> bool:
    for record in prefix_records(before_sequence):
        candidate = _prepare_historical_record(record)
        coverage = candidate.coverage
        if (
            coverage is None
            or candidate.fact.classification.action != "sequence_open"
            or not _is_primary(
                prefix_records(candidate.envelope.source_sequence),
                candidate,
            )
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
    prefix_records: Callable[[int], Iterable[StoredEvidenceRecord]],
    before_sequence: int,
    opened_at: str,
    generation: int,
) -> bool:
    for record in prefix_records(before_sequence):
        candidate = _prepare_historical_record(record)
        coverage = candidate.coverage
        if (
            coverage is not None
            and candidate.fact.classification.action == "docker_open"
            and coverage.opened_at == opened_at
            and coverage.reconcile_generation == generation
            and _is_primary(
                prefix_records(candidate.envelope.source_sequence),
                candidate,
            )
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
    _prefix_records: Callable[[int], Iterable[StoredEvidenceRecord]] | None = None,
) -> HistoricalCoverageTimeline:
    if _prefix_records is None:
        if type(records) is not tuple:
            raise HistoricalCoverageUnavailable(
                "historical reduction requires a transaction-bound prefix oracle"
            )
        test_records = records
        _prefix_records = lambda sequence: (
            item
            for item in test_records
            if item.ref.source_sequence < sequence
        )
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

    for stored in records:
        prepared = _prepare_historical_record(stored)
        envelope = prepared.envelope
        if envelope.host_id != host_id or envelope.source_sequence <= last_sequence:
            raise HistoricalCoverageConflict("historical records are not one host in order")
        last_sequence = envelope.source_sequence
        if envelope.source_sequence > coverage_through_sequence:
            continue
        if not _is_primary(_prefix_records(envelope.source_sequence), prepared):
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
                _prefix_records,
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
                _prefix_records,
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
                        _prefix_records,
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
                for prior_record in _prefix_records(envelope.source_sequence):
                    prior = _prepare_historical_record(prior_record)
                    if (
                        _is_primary(
                            _prefix_records(prior.envelope.source_sequence),
                            prior,
                        )
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
    sorted_intervals = tuple(
        sorted(
            intervals,
            key=lambda item: (
                item.opened_at,
                item.component,
                item.kind,
                item.open_event_id,
                item.close_event_id or "",
            ),
        )
    )
    _bounded_for_test("final intervals", sorted_intervals)
    coverage_ids = tuple(sorted(set(final_ids)))
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
    return HistoricalCoverageTimeline(assessment, sorted_intervals, coverage_ids)


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
    authority = HistoricalPathAuthority(
        store,
        _new_path_binding(store, authenticated),
        _factory=_PATH_FACTORY,
    )
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
    if (
        _ISSUED_PATHS.get(authority) is not binding
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
            _prefix_records=lambda sequence: store.iter_authenticated_records(
                after=0,
                through=sequence - 1,
            ),
        )
        _revalidate_authority(authenticated, authority)
        return timeline.assessment
    except HistoricalCoverageUnavailable:
        raise
    except (EvidenceStoreError, ValueError, TypeError) as error:
        raise HistoricalCoverageUnavailable("historical reduction lost store authority") from error


__all__ = [
    "HistoricalCoverageConflict",
    "HistoricalCoverageRecord",
    "HistoricalCoverageTimeline",
    "HistoricalCoverageUnavailable",
    "HistoricalCriticalEpisode",
    "derive_historical_coverage",
]


_ISSUED_PATHS = weakref.WeakKeyDictionary()
