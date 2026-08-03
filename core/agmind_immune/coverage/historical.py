"""Bounded historical coverage reduction over authenticated evidence."""

from __future__ import annotations

import hashlib
import json
import weakref
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextvars import ContextVar, Token
from dataclasses import dataclass, replace
from threading import RLock, get_ident
from typing import Never, SupportsIndex, cast, final, overload

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
    _exact_coverage_record_key,
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


@dataclass(frozen=True, slots=True)
class _HistoricalPrefixOracle:
    prepared_before: Callable[[int], Iterable[_PreparedHistoricalRecord]]
    is_primary: Callable[[_PreparedHistoricalRecord], bool]


def _episode_was_closed(
    prefix: _HistoricalPrefixOracle,
    before_sequence: int,
    key: tuple[str | None, str, str, str],
) -> bool:
    closed = False
    for candidate in prefix.prepared_before(before_sequence):
        if not prefix.is_primary(candidate):
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
    prefix: _HistoricalPrefixOracle,
    before_sequence: int,
    start: int,
    end: int,
) -> bool:
    for candidate in prefix.prepared_before(before_sequence):
        coverage = candidate.coverage
        if (
            coverage is None
            or candidate.fact.classification.action != "sequence_open"
            or not prefix.is_primary(candidate)
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
    prefix: _HistoricalPrefixOracle,
    before_sequence: int,
    opened_at: str,
    generation: int,
) -> bool:
    for candidate in prefix.prepared_before(before_sequence):
        coverage = candidate.coverage
        if (
            coverage is not None
            and candidate.fact.classification.action == "docker_open"
            and coverage.opened_at == opened_at
            and coverage.reconcile_generation == generation
            and prefix.is_primary(candidate)
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
    _prepared_records: Iterable[_PreparedHistoricalRecord] | None = None,
    _prefix_oracle: _HistoricalPrefixOracle | None = None,
) -> HistoricalCoverageTimeline:
    if _prefix_records is None and _prefix_oracle is None:
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
    if _prefix_oracle is None:
        if _prefix_records is None:
            raise HistoricalCoverageUnavailable(
                "historical reduction lost its prefix oracle"
            )
        prefix_records = _prefix_records
        _prefix_oracle = _HistoricalPrefixOracle(
            prepared_before=lambda sequence: (
                _prepare_historical_record(item)
                for item in prefix_records(sequence)
            ),
            is_primary=lambda prepared: _is_primary(
                prefix_records(prepared.envelope.source_sequence),
                prepared,
            ),
        )
    selected_prepared = (
        tuple(_prepare_historical_record(stored) for stored in records)
        if _prepared_records is None
        else _prepared_records
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

    for prepared in selected_prepared:
        envelope = prepared.envelope
        if envelope.host_id != host_id or envelope.source_sequence <= last_sequence:
            raise HistoricalCoverageConflict("historical records are not one host in order")
        last_sequence = envelope.source_sequence
        if envelope.source_sequence > coverage_through_sequence:
            continue
        if not _prefix_oracle.is_primary(prepared):
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
                _prefix_oracle,
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
                _prefix_oracle,
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
                        _prefix_oracle,
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
                for prior in _prefix_oracle.prepared_before(
                    envelope.source_sequence
                ):
                    if (
                        _prefix_oracle.is_primary(prior)
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


@dataclass(frozen=True, slots=True)
class _ReplayPathBinding:
    session: _ReplayHistoricalSession
    pcc: AuthenticatedPCCInput
    compact_records: _BoundedView[StoredEvidenceRecord]
    compact_prepared: _BoundedView[_PreparedHistoricalRecord]
    compact_count: int
    compact_digest: str
    event_token: _ReplayEventToken | None
    phase: str
    access_nonce: object


@final
class _ReplayHandle:
    __slots__ = ("__weakref__",)

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
    __slots__ = ("__weakref__",)

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


@dataclass(slots=True)
class _ReplayAccessBinding:
    session: _ReplayHistoricalSession
    pcc: AuthenticatedPCCInput
    phase: str
    event_token: _ReplayEventToken | None
    nonce: object
    open: bool = True


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
class _ReplayCompactPairState:
    record: StoredEvidenceRecord
    prepared: _PreparedHistoricalRecord
    record_identity: int
    prepared_identity: int
    record_key: tuple[object, ...]
    envelope_canonical: bytes
    coverage_canonical: bytes | None


@dataclass(frozen=True, slots=True)
class _ReplayPCCState:
    key: tuple[str, str]
    pcc: AuthenticatedPCCInput
    identity: int
    canonical: bytes
    ref: _RefFingerprint
    request_canonical: bytes
    snapshot_canonical: bytes


@dataclass(frozen=True, slots=True)
class _ReplayMemoState:
    key: tuple[str, str]
    assessment_facts: tuple[
        str,
        str,
        str,
        int,
        int,
        str | None,
        str,
        bool,
        bool,
        str | None,
    ]
    intersecting_intervals: tuple[
        tuple[str, str, str, str, str | None, str | None], ...
    ]
    coverage_event_ids: tuple[str, ...]
    compact_count: int
    compact_digest: str


@dataclass(frozen=True, slots=True)
class _ReplayValidatedState:
    projected_head: int
    compact_count: int
    compact_digest: str
    compact_pairs: tuple[_ReplayCompactPairState, ...]
    used_pcc: tuple[_ReplayPCCState, ...]
    memos: tuple[_ReplayMemoState, ...]
    validated_memo_keys: frozenset[tuple[str, str]]


@dataclass(frozen=True, slots=True)
class _ReplayMemo:
    timeline: HistoricalCoverageTimeline
    compact_count: int
    compact_digest: str


@dataclass(frozen=True, slots=True)
class _FrozenReplayEntry:
    record: StoredEvidenceRecord
    prepared: _PreparedHistoricalRecord
    expected_primary: bool
    compact_member: bool


_REPLAY_EVENT_TOKEN_FACTORY = object()
_REPLAY_SESSION_FACTORY = object()


@final
class _ReplayEventToken:
    __slots__ = ("_entry_index", "_session", "_state")
    _entry_index: int
    _session: _ReplayHistoricalSession
    _state: str

    def __init__(
        self,
        session: _ReplayHistoricalSession,
        entry_index: int,
        *,
        _factory: object,
    ) -> None:
        if _factory is not _REPLAY_EVENT_TOKEN_FACTORY:
            raise TypeError("historical replay event tokens are session-issued")
        object.__setattr__(self, "_entry_index", entry_index)
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_state", "issued")

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


@final
class _ReplayHistoricalSession:
    __slots__ = (
        "__weakref__",
        "compact_count",
        "compact_digest",
        "compact_prepared",
        "compact_records",
        "creator_thread",
        "entries",
        "frozen_record_keys",
        "frozen_retired_ranges",
        "frozen_status",
        "lifecycle",
        "memo",
        "pending_event",
        "phase",
        "projected_head",
        "store",
        "terminal_ref",
        "used_pcc",
        "validated_memo_keys",
        "validated_state",
        "verifier",
        "verifier_authority",
        "verifier_generation",
    )

    def __init__(
        self,
        store: SegmentStore,
        terminal_ref: EvidenceRef,
        *,
        _factory: object,
    ) -> None:
        if _factory is not _REPLAY_SESSION_FACTORY:
            raise TypeError("historical replay sessions are factory-issued")
        if type(store) is not SegmentStore or type(terminal_ref) is not EvidenceRef:
            raise HistoricalCoverageUnavailable(
                "historical replay session requires exact source authority"
            )
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
        except (EvidenceStoreError, ValueError, TypeError) as error:
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
            or frozen_records[-1].ref != terminal_ref
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
        self.store = store
        self.creator_thread = get_ident()
        self.terminal_ref = terminal_ref
        self.lifecycle = lifecycle
        self.verifier = verifier
        self.verifier_authority = verifier._authority
        self.verifier_generation = verifier._authority.generation
        self.frozen_status = status_before
        self.frozen_record_keys = tuple(
            _exact_coverage_record_key(record) for record in frozen_records
        )
        self.frozen_retired_ranges = tuple(store._authenticated_retired_ranges)
        self.entries = entries
        self.projected_head = 0
        self.compact_records: (
            _ReplayLedger[StoredEvidenceRecord] | tuple[StoredEvidenceRecord, ...]
        ) = _ReplayLedger()
        self.compact_prepared: (
            _ReplayLedger[_PreparedHistoricalRecord]
            | tuple[_PreparedHistoricalRecord, ...]
        ) = _ReplayLedger()
        self.compact_count = 0
        self.compact_digest = _initial_replay_compact_digest()
        self.memo: dict[tuple[str, str], _ReplayMemo] = {}
        self.pending_event: _ReplayEventToken | None = None
        self.phase = "projecting"
        self.used_pcc: dict[tuple[str, str], AuthenticatedPCCInput] = {}
        self.validated_memo_keys: set[tuple[str, str]] = set()
        self.validated_state: _ReplayValidatedState | None = None

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("historical replay sessions are final")

    @property
    def live(self) -> bool:
        return self.phase != "revoked"

    def __copy__(self) -> Never:
        raise TypeError("historical replay sessions cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        del memo
        raise TypeError("historical replay sessions cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("historical replay sessions cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("historical replay sessions cannot be serialized")

    def _require_active(self) -> None:
        if (
            self.phase not in {"projecting", "validating"}
            or get_ident() != self.creator_thread
            or _ACTIVE_REPLAY_SESSION.get() is not self
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay session is not active in its creator context"
            )
        status = self.store.status()
        if (
            status != self.frozen_status
            or self.store._lifecycle_identity is not self.lifecycle
            or self.store._bound_verifier is not self.verifier
            or self.verifier._authority is not self.verifier_authority
            or self.verifier._authority.generation != self.verifier_generation
            or not self.store._is_bound_verifier(self.verifier)
        ):
            self.phase = "revoked"
            raise HistoricalCoverageUnavailable(
                "historical replay frozen source authority changed"
            )

    def open_access(
        self,
        handle: _ReplayHandle,
        authenticated: AuthenticatedPCCInput,
    ) -> _ReplayAccess:
        self._require_active()
        handle_binding = _REPLAY_HANDLE_BINDINGS.get(handle)
        if handle_binding is not self:
            raise HistoricalCoverageUnavailable(
                "historical replay handle is not exact and live"
            )
        if (
            type(authenticated) is not AuthenticatedPCCInput
            or not self.store._authenticated_pcc_input_is_exact(authenticated)
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay access requires an exact PCC"
            )
        key = (authenticated.event_id, authenticated.content_sha256)
        event_token: _ReplayEventToken | None
        if self.phase == "projecting":
            event_token = self.pending_event
            if (
                event_token is None
                or event_token._state not in {"issued", "observed"}
                or authenticated.source_sequence != self.projected_head + 1
            ):
                raise HistoricalCoverageUnavailable(
                    "projecting replay access is outside its exact event"
                )
            used = self.used_pcc.get(key)
            if used is not None and used is not authenticated:
                raise HistoricalCoverageUnavailable(
                    "projecting replay rejects a value-equal PCC substitute"
                )
        elif self.phase == "validating":
            event_token = None
            if key not in self.validated_memo_keys or key not in self.memo:
                raise HistoricalCoverageUnavailable(
                    "validation replay access lacks an independently sealed memo"
                )
        else:
            raise HistoricalCoverageUnavailable(
                "historical replay access is out of phase"
            )
        self._revoke_accesses()
        access = _ReplayAccess()
        nonce = object()
        _REPLAY_ACCESS_BINDINGS[access] = _ReplayAccessBinding(
            session=self,
            pcc=authenticated,
            phase=self.phase,
            event_token=event_token,
            nonce=nonce,
        )
        return access

    def validate_access(
        self,
        access: _ReplayAccess,
        authenticated: AuthenticatedPCCInput,
    ) -> _ReplayAccessBinding:
        binding = _REPLAY_ACCESS_BINDINGS.get(access)
        if (
            type(access) is not _ReplayAccess
            or binding is None
            or not binding.open
            or binding.session is not self
            or binding.pcc is not authenticated
            or binding.phase != self.phase
            or (
                binding.phase == "projecting"
                and (
                    binding.event_token is not self.pending_event
                    or binding.event_token is None
                    or binding.event_token._state not in {"issued", "observed"}
                )
            )
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay access was revoked or substituted"
            )
        return binding

    def close_access(self, access: _ReplayAccess) -> None:
        binding = _REPLAY_ACCESS_BINDINGS.get(access)
        if binding is not None and binding.session is self:
            binding.open = False
            _REPLAY_ACCESS_BINDINGS.pop(access, None)
        paths = _REPLAY_PATHS_BY_ACCESS.pop(access, None)
        if paths is not None:
            for path in tuple(paths):
                _ISSUED_PATHS.pop(path, None)

    def _revoke_accesses(self) -> None:
        for access, binding in tuple(_REPLAY_ACCESS_BINDINGS.items()):
            if binding.session is self:
                self.close_access(access)

    def begin_event(self, ref: EvidenceRef) -> _ReplayEventToken:
        self._require_active()
        if (
            self.phase != "projecting"
            or self.pending_event is not None
            or type(ref) is not EvidenceRef
            or ref.source_sequence != self.projected_head + 1
            or self.entries[self.projected_head].record.ref != ref
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay event is not the exact frozen next entry"
            )
        token = _ReplayEventToken(
            self,
            self.projected_head,
            _factory=_REPLAY_EVENT_TOKEN_FACTORY,
        )
        self.pending_event = token
        return token

    def validate_event(self, token: _ReplayEventToken, ref: EvidenceRef) -> None:
        self._require_active()
        if (
            type(token) is not _ReplayEventToken
            or token._session is not self
            or token._state not in {"issued", "observed"}
            or self.pending_event is not token
            or token._entry_index != self.projected_head
            or type(ref) is not EvidenceRef
            or self.entries[token._entry_index].record.ref != ref
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay event token is not exact and pending"
            )

    def compare_primary(
        self,
        token: _ReplayEventToken,
        ref: EvidenceRef,
        observed_primary: bool,
    ) -> None:
        self.validate_event(token, ref)
        entry = self.entries[token._entry_index]
        if (
            type(observed_primary) is not bool
            or observed_primary is not entry.expected_primary
        ):
            self.phase = "revoked"
            raise HistoricalCoverageConflict(
                "projection primary differs from frozen replay authority"
            )
        object.__setattr__(token, "_state", "observed")

    def begin_commit(self, token: _ReplayEventToken, ref: EvidenceRef) -> None:
        self.validate_event(token, ref)
        if token._state != "observed":
            raise HistoricalCoverageUnavailable(
                "historical replay event lacks observed primary equality"
            )
        self._revoke_accesses()
        object.__setattr__(token, "_state", "committing")
        self.phase = "committing"

    def complete_event(self, token: _ReplayEventToken) -> None:
        if (
            self.phase != "committing"
            or get_ident() != self.creator_thread
            or _ACTIVE_REPLAY_SESSION.get() is not self
            or type(token) is not _ReplayEventToken
            or token._session is not self
            or token._state != "committing"
            or self.pending_event is not token
            or token._entry_index != self.projected_head
            or self.store.status() != self.frozen_status
            or self.store._lifecycle_identity is not self.lifecycle
            or self.store._bound_verifier is not self.verifier
            or self.verifier._authority is not self.verifier_authority
            or self.verifier._authority.generation != self.verifier_generation
            or not self.store._is_bound_verifier(self.verifier)
        ):
            self.phase = "revoked"
            raise HistoricalCoverageUnavailable(
                "historical replay committing event cannot complete"
            )
        entry = self.entries[token._entry_index]
        if entry.compact_member:
            compact_records = self.compact_records
            compact_prepared = self.compact_prepared
            if (
                type(compact_records) is not _ReplayLedger
                or type(compact_prepared) is not _ReplayLedger
            ):
                self.phase = "revoked"
                raise HistoricalCoverageUnavailable(
                    "historical replay compact ledger was sealed early"
                )
            compact_records.append(entry.record)
            compact_prepared.append(entry.prepared)
            self.compact_count += 1
            self.compact_digest = _update_replay_compact_digest(
                self.compact_digest,
                entry.record,
            )
        self.projected_head = entry.record.ref.source_sequence
        object.__setattr__(token, "_state", "completed")
        self.pending_event = None
        self.phase = "projecting"

    def issue(
        self,
        authenticated: AuthenticatedPCCInput,
        access: _ReplayAccess,
    ) -> _ReplayPathBinding:
        self._require_active()
        access_binding = self.validate_access(access, authenticated)
        if not self.store._authenticated_pcc_input_is_exact(authenticated):
            raise HistoricalCoverageUnavailable(
                "historical replay PCC is not exact at the projected head"
            )
        key = (authenticated.event_id, authenticated.content_sha256)
        used = self.used_pcc.get(key)
        if used is None:
            if self.phase != "projecting":
                raise HistoricalCoverageUnavailable(
                    "validating replay cannot add a PCC binding"
                )
            self.used_pcc[key] = authenticated
        elif (
            used.canonical != authenticated.canonical
            or used.evidence_ref != authenticated.evidence_ref
            or canonical_json(used.request) != canonical_json(authenticated.request)
            or canonical_json(used.snapshot) != canonical_json(authenticated.snapshot)
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay PCC binding changed"
            )
        cached = self.memo.get(key)
        if cached is not None:
            compact_count = cached.compact_count
            compact_digest = cached.compact_digest
        elif (
            authenticated.source_sequence == self.projected_head + 1
            and authenticated.snapshot.coverage_through_sequence
            == self.projected_head
            and self.pending_event is not None
            and self.pending_event._entry_index == self.projected_head
            and self.pending_event._state in {"issued", "observed"}
        ):
            compact_count = self.compact_count
            compact_digest = self.compact_digest
        else:
            raise HistoricalCoverageUnavailable(
                "historical replay PCC is not exact at the projected head"
            )
        return _ReplayPathBinding(
            session=self,
            pcc=authenticated,
            compact_records=_BoundedView(self.compact_records, compact_count),
            compact_prepared=_BoundedView(self.compact_prepared, compact_count),
            compact_count=compact_count,
            compact_digest=compact_digest,
            event_token=self.pending_event,
            phase=self.phase,
            access_nonce=access_binding.nonce,
        )

    def reduce(
        self,
        binding: _ReplayPathBinding,
        access: _ReplayAccess,
    ) -> HistoricalCoverageAssessment:
        access_binding = self.validate_access(access, binding.pcc)
        if binding.access_nonce is not access_binding.nonce:
            raise HistoricalCoverageUnavailable(
                "historical replay path belongs to another lexical access"
            )
        authenticated = binding.pcc
        key = (authenticated.event_id, authenticated.content_sha256)
        cached = self.memo.get(key)
        if cached is None:
            if self.phase != "projecting":
                raise HistoricalCoverageUnavailable(
                    "validating replay cannot add a historical memo"
                )
            trigger = authenticated.snapshot.trigger
            records = binding.compact_records
            prepared_records = binding.compact_prepared

            def exact_primary(candidate: _PreparedHistoricalRecord) -> bool:
                sequence = candidate.envelope.source_sequence
                if not 1 <= sequence <= len(self.entries):
                    raise HistoricalCoverageConflict(
                        "compact primary lies outside the frozen transcript"
                    )
                entry = self.entries[sequence - 1]
                if (
                    entry.prepared is not candidate
                    or not entry.expected_primary
                    or not entry.compact_member
                ):
                    raise HistoricalCoverageConflict(
                        "compact primary differs from the frozen transcript"
                    )
                return True

            prefix_oracle = _HistoricalPrefixOracle(
                prepared_before=lambda sequence: (
                    item
                    for item in prepared_records
                    if item.envelope.source_sequence < sequence
                ),
                is_primary=exact_primary,
            )
            timeline = _reduce_historical_coverage(
                records,
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
                _prepared_records=prepared_records,
                _prefix_oracle=prefix_oracle,
            )
            self.memo[key] = _ReplayMemo(
                timeline,
                binding.compact_count,
                binding.compact_digest,
            )
        else:
            timeline = cached.timeline
        return timeline.assessment

    def validate_binding(
        self,
        binding: _ReplayPathBinding,
        access: _ReplayAccess,
    ) -> None:
        self._require_active()
        access_binding = self.validate_access(access, binding.pcc)
        authenticated = binding.pcc
        key = (authenticated.event_id, authenticated.content_sha256)
        used = self.used_pcc.get(key)
        cached = self.memo.get(key)
        if cached is None:
            exact_compact = (
                binding.compact_count == self.compact_count
                and binding.compact_digest == self.compact_digest
                and binding.compact_count == len(binding.compact_records)
            )
        else:
            exact_compact = (
                binding.compact_records.ledger is self.compact_records
                and binding.compact_prepared.ledger is self.compact_prepared
                and binding.compact_count == cached.compact_count
                and binding.compact_digest == cached.compact_digest
            )
        exact_phase = (
            binding.phase == "projecting"
            and self.phase == "projecting"
            and binding.event_token is self.pending_event
            and binding.event_token is not None
            and binding.event_token._state in {"issued", "observed"}
        ) or (
            binding.phase == "validating"
            and self.phase == "validating"
            and binding.event_token is None
        )
        if (
            binding.session is not self
            or used is None
            or used.canonical != authenticated.canonical
            or used.evidence_ref != authenticated.evidence_ref
            or not self.store._authenticated_pcc_input_is_exact(authenticated)
            or not exact_compact
            or not exact_phase
            or binding.access_nonce is not access_binding.nonce
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay path binding changed"
            )

    def _capture_validated_state(self) -> _ReplayValidatedState:
        records = tuple(self.compact_records)
        prepared = tuple(self.compact_prepared)
        if (
            len(records) != len(prepared)
            or len(records) != self.compact_count
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay compact pairing changed"
            )
        compact_pairs = tuple(
            _ReplayCompactPairState(
                record=record,
                prepared=prepared_record,
                record_identity=id(record),
                prepared_identity=id(prepared_record),
                record_key=_exact_coverage_record_key(record),
                envelope_canonical=canonical_json(prepared_record.envelope),
                coverage_canonical=(
                    None
                    if prepared_record.coverage is None
                    else canonical_json(prepared_record.coverage)
                ),
            )
            for record, prepared_record in zip(records, prepared, strict=True)
        )
        used_pcc = tuple(
            _ReplayPCCState(
                key=key,
                pcc=authenticated,
                identity=id(authenticated),
                canonical=authenticated.canonical,
                ref=_ref_fingerprint(authenticated.evidence_ref),
                request_canonical=canonical_json(authenticated.request),
                snapshot_canonical=canonical_json(authenticated.snapshot),
            )
            for key, authenticated in self.used_pcc.items()
        )
        memos = tuple(
            _ReplayMemoState(
                key=key,
                assessment_facts=(
                    memo.timeline.assessment.host_id,
                    memo.timeline.assessment.boot_id,
                    memo.timeline.assessment.trigger_event_id,
                    memo.timeline.assessment.trigger_source_sequence,
                    memo.timeline.assessment.coverage_through_sequence,
                    memo.timeline.assessment.window_start,
                    memo.timeline.assessment.window_end,
                    memo.timeline.assessment.complete,
                    memo.timeline.assessment.critical_gap,
                    memo.timeline.assessment.coverage_snapshot_sha256,
                ),
                intersecting_intervals=tuple(
                    (
                        interval.component,
                        interval.kind,
                        interval.opened_at,
                        interval.open_event_id,
                        interval.closed_at,
                        interval.close_event_id,
                    )
                    for interval in memo.timeline.intersecting_intervals
                ),
                coverage_event_ids=tuple(memo.timeline.coverage_event_ids),
                compact_count=memo.compact_count,
                compact_digest=memo.compact_digest,
            )
            for key, memo in self.memo.items()
        )
        return _ReplayValidatedState(
            projected_head=self.projected_head,
            compact_count=len(records),
            compact_digest=self.compact_digest,
            compact_pairs=compact_pairs,
            used_pcc=used_pcc,
            memos=memos,
            validated_memo_keys=frozenset(self.validated_memo_keys),
        )

    def begin_validation(self) -> None:
        self._require_active()
        if (
            self.phase != "projecting"
            or self.projected_head != self.terminal_ref.source_sequence
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay did not reach its frozen terminal"
            )
        self.phase = "validating"
        self._revoke_accesses()
        self.validated_memo_keys.clear()
        try:
            rebuilt_records = tuple(
                self.store.iter_authenticated_records(
                    after=0,
                    through=self.terminal_ref.source_sequence,
                )
            )
            rebuilt_prepared = tuple(
                _prepare_historical_record(record) for record in rebuilt_records
            )
            rebuilt_entries = _build_frozen_replay_entries(
                rebuilt_records,
                rebuilt_prepared,
            )
            self._require_active()
            if (
                len(rebuilt_entries) != len(self.entries)
                or not rebuilt_entries
                or rebuilt_entries[-1].record.ref != self.terminal_ref
                or any(
                    _exact_coverage_record_key(rebuilt.record)
                    != _exact_coverage_record_key(frozen.record)
                    or rebuilt.expected_primary is not frozen.expected_primary
                    or rebuilt.compact_member is not frozen.compact_member
                    for rebuilt, frozen in zip(
                        rebuilt_entries,
                        self.entries,
                        strict=True,
                    )
                )
                or tuple(self.store._authenticated_retired_ranges)
                != self.frozen_retired_ranges
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay independent source rebuild changed"
                )
            rebuilt_compact_records: _ReplayLedger[StoredEvidenceRecord] = (
                _ReplayLedger()
            )
            rebuilt_compact_prepared: _ReplayLedger[_PreparedHistoricalRecord] = (
                _ReplayLedger()
            )
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
                self.compact_count != len(self.compact_records)
                or self.compact_count != len(self.compact_prepared)
                or len(rebuilt_compact_records) != self.compact_count
                or rebuilt_prefix_digests[-1] != self.compact_digest
                or any(
                    rebuilt.ref != accumulated.ref
                    or rebuilt.canonical_envelope
                    != accumulated.canonical_envelope
                    for rebuilt, accumulated in zip(
                        rebuilt_compact_records,
                        self.compact_records,
                        strict=True,
                    )
                )
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay accumulated compact transcript changed"
                )
            for key, authenticated in self.used_pcc.items():
                cached = self.memo.get(key)
                if cached is None:
                    raise HistoricalCoverageUnavailable(
                        "historical replay used PCC lacks one memo"
                    )
                ref = authenticated.evidence_ref
                if type(ref) is not EvidenceRef:
                    raise HistoricalCoverageUnavailable(
                        "historical replay used PCC ref changed"
                    )
                fresh = self.store._authenticated_pcc_input(
                    self.verifier,
                    ref,
                    authenticated.request,
                )
                if (
                    fresh.canonical != authenticated.canonical
                    or fresh.evidence_ref != authenticated.evidence_ref
                    or canonical_json(fresh.request)
                    != canonical_json(authenticated.request)
                    or canonical_json(fresh.snapshot)
                    != canonical_json(authenticated.snapshot)
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
                selected_prepared = _BoundedView(
                    rebuilt_compact_prepared,
                    selected_count,
                )

                def exact_rebuilt_primary(
                    candidate: _PreparedHistoricalRecord,
                ) -> bool:
                    sequence = candidate.envelope.source_sequence
                    if not 1 <= sequence <= len(rebuilt_entries):
                        raise HistoricalCoverageConflict(
                            "rebuilt compact primary is outside the transcript"
                        )
                    entry = rebuilt_entries[sequence - 1]
                    if (
                        entry.prepared is not candidate
                        or not entry.expected_primary
                        or not entry.compact_member
                    ):
                        raise HistoricalCoverageConflict(
                            "rebuilt compact primary differs from the transcript"
                        )
                    return True

                def prepared_before(
                    sequence: int,
                    prepared: _BoundedView[_PreparedHistoricalRecord] = (
                        selected_prepared
                    ),
                ) -> Iterable[_PreparedHistoricalRecord]:
                    return (
                        item
                        for item in prepared
                        if item.envelope.source_sequence < sequence
                    )

                prefix_oracle = _HistoricalPrefixOracle(
                    prepared_before=prepared_before,
                    is_primary=exact_rebuilt_primary,
                )
                trigger = fresh.snapshot.trigger
                rebuilt_timeline = _reduce_historical_coverage(
                    selected_records,
                    host_id=fresh.host_id,
                    boot_id=fresh.boot_id,
                    trigger_event_id=trigger.event_id,
                    trigger_source_sequence=trigger.source_sequence,
                    trigger_event_time=trigger.event_time,
                    clock_uncertainty_ms=trigger.clock_uncertainty_ms,
                    coverage_through_sequence=coverage_through,
                    window_end=fresh.snapshot.decision_time,
                    _prepared_records=selected_prepared,
                    _prefix_oracle=prefix_oracle,
                )
                if rebuilt_timeline != cached.timeline:
                    raise HistoricalCoverageUnavailable(
                        "historical replay assessment changed in final rebuild"
                    )
                self.validated_memo_keys.add(key)
            if (
                self.validated_memo_keys != set(self.used_pcc)
                or self.validated_memo_keys != set(self.memo)
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay memo validation closure changed"
                )
            compact_records = self.compact_records
            compact_prepared = self.compact_prepared
            if (
                type(compact_records) is not _ReplayLedger
                or type(compact_prepared) is not _ReplayLedger
            ):
                raise HistoricalCoverageUnavailable(
                    "historical replay compact ledger sealed unexpectedly"
                )
            self._revoke_accesses()
            self.compact_records = compact_records.freeze()
            self.compact_prepared = compact_prepared.freeze()
            self.validated_state = self._capture_validated_state()
        except BaseException:
            self.phase = "revoked"
            raise

    def final_seal(self, authority_check: Callable[[], None]) -> None:
        self._require_active()
        if self.phase != "validating":
            raise HistoricalCoverageUnavailable(
                "historical replay final seal is out of phase"
            )
        try:
            record_keys = tuple(
                _exact_coverage_record_key(record)
                for record in self.store.iter_authenticated_records(
                    after=0,
                    through=self.terminal_ref.source_sequence,
                )
            )
            resolved_keys = tuple(
                _exact_coverage_record_key(
                    self.store.resolve_authenticated_ref(entry.record.ref)
                )
                for entry in self.entries
            )
            resident_keys = tuple(
                _exact_coverage_record_key(record) for record in self.store._records
            )
            retired_ranges = tuple(self.store._authenticated_retired_ranges)
        except (EvidenceStoreError, TypeError, ValueError) as error:
            self.phase = "revoked"
            raise HistoricalCoverageUnavailable(
                "historical replay final transcript is unavailable"
            ) from error
        self._require_active()
        if (
            record_keys != self.frozen_record_keys
            or resolved_keys != self.frozen_record_keys
            or resident_keys != self.frozen_record_keys
            or retired_ranges != self.frozen_retired_ranges
        ):
            self.phase = "revoked"
            raise HistoricalCoverageUnavailable(
                "historical replay final transcript changed"
            )
        authority_check()
        self._require_active()
        try:
            current_state = self._capture_validated_state()
        except (TypeError, ValueError) as error:
            self.phase = "revoked"
            raise HistoricalCoverageUnavailable(
                "historical replay terminal session state is invalid"
            ) from error
        if (
            self.validated_state is None
            or current_state != self.validated_state
            or self.validated_memo_keys != set(self.used_pcc)
            or self.validated_memo_keys != set(self.memo)
            or self.projected_head != self.terminal_ref.source_sequence
        ):
            self.phase = "revoked"
            raise HistoricalCoverageUnavailable(
                "historical replay terminal session state changed"
            )
        self._revoke_accesses()
        self.phase = "sealed"

    def revalidate_resident_source(self) -> None:
        self._require_active()
        try:
            resident_keys = tuple(
                _exact_coverage_record_key(record) for record in self.store._records
            )
        except (TypeError, ValueError) as error:
            self.phase = "revoked"
            raise HistoricalCoverageUnavailable(
                "historical replay resident transcript is unavailable"
            ) from error
        if resident_keys != self.frozen_record_keys:
            self.phase = "revoked"
            raise HistoricalCoverageUnavailable(
                "historical replay resident transcript changed"
            )

    def revoke(self) -> None:
        self._revoke_accesses()
        pending = _PENDING_REPLAY_HANDLES.pop(self, None)
        if pending is not None:
            _REPLAY_HANDLE_BINDINGS.pop(pending, None)
        for handle, bound_session in tuple(_REPLAY_HANDLE_BINDINGS.items()):
            if bound_session is self:
                _REPLAY_HANDLE_BINDINGS.pop(handle, None)
        for path, binding in tuple(_ISSUED_PATHS.items()):
            if type(binding) is _ReplayPathBinding and binding.session is self:
                _ISSUED_PATHS.pop(path, None)
        self.memo.clear()
        self.used_pcc.clear()
        self.validated_memo_keys.clear()
        self.validated_state = None
        self.compact_records = _ReplayLedger()
        self.compact_prepared = _ReplayLedger()
        self.compact_count = 0
        self.compact_digest = _initial_replay_compact_digest()
        self.phase = "revoked"


_ACTIVE_REPLAY_SESSION: ContextVar[_ReplayHistoricalSession | None] = ContextVar(
    "agmind_historical_replay_session",
    default=None,
)
_REPLAY_SESSION_REGISTRY_LOCK = RLock()
_REPLAY_SESSION_BY_STORE: weakref.WeakKeyDictionary[
    SegmentStore,
    weakref.ReferenceType[_ReplayHistoricalSession],
] = weakref.WeakKeyDictionary()
_REPLAY_STORE_GATES: weakref.WeakKeyDictionary[SegmentStore, RLock] = (
    weakref.WeakKeyDictionary()
)
_REPLAY_HANDLE_BINDINGS: weakref.WeakKeyDictionary[
    _ReplayHandle,
    _ReplayHistoricalSession,
] = weakref.WeakKeyDictionary()
_PENDING_REPLAY_HANDLES: weakref.WeakKeyDictionary[
    _ReplayHistoricalSession,
    _ReplayHandle,
] = weakref.WeakKeyDictionary()
_REPLAY_ACCESS_BINDINGS: weakref.WeakKeyDictionary[
    _ReplayAccess,
    _ReplayAccessBinding,
] = weakref.WeakKeyDictionary()
_REPLAY_PATHS_BY_ACCESS: weakref.WeakKeyDictionary[
    _ReplayAccess,
    weakref.WeakSet[HistoricalPathAuthority],
] = weakref.WeakKeyDictionary()


def _store_replay_gate(store: SegmentStore) -> RLock:
    with _REPLAY_SESSION_REGISTRY_LOCK:
        gate = _REPLAY_STORE_GATES.get(store)
        if gate is None:
            gate = RLock()
            _REPLAY_STORE_GATES[store] = gate
        return gate


def _activate_replay_historical_session(
    store: SegmentStore,
    terminal_ref: EvidenceRef,
) -> tuple[_ReplayHistoricalSession, Token[_ReplayHistoricalSession | None]]:
    if _ACTIVE_REPLAY_SESSION.get() is not None:
        raise HistoricalCoverageUnavailable(
            "nested historical replay sessions are forbidden"
        )
    gate = _store_replay_gate(store)
    with gate:
        with _REPLAY_SESSION_REGISTRY_LOCK:
            if store in _REPLAY_SESSION_BY_STORE:
                raise HistoricalCoverageUnavailable(
                    "historical replay store already has an active session"
                )
        session = _ReplayHistoricalSession(
            store,
            terminal_ref,
            _factory=_REPLAY_SESSION_FACTORY,
        )
        with _REPLAY_SESSION_REGISTRY_LOCK:
            if store in _REPLAY_SESSION_BY_STORE:
                raise HistoricalCoverageUnavailable(
                    "historical replay store already has an active session"
                )
            _REPLAY_SESSION_BY_STORE[store] = weakref.ref(session)
            handle = _ReplayHandle()
            _REPLAY_HANDLE_BINDINGS[handle] = session
            _PENDING_REPLAY_HANDLES[session] = handle
    try:
        token = _ACTIVE_REPLAY_SESSION.set(session)
    except BaseException:
        session.revoke()
        pending = _PENDING_REPLAY_HANDLES.pop(session, None)
        if pending is not None:
            _REPLAY_HANDLE_BINDINGS.pop(pending, None)
        for issued_handle, bound_session in tuple(_REPLAY_HANDLE_BINDINGS.items()):
            if bound_session is session:
                _REPLAY_HANDLE_BINDINGS.pop(issued_handle, None)
        with _REPLAY_SESSION_REGISTRY_LOCK:
            current_ref = _REPLAY_SESSION_BY_STORE.get(store)
            if current_ref is not None and current_ref() is session:
                _REPLAY_SESSION_BY_STORE.pop(store, None)
        raise
    return session, token


def _take_replay_historical_handle(
    session: _ReplayHistoricalSession,
) -> _ReplayHandle:
    handle = _PENDING_REPLAY_HANDLES.pop(session, None)
    if handle is None or _REPLAY_HANDLE_BINDINGS.get(handle) is not session:
        raise HistoricalCoverageUnavailable(
            "historical replay handle is unavailable or already taken"
        )
    return handle


def _open_replay_historical_access(
    handle: _ReplayHandle,
    authenticated: AuthenticatedPCCInput,
) -> _ReplayAccess:
    session = _REPLAY_HANDLE_BINDINGS.get(handle)
    if session is None:
        raise HistoricalCoverageUnavailable(
            "historical replay handle is not issued and live"
        )
    return session.open_access(handle, authenticated)


def _close_replay_historical_access(access: _ReplayAccess | None) -> None:
    if access is None:
        return
    binding = _REPLAY_ACCESS_BINDINGS.get(access)
    if binding is not None:
        binding.session.close_access(access)


def _begin_replay_historical_event(
    session: _ReplayHistoricalSession,
    ref: EvidenceRef,
) -> _ReplayEventToken:
    return session.begin_event(ref)


def _validate_replay_historical_event(
    token: object,
    ref: EvidenceRef,
) -> None:
    if type(token) is not _ReplayEventToken:
        raise HistoricalCoverageUnavailable(
            "historical replay requires an exact event token"
        )
    token._session.validate_event(token, ref)


def _compare_replay_historical_primary(
    token: object,
    ref: EvidenceRef,
    observed_primary: bool,
) -> None:
    if type(token) is not _ReplayEventToken:
        raise HistoricalCoverageUnavailable(
            "historical replay requires an exact event token"
        )
    token._session.compare_primary(token, ref, observed_primary)


def _begin_replay_historical_commit(
    token: object,
    ref: EvidenceRef,
) -> None:
    if type(token) is not _ReplayEventToken:
        raise HistoricalCoverageUnavailable(
            "historical replay requires an exact event token"
        )
    token._session.begin_commit(token, ref)


def _complete_replay_historical_event(token: object) -> None:
    if type(token) is not _ReplayEventToken:
        raise HistoricalCoverageUnavailable(
            "historical replay requires an exact event token"
        )
    token._session.complete_event(token)


def _begin_replay_historical_validation(
    session: _ReplayHistoricalSession,
) -> None:
    session.begin_validation()


def _final_seal_replay_historical_session(
    session: _ReplayHistoricalSession,
    authority_check: Callable[[], None],
) -> None:
    session.final_seal(authority_check)


def _revalidate_replay_historical_source(
    session: _ReplayHistoricalSession,
) -> None:
    session.revalidate_resident_source()


def _close_replay_historical_session(
    session: _ReplayHistoricalSession,
    token: Token[_ReplayHistoricalSession | None],
) -> None:
    session.revoke()
    pending = _PENDING_REPLAY_HANDLES.pop(session, None)
    if pending is not None:
        _REPLAY_HANDLE_BINDINGS.pop(pending, None)
    for handle, bound_session in tuple(_REPLAY_HANDLE_BINDINGS.items()):
        if bound_session is session:
            _REPLAY_HANDLE_BINDINGS.pop(handle, None)
    _ACTIVE_REPLAY_SESSION.reset(token)
    with _store_replay_gate(session.store), _REPLAY_SESSION_REGISTRY_LOCK:
        current_ref = _REPLAY_SESSION_BY_STORE.get(session.store)
        if current_ref is not None and current_ref() is session:
            _REPLAY_SESSION_BY_STORE.pop(session.store, None)


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
    session = _ACTIVE_REPLAY_SESSION.get()
    if session is not None:
        raise HistoricalCoverageUnavailable(
            "historical replay requires an explicit lexical access"
        )
    else:
        with _store_replay_gate(store):
            with _REPLAY_SESSION_REGISTRY_LOCK:
                if store in _REPLAY_SESSION_BY_STORE:
                    raise HistoricalCoverageUnavailable(
                        "historical replay store is active in another context"
                    )
            binding = _new_path_binding(store, authenticated)
    authority = HistoricalPathAuthority(
        store,
        binding,
        _factory=_PATH_FACTORY,
    )
    _ISSUED_PATHS[authority] = authority._binding
    return authority


def _issue_replay_historical_path_authority(
    store: SegmentStore,
    authenticated: AuthenticatedPCCInput,
    access: _ReplayAccess | None,
) -> HistoricalPathAuthority:
    session = _ACTIVE_REPLAY_SESSION.get()
    if session is None:
        if access is not None:
            raise HistoricalCoverageUnavailable(
                "ordinary historical issue rejects replay access"
            )
        return _issue_historical_path_authority(store, authenticated)
    if session.store is not store or access is None:
        raise HistoricalCoverageUnavailable(
            "historical replay issue lacks its explicit lexical access"
        )
    binding: _PathBinding | _ReplayPathBinding = session.issue(
        authenticated,
        access,
    )
    authority = HistoricalPathAuthority(store, binding, _factory=_PATH_FACTORY)
    _ISSUED_PATHS[authority] = binding
    paths = _REPLAY_PATHS_BY_ACCESS.get(access)
    if paths is None:
        paths = weakref.WeakSet()
        _REPLAY_PATHS_BY_ACCESS[access] = paths
    paths.add(authority)
    return authority


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
        if (
            _ISSUED_PATHS.get(authority) is not binding
            or store is not binding.session.store
            or authenticated is not binding.pcc
            or access is None
        ):
            raise HistoricalCoverageUnavailable(
                "historical replay path belongs to another PCC or store"
            )
        binding.session.validate_binding(binding, access)
        return store, binding
    if (
        type(binding) is not _PathBinding
        or _ISSUED_PATHS.get(authority) is not binding
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
    store_ref = authority._store_ref() if type(authority) is HistoricalPathAuthority else None
    if store_ref is None:
        raise HistoricalCoverageUnavailable("historical path lost its store")
    with _store_replay_gate(store_ref):
        binding_value = authority._binding
        if type(binding_value) is _ReplayPathBinding:
            if access is None:
                raise HistoricalCoverageUnavailable(
                    "historical replay requires explicit lexical access"
                )
        else:
            with _REPLAY_SESSION_REGISTRY_LOCK:
                if store_ref in _REPLAY_SESSION_BY_STORE:
                    raise HistoricalCoverageUnavailable(
                        "historical replay revoked ordinary path authority"
                    )
        store, replay_binding = _revalidate_authority(
            authenticated,
            authority,
            access,
        )
        if type(replay_binding) is _ReplayPathBinding:
            if access is None:
                raise HistoricalCoverageUnavailable(
                    "historical replay derive lacks explicit access"
                )
            assessment = replay_binding.session.reduce(replay_binding, access)
            _revalidate_authority(authenticated, authority, access)
            return assessment
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
