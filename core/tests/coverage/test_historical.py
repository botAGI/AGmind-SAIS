from __future__ import annotations

import importlib
from itertools import chain, repeat
from typing import Any

import pytest
from agmind_immune.contracts import MAX_UINT64
from agmind_immune.evidence.segments import SegmentStore
from tests.coverage.test_state import (
    T0,
    T1,
    T2,
    T3,
    _coverage,
    _docker_open,
    _docker_recovery,
    _event,
    _falco_point,
    _gap_close,
    _gap_open,
    _generic_critical,
    _stored,
)
from tests.phase5b_helpers import (
    BOOT_A,
    HOST_ID,
    boot_boundary,
    private_key,
    rotation_pair,
)


def _subject() -> Any:
    try:
        return importlib.import_module("agmind_immune.coverage.historical")
    except ModuleNotFoundError:
        pytest.fail("Task 2B historical coverage reducer is not implemented")


def _episode(
    *,
    component: str,
    kind: str,
    opened_at: str,
    open_digit: str,
    closed_at: str | None = None,
    close_digit: str | None = None,
) -> Any:
    subject = _subject()
    return subject.HistoricalCriticalEpisode(
        component=component,
        kind=kind,
        opened_at=opened_at,
        closed_at=closed_at,
        open_event_id="evt_" + open_digit * 64,
        close_event_id=(None if close_digit is None else "evt_" + close_digit * 64),
    )


def _counted_critical(
    sequence: int,
    count: int | None,
    *,
    closed_at: str | None = None,
    source_hash_digit: str = "1",
) -> Any:
    fields: dict[str, object] = {
        "component": "falco-adapter",
        "kind": "falco_queue_drop",
        "severity": "CRITICAL",
        "opened_at": T0,
        "reason_code": (
            "routine_queue_recovered"
            if closed_at is not None
            else "routine_capacity_exceeded"
        ),
    }
    if count is not None:
        fields["dropped_count"] = count
    if closed_at is not None:
        fields["closed_at"] = closed_at
    return _stored(
        _coverage(
            private_key(11),
            sequence,
            fields,
            coverage_flags=[] if closed_at is not None else ["falco_queue_drop"],
            source_payload_hash=source_hash_digit * 64,
        )
    )


@pytest.mark.parametrize(
    ("interval_specs", "coverage_ids", "expected"),
    [
        ((), (), "dfca18e495e27088751ed522869c0ae2011405f92e40ba27d286ecc280e58310"),
        (
            (
                ("falco-adapter", "falco_heartbeat_gap", "2026-08-01T00:00:00Z", "2", None, None),
            ),
            ("evt_" + "2" * 64,),
            "7fe479fcf7195914c4fd3dff5272cfb9083c6b8a88b7e3cf5533df70700dfbec",
        ),
        (
            (
                ("observer", "observer_sequence_gap", "2026-07-31T23:59:59Z", "3", "2026-08-01T00:00:00Z", "4"),
            ),
            ("evt_" + "3" * 64, "evt_" + "4" * 64),
            "846b7d318ff81284c07d5bb23299b50c1784ea87df3773e58f095de62a11687f",
        ),
    ],
)
def test_frozen_coverage_hash_vectors(
    interval_specs: tuple[tuple[str, str, str, str, str | None, str | None], ...],
    coverage_ids: tuple[str, ...],
    expected: str,
) -> None:
    intervals = tuple(
        _episode(
            component=component,
            kind=kind,
            opened_at=opened_at,
            open_digit=open_digit,
            closed_at=closed_at,
            close_digit=close_digit,
        )
        for component, kind, opened_at, open_digit, closed_at, close_digit in interval_specs
    )
    assert _subject()._coverage_snapshot_sha256(
        host_id="123e4567-e89b-42d3-a456-426614174000",
        boot_id="223e4567-e89b-42d3-a456-426614174000",
        trigger_event_id="evt_" + "1" * 64,
        trigger_source_sequence=10,
        coverage_through_sequence=12,
        window_start="2026-08-01T00:00:00Z",
        window_end="2026-08-01T00:00:01Z",
        intersecting_intervals=intervals,
        coverage_event_ids=coverage_ids,
    ) == expected


def test_hash_canonicalizes_interval_order_optional_omission_and_id_set() -> None:
    subject = _subject()
    later = _episode(
        component="z",
        kind="later",
        opened_at=T1,
        open_digit="8",
    )
    earlier = _episode(
        component="a",
        kind="earlier",
        opened_at=T0,
        closed_at=T1,
        open_digit="7",
        close_digit="9",
    )
    values = {
        "host_id": HOST_ID,
        "boot_id": BOOT_A,
        "trigger_event_id": "evt_" + "6" * 64,
        "trigger_source_sequence": 10,
        "coverage_through_sequence": 12,
        "window_start": T0,
        "window_end": T2,
    }

    first = subject._coverage_snapshot_sha256(
        **values,
        intersecting_intervals=(later, earlier),
        coverage_event_ids=(later.open_event_id, earlier.open_event_id, later.open_event_id),
    )
    second = subject._coverage_snapshot_sha256(
        **values,
        intersecting_intervals=(earlier, later),
        coverage_event_ids=(earlier.open_event_id, later.open_event_id),
    )

    assert first == second


def test_late_coverage_candidate_relevance_is_closed_to_critical_actions() -> None:
    key = private_key(11)
    critical = _generic_critical(
        key,
        2,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T0,
        closed_at=T0,
    )
    lease = _falco_point(
        key,
        3,
        kind="falco_heartbeat_lease",
        severity="INFO",
        at=T0,
        reason="valid_heartbeat",
    )

    assert _subject()._late_coverage_may_invalidate_candidate(critical) is True
    assert _subject()._late_coverage_may_invalidate_candidate(lease) is False


def test_pretrigger_episode_uses_open_latest_effective_update_and_close_ids() -> None:
    subject = _subject()
    key = private_key(11)
    opened = _generic_critical(
        key,
        1,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T0,
    )
    trigger = _event(key, 2, kind="trigger", event_time=T1)
    update = _stored(
        _coverage(
            key,
            3,
            {
                "component": "falco-adapter",
                "kind": "falco_heartbeat_gap",
                "severity": "CRITICAL",
                "opened_at": T0,
                "reason_code": "falco_heartbeat_timeout",
            },
            coverage_flags=["falco_heartbeat_gap"],
            source_payload_hash="b" * 64,
        )
    )
    close = _generic_critical(
        key,
        4,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T0,
        closed_at=T2,
    )

    timeline = subject._reduce_historical_coverage(
        (opened, _stored(trigger), update, close),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id=str(trigger["event_id"]),
        trigger_source_sequence=2,
        trigger_event_time=T1,
        clock_uncertainty_ms=1_000,
        coverage_through_sequence=4,
        window_end=T2,
    )

    assert timeline.assessment.complete is True
    assert timeline.assessment.critical_gap is True
    assert timeline.coverage_event_ids == tuple(
        sorted((opened.ref.event_id, update.ref.event_id, close.ref.event_id))
    )


def test_open_structural_gap_is_incomplete_without_hash_or_critical_claim() -> None:
    subject = _subject()
    key = private_key(11)
    gap = _gap_open(key, 3, start=4, end=5, opened_at=T0)
    timeline = subject._reduce_historical_coverage(
        (gap,),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id="evt_" + "1" * 64,
        trigger_source_sequence=2,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=5,
        window_end=T2,
    )

    assert timeline.assessment.complete is False
    assert timeline.assessment.critical_gap is False
    assert timeline.assessment.coverage_snapshot_sha256 is None


@pytest.mark.parametrize(
    ("opened_at", "affected_start", "affected_end"),
    [
        (T2, 50, 51),
        (T0, 2, 2),
    ],
    ids=("timestamp-only", "range-only"),
)
def test_open_structural_gap_is_incomplete_on_time_or_range_intersection(
    opened_at: str,
    affected_start: int,
    affected_end: int,
) -> None:
    subject = _subject()
    key = private_key(11)
    gap = _gap_open(
        key,
        1,
        start=affected_start,
        end=affected_end,
        opened_at=opened_at,
    )

    timeline = subject._reduce_historical_coverage(
        (gap,),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id="evt_" + "c" * 64,
        trigger_source_sequence=2,
        trigger_event_time=T2,
        clock_uncertainty_ms=0,
        coverage_through_sequence=2,
        window_end=T3,
    )

    assert timeline.assessment.complete is False
    assert timeline.assessment.coverage_snapshot_sha256 is None
    assert timeline.assessment.critical_gap is False


def test_falco_stop_is_a_closed_critical_point_with_frozen_hash() -> None:
    subject = _subject()
    key = private_key(11)
    stop = _falco_point(
        key,
        2,
        kind="falco_adapter_stop",
        severity="CRITICAL",
        at=T1,
        reason="adapter_stopping",
    )

    timeline = subject._reduce_historical_coverage(
        (stop,),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id="evt_" + "d" * 64,
        trigger_source_sequence=1,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=2,
        window_end=T2,
    )

    assert timeline.intersecting_intervals == (
        subject.HistoricalCriticalEpisode(
            component="falco-adapter",
            kind="falco_adapter_stop",
            opened_at=T1,
            closed_at=T1,
            open_event_id=stop.ref.event_id,
            close_event_id=stop.ref.event_id,
        ),
    )
    assert timeline.coverage_event_ids == (stop.ref.event_id,)
    assert timeline.assessment.coverage_snapshot_sha256 == (
        "b0484fac1afe3affaaee92981ab72ad2e238362fec68861ec2e7f2fb9438c2cc"
    )


def test_self_contained_close_has_literal_frozen_hash() -> None:
    subject = _subject()
    close = _generic_critical(
        private_key(11),
        1,
        component="falco-adapter",
        kind="falco_delivery_failure",
        opened_at=T0,
        closed_at=T1,
    )

    timeline = subject._reduce_historical_coverage(
        (close,),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id="evt_" + "e" * 64,
        trigger_source_sequence=2,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=2,
        window_end=T2,
    )

    assert timeline.coverage_event_ids == (close.ref.event_id,)
    assert timeline.assessment.coverage_snapshot_sha256 == (
        "546bf0206118eb36364af010bed45acea8d15da9d47c3c13901182f2a3aa2d0a"
    )


def test_pretrigger_updates_hash_only_open_latest_update_and_close() -> None:
    subject = _subject()
    opened = _counted_critical(1, 1, source_hash_digit="1")
    first_update = _counted_critical(2, 2, source_hash_digit="2")
    latest_update = _counted_critical(3, 3, source_hash_digit="3")
    trigger = _stored(_event(private_key(11), 4, kind="trigger", event_time=T1))
    close = _counted_critical(5, 3, closed_at=T2, source_hash_digit="5")

    timeline = subject._reduce_historical_coverage(
        (opened, first_update, latest_update, trigger, close),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id="evt_" + "f" * 64,
        trigger_source_sequence=4,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=5,
        window_end=T2,
    )

    assert first_update.ref.event_id not in timeline.coverage_event_ids
    assert timeline.coverage_event_ids == tuple(
        sorted((opened.ref.event_id, latest_update.ref.event_id, close.ref.event_id))
    )
    assert timeline.assessment.coverage_snapshot_sha256 == (
        "6c25343a6c8926a7c353c9f490c6ba3aecef0592e75d3f569b3fc24198df755e"
    )


def test_sequence_close_hashes_endpoints_matched_recovery_and_prior_baseline() -> None:
    subject = _subject()
    key = private_key(11)
    records = (
        _docker_open(key, 1, opened_at=T0, generation=1),
        _docker_recovery(key, 2, opened_at=T0, closed_at=T1, generation=1),
        _gap_open(key, 3, start=10, end=11, opened_at=T0),
        _docker_open(key, 4, opened_at=T1, generation=2),
        _docker_recovery(key, 5, opened_at=T1, closed_at=T2, generation=2),
        _gap_close(
            key,
            6,
            start=10,
            end=11,
            opened_at=T0,
            closed_at=T2,
            generation=2,
        ),
    )

    timeline = subject._reduce_historical_coverage(
        records,
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id="evt_" + "a" * 64,
        trigger_source_sequence=10,
        trigger_event_time=T1,
        clock_uncertainty_ms=0,
        coverage_through_sequence=11,
        window_end=T2,
    )

    assert timeline.assessment.complete is True
    assert timeline.assessment.critical_gap is True
    assert timeline.coverage_event_ids == tuple(
        sorted(record.ref.event_id for record in records)
    )
    assert timeline.assessment.coverage_snapshot_sha256 == (
        "e0b450b36f0105af03d97af9decbff19694f14fc9d5d905fbbbc068096616dd3"
    )


def test_closed_sequence_gap_range_overlap_is_critical_when_timestamps_miss() -> None:
    subject = _subject()
    key = private_key(11)
    records = (
        _docker_open(key, 1, opened_at=T0, generation=1),
        _docker_recovery(key, 2, opened_at=T0, closed_at=T0, generation=1),
        _gap_open(key, 3, start=10, end=11, opened_at=T0),
        _docker_open(key, 4, opened_at=T0, generation=2),
        _docker_recovery(key, 5, opened_at=T0, closed_at=T1, generation=2),
        _gap_close(
            key,
            6,
            start=10,
            end=11,
            opened_at=T0,
            closed_at=T1,
            generation=2,
        ),
    )

    timeline = subject._reduce_historical_coverage(
        records,
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id="evt_" + "5" * 64,
        trigger_source_sequence=10,
        trigger_event_time=T2,
        clock_uncertainty_ms=0,
        coverage_through_sequence=11,
        window_end=T3,
    )

    assert timeline.assessment.complete is True
    assert timeline.assessment.critical_gap is True
    assert [item.kind for item in timeline.intersecting_intervals] == [
        "observer_sequence_gap"
    ]
    assert timeline.coverage_event_ids == tuple(
        sorted(record.ref.event_id for record in records)
    )


def test_second_close_and_reopen_conflict_via_prefix_probe() -> None:
    subject = _subject()
    key = private_key(11)
    opened = _generic_critical(
        key,
        1,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T0,
    )
    closed = _generic_critical(
        key,
        2,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T0,
        closed_at=T1,
    )
    second_close = _generic_critical(
        key,
        3,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T0,
        closed_at=T2,
    )
    reopened = _stored(
        _coverage(
            key,
            3,
            {
                "component": "falco-adapter",
                "kind": "falco_heartbeat_gap",
                "severity": "CRITICAL",
                "opened_at": T0,
                "reason_code": "falco_heartbeat_timeout",
            },
            coverage_flags=["falco_heartbeat_gap"],
            source_payload_hash="c" * 64,
        )
    )
    arguments = {
        "host_id": HOST_ID,
        "boot_id": BOOT_A,
        "trigger_event_id": "evt_" + "b" * 64,
        "trigger_source_sequence": 1,
        "trigger_event_time": T0,
        "clock_uncertainty_ms": 0,
        "coverage_through_sequence": 3,
        "window_end": T2,
    }

    for terminal in (second_close, reopened):
        with pytest.raises(subject.HistoricalCoverageConflict):
            subject._reduce_historical_coverage(
                (opened, closed, terminal),
                **arguments,
            )


def test_boot_change_clears_process_episode_but_not_permanent_observer_loss() -> None:
    subject = _subject()
    key = private_key(11)
    process_open = _generic_critical(
        key,
        1,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T0,
    )
    spool_open = _stored(
        _coverage(
            key,
            2,
            {
                "component": "observer",
                "kind": "observer_spool_drop",
                "severity": "CRITICAL",
                "opened_at": T0,
                "dropped_count": 1,
                "reason_code": "routine_spool_quota",
            },
            coverage_flags=["storage_pressure"],
        )
    )
    docker_open = _docker_open(key, 3, opened_at=T0, generation=1)
    gap_open = _gap_open(key, 4, start=5, end=5, opened_at=T0)
    boundary = _stored(
        boot_boundary(
            key,
            sequence=5,
            boot_id="323e4567-e89b-42d3-a456-426614174000",
            previous_boot_id=BOOT_A,
            previous_source_sequence=4,
        )
    )

    timeline = subject._reduce_historical_coverage(
        (process_open, spool_open, docker_open, gap_open, boundary),
        host_id=HOST_ID,
        boot_id="323e4567-e89b-42d3-a456-426614174000",
        trigger_event_id=boundary.ref.event_id,
        trigger_source_sequence=5,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=5,
        window_end=T2,
    )

    assert [item.kind for item in timeline.intersecting_intervals] == [
        "docker_reconcile_gap",
        "observer_spool_drop",
    ]
    assert timeline.assessment.complete is False


def test_same_boot_key_rotation_preserves_process_host_docker_and_sequence_state() -> None:
    subject = _subject()
    old_key = private_key(11)
    new_key = private_key(12)
    process_open = _generic_critical(
        old_key,
        1,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T0,
    )
    spool_open = _stored(
        _coverage(
            old_key,
            2,
            {
                "component": "observer",
                "kind": "observer_spool_drop",
                "severity": "CRITICAL",
                "opened_at": T0,
                "dropped_count": 1,
                "reason_code": "routine_spool_quota",
            },
            coverage_flags=["storage_pressure"],
        )
    )
    docker_open = _docker_open(old_key, 3, opened_at=T0, generation=1)
    gap_open = _gap_open(old_key, 4, start=20, end=21, opened_at=T0)
    _metadata, transition, epoch_start = rotation_pair(
        old_key,
        new_key,
        transition_sequence=5,
        transition_boot=BOOT_A,
        start_boot=BOOT_A,
        mode="d",
    )
    docker_recovered = _docker_recovery(
        new_key,
        7,
        opened_at=T0,
        closed_at=T1,
        generation=1,
    )
    gap_closed = _gap_close(
        new_key,
        8,
        start=20,
        end=21,
        opened_at=T0,
        closed_at=T1,
        generation=1,
    )

    timeline = subject._reduce_historical_coverage(
        (
            process_open,
            spool_open,
            docker_open,
            gap_open,
            _stored(transition),
            _stored(epoch_start),
            docker_recovered,
            gap_closed,
        ),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id="evt_" + "7" * 64,
        trigger_source_sequence=10,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=10,
        window_end=T2,
    )

    assert {item.kind for item in timeline.intersecting_intervals} == {
        "docker_reconcile_gap",
        "falco_heartbeat_gap",
        "observer_sequence_gap",
        "observer_spool_drop",
    }


def test_transport_replay_is_suppressed_but_cumulative_primary_is_retained() -> None:
    subject = _subject()
    opened = _counted_critical(1, 1, source_hash_digit="1")
    replay = _counted_critical(2, 1, source_hash_digit="1")
    cumulative = _counted_critical(3, 2, source_hash_digit="3")
    close = _counted_critical(4, 2, closed_at=T2, source_hash_digit="4")

    timeline = subject._reduce_historical_coverage(
        (opened, replay, cumulative, close),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id=opened.ref.event_id,
        trigger_source_sequence=1,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=4,
        window_end=T2,
    )

    assert replay.ref.event_id not in timeline.coverage_event_ids
    assert cumulative.ref.event_id in timeline.coverage_event_ids
    assert timeline.coverage_event_ids == tuple(
        sorted((opened.ref.event_id, cumulative.ref.event_id, close.ref.event_id))
    )


def test_spool_recovery_point_cannot_close_permanent_loss() -> None:
    subject = _subject()
    key = private_key(11)
    opened = _stored(
        _coverage(
            key,
            1,
            {
                "component": "observer",
                "kind": "observer_spool_drop",
                "severity": "CRITICAL",
                "opened_at": T0,
                "dropped_count": 1,
                "reason_code": "routine_spool_quota",
            },
            coverage_flags=["storage_pressure"],
        )
    )
    recovered = _stored(
        _coverage(
            key,
            2,
            {
                "component": "observer",
                "kind": "observer_spool_drop_recovered",
                "severity": "INFO",
                "opened_at": T1,
                "closed_at": T1,
                "dropped_count": 1,
                "reason_code": "routine_spool_recovered",
            },
            coverage_flags=["storage_pressure"],
        )
    )

    timeline = subject._reduce_historical_coverage(
        (opened, recovered),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id=opened.ref.event_id,
        trigger_source_sequence=1,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=2,
        window_end=T2,
    )

    assert [item.kind for item in timeline.intersecting_intervals] == [
        "observer_spool_drop"
    ]
    assert recovered.ref.event_id in timeline.coverage_event_ids


def test_docker_logging_warning_is_noncritical_noop_but_primary_is_bound() -> None:
    subject = _subject()
    warning = _stored(
        _coverage(
            private_key(11),
            2,
            {
                "component": "observer",
                "kind": "docker_logging_visibility_degraded",
                "severity": "WARNING",
                "opened_at": T1,
                "reason_code": "docker_logging_unavailable",
                "reconcile_generation": 7,
            },
            inventory_generation=7,
            coverage_flags=["docker_logging_unavailable"],
        )
    )

    timeline = subject._reduce_historical_coverage(
        (warning,),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id="evt_" + "9" * 64,
        trigger_source_sequence=1,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=2,
        window_end=T2,
    )

    assert timeline.intersecting_intervals == ()
    assert timeline.coverage_event_ids == (warning.ref.event_id,)


def test_historical_and_live_reducers_share_the_exact_classifier() -> None:
    from agmind_immune.coverage import grammar

    assert _subject()._classify_coverage_record is grammar._classify_coverage_record


@pytest.mark.parametrize(
    "records",
    [
        (_counted_critical(1, 2, source_hash_digit="1"), _counted_critical(2, 1, source_hash_digit="2")),
        (_counted_critical(1, 2, source_hash_digit="1"), _counted_critical(2, 2, source_hash_digit="2")),
        (_counted_critical(1, 2, source_hash_digit="1"), _counted_critical(2, None, source_hash_digit="2")),
        (
            _docker_recovery(
                private_key(11),
                1,
                opened_at=T0,
                closed_at=T1,
                generation=1,
            ),
        ),
        (
            _gap_close(
                private_key(11),
                1,
                start=10,
                end=11,
                opened_at=T0,
                closed_at=T1,
                generation=1,
            ),
        ),
        (
            _docker_open(private_key(11), 1, opened_at=T0, generation=1),
            _docker_open(
                private_key(11),
                2,
                opened_at=T0,
                generation=1,
                reason="docker_event_stream_error",
            ),
        ),
        (
            _stored(
                _coverage(
                    private_key(11),
                    1,
                    {
                        "component": "falco-adapter",
                        "kind": "falco_delivery_failure",
                        "severity": "CRITICAL",
                        "opened_at": T1,
                        "closed_at": T0,
                        "reason_code": "observer_delivery_recovered",
                    },
                )
            ),
        ),
    ],
    ids=(
        "counter-rollback",
        "counter-equality-below-max",
        "count-disappearance",
        "unmatched-docker-close",
        "unmatched-sequence-close",
        "immutable-docker-key-reason",
        "backwards-close",
    ),
)
def test_historical_conflict_matrix(records: tuple[Any, ...]) -> None:
    subject = _subject()
    with pytest.raises(subject.HistoricalCoverageConflict):
        subject._reduce_historical_coverage(
            records,
            host_id=HOST_ID,
            boot_id=BOOT_A,
            trigger_event_id="evt_" + "8" * 64,
            trigger_source_sequence=1,
            trigger_event_time=T0,
            clock_uncertainty_ms=0,
            coverage_through_sequence=max(record.ref.source_sequence for record in records),
            window_end=T2,
        )


def test_counted_maximum_can_repeat_but_uncounted_kind_cannot_gain_count() -> None:
    subject = _subject()
    maximum = _counted_critical(1, MAX_UINT64, source_hash_digit="1")
    repeated = _counted_critical(2, MAX_UINT64, source_hash_digit="2")
    timeline = subject._reduce_historical_coverage(
        (maximum, repeated),
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id=maximum.ref.event_id,
        trigger_source_sequence=1,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=2,
        window_end=T2,
    )
    assert timeline.assessment.complete is True

    invalid = _stored(
        _coverage(
            private_key(11),
            1,
            {
                "component": "falco-adapter",
                "kind": "falco_heartbeat_gap",
                "severity": "CRITICAL",
                "opened_at": T0,
                "dropped_count": 1,
                "reason_code": "awaiting_initial_heartbeat",
            },
            coverage_flags=["falco_heartbeat_gap"],
        )
    )
    with pytest.raises(subject.HistoricalCoverageConflict):
        subject._reduce_historical_coverage(
            (invalid,),
            host_id=HOST_ID,
            boot_id=BOOT_A,
            trigger_event_id=invalid.ref.event_id,
            trigger_source_sequence=1,
            trigger_event_time=T0,
            clock_uncertainty_ms=0,
            coverage_through_sequence=1,
            window_end=T2,
        )


@pytest.mark.parametrize("severity", ["INFO", "WARNING"])
def test_noncritical_generic_record_cannot_open_episode(severity: str) -> None:
    subject = _subject()
    invalid = _stored(
        _coverage(
            private_key(11),
            1,
            {
                "component": "falco-adapter",
                "kind": "falco_heartbeat_gap",
                "severity": severity,
                "opened_at": T0,
                "reason_code": "awaiting_initial_heartbeat",
            },
            coverage_flags=["falco_heartbeat_gap"],
        )
    )
    with pytest.raises(subject.HistoricalCoverageConflict):
        subject._reduce_historical_coverage(
            (invalid,),
            host_id=HOST_ID,
            boot_id=BOOT_A,
            trigger_event_id=invalid.ref.event_id,
            trigger_source_sequence=1,
            trigger_event_time=T0,
            clock_uncertainty_ms=0,
            coverage_through_sequence=1,
            window_end=T2,
        )


def _fractional_time(index: int) -> str:
    return T0 if index == 0 else f"2026-07-28T10:00:00.{index:09d}Z"


def _spool_records(count: int, *, first_sequence: int = 1) -> Any:
    key = private_key(11)
    for index in range(count):
        yield _stored(
            _coverage(
                key,
                first_sequence + index,
                {
                    "component": "observer",
                    "kind": "observer_spool_drop",
                    "severity": "CRITICAL",
                    "opened_at": _fractional_time(index),
                    "dropped_count": 1,
                    "reason_code": "routine_spool_quota",
                },
                coverage_flags=["storage_pressure"],
            )
        )


def _self_close_records(count: int, *, first_sequence: int = 1) -> Any:
    key = private_key(11)
    for index in range(count):
        at = _fractional_time(index)
        yield _stored(
            _coverage(
                key,
                first_sequence + index,
                {
                    "component": "falco-adapter",
                    "kind": "falco_delivery_failure",
                    "severity": "CRITICAL",
                    "opened_at": at,
                    "closed_at": at,
                    "reason_code": "observer_delivery_recovered",
                },
                source_payload_hash=f"{index + 1:064x}",
            )
        )


def _warning_records(count: int, *, first_sequence: int) -> Any:
    key = private_key(11)
    for index in range(count):
        generation = index + 1
        yield _stored(
            _coverage(
                key,
                first_sequence + index,
                {
                    "component": "observer",
                    "kind": "docker_logging_visibility_degraded",
                    "severity": "WARNING",
                    "opened_at": _fractional_time(index),
                    "reason_code": "docker_logging_unavailable",
                    "reconcile_generation": generation,
                },
                inventory_generation=generation,
                coverage_flags=["docker_logging_unavailable"],
            )
        )


def _bounded_reduce(records: Any, *, trigger: int, through: int) -> Any:
    return _subject()._reduce_historical_coverage(
        records,
        host_id=HOST_ID,
        boot_id=BOOT_A,
        trigger_event_id="evt_" + "6" * 64,
        trigger_source_sequence=trigger,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=through,
        window_end=T1,
        _prefix_records=lambda _sequence: (),
    )


def test_active_episode_cap_is_enforced_by_streaming_reducer() -> None:
    assert len(
        _bounded_reduce(_spool_records(4_096), trigger=4_096, through=4_096)
        .intersecting_intervals
    ) == 4_096
    with pytest.raises(
        _subject().HistoricalCoverageUnavailable,
        match="active episodes",
    ):
        _bounded_reduce(_spool_records(4_097), trigger=4_097, through=4_097)


def test_pretrigger_summary_cap_is_enforced_by_streaming_reducer() -> None:
    assert len(
        _bounded_reduce(_self_close_records(4_096), trigger=4_096, through=4_096)
        .intersecting_intervals
    ) == 4_096
    with pytest.raises(
        _subject().HistoricalCoverageUnavailable,
        match="pre-trigger summaries",
    ):
        _bounded_reduce(_self_close_records(4_097), trigger=4_097, through=4_097)


def test_recent_primary_cap_is_enforced_by_streaming_reducer() -> None:
    assert len(
        _bounded_reduce(_warning_records(4_096, first_sequence=2), trigger=1, through=4_097)
        .coverage_event_ids
    ) == 4_096
    with pytest.raises(
        _subject().HistoricalCoverageUnavailable,
        match="recent primary IDs",
    ):
        _bounded_reduce(
            _warning_records(4_097, first_sequence=2),
            trigger=1,
            through=4_098,
        )


def test_recent_path_event_cap_is_enforced_by_store_path_collector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    record = _stored(_event(private_key(11), 1, kind="path"))
    store = object.__new__(SegmentStore)
    count = 4_096
    monkeypatch.setattr(
        SegmentStore,
        "iter_authenticated_records",
        lambda _self, **_kwargs: iter(repeat(record, count)),
    )
    assert len(subject._path_records(store, 1, count)) == count
    count = 4_097
    with pytest.raises(
        subject.HistoricalCoverageUnavailable,
        match="recent path events",
    ):
        subject._path_records(store, 1, count)


def test_final_interval_cap_is_independent_of_source_collection_caps() -> None:
    assert len(
        _bounded_reduce(
            chain(_self_close_records(2_048), _spool_records(2_048, first_sequence=2_049)),
            trigger=4_096,
            through=4_096,
        ).intersecting_intervals
    ) == 4_096
    with pytest.raises(
        _subject().HistoricalCoverageUnavailable,
        match="final intervals",
    ):
        _bounded_reduce(
            chain(_self_close_records(2_048), _spool_records(2_049, first_sequence=2_049)),
            trigger=4_097,
            through=4_097,
        )


def test_final_id_cap_is_independent_of_recent_primary_cap() -> None:
    assert len(
        _bounded_reduce(
            chain(_self_close_records(1), _warning_records(4_095, first_sequence=3)),
            trigger=2,
            through=4_097,
        ).coverage_event_ids
    ) == 4_096
    with pytest.raises(
        _subject().HistoricalCoverageUnavailable,
        match="final coverage IDs",
    ):
        _bounded_reduce(
            chain(_self_close_records(1), _warning_records(4_096, first_sequence=3)),
            trigger=2,
            through=4_098,
        )
