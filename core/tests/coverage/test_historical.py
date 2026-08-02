from __future__ import annotations

import importlib
from typing import Any

import pytest
from tests.coverage.test_state import (
    T0,
    T1,
    T2,
    _coverage,
    _docker_open,
    _docker_recovery,
    _event,
    _gap_close,
    _gap_open,
    _generic_critical,
    _stored,
)
from tests.phase5b_helpers import BOOT_A, HOST_ID, boot_boundary, private_key


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
    boundary = _stored(
        boot_boundary(
            key,
            sequence=3,
            boot_id="323e4567-e89b-42d3-a456-426614174000",
            previous_boot_id=BOOT_A,
            previous_source_sequence=2,
        )
    )

    timeline = subject._reduce_historical_coverage(
        (process_open, spool_open, boundary),
        host_id=HOST_ID,
        boot_id="323e4567-e89b-42d3-a456-426614174000",
        trigger_event_id=boundary.ref.event_id,
        trigger_source_sequence=3,
        trigger_event_time=T0,
        clock_uncertainty_ms=0,
        coverage_through_sequence=3,
        window_end=T2,
    )

    assert [item.kind for item in timeline.intersecting_intervals] == [
        "observer_spool_drop"
    ]


def test_historical_and_live_reducers_share_the_exact_classifier() -> None:
    from agmind_immune.coverage import grammar

    assert _subject()._classify_coverage_record is grammar._classify_coverage_record


def test_every_bounded_collection_fails_at_cap_plus_one() -> None:
    subject = _subject()
    for collection in (
        "active episodes",
        "pre-trigger summaries",
        "recent path events",
        "recent primary IDs",
        "final intervals",
        "final coverage IDs",
    ):
        with pytest.raises(subject.HistoricalCoverageUnavailable, match=collection):
            subject._bounded_for_test(collection, range(4_097))
        assert len(subject._bounded_for_test(collection, range(4_096))) == 4_096
