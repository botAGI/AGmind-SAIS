from __future__ import annotations

import importlib
from typing import Any

import pytest
from agmind_immune.contracts import MAX_UINT64, CoverageEventV1, EventEnvelopeV1
from agmind_immune.correlation.primitives import parse_rfc3339nano_utc_ns
from tests.coverage.test_state import (
    T0,
    T1,
    _coverage,
    _docker_open,
    _docker_recovery,
    _falco_point,
    _gap_close,
    _gap_open,
    _stored,
)
from tests.phase5b_helpers import private_key


def _subject() -> Any:
    try:
        return importlib.import_module("agmind_immune.coverage.grammar")
    except ModuleNotFoundError:
        pytest.fail("Task 2A exact coverage grammar is not implemented")


def _classified(record: object) -> Any:
    stored = record
    assert hasattr(stored, "envelope")
    envelope = EventEnvelopeV1.model_validate(stored.envelope, strict=True)
    coverage = None
    if envelope.event_type == "coverage":
        coverage = CoverageEventV1.model_validate(
            envelope.normalized_fields,
            strict=True,
        )
    return _subject()._classify_coverage_record(envelope, coverage)


@pytest.mark.parametrize(
    ("wire", "rendered"),
    [
        ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z"),
        ("1970-01-01T00:00:00.1Z", "1970-01-01T00:00:00.1Z"),
        ("2026-08-01T12:34:56.123456Z", "2026-08-01T12:34:56.123456Z"),
        ("2026-08-01T12:34:56.123456789Z", "2026-08-01T12:34:56.123456789Z"),
        ("9999-12-31T23:59:59.999999999Z", "9999-12-31T23:59:59.999999999Z"),
        ("2026-08-01T12:34:56.100000000Z", "2026-08-01T12:34:56.1Z"),
    ],
)
def test_integer_nanosecond_formatter_round_trips_full_contract_range(
    wire: str,
    rendered: str,
) -> None:
    timestamp_ns = parse_rfc3339nano_utc_ns(wire)

    assert _subject()._format_rfc3339nano_utc_ns(timestamp_ns) == rendered
    assert parse_rfc3339nano_utc_ns(rendered) == timestamp_ns


def test_historical_window_underflow_and_reversal_are_deterministically_incomplete() -> None:
    underflow = _subject()._historical_coverage_window(
        "0001-01-01T00:00:00Z",
        1,
        "0001-01-01T00:00:00Z",
    )
    assert underflow.window_start is None
    assert underflow.window_start_ns is None
    assert underflow.window_end == "0001-01-01T00:00:00Z"
    assert underflow.complete is False

    reversed_window = _subject()._historical_coverage_window(
        "2026-08-01T00:00:01.000000001Z",
        0,
        "2026-08-01T00:00:01Z",
    )
    assert reversed_window.window_start == "2026-08-01T00:00:01.000000001Z"
    assert reversed_window.complete is False


def test_historical_window_intersections_are_closed_at_both_nanosecond_boundaries() -> None:
    window = _subject()._historical_coverage_window(
        "2026-08-01T00:00:01Z",
        0,
        "2026-08-01T00:00:02Z",
    )

    assert _subject()._interval_intersects_window(
        "2026-08-01T00:00:00Z",
        "2026-08-01T00:00:01Z",
        window,
    )
    assert _subject()._interval_intersects_window(
        "2026-08-01T00:00:02Z",
        "2026-08-01T00:00:02Z",
        window,
    )
    assert not _subject()._interval_intersects_window(
        "2026-08-01T00:00:00Z",
        "2026-08-01T00:00:00.999999999Z",
        window,
    )
    assert not _subject()._interval_intersects_window(
        "2026-08-01T00:00:02.000000001Z",
        None,
        window,
    )


def test_classifier_locks_docker_sequence_and_falco_lifecycle_forms() -> None:
    key = private_key(11)
    records_and_actions = (
        (_docker_open(key, 1, opened_at=T0, generation=1), "docker_open"),
        (
            _docker_recovery(
                key,
                2,
                opened_at=T0,
                closed_at=T1,
                generation=1,
            ),
            "docker_close",
        ),
        (_gap_open(key, 3, start=20, end=21, opened_at=T0), "sequence_open"),
        (
            _gap_close(
                key,
                4,
                start=20,
                end=21,
                opened_at=T0,
                closed_at=T1,
                generation=1,
            ),
            "sequence_close",
        ),
        (
            _falco_point(
                key,
                5,
                kind="falco_adapter_start",
                severity="INFO",
                at=T0,
                reason="adapter_started",
            ),
            "falco_start",
        ),
        (
            _falco_point(
                key,
                6,
                kind="falco_adapter_stop",
                severity="CRITICAL",
                at=T1,
                reason="adapter_stopping",
            ),
            "falco_stop",
        ),
        (
            _falco_point(
                key,
                7,
                kind="falco_heartbeat_lease",
                severity="INFO",
                at=T1,
                reason="valid_heartbeat",
            ),
            "falco_lease",
        ),
    )

    for record, action in records_and_actions:
        assert _classified(record).action == action


@pytest.mark.parametrize(
    "reason",
    [
        "observer_startup",
        "docker_event_stream_error",
        "docker_event_reconcile_retry",
    ],
)
def test_classifier_accepts_only_production_docker_open_reasons(reason: str) -> None:
    assert _classified(
        _docker_open(
            private_key(11),
            1,
            opened_at=T0,
            generation=1,
            reason=reason,
        )
    ).action == "docker_open"


def test_classifier_rejects_unknown_docker_open_reason() -> None:
    with pytest.raises(ValueError, match="Docker reconcile open form"):
        _classified(
            _docker_open(
                private_key(11),
                1,
                opened_at=T0,
                generation=1,
                reason="unknown_reason",
            )
        )


@pytest.mark.parametrize(
    ("kind", "reason", "count"),
    [
        ("falco_parse_rejection", "invalid_falco_body", 1),
        ("falco_queue_drop", "routine_capacity_exceeded", 1),
        ("falco_delivery_failure", "observer_delivery_failed", None),
        ("falco_heartbeat_gap", "awaiting_initial_heartbeat", None),
        ("falco_heartbeat_gap", "falco_heartbeat_timeout", None),
        ("falco_configuration_mismatch", "falco_version_mismatch", None),
        ("falco_configuration_mismatch", "falco_engine_mismatch", None),
        ("falco_configuration_mismatch", "falco_config_hash_mismatch", None),
        ("falco_configuration_mismatch", "falco_rules_hash_mismatch", None),
        ("falco_configuration_mismatch", "falco_counter_rollback", None),
        ("falco_kernel_event_drop", "falco_kernel_drop_counter_increase", MAX_UINT64),
        ("falco_outputs_queue_drop", "falco_outputs_queue_counter_increase", 1),
    ],
)
def test_classifier_accepts_only_exact_falco_open_grammar(
    kind: str,
    reason: str,
    count: int | None,
) -> None:
    fields: dict[str, object] = {
        "component": "falco-adapter",
        "kind": kind,
        "severity": "CRITICAL",
        "opened_at": T0,
        "reason_code": reason,
    }
    if count is not None:
        fields["dropped_count"] = count
    record = _stored(
        _coverage(
            private_key(11),
            1,
            fields,
            coverage_flags=[kind],
            source_payload_hash="a" * 64,
        )
    )

    classified = _classified(record)
    assert classified.action == "generic_open"
    assert classified.scope == "process"
    assert classified.counter_required is (count is not None)


@pytest.mark.parametrize(
    ("kind", "reason", "count"),
    [
        ("falco_parse_rejection", "valid_heartbeat_recovered", 2),
        ("falco_queue_drop", "routine_queue_recovered", 2),
        ("falco_delivery_failure", "observer_delivery_recovered", None),
        ("falco_heartbeat_gap", "recovered", None),
        ("falco_configuration_mismatch", "recovered", None),
        ("falco_kernel_event_drop", "recovered", 2),
        ("falco_outputs_queue_drop", "recovered", 2),
    ],
)
def test_classifier_accepts_only_exact_falco_close_grammar(
    kind: str,
    reason: str,
    count: int | None,
) -> None:
    fields: dict[str, object] = {
        "component": "falco-adapter",
        "kind": kind,
        "severity": "CRITICAL",
        "opened_at": T0,
        "closed_at": T1,
        "reason_code": reason,
    }
    if count is not None:
        fields["dropped_count"] = count
    record = _stored(
        _coverage(
            private_key(11),
            1,
            fields,
            source_payload_hash="b" * 64,
        )
    )

    assert _classified(record).action == "generic_close"


@pytest.mark.parametrize(
    "fields",
    [
        {
            "component": "falco-adapter",
            "kind": "falco_parse_rejection",
            "severity": "CRITICAL",
            "opened_at": T0,
            "reason_code": "invalid_falco_body",
        },
        {
            "component": "falco-adapter",
            "kind": "falco_delivery_failure",
            "severity": "CRITICAL",
            "opened_at": T0,
            "dropped_count": 1,
            "reason_code": "observer_delivery_failed",
        },
        {
            "component": "falco-adapter",
            "kind": "falco_heartbeat_gap",
            "severity": "CRITICAL",
            "opened_at": T0,
            "reason_code": "unknown_reason",
        },
    ],
)
def test_classifier_rejects_wrong_falco_counter_or_reason_form(
    fields: dict[str, object],
) -> None:
    kind = str(fields["kind"])
    record = _stored(
        _coverage(
            private_key(11),
            1,
            fields,
            coverage_flags=[kind],
            source_payload_hash="c" * 64,
        )
    )

    with pytest.raises(ValueError, match="Falco adapter coverage form"):
        _classified(record)


def test_classifier_locks_persistent_observer_loss_and_noncritical_points() -> None:
    key = private_key(11)
    spool_open = _stored(
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
    pressure_recovered = _stored(
        _coverage(
            key,
            2,
            {
                "component": "observer",
                "kind": "observer_spool_drop_recovered",
                "severity": "INFO",
                "opened_at": T1,
                "closed_at": T1,
                "dropped_count": 3,
                "reason_code": "routine_spool_recovered",
            },
            coverage_flags=["storage_pressure"],
        )
    )
    logging = _stored(
        _coverage(
            key,
            3,
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

    assert _classified(spool_open).action == "generic_open"
    assert _classified(spool_open).scope == "host"
    assert _classified(pressure_recovered).action == "observer_pressure_recovered"
    assert _classified(logging).action == "docker_logging_degraded"


def test_classifier_rejects_malformed_observer_recovery_and_logging_points() -> None:
    key = private_key(11)
    malformed_recovery = _stored(
        _coverage(
            key,
            1,
            {
                "component": "observer",
                "kind": "observer_spool_drop_recovered",
                "severity": "INFO",
                "opened_at": T0,
                "closed_at": T0,
                "dropped_count": 1,
                "reason_code": "routine_spool_recovered",
            },
            coverage_flags=[],
        )
    )
    malformed_logging = _stored(
        _coverage(
            key,
            2,
            {
                "component": "observer",
                "kind": "docker_logging_visibility_degraded",
                "severity": "WARNING",
                "opened_at": T0,
                "reason_code": "docker_logging_unavailable",
                "reconcile_generation": 7,
            },
            inventory_generation=6,
            coverage_flags=["docker_logging_unavailable"],
        )
    )

    for record in (malformed_recovery, malformed_logging):
        with pytest.raises(ValueError):
            _classified(record)


def test_classifier_rejects_unknown_free_form_critical_coverage() -> None:
    record = _stored(
        _coverage(
            private_key(11),
            1,
            {
                "component": "unknown",
                "kind": "unknown_gap",
                "severity": "CRITICAL",
                "opened_at": T0,
                "reason_code": "unknown",
            },
            source_payload_hash="d" * 64,
        )
    )

    with pytest.raises(ValueError, match="unsupported coverage form"):
        _classified(record)
