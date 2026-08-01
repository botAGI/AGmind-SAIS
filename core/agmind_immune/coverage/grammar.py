"""Private exact coverage grammar and integer-nanosecond window facts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Literal

from pydantic import ValidationError

from agmind_immune.contracts import (
    CoverageEventV1,
    EventEnvelopeV1,
    KeyTransitionV1,
    ObserverBootBoundaryV1,
)
from agmind_immune.correlation.primitives import parse_rfc3339nano_utc_ns

_NANOSECONDS_PER_SECOND = 1_000_000_000
_SECONDS_PER_DAY = 86_400
_UNIX_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()
_MIN_TIMESTAMP_NS = parse_rfc3339nano_utc_ns("0001-01-01T00:00:00Z")
_MAX_TIMESTAMP_NS = parse_rfc3339nano_utc_ns(
    "9999-12-31T23:59:59.999999999Z"
)

_CoverageAction = Literal[
    "ignore",
    "boot_boundary",
    "key_transition",
    "observer_start",
    "docker_open",
    "docker_close",
    "sequence_open",
    "sequence_close",
    "falco_start",
    "falco_stop",
    "falco_lease",
    "generic_open",
    "generic_close",
    "observer_pressure_recovered",
    "docker_logging_degraded",
]
_CoverageScope = Literal["process", "host"]


@dataclass(frozen=True, slots=True)
class _CoverageClassification:
    action: _CoverageAction
    scope: _CoverageScope | None = None
    counter_required: bool = False
    opened_at_ns: int | None = None
    closed_at_ns: int | None = None


@dataclass(frozen=True, slots=True)
class _HistoricalCoverageWindow:
    window_start: str | None
    window_end: str
    window_start_ns: int | None
    window_end_ns: int
    complete: bool


_IGNORE = _CoverageClassification("ignore")

_FALCO_OPEN_REASONS: dict[str, frozenset[str]] = {
    "falco_parse_rejection": frozenset({"invalid_falco_body"}),
    "falco_queue_drop": frozenset({"routine_capacity_exceeded"}),
    "falco_delivery_failure": frozenset({"observer_delivery_failed"}),
    "falco_heartbeat_gap": frozenset(
        {"awaiting_initial_heartbeat", "falco_heartbeat_timeout"}
    ),
    "falco_configuration_mismatch": frozenset(
        {
            "falco_version_mismatch",
            "falco_engine_mismatch",
            "falco_config_hash_mismatch",
            "falco_rules_hash_mismatch",
            "falco_counter_rollback",
        }
    ),
    "falco_kernel_event_drop": frozenset(
        {"falco_kernel_drop_counter_increase"}
    ),
    "falco_outputs_queue_drop": frozenset(
        {"falco_outputs_queue_counter_increase"}
    ),
}
_FALCO_CLOSE_REASONS = {
    "falco_parse_rejection": "valid_heartbeat_recovered",
    "falco_queue_drop": "routine_queue_recovered",
    "falco_delivery_failure": "observer_delivery_recovered",
    "falco_heartbeat_gap": "recovered",
    "falco_configuration_mismatch": "recovered",
    "falco_kernel_event_drop": "recovered",
    "falco_outputs_queue_drop": "recovered",
}
_FALCO_COUNTED_KINDS = frozenset(
    {
        "falco_parse_rejection",
        "falco_queue_drop",
        "falco_kernel_event_drop",
        "falco_outputs_queue_drop",
    }
)


def _format_rfc3339nano_utc_ns(value: int) -> str:
    """Render an exact in-range Unix nanosecond value without floating point."""
    if type(value) is not int:
        raise TypeError("timestamp nanoseconds must be an exact integer")
    if not _MIN_TIMESTAMP_NS <= value <= _MAX_TIMESTAMP_NS:
        raise ValueError("timestamp nanoseconds are outside years 0001..9999")
    seconds, nanosecond = divmod(value, _NANOSECONDS_PER_SECOND)
    days, second_of_day = divmod(seconds, _SECONDS_PER_DAY)
    calendar = date.fromordinal(days + _UNIX_EPOCH_ORDINAL)
    hour, remainder = divmod(second_of_day, 3_600)
    minute, second = divmod(remainder, 60)
    rendered = (
        f"{calendar.year:04d}-{calendar.month:02d}-{calendar.day:02d}"
        f"T{hour:02d}:{minute:02d}:{second:02d}"
    )
    if nanosecond:
        rendered += "." + f"{nanosecond:09d}".rstrip("0")
    return rendered + "Z"


def _historical_coverage_window(
    trigger_event_time: str,
    clock_uncertainty_ms: int,
    decision_time: str,
) -> _HistoricalCoverageWindow:
    if (
        type(clock_uncertainty_ms) is not int
        or not 0 <= clock_uncertainty_ms <= 2_000
    ):
        raise ValueError("clock uncertainty must be exact milliseconds")
    trigger_ns = parse_rfc3339nano_utc_ns(trigger_event_time)
    window_end_ns = parse_rfc3339nano_utc_ns(decision_time)
    window_start_ns = trigger_ns - clock_uncertainty_ms * 1_000_000
    if window_start_ns < _MIN_TIMESTAMP_NS:
        return _HistoricalCoverageWindow(
            window_start=None,
            window_end=decision_time,
            window_start_ns=None,
            window_end_ns=window_end_ns,
            complete=False,
        )
    window_start = _format_rfc3339nano_utc_ns(window_start_ns)
    return _HistoricalCoverageWindow(
        window_start=window_start,
        window_end=decision_time,
        window_start_ns=window_start_ns,
        window_end_ns=window_end_ns,
        complete=window_end_ns >= window_start_ns,
    )


def _interval_intersects_window(
    opened_at: str,
    closed_at: str | None,
    window: _HistoricalCoverageWindow,
) -> bool:
    if type(window) is not _HistoricalCoverageWindow:
        raise TypeError("coverage intersection requires an exact historical window")
    if not window.complete or window.window_start_ns is None:
        return False
    opened_at_ns = parse_rfc3339nano_utc_ns(opened_at)
    closed_at_ns = (
        None
        if closed_at is None
        else parse_rfc3339nano_utc_ns(closed_at)
    )
    if closed_at_ns is not None and closed_at_ns < opened_at_ns:
        raise ValueError("coverage interval is reversed")
    return opened_at_ns <= window.window_end_ns and (
        closed_at_ns is None or closed_at_ns >= window.window_start_ns
    )


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


def _coverage_context_is_empty(envelope: EventEnvelopeV1) -> bool:
    return (
        envelope.container_id is None
        and envelope.container_start_time is None
        and envelope.release_id is None
        and envelope.inventory_revision is None
        and envelope.redaction_flags == []
    )


def _classify_boot_or_start(envelope: EventEnvelopeV1) -> _CoverageClassification | None:
    try:
        if envelope.event_type == "observer_boot_boundary":
            ObserverBootBoundaryV1.model_validate(
                envelope.normalized_fields,
                strict=True,
            )
            if (
                envelope.coverage_flags
                != ["boot_transition", "reconcile_required"]
                or not _empty_security_context(envelope)
            ):
                raise ValueError("boot transition context is invalid")
            return _CoverageClassification("boot_boundary")
        if envelope.event_type == "observer_key_transition":
            KeyTransitionV1.model_validate(envelope.normalized_fields, strict=True)
            if envelope.coverage_flags not in (
                ["key_rotation"],
                ["boot_transition", "key_rotation"],
            ) or not _empty_security_context(envelope):
                raise ValueError("key transition context is invalid")
            return _CoverageClassification("key_transition")
        if envelope.event_type == "observer_key_epoch_start":
            if (
                set(envelope.normalized_fields) != {"kind", "key_id", "key_epoch"}
                or envelope.normalized_fields.get("kind")
                != "observer_key_epoch_start"
                or envelope.normalized_fields.get("key_id") != envelope.key_id
                or envelope.normalized_fields.get("key_epoch") != envelope.key_epoch
                or envelope.coverage_flags
                not in (["key_rotation"], ["boot_transition", "key_rotation"])
                or not _empty_security_context(envelope)
            ):
                raise ValueError("key epoch-start context is invalid")
            return _CoverageClassification("key_transition")
        if envelope.event_type == "observer_start":
            if (
                envelope.normalized_fields
                != {"kind": "observer_start", "reconcile_required": True}
                or envelope.coverage_flags != ["reconcile_required"]
                or not _empty_security_context(envelope)
            ):
                raise ValueError("observer-start form is invalid")
            return _CoverageClassification("observer_start")
    except (TypeError, ValidationError) as error:
        raise ValueError("coverage boundary form is invalid") from error
    return None


def _classify_docker(
    envelope: EventEnvelopeV1,
    coverage: CoverageEventV1,
) -> _CoverageClassification | None:
    if coverage.kind not in {
        "docker_reconcile_gap",
        "docker_reconcile_recovered",
    }:
        return None
    generation = coverage.reconcile_generation
    common = (
        coverage.component == "observer"
        and generation is not None
        and generation > 0
        and envelope.inventory_generation == generation
        and _coverage_context_is_empty(envelope)
        and envelope.coverage_flags == ["docker_event_gap", "reconcile_required"]
        and envelope.source_payload_hash == envelope.normalized_fields_sha256
    )
    if coverage.kind == "docker_reconcile_gap":
        expected_fields = {
            "component",
            "kind",
            "severity",
            "opened_at",
            "reason_code",
            "reconcile_generation",
        }
        if (
            not common
            or set(envelope.normalized_fields) != expected_fields
            or coverage.severity != "CRITICAL"
            or coverage.closed_at is not None
            or envelope.event_time != coverage.opened_at
        ):
            raise ValueError("Docker reconcile open form is invalid")
        return _CoverageClassification(
            "docker_open",
            scope="host",
            opened_at_ns=parse_rfc3339nano_utc_ns(coverage.opened_at),
        )
    expected_fields = {
        "component",
        "kind",
        "severity",
        "opened_at",
        "closed_at",
        "reason_code",
        "reconcile_generation",
    }
    closed_at = coverage.closed_at
    if (
        not common
        or set(envelope.normalized_fields) != expected_fields
        or coverage.severity != "INFO"
        or coverage.reason_code != "docker_full_reconcile_succeeded"
        or closed_at is None
        or envelope.event_time != closed_at
    ):
        raise ValueError("Docker reconcile recovery form is invalid")
    opened_at_ns = parse_rfc3339nano_utc_ns(coverage.opened_at)
    closed_at_ns = parse_rfc3339nano_utc_ns(closed_at)
    if closed_at_ns < opened_at_ns:
        raise ValueError("Docker reconcile recovery form is invalid")
    return _CoverageClassification(
        "docker_close",
        scope="host",
        opened_at_ns=opened_at_ns,
        closed_at_ns=closed_at_ns,
    )


def _classify_sequence(
    envelope: EventEnvelopeV1,
    coverage: CoverageEventV1,
) -> _CoverageClassification | None:
    if coverage.kind != "observer_sequence_gap":
        return None
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
    if (
        common
        and set(envelope.normalized_fields) == open_fields
        and coverage.severity == "CRITICAL"
        and coverage.reason_code == "reserved_sequence_not_published"
        and coverage.closed_at is None
        and coverage.reconcile_generation is None
        and envelope.event_time == coverage.opened_at
        and envelope.inventory_generation == 0
    ):
        return _CoverageClassification(
            "sequence_open",
            scope="host",
            opened_at_ns=parse_rfc3339nano_utc_ns(coverage.opened_at),
        )
    closed_at = coverage.closed_at
    generation = coverage.reconcile_generation
    if (
        common
        and set(envelope.normalized_fields) == close_fields
        and coverage.severity == "INFO"
        and coverage.reason_code == "reserved_sequence_reconciled"
        and closed_at is not None
        and generation is not None
        and generation > 0
        and envelope.event_time == closed_at
        and envelope.inventory_generation == generation
    ):
        opened_at_ns = parse_rfc3339nano_utc_ns(coverage.opened_at)
        closed_at_ns = parse_rfc3339nano_utc_ns(closed_at)
        if closed_at_ns < opened_at_ns:
            raise ValueError("sequence-gap coverage form is invalid")
        return _CoverageClassification(
            "sequence_close",
            scope="host",
            opened_at_ns=opened_at_ns,
            closed_at_ns=closed_at_ns,
        )
    raise ValueError("sequence-gap coverage form is invalid")


def _classify_falco_point(
    envelope: EventEnvelopeV1,
    coverage: CoverageEventV1,
) -> _CoverageClassification | None:
    expected: dict[str, tuple[str, str, _CoverageAction]] = {
        "falco_adapter_start": ("INFO", "adapter_started", "falco_start"),
        "falco_adapter_stop": ("CRITICAL", "adapter_stopping", "falco_stop"),
        "falco_heartbeat_lease": ("INFO", "valid_heartbeat", "falco_lease"),
    }
    selected = expected.get(coverage.kind)
    if selected is None:
        return None
    severity, reason, action = selected
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
        or (coverage.severity, coverage.reason_code) != (severity, reason)
        or coverage.closed_at != coverage.opened_at
        or envelope.event_time != coverage.opened_at
        or not _coverage_context_is_empty(envelope)
        or envelope.coverage_flags != []
    ):
        raise ValueError("Falco lifecycle coverage form is invalid")
    point_ns = parse_rfc3339nano_utc_ns(coverage.opened_at)
    return _CoverageClassification(
        action,
        scope="process",
        opened_at_ns=point_ns,
        closed_at_ns=point_ns,
    )


def _classify_falco_generic(
    envelope: EventEnvelopeV1,
    coverage: CoverageEventV1,
) -> _CoverageClassification | None:
    open_reasons = _FALCO_OPEN_REASONS.get(coverage.kind)
    if coverage.component != "falco-adapter" or open_reasons is None:
        return None
    closed_at = coverage.closed_at
    counted = coverage.kind in _FALCO_COUNTED_KINDS
    expected_fields = {
        "component",
        "kind",
        "severity",
        "opened_at",
        "reason_code",
    }
    if counted:
        expected_fields.add("dropped_count")
    if closed_at is not None:
        expected_fields.add("closed_at")
    valid_counter = (
        coverage.dropped_count is not None and coverage.dropped_count > 0
        if counted
        else coverage.dropped_count is None
    )
    expected_reason = (
        coverage.reason_code in open_reasons
        if closed_at is None
        else coverage.reason_code == _FALCO_CLOSE_REASONS[coverage.kind]
    )
    expected_flags = [coverage.kind] if closed_at is None else []
    expected_time = coverage.opened_at if closed_at is None else closed_at
    if (
        set(envelope.normalized_fields) != expected_fields
        or coverage.severity != "CRITICAL"
        or not valid_counter
        or not expected_reason
        or envelope.event_time != expected_time
        or not _coverage_context_is_empty(envelope)
        or envelope.coverage_flags != expected_flags
    ):
        raise ValueError("Falco adapter coverage form is invalid")
    opened_at_ns = parse_rfc3339nano_utc_ns(coverage.opened_at)
    closed_at_ns = (
        None
        if closed_at is None
        else parse_rfc3339nano_utc_ns(closed_at)
    )
    if closed_at_ns is not None and closed_at_ns < opened_at_ns:
        raise ValueError("Falco adapter coverage form is invalid")
    return _CoverageClassification(
        "generic_open" if closed_at is None else "generic_close",
        scope="process",
        counter_required=counted,
        opened_at_ns=opened_at_ns,
        closed_at_ns=closed_at_ns,
    )


def _classify_observer_specific(
    envelope: EventEnvelopeV1,
    coverage: CoverageEventV1,
) -> _CoverageClassification | None:
    fields = envelope.normalized_fields
    if coverage.kind == "observer_spool_drop":
        if (
            set(fields)
            != {
                "component",
                "kind",
                "severity",
                "opened_at",
                "dropped_count",
                "reason_code",
            }
            or coverage.component != "observer"
            or coverage.severity != "CRITICAL"
            or coverage.closed_at is not None
            or coverage.dropped_count != 1
            or coverage.reason_code != "routine_spool_quota"
            or envelope.event_time != coverage.opened_at
            or envelope.inventory_generation != 0
            or not _coverage_context_is_empty(envelope)
            or envelope.coverage_flags != ["storage_pressure"]
            or envelope.source_payload_hash != envelope.normalized_fields_sha256
        ):
            raise ValueError("observer spool-loss coverage form is invalid")
        return _CoverageClassification(
            "generic_open",
            scope="host",
            counter_required=True,
            opened_at_ns=parse_rfc3339nano_utc_ns(coverage.opened_at),
        )
    if coverage.kind == "observer_spool_drop_recovered":
        if (
            set(fields)
            != {
                "component",
                "kind",
                "severity",
                "opened_at",
                "closed_at",
                "dropped_count",
                "reason_code",
            }
            or coverage.component != "observer"
            or coverage.severity != "INFO"
            or coverage.closed_at != coverage.opened_at
            or coverage.dropped_count is None
            or coverage.dropped_count <= 0
            or coverage.reason_code != "routine_spool_recovered"
            or envelope.event_time != coverage.opened_at
            or envelope.inventory_generation != 0
            or not _coverage_context_is_empty(envelope)
            or envelope.coverage_flags != ["storage_pressure"]
            or envelope.source_payload_hash != envelope.normalized_fields_sha256
        ):
            raise ValueError("observer spool recovery coverage form is invalid")
        point_ns = parse_rfc3339nano_utc_ns(coverage.opened_at)
        return _CoverageClassification(
            "observer_pressure_recovered",
            scope="host",
            counter_required=True,
            opened_at_ns=point_ns,
            closed_at_ns=point_ns,
        )
    if coverage.kind == "docker_logging_visibility_degraded":
        generation = coverage.reconcile_generation
        if (
            set(fields)
            != {
                "component",
                "kind",
                "severity",
                "opened_at",
                "reason_code",
                "reconcile_generation",
            }
            or coverage.component != "observer"
            or coverage.severity != "WARNING"
            or coverage.closed_at is not None
            or coverage.reason_code != "docker_logging_unavailable"
            or generation is None
            or generation <= 0
            or envelope.inventory_generation != generation
            or envelope.event_time != coverage.opened_at
            or not _coverage_context_is_empty(envelope)
            or envelope.coverage_flags != ["docker_logging_unavailable"]
            or envelope.source_payload_hash != envelope.normalized_fields_sha256
        ):
            raise ValueError("Docker logging coverage form is invalid")
        return _CoverageClassification(
            "docker_logging_degraded",
            scope="host",
            opened_at_ns=parse_rfc3339nano_utc_ns(coverage.opened_at),
        )
    return None


def _classify_coverage_record(
    envelope: EventEnvelopeV1,
    coverage: CoverageEventV1 | None,
) -> _CoverageClassification:
    """Classify one exact decoded envelope through the closed coverage grammar."""
    if type(envelope) is not EventEnvelopeV1:
        raise TypeError("coverage grammar requires an exact EventEnvelopeV1")
    boundary = _classify_boot_or_start(envelope)
    if boundary is not None:
        if coverage is not None:
            raise ValueError("non-coverage boundary carries coverage fields")
        return boundary
    if envelope.event_type != "coverage":
        if coverage is not None:
            raise ValueError("non-coverage envelope carries coverage fields")
        return _IGNORE
    if type(coverage) is not CoverageEventV1:
        raise ValueError("coverage event has no exact typed fields")
    if coverage.model_dump(exclude_none=True) != envelope.normalized_fields:
        raise ValueError("typed coverage fields differ from their envelope")
    for classifier in (
        _classify_docker,
        _classify_sequence,
        _classify_falco_point,
        _classify_falco_generic,
        _classify_observer_specific,
    ):
        selected = classifier(envelope, coverage)
        if selected is not None:
            return selected
    raise ValueError("unsupported coverage form")


__all__: list[str] = []
