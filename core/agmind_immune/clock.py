"""Strict injected clock values for Core mutation decisions."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Protocol


class CoreClockError(RuntimeError):
    """Base class for Core decision-clock failures."""


class CoreClockValidationError(CoreClockError):
    """A clock sample is not an exact safe runtime value."""


@dataclass(frozen=True)
class CoreClockSample:
    decision_utc: datetime
    decision_monotonic: float
    healthy: bool
    uncertainty_seconds: Decimal | None
    max_uncertainty_seconds: Decimal

    def __post_init__(self) -> None:
        _validate_core_clock_sample(self)


def _validate_core_clock_sample(sample: CoreClockSample) -> None:
    decision_utc = sample.decision_utc
    if type(decision_utc) is not datetime:
        raise CoreClockValidationError("decision UTC is not an exact datetime")
    try:
        exact_utc = (
            decision_utc.tzinfo == UTC
            and decision_utc.utcoffset() == timedelta(0)
            and decision_utc.fold == 0
        )
    except Exception as error:
        raise CoreClockValidationError("decision UTC validation failed") from error
    if not exact_utc:
        raise CoreClockValidationError("decision UTC is not exact canonical UTC")
    if (
        type(sample.decision_monotonic) is not float
        or not math.isfinite(sample.decision_monotonic)
        or sample.decision_monotonic < 0
    ):
        raise CoreClockValidationError("decision monotonic is invalid")
    if type(sample.healthy) is not bool:
        raise CoreClockValidationError("clock health is not exact bool")
    uncertainty = sample.uncertainty_seconds
    if uncertainty is not None and (
        type(uncertainty) is not Decimal
        or not uncertainty.is_finite()
        or uncertainty < 0
    ):
        raise CoreClockValidationError("clock uncertainty is invalid")
    maximum = sample.max_uncertainty_seconds
    if (
        type(maximum) is not Decimal
        or not maximum.is_finite()
        or maximum < 0
    ):
        raise CoreClockValidationError("maximum clock uncertainty is invalid")


class CoreClockProvider(Protocol):
    def live_receipt_monotonic(self) -> float | None: ...

    def decision_sample(self) -> CoreClockSample: ...
