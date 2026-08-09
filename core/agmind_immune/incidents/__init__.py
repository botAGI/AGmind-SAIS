"""Immutable incident and containment-candidate facts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import (
    CORRELATION_REASON_CODES,
    ContainmentCandidateV1,
    CorrelationReasonCode,
    IncidentV1,
)

if TYPE_CHECKING:
    from .admission import (
        CandidateAdmissionError,
        CandidateAdmissionView,
        CandidateStatusObservation,
    )

__all__ = [
    "CORRELATION_REASON_CODES",
    "CandidateAdmissionError",
    "CandidateAdmissionView",
    "CandidateStatusObservation",
    "ContainmentCandidateV1",
    "CorrelationReasonCode",
    "IncidentV1",
]


def __getattr__(name: str) -> Any:
    if name in {
        "CandidateAdmissionError",
        "CandidateAdmissionView",
        "CandidateStatusObservation",
    }:
        from . import admission

        return getattr(admission, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
