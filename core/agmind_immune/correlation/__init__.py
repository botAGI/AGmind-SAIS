"""Pure, side-effect-free correlation primitives."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .pcc import (
    ActiveCandidateObservation,
    CandidateCreated,
    CandidateDuplicateKey,
    CorrelationContext,
    CorrelationProjectionError,
    CorrelationResult,
    Duplicate,
    HistoricalCoverageAssessment,
    InvestigationOnly,
    Rejected,
    TerminalCandidateObservation,
    TerminalState,
    correlate_pcc,
    correlate_pcc_facts,
    incident_from_retained_trigger,
    incident_from_verified_falco,
)
from .primitives import (
    GlobalReachability,
    SpecialUseEntry,
    SpecialUseRegistry,
    load_pinned_special_use_registry,
    parse_rfc3339nano_utc_ns,
)

if TYPE_CHECKING:
    from .authority import CorrelationProjectionAuthority

__all__ = [
    "ActiveCandidateObservation",
    "CandidateCreated",
    "CandidateDuplicateKey",
    "CorrelationContext",
    "CorrelationProjectionAuthority",
    "CorrelationProjectionError",
    "CorrelationResult",
    "Duplicate",
    "GlobalReachability",
    "HistoricalCoverageAssessment",
    "InvestigationOnly",
    "Rejected",
    "SpecialUseEntry",
    "SpecialUseRegistry",
    "TerminalCandidateObservation",
    "TerminalState",
    "correlate_pcc",
    "correlate_pcc_facts",
    "incident_from_retained_trigger",
    "incident_from_verified_falco",
    "load_pinned_special_use_registry",
    "parse_rfc3339nano_utc_ns",
]


def __getattr__(name: str) -> type[CorrelationProjectionAuthority]:
    if name == "CorrelationProjectionAuthority":
        from .authority import CorrelationProjectionAuthority

        return CorrelationProjectionAuthority
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
