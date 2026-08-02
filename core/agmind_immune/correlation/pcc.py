"""Pure fail-closed correlation over post-commit PCC authority."""

from __future__ import annotations

import ipaddress
import re
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Literal, Never, SupportsIndex, cast

from agmind_immune.canonicaljson import (
    candidate_id,
    canonical_json,
    incident_id,
)
from agmind_immune.contracts import (
    MAX_UINT64,
    PCCCorrelationSnapshotV1,
    PCCFalcoTriggerProjectionV1,
)
from agmind_immune.correlation.primitives import (
    ParsedSpecialUseRegistry,
    SpecialUseEntry,
    SpecialUseRegistry,
    parse_rfc3339nano_utc_ns,
    special_use_registry_is_issued,
)
from agmind_immune.incidents.models import (
    ContainmentCandidateV1,
    CorrelationReasonCode,
    IncidentV1,
)
from agmind_immune.ingest.envelope import (
    AuthenticatedFalcoInput,
    AuthenticatedPCCInput,
    authenticated_falco_input_is_issued,
    authenticated_pcc_input_is_issued,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_CANDIDATE_ID = re.compile(r"^cand_[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_MAX_TRIGGER_AGE_NS = 30 * 1_000_000_000
_MAX_INVENTORY_AGE_NS = 10 * 1_000_000_000
_COOLDOWN_NS = 10 * 60 * 1_000_000_000
_TERMINAL_STATES = frozenset(
    {
        "VERIFIED",
        "EXPIRED",
        "STALE_ABORT",
        "REJECTED",
        "FAILED_DIRTY",
        "EXPIRED_UNAPPLIED",
    }
)
type TerminalState = Literal[
    "VERIFIED",
    "EXPIRED",
    "STALE_ABORT",
    "REJECTED",
    "FAILED_DIRTY",
    "EXPIRED_UNAPPLIED",
]


class CorrelationProjectionError(RuntimeError):
    """Authenticated projection state contradicts source-order authority."""


def _exact_string(value: object, field: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field} must be an exact string")
    return value


def _exact_hex64(value: object, field: str) -> str:
    text = _exact_string(value, field)
    if _HEX64.fullmatch(text) is None:
        raise ValueError(f"{field} must be 64 lowercase hex")
    return text


def _exact_event_id(value: object, field: str) -> str:
    text = _exact_string(value, field)
    if _EVENT_ID.fullmatch(text) is None:
        raise ValueError(f"{field} must be an exact event ID")
    return text


def _exact_candidate_id(value: object, field: str) -> str:
    text = _exact_string(value, field)
    if _CANDIDATE_ID.fullmatch(text) is None:
        raise ValueError(f"{field} must be an exact candidate ID")
    return text


def _exact_uuid4(value: object, field: str) -> str:
    text = _exact_string(value, field)
    if _UUID4.fullmatch(text) is None:
        raise ValueError(f"{field} must be a lowercase UUIDv4")
    return text


def _exact_sequence(value: object, field: str) -> int:
    if (
        type(value) is not int
        or not 1 <= value <= MAX_UINT64
    ):
        raise ValueError(f"{field} must be an exact positive uint64")
    return value


@dataclass(frozen=True, slots=True)
class CandidateDuplicateKey:
    host_id: str
    boot_id: str
    docker_container_id: str
    docker_started_at: str
    detector_bundle_sha256: str
    destination_ipv4: str

    def __post_init__(self) -> None:
        _exact_uuid4(self.host_id, "host_id")
        _exact_uuid4(self.boot_id, "boot_id")
        _exact_hex64(self.docker_container_id, "docker_container_id")
        parse_rfc3339nano_utc_ns(self.docker_started_at)
        _exact_hex64(
            self.detector_bundle_sha256,
            "detector_bundle_sha256",
        )
        address = ipaddress.ip_address(self.destination_ipv4)
        if (
            type(address) is not ipaddress.IPv4Address
            or str(address) != self.destination_ipv4
        ):
            raise ValueError(
                "destination_ipv4 must be canonical dotted decimal"
            )


@dataclass(frozen=True, slots=True)
class HistoricalCoverageAssessment:
    host_id: str
    boot_id: str
    trigger_event_id: str
    trigger_source_sequence: int
    coverage_through_sequence: int
    window_start: str | None
    window_end: str
    complete: bool
    critical_gap: bool
    coverage_snapshot_sha256: str | None

    def __post_init__(self) -> None:
        _exact_uuid4(self.host_id, "host_id")
        _exact_uuid4(self.boot_id, "boot_id")
        _exact_event_id(self.trigger_event_id, "trigger_event_id")
        _exact_sequence(
            self.trigger_source_sequence,
            "trigger_source_sequence",
        )
        _exact_sequence(
            self.coverage_through_sequence,
            "coverage_through_sequence",
        )
        window_start_ns = (
            None
            if self.window_start is None
            else parse_rfc3339nano_utc_ns(self.window_start)
        )
        window_end_ns = parse_rfc3339nano_utc_ns(self.window_end)
        if type(self.complete) is not bool:
            raise TypeError("complete must be an exact Boolean")
        if type(self.critical_gap) is not bool:
            raise TypeError("critical_gap must be an exact Boolean")
        if self.window_start is None and self.complete:
            raise ValueError("complete coverage requires a representable window start")
        if self.complete and window_start_ns is not None and window_end_ns < window_start_ns:
            raise ValueError("coverage window is reversed")
        if self.complete:
            _exact_hex64(
                self.coverage_snapshot_sha256,
                "coverage_snapshot_sha256",
            )
        else:
            if self.critical_gap:
                raise ValueError("incomplete coverage cannot report a critical gap")
            if self.coverage_snapshot_sha256 is not None:
                raise ValueError(
                    "incomplete coverage cannot carry an authority hash"
                )


@dataclass(frozen=True, slots=True)
class ActiveCandidateObservation:
    key: CandidateDuplicateKey
    candidate_id: str
    primary_source_sequence: int
    primary_event_id: str

    def __post_init__(self) -> None:
        if type(self.key) is not CandidateDuplicateKey:
            raise TypeError("active candidate key is not exact")
        _exact_candidate_id(self.candidate_id, "candidate_id")
        _exact_sequence(
            self.primary_source_sequence,
            "primary_source_sequence",
        )
        _exact_event_id(self.primary_event_id, "primary_event_id")


@dataclass(frozen=True, slots=True)
class TerminalCandidateObservation:
    key: CandidateDuplicateKey
    candidate_id: str
    state: TerminalState
    terminal_at: str

    def __post_init__(self) -> None:
        if type(self.key) is not CandidateDuplicateKey:
            raise TypeError("terminal candidate key is not exact")
        _exact_candidate_id(self.candidate_id, "candidate_id")
        if type(self.state) is not str or self.state not in _TERMINAL_STATES:
            raise ValueError("terminal candidate state is not closed")
        parse_rfc3339nano_utc_ns(self.terminal_at)


@dataclass(frozen=True, slots=True, init=False, weakref_slot=True)
class CorrelationContext:
    _authority_kind: Literal["raw", "failed_only"]
    pinned_detector_bundle_sha256: str | None
    special_use_registry: SpecialUseRegistry | None
    coverage: HistoricalCoverageAssessment | None
    lookup_key: CandidateDuplicateKey | None
    active_duplicate: ActiveCandidateObservation | None
    terminal_observation: TerminalCandidateObservation | None

    def __init__(
        self,
        *,
        pinned_detector_bundle_sha256: str | None = None,
        special_use_registry: SpecialUseRegistry | None = None,
        coverage: HistoricalCoverageAssessment | None = None,
        lookup_key: CandidateDuplicateKey | None = None,
        active_duplicate: ActiveCandidateObservation | None = None,
        terminal_observation: TerminalCandidateObservation | None = None,
    ) -> None:
        _exact_hex64(
            pinned_detector_bundle_sha256,
            "pinned_detector_bundle_sha256",
        )
        if (
            type(special_use_registry) is not SpecialUseRegistry
            or not special_use_registry_is_issued(special_use_registry)
        ):
            raise TypeError(
                "correlation requires fixed-loader special-use authority"
            )
        if type(coverage) is not HistoricalCoverageAssessment:
            raise TypeError(
                "historical coverage assessment is not exact"
            )
        if type(lookup_key) is not CandidateDuplicateKey:
            raise TypeError("candidate lookup key is not exact")
        if (
            active_duplicate is not None
            and type(active_duplicate)
            is not ActiveCandidateObservation
        ):
            raise TypeError(
                "active duplicate observation is not exact"
            )
        if (
            terminal_observation is not None
            and type(terminal_observation)
            is not TerminalCandidateObservation
        ):
            raise TypeError("terminal observation is not exact")
        object.__setattr__(self, "_authority_kind", "raw")
        object.__setattr__(
            self,
            "pinned_detector_bundle_sha256",
            pinned_detector_bundle_sha256,
        )
        object.__setattr__(
            self,
            "special_use_registry",
            special_use_registry,
        )
        object.__setattr__(self, "coverage", coverage)
        object.__setattr__(self, "lookup_key", lookup_key)
        object.__setattr__(
            self,
            "active_duplicate",
            active_duplicate,
        )
        object.__setattr__(
            self,
            "terminal_observation",
            terminal_observation,
        )

    @classmethod
    def failed_snapshot(cls) -> CorrelationContext:
        """Return the authority-free context valid only for failed PCCs."""
        context = object.__new__(cls)
        object.__setattr__(context, "_authority_kind", "failed_only")
        object.__setattr__(context, "pinned_detector_bundle_sha256", None)
        object.__setattr__(context, "special_use_registry", None)
        object.__setattr__(context, "coverage", None)
        object.__setattr__(context, "lookup_key", None)
        object.__setattr__(context, "active_duplicate", None)
        object.__setattr__(context, "terminal_observation", None)
        return context

    def __copy__(self) -> Never:
        raise TypeError("correlation contexts cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        del memo
        raise TypeError("correlation contexts cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("correlation contexts cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("correlation contexts cannot be serialized")


@dataclass(frozen=True, slots=True)
class CandidateCreated:
    incident: IncidentV1
    candidate: ContainmentCandidateV1

    def __post_init__(self) -> None:
        if (
            type(self.incident) is not IncidentV1
            or type(self.candidate) is not ContainmentCandidateV1
            or self.incident.incident_id != self.candidate.incident_id
            or self.incident.reason_codes
        ):
            raise TypeError("candidate result facts are not exact")


@dataclass(frozen=True, slots=True)
class InvestigationOnly:
    incident: IncidentV1
    reason_codes: tuple[CorrelationReasonCode, ...]

    def __post_init__(self) -> None:
        if (
            type(self.incident) is not IncidentV1
            or type(self.reason_codes) is not tuple
            or self.incident.reason_codes != self.reason_codes
        ):
            raise TypeError("investigation result facts are not exact")


@dataclass(frozen=True, slots=True)
class Duplicate:
    incident: IncidentV1
    existing_candidate_id: str

    def __post_init__(self) -> None:
        if type(self.incident) is not IncidentV1:
            raise TypeError("duplicate incident is not exact")
        _exact_candidate_id(
            self.existing_candidate_id,
            "existing_candidate_id",
        )
        if self.incident.reason_codes:
            raise ValueError("duplicate incident cannot carry rejection reasons")


@dataclass(frozen=True, slots=True)
class Rejected:
    incident: IncidentV1
    reason_codes: tuple[CorrelationReasonCode, ...]

    def __post_init__(self) -> None:
        if (
            type(self.incident) is not IncidentV1
            or type(self.reason_codes) is not tuple
            or not self.reason_codes
            or self.incident.reason_codes != self.reason_codes
        ):
            raise TypeError("rejected result facts are not exact")


type CorrelationResult = (
    CandidateCreated | InvestigationOnly | Duplicate | Rejected
)


type _AuthorityEvaluator = Callable[[Callable[[], object]], object]
type _PCCFactsFingerprint = tuple[object, ...]
type _ContextFactsFingerprint = tuple[object, ...]


def _evidence_ref_fingerprint(value: object) -> tuple[object, ...]:
    return (
        type(value),
        value.segment_id,  # type: ignore[attr-defined]
        value.segment_relative_path,  # type: ignore[attr-defined]
        value.frame_offset,  # type: ignore[attr-defined]
        value.frame_size,  # type: ignore[attr-defined]
        value.frame_sha256,  # type: ignore[attr-defined]
        value.event_id,  # type: ignore[attr-defined]
        value.source_sequence,  # type: ignore[attr-defined]
        value.content_sha256,  # type: ignore[attr-defined]
    )


def _pcc_canonical_facts(
    value: AuthenticatedPCCInput,
) -> _PCCFactsFingerprint:
    request = value.request
    snapshot = value.snapshot
    return (
        value.boot_id,
        value.canonical,
        value.content_sha256,
        value.event_id,
        value.event_type,
        value.host_id,
        value.source_sequence,
        _evidence_ref_fingerprint(value.evidence_ref),
        canonical_json(request),
        frozenset(request.model_fields_set),
        canonical_json(snapshot),
        frozenset(snapshot.model_fields_set),
    )


def _pcc_live_fingerprint(
    value: object,
) -> _PCCFactsFingerprint | None:
    if type(value) is not AuthenticatedPCCInput:
        return None
    try:
        request = value.request
        snapshot = value.snapshot
        return (
            id(value.evidence_ref),
            id(request),
            id(snapshot),
            id(snapshot.trigger),
            *_pcc_canonical_facts(value),
        )
    except (
        AttributeError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        return None


def _key_fingerprint(value: CandidateDuplicateKey | None) -> tuple[object, ...]:
    if value is None:
        return (None,)
    return (
        id(value),
        value.host_id,
        value.boot_id,
        value.docker_container_id,
        value.docker_started_at,
        value.detector_bundle_sha256,
        value.destination_ipv4,
    )


def _coverage_fingerprint(
    value: HistoricalCoverageAssessment | None,
) -> tuple[object, ...]:
    if value is None:
        return (None,)
    return (
        id(value),
        value.host_id,
        value.boot_id,
        value.trigger_event_id,
        value.trigger_source_sequence,
        value.coverage_through_sequence,
        value.window_start,
        value.window_end,
        value.complete,
        value.critical_gap,
        value.coverage_snapshot_sha256,
    )


def _active_fingerprint(
    value: ActiveCandidateObservation | None,
) -> tuple[object, ...]:
    if value is None:
        return (None,)
    return (
        id(value),
        *_key_fingerprint(value.key),
        value.candidate_id,
        value.primary_source_sequence,
        value.primary_event_id,
    )


def _terminal_fingerprint(
    value: TerminalCandidateObservation | None,
) -> tuple[object, ...]:
    if value is None:
        return (None,)
    return (
        id(value),
        *_key_fingerprint(value.key),
        value.candidate_id,
        value.state,
        value.terminal_at,
    )


def _context_live_fingerprint(
    value: object,
) -> _ContextFactsFingerprint | None:
    if type(value) is not CorrelationContext:
        return None
    try:
        registry = value.special_use_registry
        return (
            value._authority_kind,
            value.pinned_detector_bundle_sha256,
            None if registry is None else id(registry),
            *_coverage_fingerprint(value.coverage),
            *_key_fingerprint(value.lookup_key),
            *_active_fingerprint(value.active_duplicate),
            *_terminal_fingerprint(value.terminal_observation),
        )
    except (AttributeError, RecursionError, TypeError, ValueError):
        return None


def _key_semantic_fingerprint(
    value: CandidateDuplicateKey | None,
) -> tuple[object, ...]:
    if value is None:
        return (None,)
    return (
        value.host_id,
        value.boot_id,
        value.docker_container_id,
        value.docker_started_at,
        value.detector_bundle_sha256,
        value.destination_ipv4,
    )


def _registry_semantic_fingerprint(
    value: SpecialUseRegistry | None,
) -> tuple[object, ...]:
    if value is None:
        return (None,)
    if type(value.entries) is not tuple or type(value._index) is not tuple:
        raise TypeError("correlation registry facts are not exact tuples")
    return (
        value.authority_sha256,
        tuple(
            (entry.prefix, entry.globally_reachable.value)
            for entry in value.entries
        ),
        tuple(
            (network, prefix, reachability.value)
            for network, prefix, reachability in value._index
        ),
    )


def _context_semantic_fingerprint(
    value: CorrelationContext,
) -> tuple[object, ...]:
    coverage = value.coverage
    active = value.active_duplicate
    terminal = value.terminal_observation
    return (
        value._authority_kind,
        value.pinned_detector_bundle_sha256,
        *_registry_semantic_fingerprint(value.special_use_registry),
        (
            None,
        )
        if coverage is None
        else (
            coverage.host_id,
            coverage.boot_id,
            coverage.trigger_event_id,
            coverage.trigger_source_sequence,
            coverage.coverage_through_sequence,
            coverage.window_start,
            coverage.window_end,
            coverage.complete,
            coverage.critical_gap,
            coverage.coverage_snapshot_sha256,
        ),
        *_key_semantic_fingerprint(value.lookup_key),
        (
            None,
        )
        if active is None
        else (
            *_key_semantic_fingerprint(active.key),
            active.candidate_id,
            active.primary_source_sequence,
            active.primary_event_id,
        ),
        (
            None,
        )
        if terminal is None
        else (
            *_key_semantic_fingerprint(terminal.key),
            terminal.candidate_id,
            terminal.state,
            terminal.terminal_at,
        ),
    )


def _clone_duplicate_key(value: CandidateDuplicateKey) -> CandidateDuplicateKey:
    return CandidateDuplicateKey(
        host_id=value.host_id,
        boot_id=value.boot_id,
        docker_container_id=value.docker_container_id,
        docker_started_at=value.docker_started_at,
        detector_bundle_sha256=value.detector_bundle_sha256,
        destination_ipv4=value.destination_ipv4,
    )


def _trusted_context(value: CorrelationContext) -> CorrelationContext:
    registry = value.special_use_registry
    coverage = value.coverage
    lookup_key = value.lookup_key
    if (
        value._authority_kind != "raw"
        or type(registry) is not SpecialUseRegistry
        or type(coverage) is not HistoricalCoverageAssessment
        or type(lookup_key) is not CandidateDuplicateKey
    ):
        raise TypeError("issued correlation context facts are incomplete")
    trusted_registry = object.__new__(SpecialUseRegistry)
    ParsedSpecialUseRegistry.__init__(
        trusted_registry,
        tuple(
            SpecialUseEntry(entry.prefix, entry.globally_reachable)
            for entry in registry.entries
        ),
    )
    trusted_coverage = HistoricalCoverageAssessment(
        host_id=coverage.host_id,
        boot_id=coverage.boot_id,
        trigger_event_id=coverage.trigger_event_id,
        trigger_source_sequence=coverage.trigger_source_sequence,
        coverage_through_sequence=coverage.coverage_through_sequence,
        window_start=coverage.window_start,
        window_end=coverage.window_end,
        complete=coverage.complete,
        critical_gap=coverage.critical_gap,
        coverage_snapshot_sha256=coverage.coverage_snapshot_sha256,
    )
    trusted_key = _clone_duplicate_key(lookup_key)
    active = value.active_duplicate
    trusted_active = (
        None
        if active is None
        else ActiveCandidateObservation(
            key=_clone_duplicate_key(active.key),
            candidate_id=active.candidate_id,
            primary_source_sequence=active.primary_source_sequence,
            primary_event_id=active.primary_event_id,
        )
    )
    terminal = value.terminal_observation
    trusted_terminal = (
        None
        if terminal is None
        else TerminalCandidateObservation(
            key=_clone_duplicate_key(terminal.key),
            candidate_id=terminal.candidate_id,
            state=terminal.state,
            terminal_at=terminal.terminal_at,
        )
    )
    trusted = object.__new__(CorrelationContext)
    object.__setattr__(trusted, "_authority_kind", "raw")
    object.__setattr__(
        trusted,
        "pinned_detector_bundle_sha256",
        value.pinned_detector_bundle_sha256,
    )
    object.__setattr__(trusted, "special_use_registry", trusted_registry)
    object.__setattr__(trusted, "coverage", trusted_coverage)
    object.__setattr__(trusted, "lookup_key", trusted_key)
    object.__setattr__(trusted, "active_duplicate", trusted_active)
    object.__setattr__(trusted, "terminal_observation", trusted_terminal)
    return trusted


@dataclass(frozen=True, slots=True)
class _ClaimedCorrelationContext:
    public_context_ref: weakref.ReferenceType[CorrelationContext]
    public_context_identity: int
    public_context_fingerprint: _ContextFactsFingerprint
    public_proof: AuthenticatedPCCInput
    public_proof_fingerprint: _PCCFactsFingerprint
    trusted_proof: AuthenticatedPCCInput
    trusted_context: CorrelationContext
    evaluator: _AuthorityEvaluator


def _correlation_context_protocol() -> tuple[
    Callable[
        [
            CorrelationContext,
            AuthenticatedPCCInput,
            AuthenticatedPCCInput,
            _AuthorityEvaluator,
        ],
        None,
    ],
    Callable[[object], _ClaimedCorrelationContext | None],
]:
    issued: dict[
        int,
        tuple[
            weakref.ReferenceType[CorrelationContext],
            _ClaimedCorrelationContext,
        ],
    ] = {}
    lock = Lock()

    def register(
        context: CorrelationContext,
        public_proof: AuthenticatedPCCInput,
        trusted_proof: AuthenticatedPCCInput,
        evaluator: _AuthorityEvaluator,
    ) -> None:
        if (
            type(context) is not CorrelationContext
            or type(public_proof) is not AuthenticatedPCCInput
            or type(trusted_proof) is not AuthenticatedPCCInput
            or public_proof is trusted_proof
            or not authenticated_pcc_input_is_issued(public_proof)
            or not authenticated_pcc_input_is_issued(trusted_proof)
            or not callable(evaluator)
        ):
            raise TypeError("correlation context registration is not exact")
        public_fingerprint = _pcc_live_fingerprint(public_proof)
        trusted_fingerprint = _pcc_live_fingerprint(trusted_proof)
        context_fingerprint = _context_live_fingerprint(context)
        try:
            semantic_before = _context_semantic_fingerprint(context)
            trusted_context = _trusted_context(context)
            semantic_after = _context_semantic_fingerprint(context)
            trusted_semantic = _context_semantic_fingerprint(trusted_context)
        except (AttributeError, RecursionError, TypeError, ValueError) as error:
            raise TypeError(
                "correlation context registration facts are not exact"
            ) from error
        if (
            public_fingerprint is None
            or trusted_fingerprint is None
            or context_fingerprint is None
            or _context_live_fingerprint(context) != context_fingerprint
            or semantic_before != semantic_after
            or semantic_before != trusted_semantic
            or _pcc_canonical_facts(public_proof)
            != _pcc_canonical_facts(trusted_proof)
        ):
            raise TypeError("correlation context registration facts changed")
        identity = id(context)
        reference: weakref.ReferenceType[CorrelationContext]
        binding = _ClaimedCorrelationContext(
            public_context_ref=weakref.ref(context),
            public_context_identity=identity,
            public_context_fingerprint=context_fingerprint,
            public_proof=public_proof,
            public_proof_fingerprint=public_fingerprint,
            trusted_proof=trusted_proof,
            trusted_context=trusted_context,
            evaluator=evaluator,
        )

        def cleanup(reference: weakref.ReferenceType[CorrelationContext]) -> None:
            with lock:
                current = issued.get(identity)
                if current is not None and current[0] is reference:
                    issued.pop(identity, None)

        reference = weakref.ref(context, cleanup)
        with lock:
            if identity in issued:
                raise TypeError("correlation context is already registered")
            issued[identity] = (reference, binding)

    def claim(value: object) -> _ClaimedCorrelationContext | None:
        if type(value) is not CorrelationContext:
            return None
        with lock:
            registered = issued.pop(id(value), None)
        if registered is None or registered[0]() is not value:
            return None
        return registered[1]

    return register, claim


(
    _register_correlation_context,
    _claim_correlation_context,
) = _correlation_context_protocol()
del _correlation_context_protocol


_CONTEXT_MISMATCH = object()


def _claimed_context_matches(
    claim: _ClaimedCorrelationContext,
    proof: object,
    context: object,
) -> bool:
    return (
        proof is claim.public_proof
        and id(context) == claim.public_context_identity
        and context is claim.public_context_ref()
        and _pcc_live_fingerprint(proof)
        == claim.public_proof_fingerprint
        and _context_live_fingerprint(context)
        == claim.public_context_fingerprint
    )


def _evaluate_claimed_context(
    claim: _ClaimedCorrelationContext,
    proof: AuthenticatedPCCInput,
    context: CorrelationContext,
) -> CorrelationResult | None:
    if not _claimed_context_matches(claim, proof, context):
        return None

    callback_invoked = False

    def evaluate_kernel() -> object:
        nonlocal callback_invoked
        if callback_invoked:
            raise CorrelationProjectionError(
                "correlation authority invoked its evaluation callback twice"
            )
        callback_invoked = True
        if not _claimed_context_matches(claim, proof, context):
            return _CONTEXT_MISMATCH
        result = _correlate_pcc_kernel(
            claim.trusted_proof,
            claim.trusted_context,
        )
        if not _claimed_context_matches(claim, proof, context):
            return _CONTEXT_MISMATCH
        return result

    result = claim.evaluator(evaluate_kernel)
    if (
        not callback_invoked
        or result is _CONTEXT_MISMATCH
        or not _claimed_context_matches(claim, proof, context)
    ):
        return None
    if type(result) not in {
        CandidateCreated,
        InvestigationOnly,
        Duplicate,
        Rejected,
    }:
        raise CorrelationProjectionError(
            "correlation authority returned an invalid evaluation result"
        )
    return cast(CorrelationResult, result)


def _incident(
    authenticated: AuthenticatedPCCInput,
    reasons: tuple[CorrelationReasonCode, ...],
) -> IncidentV1:
    trigger = authenticated.snapshot.trigger
    evidence_ids = tuple(
        sorted((trigger.event_id, authenticated.event_id))
    )
    fields: dict[str, object] = {
        "schema_version": "agmind.incident.v1",
        "incident_id": incident_id(trigger.event_id),
        "primary_event_id": trigger.event_id,
        "primary_source_sequence": trigger.source_sequence,
        "host_id": trigger.host_id,
        "boot_id": trigger.boot_id,
        "detector_rule": trigger.detector_rule,
        "detector_rule_version": trigger.detector_rule_version,
        "event_time": trigger.event_time,
        "ingest_time": trigger.ingest_time,
        "successful_connect": trigger.successful_connect,
        "investigation_only": trigger.investigation_only,
        "docker_container_id": trigger.container_id,
        "docker_started_at": trigger.container_start_time,
        "proc_name": trigger.proc_name,
        "proc_exe_path": trigger.proc_exe_path,
        "proc_parent_name": trigger.proc_parent_name,
        "destination_ipv4": trigger.destination_ipv4,
        "destination_port": trigger.destination_port,
        "l4_protocol": trigger.l4_protocol,
        "missing_required_fields": trigger.missing_required_fields,
        "coverage_flags": trigger.coverage_flags,
        "evidence_ids": evidence_ids,
        "reason_codes": reasons,
        "authority_event_id": authenticated.event_id,
    }
    return IncidentV1.model_validate(fields, strict=True)


def incident_from_verified_falco(
    authenticated: AuthenticatedFalcoInput,
) -> IncidentV1:
    """Build one trigger-only investigation incident after durable acceptance."""
    if (
        type(authenticated) is not AuthenticatedFalcoInput
        or not authenticated_falco_input_is_issued(authenticated)
    ):
        raise TypeError(
            "direct incident requires exact issued Falco authority"
        )
    falco = authenticated.falco
    if not falco.successful_connect:
        reasons: tuple[CorrelationReasonCode, ...] = (
            "connect_not_successful",
        )
    elif falco.missing_required_fields:
        reasons = ("sensor_fields_incomplete",)
    elif falco.investigation_only:
        reasons = ("investigation_only",)
    else:
        raise ValueError(
            "candidate-capable Falco success must await authenticated PCC"
        )
    fields: dict[str, object] = {
        "schema_version": "agmind.incident.v1",
        "incident_id": incident_id(authenticated.event_id),
        "primary_event_id": authenticated.event_id,
        "primary_source_sequence": authenticated.source_sequence,
        "host_id": authenticated.host_id,
        "boot_id": authenticated.boot_id,
        "detector_rule": falco.detector_rule,
        "detector_rule_version": falco.detector_rule_version,
        "event_time": authenticated.event_time,
        "ingest_time": authenticated.ingest_time,
        "successful_connect": falco.successful_connect,
        "investigation_only": falco.investigation_only,
        "missing_required_fields": tuple(falco.missing_required_fields),
        "coverage_flags": authenticated.coverage_flags,
        "evidence_ids": (authenticated.event_id,),
        "reason_codes": reasons,
        "authority_event_id": authenticated.event_id,
    }
    optional = {
        "docker_container_id": falco.docker_container_id,
        "docker_started_at": falco.docker_started_at,
        "proc_name": falco.proc_name,
        "proc_exe_path": falco.proc_exe_path,
        "proc_parent_name": falco.proc_parent_name,
        "destination_ipv4": falco.destination_ipv4,
        "destination_port": falco.destination_port,
        "l4_protocol": falco.l4_protocol,
    }
    fields.update(
        {
            name: value
            for name, value in optional.items()
            if value is not None
        }
    )
    return IncidentV1.model_validate(fields, strict=True)


def incident_from_retained_trigger(
    proof: AuthenticatedPCCInput,
) -> IncidentV1:
    """Build proof-backed incident facts from the retained trigger projection."""
    if (
        type(proof) is not AuthenticatedPCCInput
        or not authenticated_pcc_input_is_issued(proof)
    ):
        raise TypeError(
            "retained incident requires an exact issued PCC authority binding"
        )
    return _incident(proof, ())


def _rejected(
    authenticated: AuthenticatedPCCInput,
    reasons: tuple[CorrelationReasonCode, ...],
) -> Rejected:
    return Rejected(
        incident=_incident(authenticated, reasons),
        reason_codes=reasons,
    )


def _one_rejection(
    authenticated: AuthenticatedPCCInput,
    reason: CorrelationReasonCode,
) -> Rejected:
    return _rejected(authenticated, (reason,))


def _duplicate_key(
    authenticated: AuthenticatedPCCInput,
    snapshot: PCCCorrelationSnapshotV1,
) -> CandidateDuplicateKey:
    if (
        snapshot.docker_container_id is None
        or snapshot.docker_started_at is None
        or snapshot.detector_bundle_sha256 is None
    ):
        raise CorrelationProjectionError(
            "complete snapshot lost duplicate-key authority"
        )
    return CandidateDuplicateKey(
        host_id=authenticated.host_id,
        boot_id=authenticated.boot_id,
        docker_container_id=snapshot.docker_container_id,
        docker_started_at=snapshot.docker_started_at,
        detector_bundle_sha256=snapshot.detector_bundle_sha256,
        destination_ipv4=snapshot.trigger.destination_ipv4,
    )


def _address_in_denies(
    address: ipaddress.IPv4Address,
    networks: tuple[str, ...],
    addresses: tuple[str, ...],
) -> bool:
    if any(address == ipaddress.IPv4Address(value) for value in addresses):
        return True
    return any(
        address in ipaddress.IPv4Network(value, strict=True)
        for value in networks
    )


def _docker_destination(
    address: ipaddress.IPv4Address,
    snapshot: PCCCorrelationSnapshotV1,
) -> bool:
    assert snapshot.docker_networks is not None
    for network in snapshot.docker_networks:
        for raw in network.gateway_addresses:
            gateway = ipaddress.ip_address(raw)
            if (
                type(gateway) is ipaddress.IPv4Address
                and address == gateway
            ):
                return True
        for raw in network.subnet_cidrs:
            subnet = ipaddress.ip_network(raw, strict=True)
            if (
                type(subnet) is ipaddress.IPv4Network
                and address in subnet
            ):
                return True
    return False


def _configured_net_admin(values: tuple[str, ...]) -> bool:
    unsafe = {"net_admin", "cap_net_admin", "all"}
    return any(value.casefold() in unsafe for value in values)


def _coverage_binding_matches(
    authenticated: AuthenticatedPCCInput,
    coverage: HistoricalCoverageAssessment,
) -> bool:
    snapshot = authenticated.snapshot
    trigger = snapshot.trigger
    trigger_ns = parse_rfc3339nano_utc_ns(trigger.event_time)
    expected_window_start = (
        trigger_ns - trigger.clock_uncertainty_ms * 1_000_000
    )
    minimum_timestamp_ns = parse_rfc3339nano_utc_ns(
        "0001-01-01T00:00:00Z"
    )
    window_start_matches = (
        coverage.window_start is None
        and expected_window_start < minimum_timestamp_ns
    ) or (
        coverage.window_start is not None
        and parse_rfc3339nano_utc_ns(coverage.window_start)
        == expected_window_start
    )
    return (
        coverage.host_id == authenticated.host_id
        and coverage.boot_id == authenticated.boot_id
        and coverage.trigger_event_id == trigger.event_id
        and coverage.trigger_source_sequence == trigger.source_sequence
        and coverage.coverage_through_sequence
        == snapshot.coverage_through_sequence
        and window_start_matches
        and parse_rfc3339nano_utc_ns(coverage.window_end)
        == parse_rfc3339nano_utc_ns(snapshot.decision_time)
    )


def _candidate(
    authenticated: AuthenticatedPCCInput,
    coverage: HistoricalCoverageAssessment,
) -> ContainmentCandidateV1:
    snapshot = authenticated.snapshot
    trigger = snapshot.trigger
    required = (
        snapshot.detector_bundle_sha256,
        snapshot.docker_container_id,
        snapshot.docker_started_at,
        snapshot.image_id,
        snapshot.repo_digests,
        snapshot.immutable_spec_sha256,
        snapshot.inventory_generation,
        snapshot.inventory_revision,
        snapshot.docker_network_snapshot_sha256,
        snapshot.special_use_registry_sha256,
        snapshot.operator_denylist_sha256,
        snapshot.management_denylist_sha256,
        coverage.coverage_snapshot_sha256,
    )
    if any(value is None for value in required):
        raise CorrelationProjectionError(
            "candidate construction lost complete proof authority"
        )
    detector_bundle = cast(str, snapshot.detector_bundle_sha256)
    container_id = cast(str, snapshot.docker_container_id)
    started_at = cast(str, snapshot.docker_started_at)
    return ContainmentCandidateV1.model_validate(
        {
            "schema_version": "agmind.containment-candidate.v1",
            "candidate_id": candidate_id(
                trigger.event_id,
                container_id,
                started_at,
                trigger.destination_ipv4,
                detector_bundle,
            ),
            "incident_id": incident_id(trigger.event_id),
            "host_id": authenticated.host_id,
            "boot_id": authenticated.boot_id,
            "primary_event_id": trigger.event_id,
            "primary_source_sequence": trigger.source_sequence,
            "correlation_snapshot_event_id": authenticated.event_id,
            "docker_container_id": container_id,
            "docker_started_at": started_at,
            "image_id": snapshot.image_id,
            "repo_digests": snapshot.repo_digests,
            "immutable_spec_sha256": snapshot.immutable_spec_sha256,
            "inventory_generation": snapshot.inventory_generation,
            "inventory_revision": snapshot.inventory_revision,
            "destination_ipv4": trigger.destination_ipv4,
            "destination_port": trigger.destination_port,
            "l4_protocol": trigger.l4_protocol,
            "ttl_seconds": snapshot.requested_ttl_seconds,
            "detector_rule": trigger.detector_rule,
            "detector_rule_version": trigger.detector_rule_version,
            "detector_bundle_sha256": detector_bundle,
            "coverage_snapshot_sha256": (
                coverage.coverage_snapshot_sha256
            ),
            "docker_network_snapshot_sha256": (
                snapshot.docker_network_snapshot_sha256
            ),
            "special_use_registry_sha256": (
                snapshot.special_use_registry_sha256
            ),
            "operator_denylist_sha256": (
                snapshot.operator_denylist_sha256
            ),
            "management_denylist_sha256": (
                snapshot.management_denylist_sha256
            ),
            "evidence_ids": tuple(
                sorted((trigger.event_id, authenticated.event_id))
            ),
            "created_at": snapshot.decision_time,
        },
        strict=True,
    )


def _correlate_pcc_kernel(
    authenticated: AuthenticatedPCCInput,
    context: CorrelationContext,
) -> CorrelationResult:
    """Deterministic fact kernel with no public authority promotion."""
    if (
        type(authenticated) is not AuthenticatedPCCInput
        or not authenticated_pcc_input_is_issued(authenticated)
        or type(context) is not CorrelationContext
    ):
        raise TypeError(
            "correlation requires exact issued proof and context facts"
        )
    snapshot = authenticated.snapshot
    trigger = snapshot.trigger

    if snapshot.outcome == "failed":
        if snapshot.failure_reasons is None:
            raise CorrelationProjectionError(
                "failed snapshot lost exact failure reasons"
            )
        return _rejected(
            authenticated,
            cast(
                tuple[CorrelationReasonCode, ...],
                snapshot.failure_reasons,
            ),
        )

    if context._authority_kind != "raw":
        return _one_rejection(
            authenticated,
            "correlation_proof_mismatch",
        )
    if (
        snapshot.detector_bundle_sha256 is None
        or context.pinned_detector_bundle_sha256 is None
        or snapshot.detector_bundle_sha256
        != context.pinned_detector_bundle_sha256
    ):
        return _one_rejection(
            authenticated,
            "detector_bundle_not_pinned",
        )

    if not trigger.successful_connect:
        return InvestigationOnly(
            incident=_incident(
                authenticated,
                ("connect_not_successful",),
            ),
            reason_codes=("connect_not_successful",),
        )
    if trigger.missing_required_fields:
        return InvestigationOnly(
            incident=_incident(
                authenticated,
                ("sensor_fields_incomplete",),
            ),
            reason_codes=("sensor_fields_incomplete",),
        )
    if trigger.investigation_only:
        return InvestigationOnly(
            incident=_incident(
                authenticated,
                ("investigation_only",),
            ),
            reason_codes=("investigation_only",),
        )

    decision_ns = parse_rfc3339nano_utc_ns(snapshot.decision_time)
    event_age_ns = decision_ns - parse_rfc3339nano_utc_ns(
        trigger.event_time
    )
    if not 0 <= event_age_ns <= _MAX_TRIGGER_AGE_NS:
        return _one_rejection(authenticated, "event_stale")

    if snapshot.inventory_observed_at is None:
        return _one_rejection(
            authenticated,
            "authoritative_identity_incomplete",
        )
    inventory_age_ns = decision_ns - parse_rfc3339nano_utc_ns(
        snapshot.inventory_observed_at
    )
    if not 0 <= inventory_age_ns <= _MAX_INVENTORY_AGE_NS:
        return _one_rejection(authenticated, "inventory_stale")
    if trigger.clock_uncertainty_ms > 2_000:
        return _one_rejection(authenticated, "clock_uncertain")

    coverage = context.coverage
    if coverage is None or not coverage.complete:
        return _one_rejection(
            authenticated,
            "historical_coverage_incomplete",
        )
    if coverage.critical_gap:
        return _one_rejection(
            authenticated,
            "critical_coverage_gap",
        )
    if (
        not _coverage_binding_matches(authenticated, coverage)
        or coverage.coverage_snapshot_sha256 is None
    ):
        return _one_rejection(
            authenticated,
            "correlation_proof_mismatch",
        )

    expected_key = _duplicate_key(authenticated, snapshot)
    if (
        authenticated.host_id != trigger.host_id
        or authenticated.boot_id != trigger.boot_id
        or context.lookup_key != expected_key
    ):
        return _one_rejection(
            authenticated,
            "correlation_proof_mismatch",
        )

    registry = context.special_use_registry
    if registry is None:
        return _one_rejection(
            authenticated,
            "special_use_registry_unavailable",
        )
    if (
        snapshot.special_use_registry_sha256 is None
        or registry.authority_sha256
        != snapshot.special_use_registry_sha256
    ):
        return _one_rejection(
            authenticated,
            "correlation_proof_mismatch",
        )
    destination = ipaddress.IPv4Address(trigger.destination_ipv4)
    if not registry.is_globally_reachable(trigger.destination_ipv4):
        return _one_rejection(
            authenticated,
            "destination_not_public",
        )
    if _docker_destination(destination, snapshot):
        return _one_rejection(authenticated, "docker_destination")

    assert snapshot.operator_denied_networks is not None
    assert snapshot.operator_denied_addresses is not None
    if _address_in_denies(
        destination,
        snapshot.operator_denied_networks,
        snapshot.operator_denied_addresses,
    ):
        return _one_rejection(authenticated, "operator_destination")
    assert snapshot.management_denied_networks is not None
    assert snapshot.management_denied_addresses is not None
    if _address_in_denies(
        destination,
        snapshot.management_denied_networks,
        snapshot.management_denied_addresses,
    ):
        return _one_rejection(
            authenticated,
            "management_destination",
        )

    if snapshot.running is not True:
        return _one_rejection(authenticated, "target_not_running")
    if snapshot.network_mode is None:
        return _one_rejection(
            authenticated,
            "unsupported_network_mode",
        )
    network_mode = snapshot.network_mode.casefold()
    if network_mode == "container" or network_mode.startswith(
        "container:"
    ):
        return _one_rejection(
            authenticated,
            "shared_network_namespace",
        )
    if network_mode in {"host", "none"}:
        return _one_rejection(
            authenticated,
            "unsupported_network_mode",
        )
    if (
        snapshot.network_driver is None
        or snapshot.network_driver.casefold() != "bridge"
    ):
        return _one_rejection(
            authenticated,
            "unsupported_network_driver",
        )

    if snapshot.privileged is not False:
        return _one_rejection(authenticated, "privileged_target")
    assert snapshot.configured_cap_add is not None
    if (
        _configured_net_admin(snapshot.configured_cap_add)
        or snapshot.effective_cap_net_admin is not False
    ):
        return _one_rejection(
            authenticated,
            "target_cap_net_admin",
        )
    if not 30 <= snapshot.requested_ttl_seconds <= 300:
        return _one_rejection(authenticated, "ttl_out_of_bounds")

    active = context.active_duplicate
    if active is not None:
        if active.key != expected_key:
            raise CorrelationProjectionError(
                "active duplicate query returned a different key"
            )
        current_order = (
            trigger.source_sequence,
            trigger.event_id,
        )
        primary_order = (
            active.primary_source_sequence,
            active.primary_event_id,
        )
        if primary_order > current_order:
            raise CorrelationProjectionError(
                "active duplicate is ahead of authenticated source order"
            )
        expected_existing_id = candidate_id(
            active.primary_event_id,
            expected_key.docker_container_id,
            expected_key.docker_started_at,
            expected_key.destination_ipv4,
            expected_key.detector_bundle_sha256,
        )
        if active.candidate_id != expected_existing_id:
            raise CorrelationProjectionError(
                "active duplicate ID does not bind its primary evidence"
            )
        return Duplicate(
            incident=_incident(authenticated, ()),
            existing_candidate_id=active.candidate_id,
        )

    terminal = context.terminal_observation
    if terminal is not None:
        if terminal.key != expected_key:
            raise CorrelationProjectionError(
                "terminal cooldown query returned a different key"
            )
        terminal_age_ns = decision_ns - parse_rfc3339nano_utc_ns(
            terminal.terminal_at
        )
        if terminal_age_ns < _COOLDOWN_NS:
            return _one_rejection(
                authenticated,
                "candidate_cooldown",
            )

    candidate = _candidate(authenticated, coverage)
    return CandidateCreated(
        incident=_incident(authenticated, ()),
        candidate=candidate,
    )


def _validate_pcc_facts_binding(
    trigger: PCCFalcoTriggerProjectionV1,
    proof: AuthenticatedPCCInput,
    context: CorrelationContext,
) -> None:
    if (
        type(trigger) is not PCCFalcoTriggerProjectionV1
        or type(proof) is not AuthenticatedPCCInput
        or not authenticated_pcc_input_is_issued(proof)
        or type(context) is not CorrelationContext
    ):
        raise TypeError(
            "correlate_pcc_facts requires exact trigger, proof, and context"
        )
    if canonical_json(trigger) != canonical_json(proof.snapshot.trigger):
        raise ValueError(
            "trigger facts do not bind the authenticated PCC snapshot"
        )


def _correlate_pcc_facts(
    trigger: PCCFalcoTriggerProjectionV1,
    proof: AuthenticatedPCCInput,
    context: CorrelationContext,
) -> CorrelationResult:
    """Internal deterministic kernel for exact proof-bound fact rebuilds."""
    _validate_pcc_facts_binding(trigger, proof, context)
    return _correlate_pcc_kernel(proof, context)


def correlate_pcc_facts(
    trigger: PCCFalcoTriggerProjectionV1,
    proof: AuthenticatedPCCInput,
    context: CorrelationContext,
) -> CorrelationResult:
    """Evaluate proof-bound facts only under issued local context authority."""
    claimed = _claim_correlation_context(context)
    _validate_pcc_facts_binding(trigger, proof, context)
    if proof.snapshot.outcome != "complete":
        return _correlate_pcc_kernel(proof, context)
    if claimed is None:
        return _one_rejection(
            proof,
            "correlation_proof_mismatch",
        )
    result = _evaluate_claimed_context(claimed, proof, context)
    if result is None:
        return _one_rejection(
            proof,
            "correlation_proof_mismatch",
        )
    return result


def correlate_pcc(
    authenticated: AuthenticatedPCCInput,
    context: CorrelationContext,
) -> CorrelationResult:
    """Reduce only post-commit proof plus issued local context authority."""
    claimed = _claim_correlation_context(context)
    if (
        type(authenticated) is not AuthenticatedPCCInput
        or not authenticated_pcc_input_is_issued(authenticated)
        or type(context) is not CorrelationContext
    ):
        raise TypeError(
            "correlate_pcc requires exact issued authenticated input and context"
        )
    if authenticated.snapshot.outcome != "complete":
        return _correlate_pcc_kernel(authenticated, context)
    if claimed is None:
        return _one_rejection(
            authenticated,
            "correlation_proof_mismatch",
        )
    result = _evaluate_claimed_context(
        claimed,
        authenticated,
        context,
    )
    if result is None:
        return _one_rejection(
            authenticated,
            "correlation_proof_mismatch",
        )
    return result


__all__ = [
    "ActiveCandidateObservation",
    "CandidateCreated",
    "CandidateDuplicateKey",
    "CorrelationContext",
    "CorrelationProjectionError",
    "CorrelationResult",
    "Duplicate",
    "HistoricalCoverageAssessment",
    "InvestigationOnly",
    "Rejected",
    "TerminalCandidateObservation",
    "TerminalState",
    "correlate_pcc",
    "correlate_pcc_facts",
    "incident_from_retained_trigger",
    "incident_from_verified_falco",
]
