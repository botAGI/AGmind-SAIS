"""Production composition root for delivery, coverage, and projection."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from typing import Literal, Never

from agmind_immune.canonicaljson import candidate_facts_sha256, canonical_json
from agmind_immune.clock import (
    CoreClockProvider,
    CoreClockSample,
    _validate_core_clock_sample,
)
from agmind_immune.contracts import (
    HEX64,
    MAX_UINT64,
    UUID4,
    RetentionBlockedV1,
    RetentionTombstoneV2,
)
from agmind_immune.correlation.primitives import (
    SpecialUseRegistry,
    special_use_registry_is_issued,
)
from agmind_immune.coverage import (
    CoverageState,
    MutationReadiness,
    MutationReadinessContext,
)
from agmind_immune.evidence.projection import (
    _CANDIDATE_ADMISSION_GATE_FACTORY,
    _RETENTION_REBUILD_FACTORY,
    ProjectionApplyResult,
    ProjectionCursor,
    ProjectionError,
    ProjectionStatus,
    ProjectionStore,
    RebuildReport,
    _CandidateAdmissionSnapshot,
)
from agmind_immune.evidence.retention import (
    AcceptedRetentionBlocked,
    RetentionProtocolError,
    RetentionStateV1,
    RetentionTargetV1,
    _open_retention_state_journal,
    _select_retention_lazily,
)
from agmind_immune.evidence.segments import (
    _RETENTION_PROOF_FACTORY,
    EvidenceRef,
    EvidenceStatus,
    EvidenceStoreError,
    SegmentStore,
    StoredEvidenceRecord,
)
from agmind_immune.incidents.admission import (
    CandidateAdmissionError,
    CandidateAdmissionView,
    _issue_candidate_admission_view,
)
from agmind_immune.incidents.models import ContainmentCandidateV1
from agmind_immune.ingest.ack_journal import (
    AckIdentity,
    AckJournal,
    AckJournalError,
    AckJournalSnapshot,
)
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import MAX_PAGE_EVENTS, EnvelopeVerifier
from agmind_immune.ingest.service import (
    _RETENTION_DELIVERY_FACTORY,
    AcceptanceCoordinator,
    DeliveryCoordinator,
    DeliveryRetryableError,
    ObserverCoreTransport,
    PollResult,
)

_CONTROLLER_FACTORY = object()
_PROJECTION_BATCH = 100

RetentionOutcome = Literal[
    "not_due",
    "blocked_unchanged",
    "retry_required",
    "blocked_reported",
    "tombstone_completed",
]
RetentionRetryReason = Literal[
    "pending_ack",
    "ack_prefix_lag",
    "observer_retryable",
]
_RetentionRequestKind = Literal["tombstone", "blocked"]
_RETENTION_OUTCOMES = frozenset(
    {
        "not_due",
        "blocked_unchanged",
        "retry_required",
        "blocked_reported",
        "tombstone_completed",
    }
)
_RETENTION_RETRY_REASONS = frozenset(
    {
        "pending_ack",
        "ack_prefix_lag",
        "observer_retryable",
    }
)
_RETENTION_REQUEST_KINDS = frozenset({"tombstone", "blocked"})


class CoreControllerError(RuntimeError):
    """Base class for production Core composition failures."""


class CoreControllerAuthorityError(CoreControllerError):
    """Retained authorities no longer describe one exact lifecycle."""


class CoreControllerClockError(CoreControllerError):
    """The injected decision clock failed its exact runtime contract."""


class CoreControllerClosed(CoreControllerError):
    """The production Core composition root is closed."""


@dataclass(frozen=True)
class CorePollResult:
    delivery: PollResult
    projected: int
    readiness: MutationReadiness


@dataclass(frozen=True, slots=True)
class CoreRetentionResult:
    outcome: RetentionOutcome
    retry_reason: RetentionRetryReason | None
    request_kind: Literal["tombstone", "blocked"] | None
    request_id: str | None
    target_sequence: int | None
    target_event_id: str | None
    target_content_sha256: str | None
    unlinked_manifest_count: int
    unlinked_bytes: int
    projected: int
    projection_rebuilt: bool
    readiness: MutationReadiness


@dataclass(frozen=True, slots=True)
class _RetentionObservation:
    outcome: RetentionOutcome
    retry_reason: RetentionRetryReason | None
    request_kind: _RetentionRequestKind | None
    request_id: str | None
    target_sequence: int | None
    target_event_id: str | None
    target_content_sha256: str | None
    unlinked_manifest_count: int
    unlinked_bytes: int
    projection_rebuilt: bool


@dataclass(frozen=True, slots=True)
class _RetentionExecution:
    observation: _RetentionObservation
    projected: int
    readiness: MutationReadiness


@dataclass(frozen=True, slots=True)
class _CandidateAdmissionBinding:
    view: CandidateAdmissionView
    nonce: object
    candidate_id: str
    candidate_bytes: bytes
    candidate_facts_sha256: str
    authority_snapshot_event_id: str
    projection_cursor: ProjectionCursor
    terminal_ref: EvidenceRef
    admission_rebuild_epoch: int
    authority_revision: int
    readiness: MutationReadiness
    controller_lifecycle: object
    projection_lifecycle: object
    evidence_lifecycle: object


def _invalid_retention_result(message: str) -> Never:
    raise CoreControllerAuthorityError(
        f"Core retention result {message}"
    )


def _validate_core_retention_result(result: CoreRetentionResult) -> None:
    if type(result) is not CoreRetentionResult:
        _invalid_retention_result("has an inexact runtime type")
    if (
        type(result.outcome) is not str
        or result.outcome not in _RETENTION_OUTCOMES
    ):
        _invalid_retention_result("has an invalid outcome")
    if (
        result.retry_reason is not None
        and (
            type(result.retry_reason) is not str
            or result.retry_reason not in _RETENTION_RETRY_REASONS
        )
    ):
        _invalid_retention_result("has an invalid retry reason")
    if (result.outcome == "retry_required") != (
        result.retry_reason is not None
    ):
        _invalid_retention_result("has an inconsistent retry reason")

    request_present = result.request_kind is not None
    if request_present != (result.request_id is not None):
        _invalid_retention_result("has a partial request identity")
    if request_present and (
        type(result.request_kind) is not str
        or result.request_kind not in _RETENTION_REQUEST_KINDS
        or type(result.request_id) is not str
        or UUID4.fullmatch(result.request_id) is None
    ):
        _invalid_retention_result("has an invalid request identity")

    target_fields = (
        result.target_sequence,
        result.target_event_id,
        result.target_content_sha256,
    )
    target_present = all(value is not None for value in target_fields)
    if target_present != any(value is not None for value in target_fields):
        _invalid_retention_result("has a partial target identity")
    if target_present and (
        not request_present
        or type(result.target_sequence) is not int
        or not 1 <= result.target_sequence <= MAX_UINT64
        or type(result.target_event_id) is not str
        or not result.target_event_id.startswith("evt_")
        or HEX64.fullmatch(result.target_event_id[4:]) is None
        or type(result.target_content_sha256) is not str
        or HEX64.fullmatch(result.target_content_sha256) is None
    ):
        _invalid_retention_result("has an invalid target identity")

    if (
        type(result.unlinked_manifest_count) is not int
        or not 0 <= result.unlinked_manifest_count <= 128
        or type(result.unlinked_bytes) is not int
        or not 0 <= result.unlinked_bytes <= MAX_UINT64
        or type(result.projected) is not int
        or not 0 <= result.projected <= MAX_UINT64
        or type(result.projection_rebuilt) is not bool
        or type(result.readiness) is not MutationReadiness
    ):
        _invalid_retention_result("has invalid exact values")

    if result.outcome == "not_due":
        if request_present or target_present:
            _invalid_retention_result("exposes identity for a no-op")
    elif result.outcome in {"blocked_unchanged", "blocked_reported"}:
        if result.request_kind != "blocked" or not target_present:
            _invalid_retention_result(
                "does not bind an exact blocked observation"
            )
    elif result.outcome == "tombstone_completed":
        if (
            result.request_kind != "tombstone"
            or not target_present
            or not 1 <= result.unlinked_manifest_count <= 128
            or not 1 <= result.unlinked_bytes <= MAX_UINT64
            or result.projection_rebuilt is not True
        ):
            _invalid_retention_result(
                "does not bind an exact tombstone completion"
            )
    else:
        reason = result.retry_reason
        if reason == "pending_ack":
            if not request_present and target_present:
                _invalid_retention_result(
                    "has a target without durable pending identity"
                )
        elif reason == "ack_prefix_lag":
            if result.request_kind != "tombstone":
                _invalid_retention_result(
                    "has a non-tombstone ACK prefix retry"
                )
        elif reason == "observer_retryable":
            if not request_present:
                _invalid_retention_result(
                    "has no durable observer retry identity"
                )
        else:
            _invalid_retention_result("has no exact retry branch")

    if result.outcome != "tombstone_completed" and (
        result.unlinked_manifest_count != 0
        or result.unlinked_bytes != 0
        or result.projection_rebuilt is not False
    ):
        _invalid_retention_result(
            "reports mutation outside tombstone completion"
        )


def _public_retention_result(execution: object) -> CoreRetentionResult:
    if type(execution) is not _RetentionExecution:
        _invalid_retention_result("has an inexact execution envelope")
    observation = execution.observation
    if type(observation) is not _RetentionObservation:
        _invalid_retention_result("has an inexact observation envelope")
    result = CoreRetentionResult(
        outcome=observation.outcome,
        retry_reason=observation.retry_reason,
        request_kind=observation.request_kind,
        request_id=observation.request_id,
        target_sequence=observation.target_sequence,
        target_event_id=observation.target_event_id,
        target_content_sha256=observation.target_content_sha256,
        unlinked_manifest_count=observation.unlinked_manifest_count,
        unlinked_bytes=observation.unlinked_bytes,
        projected=execution.projected,
        projection_rebuilt=observation.projection_rebuilt,
        readiness=execution.readiness,
    )
    _validate_core_retention_result(result)
    return result


class CoreController:
    """Own one exact live evidence/ACK/coverage/projection composition."""

    def __init__(
        self,
        acceptance: AcceptanceCoordinator,
        acknowledgements: AckJournal,
        correlation_requests: CorrelationRequestJournal,
        registry: SpecialUseRegistry,
        coverage: CoverageState,
        projection: ProjectionStore,
        clock: CoreClockProvider,
        delivery: DeliveryCoordinator,
        store: SegmentStore,
        verifier: EnvelopeVerifier,
        *,
        _factory: object,
    ) -> None:
        if _factory is not _CONTROLLER_FACTORY:
            raise TypeError("use CoreController.create()")
        self._acceptance = acceptance
        self._store = store
        self._verifier = verifier
        self._acknowledgements = acknowledgements
        self._correlation_requests = correlation_requests
        self._registry = registry
        self._coverage = coverage
        self._projection = projection
        self._clock = clock
        self._delivery = delivery
        self._lock = asyncio.Lock()
        self._projection_healthy = True
        self._admission_lifecycle = object()
        self._candidate_admission_binding: _CandidateAdmissionBinding | None = None
        self._closed = False

    @classmethod
    def create(
        cls,
        acceptance: AcceptanceCoordinator,
        acknowledgements: AckJournal,
        correlation_requests: CorrelationRequestJournal,
        registry: SpecialUseRegistry,
        coverage: CoverageState,
        projection: ProjectionStore,
        transport: ObserverCoreTransport,
        clock: CoreClockProvider,
        *,
        ack_budget: int = MAX_PAGE_EVENTS,
    ) -> CoreController:
        if type(acceptance) is not AcceptanceCoordinator:
            raise TypeError("controller requires exact acceptance authority")
        if type(acknowledgements) is not AckJournal:
            raise TypeError("controller requires exact ACK authority")
        if type(correlation_requests) is not CorrelationRequestJournal:
            raise TypeError(
                "controller requires exact correlation-request authority"
            )
        if (
            type(registry) is not SpecialUseRegistry
            or not special_use_registry_is_issued(registry)
        ):
            raise TypeError("controller requires exact issued registry authority")
        if type(coverage) is not CoverageState:
            raise TypeError("controller requires exact coverage authority")
        if type(projection) is not ProjectionStore:
            raise TypeError("controller requires exact projection authority")
        store = acceptance.segment_store
        verifier = acceptance.verifier
        if type(store) is not SegmentStore or type(verifier) is not EnvelopeVerifier:
            raise TypeError("controller requires exact evidence authority")
        if (
            acceptance.segment_store is not store
            or acceptance.verifier is not verifier
            or not store._is_bound_verifier(verifier)
        ):
            raise CoreControllerAuthorityError(
                "acceptance authority binding is invalid"
            )
        if not correlation_requests._is_bound_to(store):
            raise CoreControllerAuthorityError(
                "correlation-request authority binding is invalid"
            )
        if not projection._is_bound_to(
            store,
            acknowledgements,
            correlation_requests,
            registry,
        ):
            raise CoreControllerAuthorityError(
                "projection authority binding is invalid"
            )
        if (
            not callable(getattr(clock, "live_receipt_monotonic", None))
            or not callable(getattr(clock, "decision_sample", None))
        ):
            raise TypeError("controller requires one typed Core clock provider")
        delivery = DeliveryCoordinator.create(
            acceptance,
            acknowledgements,
            correlation_requests,
            transport,
            coverage=coverage,
            clock=clock,
            ack_budget=ack_budget,
        )
        try:
            if (
                acceptance.segment_store is not store
                or acceptance.verifier is not verifier
                or not store._is_bound_verifier(verifier)
                or not correlation_requests._is_bound_to(store)
                or not projection._is_bound_to(
                    store,
                    acknowledgements,
                    correlation_requests,
                    registry,
                )
                or delivery._store is not store
                or delivery._verifier is not verifier
                or not delivery._is_bound_to(
                    acceptance,
                    acknowledgements,
                    correlation_requests,
                    coverage,
                    clock,
                )
            ):
                raise CoreControllerAuthorityError(
                    "controller authority changed during composition"
                )
            return cls(
                acceptance,
                acknowledgements,
                correlation_requests,
                registry,
                coverage,
                projection,
                clock,
                delivery,
                store,
                verifier,
                _factory=_CONTROLLER_FACTORY,
            )
        except BaseException as primary:
            try:
                delivery._delivery_lease.release()
            except BaseException as cleanup_error:  # noqa: BLE001
                primary.add_note(
                    "secondary controller composition cleanup failure "
                    f"({type(cleanup_error).__name__})"
                )
            else:
                delivery._lease_released = True
                delivery._closed = True
            raise

    def _require_open(self) -> None:
        if self._closed:
            raise CoreControllerClosed("Core controller is closed")

    @staticmethod
    def _validate_ack_identity(identity: AckIdentity) -> None:
        if (
            type(identity) is not AckIdentity
            or type(identity.sequence) is not int
            or not 1 <= identity.sequence <= MAX_UINT64
            or type(identity.event_id) is not str
            or type(identity.content_sha256) is not str
        ):
            raise CoreControllerAuthorityError(
                "ACK identity is not an exact frozen boundary"
            )

    @staticmethod
    def _validate_evidence_status(status: EvidenceStatus) -> None:
        if (
            type(status) is not EvidenceStatus
            or type(status.healthy) is not bool
            or type(status.key_healthy) is not bool
            or type(status.repair_pending) is not bool
            or type(status.retention_pending) is not bool
            or (
                status.host_id is not None
                and type(status.host_id) is not str
            )
            or type(status.evidence_head) is not int
            or type(status.acceptance_cursor) is not int
            or not (
                0
                <= status.acceptance_cursor
                <= status.evidence_head
                <= MAX_UINT64
            )
        ):
            raise CoreControllerAuthorityError(
                "evidence status is not an exact frozen snapshot"
            )

    @classmethod
    def _validate_ack_snapshot(cls, snapshot: AckJournalSnapshot) -> None:
        if (
            type(snapshot) is not AckJournalSnapshot
            or type(snapshot.healthy) is not bool
        ):
            raise CoreControllerAuthorityError(
                "ACK status is not an exact frozen snapshot"
            )
        if snapshot.confirmed is not None:
            cls._validate_ack_identity(snapshot.confirmed)
        if snapshot.pending is not None:
            cls._validate_ack_identity(snapshot.pending)

    def _ref_at(self, sequence: int) -> EvidenceRef:
        if type(sequence) is not int or not 1 <= sequence <= MAX_UINT64:
            raise CoreControllerAuthorityError(
                "evidence lookup sequence is invalid"
            )
        refs = self._store.authenticated_refs(
            after_sequence=sequence - 1,
            through_sequence=sequence,
            limit=1,
        )
        if (
            type(refs) is not tuple
            or len(refs) != 1
            or type(refs[0]) is not EvidenceRef
            or refs[0].source_sequence != sequence
        ):
            raise CoreControllerAuthorityError(
                "frozen boundary lacks one exact authenticated ref"
            )
        return refs[0]

    def _ref_host(self, ref: EvidenceRef) -> str:
        record = self._store.resolve_authenticated_ref(ref)
        if (
            type(record) is not StoredEvidenceRecord
            or record.ref != ref
            or type(record.envelope) is not dict
        ):
            raise CoreControllerAuthorityError(
                "authenticated ref did not resolve to its exact record"
            )
        host_id = record.envelope.get("host_id")
        if type(host_id) is not str:
            raise CoreControllerAuthorityError(
                "authenticated ref has no exact host identity"
            )
        return host_id

    def _cursor_matches_ref(
        self,
        cursor: ProjectionCursor,
        ref: EvidenceRef,
    ) -> bool:
        if (
            type(cursor) is not ProjectionCursor
            or type(ref) is not EvidenceRef
            or type(cursor.host_id) is not str
            or type(cursor.source_sequence) is not int
            or type(cursor.event_id) is not str
            or type(cursor.content_sha256) is not str
            or type(cursor.frame_sha256) is not str
        ):
            return False
        return (
            cursor.host_id == self._ref_host(ref)
            and cursor.source_sequence == ref.source_sequence
            and cursor.event_id == ref.event_id
            and cursor.content_sha256 == ref.content_sha256
            and cursor.frame_sha256 == ref.frame_sha256
        )

    @staticmethod
    def _ack_matches_ref(identity: AckIdentity, ref: EvidenceRef) -> bool:
        return (
            identity.sequence == ref.source_sequence
            and identity.event_id == ref.event_id
            and identity.content_sha256 == ref.content_sha256
        )

    def _projection_boundary(
        self,
        snapshot: AckJournalSnapshot,
        status: ProjectionStatus,
    ) -> tuple[int, EvidenceRef | None]:
        self._validate_ack_snapshot(snapshot)
        if type(status) is not ProjectionStatus:
            raise CoreControllerAuthorityError(
                "projection status is not an exact frozen snapshot"
            )
        if type(status.healthy) is not bool:
            raise CoreControllerAuthorityError(
                "projection health is not an exact bool"
            )
        if not status.healthy:
            raise CoreControllerAuthorityError("projection status is unhealthy")
        confirmed = snapshot.confirmed
        cursor = status.cursor
        if confirmed is None:
            if cursor is not None:
                raise CoreControllerAuthorityError(
                    "projection exists without confirmed ACK authority"
                )
            return 0, None
        terminal = self._ref_at(confirmed.sequence)
        if not self._ack_matches_ref(confirmed, terminal):
            raise CoreControllerAuthorityError(
                "frozen ACK identity differs from authenticated evidence"
            )
        if cursor is None:
            return 0, terminal
        if (
            type(cursor) is not ProjectionCursor
            or type(cursor.source_sequence) is not int
            or not 1 <= cursor.source_sequence <= MAX_UINT64
        ):
            raise CoreControllerAuthorityError(
                "projection cursor is not an exact frozen cursor"
            )
        current = self._ref_at(cursor.source_sequence)
        if not self._cursor_matches_ref(cursor, current):
            raise CoreControllerAuthorityError(
                "projection cursor differs from authenticated evidence"
            )
        if cursor.source_sequence > confirmed.sequence:
            raise CoreControllerAuthorityError(
                "projection cursor exceeds frozen ACK authority"
            )
        if (
            cursor.source_sequence == confirmed.sequence
            and not self._cursor_matches_ref(cursor, terminal)
        ):
            raise CoreControllerAuthorityError(
                "projection terminal identity differs from frozen ACK authority"
            )
        return cursor.source_sequence, terminal

    def _latch_projection_failure(self) -> None:
        self._projection_healthy = False

    def _catch_up_projection(self) -> int:
        if not self._projection_healthy:
            return 0
        applied = 0
        try:
            snapshot = self._acknowledgements.snapshot()
            self._validate_ack_snapshot(snapshot)
            if not snapshot.healthy:
                return 0
            status = self._projection.status()
            cursor, terminal = self._projection_boundary(snapshot, status)
            if terminal is None:
                final_status = self._projection.status()
                final_cursor, final_terminal = self._projection_boundary(
                    snapshot,
                    final_status,
                )
                if (
                    final_cursor != 0
                    or final_terminal is not None
                    or final_status.cursor is not None
                ):
                    raise CoreControllerAuthorityError(
                        "empty projection changed during catch-up"
                    )
                return 0
            while cursor < terminal.source_sequence:
                refs = self._store.authenticated_refs(
                    after_sequence=cursor,
                    through_sequence=terminal.source_sequence,
                    limit=_PROJECTION_BATCH,
                )
                if type(refs) is not tuple or not refs:
                    raise CoreControllerAuthorityError(
                        "projection catch-up made no progress"
                    )
                for ref in refs:
                    if (
                        type(ref) is not EvidenceRef
                        or ref.source_sequence <= cursor
                        or ref.source_sequence > terminal.source_sequence
                    ):
                        raise CoreControllerAuthorityError(
                            "projection catch-up refs are out of order"
                        )
                    result = self._projection.apply(ref)
                    if (
                        type(result) is not ProjectionApplyResult
                        or type(result.cursor) is not ProjectionCursor
                        or not self._cursor_matches_ref(result.cursor, ref)
                    ):
                        raise CoreControllerAuthorityError(
                            "projection apply returned the wrong exact cursor"
                        )
                    cursor = ref.source_sequence
                    applied += 1
            final_status = self._projection.status()
            final_cursor, final_terminal = self._projection_boundary(
                snapshot,
                final_status,
            )
            if (
                final_terminal is None
                or final_cursor != terminal.source_sequence
                or final_terminal != terminal
                or final_status.cursor is None
                or not self._cursor_matches_ref(final_status.cursor, terminal)
            ):
                raise CoreControllerAuthorityError(
                    "projection did not reach the frozen ACK identity"
                )
        except (
            CoreControllerAuthorityError,
            ProjectionError,
            EvidenceStoreError,
            AckJournalError,
            OSError,
        ):
            self._latch_projection_failure()
        return applied

    def _catch_up_projection_for_retention(self) -> int:
        evidence = self._store.status()
        self._validate_evidence_status(evidence)
        if not evidence.healthy or evidence.repair_pending:
            raise CoreControllerAuthorityError(
                "retention requires healthy evidence authority"
            )
        if not evidence.retention_pending:
            return self._catch_up_projection()
        try:
            projection = self._projection.status()
        except (ProjectionError, OSError):
            self._latch_projection_failure()
            return 0
        if type(projection) is not ProjectionStatus or not projection.healthy:
            self._latch_projection_failure()
        return 0

    def _read_ack_for_readiness(self) -> AckJournalSnapshot:
        try:
            snapshot = self._acknowledgements.snapshot()
        except (AckJournalError, OSError):
            return AckJournalSnapshot(
                confirmed=None,
                pending=None,
                healthy=False,
            )
        self._validate_ack_snapshot(snapshot)
        return snapshot

    def _read_projection_for_readiness(self) -> ProjectionStatus:
        try:
            status = self._projection.status()
        except (ProjectionError, OSError):
            self._latch_projection_failure()
            return ProjectionStatus(False, None)
        if type(status) is not ProjectionStatus:
            raise CoreControllerAuthorityError(
                "projection status is not an exact frozen snapshot"
            )
        if type(status.healthy) is not bool:
            raise CoreControllerAuthorityError(
                "projection health is not an exact bool"
            )
        return status

    def _projection_readiness(
        self,
        evidence: EvidenceStatus,
        acknowledgements: AckJournalSnapshot,
        projection: ProjectionStatus,
    ) -> tuple[int, bool]:
        terminal: EvidenceRef | None = None
        confirmed = acknowledgements.confirmed
        if confirmed is not None:
            try:
                terminal = self._ref_at(confirmed.sequence)
                if not self._ack_matches_ref(confirmed, terminal):
                    raise CoreControllerAuthorityError(
                        "confirmed ACK differs from authenticated evidence"
                    )
            except (
                CoreControllerAuthorityError,
                EvidenceStoreError,
                AckJournalError,
                OSError,
            ):
                self._latch_projection_failure()
                terminal = None
        cursor = projection.cursor
        if cursor is None:
            return (
                0,
                projection.healthy
                and self._projection_healthy
                and confirmed is None,
            )
        if type(cursor) is not ProjectionCursor:
            self._latch_projection_failure()
            return 0, False
        observed = cursor.source_sequence
        if type(observed) is not int or not 1 <= observed <= MAX_UINT64:
            self._latch_projection_failure()
            return 0, False
        healthy = projection.healthy and self._projection_healthy
        try:
            ref = self._ref_at(observed)
            healthy = (
                healthy
                and cursor.host_id == evidence.host_id
                and self._cursor_matches_ref(cursor, ref)
            )
            if confirmed is None or terminal is None or observed > confirmed.sequence:
                healthy = False
            elif observed == confirmed.sequence:
                healthy = (
                    healthy
                    and ref == terminal
                    and self._cursor_matches_ref(cursor, ref)
                )
        except (
            CoreControllerAuthorityError,
            EvidenceStoreError,
            AckJournalError,
            OSError,
        ):
            healthy = False
        if not healthy:
            self._latch_projection_failure()
        return observed, healthy

    def _decision_sample(self) -> CoreClockSample:
        try:
            sample = self._clock.decision_sample()
            if type(sample) is not CoreClockSample:
                raise TypeError("decision sample has the wrong runtime type")
            _validate_core_clock_sample(sample)
        except Exception as error:
            raise CoreControllerClockError(
                "Core decision clock is unavailable or invalid"
            ) from error
        return sample

    def _mutation_readiness(self) -> MutationReadiness:
        evidence = self._store.status()
        self._validate_evidence_status(evidence)
        acknowledgements = self._read_ack_for_readiness()
        projection = self._read_projection_for_readiness()
        projection_cursor, projection_healthy = self._projection_readiness(
            evidence,
            acknowledgements,
            projection,
        )
        sample = self._decision_sample()
        context = MutationReadinessContext(
            decision_utc=sample.decision_utc,
            decision_monotonic=sample.decision_monotonic,
            clock_healthy=sample.healthy,
            clock_uncertainty_seconds=sample.uncertainty_seconds,
            max_clock_uncertainty_seconds=sample.max_uncertainty_seconds,
            evidence_head=evidence.evidence_head,
            acceptance_cursor=evidence.acceptance_cursor,
            confirmed_through=acknowledgements.confirmed_through,
            projection_cursor=projection_cursor,
            evidence_healthy=evidence.healthy,
            repair_pending=evidence.repair_pending,
            retention_pending=evidence.retention_pending,
            key_healthy=evidence.key_healthy,
            ack_journal_healthy=acknowledgements.healthy,
            projection_healthy=projection_healthy,
        )
        readiness = self._coverage.mutation_readiness(context)
        if type(readiness) is not MutationReadiness:
            raise CoreControllerAuthorityError(
                "coverage returned a non-exact readiness value"
            )
        return readiness

    def mutation_readiness(self) -> MutationReadiness:
        self._require_open()
        return self._mutation_readiness()

    @staticmethod
    def _candidate_copy(candidate: ContainmentCandidateV1) -> ContainmentCandidateV1:
        if type(candidate) is not ContainmentCandidateV1:
            raise CandidateAdmissionError("candidate admission facts are not exact")
        try:
            copied = ContainmentCandidateV1.model_validate(
                candidate.model_dump(mode="python"),
                strict=True,
            )
        except Exception as error:
            raise CandidateAdmissionError(
                "candidate admission facts cannot be reconstructed"
            ) from error
        if type(copied) is not ContainmentCandidateV1 or copied != candidate:
            raise CandidateAdmissionError("candidate admission facts changed")
        return copied

    @classmethod
    def _candidate_bytes(cls, candidate: ContainmentCandidateV1) -> bytes:
        copied = cls._candidate_copy(candidate)
        try:
            return canonical_json(copied.model_dump(mode="json"))
        except Exception as error:
            raise CandidateAdmissionError(
                "candidate admission facts are not canonical"
            ) from error

    @staticmethod
    def _readiness_cursors(
        readiness: MutationReadiness,
    ) -> tuple[int, int, int, int]:
        if (
            type(readiness) is not MutationReadiness
            or readiness.ready is not True
            or type(readiness.reason_codes) is not tuple
            or readiness.reason_codes != ()
            or not (
                type(readiness.observer_reconcile_generation) is int
                and 1
                <= readiness.observer_reconcile_generation
                <= MAX_UINT64
            )
            or type(readiness.coverage_snapshot_sha256) is not str
            or HEX64.fullmatch(readiness.coverage_snapshot_sha256) is None
        ):
            raise CandidateAdmissionError(
                "candidate admission requires exact ready mutation authority"
            )
        cursors = (
            readiness.evidence_head,
            readiness.acceptance_cursor,
            readiness.confirmed_through,
            readiness.projection_cursor,
        )
        if (
            any(
                type(cursor) is not int or not 0 <= cursor <= MAX_UINT64
                for cursor in cursors
            )
            or len(set(cursors)) != 1
        ):
            raise CandidateAdmissionError(
                "candidate admission cursors are not independently equal"
            )
        return cursors

    def _require_admission_composition(self) -> None:
        if (
            self._acceptance.segment_store is not self._store
            or self._acceptance.verifier is not self._verifier
            or not self._store._is_bound_verifier(self._verifier)
            or not self._correlation_requests._is_bound_to(self._store)
            or self._coverage._evidence is not self._store
            or self._coverage._lifecycle_identity
            is not self._store._lifecycle_identity
            or not self._projection._is_bound_to(
                self._store,
                self._acknowledgements,
                self._correlation_requests,
                self._registry,
            )
        ):
            raise CandidateAdmissionError(
                "candidate admission authorities do not share one lifecycle"
            )

    def _admission_terminal(
        self,
        cursors: tuple[int, int, int, int],
    ) -> tuple[ProjectionCursor, EvidenceRef, str, str]:
        acknowledgements = self._acknowledgements.snapshot()
        self._validate_ack_snapshot(acknowledgements)
        status = self._projection.status()
        cursor_sequence, terminal = self._projection_boundary(
            acknowledgements,
            status,
        )
        cursor = status.cursor
        if (
            not acknowledgements.healthy
            or terminal is None
            or type(cursor) is not ProjectionCursor
            or cursor_sequence != cursors[3]
            or cursor.source_sequence != cursors[3]
            or not self._cursor_matches_ref(cursor, terminal)
        ):
            raise CandidateAdmissionError(
                "candidate admission terminal is not exact"
            )
        record = self._store.resolve_authenticated_ref(terminal)
        if (
            type(record) is not StoredEvidenceRecord
            or record.ref != terminal
            or type(record.envelope) is not dict
        ):
            raise CandidateAdmissionError(
                "candidate admission terminal is not authenticated"
            )
        host_id = record.envelope.get("host_id")
        boot_id = record.envelope.get("boot_id")
        if type(host_id) is not str or type(boot_id) is not str:
            raise CandidateAdmissionError(
                "candidate admission terminal lost host lifecycle"
            )
        return cursor, terminal, host_id, boot_id

    @classmethod
    def _view_matches_binding(
        cls,
        view: object,
        binding: _CandidateAdmissionBinding,
    ) -> bool:
        if type(view) is not CandidateAdmissionView or view is not binding.view:
            return False
        try:
            return (
                view._nonce is binding.nonce
                and view._controller_lifecycle is binding.controller_lifecycle
                and view._projection_lifecycle is binding.projection_lifecycle
                and view._evidence_lifecycle is binding.evidence_lifecycle
                and view.candidate.candidate_id == binding.candidate_id
                and cls._candidate_bytes(view.candidate) == binding.candidate_bytes
                and candidate_facts_sha256(view.candidate)
                == binding.candidate_facts_sha256
                and view.candidate_facts_sha256
                == binding.candidate_facts_sha256
                and view.authority_snapshot_event_id
                == binding.authority_snapshot_event_id
                and view.projection_cursor == binding.projection_cursor
                and view.terminal_ref == binding.terminal_ref
                and view.admission_rebuild_epoch
                == binding.admission_rebuild_epoch
                and view.authority_revision == binding.authority_revision
                and view.readiness == binding.readiness
            )
        except (AttributeError, CandidateAdmissionError, TypeError, ValueError):
            return False

    def _latch_admission_projection_if_unhealthy(self) -> None:
        try:
            status = self._projection.status()
        except (ProjectionError, OSError):
            self._latch_projection_failure()
            return
        if type(status) is not ProjectionStatus or status.healthy is not True:
            self._latch_projection_failure()

    async def issue_candidate_admission(
        self,
        candidate_id: str,
    ) -> CandidateAdmissionView:
        """Issue one fresh, local, single-use candidate admission authority."""
        async with self._lock:
            self._candidate_admission_binding = None
            try:
                self._require_open()
                with self._projection._candidate_admission_scope(
                    _factory=_CANDIDATE_ADMISSION_GATE_FACTORY,
                ):
                    self._require_admission_composition()
                    self._catch_up_projection()
                    if not self._projection_healthy:
                        raise CandidateAdmissionError(
                            "candidate admission projection catch-up failed"
                        )
                    before = self._mutation_readiness()
                    before_cursors = self._readiness_cursors(before)
                    _cursor, terminal, host_id, boot_id = self._admission_terminal(
                        before_cursors
                    )
                    snapshot = self._projection._issue_candidate_admission_snapshot(
                        candidate_id,
                        _factory=_CANDIDATE_ADMISSION_GATE_FACTORY,
                    )
                    if type(snapshot) is not _CandidateAdmissionSnapshot:
                        raise CandidateAdmissionError(
                            "candidate admission candidate is unknown"
                        )
                    candidate = snapshot.candidate
                    if (
                        type(candidate) is not ContainmentCandidateV1
                        or snapshot.cursor != _cursor
                        or snapshot.terminal_ref != terminal
                        or candidate.host_id != host_id
                        or candidate.boot_id != boot_id
                        or snapshot.invalidation_event_ids
                    ):
                        raise CandidateAdmissionError(
                            "candidate admission candidate is stale or invalidated"
                        )
                    after = self._mutation_readiness()
                    after_cursors = self._readiness_cursors(after)
                    if after_cursors != before_cursors:
                        raise CandidateAdmissionError(
                            "candidate admission cursors changed during issuance"
                        )
                    final_cursor, final_terminal, final_host, final_boot = (
                        self._admission_terminal(after_cursors)
                    )
                    if (
                        final_cursor != snapshot.cursor
                        or final_terminal != snapshot.terminal_ref
                        or final_host != candidate.host_id
                        or final_boot != candidate.boot_id
                        or after.coverage_snapshot_sha256
                        != candidate.coverage_snapshot_sha256
                        or snapshot.candidate_facts_sha256
                        != candidate_facts_sha256(candidate)
                        or snapshot.authority_snapshot_event_id
                        != candidate.correlation_snapshot_event_id
                    ):
                        raise CandidateAdmissionError(
                            "candidate admission authority changed during issuance"
                        )
                    candidate_copy = self._candidate_copy(candidate)
                    candidate_bytes = self._candidate_bytes(candidate_copy)
                    nonce = object()
                    view = _issue_candidate_admission_view(
                        candidate=candidate_copy,
                        candidate_facts_sha256=snapshot.candidate_facts_sha256,
                        authority_snapshot_event_id=(
                            snapshot.authority_snapshot_event_id
                        ),
                        projection_cursor=replace(snapshot.cursor),
                        terminal_ref=replace(snapshot.terminal_ref),
                        admission_rebuild_epoch=(
                            snapshot.admission_rebuild_epoch
                        ),
                        authority_revision=snapshot.authority_revision,
                        readiness=replace(after),
                        controller_lifecycle=self._admission_lifecycle,
                        projection_lifecycle=snapshot.projection_lifecycle,
                        evidence_lifecycle=snapshot.evidence_lifecycle,
                        nonce=nonce,
                    )
                    binding = _CandidateAdmissionBinding(
                        view=view,
                        nonce=nonce,
                        candidate_id=candidate.candidate_id,
                        candidate_bytes=candidate_bytes,
                        candidate_facts_sha256=(
                            snapshot.candidate_facts_sha256
                        ),
                        authority_snapshot_event_id=(
                            snapshot.authority_snapshot_event_id
                        ),
                        projection_cursor=replace(snapshot.cursor),
                        terminal_ref=replace(snapshot.terminal_ref),
                        admission_rebuild_epoch=(
                            snapshot.admission_rebuild_epoch
                        ),
                        authority_revision=snapshot.authority_revision,
                        readiness=replace(after),
                        controller_lifecycle=self._admission_lifecycle,
                        projection_lifecycle=snapshot.projection_lifecycle,
                        evidence_lifecycle=snapshot.evidence_lifecycle,
                    )
                    if not self._view_matches_binding(view, binding):
                        raise CandidateAdmissionError(
                            "candidate admission view could not be sealed"
                        )
                    self._candidate_admission_binding = binding
                    return view
            except CandidateAdmissionError:
                self._latch_admission_projection_if_unhealthy()
                raise
            except (
                CoreControllerError,
                ProjectionError,
                EvidenceStoreError,
                AckJournalError,
                OSError,
                TypeError,
                ValueError,
            ) as error:
                self._latch_admission_projection_if_unhealthy()
                raise CandidateAdmissionError(
                    "candidate admission issuance was denied"
                ) from error

    async def consume_candidate_admission(
        self,
        view: object,
    ) -> ContainmentCandidateV1:
        """Consume exactly one unchanged authority and return observation facts."""
        async with self._lock:
            binding = self._candidate_admission_binding
            self._candidate_admission_binding = None
            try:
                self._require_open()
                with self._projection._candidate_admission_scope(
                    _factory=_CANDIDATE_ADMISSION_GATE_FACTORY,
                ):
                    if (
                        binding is None
                        or not self._view_matches_binding(view, binding)
                        or binding.controller_lifecycle
                        is not self._admission_lifecycle
                        or binding.evidence_lifecycle
                        is not self._store._lifecycle_identity
                    ):
                        raise CandidateAdmissionError(
                            "candidate admission view is foreign, stale, or mutated"
                        )
                    self._require_admission_composition()
                    self._catch_up_projection()
                    if not self._projection_healthy:
                        raise CandidateAdmissionError(
                            "candidate admission projection catch-up failed"
                        )
                    readiness = self._mutation_readiness()
                    cursors = self._readiness_cursors(readiness)
                    bound_cursors = (
                        binding.readiness.evidence_head,
                        binding.readiness.acceptance_cursor,
                        binding.readiness.confirmed_through,
                        binding.readiness.projection_cursor,
                    )
                    if cursors != bound_cursors:
                        raise CandidateAdmissionError(
                            "candidate admission boundary is stale"
                        )
                    cursor, terminal, host_id, boot_id = self._admission_terminal(
                        cursors
                    )
                    if (
                        cursor != binding.projection_cursor
                        or terminal != binding.terminal_ref
                    ):
                        raise CandidateAdmissionError(
                            "candidate admission terminal changed"
                        )
                    snapshot = (
                        self._projection._reauthenticate_candidate_admission_snapshot(
                            binding.candidate_id,
                            admission_rebuild_epoch=(
                                binding.admission_rebuild_epoch
                            ),
                            authority_revision=binding.authority_revision,
                            projection_lifecycle=binding.projection_lifecycle,
                            _factory=_CANDIDATE_ADMISSION_GATE_FACTORY,
                        )
                    )
                    if type(snapshot) is not _CandidateAdmissionSnapshot:
                        raise CandidateAdmissionError(
                            "candidate admission candidate disappeared"
                        )
                    candidate = snapshot.candidate
                    if (
                        type(candidate) is not ContainmentCandidateV1
                        or snapshot.invalidation_event_ids
                        or snapshot.cursor != binding.projection_cursor
                        or snapshot.terminal_ref != binding.terminal_ref
                        or snapshot.admission_rebuild_epoch
                        != binding.admission_rebuild_epoch
                        or snapshot.authority_revision
                        != binding.authority_revision
                        or snapshot.projection_lifecycle
                        is not binding.projection_lifecycle
                        or snapshot.evidence_lifecycle
                        is not binding.evidence_lifecycle
                        or candidate.host_id != host_id
                        or candidate.boot_id != boot_id
                        or candidate.candidate_id != binding.candidate_id
                        or snapshot.candidate_facts_sha256
                        != binding.candidate_facts_sha256
                        or candidate_facts_sha256(candidate)
                        != binding.candidate_facts_sha256
                        or self._candidate_bytes(candidate)
                        != binding.candidate_bytes
                        or snapshot.authority_snapshot_event_id
                        != binding.authority_snapshot_event_id
                    ):
                        raise CandidateAdmissionError(
                            "candidate admission facts changed"
                        )
                    final = self._mutation_readiness()
                    final_cursors = self._readiness_cursors(final)
                    final_cursor, final_terminal, final_host, final_boot = (
                        self._admission_terminal(final_cursors)
                    )
                    if (
                        final_cursors != bound_cursors
                        or final_cursor != binding.projection_cursor
                        or final_terminal != binding.terminal_ref
                        or final_host != candidate.host_id
                        or final_boot != candidate.boot_id
                    ):
                        raise CandidateAdmissionError(
                            "candidate admission authority changed before consume"
                        )
                    return self._candidate_copy(candidate)
            except CandidateAdmissionError:
                self._latch_admission_projection_if_unhealthy()
                raise
            except (
                CoreControllerError,
                ProjectionError,
                EvidenceStoreError,
                AckJournalError,
                OSError,
                TypeError,
                ValueError,
            ) as error:
                self._latch_admission_projection_if_unhealthy()
                raise CandidateAdmissionError(
                    "candidate admission consume was denied"
                ) from error

    async def _execute_retention_locked(
        self,
        *,
        _lock_authority: object,
    ) -> _RetentionObservation:
        self._delivery._require_retention_delivery(
            _factory=_RETENTION_DELIVERY_FACTORY,
            _lock_authority=_lock_authority,
        )

        def settled_ack() -> AckJournalSnapshot:
            snapshot = self._acknowledgements.snapshot()
            self._validate_ack_snapshot(snapshot)
            if not snapshot.healthy:
                raise CoreControllerAuthorityError(
                    "retention requires one healthy ACK snapshot"
                )
            confirmed = snapshot.confirmed
            if confirmed is not None:
                ref = self._ref_at(confirmed.sequence)
                if not self._ack_matches_ref(confirmed, ref):
                    raise CoreControllerAuthorityError(
                        "retention ACK differs from authenticated evidence"
                    )
            pending = snapshot.pending
            if pending is not None:
                ref = self._ref_at(pending.sequence)
                if (
                    pending.sequence <= snapshot.confirmed_through
                    or not self._ack_matches_ref(pending, ref)
                ):
                    raise CoreControllerAuthorityError(
                        "retention pending ACK differs from authenticated evidence"
                    )
            return snapshot

        def request_identity(
            state: RetentionStateV1,
        ) -> tuple[_RetentionRequestKind, str]:
            request = state.request
            if type(request) is RetentionTombstoneV2:
                return "tombstone", request.tombstone_id
            if type(request) is RetentionBlockedV1:
                return "blocked", request.blocked_id
            raise CoreControllerAuthorityError(
                "retention state has an inexact request"
            )

        def target_identity(
            target: RetentionTargetV1 | EvidenceRef | None,
        ) -> tuple[int | None, str | None, str | None]:
            if target is None:
                return None, None, None
            if type(target) is RetentionTargetV1:
                return (
                    target.sequence,
                    target.event_id,
                    target.content_sha256,
                )
            if type(target) is EvidenceRef:
                return (
                    target.source_sequence,
                    target.event_id,
                    target.content_sha256,
                )
            raise CoreControllerAuthorityError(
                "retention target identity is inexact"
            )

        def state_observation(
            state: RetentionStateV1,
            *,
            outcome: RetentionOutcome,
            retry_reason: RetentionRetryReason | None = None,
            target_ref: EvidenceRef | None = None,
            unlinked_manifest_count: int = 0,
            unlinked_bytes: int = 0,
            projection_rebuilt: bool = False,
        ) -> _RetentionObservation:
            request_kind, request_id = request_identity(state)
            target: RetentionTargetV1 | EvidenceRef | None = (
                target_ref if target_ref is not None else state.target
            )
            target_sequence, target_event_id, target_content_sha256 = (
                target_identity(target)
            )
            return _RetentionObservation(
                outcome=outcome,
                retry_reason=retry_reason,
                request_kind=request_kind,
                request_id=request_id,
                target_sequence=target_sequence,
                target_event_id=target_event_id,
                target_content_sha256=target_content_sha256,
                unlinked_manifest_count=unlinked_manifest_count,
                unlinked_bytes=unlinked_bytes,
                projection_rebuilt=projection_rebuilt,
            )

        initial_ack = settled_ack()
        if initial_ack.pending is not None:
            return _RetentionObservation(
                outcome="retry_required",
                retry_reason="pending_ack",
                request_kind=None,
                request_id=None,
                target_sequence=None,
                target_event_id=None,
                target_content_sha256=None,
                unlinked_manifest_count=0,
                unlinked_bytes=0,
                projection_rebuilt=False,
            )

        journal = _open_retention_state_journal(self._store)
        state = journal.state
        if state is None:
            snapshot = self._store._freeze_retention_snapshot(
                self._decision_sample(),
                _factory=_RETENTION_PROOF_FACTORY,
            )
            decision = _select_retention_lazily(snapshot)
            request = decision.request
            if request is None:
                reused = decision.reused_blocked
                if reused is None:
                    return _RetentionObservation(
                        outcome="not_due",
                        retry_reason=None,
                        request_kind=None,
                        request_id=None,
                        target_sequence=None,
                        target_event_id=None,
                        target_content_sha256=None,
                        unlinked_manifest_count=0,
                        unlinked_bytes=0,
                        projection_rebuilt=False,
                    )
                if type(reused) is not AcceptedRetentionBlocked:
                    raise CoreControllerAuthorityError(
                        "retention reused blocked authority is inexact"
                    )
                blocked = reused.request
                return _RetentionObservation(
                    outcome="blocked_unchanged",
                    retry_reason=None,
                    request_kind="blocked",
                    request_id=blocked.blocked_id,
                    target_sequence=reused.sequence,
                    target_event_id=reused.event_id,
                    target_content_sha256=reused.content_sha256,
                    unlinked_manifest_count=0,
                    unlinked_bytes=0,
                    projection_rebuilt=False,
                )
            journal.prepare_publication(decision)
            state = journal.state
            if type(state) is not RetentionStateV1:
                raise CoreControllerAuthorityError(
                    "retention selection did not publish exact durable state"
                )
        elif type(state) is not RetentionStateV1:
            raise CoreControllerAuthorityError(
                "retention journal returned an inexact state"
            )

        if state.phase not in {
            "selected",
            "target_bound",
            "evidence_appended",
        }:
            raise RetentionProtocolError(
                "durable retention execution phase requires restart recovery"
            )

        selected_max: int | None = None
        if state.operation == "tombstone":
            selected_max = self._store._retention_selected_max_sequence(
                state
            )
            if selected_max >= MAX_UINT64:
                raise RetentionProtocolError(
                    "retention selection has no surviving ACK position"
                )
            before_delivery = settled_ack()
            if before_delivery.pending is not None:
                return state_observation(
                    state,
                    outcome="retry_required",
                    retry_reason="pending_ack",
                )
            if before_delivery.confirmed_through < selected_max:
                return state_observation(
                    state,
                    outcome="retry_required",
                    retry_reason="ack_prefix_lag",
                )

        delivery_phase = state.phase
        delivery_status = self._store.status()
        self._validate_evidence_status(delivery_status)
        future_observer_path = delivery_phase == "selected" or (
            delivery_phase == "target_bound"
            and type(state.target) is RetentionTargetV1
            and state.target.sequence > delivery_status.evidence_head
        )
        try:
            target_ref = (
                await self._delivery._deliver_retention_target_locked(
                    journal,
                    _factory=_RETENTION_DELIVERY_FACTORY,
                    _lock_authority=_lock_authority,
                )
            )
        except DeliveryRetryableError:
            if not future_observer_path:
                raise
            retry_ack = settled_ack()
            journal._assert_consistent()
            durable_state = journal.state
            durable_raw = journal._raw
            if (
                type(durable_state) is not RetentionStateV1
                or type(durable_raw) is not bytes
                or durable_state.phase not in {
                    "selected",
                    "target_bound",
                }
            ):
                raise
            journal._prove_publication(durable_raw)
            if retry_ack.pending is not None:
                return state_observation(
                    durable_state,
                    outcome="retry_required",
                    retry_reason="pending_ack",
                )
            return state_observation(
                durable_state,
                outcome="retry_required",
                retry_reason="observer_retryable",
            )

        state = journal.state
        if (
            type(state) is not RetentionStateV1
            or state.phase != "evidence_appended"
        ):
            raise CoreControllerAuthorityError(
                "retention delivery did not publish exact evidence authority"
            )
        request_kind, _request_id = request_identity(state)
        if request_kind == "blocked":
            self._delivery._clear_retention_blocked_locked(
                journal,
                target_ref,
                _factory=_RETENTION_DELIVERY_FACTORY,
                _lock_authority=_lock_authority,
            )
            return state_observation(
                state,
                outcome="blocked_reported",
                target_ref=target_ref,
            )

        if selected_max is None:
            raise CoreControllerAuthorityError(
                "tombstone retention lost its selected range"
            )
        surviving_ack = settled_ack()
        if surviving_ack.pending is not None:
            return state_observation(
                state,
                outcome="retry_required",
                retry_reason="pending_ack",
                target_ref=target_ref,
            )
        if surviving_ack.confirmed_through < selected_max + 1:
            return state_observation(
                state,
                outcome="retry_required",
                retry_reason="ack_prefix_lag",
                target_ref=target_ref,
            )

        final_snapshot = self._store._freeze_retention_snapshot(
            self._decision_sample(),
            _factory=_RETENTION_PROOF_FACTORY,
        )
        proof = self._store._authenticate_retention_tombstone(
            journal,
            final_snapshot,
            target_ref,
            _factory=_RETENTION_PROOF_FACTORY,
        )
        completion = self._store._execute_authenticated_retention_unlink(
            proof,
            _factory=_RETENTION_PROOF_FACTORY,
        )
        try:
            rebuild = (
                self._projection
                ._rebuild_after_authenticated_retention(
                    completion,
                    _factory=_RETENTION_REBUILD_FACTORY,
                )
            )
            if type(rebuild) is not RebuildReport:
                raise CoreControllerAuthorityError(
                    "retention projection rebuild result is inexact"
                )
            rebuilt_ack = settled_ack()
            rebuilt_status = self._projection.status()
            rebuilt_cursor, rebuilt_terminal = self._projection_boundary(
                rebuilt_ack,
                rebuilt_status,
            )
            rebuilt_confirmed = rebuilt_ack.confirmed
            if (
                rebuilt_ack != surviving_ack
                or rebuilt_confirmed is None
                or rebuilt_terminal is None
                or rebuilt_cursor != rebuilt_confirmed.sequence
                or rebuilt_status.cursor != rebuild.cursor
                or rebuild.cursor is None
                or not self._cursor_matches_ref(
                    rebuild.cursor,
                    rebuilt_terminal,
                )
                or not self._projection._is_bound_to(
                    self._store,
                    self._acknowledgements,
                    self._correlation_requests,
                    self._registry,
                )
            ):
                raise CoreControllerAuthorityError(
                    "retention projection rebuild lost exact ACK authority"
                )
        except BaseException:
            self._latch_projection_failure()
            raise
        self._store._finalize_authenticated_retention_completion(
            completion,
            _factory=_RETENTION_PROOF_FACTORY,
        )
        request = state.request
        if type(request) is not RetentionTombstoneV2:
            raise CoreControllerAuthorityError(
                "completed retention request is not an exact tombstone"
            )
        return state_observation(
            state,
            outcome="tombstone_completed",
            target_ref=target_ref,
            unlinked_manifest_count=len(
                request.removed_manifest_hashes
            ),
            unlinked_bytes=request.removed_bytes,
            projection_rebuilt=True,
        )

    async def _run_retention_once(self) -> _RetentionExecution:
        async with self._lock:
            self._require_open()
            projected = self._catch_up_projection_for_retention()
            if not self._projection_healthy:
                raise CoreControllerAuthorityError(
                    "retention requires complete projection catch-up"
                )
            async with self._delivery._retention_preflight_scope(
                _factory=_RETENTION_DELIVERY_FACTORY,
            ) as lock_authority:
                observation = await self._execute_retention_locked(
                    _lock_authority=lock_authority,
                )
            projected += self._catch_up_projection_for_retention()
            if not self._projection_healthy:
                raise CoreControllerAuthorityError(
                    "retention projection catch-up failed"
                )
            readiness = self._mutation_readiness()
            return _RetentionExecution(
                observation=observation,
                projected=projected,
                readiness=readiness,
            )

    async def run_retention_once(self) -> CoreRetentionResult:
        """Execute at most one retention transaction and return observation only."""
        execution = await self._run_retention_once()
        return _public_retention_result(execution)

    async def poll_once(self, *, limit: int = MAX_PAGE_EVENTS) -> CorePollResult:
        if (
            type(limit) is not int
            or not 1 <= limit <= MAX_PAGE_EVENTS
        ):
            raise ValueError("poll limit must be in 1..100")
        async with self._lock:
            self._require_open()
            projected = self._catch_up_projection()
            delivery = await self._delivery.poll_once(limit=limit)
            projected += self._catch_up_projection()
            readiness = self._mutation_readiness()
            return CorePollResult(
                delivery=delivery,
                projected=projected,
                readiness=readiness,
            )

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._candidate_admission_binding = None
            self._admission_lifecycle = object()
            self._closed = True
            primary: BaseException | None = None

            async def close_delivery() -> None:
                await self._delivery.close()

            steps = (
                close_delivery,
                self._projection.close,
                self._coverage.close,
                self._correlation_requests.close,
                self._acknowledgements.close,
                self._store.close,
            )
            for step in steps:
                try:
                    outcome = step()
                    if outcome is not None:
                        await outcome
                except BaseException as error:  # noqa: BLE001 - cleanup boundary
                    if primary is None:
                        primary = error
                    else:
                        primary.add_note(
                            "secondary Core cleanup failure "
                            f"({type(error).__name__})"
                        )
            if primary is not None:
                raise primary
