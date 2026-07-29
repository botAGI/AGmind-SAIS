"""Production composition root for delivery, coverage, and projection."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from agmind_immune.clock import (
    CoreClockProvider,
    CoreClockSample,
    _validate_core_clock_sample,
)
from agmind_immune.contracts import MAX_UINT64
from agmind_immune.coverage import (
    CoverageState,
    MutationReadiness,
    MutationReadinessContext,
)
from agmind_immune.evidence.projection import (
    ProjectionApplyResult,
    ProjectionCursor,
    ProjectionError,
    ProjectionStatus,
    ProjectionStore,
)
from agmind_immune.evidence.segments import (
    EvidenceRef,
    EvidenceStatus,
    EvidenceStoreError,
    SegmentStore,
    StoredEvidenceRecord,
)
from agmind_immune.ingest.ack_journal import (
    AckIdentity,
    AckJournal,
    AckJournalError,
    AckJournalSnapshot,
)
from agmind_immune.ingest.envelope import MAX_PAGE_EVENTS, EnvelopeVerifier
from agmind_immune.ingest.service import (
    AcceptanceCoordinator,
    DeliveryCoordinator,
    ObserverCoreTransport,
    PollResult,
)

_CONTROLLER_FACTORY = object()
_PROJECTION_BATCH = 100


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


class CoreController:
    """Own one exact live evidence/ACK/coverage/projection composition."""

    def __init__(
        self,
        acceptance: AcceptanceCoordinator,
        acknowledgements: AckJournal,
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
        self._coverage = coverage
        self._projection = projection
        self._clock = clock
        self._delivery = delivery
        self._lock = asyncio.Lock()
        self._projection_healthy = True
        self._closed = False

    @classmethod
    def create(
        cls,
        acceptance: AcceptanceCoordinator,
        acknowledgements: AckJournal,
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
        if not projection._is_bound_to(store, acknowledgements):
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
                or not projection._is_bound_to(store, acknowledgements)
                or delivery._store is not store
                or delivery._verifier is not verifier
                or not delivery._is_bound_to(
                    acceptance,
                    acknowledgements,
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
            self._closed = True
            primary: BaseException | None = None

            async def close_delivery() -> None:
                await self._delivery.close()

            steps = (
                close_delivery,
                self._projection.close,
                self._coverage.close,
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
