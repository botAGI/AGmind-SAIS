"""Durable observer acceptance and bounded Phase-5C1 delivery coordination."""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, final

import httpx

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.clock import CoreClockProvider
from agmind_immune.contracts import MAX_UINT64
from agmind_immune.coverage import CoverageAckBarrier, CoverageState
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    EvidenceStatus,
    SegmentStore,
)
from agmind_immune.ingest.ack_journal import (
    AckDeliveryLease,
    AckIdentity,
    AckJournal,
    AckJournalSnapshot,
)
from agmind_immune.ingest.envelope import (
    MAX_CORE_EVENT_RESPONSE_BYTES,
    MAX_EVENTS_PAGE_BYTES,
    MAX_PAGE_EVENTS,
    CoreEventsPageV1,
    CoreEventV1,
    EnvelopeConflict,
    EnvelopeVerifier,
    PageDecodeError,
    decode_core_event,
    decode_events_page,
)

_COORDINATOR_FACTORY = object()
_REPAIR_ACCEPTANCE_FACTORY = object()
_DELIVERY_FACTORY = object()
_REPAIR_DELIVERY_FACTORY = object()
_COVERAGE_ADAPTER_FACTORY = object()
_MAX_ERROR_BODY_BYTES = 4_096
_MAX_REPAIR_DRAIN_EVENTS = 4_096
_MAX_REPAIR_DRAIN_PAGES = 64
_MAX_REPAIR_DRAIN_RESPONSE_BYTES = 64 * 1024 * 1024


@final
class AcceptanceCoordinator:
    """Durably append a staged envelope before committing verifier/FSM state."""

    __slots__ = ("_repair_mode", "_segment_store", "_verifier")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("AcceptanceCoordinator is final")

    def __init__(
        self,
        verifier: EnvelopeVerifier,
        segment_store: SegmentStore,
        *,
        _repair_mode: bool = False,
        _factory: object,
    ) -> None:
        if (
            (_factory is _COORDINATOR_FACTORY and _repair_mode is not False)
            or (
                _factory is _REPAIR_ACCEPTANCE_FACTORY
                and _repair_mode is not True
            )
            or (
                _factory is not _COORDINATOR_FACTORY
                and _factory is not _REPAIR_ACCEPTANCE_FACTORY
            )
        ):
            raise TypeError(
                "use AcceptanceCoordinator.create_empty() or open_and_recover()"
            )
        self._verifier = verifier
        self._segment_store = segment_store
        self._repair_mode = _repair_mode

    @property
    def verifier(self) -> EnvelopeVerifier:
        return self._verifier

    @property
    def segment_store(self) -> SegmentStore:
        return self._segment_store

    def _accept_bound(self, item: CoreEventV1) -> EvidenceRef:
        verifier = self._verifier
        segment_store = self._segment_store
        try:
            verified = verifier.verify(
                item.envelope,
                sequence=item.sequence,
                event_id=item.event_id,
                content_sha256=item.content_sha256,
            )
        except EnvelopeConflict:
            segment_store.enter_read_only("evidence_conflict")
            verifier._enter_read_only_after_durable_fence()
            raise
        return segment_store.append(
            verified,
            EvidencePriority(verified.evidence_priority),
        )

    def accept(self, item: CoreEventV1) -> EvidenceRef:
        status = self._segment_store.status()
        if self._repair_mode or (
            type(status) is EvidenceStatus
            and status.repair_pending is True
        ):
            raise DeliveryFatalError(
                "repair-resumed acceptance requires repair delivery authority"
            )
        return self._accept_bound(item)

    def _accept_for_repair(
        self,
        item: CoreEventV1,
        *,
        _factory: object,
    ) -> EvidenceRef:
        if _factory is not _REPAIR_DELIVERY_FACTORY:
            raise TypeError("repair acceptance requires the delivery factory")
        status = self._segment_store.status()
        if (
            self._repair_mode is not True
            or type(status) is not EvidenceStatus
            or status.repair_pending is not True
            or not self._segment_store._is_bound_verifier(self._verifier)
        ):
            raise DeliveryFatalError(
                "repair acceptance is outside its resumed delivery lifecycle"
            )
        return self._accept_bound(item)

    def _finish_repair_resume(self, *, _factory: object) -> None:
        if _factory is not _REPAIR_DELIVERY_FACTORY:
            raise TypeError("repair acceptance finalization requires the delivery factory")
        status = self._segment_store.status()
        if (
            self._repair_mode is not True
            or type(status) is not EvidenceStatus
            or not status.healthy
            or status.repair_pending is not False
            or not self._segment_store._is_bound_verifier(self._verifier)
        ):
            raise DeliveryFatalError(
                "repair acceptance cannot become ordinary before gate clear"
            )
        self._repair_mode = False

    @classmethod
    def create_empty(
        cls,
        verifier: EnvelopeVerifier,
        segment_store: SegmentStore,
    ) -> AcceptanceCoordinator:
        """Bind a verifier only when the locked evidence lifecycle is pristine."""
        segment_store._bind_empty(verifier)
        return cls(verifier, segment_store, _factory=_COORDINATOR_FACTORY)

    @classmethod
    def open_and_recover(
        cls,
        verifier: EnvelopeVerifier,
        segment_store: SegmentStore,
    ) -> AcceptanceCoordinator:
        """Rebuild verifier authority from every reverified AGF1 record."""
        segment_store._bind_and_recover(verifier)
        return cls(verifier, segment_store, _factory=_COORDINATOR_FACTORY)

    @classmethod
    def _from_repair_resume(
        cls,
        verifier: EnvelopeVerifier,
        segment_store: SegmentStore,
        *,
        _factory: object,
    ) -> AcceptanceCoordinator:
        """Wrap the already-recovered same-lock store without verifier replay."""
        if _factory is not _REPAIR_ACCEPTANCE_FACTORY:
            raise TypeError("repair acceptance requires the exact repair factory")
        if (
            type(verifier) is not EnvelopeVerifier
            or type(segment_store) is not SegmentStore
            or segment_store._repair_resumed is not True
            or segment_store.status().repair_pending is not True
            or not segment_store._is_bound_verifier(verifier)
        ):
            raise DeliveryFatalError(
                "repair acceptance requires one resumed bound store"
            )
        return cls(
            verifier,
            segment_store,
            _repair_mode=True,
            _factory=_REPAIR_ACCEPTANCE_FACTORY,
        )

    recover = open_and_recover


class DeliveryError(RuntimeError):
    """Base class for observer delivery failures."""


class DeliveryRetryableError(DeliveryError):
    """A fetch failed before it could change observer ACK authority."""


class DeliveryAmbiguousAck(DeliveryRetryableError):
    """An ACK may have committed remotely and must be retried byte-for-byte."""


class DeliveryFatalError(DeliveryError):
    """Delivery authority or protocol state is unsafe until restart/operator repair."""


class ObserverCoreTransport(Protocol):
    async def fetch_events(self, *, after: int, limit: int) -> bytes: ...

    async def ack_event(self, body: bytes) -> None: ...

    async def publish_repair_authorization(self, canonical_body: bytes) -> bytes: ...

    async def publish_repair_completion(self, canonical_body: bytes) -> bytes: ...

    async def close(self) -> None: ...


@dataclass(frozen=True)
class PollResult:
    accepted: int
    confirmed: int
    evidence_head: int
    acceptance_cursor: int
    confirmed_through: int
    pending: AckIdentity | None
    retry_required: bool


class HTTPXObserverCoreTransport:
    """One bounded HTTP/1.1 client for the observer Core-only UDS."""

    def __init__(
        self,
        socket_path: str | Path,
        *,
        timeout: httpx.Timeout | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        selected_timeout = timeout or httpx.Timeout(
            connect=2.0,
            read=12.0,
            write=5.0,
            pool=1.0,
        )
        self._validate_timeout(selected_timeout)
        limits = httpx.Limits(
            max_connections=1,
            max_keepalive_connections=1,
        )
        selected_transport = transport
        if selected_transport is None:
            selected_transport = httpx.AsyncHTTPTransport(
                uds=str(socket_path),
                http1=True,
                http2=False,
                limits=limits,
                retries=0,
            )
        self._client = httpx.AsyncClient(
            base_url="http://observer",
            transport=selected_transport,
            timeout=selected_timeout,
            limits=limits,
            trust_env=False,
            follow_redirects=False,
        )
        self._closed = False

    @staticmethod
    def _validate_timeout(timeout: httpx.Timeout) -> None:
        for field in ("connect", "read", "write", "pool"):
            value = getattr(timeout, field)
            if (
                value is None
                or isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value <= 0
                or not math.isfinite(value)
            ):
                raise ValueError("observer transport timeout must be finite")

    @staticmethod
    async def _read_raw_bounded(
        response: httpx.Response,
        limit: int,
    ) -> bytes:
        collected = bytearray()
        async for chunk in response.aiter_raw():
            remaining = limit - len(collected)
            if remaining <= 0:
                break
            collected.extend(chunk[:remaining])
            if len(chunk) >= remaining:
                break
        return bytes(collected)

    @classmethod
    async def _discard_error_body(cls, response: httpx.Response) -> None:
        try:
            await cls._read_raw_bounded(response, _MAX_ERROR_BODY_BYTES)
        except (httpx.HTTPError, OSError, TimeoutError):
            # Headers already determine the protocol class. A broken private
            # diagnostic body must not downgrade a known fatal status.
            return

    @staticmethod
    def _validate_fetch_arguments(after: int, limit: int) -> None:
        if (
            isinstance(after, bool)
            or not isinstance(after, int)
            or not 0 <= after <= MAX_UINT64
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_PAGE_EVENTS
        ):
            raise DeliveryFatalError("observer fetch arguments are invalid")

    async def fetch_events(self, *, after: int, limit: int) -> bytes:
        if self._closed:
            raise DeliveryFatalError("observer transport is closed")
        self._validate_fetch_arguments(after, limit)
        path = f"/v1/events?after={after}&limit={limit}"
        try:
            async with self._client.stream("GET", path) as response:
                if "content-encoding" in response.headers:
                    await self._discard_error_body(response)
                    raise DeliveryFatalError(
                        "observer fetch response has Content-Encoding"
                    )
                if 500 <= response.status_code <= 599:
                    await self._discard_error_body(response)
                    raise DeliveryRetryableError(
                        f"observer fetch returned {response.status_code}"
                    )
                if response.status_code != 200:
                    await self._discard_error_body(response)
                    raise DeliveryFatalError(
                        f"observer fetch returned {response.status_code}"
                    )
                if response.headers.get("Content-Type") != "application/json":
                    await self._discard_error_body(response)
                    raise DeliveryFatalError(
                        "observer fetch Content-Type is not exact JSON"
                    )
                raw = await self._read_raw_bounded(
                    response,
                    MAX_EVENTS_PAGE_BYTES + 1,
                )
                if len(raw) > MAX_EVENTS_PAGE_BYTES:
                    raise DeliveryFatalError("observer fetch page exceeds bound")
                return raw
        except DeliveryError:
            raise
        except (httpx.HTTPError, OSError, TimeoutError) as error:
            raise DeliveryRetryableError("observer fetch transport failed") from error

    async def ack_event(self, body: bytes) -> None:
        if self._closed:
            raise DeliveryFatalError("observer transport is closed")
        try:
            async with self._client.stream(
                "POST",
                "/v1/events/ack",
                content=body,
                headers={"Content-Type": "application/json"},
            ) as response:
                if "content-encoding" in response.headers:
                    await self._discard_error_body(response)
                    raise DeliveryFatalError(
                        "observer ACK response has Content-Encoding"
                    )
                if response.status_code == 204:
                    delivered = await self._read_raw_bounded(response, 1)
                    if delivered:
                        raise DeliveryFatalError(
                            "observer ACK 204 delivered a response body"
                        )
                    return
                await self._discard_error_body(response)
                if 500 <= response.status_code <= 599:
                    raise DeliveryAmbiguousAck(
                        f"observer ACK returned {response.status_code}"
                    )
                if response.status_code == 409:
                    raise DeliveryFatalError("observer rejected exact ACK authority")
                raise DeliveryFatalError(
                    f"observer ACK returned {response.status_code}"
                )
        except DeliveryError:
            raise
        except (httpx.HTTPError, OSError, TimeoutError) as error:
            raise DeliveryAmbiguousAck("observer ACK transport failed") from error

    async def _publish_repair(self, path: str, canonical_body: bytes) -> bytes:
        if self._closed:
            raise DeliveryFatalError("observer transport is closed")
        if type(canonical_body) is not bytes or not canonical_body:
            raise DeliveryFatalError("repair request body must be exact nonempty bytes")
        try:
            async with self._client.stream(
                "POST",
                path,
                content=canonical_body,
                headers={"Content-Type": "application/json"},
            ) as response:
                if "content-encoding" in response.headers:
                    await self._discard_error_body(response)
                    raise DeliveryFatalError(
                        "observer repair response has Content-Encoding"
                    )
                if response.status_code in (200, 201):
                    if response.headers.get("Content-Type") != "application/json":
                        await self._discard_error_body(response)
                        raise DeliveryFatalError(
                            "observer repair Content-Type is not exact JSON"
                        )
                    raw = await self._read_raw_bounded(
                        response,
                        MAX_CORE_EVENT_RESPONSE_BYTES + 1,
                    )
                    if len(raw) > MAX_CORE_EVENT_RESPONSE_BYTES:
                        raise DeliveryFatalError(
                            "observer repair response exceeds bound"
                        )
                    return raw
                await self._discard_error_body(response)
                if response.status_code == 409:
                    raise DeliveryFatalError(
                        "observer rejected exact repair authority"
                    )
                if response.status_code == 408 or 500 <= response.status_code <= 599:
                    raise DeliveryRetryableError(
                        f"observer repair POST returned {response.status_code}"
                    )
                raise DeliveryFatalError(
                    f"observer repair POST returned {response.status_code}"
                )
        except DeliveryError:
            raise
        except (httpx.HTTPError, OSError, TimeoutError) as error:
            raise DeliveryRetryableError(
                "observer repair POST transport failed"
            ) from error

    async def publish_repair_authorization(self, canonical_body: bytes) -> bytes:
        return await self._publish_repair(
            "/v1/events/evidence-repair-authorize",
            canonical_body,
        )

    async def publish_repair_completion(self, canonical_body: bytes) -> bytes:
        return await self._publish_repair(
            "/v1/events/evidence-repair-complete",
            canonical_body,
        )

    async def close(self) -> None:
        if self._closed:
            return
        await self._client.aclose()
        self._closed = True


@dataclass(frozen=True)
class _DeliveryState:
    evidence_head: int
    acceptance_cursor: int
    confirmed_through: int
    pending: AckIdentity | None
    pending_ref: EvidenceRef | None
    pending_body: bytes | None
    delivery_ceiling: int


@final
class _CoverageDeliveryAdapter:
    __slots__ = ("_barrier", "_coverage", "_evidence")

    def __init__(
        self,
        factory: object,
        coverage: CoverageState,
        barrier: CoverageAckBarrier,
        evidence: SegmentStore,
    ) -> None:
        if factory is not _COVERAGE_ADAPTER_FACTORY:
            raise TypeError("coverage delivery adapter is factory-only")
        self._coverage = coverage
        self._barrier = barrier
        self._evidence = evidence

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("coverage delivery adapter is final")

    def apply_live_accepted(
        self,
        ref: EvidenceRef,
        receipt_monotonic: float | None,
    ) -> None:
        self._coverage._apply_live_accepted(
            self._evidence,
            ref,
            receipt_monotonic,
        )

    def first_unclosed_sequence_gap(self) -> int | None:
        return self._barrier._first_unclosed_sequence_gap(self._evidence)


@final
class DeliveryCoordinator:
    """Serialize one evidence-first observer delivery/ACK lifecycle."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("DeliveryCoordinator is final")

    def __init__(
        self,
        acceptance: AcceptanceCoordinator,
        store: SegmentStore,
        verifier: EnvelopeVerifier,
        ack_journal: AckJournal,
        delivery_lease: AckDeliveryLease,
        transport: ObserverCoreTransport,
        *,
        coverage_adapter: _CoverageDeliveryAdapter,
        clock: CoreClockProvider,
        ack_budget: int = MAX_PAGE_EVENTS,
        _repair_mode: bool = False,
        _factory: object,
    ) -> None:
        if (
            (_factory is _DELIVERY_FACTORY and _repair_mode is not False)
            or (
                _factory is _REPAIR_DELIVERY_FACTORY
                and _repair_mode is not True
            )
            or (
                _factory is not _DELIVERY_FACTORY
                and _factory is not _REPAIR_DELIVERY_FACTORY
            )
        ):
            raise TypeError("use DeliveryCoordinator.create()")
        if type(delivery_lease) is not AckDeliveryLease:
            raise TypeError("delivery requires an exact ACK-journal lease")
        if type(coverage_adapter) is not _CoverageDeliveryAdapter:
            raise TypeError("delivery requires its exact coverage adapter")
        if (
            isinstance(ack_budget, bool)
            or not isinstance(ack_budget, int)
            or not 1 <= ack_budget <= MAX_PAGE_EVENTS
        ):
            raise ValueError("ACK budget must be in 1..100")
        self._acceptance = acceptance
        self._store = store
        self._verifier = verifier
        self._ack_journal = ack_journal
        self._delivery_lease = delivery_lease
        self._transport = transport
        self._coverage_adapter = coverage_adapter
        self._clock = clock
        self._ack_budget = ack_budget
        self._repair_mode = _repair_mode
        self._lock = asyncio.Lock()
        self._fatal: DeliveryFatalError | None = None
        self._closed = False
        self._transport_closed = False
        self._lease_released = False

    @classmethod
    def create(
        cls,
        acceptance: AcceptanceCoordinator,
        acknowledgements: AckJournal,
        transport: ObserverCoreTransport,
        *,
        coverage: CoverageState,
        clock: CoreClockProvider,
        ack_budget: int = MAX_PAGE_EVENTS,
    ) -> DeliveryCoordinator:
        return cls._compose(
            acceptance,
            acknowledgements,
            transport,
            coverage=coverage,
            clock=clock,
            ack_budget=ack_budget,
            repair_mode=False,
            factory=_DELIVERY_FACTORY,
        )

    @classmethod
    def _create_for_repair(
        cls,
        acceptance: AcceptanceCoordinator,
        acknowledgements: AckJournal,
        transport: ObserverCoreTransport,
        *,
        coverage: CoverageState,
        clock: CoreClockProvider,
        ack_budget: int = MAX_PAGE_EVENTS,
        _factory: object,
    ) -> DeliveryCoordinator:
        if _factory is not _REPAIR_DELIVERY_FACTORY:
            raise TypeError("repair delivery requires the exact repair factory")
        return cls._compose(
            acceptance,
            acknowledgements,
            transport,
            coverage=coverage,
            clock=clock,
            ack_budget=ack_budget,
            repair_mode=True,
            factory=_REPAIR_DELIVERY_FACTORY,
        )

    @classmethod
    def _compose(
        cls,
        acceptance: AcceptanceCoordinator,
        acknowledgements: AckJournal,
        transport: ObserverCoreTransport,
        *,
        coverage: CoverageState,
        clock: CoreClockProvider,
        ack_budget: int,
        repair_mode: bool,
        factory: object,
    ) -> DeliveryCoordinator:
        if type(acceptance) is not AcceptanceCoordinator:
            raise TypeError("delivery requires exact acceptance authority")
        store = acceptance.segment_store
        verifier = acceptance.verifier
        if type(store) is not SegmentStore or type(verifier) is not EnvelopeVerifier:
            raise TypeError("delivery requires exact evidence authority")
        if type(acknowledgements) is not AckJournal:
            raise TypeError("delivery requires exact ACK authority")
        if type(coverage) is not CoverageState:
            raise TypeError("delivery requires exact coverage authority")
        mode_status = store.status()
        if (
            type(mode_status) is not EvidenceStatus
            or type(mode_status.repair_pending) is not bool
            or mode_status.repair_pending is not repair_mode
        ):
            raise DeliveryFatalError(
                "delivery mode does not match the evidence repair gate"
            )
        if (
            acceptance.segment_store is not store
            or acceptance.verifier is not verifier
            or acceptance._repair_mode is not repair_mode
            or not store._is_bound_verifier(verifier)
        ):
            raise DeliveryFatalError("acceptance authority binding is invalid")
        if (
            not callable(getattr(clock, "live_receipt_monotonic", None))
            or not callable(getattr(clock, "decision_sample", None))
        ):
            raise TypeError("delivery requires one typed Core clock provider")
        barrier = coverage.ack_barrier_capability()
        if type(barrier) is not CoverageAckBarrier:
            raise DeliveryFatalError("coverage issued a non-exact ACK barrier")
        barrier._first_unclosed_sequence_gap(store)
        adapter = _CoverageDeliveryAdapter(
            _COVERAGE_ADAPTER_FACTORY,
            coverage,
            barrier,
            store,
        )
        lease = acknowledgements.claim_delivery(store)
        try:
            delivery = cls(
                acceptance,
                store,
                verifier,
                acknowledgements,
                lease,
                transport,
                coverage_adapter=adapter,
                clock=clock,
                ack_budget=ack_budget,
                _repair_mode=repair_mode,
                _factory=factory,
            )
            if (
                acceptance.segment_store is not store
                or acceptance.verifier is not verifier
                or not store._is_bound_verifier(verifier)
                or delivery._store is not store
                or delivery._verifier is not verifier
                or not delivery._status_matches_repair_mode(
                    store.status(),
                )
            ):
                raise DeliveryFatalError(
                    "acceptance authority changed during delivery composition"
                )
            return delivery
        except BaseException as primary:
            try:
                lease.release()
            except BaseException as cleanup_error:  # noqa: BLE001
                primary.add_note(
                    "secondary delivery composition cleanup failure "
                    f"({type(cleanup_error).__name__})"
                )
            raise

    @property
    def acceptance(self) -> AcceptanceCoordinator:
        return self._acceptance

    @property
    def ack_journal(self) -> AckJournal:
        return self._ack_journal

    @property
    def transport(self) -> ObserverCoreTransport:
        return self._transport

    @property
    def ack_budget(self) -> int:
        return self._ack_budget

    def _is_bound_to(
        self,
        acceptance: AcceptanceCoordinator,
        acknowledgements: AckJournal,
        coverage: CoverageState,
        clock: CoreClockProvider,
    ) -> bool:
        return (
            self._acceptance is acceptance
            and self._ack_journal is acknowledgements
            and self._coverage_adapter._coverage is coverage
            and self._clock is clock
        )

    def _validate_acceptance_binding(self) -> None:
        if (
            self._acceptance.segment_store is not self._store
            or self._acceptance.verifier is not self._verifier
            or self._acceptance._repair_mode is not self._repair_mode
            or not self._store._is_bound_verifier(self._verifier)
        ):
            raise self._latch("retained acceptance authority changed")

    def _status_matches_repair_mode(self, status: object) -> bool:
        return (
            type(status) is EvidenceStatus
            and type(status.repair_pending) is bool
            and status.repair_pending is self._repair_mode
        )

    def _live_receipt(self) -> float | None:
        try:
            value = self._clock.live_receipt_monotonic()
        except Exception:  # noqa: BLE001 - optional provider receipt boundary
            return None
        if value is None:
            return None
        if (
            type(value) is not float
            or not math.isfinite(value)
            or value < 0
        ):
            return None
        return value

    def _raise_if_unavailable(self) -> None:
        if self._closed:
            raise DeliveryFatalError("delivery coordinator is closed")
        if self._fatal is not None:
            raise DeliveryFatalError(
                "delivery coordinator has latched a fatal failure"
            ) from self._fatal

    def _latch(self, message: str, error: BaseException | None = None) -> DeliveryFatalError:
        fatal = DeliveryFatalError(message)
        if self._fatal is None:
            self._fatal = fatal
        if error is not None:
            fatal.__cause__ = error
        return fatal

    def _authenticated_refs(
        self,
        *,
        after: int,
        through: int,
        limit: int,
    ) -> tuple[EvidenceRef, ...]:
        if through <= after or limit <= 0:
            return ()
        try:
            return self._store.authenticated_refs(
                after_sequence=after,
                through_sequence=through,
                limit=limit,
            )
        except Exception as error:  # noqa: BLE001 - evidence authority boundary
            raise self._latch("authenticated evidence lookup failed", error)

    @staticmethod
    def _identity_matches(ref: EvidenceRef, identity: AckIdentity) -> bool:
        return (
            ref.source_sequence == identity.sequence
            and ref.event_id == identity.event_id
            and ref.content_sha256 == identity.content_sha256
        )

    def _barrier_ceiling(
        self,
        *,
        evidence_head: int,
        acceptance_cursor: int,
        confirmed_through: int,
    ) -> int:
        try:
            barrier = self._coverage_adapter.first_unclosed_sequence_gap()
        except Exception as error:  # noqa: BLE001 - fail closed at capability boundary
            raise self._latch("evidence-derived ACK barrier failed", error)
        if barrier is None:
            return acceptance_cursor
        if (
            isinstance(barrier, bool)
            or not isinstance(barrier, int)
            or not 1 <= barrier <= evidence_head
            or barrier <= confirmed_through
        ):
            raise self._latch("evidence-derived ACK barrier is inconsistent")
        bound = self._authenticated_refs(
            after=barrier - 1,
            through=barrier,
            limit=1,
        )
        if len(bound) != 1 or bound[0].source_sequence != barrier:
            raise self._latch(
                "evidence-derived ACK barrier lacks an authenticated ref"
            )
        return min(acceptance_cursor, barrier - 1)

    def _local_state(
        self,
        *,
        apply_coverage_barrier: bool,
    ) -> _DeliveryState:
        self._raise_if_unavailable()
        try:
            self._validate_acceptance_binding()
            snapshot = self._ack_journal.snapshot()
            status = self._store.status()
            if type(snapshot) is not AckJournalSnapshot or not snapshot.healthy:
                raise self._latch("ACK journal is unhealthy")
            if type(status) is not EvidenceStatus or not status.healthy:
                raise self._latch("evidence status is unhealthy")
            if not self._status_matches_repair_mode(status):
                raise self._latch(
                    "delivery mode does not match the evidence repair gate"
                )
            pending_body = self._ack_journal.pending_request_body()
            evidence_head = status.evidence_head
            acceptance_cursor = status.acceptance_cursor
        except DeliveryFatalError:
            raise
        except Exception as error:  # noqa: BLE001 - local authority boundary
            raise self._latch("local delivery authority is unavailable", error)
        confirmed_through = snapshot.confirmed_through
        if not 0 <= confirmed_through <= acceptance_cursor <= evidence_head:
            raise self._latch("local delivery cursors are inconsistent")
        try:
            self._store.authenticated_refs(
                after_sequence=confirmed_through,
                through_sequence=confirmed_through,
                limit=1,
            )
        except Exception as error:  # noqa: BLE001 - store authority boundary
            raise self._latch("evidence store is unavailable for delivery", error)
        delivery_ceiling = (
            self._barrier_ceiling(
                evidence_head=evidence_head,
                acceptance_cursor=acceptance_cursor,
                confirmed_through=confirmed_through,
            )
            if apply_coverage_barrier
            else acceptance_cursor
        )
        pending_ref: EvidenceRef | None = None
        if snapshot.pending is None:
            if pending_body is not None:
                raise self._latch("ACK journal body exists without pending identity")
        else:
            pending = snapshot.pending
            if (
                pending_body is None
                or not confirmed_through < pending.sequence <= acceptance_cursor
                or (
                    apply_coverage_barrier
                    and pending.sequence > delivery_ceiling
                )
            ):
                raise self._latch("pending ACK is outside local delivery authority")
            first = self._authenticated_refs(
                after=confirmed_through,
                through=acceptance_cursor,
                limit=1,
            )
            if len(first) != 1 or not self._identity_matches(first[0], pending):
                raise self._latch(
                    "pending ACK is not the next authenticated evidence ref"
                )
            pending_ref = first[0]
            if apply_coverage_barrier:
                try:
                    # The exact idempotent transition re-proves that the
                    # recovered journal and this acceptance lifecycle bind the
                    # same ref only after the coverage ceiling is known.
                    self._ack_journal.record_pending(pending_ref)
                except Exception as error:  # noqa: BLE001 - journal authority boundary
                    raise self._latch(
                        "pending ACK is outside this evidence lifecycle",
                        error,
                    )
        return _DeliveryState(
            evidence_head=evidence_head,
            acceptance_cursor=acceptance_cursor,
            confirmed_through=confirmed_through,
            pending=snapshot.pending,
            pending_ref=pending_ref,
            pending_body=pending_body,
            delivery_ceiling=delivery_ceiling,
        )

    async def _post_pending(self, state: _DeliveryState) -> None:
        if (
            state.pending is None
            or state.pending_ref is None
            or state.pending_body is None
        ):
            raise self._latch("pending ACK lacks exact durable identity")
        try:
            await self._transport.ack_event(state.pending_body)
        except asyncio.CancelledError:
            raise
        except DeliveryAmbiguousAck:
            raise
        except DeliveryRetryableError as error:
            raise DeliveryAmbiguousAck(
                "observer ACK result is ambiguous"
            ) from error
        except DeliveryFatalError as error:
            raise self._latch("observer ACK failed fatally", error)
        except (httpx.HTTPError, OSError, TimeoutError) as error:
            raise DeliveryAmbiguousAck("observer ACK transport failed") from error
        except Exception as error:  # noqa: BLE001 - transport protocol boundary
            raise self._latch("observer ACK transport violated its contract", error)
        try:
            self._ack_journal.record_confirmed(state.pending_ref)
        except Exception as error:  # noqa: BLE001 - journal authority boundary
            raise self._latch(
                "ACK confirmation durability is uncertain",
                error,
            )

    async def recover_pending_ack(self) -> bool:
        if self._repair_mode:
            raise DeliveryFatalError(
                "repair delivery must recover pending ACKs through exact drain"
            )
        async with self._lock:
            state = self._local_state(apply_coverage_barrier=True)
            if state.pending is None:
                return False
            await self._post_pending(state)
            return True

    @staticmethod
    def _validate_page_binding(
        page: CoreEventsPageV1,
        *,
        after: int,
        limit: int,
        confirmed_through: int,
    ) -> None:
        if page.acked_through != confirmed_through:
            raise DeliveryFatalError("observer ACK cursor diverges from Core")
        if page.reserved_through < after:
            raise DeliveryFatalError("observer reservation cursor rolled back")
        if len(page.events) > limit:
            raise DeliveryFatalError("observer returned more events than requested")
        if any(
            event.sequence <= after or event.sequence <= page.acked_through
            for event in page.events
        ):
            raise DeliveryFatalError("observer event is outside the fetch request")
        if any(gap.start <= after for gap in page.uncovered_gaps):
            raise DeliveryFatalError("observer gap is outside the fetch request")

    async def _fetch_page_with_size(
        self,
        *,
        after: int,
        limit: int,
        confirmed_through: int,
    ) -> tuple[CoreEventsPageV1, int]:
        try:
            raw = await self._transport.fetch_events(after=after, limit=limit)
        except asyncio.CancelledError:
            raise
        except DeliveryRetryableError:
            raise
        except DeliveryFatalError as error:
            raise self._latch("observer fetch failed fatally", error)
        except (httpx.HTTPError, OSError, TimeoutError) as error:
            raise DeliveryRetryableError("observer fetch transport failed") from error
        except Exception as error:  # noqa: BLE001 - transport protocol boundary
            raise self._latch("observer fetch transport violated its contract", error)
        try:
            if type(raw) is not bytes:
                raise DeliveryFatalError(
                    "observer fetch returned a non-exact byte response"
                )
            page = decode_events_page(raw)
            self._validate_page_binding(
                page,
                after=after,
                limit=limit,
                confirmed_through=confirmed_through,
            )
            return page, len(raw)
        except DeliveryFatalError as error:
            raise self._latch("observer page binding is invalid", error)
        except PageDecodeError as error:
            raise self._latch("observer page is invalid", error)

    async def _fetch_page(
        self,
        *,
        after: int,
        limit: int,
        confirmed_through: int,
    ) -> CoreEventsPageV1:
        page, _size = await self._fetch_page_with_size(
            after=after,
            limit=limit,
            confirmed_through=confirmed_through,
        )
        return page

    @staticmethod
    def _repair_target_bytes(expected: CoreEventV1) -> bytes:
        if type(expected) is not CoreEventV1:
            raise TypeError("repair target must use the exact CoreEventV1 type")
        try:
            raw = canonical_json(expected.model_dump(mode="python"))
            decoded = decode_core_event(raw)
        except (TypeError, ValueError) as error:
            raise DeliveryFatalError(
                "repair target does not have an exact outer identity"
            ) from error
        if (
            canonical_json(decoded.model_dump(mode="python")) != raw
            or expected.envelope.get("event_type")
            not in {
                "evidence_repair_authorized",
                "evidence_repair_completed",
            }
        ):
            raise DeliveryFatalError("repair target is not an exact repair event")
        return raw

    def _exact_authenticated_target(
        self,
        expected: CoreEventV1,
    ) -> EvidenceRef:
        refs = self._authenticated_refs(
            after=expected.sequence - 1,
            through=expected.sequence,
            limit=1,
        )
        if len(refs) != 1 or refs[0].source_sequence != expected.sequence:
            raise self._latch(
                "exact repair target is absent from authenticated evidence"
            )
        ref = refs[0]
        try:
            record = self._store.resolve_authenticated_ref(ref)
            expected_envelope = canonical_json(expected.envelope)
        except Exception as error:  # noqa: BLE001 - authenticated store boundary
            raise self._latch(
                "exact repair target evidence lookup failed",
                error,
            )
        if (
            ref.event_id != expected.event_id
            or ref.content_sha256 != expected.content_sha256
            or record.canonical_envelope != expected_envelope
        ):
            raise self._latch(
                "authenticated evidence differs from the exact repair target"
            )
        return ref

    def _settle_repair_boundary(self) -> None:
        try:
            self._validate_acceptance_binding()
            before = self._store.status()
            if type(before) is not EvidenceStatus or not before.healthy:
                raise DeliveryFatalError(
                    "pre-settlement evidence status is unhealthy"
                )
            self._store.flush_security_boundary()
            self._validate_acceptance_binding()
            after = self._store.status()
            if (
                type(after) is not EvidenceStatus
                or not after.healthy
                or after.evidence_head != before.evidence_head
                or after.acceptance_cursor != before.acceptance_cursor
            ):
                raise DeliveryFatalError(
                    "repair settlement changed acceptance authority"
                )
        except Exception as error:  # noqa: BLE001 - evidence settlement boundary
            raise self._latch(
                "repair evidence settlement failed",
                error,
            )

    async def _confirm_authenticated_through(self, through: int) -> None:
        while True:
            state = self._local_state(apply_coverage_barrier=True)
            if state.pending is not None:
                await self._post_pending(state)
                continue
            if state.confirmed_through >= through:
                return
            ceiling = min(through, state.delivery_ceiling)
            refs = self._authenticated_refs(
                after=state.confirmed_through,
                through=ceiling,
                limit=1,
            )
            if len(refs) != 1:
                raise self._latch(
                    "repair ACK cannot advance through authenticated evidence"
                )
            try:
                self._ack_journal.record_pending(refs[0])
                pending_state = self._local_state(
                    apply_coverage_barrier=True,
                )
            except DeliveryFatalError:
                raise
            except Exception as error:  # noqa: BLE001 - ACK journal boundary
                raise self._latch(
                    "repair pending ACK durability is uncertain",
                    error,
                )
            await self._post_pending(pending_state)

    async def _accept_settle_and_confirm(
        self,
        item: CoreEventV1,
    ) -> EvidenceRef:
        receipt = self._live_receipt()
        try:
            self._validate_acceptance_binding()
            before = self._store.status()
            if type(before) is not EvidenceStatus or not before.healthy:
                raise DeliveryFatalError(
                    "pre-accept repair evidence status is unhealthy"
                )
            ref = self._acceptance._accept_for_repair(
                item,
                _factory=_REPAIR_DELIVERY_FACTORY,
            )
            self._validate_acceptance_binding()
            accepted = self._store.status()
            if (
                type(accepted) is not EvidenceStatus
                or not accepted.healthy
                or type(ref) is not EvidenceRef
                or ref.source_sequence != item.sequence
                or ref.event_id != item.event_id
                or ref.content_sha256 != item.content_sha256
                or ref.source_sequence != accepted.evidence_head
                or ref.source_sequence <= before.evidence_head
            ):
                raise DeliveryFatalError(
                    "repair acceptance did not advance the exact evidence head"
                )
            self._settle_repair_boundary()
            self._coverage_adapter.apply_live_accepted(ref, receipt)
        except DeliveryFatalError:
            raise
        except Exception as error:  # noqa: BLE001 - repair evidence boundary
            raise self._latch(
                "repair evidence, settlement, or coverage failed",
                error,
            )
        try:
            self._ack_journal.record_pending(ref)
            pending_state = self._local_state(
                apply_coverage_barrier=True,
            )
        except DeliveryFatalError:
            raise
        except Exception as error:  # noqa: BLE001 - ACK journal boundary
            raise self._latch(
                "repair pending ACK durability is uncertain",
                error,
            )
        await self._post_pending(pending_state)
        confirmed = self._local_state(apply_coverage_barrier=False)
        if (
            confirmed.pending is not None
            or confirmed.confirmed_through != ref.source_sequence
        ):
            raise self._latch(
                "repair ACK did not durably confirm the accepted item"
            )
        return ref

    async def drain_until_exact(
        self,
        expected: CoreEventV1,
        *,
        settle_each: Literal[True] = True,
    ) -> EvidenceRef:
        """Deliver through one exact repair event with a boundary per accepted item."""
        if not self._repair_mode:
            raise DeliveryFatalError(
                "exact repair drain requires the repair factory"
            )
        if settle_each is not True:
            raise ValueError("exact repair drain requires settle_each=True")
        expected_bytes = self._repair_target_bytes(expected)
        async with self._lock:
            state = self._local_state(apply_coverage_barrier=False)
            if state.pending is not None:
                pending_state = self._local_state(
                    apply_coverage_barrier=True,
                )
                await self._post_pending(pending_state)
                state = self._local_state(apply_coverage_barrier=False)

            target_ref: EvidenceRef | None = None
            if state.evidence_head > expected.sequence:
                raise self._latch(
                    "authenticated evidence advanced beyond the exact repair target"
                )
            if state.evidence_head == expected.sequence:
                target_ref = self._exact_authenticated_target(expected)

            existing_through = min(state.evidence_head, expected.sequence)
            if state.confirmed_through < existing_through:
                self._settle_repair_boundary()
                await self._confirm_authenticated_through(existing_through)
                state = self._local_state(apply_coverage_barrier=False)

            if target_ref is not None:
                if state.confirmed_through < expected.sequence:
                    raise self._latch(
                        "exact repair target lacks durable ACK confirmation"
                    )
                return target_ref

            total_events = 0
            total_response_bytes = 0
            for _page_number in range(_MAX_REPAIR_DRAIN_PAGES):
                state = self._local_state(apply_coverage_barrier=False)
                remaining_events = _MAX_REPAIR_DRAIN_EVENTS - total_events
                if remaining_events <= 0:
                    raise self._latch("repair drain event bound exhausted")
                page, response_bytes = await self._fetch_page_with_size(
                    after=state.evidence_head,
                    limit=min(
                        MAX_PAGE_EVENTS,
                        remaining_events,
                        expected.sequence - state.evidence_head,
                    ),
                    confirmed_through=state.confirmed_through,
                )
                total_response_bytes += response_bytes
                if total_response_bytes > _MAX_REPAIR_DRAIN_RESPONSE_BYTES:
                    raise self._latch(
                        "repair drain response-byte bound exhausted"
                    )
                if page.reserved_through < expected.sequence:
                    raise self._latch(
                        "observer reservation does not include exact repair target"
                    )
                if not page.events:
                    raise self._latch(
                        "observer returned no path to the exact repair target"
                    )
                total_events += len(page.events)
                if total_events > _MAX_REPAIR_DRAIN_EVENTS:
                    raise self._latch("repair drain event bound exhausted")

                for item in page.events:
                    if item.sequence > expected.sequence:
                        raise self._latch(
                            "observer passed the exact repair target"
                        )
                    if (
                        item.sequence == expected.sequence
                        and canonical_json(item.model_dump(mode="python"))
                        != expected_bytes
                    ):
                        raise self._latch(
                            "observer returned a different exact repair target"
                        )
                for item in page.events:
                    ref = await self._accept_settle_and_confirm(item)
                    if item.sequence == expected.sequence:
                        return ref
            raise self._latch("repair drain page bound exhausted")

    async def finalize_repair(
        self,
        proof: object,
        *,
        _factory: object,
    ) -> None:
        """Close delivery, then consume the exact gate-clear proof last."""
        from agmind_immune.evidence.repair import (
            _FINAL_REPAIR_COMPLETION_FACTORY,
            AuthenticatedRepairCompletion,
        )

        if _factory is not _REPAIR_DELIVERY_FACTORY:
            raise TypeError(
                "repair finalization requires the exact finalization factory"
            )
        if (
            type(proof) is not AuthenticatedRepairCompletion
            or getattr(proof, "_factory_marker", None)
            is not _FINAL_REPAIR_COMPLETION_FACTORY
            or getattr(proof, "_store", None) is not self._store
            or getattr(proof, "_verifier", None) is not self._verifier
            or getattr(proof, "_acknowledgements", None)
            is not self._ack_journal
        ):
            raise TypeError(
                "repair finalization requires exact completion authority"
            )
        if not self._repair_mode:
            raise DeliveryFatalError(
                "repair finalization requires the repair delivery factory"
            )
        async with self._lock:
            self._local_state(apply_coverage_barrier=False)
            status = self._store.status()
            if (
                type(status) is not EvidenceStatus
                or not status.healthy
                or status.repair_pending is not True
                or not self._store._is_bound_verifier(self._verifier)
                or self._acceptance._repair_mode is not True
            ):
                raise DeliveryFatalError(
                    "repair finalization precondition is not exact"
                )
            self._closed = True
            await self._close_resources_under_lock()
            proof._clear_under_delivery_fence(
                _factory=_REPAIR_DELIVERY_FACTORY,
            )
            self._acceptance._repair_mode = False
            self._repair_mode = False

    def _result(
        self,
        *,
        accepted: int,
        confirmed: int,
        retry_required: bool,
    ) -> PollResult:
        state = self._local_state(apply_coverage_barrier=True)
        return PollResult(
            accepted=accepted,
            confirmed=confirmed,
            evidence_head=state.evidence_head,
            acceptance_cursor=state.acceptance_cursor,
            confirmed_through=state.confirmed_through,
            pending=state.pending,
            retry_required=retry_required,
        )

    async def poll_once(self, *, limit: int = MAX_PAGE_EVENTS) -> PollResult:
        if self._repair_mode:
            raise DeliveryFatalError(
                "repair delivery must use drain_until_exact"
            )
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_PAGE_EVENTS
        ):
            raise ValueError("poll limit must be in 1..100")
        async with self._lock:
            state = self._local_state(apply_coverage_barrier=False)
            accepted = 0
            confirmed = 0
            remaining_budget = self._ack_budget
            if state.pending is not None:
                state = self._local_state(apply_coverage_barrier=True)
                try:
                    await self._post_pending(state)
                except DeliveryAmbiguousAck:
                    return self._result(
                        accepted=0,
                        confirmed=0,
                        retry_required=True,
                    )
                confirmed += 1
                remaining_budget -= 1
                state = self._local_state(apply_coverage_barrier=False)

            page = await self._fetch_page(
                after=state.evidence_head,
                limit=limit,
                confirmed_through=state.confirmed_through,
            )
            for item in page.events:
                receipt = self._live_receipt()
                try:
                    self._validate_acceptance_binding()
                    before = self._store.status()
                    if type(before) is not EvidenceStatus or not before.healthy:
                        raise DeliveryFatalError(
                            "pre-accept evidence status is unhealthy"
                        )
                    ref = self._acceptance.accept(item)
                    self._validate_acceptance_binding()
                    after = self._store.status()
                    if (
                        type(after) is not EvidenceStatus
                        or not after.healthy
                        or type(ref) is not EvidenceRef
                        or ref.source_sequence != after.evidence_head
                        or ref.source_sequence <= before.evidence_head
                    ):
                        raise DeliveryFatalError(
                            "accepted ref did not advance the exact evidence head"
                        )
                    self._coverage_adapter.apply_live_accepted(ref, receipt)
                except Exception as error:  # noqa: BLE001 - evidence boundary is fail-closed
                    raise self._latch(
                        "observer evidence or coverage acceptance failed",
                        error,
                    )
                accepted += 1

            state = self._local_state(apply_coverage_barrier=True)
            refs = self._authenticated_refs(
                after=state.confirmed_through,
                through=state.delivery_ceiling,
                limit=remaining_budget,
            )
            for ref in refs:
                try:
                    self._ack_journal.record_pending(ref)
                    pending_state = self._local_state(
                        apply_coverage_barrier=True,
                    )
                except DeliveryFatalError:
                    raise
                except Exception as error:  # noqa: BLE001 - journal authority boundary
                    raise self._latch(
                        "pending ACK durability is uncertain",
                        error,
                    )
                try:
                    await self._post_pending(pending_state)
                except DeliveryAmbiguousAck:
                    return self._result(
                        accepted=accepted,
                        confirmed=confirmed,
                        retry_required=True,
                    )
                confirmed += 1
            return self._result(
                accepted=accepted,
                confirmed=confirmed,
                retry_required=False,
            )

    async def _close_resources_under_lock(self) -> None:
        primary: BaseException | None = None
        if not self._transport_closed:
            try:
                await self._transport.close()
            except BaseException as error:  # noqa: BLE001 - cleanup boundary
                primary = error
            else:
                self._transport_closed = True
        if not self._lease_released:
            try:
                self._delivery_lease.release()
            except BaseException as error:  # noqa: BLE001 - preserve close primary
                if primary is None:
                    primary = error
                else:
                    primary.add_note(
                        "secondary ACK delivery-lease release failure "
                        f"({type(error).__name__})"
                    )
            else:
                self._lease_released = True
        if primary is not None:
            raise primary

    async def close(self) -> None:
        async with self._lock:
            if self._transport_closed and self._lease_released:
                return
            self._closed = True
            await self._close_resources_under_lock()
