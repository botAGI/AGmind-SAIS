"""Durable observer acceptance and bounded Phase-5C1 delivery coordination."""

from __future__ import annotations

import asyncio
import math
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast, final

import httpx

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.clock import CoreClockProvider
from agmind_immune.contracts import (
    MAX_UINT64,
    RetentionBlockedV1,
    RetentionTombstoneV2,
)
from agmind_immune.coverage import CoverageAckBarrier, CoverageState
from agmind_immune.evidence.retention import (
    RetentionStateJournal,
    RetentionStateV1,
    RetentionTargetV1,
)
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    EvidenceStatus,
    SegmentStore,
    _RetentionStateAuthority,
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
    IngestVerificationError,
    PageDecodeError,
    SimulatedEvent,
    SimulatedRetentionBlocked,
    SimulatedRetentionTombstone,
    VerifierCommitError,
    decode_core_event,
    decode_events_page,
)

_COORDINATOR_FACTORY = object()
_REPAIR_ACCEPTANCE_FACTORY = object()
_DELIVERY_FACTORY = object()
_REPAIR_DELIVERY_FACTORY = object()
_RETENTION_PREFLIGHT_FACTORY = object()
_RETENTION_DELIVERY_FACTORY = object()
_COVERAGE_ADAPTER_FACTORY = object()
_MAX_ERROR_BODY_BYTES = 4_096
_MAX_REPAIR_DRAIN_EVENTS = 4_096
_MAX_REPAIR_DRAIN_PAGES = 64
_MAX_REPAIR_DRAIN_RESPONSE_BYTES = 64 * 1024 * 1024
_MAX_RETENTION_PREFLIGHT_EVENTS = 4_096
_MAX_RETENTION_PREFLIGHT_PAGES = 64
_MAX_RETENTION_PREFLIGHT_RESPONSE_BYTES = 64 * 1024 * 1024
_MAX_RETENTION_TOMBSTONE_REQUEST_BYTES = 16 * 1024
_MAX_RETENTION_BLOCKED_REQUEST_BYTES = 4 * 1024


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

    async def publish_retention_tombstone(
        self,
        canonical_body: bytes,
    ) -> bytes: ...

    async def publish_retention_blocked(self, canonical_body: bytes) -> bytes: ...

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

    async def _publish_control(
        self,
        path: str,
        canonical_body: bytes,
        *,
        operation: str,
        request_limit: int | None = None,
        request_limit_label: str | None = None,
    ) -> bytes:
        if self._closed:
            raise DeliveryFatalError("observer transport is closed")
        if type(canonical_body) is not bytes or not canonical_body:
            raise DeliveryFatalError(
                f"{operation} request body must be exact nonempty bytes"
            )
        if request_limit is not None and len(canonical_body) > request_limit:
            if request_limit_label is None:
                raise DeliveryFatalError(
                    f"{operation} request body exceeds its bound"
                )
            raise DeliveryFatalError(
                f"{operation} request body exceeds {request_limit_label}"
            )
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
                        f"observer {operation} response has Content-Encoding"
                    )
                if response.status_code in (200, 201):
                    if response.headers.get("Content-Type") != "application/json":
                        await self._discard_error_body(response)
                        raise DeliveryFatalError(
                            f"observer {operation} Content-Type is not exact JSON"
                        )
                    raw = await self._read_raw_bounded(
                        response,
                        MAX_CORE_EVENT_RESPONSE_BYTES + 1,
                    )
                    if len(raw) > MAX_CORE_EVENT_RESPONSE_BYTES:
                        raise DeliveryFatalError(
                            f"observer {operation} response exceeds bound"
                        )
                    return raw
                await self._discard_error_body(response)
                if response.status_code == 409:
                    raise DeliveryFatalError(
                        f"observer rejected exact {operation} authority"
                    )
                if response.status_code == 408 or 500 <= response.status_code <= 599:
                    raise DeliveryRetryableError(
                        f"observer {operation} POST returned {response.status_code}"
                    )
                raise DeliveryFatalError(
                    f"observer {operation} POST returned {response.status_code}"
                )
        except DeliveryError:
            raise
        except (httpx.HTTPError, OSError, TimeoutError) as error:
            raise DeliveryRetryableError(
                f"observer {operation} POST transport failed"
            ) from error

    async def _publish_repair(self, path: str, canonical_body: bytes) -> bytes:
        return await self._publish_control(
            path,
            canonical_body,
            operation="repair",
        )

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

    async def publish_retention_tombstone(
        self,
        canonical_body: bytes,
    ) -> bytes:
        return await self._publish_control(
            "/v1/events/retention-tombstone",
            canonical_body,
            operation="retention tombstone",
            request_limit=_MAX_RETENTION_TOMBSTONE_REQUEST_BYTES,
            request_limit_label="16 KiB",
        )

    async def publish_retention_blocked(self, canonical_body: bytes) -> bytes:
        return await self._publish_control(
            "/v1/events/retention-blocked",
            canonical_body,
            operation="retention blocked",
            request_limit=_MAX_RETENTION_BLOCKED_REQUEST_BYTES,
            request_limit_label="4 KiB",
        )

    async def close(self) -> None:
        if self._closed:
            return
        await self._client.aclose()
        self._closed = True


@final
class _DeliveryLock:
    """Task-owned async lock with a monotonic transition epoch."""

    __slots__ = ("_epoch", "_lock", "_owner")

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._owner: asyncio.Task[object] | None = None
        self._epoch = 0

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("_DeliveryLock is final")

    async def acquire(self) -> bool:
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("delivery lock requires an asyncio task")
        if self._owner is task:
            raise RuntimeError("delivery lock is not reentrant")
        acquired = await self._lock.acquire()
        if acquired is not True or self._owner is not None:
            raise RuntimeError("delivery lock ownership is inconsistent")
        self._owner = task
        self._epoch += 1
        return True

    def release(self) -> None:
        task = asyncio.current_task()
        if (
            task is None
            or self._owner is not task
            or self._lock.locked() is not True
        ):
            raise RuntimeError(
                "delivery lock can only be released by its exact task owner"
            )
        self._lock.release()
        self._owner = None
        self._epoch += 1

    def locked(self) -> bool:
        return self._lock.locked()

    async def __aenter__(self) -> _DeliveryLock:
        await self.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        del exc_type, exc_value, traceback
        self.release()


@dataclass(frozen=True)
class _DeliveryState:
    evidence_head: int
    acceptance_cursor: int
    confirmed_through: int
    pending: AckIdentity | None
    pending_ref: EvidenceRef | None
    pending_body: bytes | None
    delivery_ceiling: int


@dataclass(frozen=True)
class _RetentionPreflightInvariant:
    state: _DeliveryState
    status: EvidenceStatus
    ack_snapshot: AckJournalSnapshot
    pending_body: bytes | None
    acceptance: object
    store: object
    store_lifecycle: object
    store_bound_verifier: object
    verifier: object
    verifier_root: object
    verifier_key_chain: object
    verifier_authority: object
    verifier_bound_lifecycle: object | None
    verifier_repair_lifecycle: object | None
    verifier_repair_owner: object
    verifier_staged: object
    verifier_authorizations: object
    verifier_transient_generation: int
    ack_journal: object
    ack_store: object
    ack_lifecycle: object
    ack_delivery_lease: object
    coverage_adapter: object
    coverage_barrier: object
    coverage_adapter_evidence: object
    coverage: object
    coverage_snapshot: object
    coverage_evidence: object
    coverage_lifecycle: object | None
    coverage_capability: object | None
    coverage_healthy: bool
    coverage_closed: bool
    lock: _DeliveryLock
    lock_epoch: int
    delivery_lock_owner: object
    lock_owner: object
    lock_authority: object


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
        self._lock = _DeliveryLock()
        self._retention_lock_owner: asyncio.Task[object] | None = None
        self._retention_lock_authority: object | None = None
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

    @asynccontextmanager
    async def _retention_preflight_scope(
        self,
        *,
        _factory: object,
    ) -> AsyncIterator[object]:
        if (
            (
                _factory is not _RETENTION_PREFLIGHT_FACTORY
                and _factory is not _RETENTION_DELIVERY_FACTORY
            )
            or type(self) is not DeliveryCoordinator
            or self._repair_mode
        ):
            raise TypeError(
                "retention preflight requires the exact ordinary delivery factory"
            )
        if self._retention_lock_owner is not None:
            raise TypeError(
                "retention preflight already has an exact lock owner"
            )
        self._raise_if_unavailable()
        task = asyncio.current_task()
        if task is None:
            raise TypeError("retention preflight requires an asyncio task owner")
        lock = self._lock
        await lock.acquire()
        lock_epoch = lock._epoch
        scope_entered = False
        primary: BaseException | None = None
        authority: object | None = None
        try:
            self._raise_if_unavailable()
            if (
                self._lock is not lock
                or self._retention_lock_owner is not None
                or self._retention_lock_authority is not None
            ):
                raise TypeError(
                    "retention preflight already has an exact lock owner"
                )
            authority = object()
            self._retention_lock_owner = task
            self._retention_lock_authority = authority
            scope_entered = True
            yield authority
        except BaseException as error:
            primary = error
            raise
        finally:
            lock_unchanged = (
                self._lock is lock
                and lock.locked()
                and lock._owner is task
                and lock._epoch == lock_epoch
            )
            owner_unchanged = (
                not scope_entered
                or (
                    asyncio.current_task() is task
                    and self._retention_lock_owner is task
                    and self._retention_lock_authority is authority
                )
            )
            if scope_entered:
                self._retention_lock_owner = None
                self._retention_lock_authority = None
            if lock.locked() and lock._owner is task:
                lock.release()
            if not lock_unchanged or not owner_unchanged:
                raise self._latch(
                    "retention preflight changed live authority",
                    primary,
                )

    def _require_retention_delivery(
        self,
        *,
        _factory: object,
        _lock_authority: object,
    ) -> None:
        if (
            _factory is not _RETENTION_DELIVERY_FACTORY
            or type(self) is not DeliveryCoordinator
            or self._repair_mode
        ):
            raise TypeError(
                "retention target delivery requires its exact factory"
            )
        task = asyncio.current_task()
        if (
            task is None
            or self._lock.locked() is not True
            or self._lock._owner is not task
            or self._retention_lock_owner is not task
            or self._retention_lock_authority is None
            or _lock_authority is not self._retention_lock_authority
        ):
            raise TypeError(
                "retention target delivery requires its exact locked scope"
            )
        self._raise_if_unavailable()

    def _require_retention_preflight(
        self,
        *,
        _factory: object,
        _lock_authority: object,
    ) -> None:
        if (
            _factory is not _RETENTION_PREFLIGHT_FACTORY
            or type(self) is not DeliveryCoordinator
            or self._repair_mode
        ):
            raise TypeError(
                "retention preflight requires the exact ordinary delivery factory"
            )
        task = asyncio.current_task()
        if (
            task is None
            or self._lock.locked() is not True
            or self._lock._owner is not task
            or self._retention_lock_owner is not task
            or self._retention_lock_authority is None
            or _lock_authority is not self._retention_lock_authority
        ):
            raise TypeError(
                "retention preflight requires its exact current-task lock owner"
            )
        self._raise_if_unavailable()

    @staticmethod
    def _exact_retention_body(
        request: RetentionTombstoneV2 | RetentionBlockedV1,
        canonical_body: bytes,
    ) -> tuple[
        RetentionTombstoneV2 | RetentionBlockedV1,
        bytes,
    ]:
        if type(canonical_body) is not bytes or not canonical_body:
            raise DeliveryFatalError(
                "retention preflight body must be exact nonempty bytes"
            )
        request_type: type[
            RetentionTombstoneV2 | RetentionBlockedV1
        ]
        if type(request) is RetentionTombstoneV2:
            request_type = RetentionTombstoneV2
        elif type(request) is RetentionBlockedV1:
            request_type = RetentionBlockedV1
        else:
            raise TypeError(
                "retention preflight requires an exact request type"
            )
        try:
            encoded = canonical_json(request.model_dump(mode="python"))
            decoded = request_type.model_validate_json(
                canonical_body,
                strict=True,
            )
            expected = canonical_json(decoded.model_dump(mode="python"))
        except (
            OverflowError,
            RecursionError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as error:
            raise DeliveryFatalError(
                "retention preflight exact request is invalid"
            ) from error
        if (
            type(decoded) is not request_type
            or decoded != request
            or expected != encoded
            or canonical_body != expected
        ):
            raise DeliveryFatalError(
                "retention preflight body differs from the exact request"
            )
        return decoded, expected

    def _capture_retention_preflight_invariant(
        self,
        state: _DeliveryState,
    ) -> _RetentionPreflightInvariant:
        coverage = self._coverage_adapter._coverage
        return _RetentionPreflightInvariant(
            state=state,
            status=self._store.status(),
            ack_snapshot=self._ack_journal.snapshot(),
            pending_body=self._ack_journal.pending_request_body(),
            acceptance=self._acceptance,
            store=self._store,
            store_lifecycle=self._store._lifecycle_identity,
            store_bound_verifier=self._store._bound_verifier,
            verifier=self._verifier,
            verifier_root=self._verifier.root,
            verifier_key_chain=self._verifier.key_chain,
            verifier_authority=self._verifier._authority,
            verifier_bound_lifecycle=self._verifier._bound_lifecycle,
            verifier_repair_lifecycle=(
                self._verifier._repair_lifecycle_identity
            ),
            verifier_repair_owner=self._verifier._repair_owner_identity,
            verifier_staged=dict(self._verifier._staged),
            verifier_authorizations=dict(
                self._verifier._authorizations
            ),
            verifier_transient_generation=(
                self._verifier._repair_transient_generation
            ),
            ack_journal=self._ack_journal,
            ack_store=self._ack_journal._store,
            ack_lifecycle=self._ack_journal._lifecycle_identity,
            ack_delivery_lease=self._ack_journal._delivery_lease,
            coverage_adapter=self._coverage_adapter,
            coverage_barrier=self._coverage_adapter._barrier,
            coverage_adapter_evidence=self._coverage_adapter._evidence,
            coverage=coverage,
            coverage_snapshot=coverage._snapshot,
            coverage_evidence=coverage._evidence,
            coverage_lifecycle=coverage._lifecycle_identity,
            coverage_capability=coverage._capability_token,
            coverage_healthy=coverage._healthy,
            coverage_closed=coverage._closed,
            lock=self._lock,
            lock_epoch=self._lock._epoch,
            delivery_lock_owner=self._lock._owner,
            lock_owner=self._retention_lock_owner,
            lock_authority=self._retention_lock_authority,
        )

    def _retention_preflight_invariant_changed(
        self,
        before: _RetentionPreflightInvariant,
    ) -> bool:
        try:
            coverage = self._coverage_adapter._coverage
            return (
                self._acceptance is not before.acceptance
                or self._store is not before.store
                or self._store._lifecycle_identity
                is not before.store_lifecycle
                or self._store._bound_verifier
                is not before.store_bound_verifier
                or self._acceptance.segment_store is not self._store
                or self._acceptance.verifier is not self._verifier
                or self._acceptance._repair_mode is not False
                or self._verifier is not before.verifier
                or self._verifier.root is not before.verifier_root
                or self._verifier.key_chain is not before.verifier_key_chain
                or self._verifier._authority
                is not before.verifier_authority
                or self._verifier._bound_lifecycle
                is not before.verifier_bound_lifecycle
                or self._verifier._repair_lifecycle_identity
                is not before.verifier_repair_lifecycle
                or self._verifier._repair_owner_identity
                is not before.verifier_repair_owner
                or self._verifier._staged != before.verifier_staged
                or self._verifier._authorizations
                != before.verifier_authorizations
                or self._verifier._repair_transient_generation
                != before.verifier_transient_generation
                or self._ack_journal is not before.ack_journal
                or self._ack_journal._store is not before.ack_store
                or self._ack_journal._lifecycle_identity
                is not before.ack_lifecycle
                or self._ack_journal._delivery_lease
                is not before.ack_delivery_lease
                or self._coverage_adapter
                is not before.coverage_adapter
                or self._coverage_adapter._barrier
                is not before.coverage_barrier
                or self._coverage_adapter._evidence
                is not before.coverage_adapter_evidence
                or coverage is not before.coverage
                or coverage._snapshot is not before.coverage_snapshot
                or coverage._evidence is not before.coverage_evidence
                or coverage._lifecycle_identity
                is not before.coverage_lifecycle
                or coverage._capability_token
                is not before.coverage_capability
                or coverage._healthy is not before.coverage_healthy
                or coverage._closed is not before.coverage_closed
                or self._lock is not before.lock
                or before.lock.locked() is not True
                or before.lock._epoch != before.lock_epoch
                or before.lock._owner is not before.delivery_lock_owner
                or before.delivery_lock_owner is not before.lock_owner
                or self._retention_lock_owner is not before.lock_owner
                or self._retention_lock_authority
                is not before.lock_authority
                or asyncio.current_task() is not before.lock_owner
                or self._store.status() != before.status
                or self._ack_journal.snapshot()
                != before.ack_snapshot
                or self._ack_journal.pending_request_body()
                != before.pending_body
            )
        except BaseException:  # noqa: BLE001 - invariant loss fails closed
            return True

    async def _preflight_retention(
        self,
        request: RetentionTombstoneV2 | RetentionBlockedV1,
        canonical_body: bytes,
        *,
        _factory: object,
        _lock_authority: object,
    ) -> SimulatedRetentionTombstone | SimulatedRetentionBlocked:
        self._require_retention_preflight(
            _factory=_factory,
            _lock_authority=_lock_authority,
        )
        frozen_request, frozen_body = self._exact_retention_body(
            request,
            canonical_body,
        )
        state = self._local_state(apply_coverage_barrier=False)
        if state.pending is not None:
            raise DeliveryRetryableError(
                "retention preflight requires pending ACK recovery"
            )
        invariant = self._capture_retention_preflight_invariant(state)
        try:
            proof = await self._preflight_retention_inner(
                frozen_request,
                frozen_body,
                _factory=_factory,
                _lock_authority=_lock_authority,
            )
        except BaseException as primary:
            if self._retention_preflight_invariant_changed(invariant):
                raise self._latch(
                    "retention preflight changed live authority",
                    primary,
                )
            raise
        if self._retention_preflight_invariant_changed(invariant):
            raise self._latch(
                "retention preflight changed live authority"
            )
        return proof

    async def _preflight_retention_inner(
        self,
        request: RetentionTombstoneV2 | RetentionBlockedV1,
        canonical_body: bytes,
        *,
        _factory: object,
        _lock_authority: object,
    ) -> SimulatedRetentionTombstone | SimulatedRetentionBlocked:
        self._require_retention_preflight(
            _factory=_factory,
            _lock_authority=_lock_authority,
        )
        request, body = self._exact_retention_body(
            request,
            canonical_body,
        )
        state_before = self._local_state(apply_coverage_barrier=False)
        if state_before.pending is not None:
            raise DeliveryRetryableError(
                "retention preflight requires pending ACK recovery"
            )
        status_before = self._store.status()
        ack_before = self._ack_journal.snapshot()
        authority_before = self._verifier._authority
        stages_before = dict(self._verifier._staged)
        authorizations_before = dict(self._verifier._authorizations)
        transient_before = self._verifier._repair_transient_generation
        simulation = self._verifier._new_control_simulation()
        try:
            if type(request) is RetentionTombstoneV2:
                direct_raw = (
                    await self._transport.publish_retention_tombstone(body)
                )
            elif type(request) is RetentionBlockedV1:
                direct_raw = await self._transport.publish_retention_blocked(
                    body
                )
            else:
                raise TypeError(
                    "retention preflight requires an exact request type"
                )
        except asyncio.CancelledError:
            raise
        except DeliveryRetryableError:
            raise
        except DeliveryFatalError as error:
            raise self._latch("retention POST failed fatally", error)
        except (httpx.HTTPError, OSError, TimeoutError) as error:
            raise DeliveryRetryableError(
                "retention POST transport failed"
            ) from error
        except Exception as error:  # noqa: BLE001 - transport protocol boundary
            raise self._latch(
                "retention POST transport violated its contract",
                error,
            )
        try:
            if type(direct_raw) is not bytes:
                raise DeliveryFatalError(
                    "retention POST returned a non-exact byte response"
                )
            direct = decode_core_event(direct_raw)
            direct_canonical = canonical_json(
                direct.model_dump(mode="python")
            )
        except (
            IngestVerificationError,
            RecursionError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as error:
            raise self._latch(
                "retention direct response is invalid",
                error,
            )
        if direct.sequence <= state_before.evidence_head:
            raise self._latch(
                "retention preflight target is not ahead of evidence"
            )

        after = state_before.evidence_head
        total_events = 0
        total_response_bytes = 0
        fetched: list[CoreEventV1] = []
        for _page_number in range(_MAX_RETENTION_PREFLIGHT_PAGES):
            remaining_events = (
                _MAX_RETENTION_PREFLIGHT_EVENTS - total_events
            )
            if remaining_events <= 0:
                raise self._latch(
                    "retention preflight event bound exhausted"
                )
            page, response_bytes = await self._fetch_page_with_size(
                after=after,
                limit=min(
                    MAX_PAGE_EVENTS,
                    remaining_events,
                    direct.sequence - after,
                ),
                confirmed_through=state_before.confirmed_through,
            )
            total_response_bytes += response_bytes
            total_events += len(page.events)
            if (
                total_response_bytes
                > _MAX_RETENTION_PREFLIGHT_RESPONSE_BYTES
            ):
                raise self._latch(
                    "retention preflight response-byte bound exhausted"
                )
            if total_events > _MAX_RETENTION_PREFLIGHT_EVENTS:
                raise self._latch(
                    "retention preflight event bound exhausted"
                )
            if page.reserved_through < direct.sequence:
                raise self._latch(
                    "observer reservation does not include retention target"
                )
            if not page.events:
                raise self._latch(
                    "observer returned no path to the retention target"
                )

            target_found = False
            normalized_page: list[CoreEventV1] = []
            for item in page.events:
                try:
                    normalized = decode_core_event(
                        canonical_json(item.model_dump(mode="python"))
                    )
                except (
                    IngestVerificationError,
                    RecursionError,
                    TypeError,
                    UnicodeError,
                    ValueError,
                ) as error:
                    raise self._latch(
                        "retention page item outer binding is invalid",
                        error,
                    )
                if normalized.sequence <= after:
                    raise self._latch(
                        "retention preflight local cursor did not advance"
                    )
                if not target_found:
                    if normalized.sequence > direct.sequence:
                        raise self._latch(
                            "observer passed the exact retention target"
                        )
                    if normalized.sequence == direct.sequence:
                        if (
                            canonical_json(
                                normalized.model_dump(mode="python")
                            )
                            != direct_canonical
                        ):
                            raise self._latch(
                                "observer returned a different retention target"
                            )
                        target_found = True
                normalized_page.append(normalized)
            fetched.extend(normalized_page)
            after = normalized_page[-1].sequence
            if not target_found:
                continue
            try:
                if type(request) is RetentionTombstoneV2:
                    tombstone_proof = (
                        simulation.verify_exact_retention_tombstone(
                            request,
                            direct,
                            tuple(fetched),
                        )
                    )
                    proof: (
                        SimulatedRetentionTombstone
                        | SimulatedRetentionBlocked
                    ) = tombstone_proof
                    self._verifier._validate_retention_tombstone_proof(
                        tombstone_proof
                    )
                else:
                    blocked_request = cast(RetentionBlockedV1, request)
                    blocked_proof = simulation.verify_exact_retention_blocked(
                        blocked_request,
                        direct,
                        tuple(fetched),
                    )
                    proof = blocked_proof
                    self._verifier._validate_retention_blocked_proof(
                        blocked_proof
                    )
            except (IngestVerificationError, VerifierCommitError) as error:
                raise self._latch(
                    "retention simulation proof is invalid",
                    error,
                )
            state_after = self._local_state(
                apply_coverage_barrier=False
            )
            if (
                self._verifier._authority is not authority_before
                or self._verifier._staged != stages_before
                or self._verifier._authorizations
                != authorizations_before
                or self._verifier._repair_transient_generation
                != transient_before
                or self._store.status() != status_before
                or self._ack_journal.snapshot() != ack_before
                or state_after != state_before
            ):
                raise self._latch(
                    "retention preflight changed live authority"
                )
            return proof
        raise self._latch("retention preflight page bound exhausted")

    async def _preflight_retention_tombstone(
        self,
        request: RetentionTombstoneV2,
        canonical_body: bytes,
        *,
        _factory: object,
        _lock_authority: object,
    ) -> SimulatedRetentionTombstone:
        if type(request) is not RetentionTombstoneV2:
            raise TypeError(
                "retention tombstone preflight requires its exact request"
            )
        proof = await self._preflight_retention(
            request,
            canonical_body,
            _factory=_factory,
            _lock_authority=_lock_authority,
        )
        if type(proof) is not SimulatedRetentionTombstone:
            raise DeliveryFatalError(
                "retention tombstone preflight returned the wrong proof"
            )
        return proof

    async def _preflight_retention_blocked(
        self,
        request: RetentionBlockedV1,
        canonical_body: bytes,
        *,
        _factory: object,
        _lock_authority: object,
    ) -> SimulatedRetentionBlocked:
        if type(request) is not RetentionBlockedV1:
            raise TypeError(
                "retention blocked preflight requires its exact request"
            )
        proof = await self._preflight_retention(
            request,
            canonical_body,
            _factory=_factory,
            _lock_authority=_lock_authority,
        )
        if type(proof) is not SimulatedRetentionBlocked:
            raise DeliveryFatalError(
                "retention blocked preflight returned the wrong proof"
            )
        return proof

    def _retention_journal_state(
        self,
        journal: RetentionStateJournal,
    ) -> RetentionStateV1:
        if type(journal) is not RetentionStateJournal:
            raise TypeError(
                "retention target delivery requires the exact journal type"
            )
        authority = journal._authority
        if (
            type(authority) is not _RetentionStateAuthority
            or authority._store is not self._store
            or authority._lifecycle_identity
            is not self._store._lifecycle_identity
            or self._store._retention_state_authority is not authority
            or authority._retention_journal is not journal
        ):
            raise TypeError(
                "retention target delivery requires the cached same-store journal"
            )
        try:
            if authority._require() is not self._store:
                raise DeliveryFatalError(
                    "retention journal lost its exact store lifecycle"
                )
            journal._assert_consistent()
            state = journal.state
        except DeliveryFatalError as error:
            raise self._latch(
                "retention journal authority is unavailable",
                error,
            )
        except Exception as error:  # noqa: BLE001 - journal authority boundary
            raise self._latch(
                "retention journal authority is unavailable",
                error,
            )
        if type(state) is not RetentionStateV1:
            raise self._latch(
                "retention target delivery has no exact selected state"
            )
        if (
            (
                type(state.request) is RetentionTombstoneV2
                and state.operation != "tombstone"
            )
            or (
                type(state.request) is RetentionBlockedV1
                and state.operation != "blocked"
            )
            or type(state.request)
            not in {RetentionTombstoneV2, RetentionBlockedV1}
        ):
            raise self._latch(
                "retention state request and operation differ"
            )
        return state

    @staticmethod
    def _retention_event_type(
        request: RetentionTombstoneV2 | RetentionBlockedV1,
    ) -> str:
        if type(request) is RetentionTombstoneV2:
            return "retention_tombstone"
        if type(request) is RetentionBlockedV1:
            return "retention_blocked_priority_evidence"
        raise TypeError("retention target has the wrong exact request type")

    def _exact_authenticated_retention_target(
        self,
        target: RetentionTargetV1,
        request: RetentionTombstoneV2 | RetentionBlockedV1,
    ) -> tuple[CoreEventV1, EvidenceRef]:
        if type(target) is not RetentionTargetV1:
            raise TypeError(
                "retention evidence lookup requires the exact target type"
            )
        expected_event_type = self._retention_event_type(request)
        expected_request = canonical_json(
            request.model_dump(mode="python")
        )
        refs = self._authenticated_refs(
            after=target.sequence - 1,
            through=target.sequence,
            limit=1,
        )
        if len(refs) != 1 or refs[0].source_sequence != target.sequence:
            raise self._latch(
                "exact retention target is absent from authenticated evidence"
            )
        ref = refs[0]
        try:
            record = self._store.resolve_authenticated_ref(ref)
            item = decode_core_event(
                canonical_json(
                    {
                        "sequence": target.sequence,
                        "event_id": target.event_id,
                        "content_sha256": target.content_sha256,
                        "envelope": record.envelope,
                    }
                )
            )
            canonical_envelope = canonical_json(item.envelope)
            normalized_fields = canonical_json(
                item.envelope.get("normalized_fields")
            )
        except Exception as error:  # noqa: BLE001 - authenticated store boundary
            raise self._latch(
                "exact retention target evidence lookup failed",
                error,
            )
        if (
            ref.event_id != target.event_id
            or ref.content_sha256 != target.content_sha256
            or item.sequence != target.sequence
            or item.event_id != target.event_id
            or item.content_sha256 != target.content_sha256
            or record.ref != ref
            or record.canonical_envelope != canonical_envelope
            or record.priority is not EvidencePriority.PROTECTED
            or item.envelope.get("event_type") != expected_event_type
            or normalized_fields != expected_request
            or self._verifier.accepted_ref(target.sequence) != ref
        ):
            raise self._latch(
                "authenticated evidence differs from the exact retention target"
            )
        return item, ref

    def _accept_retention_item(
        self,
        item: CoreEventV1,
        *,
        _factory: object,
        _lock_authority: object,
    ) -> EvidenceRef:
        self._require_retention_delivery(
            _factory=_factory,
            _lock_authority=_lock_authority,
        )
        if type(item) is not CoreEventV1:
            raise TypeError(
                "retention target delivery accepts exact CoreEventV1 items only"
            )
        receipt = self._live_receipt()
        try:
            state_before = self._local_state(
                apply_coverage_barrier=False
            )
            if state_before.pending is not None:
                raise DeliveryRetryableError(
                    "retention target delivery requires pending ACK recovery"
                )
            status_before = self._store.status()
            authority_before = self._verifier._authority
            generation_before = authority_before.generation
            if (
                type(status_before) is not EvidenceStatus
                or not status_before.healthy
                or status_before.evidence_head != state_before.evidence_head
                or item.sequence <= status_before.evidence_head
            ):
                raise DeliveryFatalError(
                    "retention item is outside the exact evidence head"
                )
            ref = self._acceptance.accept(item)
            self._validate_acceptance_binding()
            status_after = self._store.status()
            authority_after = self._verifier._authority
            accepted = authority_after.accepted.get(item.sequence)
            record = self._store.resolve_authenticated_ref(ref)
            item_envelope = canonical_json(item.envelope)
            if (
                type(ref) is not EvidenceRef
                or type(status_after) is not EvidenceStatus
                or not status_after.healthy
                or status_after.evidence_head != item.sequence
                or ref.source_sequence != item.sequence
                or ref.event_id != item.event_id
                or ref.content_sha256 != item.content_sha256
                or authority_after is authority_before
                or authority_after.generation != generation_before + 1
                or accepted is None
                or accepted.evidence_ref != ref
                or accepted.canonical != item_envelope
                or record.ref != ref
                or record.canonical_envelope != item_envelope
                or record.priority.value != accepted.evidence_priority
            ):
                raise DeliveryFatalError(
                    "ordinary retention acceptance did not commit the exact item"
                )
            self._coverage_adapter.apply_live_accepted(ref, receipt)
            coverage = self._coverage_adapter._coverage
            coverage_snapshot = coverage._snapshot
            state_after = self._local_state(
                apply_coverage_barrier=False
            )
            if (
                coverage._healthy is not True
                or coverage._closed is not False
                or coverage._evidence is not self._store
                or coverage_snapshot.head_sequence != item.sequence
                or coverage_snapshot.head_ref != ref
                or state_after.pending is not None
                or state_after.evidence_head != item.sequence
            ):
                raise DeliveryFatalError(
                    "retention coverage did not commit the exact accepted item"
                )
            return ref
        except DeliveryRetryableError:
            raise
        except DeliveryFatalError as error:
            raise self._latch(
                "retention evidence or coverage acceptance failed",
                error,
            )
        except Exception as error:  # noqa: BLE001 - evidence boundary is fail-closed
            raise self._latch(
                "retention evidence or coverage acceptance failed",
                error,
            )

    def _settle_retention_boundary(self) -> None:
        try:
            self._validate_acceptance_binding()
            before = self._store.status()
            if type(before) is not EvidenceStatus or not before.healthy:
                raise DeliveryFatalError(
                    "pre-settlement retention evidence status is unhealthy"
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
                    "retention settlement changed acceptance authority"
                )
        except Exception as error:  # noqa: BLE001 - evidence settlement boundary
            raise self._latch(
                "retention evidence settlement failed",
                error,
            )

    def _require_retention_coverage(
        self,
        ref: EvidenceRef,
        *,
        allow_later: bool,
    ) -> None:
        coverage = self._coverage_adapter._coverage
        snapshot = coverage._snapshot
        status = self._store.status()
        head_ref: EvidenceRef | None = None
        if type(status) is EvidenceStatus and status.evidence_head > 0:
            refs = self._authenticated_refs(
                after=status.evidence_head - 1,
                through=status.evidence_head,
                limit=1,
            )
            if (
                len(refs) == 1
                and refs[0].source_sequence == status.evidence_head
            ):
                head_ref = refs[0]
        if (
            type(ref) is not EvidenceRef
            or type(status) is not EvidenceStatus
            or not status.healthy
            or status.evidence_head < ref.source_sequence
            or head_ref is None
            or coverage._healthy is not True
            or coverage._closed is not False
            or coverage._evidence is not self._store
            or coverage._lifecycle_identity
            is not self._store._lifecycle_identity
            or snapshot.head_sequence != status.evidence_head
            or snapshot.head_ref != head_ref
            or (
                not allow_later
                and (
                    status.evidence_head != ref.source_sequence
                    or head_ref != ref
                )
            )
        ):
            raise self._latch(
                "retention target lacks exact same-store coverage"
            )

    def _advance_retention_evidence_appended(
        self,
        journal: RetentionStateJournal,
        target: RetentionTargetV1,
    ) -> None:
        try:
            journal.advance_evidence_appended(target)
            advanced = self._retention_journal_state(journal)
        except DeliveryFatalError:
            raise
        except Exception as error:  # noqa: BLE001 - journal CAS boundary
            raise self._latch(
                "retention evidence-appended publication is uncertain",
                error,
            )
        if advanced.phase != "evidence_appended" or advanced.target != target:
            raise self._latch(
                "retention journal did not publish exact evidence authority"
            )

    @staticmethod
    def _retention_ack_changed(
        acknowledgements: AckJournal,
        before: AckJournalSnapshot,
        body_before: bytes | None,
    ) -> bool:
        try:
            return (
                acknowledgements.snapshot() != before
                or acknowledgements.pending_request_body() != body_before
            )
        except BaseException:  # noqa: BLE001 - unreadable ACK authority changed
            return True

    async def _deliver_future_retention_target(
        self,
        journal: RetentionStateJournal,
        state: RetentionStateV1,
        *,
        _factory: object,
        _lock_authority: object,
    ) -> EvidenceRef:
        self._require_retention_delivery(
            _factory=_factory,
            _lock_authority=_lock_authority,
        )
        request = state.request
        body = canonical_json(request.model_dump(mode="python"))
        if type(request) is RetentionTombstoneV2:
            proof: SimulatedRetentionTombstone | SimulatedRetentionBlocked = (
                await self._preflight_retention_tombstone(
                    request,
                    body,
                    _factory=_RETENTION_PREFLIGHT_FACTORY,
                    _lock_authority=_lock_authority,
                )
            )
        elif type(request) is RetentionBlockedV1:
            proof = await self._preflight_retention_blocked(
                request,
                body,
                _factory=_RETENTION_PREFLIGHT_FACTORY,
                _lock_authority=_lock_authority,
            )
        else:
            raise TypeError(
                "retention target delivery has the wrong request type"
            )
        simulated_target = proof.target
        if type(simulated_target) is not SimulatedEvent:
            raise self._latch(
                "retention proof has no exact simulated target"
            )
        try:
            target = RetentionTargetV1(
                sequence=simulated_target.sequence,
                event_id=simulated_target.event_id,
                content_sha256=simulated_target.content_sha256,
            )
        except Exception as error:  # noqa: BLE001 - proof target boundary
            raise self._latch(
                "retention proof target identity is invalid",
                error,
            )
        if state.target is not None and state.target != target:
            raise self._latch(
                "retention proof differs from the durable target"
            )
        try:
            journal.bind_target(target)
        except Exception as error:  # noqa: BLE001 - journal CAS boundary
            raise self._latch(
                "retention target publication is uncertain",
                error,
            )
        rebound = self._retention_journal_state(journal)
        if rebound.phase != "target_bound" or rebound.target != target:
            raise self._latch(
                "retention journal did not bind the exact proof target"
            )
        try:
            if type(proof) is SimulatedRetentionTombstone:
                path = self._verifier._consume_retention_tombstone_proof(
                    proof
                )
            elif type(proof) is SimulatedRetentionBlocked:
                path = self._verifier._consume_retention_blocked_proof(
                    proof
                )
            else:
                raise TypeError(
                    "retention preflight returned the wrong proof type"
                )
        except (IngestVerificationError, VerifierCommitError) as error:
            raise self._latch(
                "retention proof consumption failed",
                error,
            )
        if (
            type(path) is not tuple
            or not path
            or any(type(item) is not CoreEventV1 for item in path)
            or path[-1].sequence != target.sequence
            or path[-1].event_id != target.event_id
            or path[-1].content_sha256 != target.content_sha256
            or canonical_json(path[-1].envelope)
            != simulated_target._canonical_envelope
        ):
            raise self._latch(
                "retention proof did not consume its exact prefix"
            )
        target_ref: EvidenceRef | None = None
        for item in path:
            target_ref = self._accept_retention_item(
                item,
                _factory=_RETENTION_DELIVERY_FACTORY,
                _lock_authority=_lock_authority,
            )
        if target_ref is None or target_ref.source_sequence != target.sequence:
            raise self._latch(
                "retention prefix did not accept its exact target"
            )
        self._settle_retention_boundary()
        stored_item, exact_ref = (
            self._exact_authenticated_retention_target(
                target,
                request,
            )
        )
        self._require_retention_coverage(exact_ref, allow_later=False)
        status = self._store.status()
        if (
            exact_ref != target_ref
            or canonical_json(stored_item.envelope)
            != simulated_target._canonical_envelope
            or type(status) is not EvidenceStatus
            or status.evidence_head != target.sequence
            or self._verifier._authority.generation
            != proof.predicted_generation
        ):
            raise self._latch(
                "retention target commit differs from its consumed proof"
            )
        self._advance_retention_evidence_appended(
            journal,
            target,
        )
        return exact_ref

    def _deliver_historical_retention_target(
        self,
        journal: RetentionStateJournal,
        state: RetentionStateV1,
        *,
        _factory: object,
        _lock_authority: object,
    ) -> EvidenceRef:
        self._require_retention_delivery(
            _factory=_factory,
            _lock_authority=_lock_authority,
        )
        target = state.target
        if type(target) is not RetentionTargetV1:
            raise self._latch(
                "historical retention delivery lacks an exact target"
            )
        request = state.request
        status_before = self._store.status()
        authority_before = self._verifier._authority
        coverage = self._coverage_adapter._coverage
        coverage_before = coverage._snapshot
        item, target_ref = self._exact_authenticated_retention_target(
            target,
            request,
        )
        self._require_retention_coverage(target_ref, allow_later=True)
        try:
            replayed = (
                self._verifier._restricted_historical_retention_replay(
                    (item, target_ref),
                    request,
                )
            )
        except (IngestVerificationError, VerifierCommitError) as error:
            raise self._latch(
                "historical retention replay failed",
                error,
            )
        if (
            type(replayed) is not SimulatedEvent
            or replayed.sequence != target.sequence
            or replayed.event_id != target.event_id
            or replayed.content_sha256 != target.content_sha256
            or replayed.event_type != self._retention_event_type(request)
            or replayed.evidence_priority != "protected"
            or replayed.is_retry is not True
            or replayed._canonical_envelope
            != canonical_json(item.envelope)
            or replayed._normalized_fields_canonical
            != canonical_json(request.model_dump(mode="python"))
            or self._verifier._authority is not authority_before
            or self._store.status() != status_before
            or coverage._snapshot is not coverage_before
        ):
            raise self._latch(
                "historical retention replay changed exact live authority"
            )
        self._settle_retention_boundary()
        stored_item, settled_ref = (
            self._exact_authenticated_retention_target(
                target,
                request,
            )
        )
        self._require_retention_coverage(settled_ref, allow_later=True)
        if (
            settled_ref != target_ref
            or canonical_json(stored_item.envelope)
            != canonical_json(item.envelope)
            or self._verifier._authority is not authority_before
            or self._store.status() != status_before
            or coverage._snapshot is not coverage_before
        ):
            raise self._latch(
                "historical retention settlement changed live authority"
            )
        self._advance_retention_evidence_appended(
            journal,
            target,
        )
        return target_ref

    async def _deliver_retention_target(
        self,
        journal: RetentionStateJournal,
        *,
        _factory: object,
    ) -> EvidenceRef:
        """Commit one selected retention target without touching ACK state."""
        if (
            _factory is not _RETENTION_DELIVERY_FACTORY
            or type(self) is not DeliveryCoordinator
            or self._repair_mode
        ):
            raise TypeError(
                "retention target delivery requires its exact factory"
            )
        async with self._retention_preflight_scope(
            _factory=_RETENTION_DELIVERY_FACTORY,
        ) as lock_authority:
            self._require_retention_delivery(
                _factory=_factory,
                _lock_authority=lock_authority,
            )
            state = self._retention_journal_state(journal)
            ack_before = self._ack_journal.snapshot()
            ack_body_before = self._ack_journal.pending_request_body()
            local = self._local_state(apply_coverage_barrier=False)
            if local.pending is not None:
                raise DeliveryRetryableError(
                    "retention target delivery requires pending ACK recovery"
                )
            try:
                target = state.target
                if (
                    state.phase == "target_bound"
                    and type(target) is RetentionTargetV1
                    and target.sequence <= local.evidence_head
                ):
                    result = self._deliver_historical_retention_target(
                        journal,
                        state,
                        _factory=_RETENTION_DELIVERY_FACTORY,
                        _lock_authority=lock_authority,
                    )
                elif state.phase in {"selected", "target_bound"}:
                    result = await self._deliver_future_retention_target(
                        journal,
                        state,
                        _factory=_RETENTION_DELIVERY_FACTORY,
                        _lock_authority=lock_authority,
                    )
                elif (
                    state.phase == "evidence_appended"
                    and type(target) is RetentionTargetV1
                ):
                    _item, result = (
                        self._exact_authenticated_retention_target(
                            target,
                            state.request,
                        )
                    )
                    self._require_retention_coverage(
                        result,
                        allow_later=True,
                    )
                else:
                    raise self._latch(
                        "retention state phase cannot deliver a target"
                    )
            except BaseException as primary:
                if self._retention_ack_changed(
                    self._ack_journal,
                    ack_before,
                    ack_body_before,
                ):
                    raise self._latch(
                        "retention target delivery changed ACK authority",
                        primary,
                    )
                raise
            if self._retention_ack_changed(
                self._ack_journal,
                ack_before,
                ack_body_before,
            ):
                raise self._latch(
                    "retention target delivery changed ACK authority"
                )
            return result

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
