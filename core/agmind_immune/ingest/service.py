"""Durable observer acceptance and bounded Phase-5C1 delivery coordination."""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx

from agmind_immune.contracts import MAX_UINT64
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    SegmentStore,
)
from agmind_immune.ingest.ack_journal import (
    AckDeliveryLease,
    AckIdentity,
    AckJournal,
)
from agmind_immune.ingest.envelope import (
    MAX_EVENTS_PAGE_BYTES,
    MAX_PAGE_EVENTS,
    CoreEventsPageV1,
    CoreEventV1,
    EnvelopeConflict,
    EnvelopeVerifier,
    PageDecodeError,
    decode_events_page,
)

_COORDINATOR_FACTORY = object()
_DELIVERY_FACTORY = object()
_MAX_ERROR_BODY_BYTES = 4_096


class AcceptanceCoordinator:
    """Durably append a staged envelope before committing verifier/FSM state."""

    def __init__(
        self,
        verifier: EnvelopeVerifier,
        segment_store: SegmentStore,
        *,
        _factory: object,
    ) -> None:
        if _factory is not _COORDINATOR_FACTORY:
            raise TypeError(
                "use AcceptanceCoordinator.create_empty() or open_and_recover()"
            )
        self.verifier = verifier
        self.segment_store = segment_store

    def accept(self, item: CoreEventV1) -> EvidenceRef:
        try:
            verified = self.verifier.verify(
                item.envelope,
                sequence=item.sequence,
                event_id=item.event_id,
                content_sha256=item.content_sha256,
            )
        except EnvelopeConflict:
            self.segment_store.enter_read_only("evidence_conflict")
            self.verifier._enter_read_only_after_durable_fence()
            raise
        return self.segment_store.append(
            verified,
            EvidencePriority(verified.evidence_priority),
        )

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

    async def close(self) -> None: ...


class _AckBarrier(Protocol):
    """Evidence-derived first source sequence whose ACK must be held."""

    def __call__(self) -> int | None: ...


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


class DeliveryCoordinator:
    """Serialize one evidence-first observer delivery/ACK lifecycle."""

    def __init__(
        self,
        acceptance: AcceptanceCoordinator,
        ack_journal: AckJournal,
        delivery_lease: AckDeliveryLease,
        transport: ObserverCoreTransport,
        *,
        ack_barrier: _AckBarrier,
        ack_budget: int = MAX_PAGE_EVENTS,
        _factory: object,
    ) -> None:
        if _factory is not _DELIVERY_FACTORY:
            raise TypeError("DeliveryCoordinator has no production factory before 5C1D")
        if not isinstance(delivery_lease, AckDeliveryLease):
            raise TypeError("delivery requires an exact ACK-journal lease")
        if not callable(ack_barrier):
            raise TypeError("delivery requires an ACK barrier capability")
        if (
            isinstance(ack_budget, bool)
            or not isinstance(ack_budget, int)
            or not 1 <= ack_budget <= MAX_PAGE_EVENTS
        ):
            raise ValueError("ACK budget must be in 1..100")
        self.acceptance = acceptance
        self.ack_journal = ack_journal
        self._delivery_lease = delivery_lease
        self.transport = transport
        self.ack_barrier = ack_barrier
        self.ack_budget = ack_budget
        self._lock = asyncio.Lock()
        self._fatal: DeliveryFatalError | None = None
        self._closed = False
        self._transport_closed = False
        self._lease_released = False

    @classmethod
    def _create_unsafe_for_test(
        cls,
        acceptance: AcceptanceCoordinator,
        ack_journal: AckJournal,
        transport: ObserverCoreTransport,
        *,
        ack_barrier: _AckBarrier,
        ack_budget: int = MAX_PAGE_EVENTS,
    ) -> DeliveryCoordinator:
        """Exercise the 5C1B contract before 5C1D issues a bound barrier."""
        lease = ack_journal.claim_delivery(acceptance.segment_store)
        try:
            return cls(
                acceptance,
                ack_journal,
                lease,
                transport,
                ack_barrier=ack_barrier,
                ack_budget=ack_budget,
                _factory=_DELIVERY_FACTORY,
            )
        except BaseException:
            lease.release()
            raise

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
            return self.acceptance.segment_store.authenticated_refs(
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
            barrier = self.ack_barrier()
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

    def _local_state(self) -> _DeliveryState:
        self._raise_if_unavailable()
        try:
            snapshot = self.ack_journal.snapshot()
            if not snapshot.healthy:
                raise self._latch("ACK journal is unhealthy")
            pending_body = self.ack_journal.pending_request_body()
            evidence_head = self.acceptance.verifier.fsm.last_sequence
            acceptance_cursor = self.acceptance.segment_store.acceptance_cursor
        except DeliveryFatalError:
            raise
        except Exception as error:  # noqa: BLE001 - local authority boundary
            raise self._latch("local delivery authority is unavailable", error)
        confirmed_through = snapshot.confirmed_through
        if not 0 <= confirmed_through <= acceptance_cursor <= evidence_head:
            raise self._latch("local delivery cursors are inconsistent")
        try:
            self.acceptance.segment_store.authenticated_refs(
                after_sequence=confirmed_through,
                through_sequence=confirmed_through,
                limit=1,
            )
        except Exception as error:  # noqa: BLE001 - store authority boundary
            raise self._latch("evidence store is unavailable for delivery", error)
        delivery_ceiling = self._barrier_ceiling(
            evidence_head=evidence_head,
            acceptance_cursor=acceptance_cursor,
            confirmed_through=confirmed_through,
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
                or pending.sequence > delivery_ceiling
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
            try:
                # The exact idempotent transition re-proves that the recovered
                # journal and this acceptance lifecycle bind the same ref.
                self.ack_journal.record_pending(pending_ref)
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
            await self.transport.ack_event(state.pending_body)
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
            self.ack_journal.record_confirmed(state.pending_ref)
        except Exception as error:  # noqa: BLE001 - journal authority boundary
            raise self._latch(
                "ACK confirmation durability is uncertain",
                error,
            )

    async def recover_pending_ack(self) -> bool:
        async with self._lock:
            state = self._local_state()
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

    async def _fetch_page(
        self,
        *,
        after: int,
        limit: int,
        confirmed_through: int,
    ) -> CoreEventsPageV1:
        try:
            raw = await self.transport.fetch_events(after=after, limit=limit)
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
            page = decode_events_page(raw)
            self._validate_page_binding(
                page,
                after=after,
                limit=limit,
                confirmed_through=confirmed_through,
            )
            return page
        except DeliveryFatalError as error:
            raise self._latch("observer page binding is invalid", error)
        except PageDecodeError as error:
            raise self._latch("observer page is invalid", error)

    def _result(
        self,
        *,
        accepted: int,
        confirmed: int,
        retry_required: bool,
    ) -> PollResult:
        state = self._local_state()
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
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_PAGE_EVENTS
        ):
            raise ValueError("poll limit must be in 1..100")
        async with self._lock:
            state = self._local_state()
            accepted = 0
            confirmed = 0
            remaining_budget = self.ack_budget
            if state.pending is not None:
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
                state = self._local_state()

            page = await self._fetch_page(
                after=state.evidence_head,
                limit=limit,
                confirmed_through=state.confirmed_through,
            )
            for item in page.events:
                try:
                    self.acceptance.accept(item)
                except Exception as error:  # noqa: BLE001 - evidence boundary is fail-closed
                    raise self._latch(
                        "observer evidence page failed durable acceptance",
                        error,
                    )
                accepted += 1

            state = self._local_state()
            refs = self._authenticated_refs(
                after=state.confirmed_through,
                through=state.delivery_ceiling,
                limit=remaining_budget,
            )
            for ref in refs:
                try:
                    self.ack_journal.record_pending(ref)
                    pending_state = self._local_state()
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

    async def close(self) -> None:
        async with self._lock:
            if self._transport_closed and self._lease_released:
                return
            self._closed = True
            primary: BaseException | None = None
            if not self._transport_closed:
                try:
                    await self.transport.close()
                except asyncio.CancelledError as error:
                    primary = error
                except Exception as error:  # noqa: BLE001 - cleanup boundary
                    primary = error
                else:
                    self._transport_closed = True
            if not self._lease_released:
                try:
                    self._delivery_lease.release()
                except Exception as error:  # noqa: BLE001 - preserve close primary
                    if primary is None:
                        primary = error
                    else:
                        primary.add_note(
                            "secondary ACK delivery-lease release failure: "
                            f"{type(error).__name__}: {error}"
                        )
                else:
                    self._lease_released = True
            if primary is not None:
                raise primary
