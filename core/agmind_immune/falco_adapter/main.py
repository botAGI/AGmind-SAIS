"""FastAPI ingress, bounded outbox, and one-worker observer delivery."""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import os
import re
import time
from collections import OrderedDict, deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Literal, Protocol

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agmind_immune import canonicaljson
from agmind_immune.contracts import (
    MAX_UINT64,
    ContractModel,
    _valid_timestamp,
    decode_strict,
)

from .parser import (
    FALCO_MAX_BODY_BYTES,
    FalcoMetricsHeartbeat,
    parse_falco_body,
)

OBSERVER_SOCKET = "/run/agmind-sais/observer-ingest/socket"
FALCO_EVENT_PATH: Literal["/v1/events/falco"] = "/v1/events/falco"
FALCO_COVERAGE_PATH: Literal["/v1/events/falco-coverage"] = "/v1/events/falco-coverage"
ROUTINE_CAPACITY = 1_024
PRIORITY_CAPACITY = 16
DELIVERY_TIMEOUT_SECONDS = 2.0
MAX_RETRY_SECONDS = 5.0
HEARTBEAT_TIMEOUT_SECONDS = 15.0
SHUTDOWN_DRAIN_SECONDS = 5.0
HEX64 = re.compile(r"^[0-9a-f]{64}$")

CoverageKind = Literal[
    "falco_adapter_start",
    "falco_adapter_stop",
    "falco_parse_rejection",
    "falco_queue_drop",
    "falco_delivery_failure",
    "falco_heartbeat_gap",
    "falco_heartbeat_lease",
    "falco_configuration_mismatch",
    "falco_kernel_event_drop",
    "falco_outputs_queue_drop",
]


class FalcoAdapterCoverageInputV1(BaseModel):
    """The narrow sensor-owned input accepted by observerd."""

    model_config = ConfigDict(extra="forbid", strict=True)

    kind: CoverageKind
    opened_at: str
    closed_at: str | None = None
    dropped_count: int | None = Field(default=None, ge=1, le=MAX_UINT64)
    reason_code: str
    source_payload_sha256: str

    @field_validator("opened_at", "closed_at")
    @classmethod
    def timestamp_is_utc(cls, value: str | None) -> str | None:
        return None if value is None else _valid_timestamp(value)

    @field_validator("reason_code")
    @classmethod
    def reason_is_ascii(cls, value: str) -> str:
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("reason_code must be ASCII") from error
        if not 1 <= len(encoded) <= 64 or any(byte < 0x20 or byte > 0x7E for byte in encoded):
            raise ValueError("reason_code must be bounded printable ASCII")
        return value

    @field_validator("source_payload_sha256")
    @classmethod
    def source_hash_is_valid(cls, value: str) -> str:
        if HEX64.fullmatch(value) is None:
            raise ValueError("source_payload_sha256 must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def interval_is_ordered(self) -> FalcoAdapterCoverageInputV1:
        if self.closed_at is not None:
            opened = dt.datetime.fromisoformat(self.opened_at)
            closed = dt.datetime.fromisoformat(self.closed_at)
            if closed < opened:
                raise ValueError("coverage close precedes open")
        if self.kind in {
            "falco_adapter_start",
            "falco_adapter_stop",
            "falco_heartbeat_lease",
        } and (self.closed_at != self.opened_at or self.dropped_count is not None):
            raise ValueError("Falco adapter lifecycle and lease must be closed points")
        return self


@dataclass(frozen=True)
class AdapterSettings:
    expected_falco_config_sha256: str
    expected_falco_rules_sha256: str
    observer_socket: str = OBSERVER_SOCKET

    def __post_init__(self) -> None:
        if (
            HEX64.fullmatch(self.expected_falco_config_sha256) is None
            or HEX64.fullmatch(self.expected_falco_rules_sha256) is None
        ):
            raise ValueError("expected Falco hashes must be lowercase SHA-256")
        if not self.observer_socket.startswith("/"):
            raise ValueError("observer socket path must be absolute")

    @classmethod
    def from_environment(cls) -> AdapterSettings:
        return cls(
            expected_falco_config_sha256=os.environ["AGMIND_FALCO_CONFIG_SHA256"],
            expected_falco_rules_sha256=os.environ["AGMIND_FALCO_RULES_SHA256"],
        )


@dataclass(frozen=True)
class DeliveryItem:
    path: Literal["/v1/events/falco", "/v1/events/falco-coverage"]
    body: bytes
    expires_at_monotonic: float | None = None

    def __post_init__(self) -> None:
        if self.path not in {FALCO_EVENT_PATH, FALCO_COVERAGE_PATH}:
            raise ValueError("delivery path is not allowlisted")
        if not self.body or len(self.body) > FALCO_MAX_BODY_BYTES:
            raise ValueError("delivery body must be 1..65536 bytes")


class BoundedOutbox:
    """Fixed queues with an explicit single-inflight acknowledgement gate."""

    _CRITICAL_PRIORITY_KEYS = frozenset(
        {
            "falco_adapter_stop",
            "falco_parse_rejection",
            "falco_queue_drop",
            "falco_delivery_failure",
            "falco_heartbeat_gap",
            "falco_configuration_mismatch",
            "falco_kernel_event_drop",
            "falco_outputs_queue_drop",
        }
    )

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._routine: deque[DeliveryItem] = deque()
        self._priority: OrderedDict[str, DeliveryItem] = OrderedDict()
        self._inflight: DeliveryItem | None = None

    @property
    def routine_pending(self) -> int:
        return len(self._routine)

    @property
    def priority_pending(self) -> int:
        return len(self._priority)

    @property
    def inflight(self) -> DeliveryItem | None:
        return self._inflight

    @property
    def empty(self) -> bool:
        return self._inflight is None and not self._routine and not self._priority

    async def admit_routine(self, item: DeliveryItem) -> int:
        async with self._condition:
            dropped = 0
            if len(self._routine) == ROUTINE_CAPACITY:
                self._routine.popleft()
                dropped = 1
            self._routine.append(item)
            self._condition.notify_all()
            return dropped

    async def admit_priority(self, key: str, item: DeliveryItem) -> None:
        async with self._condition:
            if key in self._priority:
                self._priority[key] = item
            else:
                if len(self._priority) >= PRIORITY_CAPACITY:
                    raise RuntimeError("priority coverage capacity exhausted")
                self._priority[key] = item
            self._condition.notify_all()

    @classmethod
    def _priority_class(cls, key: str) -> int:
        if key in cls._CRITICAL_PRIORITY_KEYS:
            return 0
        if key == "falco_heartbeat_lease":
            return 2
        return 1

    async def get(self) -> DeliveryItem:
        async with self._condition:
            await self._condition.wait_for(
                lambda: self._inflight is None and bool(self._priority or self._routine)
            )
            if self._priority:
                key = min(self._priority, key=self._priority_class)
                item = self._priority.pop(key)
            else:
                item = self._routine.popleft()
            self._inflight = item
            return item

    async def ack(self, item: DeliveryItem) -> None:
        async with self._condition:
            if self._inflight is not item:
                raise RuntimeError("delivery acknowledgement does not match inflight")
            self._inflight = None
            self._condition.notify_all()

    async def discard_inflight(self, item: DeliveryItem) -> None:
        await self.ack(item)

    async def wait_available(self, timeout: float) -> bool:
        async with self._condition:
            if self._inflight is None and bool(self._priority or self._routine):
                return True
            try:
                await asyncio.wait_for(
                    self._condition.wait_for(
                        lambda: self._inflight is None and bool(self._priority or self._routine)
                    ),
                    timeout=timeout,
                )
            except TimeoutError:
                return False
            return True

    async def wake(self) -> None:
        async with self._condition:
            self._condition.notify_all()


class PostCallable(Protocol):
    async def __call__(self, path: str, body: bytes, timeout: float) -> None: ...


class _ObserverAck(ContractModel):
    event_id: str

    @field_validator("event_id")
    @classmethod
    def event_id_is_valid(cls, value: str) -> str:
        if re.fullmatch(r"evt_[0-9a-f]{64}", value) is None:
            raise ValueError("observer acknowledgement has invalid event_id")
        return value


class ObserverUDSClient:
    """The only network capability available to the delivery worker."""

    def __init__(
        self,
        socket_path: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if transport is None:
            transport = httpx.AsyncHTTPTransport(uds=socket_path)
        self._client = httpx.AsyncClient(
            transport=transport,
            base_url="http://observer",
            follow_redirects=False,
        )

    async def post(self, path: str, body: bytes, timeout: float) -> None:
        response = await self._client.post(
            path,
            content=body,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        if response.status_code != 201:
            raise httpx.HTTPStatusError(
                "observer did not return exact durable-append status",
                request=response.request,
                response=response,
            )
        try:
            decode_strict(response.content, _ObserverAck, 1_024)
        except (TypeError, UnicodeError, ValueError) as error:
            raise httpx.RemoteProtocolError(
                "observer acknowledgement is malformed",
                request=response.request,
            ) from error

    async def close(self) -> None:
        await self._client.aclose()


class DeliveryWorker:
    """Sequential stable-body delivery with local expiry only for leases."""

    def __init__(
        self,
        outbox: BoundedOutbox,
        *,
        post: PostCallable,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        deadline_provider: Callable[[], float | None] | None = None,
        on_cycle: Callable[[], Awaitable[None]] | None = None,
        on_failure: Callable[[DeliveryItem], Awaitable[None]] | None = None,
        on_recovery: Callable[[DeliveryItem], Awaitable[None]] | None = None,
    ) -> None:
        self._outbox = outbox
        self._post = post
        self._sleep = sleep
        self._monotonic = monotonic
        self._deadline_provider = deadline_provider or (lambda: None)
        self._on_cycle = on_cycle
        self._on_failure = on_failure
        self._on_recovery = on_recovery

    def _remaining(self) -> float | None:
        deadline = self._deadline_provider()
        if deadline is None:
            return None
        return max(0.0, deadline - self._monotonic())

    async def deliver_next(self) -> bool:
        item = await self._outbox.get()
        delay = 0.125
        failure_reported = False
        while True:
            if self._on_cycle is not None:
                await self._on_cycle()
            if (
                item.expires_at_monotonic is not None
                and self._monotonic() >= item.expires_at_monotonic
            ):
                await self._outbox.discard_inflight(item)
                return True
            remaining = self._remaining()
            if remaining is not None and remaining <= 0:
                return False
            timeout = (
                DELIVERY_TIMEOUT_SECONDS
                if remaining is None
                else min(DELIVERY_TIMEOUT_SECONDS, remaining)
            )
            try:
                await self._post(
                    item.path,
                    item.body,
                    timeout,
                )
            except (httpx.HTTPError, OSError, TimeoutError):
                if not failure_reported and self._on_failure is not None:
                    await self._on_failure(item)
                    failure_reported = True
                remaining = self._remaining()
                if remaining is not None and remaining <= 0:
                    return False
                sleep_for = min(delay, MAX_RETRY_SECONDS)
                if remaining is not None:
                    sleep_for = min(sleep_for, remaining)
                await self._sleep(sleep_for)
                delay = min(delay * 2, MAX_RETRY_SECONDS)
                continue
            await self._outbox.ack(item)
            if self._on_recovery is not None:
                await self._on_recovery(item)
            return True


class HeartbeatWatchdog:
    """Monotonic Falco health state derived only from exact metrics snapshots."""

    def __init__(
        self,
        settings: AdapterSettings,
        *,
        emit: Callable[[FalcoAdapterCoverageInputV1], Awaitable[None]],
        now: Callable[[], dt.datetime],
        monotonic: Callable[[], float],
    ) -> None:
        self._settings = settings
        self._emit = emit
        self._now = now
        self._monotonic = monotonic
        self._last_valid_monotonic = monotonic()
        self._last_valid_wall = self._timestamp(now())
        self._last_valid_event_time: str | None = None
        self._last_counters: tuple[int, int] | None = None
        self._pending_rebase: tuple[int, int] | None = None
        self._opened: dict[CoverageKind, str] = {}
        self._drop_totals: dict[CoverageKind, int] = {}

    @staticmethod
    def _timestamp(value: dt.datetime) -> str:
        if value.tzinfo is None:
            raise ValueError("coverage clock must be timezone-aware")
        utc = value.astimezone(dt.UTC)
        rendered = utc.strftime("%Y-%m-%dT%H:%M:%S")
        if utc.microsecond:
            rendered += "." + f"{utc.microsecond:06d}".rstrip("0")
        return rendered + "Z"

    async def _open(
        self,
        kind: CoverageKind,
        reason: str,
        source_hash: str,
        dropped_count: int | None = None,
        *,
        opened_at: str | None = None,
    ) -> None:
        interval_start = self._opened.setdefault(
            kind,
            opened_at or self._timestamp(self._now()),
        )
        await self._emit(
            FalcoAdapterCoverageInputV1(
                kind=kind,
                opened_at=interval_start,
                dropped_count=dropped_count,
                reason_code=reason,
                source_payload_sha256=source_hash,
            )
        )

    async def _close(
        self,
        kind: CoverageKind,
        source_hash: str,
        *,
        closed_at: str,
    ) -> None:
        opened_at = self._opened.get(kind)
        if opened_at is None:
            return
        dropped_count = self._drop_totals.get(kind)
        await self._emit(
            FalcoAdapterCoverageInputV1(
                kind=kind,
                opened_at=opened_at,
                closed_at=closed_at,
                dropped_count=dropped_count,
                reason_code="recovered",
                source_payload_sha256=source_hash,
            )
        )
        self._opened.pop(kind, None)
        self._drop_totals.pop(kind, None)

    async def open_initial_gap(self, started_at: str) -> None:
        """Fence external readiness before runtime intake becomes available."""
        self._last_valid_wall = started_at
        self._last_valid_event_time = None
        self._last_valid_monotonic = self._monotonic()
        source_hash = hashlib.sha256(b"AGMIND_FALCO_AWAITING_INITIAL_HEARTBEAT_V1\0").hexdigest()
        await self._open(
            "falco_heartbeat_gap",
            "awaiting_initial_heartbeat",
            source_hash,
            opened_at=started_at,
        )

    @property
    def ready(self) -> bool:
        return (
            self._last_valid_event_time is not None
            and self._monotonic() - self._last_valid_monotonic <= HEARTBEAT_TIMEOUT_SECONDS
            and "falco_heartbeat_gap" not in self._opened
            and "falco_configuration_mismatch" not in self._opened
        )

    @staticmethod
    def _identity_mismatch(
        settings: AdapterSettings,
        heartbeat: FalcoMetricsHeartbeat,
    ) -> str | None:
        if heartbeat.falco_version != "0.44.1":
            return "falco_version_mismatch"
        if heartbeat.engine_name != "modern_bpf":
            return "falco_engine_mismatch"
        if heartbeat.config_sha256 != settings.expected_falco_config_sha256:
            return "falco_config_hash_mismatch"
        if heartbeat.rules_sha256 != settings.expected_falco_rules_sha256:
            return "falco_rules_hash_mismatch"
        return None

    async def _record_drop_delta(
        self,
        kind: Literal[
            "falco_kernel_event_drop",
            "falco_outputs_queue_drop",
        ],
        reason: str,
        source_hash: str,
        delta: int,
        received_at: str,
    ) -> None:
        if delta == 0:
            await self._close(
                kind,
                source_hash,
                closed_at=received_at,
            )
            return
        cumulative = min(
            MAX_UINT64,
            self._drop_totals.get(kind, 0) + delta,
        )
        self._drop_totals[kind] = cumulative
        await self._open(
            kind,
            reason,
            source_hash,
            cumulative,
            opened_at=self._last_valid_wall,
        )

    async def _record_counter_changes(
        self,
        previous: tuple[int, int],
        current: tuple[int, int],
        heartbeat: FalcoMetricsHeartbeat,
        received_at: str,
    ) -> None:
        await self._record_drop_delta(
            "falco_kernel_event_drop",
            "falco_kernel_drop_counter_increase",
            heartbeat.raw_event_sha256,
            current[1] - previous[1],
            received_at,
        )
        await self._record_drop_delta(
            "falco_outputs_queue_drop",
            "falco_outputs_queue_counter_increase",
            heartbeat.raw_event_sha256,
            current[0] - previous[0],
            received_at,
        )

    async def observe(
        self,
        heartbeat: FalcoMetricsHeartbeat,
        *,
        received_at: str | None = None,
        received_monotonic: float | None = None,
    ) -> bool:
        """Return true only when this heartbeat renews external readiness."""
        receipt_wall = received_at or self._timestamp(self._now())
        receipt_monotonic = self._monotonic() if received_monotonic is None else received_monotonic
        mismatch_reason = self._identity_mismatch(self._settings, heartbeat)
        if mismatch_reason is not None:
            await self._open(
                "falco_configuration_mismatch",
                mismatch_reason,
                heartbeat.raw_event_sha256,
                opened_at=self._last_valid_wall,
            )
            return False

        current = (
            heartbeat.outputs_queue_num_drops,
            heartbeat.scap_n_drops,
        )
        previous = self._last_counters
        if self._pending_rebase is not None:
            pending = self._pending_rebase
            if current[0] < pending[0] or current[1] < pending[1]:
                self._pending_rebase = current
                await self._open(
                    "falco_configuration_mismatch",
                    "falco_counter_rollback",
                    heartbeat.raw_event_sha256,
                    opened_at=self._last_valid_wall,
                )
                return False
            previous = pending
            self._pending_rebase = None
        elif previous is not None and (current[0] < previous[0] or current[1] < previous[1]):
            self._pending_rebase = current
            await self._open(
                "falco_configuration_mismatch",
                "falco_counter_rollback",
                heartbeat.raw_event_sha256,
                opened_at=self._last_valid_wall,
            )
            return False

        if previous is not None:
            await self._record_counter_changes(
                previous,
                current,
                heartbeat,
                receipt_wall,
            )
        await self._close(
            "falco_heartbeat_gap",
            heartbeat.raw_event_sha256,
            closed_at=receipt_wall,
        )
        await self._close(
            "falco_configuration_mismatch",
            heartbeat.raw_event_sha256,
            closed_at=receipt_wall,
        )
        await self._emit(
            FalcoAdapterCoverageInputV1(
                kind="falco_heartbeat_lease",
                opened_at=receipt_wall,
                closed_at=receipt_wall,
                reason_code="valid_heartbeat",
                source_payload_sha256=heartbeat.raw_event_sha256,
            )
        )
        self._last_counters = current
        self._last_valid_event_time = heartbeat.event_time
        self._last_valid_wall = receipt_wall
        self._last_valid_monotonic = receipt_monotonic
        return True

    async def check(self) -> None:
        if self._monotonic() - self._last_valid_monotonic <= HEARTBEAT_TIMEOUT_SECONDS:
            return
        source_hash = hashlib.sha256(b"AGMIND_FALCO_HEARTBEAT_TIMEOUT_V1\0").hexdigest()
        await self._open(
            "falco_heartbeat_gap",
            "falco_heartbeat_timeout",
            source_hash,
            opened_at=self._last_valid_wall,
        )


class AdapterRuntime:
    """Own intake, one delivery worker, watchdog, and one shutdown deadline."""

    def __init__(
        self,
        settings: AdapterSettings,
        *,
        now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC),
        monotonic: Callable[[], float] = time.monotonic,
        post: PostCallable | None = None,
    ) -> None:
        self.settings = settings
        self.outbox = BoundedOutbox()
        self._now = now
        self._monotonic = monotonic
        self._post = post
        self._client: ObserverUDSClient | None = None
        self._task: asyncio.Task[None] | None = None
        self._accepting = False
        self._started = False
        self._drain_deadline: float | None = None
        self._queue_dropped = 0
        self._queue_drop_opened_at: str | None = None
        self._delivery_failure_opened_at: str | None = None
        self._delivered_heartbeat_monotonic: float | None = None
        self._parse_rejection_opened_at: str | None = None
        self._parse_rejection_count = 0
        self._parse_rejection_source_hash: str | None = None
        self.watchdog = HeartbeatWatchdog(
            settings,
            emit=self._admit_coverage,
            now=now,
            monotonic=monotonic,
        )

    @property
    def drain_deadline(self) -> float | None:
        return self._drain_deadline

    @property
    def ready(self) -> bool:
        delivered = self._delivered_heartbeat_monotonic
        return (
            self._started
            and self._accepting
            and self._task is not None
            and not self._task.done()
            and self._delivery_failure_opened_at is None
            and delivered is not None
            and self._monotonic() - delivered <= HEARTBEAT_TIMEOUT_SECONDS
            and self.watchdog.ready
        )

    @staticmethod
    def _timestamp(value: dt.datetime) -> str:
        return HeartbeatWatchdog._timestamp(value)

    @staticmethod
    def _derived_hash(label: str) -> str:
        return hashlib.sha256(
            b"AGMIND_FALCO_ADAPTER_COVERAGE_V1\0" + label.encode("ascii")
        ).hexdigest()

    async def _admit_coverage(
        self,
        value: FalcoAdapterCoverageInputV1,
    ) -> None:
        await self.outbox.admit_priority(
            value.kind,
            DeliveryItem(
                FALCO_COVERAGE_PATH,
                canonicaljson.canonical_json(value),
                expires_at_monotonic=(
                    self._monotonic() + HEARTBEAT_TIMEOUT_SECONDS
                    if value.kind == "falco_heartbeat_lease"
                    else None
                ),
            ),
        )

    async def _emit_point_coverage(
        self,
        kind: CoverageKind,
        reason: str,
        source_hash: str,
        *,
        dropped_count: int | None = None,
        opened_at: str | None = None,
        closed_at: str | None = None,
    ) -> None:
        await self._admit_coverage(
            FalcoAdapterCoverageInputV1(
                kind=kind,
                opened_at=opened_at or self._timestamp(self._now()),
                closed_at=closed_at,
                dropped_count=dropped_count,
                reason_code=reason,
                source_payload_sha256=source_hash,
            )
        )

    async def admit_raw(self, raw: bytes) -> None:
        if not self._accepting:
            if not self._started:
                raise RuntimeError("Falco adapter startup coverage is not admitted")
            raise RuntimeError("Falco adapter intake is stopped")
        received_at = self._timestamp(self._now())
        received_monotonic = self._monotonic()
        raw_hash = hashlib.sha256(raw).hexdigest()
        try:
            parsed = parse_falco_body(raw)
        except (TypeError, UnicodeError, ValueError):
            if self._parse_rejection_opened_at is None:
                self._parse_rejection_opened_at = received_at
            self._parse_rejection_count = min(
                MAX_UINT64,
                self._parse_rejection_count + 1,
            )
            self._parse_rejection_source_hash = raw_hash
            await self._emit_point_coverage(
                "falco_parse_rejection",
                "invalid_falco_body",
                raw_hash,
                dropped_count=self._parse_rejection_count,
                opened_at=self._parse_rejection_opened_at,
            )
            raise
        if isinstance(parsed, FalcoMetricsHeartbeat):
            valid = await self.watchdog.observe(
                parsed,
                received_at=received_at,
                received_monotonic=received_monotonic,
            )
            if (
                valid
                and self._parse_rejection_opened_at is not None
                and self._parse_rejection_source_hash is not None
            ):
                await self._emit_point_coverage(
                    "falco_parse_rejection",
                    "valid_heartbeat_recovered",
                    self._parse_rejection_source_hash,
                    dropped_count=self._parse_rejection_count,
                    opened_at=self._parse_rejection_opened_at,
                    closed_at=received_at,
                )
                self._parse_rejection_opened_at = None
                self._parse_rejection_count = 0
                self._parse_rejection_source_hash = None
            return
        dropped = await self.outbox.admit_routine(
            DeliveryItem(
                FALCO_EVENT_PATH,
                canonicaljson.canonical_json(parsed),
            )
        )
        if dropped:
            self._queue_dropped += dropped
            if self._queue_drop_opened_at is None:
                self._queue_drop_opened_at = self._timestamp(self._now())
            await self._emit_point_coverage(
                "falco_queue_drop",
                "routine_capacity_exceeded",
                raw_hash,
                dropped_count=self._queue_dropped,
                opened_at=self._queue_drop_opened_at,
            )

    async def delivery_failed(self, item: DeliveryItem) -> None:
        if self._delivery_failure_opened_at is None:
            self._delivery_failure_opened_at = self._timestamp(self._now())
        await self._emit_point_coverage(
            "falco_delivery_failure",
            "observer_delivery_failed",
            hashlib.sha256(item.body).hexdigest(),
            opened_at=self._delivery_failure_opened_at,
        )

    async def delivery_recovered(self, item: DeliveryItem) -> None:
        source_hash = hashlib.sha256(item.body).hexdigest()
        closed_at = self._timestamp(self._now())
        if self._delivery_failure_opened_at is not None:
            await self._emit_point_coverage(
                "falco_delivery_failure",
                "observer_delivery_recovered",
                source_hash,
                opened_at=self._delivery_failure_opened_at,
                closed_at=closed_at,
            )
            self._delivery_failure_opened_at = None
        if item.expires_at_monotonic is not None:
            self._delivered_heartbeat_monotonic = self._monotonic()
        if (
            self._queue_drop_opened_at is not None
            and self.outbox.routine_pending < ROUTINE_CAPACITY
        ):
            await self._emit_point_coverage(
                "falco_queue_drop",
                "routine_queue_recovered",
                source_hash,
                dropped_count=self._queue_dropped,
                opened_at=self._queue_drop_opened_at,
                closed_at=closed_at,
            )
            self._queue_drop_opened_at = None
            self._queue_dropped = 0

    def begin_shutdown(self) -> float:
        self._accepting = False
        if self._drain_deadline is None:
            self._drain_deadline = self._monotonic() + SHUTDOWN_DRAIN_SECONDS
        return self._drain_deadline

    async def start(self) -> None:
        if self._task is not None:
            raise RuntimeError("Falco adapter runtime already started")
        started_at = self._timestamp(self._now())
        await self._emit_point_coverage(
            "falco_adapter_start",
            "adapter_started",
            self._derived_hash("adapter_started"),
            opened_at=started_at,
            closed_at=started_at,
        )
        await self.watchdog.open_initial_gap(started_at)
        if self._post is None:
            self._client = ObserverUDSClient(self.settings.observer_socket)
            post = self._client.post
        else:
            post = self._post
        worker = DeliveryWorker(
            self.outbox,
            post=post,
            monotonic=self._monotonic,
            deadline_provider=lambda: self._drain_deadline,
            on_cycle=self.watchdog.check,
            on_failure=self.delivery_failed,
            on_recovery=self.delivery_recovered,
        )
        self._task = asyncio.create_task(self._run(worker))
        self._started = True
        self._accepting = True

    async def _run(self, worker: DeliveryWorker) -> None:
        while True:
            if self._drain_deadline is not None and (
                self.outbox.empty or self._monotonic() >= self._drain_deadline
            ):
                return
            available = await self.outbox.wait_available(1.0)
            if self._drain_deadline is not None and self._monotonic() >= self._drain_deadline:
                return
            if not available:
                await self.watchdog.check()
                continue
            if not await worker.deliver_next():
                return

    async def shutdown(self) -> None:
        deadline = self.begin_shutdown()
        stopped_at = self._timestamp(self._now())
        await self._emit_point_coverage(
            "falco_adapter_stop",
            "adapter_stopping",
            self._derived_hash("adapter_stopping"),
            opened_at=stopped_at,
            closed_at=stopped_at,
        )
        await self.outbox.wake()
        task = self._task
        if task is not None:
            remaining = max(0.0, deadline - self._monotonic())
            try:
                await asyncio.wait_for(task, timeout=remaining)
            except TimeoutError:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            self._task = None
        if self._client is not None:
            await self._client.close()
            self._client = None


class _BodyTooLarge(Exception):
    pass


async def _bounded_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > FALCO_MAX_BODY_BYTES:
            raise _BodyTooLarge
        body.extend(chunk)
    return bytes(body)


def create_app(runtime: AdapterRuntime) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await runtime.start()
        try:
            yield
        finally:
            await runtime.shutdown()

    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.post("/v1/falco/raw", status_code=202)
    async def falco_raw(request: Request) -> JSONResponse:
        if request.headers.get("content-type") != "application/json":
            return JSONResponse(
                {"error": "unsupported_media_type"},
                status_code=415,
            )
        try:
            raw = await _bounded_body(request)
        except _BodyTooLarge:
            return JSONResponse({"error": "body_too_large"}, status_code=413)
        try:
            await runtime.admit_raw(raw)
        except RuntimeError:
            return JSONResponse({"error": "intake_stopped"}, status_code=503)
        except (TypeError, UnicodeError, ValueError):
            return JSONResponse({"error": "invalid_falco_body"}, status_code=400)
        return JSONResponse({"status": "accepted"}, status_code=202)

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"live": True, "version": "0.1.0"})

    @app.get("/ready")
    async def ready() -> JSONResponse:
        is_ready = runtime.ready
        return JSONResponse(
            {"ready": is_ready, "version": "0.1.0"},
            status_code=200 if is_ready else 503,
        )

    return app


def main() -> None:
    uvicorn.run(
        create_app(AdapterRuntime(AdapterSettings.from_environment())),
        host="0.0.0.0",
        port=8765,
        access_log=False,
    )


if __name__ == "__main__":
    main()
