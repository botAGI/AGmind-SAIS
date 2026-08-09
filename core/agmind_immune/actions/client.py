"""Bounded Core-to-actuator intent delivery over one fixed Unix socket."""

from __future__ import annotations

import asyncio
import hmac
import os
from pathlib import Path
from typing import final

import httpx

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import (
    PreparedTemporaryEgressDenyPlanV1,
    TemporaryEgressDenyIntentV1,
    decode_strict,
)

_ACTUATOR_BASE_URL = "http://actuator"
_INTENT_ROUTE = "/v1/intents"
_MAX_WIRE_BYTES = 65_536
_MAX_ERROR_BYTES = 4_096
_CONNECT_TIMEOUT_SECONDS = 2.0
_TOTAL_TIMEOUT_SECONDS = 10.0
_CLIENT_FACTORY = object()
_TEST_CLIENT_FACTORY = object()
_TERMINAL_REJECTIONS = {
    (409, b'{"error":"intent_conflict"}\n'): "intent_conflict",
    (409, b'{"error":"target_stale"}\n'): "target_stale",
    (422, b'{"error":"intent_rejected"}\n'): "intent_rejected",
}
_INTENT_BINDING_FIELDS = (
    "intent_id",
    "verb",
    "host_id",
    "docker_container_id",
    "docker_started_at",
    "image_id",
    "repo_digests",
    "immutable_spec_sha256",
    "inventory_generation",
    "inventory_revision",
    "destination_ipv4",
    "ttl_seconds",
    "evidence_ids",
    "detector_bundle_sha256",
    "policy_bundle_version",
    "policy_bundle_sha256",
    "coverage_snapshot_sha256",
    "created_at",
)


class IntentDeliveryError(RuntimeError):
    """Base class for typed intent-delivery failures."""


class IntentDeliveryRetryable(IntentDeliveryError):
    """Exact intent delivery may be retried without changing its bytes."""


class IntentDeliveryRejected(IntentDeliveryError):
    """The actuator returned one exact, per-intent terminal rejection."""

    def __init__(self, status_code: int, reason_code: str) -> None:
        if (
            type(status_code) is not int
            or type(reason_code) is not str
            or reason_code not in _TERMINAL_REJECTIONS.values()
            or not any(
                status == status_code and reason == reason_code
                for (status, _raw), reason in _TERMINAL_REJECTIONS.items()
            )
        ):
            raise ValueError("terminal actuator rejection is invalid")
        self.status_code = status_code
        self.reason_code = reason_code
        super().__init__(
            f"actuator terminally rejected intent: {status_code} {reason_code}"
        )


class IntentDeliveryFatal(IntentDeliveryError):
    """Intent delivery failed a local or remote authority check."""


def _decode_exact_intent(raw: bytes) -> TemporaryEgressDenyIntentV1:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_WIRE_BYTES:
        raise IntentDeliveryFatal("intent bytes are absent or exceed 64 KiB")
    try:
        intent = decode_strict(raw, TemporaryEgressDenyIntentV1, _MAX_WIRE_BYTES)
    except (TypeError, UnicodeError, ValueError) as error:
        raise IntentDeliveryFatal("intent is not strict JSON") from error
    if type(intent) is not TemporaryEgressDenyIntentV1 or not hmac.compare_digest(
        canonical_json(intent), raw
    ):
        raise IntentDeliveryFatal("intent bytes are not canonical")
    return intent


def _decode_exact_plan(raw: bytes) -> PreparedTemporaryEgressDenyPlanV1:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_WIRE_BYTES:
        raise IntentDeliveryFatal("prepared plan is absent or exceeds 64 KiB")
    try:
        plan = decode_strict(raw, PreparedTemporaryEgressDenyPlanV1, _MAX_WIRE_BYTES)
    except (TypeError, UnicodeError, ValueError) as error:
        raise IntentDeliveryFatal("prepared plan is not strict JSON") from error
    if type(plan) is not PreparedTemporaryEgressDenyPlanV1 or not hmac.compare_digest(
        canonical_json(plan), raw
    ):
        raise IntentDeliveryFatal("prepared plan bytes are not canonical")
    return plan


def _require_plan_binds_intent(
    plan: PreparedTemporaryEgressDenyPlanV1,
    intent: TemporaryEgressDenyIntentV1,
) -> None:
    if (
        type(plan) is not PreparedTemporaryEgressDenyPlanV1
        or type(intent) is not TemporaryEgressDenyIntentV1
        or any(getattr(plan, field) != getattr(intent, field) for field in _INTENT_BINDING_FIELDS)
    ):
        raise IntentDeliveryFatal("prepared plan changed an intent field")


def _new_http_client(
    transport: httpx.AsyncBaseTransport,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=_ACTUATOR_BASE_URL,
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Content-Type": "application/json",
        },
        timeout=httpx.Timeout(
            _TOTAL_TIMEOUT_SECONDS,
            connect=_CONNECT_TIMEOUT_SECONDS,
            read=_TOTAL_TIMEOUT_SECONDS,
            write=_TOTAL_TIMEOUT_SECONDS,
            pool=_CONNECT_TIMEOUT_SECONDS,
        ),
        follow_redirects=False,
        max_redirects=0,
        limits=httpx.Limits(
            max_connections=1,
            max_keepalive_connections=1,
            keepalive_expiry=2.0,
        ),
        http1=True,
        http2=False,
        transport=transport,
        trust_env=False,
    )


async def _read_bounded(response: httpx.Response, limit: int) -> bytes:
    if response.is_stream_consumed:
        raw = response.content
        if type(raw) is not bytes or len(raw) > limit:
            raise IntentDeliveryFatal("actuator response exceeds its byte limit")
        return raw
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_raw():
        if type(chunk) is not bytes:
            raise IntentDeliveryFatal("actuator response yielded inexact bytes")
        total += len(chunk)
        if total > limit:
            raise IntentDeliveryFatal("actuator response exceeds its byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


async def _discard_error(response: httpx.Response) -> None:
    try:
        await _read_bounded(response, _MAX_ERROR_BYTES)
    except (httpx.HTTPError, IntentDeliveryError, OSError, TimeoutError):
        return


def _declared_length(response: httpx.Response) -> int | None:
    values = response.headers.get_list("content-length")
    if not values:
        return None
    if len(values) != 1:
        raise IntentDeliveryFatal("actuator returned duplicate Content-Length")
    value = values[0]
    if not value.isascii() or not value.isdecimal() or (len(value) > 1 and value.startswith("0")):
        raise IntentDeliveryFatal("actuator Content-Length is not canonical")
    length = int(value)
    if not 0 <= length <= _MAX_WIRE_BYTES:
        raise IntentDeliveryFatal("actuator response exceeds 64 KiB")
    return length


@final
class ActuatorIntentClient:
    """Concurrency-one client for the actuator's sole Core mutation route."""

    __slots__ = ("_client", "_closed", "_lock")

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        _factory: object,
    ) -> None:
        if _factory not in {_CLIENT_FACTORY, _TEST_CLIENT_FACTORY}:
            raise TypeError("use ActuatorIntentClient.create()")
        if type(client) is not httpx.AsyncClient:
            raise TypeError("actuator intent HTTP client is inexact")
        self._client = client
        self._closed = False
        self._lock = asyncio.Lock()

    @classmethod
    def create(cls, socket_path: Path) -> ActuatorIntentClient:
        if (
            not isinstance(socket_path, Path)
            or not socket_path.is_absolute()
            or Path(os.path.normpath(socket_path)) != socket_path
            or "\x00" in str(socket_path)
        ):
            raise IntentDeliveryFatal("actuator socket path is invalid")
        transport = httpx.AsyncHTTPTransport(
            uds=str(socket_path),
            retries=0,
            limits=httpx.Limits(
                max_connections=1,
                max_keepalive_connections=1,
                keepalive_expiry=2.0,
            ),
        )
        return cls(
            _new_http_client(transport),
            _factory=_CLIENT_FACTORY,
        )

    async def prepare(
        self,
        intent_canonical: bytes,
    ) -> PreparedTemporaryEgressDenyPlanV1:
        intent = _decode_exact_intent(intent_canonical)
        try:
            async with asyncio.timeout(_TOTAL_TIMEOUT_SECONDS):
                async with self._lock:
                    if self._closed:
                        raise IntentDeliveryFatal("actuator intent client is closed")
                    return await self._prepare_locked(intent_canonical, intent)
        except IntentDeliveryError:
            raise
        except TimeoutError as error:
            raise IntentDeliveryRetryable("actuator intent whole-call deadline expired") from error

    async def _prepare_locked(
        self,
        intent_canonical: bytes,
        intent: TemporaryEgressDenyIntentV1,
    ) -> PreparedTemporaryEgressDenyPlanV1:
        try:
            async with self._client.stream(
                "POST",
                _INTENT_ROUTE,
                content=intent_canonical,
            ) as response:
                if response.headers.get_list("content-encoding"):
                    await _discard_error(response)
                    raise IntentDeliveryFatal("actuator response content encoding is forbidden")
                if response.status_code in {408, 425, 429} or 500 <= response.status_code <= 599:
                    await _discard_error(response)
                    raise IntentDeliveryRetryable(
                        f"actuator intent POST returned {response.status_code}"
                    )
                if response.status_code != 200:
                    if response.headers.get_list("content-type") != ["application/json"]:
                        await _discard_error(response)
                        raise IntentDeliveryFatal(
                            "actuator rejection Content-Type is not exact JSON"
                        )
                    declared = _declared_length(response)
                    raw = await _read_bounded(response, _MAX_ERROR_BYTES)
                    if declared is not None and declared != len(raw):
                        raise IntentDeliveryFatal(
                            "actuator rejection Content-Length differs from response bytes"
                        )
                    reason_code = _TERMINAL_REJECTIONS.get(
                        (response.status_code, raw)
                    )
                    if reason_code is not None:
                        raise IntentDeliveryRejected(
                            response.status_code,
                            reason_code,
                        )
                    raise IntentDeliveryFatal(
                        f"actuator intent POST returned {response.status_code}"
                    )
                if response.headers.get_list("content-type") != ["application/json"]:
                    await _discard_error(response)
                    raise IntentDeliveryFatal("actuator response Content-Type is not exact JSON")
                declared = _declared_length(response)
                raw = await _read_bounded(response, _MAX_WIRE_BYTES)
                if declared is not None and declared != len(raw):
                    raise IntentDeliveryFatal("actuator Content-Length differs from response bytes")
        except IntentDeliveryError:
            raise
        except (httpx.HTTPError, OSError, TimeoutError) as error:
            raise IntentDeliveryRetryable("actuator intent POST transport is ambiguous") from error
        plan = _decode_exact_plan(raw)
        _require_plan_binds_intent(plan, intent)
        return plan

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                await self._client.aclose()
            except (httpx.HTTPError, OSError) as error:
                raise IntentDeliveryRetryable("actuator intent client close failed") from error


def _actuator_intent_client_for_test(
    transport: httpx.AsyncBaseTransport,
) -> ActuatorIntentClient:
    if not isinstance(transport, httpx.AsyncBaseTransport):
        raise TypeError("actuator test transport is inexact")
    return ActuatorIntentClient(
        _new_http_client(transport),
        _factory=_TEST_CLIENT_FACTORY,
    )


__all__ = [
    "ActuatorIntentClient",
    "IntentDeliveryError",
    "IntentDeliveryFatal",
    "IntentDeliveryRejected",
    "IntentDeliveryRetryable",
]
