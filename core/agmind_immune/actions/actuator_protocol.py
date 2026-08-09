"""Bounded read-only Core client for the actuator intent/journal UDS API."""

from __future__ import annotations

import asyncio
import base64
import binascii
import datetime as dt
import hmac
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, final

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import (
    ActionRecordV1,
    PreparedTemporaryEgressDenyPlanV1,
    decode_strict,
)
from agmind_immune.evidence.frames import encode_frame

from .actuator_records import (
    ActuatorRecordError,
    ActuatorRecordProjection,
    MirroredIntentState,
    VerifiedActuatorPayload,
    actuator_intent_sha256,
)

_ACTUATOR_BASE_URL = "http://actuator"
_INTENT_ID = re.compile(r"^int_[0-9a-f]{32}$")
_RECORD_ID = re.compile(r"^ar_[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"^(?P<whole>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?Z$"
)
_STATUS_STATES = {
    "RESERVED",
    "PREPARED",
    "APPROVED",
    "REJECTED",
    "EXPIRED_UNAPPLIED",
    "APPLIED",
    "VERIFIED",
    "EXPIRED",
    "STALE_ABORT",
    "FAILED_DIRTY",
}
_MAX_FRAME_PAYLOAD = 65_536
_FRAME_OVERHEAD = 76
_MAX_JOURNAL_RECORDS = 65_536
_MAX_JOURNAL_BYTES = 64 * 1024 * 1024
_MAX_PAGE_BYTES = 4 * 1024 * 1024
_MAX_STATUS_BYTES = 131_072
_MAX_ERROR_BYTES = 4_096
_CONNECT_TIMEOUT_SECONDS = 2.0
_REQUEST_TIMEOUT_SECONDS = 10.0
_SNAPSHOT_TIMEOUT_SECONDS = 60.0
_CLIENT_FACTORY = object()
_TEST_CLIENT_FACTORY = object()


class ActuatorJournalError(RuntimeError):
    """Base class for read-only actuator journal failures."""


class ActuatorJournalRetryable(ActuatorJournalError):
    """A read failed before a complete authenticated result was available."""


class ActuatorJournalFatal(ActuatorJournalError):
    """The actuator wire contract, chain, or signed payload is invalid."""


class ActuatorJournalConflict(ActuatorJournalFatal):
    """The actuator rejected or changed one pinned journal prefix."""


class ActuatorIntentNotFound(ActuatorJournalError):
    """The exact intent ID is absent from the actuator's durable journal."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _timestamp_is_canonical(value: str) -> bool:
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        return False
    fraction = match.group("fraction")
    if fraction is not None and fraction.endswith("0"):
        return False
    try:
        dt.datetime.strptime(match.group("whole"), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.UTC)
    except ValueError:
        return False
    return True


class IntentActionStatusV1(_FrozenModel):
    state: str
    record_id: str
    record_sha256: str
    observed_at: str

    @field_validator("state")
    @classmethod
    def state_is_exact(cls, value: str) -> str:
        if value not in _STATUS_STATES - {"RESERVED"}:
            raise ValueError("invalid intent action state")
        return value

    @field_validator("record_id")
    @classmethod
    def record_is_exact(cls, value: str) -> str:
        if _RECORD_ID.fullmatch(value) is None:
            raise ValueError("invalid action record ID")
        return value

    @field_validator("record_sha256")
    @classmethod
    def hash_is_exact(cls, value: str) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError("invalid action record hash")
        return value

    @field_validator("observed_at")
    @classmethod
    def timestamp_is_exact(cls, value: str) -> str:
        if not _timestamp_is_canonical(value):
            raise ValueError("invalid action observation timestamp")
        return value

    @model_validator(mode="after")
    def identity_binds_hash(self) -> IntentActionStatusV1:
        if self.record_id != "ar_" + self.record_sha256[:32]:
            raise ValueError("action status record ID does not bind its hash")
        return self


class ActuatorIntentStatusV1(_FrozenModel):
    schema_version: Literal["agmind.actuator-intent-status.v1"]
    intent_id: str
    intent_sha256: str
    state: str
    prepared_plan: PreparedTemporaryEgressDenyPlanV1 | None = None
    latest_action: IntentActionStatusV1 | None = None

    @field_validator("intent_id")
    @classmethod
    def intent_is_exact(cls, value: str) -> str:
        if _INTENT_ID.fullmatch(value) is None:
            raise ValueError("invalid intent ID")
        return value

    @field_validator("intent_sha256")
    @classmethod
    def hash_is_exact(cls, value: str) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError("invalid intent hash")
        return value

    @field_validator("state")
    @classmethod
    def state_is_exact(cls, value: str) -> str:
        if value not in _STATUS_STATES:
            raise ValueError("invalid intent state")
        return value

    @model_validator(mode="after")
    def fields_bind_state(self) -> ActuatorIntentStatusV1:
        if self.state == "RESERVED":
            if self.prepared_plan is not None or self.latest_action is not None:
                raise ValueError("RESERVED status cannot contain a plan or action")
            if "prepared_plan" in self.model_fields_set or "latest_action" in self.model_fields_set:
                raise ValueError("absent RESERVED fields must be omitted")
            return self
        if (
            self.prepared_plan is None
            or self.latest_action is None
            or self.prepared_plan.intent_id != self.intent_id
            or actuator_intent_sha256(self.prepared_plan) != self.intent_sha256
            or self.latest_action.state != self.state
        ):
            raise ValueError("intent status does not bind its plan and latest action")
        if (
            self.state == "PREPARED"
            and self.latest_action.observed_at != self.prepared_plan.prepared_at
        ):
            raise ValueError("PREPARED status action is inconsistent")
        return self


class _JournalSnapshotWire(_FrozenModel):
    record_count: int = Field(ge=0, le=_MAX_JOURNAL_RECORDS)
    verified_bytes: int = Field(ge=0, le=_MAX_JOURNAL_BYTES)
    head_sha256: str

    @field_validator("head_sha256")
    @classmethod
    def head_is_exact(cls, value: str) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError("invalid journal snapshot head")
        return value


class _JournalRecordWire(_FrozenModel):
    index: int = Field(ge=1, le=_MAX_JOURNAL_RECORDS)
    offset: int = Field(ge=0, le=_MAX_JOURNAL_BYTES)
    size: int = Field(ge=_FRAME_OVERHEAD, le=_MAX_FRAME_PAYLOAD + _FRAME_OVERHEAD)
    payload_length: int = Field(ge=0, le=_MAX_FRAME_PAYLOAD)
    previous_frame_sha256: str
    frame_sha256: str
    payload_base64: str = Field(max_length=90_000)

    @field_validator("previous_frame_sha256", "frame_sha256")
    @classmethod
    def hash_is_exact(cls, value: str) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError("invalid journal frame hash")
        return value


class _JournalPageWire(_FrozenModel):
    schema_version: Literal["agmind.actuator-journal-page.v1"]
    snapshot: _JournalSnapshotWire
    after: int = Field(ge=0, le=_MAX_JOURNAL_RECORDS)
    records: list[_JournalRecordWire] = Field(max_length=100)
    next_after: int = Field(ge=0, le=_MAX_JOURNAL_RECORDS)
    more: bool


@dataclass(frozen=True, slots=True)
class ActuatorJournalSnapshot:
    record_count: int
    verified_bytes: int
    head_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedActuatorJournalRecord:
    index: int
    offset: int
    size: int
    payload_length: int
    previous_frame_sha256: str
    frame_sha256: str
    payload: bytes
    frame: bytes
    verified_payload: VerifiedActuatorPayload


@dataclass(frozen=True, slots=True)
class _VerifiedOuterRecord:
    index: int
    offset: int
    size: int
    payload_length: int
    previous_frame_sha256: str
    frame_sha256: str
    payload: bytes
    frame: bytes


@dataclass(frozen=True, slots=True)
class VerifiedActuatorJournalExtension:
    snapshot: ActuatorJournalSnapshot
    records: tuple[VerifiedActuatorJournalRecord, ...]
    intents: tuple[MirroredIntentState, ...]
    action_records: tuple[ActionRecordV1, ...]


def _new_http_client(transport: httpx.AsyncBaseTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=_ACTUATOR_BASE_URL,
        headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        timeout=httpx.Timeout(
            _REQUEST_TIMEOUT_SECONDS,
            connect=_CONNECT_TIMEOUT_SECONDS,
            read=_REQUEST_TIMEOUT_SECONDS,
            write=_REQUEST_TIMEOUT_SECONDS,
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
            raise ActuatorJournalFatal("actuator response exceeds its byte limit")
        return raw
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_raw():
        if type(chunk) is not bytes:
            raise ActuatorJournalFatal("actuator response yielded inexact bytes")
        total += len(chunk)
        if total > limit:
            raise ActuatorJournalFatal("actuator response exceeds its byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _declared_length(response: httpx.Response, limit: int) -> int | None:
    values = response.headers.get_list("content-length")
    if not values:
        return None
    if len(values) != 1:
        raise ActuatorJournalFatal("actuator returned duplicate Content-Length")
    value = values[0]
    if not value.isascii() or not value.isdecimal() or (len(value) > 1 and value.startswith("0")):
        raise ActuatorJournalFatal("actuator Content-Length is not canonical")
    length = int(value)
    if length > limit:
        raise ActuatorJournalFatal("actuator response exceeds its byte limit")
    return length


def _decode_canonical(raw: bytes, model: type[Any], limit: int) -> Any:
    try:
        decoded = decode_strict(raw, model, limit)
        if not hmac.compare_digest(canonical_json(decoded), raw):
            raise ValueError("response is not canonical")
        return decoded
    except (TypeError, UnicodeError, ValueError) as error:
        raise ActuatorJournalFatal("actuator response is not strict canonical JSON") from error


def _snapshot_from_wire(value: _JournalSnapshotWire) -> ActuatorJournalSnapshot:
    snapshot = ActuatorJournalSnapshot(
        value.record_count,
        value.verified_bytes,
        value.head_sha256,
    )
    minimum_bytes = snapshot.record_count * _FRAME_OVERHEAD
    empty = snapshot.record_count == 0
    if (
        snapshot.verified_bytes < minimum_bytes
        or empty != (snapshot.verified_bytes == 0)
        or empty != (snapshot.head_sha256 == "0" * 64)
    ):
        raise ActuatorJournalFatal("actuator journal snapshot bounds are inconsistent")
    return snapshot


def _decode_payload_base64(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ActuatorJournalFatal("actuator payload base64 is invalid") from error
    if base64.b64encode(raw).decode("ascii") != value:
        raise ActuatorJournalFatal("actuator payload base64 is not canonical RFC4648")
    return raw


def _decode_page(raw: bytes) -> tuple[_JournalPageWire, ActuatorJournalSnapshot]:
    page = _decode_canonical(raw, _JournalPageWire, _MAX_PAGE_BYTES)
    if type(page) is not _JournalPageWire:
        raise ActuatorJournalFatal("actuator journal page type is inexact")
    return page, _snapshot_from_wire(page.snapshot)


def _verify_outer_page(
    page: _JournalPageWire,
    *,
    pinned: ActuatorJournalSnapshot,
    expected_after: int,
    expected_offset: int,
    expected_previous: bytes,
    limit: int,
) -> tuple[tuple[_VerifiedOuterRecord, ...], int, bytes]:
    if (
        _snapshot_from_wire(page.snapshot) != pinned
        or page.after != expected_after
        or len(page.records) > limit
    ):
        raise ActuatorJournalConflict("actuator changed pinned snapshot metadata")
    verified: list[_VerifiedOuterRecord] = []
    offset = expected_offset
    previous = expected_previous
    for page_index, record in enumerate(page.records, start=1):
        payload = _decode_payload_base64(record.payload_base64)
        if (
            record.index != expected_after + page_index
            or record.offset != offset
            or record.payload_length != len(payload)
            or record.size != len(payload) + _FRAME_OVERHEAD
            or record.previous_frame_sha256 != previous.hex()
        ):
            raise ActuatorJournalFatal("actuator journal record metadata is invalid")
        frame = encode_frame(
            payload,
            previous_hash=previous,
            max_frame=_MAX_FRAME_PAYLOAD,
        )
        frame_sha256 = frame[-32:]
        if len(frame) != record.size or not hmac.compare_digest(
            frame_sha256.hex(), record.frame_sha256
        ):
            raise ActuatorJournalFatal("actuator AGF1 frame reconstruction differs")
        verified.append(
            _VerifiedOuterRecord(
                record.index,
                record.offset,
                record.size,
                record.payload_length,
                record.previous_frame_sha256,
                record.frame_sha256,
                payload,
                frame,
            )
        )
        previous = frame_sha256
        offset += len(frame)
    next_after = expected_after + len(page.records)
    if (
        page.next_after != next_after
        or page.next_after > pinned.record_count
        or page.more != (page.next_after < pinned.record_count)
        or (page.more and not page.records)
    ):
        raise ActuatorJournalFatal("actuator journal page continuation is invalid")
    return tuple(verified), offset, previous


def _with_inner(
    record: _VerifiedOuterRecord,
    projection: ActuatorRecordProjection,
) -> VerifiedActuatorJournalRecord:
    try:
        inner = projection.append(record.payload)
    except ActuatorRecordError as error:
        raise ActuatorJournalFatal("actuator signed journal payload is invalid") from error
    return VerifiedActuatorJournalRecord(
        record.index,
        record.offset,
        record.size,
        record.payload_length,
        record.previous_frame_sha256,
        record.frame_sha256,
        record.payload,
        record.frame,
        inner,
    )


@final
class ActuatorJournalClient:
    """Concurrency-one client for the actuator's read-only Core routes."""

    __slots__ = ("_client", "_closed", "_lock")

    def __init__(self, client: httpx.AsyncClient, *, _factory: object) -> None:
        if _factory not in {_CLIENT_FACTORY, _TEST_CLIENT_FACTORY}:
            raise TypeError("use ActuatorJournalClient.create()")
        if type(client) is not httpx.AsyncClient:
            raise TypeError("actuator journal HTTP client is inexact")
        self._client = client
        self._closed = False
        self._lock = asyncio.Lock()

    @classmethod
    def create(cls, socket_path: Path) -> ActuatorJournalClient:
        if (
            not isinstance(socket_path, Path)
            or not socket_path.is_absolute()
            or Path(os.path.normpath(socket_path)) != socket_path
            or "\x00" in str(socket_path)
        ):
            raise ActuatorJournalFatal("actuator socket path is invalid")
        transport = httpx.AsyncHTTPTransport(
            uds=str(socket_path),
            retries=0,
            limits=httpx.Limits(
                max_connections=1,
                max_keepalive_connections=1,
                keepalive_expiry=2.0,
            ),
        )
        return cls(_new_http_client(transport), _factory=_CLIENT_FACTORY)

    async def _get_locked(self, target: str, limit: int) -> bytes:
        try:
            async with self._client.stream("GET", target) as response:
                if response.headers.get_list("content-encoding"):
                    await _read_bounded(response, _MAX_ERROR_BYTES)
                    raise ActuatorJournalFatal("actuator response encoding is forbidden")
                declared = _declared_length(response, limit)
                if response.status_code != 200:
                    raw = await _read_bounded(response, _MAX_ERROR_BYTES)
                    if declared is not None and declared != len(raw):
                        raise ActuatorJournalFatal(
                            "actuator error Content-Length differs from response bytes"
                        )
                    if response.headers.get_list("content-type") != ["application/json"]:
                        raise ActuatorJournalFatal("actuator error Content-Type is not exact JSON")
                    if response.status_code == 404 and raw == b'{"error":"intent_not_found"}\n':
                        raise ActuatorIntentNotFound("actuator intent is absent")
                    if response.status_code == 409 and raw == b'{"error":"snapshot_mismatch"}\n':
                        raise ActuatorJournalConflict("actuator journal snapshot changed")
                    if (
                        response.status_code in {408, 425, 429}
                        or 500 <= response.status_code <= 599
                    ):
                        raise ActuatorJournalRetryable(
                            f"actuator journal GET returned {response.status_code}"
                        )
                    raise ActuatorJournalFatal(
                        f"actuator journal GET returned {response.status_code}"
                    )
                if response.headers.get_list("content-type") != ["application/json"]:
                    await _read_bounded(response, _MAX_ERROR_BYTES)
                    raise ActuatorJournalFatal("actuator response Content-Type is not exact JSON")
                raw = await _read_bounded(response, limit)
                if declared is not None and declared != len(raw):
                    raise ActuatorJournalFatal(
                        "actuator Content-Length differs from response bytes"
                    )
                return raw
        except ActuatorJournalError:
            raise
        except (httpx.HTTPError, OSError, TimeoutError) as error:
            raise ActuatorJournalRetryable("actuator journal GET failed ambiguously") from error

    async def get_intent_status(self, intent_id: str) -> ActuatorIntentStatusV1:
        if type(intent_id) is not str or _INTENT_ID.fullmatch(intent_id) is None:
            raise ActuatorJournalFatal("intent ID is invalid")
        try:
            async with asyncio.timeout(_REQUEST_TIMEOUT_SECONDS):
                async with self._lock:
                    if self._closed:
                        raise ActuatorJournalFatal("actuator journal client is closed")
                    raw = await self._get_locked(f"/v1/intents/{intent_id}", _MAX_STATUS_BYTES)
        except ActuatorJournalError:
            raise
        except TimeoutError as error:
            raise ActuatorJournalRetryable("actuator status deadline expired") from error
        decoded = _decode_canonical(raw, ActuatorIntentStatusV1, _MAX_STATUS_BYTES)
        if type(decoded) is not ActuatorIntentStatusV1:
            raise ActuatorJournalFatal("actuator intent status type is inexact")
        return decoded

    async def fetch_verified_extension(
        self,
        projection: ActuatorRecordProjection,
        local: ActuatorJournalSnapshot,
        *,
        local_first: VerifiedActuatorJournalRecord | None,
        local_last: VerifiedActuatorJournalRecord | None,
        page_limit: int = 100,
    ) -> VerifiedActuatorJournalExtension:
        if (
            type(projection) is not ActuatorRecordProjection
            or type(local) is not ActuatorJournalSnapshot
            or type(page_limit) is not int
            or not 1 <= page_limit <= 100
        ):
            raise ActuatorJournalFatal("actuator extension inputs are invalid")
        empty = local.record_count == 0
        if (
            empty != (local_first is None)
            or empty != (local_last is None)
            or empty != (local.verified_bytes == 0)
            or empty != (local.head_sha256 == "0" * 64)
        ):
            raise ActuatorJournalFatal("local actuator cursor is inconsistent")
        if not empty:
            assert local_first is not None and local_last is not None
            if (
                local_first.index != 1
                or local_first.offset != 0
                or local_first.previous_frame_sha256 != "0" * 64
                or local_last.index != local.record_count
                or local_last.offset + local_last.size != local.verified_bytes
                or local_last.frame_sha256 != local.head_sha256
                or projection.previous_record_sha256 != local_last.verified_payload.record_sha256
            ):
                raise ActuatorJournalFatal("local actuator boundary is inconsistent")
        try:
            async with asyncio.timeout(_SNAPSHOT_TIMEOUT_SECONDS):
                async with self._lock:
                    if self._closed:
                        raise ActuatorJournalFatal("actuator journal client is closed")
                    return await self._fetch_extension_locked(
                        projection,
                        local,
                        local_first,
                        local_last,
                        page_limit,
                    )
        except ActuatorJournalError:
            raise
        except TimeoutError as error:
            raise ActuatorJournalRetryable("actuator snapshot deadline expired") from error

    async def _fetch_extension_locked(
        self,
        projection: ActuatorRecordProjection,
        local: ActuatorJournalSnapshot,
        local_first: VerifiedActuatorJournalRecord | None,
        local_last: VerifiedActuatorJournalRecord | None,
        page_limit: int,
    ) -> VerifiedActuatorJournalExtension:
        raw = await self._get_locked("/v1/journal-records?after=0&limit=1", _MAX_PAGE_BYTES)
        first_page, pinned = _decode_page(raw)
        first_outer, first_offset, first_previous = _verify_outer_page(
            first_page,
            pinned=pinned,
            expected_after=0,
            expected_offset=0,
            expected_previous=bytes(32),
            limit=1,
        )
        if pinned.record_count < local.record_count:
            raise ActuatorJournalConflict("actuator journal is shorter than durable mirror")
        if pinned.record_count > 0 and len(first_outer) != 1:
            raise ActuatorJournalFatal("actuator initial page omitted its first record")
        if local.record_count > 0:
            assert local_first is not None
            if not hmac.compare_digest(first_outer[0].frame, local_first.frame):
                raise ActuatorJournalConflict("actuator journal first frame changed")
        if pinned.record_count == local.record_count:
            if (
                pinned.verified_bytes != local.verified_bytes
                or pinned.head_sha256 != local.head_sha256
            ):
                raise ActuatorJournalConflict("actuator journal head conflicts with mirror")
            return VerifiedActuatorJournalExtension(
                pinned,
                (),
                (),
                (),
            )

        extension: list[VerifiedActuatorJournalRecord] = []
        if local.record_count == 0:
            extension.append(_with_inner(first_outer[0], projection))
            expected_after = 1
            expected_offset = first_offset
            expected_previous = first_previous
        else:
            assert local_last is not None
            if local.record_count == 1:
                boundary = first_outer[0]
            else:
                boundary_after = local.record_count - 1
                target = (
                    f"/v1/journal-records?after={boundary_after}&limit=1"
                    f"&snapshot_records={pinned.record_count}"
                    f"&snapshot_bytes={pinned.verified_bytes}"
                    f"&snapshot_head={pinned.head_sha256}"
                )
                boundary_raw = await self._get_locked(target, _MAX_PAGE_BYTES)
                boundary_page, boundary_snapshot = _decode_page(boundary_raw)
                if boundary_snapshot != pinned:
                    raise ActuatorJournalConflict("actuator boundary snapshot changed")
                boundary_records, _, _ = _verify_outer_page(
                    boundary_page,
                    pinned=pinned,
                    expected_after=boundary_after,
                    expected_offset=local_last.offset,
                    expected_previous=bytes.fromhex(local_last.previous_frame_sha256),
                    limit=1,
                )
                if len(boundary_records) != 1:
                    raise ActuatorJournalFatal("actuator boundary page is incomplete")
                boundary = boundary_records[0]
            if not hmac.compare_digest(boundary.frame, local_last.frame):
                raise ActuatorJournalConflict("actuator journal boundary frame changed")
            expected_after = local.record_count
            expected_offset = local.verified_bytes
            expected_previous = bytes.fromhex(local.head_sha256)

        while expected_after < pinned.record_count:
            target = (
                f"/v1/journal-records?after={expected_after}&limit={page_limit}"
                f"&snapshot_records={pinned.record_count}"
                f"&snapshot_bytes={pinned.verified_bytes}"
                f"&snapshot_head={pinned.head_sha256}"
            )
            page_raw = await self._get_locked(target, _MAX_PAGE_BYTES)
            page, page_snapshot = _decode_page(page_raw)
            if page_snapshot != pinned:
                raise ActuatorJournalConflict("actuator suffix snapshot changed")
            outer, expected_offset, expected_previous = _verify_outer_page(
                page,
                pinned=pinned,
                expected_after=expected_after,
                expected_offset=expected_offset,
                expected_previous=expected_previous,
                limit=page_limit,
            )
            if not outer:
                raise ActuatorJournalFatal("actuator suffix page made no progress")
            extension.extend(_with_inner(record, projection) for record in outer)
            expected_after += len(outer)
        if (
            expected_after != pinned.record_count
            or expected_offset != pinned.verified_bytes
            or expected_previous.hex() != pinned.head_sha256
        ):
            raise ActuatorJournalFatal("actuator suffix does not reach its pinned snapshot")
        return VerifiedActuatorJournalExtension(
            pinned,
            tuple(extension),
            projection.intents(),
            projection.action_records(),
        )

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                await self._client.aclose()
            except httpx.HTTPError as error:
                raise ActuatorJournalRetryable("actuator journal client close failed") from error


def _actuator_journal_client_for_test(
    transport: httpx.AsyncBaseTransport,
) -> ActuatorJournalClient:
    if not isinstance(transport, httpx.AsyncBaseTransport):
        raise TypeError("test actuator transport is invalid")
    return ActuatorJournalClient(
        _new_http_client(transport),
        _factory=_TEST_CLIENT_FACTORY,
    )


__all__ = [
    "ActuatorIntentNotFound",
    "ActuatorIntentStatusV1",
    "ActuatorJournalClient",
    "ActuatorJournalConflict",
    "ActuatorJournalError",
    "ActuatorJournalFatal",
    "ActuatorJournalRetryable",
    "ActuatorJournalSnapshot",
    "IntentActionStatusV1",
    "VerifiedActuatorJournalExtension",
    "VerifiedActuatorJournalRecord",
]
