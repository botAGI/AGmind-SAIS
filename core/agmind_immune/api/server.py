"""Bounded HTTP/1.1 boundary for coarse health and protected read-only views."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

_LOG = logging.getLogger("agmind_immune.api")
_ROOT_UID = 0
_TOKEN_NAME = "core-api.token"
_TOKEN_MODES = frozenset({0o400, 0o440, 0o600, 0o640})
_MAX_TOKEN_BYTES = 4_096
_MAX_REQUEST_BYTES = 4_096
_MAX_RESPONSE_BYTES = 64 * 1_024
_MAX_HEADERS = 32
_MAX_CONNECTIONS = 32
_BURST = 20.0
_REFILL_PER_SECOND = 1.0
_TOKEN_CHARS = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_STATUS_LINES = {
    200: b"200 OK",
    400: b"400 Bad Request",
    401: b"401 Unauthorized",
    404: b"404 Not Found",
    405: b"405 Method Not Allowed",
    409: b"409 Conflict",
    429: b"429 Too Many Requests",
    500: b"500 Internal Server Error",
    503: b"503 Service Unavailable",
}
_LIVE = b'{"live":true}'
_READY = b'{"ready":true}'
_NOT_READY = b'{"ready":false}'


class _TokenUnavailable(RuntimeError):
    pass


class _RequestInvalid(ValueError):
    pass


def _reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(_: str) -> object:
    raise ValueError("non-finite JSON number")


def _validate_json_object(raw: bytes) -> None:
    try:
        decoded = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("management response must be strict JSON") from error
    if type(decoded) is not dict:
        raise ValueError("management response must be one JSON object")


@dataclass(frozen=True, slots=True)
class ManagementResponse:
    """One bounded JSON response from a protected read-only provider."""

    status_code: int
    body: bytes

    def __post_init__(self) -> None:
        if (
            type(self.status_code) is not int
            or self.status_code not in _STATUS_LINES
            or type(self.body) is not bytes
            or not 2 <= len(self.body) <= _MAX_RESPONSE_BYTES
        ):
            raise ValueError("management response is invalid")
        _validate_json_object(self.body)


class ProtectedRouteProvider(Protocol):
    """Runtime-independent adapter for future protected GET routes."""

    async def get(self, target: str) -> ManagementResponse: ...


@dataclass(frozen=True, slots=True)
class _Request:
    method: bytes
    target: str
    headers: dict[bytes, bytes]


def _parse_request(raw: bytes) -> _Request:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= _MAX_REQUEST_BYTES
        or not raw.endswith(b"\r\n\r\n")
        or raw.find(b"\r\n\r\n") != len(raw) - 4
    ):
        raise _RequestInvalid("request framing is invalid")
    lines = raw[:-4].split(b"\r\n")
    if not lines or len(lines) - 1 > _MAX_HEADERS:
        raise _RequestInvalid("request header count is invalid")
    parts = lines[0].split(b" ")
    if len(parts) != 3 or any(not part for part in parts) or parts[2] != b"HTTP/1.1":
        raise _RequestInvalid("request line is invalid")
    method, target_raw, _ = parts
    if (
        len(target_raw) > 2_048
        or not target_raw.startswith(b"/")
        or b"#" in target_raw
        or any(byte < 0x21 or byte > 0x7E for byte in target_raw)
    ):
        raise _RequestInvalid("request target is invalid")
    try:
        target = target_raw.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise _RequestInvalid("request target is not ASCII") from error

    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        if (
            not line
            or line[:1] in {b" ", b"\t"}
            or b":" not in line
            or any(byte < 0x20 or byte > 0x7E for byte in line)
        ):
            raise _RequestInvalid("request header is invalid")
        name, value = line.split(b":", 1)
        lowered = name.lower()
        if not name or any(byte not in _TOKEN_CHARS for byte in name) or lowered in headers:
            raise _RequestInvalid("request header name is invalid")
        if value.startswith(b" "):
            value = value[1:]
        if value.startswith(b" ") or value.endswith(b" "):
            raise _RequestInvalid("request header whitespace is invalid")
        headers[lowered] = value
    if not headers.get(b"host"):
        raise _RequestInvalid("HTTP/1.1 Host is required")
    if any(name in headers for name in (b"content-length", b"transfer-encoding", b"expect")):
        raise _RequestInvalid("request bodies are forbidden")
    return _Request(method=method, target=target, headers=headers)


def _read_token(path: Path) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise _TokenUnavailable("token loading requires O_NOFOLLOW")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != _ROOT_UID
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in _TOKEN_MODES
            or not 1 <= before.st_size <= _MAX_TOKEN_BYTES + 2
        ):
            raise _TokenUnavailable("API token file is unsafe")
        raw = os.read(descriptor, _MAX_TOKEN_BYTES + 3)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
        )
        if (
            len(raw) != before.st_size
            or stable_before != stable_after
            or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise _TokenUnavailable("API token changed while loading")
    except _TokenUnavailable:
        raise
    except OSError as error:
        raise _TokenUnavailable("API token is unavailable") from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as error:
                raise _TokenUnavailable("API token close failed") from error

    if raw.endswith(b"\n"):
        raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
    if not 1 <= len(raw) <= _MAX_TOKEN_BYTES or any(byte < 0x21 or byte > 0x7E for byte in raw):
        raise _TokenUnavailable("API token is not bounded printable ASCII")
    return raw


def _response(status_code: int, body: bytes) -> bytes:
    extra = b""
    if status_code == 401:
        extra = b'WWW-Authenticate: Bearer realm="agmind-core"\r\n'
    elif status_code == 405:
        extra = b"Allow: GET\r\n"
    elif status_code == 429:
        extra = b"Retry-After: 1\r\n"
    return b"".join(
        (
            b"HTTP/1.1 ",
            _STATUS_LINES[status_code],
            b"\r\nContent-Type: application/json\r\nContent-Length: ",
            str(len(body)).encode("ascii"),
            b"\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
            extra,
            b"Connection: close\r\n\r\n",
            body,
        )
    )


class ManagementServer:
    """Single-request connections with anonymous coarse health and protected GETs."""

    def __init__(
        self,
        *,
        readiness: Callable[[], bool],
        token_file: Path,
        provider: ProtectedRouteProvider,
    ) -> None:
        if (
            not callable(readiness)
            or not isinstance(token_file, Path)
            or not token_file.is_absolute()
            or Path(os.path.normpath(token_file)) != token_file
            or token_file.name != _TOKEN_NAME
            or not callable(getattr(provider, "get", None))
        ):
            raise TypeError("management server authorities are invalid")
        self._readiness = readiness
        self._token_file = token_file
        self._provider = provider
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._bucket_tokens = _BURST
        self._bucket_updated = time.monotonic()

    def _take_rate_token(self) -> bool:
        now = time.monotonic()
        elapsed = max(0.0, now - self._bucket_updated)
        self._bucket_updated = now
        self._bucket_tokens = min(
            _BURST,
            self._bucket_tokens + elapsed * _REFILL_PER_SECOND,
        )
        if self._bucket_tokens < 1.0:
            return False
        self._bucket_tokens -= 1.0
        return True

    async def _dispatch(self, raw: bytes) -> bytes:
        try:
            request = _parse_request(raw)
        except _RequestInvalid:
            return _response(400, b'{"error":"bad_request"}')

        if request.target in {"/health", "/ready"}:
            if request.method != b"GET":
                return _response(405, b'{"error":"method_not_allowed"}')
            if request.target == "/health":
                return _response(200, _LIVE)
            try:
                ready = self._readiness() is True
            except Exception:  # noqa: BLE001 - readiness is fail-closed
                ready = False
            return _response(200 if ready else 503, _READY if ready else _NOT_READY)

        protected = request.target == "/v1" or request.target.startswith("/v1/")
        if protected:
            try:
                token = _read_token(self._token_file)
            except _TokenUnavailable:
                return _response(503, b'{"error":"auth_unavailable"}')
            supplied = request.headers.get(b"authorization", b"")
            if not hmac.compare_digest(supplied, b"Bearer " + token):
                return _response(401, b'{"error":"unauthorized"}')
            if request.method != b"GET":
                return _response(405, b'{"error":"method_not_allowed"}')
            if not self._take_rate_token():
                return _response(429, b'{"error":"rate_limited"}')
            try:
                async with asyncio.timeout(2.0):
                    result = await self._provider.get(request.target)
                if type(result) is not ManagementResponse:
                    raise TypeError("protected provider returned an inexact response")
            except Exception:  # noqa: BLE001 - management reads fail closed
                _LOG.exception("protected management provider failed")
                return _response(503, b'{"error":"provider_unavailable"}')
            return _response(result.status_code, result.body)

        if request.method != b"GET":
            return _response(405, b'{"error":"method_not_allowed"}')
        return _response(404, b'{"error":"not_found"}')

    async def start(self, host: str, port: int) -> None:
        if self._server is not None or host != "0.0.0.0" or port != 8787:
            raise ValueError("management listener requires the fixed container endpoint")
        self._server = await asyncio.start_server(
            self._handle,
            host=host,
            port=port,
            limit=_MAX_REQUEST_BYTES,
            backlog=_MAX_CONNECTIONS,
            start_serving=True,
        )

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is None:
            writer.close()
            return
        if len(self._tasks) >= _MAX_CONNECTIONS:
            response = _response(503, b'{"error":"connection_limit"}')
            writer.write(response)
            try:
                await writer.drain()
            except (ConnectionError, OSError):
                pass
            writer.close()
            return
        self._tasks.add(task)
        self._writers.add(writer)
        try:
            try:
                async with asyncio.timeout(2.0):
                    raw = await reader.readuntil(b"\r\n\r\n")
            except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                response = _response(400, b'{"error":"bad_request"}')
            else:
                response = await self._dispatch(raw)
            writer.write(response)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            self._writers.discard(writer)
            self._tasks.discard(task)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def close(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()
        tasks = tuple(self._tasks)
        for writer in tuple(self._writers):
            writer.close()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


__all__ = ["ManagementResponse", "ManagementServer", "ProtectedRouteProvider"]
