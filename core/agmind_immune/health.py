"""Tiny bounded HTTP liveness endpoint; no management API lives here."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

_MAX_REQUEST_BYTES = 4_096
_MAX_CONNECTIONS = 32
_BODY = b'{"live":true,"version":"0.1.0"}'
_READY_BODY = b'{"ready":true,"version":"0.1.0"}'
_NOT_READY_BODY = b'{"ready":false,"version":"0.1.0"}'


class HealthServer:
    def __init__(self, readiness: Callable[[], bool]) -> None:
        if not callable(readiness):
            raise TypeError("health readiness provider must be callable")
        self._readiness = readiness
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self, host: str, port: int) -> None:
        if self._server is not None or host != "0.0.0.0" or port != 8787:
            raise ValueError("health listener requires the fixed container endpoint")
        self._server = await asyncio.start_server(
            self._handle,
            host=host,
            port=port,
            limit=_MAX_REQUEST_BYTES,
            backlog=32,
            start_serving=True,
        )

    @staticmethod
    def _response(status: bytes, body: bytes) -> bytes:
        return b"".join(
            (
                b"HTTP/1.1 ",
                status,
                b"\r\nContent-Type: application/json\r\nContent-Length: ",
                str(len(body)).encode("ascii"),
                b"\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                body,
            )
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
            writer.write(
                self._response(b"503 Service Unavailable", b'{"live":false}')
            )
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
                response = self._response(b"400 Bad Request", b'{"live":false}')
            else:
                lines = raw[:-4].split(b"\r\n")
                headers = lines[1:]
                invalid = (
                    not lines
                    or len(raw) > _MAX_REQUEST_BYTES
                    or len(headers) > 32
                    or any(
                        not line
                        or b":" not in line
                        or b"\x00" in line
                        or any(byte < 0x20 or byte > 0x7E for byte in line)
                        for line in headers
                    )
                    or any(
                        line.lower().startswith(b"content-length:")
                        and line.lower() != b"content-length: 0"
                        for line in headers
                    )
                    or any(
                        line.lower().startswith(b"transfer-encoding:")
                        for line in headers
                    )
                )
                if invalid:
                    response = self._response(
                        b"400 Bad Request",
                        b'{"live":false}',
                    )
                elif lines[0] == b"GET /health HTTP/1.1":
                    response = self._response(b"200 OK", _BODY)
                elif lines[0] == b"GET /ready HTTP/1.1":
                    try:
                        ready = self._readiness() is True
                    except Exception:  # noqa: BLE001 - readiness is fail-closed
                        ready = False
                    response = self._response(
                        b"200 OK" if ready else b"503 Service Unavailable",
                        _READY_BODY if ready else _NOT_READY_BODY,
                    )
                elif lines[0].startswith(b"GET "):
                    response = self._response(b"404 Not Found", b'{"error":"not_found"}')
                else:
                    response = self._response(
                        b"405 Method Not Allowed",
                        b'{"error":"method_not_allowed"}',
                    )
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


__all__ = ["HealthServer"]
