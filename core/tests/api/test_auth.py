from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest


@pytest.mark.asyncio
async def test_protected_route_requires_exact_fresh_bearer_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert importlib.util.find_spec("agmind_immune.api") is not None
    assert importlib.util.find_spec("agmind_immune.api.server") is not None
    from agmind_immune.api import server as api_server

    monkeypatch.setattr(api_server, "_ROOT_UID", os.geteuid())
    token_file = tmp_path / "core-api.token"
    first_token = b"first_token_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    second_token = b"second_token_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    token_file.write_bytes(first_token + b"\n")
    token_file.chmod(0o640)

    class Provider:
        def __init__(self) -> None:
            self.targets: list[str] = []

        async def get(self, target: str) -> api_server.ManagementResponse:
            self.targets.append(target)
            return api_server.ManagementResponse(200, b'{"scope":"protected"}')

    provider = Provider()
    boundary = api_server.ManagementServer(
        readiness=lambda: True,
        token_file=token_file,
        provider=provider,
    )

    async def request(target: str, authorization: bytes | None = None) -> bytes:
        headers = [b"Host: core"]
        if authorization is not None:
            headers.append(b"Authorization: " + authorization)
        raw = b"GET " + target.encode() + b" HTTP/1.1\r\n" + b"\r\n".join(headers)
        return await boundary._dispatch(raw + b"\r\n\r\n")

    health = await request("/health")
    assert health.startswith(b"HTTP/1.1 200 OK\r\n")
    assert health.endswith(b'{"live":true}')
    assert provider.targets == []

    missing = await request("/v1/status")
    wrong = await request("/v1/status", b"Bearer wrong")
    accepted = await request("/v1/status", b"Bearer " + first_token)
    assert missing.startswith(b"HTTP/1.1 401 Unauthorized\r\n")
    assert wrong.startswith(b"HTTP/1.1 401 Unauthorized\r\n")
    assert accepted.endswith(b'{"scope":"protected"}')
    assert provider.targets == ["/v1/status"]

    token_file.write_bytes(second_token + b"\n")
    stale = await request("/v1/status", b"Bearer " + first_token)
    rotated = await request("/v1/status", b"Bearer " + second_token)
    assert stale.startswith(b"HTTP/1.1 401 Unauthorized\r\n")
    assert rotated.startswith(b"HTTP/1.1 200 OK\r\n")
    assert provider.targets == ["/v1/status", "/v1/status"]
