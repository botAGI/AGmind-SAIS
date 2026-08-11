from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path

import agmind_immune.hunter as hunter_module
import httpx
import pytest
from agmind_immune.canonicaljson import canonical_json, incident_id
from agmind_immune.contracts import HunterOutputV1
from agmind_immune.hunter import (
    HUNTER_SYSTEM_V1,
    HunterClient,
    HunterConfigV1,
    HunterEvidenceFactV1,
    HunterResult,
    build_hunter_bundle,
)
from agmind_immune.hunter.client import _hunter_client_for_test
from agmind_immune.incidents.models import IncidentV1
from agmind_immune.runtime import CoreRuntime
from pydantic import ValidationError

PRIMARY_EVENT_ID = "evt_" + "1" * 64
AUTHORITY_EVENT_ID = "evt_" + "2" * 64


def _incident() -> IncidentV1:
    return IncidentV1(
        schema_version="agmind.incident.v1",
        incident_id=incident_id(PRIMARY_EVENT_ID),
        primary_event_id=PRIMARY_EVENT_ID,
        primary_source_sequence=7,
        host_id="12345678-1234-4123-8123-123456789abc",
        boot_id="abcdefab-cdef-4abc-8def-abcdefabcdef",
        detector_rule="AGmind PCC Suspicious Process Outbound Connect",
        detector_rule_version="agmind-pcc-rules-v1",
        event_time="2026-07-27T11:00:00Z",
        ingest_time="2026-07-27T11:00:01Z",
        successful_connect=True,
        investigation_only=False,
        docker_container_id="3" * 64,
        docker_started_at="2026-07-27T10:59:00Z",
        proc_name="curl",
        proc_exe_path="/SECRET_ENV_CANARY/usr/bin/curl",
        proc_parent_name="sh",
        destination_ipv4="1.1.1.1",
        destination_port=443,
        l4_protocol="tcp",
        missing_required_fields=(),
        coverage_flags=(),
        evidence_ids=(PRIMARY_EVENT_ID, AUTHORITY_EVENT_ID),
        reason_codes=(),
        authority_event_id=AUTHORITY_EVENT_ID,
    )


def _fact(evidence_id: str = PRIMARY_EVENT_ID) -> HunterEvidenceFactV1:
    return HunterEvidenceFactV1(
        evidence_id=evidence_id,
        detector_rule="AGmind PCC Suspicious Process Outbound Connect",
        detector_rule_version="agmind-pcc-rules-v1",
        event_time="2026-07-27T11:00:00Z",
        proc_name="curl",
        proc_exe_basename="curl",
        proc_parent_basename="sh",
        destination_ipv4="1.1.1.1",
        destination_port=443,
        l4_protocol="tcp",
        image_id="sha256:" + "4" * 64,
        coverage_flags=(),
    )


def _config() -> HunterConfigV1:
    return HunterConfigV1(
        schema_version="agmind.hunter-config.v1",
        base_url="http://127.0.0.1:8000/v1",
        model="deepseek-v4-flash",
        api_token_file="/run/secrets/hunter-api-token",
        max_input_bytes=32_768,
        max_output_bytes=16_384,
        max_output_tokens=2_048,
        queue_size=32,
        queue_ttl_seconds=60,
        connect_timeout_seconds=3,
        read_timeout_seconds=45,
    )


def _completion(content: str) -> bytes:
    return json.dumps(
        {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 1,
            "model": "deepseek-v4-flash",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


def test_bundle_is_bounded_allowlisted_and_deterministic() -> None:
    incident = _incident()
    fact = _fact()

    first = build_hunter_bundle(incident, (fact,))
    second = build_hunter_bundle(incident, (fact,))
    raw = canonical_json(first)

    assert raw == canonical_json(second)
    assert len(raw) <= 32_768
    assert first.evidence == (fact,)
    assert first.omitted_evidence_ids == ()
    assert set(first.model_dump()["evidence"][0]) == {
        "evidence_id",
        "detector_rule",
        "detector_rule_version",
        "event_time",
        "proc_name",
        "proc_exe_basename",
        "proc_parent_basename",
        "destination_ipv4",
        "destination_port",
        "l4_protocol",
        "image_id",
        "coverage_flags",
    }
    for forbidden in (
        b"SECRET_ENV_CANARY",
        b"DOCKER_SOCKET",
        b"approval_nonce",
        b"plan_hash",
        b"/proc/",
        b"nftables",
    ):
        assert forbidden not in raw

    with pytest.raises(ValidationError):
        HunterEvidenceFactV1.model_validate(
            {**fact.model_dump(), "command_args": "SECRET_ENV_CANARY"},
            strict=True,
        )
    with pytest.raises(ValueError, match="incident evidence"):
        build_hunter_bundle(incident, (_fact("evt_" + "9" * 64),))


@pytest.mark.asyncio
async def test_client_returns_only_strict_evidence_bound_annotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = build_hunter_bundle(_incident(), (_fact(),))
    valid_output = json.dumps(
        {
            "schema_version": "agmind.hunter-output.v1",
            "hypotheses": ["Unexpected public egress"],
            "supporting_evidence_ids": [PRIMARY_EVENT_ID],
            "refuting_questions": ["Is this destination approved?"],
            "narrative": "Bounded read-only investigation.",
            "limitations": ["No authority to act"],
        },
        separators=(",", ":"),
    )
    hostile_outputs = {
        "action_field": valid_output[:-1] + ',"action":"block 1.1.1.1"}',
        "foreign_evidence": valid_output.replace(PRIMARY_EVENT_ID, "evt_" + "9" * 64),
        "trailing_json": valid_output + "{}",
        "duplicate_key": valid_output.replace(
            '"schema_version":"agmind.hunter-output.v1"',
            '"schema_version":"agmind.hunter-output.v1",'
            '"schema_version":"agmind.hunter-output.v1"',
        ),
        "terminal_escape": valid_output.replace(
            "Bounded read-only investigation.",
            "\\u001b[31mhostile",
        ),
        "bidi_override": valid_output.replace(
            "Bounded read-only investigation.",
            "hostile\\u202etxt",
        ),
    }

    async def run_case(
        response_factory: Callable[[httpx.Request], httpx.Response],
    ) -> tuple[HunterResult, dict[str, object]]:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return response_factory(request)

        client: HunterClient = _hunter_client_for_test(
            config=_config(),
            transport=httpx.MockTransport(handler),
            api_token="TEST_ONLY_TOKEN",
        )
        try:
            return await client.investigate(bundle), captured
        finally:
            await client.close()

    result, request = await run_case(
        lambda call: httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=_completion(valid_output),
            request=call,
        )
    )
    assert result.status == "available"
    assert result.output is not None
    assert result.output.supporting_evidence_ids == [PRIMARY_EVENT_ID]
    assert request["model"] == "deepseek-v4-flash"
    assert request["temperature"] == 0
    assert request["max_tokens"] == 2_048
    assert request["stream"] is False
    assert request["tools"] is None
    assert request["messages"] == [
        {"role": "system", "content": HUNTER_SYSTEM_V1},
        {
            "role": "user",
            "content": (
                "UNTRUSTED_EVIDENCE_BEGIN\n"
                + canonical_json(bundle).decode()
                + "\nUNTRUSTED_EVIDENCE_END"
            ),
        },
    ]

    for hostile in hostile_outputs.values():
        rejected, _ = await run_case(
            lambda call, body=hostile: httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=_completion(body),
                request=call,
            )
        )
        assert rejected.status == "invalid"
        assert rejected.output is None

    oversized, _ = await run_case(
        lambda call: httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=b"{" + b"x" * 16_384 + b"}",
            request=call,
        )
    )
    assert oversized.status == "invalid"
    assert oversized.output is None

    redirected, _ = await run_case(
        lambda call: httpx.Response(
            302,
            headers={"Location": "http://attacker.invalid/v1"},
            request=call,
        )
    )
    assert redirected.status == "invalid"
    assert redirected.output is None

    cookie_headers: list[str | None] = []

    def cookie_handler(request: httpx.Request) -> httpx.Response:
        cookie_headers.append(request.headers.get("cookie"))
        return httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "Set-Cookie": "model_memory=hostile; Path=/",
            },
            content=_completion(valid_output),
            request=request,
        )

    cookie_client = _hunter_client_for_test(
        config=_config(),
        transport=httpx.MockTransport(cookie_handler),
        api_token="TEST_ONLY_TOKEN",
    )
    try:
        first_cookie = await cookie_client.investigate(bundle)
        second_cookie = await cookie_client.investigate(bundle)
    finally:
        await cookie_client.close()
    assert first_cookie.status == "invalid"
    assert second_cookie.status == "invalid"
    assert cookie_headers == [None, None]

    cancellation_calls = 0

    async def cancellation_handler(request: httpx.Request) -> httpx.Response:
        nonlocal cancellation_calls
        cancellation_calls += 1
        if cancellation_calls == 1:
            await asyncio.Future()
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=_completion(valid_output),
            request=request,
        )

    cancellation_client = _hunter_client_for_test(
        config=_config(),
        transport=httpx.MockTransport(cancellation_handler),
        api_token="TEST_ONLY_TOKEN",
    )
    await cancellation_client._semaphore.acquire()
    cancelled = asyncio.create_task(cancellation_client.investigate(bundle))
    await asyncio.sleep(0)
    await cancellation_client._queue_lock.acquire()
    cancellation_client._semaphore.release()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    cancelled.cancel()
    cancellation_client._queue_lock.release()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    try:
        async with asyncio.timeout(1):
            after_cancel = await cancellation_client.investigate(bundle)
    finally:
        await cancellation_client.close()
    assert after_cancel.status == "available"

    loop = asyncio.get_running_loop()
    breaker_now = [loop.time()]
    breaker_calls = 0
    breaker_body = [hostile_outputs["action_field"]]

    def breaker_handler(request: httpx.Request) -> httpx.Response:
        nonlocal breaker_calls
        breaker_calls += 1
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=_completion(breaker_body[0]),
            request=request,
        )

    breaker_client = _hunter_client_for_test(
        config=_config(),
        transport=httpx.MockTransport(breaker_handler),
        api_token="TEST_ONLY_TOKEN",
    )
    try:
        with monkeypatch.context() as patch:
            patch.setattr(loop, "time", lambda: breaker_now[0])
            for _ in range(3):
                failure = await breaker_client.investigate(bundle)
                assert failure.status == "invalid"
            blocked = await breaker_client.investigate(bundle)
            assert blocked.status == "unavailable"
            assert blocked.reason_code == "circuit_open"
            assert breaker_calls == 3

            breaker_now[0] += 61
            breaker_body[0] = valid_output
            recovered = await breaker_client.investigate(bundle)
            assert recovered.status == "available"
            assert breaker_calls == 4

            breaker_body[0] = hostile_outputs["action_field"]
            after_recovery = await breaker_client.investigate(bundle)
            assert after_recovery.status == "invalid"
            assert breaker_calls == 5
    finally:
        await breaker_client.close()


@pytest.mark.asyncio
async def test_terminal_hunter_result_is_durably_bound_to_candidate(
    tmp_path: Path,
) -> None:
    assert hasattr(hunter_module, "HunterInvestigationStore")
    store_type = hunter_module.HunterInvestigationStore
    state = tmp_path / "core"
    state.mkdir(mode=0o700)
    path = state / "hunter-investigations.sqlite3"
    store = store_type.open(path)
    candidate_id = "cand_" + "7" * 64
    output = HunterOutputV1(
        schema_version="agmind.hunter-output.v1",
        hypotheses=["Unexpected public egress"],
        supporting_evidence_ids=[PRIMARY_EVENT_ID],
        refuting_questions=["Is this destination approved?"],
        narrative="Bounded read-only investigation.",
        limitations=["No authority to act"],
    )
    available = HunterResult(
        status="available",
        output=output,
        bundle_sha256="a" * 64,
        reason_code="available",
    )

    runtime = object.__new__(CoreRuntime)
    runtime._hunter_tasks = {}
    runtime._hunter_scheduled = set()
    runtime._hunter_investigations = store
    runtime._last_hunter_status = None
    runtime._hunter_persistence_status = "ready"
    runtime._commits = {}

    class RecoveredCommit:
        candidate_id = "cand_" + "7" * 64
        effect = "deny"

    recovered_commit = RecoveredCommit()

    class RecoveredController:
        async def decision_intent_commits(self) -> tuple[RecoveredCommit, ...]:
            return (recovered_commit,)

        async def hunter_bundle(self, recovered_candidate_id: str) -> object:
            assert recovered_candidate_id == candidate_id
            return object()

    class RecoveredHunter:
        def __init__(self) -> None:
            self.calls = 0

        async def investigate(self, bundle: object) -> HunterResult:
            assert type(bundle) is object
            self.calls += 1
            return available

    recovered_hunter = RecoveredHunter()
    runtime._controller = RecoveredController()
    runtime._hunter = recovered_hunter

    async def complete(result: HunterResult) -> HunterResult:
        return result

    async def deliver(result: HunterResult) -> None:
        task = asyncio.create_task(complete(result))
        runtime._hunter_tasks[task] = candidate_id
        task.add_done_callback(runtime._hunter_done)
        await task
        await asyncio.sleep(0)

    await runtime._refresh_commits()
    recovered_tasks = tuple(runtime._hunter_tasks)
    assert len(recovered_tasks) == 1
    await asyncio.gather(*recovered_tasks)
    await asyncio.sleep(0)
    await runtime._refresh_commits()
    assert recovered_hunter.calls == 1
    first = store.get(candidate_id)
    assert first is not None
    assert first.bundle_sha256 == "a" * 64
    assert first.status == "available"
    assert first.reason_code == "available"
    assert first.output_canonical == canonical_json(output)
    assert store.page(after=None, limit=10) == (first,)
    assert runtime._hunter_persistence_status == "durable"

    await deliver(available)
    assert store.page(after=None, limit=10) == (first,)

    await deliver(
        HunterResult(
            status="unavailable",
            output=None,
            bundle_sha256="a" * 64,
            reason_code="transport_unavailable",
        )
    )
    assert runtime._last_hunter_status == "unavailable"
    assert runtime._hunter_persistence_status == "equivocation"
    assert store.get(candidate_id) == first
    store.close()

    reopened = store_type.open(path)
    try:
        assert reopened.get(candidate_id) == first
    finally:
        reopened.close()
