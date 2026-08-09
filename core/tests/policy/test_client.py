from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.clock import CoreClockSample
from agmind_immune.incidents.models import ContainmentCandidateV1
from tests.admission_helpers import AdmissionClock, build_admission_runtime
from tests.phase5b_helpers import NOW

_ROOT = Path(__file__).resolve().parents[3]
_POLICY_PATH = _ROOT / "policies/pcc.rego"
_INPUT_HASH_DOMAIN = b"AGMIND_POLICY_INPUT_V1\0"
_DECISION_HASH_DOMAIN = b"AGMIND_POLICY_DECISION_V1\0"


def _request_input(request: httpx.Request) -> dict[str, Any]:
    assert request.method == "POST"
    assert str(request.url) == "http://opa:8181/v1/data/agmind/pcc/decision"
    assert request.headers["content-type"] == "application/json"
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    document = json.loads(request.content)
    assert type(document) is dict
    assert set(document) == {"input"}
    policy_input = document["input"]
    assert type(policy_input) is dict
    return policy_input


def _manual_result(policy_input: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "agmind.policy-decision.v1",
        "effect": "manual_approval_required",
        "reason_codes": ["manual_approval_required"],
        "max_ttl_seconds": min(policy_input["requested_ttl_seconds"], 120),
        "allowed_evidence_ids": policy_input["evidence_ids"],
        "candidate_id": policy_input["candidate_id"],
        "candidate_facts_sha256": policy_input["candidate_facts_sha256"],
        "policy_input_sha256": policy_input["policy_input_sha256"],
        "policy_bundle_version": policy_input["policy_bundle_version"],
        "policy_bundle_sha256": policy_input["policy_bundle_sha256"],
    }


def _client(clock: object, transport: httpx.AsyncBaseTransport) -> Any:
    client_module = importlib.import_module("agmind_immune.policy.client")
    return client_module._policy_client_for_test(
        clock=clock,
        transport=transport,
        policy_path=_POLICY_PATH,
    )


@pytest.mark.asyncio
async def test_candidate_bound_manual_only_policy_request_and_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = importlib.import_module("agmind_immune.policy")
    requests: list[httpx.Request] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        policy_input = _request_input(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=canonical_json({"result": _manual_result(policy_input)}),
        )

    runtime = build_admission_runtime(tmp_path / "runtime", monkeypatch)
    client = _client(AdmissionClock(), httpx.MockTransport(respond))
    try:
        view = await runtime.controller.issue_candidate_admission(
            runtime.candidate.candidate_id
        )
        assert type(view.candidate) is ContainmentCandidateV1
        evaluation = await client.evaluate(view)
        assert type(evaluation) is policy.PolicyEvaluation
        assert type(evaluation.decision) is policy.PolicyDecisionV1
        assert evaluation.decision.effect == "manual_approval_required"
        assert evaluation.decision.reason_codes == ("manual_approval_required",)
        assert evaluation.decision.max_ttl_seconds == min(
            runtime.candidate.ttl_seconds,
            120,
        )
        assert evaluation.decision.allowed_evidence_ids == (
            runtime.candidate.evidence_ids
        )
        assert evaluation.candidate_id == runtime.candidate.candidate_id
        assert evaluation.candidate_facts_sha256 == view.candidate_facts_sha256
        assert evaluation.policy_input_sha256 == (
            evaluation.policy_input.policy_input_sha256
        )
        assert evaluation.policy_bundle == policy.PolicyBundleIdentity(
            version="pcc-policy-v1",
            sha256=evaluation.policy_input.policy_bundle_sha256,
        )
        assert evaluation.evaluated_at == NOW
        assert evaluation.evidence_age_ms == 100
        assert len(requests) == 1
        assert requests[0].content == canonical_json(
            {"input": evaluation.policy_input}
        )

        input_document = evaluation.policy_input.model_dump(mode="python")
        claimed_input_hash = input_document.pop("policy_input_sha256")
        assert claimed_input_hash == hashlib.sha256(
            _INPUT_HASH_DOMAIN + canonical_json(input_document)
        ).hexdigest()
        assert evaluation.policy_decision_sha256 == hashlib.sha256(
            _DECISION_HASH_DOMAIN + canonical_json(evaluation.decision)
        ).hexdigest()
        assert not {
            "admission_rebuild_epoch",
            "authority_revision",
            "authority_snapshot_event_id",
            "command",
            "network_namespace_inode",
            "nonce",
            "plan_id",
            "projection_cursor",
            "terminal_ref",
        }.intersection(input_document)
        assert (
            await runtime.controller.consume_candidate_admission(view)
            == runtime.candidate
        )
    finally:
        await client.close()
        await runtime.close()


@pytest.mark.asyncio
async def test_policy_response_cannot_widen_replay_or_inject_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = importlib.import_module("agmind_immune.policy")

    def effect_allow(result: dict[str, Any]) -> None:
        result["effect"] = "allow"

    def widen_ttl(result: dict[str, Any]) -> None:
        result["max_ttl_seconds"] = 121

    def drop_proof(result: dict[str, Any]) -> None:
        result["allowed_evidence_ids"] = result["allowed_evidence_ids"][:1]

    def substitute_candidate(result: dict[str, Any]) -> None:
        result["candidate_id"] = "cand_" + "0" * 64

    def substitute_input(result: dict[str, Any]) -> None:
        result["policy_input_sha256"] = "0" * 64

    def inject_command(result: dict[str, Any]) -> None:
        result["command"] = "nft add rule"

    mutations: tuple[Callable[[dict[str, Any]], None], ...] = (
        effect_allow,
        widen_ttl,
        drop_proof,
        substitute_candidate,
        substitute_input,
        inject_command,
    )
    runtime = build_admission_runtime(tmp_path / "runtime", monkeypatch)
    try:
        for mutate in mutations:
            async def respond(
                request: httpx.Request,
                mutation: Callable[[dict[str, Any]], None] = mutate,
            ) -> httpx.Response:
                result = _manual_result(_request_input(request))
                mutation(result)
                return httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    content=canonical_json({"result": result}),
                )

            client = _client(AdmissionClock(), httpx.MockTransport(respond))
            try:
                view = await runtime.controller.issue_candidate_admission(
                    runtime.candidate.candidate_id
                )
                with pytest.raises(policy.PolicyResponseInvalid):
                    await client.evaluate(view)
                assert (
                    await runtime.controller.consume_candidate_admission(view)
                    == runtime.candidate
                )
            finally:
                await client.close()
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_policy_transport_and_wire_failures_do_not_consume_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = importlib.import_module("agmind_immune.policy")

    async def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("unavailable")

    async def server_error(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async def malformed(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b"{",
        )

    async def duplicate(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b'{"result":{},"result":{}}',
        )

    async def oversized(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b"x" * 65_537,
        )

    async def encoded(request: httpx.Request) -> httpx.Response:
        policy_input = _request_input(request)
        return httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-encoding": "identity",
            },
            content=canonical_json({"result": _manual_result(policy_input)}),
        )

    async def oversized_header(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "x-opa-padding": "x" * 4_097,
            },
            content=b"{}",
        )

    cases = (
        (timeout, policy.PolicyUnavailable),
        (server_error, policy.PolicyUnavailable),
        (malformed, policy.PolicyResponseInvalid),
        (duplicate, policy.PolicyResponseInvalid),
        (oversized, policy.PolicyResponseInvalid),
        (encoded, policy.PolicyResponseInvalid),
        (oversized_header, policy.PolicyResponseInvalid),
    )
    runtime = build_admission_runtime(tmp_path / "runtime", monkeypatch)
    try:
        for handler, error_type in cases:
            client = _client(AdmissionClock(), httpx.MockTransport(handler))
            try:
                view = await runtime.controller.issue_candidate_admission(
                    runtime.candidate.candidate_id
                )
                with pytest.raises(error_type):
                    await client.evaluate(view)
                assert (
                    await runtime.controller.consume_candidate_admission(view)
                    == runtime.candidate
                )
            finally:
                await client.close()

        exact_sample = AdmissionClock().decision_sample()

        class DerivedClockSample(CoreClockSample):
            pass

        class FixedClock:
            def __init__(self, sample: object) -> None:
                self.sample = sample

            def decision_sample(self) -> Any:
                return self.sample

        derived_sample = DerivedClockSample(
            decision_utc=exact_sample.decision_utc,
            decision_monotonic=exact_sample.decision_monotonic,
            healthy=exact_sample.healthy,
            uncertainty_seconds=exact_sample.uncertainty_seconds,
            max_uncertainty_seconds=exact_sample.max_uncertainty_seconds,
        )
        oversized_uncertainty = CoreClockSample(
            decision_utc=exact_sample.decision_utc,
            decision_monotonic=exact_sample.decision_monotonic,
            healthy=True,
            uncertainty_seconds=Decimal("1E+999999"),
            max_uncertainty_seconds=Decimal("1E+999999"),
        )

        invalid_clock_requests = 0

        async def unexpected_request(_request: httpx.Request) -> httpx.Response:
            nonlocal invalid_clock_requests
            invalid_clock_requests += 1
            raise AssertionError("invalid clock reached OPA")

        for unsafe_sample in (derived_sample, oversized_uncertainty):
            client = _client(
                FixedClock(unsafe_sample),
                httpx.MockTransport(unexpected_request),
            )
            try:
                view = await runtime.controller.issue_candidate_admission(
                    runtime.candidate.candidate_id
                )
                with pytest.raises(policy.PolicyUnavailable):
                    await client.evaluate(view)
                assert invalid_clock_requests == 0
                assert (
                    await runtime.controller.consume_candidate_admission(view)
                    == runtime.candidate
                )
            finally:
                await client.close()

        client = _client(
            AdmissionClock(),
            httpx.MockTransport(unexpected_request),
        )
        try:
            view = await runtime.controller.issue_candidate_admission(
                runtime.candidate.candidate_id
            )
            cursor = view.projection_cursor
            source_sequence = cursor.source_sequence
            object.__setattr__(cursor, "source_sequence", float(source_sequence))
            try:
                with pytest.raises(policy.PolicyError):
                    await client.evaluate(view)
            finally:
                object.__setattr__(cursor, "source_sequence", source_sequence)
            assert (
                await runtime.controller.consume_candidate_admission(view)
                == runtime.candidate
            )
        finally:
            await client.close()

        client_module = importlib.import_module("agmind_immune.policy.client")

        async def slow(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0.05)
            policy_input = _request_input(request)
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=canonical_json({"result": _manual_result(policy_input)}),
            )

        with monkeypatch.context() as scoped:
            scoped.setattr(client_module, "_TOTAL_TIMEOUT_SECONDS", 0.01)
            client = _client(AdmissionClock(), httpx.MockTransport(slow))
            try:
                view = await runtime.controller.issue_candidate_admission(
                    runtime.candidate.candidate_id
                )
                with pytest.raises(policy.PolicyUnavailable):
                    await client.evaluate(view)
                assert (
                    await runtime.controller.consume_candidate_admission(view)
                    == runtime.candidate
                )
            finally:
                await client.close()
    finally:
        await runtime.close()
