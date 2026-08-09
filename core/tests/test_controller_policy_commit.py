from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.clock import CoreClockSample
from agmind_immune.contracts import TemporaryEgressDenyIntentV1, decode_strict
from agmind_immune.incidents.admission import (
    CandidateAdmissionError,
    CandidateAdmissionView,
)
from agmind_immune.policy import (
    PolicyDecisionV1,
    PolicyEvaluation,
)
from agmind_immune.policy.client import _policy_client_for_test
from agmind_immune.policy.models import _policy_decision_sha256

from tests.admission_helpers import AdmissionClock, build_admission_runtime
from tests.phase5b_helpers import NOW

_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _ROOT / "policies/pcc.rego"


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


async def _manual_evaluation(view: CandidateAdmissionView) -> PolicyEvaluation:
    async def respond(request: httpx.Request) -> httpx.Response:
        document = json.loads(request.content)
        policy_input = document["input"]
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=canonical_json({"result": _manual_result(policy_input)}),
        )

    client = _policy_client_for_test(
        clock=AdmissionClock(),
        transport=httpx.MockTransport(respond),
        policy_path=_POLICY_PATH,
    )
    try:
        return await client.evaluate(view)
    finally:
        await client.close()


def _deny_evaluation(manual: PolicyEvaluation) -> PolicyEvaluation:
    policy_input = manual.policy_input
    decision = PolicyDecisionV1.model_validate(
        {
            "schema_version": "agmind.policy-decision.v1",
            "effect": "deny",
            "reason_codes": ["policy_default_deny"],
            "max_ttl_seconds": 0,
            "allowed_evidence_ids": [],
            "candidate_id": policy_input.candidate_id,
            "candidate_facts_sha256": policy_input.candidate_facts_sha256,
            "policy_input_sha256": policy_input.policy_input_sha256,
            "policy_bundle_version": policy_input.policy_bundle_version,
            "policy_bundle_sha256": policy_input.policy_bundle_sha256,
        },
        strict=True,
    )
    return PolicyEvaluation.model_validate(
        {
            "policy_input": policy_input,
            "decision": decision,
            "candidate_id": manual.candidate_id,
            "candidate_facts_sha256": manual.candidate_facts_sha256,
            "policy_input_sha256": manual.policy_input_sha256,
            "policy_decision_sha256": _policy_decision_sha256(decision),
            "policy_bundle": manual.policy_bundle,
            "evaluated_at": manual.evaluated_at,
            "evidence_age_ms": manual.evidence_age_ms,
        },
        strict=True,
    )


class _LaterClock:
    def __init__(self, store: Any) -> None:
        self._store = store
        self.calls = 0

    def live_receipt_monotonic(self) -> float | None:
        return None

    def decision_sample(self) -> CoreClockSample:
        assert self._store._source_terminal_token is None
        self.calls += 1
        return CoreClockSample(
            decision_utc=datetime.fromisoformat(NOW).astimezone(UTC)
            + timedelta(seconds=1),
            decision_monotonic=102.0,
            healthy=True,
            uncertainty_seconds=Decimal("0.1"),
            max_uncertainty_seconds=Decimal(1),
        )


@pytest.mark.asyncio
async def test_policy_commit_revalidates_burns_and_serializes_same_admission_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agmind_immune.actions import DecisionIntentCommit

    runtime = build_admission_runtime(tmp_path / "runtime", monkeypatch)
    try:
        view = await runtime.controller.issue_candidate_admission(
            runtime.candidate.candidate_id
        )
        evaluation = await _manual_evaluation(view)

        committed = await runtime.controller.commit_policy_evaluation(
            view,
            evaluation,
        )

        assert type(committed) is DecisionIntentCommit
        assert committed.candidate_id == runtime.candidate.candidate_id
        assert committed.effect == "manual_approval_required"
        assert committed.intent_id is not None
        assert committed.intent_canonical is not None
        assert committed.record_sha256 == hashlib.sha256(
            b"AGMIND_DECISION_INTENT_RECORD_V1\0"
            + canonical_json(
                {
                    key: value
                    for key, value in json.loads(
                        committed.record_canonical
                    ).items()
                    if key != "record_sha256"
                }
            )
        ).hexdigest()
        intent = decode_strict(
            committed.intent_canonical,
            TemporaryEgressDenyIntentV1,
            65_536,
        )
        assert intent.intent_id == committed.intent_id
        assert intent.host_id == runtime.candidate.host_id
        assert intent.docker_container_id == runtime.candidate.docker_container_id
        assert intent.destination_ipv4 == runtime.candidate.destination_ipv4
        assert intent.ttl_seconds == evaluation.decision.max_ttl_seconds
        assert tuple(intent.evidence_ids) == runtime.candidate.evidence_ids
        assert intent.created_at == NOW
        assert len(runtime.controller._decision_intents.records()) == 1

        with pytest.raises(CandidateAdmissionError):
            await runtime.controller.consume_candidate_admission(view)
        with pytest.raises(CandidateAdmissionError):
            await runtime.controller.commit_policy_evaluation(view, evaluation)
        assert len(runtime.controller._decision_intents.records()) == 1
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_manual_commit_recomputes_age_and_cannot_widen_or_inject_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = build_admission_runtime(tmp_path / "runtime", monkeypatch)
    try:
        view = await runtime.controller.issue_candidate_admission(
            runtime.candidate.candidate_id
        )
        evaluation = await _manual_evaluation(view)
        commit_clock = _LaterClock(runtime.store)
        runtime.controller._clock = commit_clock
        committed = await runtime.controller.commit_policy_evaluation(
            view,
            evaluation,
        )
        assert commit_clock.calls == 1
        record = json.loads(committed.record_canonical)
        assert evaluation.evidence_age_ms == 100
        assert record["fresh_evidence_age_ms"] == 1_100
        assert record["committed_at"] == (
            datetime.fromisoformat(NOW).astimezone(UTC) + timedelta(seconds=1)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")

        def widen_ttl(value: PolicyEvaluation) -> PolicyEvaluation:
            return value.model_copy(
                update={
                    "decision": value.decision.model_copy(
                        update={"max_ttl_seconds": 121}
                    )
                }
            )

        def drop_evidence(value: PolicyEvaluation) -> PolicyEvaluation:
            return value.model_copy(
                update={
                    "decision": value.decision.model_copy(
                        update={
                            "allowed_evidence_ids": value.decision.allowed_evidence_ids[
                                :1
                            ]
                        }
                    )
                }
            )

        def inject_intent(value: PolicyEvaluation) -> PolicyEvaluation:
            return value.model_copy(update={"intent": {"command": "nft flush ruleset"}})

        mutations: tuple[
            Callable[[PolicyEvaluation], PolicyEvaluation],
            ...,
        ] = (widen_ttl, drop_evidence, inject_intent)
        for mutate in mutations:
            next_view = await runtime.controller.issue_candidate_admission(
                runtime.candidate.candidate_id
            )
            next_evaluation = await _manual_evaluation(next_view)
            with pytest.raises(CandidateAdmissionError):
                await runtime.controller.commit_policy_evaluation(
                    next_view,
                    mutate(next_evaluation),
                )
            with pytest.raises(CandidateAdmissionError):
                await runtime.controller.consume_candidate_admission(next_view)
            assert len(runtime.controller._decision_intents.records()) == 1
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_deny_has_no_intent_and_manual_decision_plus_intent_are_one_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manual_runtime = build_admission_runtime(tmp_path / "manual", monkeypatch)
    try:
        manual_view = await manual_runtime.controller.issue_candidate_admission(
            manual_runtime.candidate.candidate_id
        )
        manual_evaluation = await _manual_evaluation(manual_view)
        manual_commit = await manual_runtime.controller.commit_policy_evaluation(
            manual_view,
            manual_evaluation,
        )
        manual_record = json.loads(manual_commit.record_canonical)
        assert manual_record["policy_decision"]["effect"] == (
            "manual_approval_required"
        )
        assert manual_record["intent"]["intent_id"] == manual_commit.intent_id
        assert len(manual_runtime.controller._decision_intents.records()) == 1
    finally:
        await manual_runtime.close()

    deny_runtime = build_admission_runtime(tmp_path / "deny", monkeypatch)
    try:
        deny_view = await deny_runtime.controller.issue_candidate_admission(
            deny_runtime.candidate.candidate_id
        )
        deny_evaluation = _deny_evaluation(await _manual_evaluation(deny_view))
        deny_commit = await deny_runtime.controller.commit_policy_evaluation(
            deny_view,
            deny_evaluation,
        )
        deny_record = json.loads(deny_commit.record_canonical)
        assert deny_commit.effect == "deny"
        assert deny_commit.intent_id is None
        assert deny_commit.intent_canonical is None
        assert "intent" not in deny_record
        assert deny_record["policy_decision"]["effect"] == "deny"
        assert len(deny_runtime.controller._decision_intents.records()) == 1
    finally:
        await deny_runtime.close()
