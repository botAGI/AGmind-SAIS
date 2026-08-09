from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest
from agmind_immune.canonicaljson import canonical_json, plan_hash, plan_id
from agmind_immune.contracts import (
    PreparedTemporaryEgressDenyPlanV1,
    TemporaryEgressDenyIntentV1,
    decode_strict,
)
from agmind_immune.incidents.admission import CandidateAdmissionView
from tests.admission_helpers import build_admission_runtime
from tests.test_controller_policy_commit import _manual_evaluation


def _plan_for(
    intent: TemporaryEgressDenyIntentV1,
    *,
    ttl_seconds: int | None = None,
) -> PreparedTemporaryEgressDenyPlanV1:
    prepared = datetime.fromisoformat(intent.created_at)
    nonce = "ab" * 32
    document = intent.model_dump(mode="python")
    document.update(
        {
            "schema_version": "agmind.prepared-temporary-egress-deny-plan.v1",
            "ttl_seconds": intent.ttl_seconds if ttl_seconds is None else ttl_seconds,
            "plan_id": plan_id(intent.intent_id, bytes.fromhex(nonce)),
            "boot_id": "123e4567-e89b-42d3-a456-426614174000",
            "init_pid": 4242,
            "pid_start_ticks": 77,
            "cgroup_path_sha256": "1" * 64,
            "network_namespace_inode": 9001,
            "docker_network_snapshot_sha256": "2" * 64,
            "special_use_registry_sha256": "3" * 64,
            "management_denylist_sha256": "4" * 64,
            "hard_limits_version": "pcc-hard-limits-v1",
            "prepared_at": prepared.isoformat(timespec="seconds").replace(
                "+00:00",
                "Z",
            ),
            "approval_expires_at": (prepared + timedelta(minutes=5))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "nonce": nonce,
        }
    )
    document["plan_hash"] = plan_hash(document)
    return PreparedTemporaryEgressDenyPlanV1.model_validate(document, strict=True)


@pytest.mark.asyncio
async def test_delivery_is_bounded_crash_idempotent_and_conflict_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agmind_immune.actions import (
        IntentDeliveryFatal,
        IntentDeliveryRetryable,
        QuarantinedIntentReceipt,
    )
    from agmind_immune.actions.client import _actuator_intent_client_for_test
    from agmind_immune.actions.state_machine import (
        _intent_delivery_state_machine_for_test,
    )

    runtime = build_admission_runtime(tmp_path / "runtime", monkeypatch)
    client = None
    machines = []
    try:
        view = await runtime.controller.issue_candidate_admission(runtime.candidate.candidate_id)
        assert type(view) is CandidateAdmissionView
        commit = await runtime.controller.commit_policy_evaluation(
            view,
            await _manual_evaluation(view),
        )
        assert commit.intent_canonical is not None
        intent = decode_strict(
            commit.intent_canonical,
            TemporaryEgressDenyIntentV1,
            65_536,
        )
        plan = _plan_for(intent)
        mismatched_plan = _plan_for(intent, ttl_seconds=30)

        behavior = {"value": "retry"}
        requests: list[bytes] = []

        async def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request.content)
            assert request.method == "POST"
            assert str(request.url) == "http://actuator/v1/intents"
            assert request.headers.get_list("content-type") == ["application/json"]
            assert request.headers.get_list("accept") == ["application/json"]
            assert request.headers.get_list("accept-encoding") == ["identity"]
            if behavior["value"] == "retry":
                return httpx.Response(
                    503,
                    headers={"Content-Type": "application/json"},
                    content=b'{"error":"actuator_unavailable"}',
                )
            if behavior["value"] == "redirect":
                return httpx.Response(307, headers={"Location": "http://elsewhere/"})
            if behavior["value"] == "mismatch":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    content=canonical_json(mismatched_plan),
                )
            if behavior["value"] == "terminal":
                return httpx.Response(
                    409,
                    headers={"Content-Type": "application/json"},
                    content=b'{"error":"target_stale"}\n',
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=canonical_json(plan),
            )

        client = _actuator_intent_client_for_test(httpx.MockTransport(respond))
        with pytest.raises(IntentDeliveryFatal):
            await client.prepare(b" " + commit.intent_canonical)
        assert requests == []
        with pytest.raises(IntentDeliveryRetryable):
            await client.prepare(commit.intent_canonical)
        behavior["value"] = "redirect"
        with pytest.raises(IntentDeliveryFatal):
            await client.prepare(commit.intent_canonical)
        behavior["value"] = "mismatch"
        with pytest.raises(IntentDeliveryFatal):
            await client.prepare(commit.intent_canonical)
        assert len(requests) == 3

        terminal_root = tmp_path / "terminal-delivery"
        terminal_root.mkdir(mode=0o700)
        os.chmod(terminal_root, 0o700)
        terminal_database = terminal_root / "intent-delivery.sqlite3"
        behavior["value"] = "terminal"
        terminal = _intent_delivery_state_machine_for_test(
            terminal_database,
            client,
        )
        machines.append(terminal)
        terminal_before = len(requests)
        quarantine = await terminal.deliver(commit)
        assert type(quarantine) is QuarantinedIntentReceipt
        assert quarantine.reason_code == "target_stale"
        assert len(requests) == terminal_before + 1
        await terminal.close()
        machines.remove(terminal)
        terminal = _intent_delivery_state_machine_for_test(
            terminal_database,
            client,
        )
        machines.append(terminal)
        assert await terminal.deliver(commit) == quarantine
        assert len(requests) == terminal_before + 1
        await terminal.close()
        machines.remove(terminal)

        empty_root = tmp_path / "existing-empty-delivery"
        empty_root.mkdir(mode=0o700)
        os.chmod(empty_root, 0o700)
        empty_database = empty_root / "intent-delivery.sqlite3"
        empty_database.touch(mode=0o600)
        with pytest.raises(IntentDeliveryFatal):
            _intent_delivery_state_machine_for_test(empty_database, client)
        assert empty_database.stat().st_size == 0

        partial_root = tmp_path / "existing-partial-delivery"
        partial_root.mkdir(mode=0o700)
        os.chmod(partial_root, 0o700)
        partial_database = partial_root / "intent-delivery.sqlite3"
        initialized = _intent_delivery_state_machine_for_test(partial_database, client)
        await initialized.close()
        connection = sqlite3.connect(partial_database)
        try:
            connection.execute("DELETE FROM delivery_metadata WHERE key='read_only'")
            connection.commit()
        finally:
            connection.close()
        with pytest.raises(IntentDeliveryFatal):
            _intent_delivery_state_machine_for_test(partial_database, client)
        connection = sqlite3.connect(partial_database)
        try:
            assert dict(connection.execute("SELECT key,value FROM delivery_metadata")) == {
                "schema_version": "agmind.intent-delivery-state.v2"
            }
        finally:
            connection.close()

        state_root = tmp_path / "delivery"
        state_root.mkdir(mode=0o700)
        os.chmod(state_root, 0o700)
        database = state_root / "intent-delivery.sqlite3"

        class SimulatedCrash(BaseException):
            pass

        def crash_after_prepare() -> None:
            raise SimulatedCrash

        behavior["value"] = "success"
        crashing = _intent_delivery_state_machine_for_test(
            database,
            client,
            after_prepare=crash_after_prepare,
        )
        machines.append(crashing)
        before_crash = len(requests)
        with pytest.raises(SimulatedCrash):
            await crashing.deliver(commit)
        assert len(requests) == before_crash + 1
        await crashing.close()
        machines.remove(crashing)

        recovered = _intent_delivery_state_machine_for_test(database, client)
        machines.append(recovered)
        delivered = await recovered.deliver(commit)
        assert canonical_json(delivered) == canonical_json(plan)
        assert len(requests) == before_crash + 2
        await recovered.close()
        machines.remove(recovered)

        restarted = _intent_delivery_state_machine_for_test(database, client)
        machines.append(restarted)
        from_receipt = await restarted.deliver(commit)
        assert canonical_json(from_receipt) == canonical_json(plan)
        assert len(requests) == before_crash + 2
        await restarted.close()
        machines.remove(restarted)

        changed_decision_hash = "f" * 64
        connection = sqlite3.connect(database)
        try:
            intent_sha256 = connection.execute(
                "SELECT intent_sha256 FROM prepared_plan_receipts"
            ).fetchone()[0]
            changed_receipt = {
                "schema_version": "agmind.prepared-plan-receipt.v1",
                "candidate_id": commit.candidate_id,
                "decision_record_sha256": changed_decision_hash,
                "intent_id": intent.intent_id,
                "intent_sha256": intent_sha256,
                "intent": intent,
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "plan": plan,
            }
            receipt_sha256 = hashlib.sha256(
                b"AGMIND_PREPARED_PLAN_RECEIPT_V1\0" + canonical_json(changed_receipt)
            ).hexdigest()
            connection.execute(
                "UPDATE prepared_plan_receipts SET decision_record_sha256=?,receipt_sha256=?",
                (changed_decision_hash, receipt_sha256),
            )
            connection.commit()
        finally:
            connection.close()

        conflicted = _intent_delivery_state_machine_for_test(database, client)
        machines.append(conflicted)
        assert conflicted.read_only is False
        with pytest.raises(IntentDeliveryFatal):
            await conflicted.deliver(commit)
        assert conflicted.read_only is True
        await conflicted.close()
        machines.remove(conflicted)

        connection = sqlite3.connect(database)
        try:
            connection.execute("UPDATE delivery_metadata SET value='0' WHERE key='read_only'")
            connection.commit()
        finally:
            connection.close()

        latch_fallback = _intent_delivery_state_machine_for_test(database, client)
        machines.append(latch_fallback)
        blocker = sqlite3.connect(database, isolation_level=None, timeout=0.0)
        try:
            blocker.execute("BEGIN EXCLUSIVE")
            with pytest.raises(IntentDeliveryFatal):
                await latch_fallback.deliver(commit)
            assert latch_fallback.read_only is True
        finally:
            blocker.execute("ROLLBACK")
            blocker.close()
        await latch_fallback.close()
        machines.remove(latch_fallback)

        marker_fenced = _intent_delivery_state_machine_for_test(database, client)
        machines.append(marker_fenced)
        assert marker_fenced.read_only is True
        with pytest.raises(IntentDeliveryFatal):
            await marker_fenced.deliver(commit)
        assert len(requests) == before_crash + 2
        await marker_fenced.close()
        machines.remove(marker_fenced)

        (state_root / "intent-delivery.read-only").unlink()
        connection = sqlite3.connect(database)
        try:
            connection.execute("UPDATE delivery_metadata SET value='0' WHERE key='read_only'")
            connection.execute(
                "UPDATE prepared_plan_receipts SET receipt_sha256=?",
                ("e" * 64,),
            )
            connection.commit()
        finally:
            connection.close()

        semantic_fence = _intent_delivery_state_machine_for_test(database, client)
        machines.append(semantic_fence)
        assert semantic_fence.read_only is True
        with pytest.raises(IntentDeliveryFatal):
            await semantic_fence.deliver(commit)
        assert len(requests) == before_crash + 2
    finally:
        for machine in reversed(machines):
            await machine.close()
        if client is not None:
            await client.close()
        await runtime.close()
