from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path

import httpx
import pytest
from agmind_immune.canonicaljson import action_id, canonical_json
from agmind_immune.contracts import (
    PreparedTemporaryEgressDenyPlanV1,
    TemporaryEgressDenyIntentV1,
    decode_strict,
)
from agmind_immune.evidence.frames import encode_frame, iter_frames
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.incidents.admission import CandidateAdmissionView
from agmind_immune.ingest.envelope import EnvelopeVerifier
from agmind_immune.ingest.service import AcceptanceCoordinator
from agmind_immune.policy import PolicyEvaluation
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.admission_helpers import build_admission_runtime
from tests.ingest.test_pcc_correlation_snapshot import _identity
from tests.phase5b_helpers import private_key
from tests.test_controller_policy_commit import _manual_evaluation

_MAX_FRAME_PAYLOAD = 131_072


def _frame_count(path: Path) -> int:
    with path.open("rb") as stream:
        return sum(1 for _frame in iter_frames(stream, max_frame=_MAX_FRAME_PAYLOAD))


# fmt: off
def _actuator_signed(document: dict[str, object], key: Ed25519PrivateKey) -> bytes:
    domain, signing, identity, prefix = {
        "agmind.intent-rate-reservation.v1": (b"AGMIND_RATE_RESERVATION_HASH_V1\0", b"AGMIND_RATE_RESERVATION_V1\0", "reservation_id", "rr_"),
        "agmind.action-record.v1": (b"AGMIND_ACTION_RECORD_HASH_V1\0", b"AGMIND_ACTION_RECORD_V1\0", "record_id", "ar_"),
        "agmind.apply-attempt.v1": (b"AGMIND_APPLY_ATTEMPT_HASH_V1\0", b"AGMIND_APPLY_ATTEMPT_V1\0", "attempt_id", "aa_"),
    }[str(document["schema_version"])]
    hashed = {
        name: value
        for name, value in document.items()
        if name not in {identity, "record_sha256", "actuator_signature"}
    }
    digest = hashlib.sha256(domain + canonical_json(hashed)).hexdigest()
    document |= {identity: prefix + digest[:32], "record_sha256": digest}
    signed = {name: value for name, value in document.items() if name != "actuator_signature"}
    document["actuator_signature"] = key.sign(signing + canonical_json(signed)).hex()
    return canonical_json(document)


def _actuator_payloads(key: Ed25519PrivateKey, reserved_at: str) -> tuple[bytes, ...]:
    fixtures = Path("contracts/fixtures/v1")
    intent = decode_strict((fixtures / "intent.valid.json").read_bytes(), TemporaryEgressDenyIntentV1, 65_536)
    plan = decode_strict((fixtures / "plan.valid.json").read_bytes(), PreparedTemporaryEgressDenyPlanV1, 65_536)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(public).hexdigest()[:32]
    intent_sha = hashlib.sha256(b"AGMIND_ACTUATOR_INTENT_V1\0" + canonical_json(intent)).hexdigest()
    reservation = _actuator_signed(
        {
            "schema_version": "agmind.intent-rate-reservation.v1",
            "intent_id": intent.intent_id, "intent_sha256": intent_sha, "reserved_at": reserved_at,
            "previous_record_sha256": "0" * 64,
            "actuator_key_id": key_id,
        }, key,
    )
    previous = json.loads(reservation)["record_sha256"]
    common = {"action_id": action_id(plan.plan_hash), "plan_id": plan.plan_id,
              "plan_hash": plan.plan_hash, "actuator_key_id": key_id}
    prepared = _actuator_signed(
        {
            "schema_version": "agmind.action-record.v1",
            **common, "state": "PREPARED", "reason_code": "intent_prepared", "observed_at": plan.prepared_at,
            "previous_record_sha256": previous,
            "details": {
                "approval_deadline_boottime_ns": 500_000_000_000,
                "intent_sha256": intent_sha, "prepared_plan": plan.model_dump(mode="python"),
            },
        }, key,
    )
    previous = json.loads(prepared)["record_sha256"]
    approved = _actuator_signed(
        {
            "schema_version": "agmind.action-record.v1",
            **common, "state": "APPROVED", "reason_code": "local_admin_approved",
            "observed_at": "2026-07-27T12:00:03Z",
            "previous_record_sha256": previous,
            "details": {
                "previous_action_record_sha256": previous,
                "decision_boot_id": plan.boot_id, "decision_boottime_ns": 250_000_000_000,
                "admin_uid": 1000, "admin_gid": 1000,
                "authorization_basis": "primary_group", "decision_basis": "local_admin_approval",
            },
        }, key,
    )
    previous = json.loads(approved)["record_sha256"]
    attempt = _actuator_signed(
        {
            "schema_version": "agmind.apply-attempt.v1",
            "plan_id": plan.plan_id, "plan_hash": plan.plan_hash, "started_at": "2026-07-27T12:00:04Z",
            "boot_id": plan.boot_id, "boottime_ns": 260_000_000_000,
            "target_netns_inode": plan.network_namespace_inode, "destination_ipv4": plan.destination_ipv4,
            "ttl_seconds": plan.ttl_seconds,
            "expected_ruleset_sha256": "4" * 64,
            "previous_action_record_sha256": previous, "previous_record_sha256": previous,
            "actuator_key_id": key_id,
        }, key,
    )
    return reservation, prepared, approved, attempt


def _actuator_page(payloads: tuple[bytes, ...], after: int, limit: int) -> tuple[bytes, bytes]:
    frames: list[bytes] = []
    records: list[dict[str, object]] = []
    previous, offset = bytes(32), 0
    for index, payload in enumerate(payloads, 1):
        frame = encode_frame(payload, previous_hash=previous, max_frame=65_536)
        records.append(
            {
                "index": index, "offset": offset, "size": len(frame), "payload_length": len(payload),
                "previous_frame_sha256": previous.hex(), "frame_sha256": frame[-32:].hex(),
                "payload_base64": base64.b64encode(payload).decode("ascii"),
            }
        )
        frames.append(frame)
        previous, offset = frame[-32:], offset + len(frame)
    selected = records[after : after + limit]
    next_after = after + len(selected)
    page = {
        "schema_version": "agmind.actuator-journal-page.v1",
        "snapshot": {"record_count": len(records), "verified_bytes": offset, "head_sha256": previous.hex()},
        "after": after, "records": selected, "next_after": next_after,
        "more": next_after < len(records),
    }
    return canonical_json(page), b"".join(frames)
# fmt: on


@pytest.mark.asyncio
async def test_commit_crash_edges_recover_exactly_once_before_any_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agmind_immune.actions.journal import (
        _JOURNAL_COMMIT_FACTORY,
        DecisionIntentJournal,
    )
    from agmind_immune.actions.models import _decode_decision_intent_record

    runtime = build_admission_runtime(tmp_path / "runtime", monkeypatch)
    recovered: DecisionIntentJournal | None = None
    restarted_store: SegmentStore | None = None
    runtime_closed = False
    try:
        view = await runtime.controller.issue_candidate_admission(runtime.candidate.candidate_id)
        assert type(view) is CandidateAdmissionView
        evaluation = await _manual_evaluation(view)
        assert type(evaluation) is PolicyEvaluation
        committed = await runtime.controller.commit_policy_evaluation(
            view,
            evaluation,
        )
        path = runtime.store.root / "decision-intents.agf"
        committed_size = path.stat().st_size
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert _frame_count(path) == 1

        await runtime.close()
        runtime_closed = True
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
        try:
            os.write(descriptor, b"AGF")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        assert path.stat().st_size == committed_size + 3

        root, chain = _identity(private_key(11))
        restarted_store = SegmentStore(runtime.store.root)
        AcceptanceCoordinator.open_and_recover(
            EnvelopeVerifier(root, chain),
            restarted_store,
        )
        recovered = DecisionIntentJournal.open(restarted_store)
        assert path.stat().st_size == committed_size
        records = recovered.records()
        assert len(records) == 1
        assert records[0] == committed
        assert _frame_count(path) == 1

        exact_record = _decode_decision_intent_record(committed.record_canonical)
        duplicate = recovered._commit(
            exact_record,
            _factory=_JOURNAL_COMMIT_FACTORY,
        )
        assert duplicate == committed
        assert len(recovered.records()) == 1
        assert _frame_count(path) == 1
        assert json.loads(records[0].record_canonical)["intent"]["intent_id"] == (
            committed.intent_id
        )
    finally:
        if recovered is not None:
            recovered.close()
        if restarted_store is not None:
            restarted_store.close()
        if not runtime_closed:
            await runtime.close()


@pytest.mark.asyncio
async def test_actuator_mirror_extends_once_and_fails_closed_on_conflicting_prefix(
    tmp_path: Path,
) -> None:
    from agmind_immune.actions.actuator_mirror import (
        ActuatorMirrorConflict,
        _actuator_mirror_for_test,
    )
    from agmind_immune.actions.actuator_protocol import _actuator_journal_client_for_test

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    payloads = _actuator_payloads(key, "2026-07-27T12:00:01Z")
    conflict = (_actuator_payloads(key, "2026-07-27T12:00:00Z")[0],)
    _, expected_frames = _actuator_page(payloads, 0, 2)
    conflict_mode = False

    async def respond(request: httpx.Request) -> httpx.Response:
        active = conflict if conflict_mode else payloads
        assert request.method == "GET"
        assert request.headers.get_list("accept-encoding") == ["identity"]
        after = int(request.url.params["after"])
        limit = int(request.url.params["limit"])
        if after:
            first_page, _ = _actuator_page(active, 0, 2)
            snapshot = json.loads(first_page)["snapshot"]
            assert request.url.params["snapshot_records"] == str(snapshot["record_count"])
            assert request.url.params["snapshot_bytes"] == str(snapshot["verified_bytes"])
            assert request.url.params["snapshot_head"] == snapshot["head_sha256"]
        page, _ = _actuator_page(active, after, limit)
        return httpx.Response(200, headers={"Content-Type": "application/json"}, content=page)

    client = _actuator_journal_client_for_test(httpx.MockTransport(respond))
    root = tmp_path / "mirror"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    path = root / "actuator-actions.agf"
    mirror = _actuator_mirror_for_test(path, public, client)
    try:
        snapshot = await mirror.sync_once(page_limit=2)
        assert (snapshot.record_count, path.read_bytes()) == (4, expected_frames)
        assert mirror.latest_for_intent(json.loads(payloads[0])["intent_id"]).state == "APPROVED"
        assert await mirror.sync_once(page_limit=2) == snapshot

        conflict_mode = True
        with pytest.raises(ActuatorMirrorConflict):
            await mirror.sync_once(page_limit=2)
        assert mirror.read_only
        assert mirror.fatal_error == "actuator journal prefix conflicts with durable mirror"
        assert path.read_bytes() == expected_frames
    finally:
        mirror.close()
        await client.close()
