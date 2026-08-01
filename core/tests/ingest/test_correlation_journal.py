from __future__ import annotations

import hashlib
import io
import json
import os
from dataclasses import replace
from pathlib import Path

import agmind_immune.ingest.correlation_journal as correlation_module
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import PCCCorrelationSnapshotRequestV1
from agmind_immune.evidence.frames import encode_frame, iter_frames
from agmind_immune.evidence.segments import EvidenceCorrupt, EvidenceRef, SegmentStore
from agmind_immune.ingest.correlation_journal import (
    CorrelationRequestJournal,
    CorrelationRequestJournalAuthorityError,
    CorrelationRequestJournalCorrupt,
    CorrelationRequestJournalStateError,
    CorrelationRequestJournalUnhealthy,
)
from agmind_immune.ingest.envelope import EnvelopeVerifier
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.ingest.test_pcc_correlation_snapshot import (
    _accept,
    _candidate_trigger,
    _coordinator,
    _failed_snapshot,
    _identity,
    _item,
    _snapshot_envelope,
)
from tests.phase5b_helpers import boot_boundary, private_key


def seeded_correlation_store(
    path: Path,
) -> tuple[object, SegmentStore, EvidenceRef, dict[str, object]]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    trigger_ref = _accept(coordinator, trigger)
    assert isinstance(trigger_ref, EvidenceRef)
    return coordinator, coordinator.segment_store, trigger_ref, trigger


def read_correlation_frame_payloads(path: Path) -> tuple[bytes, ...]:
    with path.open("rb") as stream:
        return tuple(
            frame.payload
            for frame in iter_frames(stream, max_frame=64 * 1024)
        )


def _request(ref: EvidenceRef) -> PCCCorrelationSnapshotRequestV1:
    return PCCCorrelationSnapshotRequestV1.model_validate(
        {
            "schema_version": "agmind.pcc-correlation-snapshot-request.v1",
            "trigger_event_id": ref.event_id,
            "trigger_content_sha256": ref.content_sha256,
            "trigger_source_sequence": ref.source_sequence,
            "requested_ttl_seconds": 120,
        },
        strict=True,
    )


def _accept_snapshot(
    coordinator: object,
    trigger: dict[str, object],
    request: PCCCorrelationSnapshotRequestV1,
    *,
    sequence: int = 3,
) -> EvidenceRef:
    key = private_key(11)
    item = _item(
        _snapshot_envelope(
            key,
            _failed_snapshot(
                trigger,
                request,
                snapshot_sequence=sequence,
            ),
            sequence=sequence,
        )
    )
    ref = coordinator.accept_pcc(item, request)  # type: ignore[attr-defined]
    assert isinstance(ref, EvidenceRef)
    return ref


def _append_payload(path: Path, payload: bytes) -> None:
    existing = path.read_bytes()
    records = tuple(iter_frames(io.BytesIO(existing), max_frame=64 * 1024))
    previous = records[-1].record_hash if records else bytes(32)
    with path.open("ab") as stream:
        stream.write(
            encode_frame(
                payload,
                previous_hash=previous,
                max_frame=max(64 * 1024, len(payload)),
            )
        )


def _rewrite_payloads(path: Path, payloads: tuple[bytes, ...]) -> None:
    path.write_bytes(b"")
    for payload in payloads:
        _append_payload(path, payload)


def _reopen_correlation_store(path: Path) -> SegmentStore:
    root, chain = _identity(private_key(11))
    store = SegmentStore(path)
    AcceptanceCoordinator.open_and_recover(
        EnvelopeVerifier(root, chain),
        store,
    )
    return store


def test_correlation_journal_selected_record_has_exact_schema_and_ttl_120(
    tmp_path: Path,
) -> None:
    _coordinator_value, store, trigger_ref, _trigger = seeded_correlation_store(
        tmp_path
    )
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)

    selected = journal.select(trigger_ref, canonical_json(request))
    payload = json.loads(
        read_correlation_frame_payloads(
            tmp_path / "correlation-requests.agf"
        )[0]
    )

    assert selected.phase == "selected"
    assert set(payload) == {
        "operation_key",
        "phase",
        "request",
        "request_sha256",
        "schema_version",
    }
    assert payload["schema_version"] == "agmind.correlation-request-state.v1"
    assert payload["operation_key"] == f"pcc_correlation_snapshot:{trigger_ref.event_id}"
    assert payload["request"] == request.model_dump(mode="json")
    assert payload["request"]["requested_ttl_seconds"] == 120
    journal.close()
    store.close()


def test_correlation_journal_rederives_identical_canonical_request(
    tmp_path: Path,
) -> None:
    _coordinator_value, store, trigger_ref, _trigger = seeded_correlation_store(
        tmp_path
    )
    journal = CorrelationRequestJournal.create_new(store)
    request_raw = canonical_json(_request(trigger_ref))
    selected = journal.select(trigger_ref, request_raw)
    journal.close()

    recovered = CorrelationRequestJournal.open_and_recover(store)
    pending = recovered.pending()
    assert len(pending) == 1
    assert canonical_json(pending[0].request) == request_raw
    assert hashlib.sha256(request_raw).hexdigest() == selected.request_sha256
    value = pending[0].model_dump(mode="json", exclude_none=True)
    assert set(value) == {
        "schema_version",
        "operation_key",
        "request_sha256",
        "request",
        "phase",
    }
    assert set(value["request"]) == {
        "schema_version",
        "trigger_event_id",
        "trigger_content_sha256",
        "trigger_source_sequence",
        "requested_ttl_seconds",
    }
    assert not ({"request_bytes", "deadline", "selected_at"} & set(value))
    recovered.close()
    store.close()


def test_correlation_journal_allows_only_selected_proof_observed_completed(
    tmp_path: Path,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(tmp_path)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))
    with pytest.raises(CorrelationRequestJournalStateError):
        journal.mark_completed(selected.request_sha256)

    snapshot_ref = _accept_snapshot(coordinator, trigger, request)
    observed = journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    completed = journal.mark_completed(selected.request_sha256)

    assert (selected.phase, observed.phase, completed.phase) == (
        "selected",
        "proof_observed",
        "completed",
    )
    assert observed.snapshot_event_id == snapshot_ref.event_id
    assert observed.snapshot_content_sha256 == snapshot_ref.content_sha256
    assert journal.pending() == ()
    journal.close()
    store.close()


def test_correlation_journal_exact_phase_retries_are_idempotent(
    tmp_path: Path,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(tmp_path)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    request_raw = canonical_json(request)

    selected = journal.select(trigger_ref, request_raw)
    assert journal.select(trigger_ref, request_raw) == selected
    snapshot_ref = _accept_snapshot(coordinator, trigger, request)
    observed = journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    assert journal.mark_proof_observed(selected.request_sha256, snapshot_ref) == observed
    completed = journal.mark_completed(selected.request_sha256)
    assert journal.mark_completed(selected.request_sha256) == completed
    assert len(read_correlation_frame_payloads(tmp_path / "correlation-requests.agf")) == 3
    journal.close()
    store.close()


@pytest.mark.parametrize("conflict", ["request", "proof"])
def test_correlation_journal_rejects_conflicting_request_or_proof(
    tmp_path: Path,
    conflict: str,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(tmp_path)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))

    if conflict == "request":
        changed = request.model_copy(
            update={"trigger_content_sha256": "0" * 64}
        )
        with pytest.raises(CorrelationRequestJournalStateError):
            journal.select(trigger_ref, canonical_json(changed))
    else:
        first = _accept_snapshot(coordinator, trigger, request, sequence=3)
        journal.mark_proof_observed(selected.request_sha256, first)
        second = _accept_snapshot(coordinator, trigger, request, sequence=4)
        with pytest.raises(CorrelationRequestJournalStateError):
            journal.mark_proof_observed(selected.request_sha256, second)

    assert store.read_only_reason == "evidence_conflict"
    assert coordinator.verifier.fsm.mutation_read_only is True  # type: ignore[attr-defined]
    journal.close()
    store.close(flush=False)


def test_correlation_conflict_never_returns_state_error_without_durable_fence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(
        tmp_path
    )
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))
    first = _accept_snapshot(coordinator, trigger, request, sequence=3)
    journal.mark_proof_observed(selected.request_sha256, first)
    second = _accept_snapshot(coordinator, trigger, request, sequence=4)
    attempts = 0

    def fail_fence(reason: str) -> None:
        nonlocal attempts
        assert reason == "evidence_conflict"
        attempts += 1
        raise OSError("injected evidence-conflict persistence failure")

    monkeypatch.setattr(store, "enter_read_only", fail_fence)
    with pytest.raises(CorrelationRequestJournalUnhealthy, match="fence"):
        journal.mark_proof_observed(selected.request_sha256, second)

    assert attempts == 2
    assert store.read_only_reason is None
    assert not journal._is_bound_to(store)
    journal.close()
    store.close(flush=False)


def test_correlation_conflict_latch_failure_makes_journal_unhealthy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(tmp_path)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))
    first = _accept_snapshot(coordinator, trigger, request, sequence=3)
    journal.mark_proof_observed(selected.request_sha256, first)
    second = _accept_snapshot(coordinator, trigger, request, sequence=4)

    def fail_latch(_verifier: object) -> None:
        raise OSError("injected verifier latch failure")

    monkeypatch.setattr(
        type(coordinator.verifier),  # type: ignore[attr-defined]
        "_enter_read_only_after_durable_fence",
        fail_latch,
    )
    with pytest.raises(CorrelationRequestJournalUnhealthy, match="latch"):
        journal.mark_proof_observed(selected.request_sha256, second)

    assert store.read_only_reason == "evidence_conflict"
    assert not journal._is_bound_to(store)
    journal.close()
    store.close(flush=False)


def test_correlation_retry_authenticates_proof_before_declaring_conflict(
    tmp_path: Path,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(tmp_path)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))
    snapshot_ref = _accept_snapshot(coordinator, trigger, request)
    observed = journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    fabricated = replace(
        snapshot_ref,
        event_id="evt_" + "0" * 64,
        content_sha256="0" * 64,
    )

    with pytest.raises(CorrelationRequestJournalAuthorityError):
        journal.mark_proof_observed(selected.request_sha256, fabricated)

    assert store.read_only_reason is None
    assert journal.pending() == (observed,)
    journal.close()
    store.close()


def test_correlation_retry_authenticates_trigger_before_declaring_conflict(
    tmp_path: Path,
) -> None:
    _coordinator_value, store, trigger_ref, _trigger = seeded_correlation_store(
        tmp_path
    )
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))
    fabricated = replace(trigger_ref, content_sha256="0" * 64)

    with pytest.raises(CorrelationRequestJournalAuthorityError):
        journal.select(fabricated, canonical_json(request))

    assert store.read_only_reason is None
    assert journal.pending() == (selected,)
    journal.close()
    store.close()


@pytest.mark.parametrize("stage", ["trigger", "proof"])
def test_correlation_internal_evidence_corruption_is_never_authority_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(tmp_path)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)

    def corrupt(*_args: object, **_kwargs: object) -> None:
        raise EvidenceCorrupt("injected authenticated evidence corruption")

    if stage == "trigger":
        monkeypatch.setattr(store, "resolve_authenticated_ref", corrupt)
        operation = lambda: journal.select(trigger_ref, canonical_json(request))
    else:
        selected = journal.select(trigger_ref, canonical_json(request))
        snapshot_ref = _accept_snapshot(coordinator, trigger, request)
        monkeypatch.setattr(store, "_authenticated_pcc_input", corrupt)
        operation = lambda: journal.mark_proof_observed(
            selected.request_sha256,
            snapshot_ref,
        )

    with pytest.raises(CorrelationRequestJournalCorrupt):
        operation()

    assert store.read_only_reason == "segment_corrupt"
    journal.close()
    store.close(flush=False)


def test_correlation_returned_states_cannot_mutate_journal_authority(
    tmp_path: Path,
) -> None:
    _coordinator_value, store, trigger_ref, _trigger = seeded_correlation_store(
        tmp_path
    )
    journal = CorrelationRequestJournal.create_new(store)
    request_raw = canonical_json(_request(trigger_ref))
    selected = journal.select(trigger_ref, request_raw)

    selected.__dict__["phase"] = "completed"
    selected.request.__dict__["requested_ttl_seconds"] = 30

    pending = journal.pending()
    assert tuple(state.phase for state in pending) == ("selected",)
    assert pending[0].request.requested_ttl_seconds == 120
    assert journal.select(trigger_ref, request_raw).phase == "selected"
    journal.close()
    store.close()


@pytest.mark.parametrize(
    ("damage", "payload_indexes"),
    [
        ("duplicate", (0, 0)),
        ("skip", (1,)),
        ("rollback", (0, 1, 0)),
        ("post_completion", (0, 1, 2, 1)),
    ],
)
def test_correlation_recovery_rejects_illegal_phase_history(
    tmp_path: Path,
    damage: str,
    payload_indexes: tuple[int, ...],
) -> None:
    root = tmp_path / damage
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(root)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))
    snapshot_ref = _accept_snapshot(coordinator, trigger, request)
    journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    journal.mark_completed(selected.request_sha256)
    journal.close()
    store.close()

    path = root / "correlation-requests.agf"
    valid_payloads = read_correlation_frame_payloads(path)
    _rewrite_payloads(
        path,
        tuple(valid_payloads[index] for index in payload_indexes),
    )
    recovered_store = _reopen_correlation_store(root)

    with pytest.raises(CorrelationRequestJournalCorrupt):
        CorrelationRequestJournal.open_and_recover(recovered_store)

    assert recovered_store.read_only_reason == "segment_corrupt"
    recovered_store.close(flush=False)


@pytest.mark.parametrize(
    "bound_name",
    ["_MAX_RECORDS", "_MAX_VERIFIED_BYTES", "_MAX_FRAME_PAYLOAD"],
)
def test_correlation_recovery_quota_bounds_are_inclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bound_name: str,
) -> None:
    root = tmp_path / bound_name
    _coordinator_value, store, trigger_ref, _trigger = seeded_correlation_store(
        root
    )
    journal = CorrelationRequestJournal.create_new(store)
    journal.select(trigger_ref, canonical_json(_request(trigger_ref)))
    journal.close()
    path = root / "correlation-requests.agf"
    payload = read_correlation_frame_payloads(path)[0]
    exact = {
        "_MAX_RECORDS": 1,
        "_MAX_VERIFIED_BYTES": path.stat().st_size,
        "_MAX_FRAME_PAYLOAD": len(payload),
    }[bound_name]

    monkeypatch.setattr(correlation_module, bound_name, exact)
    recovered = CorrelationRequestJournal.open_and_recover(store)
    recovered.close()

    monkeypatch.setattr(correlation_module, bound_name, exact - 1)
    with pytest.raises(CorrelationRequestJournalCorrupt):
        CorrelationRequestJournal.open_and_recover(store)

    assert store.read_only_reason == "segment_corrupt"
    store.close(flush=False)


def test_correlation_journal_recovers_each_phase_and_quota_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert correlation_module._MAX_RECORDS == 4_096
    assert correlation_module._MAX_VERIFIED_BYTES == 16 * 1024 * 1024
    assert correlation_module._MAX_FRAME_PAYLOAD == 64 * 1024
    for phase in ("selected", "proof_observed", "completed"):
        root = tmp_path / phase
        coordinator, store, trigger_ref, trigger = seeded_correlation_store(root)
        journal = CorrelationRequestJournal.create_new(store)
        request = _request(trigger_ref)
        selected = journal.select(trigger_ref, canonical_json(request))
        if phase != "selected":
            snapshot = _accept_snapshot(coordinator, trigger, request)
            journal.mark_proof_observed(selected.request_sha256, snapshot)
        if phase == "completed":
            journal.mark_completed(selected.request_sha256)
        journal.close()
        recovered = CorrelationRequestJournal.open_and_recover(store)
        states = recovered.pending()
        if phase == "completed":
            assert states == ()
        else:
            assert tuple(state.phase for state in states) == (phase,)
        recovered.close()
        store.close()

    root = tmp_path / "quota"
    _coordinator_value, store, trigger_ref, _trigger = seeded_correlation_store(root)
    journal = CorrelationRequestJournal.create_new(store)
    journal.select(trigger_ref, canonical_json(_request(trigger_ref)))
    journal.close()
    raw_size = (root / "correlation-requests.agf").stat().st_size
    monkeypatch.setattr(correlation_module, "_MAX_VERIFIED_BYTES", raw_size - 1)
    with pytest.raises(CorrelationRequestJournalCorrupt):
        CorrelationRequestJournal.open_and_recover(store)
    store.close(flush=False)

@pytest.mark.parametrize(
    "damage",
    [
        "torn",
        "interior",
        "noncanonical",
        "disappearance",
        "replacement",
        "mode",
        "symlink",
        "hardlink",
    ],
)
def test_correlation_journal_fails_closed_on_unsafe_or_unbound_artifact(
    tmp_path: Path,
    damage: str,
) -> None:
    root = tmp_path / damage
    _coordinator_value, store, trigger_ref, _trigger = seeded_correlation_store(root)
    journal = CorrelationRequestJournal.create_new(store)
    journal.select(trigger_ref, canonical_json(_request(trigger_ref)))
    journal.close()
    path = root / "correlation-requests.agf"

    if damage == "torn":
        path.write_bytes(path.read_bytes()[:-1])
    elif damage == "interior":
        raw = bytearray(path.read_bytes())
        raw[45] ^= 1
        path.write_bytes(raw)
    elif damage == "noncanonical":
        value = json.loads(read_correlation_frame_payloads(path)[0])
        path.write_bytes(b"")
        _append_payload(path, json.dumps(value, indent=1).encode())
    elif damage == "disappearance":
        path.unlink()
    elif damage == "replacement":
        replacement = root / "replacement"
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, path)
    elif damage == "mode":
        path.chmod(0o644)
    elif damage == "symlink":
        target = root.parent / f"{root.name}-symlink-target.agf"
        target.write_bytes(path.read_bytes())
        target.chmod(0o600)
        path.unlink()
        path.symlink_to(target)
    else:
        os.link(path, root.parent / f"{root.name}-hardlink.agf")

    with pytest.raises((CorrelationRequestJournalCorrupt, EvidenceCorrupt)):
        CorrelationRequestJournal.open_and_recover(store)
    assert store.read_only_reason == "segment_corrupt"
    store.close(flush=False)


def test_correlation_startup_rejects_unexpected_root_artifact(
    tmp_path: Path,
) -> None:
    root = tmp_path / "unexpected"
    _coordinator_value, store, trigger_ref, _trigger = seeded_correlation_store(
        root
    )
    journal = CorrelationRequestJournal.create_new(store)
    journal.select(trigger_ref, canonical_json(_request(trigger_ref)))
    journal.close()
    store.close()
    (root / "unexpected.bin").write_bytes(b"not managed")

    with pytest.raises(EvidenceCorrupt, match="unexpected evidence-root artifact"):
        SegmentStore(root)
