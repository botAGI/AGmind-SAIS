from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import pickle
import shutil
from dataclasses import replace
from pathlib import Path
from threading import Event, Thread

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
from agmind_immune.ingest.envelope import AuthenticatedPCCInput, EnvelopeVerifier
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


def _completed_snapshot_case(
    path: Path,
) -> tuple[
    object,
    SegmentStore,
    CorrelationRequestJournal,
    PCCCorrelationSnapshotRequestV1,
    EvidenceRef,
    object,
]:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(path)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))
    snapshot_ref = _accept_snapshot(coordinator, trigger, request)
    journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    journal.mark_completed(selected.request_sha256)
    authority = journal.completed_for_snapshot(snapshot_ref)
    return coordinator, store, journal, request, snapshot_ref, authority


def _two_completed_snapshot_case(
    path: Path,
) -> tuple[SegmentStore, CorrelationRequestJournal, EvidenceRef, EvidenceRef]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    refs: list[EvidenceRef] = []
    for trigger_sequence in (2, 4):
        trigger = _candidate_trigger(key, sequence=trigger_sequence)
        trigger_ref = _accept(coordinator, trigger)
        assert isinstance(trigger_ref, EvidenceRef)
        request = _request(trigger_ref)
        selected = journal.select(trigger_ref, canonical_json(request))
        snapshot_ref = _accept_snapshot(
            coordinator,
            trigger,
            request,
            sequence=trigger_sequence + 1,
        )
        journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
        journal.mark_completed(selected.request_sha256)
        refs.append(snapshot_ref)
    return coordinator.segment_store, journal, refs[0], refs[1]


def test_correlation_journal_replay_snapshot_rejects_real_completed_writer(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path, key)
    _accept(coordinator, boot_boundary(key))
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    completed_refs: list[EvidenceRef] = []
    try:
        for trigger_sequence in (2, 4):
            trigger = _candidate_trigger(key, sequence=trigger_sequence)
            trigger_ref = _accept(coordinator, trigger)
            assert isinstance(trigger_ref, EvidenceRef)
            request = _request(trigger_ref)
            selected = journal.select(trigger_ref, canonical_json(request))
            snapshot_ref = _accept_snapshot(
                coordinator,
                trigger,
                request,
                sequence=trigger_sequence + 1,
            )
            journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
            journal.mark_completed(selected.request_sha256)
            completed_refs.append(snapshot_ref)

        with correlation_module._correlation_journal_replay_gate(journal):
            snapshot, proofs = (
                correlation_module._capture_correlation_journal_replay_locked(
                    journal,
                    through_sequence=completed_refs[-1].source_sequence,
                )
            )

        trigger = _candidate_trigger(key, sequence=6)
        trigger_ref = _accept(coordinator, trigger)
        assert isinstance(trigger_ref, EvidenceRef)
        request = _request(trigger_ref)
        selected = journal.select(trigger_ref, canonical_json(request))
        snapshot_ref = _accept_snapshot(coordinator, trigger, request, sequence=7)
        journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
        journal.mark_completed(selected.request_sha256)

        with (
            correlation_module._correlation_journal_replay_gate(journal),
            pytest.raises(CorrelationRequestJournalAuthorityError),
        ):
            correlation_module._revalidate_correlation_journal_replay_locked(
                journal,
                snapshot,
            )
        assert tuple(proof.event_id for proof in proofs) == tuple(
            ref.event_id for ref in completed_refs
        )
    finally:
        journal.close()
        store.close()


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
    assert correlation_module._MAX_RECORDS == 12_291
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


def test_correlation_journal_12291st_record_is_inclusive_and_next_fails(
    tmp_path: Path,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(tmp_path)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    journal._record_count = 12_290
    selected = journal.select(trigger_ref, canonical_json(request))
    assert journal._record_count == 12_291
    assert correlation_module._MAX_VERIFIED_BYTES == 16 * 1024 * 1024
    snapshot_ref = _accept_snapshot(coordinator, trigger, request)

    with pytest.raises(
        CorrelationRequestJournalStateError,
        match="record quota is exhausted",
    ):
        journal.mark_proof_observed(selected.request_sha256, snapshot_ref)

    journal._record_count = 1
    journal.close()
    store.close()


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


def test_completed_snapshot_batch_is_ordered_and_replays_exactly_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, journal, first, second = _two_completed_snapshot_case(tmp_path)
    real_replay = journal._authenticated_journal_replay
    replay_count = 0

    def counted_replay() -> object:
        nonlocal replay_count
        replay_count += 1
        return real_replay()

    monkeypatch.setattr(journal, "_authenticated_journal_replay", counted_replay)
    try:
        result = correlation_module._evaluate_completed_snapshot_batch(
            journal,
            (second, first),
            lambda proofs: tuple(proof.event_id for proof in proofs),
        )

        assert result == (second.event_id, first.event_id)
        assert replay_count == 2
    finally:
        journal.close()
        store.close()


def test_completed_snapshot_batch_items_use_o1_anchor_then_full_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, journal, first, second = _two_completed_snapshot_case(tmp_path)
    real_replay = journal._authenticated_journal_replay
    replay_count = 0

    def counted_replay() -> object:
        nonlocal replay_count
        replay_count += 1
        return real_replay()

    monkeypatch.setattr(journal, "_authenticated_journal_replay", counted_replay)
    try:
        batch = correlation_module._issue_completed_snapshot_batch(
            journal,
            (second, first),
        )
        items = correlation_module._completed_snapshot_batch_items(batch)
        assert replay_count == 2

        proofs = tuple(
            correlation_module._revalidate_completed_snapshot(item)
            for item in items
        )

        assert tuple(proof.event_id for proof in proofs) == (
            second.event_id,
            first.event_id,
        )
        assert replay_count == 2
        correlation_module._seal_completed_snapshot_batch(batch)
        assert replay_count == 3
        with pytest.raises(CorrelationRequestJournalAuthorityError):
            correlation_module._revalidate_completed_snapshot(items[0])
    finally:
        journal.close()
        store.close()


def test_completed_snapshot_batch_item_rejects_append_only_extension_in_o1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path, key)
    _accept(coordinator, boot_boundary(key))
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    trigger = _candidate_trigger(key, sequence=2)
    trigger_ref = _accept(coordinator, trigger)
    assert isinstance(trigger_ref, EvidenceRef)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))
    snapshot_ref = _accept_snapshot(coordinator, trigger, request, sequence=3)
    journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    journal.mark_completed(selected.request_sha256)
    real_replay = journal._authenticated_journal_replay
    replay_count = 0

    def counted_replay() -> object:
        nonlocal replay_count
        replay_count += 1
        return real_replay()

    monkeypatch.setattr(journal, "_authenticated_journal_replay", counted_replay)
    batch = correlation_module._issue_completed_snapshot_batch(
        journal,
        (snapshot_ref,),
    )
    item = correlation_module._completed_snapshot_batch_items(batch)[0]
    assert replay_count == 2
    later_trigger = _candidate_trigger(key, sequence=4)
    later_ref = _accept(coordinator, later_trigger)
    assert isinstance(later_ref, EvidenceRef)
    journal.select(later_ref, canonical_json(_request(later_ref)))

    try:
        with pytest.raises(CorrelationRequestJournalAuthorityError):
            correlation_module._revalidate_completed_snapshot(item)
        assert replay_count == 2
        assert journal._healthy is True
    finally:
        journal.close()
        coordinator.segment_store.close()


def test_completed_snapshot_batch_item_rejects_revoke_during_revalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, journal, first, _second = _two_completed_snapshot_case(tmp_path)
    batch = correlation_module._issue_completed_snapshot_batch(
        journal,
        (first,),
    )
    item = correlation_module._completed_snapshot_batch_items(batch)[0]
    real_exact = store._authenticated_pcc_input_is_exact
    revoked = False

    def revoke_during_exact_check(proof: object) -> bool:
        nonlocal revoked
        if not revoked:
            revoked = True
            correlation_module._revoke_completed_snapshot_batch(batch)
        return real_exact(proof)

    monkeypatch.setattr(
        store,
        "_authenticated_pcc_input_is_exact",
        revoke_during_exact_check,
    )
    try:
        with pytest.raises(
            CorrelationRequestJournalAuthorityError,
            match="batch item was revoked",
        ):
            correlation_module._revalidate_completed_snapshot(item)
    finally:
        journal.close()
        store.close()


def test_completed_snapshot_batch_seal_rejects_revoke_during_final_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, journal, first, _second = _two_completed_snapshot_case(tmp_path)
    real_replay = journal._authenticated_journal_replay
    replay_count = 0
    batch: object | None = None

    def revoke_during_final_replay() -> object:
        nonlocal replay_count
        replay_count += 1
        if replay_count == 3:
            assert batch is not None
            correlation_module._revoke_completed_snapshot_batch(batch)
        return real_replay()

    monkeypatch.setattr(
        journal,
        "_authenticated_journal_replay",
        revoke_during_final_replay,
    )
    batch = correlation_module._issue_completed_snapshot_batch(
        journal,
        (first,),
    )
    correlation_module._completed_snapshot_batch_items(batch)
    try:
        with pytest.raises(
            CorrelationRequestJournalAuthorityError,
            match="batch was revoked during final seal",
        ):
            correlation_module._seal_completed_snapshot_batch(batch)
    finally:
        journal.close()
        store.close()


@pytest.mark.parametrize("attack", ["substitution", "reuse"])
def test_completed_snapshot_batch_rejects_substitution_and_item_reuse(
    tmp_path: Path,
    attack: str,
) -> None:
    store, journal, first, second = _two_completed_snapshot_case(tmp_path)
    batch = correlation_module._issue_completed_snapshot_batch(
        journal,
        (first, second),
    )
    items = correlation_module._completed_snapshot_batch_items(batch)
    try:
        if attack == "substitution":
            object.__setattr__(items[0], "_token", object())
            with pytest.raises(CorrelationRequestJournalAuthorityError):
                correlation_module._revalidate_completed_snapshot(items[0])
        else:
            with pytest.raises(CorrelationRequestJournalAuthorityError):
                correlation_module._completed_snapshot_batch_items(batch)
    finally:
        journal.close()
        store.close()


@pytest.mark.parametrize("invalid", ["duplicate", "subclass", "overflow"])
def test_completed_snapshot_batch_rejects_invalid_ref_sets(
    tmp_path: Path,
    invalid: str,
) -> None:
    store, journal, first, second = _two_completed_snapshot_case(tmp_path)
    callback_called = False

    def callback(proofs: tuple[AuthenticatedPCCInput, ...]) -> tuple[str, ...]:
        nonlocal callback_called
        callback_called = True
        return tuple(proof.event_id for proof in proofs)

    if invalid == "duplicate":
        refs: tuple[EvidenceRef, ...] = (first, first)
    elif invalid == "subclass":
        class SubclassedRef(EvidenceRef):
            pass

        refs = (
            SubclassedRef(
                segment_id=first.segment_id,
                segment_relative_path=first.segment_relative_path,
                frame_offset=first.frame_offset,
                frame_size=first.frame_size,
                frame_sha256=first.frame_sha256,
                event_id=first.event_id,
                source_sequence=first.source_sequence,
                content_sha256=first.content_sha256,
            ),
            second,
        )
    else:
        refs = (first,) * 4_097
    try:
        with pytest.raises(CorrelationRequestJournalAuthorityError):
            correlation_module._evaluate_completed_snapshot_batch(
                journal,
                refs,
                callback,
            )
        assert callback_called is False
    finally:
        journal.close()
        store.close()


def test_completed_snapshot_batch_withholds_result_on_journal_drift(
    tmp_path: Path,
) -> None:
    store, journal, first, second = _two_completed_snapshot_case(tmp_path)
    result_observed = False

    def drift(
        proofs: tuple[AuthenticatedPCCInput, ...],
    ) -> tuple[str, ...]:
        nonlocal result_observed
        result_observed = True
        journal._states_by_operation = {}
        return tuple(proof.event_id for proof in proofs)

    try:
        with pytest.raises(CorrelationRequestJournalCorrupt):
            correlation_module._evaluate_completed_snapshot_batch(
                journal,
                (first, second),
                drift,
            )
        assert result_observed is True
    finally:
        journal.close()
        store.close()


@pytest.mark.parametrize("phase", ["selected", "proof_observed"])
def test_completed_snapshot_authority_requires_completed_phase(
    tmp_path: Path,
    phase: str,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(
        tmp_path / phase
    )
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))
    snapshot_ref = _accept_snapshot(coordinator, trigger, request)
    if phase == "proof_observed":
        journal.mark_proof_observed(selected.request_sha256, snapshot_ref)

    with pytest.raises(CorrelationRequestJournalAuthorityError):
        journal.completed_for_snapshot(snapshot_ref)

    journal.close()
    store.close()


def test_completed_snapshot_authority_reauthenticates_exact_completed_pcc(
    tmp_path: Path,
) -> None:
    _coordinator_value, store, journal, request, snapshot_ref, authority = (
        _completed_snapshot_case(tmp_path)
    )

    authenticated = correlation_module._revalidate_completed_snapshot(authority)

    assert type(authenticated) is AuthenticatedPCCInput
    assert store._authenticated_pcc_input_is_exact(authenticated)
    assert authenticated.evidence_ref == snapshot_ref
    assert authenticated.canonical == store.resolve_authenticated_ref(
        snapshot_ref
    ).canonical_envelope
    assert authenticated.request == request
    assert authenticated.snapshot.request_sha256 == hashlib.sha256(
        canonical_json(request)
    ).hexdigest()
    assert (
        authenticated.snapshot.trigger.event_id,
        authenticated.snapshot.trigger.content_sha256,
        authenticated.snapshot.trigger.source_sequence,
    ) == (
        request.trigger_event_id,
        request.trigger_content_sha256,
        request.trigger_source_sequence,
    )
    journal.close()
    store.close()


def test_completed_snapshot_authority_rejects_direct_pcc_and_changed_ref(
    tmp_path: Path,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(
        tmp_path / "direct"
    )
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    snapshot_ref = _accept_snapshot(coordinator, trigger, request)

    with pytest.raises(CorrelationRequestJournalAuthorityError):
        journal.completed_for_snapshot(snapshot_ref)

    journal.close()
    store.close()

    (
        _coordinator_value,
        store,
        journal,
        _request_value,
        snapshot_ref,
        _authority,
    ) = _completed_snapshot_case(tmp_path / "changed")
    changed_refs = (
        replace(snapshot_ref, frame_offset=snapshot_ref.frame_offset + 1),
        replace(snapshot_ref, content_sha256="0" * 64),
        replace(snapshot_ref, event_id="evt_" + "0" * 64),
    )
    for changed in changed_refs:
        with pytest.raises(CorrelationRequestJournalAuthorityError):
            journal.completed_for_snapshot(changed)
    journal.close()
    store.close()


def test_completed_snapshot_authority_rejects_byte_identical_cross_store_pcc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    clone = tmp_path / "clone"
    (
        _coordinator_value,
        store,
        journal,
        request,
        snapshot_ref,
        authority,
    ) = _completed_snapshot_case(source)
    original = correlation_module._revalidate_completed_snapshot(authority)
    shutil.copytree(source, clone)
    clone_store = _reopen_correlation_store(clone)
    clone_verifier = clone_store._bound_verifier
    assert clone_verifier is not None
    clone_pcc = clone_store._authenticated_pcc_input(
        clone_verifier,
        snapshot_ref,
        request,
    )
    assert clone_pcc.canonical == original.canonical

    def issue_clone(
        _verifier: object,
        _ref: EvidenceRef,
        _request_value: PCCCorrelationSnapshotRequestV1,
    ) -> AuthenticatedPCCInput:
        return clone_pcc

    monkeypatch.setattr(store, "_authenticated_pcc_input", issue_clone)
    with pytest.raises(CorrelationRequestJournalAuthorityError):
        journal.completed_for_snapshot(snapshot_ref)

    clone_store.close()
    journal.close()
    store.close()


def test_completed_snapshot_capability_is_opaque_final_and_unforgeable(
    tmp_path: Path,
) -> None:
    _coordinator_value, store, journal, _request_value, _ref, authority = (
        _completed_snapshot_case(tmp_path)
    )
    capability_type = type(authority)

    with pytest.raises(TypeError):
        capability_type()
    with pytest.raises(TypeError):
        type("ForgedCompletedSnapshotAuthority", (capability_type,), {})
    with pytest.raises(AttributeError):
        authority._token = object()
    with pytest.raises(TypeError):
        copy.copy(authority)
    with pytest.raises(TypeError):
        copy.deepcopy(authority)
    with pytest.raises(TypeError):
        pickle.dumps(authority)

    fabricated = object.__new__(capability_type)
    object.__setattr__(fabricated, "_token", object())
    with pytest.raises(CorrelationRequestJournalAuthorityError):
        correlation_module._revalidate_completed_snapshot(fabricated)

    object.__setattr__(authority, "_token", object())
    with pytest.raises(CorrelationRequestJournalAuthorityError):
        correlation_module._revalidate_completed_snapshot(authority)
    journal.close()
    store.close()


def test_completed_snapshot_authority_is_revoked_by_unrelated_journal_append(
    tmp_path: Path,
) -> None:
    coordinator, store, journal, _request_value, snapshot_ref, old_authority = (
        _completed_snapshot_case(tmp_path)
    )
    key = private_key(11)
    second_trigger = _candidate_trigger(key, sequence=4)
    second_ref = coordinator.accept(_item(second_trigger))  # type: ignore[attr-defined]
    assert isinstance(second_ref, EvidenceRef)
    fresh_authority = journal.completed_for_snapshot(snapshot_ref)
    assert fresh_authority is not old_authority

    journal.select(second_ref, canonical_json(_request(second_ref)))

    with pytest.raises(CorrelationRequestJournalAuthorityError):
        correlation_module._revalidate_completed_snapshot(fresh_authority)
    journal.close()
    store.close()


def test_completed_snapshot_authority_detects_state_and_request_mutation(
    tmp_path: Path,
) -> None:
    _coordinator_value, store, journal, _request_value, snapshot_ref, authority = (
        _completed_snapshot_case(tmp_path)
    )
    state = next(iter(journal._states_by_operation.values()))
    operation = state.operation_key
    canonical_copy = state.model_copy(deep=True)
    journal._states_by_operation[operation] = canonical_copy
    assert (
        correlation_module._revalidate_completed_snapshot(authority).evidence_ref
        == snapshot_ref
    )

    original_request = canonical_copy.request
    canonical_copy.__dict__["request"] = original_request.model_copy(
        update={"requested_ttl_seconds": 30}
    )
    try:
        with pytest.raises(CorrelationRequestJournalCorrupt):
            correlation_module._revalidate_completed_snapshot(authority)
        assert store.read_only_reason == "segment_corrupt"
    finally:
        canonical_copy.__dict__["request"] = original_request
    journal.close()
    store.close(flush=False)


def test_completed_snapshot_authority_is_revoked_by_verifier_change_and_close(
    tmp_path: Path,
) -> None:
    coordinator, store, journal, _request_value, _ref, authority = (
        _completed_snapshot_case(tmp_path / "generation")
    )
    coordinator.accept(  # type: ignore[attr-defined]
        _item(_candidate_trigger(private_key(11), sequence=4))
    )
    with pytest.raises(CorrelationRequestJournalAuthorityError):
        correlation_module._revalidate_completed_snapshot(authority)
    journal.close()
    store.close()

    _coordinator_value, store, journal, _request_value, _ref, authority = (
        _completed_snapshot_case(tmp_path / "close")
    )
    journal.close()
    with pytest.raises(CorrelationRequestJournalAuthorityError):
        correlation_module._revalidate_completed_snapshot(authority)
    store.close()


def test_completed_snapshot_recovery_reissues_fresh_lifecycle_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / "restart"
    _coordinator_value, store, journal, _request_value, snapshot_ref, authority = (
        _completed_snapshot_case(root)
    )
    journal.close()
    store.close()

    with pytest.raises(CorrelationRequestJournalAuthorityError):
        correlation_module._revalidate_completed_snapshot(authority)

    recovered_store = _reopen_correlation_store(root)
    recovered = CorrelationRequestJournal.open_and_recover(recovered_store)
    fresh = recovered.completed_for_snapshot(snapshot_ref)
    authenticated = correlation_module._revalidate_completed_snapshot(fresh)

    assert fresh is not authority
    assert authenticated.evidence_ref == snapshot_ref
    assert recovered_store._authenticated_pcc_input_is_exact(authenticated)
    recovered.close()
    recovered_store.close()


def test_correlation_recovery_rejects_duplicate_completed_snapshot_owner(
    tmp_path: Path,
) -> None:
    root = tmp_path / "duplicate-snapshot-owner"
    coordinator, store, journal, _request_value, snapshot_ref, _authority = (
        _completed_snapshot_case(root)
    )
    second_trigger = _candidate_trigger(private_key(11), sequence=4)
    second_ref = coordinator.accept(_item(second_trigger))  # type: ignore[attr-defined]
    assert isinstance(second_ref, EvidenceRef)
    journal.select(second_ref, canonical_json(_request(second_ref)))
    journal.close()
    store.close()

    path = root / "correlation-requests.agf"
    payloads = read_correlation_frame_payloads(path)
    assert len(payloads) == 4
    selected = json.loads(payloads[-1])
    observed = {
        **selected,
        "phase": "proof_observed",
        "snapshot_event_id": snapshot_ref.event_id,
        "snapshot_content_sha256": snapshot_ref.content_sha256,
    }
    completed = {**observed, "phase": "completed"}
    _rewrite_payloads(
        path,
        (*payloads, canonical_json(observed), canonical_json(completed)),
    )
    recovered_store = _reopen_correlation_store(root)

    with pytest.raises(CorrelationRequestJournalCorrupt):
        CorrelationRequestJournal.open_and_recover(recovered_store)

    assert recovered_store.read_only_reason == "segment_corrupt"
    recovered_store.close(flush=False)


def test_completed_snapshot_corrupt_current_bytes_trip_fence_without_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / "corrupt-current"
    _coordinator_value, store, journal, _request_value, snapshot_ref, authority = (
        _completed_snapshot_case(root)
    )
    offset = min(64, journal._size - 1)
    original = os.pread(journal._descriptor, 1, offset)
    assert len(original) == 1
    os.pwrite(journal._descriptor, bytes((original[0] ^ 1,)), offset)
    os.fsync(journal._descriptor)

    with pytest.raises(CorrelationRequestJournalCorrupt):
        correlation_module._revalidate_completed_snapshot(authority)
    with pytest.raises(CorrelationRequestJournalUnhealthy):
        journal.completed_for_snapshot(snapshot_ref)

    assert store.read_only_reason == "segment_corrupt"
    journal.close()
    store.close(flush=False)


def test_completed_snapshot_rejects_injected_completed_cache_over_empty_journal(
    tmp_path: Path,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(tmp_path)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    snapshot_ref = _accept_snapshot(coordinator, trigger, request)
    operation_key = f"pcc_correlation_snapshot:{trigger_ref.event_id}"
    completed = correlation_module._CorrelationRequestStateV1.model_validate(
        {
            "schema_version": "agmind.correlation-request-state.v1",
            "operation_key": operation_key,
            "request_sha256": hashlib.sha256(canonical_json(request)).hexdigest(),
            "request": request,
            "phase": "completed",
            "snapshot_event_id": snapshot_ref.event_id,
            "snapshot_content_sha256": snapshot_ref.content_sha256,
        },
        strict=True,
    )
    journal._states_by_operation[operation_key] = completed
    journal._operation_by_request[completed.request_sha256] = operation_key
    journal._operation_by_snapshot[
        (snapshot_ref.event_id, snapshot_ref.content_sha256)
    ] = operation_key
    assert read_correlation_frame_payloads(
        tmp_path / "correlation-requests.agf"
    ) == ()

    with pytest.raises(CorrelationRequestJournalCorrupt):
        journal.completed_for_snapshot(snapshot_ref)

    assert store.read_only_reason == "segment_corrupt"
    journal.close()
    store.close(flush=False)


def test_completed_snapshot_rejects_completed_cache_over_durable_proof_observed(
    tmp_path: Path,
) -> None:
    coordinator, store, trigger_ref, trigger = seeded_correlation_store(tmp_path)
    journal = CorrelationRequestJournal.create_new(store)
    request = _request(trigger_ref)
    selected = journal.select(trigger_ref, canonical_json(request))
    snapshot_ref = _accept_snapshot(coordinator, trigger, request)
    observed = journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    completed = correlation_module._CorrelationRequestStateV1.model_validate(
        {**observed.model_dump(mode="python"), "phase": "completed"},
        strict=True,
    )
    journal._states_by_operation[completed.operation_key] = completed
    payloads = read_correlation_frame_payloads(
        tmp_path / "correlation-requests.agf"
    )
    assert len(payloads) == 2
    assert json.loads(payloads[-1])["phase"] == "proof_observed"

    with pytest.raises(CorrelationRequestJournalCorrupt):
        journal.completed_for_snapshot(snapshot_ref)

    payloads_after = read_correlation_frame_payloads(
        tmp_path / "correlation-requests.agf"
    )
    assert json.loads(payloads_after[-1])["phase"] == "proof_observed"
    assert store.read_only_reason == "segment_corrupt"
    journal.close()
    store.close(flush=False)


@pytest.mark.parametrize(
    "damage",
    ["request_index", "state_remove", "state_remap", "snapshot_index"],
)
def test_completed_snapshot_revalidation_fences_cache_index_drift(
    tmp_path: Path,
    damage: str,
) -> None:
    root = tmp_path / damage
    _coordinator_value, store, journal, _request_value, ref, authority = (
        _completed_snapshot_case(root)
    )
    state = next(iter(journal._states_by_operation.values()))
    if damage == "request_index":
        journal._operation_by_request.pop(state.request_sha256)
    elif damage == "state_remove":
        journal._states_by_operation.pop(state.operation_key)
    elif damage == "state_remap":
        journal._states_by_operation["wrong-operation-key"] = (
            journal._states_by_operation.pop(state.operation_key)
        )
    else:
        journal._operation_by_snapshot[
            (ref.event_id, ref.content_sha256)
        ] = "wrong-operation-key"

    try:
        with pytest.raises(CorrelationRequestJournalCorrupt):
            correlation_module._revalidate_completed_snapshot(authority)
        assert store.read_only_reason == "segment_corrupt"
    finally:
        journal.close()
        store.close(flush=False)


def test_completed_snapshot_token_mutation_during_validation_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _coordinator_value, store, journal, _request_value, _ref, authority = (
        _completed_snapshot_case(tmp_path)
    )
    entered = Event()
    release = Event()
    outcome: dict[str, object] = {}
    validate = CorrelationRequestJournal._revalidate_completed_binding

    def blocked_validation(
        owner: CorrelationRequestJournal,
        binding: object,
    ) -> object:
        entered.set()
        assert release.wait(timeout=5)
        return validate(owner, binding)  # type: ignore[arg-type]

    monkeypatch.setattr(
        CorrelationRequestJournal,
        "_revalidate_completed_binding",
        blocked_validation,
    )

    def worker() -> None:
        try:
            outcome["value"] = correlation_module._revalidate_completed_snapshot(
                authority
            )
        except BaseException as error:  # noqa: BLE001 - thread result boundary
            outcome["error"] = error

    thread = Thread(target=worker)
    thread.start()
    try:
        assert entered.wait(timeout=5)
        object.__setattr__(authority, "_token", object())
    finally:
        release.set()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert "value" not in outcome
    assert isinstance(
        outcome.get("error"),
        CorrelationRequestJournalAuthorityError,
    )
    journal.close()
    store.close()
