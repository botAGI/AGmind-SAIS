from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.segments import (
    EvidenceCorrupt,
    EvidenceRef,
    EvidenceSealError,
    SegmentStore,
)
from agmind_immune.ingest.ack_journal import (
    AckJournal,
    AckJournalAuthorityError,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.evidence.test_retention_restart import _fresh_verifier
from tests.evidence.test_retention_unlink import _issued_case
from tests.ingest.test_ack_journal import _frame_stream, _record_value


def _ordered_refs(store: SegmentStore) -> tuple[EvidenceRef, ...]:
    refs = tuple(record.ref for record in store.iter_authenticated_records())
    assert [ref.source_sequence for ref in refs] == [1, 2, 3]
    return refs


def _confirm(journal: AckJournal, refs: tuple[EvidenceRef, ...]) -> None:
    for ref in refs:
        journal.record_pending(ref)
        journal.record_confirmed(ref)


@pytest.mark.parametrize("unsafe_ack", ["lag", "pending"])
def test_retention_unlink_requires_settled_ack_prefix(
    tmp_path: Path,
    unsafe_ack: str,
) -> None:
    case, capability = _issued_case(
        tmp_path,
        acknowledge=False,
    )
    refs = _ordered_refs(case.store)
    journal = AckJournal.create_new(case.store)
    selected_paths = tuple(
        tmp_path / entry.segment_relative_path for entry in case.journal.state.entries
    )
    try:
        if unsafe_ack == "lag":
            _confirm(journal, refs[:1])
            assert journal.snapshot().confirmed_through == 1
            assert journal.snapshot().pending is None
        else:
            _confirm(journal, refs[:2])
            journal.record_pending(refs[2])
            assert journal.snapshot().confirmed_through == 2
            assert journal.snapshot().pending is not None

        with pytest.raises(EvidenceSealError, match="ACK|ack"):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )

        assert case.journal.state.phase == "evidence_appended"
        assert all(path.exists() for path in selected_paths)
    finally:
        journal.close()
        case.coverage.close()
        case.store.close(flush=False)


def _finalized_acknowledged_run(
    path: Path,
) -> tuple[EvidenceRef, EvidenceRef, EvidenceRef]:
    case, capability = _issued_case(
        path,
        acknowledge=False,
    )
    refs = _ordered_refs(case.store)
    journal = AckJournal.create_new(case.store)
    try:
        _confirm(journal, refs)
        assert journal.snapshot().confirmed_through == 3
        assert journal.snapshot().pending is None
        completion = case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        case.store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
    finally:
        journal.close()
        case.coverage.close()
        case.store.close(flush=False)
    return refs


def test_ack_restart_recovers_live_retired_live_history_without_live_standin(
    tmp_path: Path,
) -> None:
    before_ref, retired_ref, after_ref = _finalized_acknowledged_run(tmp_path)
    assert before_ref.source_sequence == 1
    assert retired_ref.source_sequence == 2
    assert after_ref.source_sequence == 3

    restarted_store = SegmentStore(tmp_path)
    try:
        AcceptanceCoordinator.open_and_recover(
            _fresh_verifier(),
            restarted_store,
        )
        recovered = AckJournal.open_and_recover(restarted_store)

        snapshot = recovered.snapshot()
        assert snapshot.healthy is True
        assert snapshot.confirmed_through == after_ref.source_sequence
        assert snapshot.pending is None
        with pytest.raises(AckJournalAuthorityError):
            recovered.record_pending(retired_ref)
    finally:
        restarted_store.close(flush=False)


def _forge_ack_history(
    path: Path,
    refs: tuple[EvidenceRef, ...],
) -> None:
    payloads = tuple(
        canonical_json(_record_value(ref, kind))
        for ref in refs
        for kind in ("pending_ack", "confirmed_ack")
    )
    raw = _frame_stream(*payloads)
    confirmed = refs[-1]
    (path / "ack-journal.agf").write_bytes(raw)
    (path / "ack-commitment.json").write_bytes(
        canonical_json(
            {
                "schema_version": "agmind.core-ack-commitment.v1",
                "phase": "ready",
                "generation": len(refs),
                "confirmed": {
                    "sequence": confirmed.source_sequence,
                    "event_id": confirmed.event_id,
                    "content_sha256": confirmed.content_sha256,
                },
                "journal_prefix_size": len(raw),
                "journal_prefix_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    )


def test_ack_restart_rejects_one_ahead_identity_for_retired_sequence(
    tmp_path: Path,
) -> None:
    before_ref, retired_ref, _after_ref = _finalized_acknowledged_run(tmp_path)
    forged_retired = replace(
        retired_ref,
        event_id="evt_" + "4" * 64,
        content_sha256="5" * 64,
    )
    committed_payloads = tuple(
        canonical_json(_record_value(before_ref, kind)) for kind in ("pending_ack", "confirmed_ack")
    )
    all_payloads = (
        *committed_payloads,
        *(
            canonical_json(_record_value(forged_retired, kind))
            for kind in ("pending_ack", "confirmed_ack")
        ),
    )
    committed_raw = _frame_stream(*committed_payloads)
    full_raw = _frame_stream(*all_payloads)
    (tmp_path / "ack-journal.agf").write_bytes(full_raw)
    (tmp_path / "ack-commitment.json").write_bytes(
        canonical_json(
            {
                "schema_version": "agmind.core-ack-commitment.v1",
                "phase": "ready",
                "generation": 1,
                "confirmed": {
                    "sequence": before_ref.source_sequence,
                    "event_id": before_ref.event_id,
                    "content_sha256": before_ref.content_sha256,
                },
                "journal_prefix_size": len(committed_raw),
                "journal_prefix_sha256": hashlib.sha256(committed_raw).hexdigest(),
            }
        )
    )

    restarted_store = SegmentStore(tmp_path)
    try:
        with pytest.raises(EvidenceCorrupt, match="ACK|ack"):
            AcceptanceCoordinator.open_and_recover(
                _fresh_verifier(),
                restarted_store,
            )
    finally:
        restarted_store.close(flush=False)


def test_ack_restart_rejects_missing_identity_outside_retired_union(
    tmp_path: Path,
) -> None:
    refs = _finalized_acknowledged_run(tmp_path)

    baseline_store = SegmentStore(tmp_path)
    try:
        AcceptanceCoordinator.open_and_recover(
            _fresh_verifier(),
            baseline_store,
        )
        baseline = AckJournal.open_and_recover(baseline_store)
        assert baseline.snapshot().confirmed_through == refs[-1].source_sequence
        baseline.close()
    finally:
        baseline_store.close(flush=False)

    missing = replace(
        refs[-1],
        source_sequence=4,
        event_id="evt_" + "4" * 64,
        content_sha256="5" * 64,
    )
    _forge_ack_history(tmp_path, (*refs, missing))

    restarted_store = SegmentStore(tmp_path)
    try:
        with pytest.raises(EvidenceCorrupt, match="ACK|ack"):
            AcceptanceCoordinator.open_and_recover(
                _fresh_verifier(),
                restarted_store,
            )
    finally:
        restarted_store.close(flush=False)
