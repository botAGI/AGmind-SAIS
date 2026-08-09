from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from agmind_immune.evidence.frames import iter_frames
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.incidents.admission import CandidateAdmissionView
from agmind_immune.ingest.envelope import EnvelopeVerifier
from agmind_immune.ingest.service import AcceptanceCoordinator
from agmind_immune.policy import PolicyEvaluation
from tests.admission_helpers import build_admission_runtime
from tests.ingest.test_pcc_correlation_snapshot import _identity
from tests.phase5b_helpers import private_key
from tests.test_controller_policy_commit import _manual_evaluation

_MAX_FRAME_PAYLOAD = 131_072


def _frame_count(path: Path) -> int:
    with path.open("rb") as stream:
        return sum(1 for _frame in iter_frames(stream, max_frame=_MAX_FRAME_PAYLOAD))


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
        view = await runtime.controller.issue_candidate_admission(
            runtime.candidate.candidate_id
        )
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
