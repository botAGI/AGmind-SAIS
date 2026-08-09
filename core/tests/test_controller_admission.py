from __future__ import annotations

import asyncio
import importlib
from collections.abc import Awaitable
from dataclasses import replace
from pathlib import Path

import pytest
from agmind_immune.contracts import MAX_UINT64
from agmind_immune.incidents.models import ContainmentCandidateV1

from tests.admission_helpers import (
    accept_one,
    append_and_project_one,
    append_late_invalidation,
    build_admission_runtime,
    mutate_projection_from_second_connection,
)


async def _cancel_while_controller_lock_is_held(
    controller: object,
    operations: tuple[Awaitable[object], ...],
) -> tuple[asyncio.Task[object], ...]:
    lock = controller._lock
    await lock.acquire()
    tasks = tuple(asyncio.create_task(operation) for operation in operations)
    try:
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert all(not task.done() for task in tasks)
    finally:
        for task in tasks:
            task.cancel()
        lock.release()
        await asyncio.gather(*tasks, return_exceptions=True)
    return tasks


@pytest.mark.asyncio
async def test_locked_candidate_admission_issue_and_consume_serialize_with_poll_retention_and_stale_edges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = importlib.import_module("agmind_immune.incidents.admission")
    CandidateAdmissionError = admission.CandidateAdmissionError
    runtime = build_admission_runtime(tmp_path / "serialized", monkeypatch)
    try:
        status_calls = 0
        original_status = runtime.projection.status

        def traced_status() -> object:
            nonlocal status_calls
            status_calls += 1
            return original_status()

        monkeypatch.setattr(runtime.projection, "status", traced_status)
        await _cancel_while_controller_lock_is_held(
            runtime.controller,
            (
                runtime.controller.issue_candidate_admission(
                    runtime.candidate.candidate_id
                ),
                runtime.controller.poll_once(),
                runtime.controller.run_retention_once(),
            ),
        )
        assert status_calls == 0

        view = await runtime.controller.issue_candidate_admission(
            runtime.candidate.candidate_id
        )
        status_calls = 0
        await _cancel_while_controller_lock_is_held(
            runtime.controller,
            (runtime.controller.consume_candidate_admission(view),),
        )
        assert status_calls == 0
        assert (
            await runtime.controller.consume_candidate_admission(view)
            == runtime.candidate
        )

        exact_readiness = runtime.controller.mutation_readiness()
        for inexact_readiness in (
            replace(exact_readiness, reason_codes=("inexact_ready_reason",)),
            replace(exact_readiness, observer_reconcile_generation=0),
            replace(
                exact_readiness,
                evidence_head=MAX_UINT64 + 1,
                acceptance_cursor=MAX_UINT64 + 1,
                confirmed_through=MAX_UINT64 + 1,
                projection_cursor=MAX_UINT64 + 1,
            ),
        ):
            with pytest.raises(CandidateAdmissionError):
                runtime.controller._readiness_cursors(inexact_readiness)
    finally:
        await runtime.close()

    lagged = build_admission_runtime(tmp_path / "unprojected", monkeypatch)
    try:
        accept_one(lagged)
        with pytest.raises(CandidateAdmissionError):
            await lagged.controller.issue_candidate_admission(
                lagged.candidate.candidate_id
            )
        assert lagged.projection.status().healthy is True
    finally:
        await lagged.close()

    applied = build_admission_runtime(tmp_path / "applied", monkeypatch)
    try:
        stale = await applied.controller.issue_candidate_admission(
            applied.candidate.candidate_id
        )
        append_and_project_one(applied)
        with pytest.raises(CandidateAdmissionError):
            await applied.controller.consume_candidate_admission(stale)
        refreshed = await applied.controller.issue_candidate_admission(
            applied.candidate.candidate_id
        )
        assert refreshed.authority_revision > stale.authority_revision
        assert (
            await applied.controller.consume_candidate_admission(refreshed)
            == applied.candidate
        )
    finally:
        await applied.close()

    rebuilt = build_admission_runtime(tmp_path / "rebuilt", monkeypatch)
    try:
        stale = await rebuilt.controller.issue_candidate_admission(
            rebuilt.candidate.candidate_id
        )
        rebuilt.projection.rebuild()
        with pytest.raises(CandidateAdmissionError):
            await rebuilt.controller.consume_candidate_admission(stale)
        refreshed = await rebuilt.controller.issue_candidate_admission(
            rebuilt.candidate.candidate_id
        )
        assert refreshed.admission_rebuild_epoch == (
            stale.admission_rebuild_epoch + 1
        )
        assert (
            await rebuilt.controller.consume_candidate_admission(refreshed)
            == rebuilt.candidate
        )
    finally:
        await rebuilt.close()

    closed = build_admission_runtime(tmp_path / "closed", monkeypatch)
    stale = await closed.controller.issue_candidate_admission(
        closed.candidate.candidate_id
    )
    await closed.close()
    with pytest.raises(CandidateAdmissionError):
        await closed.controller.consume_candidate_admission(stale)

    first = build_admission_runtime(tmp_path / "first", monkeypatch)
    second = build_admission_runtime(tmp_path / "second", monkeypatch)
    try:
        first_view = await first.controller.issue_candidate_admission(
            first.candidate.candidate_id
        )
        second_view = await second.controller.issue_candidate_admission(
            second.candidate.candidate_id
        )
        assert first.candidate.candidate_id == second.candidate.candidate_id
        with pytest.raises(CandidateAdmissionError):
            await second.controller.consume_candidate_admission(first_view)
        with pytest.raises(CandidateAdmissionError):
            await second.controller.consume_candidate_admission(second_view)
        assert (
            await first.controller.consume_candidate_admission(first_view)
            == first.candidate
        )
    finally:
        await first.close()
        await second.close()

    invalidated = build_admission_runtime(tmp_path / "invalidated", monkeypatch)
    try:
        with pytest.raises(CandidateAdmissionError):
            await invalidated.controller.issue_candidate_admission(
                "cand_" + "0" * 64
            )
        assert invalidated.projection.status().healthy is True
        stale = await invalidated.controller.issue_candidate_admission(
            invalidated.candidate.candidate_id
        )
        append_late_invalidation(invalidated)
        with pytest.raises(CandidateAdmissionError):
            await invalidated.controller.consume_candidate_admission(stale)
        with pytest.raises(CandidateAdmissionError):
            await invalidated.controller.issue_candidate_admission(
                invalidated.candidate.candidate_id
            )
        assert invalidated.projection.status().healthy is True
    finally:
        await invalidated.close()


@pytest.mark.asyncio
async def test_candidate_admission_reauthenticates_projection_rows_proofs_and_invalidations_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = importlib.import_module("agmind_immune.incidents.admission")
    CandidateAdmissionError = admission.CandidateAdmissionError
    for mutation in ("candidate-row", "proof-row", "invalidation-row"):
        runtime = build_admission_runtime(tmp_path / mutation, monkeypatch)
        try:
            view = await runtime.controller.issue_candidate_admission(
                runtime.candidate.candidate_id
            )
            assert type(view.candidate) is ContainmentCandidateV1
            mutate_projection_from_second_connection(runtime, mutation)
            with pytest.raises(CandidateAdmissionError):
                await runtime.controller.consume_candidate_admission(view)
            assert runtime.projection.status().healthy is False
            with pytest.raises(CandidateAdmissionError):
                await runtime.controller.issue_candidate_admission(
                    runtime.candidate.candidate_id
                )
        finally:
            await runtime.close()
