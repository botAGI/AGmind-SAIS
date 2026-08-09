from __future__ import annotations

import copy
import importlib
import json
import pickle
import types
from pathlib import Path

import pytest
from agmind_immune.canonicaljson import candidate_facts_sha256
from agmind_immune.incidents.models import ContainmentCandidateV1

from tests.admission_helpers import build_admission_runtime


@pytest.mark.asyncio
async def test_candidate_admission_view_is_opaque_single_use_and_mutation_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = importlib.import_module("agmind_immune.incidents.admission")
    CandidateAdmissionError = admission.CandidateAdmissionError
    CandidateAdmissionView = admission.CandidateAdmissionView
    CandidateStatusObservation = admission.CandidateStatusObservation
    runtime = build_admission_runtime(tmp_path / "runtime", monkeypatch)
    try:
        assert CandidateAdmissionView.__final__ is True
        with pytest.raises(TypeError):
            CandidateAdmissionView()

        view = await runtime.controller.issue_candidate_admission(
            runtime.candidate.candidate_id
        )
        cursor = runtime.projection.status().cursor
        readiness = runtime.controller.mutation_readiness()
        assert type(view) is CandidateAdmissionView
        assert type(view.candidate) is ContainmentCandidateV1
        assert view.candidate == runtime.candidate
        assert view.candidate_facts_sha256 == candidate_facts_sha256(
            runtime.candidate
        )
        assert (
            view.authority_snapshot_event_id
            == runtime.candidate.correlation_snapshot_event_id
        )
        assert view.projection_cursor == cursor
        assert view.terminal_ref == runtime.terminal_ref
        assert view.admission_rebuild_epoch == 1
        assert type(view.authority_revision) is int
        assert view.authority_revision >= 1
        assert view.readiness == readiness
        assert view.readiness.coverage_snapshot_sha256 == (
            runtime.candidate.coverage_snapshot_sha256
        )
        assert not hasattr(view, "__dict__")
        assert not hasattr(view, "model_dump")
        with pytest.raises(AttributeError):
            view.authority_revision = 0
        with pytest.raises((CandidateAdmissionError, TypeError)):
            copy.copy(view)
        with pytest.raises((CandidateAdmissionError, TypeError)):
            copy.deepcopy(view)
        with pytest.raises(
            (CandidateAdmissionError, TypeError, pickle.PicklingError)
        ):
            pickle.dumps(view)
        with pytest.raises(TypeError):
            json.dumps(view)

        observation = CandidateStatusObservation(
            candidate=runtime.candidate,
            invalidation_event_ids=(),
        )
        with pytest.raises(AttributeError):
            observation.invalidation_event_ids = (
                runtime.terminal_ref.event_id,
            )
        with pytest.raises(CandidateAdmissionError):
            await runtime.controller.consume_candidate_admission(observation)
        with pytest.raises(CandidateAdmissionError):
            await runtime.controller.consume_candidate_admission(view)

        usable = await runtime.controller.issue_candidate_admission(
            runtime.candidate.candidate_id
        )
        returned = await runtime.controller.consume_candidate_admission(usable)
        assert type(returned) is ContainmentCandidateV1
        assert returned == runtime.candidate
        assert returned is not usable.candidate
        with pytest.raises(CandidateAdmissionError):
            await runtime.controller.consume_candidate_admission(usable)

        slots = tuple(
            name
            for owner in CandidateAdmissionView.__mro__
            for name, descriptor in vars(owner).items()
            if isinstance(descriptor, types.MemberDescriptorType)
            and name != "__weakref__"
        )
        assert slots
        for slot in slots:
            mutated = await runtime.controller.issue_candidate_admission(
                runtime.candidate.candidate_id
            )
            object.__setattr__(mutated, slot, object())
            with pytest.raises(CandidateAdmissionError):
                await runtime.controller.consume_candidate_admission(mutated)
            with pytest.raises(CandidateAdmissionError):
                await runtime.controller.consume_candidate_admission(mutated)
    finally:
        await runtime.close()
