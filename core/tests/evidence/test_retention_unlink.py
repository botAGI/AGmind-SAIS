from __future__ import annotations

import copy
import os
import pickle
from pathlib import Path

import pytest
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.segments import EvidenceCorrupt, EvidenceSealError
from tests.evidence.test_retention import _retention_proof_case


def _issued_case(path: Path) -> tuple[object, object]:
    case = _retention_proof_case(path)
    capability = case.store._authenticate_retention_tombstone(
        case.journal,
        case.final_snapshot,
        case.target_ref,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    return case, capability


def test_authenticated_retention_unlink_is_ordered_and_payload_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case, capability = _issued_case(tmp_path)
    state = case.journal.state
    assert state is not None
    selected_paths = tuple(
        tmp_path / entry.segment_relative_path for entry in state.entries
    )
    manifest_bytes = {
        path: path.read_bytes()
        for path in sorted((tmp_path / "manifests").iterdir())
    }
    head_bytes = (tmp_path / "chain-head.json").read_bytes()
    manifests_before = tuple(case.store._manifests)
    records_before = tuple(case.store._records)
    index_before = dict(case.store._index)
    active_before = case.store._active
    unlink_observations: list[tuple[str, bool]] = []
    original_unlink = segments_module.os.unlink

    def traced_unlink(
        name: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if os.fspath(name).endswith(".agseg"):
            current = case.journal.state
            assert current is not None
            unlink_observations.append(
                (
                    current.phase,
                    case.store._authenticated_retention_tombstone is None,
                )
            )
        original_unlink(name, dir_fd=dir_fd)

    monkeypatch.setattr(segments_module.os, "unlink", traced_unlink)
    try:
        completion = (
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
        )

        completed = case.journal.state
        assert completed is not None
        assert completed.phase == "completed"
        assert unlink_observations
        assert unlink_observations[0] == (
            "retention_unlink_in_progress",
            True,
        )
        assert all(not path.exists() for path in selected_paths)
        assert {
            path: path.read_bytes()
            for path in sorted((tmp_path / "manifests").iterdir())
        } == manifest_bytes
        assert (tmp_path / "chain-head.json").read_bytes() == head_bytes
        assert tuple(case.store._manifests) == manifests_before
        assert tuple(case.store._records) == records_before
        assert case.store._index == index_before
        assert case.store._active is active_before
        assert not hasattr(completion, "__dict__")
        with pytest.raises(TypeError, match="cop"):
            copy.copy(completion)
        with pytest.raises(TypeError, match="serial"):
            pickle.dumps(completion)
        with pytest.raises(EvidenceSealError, match="retention|registered|exact"):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
    finally:
        case.coverage.close()
        case.store.close(flush=False)


def test_authenticated_retention_unlink_retries_exact_in_progress_before_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case, capability = _issued_case(tmp_path)
    state = case.journal.state
    assert state is not None
    selected_paths = tuple(
        tmp_path / entry.segment_relative_path for entry in state.entries
    )
    journal_type = type(case.journal)
    original_prove = journal_type._prove_publication
    binding = case.store._authenticated_retention_tombstone
    assert binding is not None
    in_progress_raw = binding.unlink_in_progress_state_raw
    failed = False

    def fail_after_in_progress_publication(
        owner: object,
        expected: bytes | None,
    ) -> None:
        nonlocal failed
        original_prove(owner, expected)
        if expected == in_progress_raw and not failed:
            failed = True
            raise EvidenceSealError(
                "injected failure after durable retention intent"
            )

    monkeypatch.setattr(
        journal_type,
        "_prove_publication",
        fail_after_in_progress_publication,
    )
    try:
        with pytest.raises(EvidenceSealError, match="injected"):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )

        in_progress = case.journal.state
        assert in_progress is not None
        assert in_progress.phase == "retention_unlink_in_progress"
        assert all(path.exists() for path in selected_paths)
        assert (
            case.store._authenticated_retention_tombstone.capability
            is capability
        )

        monkeypatch.setattr(
            journal_type,
            "_prove_publication",
            original_prove,
        )
        case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        completed = case.journal.state
        assert completed is not None
        assert completed.phase == "completed"
        assert all(not path.exists() for path in selected_paths)
    finally:
        case.coverage.close()
        case.store.close(flush=False)


def test_authenticated_retention_unlink_rejects_hardlink_before_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case, capability = _issued_case(tmp_path / "root")
    state = case.journal.state
    assert state is not None
    selected = tmp_path / "root" / state.entries[0].segment_relative_path
    outside_link = tmp_path / "outside-link"
    os.link(selected, outside_link)
    payload_unlinks = 0
    original_unlink = segments_module.os.unlink

    def count_payload_unlinks(
        name: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal payload_unlinks
        if os.fspath(name).endswith(".agseg"):
            payload_unlinks += 1
        original_unlink(name, dir_fd=dir_fd)

    monkeypatch.setattr(
        segments_module.os,
        "unlink",
        count_payload_unlinks,
    )
    try:
        with pytest.raises(
            (EvidenceCorrupt, EvidenceSealError),
            match="retention|payload|evidence|unsafe",
        ):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )

        current = case.journal.state
        assert current is not None
        assert current.phase == "evidence_appended"
        assert selected.exists()
        assert outside_link.exists()
        assert payload_unlinks == 0
        assert (
            case.store._authenticated_retention_tombstone.capability
            is capability
        )
    finally:
        outside_link.unlink(missing_ok=True)
        case.coverage.close()
        case.store.close(flush=False)


@pytest.mark.parametrize("failure", ["unlink", "directory_fsync"])
def test_authenticated_retention_unlink_failure_latches_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    case, capability = _issued_case(tmp_path)
    original_unlink = segments_module.os.unlink
    original_fsync = segments_module.os.fsync
    payload_unlink_calls = 0
    payload_call_began = False
    injected = False

    def fail_payload_unlink(
        name: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal payload_unlink_calls, payload_call_began, injected
        if os.fspath(name).endswith(".agseg"):
            payload_unlink_calls += 1
            payload_call_began = True
            if failure == "unlink" and not injected:
                injected = True
                raise OSError("injected payload unlink ambiguity")
        original_unlink(name, dir_fd=dir_fd)

    def fail_directory_fsync(descriptor: int) -> None:
        nonlocal injected
        if (
            failure == "directory_fsync"
            and payload_call_began
            and descriptor != case.store._root_descriptor
            and not injected
        ):
            injected = True
            raise OSError("injected retention directory fsync ambiguity")
        original_fsync(descriptor)

    monkeypatch.setattr(segments_module.os, "unlink", fail_payload_unlink)
    monkeypatch.setattr(segments_module.os, "fsync", fail_directory_fsync)
    try:
        with pytest.raises(EvidenceCorrupt, match="retention|unlink|uncertain"):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )

        uncertain = case.journal.state
        assert uncertain is not None
        assert uncertain.phase == "retention_commit_uncertain"
        assert case.store._retention_commit_uncertain_latched is True
        calls_before_retry = payload_unlink_calls
        with pytest.raises(EvidenceSealError, match="uncertain|retention"):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
        assert payload_unlink_calls == calls_before_retry
    finally:
        case.coverage.close()
        case.store.close(flush=False)


def test_retention_unlink_uncertain_persist_failure_keeps_intent_and_latch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case, capability = _issued_case(tmp_path)
    journal_type = type(case.journal)
    original_transition = journal_type._transition
    original_unlink = segments_module.os.unlink
    payload_unlink_calls = 0

    def fail_uncertain_transition(
        owner: object,
        next_state: object,
    ) -> None:
        if (
            getattr(next_state, "phase", None)
            == "retention_commit_uncertain"
        ):
            raise EvidenceSealError(
                "injected uncertain-state persistence failure"
            )
        original_transition(owner, next_state)

    def fail_payload_unlink(
        name: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal payload_unlink_calls
        if os.fspath(name).endswith(".agseg"):
            payload_unlink_calls += 1
            raise OSError("injected payload unlink ambiguity")
        original_unlink(name, dir_fd=dir_fd)

    monkeypatch.setattr(
        journal_type,
        "_transition",
        fail_uncertain_transition,
    )
    monkeypatch.setattr(
        segments_module.os,
        "unlink",
        fail_payload_unlink,
    )
    try:
        with pytest.raises(EvidenceCorrupt, match="retention|uncertain"):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )

        retained_intent = case.journal.state
        assert retained_intent is not None
        assert retained_intent.phase == "retention_unlink_in_progress"
        assert case.store._retention_commit_uncertain_latched is True
        assert payload_unlink_calls == 1
        with pytest.raises(EvidenceSealError, match="uncertain"):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
        assert payload_unlink_calls == 1
    finally:
        case.coverage.close()
        case.store.close(flush=False)
