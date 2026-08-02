from __future__ import annotations

import copy
import importlib
import pickle
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.evidence.test_pcc_retention_restart import _build_pcc_retention_case
from tests.evidence.test_retention_restart import _fresh_verifier


def _subject() -> Any:
    try:
        return importlib.import_module("agmind_immune.coverage.historical")
    except ModuleNotFoundError:
        pytest.fail("Task 2B historical path authority is not implemented")


def test_path_authority_is_factory_only_opaque_and_same_store_bound(
    tmp_path: Path,
) -> None:
    subject = _subject()
    case = _build_pcc_retention_case(tmp_path / "case", finalize_retention=False)
    store = SegmentStore(tmp_path / "case")
    recovered = AcceptanceCoordinator.open_and_recover(_fresh_verifier(), store)
    authenticated = recovered.authenticated_pcc_input(case.ref, case.request)

    with pytest.raises(TypeError):
        subject.HistoricalPathAuthority()
    authority = store._historical_path_authority(authenticated)
    for operation in (
        lambda: copy.copy(authority),
        lambda: copy.deepcopy(authority),
        lambda: pickle.dumps(authority),
    ):
        with pytest.raises(TypeError):
            operation()
    with pytest.raises(AttributeError):
        authority.extra = True
    coverage_package = importlib.import_module("agmind_immune.coverage")
    assert not hasattr(coverage_package, "HistoricalPathAuthority")

    result = subject.derive_historical_coverage(authenticated, authority)
    assert result.complete is True
    assert result.coverage_through_sequence == authenticated.source_sequence - 1
    original_binding = authority._binding
    object.__setattr__(
        authority,
        "_binding",
        replace(original_binding, acceptance_cursor=original_binding.acceptance_cursor + 1),
    )
    with pytest.raises(subject.HistoricalCoverageUnavailable):
        subject.derive_historical_coverage(authenticated, authority)
    object.__setattr__(authority, "_binding", original_binding)
    store.close(flush=False)
    with pytest.raises(subject.HistoricalCoverageUnavailable):
        subject.derive_historical_coverage(authenticated, authority)


def test_raw_retired_ranges_and_cross_store_authority_are_rejected(
    tmp_path: Path,
) -> None:
    subject = _subject()
    first = _build_pcc_retention_case(tmp_path / "first", finalize_retention=False)
    second = _build_pcc_retention_case(tmp_path / "second", finalize_retention=False)
    first_store = SegmentStore(tmp_path / "first")
    second_store = SegmentStore(tmp_path / "second")
    first_recovered = AcceptanceCoordinator.open_and_recover(
        _fresh_verifier(), first_store
    )
    second_recovered = AcceptanceCoordinator.open_and_recover(
        _fresh_verifier(), second_store
    )
    first_input = first_recovered.authenticated_pcc_input(first.ref, first.request)
    second_input = second_recovered.authenticated_pcc_input(second.ref, second.request)
    authority = first_store._historical_path_authority(first_input)

    with pytest.raises(TypeError):
        subject.derive_historical_coverage(first_input, ((1, 1),))
    with pytest.raises(subject.HistoricalCoverageUnavailable):
        subject.derive_historical_coverage(second_input, authority)

    first_store.close(flush=False)
    second_store.close(flush=False)
