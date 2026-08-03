from __future__ import annotations

from agmind_immune.coverage.historical import (
    _HistoricalReductionResult,
    _reduce_historical_coverage_result,
)
from tests.coverage.test_historical import _self_close_records
from tests.coverage.test_state import T0, T1
from tests.phase5b_helpers import BOOT_A, HOST_ID

_PCC_CONTENT_HASHES = (
    "6f0db0a71c24c3a490f886bc3537a66826722e188d0557099f3b200876544e9f",
    "5db77018947a3a4163aa7e266060baaab36d48798e81937400e639bc01defa16",
    "a1384bae9bddfda5c876f0445705ccd8c63dc36849270d7b6301838f409518cc",
    "2499cb92e6358c9b0df96fefa49f87dc3f38ae8aaa0424bc33aa8d6cb2734211",
    "5b87ba53f9e0b73640689c625714de16dd2ef063d7688ccd175224d367e442fc",
    "a6bc229473ac99afadff93197592333e0841cd8cf87bde866174d7846bef7fb4",
    "6764d6251e5c2d314a9f768e3a97b4aa96087505e42990620971f3ee97604005",
    "58986446964c7f26eb5c2b44ef6a89a30c1c0836bea70a4c55bd1b9a5755e2f2",
)


def _pcc_fixture(count: int) -> dict[str, object]:
    records = tuple(_self_close_records(count))
    assert tuple(record.ref.source_sequence for record in records) == tuple(
        range(1, count + 1)
    )
    assert tuple(record.ref.content_sha256 for record in records) == _PCC_CONTENT_HASHES[
        :count
    ]
    assert len({record.ref.event_id for record in records}) == count
    return {
        "records": records,
        "host_id": HOST_ID,
        "boot_id": BOOT_A,
        "trigger_event_id": "evt_" + "6" * 64,
        "trigger_source_sequence": count,
        "trigger_event_time": T0,
        "clock_uncertainty_ms": 0,
        "coverage_through_sequence": count,
        "window_end": T1,
    }


def four_pcc_fixture() -> dict[str, object]:
    return _pcc_fixture(4)


def eight_pcc_fixture() -> dict[str, object]:
    return _pcc_fixture(8)


def test_replay_reduction_returns_immutable_ordered_leaf_facts() -> None:
    result = _reduce_historical_coverage_result(**four_pcc_fixture())
    assert type(result) is _HistoricalReductionResult
    assert type(result.timeline.intersecting_intervals) is tuple
    assert type(result.timeline.coverage_event_ids) is tuple
    assert result.interval_count == len(result.timeline.intersecting_intervals)
    assert result.event_count == len(result.timeline.coverage_event_ids)
    assert len(result.assessment_digest) == 32
    assert len(result.interval_digest) == 32
    assert len(result.event_digest) == 32
    assert len(result.semantic_digest) == 32


def test_replay_reduction_reports_exact_admin_and_semantic_work_at_four_and_eight() -> None:
    four = _reduce_historical_coverage_result(**four_pcc_fixture())
    eight = _reduce_historical_coverage_result(**eight_pcc_fixture())
    assert four.diagnostics.semantic_prefix_visits == 20
    assert eight.diagnostics.semantic_prefix_visits == 72
    assert eight.diagnostics.prepared_records == 2 * four.diagnostics.prepared_records
    assert eight.diagnostics.primary_checks == 2 * four.diagnostics.primary_checks
    assert eight.diagnostics.leaf_materializations == 2 * four.diagnostics.leaf_materializations
