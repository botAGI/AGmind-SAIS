from __future__ import annotations

import copy
import hashlib
import os
import pickle
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from threading import Barrier, Thread
from typing import Literal

import pytest
from agmind_immune.canonicaljson import canonical_json, release_id
from agmind_immune.clock import CoreClockSample
from agmind_immune.contracts import (
    MAX_UINT64,
    ZERO_SHA256,
    RetentionBlockedV1,
    RetentionTombstoneV2,
)
from agmind_immune.coverage import CoverageState
from agmind_immune.evidence import retention as retention_module
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.manifest import (
    SegmentManifestV1,
    chain_head_for,
    segment_manifest_hash,
)
from agmind_immune.evidence.retention import (
    RETENTION_TARGET_BYTES,
    AcceptedRetentionTombstone,
    FrozenRetentionFact,
    RetentionCorruption,
    RetentionSnapshot,
    _freeze_accepted_retention_tombstone,
    _freeze_retention_fact,
    _freeze_retention_record,
    _freeze_retention_snapshot,
    select_retention,
)
from agmind_immune.evidence.segments import (
    EvidenceCorrupt,
    EvidenceRef,
    EvidenceSealError,
    SegmentStore,
)
from agmind_immune.ingest.envelope import OuterBindingError
from agmind_immune.ingest.service import AcceptanceCoordinator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.evidence.test_projection import _falco_fields
from tests.ingest.test_retention_delivery import _bound_verifier, _item
from tests.phase5b_helpers import (
    NOW,
    envelope_value,
    private_key,
)

REQUEST_ID = "11111111-1111-4111-8111-111111111111"
OTHER_REQUEST_ID = "22222222-2222-4222-8222-222222222222"
HOST_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
DECISION_UTC = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
EXPIRED = "2026-07-22T11:59:59.999999999Z"
BOUNDARY = "2026-07-22T12:00:00Z"
FRESH = "2026-07-23T12:00:00Z"
PROOF_DECISION_UTC = datetime(2036, 7, 29, 12, 0, tzinfo=UTC)


@dataclass(frozen=True)
class _FactSpec:
    closed_at: str
    size: int
    priority: Literal["routine", "protected"] = "routine"
    event_types: tuple[str, ...] = ("falco_connect",)
    record_priorities: tuple[Literal["routine", "protected"], ...] | None = None


def _clock(
    *,
    healthy: bool = True,
    uncertainty: Decimal | None = Decimal(0),
    maximum: Decimal = Decimal(2),
) -> CoreClockSample:
    return CoreClockSample(
        decision_utc=DECISION_UTC,
        decision_monotonic=100.0,
        healthy=healthy,
        uncertainty_seconds=uncertainty,
        max_uncertainty_seconds=maximum,
    )


def _proof_clock(*, seconds: int = 0) -> CoreClockSample:
    return CoreClockSample(
        decision_utc=PROOF_DECISION_UTC + timedelta(seconds=seconds),
        decision_monotonic=100.0 + seconds,
        healthy=True,
        uncertainty_seconds=Decimal(0),
        max_uncertainty_seconds=Decimal(2),
    )


def _manifest(
    index: int,
    spec: _FactSpec,
    previous_manifest_sha256: str,
) -> SegmentManifestV1:
    sequence = index * 100 + 1
    segment_id = f"{sequence:08x}-0000-4000-8000-{sequence:012x}"
    seed = f"{sequence}|{spec!r}"
    event_hash = hashlib.sha256(f"event-{seed}".encode()).hexdigest()
    value: dict[str, object] = {
        "schema_version": "agmind.segment-manifest.v1",
        "segment_id": segment_id,
        "segment_relative_path": (
            f"segments/2026-07-01/{sequence:020d}-{segment_id}.agseg"
        ),
        "host_id": HOST_ID,
        "evidence_priority": spec.priority,
        "first_event_id": f"evt_{event_hash}",
        "last_event_id": f"evt_{event_hash}",
        "first_source_sequence": sequence,
        "last_source_sequence": sequence + len(spec.event_types) - 1,
        "record_count": len(spec.event_types),
        "opened_at": "2026-07-01T00:00:00Z",
        "closed_at": spec.closed_at,
        "segment_size_bytes": spec.size,
        "segment_sha256": hashlib.sha256(f"segment-{seed}".encode()).hexdigest(),
        "first_frame_sha256": hashlib.sha256(f"first-{seed}".encode()).hexdigest(),
        "last_frame_sha256": hashlib.sha256(f"last-{seed}".encode()).hexdigest(),
        "previous_manifest_sha256": previous_manifest_sha256,
        "manifest_sha256": ZERO_SHA256,
    }
    value["manifest_sha256"] = segment_manifest_hash(value)
    return SegmentManifestV1.model_validate(value, strict=True)


def _snapshot(
    *specs: _FactSpec,
    clock: CoreClockSample | None = None,
    prior: tuple[AcceptedRetentionTombstone, ...] = (),
    prior_index_through_sequence: int | None = None,
) -> RetentionSnapshot:
    facts: list[FrozenRetentionFact] = []
    previous = ZERO_SHA256
    for index, spec in enumerate(specs):
        manifest = _manifest(index, spec, previous)
        facts.append(
            _freeze_retention_fact(
                manifest=manifest,
                records=tuple(
                    _freeze_retention_record(
                        event_type=event_type,
                        evidence_priority=(
                            spec.priority
                            if spec.record_priorities is None
                            else spec.record_priorities[position]
                        ),
                    )
                    for position, event_type in enumerate(spec.event_types)
                ),
                original_device=100 + index,
                original_inode=1_000 + index,
            )
        )
        previous = manifest.manifest_sha256
    return _freeze_retention_snapshot(
        facts=tuple(facts),
        clock=_clock() if clock is None else clock,
        prior_tombstones=prior,
        prior_index_through_sequence=(
            max((item.sequence for item in prior), default=0)
            if prior_index_through_sequence is None
            else prior_index_through_sequence
        ),
    )


def _run_hash(manifest_hashes: list[str]) -> str:
    return hashlib.sha256(
        b"AGMIND_RETENTION_RUN_V2\x00" + canonical_json(manifest_hashes)
    ).hexdigest()


def _tombstone(
    snapshot: RetentionSnapshot,
    positions: tuple[int, ...],
    *,
    tombstone_id: str = REQUEST_ID,
) -> RetentionTombstoneV2:
    hashes = [snapshot.facts[position].manifest_sha256 for position in positions]
    last_position = positions[-1]
    successor = (
        snapshot.facts[last_position + 1].manifest_sha256
        if last_position + 1 < len(snapshot.facts)
        else ZERO_SHA256
    )
    return RetentionTombstoneV2(
        schema_version="agmind.retention-tombstone.v2",
        tombstone_id=tombstone_id,
        removed_manifest_hashes=hashes,
        first_removed_manifest_sha256=hashes[0],
        last_removed_manifest_sha256=hashes[-1],
        first_retained_manifest_sha256=successor,
        removed_bytes=sum(
            snapshot.facts[position].segment_size_bytes
            for position in positions
        ),
        reason="retention_age_limit",
        policy_version="agmind-retention-v1",
        current_chain_head_sha256=snapshot.current_chain_head_sha256,
        manifest_run_sha256=_run_hash(hashes),
    )


def _accepted(
    request: RetentionTombstoneV2,
    *,
    sequence: int = 80,
) -> AcceptedRetentionTombstone:
    return _freeze_accepted_retention_tombstone(
        sequence=sequence,
        event_id="evt_" + hashlib.sha256(f"outer-{sequence}".encode()).hexdigest(),
        content_sha256=hashlib.sha256(f"content-{sequence}".encode()).hexdigest(),
        request=request,
    )


def _selected_state(
    snapshot: RetentionSnapshot,
    *,
    request_id: str = REQUEST_ID,
) -> object:
    decision = select_retention(
        snapshot,
        request_id=request_id,
    )
    assert decision.request is not None
    return retention_module.selected_retention_state(decision)


def _live_store_with_active_routine(
    path: Path,
) -> tuple[
    Ed25519PrivateKey,
    AcceptanceCoordinator,
    SegmentStore,
    CoverageState,
]:
    key = private_key(11)
    acceptance, store, _verifier = _bound_verifier(path)
    coverage = CoverageState.open_and_recover(store)
    store.flush_security_boundary()
    raw_hash = hashlib.sha256(b"retention proof routine").hexdigest()
    routine_ref = acceptance.accept(
        _item(
            envelope_value(
                key,
                sequence=2,
                event_type="falco_connect",
                normalized_fields=_falco_fields(raw_hash),
                source_payload_hash=raw_hash,
                container_id="a" * 64,
                container_start_time=NOW,
                release_id=release_id(
                    f"sha256:{'b' * 64}",
                    "d" * 64,
                ),
                inventory_revision=2**63,
            )
        )
    )
    coverage._apply_live_accepted(store, routine_ref, None)
    return key, acceptance, store, coverage


@dataclass(frozen=True)
class _RetentionProofCase:
    store: SegmentStore
    coverage: CoverageState
    selected_snapshot: RetentionSnapshot
    final_snapshot: RetentionSnapshot
    journal: retention_module.RetentionStateJournal
    target_ref: EvidenceRef
    request: RetentionTombstoneV2


def _retention_proof_case(path: Path) -> _RetentionProofCase:
    key, acceptance, store, coverage = _live_store_with_active_routine(path)
    try:
        selected_snapshot = store._freeze_retention_snapshot(
            _proof_clock(),
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        decision = select_retention(
            selected_snapshot,
            request_id=REQUEST_ID,
        )
        assert type(decision.request) is RetentionTombstoneV2
        request = decision.request
        journal = retention_module._open_retention_state_journal(store)
        journal.prepare_publication(decision)
        target_item = _item(
            envelope_value(
                key,
                sequence=3,
                event_type="retention_tombstone",
                normalized_fields=request.model_dump(mode="python"),
            )
        )
        target_ref = acceptance.accept(target_item)
        coverage._apply_live_accepted(store, target_ref, None)
        target = retention_module.RetentionTargetV1(
            sequence=target_item.sequence,
            event_id=target_item.event_id,
            content_sha256=target_item.content_sha256,
        )
        journal.bind_target(target)
        journal.advance_evidence_appended(target)
        final_snapshot = store._freeze_retention_snapshot(
            _proof_clock(seconds=1),
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        return _RetentionProofCase(
            store=store,
            coverage=coverage,
            selected_snapshot=selected_snapshot,
            final_snapshot=final_snapshot,
            journal=journal,
            target_ref=target_ref,
            request=request,
        )
    except BaseException:
        coverage.close()
        store.close(flush=False)
        raise


def test_selection_seven_day_nanosecond_boundary_is_strict() -> None:
    snapshot = _snapshot(
        _FactSpec(BOUNDARY, 1),
        _FactSpec(EXPIRED, 1),
    )

    decision = select_retention(snapshot, request_id=REQUEST_ID)

    assert isinstance(decision.request, RetentionTombstoneV2)
    assert decision.request.removed_manifest_hashes == [
        snapshot.facts[1].manifest_sha256
    ]
    assert decision.request.first_retained_manifest_sha256 == ZERO_SHA256


def test_selection_clock_uncertainty_subtracts_and_invalid_health_disables_age() -> None:
    just_expired = "2026-07-22T11:59:59.499999999Z"
    uncertainty_boundary = "2026-07-22T11:59:59.500000000Z"
    healthy = _snapshot(
        _FactSpec(uncertainty_boundary, 1),
        _FactSpec(just_expired, 1),
        clock=_clock(uncertainty=Decimal("0.5")),
    )
    subnanosecond = _snapshot(
        _FactSpec("2026-07-22T11:59:59.999999999Z", 1),
        _FactSpec("2026-07-22T11:59:59.999999998Z", 1),
        clock=_clock(uncertainty=Decimal("0.0000000001")),
    )
    high_precision = _snapshot(
        _FactSpec("2026-07-22T11:59:59.999999998Z", 1),
        _FactSpec("2026-07-22T11:59:59.999999997Z", 1),
        clock=_clock(
            uncertainty=Decimal(
                "0.0000000010000000000000000000000000001"
            )
        ),
    )
    disabled_samples = (
        _clock(healthy=False, uncertainty=Decimal(0)),
        _clock(uncertainty=None),
        _clock(uncertainty=Decimal("2.000000001"), maximum=Decimal(2)),
    )

    selected = select_retention(healthy, request_id=REQUEST_ID)
    subnanosecond_selected = select_retention(
        subnanosecond,
        request_id=REQUEST_ID,
    )
    high_precision_selected = select_retention(
        high_precision,
        request_id=REQUEST_ID,
    )

    assert isinstance(selected.request, RetentionTombstoneV2)
    assert selected.request.removed_manifest_hashes == [
        healthy.facts[1].manifest_sha256
    ]
    assert isinstance(subnanosecond_selected.request, RetentionTombstoneV2)
    assert subnanosecond_selected.uncertainty_ns == 1
    assert subnanosecond_selected.request.removed_manifest_hashes == [
        subnanosecond.facts[1].manifest_sha256
    ]
    assert high_precision_selected.uncertainty_ns == 2
    assert isinstance(high_precision_selected.request, RetentionTombstoneV2)
    assert high_precision_selected.request.removed_manifest_hashes == [
        high_precision.facts[1].manifest_sha256
    ]
    for sample in disabled_samples:
        decision = select_retention(
            _snapshot(_FactSpec(EXPIRED, 1), clock=sample),
            request_id=REQUEST_ID,
        )
        assert decision.request is None
        size_only = select_retention(
            _snapshot(
                _FactSpec(EXPIRED, RETENTION_TARGET_BYTES + 1),
                clock=sample,
            ),
            request_id=REQUEST_ID,
        )
        assert isinstance(size_only.request, RetentionTombstoneV2)
        assert size_only.request.reason == "retention_size_limit"
    oversized = Decimal("18446744073.709551616")
    with pytest.raises(RetentionCorruption, match="uint64"):
        select_retention(
            _snapshot(
                _FactSpec(FRESH, 1),
                clock=_clock(uncertainty=oversized, maximum=oversized),
            ),
            request_id=REQUEST_ID,
        )


@pytest.mark.parametrize(
    ("size", "selected"),
    [
        (RETENTION_TARGET_BYTES, False),
        (RETENTION_TARGET_BYTES + 1, True),
    ],
)
def test_selection_binary_five_gib_boundary(size: int, selected: bool) -> None:
    decision = select_retention(
        _snapshot(_FactSpec(FRESH, size)),
        request_id=REQUEST_ID,
    )

    assert isinstance(decision.request, RetentionTombstoneV2) is selected
    if selected:
        assert decision.request.reason == "retention_size_limit"


def test_selection_unions_age_first_with_oldest_size_candidates() -> None:
    gib = 1024**3
    snapshot = _snapshot(
        _FactSpec(EXPIRED, gib),
        _FactSpec(FRESH, 3 * gib),
        _FactSpec(FRESH, 3 * gib),
    )

    decision = select_retention(snapshot, request_id=REQUEST_ID)

    assert isinstance(decision.request, RetentionTombstoneV2)
    assert decision.request.removed_manifest_hashes == [
        snapshot.facts[0].manifest_sha256,
        snapshot.facts[1].manifest_sha256,
    ]
    assert decision.request.removed_bytes == 4 * gib
    assert decision.request.reason == "retention_age_and_size_limit"


def test_selection_returns_oldest_contiguous_run_and_splits_at_128() -> None:
    gap = _snapshot(
        _FactSpec(EXPIRED, 1),
        _FactSpec(EXPIRED, 1, event_types=("future_routine",)),
        _FactSpec(EXPIRED, 1),
    )
    long = _snapshot(*(_FactSpec(EXPIRED, 1) for _ in range(129)))

    gap_decision = select_retention(gap, request_id=REQUEST_ID)
    long_decision = select_retention(long, request_id=REQUEST_ID)

    assert isinstance(gap_decision.request, RetentionTombstoneV2)
    assert gap_decision.request.removed_manifest_hashes == [
        gap.facts[0].manifest_sha256
    ]
    assert (
        gap_decision.request.first_retained_manifest_sha256
        == gap.facts[1].manifest_sha256
    )
    assert isinstance(long_decision.request, RetentionTombstoneV2)
    assert len(long_decision.request.removed_manifest_hashes) == 128
    assert (
        long_decision.request.first_retained_manifest_sha256
        == long.facts[128].manifest_sha256
    )


@pytest.mark.parametrize(
    ("specs", "reason"),
    [
        ((_FactSpec(FRESH, 1),), None),
        ((_FactSpec(EXPIRED, 1),), "retention_age_limit"),
        (
            (_FactSpec(FRESH, RETENTION_TARGET_BYTES + 1),),
            "retention_size_limit",
        ),
        (
            (
                _FactSpec(EXPIRED, 1),
                _FactSpec(FRESH, RETENTION_TARGET_BYTES),
            ),
            "retention_age_and_size_limit",
        ),
    ],
)
def test_selection_uses_global_age_size_reason_matrix(
    specs: tuple[_FactSpec, ...],
    reason: str | None,
) -> None:
    decision = select_retention(_snapshot(*specs), request_id=REQUEST_ID)

    if reason is None:
        assert decision.request is None
    else:
        assert isinstance(decision.request, RetentionTombstoneV2)
        assert decision.request.reason == reason


def test_selection_checks_uint64_aggregate_overflow() -> None:
    snapshot = _snapshot(
        _FactSpec(FRESH, MAX_UINT64, event_types=("future_routine",)),
        _FactSpec(FRESH, 1, priority="protected", event_types=("coverage",)),
    )

    with pytest.raises(RetentionCorruption, match="uint64"):
        select_retention(snapshot, request_id=REQUEST_ID)


def test_selection_allowlist_unknown_and_priority_corruption() -> None:
    removable = select_retention(
        _snapshot(_FactSpec(EXPIRED, 1, event_types=("falco_connect",))),
        request_id=REQUEST_ID,
    )
    unknown = select_retention(
        _snapshot(_FactSpec(EXPIRED, 1, event_types=("future_routine",))),
        request_id=REQUEST_ID,
    )

    assert isinstance(removable.request, RetentionTombstoneV2)
    assert unknown.request is None
    with pytest.raises(RetentionCorruption, match="protected event"):
        select_retention(
            _snapshot(
                _FactSpec(
                    EXPIRED,
                    1,
                    event_types=("coverage",),
                    record_priorities=("protected",),
                )
            ),
            request_id=REQUEST_ID,
        )


def test_selection_production_policy_is_not_module_mutable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(_FactSpec(FRESH, 2))
    assert select_retention(snapshot, request_id=REQUEST_ID).request is None

    monkeypatch.setattr(retention_module, "RETENTION_TARGET_BYTES", 1)
    monkeypatch.setattr(retention_module, "RETENTION_MAX_AGE_NS", 0)
    monkeypatch.setattr(retention_module, "RETENTION_MAX_RUN_MANIFESTS", 1)
    monkeypatch.setattr(
        retention_module,
        "RETENTION_REMOVABLE_EVENT_TYPES",
        frozenset({"falco_connect", "future_routine"}),
    )
    monkeypatch.setattr(retention_module, "_RUN_DOMAIN", b"weakened\x00")

    assert select_retention(snapshot, request_id=REQUEST_ID).request is None


def test_selection_rejects_valid_value_post_freeze_tamper() -> None:
    record_snapshot = _snapshot(
        _FactSpec(EXPIRED, 1, event_types=("future_routine",))
    )
    object.__setattr__(
        record_snapshot.facts[0].records[0],
        "event_type",
        "falco_connect",
    )
    with pytest.raises(RetentionCorruption, match="construction authority"):
        select_retention(record_snapshot, request_id=REQUEST_ID)

    h0_snapshot = _snapshot(_FactSpec(FRESH, 1))
    object.__setattr__(
        h0_snapshot.facts[0],
        "prefix_chain_head_sha256",
        "f" * 64,
    )
    with pytest.raises(RetentionCorruption, match="construction authority"):
        _ = h0_snapshot.current_chain_head_sha256

    clock_snapshot = _snapshot(_FactSpec(BOUNDARY, 1))
    object.__setattr__(
        clock_snapshot.clock,
        "decision_utc",
        DECISION_UTC + timedelta(microseconds=1),
    )
    with pytest.raises(RetentionCorruption, match="construction authority"):
        select_retention(clock_snapshot, request_id=REQUEST_ID)

    recipient = _snapshot(_FactSpec(FRESH, 1))
    donor = _snapshot(_FactSpec(EXPIRED, 1))
    object.__setattr__(recipient, "facts", donor.facts)
    with pytest.raises(RetentionCorruption, match="construction authority"):
        select_retention(recipient, request_id=REQUEST_ID)

    base = _snapshot(_FactSpec(EXPIRED, 1))
    accepted = _accepted(_tombstone(base, (0,)))
    prior_snapshot = _snapshot(_FactSpec(EXPIRED, 1), prior=(accepted,))
    object.__setattr__(accepted, "sequence", 81)
    with pytest.raises(RetentionCorruption, match="construction authority"):
        select_retention(prior_snapshot, request_id=OTHER_REQUEST_ID)

    decision = select_retention(
        _snapshot(_FactSpec(EXPIRED, 1)),
        request_id=REQUEST_ID,
    )
    run = decision.run
    assert run is not None
    with pytest.raises(AttributeError):
        object.__setattr__(run, "removed_bytes", 999)
    object.__setattr__(run, "_removed_bytes", 999)
    with pytest.raises(RetentionCorruption, match="construction authority"):
        _ = decision.request

    noncanonical = select_retention(
        _snapshot(_FactSpec(EXPIRED, 1)),
        request_id=REQUEST_ID,
    )
    assert noncanonical._request_canonical is not None
    object.__setattr__(
        noncanonical,
        "_request_canonical",
        b" " + noncanonical._request_canonical,
    )
    with pytest.raises(RetentionCorruption, match="construction authority"):
        _ = noncanonical.request


def test_selection_prior_exact_retry_is_idempotent() -> None:
    base = _snapshot(_FactSpec(EXPIRED, 1))
    accepted = _accepted(_tombstone(base, (0,)))
    snapshot = _snapshot(
        _FactSpec(EXPIRED, 1),
        prior=(accepted, _accepted(accepted.request)),
    )

    decision = select_retention(snapshot, request_id=OTHER_REQUEST_ID)

    assert decision.request is None
    assert decision.routine_bytes == 0
    assert decision.protected_bytes == 0


def test_selection_prior_historical_h0_allows_append_only_suffix() -> None:
    spec = _FactSpec(EXPIRED, 1)
    historical = _snapshot(spec)
    historical_manifest = _manifest(0, spec, ZERO_SHA256)
    expected_h0 = hashlib.sha256(
        canonical_json(chain_head_for(historical_manifest))
    ).hexdigest()
    assert historical.current_chain_head_sha256 == expected_h0
    historical_request = _tombstone(historical, (0,))
    assert historical_request.first_retained_manifest_sha256 == ZERO_SHA256
    accepted = _accepted(historical_request)
    extended = _snapshot(
        spec,
        _FactSpec(EXPIRED, 1),
        prior=(accepted,),
    )

    decision = select_retention(extended, request_id=OTHER_REQUEST_ID)

    assert isinstance(decision.request, RetentionTombstoneV2)
    assert decision.request.removed_manifest_hashes == [
        extended.facts[1].manifest_sha256
    ]

    unknown_h0 = historical_request.model_dump(mode="python")
    unknown_h0["current_chain_head_sha256"] = "f" * 64
    with pytest.raises(RetentionCorruption, match="historical prefix"):
        select_retention(
            _snapshot(
                spec,
                _FactSpec(EXPIRED, 1),
                prior=(
                    _accepted(
                        RetentionTombstoneV2.model_validate(
                            unknown_h0,
                            strict=True,
                        )
                    ),
                ),
            ),
            request_id=OTHER_REQUEST_ID,
        )

    wrong_successor = historical_request.model_dump(mode="python")
    wrong_successor["first_retained_manifest_sha256"] = (
        extended.facts[1].manifest_sha256
    )
    with pytest.raises(RetentionCorruption, match="historical prefix"):
        select_retention(
            _snapshot(
                spec,
                _FactSpec(EXPIRED, 1),
                prior=(
                    _accepted(
                        RetentionTombstoneV2.model_validate(
                            wrong_successor,
                            strict=True,
                        )
                    ),
                ),
            ),
            request_id=OTHER_REQUEST_ID,
        )


def test_selection_prior_retry_requires_same_authenticated_outer_identity() -> None:
    base = _snapshot(_FactSpec(EXPIRED, 1))
    request = _tombstone(base, (0,))

    with pytest.raises(RetentionCorruption, match="outer identity"):
        select_retention(
            _snapshot(
                _FactSpec(EXPIRED, 1),
                prior=(
                    _accepted(request),
                    _accepted(request, sequence=81),
                ),
            ),
            request_id=OTHER_REQUEST_ID,
        )


def test_selection_rejects_prior_overlap_and_same_id_conflict() -> None:
    base = _snapshot(_FactSpec(EXPIRED, 1), _FactSpec(EXPIRED, 1))
    first = _tombstone(base, (0,))
    overlap = _tombstone(base, (0,), tombstone_id=OTHER_REQUEST_ID)
    conflict = _tombstone(base, (1,), tombstone_id=REQUEST_ID)

    with pytest.raises(RetentionCorruption, match="overlap"):
        select_retention(
            _snapshot(
                _FactSpec(EXPIRED, 1),
                _FactSpec(EXPIRED, 1),
                prior=(_accepted(first), _accepted(overlap, sequence=81)),
            ),
            request_id=OTHER_REQUEST_ID,
        )
    with pytest.raises(RetentionCorruption, match="conflict"):
        select_retention(
            _snapshot(
                _FactSpec(EXPIRED, 1),
                _FactSpec(EXPIRED, 1),
                prior=(_accepted(first), _accepted(conflict, sequence=81)),
            ),
            request_id=OTHER_REQUEST_ID,
        )


def test_selection_rejects_disjoint_prior_runs_out_of_manifest_order() -> None:
    base = _snapshot(
        _FactSpec(EXPIRED, 1),
        _FactSpec(EXPIRED, 1),
        _FactSpec(EXPIRED, 1),
    )

    with pytest.raises(RetentionCorruption, match="order"):
        select_retention(
            _snapshot(
                _FactSpec(EXPIRED, 1),
                _FactSpec(EXPIRED, 1),
                _FactSpec(EXPIRED, 1),
                prior=(
                    _accepted(_tombstone(base, (2,)), sequence=80),
                    _accepted(
                        _tombstone(
                            base,
                            (0,),
                            tombstone_id=OTHER_REQUEST_ID,
                        ),
                        sequence=81,
                    ),
                ),
            ),
            request_id=OTHER_REQUEST_ID,
        )


@pytest.mark.parametrize(
    ("priority", "events", "routine_bytes", "protected_bytes"),
    [
        ("protected", ("coverage",), 0, RETENTION_TARGET_BYTES + 17),
        ("routine", ("future_routine",), RETENTION_TARGET_BYTES + 17, 0),
    ],
)
def test_selection_blocked_arithmetic_is_exact_and_reason_is_canonical(
    priority: Literal["routine", "protected"],
    events: tuple[str, ...],
    routine_bytes: int,
    protected_bytes: int,
) -> None:
    decision = select_retention(
        _snapshot(
            _FactSpec(
                FRESH,
                RETENTION_TARGET_BYTES + 17,
                priority=priority,
                event_types=events,
            )
        ),
        request_id=REQUEST_ID,
    )

    assert isinstance(decision.request, RetentionBlockedV1)
    assert decision.request.target_bytes == RETENTION_TARGET_BYTES
    assert decision.request.routine_bytes == routine_bytes
    assert decision.request.protected_bytes == protected_bytes
    assert decision.request.blocked_bytes == 17
    assert decision.request.reason == "protected_evidence"


def test_selection_age_only_protected_pressure_does_not_fabricate_blocked() -> None:
    decision = select_retention(
        _snapshot(
            _FactSpec(
                EXPIRED,
                1,
                priority="protected",
                event_types=("coverage",),
            )
        ),
        request_id=REQUEST_ID,
    )

    assert decision.request is None


def test_state_selection_witness_is_canonical_bounded_and_complete() -> None:
    base = _snapshot(
        _FactSpec(EXPIRED, 3),
        _FactSpec(EXPIRED, 5),
    )
    prior = _accepted(_tombstone(base, (0,)))
    snapshot = _snapshot(
        _FactSpec(EXPIRED, 3),
        _FactSpec(EXPIRED, 5),
        prior=(prior,),
        prior_index_through_sequence=90,
    )
    decision = select_retention(
        snapshot,
        request_id=OTHER_REQUEST_ID,
    )
    state = retention_module.selected_retention_state(decision)

    request = prior.request
    index_record = canonical_json(
        {
            "sequence": prior.sequence,
            "event_id": prior.event_id,
            "content_sha256": prior.content_sha256,
            "tombstone_id": request.tombstone_id,
            "h0": request.current_chain_head_sha256,
            "first_removed_manifest_sha256": (
                request.first_removed_manifest_sha256
            ),
            "last_removed_manifest_sha256": (
                request.last_removed_manifest_sha256
            ),
            "first_retained_manifest_sha256": (
                request.first_retained_manifest_sha256
            ),
            "removed_manifest_count": len(request.removed_manifest_hashes),
            "removed_bytes": request.removed_bytes,
            "manifest_run_sha256": request.manifest_run_sha256,
        }
    )
    expected_index = hashlib.sha256(
        b"agmind.retention-prior-index.v1\0"
        + len(index_record).to_bytes(8, "big")
        + index_record
    ).hexdigest()
    raw = retention_module.encode_retention_state(state)

    assert len(raw) <= 128 * 1024
    assert retention_module.decode_retention_state(raw) == state
    assert state.phase == "selected"
    assert state.target is None
    assert state.selection_witness.policy_version == "agmind-retention-v1"
    assert state.selection_witness.maximum_age_ns == 7 * 24 * 60 * 60 * 10**9
    assert state.selection_witness.target_bytes == 5 * 1024**3
    assert state.selection_witness.maximum_run_manifests == 128
    assert state.selection_witness.removable_event_types == ["falco_connect"]
    assert state.selection_witness.prior_index_count == 1
    assert state.selection_witness.prior_index_through_sequence == 90
    assert state.selection_witness.prior_index_sha256 == expected_index
    assert decision.prior_index_sha256 == expected_index
    assert state.entries[0].original_device == snapshot.facts[1].original_device
    assert state.entries[0].original_inode == snapshot.facts[1].original_inode

    with pytest.raises(retention_module.RetentionStateCorrupt, match="canonical"):
        retention_module.decode_retention_state(raw + b"\n")
    with pytest.raises(retention_module.RetentionStateCorrupt, match="128 KiB"):
        retention_module.decode_retention_state(b"x" * (128 * 1024 + 1))


def test_state_target_binding_historical_advance_and_exact_cas(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(_FactSpec(EXPIRED, 5))
    decision = select_retention(snapshot, request_id=REQUEST_ID)
    selected = retention_module.selected_retention_state(decision)
    target = retention_module.RetentionTargetV1(
        sequence=81,
        event_id="evt_" + "a" * 64,
        content_sha256="b" * 64,
    )
    other_target = retention_module.RetentionTargetV1(
        sequence=81,
        event_id="evt_" + "c" * 64,
        content_sha256="d" * 64,
    )
    bound = retention_module.bind_retention_target(selected, target)
    appended = retention_module.advance_retention_evidence_appended(
        bound,
        target,
    )
    historical = retention_module.advance_retention_evidence_appended(
        selected,
        target,
    )

    assert bound.phase == "target_bound"
    assert appended.phase == "evidence_appended"
    assert historical == appended
    with pytest.raises(retention_module.RetentionProtocolError, match="target"):
        retention_module.advance_retention_evidence_appended(
            bound,
            other_target,
        )

    store = SegmentStore(tmp_path)
    journal = retention_module._open_retention_state_journal(store)
    reopened = retention_module._open_retention_state_journal(store)
    body = journal.prepare_publication(decision)
    durable = (tmp_path / "retention-state.json").read_bytes()

    assert retention_module.decode_retention_state(durable) == selected
    assert reopened is journal
    assert body == canonical_json(selected.request.model_dump(mode="python"))
    assert journal.prepare_publication(decision) == body
    journal.bind_target(target)
    journal.bind_target(target)
    mutated_document = bound.model_dump(exclude_none=False)
    mutated_document["entries"][0]["original_inode"] += 1
    mutated = retention_module.RetentionStateV1.model_validate(
        mutated_document,
        strict=True,
    )
    with pytest.raises(
        retention_module.RetentionProtocolError,
        match="immutable",
    ):
        journal._transition(mutated)
    skipped_document = bound.model_dump(exclude_none=False)
    skipped_document["phase"] = "completed"
    skipped = retention_module.RetentionStateV1.model_validate(
        skipped_document,
        strict=True,
    )
    with pytest.raises(
        retention_module.RetentionProtocolError,
        match="transition",
    ):
        journal._transition(skipped)
    with pytest.raises(retention_module.RetentionStateConflict, match="CAS"):
        journal._authority.replace_retention_state_bytes(
            retention_module.encode_retention_state(selected),
            retention_module.encode_retention_state(appended),
        )
    with pytest.raises(retention_module.RetentionProtocolError, match="transition"):
        journal.prepare_publication(decision)
    with pytest.raises(TypeError, match="copied"):
        copy.copy(journal)
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(journal)
    assert not hasattr(journal, "clear")
    assert not hasattr(journal, "path")
    store.close(flush=False)


def test_state_publication_retries_only_exact_durable_body(tmp_path: Path) -> None:
    snapshot = _snapshot(_FactSpec(EXPIRED, 5))
    decision = select_retention(snapshot, request_id=REQUEST_ID)
    conflicting = select_retention(snapshot, request_id=OTHER_REQUEST_ID)
    selected = retention_module.selected_retention_state(decision)
    store = SegmentStore(tmp_path)
    journal = retention_module._open_retention_state_journal(store)

    first = journal.prepare_publication(decision)
    second = journal.prepare_publication(decision)

    assert first == second
    with pytest.raises(retention_module.RetentionStateConflict, match="request"):
        journal.prepare_publication(conflicting)
    with pytest.raises(TypeError, match="decision"):
        journal.prepare_publication(
            retention_module.decode_retention_state(
                retention_module.encode_retention_state(selected)
            )
        )
    assert (tmp_path / "retention-state.json").read_bytes() == (
        retention_module.encode_retention_state(selected)
    )
    store.close(flush=False)


def test_state_temp_namespace_is_discarded_without_promotion(
    tmp_path: Path,
) -> None:
    selected = _selected_state(_snapshot(_FactSpec(EXPIRED, 5)))
    selected_raw = retention_module.encode_retention_state(selected)
    temporary_name = (
        ".retention-state.json."
        "33333333-3333-4333-8333-333333333333.tmp"
    )

    temp_only = tmp_path / "temp-only"
    temp_only.mkdir(mode=0o700)
    store = SegmentStore(temp_only)
    store.close(flush=False)
    temporary = temp_only / temporary_name
    temporary.write_bytes(b'{"partial":')
    temporary.chmod(0o600)

    recovered = SegmentStore(temp_only)
    assert not temporary.exists()
    assert retention_module._open_retention_state_journal(recovered).state is None
    recovered.close(flush=False)

    final_and_temp = tmp_path / "final-and-temp"
    final_and_temp.mkdir(mode=0o700)
    store = SegmentStore(final_and_temp)
    store.close(flush=False)
    final = final_and_temp / "retention-state.json"
    final.write_bytes(selected_raw)
    final.chmod(0o600)
    temporary = final_and_temp / temporary_name
    temporary.write_bytes(b'{"partial":')
    temporary.chmod(0o600)

    recovered = SegmentStore(final_and_temp)
    assert not temporary.exists()
    assert final.read_bytes() == selected_raw
    assert retention_module._open_retention_state_journal(recovered).state == selected
    recovered.close(flush=False)

    multiple = tmp_path / "multiple"
    multiple.mkdir(mode=0o700)
    store = SegmentStore(multiple)
    store.close(flush=False)
    for request_id in (REQUEST_ID, OTHER_REQUEST_ID):
        path = multiple / f".retention-state.json.{request_id}.tmp"
        path.write_bytes(b"")
        path.chmod(0o600)
    with pytest.raises(EvidenceCorrupt, match="multiple retention-state"):
        SegmentStore(multiple)


def test_state_unbound_temporary_appearing_after_open_is_rejected(
    tmp_path: Path,
) -> None:
    decision = select_retention(
        _snapshot(_FactSpec(EXPIRED, 5)),
        request_id=REQUEST_ID,
    )
    store = SegmentStore(tmp_path)
    journal = retention_module._open_retention_state_journal(store)
    temporary = (
        tmp_path
        / ".retention-state.json."
        "33333333-3333-4333-8333-333333333333.tmp"
    )
    temporary.write_bytes(b'{"foreign":true}')
    temporary.chmod(0o600)

    with pytest.raises(EvidenceCorrupt, match="unbound retention-state temporary"):
        journal.prepare_publication(decision)

    store.close(flush=False)


@pytest.mark.parametrize("artifact_kind", ["final", "temporary"])
@pytest.mark.parametrize("attack", ["mode", "type", "link", "oversize"])
def test_state_startup_rejects_unsafe_final_and_temporary_artifacts(
    tmp_path: Path,
    artifact_kind: str,
    attack: str,
) -> None:
    root = tmp_path / f"{artifact_kind}-{attack}"
    store = SegmentStore(root)
    store.close(flush=False)
    name = (
        "retention-state.json"
        if artifact_kind == "final"
        else (
            ".retention-state.json."
            "33333333-3333-4333-8333-333333333333.tmp"
        )
    )
    artifact = root / name
    if attack == "type":
        artifact.mkdir(mode=0o700)
    elif attack == "link":
        source = tmp_path / f"{artifact_kind}-{attack}-source"
        source.write_bytes(b"{}")
        source.chmod(0o600)
        os.link(source, artifact)
    else:
        artifact.write_bytes(
            b"x" * (128 * 1024 + 1)
            if attack == "oversize"
            else b"{}"
        )
        artifact.chmod(0o644 if attack == "mode" else 0o600)

    with pytest.raises(
        EvidenceCorrupt,
        match="unsafe evidence file|exceeds 128 KiB",
    ):
        SegmentStore(root)


def test_state_cas_destination_swap_keeps_valid_new_final_and_fences(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(_FactSpec(EXPIRED, 5))
    decision = select_retention(snapshot, request_id=REQUEST_ID)
    selected = retention_module.selected_retention_state(decision)
    target = retention_module.RetentionTargetV1(
        sequence=81,
        event_id="evt_" + "a" * 64,
        content_sha256="b" * 64,
    )
    expected_new = retention_module.encode_retention_state(
        retention_module.bind_retention_target(selected, target)
    )
    store = SegmentStore(tmp_path)
    journal = retention_module._open_retention_state_journal(store)
    journal.prepare_publication(decision)
    foreign_name = ".adversarial-retention-state"
    hidden_old_name = ".adversarial-held-old-retention-state"
    foreign = tmp_path / foreign_name
    foreign_raw = b'{"foreign":true}'
    foreign.write_bytes(foreign_raw)
    foreign.chmod(0o600)
    original_exchange = segments_module._rename_exchange

    def exchange_after_destination_swap(
        left_name: str,
        right_name: str,
        *,
        parent_descriptor: int,
    ) -> None:
        os.rename(
            right_name,
            hidden_old_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.rename(
            foreign_name,
            right_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        original_exchange(
            left_name,
            right_name,
            parent_descriptor=parent_descriptor,
        )

    monkeypatch.setattr(
        segments_module,
        "_rename_exchange",
        exchange_after_destination_swap,
    )

    with pytest.raises(EvidenceCorrupt, match="namespace is uncertain"):
        journal.bind_target(target)

    assert (tmp_path / "retention-state.json").read_bytes() == expected_new
    assert (tmp_path / "retention-state.json").read_bytes() != foreign_raw
    with pytest.raises(EvidenceSealError, match="exact store lifecycle"):
        journal.bind_target(target)

    store.close(flush=False)


def test_state_root_fsync_ambiguity_fences_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(_FactSpec(EXPIRED, 5))
    decision = select_retention(snapshot, request_id=REQUEST_ID)
    target = retention_module.RetentionTargetV1(
        sequence=81,
        event_id="evt_" + "a" * 64,
        content_sha256="b" * 64,
    )
    store = SegmentStore(tmp_path)
    journal = retention_module._open_retention_state_journal(store)
    journal.prepare_publication(decision)
    original_fsync = segments_module.os.fsync
    failed = False

    def fail_first_root_fsync(descriptor: int) -> None:
        nonlocal failed
        if descriptor == store._root_descriptor and not failed:
            failed = True
            raise OSError("injected root fsync ambiguity")
        original_fsync(descriptor)

    monkeypatch.setattr(segments_module.os, "fsync", fail_first_root_fsync)

    with pytest.raises(EvidenceCorrupt, match="namespace became uncertain"):
        journal.bind_target(target)

    assert failed
    with pytest.raises(EvidenceSealError, match="exact store lifecycle"):
        journal.bind_target(target)

    monkeypatch.setattr(segments_module.os, "fsync", original_fsync)
    store.close(flush=False)


@pytest.mark.parametrize("attack", ["none", "manifest", "payload"])
def test_retention_proof_snapshot_is_factory_only_and_jit_reverifies(
    tmp_path: Path,
    attack: str,
) -> None:
    _key, _acceptance, store, coverage = _live_store_with_active_routine(
        tmp_path
    )
    try:
        active_before = store.active_path
        manifests_before = store.manifests
        assert active_before is not None
        with pytest.raises(TypeError, match="factory"):
            store._freeze_retention_snapshot(
                _proof_clock(),
                _factory=object(),
            )
        assert store.active_path == active_before
        assert store.manifests == manifests_before
        if attack == "none":
            snapshot = store._freeze_retention_snapshot(
                _proof_clock(),
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
            assert store.active_path is None
            assert tuple(
                fact.manifest_sha256 for fact in snapshot.facts
            ) == tuple(
                manifest.manifest_sha256 for manifest in store.manifests
            )
            assert tuple(
                record.event_type for record in snapshot.facts[-1].records
            ) == ("falco_connect",)
            return

        store.flush_security_boundary()
        manifest = store.manifests[-1]
        if attack == "manifest":
            manifest_path = (
                tmp_path / "manifests" / f"{manifest.segment_id}.json"
            )
            manifest_path.write_bytes(manifest_path.read_bytes() + b"\n")
        else:
            payload_path = tmp_path / manifest.segment_relative_path
            raw = payload_path.read_bytes()
            payload_path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])

        with pytest.raises(EvidenceCorrupt, match="manifest|segment|payload"):
            store._freeze_retention_snapshot(
                _proof_clock(),
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
    finally:
        coverage.close()
        store.close(flush=False)


def test_retention_proof_accepts_h0_extension_and_exact_target(
    tmp_path: Path,
) -> None:
    case = _retention_proof_case(tmp_path)
    try:
        assert (
            case.request.current_chain_head_sha256
            == case.selected_snapshot.current_chain_head_sha256
        )
        assert (
            case.final_snapshot.current_chain_head_sha256
            != case.request.current_chain_head_sha256
        )
        assert (
            case.final_snapshot.facts[1].prefix_chain_head_sha256
            == case.request.current_chain_head_sha256
        )
        with pytest.raises(TypeError, match="snapshot"):
            case.store._authenticate_retention_tombstone(
                case.journal,
                case.store.manifests,
                case.target_ref,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
        with pytest.raises(EvidenceSealError, match="target|authenticated"):
            case.store._authenticate_retention_tombstone(
                case.journal,
                case.final_snapshot,
                replace(case.target_ref, content_sha256="0" * 64),
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )

        capability = case.store._authenticate_retention_tombstone(
            case.journal,
            case.final_snapshot,
            case.target_ref,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )

        assert type(capability).__name__ == "AuthenticatedRetentionTombstone"
        assert (
            case.store.resolve_authenticated_ref(case.target_ref).ref
            == case.target_ref
        )
    finally:
        case.coverage.close()
        case.store.close(flush=False)


@pytest.mark.parametrize(
    "attack",
    ["stale_snapshot", "mutated_fact", "selector_witness"],
)
def test_retention_proof_rejects_stale_or_mutated_authority(
    tmp_path: Path,
    attack: str,
) -> None:
    case = _retention_proof_case(tmp_path)
    candidate = case.final_snapshot
    try:
        if attack == "stale_snapshot":
            candidate = case.selected_snapshot
        elif attack == "mutated_fact":
            fact = candidate.facts[1]
            object.__setattr__(
                fact,
                "original_inode",
                fact.original_inode + 1,
            )
        else:
            state = case.journal.state
            assert state is not None
            document = state.model_dump(exclude_none=False)
            witness = document["selection_witness"]
            assert isinstance(witness, dict)
            witness["decision_utc"] = "2026-07-20T12:00:00Z"
            mutated = retention_module.RetentionStateV1.model_validate(
                document,
                strict=True,
            )
            expected = case.journal._raw
            assert expected is not None
            mutated_raw = retention_module.encode_retention_state(mutated)
            case.journal._authority.replace_retention_state_bytes(
                expected,
                mutated_raw,
            )
            case.journal._state = mutated
            case.journal._raw = mutated_raw

        with pytest.raises(
            (EvidenceSealError, RetentionCorruption),
            match="snapshot|stale|generation|authority|selector|witness",
        ):
            case.store._authenticate_retention_tombstone(
                case.journal,
                candidate,
                case.target_ref,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
    finally:
        case.coverage.close()
        case.store.close(flush=False)


def test_authenticated_retention_tombstone_is_registered_and_one_use(
    tmp_path: Path,
) -> None:
    case = _retention_proof_case(tmp_path / "owner")
    foreign = SegmentStore(tmp_path / "foreign")
    try:
        capability = case.store._authenticate_retention_tombstone(
            case.journal,
            case.final_snapshot,
            case.target_ref,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        assert not hasattr(capability, "__dict__")
        for authority_name in (
            "_coverage",
            "_coverage_snapshot",
            "_coverage_token",
            "_journal",
            "_journal_identity",
            "_snapshot",
            "_state_raw",
            "_status",
            "_store",
            "_target_ref",
            "_transient_generation",
            "_used",
            "_verifier",
            "_verifier_authority",
            "_verifier_generation",
        ):
            assert not hasattr(capability, authority_name)
        with pytest.raises(TypeError, match="cop"):
            copy.copy(capability)
        with pytest.raises(TypeError, match="cop"):
            copy.deepcopy(capability)
        with pytest.raises(TypeError, match="serial"):
            pickle.dumps(capability)
        lookalike = object.__new__(type(capability))
        with pytest.raises(EvidenceSealError, match="issued|registered|exact"):
            case.store._consume_authenticated_retention_tombstone(
                lookalike,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
        with pytest.raises(EvidenceSealError, match="store|lifecycle|registered"):
            foreign._consume_authenticated_retention_tombstone(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
        with pytest.raises(TypeError, match="factory"):
            case.store._consume_authenticated_retention_tombstone(
                capability,
                _factory=object(),
            )

        assert (
            case.store._consume_authenticated_retention_tombstone(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
            is None
        )
        with pytest.raises(EvidenceSealError, match="used|registered|exact"):
            case.store._consume_authenticated_retention_tombstone(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
    finally:
        foreign.close(flush=False)
        case.coverage.close()
        case.store.close(flush=False)


def test_authenticated_retention_tombstone_concurrent_consumers_claim_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _retention_proof_case(tmp_path)
    capability = case.store._authenticate_retention_tombstone(
        case.journal,
        case.final_snapshot,
        case.target_ref,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    loaded_binding = Barrier(2)
    original_type = type

    def synchronized_type(value: object) -> type[object]:
        if value is capability:
            loaded_binding.wait(timeout=5)
        return original_type(value)

    monkeypatch.setattr(
        segments_module,
        "type",
        synchronized_type,
        raising=False,
    )
    results: list[BaseException | None] = []

    def consume() -> None:
        try:
            case.store._consume_authenticated_retention_tombstone(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
        except EvidenceSealError as error:
            results.append(error)
        else:
            results.append(None)

    consumers = (Thread(target=consume), Thread(target=consume))
    try:
        for consumer in consumers:
            consumer.start()
        for consumer in consumers:
            consumer.join(timeout=10)

        assert all(not consumer.is_alive() for consumer in consumers)
        assert sum(result is None for result in results) == 1
        failures = [result for result in results if result is not None]
        assert len(failures) == 1
        assert isinstance(failures[0], EvidenceSealError)
    finally:
        case.coverage.close()
        case.store.close(flush=False)


def test_authenticated_retention_tombstone_stale_owner_failure_burns_claim(
    tmp_path: Path,
) -> None:
    case = _retention_proof_case(tmp_path)
    capability = case.store._authenticate_retention_tombstone(
        case.journal,
        case.final_snapshot,
        case.target_ref,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    verifier = case.store._bound_verifier
    assert verifier is not None
    original_transient = verifier._repair_transient_generation
    verifier._repair_transient_generation += 1
    try:
        with pytest.raises(EvidenceSealError, match="authority"):
            case.store._consume_authenticated_retention_tombstone(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
        verifier._repair_transient_generation = original_transient
        with pytest.raises(EvidenceSealError, match="registered"):
            case.store._consume_authenticated_retention_tombstone(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
    finally:
        verifier._repair_transient_generation = original_transient
        case.coverage.close()
        case.store.close(flush=False)


def test_retention_proof_directory_rebind_rejects_root_rename_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    _key, _acceptance, store, coverage = _live_store_with_active_routine(root)
    parked = tmp_path / "parked"
    replacement = tmp_path / "replacement"
    replacement.mkdir(mode=0o700)
    (replacement / "manifests").mkdir(mode=0o700)
    (replacement / "segments").mkdir(mode=0o700)
    original_reopen = segments_module._reopen_root_directory
    swapped = False

    def reopen_then_swap(path: Path) -> int:
        nonlocal swapped
        descriptor = original_reopen(path)
        if not swapped:
            root.rename(parked)
            replacement.rename(root)
            swapped = True
        return descriptor

    monkeypatch.setattr(
        segments_module,
        "_reopen_root_directory",
        reopen_then_swap,
    )
    try:
        with pytest.raises(EvidenceCorrupt, match="root changed"):
            store._require_retention_directory_bindings()
    finally:
        coverage.close()
        store.close(flush=False)
        if swapped:
            (root / "manifests").rmdir()
            (root / "segments").rmdir()
            root.rmdir()
            parked.rename(root)


def test_retention_proof_rejects_equal_distinct_accepted_ref_substitution(
    tmp_path: Path,
) -> None:
    case = _retention_proof_case(tmp_path)
    verifier = case.store._bound_verifier
    assert verifier is not None
    accepted = verifier._authority.accepted[
        case.target_ref.source_sequence
    ]
    original_ref = accepted.evidence_ref
    substitute = replace(case.target_ref)
    assert substitute == original_ref
    assert substitute is not original_ref
    object.__setattr__(accepted, "evidence_ref", substitute)
    try:
        with pytest.raises(EvidenceSealError, match="authority"):
            case.store._require_retention_snapshot(case.final_snapshot)
    finally:
        object.__setattr__(accepted, "evidence_ref", original_ref)
        case.coverage.close()
        case.store.close(flush=False)


def test_retention_proof_snapshot_rejects_preissuance_equal_distinct_ref(
    tmp_path: Path,
) -> None:
    _key, _acceptance, store, coverage = _live_store_with_active_routine(
        tmp_path
    )
    verifier = store._bound_verifier
    assert verifier is not None
    accepted = verifier._authority.accepted[2]
    original_ref = accepted.evidence_ref
    assert type(original_ref) is EvidenceRef
    substitute = replace(original_ref)
    assert substitute == original_ref
    assert substitute is not original_ref
    object.__setattr__(accepted, "evidence_ref", substitute)
    try:
        with pytest.raises(EvidenceCorrupt, match="verifier authority"):
            store._freeze_retention_snapshot(
                _proof_clock(),
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
    finally:
        object.__setattr__(accepted, "evidence_ref", original_ref)
        coverage.close()
        store.close(flush=False)


def test_retention_proof_chain_length_race_is_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _key, _acceptance, store, coverage = _live_store_with_active_routine(
        tmp_path
    )
    original_read = store._read_retention_manifest_chain
    reads = 0

    def lengthened_chain() -> tuple[
        tuple[SegmentManifestV1, ...],
        tuple[bytes, ...],
    ]:
        nonlocal reads
        chain, canonical = original_read()
        reads += 1
        if reads == 2:
            return chain + (chain[-1],), canonical + (canonical[-1],)
        return chain, canonical

    monkeypatch.setattr(
        store,
        "_read_retention_manifest_chain",
        lengthened_chain,
    )
    try:
        with pytest.raises(EvidenceSealError, match="authority changed"):
            store._freeze_retention_snapshot(
                _proof_clock(),
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
    finally:
        coverage.close()
        store.close(flush=False)


def test_retention_proof_replay_validation_failure_is_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _retention_proof_case(tmp_path)
    verifier = case.store._bound_verifier
    assert verifier is not None

    def invalid_replay(*_args: object, **_kwargs: object) -> None:
        raise OuterBindingError("injected replay validation failure")

    monkeypatch.setattr(
        type(verifier),
        "_restricted_historical_retention_replay",
        invalid_replay,
    )
    try:
        with pytest.raises(EvidenceSealError, match="historical replay"):
            case.store._authenticate_retention_tombstone(
                case.journal,
                case.final_snapshot,
                case.target_ref,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
    finally:
        case.coverage.close()
        case.store.close(flush=False)


def test_retention_proof_rejects_malformed_protected_blocked_prior(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _retention_proof_case(tmp_path)
    verifier = case.store._bound_verifier
    assert verifier is not None
    original_scan = case.store._retention_scanned_record

    def malformed_blocked(
        record: object,
        exact_verifier: object,
    ) -> object:
        envelope = original_scan(record, exact_verifier)
        if record.ref == case.target_ref:
            return envelope.model_copy(
                update={
                    "event_type": "retention_blocked_priority_evidence",
                    "normalized_fields": {
                        "schema_version": "agmind.retention-blocked.v1",
                        "blocked_id": "not-a-uuid",
                    },
                }
            )
        return envelope

    monkeypatch.setattr(
        case.store,
        "_retention_scanned_record",
        malformed_blocked,
    )
    try:
        with pytest.raises(EvidenceCorrupt, match="blocked record is invalid"):
            case.store._retention_prior_tombstones(
                verifier,
                through_sequence=case.target_ref.source_sequence,
            )
    finally:
        case.coverage.close()
        case.store.close(flush=False)


def test_retention_proof_rejects_transient_verifier_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _key, _acceptance, store, coverage = _live_store_with_active_routine(
        tmp_path
    )
    verifier = store._bound_verifier
    assert verifier is not None
    original_verify = store._verify_retention_payload
    raced = False

    def race_transient(manifest: SegmentManifestV1) -> object:
        nonlocal raced
        scan = original_verify(manifest)
        if not raced:
            verifier._repair_transient_generation += 1
            raced = True
        return scan

    monkeypatch.setattr(
        store,
        "_verify_retention_payload",
        race_transient,
    )
    try:
        with pytest.raises(
            EvidenceSealError,
            match="authority changed during JIT",
        ):
            store._freeze_retention_snapshot(
                _proof_clock(),
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
    finally:
        coverage.close()
        store.close(flush=False)
