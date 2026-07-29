from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Literal

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.clock import CoreClockSample
from agmind_immune.contracts import (
    MAX_UINT64,
    ZERO_SHA256,
    RetentionBlockedV1,
    RetentionTombstoneV2,
)
from agmind_immune.evidence import retention as retention_module
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

REQUEST_ID = "11111111-1111-4111-8111-111111111111"
OTHER_REQUEST_ID = "22222222-2222-4222-8222-222222222222"
HOST_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
DECISION_UTC = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
EXPIRED = "2026-07-22T11:59:59.999999999Z"
BOUNDARY = "2026-07-22T12:00:00Z"
FRESH = "2026-07-23T12:00:00Z"


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
            )
        )
        previous = manifest.manifest_sha256
    return _freeze_retention_snapshot(
        facts=tuple(facts),
        clock=_clock() if clock is None else clock,
        prior_tombstones=prior,
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
