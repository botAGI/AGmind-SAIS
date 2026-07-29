from __future__ import annotations

import hashlib
import importlib
import math
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agmind_immune.canonicaljson import (
    canonical_json,
    event_signing_message,
)
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    EvidenceStoreError,
    SegmentStore,
    StoredEvidenceRecord,
)
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeVerifier,
    PinnedObserverRoot,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.phase5b_helpers import (
    BOOT_A,
    BOOT_B,
    HOST_ID,
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
)

T0 = "2026-07-28T10:00:00Z"
T1 = "2026-07-28T10:00:01Z"
T2 = "2026-07-28T10:00:02Z"
T3 = "2026-07-28T10:00:03Z"
T4 = "2026-07-28T10:00:04Z"
T5 = "2026-07-28T10:00:05Z"
OTHER_HOST = "423e4567-e89b-42d3-a456-426614174000"


def _coverage_module() -> Any:
    try:
        return importlib.import_module("agmind_immune.coverage")
    except ModuleNotFoundError:
        pytest.fail("Phase 5C1D coverage reducer is not implemented")


def _system(path: Path) -> tuple[AcceptanceCoordinator, SegmentStore]:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    return AcceptanceCoordinator.create_empty(EnvelopeVerifier(root, chain), store), store


def _reopen(path: Path) -> tuple[AcceptanceCoordinator, SegmentStore]:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    return AcceptanceCoordinator.open_and_recover(EnvelopeVerifier(root, chain), store), store


def _accept(
    coordinator: AcceptanceCoordinator,
    store: SegmentStore,
    value: dict[str, object],
) -> StoredEvidenceRecord:
    item = decode_events_page(canonical_json(page_value(value))).events[0]
    return store.resolve_authenticated_ref(coordinator.accept(item))


def _resign(
    value: dict[str, object],
    key: Ed25519PrivateKey,
    *,
    event_time: str,
    ingest_time: str,
) -> dict[str, object]:
    value["event_time"] = event_time
    value["ingest_time"] = ingest_time
    value["source_signature"] = key.sign(event_signing_message(value)).hex()
    return value


def _event(
    key: Ed25519PrivateKey,
    sequence: int,
    *,
    kind: str,
    event_time: str = T0,
    ingest_time: str = T0,
    host_id: str = HOST_ID,
) -> dict[str, object]:
    return _resign(
        envelope_value(
            key,
            sequence=sequence,
            host_id=host_id,
            normalized_fields={"kind": kind},
        ),
        key,
        event_time=event_time,
        ingest_time=ingest_time,
    )


def _observer_start(key: Ed25519PrivateKey, sequence: int) -> dict[str, object]:
    return envelope_value(
        key,
        sequence=sequence,
        event_type="observer_start",
        normalized_fields={"kind": "observer_start", "reconcile_required": True},
        coverage_flags=["reconcile_required"],
    )


def _coverage(
    key: Ed25519PrivateKey,
    sequence: int,
    fields: dict[str, object],
    *,
    event_time: str | None = None,
    ingest_time: str | None = None,
    inventory_generation: int = 0,
    coverage_flags: list[str] | None = None,
    source_payload_hash: str | None = None,
) -> dict[str, object]:
    selected_time = event_time or str(fields.get("closed_at", fields["opened_at"]))
    return _resign(
        envelope_value(
            key,
            sequence=sequence,
            event_type="coverage",
            normalized_fields=fields,
            inventory_generation=inventory_generation,
            coverage_flags=coverage_flags or [],
            source_payload_hash=source_payload_hash,
        ),
        key,
        event_time=selected_time,
        ingest_time=ingest_time or selected_time,
    )


def _stored(value: dict[str, object]) -> StoredEvidenceRecord:
    canonical = canonical_json(value)
    sequence = int(value["source_sequence"])
    content_sha256 = hashlib.sha256(canonical).hexdigest()
    return StoredEvidenceRecord(
        envelope=value,
        canonical_envelope=canonical,
        priority=EvidencePriority.PROTECTED,
        accepted_at=str(value["ingest_time"]),
        ref=EvidenceRef(
            segment_id="523e4567-e89b-42d3-a456-426614174000",
            segment_relative_path=(
                "segments/2026-07-28/"
                "00000000000000000001-523e4567-e89b-42d3-a456-426614174000.agseg"
            ),
            frame_offset=sequence,
            frame_size=len(canonical),
            frame_sha256=hashlib.sha256(b"frame\0" + canonical).hexdigest(),
            event_id=str(value["event_id"]),
            source_sequence=sequence,
            content_sha256=content_sha256,
        ),
    )


def _numeric_ref_type_mutations(ref: EvidenceRef) -> tuple[EvidenceRef, ...]:
    return (
        replace(ref, source_sequence=True),
        replace(ref, source_sequence=float(ref.source_sequence)),
        replace(ref, frame_offset=bool(ref.frame_offset)),
        replace(ref, frame_offset=float(ref.frame_offset)),
        replace(ref, frame_size=True),
        replace(ref, frame_size=float(ref.frame_size)),
    )


def _docker_open(
    key: Ed25519PrivateKey,
    sequence: int,
    *,
    opened_at: str,
    generation: int,
    reason: str = "observer_startup",
) -> StoredEvidenceRecord:
    return _stored(
        _coverage(
            key,
            sequence,
            {
                "component": "observer",
                "kind": "docker_reconcile_gap",
                "severity": "CRITICAL",
                "opened_at": opened_at,
                "reason_code": reason,
                "reconcile_generation": generation,
            },
            inventory_generation=generation,
            coverage_flags=["docker_event_gap", "reconcile_required"],
        )
    )


def _docker_recovery(
    key: Ed25519PrivateKey,
    sequence: int,
    *,
    opened_at: str,
    closed_at: str,
    generation: int,
    reason: str = "docker_full_reconcile_succeeded",
) -> StoredEvidenceRecord:
    return _stored(
        _coverage(
            key,
            sequence,
            {
                "component": "observer",
                "kind": "docker_reconcile_recovered",
                "severity": "INFO",
                "opened_at": opened_at,
                "closed_at": closed_at,
                "reason_code": reason,
                "reconcile_generation": generation,
            },
            inventory_generation=generation,
            coverage_flags=["docker_event_gap", "reconcile_required"],
        )
    )


def _gap_open(
    key: Ed25519PrivateKey,
    sequence: int,
    *,
    start: int,
    end: int,
    opened_at: str,
) -> StoredEvidenceRecord:
    return _stored(
        _coverage(
            key,
            sequence,
            {
                "component": "observer",
                "kind": "observer_sequence_gap",
                "severity": "CRITICAL",
                "opened_at": opened_at,
                "affected_source_sequence_start": start,
                "affected_source_sequence_end": end,
                "reason_code": "reserved_sequence_not_published",
            },
            coverage_flags=["reconcile_required", "sequence_gap"],
        )
    )


def _gap_close(
    key: Ed25519PrivateKey,
    sequence: int,
    *,
    start: int,
    end: int,
    opened_at: str,
    closed_at: str,
    generation: int,
    reason: str = "reserved_sequence_reconciled",
) -> StoredEvidenceRecord:
    return _stored(
        _coverage(
            key,
            sequence,
            {
                "component": "observer",
                "kind": "observer_sequence_gap",
                "severity": "INFO",
                "opened_at": opened_at,
                "closed_at": closed_at,
                "affected_source_sequence_start": start,
                "affected_source_sequence_end": end,
                "reason_code": reason,
                "reconcile_generation": generation,
            },
            inventory_generation=generation,
            coverage_flags=["reconcile_required", "sequence_gap"],
        )
    )


def _falco_point(
    key: Ed25519PrivateKey,
    sequence: int,
    *,
    kind: str,
    severity: str,
    at: str,
    reason: str,
    ingest_time: str | None = None,
) -> StoredEvidenceRecord:
    return _stored(
        _coverage(
            key,
            sequence,
            {
                "component": "falco-adapter",
                "kind": kind,
                "severity": severity,
                "opened_at": at,
                "closed_at": at,
                "reason_code": reason,
            },
            ingest_time=ingest_time,
            source_payload_hash="a" * 64,
        )
    )


def _readiness_context(
    coverage: Any,
    head: int,
    **overrides: object,
) -> Any:
    values: dict[str, object] = {
        "decision_utc": datetime.fromisoformat(T3),
        "decision_monotonic": 101.0,
        "clock_healthy": True,
        "clock_uncertainty_seconds": Decimal("0.5"),
        "max_clock_uncertainty_seconds": Decimal(1),
        "evidence_head": head,
        "acceptance_cursor": head,
        "confirmed_through": head,
        "projection_cursor": head,
        "evidence_healthy": True,
        "key_healthy": True,
        "ack_journal_healthy": True,
        "projection_healthy": True,
    }
    values.update(overrides)
    return coverage.MutationReadinessContext(**values)


def _live_ready_state(
    coverage: Any,
    path: Path,
    *,
    receipt_monotonic: float = 100.0,
    lease_opened_at: str = T2,
    lease_ingest_time: str = T3,
) -> tuple[Any, SegmentStore]:
    key = private_key(11)
    coordinator, store = _system(path)
    _accept(coordinator, store, boot_boundary(key))
    state = coverage.CoverageState.open_and_recover(store)
    for value in (
        _observer_start(key, 2),
        _docker_open(key, 3, opened_at=T0, generation=1).envelope,
        _docker_recovery(
            key,
            4,
            opened_at=T0,
            closed_at=T1,
            generation=1,
        ).envelope,
    ):
        state.apply(_accept(coordinator, store, value))
    lease = _accept(
        coordinator,
        store,
        _falco_point(
            key,
            5,
            kind="falco_heartbeat_lease",
            severity="INFO",
            at=lease_opened_at,
            reason="valid_heartbeat",
            ingest_time=lease_ingest_time,
        ).envelope,
    )
    state.apply(lease, live_receipt_monotonic=receipt_monotonic)
    return state, store


def _generic_critical(
    key: Ed25519PrivateKey,
    sequence: int,
    *,
    component: str,
    kind: str,
    opened_at: str,
    closed_at: str | None = None,
) -> StoredEvidenceRecord:
    fields: dict[str, object] = {
        "component": component,
        "kind": kind,
        "severity": "CRITICAL",
        "opened_at": opened_at,
        "reason_code": "test_critical",
    }
    if closed_at is not None:
        fields["closed_at"] = closed_at
    return _stored(
        _coverage(
            key,
            sequence,
            fields,
            source_payload_hash=hashlib.sha256(
                f"{component}\0{kind}\0{opened_at}\0{closed_at}".encode()
            ).hexdigest(),
        )
    )


def test_readiness_context_health_and_cursor_matrix(tmp_path: Path) -> None:
    coverage = _coverage_module()
    state, store = _live_ready_state(coverage, tmp_path / "context")
    valid = _readiness_context(coverage, 5)
    assert state.mutation_readiness(valid).ready
    equal_utc = replace(
        valid,
        decision_utc=datetime(
            2026,
            7,
            28,
            10,
            0,
            3,
            tzinfo=timezone(timedelta(0), "UTC"),
        ),
    )
    assert state.mutation_readiness(equal_utc).ready

    class DatetimeSubclass(datetime):
        pass

    class RaisingUTC(tzinfo):
        def utcoffset(self, value: datetime | None) -> timedelta:
            raise RuntimeError("hostile UTC offset")

        def dst(self, value: datetime | None) -> timedelta:
            return timedelta(0)

        def tzname(self, value: datetime | None) -> str:
            return "UTC"

        def __eq__(self, other: object) -> bool:
            return other is UTC

    invalid_fields = (
        (
            "decision_utc",
            datetime(2026, 7, 28, 10, 0, 3, tzinfo=UTC).replace(tzinfo=None),
        ),
        (
            "decision_utc",
            datetime(2026, 7, 28, 10, 0, 3, tzinfo=timezone(timedelta(hours=1))),
        ),
        ("decision_utc", datetime(2026, 7, 28, 10, 0, 3, tzinfo=UTC, fold=1)),
        ("decision_utc", DatetimeSubclass(2026, 7, 28, 10, 0, 3, tzinfo=UTC)),
        ("decision_utc", datetime(2026, 7, 28, 10, 0, 3, tzinfo=RaisingUTC())),
        ("decision_monotonic", True),
        ("decision_monotonic", 1),
        ("decision_monotonic", -1.0),
        ("decision_monotonic", math.inf),
        ("decision_monotonic", math.nan),
        ("clock_uncertainty_seconds", 0),
        ("clock_uncertainty_seconds", Decimal("-0.1")),
        ("clock_uncertainty_seconds", Decimal("NaN")),
        ("clock_uncertainty_seconds", Decimal("Infinity")),
        ("max_clock_uncertainty_seconds", 1),
        ("max_clock_uncertainty_seconds", Decimal("-0.1")),
        ("max_clock_uncertainty_seconds", Decimal("NaN")),
        ("max_clock_uncertainty_seconds", Decimal("Infinity")),
    )
    for field, value in invalid_fields:
        with pytest.raises(coverage.CoverageValidationError):
            _readiness_context(coverage, 5, **{field: value})
    for field in (
        "clock_healthy",
        "evidence_healthy",
        "key_healthy",
        "ack_journal_healthy",
        "projection_healthy",
    ):
        with pytest.raises(coverage.CoverageValidationError):
            _readiness_context(coverage, 5, **{field: 1})
    for field in (
        "evidence_head",
        "acceptance_cursor",
        "confirmed_through",
        "projection_cursor",
    ):
        for value in (True, 1.0, -1, 2**64):
            with pytest.raises(coverage.CoverageValidationError):
                _readiness_context(coverage, 5, **{field: value})

    health_reasons = {
        "clock_healthy": "clock_unhealthy",
        "evidence_healthy": "evidence_unhealthy",
        "key_healthy": "key_unhealthy",
        "ack_journal_healthy": "ack_journal_unhealthy",
        "projection_healthy": "projection_unhealthy",
    }
    for field, reason in health_reasons.items():
        result = state.mutation_readiness(replace(valid, **{field: False}))
        assert not result.ready
        assert result.reason_codes == (reason,)
    assert state.mutation_readiness(
        replace(valid, clock_uncertainty_seconds=None)
    ).reason_codes == ("clock_unhealthy",)
    assert state.mutation_readiness(
        replace(
            valid,
            clock_uncertainty_seconds=Decimal(1),
            max_clock_uncertainty_seconds=Decimal(1),
        )
    ).ready
    assert state.mutation_readiness(
        replace(valid, clock_uncertainty_seconds=Decimal("1.000000001"))
    ).reason_codes == ("clock_uncertainty_exceeded",)

    cursor_cases = (
        (
            {"acceptance_cursor": 4, "confirmed_through": 4, "projection_cursor": 4},
            "cursor_evidence_acceptance_mismatch",
        ),
        (
            {"confirmed_through": 4, "projection_cursor": 4},
            "cursor_acceptance_confirmed_mismatch",
        ),
        ({"projection_cursor": 4}, "cursor_confirmed_projection_mismatch"),
        (
            {
                "evidence_head": 4,
                "acceptance_cursor": 4,
                "confirmed_through": 4,
                "projection_cursor": 4,
            },
            "coverage_reducer_unhealthy",
        ),
    )
    for changes, reason in cursor_cases:
        result = state.mutation_readiness(replace(valid, **changes))
        assert result.reason_codes == (reason,)

    combined = state.mutation_readiness(
        replace(
            valid,
            clock_healthy=False,
            clock_uncertainty_seconds=Decimal(2),
            evidence_head=4,
            acceptance_cursor=3,
            confirmed_through=2,
            projection_cursor=1,
            evidence_healthy=False,
            key_healthy=False,
            ack_journal_healthy=False,
            projection_healthy=False,
        )
    )
    expected = (
        "ack_journal_unhealthy",
        "clock_uncertainty_exceeded",
        "clock_unhealthy",
        "coverage_reducer_unhealthy",
        "cursor_acceptance_confirmed_mismatch",
        "cursor_confirmed_projection_mismatch",
        "cursor_evidence_acceptance_mismatch",
        "evidence_unhealthy",
        "key_unhealthy",
        "projection_unhealthy",
    )
    assert combined.reason_codes == expected == tuple(sorted(set(expected)))

    class ContextSubclass(coverage.MutationReadinessContext):
        pass

    before = state._snapshot
    before_owner = store._coverage_state_owner
    barrier = state.ack_barrier_capability()
    for invalid in (valid.__dict__, object(), ContextSubclass(**valid.__dict__)):
        with pytest.raises(coverage.CoverageValidationError):
            state.mutation_readiness(invalid)
    tampered_fields = (
        (
            "decision_utc",
            datetime(2026, 7, 28, 10, 0, 3, tzinfo=UTC).replace(tzinfo=None),
        ),
        ("decision_monotonic", True),
        ("clock_healthy", 1),
        ("clock_uncertainty_seconds", 0),
        ("max_clock_uncertainty_seconds", 1),
        ("evidence_head", True),
        ("acceptance_cursor", True),
        ("confirmed_through", True),
        ("projection_cursor", True),
        ("evidence_healthy", 1),
        ("key_healthy", 1),
        ("ack_journal_healthy", 1),
        ("projection_healthy", 1),
    )
    for field, value in tampered_fields:
        tampered = replace(valid)
        object.__setattr__(tampered, field, value)
        with pytest.raises(coverage.CoverageValidationError):
            state.mutation_readiness(tampered)
    assert state._snapshot is before
    assert state._healthy
    assert store._coverage_state_owner is before_owner
    assert barrier._first_unclosed_sequence_gap(store) is None

    state.close()
    closed = state.mutation_readiness(valid)
    assert not closed.ready
    assert closed.reason_codes == ("coverage_reducer_unhealthy",)
    store.close()


def test_readiness_boot_docker_and_open_gap_matrix() -> None:
    coverage = _coverage_module()
    key = private_key(11)
    boot = _stored(boot_boundary(key))
    start = _stored(_observer_start(key, 2))
    docker_open = _docker_open(key, 3, opened_at=T0, generation=1)
    recovery = _docker_recovery(
        key,
        4,
        opened_at=T0,
        closed_at=T1,
        generation=1,
    )

    def decide(records: list[StoredEvidenceRecord]) -> Any:
        state = coverage.CoverageState.rebuild(records)
        return state.mutation_readiness(_readiness_context(coverage, state._snapshot.head_sequence))

    empty = decide([])
    assert empty.reason_codes == (
        "docker_reconcile_missing",
        "falco_lease_missing",
        "observer_start_missing",
    )
    assert empty.observer_reconcile_generation is None

    isolated_start = decide([_stored(_observer_start(key, 1))])
    assert isolated_start.reason_codes == (
        "docker_reconcile_missing",
        "falco_lease_missing",
        "observer_start_missing",
    )
    assert decide([boot]).reason_codes == isolated_start.reason_codes

    started = decide([boot, start])
    assert started.reason_codes == (
        "docker_reconcile_missing",
        "falco_lease_missing",
    )
    opened = decide([boot, start, docker_open])
    assert opened.reason_codes == (
        "docker_reconcile_missing",
        "falco_lease_missing",
    )
    assert "critical_coverage_open" not in opened.reason_codes
    assert opened.observer_reconcile_generation is None

    recovered = decide([boot, start, docker_open, recovery])
    assert recovered.reason_codes == ("falco_lease_missing",)
    assert recovered.observer_reconcile_generation == 1

    reset = decide(
        [
            boot,
            start,
            docker_open,
            recovery,
            _stored(
                boot_boundary(
                    key,
                    sequence=5,
                    boot_id=BOOT_B,
                    previous_boot_id=BOOT_A,
                    previous_source_sequence=4,
                )
            ),
        ]
    )
    assert reset.reason_codes == (
        "docker_reconcile_missing",
        "falco_lease_missing",
        "observer_start_missing",
    )
    assert reset.observer_reconcile_generation is None

    generic_open = _generic_critical(
        key,
        5,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T1,
    )
    generic_close = _generic_critical(
        key,
        6,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T1,
        closed_at=T2,
    )
    assert decide([boot, start, docker_open, recovery, generic_open]).reason_codes == (
        "critical_coverage_open",
        "falco_lease_missing",
    )
    assert decide(
        [boot, start, docker_open, recovery, generic_open, generic_close]
    ).reason_codes == ("falco_lease_missing",)

    gap_open = _gap_open(key, 5, start=20, end=21, opened_at=T1)
    next_docker_open = _docker_open(key, 6, opened_at=T2, generation=2)
    next_recovery = _docker_recovery(
        key,
        7,
        opened_at=T2,
        closed_at=T3,
        generation=2,
    )
    gap_close = _gap_close(
        key,
        8,
        start=20,
        end=21,
        opened_at=T1,
        closed_at=T3,
        generation=2,
    )
    structural = decide([boot, start, docker_open, recovery, gap_open])
    assert structural.reason_codes == ("falco_lease_missing", "structural_gap_open")
    assert "critical_coverage_open" not in structural.reason_codes
    assert structural.observer_reconcile_generation == 1

    docker_and_structural = decide([boot, start, docker_open, recovery, gap_open, next_docker_open])
    assert docker_and_structural.reason_codes == (
        "docker_reconcile_missing",
        "falco_lease_missing",
        "structural_gap_open",
    )
    assert "critical_coverage_open" not in docker_and_structural.reason_codes

    structurally_recovered = decide(
        [
            boot,
            start,
            docker_open,
            recovery,
            gap_open,
            next_docker_open,
            next_recovery,
            gap_close,
        ]
    )
    assert structurally_recovered.reason_codes == ("falco_lease_missing",)
    assert structurally_recovered.observer_reconcile_generation == 2


def test_readiness_lease_clock_edges_and_logical_hash(tmp_path: Path) -> None:
    coverage = _coverage_module()
    edge_state, edge_store = _live_ready_state(coverage, tmp_path / "edge")
    edge_context = _readiness_context(
        coverage,
        5,
        decision_utc=datetime(2026, 7, 28, 10, 0, 17, tzinfo=UTC),
        decision_monotonic=114.0,
        clock_uncertainty_seconds=Decimal(1),
        max_clock_uncertainty_seconds=Decimal(1),
    )
    edge = edge_state.mutation_readiness(edge_context)
    assert edge.ready
    assert edge.reason_codes == ()

    wall_beyond = edge_state.mutation_readiness(
        replace(
            edge_context,
            decision_utc=datetime(2026, 7, 28, 10, 0, 17, 1, tzinfo=UTC),
        )
    )
    assert wall_beyond.reason_codes == ("falco_lease_stale",)
    monotonic_beyond = edge_state.mutation_readiness(
        replace(
            edge_context,
            decision_monotonic=math.nextafter(114.0, math.inf),
        )
    )
    assert monotonic_beyond.reason_codes == ("falco_lease_stale",)
    decision_before_ingest = edge_state.mutation_readiness(
        replace(
            edge_context,
            decision_utc=datetime(2026, 7, 28, 10, 0, 2, 999999, tzinfo=UTC),
            decision_monotonic=100.0,
        )
    )
    assert decision_before_ingest.reason_codes == ("falco_lease_ingest_invalid",)
    uncertainty_beyond = edge_state.mutation_readiness(
        replace(edge_context, clock_uncertainty_seconds=Decimal("1.000000001"))
    )
    assert uncertainty_beyond.reason_codes == ("clock_uncertainty_exceeded",)

    maximum_state, maximum_store = _live_ready_state(
        coverage,
        tmp_path / "maximum-year",
        receipt_monotonic=7.0,
        lease_opened_at="9999-12-31T23:59:44Z",
        lease_ingest_time="9999-12-31T23:59:44Z",
    )
    assert maximum_state.mutation_readiness(
        _readiness_context(
            coverage,
            5,
            decision_utc=datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC),
            decision_monotonic=22.0,
        )
    ).ready

    key = private_key(11)
    replay_records = [
        _stored(boot_boundary(key)),
        _stored(_observer_start(key, 2)),
        _docker_open(key, 3, opened_at=T0, generation=1),
        _docker_recovery(
            key,
            4,
            opened_at=T0,
            closed_at=T1,
            generation=1,
        ),
        _falco_point(
            key,
            5,
            kind="falco_heartbeat_lease",
            severity="INFO",
            at=T2,
            reason="valid_heartbeat",
            ingest_time=T3,
        ),
    ]
    replay = coverage.CoverageState.rebuild(replay_records)
    assert replay.mutation_readiness(edge_context).reason_codes == ("falco_lease_missing",)
    assert replay.mutation_readiness(
        replace(
            edge_context,
            decision_utc=datetime(2026, 7, 28, 10, 0, 17, 1, tzinfo=UTC),
        )
    ).reason_codes == ("falco_lease_missing", "falco_lease_stale")
    stopped = coverage.CoverageState.rebuild(
        [
            *replay_records,
            _falco_point(
                key,
                6,
                kind="falco_adapter_stop",
                severity="CRITICAL",
                at=T4,
                reason="adapter_stopping",
            ),
        ]
    )
    assert stopped.mutation_readiness(
        _readiness_context(coverage, 6, decision_utc=datetime.fromisoformat(T4))
    ).reason_codes == ("falco_lease_missing",)

    origin_state, origin_store = _live_ready_state(
        coverage,
        tmp_path / "origin",
        receipt_monotonic=1000.0,
    )
    origin_context = replace(edge_context, decision_monotonic=1014.0)
    origin = origin_state.mutation_readiness(origin_context)
    assert origin.ready
    assert origin.coverage_snapshot_sha256 == edge.coverage_snapshot_sha256
    assert (
        edge_state.mutation_readiness(
            replace(edge_context, decision_monotonic=113.0)
        ).coverage_snapshot_sha256
        == edge.coverage_snapshot_sha256
    )
    assert (
        edge_state.mutation_readiness(
            replace(
                edge_context,
                decision_utc=datetime(2026, 7, 28, 10, 0, 16, 999999, tzinfo=UTC),
            )
        ).coverage_snapshot_sha256
        != edge.coverage_snapshot_sha256
    )

    retained = origin_state._snapshot.falco_lease
    assert retained is not None
    origin_state._snapshot = replace(
        origin_state._snapshot,
        falco_lease=replace(retained, event_id="evt_" + "f" * 64),
    )
    assert (
        origin_state.mutation_readiness(origin_context).coverage_snapshot_sha256
        != edge.coverage_snapshot_sha256
    )

    ordering_records = [
        _stored(boot_boundary(key)),
        _stored(_observer_start(key, 2)),
        _docker_open(key, 3, opened_at=T1, generation=2),
        _docker_open(key, 4, opened_at=T0, generation=1),
        _generic_critical(
            key,
            5,
            component="z-component",
            kind="z-kind",
            opened_at=T2,
        ),
        _generic_critical(
            key,
            6,
            component="a-component",
            kind="a-kind",
            opened_at=T1,
        ),
        _gap_open(key, 7, start=30, end=31, opened_at=T2),
        _gap_open(key, 8, start=10, end=11, opened_at=T1),
        _falco_point(
            key,
            9,
            kind="falco_heartbeat_lease",
            severity="INFO",
            at=T2,
            reason="valid_heartbeat",
            ingest_time=T3,
        ),
    ]
    ordered = coverage.CoverageState.rebuild(ordering_records)
    reordered = coverage.CoverageState.rebuild(ordering_records)
    reordered._snapshot = replace(
        reordered._snapshot,
        docker_opens=tuple(reversed(reordered._snapshot.docker_opens)),
        open_critical_intervals=tuple(reversed(reordered._snapshot.open_critical_intervals)),
        sequence_gaps=tuple(reversed(reordered._snapshot.sequence_gaps)),
    )
    ordering_context = _readiness_context(coverage, 9)
    assert (
        ordered.mutation_readiness(ordering_context).coverage_snapshot_sha256
        == reordered.mutation_readiness(ordering_context).coverage_snapshot_sha256
    )

    empty_context = _readiness_context(
        coverage,
        0,
        decision_utc=datetime.fromisoformat(T0),
        decision_monotonic=0.0,
    )
    empty_hash = (
        coverage.CoverageState.rebuild([])
        .mutation_readiness(empty_context)
        .coverage_snapshot_sha256
    )
    independent_payload = {
        "schema_version": "agmind.coverage-snapshot.v1",
        "decision_utc": T0,
        "ready": False,
        "reason_codes": (
            "docker_reconcile_missing",
            "falco_lease_missing",
            "observer_start_missing",
        ),
        "cursors": {
            "evidence_head": 0,
            "acceptance_cursor": 0,
            "confirmed_through": 0,
            "projection_cursor": 0,
        },
        "health_bits": {
            "ack_journal_healthy": True,
            "clock_healthy": True,
            "clock_uncertainty_present": True,
            "clock_uncertainty_within_limit": True,
            "coverage_reducer_healthy": True,
            "evidence_healthy": True,
            "key_healthy": True,
            "projection_healthy": True,
        },
        "boot_epoch": {
            "host_id": None,
            "transition_source_sequence": None,
        },
        "observer_started": False,
        "docker_generation": None,
        "open_critical_intervals": (),
        "open_sequence_gaps": (),
        "lease_logical_identity": None,
    }
    fixed_digest = "069743223f798123b9f632be2a68babdc649d5ec350430a0d2aa5115bc30acab"
    assert (
        hashlib.sha256(
            b"AGMIND_COVERAGE_SNAPSHOT_V1\0" + canonical_json(independent_payload)
        ).hexdigest()
        == fixed_digest
    )
    assert empty_hash == fixed_digest

    edge_state.close()
    maximum_state.close()
    origin_state.close()
    edge_store.close()
    maximum_store.close()
    origin_store.close()


def test_input_order_atomicity_and_unhealthy_latch(tmp_path: Path) -> None:
    coverage = _coverage_module()
    key = private_key(11)
    newest = _stored(_event(key, 2, kind="newest", ingest_time=T0))
    oldest = _stored(_event(key, 1, kind="oldest", ingest_time=T5))
    state = coverage.CoverageState.rebuild([oldest, newest])
    assert state._snapshot.head_sequence == 2

    other = _stored(_event(key, 3, kind="other-host", host_id=OTHER_HOST))
    invalid_inputs = (
        [oldest.envelope],
        [replace(oldest, canonical_envelope=b"{}")],
        [replace(oldest, ref=replace(oldest.ref, event_id="evt_" + "0" * 64))],
        [oldest, other],
        [newest, oldest],
    )
    for records in invalid_inputs:
        with pytest.raises((coverage.CoverageValidationError, coverage.CoverageConflict)):
            coverage.CoverageState.rebuild(records)
    for malformed_ref in _numeric_ref_type_mutations(oldest.ref):
        with pytest.raises(coverage.CoverageValidationError):
            coverage.CoverageState.rebuild([replace(oldest, ref=malformed_ref)])

    for index in range(6):
        strict_coordinator, strict_store = _system(tmp_path / f"strict-ref-{index}")
        strict_state = coverage.CoverageState.open_and_recover(strict_store)
        accepted = _accept(strict_coordinator, strict_store, boot_boundary(key))
        malformed_ref = _numeric_ref_type_mutations(accepted.ref)[index]
        with pytest.raises(coverage.CoverageAuthorityError):
            strict_state.apply(replace(accepted, ref=malformed_ref))
        strict_store.close()

    priority_coordinator, priority_store = _system(tmp_path / "strict-record")
    priority_state = coverage.CoverageState.open_and_recover(priority_store)
    priority_record = _accept(priority_coordinator, priority_store, boot_boundary(key))
    with pytest.raises(coverage.CoverageAuthorityError):
        priority_state.apply(replace(priority_record, priority="protected"))
    priority_store.close()

    coordinator, store = _system(tmp_path / "skip")
    first = _accept(coordinator, store, boot_boundary(key))
    bound = coverage.CoverageState.open_and_recover(store)
    second = _accept(coordinator, store, _event(key, 2, kind="second"))
    third = _accept(coordinator, store, _event(key, 3, kind="third"))
    before = bound._snapshot
    with pytest.raises(coverage.CoverageAuthorityError):
        bound.apply(third)
    assert bound._snapshot is before
    with pytest.raises(coverage.CoverageUnhealthy):
        bound.apply(second)
    with pytest.raises(coverage.CoverageUnhealthy):
        bound.ack_barrier_capability()
    assert first.ref.source_sequence == 1
    store.close()

    _failure_coordinator, failure_store = _system(tmp_path / "unexpected-recovery")
    _accept(_failure_coordinator, failure_store, boot_boundary(key))
    state_module = importlib.import_module("agmind_immune.coverage.state")

    class SyntheticReducerFailure(BaseException):
        pass

    def fail_transition(*args: object, **kwargs: object) -> object:
        raise SyntheticReducerFailure("unexpected replay failure")

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(state_module, "_transition", fail_transition)
        with pytest.raises(SyntheticReducerFailure):
            coverage.CoverageState.open_and_recover(failure_store)
    assert failure_store._coverage_state_owner is None
    recovered = coverage.CoverageState.open_and_recover(failure_store)
    unexpected = _accept(
        _failure_coordinator,
        failure_store,
        _event(key, 2, kind="unexpected-apply"),
    )
    before_unexpected = recovered._snapshot
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(state_module, "_transition", fail_transition)
        with pytest.raises(SyntheticReducerFailure):
            recovered.apply(unexpected)
    assert recovered._snapshot is before_unexpected
    assert not recovered._healthy
    with pytest.raises(coverage.CoverageUnhealthy):
        recovered.apply(unexpected)
    failure_store.close()


def test_boot_docker_generic_and_falco_transitions(tmp_path: Path) -> None:
    coverage = _coverage_module()
    key = private_key(11)
    boot = _stored(boot_boundary(key))
    start = _stored(_observer_start(key, 2))
    docker_open = _docker_open(key, 3, opened_at=T0, generation=1)
    recovery = _docker_recovery(
        key,
        4,
        opened_at=T0,
        closed_at=T1,
        generation=1,
    )
    critical_open = _stored(
        _coverage(
            key,
            5,
            {
                "component": "falco-adapter",
                "kind": "falco_heartbeat_gap",
                "severity": "CRITICAL",
                "opened_at": T1,
                "reason_code": "heartbeat_missing",
            },
            source_payload_hash="b" * 64,
        )
    )
    critical_close = _stored(
        _coverage(
            key,
            6,
            {
                "component": "falco-adapter",
                "kind": "falco_heartbeat_gap",
                "severity": "CRITICAL",
                "opened_at": T1,
                "closed_at": T2,
                "dropped_count": 1,
                "reason_code": "valid_heartbeat_recovered",
            },
            source_payload_hash="c" * 64,
        )
    )
    lease = _falco_point(
        key,
        7,
        kind="falco_heartbeat_lease",
        severity="INFO",
        at=T2,
        reason="valid_heartbeat",
        ingest_time=T3,
    )
    stop = _falco_point(
        key,
        8,
        kind="falco_adapter_stop",
        severity="CRITICAL",
        at=T3,
        reason="adapter_stopping",
    )
    inherited_lease = _falco_point(
        key,
        9,
        kind="falco_heartbeat_lease",
        severity="INFO",
        at=T4,
        reason="valid_heartbeat",
    )
    retained_open = _stored(
        _coverage(
            key,
            10,
            {
                "component": "falco-adapter",
                "kind": "falco_queue_drop",
                "severity": "CRITICAL",
                "opened_at": T4,
                "reason_code": "routine_queue_full",
            },
            source_payload_hash="d" * 64,
        )
    )
    restart = _stored(_observer_start(key, 11))
    next_boot = _stored(
        boot_boundary(
            key,
            sequence=12,
            boot_id=BOOT_B,
            previous_boot_id=BOOT_A,
            previous_source_sequence=11,
        )
    )

    coordinator, store = _system(tmp_path / "transitions")
    accepted_boot = _accept(coordinator, store, boot.envelope)
    state = coverage.CoverageState.open_and_recover(store)
    for record in (start, docker_open, recovery, critical_open, critical_close):
        accepted = _accept(coordinator, store, record.envelope)
        state.apply(accepted)
    accepted_lease = _accept(coordinator, store, lease.envelope)
    state.apply(accepted_lease, live_receipt_monotonic=100.0)
    assert state._snapshot.observer_started is True
    assert state._snapshot.docker_generation == 1
    assert state._snapshot.open_critical_intervals == ()
    assert state._snapshot.live_lease_deadline == 114.0
    state.apply(_accept(coordinator, store, stop.envelope))
    assert state._snapshot.live_lease_deadline is None
    state.apply(
        _accept(coordinator, store, inherited_lease.envelope),
        live_receipt_monotonic=200.0,
    )
    state.apply(_accept(coordinator, store, retained_open.envelope))
    state.apply(_accept(coordinator, store, restart.envelope))
    assert state._snapshot.observer_started is True
    assert state._snapshot.docker_generation is None
    assert state._snapshot.live_lease_deadline is None
    assert len(state._snapshot.open_critical_intervals) == 1
    state.apply(_accept(coordinator, store, next_boot.envelope))
    assert state._snapshot.observer_started is False
    assert state._snapshot.docker_generation is None
    assert state._snapshot.live_lease_deadline is None
    assert len(state._snapshot.docker_recoveries) == 1
    assert len(state._snapshot.open_critical_intervals) == 1
    assert accepted_boot.ref.source_sequence == 1
    store.close()

    replay = coverage.CoverageState.rebuild(
        [boot, start, docker_open, recovery, critical_open, critical_close, lease]
    )
    assert replay._snapshot.live_lease_deadline is None

    repeat_fields = {
        "component": "falco-adapter",
        "kind": "falco_heartbeat_gap",
        "severity": "CRITICAL",
        "opened_at": T1,
        "reason_code": "heartbeat_missing",
    }
    repeat_open = _stored(
        _coverage(
            key,
            2,
            repeat_fields,
            source_payload_hash="e" * 64,
        )
    )
    exact_repeat = _stored(
        _coverage(
            key,
            3,
            repeat_fields,
            source_payload_hash="e" * 64,
        )
    )
    repeat_close = _stored(
        _coverage(
            key,
            4,
            {
                **repeat_fields,
                "closed_at": T2,
                "dropped_count": 1,
                "reason_code": "valid_heartbeat_recovered",
            },
            source_payload_hash="f" * 64,
        )
    )
    repeat_coordinator, repeat_store = _system(tmp_path / "generic-repeat")
    _accept(repeat_coordinator, repeat_store, boot.envelope)
    repeat_state = coverage.CoverageState.open_and_recover(repeat_store)
    accepted_open = _accept(repeat_coordinator, repeat_store, repeat_open.envelope)
    repeat_state.apply(accepted_open)
    original_interval = repeat_state._snapshot.open_critical_intervals[0]
    accepted_repeat = _accept(repeat_coordinator, repeat_store, exact_repeat.envelope)
    repeat_state.apply(accepted_repeat)
    assert repeat_state._snapshot.head_ref == accepted_repeat.ref
    assert repeat_state._snapshot.open_critical_intervals == (original_interval,)
    assert repeat_state._snapshot.open_critical_intervals[0] is original_interval
    assert original_interval.source_sequence == accepted_open.ref.source_sequence
    accepted_close = _accept(repeat_coordinator, repeat_store, repeat_close.envelope)
    repeat_state.apply(accepted_close)
    assert repeat_state._snapshot.head_ref == accepted_close.ref
    assert repeat_state._snapshot.open_critical_intervals == ()
    repeat_store.close()

    changed_payload = _stored(
        _coverage(
            key,
            3,
            repeat_fields,
            source_payload_hash="0" * 64,
        )
    )
    changed_facts = _stored(
        _coverage(
            key,
            3,
            {
                **repeat_fields,
                "reason_code": "different_reason",
            },
            source_payload_hash="e" * 64,
        )
    )
    for changed_repeat in (changed_payload, changed_facts):
        with pytest.raises(coverage.CoverageConflict):
            coverage.CoverageState.rebuild([boot, repeat_open, changed_repeat])

    for index, receipt in enumerate((True, -1.0, math.inf, math.nan)):
        bad_coordinator, bad_store = _system(tmp_path / f"receipt-{index}")
        _accept(bad_coordinator, bad_store, boot.envelope)
        candidate = coverage.CoverageState.open_and_recover(bad_store)
        bad_lease = _accept(bad_coordinator, bad_store, lease.envelope)
        with pytest.raises(coverage.CoverageValidationError):
            candidate.apply(bad_lease, live_receipt_monotonic=receipt)
        bad_store.close()
    candidate = coverage.CoverageState.rebuild([boot])
    with pytest.raises(coverage.CoverageValidationError):
        candidate.apply(start, live_receipt_monotonic=1.0)

    wrong_recovery = _docker_recovery(
        key,
        4,
        opened_at=T0,
        closed_at=T1,
        generation=2,
    )
    wrong_reason = _docker_recovery(
        key,
        4,
        opened_at=T0,
        closed_at=T1,
        generation=1,
        reason="not_success",
    )
    rollback = _docker_recovery(
        key,
        4,
        opened_at=T2,
        closed_at=T1,
        generation=1,
    )
    invalid_pairs = (
        [boot, docker_open, wrong_recovery],
        [boot, docker_open, wrong_reason],
        [boot, docker_open, rollback],
        [
            boot,
            docker_open,
            recovery,
            _docker_open(key, 5, opened_at=T2, generation=1),
            _docker_recovery(
                key,
                6,
                opened_at=T2,
                closed_at=T3,
                generation=1,
            ),
        ],
    )
    for records in invalid_pairs:
        with pytest.raises((coverage.CoverageValidationError, coverage.CoverageConflict)):
            coverage.CoverageState.rebuild(records)

    same_time_distinct_generations = coverage.CoverageState.rebuild(
        [
            boot,
            _docker_open(key, 2, opened_at=T0, generation=1),
            _docker_open(key, 3, opened_at=T0, generation=2),
            _docker_recovery(
                key,
                4,
                opened_at=T0,
                closed_at=T1,
                generation=1,
            ),
            _docker_recovery(
                key,
                5,
                opened_at=T0,
                closed_at=T2,
                generation=2,
            ),
        ]
    )
    assert same_time_distinct_generations._snapshot.docker_generation == 2

    maximum_coordinator, maximum_store = _system(tmp_path / "maximum-lease")
    _accept(maximum_coordinator, maximum_store, boot.envelope)
    maximum_state = coverage.CoverageState.open_and_recover(maximum_store)
    maximum_lease = _accept(
        maximum_coordinator,
        maximum_store,
        _falco_point(
            key,
            2,
            kind="falco_heartbeat_lease",
            severity="INFO",
            at="9999-12-31T23:59:59Z",
            reason="valid_heartbeat",
        ).envelope,
    )
    maximum_state.apply(maximum_lease, live_receipt_monotonic=7.0)
    assert maximum_state._snapshot.live_lease_deadline == 22.0
    maximum_state.close()
    maximum_replay = coverage.CoverageState.open_and_recover(maximum_store)
    assert maximum_replay._snapshot.live_lease_deadline is None
    maximum_store.close()


def test_structural_pairing_and_lowest_open_sequence_barrier(tmp_path: Path) -> None:
    coverage = _coverage_module()
    key = private_key(11)
    coordinator, store = _system(tmp_path / "structural")
    _accept(coordinator, store, boot_boundary(key))
    _accept(coordinator, store, _event(key, 4, kind="after-first-hole"))
    first_open = _accept(
        coordinator,
        store,
        _gap_open(key, 5, start=2, end=3, opened_at=T0).envelope,
    )
    state = coverage.CoverageState.open_and_recover(store)
    barrier = state.ack_barrier_capability()
    assert barrier._first_unclosed_sequence_gap(store) == 5

    later = _accept(coordinator, store, _event(key, 8, kind="after-second-hole"))
    state.apply(later)
    second_open = _accept(
        coordinator,
        store,
        _gap_open(key, 9, start=6, end=7, opened_at=T0).envelope,
    )
    state.apply(second_open)
    docker_open = _accept(
        coordinator,
        store,
        _docker_open(key, 10, opened_at=T1, generation=1).envelope,
    )
    state.apply(docker_open)
    recovery = _accept(
        coordinator,
        store,
        _docker_recovery(
            key,
            11,
            opened_at=T1,
            closed_at=T2,
            generation=1,
        ).envelope,
    )
    state.apply(recovery)
    first_close = _accept(
        coordinator,
        store,
        _gap_close(
            key,
            12,
            start=2,
            end=3,
            opened_at=T0,
            closed_at=T2,
            generation=1,
        ).envelope,
    )
    state.apply(first_close)
    assert barrier._first_unclosed_sequence_gap(store) == 9
    second_close = _accept(
        coordinator,
        store,
        _gap_close(
            key,
            13,
            start=6,
            end=7,
            opened_at=T0,
            closed_at=T2,
            generation=1,
        ).envelope,
    )
    state.apply(second_close)
    assert barrier._first_unclosed_sequence_gap(store) is None
    assert {item.close_recovery_generation for item in state._snapshot.sequence_gaps} == {1}
    assert first_open.ref.source_sequence < second_open.ref.source_sequence
    store.close()

    open_one = _gap_open(key, 1, start=10, end=20, opened_at=T0)
    overlap = _gap_open(key, 2, start=20, end=30, opened_at=T1)
    unmatched = _gap_close(
        key,
        2,
        start=11,
        end=20,
        opened_at=T0,
        closed_at=T2,
        generation=1,
    )
    prior_open = _docker_open(key, 1, opened_at=T0, generation=3)
    prior_recovery = _docker_recovery(
        key,
        2,
        opened_at=T0,
        closed_at=T1,
        generation=3,
    )
    later_gap = _gap_open(key, 3, start=40, end=41, opened_at=T1)
    stale_close = _gap_close(
        key,
        4,
        start=40,
        end=41,
        opened_at=T1,
        closed_at=T1,
        generation=3,
    )
    exact_open = _gap_open(key, 1, start=50, end=51, opened_at=T0)
    exact_docker_open = _docker_open(key, 2, opened_at=T1, generation=4)
    exact_recovery = _docker_recovery(
        key,
        3,
        opened_at=T1,
        closed_at=T2,
        generation=4,
    )
    exact_close = _gap_close(
        key,
        4,
        start=50,
        end=51,
        opened_at=T0,
        closed_at=T2,
        generation=4,
    )
    duplicate_close = _gap_close(
        key,
        5,
        start=50,
        end=51,
        opened_at=T0,
        closed_at=T2,
        generation=4,
    )
    invalid_chains = (
        [open_one, overlap],
        [open_one, unmatched],
        [prior_open, prior_recovery, later_gap, stale_close],
        [exact_open, exact_docker_open, exact_recovery, exact_close, duplicate_close],
    )
    for records in invalid_chains:
        with pytest.raises((coverage.CoverageValidationError, coverage.CoverageConflict)):
            coverage.CoverageState.rebuild(records)


def test_capability_lifecycle_same_store_head_and_restart(tmp_path: Path) -> None:
    coverage = _coverage_module()
    key = private_key(11)
    path = tmp_path / "evidence"
    coordinator, store = _system(path)
    first = _accept(coordinator, store, boot_boundary(key))
    state = coverage.CoverageState.open_and_recover(store)
    barrier = state.ack_barrier_capability()
    with pytest.raises(TypeError):
        coverage.CoverageAckBarrier()
    assert not callable(barrier)

    pure = coverage.CoverageState.rebuild([first])
    with pytest.raises(coverage.CoverageAuthorityError):
        pure.ack_barrier_capability()
    with pytest.raises(coverage.CoverageAuthorityError):
        coverage.CoverageState.open_and_recover(store)

    other_coordinator, other_store = _system(tmp_path / "other")
    _accept(other_coordinator, other_store, boot_boundary(key))
    with pytest.raises(coverage.CoverageAuthorityError):
        barrier._first_unclosed_sequence_gap(other_store)

    second = _accept(coordinator, store, _event(key, 2, kind="head-lag"))
    with pytest.raises(coverage.CoverageAuthorityError):
        barrier._first_unclosed_sequence_gap(store)
    state.apply(second)
    assert barrier._first_unclosed_sequence_gap(store) is None

    state.close()
    with pytest.raises(coverage.CoverageAuthorityError):
        barrier._first_unclosed_sequence_gap(store)
    rebound = coverage.CoverageState.open_and_recover(store)
    rebound_barrier = rebound.ack_barrier_capability()
    assert rebound_barrier._first_unclosed_sequence_gap(store) is None
    store.close()
    with pytest.raises(coverage.CoverageAuthorityError):
        rebound_barrier._first_unclosed_sequence_gap(store)

    _recovered_coordinator, reopened = _reopen(path)
    restarted = coverage.CoverageState.open_and_recover(reopened)
    with pytest.raises(coverage.CoverageAuthorityError):
        rebound_barrier._first_unclosed_sequence_gap(reopened)
    restarted_barrier = restarted.ack_barrier_capability()
    assert restarted_barrier._first_unclosed_sequence_gap(reopened) is None
    reopened.close()
    other_store.close()

    _release_coordinator, release_store = _system(tmp_path / "release-failure")
    _accept(_release_coordinator, release_store, boot_boundary(key))
    release_state = coverage.CoverageState.open_and_recover(release_store)
    release_barrier = release_state.ack_barrier_capability()
    original_release = SegmentStore._release_coverage_state

    def release_then_fail(
        target: SegmentStore,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        original_release(target, owner, lifecycle_identity)
        raise EvidenceStoreError("synthetic release failure")

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(SegmentStore, "_release_coverage_state", release_then_fail)
        with pytest.raises(
            coverage.CoverageAuthorityError,
            match="coverage owner release failed",
        ):
            release_state.close()
    assert release_state._closed
    assert release_state._capability_token is None
    assert release_state._evidence is None
    assert release_state._lifecycle_identity is None
    with pytest.raises(coverage.CoverageAuthorityError):
        release_barrier._first_unclosed_sequence_gap(release_store)
    release_store.close()

    close_calls: list[str] = []
    _failure_coordinator, failure_store = _system(tmp_path / "close-failure")

    class SyntheticShutdownFailure(BaseException):
        pass

    class FailingCoverageOwner:
        def _close_from_segment_store(self, lifecycle_identity: object) -> None:
            assert lifecycle_identity is failure_store._lifecycle_identity
            close_calls.append("coverage")
            raise SyntheticShutdownFailure("coverage callback failed")

    class ReleasingAckOwner:
        def _close_from_segment_store(self, lifecycle_identity: object) -> None:
            assert lifecycle_identity is failure_store._lifecycle_identity
            close_calls.append("ack")
            failure_store._ack_journal_owner = None

    failure_store._coverage_state_owner = FailingCoverageOwner()
    failure_store._ack_journal_owner = ReleasingAckOwner()
    with pytest.raises(
        EvidenceStoreError,
        match="coverage-state owner survived evidence shutdown",
    ):
        failure_store.close()
    assert close_calls == ["coverage", "ack"]
    assert failure_store._coverage_state_owner is None
    assert failure_store._ack_journal_owner is None
    assert failure_store._closed

    lookup_calls: list[str] = []
    _lookup_coordinator, lookup_store = _system(tmp_path / "close-lookup-failure")

    class LookupFailingCoverageOwner:
        def __getattribute__(self, name: str) -> object:
            if name == "_close_from_segment_store":
                lookup_calls.append("coverage-lookup")
                raise SyntheticShutdownFailure("coverage callback lookup failed")
            return object.__getattribute__(self, name)

    class LookupReleasingAckOwner:
        def _close_from_segment_store(self, lifecycle_identity: object) -> None:
            assert lifecycle_identity is lookup_store._lifecycle_identity
            lookup_calls.append("ack")
            lookup_store._ack_journal_owner = None

    lookup_store._coverage_state_owner = LookupFailingCoverageOwner()
    lookup_store._ack_journal_owner = LookupReleasingAckOwner()
    with pytest.raises(
        EvidenceStoreError,
        match="coverage-state owner survived evidence shutdown",
    ):
        lookup_store.close()
    assert lookup_calls == ["coverage-lookup", "ack"]
    assert lookup_store._coverage_state_owner is None
    assert lookup_store._ack_journal_owner is None
    assert lookup_store._closed
