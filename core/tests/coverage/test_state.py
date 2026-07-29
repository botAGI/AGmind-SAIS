from __future__ import annotations

import hashlib
import importlib
import math
from dataclasses import replace
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
