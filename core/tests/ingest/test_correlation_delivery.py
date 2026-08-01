from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import pytest
from agmind_immune.canonicaljson import (
    canonical_json,
    pcc_correlation_request_sha256,
)
from agmind_immune.coverage import CoverageState
from agmind_immune.evidence.segments import EvidenceRef, SegmentStore
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.service import (
    AcceptanceCoordinator,
    DeliveryCoordinator,
    DeliveryFatalError,
    DeliveryRetryableError,
)
from tests.ingest.test_pcc_correlation_snapshot import (
    _candidate_trigger,
    _cross_boot_case,
    _failed_snapshot,
    _item,
    _request,
    _snapshot_envelope,
)
from tests.ingest.test_service import (
    _coordinator,
    _DeliveryClock,
    _page_bytes,
    _recovered_coordinator,
    _ScriptedTransport,
)
from tests.phase5b_helpers import (
    BOOT_B,
    NOW,
    boot_boundary,
    envelope_value,
    private_key,
)

CORRELATION_CRASH_POINTS = (
    "after_trigger_append",
    "after_selected",
    "after_post_response",
    "after_intervening_append",
    "after_proof_observed",
    "after_ack_intent",
    "after_observer_ack",
)


class _Crash(BaseException):
    pass


def _direct(envelope: dict[str, object]) -> bytes:
    return canonical_json(_item(envelope))


def _runtime(
    path: Path,
    transport: _ScriptedTransport,
) -> tuple[
    AcceptanceCoordinator,
    SegmentStore,
    AckJournal,
    CorrelationRequestJournal,
    CoverageState,
    DeliveryCoordinator,
]:
    acceptance, store, _verifier = _coordinator(path)
    acknowledgements = AckJournal.create_new(store)
    correlation = CorrelationRequestJournal.create_new(store)
    coverage = CoverageState.open_and_recover(store)
    delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        correlation,
        transport,
        coverage=coverage,
        clock=_DeliveryClock(),
    )
    return acceptance, store, acknowledgements, correlation, coverage, delivery


async def _close_runtime(
    delivery: DeliveryCoordinator,
    coverage: CoverageState,
    correlation: CorrelationRequestJournal,
    acknowledgements: AckJournal,
    store: SegmentStore,
) -> None:
    await delivery.close()
    coverage.close()
    correlation.close()
    acknowledgements.close()
    store.close()


def _reopen_runtime(
    path: Path,
    transport: _ScriptedTransport,
) -> tuple[
    AcceptanceCoordinator,
    SegmentStore,
    AckJournal,
    CorrelationRequestJournal,
    CoverageState,
    DeliveryCoordinator,
]:
    acceptance, store, _verifier = _recovered_coordinator(path)
    acknowledgements = AckJournal.open_and_recover(store)
    correlation = CorrelationRequestJournal.open_and_recover(store)
    coverage = CoverageState.open_and_recover(store)
    delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        correlation,
        transport,
        coverage=coverage,
        clock=_DeliveryClock(),
    )
    return acceptance, store, acknowledgements, correlation, coverage, delivery


def _seed_selected(
    path: Path,
) -> tuple[
    AcceptanceCoordinator,
    SegmentStore,
    AckJournal,
    CorrelationRequestJournal,
    CoverageState,
    dict[str, object],
    dict[str, object],
    bytes,
]:
    key = private_key(11)
    acceptance, store, _verifier = _coordinator(path)
    boot_ref = acceptance.accept(_item(boot_boundary(key)))
    trigger = _candidate_trigger(key, sequence=2)
    trigger_ref = acceptance.accept(_item(trigger))
    acknowledgements = AckJournal.create_new(store)
    acknowledgements.record_pending(boot_ref)
    acknowledgements.record_confirmed(boot_ref)
    correlation = CorrelationRequestJournal.create_new(store)
    request = _request(trigger, ttl_seconds=120)
    selected = correlation.select(trigger_ref, canonical_json(request))
    coverage = CoverageState.open_and_recover(store)
    snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(trigger, selected.request, snapshot_sequence=3),
        sequence=3,
    )
    return (
        acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        trigger,
        snapshot,
        canonical_json(selected.request),
    )


def _cross_boot_with_ttl_120(
    path: Path,
    mode: Literal["a", "b", "c"],
) -> tuple[AcceptanceCoordinator, object, dict[str, object]]:
    acceptance, original_request, original_snapshot = _cross_boot_case(path, mode)
    request = original_request.model_copy(
        update={"requested_ttl_seconds": 120},
    )
    fields = dict(original_snapshot["normalized_fields"])
    fields["request_sha256"] = pcc_correlation_request_sha256(request)
    fields["requested_ttl_seconds"] = 120
    key_epoch = int(original_snapshot["key_epoch"])
    snapshot = _snapshot_envelope(
        private_key(11 if key_epoch == 1 else 12),
        fields,
        sequence=int(original_snapshot["source_sequence"]),
        boot_id=str(original_snapshot["boot_id"]),
        key_epoch=key_epoch,
    )
    return acceptance, request, snapshot


def _candidate_case(
    *,
    intervening: tuple[dict[str, object], ...] = (),
    with_gap: bool = False,
) -> tuple[_ScriptedTransport, dict[str, object]]:
    key = private_key(11)
    trigger = _candidate_trigger(key, sequence=2)
    request = _request(trigger, ttl_seconds=120)
    snapshot_sequence = 4 if with_gap else 3 + len(intervening)
    snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(
            trigger,
            request,
            snapshot_sequence=snapshot_sequence,
        ),
        sequence=snapshot_sequence,
    )
    path_events: tuple[dict[str, object], ...]
    gaps: list[dict[str, int]] | None = None
    if with_gap:
        path_events = (snapshot,)
        gaps = [{"start": 3, "end": 3}]
    else:
        path_events = (*intervening, snapshot)
    return (
        _ScriptedTransport(
            pages=[
                _page_bytes(
                    boot_boundary(key),
                    trigger,
                    reserved_through=2,
                ),
                _page_bytes(
                    *path_events,
                    reserved_through=snapshot_sequence,
                    uncovered_gaps=gaps,
                ),
            ],
            acknowledgements=[None] * snapshot_sequence,
            publications=[_direct(snapshot)],
        ),
        trigger,
    )


@pytest.mark.asyncio
async def test_candidate_trigger_is_selected_after_accept_before_any_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, _trigger = _candidate_case()
    acceptance, store, acknowledgements, correlation, coverage, delivery = _runtime(
        tmp_path,
        transport,
    )
    timeline: list[str] = []
    accept = acceptance.accept
    select = correlation.select
    publish = transport.publish_correlation_snapshot
    ack = transport.ack_event

    def traced_accept(owner: object, item: object) -> object:
        assert owner is acceptance
        ref = accept(item)  # type: ignore[arg-type]
        if ref.source_sequence == 2:  # type: ignore[attr-defined]
            timeline.append("evidence_trigger")
        return ref

    def traced_select(owner: object, ref: object, body: bytes) -> object:
        assert owner is correlation
        assert store.status().evidence_head >= 2
        timeline.append("journal_selected")
        return select(ref, body)  # type: ignore[arg-type]

    async def traced_publish(body: bytes) -> bytes:
        timeline.append("post")
        return await publish(body)

    async def traced_ack(body: bytes) -> None:
        timeline.append("ack")
        await ack(body)

    monkeypatch.setattr(type(acceptance), "accept", traced_accept)
    monkeypatch.setattr(type(correlation), "select", traced_select)
    monkeypatch.setattr(transport, "publish_correlation_snapshot", traced_publish)
    monkeypatch.setattr(transport, "ack_event", traced_ack)

    result = await delivery.poll_once()

    assert result.retry_required is False
    assert timeline[:3] == ["evidence_trigger", "journal_selected", "post"]
    assert timeline.index("journal_selected") < timeline.index("ack")
    assert correlation.pending() == ()
    await delivery.close()
    coverage.close()
    correlation.close()
    acknowledgements.close()
    store.close()


@pytest.mark.asyncio
async def test_intervening_events_are_accepted_before_bound_pcc_and_contiguous_ack(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    intervening = envelope_value(
        key,
        sequence=3,
        normalized_fields={"kind": "intervening"},
    )
    transport, _trigger = _candidate_case(intervening=(intervening,))
    _acceptance, store, acknowledgements, correlation, coverage, delivery = _runtime(
        tmp_path,
        transport,
    )

    result = await delivery.poll_once()

    assert (result.accepted, result.confirmed, result.confirmed_through) == (4, 4, 4)
    assert [
        action[0]
        for action in transport.actions
    ] == ["fetch", "pcc", "fetch", "ack", "ack", "ack", "ack"]
    assert correlation.pending() == ()
    assert [record.ref.source_sequence for record in store.iter_records()] == [1, 2, 3, 4]
    await delivery.close()
    coverage.close()
    correlation.close()
    acknowledgements.close()
    store.close()


@pytest.mark.asyncio
async def test_intervening_candidate_gets_its_own_proof_before_ack(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    outer_trigger = _candidate_trigger(key, sequence=2)
    nested_trigger = _candidate_trigger(key, sequence=3)
    outer_request = _request(outer_trigger, ttl_seconds=120)
    nested_request = _request(nested_trigger, ttl_seconds=120)
    outer_snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(outer_trigger, outer_request, snapshot_sequence=4),
        sequence=4,
    )
    nested_snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(nested_trigger, nested_request, snapshot_sequence=5),
        sequence=5,
    )
    transport = _ScriptedTransport(
        pages=[
            _page_bytes(
                boot_boundary(key),
                outer_trigger,
                reserved_through=2,
            ),
            _page_bytes(
                nested_trigger,
                outer_snapshot,
                reserved_through=4,
            ),
            _page_bytes(
                nested_snapshot,
                acked_through=2,
                reserved_through=5,
            ),
        ],
        acknowledgements=[None] * 5,
        publications=[_direct(outer_snapshot), _direct(nested_snapshot)],
    )
    _acceptance, store, acknowledgements, correlation, coverage, delivery = _runtime(
        tmp_path,
        transport,
    )

    results = [await delivery.poll_once() for _ in range(4)]

    assert [result.retry_required for result in results] == [True, True, True, False]
    assert results[-1].confirmed_through == 5
    assert correlation.pending() == ()
    actions = transport.actions
    publication_indexes = [
        index for index, action in enumerate(actions) if action[0] == "pcc"
    ]
    nested_ack_index = next(
        index
        for index, (action, body, _limit) in enumerate(actions)
        if action == "ack" and json.loads(body)["sequence"] == 3
    )
    assert len(publication_indexes) == 2
    assert publication_indexes[1] < nested_ack_index
    assert [
        json.loads(body)["trigger_event_id"]
        for action, body, _limit in actions
        if action == "pcc"
    ] == [outer_request.trigger_event_id, nested_request.trigger_event_id]
    await _close_runtime(
        delivery,
        coverage,
        correlation,
        acknowledgements,
        store,
    )


@pytest.mark.asyncio
async def test_snapshot_response_with_source_gap_forces_fetch_not_ack(
    tmp_path: Path,
) -> None:
    transport, _trigger = _candidate_case(with_gap=True)
    _acceptance, store, acknowledgements, correlation, coverage, delivery = _runtime(
        tmp_path,
        transport,
    )

    result = await delivery.poll_once()

    assert result.retry_required is True
    assert not any(action[0] == "ack" for action in transport.actions)
    assert tuple(state.phase for state in correlation.pending()) == ("selected",)
    assert store.status().evidence_head == 2
    await delivery.close()
    coverage.close()
    correlation.close()
    acknowledgements.close()
    store.close()


@pytest.mark.asyncio
async def test_proof_observed_keeps_ingesting_until_coverage_gap_closes(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    trigger = _candidate_trigger(key, sequence=4)
    request = _request(trigger, ttl_seconds=120)
    gap_open = envelope_value(
        key,
        sequence=5,
        event_type="coverage",
        normalized_fields={
            "component": "observer",
            "kind": "observer_sequence_gap",
            "severity": "CRITICAL",
            "opened_at": NOW,
            "affected_source_sequence_start": 2,
            "affected_source_sequence_end": 3,
            "reason_code": "reserved_sequence_not_published",
        },
        coverage_flags=["reconcile_required", "sequence_gap"],
    )
    docker_open = envelope_value(
        key,
        sequence=7,
        event_type="coverage",
        normalized_fields={
            "component": "observer",
            "kind": "docker_reconcile_gap",
            "severity": "CRITICAL",
            "opened_at": NOW,
            "reason_code": "observer_startup",
            "reconcile_generation": 1,
        },
        coverage_flags=["docker_event_gap", "reconcile_required"],
        inventory_generation=1,
    )
    docker_recovery = envelope_value(
        key,
        sequence=8,
        event_type="coverage",
        normalized_fields={
            "component": "observer",
            "kind": "docker_reconcile_recovered",
            "severity": "INFO",
            "opened_at": NOW,
            "closed_at": NOW,
            "reason_code": "docker_full_reconcile_succeeded",
            "reconcile_generation": 1,
        },
        coverage_flags=["docker_event_gap", "reconcile_required"],
        inventory_generation=1,
    )
    gap_close = envelope_value(
        key,
        sequence=9,
        event_type="coverage",
        normalized_fields={
            "component": "observer",
            "kind": "observer_sequence_gap",
            "severity": "INFO",
            "opened_at": NOW,
            "closed_at": NOW,
            "affected_source_sequence_start": 2,
            "affected_source_sequence_end": 3,
            "reason_code": "reserved_sequence_reconciled",
            "reconcile_generation": 1,
        },
        coverage_flags=["reconcile_required", "sequence_gap"],
        inventory_generation=1,
    )
    snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(trigger, request, snapshot_sequence=6),
        sequence=6,
    )
    transport = _ScriptedTransport(
        pages=[
            _page_bytes(
                boot_boundary(key),
                trigger,
                reserved_through=4,
                uncovered_gaps=[{"start": 2, "end": 3}],
            ),
            _page_bytes(gap_open, snapshot, reserved_through=6),
            _page_bytes(
                docker_open,
                docker_recovery,
                gap_close,
                acked_through=4,
                reserved_through=9,
            ),
        ],
        acknowledgements=[None] * 4,
        publications=[_direct(snapshot)],
    )
    _acceptance, store, acknowledgements, correlation, coverage, delivery = _runtime(
        tmp_path,
        transport,
    )

    blocked = await delivery.poll_once()
    released = await delivery.poll_once()

    assert (blocked.confirmed_through, blocked.evidence_head) == (4, 9)
    assert blocked.retry_required is True
    assert (released.confirmed_through, released.evidence_head) == (6, 9)
    assert released.retry_required is False
    assert correlation.pending() == ()
    assert [action[0] for action in transport.actions].count("fetch") == 3
    await _close_runtime(
        delivery,
        coverage,
        correlation,
        acknowledgements,
        store,
    )


@pytest.mark.asyncio
async def test_non_candidate_and_investigation_only_keep_generic_delivery(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    ordinary = envelope_value(
        key,
        sequence=2,
        normalized_fields={"kind": "ordinary"},
    )
    candidate = _candidate_trigger(key, sequence=3)
    fields = dict(candidate["normalized_fields"])
    fields["investigation_only"] = True
    investigation = envelope_value(
        key,
        sequence=3,
        event_type="falco_connect",
        normalized_fields=fields,
        source_payload_hash=str(fields["raw_event_sha256"]),
        container_id=str(candidate["container_id"]),
        container_start_time=str(candidate["container_start_time"]),
        release_id=str(candidate["release_id"]),
        inventory_generation=int(candidate["inventory_generation"]),
        inventory_revision=int(candidate["inventory_revision"]),
    )
    transport = _ScriptedTransport(
        pages=[
            _page_bytes(
                boot_boundary(key),
                ordinary,
                investigation,
                reserved_through=3,
            )
        ],
        acknowledgements=[None, None, None],
    )
    _acceptance, store, acknowledgements, correlation, coverage, delivery = _runtime(
        tmp_path,
        transport,
    )

    result = await delivery.poll_once()

    assert (result.accepted, result.confirmed) == (3, 3)
    assert not any(action[0] == "pcc" for action in transport.actions)
    assert correlation.pending() == ()
    await delivery.close()
    coverage.close()
    correlation.close()
    acknowledgements.close()
    store.close()


@pytest.mark.asyncio
async def test_recovered_selected_rejects_an_already_confirmed_trigger(
    tmp_path: Path,
) -> None:
    path = tmp_path / "retroactive-proof"
    (
        acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        _trigger,
        snapshot,
        _expected_body,
    ) = _seed_selected(path)
    trigger_ref = store.authenticated_refs(
        after_sequence=1,
        through_sequence=2,
        limit=1,
    )[0]
    acknowledgements.record_pending(trigger_ref)
    acknowledgements.record_confirmed(trigger_ref)
    transport = _ScriptedTransport(publications=[_direct(snapshot)])
    delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        correlation,
        transport,
        coverage=coverage,
        clock=_DeliveryClock(),
    )

    with pytest.raises(DeliveryFatalError, match="behind durable confirmation"):
        await delivery.poll_once()

    assert transport.actions == []
    assert tuple(state.phase for state in correlation.pending()) == ("selected",)
    await _close_runtime(
        delivery,
        coverage,
        correlation,
        acknowledgements,
        store,
    )


@pytest.mark.asyncio
async def test_mutation_read_only_unavailable_keeps_selected_and_unacknowledged(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unavailable"
    (
        acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        _trigger,
        _snapshot,
        expected_body,
    ) = _seed_selected(path)
    transport = _ScriptedTransport(
        publications=[DeliveryRetryableError("typed 503 unavailable")],
    )
    delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        correlation,
        transport,
        coverage=coverage,
        clock=_DeliveryClock(),
    )

    result = await delivery.poll_once()

    assert result.retry_required is True
    assert result.confirmed_through == 1
    assert acknowledgements.snapshot().pending is None
    assert tuple(state.phase for state in correlation.pending()) == ("selected",)
    assert transport.actions == [("pcc", expected_body, None)]
    await _close_runtime(
        delivery,
        coverage,
        correlation,
        acknowledgements,
        store,
    )


@pytest.mark.asyncio
async def test_recovered_selected_repeats_the_identical_persisted_request(
    tmp_path: Path,
) -> None:
    path = tmp_path / "selected-restart"
    (
        acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        _trigger,
        snapshot,
        expected_body,
    ) = _seed_selected(path)
    first_transport = _ScriptedTransport(
        publications=[DeliveryRetryableError("typed 503 unavailable")],
    )
    first_delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        correlation,
        first_transport,
        coverage=coverage,
        clock=_DeliveryClock(),
    )
    first = await first_delivery.poll_once()
    assert first.retry_required is True
    await _close_runtime(
        first_delivery,
        coverage,
        correlation,
        acknowledgements,
        store,
    )

    second_transport = _ScriptedTransport(
        pages=[
            _page_bytes(
                snapshot,
                acked_through=1,
                reserved_through=3,
            )
        ],
        acknowledgements=[None, None],
        publications=[_direct(snapshot)],
    )
    (
        _acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        second_delivery,
    ) = _reopen_runtime(path, second_transport)

    recovered = await second_delivery.poll_once()

    published = [
        body
        for action, body, _limit in first_transport.actions + second_transport.actions
        if action == "pcc"
    ]
    assert published == [expected_body, expected_body]
    assert json.loads(expected_body)["requested_ttl_seconds"] == 120
    assert recovered.confirmed_through == 3
    assert recovered.retry_required is False
    assert correlation.pending() == ()
    await _close_runtime(
        second_delivery,
        coverage,
        correlation,
        acknowledgements,
        store,
    )


@pytest.mark.asyncio
async def test_recovered_proof_observed_skips_post_and_resumes_only_ack(
    tmp_path: Path,
) -> None:
    path = tmp_path / "proof-restart"
    (
        acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        _trigger,
        snapshot,
        _expected_body,
    ) = _seed_selected(path)
    selected = correlation.pending()[0]
    snapshot_ref = acceptance.accept_pcc(_item(snapshot), selected.request)
    coverage._apply_live_accepted(store, snapshot_ref, None)
    correlation.mark_proof_observed(selected.request_sha256, snapshot_ref)
    inert_transport = _ScriptedTransport()
    delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        correlation,
        inert_transport,
        coverage=coverage,
        clock=_DeliveryClock(),
    )
    await _close_runtime(
        delivery,
        coverage,
        correlation,
        acknowledgements,
        store,
    )

    resumed_transport = _ScriptedTransport(
        acknowledgements=[None, None],
    )
    (
        _acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        resumed,
    ) = _reopen_runtime(path, resumed_transport)

    result = await resumed.poll_once()

    assert not any(action == "pcc" for action, _body, _limit in resumed_transport.actions)
    assert [
        json.loads(body)["sequence"]
        for action, body, _limit in resumed_transport.actions
        if action == "ack"
    ] == [2, 3]
    assert result.confirmed_through == 3
    assert correlation.pending() == ()
    await _close_runtime(
        resumed,
        coverage,
        correlation,
        acknowledgements,
        store,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "crash_point",
    ["after_ack_intent", "after_observer_ack"],
)
async def test_recovered_proof_replays_exact_pending_ack(
    tmp_path: Path,
    crash_point: Literal["after_ack_intent", "after_observer_ack"],
) -> None:
    path = tmp_path / crash_point
    (
        acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        _trigger,
        snapshot,
        _expected_body,
    ) = _seed_selected(path)
    selected = correlation.pending()[0]
    snapshot_ref = acceptance.accept_pcc(_item(snapshot), selected.request)
    coverage._apply_live_accepted(store, snapshot_ref, None)
    correlation.mark_proof_observed(selected.request_sha256, snapshot_ref)
    trigger_ref = store.authenticated_refs(
        after_sequence=1,
        through_sequence=2,
        limit=1,
    )[0]
    acknowledgements.record_pending(trigger_ref)
    pending_body = acknowledgements.pending_request_body()
    assert pending_body is not None
    observer_before_restart = _ScriptedTransport(acknowledgements=[None])
    if crash_point == "after_observer_ack":
        await observer_before_restart.ack_event(pending_body)

    coverage.close()
    correlation.close()
    acknowledgements.close()
    store.close()

    resumed_transport = _ScriptedTransport(acknowledgements=[None, None])
    (
        _acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        resumed,
    ) = _reopen_runtime(path, resumed_transport)

    result = await resumed.poll_once()

    replayed = [
        body
        for action, body, _limit in resumed_transport.actions
        if action == "ack"
    ]
    assert replayed[0] == pending_body
    assert not any(action == "pcc" for action, _body, _limit in resumed_transport.actions)
    assert result.confirmed_through == 3
    assert correlation.pending() == ()
    await _close_runtime(
        resumed,
        coverage,
        correlation,
        acknowledgements,
        store,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("crash_point", CORRELATION_CRASH_POINTS)
async def test_correlation_delivery_restart_converges_with_identical_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
) -> None:
    path = tmp_path / f"matrix-{crash_point}"
    key = private_key(11)
    intervening = envelope_value(
        key,
        sequence=3,
        normalized_fields={"kind": "intervening"},
    )
    first_transport, trigger = _candidate_case(intervening=(intervening,))
    request = _request(trigger, ttl_seconds=120)
    snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(trigger, request, snapshot_sequence=4),
        sequence=4,
    )
    expected_body = canonical_json(request)
    (
        _acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        delivery,
    ) = _runtime(path, first_transport)
    tripped = False

    with monkeypatch.context() as crash_patch:
        if crash_point in {"after_trigger_append", "after_intervening_append"}:
            original_accept_live = DeliveryCoordinator._accept_live_item
            target_sequence = 2 if crash_point == "after_trigger_append" else 3

            def crash_after_live_accept(
                owner: DeliveryCoordinator,
                item: object,
                *,
                request: object | None = None,
            ) -> EvidenceRef:
                nonlocal tripped
                ref = original_accept_live(owner, item, request=request)  # type: ignore[arg-type]
                if (
                    owner is delivery
                    and ref.source_sequence == target_sequence
                    and not tripped
                ):
                    tripped = True
                    raise _Crash(crash_point)
                return ref

            crash_patch.setattr(
                DeliveryCoordinator,
                "_accept_live_item",
                crash_after_live_accept,
            )
        elif crash_point == "after_selected":
            original_select = CorrelationRequestJournal.select

            def crash_after_select(
                owner: CorrelationRequestJournal,
                trigger_ref: EvidenceRef,
                canonical_request: bytes,
            ) -> object:
                nonlocal tripped
                state = original_select(owner, trigger_ref, canonical_request)
                if owner is correlation and not tripped:
                    tripped = True
                    raise _Crash(crash_point)
                return state

            crash_patch.setattr(
                CorrelationRequestJournal,
                "select",
                crash_after_select,
            )
        elif crash_point == "after_post_response":
            original_publish = first_transport.publish_correlation_snapshot

            async def crash_after_post(body: bytes) -> bytes:
                nonlocal tripped
                raw = await original_publish(body)
                if not tripped:
                    tripped = True
                    raise _Crash(crash_point)
                return raw

            crash_patch.setattr(
                first_transport,
                "publish_correlation_snapshot",
                crash_after_post,
            )
        elif crash_point == "after_proof_observed":
            original_observed = CorrelationRequestJournal.mark_proof_observed

            def crash_after_observed(
                owner: CorrelationRequestJournal,
                request_sha256: str,
                snapshot_ref: EvidenceRef,
            ) -> object:
                nonlocal tripped
                state = original_observed(owner, request_sha256, snapshot_ref)
                if owner is correlation and not tripped:
                    tripped = True
                    raise _Crash(crash_point)
                return state

            crash_patch.setattr(
                CorrelationRequestJournal,
                "mark_proof_observed",
                crash_after_observed,
            )
        elif crash_point == "after_ack_intent":
            original_pending = AckJournal.record_pending

            def crash_after_pending(
                owner: AckJournal,
                ref: EvidenceRef,
            ) -> object:
                nonlocal tripped
                result = original_pending(owner, ref)
                if (
                    owner is acknowledgements
                    and ref.source_sequence == 2
                    and not tripped
                ):
                    tripped = True
                    raise _Crash(crash_point)
                return result

            crash_patch.setattr(AckJournal, "record_pending", crash_after_pending)
        else:
            assert crash_point == "after_observer_ack"
            original_ack = first_transport.ack_event

            async def crash_after_ack(body: bytes) -> None:
                nonlocal tripped
                await original_ack(body)
                if json.loads(body)["sequence"] == 2 and not tripped:
                    tripped = True
                    raise _Crash(crash_point)

            crash_patch.setattr(first_transport, "ack_event", crash_after_ack)

        with pytest.raises(_Crash, match=crash_point):
            await delivery.poll_once()

    assert tripped is True
    first_bodies = [
        body
        for action, body, _limit in first_transport.actions
        if action == "pcc"
    ]
    await _close_runtime(
        delivery,
        coverage,
        correlation,
        acknowledgements,
        store,
    )

    expected_head = {
        "after_trigger_append": 2,
        "after_selected": 2,
        "after_post_response": 2,
        "after_intervening_append": 3,
        "after_proof_observed": 4,
        "after_ack_intent": 4,
        "after_observer_ack": 4,
    }[crash_point]
    confirmed_before_restart = (
        1 if crash_point in {"after_ack_intent", "after_observer_ack"} else 0
    )
    remaining = tuple(
        envelope
        for sequence, envelope in ((3, intervening), (4, snapshot))
        if sequence > expected_head
    )
    resumed_transport = _ScriptedTransport(
        pages=(
            [
                _page_bytes(
                    *remaining,
                    acked_through=confirmed_before_restart,
                    reserved_through=4,
                )
            ]
            if remaining
            else []
        ),
        acknowledgements=[None] * 4,
        publications=[_direct(snapshot)],
    )
    (
        _acceptance,
        store,
        acknowledgements,
        correlation,
        coverage,
        resumed,
    ) = _reopen_runtime(path, resumed_transport)

    result = await resumed.poll_once()

    resumed_bodies = [
        body
        for action, body, _limit in resumed_transport.actions
        if action == "pcc"
    ]
    all_bodies = first_bodies + resumed_bodies
    assert all_bodies
    assert all(body == expected_body for body in all_bodies)
    assert all(json.loads(body)["requested_ttl_seconds"] == 120 for body in all_bodies)
    assert result.retry_required is False
    assert result.confirmed_through == 4
    assert correlation.pending() == ()
    await _close_runtime(
        resumed,
        coverage,
        correlation,
        acknowledgements,
        store,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["a", "b", "c"])
async def test_cross_boot_abc_proof_allows_ordered_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: Literal["a", "b", "c"],
) -> None:
    path = tmp_path / f"cross-boot-{mode}"
    acceptance, request, snapshot = _cross_boot_with_ttl_120(path, mode)
    store = acceptance.segment_store
    refs = store.authenticated_refs(
        after_sequence=0,
        through_sequence=store.status().evidence_head,
        limit=10,
    )
    trigger_ref = next(ref for ref in refs if ref.source_sequence == 2)
    acknowledgements = AckJournal.create_new(store)
    acknowledgements.record_pending(refs[0])
    acknowledgements.record_confirmed(refs[0])
    correlation = CorrelationRequestJournal.create_new(store)
    selected = correlation.select(trigger_ref, canonical_json(request))
    coverage = CoverageState.open_and_recover(store)
    transport = _ScriptedTransport(
        pages=[
            _page_bytes(
                snapshot,
                acked_through=1,
                reserved_through=int(snapshot["source_sequence"]),
            )
        ],
        acknowledgements=[None] * (int(snapshot["source_sequence"]) - 1),
        publications=[_direct(snapshot)],
    )
    seen_requests: list[bytes] = []
    accept_pcc = AcceptanceCoordinator.accept_pcc

    def traced_accept_pcc(
        owner: AcceptanceCoordinator,
        item: object,
        persisted: object,
    ) -> EvidenceRef:
        if owner is acceptance:
            seen_requests.append(canonical_json(persisted))
        return accept_pcc(owner, item, persisted)  # type: ignore[arg-type]

    monkeypatch.setattr(AcceptanceCoordinator, "accept_pcc", traced_accept_pcc)
    delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        correlation,
        transport,
        coverage=coverage,
        clock=_DeliveryClock(),
    )

    result = await delivery.poll_once()

    assert seen_requests == [canonical_json(selected.request)]
    assert result.confirmed_through == int(snapshot["source_sequence"])
    assert correlation.pending() == ()
    await _close_runtime(
        delivery,
        coverage,
        correlation,
        acknowledgements,
        store,
    )


@pytest.mark.asyncio
async def test_invalid_cross_boot_chain_never_reaches_proof_observed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cross-boot-invalid"
    acceptance, request, valid_snapshot = _cross_boot_with_ttl_120(path, "b")
    fields = dict(valid_snapshot["normalized_fields"])
    fields["boot_transition_chain_sha256"] = "0" * 64
    forged = _snapshot_envelope(
        private_key(12),
        fields,
        sequence=5,
        boot_id=BOOT_B,
        key_epoch=2,
    )
    store = acceptance.segment_store
    refs = store.authenticated_refs(
        after_sequence=0,
        through_sequence=4,
        limit=10,
    )
    trigger_ref = next(ref for ref in refs if ref.source_sequence == 2)
    acknowledgements = AckJournal.create_new(store)
    acknowledgements.record_pending(refs[0])
    acknowledgements.record_confirmed(refs[0])
    correlation = CorrelationRequestJournal.create_new(store)
    correlation.select(trigger_ref, canonical_json(request))
    coverage = CoverageState.open_and_recover(store)
    transport = _ScriptedTransport(
        pages=[
            _page_bytes(
                forged,
                acked_through=1,
                reserved_through=5,
            )
        ],
        publications=[_direct(forged)],
    )
    delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        correlation,
        transport,
        coverage=coverage,
        clock=_DeliveryClock(),
    )

    with pytest.raises(DeliveryFatalError):
        await delivery.poll_once()

    assert tuple(state.phase for state in correlation.pending()) == ("selected",)
    assert acknowledgements.snapshot().confirmed_through == 1
    assert acknowledgements.snapshot().pending is None
    await _close_runtime(
        delivery,
        coverage,
        correlation,
        acknowledgements,
        store,
    )
