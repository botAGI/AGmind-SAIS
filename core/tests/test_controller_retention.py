from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest
from agmind_immune import controller as controller_module
from agmind_immune.evidence import retention as retention_module
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.projection import ProjectionError, ProjectionStore
from agmind_immune.ingest import service as service_module
from agmind_immune.ingest.ack_journal import (
    AckJournal,
    AckJournalSnapshot,
)
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import EnvelopeVerifier
from agmind_immune.ingest.service import (
    AcceptanceCoordinator,
    DeliveryRetryableError,
)

from tests.evidence.test_retention import (
    FRESH,
    RETENTION_TARGET_BYTES,
    _accepted_blocked,
    _blocked_request,
    _FactSpec,
    _live_store_with_active_routine,
    _proof_clock,
    _retention_proof_case,
    _snapshot,
)
from tests.ingest.test_retention_delivery import (
    _bound_blocked_evidence_appended,
    _item,
    _production_blocked,
    _RetentionTransport,
    _selected_blocked_retention_state,
    _selected_retention_state,
    _tombstone,
)
from tests.phase5b_helpers import (
    boot_boundary,
    envelope_value,
    private_key,
)
from tests.test_controller import _authorities, _Clock


class _CountingClock(_Clock):
    def __init__(self, *, sample: object) -> None:
        super().__init__(sample=sample)
        self.samples = 0

    def decision_sample(self) -> object:
        self.samples += 1
        return super().decision_sample()


class _RetryableBlockedTransport(_RetentionTransport):
    async def publish_retention_blocked(
        self,
        canonical_body: bytes,
    ) -> bytes:
        self.posts.append(("blocked", canonical_body))
        raise DeliveryRetryableError("injected observer retry")


class _CorruptingRetryableBlockedTransport(_RetryableBlockedTransport):
    def __init__(
        self,
        journal: retention_module.RetentionStateJournal,
        altered: retention_module.RetentionStateV1,
    ) -> None:
        super().__init__()
        self._journal = journal
        self._altered = altered

    async def publish_retention_blocked(
        self,
        canonical_body: bytes,
    ) -> bytes:
        self._journal._state = self._altered
        return await super().publish_retention_blocked(canonical_body)


class _CancellingTombstoneTransport(_RetentionTransport):
    async def publish_retention_tombstone(
        self,
        canonical_body: bytes,
    ) -> bytes:
        self.posts.append(("tombstone", canonical_body))
        raise asyncio.CancelledError


def _publish_retention_state(
    store: object,
    state: retention_module.RetentionStateV1,
) -> None:
    authority = store._open_retention_state_authority(
        _factory=segments_module._RETENTION_STATE_AUTHORITY_FACTORY,
    )
    authority.publish_initial_retention_state(
        retention_module.encode_retention_state(state)
    )


@pytest.mark.asyncio
async def test_retention_rejects_unbound_confirmed_ack_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = private_key(11)
    acceptance, _store, journal, correlation, coverage, projection, _ = _authorities(
        tmp_path / "forged-ack",
        boot_boundary(key),
    )
    actual = journal.snapshot()
    assert actual.confirmed is not None
    forged = AckJournalSnapshot(
        confirmed=replace(
            actual.confirmed,
            content_sha256="0" * 64,
        ),
        pending=None,
        healthy=True,
    )
    controller = controller_module.CoreController.create(
        acceptance,
        journal,
        correlation,
        coverage,
        projection,
        _RetentionTransport(),
        _Clock(sample=_proof_clock()),
    )
    monkeypatch.setattr(journal, "snapshot", lambda: forged)
    try:
        with pytest.raises(controller_module.CoreControllerAuthorityError):
            await controller._run_retention_once()
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_rejects_unbound_pending_ack_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = private_key(11)
    acceptance, store, journal, correlation, coverage, projection, _ = _authorities(
        tmp_path / "forged-pending",
        boot_boundary(key),
    )
    pending_ref = acceptance.accept(
        _item(
            envelope_value(
                key,
                sequence=2,
                normalized_fields={"kind": "forged-pending"},
            )
        )
    )
    coverage._apply_live_accepted(store, pending_ref, None)
    journal.record_pending(pending_ref)
    actual = journal.snapshot()
    assert actual.pending is not None
    forged = AckJournalSnapshot(
        confirmed=actual.confirmed,
        pending=replace(
            actual.pending,
            content_sha256="0" * 64,
        ),
        healthy=True,
    )
    controller = controller_module.CoreController.create(
        acceptance,
        journal,
        correlation,
        coverage,
        projection,
        _RetentionTransport(),
        _Clock(sample=_proof_clock()),
    )
    monkeypatch.setattr(journal, "snapshot", lambda: forged)
    try:
        with pytest.raises(controller_module.CoreControllerAuthorityError):
            await controller._run_retention_once()
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_pending_ack_precedes_selection_state_and_post(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    acceptance, store, journal, correlation, coverage, projection, _ = _authorities(
        tmp_path / "pending",
        boot_boundary(key),
    )
    pending_ref = acceptance.accept(
        _item(
            envelope_value(
                key,
                sequence=2,
                normalized_fields={"kind": "pending-before-retention"},
            )
        )
    )
    coverage._apply_live_accepted(store, pending_ref, None)
    journal.record_pending(pending_ref)
    transport = _RetentionTransport()
    clock = _CountingClock(sample=_proof_clock())
    controller = controller_module.CoreController.create(
        acceptance,
        journal,
        correlation,
        coverage,
        projection,
        transport,
        clock,
    )
    try:
        execution = await controller._run_retention_once()

        assert type(execution) is controller_module._RetentionExecution
        assert type(execution.observation) is controller_module._RetentionObservation
        assert execution.observation == controller_module._RetentionObservation(
            outcome="retry_required",
            retry_reason="pending_ack",
            request_kind=None,
            request_id=None,
            target_sequence=None,
            target_event_id=None,
            target_content_sha256=None,
            unlinked_manifest_count=0,
            unlinked_bytes=0,
            projection_rebuilt=False,
        )
        assert execution.projected == 1
        assert clock.samples == 1
        assert transport.posts == []
        assert not (store.root / "retention-state.json").exists()
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_pending_ack_hides_preexisting_durable_request(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    acceptance, store, journal, correlation, coverage, projection, _ = _authorities(
        tmp_path / "pending-with-state",
        boot_boundary(key),
    )
    pending_ref = acceptance.accept(
        _item(
            envelope_value(
                key,
                sequence=2,
                normalized_fields={"kind": "pending-with-state"},
            )
        )
    )
    coverage._apply_live_accepted(store, pending_ref, None)
    journal.record_pending(pending_ref)
    store.flush_security_boundary()
    request = _production_blocked(store)
    _publish_retention_state(
        store,
        _selected_blocked_retention_state(request),
    )
    transport = _RetentionTransport()
    controller = controller_module.CoreController.create(
        acceptance,
        journal,
        correlation,
        coverage,
        projection,
        transport,
        _Clock(sample=_proof_clock()),
    )
    try:
        execution = await controller._run_retention_once()

        assert execution.observation == controller_module._RetentionObservation(
            outcome="retry_required",
            retry_reason="pending_ack",
            request_kind=None,
            request_id=None,
            target_sequence=None,
            target_event_id=None,
            target_content_sha256=None,
            unlinked_manifest_count=0,
            unlinked_bytes=0,
            projection_rebuilt=False,
        )
        durable = retention_module._open_retention_state_journal(store)
        assert durable.state is not None
        assert durable.state.phase == "selected"
        assert transport.posts == []
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_not_due_is_one_exact_noop(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    acceptance, store, journal, correlation, coverage, projection, _ = _authorities(
        tmp_path / "not-due",
        boot_boundary(key),
    )
    transport = _RetentionTransport()
    controller = controller_module.CoreController.create(
        acceptance,
        journal,
        correlation,
        coverage,
        projection,
        transport,
        _Clock(sample=_proof_clock()),
    )
    try:
        execution = await controller._run_retention_once()

        assert execution.observation == controller_module._RetentionObservation(
            outcome="not_due",
            retry_reason=None,
            request_kind=None,
            request_id=None,
            target_sequence=None,
            target_event_id=None,
            target_content_sha256=None,
            unlinked_manifest_count=0,
            unlinked_bytes=0,
            projection_rebuilt=False,
        )
        assert execution.projected == 1
        assert transport.posts == []
        assert not (store.root / "retention-state.json").exists()
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_reuses_authenticated_blocked_episode_without_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = private_key(11)
    acceptance, store, journal, correlation, coverage, projection, _ = _authorities(
        tmp_path / "reused-blocked",
        boot_boundary(key),
    )
    pressure = _FactSpec(
        FRESH,
        RETENTION_TARGET_BYTES + 17,
        priority="protected",
        event_types=("coverage",),
    )
    base = _snapshot(pressure)
    accepted = _accepted_blocked(_blocked_request(base))
    snapshot = _snapshot(
        pressure,
        prior_blocked=(accepted,),
    )

    def frozen_snapshot(
        _clock_sample: object,
        *,
        _factory: object,
    ) -> object:
        assert _factory is segments_module._RETENTION_PROOF_FACTORY
        return snapshot

    monkeypatch.setattr(
        store,
        "_freeze_retention_snapshot",
        frozen_snapshot,
    )
    transport = _RetentionTransport()
    controller = controller_module.CoreController.create(
        acceptance,
        journal,
        correlation,
        coverage,
        projection,
        transport,
        _Clock(sample=_proof_clock()),
    )
    try:
        execution = await controller._run_retention_once()

        assert execution.observation == controller_module._RetentionObservation(
            outcome="blocked_unchanged",
            retry_reason=None,
            request_kind="blocked",
            request_id=accepted.request.blocked_id,
            target_sequence=accepted.sequence,
            target_event_id=accepted.event_id,
            target_content_sha256=accepted.content_sha256,
            unlinked_manifest_count=0,
            unlinked_bytes=0,
            projection_rebuilt=False,
        )
        assert transport.posts == []
        assert not (store.root / "retention-state.json").exists()
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_clears_authenticated_blocked_state_in_same_scope(
    tmp_path: Path,
) -> None:
    (
        seed_delivery,
        store,
        _verifier,
        acknowledgements,
        journal,
        target_ref,
        _seed_transport,
    ) = _bound_blocked_evidence_appended(tmp_path / "blocked-clear")
    acceptance = seed_delivery.acceptance
    correlation = seed_delivery.correlation_requests
    assert type(correlation) is CorrelationRequestJournal
    coverage = seed_delivery._coverage_adapter._coverage
    await seed_delivery.close()
    projection = ProjectionStore.open(
        (tmp_path / "blocked-projection.sqlite3").absolute(),
        evidence=store,
        acknowledgements=acknowledgements,
    )
    transport = _RetentionTransport()
    controller = controller_module.CoreController.create(
        acceptance,
        acknowledgements,
        correlation,
        coverage,
        projection,
        transport,
        _Clock(sample=_proof_clock()),
    )
    try:
        execution = await controller._run_retention_once()

        state = journal.state
        assert state is None
        assert execution.observation == controller_module._RetentionObservation(
            outcome="blocked_reported",
            retry_reason=None,
            request_kind="blocked",
            request_id="11111111-1111-4111-8111-111111111111",
            target_sequence=target_ref.source_sequence,
            target_event_id=target_ref.event_id,
            target_content_sha256=target_ref.content_sha256,
            unlinked_manifest_count=0,
            unlinked_bytes=0,
            projection_rebuilt=False,
        )
        assert not (store.root / "retention-state.json").exists()
        assert store.status().retention_pending is False
        assert transport.posts == []
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_evidence_appended_retryable_propagates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        seed_delivery,
        store,
        _verifier,
        acknowledgements,
        journal,
        _target_ref,
        _seed_transport,
    ) = _bound_blocked_evidence_appended(
        tmp_path / "evidence-appended-retry"
    )
    acceptance = seed_delivery.acceptance
    correlation = seed_delivery.correlation_requests
    assert type(correlation) is CorrelationRequestJournal
    coverage = seed_delivery._coverage_adapter._coverage
    await seed_delivery.close()
    projection = ProjectionStore.open(
        (
            tmp_path / "evidence-appended-retry.sqlite3"
        ).absolute(),
        evidence=store,
        acknowledgements=acknowledgements,
    )
    controller = controller_module.CoreController.create(
        acceptance,
        acknowledgements,
        correlation,
        coverage,
        projection,
        _RetentionTransport(),
        _Clock(sample=_proof_clock()),
    )

    async def impossible_retry(
        _journal: object,
        *,
        _factory: object,
        _lock_authority: object,
    ) -> object:
        del _journal, _factory, _lock_authority
        raise DeliveryRetryableError("injected impossible resume retry")

    monkeypatch.setattr(
        controller._delivery,
        "_deliver_retention_target_locked",
        impossible_retry,
    )
    try:
        with pytest.raises(
            DeliveryRetryableError,
            match="impossible resume",
        ):
            await controller._run_retention_once()
        durable = journal.state
        assert durable is not None
        assert durable.phase == "evidence_appended"
    finally:
        await controller.close()


@pytest.mark.parametrize("confirmed_through", (1, 2))
@pytest.mark.asyncio
async def test_retention_requires_selected_prefix_then_one_surviving_ack(
    tmp_path: Path,
    confirmed_through: int,
) -> None:
    case = _retention_proof_case(
        tmp_path / f"ack-prefix-{confirmed_through}",
        acknowledge=False,
    )
    acknowledgements = AckJournal.create_new(case.store)
    correlation = CorrelationRequestJournal.create_new(case.store)
    for ref in case.store.authenticated_refs(
        after_sequence=0,
        through_sequence=confirmed_through,
        limit=100,
    ):
        acknowledgements.record_pending(ref)
        acknowledgements.record_confirmed(ref)
    verifier = case.store._bound_verifier
    assert type(verifier) is EnvelopeVerifier
    acceptance = AcceptanceCoordinator(
        verifier,
        case.store,
        _factory=service_module._COORDINATOR_FACTORY,
    )
    projection = ProjectionStore.open(
        (
            tmp_path
            / f"ack-prefix-{confirmed_through}.sqlite3"
        ).absolute(),
        evidence=case.store,
        acknowledgements=acknowledgements,
    )
    clock = _CountingClock(sample=_proof_clock(seconds=2))
    controller = controller_module.CoreController.create(
        acceptance,
        acknowledgements,
        correlation,
        case.coverage,
        projection,
        _RetentionTransport(),
        clock,
    )
    state = case.journal.state
    assert type(state) is retention_module.RetentionStateV1
    selected_paths = tuple(
        case.store.root / entry.segment_relative_path
        for entry in state.entries
    )
    try:
        execution = await controller._run_retention_once()

        assert execution.observation.outcome == "retry_required"
        assert execution.observation.retry_reason == "ack_prefix_lag"
        assert execution.observation.request_kind == "tombstone"
        assert execution.observation.request_id == case.request.tombstone_id
        assert execution.observation.target_sequence == (
            case.target_ref.source_sequence
        )
        assert execution.observation.projection_rebuilt is False
        assert clock.samples == 1
        assert all(path.exists() for path in selected_paths)
        assert case.journal.state is not None
        assert case.journal.state.phase == "evidence_appended"
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_selected_prefix_lag_blocks_post(
    tmp_path: Path,
) -> None:
    (
        _key,
        acceptance,
        store,
        coverage,
    ) = _live_store_with_active_routine(
        tmp_path / "selected-prefix-lag",
        acknowledge=False,
    )
    snapshot = store._freeze_retention_snapshot(
        _proof_clock(),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    decision = retention_module.select_retention(
        snapshot,
        request_id="11111111-1111-4111-8111-111111111111",
    )
    request = decision.request
    assert request is not None
    retention_journal = retention_module._open_retention_state_journal(
        store
    )
    retention_journal.prepare_publication(decision)
    acknowledgements = AckJournal.create_new(store)
    correlation = CorrelationRequestJournal.create_new(store)
    first_ref = store.authenticated_refs(
        after_sequence=0,
        through_sequence=1,
        limit=1,
    )[0]
    acknowledgements.record_pending(first_ref)
    acknowledgements.record_confirmed(first_ref)
    projection = ProjectionStore.open(
        (tmp_path / "selected-prefix-lag.sqlite3").absolute(),
        evidence=store,
        acknowledgements=acknowledgements,
    )
    transport = _RetentionTransport()
    controller = controller_module.CoreController.create(
        acceptance,
        acknowledgements,
        correlation,
        coverage,
        projection,
        transport,
        _Clock(sample=_proof_clock(seconds=1)),
    )
    try:
        execution = await controller._run_retention_once()

        assert execution.observation.outcome == "retry_required"
        assert execution.observation.retry_reason == "ack_prefix_lag"
        assert execution.observation.target_sequence is None
        assert transport.posts == []
        durable = retention_journal.state
        assert durable is not None
        assert durable.phase == "selected"
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_maps_retryable_only_after_durable_request(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    acceptance, store, journal, correlation, coverage, projection, _ = _authorities(
        tmp_path / "retryable",
        boot_boundary(key),
    )
    store.flush_security_boundary()
    request = _production_blocked(store)
    _publish_retention_state(
        store,
        _selected_blocked_retention_state(request),
    )
    transport = _RetryableBlockedTransport()
    controller = controller_module.CoreController.create(
        acceptance,
        journal,
        correlation,
        coverage,
        projection,
        transport,
        _Clock(sample=_proof_clock()),
    )
    try:
        execution = await controller._run_retention_once()

        assert execution.observation == controller_module._RetentionObservation(
            outcome="retry_required",
            retry_reason="observer_retryable",
            request_kind="blocked",
            request_id=request.blocked_id,
            target_sequence=None,
            target_event_id=None,
            target_content_sha256=None,
            unlinked_manifest_count=0,
            unlinked_bytes=0,
            projection_rebuilt=False,
        )
        assert len(transport.posts) == 1
        durable = retention_module._open_retention_state_journal(store)
        assert durable.state is not None
        assert durable.state.phase == "selected"
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_retryable_rejects_cache_that_differs_from_durable_raw(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    acceptance, store, journal, correlation, coverage, projection, _ = _authorities(
        tmp_path / "retryable-corrupt-cache",
        boot_boundary(key),
    )
    store.flush_security_boundary()
    request = _production_blocked(store)
    _publish_retention_state(
        store,
        _selected_blocked_retention_state(request),
    )
    durable = retention_module._open_retention_state_journal(store)
    state = durable.state
    assert type(state) is retention_module.RetentionStateV1
    altered_document = state.model_dump(exclude_none=False)
    altered_request = dict(altered_document["request"])
    altered_request["blocked_id"] = (
        "22222222-2222-4222-8222-222222222222"
    )
    altered_document["request"] = altered_request
    altered = retention_module.RetentionStateV1.model_validate(
        altered_document,
        strict=True,
    )
    controller = controller_module.CoreController.create(
        acceptance,
        journal,
        correlation,
        coverage,
        projection,
        _CorruptingRetryableBlockedTransport(durable, altered),
        _Clock(sample=_proof_clock()),
    )
    try:
        with pytest.raises(retention_module.RetentionStateCorrupt):
            await controller._run_retention_once()
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_cancellation_propagates_with_selected_state_intact(
    tmp_path: Path,
) -> None:
    (
        _key,
        acceptance,
        store,
        coverage,
    ) = _live_store_with_active_routine(
        tmp_path / "cancelled-selected",
        acknowledge=False,
    )
    snapshot = store._freeze_retention_snapshot(
        _proof_clock(),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    decision = retention_module.select_retention(
        snapshot,
        request_id="11111111-1111-4111-8111-111111111111",
    )
    state_journal = retention_module._open_retention_state_journal(store)
    state_journal.prepare_publication(decision)
    state = state_journal.state
    assert type(state) is retention_module.RetentionStateV1
    selected_paths = tuple(
        store.root / entry.segment_relative_path
        for entry in state.entries
    )
    acknowledgements = AckJournal.create_new(store)
    correlation = CorrelationRequestJournal.create_new(store)
    for ref in store.authenticated_refs(
        after_sequence=0,
        through_sequence=2,
        limit=100,
    ):
        acknowledgements.record_pending(ref)
        acknowledgements.record_confirmed(ref)
    projection = ProjectionStore.open(
        (tmp_path / "cancelled-selected.sqlite3").absolute(),
        evidence=store,
        acknowledgements=acknowledgements,
    )
    transport = _CancellingTombstoneTransport()
    controller = controller_module.CoreController.create(
        acceptance,
        acknowledgements,
        correlation,
        coverage,
        projection,
        transport,
        _Clock(sample=_proof_clock(seconds=1)),
    )
    try:
        with pytest.raises(asyncio.CancelledError):
            await controller._run_retention_once()
        durable = state_journal.state
        assert durable is not None
        assert durable.phase == "selected"
        assert all(path.exists() for path in selected_paths)
        assert len(transport.posts) == 1
    finally:
        await controller.close()


@pytest.mark.parametrize(
    "restart_phase",
    (
        "retention_unlink_in_progress",
        "retention_commit_uncertain",
        "completed",
    ),
)
@pytest.mark.asyncio
async def test_retention_restart_only_phases_propagate(
    tmp_path: Path,
    restart_phase: str,
) -> None:
    key = private_key(11)
    acceptance, store, journal, correlation, coverage, projection, _ = _authorities(
        tmp_path / restart_phase,
        boot_boundary(key),
    )
    selected = _selected_retention_state(_tombstone())
    target = retention_module.RetentionTargetV1(
        sequence=2,
        event_id="evt_" + "1" * 64,
        content_sha256="2" * 64,
    )
    evidence_appended = (
        retention_module.advance_retention_evidence_appended(
            selected,
            target,
        )
    )
    execution_states = retention_module._retention_execution_states(
        evidence_appended
    )
    by_phase = {state.phase: state for state in execution_states}
    _publish_retention_state(store, by_phase[restart_phase])
    controller = controller_module.CoreController.create(
        acceptance,
        journal,
        correlation,
        coverage,
        projection,
        _RetentionTransport(),
        _Clock(sample=_proof_clock()),
    )
    try:
        with pytest.raises(
            retention_module.RetentionProtocolError,
            match="restart",
        ):
            await controller._run_retention_once()
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_aborts_before_unlink_when_projection_catchup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _retention_proof_case(
        tmp_path / "projection-prefix-evidence",
        acknowledge=True,
    )
    acknowledgements = case.store._ack_journal_owner
    verifier = case.store._bound_verifier
    assert type(acknowledgements) is AckJournal
    assert type(verifier) is EnvelopeVerifier
    correlation = CorrelationRequestJournal.create_new(case.store)
    acceptance = AcceptanceCoordinator(
        verifier,
        case.store,
        _factory=service_module._COORDINATOR_FACTORY,
    )
    projection = ProjectionStore.open(
        (tmp_path / "projection-prefix.sqlite3").absolute(),
        evidence=case.store,
        acknowledgements=acknowledgements,
    )
    controller = controller_module.CoreController.create(
        acceptance,
        acknowledgements,
        correlation,
        case.coverage,
        projection,
        _RetentionTransport(),
        _Clock(sample=_proof_clock(seconds=2)),
    )
    state = case.journal.state
    assert type(state) is retention_module.RetentionStateV1
    selected_paths = tuple(
        case.store.root / entry.segment_relative_path
        for entry in state.entries
    )

    def fail_apply(_ref: object) -> object:
        raise ProjectionError("injected prefix failure")

    monkeypatch.setattr(projection, "apply", fail_apply)
    try:
        with pytest.raises(
            controller_module.CoreControllerAuthorityError,
            match="projection",
        ):
            await controller._run_retention_once()
        assert all(path.exists() for path in selected_paths)
        durable = case.journal.state
        assert durable is not None
        assert durable.phase == "evidence_appended"
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_completes_unlink_rebuild_and_finalization(
    tmp_path: Path,
) -> None:
    case = _retention_proof_case(
        tmp_path / "evidence",
        acknowledge=True,
    )
    acknowledgements = case.store._ack_journal_owner
    verifier = case.store._bound_verifier
    assert type(acknowledgements) is AckJournal
    assert type(verifier) is EnvelopeVerifier
    correlation = CorrelationRequestJournal.create_new(case.store)
    acceptance = AcceptanceCoordinator(
        verifier,
        case.store,
        _factory=service_module._COORDINATOR_FACTORY,
    )
    projection = ProjectionStore.open(
        (tmp_path / "projection.sqlite3").absolute(),
        evidence=case.store,
        acknowledgements=acknowledgements,
    )
    transport = _RetentionTransport()
    controller = controller_module.CoreController.create(
        acceptance,
        acknowledgements,
        correlation,
        case.coverage,
        projection,
        transport,
        _Clock(sample=_proof_clock(seconds=2)),
    )
    state = case.journal.state
    assert type(state) is retention_module.RetentionStateV1
    selected_paths = tuple(
        case.store.root / entry.segment_relative_path
        for entry in state.entries
    )
    try:
        execution = await controller._run_retention_once()

        assert execution.observation == controller_module._RetentionObservation(
            outcome="tombstone_completed",
            retry_reason=None,
            request_kind="tombstone",
            request_id=case.request.tombstone_id,
            target_sequence=case.target_ref.source_sequence,
            target_event_id=case.target_ref.event_id,
            target_content_sha256=case.target_ref.content_sha256,
            unlinked_manifest_count=len(
                case.request.removed_manifest_hashes
            ),
            unlinked_bytes=case.request.removed_bytes,
            projection_rebuilt=True,
        )
        assert execution.projected == 3
        assert all(not path.exists() for path in selected_paths)
        assert not (case.store.root / "retention-state.json").exists()
        cursor = projection.status().cursor
        assert cursor is not None
        assert cursor.source_sequence == case.target_ref.source_sequence
        assert transport.posts == []
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_retention_rebuild_failure_latches_and_does_not_finalize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _retention_proof_case(
        tmp_path / "rebuild-failure-evidence",
        acknowledge=True,
    )
    acknowledgements = case.store._ack_journal_owner
    verifier = case.store._bound_verifier
    assert type(acknowledgements) is AckJournal
    assert type(verifier) is EnvelopeVerifier
    correlation = CorrelationRequestJournal.create_new(case.store)
    acceptance = AcceptanceCoordinator(
        verifier,
        case.store,
        _factory=service_module._COORDINATOR_FACTORY,
    )
    projection = ProjectionStore.open(
        (tmp_path / "rebuild-failure.sqlite3").absolute(),
        evidence=case.store,
        acknowledgements=acknowledgements,
    )
    controller = controller_module.CoreController.create(
        acceptance,
        acknowledgements,
        correlation,
        case.coverage,
        projection,
        _RetentionTransport(),
        _Clock(sample=_proof_clock(seconds=2)),
    )
    state = case.journal.state
    assert type(state) is retention_module.RetentionStateV1
    selected_paths = tuple(
        case.store.root / entry.segment_relative_path
        for entry in state.entries
    )

    def fail_rebuild(
        _completion: object,
        *,
        _factory: object,
    ) -> object:
        del _completion, _factory
        raise ProjectionError("injected retention rebuild failure")

    monkeypatch.setattr(
        projection,
        "_rebuild_after_authenticated_retention",
        fail_rebuild,
    )
    try:
        with pytest.raises(
            ProjectionError,
            match="retention rebuild",
        ):
            await controller._run_retention_once()
        assert controller._projection_healthy is False
        assert all(not path.exists() for path in selected_paths)
        durable = case.journal.state
        assert durable is not None
        assert durable.phase == "completed"
        assert (case.store.root / "retention-state.json").exists()
    finally:
        await controller.close()
