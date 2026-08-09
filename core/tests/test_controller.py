from __future__ import annotations

import importlib
from dataclasses import replace
from datetime import datetime
from decimal import Decimal
from pathlib import Path

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.clock import CoreClockSample
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.controller import (
    CoreController,
    CoreControllerAuthorityError,
    CoreControllerClockError,
    CoreControllerClosed,
)
from agmind_immune.correlation.primitives import (
    SpecialUseRegistry,
    load_pinned_special_use_registry,
)
from agmind_immune.coverage import CoverageState
from agmind_immune.evidence.projection import (
    ProjectionConflict,
    ProjectionCursor,
    ProjectionError,
    ProjectionStatus,
    ProjectionStore,
)
from agmind_immune.evidence.segments import EvidenceRef, SegmentStore
from agmind_immune.ingest.ack_journal import (
    AckIdentity,
    AckJournal,
    AckJournalError,
    AckJournalSnapshot,
)
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeVerifier,
    PinnedObserverRoot,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator

from tests.phase5b_helpers import (
    NOW,
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
)


@pytest.fixture(autouse=True)
def _fixed_detector_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: "1" * 64)


class _Clock:
    def __init__(
        self,
        *,
        receipts: list[float | None] | None = None,
        sample: CoreClockSample | BaseException | None = None,
    ) -> None:
        self.receipts = receipts or []
        self.sample = sample or CoreClockSample(
            decision_utc=datetime.fromisoformat(NOW),
            decision_monotonic=101.0,
            healthy=True,
            uncertainty_seconds=Decimal("0.1"),
            max_uncertainty_seconds=Decimal(1),
        )

    def live_receipt_monotonic(self) -> float | None:
        return self.receipts.pop(0) if self.receipts else None

    def decision_sample(self) -> CoreClockSample:
        if isinstance(self.sample, BaseException):
            raise self.sample
        return self.sample


class _Transport:
    def __init__(
        self,
        pages: list[bytes] | None = None,
        ack_count: int = 0,
        publications: list[bytes | BaseException] | None = None,
    ) -> None:
        self.pages = pages or []
        self.ack_count = ack_count
        self.publications = publications or []
        self.acked: list[int] = []
        self.published: list[bytes] = []

    async def fetch_events(self, *, after: int, limit: int) -> bytes:
        assert 1 <= limit <= 100
        if not self.pages:
            raise AssertionError(f"unexpected fetch after {after}")
        return self.pages.pop(0)

    async def ack_event(self, body: bytes) -> None:
        assert self.ack_count > 0
        self.ack_count -= 1
        import json

        self.acked.append(int(json.loads(body)["sequence"]))

    async def publish_correlation_snapshot(self, canonical_body: bytes) -> bytes:
        self.published.append(bytes(canonical_body))
        if not self.publications:
            raise AssertionError("unexpected PCC publication")
        result = self.publications.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    async def close(self) -> None:
        return None


def _page(
    *events: dict[str, object],
    acked: int = 0,
    reserved: int | None = None,
) -> bytes:
    value = page_value(*events)
    value["acked_through"] = acked
    if reserved is not None:
        value["reserved_through"] = reserved
    return canonical_json(value)


def _authorities(
    path: Path,
    *seed: dict[str, object],
) -> tuple[
    AcceptanceCoordinator,
    SegmentStore,
    AckJournal,
    CorrelationRequestJournal,
    SpecialUseRegistry,
    CoverageState,
    ProjectionStore,
    tuple[EvidenceRef, ...],
]:
    path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path / "evidence")
    acceptance = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    journal = AckJournal.create_new(store)
    correlation = CorrelationRequestJournal.create_new(store)
    registry = load_pinned_special_use_registry(
        Path(__file__).resolve().parents[2] / "contracts/v1/ipv4-special-use.csv"
    )
    refs = tuple(
        acceptance.accept(
            decode_events_page(canonical_json(page_value(value))).events[0]
        )
        for value in seed
    )
    for ref in refs:
        journal.record_pending(ref)
        journal.record_confirmed(ref)
    coverage = CoverageState.open_and_recover(store)
    projection = ProjectionStore.open(
        path / "projection.sqlite3",
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    return (
        acceptance,
        store,
        journal,
        correlation,
        registry,
        coverage,
        projection,
        refs,
    )


def _ready_events() -> tuple[dict[str, object], ...]:
    key = private_key(11)
    return (
        boot_boundary(key),
        envelope_value(
            key,
            sequence=2,
            event_type="observer_start",
            normalized_fields={
                "kind": "observer_start",
                "reconcile_required": True,
            },
            coverage_flags=["reconcile_required"],
        ),
        envelope_value(
            key,
            sequence=3,
            event_type="coverage",
            normalized_fields={
                "component": "observer",
                "kind": "docker_reconcile_gap",
                "severity": "CRITICAL",
                "opened_at": NOW,
                "reason_code": "observer_startup",
                "reconcile_generation": 1,
            },
            inventory_generation=1,
            coverage_flags=["docker_event_gap", "reconcile_required"],
        ),
        envelope_value(
            key,
            sequence=4,
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
            inventory_generation=1,
            coverage_flags=["docker_event_gap", "reconcile_required"],
        ),
        envelope_value(
            key,
            sequence=5,
            event_type="coverage",
            normalized_fields={
                "component": "falco-adapter",
                "kind": "falco_heartbeat_lease",
                "severity": "INFO",
                "opened_at": NOW,
                "closed_at": NOW,
                "reason_code": "valid_heartbeat",
            },
            source_payload_hash="a" * 64,
        ),
    )


def test_controller_requires_correlation_journal_from_the_same_evidence_root(
    tmp_path: Path,
) -> None:
    (
        acceptance,
        store,
        journal,
        primary_correlation,
        registry,
        coverage,
        projection,
        _,
    ) = _authorities(tmp_path / "primary")
    (
        _foreign_acceptance,
        foreign_store,
        foreign_ack,
        foreign_correlation,
        _foreign_registry,
        foreign_coverage,
        foreign_projection,
        _,
    ) = _authorities(tmp_path / "foreign")

    with pytest.raises(CoreControllerAuthorityError):
        CoreController.create(
            acceptance,
            journal,
            foreign_correlation,
            registry,
            coverage,
            projection,
            _Transport(),
            _Clock(),
        )

    projection.close()
    coverage.close()
    primary_correlation.close()
    journal.close()
    store.close()
    foreign_projection.close()
    foreign_coverage.close()
    foreign_correlation.close()
    foreign_ack.close()
    foreign_store.close()


@pytest.mark.parametrize("substitution", ("correlation", "registry", "projection"))
def test_controller_requires_projection_correlation_and_registry_from_same_root(
    tmp_path: Path,
    substitution: str,
) -> None:
    primary = _authorities(tmp_path / "primary-exact")
    foreign = _authorities(tmp_path / "foreign-exact")
    (
        acceptance,
        store,
        acknowledgements,
        correlation,
        registry,
        coverage,
        projection,
        _,
    ) = primary
    (
        _foreign_acceptance,
        foreign_store,
        foreign_acknowledgements,
        foreign_correlation,
        foreign_registry,
        foreign_coverage,
        foreign_projection,
        _,
    ) = foreign
    selected_correlation = (
        foreign_correlation if substitution == "correlation" else correlation
    )
    selected_registry = foreign_registry if substitution == "registry" else registry
    selected_projection = (
        foreign_projection if substitution == "projection" else projection
    )
    try:
        with pytest.raises(CoreControllerAuthorityError):
            CoreController.create(
                acceptance,
                acknowledgements,
                selected_correlation,
                selected_registry,
                coverage,
                selected_projection,
                _Transport(),
                _Clock(),
            )
    finally:
        projection.close()
        coverage.close()
        correlation.close()
        acknowledgements.close()
        store.close()
        foreign_projection.close()
        foreign_coverage.close()
        foreign_correlation.close()
        foreign_acknowledgements.close()
        foreign_store.close()


@pytest.mark.parametrize(
    ("pending_changes", "expected_reason"),
    (
        pytest.param(
            {"repair_pending": True},
            "repair_pending",
            id="repair-pending",
        ),
        pytest.param(
            {"retention_pending": True},
            "retention_pending",
            id="retention-pending",
        ),
    ),
)
@pytest.mark.asyncio
async def test_controller_maps_evidence_pending_without_collapsing_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pending_changes: dict[str, bool],
    expected_reason: str,
) -> None:
    acceptance, store, journal, correlation, registry, coverage, projection, _ = _authorities(
        tmp_path / "runtime"
    )
    controller = CoreController.create(
        acceptance,
        journal,
        correlation,
        registry,
        coverage,
        projection,
        _Transport([_page(*_ready_events(), reserved=5)], ack_count=5),
        _Clock(receipts=[None, None, None, None, 100.0]),
    )
    try:
        baseline = (await controller.poll_once()).readiness
        assert baseline.ready
        baseline_status = store.status()
        assert baseline_status.healthy is True

        pending_status = replace(baseline_status, **pending_changes)
        assert pending_status.healthy is True
        monkeypatch.setattr(store, "status", lambda: pending_status)

        readiness = controller.mutation_readiness()
        assert readiness.ready is False
        assert readiness.reason_codes == (expected_reason,)
        assert "evidence_unhealthy" not in readiness.reason_codes
        assert (
            readiness.evidence_head,
            readiness.acceptance_cursor,
            readiness.confirmed_through,
            readiness.projection_cursor,
        ) == (
            baseline.evidence_head,
            baseline.acceptance_cursor,
            baseline.confirmed_through,
            baseline.projection_cursor,
        )
    finally:
        await controller.close()


@pytest.mark.asyncio
async def test_controller_projection_catchup_and_readiness_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = private_key(11)
    (
        lag_acceptance,
        _lag_store,
        lag_journal,
        lag_correlation,
        lag_registry,
        lag_coverage,
        lag_projection,
        lag_refs,
    ) = _authorities(tmp_path / "startup-lag", boot_boundary(key))
    lag_controller = CoreController.create(
        lag_acceptance,
        lag_journal,
        lag_correlation,
        lag_registry,
        lag_coverage,
        lag_projection,
        _Transport([_page(acked=1, reserved=1)]),
        _Clock(),
    )
    lag_result = await lag_controller.poll_once()
    assert lag_result.projected == 1
    assert lag_projection.status().cursor is not None
    assert lag_projection.status().cursor.source_sequence == lag_refs[-1].source_sequence
    await lag_controller.close()

    acceptance, store, journal, correlation, registry, coverage, projection, _ = _authorities(
        tmp_path / "ready"
    )
    applied: list[int] = []
    projection_apply = projection.apply

    def traced_apply(ref: EvidenceRef) -> object:
        applied.append(ref.source_sequence)
        return projection_apply(ref)

    monkeypatch.setattr(projection, "apply", traced_apply)
    clock = _Clock(receipts=[None, None, None, None, 100.0])
    transport = _Transport([_page(*_ready_events(), reserved=5)], ack_count=5)
    controller = CoreController.create(
        acceptance,
        journal,
        correlation,
        registry,
        coverage,
        projection,
        transport,
        clock,
    )
    result = await controller.poll_once()
    assert applied == [1, 2, 3, 4, 5]
    assert result.projected == 5
    assert transport.acked == [1, 2, 3, 4, 5]
    assert (
        result.readiness.evidence_head,
        result.readiness.acceptance_cursor,
        result.readiness.confirmed_through,
        result.readiness.projection_cursor,
    ) == (5, 5, 5, 5)
    assert result.readiness.ready

    original_evidence_status = store.status
    baseline_evidence = original_evidence_status()
    for changes, reason in (
        ({"healthy": False}, "evidence_unhealthy"),
        ({"repair_pending": True}, "repair_pending"),
        ({"key_healthy": False}, "key_unhealthy"),
        ({"acceptance_cursor": 4}, "cursor_evidence_acceptance_mismatch"),
    ):
        selected_status = replace(baseline_evidence, **changes)
        monkeypatch.setattr(
            store,
            "status",
            lambda selected=selected_status: selected,
        )
        assert reason in controller.mutation_readiness().reason_codes
    monkeypatch.setattr(store, "status", original_evidence_status)

    healthy_sample = clock.sample
    assert type(healthy_sample) is CoreClockSample
    clock.sample = replace(healthy_sample, healthy=False)
    assert "clock_unhealthy" in controller.mutation_readiness().reason_codes
    clock.sample = healthy_sample

    original_status = projection.status
    original_snapshot = journal.snapshot
    cursor = original_status().cursor
    confirmed = original_snapshot().confirmed
    assert cursor is not None and confirmed is not None
    substitutions = (
        replace(cursor, host_id="423e4567-e89b-42d3-a456-426614174000"),
        replace(cursor, event_id="evt_" + "0" * 64),
        replace(cursor, content_sha256="0" * 64),
        replace(cursor, frame_sha256="0" * 64),
    )
    for substituted in substitutions:
        controller._projection_healthy = True
        monkeypatch.setattr(
            projection,
            "status",
            lambda selected=substituted: ProjectionStatus(True, selected),
        )
        degraded = controller.mutation_readiness()
        assert degraded.projection_cursor == 5
        assert "projection_unhealthy" in degraded.reason_codes
    monkeypatch.setattr(projection, "status", original_status)

    controller._projection_healthy = True
    wrong_ack = replace(confirmed, content_sha256="0" * 64)
    monkeypatch.setattr(
        journal,
        "snapshot",
        lambda: AckJournalSnapshot(wrong_ack, None, True),
    )
    assert "projection_unhealthy" in controller.mutation_readiness().reason_codes
    monkeypatch.setattr(journal, "snapshot", original_snapshot)

    controller._projection_healthy = True
    fourth = store.authenticated_refs(
        after_sequence=3,
        through_sequence=4,
        limit=1,
    )[0]
    fourth_cursor = ProjectionCursor(
        host_id=cursor.host_id,
        source_sequence=fourth.source_sequence,
        event_id=fourth.event_id,
        content_sha256=fourth.content_sha256,
        frame_sha256=fourth.frame_sha256,
    )
    monkeypatch.setattr(
        projection,
        "status",
        lambda: ProjectionStatus(True, fourth_cursor),
    )
    lagged = controller.mutation_readiness()
    assert lagged.projection_cursor == 4
    assert "cursor_confirmed_projection_mismatch" in lagged.reason_codes
    monkeypatch.setattr(projection, "status", original_status)

    controller._projection_healthy = True
    monkeypatch.setattr(
        journal,
        "snapshot",
        lambda: AckJournalSnapshot(AckIdentity.from_ref(fourth), None, True),
    )
    ack_lagged = controller.mutation_readiness()
    assert ack_lagged.confirmed_through == 4
    assert "cursor_acceptance_confirmed_mismatch" in ack_lagged.reason_codes
    monkeypatch.setattr(journal, "snapshot", original_snapshot)

    controller._projection_healthy = True

    def failed_ack_status() -> AckJournalSnapshot:
        raise AckJournalError("private journal failure")

    monkeypatch.setattr(journal, "snapshot", failed_ack_status)
    no_stale_ack = controller.mutation_readiness()
    assert no_stale_ack.confirmed_through == 0
    assert "ack_journal_unhealthy" in no_stale_ack.reason_codes
    monkeypatch.setattr(journal, "snapshot", original_snapshot)

    controller._projection_healthy = True

    def failed_projection_status() -> ProjectionStatus:
        raise ProjectionError("private projection failure")

    monkeypatch.setattr(projection, "status", failed_projection_status)
    no_stale_projection = controller.mutation_readiness()
    assert no_stale_projection.projection_cursor == 0
    assert "projection_unhealthy" in no_stale_projection.reason_codes
    monkeypatch.setattr(projection, "status", original_status)

    tampered_ack = AckJournalSnapshot(confirmed, None, True)
    object.__setattr__(tampered_ack, "healthy", 1)
    monkeypatch.setattr(journal, "snapshot", lambda: tampered_ack)
    with pytest.raises(CoreControllerAuthorityError):
        controller.mutation_readiness()
    monkeypatch.setattr(journal, "snapshot", original_snapshot)

    tampered_status = ProjectionStatus(True, cursor)
    object.__setattr__(tampered_status, "healthy", 1)
    monkeypatch.setattr(projection, "status", lambda: tampered_status)
    with pytest.raises(CoreControllerAuthorityError):
        controller.mutation_readiness()
    monkeypatch.setattr(projection, "status", original_status)

    clock.sample = RuntimeError("private clock failure")
    with pytest.raises(CoreControllerClockError) as normalized:
        controller.mutation_readiness()
    assert "private" not in str(normalized.value)
    clock.sample = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        controller.mutation_readiness()
    tampered_sample = healthy_sample
    object.__setattr__(tampered_sample, "decision_monotonic", 1)
    clock.sample = tampered_sample
    with pytest.raises(CoreControllerClockError):
        controller.mutation_readiness()
    object.__setattr__(tampered_sample, "decision_monotonic", 101.0)
    clock.sample = CoreClockSample(
        decision_utc=datetime.fromisoformat(NOW),
        decision_monotonic=101.0,
        healthy=True,
        uncertainty_seconds=Decimal("0.1"),
        max_uncertainty_seconds=Decimal(1),
    )
    monkeypatch.setattr(projection, "status", original_status)
    await controller.close()

    (
        capped_acceptance,
        _capped_store,
        capped_journal,
        capped_correlation,
        capped_registry,
        capped_coverage,
        capped_projection,
        capped_refs,
    ) = _authorities(
        tmp_path / "frozen-cap",
        boot_boundary(key),
        envelope_value(key, sequence=2, normalized_fields={"kind": "second"}),
    )
    second = capped_refs[1]
    capped_journal._confirmed = AckIdentity.from_ref(capped_refs[0])
    original_apply = capped_projection.apply

    def advance_during_apply(ref: EvidenceRef) -> object:
        result = original_apply(ref)
        if ref == capped_refs[0]:
            capped_journal.record_pending(second)
            capped_journal.record_confirmed(second)
        return result

    monkeypatch.setattr(capped_projection, "apply", advance_during_apply)
    capped = CoreController.create(
        capped_acceptance,
        capped_journal,
        capped_correlation,
        capped_registry,
        capped_coverage,
        capped_projection,
        _Transport(),
        _Clock(),
    )
    assert capped._catch_up_projection() == 1
    assert capped_projection.status().cursor is not None
    assert capped_projection.status().cursor.source_sequence == 1
    assert capped._catch_up_projection() == 1
    await capped.close()


@pytest.mark.asyncio
async def test_controller_projection_failure_and_shutdown_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = private_key(11)
    acceptance, store, journal, correlation, registry, coverage, projection, _ = _authorities(
        tmp_path / "failure"
    )
    transport = _Transport(
        [
            _page(boot_boundary(key), reserved=1),
            _page(
                envelope_value(
                    key,
                    sequence=2,
                    normalized_fields={"kind": "later"},
                ),
                acked=1,
                reserved=2,
            ),
        ],
        ack_count=2,
    )
    controller = CoreController.create(
        acceptance,
        journal,
        correlation,
        registry,
        coverage,
        projection,
        transport,
        _Clock(),
    )

    def fail_projection(ref: EvidenceRef) -> object:
        raise ProjectionConflict(f"projection failed at {ref.source_sequence}")

    monkeypatch.setattr(projection, "apply", fail_projection)
    first = await controller.poll_once()
    assert first.delivery.confirmed_through == 1
    assert first.readiness.projection_cursor == 0
    assert "projection_unhealthy" in first.readiness.reason_codes
    second = await controller.poll_once()
    assert second.delivery.confirmed_through == 2
    assert journal.snapshot().confirmed_through == 2
    assert second.readiness.projection_cursor == 0
    assert transport.acked == [1, 2]

    order: list[str] = []
    original_delivery_close = controller._delivery.close
    original_projection_close = projection.close
    original_coverage_close = coverage.close
    original_correlation_close = correlation.close
    original_journal_close = journal.close
    original_store_close = store.close
    first_failure = KeyboardInterrupt("private first cleanup failure")

    async def fail_delivery_close() -> None:
        order.append("delivery")
        raise first_failure

    def fail_close(label: str, failure: BaseException) -> object:
        def close() -> None:
            order.append(label)
            raise failure

        return close

    monkeypatch.setattr(controller._delivery, "close", fail_delivery_close)
    monkeypatch.setattr(
        projection,
        "close",
        fail_close("projection", RuntimeError("private projection cleanup")),
    )
    monkeypatch.setattr(
        coverage,
        "close",
        fail_close("coverage", SystemExit("private coverage cleanup")),
    )
    monkeypatch.setattr(
        correlation,
        "close",
        fail_close("correlation", RuntimeError("private correlation cleanup")),
    )
    monkeypatch.setattr(
        journal,
        "close",
        fail_close("journal", RuntimeError("private journal cleanup")),
    )
    monkeypatch.setattr(
        store,
        "close",
        fail_close("evidence", RuntimeError("private evidence cleanup")),
    )
    with pytest.raises(KeyboardInterrupt) as raised:
        await controller.close()
    assert raised.value is first_failure
    assert order == [
        "delivery",
        "projection",
        "coverage",
        "correlation",
        "journal",
        "evidence",
    ]
    assert all("private" not in note for note in getattr(first_failure, "__notes__", ()))
    await controller.close()
    with pytest.raises(CoreControllerClosed):
        controller.mutation_readiness()
    with pytest.raises(CoreControllerClosed):
        await controller.poll_once()

    monkeypatch.setattr(controller._delivery, "close", original_delivery_close)
    monkeypatch.setattr(projection, "close", original_projection_close)
    monkeypatch.setattr(coverage, "close", original_coverage_close)
    monkeypatch.setattr(correlation, "close", original_correlation_close)
    monkeypatch.setattr(journal, "close", original_journal_close)
    monkeypatch.setattr(store, "close", original_store_close)
    await original_delivery_close()
    original_projection_close()
    original_coverage_close()
    original_correlation_close()
    original_journal_close()
    original_store_close()
