from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.clock import CoreClockSample
from agmind_immune.controller import CoreController
from agmind_immune.correlation.primitives import (
    SpecialUseRegistry,
    load_pinned_special_use_registry,
)
from agmind_immune.coverage import CoverageState, MutationReadiness
from agmind_immune.evidence.projection import ProjectionStore
from agmind_immune.evidence.segments import EvidenceRef, SegmentStore
from agmind_immune.incidents.models import ContainmentCandidateV1
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import (
    AuthenticatedPCCInput,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator

from tests.correlation.test_pcc import _accepted_complete
from tests.phase5b_helpers import NOW, envelope_value, page_value, private_key


class AdmissionClock:
    def live_receipt_monotonic(self) -> float | None:
        return None

    def decision_sample(self) -> CoreClockSample:
        return CoreClockSample(
            decision_utc=datetime.fromisoformat(NOW),
            decision_monotonic=101.0,
            healthy=True,
            uncertainty_seconds=Decimal("0.1"),
            max_uncertainty_seconds=Decimal(1),
        )


class AdmissionTransport:
    async def fetch_events(self, *, after: int, limit: int) -> bytes:
        del after, limit
        raise AssertionError("admission fixture performed an unexpected poll")

    async def ack_event(self, body: bytes) -> None:
        del body
        raise AssertionError("admission fixture performed an unexpected ACK")

    async def publish_correlation_snapshot(self, canonical_body: bytes) -> bytes:
        del canonical_body
        raise AssertionError("admission fixture performed an unexpected PCC request")

    async def close(self) -> None:
        return None


@dataclass(slots=True)
class AdmissionRuntime:
    controller: CoreController
    acceptance: AcceptanceCoordinator
    store: SegmentStore
    acknowledgements: AckJournal
    correlation_requests: CorrelationRequestJournal
    registry: SpecialUseRegistry
    coverage: CoverageState
    projection: ProjectionStore
    proof: AuthenticatedPCCInput
    candidate: ContainmentCandidateV1
    terminal_ref: EvidenceRef

    async def close(self) -> None:
        await self.controller.close()


def _complete_request_journal(
    journal: CorrelationRequestJournal,
    proof: AuthenticatedPCCInput,
) -> None:
    verifier = journal._store._bound_verifier
    assert verifier is not None
    trigger_ref = verifier.accepted_ref(proof.snapshot.trigger.source_sequence)
    assert type(trigger_ref) is EvidenceRef
    selected = journal.select(trigger_ref, canonical_json(proof.request))
    snapshot_ref = cast(EvidenceRef, proof.evidence_ref)
    journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    journal.mark_completed(selected.request_sha256)


def _confirm_all(
    acknowledgements: AckJournal,
    refs: tuple[EvidenceRef, ...],
) -> None:
    for ref in refs:
        acknowledgements.record_pending(ref)
        acknowledgements.record_confirmed(ref)


def _projected_candidate(projection: ProjectionStore) -> ContainmentCandidateV1:
    subject = __import__(
        "agmind_immune.evidence.projection_v2",
        fromlist=["_CANDIDATE_COLUMNS", "_decode_candidate"],
    )
    connection = projection._connection
    assert isinstance(connection, sqlite3.Connection)
    columns = ",".join(subject._CANDIDATE_COLUMNS)
    rows = connection.execute(f"SELECT {columns} FROM candidates").fetchall()
    assert len(rows) == 1
    candidate = subject._decode_candidate(rows[0])
    assert type(candidate) is ContainmentCandidateV1
    return candidate


def build_admission_runtime(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> AdmissionRuntime:
    authority = __import__(
        "agmind_immune.correlation.authority",
        fromlist=["_load_pinned_detector_bundle"],
    )
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: "1" * 64,
    )
    path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)
    acceptance, proof = _accepted_complete(path / "evidence", ttl_seconds=120)
    store = acceptance.segment_store
    acknowledgements: AckJournal | None = None
    correlation_requests: CorrelationRequestJournal | None = None
    coverage: CoverageState | None = None
    projection: ProjectionStore | None = None
    controller: CoreController | None = None
    try:
        correlation_requests = CorrelationRequestJournal.create_new(store)
        _complete_request_journal(correlation_requests, proof)
        acknowledgements = AckJournal.create_new(store)
        records = tuple(store.iter_authenticated_records())
        assert len(records) == 3
        refs = tuple(record.ref for record in records)
        _confirm_all(acknowledgements, refs)
        registry = load_pinned_special_use_registry(
            Path(__file__).resolve().parents[2]
            / "contracts/v1/ipv4-special-use.csv"
        )
        coverage = CoverageState.open_and_recover(store)
        projection = ProjectionStore.open(
            path / "projection.sqlite3",
            evidence=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation_requests,
            registry=registry,
        )
        candidate = _projected_candidate(projection)

        def exact_ready(context: Any) -> MutationReadiness:
            return MutationReadiness(
                ready=True,
                reason_codes=(),
                evidence_head=context.evidence_head,
                acceptance_cursor=context.acceptance_cursor,
                confirmed_through=context.confirmed_through,
                projection_cursor=context.projection_cursor,
                observer_reconcile_generation=9,
                coverage_snapshot_sha256=candidate.coverage_snapshot_sha256,
            )

        monkeypatch.setattr(coverage, "mutation_readiness", exact_ready)
        controller = CoreController.create(
            acceptance,
            acknowledgements,
            correlation_requests,
            registry,
            coverage,
            projection,
            AdmissionTransport(),
            AdmissionClock(),
        )
        return AdmissionRuntime(
            controller=controller,
            acceptance=acceptance,
            store=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation_requests,
            registry=registry,
            coverage=coverage,
            projection=projection,
            proof=proof,
            candidate=candidate,
            terminal_ref=refs[-1],
        )
    except BaseException:
        if controller is not None:
            raise
        if projection is not None:
            projection.close()
        if coverage is not None:
            coverage.close()
        if correlation_requests is not None:
            correlation_requests.close()
        if acknowledgements is not None:
            acknowledgements.close()
        store.close()
        raise


def accept_one(runtime: AdmissionRuntime) -> EvidenceRef:
    sequence = runtime.terminal_ref.source_sequence + 1
    event = envelope_value(
        private_key(11),
        sequence=sequence,
        boot_id=runtime.candidate.boot_id,
        normalized_fields={"kind": "post_admission_revision"},
    )
    item = decode_events_page(canonical_json(page_value(event))).events[0]
    return runtime.acceptance.accept(item)


def append_and_project_one(runtime: AdmissionRuntime) -> EvidenceRef:
    ref = accept_one(runtime)
    runtime.acknowledgements.record_pending(ref)
    runtime.acknowledgements.record_confirmed(ref)
    runtime.projection.apply(ref)
    return ref


def append_late_invalidation(runtime: AdmissionRuntime) -> EvidenceRef:
    from tests.coverage.test_state import _generic_critical

    event = _generic_critical(
        private_key(11),
        runtime.terminal_ref.source_sequence + 1,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=NOW,
        closed_at=NOW,
    ).envelope
    item = decode_events_page(canonical_json(page_value(event))).events[0]
    ref = runtime.acceptance.accept(item)
    runtime.acknowledgements.record_pending(ref)
    runtime.acknowledgements.record_confirmed(ref)
    runtime.projection.apply(ref)
    return ref


def mutate_projection_from_second_connection(
    runtime: AdmissionRuntime,
    mutation: str,
) -> None:
    connection = sqlite3.connect(runtime.projection.path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        if mutation == "candidate-row":
            connection.execute(
                "UPDATE candidates SET destination_port=8443 WHERE candidate_id=?",
                (runtime.candidate.candidate_id,),
            )
        elif mutation == "proof-row":
            connection.execute(
                "DELETE FROM candidate_evidence WHERE candidate_id=? "
                "AND role='primary_trigger'",
                (runtime.candidate.candidate_id,),
            )
        elif mutation == "invalidation-row":
            connection.execute(
                "INSERT INTO candidate_invalidations VALUES(?,?,?,?,?)",
                (
                    runtime.candidate.candidate_id,
                    runtime.terminal_ref.event_id,
                    f"{runtime.terminal_ref.source_sequence:020d}",
                    runtime.terminal_ref.content_sha256,
                    "late_critical_coverage_gap",
                ),
            )
        else:
            raise AssertionError(f"unknown admission mutation: {mutation}")
        connection.commit()
    finally:
        connection.close()
