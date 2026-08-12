"""The durable ACK anchor must never come to rest on an uncompleted proof.

A 40-minute soak on the live host held a perfect steady state for 36 minutes
and then put Core into a permanent restart cycle.  The only exception in Core's
whole history was the downstream symptom -- "candidate discovery requires a
healthy projection".  The cause was upstream and invisible: the durable ACK
anchor came to rest exactly ON evidence sequence 7069, a
``pcc_correlation_snapshot`` whose correlation-request journal state was still
``proof_observed``.  ``ProjectionStore.apply(7069)`` then failed for the right
reason -- Projection V2 revalidates PCC authority at that sequence and demands
a unique COMPLETED journal state -- and the projection latched for good, while
the observer head ran on from 7069 to 10341.

The anchor stuck there because delivery scheduled the WRONG work:
``poll_once`` preferred STARTING a new correlation ('selected') over FINISHING
an existing one ('proof_observed'), and each drive of a selected request minted
more selected work, because the path walk to a snapshot SELECTS every
intervening trigger it passes.  Once the trigger-to-snapshot gap exceeded the
trigger spacing, a competing 'selected' request existed on every poll and the
oldest proof was never driven again.

These tests pin all three halves of the invariant:

a. the soak property -- delivery drains instead of accumulating;
b. the scheduler rule -- a resolvable proof outranks unrelated new work;
c. the cross-journal invariant, from the artifact side -- the projection latch
   is CORRECT and stays, and the barrier ceiling must never produce the anchor
   that trips it.
"""

from __future__ import annotations

import importlib
import itertools
import json
from pathlib import Path
from typing import Any, cast

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.coverage import CoverageState
from agmind_immune.evidence.projection import ProjectionAuthorityError
from agmind_immune.evidence.segments import EvidenceRef, SegmentStore
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.service import (
    PCC_CORRELATION_TTL_SECONDS,
    AcceptanceCoordinator,
    DeliveryCoordinator,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.correlation.test_pcc import _accepted_complete
from tests.evidence.test_projection_pcc import _owner, _subject
from tests.ingest.test_pcc_correlation_snapshot import (
    _accept,
    _candidate_trigger,
    _failed_snapshot,
    _item,
    _request,
    _snapshot_envelope,
)
from tests.ingest.test_service import (
    _coordinator,
    _DeliveryClock,
    _page_bytes,
    _ScriptedTransport,
)
from tests.phase5b_helpers import (
    boot_boundary,
    envelope_value,
    private_key,
)

_DETECTOR_HASH = "1" * 64


class _SoakObserverSpool:
    """An observerd-shaped transport that never stops producing.

    It emits one correlation trigger every ``spacing`` events and reserves each
    PCC snapshot at ITS OWN spool head.  Because the spool keeps growing while
    Core is behind, the path from a trigger to its snapshot CONTAINS the next
    trigger -- the exact geometry that made the live host mint new correlation
    work faster than it could finish the old.
    """

    def __init__(
        self,
        key: Ed25519PrivateKey,
        *,
        spacing: int,
        initial_events: int,
        growth_events: int,
        growth_publications: int,
    ) -> None:
        self._key = key
        self.spacing = spacing
        self.growth_events = growth_events
        self.growth_publications = growth_publications
        self.envelopes: list[dict[str, object]] = [boot_boundary(key)]
        self.triggers: dict[int, dict[str, object]] = {}
        self._until_trigger = 0
        self.acked_through = 0
        self.publications = 0
        self.snapshot_sequences: dict[int, int] = {}
        self._published: dict[int, bytes] = {}
        self._append_stream(initial_events)

    def _append_stream(self, count: int) -> None:
        for _ in range(count):
            sequence = len(self.envelopes) + 1
            if self._until_trigger == 0:
                envelope = _candidate_trigger(self._key, sequence=sequence)
                self.triggers[sequence] = envelope
                self._until_trigger = self.spacing - 1
            else:
                envelope = envelope_value(self._key, sequence=sequence)
                self._until_trigger -= 1
            self.envelopes.append(envelope)

    @property
    def first_trigger_sequence(self) -> int:
        return min(self.triggers)

    async def fetch_events(self, *, after: int, limit: int) -> bytes:
        return _page_bytes(
            *self.envelopes[after : after + limit],
            acked_through=self.acked_through,
            reserved_through=len(self.envelopes),
        )

    async def ack_event(self, body: bytes) -> None:
        ack = json.loads(body)
        sequence = int(ack["sequence"])
        if sequence != self.acked_through + 1:
            raise AssertionError("observer requires contiguous ACK")
        if ack["event_id"] != self.envelopes[sequence - 1]["event_id"]:
            raise AssertionError("ACK identity does not bind the spool item")
        self.acked_through = sequence

    async def publish_correlation_snapshot(self, canonical_body: bytes) -> bytes:
        body = bytes(canonical_body)
        trigger_sequence = int(json.loads(body)["trigger_source_sequence"])
        trigger = self.triggers[trigger_sequence]
        request = _request(trigger, ttl_seconds=PCC_CORRELATION_TTL_SECONDS)
        if body != canonical_json(request):
            raise AssertionError("Core posted an unexpected correlation request")
        published = self._published.get(trigger_sequence)
        if published is not None:
            return published
        if self.publications < self.growth_publications:
            # The observer keeps producing while Core walks the path, so the
            # snapshot lands beyond triggers Core has not even seen yet.
            self._append_stream(self.growth_events)
        self.publications += 1
        sequence = len(self.envelopes) + 1
        snapshot = _snapshot_envelope(
            self._key,
            _failed_snapshot(
                trigger,
                request,
                snapshot_sequence=sequence,
            ),
            sequence=sequence,
        )
        self.envelopes.append(snapshot)
        self.snapshot_sequences[trigger_sequence] = sequence
        self._published[trigger_sequence] = canonical_json(_item(snapshot))
        return self._published[trigger_sequence]

    async def close(self) -> None:
        pass


def _runtime(
    path: Path,
    transport: object,
    *,
    ack_budget: int,
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
        cast(Any, transport),
        coverage=coverage,
        clock=_DeliveryClock(),
        ack_budget=ack_budget,
    )
    return acceptance, store, acknowledgements, correlation, coverage, delivery


async def _close(
    store: SegmentStore,
    acknowledgements: AckJournal,
    correlation: CorrelationRequestJournal,
    coverage: CoverageState,
    delivery: DeliveryCoordinator,
) -> None:
    await delivery.close()
    coverage.close()
    correlation.close()
    acknowledgements.close()
    store.close()


def _phase(
    correlation: CorrelationRequestJournal,
    request_sha256: str,
) -> str:
    for state in correlation._states_by_operation.values():
        if state.request_sha256 == request_sha256:
            return str(state.phase)
    raise AssertionError("correlation request is absent from the journal")


@pytest.mark.asyncio
async def test_soak_drains_correlations_instead_of_accumulating_them(
    tmp_path: Path,
) -> None:
    """The soak property: pending work drains, and the OLDEST proof completes
    while the observer is still running away from Core.

    On the pre-fix scheduler the pending list grows by exactly one per poll --
    every drive promotes one 'selected' request and mints another from the
    intervening triggers on its path -- and the first correlation never reaches
    'completed', so the ACK anchor parks on its snapshot forever.
    """
    observer = _SoakObserverSpool(
        private_key(11),
        spacing=6,
        initial_events=12,
        growth_events=6,
        growth_publications=12,
    )
    acceptance, store, acknowledgements, correlation, coverage, delivery = _runtime(
        tmp_path,
        observer,
        ack_budget=4,
    )
    del acceptance
    try:
        first_trigger = observer.first_trigger_sequence
        first_sha256: str | None = None
        first_completed_poll: int | None = None
        pending_counts: list[int] = []
        confirmed_through = 0
        for poll in range(320):
            result = await delivery.poll_once()
            confirmed_through = result.confirmed_through
            pending = correlation.pending()
            pending_counts.append(len(pending))
            if first_sha256 is None:
                first_sha256 = next(
                    (
                        state.request_sha256
                        for state in pending
                        if state.request.trigger_source_sequence == first_trigger
                    ),
                    None,
                )
            if (
                first_completed_poll is None
                and first_sha256 is not None
                and _phase(correlation, first_sha256) == "completed"
            ):
                first_completed_poll = poll
            if not pending and not result.retry_required:
                break

        first_snapshot = observer.snapshot_sequences[first_trigger]
        # The geometry the live host had: the snapshot's path CONTAINS the next
        # trigger, and reaching it costs more than one poll's ACK budget.
        assert first_snapshot - first_trigger > observer.spacing
        assert first_snapshot > delivery.ack_budget

        # Liveness: the oldest proof finishes while the observer is still
        # producing new triggers, not after the spool goes quiet.
        assert first_completed_poll is not None
        assert first_completed_poll < observer.growth_publications

        # The pending list must not be a ratchet.  The pre-fix scheduler grows
        # it by one on every poll for as long as the observer produces.
        longest_run = 0
        run = 0
        for previous, current in itertools.pairwise(pending_counts):
            run = run + 1 if current > previous else 0
            longest_run = max(longest_run, run)
        assert longest_run < 4
        assert len(pending_counts) < 320

        assert len(correlation.pending()) <= 1
        assert confirmed_through > first_snapshot
        assert observer.acked_through == confirmed_through
    finally:
        await _close(store, acknowledgements, correlation, coverage, delivery)


@pytest.mark.asyncio
async def test_poll_drives_the_observed_proof_not_the_newer_selected_request(
    tmp_path: Path,
) -> None:
    """pending == (proof_observed(S), selected(T)) with T beyond S: the poll
    must finish S, not start T.

    Only a 'proof_observed' state can be completed and only completion raises
    the ACK ceiling, so starting T cannot move the anchor -- it can only lower
    the ceiling to T's trigger - 1.  The transport here offers no publication
    at all, so a scheduler that starts T fails loudly.
    """
    key = private_key(11)
    trigger = _candidate_trigger(key, sequence=2)
    request = _request(trigger, ttl_seconds=PCC_CORRELATION_TTL_SECONDS)
    snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(trigger, request, snapshot_sequence=4),
        sequence=4,
    )
    later_trigger = _candidate_trigger(key, sequence=5)

    acceptance, store, _verifier = _coordinator(tmp_path)
    _accept(acceptance, boot_boundary(key))
    _accept(acceptance, trigger)
    _accept(acceptance, envelope_value(key, sequence=3))
    acceptance.accept_pcc(_item(snapshot), request)
    _accept(acceptance, later_trigger)

    acknowledgements = AckJournal.create_new(store)
    correlation = CorrelationRequestJournal.create_new(store)
    coverage = CoverageState.open_and_recover(store)
    refs = {record.ref.source_sequence: record.ref for record in store.iter_authenticated_records()}
    observed = correlation.select(refs[2], canonical_json(request))
    correlation.mark_proof_observed(observed.request_sha256, refs[4])
    correlation.select(
        refs[5],
        canonical_json(_request(later_trigger, ttl_seconds=PCC_CORRELATION_TTL_SECONDS)),
    )
    assert tuple(state.phase for state in correlation.pending()) == (
        "proof_observed",
        "selected",
    )

    transport = _ScriptedTransport(acknowledgements=[None] * 8)
    delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        correlation,
        cast(Any, transport),
        coverage=coverage,
        clock=_DeliveryClock(),
        ack_budget=8,
    )
    try:
        result = await delivery.poll_once()

        assert not [action for action in transport.actions if action[0] == "pcc"]
        assert result.confirmed_through == 4
        assert _phase(correlation, observed.request_sha256) == "completed"
        assert tuple(state.phase for state in correlation.pending()) == ("selected",)
    finally:
        await _close(store, acknowledgements, correlation, coverage, delivery)


def test_ack_anchor_on_an_uncompleted_proof_latches_the_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The latch is CORRECT: an anchor equal to a snapshot sequence whose
    correlation is still 'proof_observed' must make ProjectionStore.apply raise
    and roll the event and cursor back.  This is the failure the live host saw;
    the fix belongs upstream, never here."""
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=PCC_CORRELATION_TTL_SECONDS,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    snapshot_ref = cast(EvidenceRef, proof.evidence_ref)
    trigger_ref = store._bound_verifier.accepted_ref(proof.snapshot.trigger.source_sequence)
    selected = journal.select(trigger_ref, canonical_json(proof.request))
    journal.mark_proof_observed(selected.request_sha256, snapshot_ref)

    # _owner confirms every accepted record, so the ACK anchor is exactly the
    # snapshot sequence -- the live 7069 state, reproduced.
    owner, connection = _owner(subject, coordinator, journal)
    try:
        records = tuple(store.iter_authenticated_records())
        assert records[-1].ref == snapshot_ref
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()

        with pytest.raises(ProjectionAuthorityError):
            owner.apply(snapshot_ref)

        assert owner.snapshot_hash() == before
        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_id=?",
                (snapshot_ref.event_id,),
            ).fetchone()[0]
            == 0
        )

        journal.mark_completed(selected.request_sha256)
        owner.apply(snapshot_ref)
        assert owner.status().cursor.source_sequence == snapshot_ref.source_sequence
    finally:
        owner.close()


@pytest.mark.asyncio
async def test_barrier_ceiling_never_produces_the_anchor_the_projection_rejects(
    tmp_path: Path,
) -> None:
    """The other side of the same invariant: while a proof is 'proof_observed'
    the ACK ceiling stops one sequence SHORT of its snapshot, so the anchor the
    projection rejects is unreachable -- and the state being DRIVEN is exempt
    from its own cap, or the walk could never complete it."""
    key = private_key(11)
    trigger = _candidate_trigger(key, sequence=2)
    request = _request(trigger, ttl_seconds=PCC_CORRELATION_TTL_SECONDS)
    snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(trigger, request, snapshot_sequence=4),
        sequence=4,
    )

    acceptance, store, _verifier = _coordinator(tmp_path)
    _accept(acceptance, boot_boundary(key))
    _accept(acceptance, trigger)
    _accept(acceptance, envelope_value(key, sequence=3))
    acceptance.accept_pcc(_item(snapshot), request)

    acknowledgements = AckJournal.create_new(store)
    correlation = CorrelationRequestJournal.create_new(store)
    coverage = CoverageState.open_and_recover(store)
    refs = {record.ref.source_sequence: record.ref for record in store.iter_authenticated_records()}
    observed = correlation.select(refs[2], canonical_json(request))
    correlation.mark_proof_observed(observed.request_sha256, refs[4])

    transport = _ScriptedTransport(acknowledgements=[None] * 8)
    delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        correlation,
        cast(Any, transport),
        coverage=coverage,
        clock=_DeliveryClock(),
        ack_budget=8,
    )
    try:
        idle = delivery._local_state(apply_coverage_barrier=True)
        assert idle.delivery_ceiling == 3

        driven = delivery._local_state(
            apply_coverage_barrier=True,
            driven_correlation=observed.request_sha256,
        )
        assert driven.delivery_ceiling == 4

        other = delivery._local_state(
            apply_coverage_barrier=True,
            driven_correlation="f" * 64,
        )
        assert other.delivery_ceiling == 3

        # The exemption is what lets the walk finish: driving the proof reaches
        # its own snapshot, completes the journal state, and only THEN does the
        # anchor rest on sequence 4 -- with a completed correlation behind it.
        result = await delivery.poll_once()
        assert result.confirmed_through == 4
        assert _phase(correlation, observed.request_sha256) == "completed"
        assert correlation.pending() == ()

        settled = delivery._local_state(apply_coverage_barrier=True)
        assert settled.delivery_ceiling == 4
    finally:
        await _close(store, acknowledgements, correlation, coverage, delivery)
