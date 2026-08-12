"""Correlation delivery when Core is far behind the observer's spool.

The observer reserves a PCC correlation snapshot at ITS OWN spool head, so the
distance between a trigger and its snapshot is exactly how far Core has fallen
behind.  On the first host where the containment half ever ran, that distance
was 5_926 events (trigger 7_272, snapshot 13_198) and Core latched fatally on
its own 4_096-event bound -- twice: once validating the publication response,
once re-deriving the proof position.  These tests drive the real
DeliveryCoordinator against an observer that behaves the way observerd does,
over a path longer than that bound.
"""

from __future__ import annotations

import json
from pathlib import Path

import agmind_immune.ingest.service as service_module
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.coverage import CoverageState
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.service import (
    _MAX_CORRELATION_PATH_EVENTS,
    DeliveryCoordinator,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.ingest.test_pcc_correlation_snapshot import (
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
)
from tests.phase5b_helpers import (
    boot_boundary,
    envelope_value,
    private_key,
)


class _ObserverSpool:
    """An observerd-shaped transport: an append-only spool that reserves the
    correlation snapshot at its own head and replays it idempotently."""

    def __init__(self, key: Ed25519PrivateKey, *, path_events: int) -> None:
        self._key = key
        self.envelopes: list[dict[str, object]] = [boot_boundary(key)]
        self.trigger = _candidate_trigger(key, sequence=2)
        self.envelopes.append(self.trigger)
        for offset in range(path_events):
            self.envelopes.append(envelope_value(key, sequence=3 + offset))
        self.acked_through = 0
        self.snapshot_sequence: int | None = None
        self.publications = 0
        self._publication: bytes | None = None
        self._publication_body: bytes | None = None

    @property
    def trigger_sequence(self) -> int:
        return int(self.trigger["source_sequence"])

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
        self.publications += 1
        body = bytes(canonical_body)
        if self._publication is not None:
            if body != self._publication_body:
                raise AssertionError("republished with a different request")
            return self._publication
        request = _request(self.trigger, ttl_seconds=120)
        if body != canonical_json(request):
            raise AssertionError("Core posted an unexpected correlation request")
        sequence = len(self.envelopes) + 1
        snapshot = _snapshot_envelope(
            self._key,
            _failed_snapshot(
                self.trigger,
                request,
                snapshot_sequence=sequence,
            ),
            sequence=sequence,
        )
        self.envelopes.append(snapshot)
        self.snapshot_sequence = sequence
        self._publication_body = body
        self._publication = canonical_json(_item(snapshot))
        return self._publication

    async def close(self) -> None:
        pass


def _runtime(
    path: Path,
    transport: _ObserverSpool,
) -> tuple[
    CorrelationRequestJournal,
    CoverageState,
    AckJournal,
    DeliveryCoordinator,
    SegmentStore,
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
    return correlation, coverage, acknowledgements, delivery, store


async def _close(
    correlation: CorrelationRequestJournal,
    coverage: CoverageState,
    acknowledgements: AckJournal,
    delivery: DeliveryCoordinator,
    store: SegmentStore,
) -> None:
    await delivery.close()
    coverage.close()
    correlation.close()
    acknowledgements.close()
    store.close()


@pytest.mark.asyncio
async def test_backlog_longer_than_the_path_bound_reaches_its_proof(
    tmp_path: Path,
) -> None:
    """Production scale, production constants: the observer's snapshot lands
    further past the trigger than one poll's acceptance budget."""
    observer = _ObserverSpool(
        private_key(11),
        path_events=_MAX_CORRELATION_PATH_EVENTS + 128,
    )
    correlation, coverage, acknowledgements, delivery, store = _runtime(
        tmp_path,
        observer,
    )
    try:
        observed = False
        for _poll in range(64):
            result = await delivery.poll_once()
            pending = correlation.pending()
            if pending and pending[0].phase == "proof_observed":
                observed = True
                if result.confirmed_through > observer.trigger_sequence:
                    break
        assert observed
        assert observer.snapshot_sequence is not None
        assert observer.snapshot_sequence - observer.trigger_sequence > _MAX_CORRELATION_PATH_EVENTS
        # ACK passed the trigger, so the bounded scan re-derived a proof
        # position that sits further than _MAX_CORRELATION_PATH_EVENTS away.
        assert result.confirmed_through > observer.trigger_sequence
        assert store.status().evidence_head >= observer.snapshot_sequence
        assert observer.snapshot_sequence == len(observer.envelopes)
    finally:
        await _close(correlation, coverage, acknowledgements, delivery, store)


@pytest.mark.asyncio
async def test_correlation_completes_across_many_budget_exhausted_polls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same shape, small budget: every bounded step must resume on the next
    poll instead of latching, and the whole lifecycle must still complete."""
    monkeypatch.setattr(service_module, "_MAX_CORRELATION_PATH_EVENTS", 16)
    observer = _ObserverSpool(private_key(11), path_events=96)
    correlation, coverage, acknowledgements, delivery, store = _runtime(
        tmp_path,
        observer,
    )
    try:
        phases: list[str] = []
        for _poll in range(64):
            result = await delivery.poll_once()
            pending = correlation.pending()
            if pending and pending[0].phase not in phases:
                phases.append(pending[0].phase)
            if not pending and not result.retry_required:
                break
        assert observer.snapshot_sequence is not None
        assert observer.snapshot_sequence - observer.trigger_sequence > 16
        assert phases == ["selected", "proof_observed"]
        assert correlation.pending() == ()
        assert observer.acked_through >= observer.snapshot_sequence
        # The path walk spans several polls, so Core re-posts the same request
        # and the observer replays one reserved snapshot, exactly as the live
        # host's repeated 200 OK publications did.
        assert observer.publications > 1
        assert observer.snapshot_sequence == len(observer.envelopes)
    finally:
        await _close(correlation, coverage, acknowledgements, delivery, store)
