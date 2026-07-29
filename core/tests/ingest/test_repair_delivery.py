from __future__ import annotations

import importlib
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.coverage import CoverageState
from agmind_immune.evidence.segments import EvidenceRef, SegmentStore
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    CoreEventV1,
    EnvelopeVerifier,
    PinnedObserverRoot,
    decode_events_page,
)
from agmind_immune.ingest.service import (
    AcceptanceCoordinator,
    DeliveryCoordinator,
    DeliveryFatalError,
    DeliveryRetryableError,
    HTTPXObserverCoreTransport,
)
from tests.phase5b_helpers import (
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
)


def _acceptance(path: Path) -> tuple[AcceptanceCoordinator, SegmentStore]:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key), strict=True)
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    return (
        AcceptanceCoordinator.create_empty(EnvelopeVerifier(root, chain), store),
        store,
    )


def _item(envelope: dict[str, object]) -> CoreEventV1:
    return decode_events_page(canonical_json(page_value(envelope))).events[0]


def _page(
    *envelopes: dict[str, object],
    acked_through: int,
    reserved_through: int,
) -> bytes:
    value = page_value(*envelopes)
    value["acked_through"] = acked_through
    value["reserved_through"] = reserved_through
    return canonical_json(value)


def _authorization(sequence: int) -> dict[str, object]:
    return envelope_value(
        private_key(11),
        sequence=sequence,
        event_type="evidence_repair_authorized",
        normalized_fields={
            "schema_version": "agmind.evidence-repair-authorize.v1",
            "repair_id": "11111111-1111-4111-8111-111111111111",
            "segment_id": "22222222-2222-4222-8222-222222222222",
            "verified_bytes": 4096,
            "discarded_bytes": 512,
            "discarded_sha256": "1" * 64,
            "last_verified_frame_sha256": "2" * 64,
            "current_chain_head_sha256": "3" * 64,
            "reason": "torn_open_tail",
        },
    )


class _Clock:
    def live_receipt_monotonic(self) -> None:
        return None

    def decision_sample(self) -> object:
        raise AssertionError("delivery must not sample the decision clock")


class _Transport:
    def __init__(
        self,
        pages: list[bytes] | None = None,
        *,
        timeline: list[str] | None = None,
    ) -> None:
        self.pages = pages or []
        self.timeline = timeline if timeline is not None else []
        self.fetches: list[tuple[int, int]] = []

    async def fetch_events(self, *, after: int, limit: int) -> bytes:
        self.fetches.append((after, limit))
        self.timeline.append(f"fetch:{after}")
        if not self.pages:
            raise AssertionError("unexpected repair fetch")
        return self.pages.pop(0)

    async def ack_event(self, body: bytes) -> None:
        item = httpx.Response(200, content=body).json()
        self.timeline.append(f"post:{item['sequence']}")

    async def publish_repair_authorization(self, canonical_body: bytes) -> bytes:
        raise AssertionError("unexpected authorization POST")

    async def publish_repair_completion(self, canonical_body: bytes) -> bytes:
        raise AssertionError("unexpected completion POST")

    async def close(self) -> None:
        return None


class _OneChunk(httpx.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self._body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._body


@pytest.mark.asyncio
async def test_repair_transport_uses_only_fixed_post_routes_and_exact_body() -> None:
    seen: list[tuple[str, str, bytes, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        seen.append(
            (
                request.method,
                request.url.path,
                body,
                request.headers["Content-Type"],
            )
        )
        status = (
            200
            if request.url.path.endswith("repair-authorize")
            else 201
        )
        return httpx.Response(
            status,
            headers={"Content-Type": "application/json"},
            stream=_OneChunk(b'{"ok":true}'),
        )

    transport = HTTPXObserverCoreTransport(
        "/unused",
        transport=httpx.MockTransport(handler),
    )
    body = b'{"schema_version":"exact"}'

    assert await transport.publish_repair_authorization(body) == b'{"ok":true}'
    assert await transport.publish_repair_completion(body) == b'{"ok":true}'
    assert seen == [
        (
            "POST",
            "/v1/events/evidence-repair-authorize",
            body,
            "application/json",
        ),
        (
            "POST",
            "/v1/events/evidence-repair-complete",
            body,
            "application/json",
        ),
    ]
    await transport.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "headers", "body", "error"),
    [
        (408, {}, b"timeout", DeliveryRetryableError),
        (503, {}, b"unavailable", DeliveryRetryableError),
        (507, {}, b"capacity", DeliveryRetryableError),
        (409, {}, b"conflict", DeliveryFatalError),
        (202, {}, b"unexpected", DeliveryFatalError),
        (
            200,
            {"Content-Type": "application/json; charset=utf-8"},
            b"{}",
            DeliveryFatalError,
        ),
        (
            200,
            {
                "Content-Type": "application/json",
                "Content-Encoding": "identity",
            },
            b"{}",
            DeliveryFatalError,
        ),
        (
            200,
            {"Content-Type": "application/json"},
            b"x" * (128 * 1024 + 1),
            DeliveryFatalError,
        ),
    ],
    ids=[
        "request-timeout",
        "server-error",
        "capacity",
        "conflict",
        "unexpected-success",
        "content-type",
        "content-encoding",
        "oversized",
    ],
)
async def test_repair_transport_response_matrix_is_fail_closed(
    status: int,
    headers: dict[str, str],
    body: bytes,
    error: type[Exception],
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers, stream=_OneChunk(body))

    transport = HTTPXObserverCoreTransport(
        "/unused",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(error):
        await transport.publish_repair_authorization(b"{}")
    await transport.close()


@pytest.mark.asyncio
async def test_repair_drain_is_factory_only_and_rejects_target_mismatch_before_append(
    tmp_path: Path,
) -> None:
    service = importlib.import_module("agmind_immune.ingest.service")
    acceptance, store = _acceptance(tmp_path)
    journal = AckJournal.create_new(store)
    coverage = CoverageState.open_and_recover(store)
    boot_ref = acceptance.accept(_item(boot_boundary(private_key(11))))
    store.flush_security_boundary()
    coverage._apply_live_accepted(store, boot_ref, None)
    journal.record_pending(boot_ref)
    journal.record_confirmed(boot_ref)
    expected = _item(_authorization(2))
    store._repair_pending = True
    assert store.status().repair_pending is True
    store._repair_resumed = True
    with pytest.raises(TypeError, match="repair factory"):
        AcceptanceCoordinator._from_repair_resume(
            acceptance.verifier,
            store,
            _factory=object(),
        )
    resumed_acceptance = AcceptanceCoordinator._from_repair_resume(
        acceptance.verifier,
        store,
        _factory=service._REPAIR_ACCEPTANCE_FACTORY,
    )
    assert resumed_acceptance.segment_store is store
    assert resumed_acceptance.verifier is acceptance.verifier
    with pytest.raises(DeliveryFatalError, match="repair delivery"):
        resumed_acceptance.accept(expected)
    assert store.status().evidence_head == 1
    mismatched = envelope_value(
        private_key(11),
        sequence=2,
        normalized_fields={"kind": "not-the-exact-repair-target"},
    )

    with pytest.raises(TypeError, match="repair factory"):
        DeliveryCoordinator._create_for_repair(
            acceptance,
            journal,
            _Transport(),
            coverage=coverage,
            clock=_Clock(),
            _factory=object(),
        )

    transport = _Transport(
        [_page(mismatched, acked_through=1, reserved_through=2)]
    )
    delivery = DeliveryCoordinator._create_for_repair(
        resumed_acceptance,
        journal,
        transport,
        coverage=coverage,
        clock=_Clock(),
        _factory=service._REPAIR_DELIVERY_FACTORY,
    )
    with pytest.raises(DeliveryFatalError, match="drain_until_exact"):
        await delivery.poll_once()
    with pytest.raises(DeliveryFatalError, match="exact drain"):
        await delivery.recover_pending_ack()
    assert transport.timeline == []
    with pytest.raises(DeliveryFatalError, match="exact repair target"):
        await delivery.drain_until_exact(expected)
    assert store.status().evidence_head == 1
    assert transport.timeline == ["fetch:1"]
    await delivery.close()

    beyond_target = envelope_value(
        private_key(11),
        sequence=3,
        normalized_fields={"kind": "past-the-repair-target"},
    )
    whole_page_transport = _Transport(
        [
            _page(
                expected.envelope,
                beyond_target,
                acked_through=1,
                reserved_through=3,
            )
        ]
    )
    whole_page = DeliveryCoordinator._create_for_repair(
        resumed_acceptance,
        journal,
        whole_page_transport,
        coverage=coverage,
        clock=_Clock(),
        _factory=service._REPAIR_DELIVERY_FACTORY,
    )
    with pytest.raises(DeliveryFatalError):
        await whole_page.drain_until_exact(expected)
    assert store.status().evidence_head == 1
    assert whole_page_transport.timeline == ["fetch:1"]
    assert whole_page_transport.fetches == [(1, 1)]
    await whole_page.close()

    ordinary_transport = _Transport()
    with pytest.raises(DeliveryFatalError, match="mode"):
        DeliveryCoordinator.create(
            acceptance,
            journal,
            ordinary_transport,
            coverage=coverage,
            clock=_Clock(),
        )
    assert ordinary_transport.timeline == []

    store._repair_pending = False
    ordinary = DeliveryCoordinator.create(
        acceptance,
        journal,
        ordinary_transport,
        coverage=coverage,
        clock=_Clock(),
    )
    with pytest.raises(DeliveryFatalError, match="repair factory"):
        await ordinary.drain_until_exact(expected)
    assert ordinary_transport.timeline == []
    await ordinary.close()

    later = _item(beyond_target)
    for item in (expected, later):
        ref = acceptance.accept(item)
        store.flush_security_boundary()
        coverage._apply_live_accepted(store, ref, None)
        journal.record_pending(ref)
        journal.record_confirmed(ref)
    store._repair_pending = True
    ahead_transport = _Transport()
    ahead = DeliveryCoordinator._create_for_repair(
        resumed_acceptance,
        journal,
        ahead_transport,
        coverage=coverage,
        clock=_Clock(),
        _factory=service._REPAIR_DELIVERY_FACTORY,
    )
    with pytest.raises(DeliveryFatalError, match="advanced beyond"):
        await ahead.drain_until_exact(expected)
    assert ahead_transport.timeline == []
    await ahead.close()
    store._repair_pending = False
    store.close()


@pytest.mark.asyncio
async def test_repair_drain_retains_journal_and_serializes_each_exact_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = importlib.import_module("agmind_immune.ingest.service")
    acceptance, store = _acceptance(tmp_path)
    journal = AckJournal.create_new(store)
    coverage = CoverageState.open_and_recover(store)
    boot_ref = acceptance.accept(_item(boot_boundary(private_key(11))))
    store.flush_security_boundary()
    coverage._apply_live_accepted(store, boot_ref, None)
    journal.record_pending(boot_ref)
    store._repair_pending = True
    assert store.status().repair_pending is True
    store._repair_resumed = True
    resumed_acceptance = AcceptanceCoordinator._from_repair_resume(
        acceptance.verifier,
        store,
        _factory=service._REPAIR_ACCEPTANCE_FACTORY,
    )

    intermediate = envelope_value(
        private_key(11),
        sequence=2,
        normalized_fields={"kind": "intervening-event"},
    )
    target = _item(_authorization(3))
    timeline: list[str] = []
    transport = _Transport(
        [
            _page(
                intermediate,
                target.envelope,
                acked_through=1,
                reserved_through=3,
            )
        ],
        timeline=timeline,
    )

    original_append = store.append
    original_settle = store.flush_security_boundary
    original_coverage = coverage._apply_live_accepted
    original_pending = journal.record_pending
    original_confirmed = journal.record_confirmed

    def traced_append(*args: object, **kwargs: object) -> EvidenceRef:
        ref = original_append(*args, **kwargs)
        timeline.append(f"accept:{ref.source_sequence}")
        return ref

    def traced_settle() -> None:
        sequence = store.status().evidence_head
        original_settle()
        timeline.append(f"settle:{sequence}")

    def traced_coverage(
        evidence: SegmentStore,
        ref: EvidenceRef,
        receipt: float | None,
    ) -> None:
        original_coverage(evidence, ref, receipt)
        timeline.append(f"coverage:{ref.source_sequence}")

    def traced_pending(ref: EvidenceRef) -> None:
        first = journal.snapshot().pending is None
        original_pending(ref)
        if first:
            timeline.append(f"pending:{ref.source_sequence}")

    def traced_confirmed(ref: EvidenceRef) -> None:
        original_confirmed(ref)
        timeline.append(f"confirmed:{ref.source_sequence}")

    monkeypatch.setattr(store, "append", traced_append)
    monkeypatch.setattr(store, "flush_security_boundary", traced_settle)
    monkeypatch.setattr(coverage, "_apply_live_accepted", traced_coverage)
    monkeypatch.setattr(journal, "record_pending", traced_pending)
    monkeypatch.setattr(journal, "record_confirmed", traced_confirmed)

    delivery = DeliveryCoordinator._create_for_repair(
        resumed_acceptance,
        journal,
        transport,
        coverage=coverage,
        clock=_Clock(),
        _factory=service._REPAIR_DELIVERY_FACTORY,
    )
    returned = await delivery.drain_until_exact(target, settle_each=True)

    assert delivery.ack_journal is journal
    assert returned.source_sequence == target.sequence
    assert journal.snapshot().confirmed_through == target.sequence
    assert journal.snapshot().pending is None
    assert transport.fetches == [(1, 2)]
    assert timeline == [
        "post:1",
        "confirmed:1",
        "fetch:1",
        "accept:2",
        "settle:2",
        "coverage:2",
        "pending:2",
        "post:2",
        "confirmed:2",
        "accept:3",
        "settle:3",
        "coverage:3",
        "pending:3",
        "post:3",
        "confirmed:3",
    ]

    with pytest.raises(TypeError, match="finalization factory"):
        await delivery.finalize_repair(
            object(),
            _factory=object(),
        )

    with pytest.raises(TypeError, match="completion authority"):
        await delivery.finalize_repair(
            object(),
            _factory=service._REPAIR_DELIVERY_FACTORY,
        )
    await delivery.close()

    repair = importlib.import_module("agmind_immune.evidence.repair")
    completion_proof = object.__new__(repair.AuthenticatedRepairCompletion)
    object.__setattr__(
        completion_proof,
        "_factory_marker",
        repair._FINAL_REPAIR_COMPLETION_FACTORY,
    )
    object.__setattr__(completion_proof, "_store", store)
    object.__setattr__(
        completion_proof,
        "_verifier",
        resumed_acceptance.verifier,
    )
    object.__setattr__(completion_proof, "_acknowledgements", journal)

    current_finalizer: list[DeliveryCoordinator] = []
    clear_calls = 0

    def clear_gate(
        self: object,
        *,
        _factory: object,
    ) -> None:
        nonlocal clear_calls
        assert self is completion_proof
        assert _factory is service._REPAIR_DELIVERY_FACTORY
        assert current_finalizer[0]._transport_closed is True
        assert current_finalizer[0]._lease_released is True
        assert store.status().repair_pending is True
        clear_calls += 1
        store._repair_pending = False

    monkeypatch.setattr(
        repair.AuthenticatedRepairCompletion,
        "_clear_under_delivery_fence",
        clear_gate,
    )

    failing_transport = _Transport()

    async def fail_close() -> None:
        raise RuntimeError("transport cleanup failed")

    monkeypatch.setattr(failing_transport, "close", fail_close)
    failed_finalizer = DeliveryCoordinator._create_for_repair(
        resumed_acceptance,
        journal,
        failing_transport,
        coverage=coverage,
        clock=_Clock(),
        _factory=service._REPAIR_DELIVERY_FACTORY,
    )
    current_finalizer[:] = [failed_finalizer]
    with pytest.raises(RuntimeError, match="transport cleanup failed"):
        await failed_finalizer.finalize_repair(
            completion_proof,
            _factory=service._REPAIR_DELIVERY_FACTORY,
        )
    assert clear_calls == 0
    assert store.status().repair_pending is True
    assert resumed_acceptance._repair_mode is True

    finalizer = DeliveryCoordinator._create_for_repair(
        resumed_acceptance,
        journal,
        _Transport(),
        coverage=coverage,
        clock=_Clock(),
        _factory=service._REPAIR_DELIVERY_FACTORY,
    )

    current_finalizer[:] = [finalizer]
    await finalizer.finalize_repair(
        completion_proof,
        _factory=service._REPAIR_DELIVERY_FACTORY,
    )
    assert clear_calls == 1
    with pytest.raises(DeliveryFatalError, match="repair factory"):
        await finalizer.drain_until_exact(target)
    await finalizer.close()
    assert resumed_acceptance.accept(target) == returned
    store.close()
