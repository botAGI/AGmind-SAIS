from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Literal

import httpx
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.evidence.frames import decode_frames, encode_frame
from agmind_immune.evidence.manifest import (
    SegmentManifestV1,
    chain_head_for,
    segment_manifest_hash,
)
from agmind_immune.evidence.segments import (
    EvidenceCorrupt,
    EvidenceReadOnly,
    SegmentStore,
)
from agmind_immune.ingest.ack_journal import (
    AckJournal,
    AckJournalAuthorityError,
    AckJournalStateError,
)
from agmind_immune.ingest.envelope import (
    MAX_EVENTS_PAGE_BYTES,
    AnchoredPublicKeyChain,
    EnvelopeConflict,
    EnvelopeSignatureError,
    EnvelopeVerifier,
    PinnedObserverRoot,
    decode_events_page,
)
from agmind_immune.ingest.service import (
    AcceptanceCoordinator,
    DeliveryAmbiguousAck,
    DeliveryCoordinator,
    DeliveryFatalError,
    DeliveryRetryableError,
    HTTPXObserverCoreTransport,
)
from tests.phase5b_helpers import (
    BOOT_A,
    NOW,
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
)


def _verifier() -> EnvelopeVerifier:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    return EnvelopeVerifier(root, chain)


def _coordinator(path: Path) -> tuple[AcceptanceCoordinator, SegmentStore, EnvelopeVerifier]:
    verifier = _verifier()
    store = SegmentStore(path)
    return AcceptanceCoordinator.create_empty(verifier, store), store, verifier


def _recovered_coordinator(
    path: Path,
) -> tuple[AcceptanceCoordinator, SegmentStore, EnvelopeVerifier]:
    verifier = _verifier()
    store = SegmentStore(path)
    return AcceptanceCoordinator.open_and_recover(verifier, store), store, verifier


def test_factories_enforce_replay_and_single_store_lifecycle(tmp_path: Path) -> None:
    path = tmp_path / "evidence"
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    raw_store = SegmentStore(path)
    with pytest.raises(TypeError):
        AcceptanceCoordinator(EnvelopeVerifier(root, chain), raw_store)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        raw_store,
    )
    item = decode_events_page(
        canonical_json(page_value(boot_boundary(key)))
    ).events[0]
    coordinator.accept(item)
    raw_store.flush_security_boundary()
    raw_store.close()

    reopened = SegmentStore(path)
    with pytest.raises(EvidenceReadOnly):
        AcceptanceCoordinator.create_empty(EnvelopeVerifier(root, chain), reopened)
    recovered = AcceptanceCoordinator.open_and_recover(
        EnvelopeVerifier(root, chain),
        reopened,
    )
    assert recovered.verifier.fsm.last_sequence == 1
    assert recovered.accept(item).source_sequence == 1
    assert len(tuple(reopened.iter_records())) == 1
    reopened.close()


def test_append_failure_leaves_fsm_uncommitted_and_retry_is_exact(tmp_path: Path) -> None:
    coordinator, store, verifier = _coordinator(tmp_path / "evidence")
    key = private_key(11)
    item = decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    store.fail_next_append = OSError("injected append failure")
    with pytest.raises(OSError, match="injected"):
        coordinator.accept(item)
    assert verifier.fsm.last_sequence == 0

    first = coordinator.accept(item)
    retry = coordinator.accept(item)
    assert retry == first
    assert next(store.iter_records()).ref == first
    conflict = decode_events_page(
        canonical_json(
            page_value(
                envelope_value(
                    key,
                    sequence=1,
                    boot_id=BOOT_A,
                    normalized_fields={"kind": "signed-conflict"},
                )
            )
        )
    ).events[0]
    with pytest.raises(EnvelopeConflict):
        coordinator.accept(conflict)
    assert json.loads((tmp_path / "evidence" / "health.json").read_bytes())[
        "reason"
    ] == "evidence_conflict"
    store.close(flush=False)
    read_only = SegmentStore(tmp_path / "evidence")
    assert read_only.read_only_reason == "evidence_conflict"
    with pytest.raises(EvidenceReadOnly):
        read_only.flush_security_boundary()
    read_only.close(flush=False)


@pytest.mark.parametrize(
    "failure_step",
    [
        "create",
        "create_directory_fsync",
        "write",
        "file_fsync",
        "rename",
        "rename_directory_fsync",
    ],
)
def test_health_intent_keeps_marker_failure_fail_closed(
    tmp_path: Path,
    failure_step: str,
) -> None:
    path = tmp_path / failure_step
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    injected = False

    def health_hook(step: str) -> None:
        nonlocal injected
        if step == failure_step and not injected:
            injected = True
            raise OSError(f"injected health {step}")

    store = SegmentStore(path, health_step_hook=health_hook)
    verifier = EnvelopeVerifier(root, chain)
    coordinator = AcceptanceCoordinator.create_empty(verifier, store)
    coordinator.accept(
        decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    )
    active = store.active_path
    assert active is not None
    triggering_bytes = active.read_bytes()
    conflict = decode_events_page(
        canonical_json(
            page_value(
                envelope_value(
                    key,
                    sequence=1,
                    boot_id=BOOT_A,
                    normalized_fields={"kind": "conflict"},
                )
            )
        )
    ).events[0]
    with pytest.raises(OSError, match="injected health"):
        coordinator.accept(conflict)
    assert store.read_only_reason == "evidence_conflict"
    assert verifier.fsm.mutation_read_only is False
    assert active.read_bytes() == triggering_bytes
    store.close(flush=False)

    restarted = SegmentStore(path)
    assert restarted.read_only_reason in {"evidence_conflict", "segment_corrupt"}
    assert active.read_bytes() == triggering_bytes
    restarted.close(flush=False)


def test_runtime_close_reread_failure_trips_persistent_fence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runtime-corruption"
    coordinator, store, _verifier = _coordinator(path)
    key = private_key(11)
    coordinator.accept(
        decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    )
    active = store.active_path
    assert active is not None
    changed = bytearray(active.read_bytes())
    changed[len(changed) // 2] ^= 1
    active.write_bytes(changed)
    triggering_bytes = active.read_bytes()
    with pytest.raises(EvidenceCorrupt):
        store.flush_security_boundary()
    assert active.read_bytes() == triggering_bytes
    assert json.loads((path / "health.json").read_bytes())["reason"] == "segment_corrupt"
    store.close(flush=False)


def test_durable_append_before_commit_retries_without_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, store, verifier = _coordinator(tmp_path / "evidence")
    key = private_key(11)
    item = decode_events_page(
        canonical_json(page_value(boot_boundary(key)))
    ).events[0]
    commit_durable = verifier._commit_durable
    failed = False

    def fail_once(authorization: Any, lifecycle: object, ref: object) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise RuntimeError("injected crash after durable append")
        commit_durable(authorization, lifecycle, ref)

    monkeypatch.setattr(verifier, "_commit_durable", fail_once)
    with pytest.raises(RuntimeError, match="after durable"):
        coordinator.accept(item)
    records = tuple(store.iter_records())
    assert len(records) == 1
    assert verifier.fsm.last_sequence == 0
    active = store.active_path
    assert active is not None
    durable_bytes = active.read_bytes()

    different = decode_events_page(
        canonical_json(page_value(boot_boundary(key, sequence=2)))
    ).events[0]
    with pytest.raises(EvidenceReadOnly):
        coordinator.accept(different)
    assert active.read_bytes() == durable_bytes
    assert len(tuple(store.iter_records())) == 1

    retried = coordinator.accept(item)
    assert retried == records[0].ref
    assert verifier.fsm.last_sequence == 1
    assert len(tuple(store.iter_records())) == 1
    expected_fsm = verifier.fsm
    store.flush_security_boundary()
    store.close()

    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    reopened_store = SegmentStore(tmp_path / "evidence")
    reopened = AcceptanceCoordinator.open_and_recover(
        EnvelopeVerifier(root, chain),
        reopened_store,
    )
    assert reopened.verifier.fsm == expected_fsm
    assert reopened.accept(item) == retried
    reopened_store.close()


def test_restart_rebuilds_verifier_authority_from_evidence(tmp_path: Path) -> None:
    path = tmp_path / "evidence"
    coordinator_before_restart, store, verifier_before_restart = _coordinator(path)
    key = private_key(11)
    item = decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    expected = coordinator_before_restart.accept(item)
    assert verifier_before_restart.fsm.last_sequence == 1
    store.flush_security_boundary()
    store.close()

    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    restarted_store = SegmentStore(path)
    restarted = AcceptanceCoordinator.recover(
        EnvelopeVerifier(root, chain),
        restarted_store,
    )
    assert restarted.accept(item) == expected
    assert restarted.verifier.fsm.last_sequence == 1
    assert len(tuple(restarted_store.iter_records())) == 1
    restarted_store.close()

    authenticity_path = tmp_path / "structurally-valid-but-unauthenticated"
    authentic_coordinator, authentic_store, _ = _coordinator(authenticity_path)
    authentic_coordinator.accept(item)
    authentic_store.flush_security_boundary()
    manifest = authentic_store.manifests[0]
    authentic_store.close()
    segment_path = authenticity_path / manifest.segment_relative_path
    frame_record = decode_frames(
        segment_path.read_bytes(),
        max_frame=128 * 1024,
    ).records[0]
    stored = json.loads(frame_record.payload)
    stored["envelope"]["source_signature"] = "0" * 128
    stored["outer"]["content_sha256"] = hashlib.sha256(
        canonical_json(stored["envelope"])
    ).hexdigest()
    rewritten = encode_frame(
        canonical_json(stored),
        previous_hash=bytes(32),
        max_frame=128 * 1024,
    )
    segment_path.write_bytes(rewritten)
    manifest_value = manifest.model_dump()
    manifest_value.update(
        {
            "segment_size_bytes": len(rewritten),
            "segment_sha256": hashlib.sha256(rewritten).hexdigest(),
            "first_frame_sha256": rewritten[-32:].hex(),
            "last_frame_sha256": rewritten[-32:].hex(),
        }
    )
    manifest_value["manifest_sha256"] = segment_manifest_hash(manifest_value)
    rewritten_manifest = SegmentManifestV1.model_validate(manifest_value, strict=True)
    (authenticity_path / "manifests" / f"{manifest.segment_id}.json").write_bytes(
        canonical_json(rewritten_manifest)
    )
    (authenticity_path / "chain-head.json").write_bytes(
        canonical_json(chain_head_for(rewritten_manifest))
    )
    triggering_bytes = segment_path.read_bytes()
    structurally_valid = SegmentStore(authenticity_path)
    with pytest.raises(EnvelopeSignatureError):
        AcceptanceCoordinator.recover(
            EnvelopeVerifier(root, chain),
            structurally_valid,
        )
    assert segment_path.read_bytes() == triggering_bytes
    assert json.loads((authenticity_path / "health.json").read_bytes())[
        "reason"
    ] == "segment_corrupt"
    structurally_valid.close()


def _page_bytes(
    *envelopes: dict[str, object],
    acked_through: int = 0,
    reserved_through: int | None = None,
    uncovered_gaps: list[dict[str, int]] | None = None,
) -> bytes:
    value = page_value(*envelopes)
    value["acked_through"] = acked_through
    if reserved_through is not None:
        value["reserved_through"] = reserved_through
    value["uncovered_gaps"] = uncovered_gaps or []
    return canonical_json(value)


class _ScriptedTransport:
    def __init__(
        self,
        pages: list[bytes | BaseException] | None = None,
        acknowledgements: list[None | BaseException] | None = None,
    ) -> None:
        self.pages = pages or []
        self.acknowledgements = acknowledgements or []
        self.actions: list[tuple[str, int | bytes, int | None]] = []

    async def fetch_events(self, *, after: int, limit: int) -> bytes:
        self.actions.append(("fetch", after, limit))
        if not self.pages:
            raise AssertionError("unexpected fetch")
        result = self.pages.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    async def ack_event(self, body: bytes) -> None:
        self.actions.append(("ack", body, None))
        if not self.acknowledgements:
            raise AssertionError("unexpected ACK")
        result = self.acknowledgements.pop(0)
        if isinstance(result, BaseException):
            raise result

    async def close(self) -> None:
        pass


class _OneChunkStream(httpx.AsyncByteStream):
    def __init__(self, body: bytes | BaseException) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        if isinstance(self.body, BaseException):
            raise self.body
        yield self.body


class _StrictEvidenceBarrier:
    """Test capability whose answer is derived only from authenticated refs."""

    def __init__(
        self,
        store: SegmentStore,
        open_sequence: int | None = None,
        close_sequence: int | None = None,
    ) -> None:
        self.store = store
        self.open_sequence = open_sequence
        self.close_sequence = close_sequence

    def __call__(self) -> int | None:
        sequences = {
            record.ref.source_sequence
            for record in self.store.iter_authenticated_records()
        }
        if self.open_sequence not in sequences:
            return None
        if self.close_sequence in sequences:
            return None
        return self.open_sequence


def _test_delivery(
    acceptance: AcceptanceCoordinator,
    journal: AckJournal,
    transport: _ScriptedTransport,
    *,
    barrier: _StrictEvidenceBarrier | None = None,
    budget: int = 100,
) -> DeliveryCoordinator:
    return DeliveryCoordinator._create_unsafe_for_test(
        acceptance,
        journal,
        transport,
        ack_barrier=barrier or _StrictEvidenceBarrier(acceptance.segment_store),
        ack_budget=budget,
    )


def _ack_sequences(transport: _ScriptedTransport) -> list[int]:
    return [
        int(json.loads(body)["sequence"])
        for action, body, _limit in transport.actions
        if action == "ack" and isinstance(body, bytes)
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "status", "headers", "body", "error_type"),
    [
        ("fetch", 200, {"Content-Type": "application/json"}, _page_bytes(), None),
        ("fetch", 503, {}, b"private", DeliveryRetryableError),
        (
            "fetch",
            200,
            {"Content-Type": "application/json; charset=utf-8"},
            _page_bytes(),
            DeliveryFatalError,
        ),
        (
            "fetch",
            200,
            {"Content-Type": "application/json", "Content-Encoding": "identity"},
            _page_bytes(),
            DeliveryFatalError,
        ),
        (
            "fetch",
            200,
            {"Content-Type": "application/json"},
            b"x" * (MAX_EVENTS_PAGE_BYTES + 1),
            DeliveryFatalError,
        ),
        ("fetch", 307, {"Location": "http://observer/elsewhere"}, b"", DeliveryFatalError),
        ("fetch", 200, {"Content-Type": "text/plain"}, OSError("private"), DeliveryFatalError),
        ("ack", 204, {}, b"", None),
        ("ack", 204, {}, b"x", DeliveryFatalError),
        ("ack", 503, {}, b"private", DeliveryAmbiguousAck),
        ("ack", 409, {}, b"private", DeliveryFatalError),
        ("ack", 409, {}, OSError("private"), DeliveryFatalError),
        ("ack", 200, {}, b"", DeliveryFatalError),
        pytest.param("close", 0, {}, b"", None, id="close_retry"),
    ],
)
async def test_delivery_transport_bounds_routes_and_statuses(
    monkeypatch: pytest.MonkeyPatch,
    operation: Literal["fetch", "ack", "close"],
    status: int,
    headers: dict[str, str],
    body: bytes | BaseException,
    error_type: type[Exception] | None,
) -> None:
    seen: list[tuple[str, str, bytes, str | None]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (request.method, str(request.url), await request.aread(), request.headers.get("Content-Type"))
        )
        return httpx.Response(status, headers=headers, stream=_OneChunkStream(body))

    transport = HTTPXObserverCoreTransport(
        Path("/run/agmind-sais/observer-core/socket"),
        transport=httpx.MockTransport(handler),
    )
    if operation == "close":
        close = transport._client.aclose
        attempts = 0

        async def cancelled_once() -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise asyncio.CancelledError
            await close()

        monkeypatch.setattr(transport._client, "aclose", cancelled_once)
        with pytest.raises(asyncio.CancelledError):
            await transport.close()
        await transport.close()
        assert attempts == 2
        assert seen == []
        return
    ack_body = (
        b'{"content_sha256":"'
        + b"a" * 64
        + b'","event_id":"evt_'
        + b"b" * 64
        + b'","schema_version":"agmind.observer-ack.v1","sequence":7}'
    )
    call = (
        transport.fetch_events(after=7, limit=3)
        if operation == "fetch"
        else transport.ack_event(ack_body)
    )
    if error_type is None:
        result = await call
        if operation == "fetch":
            assert isinstance(body, bytes)
            assert result == body
    else:
        with pytest.raises(error_type) as raised:
            await call
        assert "private" not in str(raised.value)
    if operation == "fetch":
        expected = (
            "GET",
            "http://observer/v1/events?after=7&limit=3",
            b"",
            None,
        )
    else:
        expected = (
            "POST",
            "http://observer/v1/events/ack",
            ack_body,
            "application/json",
        )
    assert seen == [expected]
    await transport.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ack_outcome",
    ["success", "ambiguous", "cancelled", "lifecycle_authority"],
)
async def test_delivery_commit_timeline_and_exact_pending_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ack_outcome: str,
) -> None:
    coordinator, store, _verifier = _coordinator(tmp_path / ack_outcome)
    journal = AckJournal.create_new(store)
    key = private_key(11)
    if ack_outcome == "lifecycle_authority":
        transport = _ScriptedTransport()
        lease = journal.claim_delivery(store)
        with pytest.raises(TypeError):
            DeliveryCoordinator(
                coordinator,
                journal,
                lease,
                transport,
                ack_barrier=lambda: None,
            )
        lease.release()

        _other, other_store, _other_verifier = _coordinator(tmp_path / "other")
        other_journal = AckJournal.create_new(other_store)
        with pytest.raises(AckJournalAuthorityError):
            _test_delivery(coordinator, other_journal, transport)
        delivery = _test_delivery(coordinator, journal, transport)
        with pytest.raises(AckJournalStateError):
            _test_delivery(coordinator, journal, transport)
        close_attempts = 0

        async def cancelled_close_once() -> None:
            nonlocal close_attempts
            close_attempts += 1
            if close_attempts == 1:
                raise asyncio.CancelledError

        monkeypatch.setattr(transport, "close", cancelled_close_once)
        with pytest.raises(asyncio.CancelledError):
            await delivery.close()
        replacement = _test_delivery(
            coordinator,
            journal,
            _ScriptedTransport(),
        )
        await delivery.close()
        await replacement.close()
        assert close_attempts == 2
        assert transport.actions == []
        other_journal.close()
        other_store.close()
        store.close()
        return
    first_page = _page_bytes(boot_boundary(key), reserved_through=1)
    outcome = {
        "success": None,
        "ambiguous": DeliveryAmbiguousAck("ambiguous observer ACK"),
        "cancelled": asyncio.CancelledError(),
    }[ack_outcome]
    transport = _ScriptedTransport([first_page], [outcome])
    delivery = _test_delivery(coordinator, journal, transport)
    timeline: list[str] = []

    def traced(label: str, function: Any) -> Any:
        def wrapper(argument: object) -> object:
            repeated = label == "pending" and journal.snapshot().pending is not None
            result = function(argument)
            if not repeated:
                timeline.append(label)
            return result

        return wrapper

    original_ack = transport.ack_event

    async def ack_with_timeline(body: bytes) -> None:
        timeline.append("post")
        await original_ack(body)

    monkeypatch.setattr(coordinator, "accept", traced("evidence", coordinator.accept))
    monkeypatch.setattr(journal, "record_pending", traced("pending", journal.record_pending))
    monkeypatch.setattr(
        journal,
        "record_confirmed",
        traced("confirmed", journal.record_confirmed),
    )
    monkeypatch.setattr(transport, "ack_event", ack_with_timeline)

    if ack_outcome == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            await delivery.poll_once()
        assert timeline == ["evidence", "pending", "post"]
        assert journal.snapshot().pending is not None
    else:
        result = await delivery.poll_once()
        if ack_outcome == "success":
            assert timeline == ["evidence", "pending", "post", "confirmed"]
            assert result.confirmed_through == 1
            assert result.retry_required is False
        else:
            assert timeline == ["evidence", "pending", "post"]
            assert result.retry_required is True
            pending_body = journal.pending_request_body()
            assert pending_body is not None
            await delivery.close()
            store.close()

            coordinator, store, _verifier_after_restart = _recovered_coordinator(
                tmp_path / ack_outcome
            )
            journal = AckJournal.open_and_recover(store)
            transport = _ScriptedTransport([], [None])
            delivery = _test_delivery(coordinator, journal, transport)
            assert await delivery.recover_pending_ack() is True
            assert transport.actions == [("ack", pending_body, None)]
            transport.pages.append(_page_bytes(acked_through=1, reserved_through=1))
            retried = await delivery.poll_once()
            assert transport.actions[-1] == ("fetch", 1, 100)
            assert retried.confirmed_through == 1
    await delivery.close()
    store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "case",
        "local_state",
        "page_kind",
        "acked",
        "reserved",
        "expected_order",
    ),
    [
        ("observer_ahead", "none", "empty", 1, 1, None),
        ("observer_rollback", "confirmed", "empty", 0, 1, None),
        ("reservation_rollback", "evidence", "empty", 0, 0, None),
        ("event_not_after_request", "evidence", "event", 0, 1, None),
        ("gap_not_after_request", "evidence", "gap", 0, 2, None),
        ("store_lookup_failure", "none", "event", 0, 1, None),
        ("clean_get_before_pending", "evidence", "empty", 0, 1, ("fetch", "ack")),
        ("pending_before_get", "pending", "empty", 1, 1, ("ack", "fetch")),
    ],
)
async def test_delivery_cursor_divergence_and_network_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    local_state: Literal["none", "evidence", "confirmed", "pending"],
    page_kind: Literal["empty", "event", "gap"],
    acked: int,
    reserved: int,
    expected_order: tuple[str, str] | None,
) -> None:
    path = tmp_path / case
    coordinator, store, _verifier_before_restart = _coordinator(path)
    journal = AckJournal.create_new(store)
    key = private_key(11)
    seeded_ref = None
    if local_state != "none":
        seeded_ref = coordinator.accept(
            decode_events_page(_page_bytes(boot_boundary(key), reserved_through=1)).events[0]
        )
    if local_state == "confirmed":
        assert seeded_ref is not None
        journal.record_pending(seeded_ref)
        journal.record_confirmed(seeded_ref)
    elif local_state == "pending":
        assert seeded_ref is not None
        journal.record_pending(seeded_ref)
    if case == "clean_get_before_pending":
        journal.close()
        store.close()
        coordinator, store, _verifier_after_restart = _recovered_coordinator(path)
        journal = AckJournal.open_and_recover(store)

    envelopes = (boot_boundary(key),) if page_kind == "event" else ()
    gaps = [{"start": 1, "end": 2}] if page_kind == "gap" else None
    page = _page_bytes(
        *envelopes, acked_through=acked, reserved_through=reserved, uncovered_gaps=gaps
    )

    transport = _ScriptedTransport([page], [None])
    delivery = _test_delivery(coordinator, journal, transport)
    if case == "store_lookup_failure":
        authenticated_refs = store.authenticated_refs
        calls = 0

        def fail_third_lookup(**kwargs: int) -> object:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise EvidenceCorrupt("injected authenticated-ref failure")
            return authenticated_refs(**kwargs)

        monkeypatch.setattr(store, "authenticated_refs", fail_third_lookup)
    if expected_order is None:
        with pytest.raises(DeliveryFatalError):
            await delivery.poll_once()
        assert _ack_sequences(transport) == []
        if case == "store_lookup_failure":
            with pytest.raises(DeliveryFatalError):
                await delivery.poll_once()
            assert [action for action, _value, _limit in transport.actions] == ["fetch"]
    else:
        result = await delivery.poll_once()
        assert result.confirmed_through == 1
        assert tuple(action for action, _value, _limit in transport.actions) == (
            expected_order
        )
        fetch_actions = [
            action for action in transport.actions if action[0] == "fetch"
        ]
        assert fetch_actions == [("fetch", 1, 100)]
    await delivery.close()
    store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["barrier_release", "hints_only", "partial_page"])
async def test_delivery_holes_barrier_restart_and_partial_page(
    tmp_path: Path,
    case: str,
) -> None:
    coordinator, store, _verifier = _coordinator(tmp_path / case)
    journal = AckJournal.create_new(store)
    key = private_key(11)
    if case == "barrier_release":
        later = envelope_value(
            key,
            sequence=4,
            normalized_fields={"kind": "later"},
        )
        gap = envelope_value(
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
        close_surrogate = envelope_value(
            key,
            sequence=6,
            normalized_fields={"kind": "authenticated-close-surrogate"},
        )
        barrier = _StrictEvidenceBarrier(store, 5, 6)
        transport = _ScriptedTransport(
            [
                _page_bytes(
                    boot_boundary(key),
                    later,
                    gap,
                    acked_through=0,
                    reserved_through=5,
                ),
                _page_bytes(acked_through=1, reserved_through=5),
                _page_bytes(
                    close_surrogate,
                    acked_through=4,
                    reserved_through=6,
                ),
                _page_bytes(acked_through=5, reserved_through=6),
            ],
            [None, None, None, None],
        )
        delivery = _test_delivery(
            coordinator,
            journal,
            transport,
            barrier=barrier,
            budget=1,
        )
        first = await delivery.poll_once()
        assert first.confirmed_through == 1
        held = await delivery.poll_once()
        assert (held.evidence_head, held.acceptance_cursor) == (5, 5)
        assert held.confirmed_through == 4
        assert _ack_sequences(transport) == [1, 4]
        released = await delivery.poll_once()
        assert released.confirmed_through == 5
        drained = await delivery.poll_once()
        assert drained.confirmed_through == 6
        assert _ack_sequences(transport) == [1, 4, 5, 6]
    elif case == "hints_only":
        page = _page_bytes(
            boot_boundary(key),
            reserved_through=3,
            uncovered_gaps=[{"start": 2, "end": 3}],
        )
        transport = _ScriptedTransport([page], [None])
        delivery = _test_delivery(coordinator, journal, transport)
        result = await delivery.poll_once()
        assert result.evidence_head == 1
        assert result.acceptance_cursor == 1
        assert result.confirmed_through == 1
        assert _ack_sequences(transport) == [1]
    else:
        invalid = envelope_value(
            key,
            sequence=2,
            normalized_fields={"kind": "invalid-signature"},
        )
        invalid["source_signature"] = "0" * 128
        page = _page_bytes(boot_boundary(key), invalid, reserved_through=2)
        transport = _ScriptedTransport([page])
        delivery = _test_delivery(coordinator, journal, transport)
        with pytest.raises(DeliveryFatalError):
            await delivery.poll_once()
        assert [record.ref.source_sequence for record in store.iter_records()] == [1]
        assert journal.snapshot().pending is None
        assert _ack_sequences(transport) == []
    await delivery.close()
    store.close()
