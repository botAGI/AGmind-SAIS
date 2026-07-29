from __future__ import annotations

import asyncio
import copy
import hashlib
import pickle
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Literal

import httpx
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import (
    ObserverTrustRootV1,
    RetentionBlockedV1,
    RetentionTombstoneV2,
)
from agmind_immune.coverage import CoverageState
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.ingest import envelope as envelope_module
from agmind_immune.ingest import service as service_module
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.envelope import (
    CoreEventV1,
    EnvelopeVerifier,
    VerifierCommitError,
)
from agmind_immune.ingest.service import (
    AcceptanceCoordinator,
    DeliveryCoordinator,
    DeliveryFatalError,
    DeliveryRetryableError,
    HTTPXObserverCoreTransport,
)
from tests.phase5b_helpers import (
    BOOT_A,
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
    rotation_pair,
)

REQUEST_ID = "11111111-1111-4111-8111-111111111111"
OTHER_REQUEST_ID = "22222222-2222-4222-8222-222222222222"


def _tombstone(
    *,
    tombstone_id: str = REQUEST_ID,
) -> RetentionTombstoneV2:
    manifest_hashes = ["1" * 64, "2" * 64]
    return RetentionTombstoneV2(
        schema_version="agmind.retention-tombstone.v2",
        tombstone_id=tombstone_id,
        removed_manifest_hashes=manifest_hashes,
        first_removed_manifest_sha256=manifest_hashes[0],
        last_removed_manifest_sha256=manifest_hashes[-1],
        first_retained_manifest_sha256="3" * 64,
        removed_bytes=17,
        reason="retention_age_limit",
        policy_version="agmind-retention-v1",
        current_chain_head_sha256="4" * 64,
        manifest_run_sha256=hashlib.sha256(
            b"AGMIND_RETENTION_RUN_V2\x00"
            + canonical_json(manifest_hashes)
        ).hexdigest(),
    )


def _blocked(
    *,
    blocked_id: str = REQUEST_ID,
) -> RetentionBlockedV1:
    return RetentionBlockedV1(
        schema_version="agmind.retention-blocked.v1",
        blocked_id=blocked_id,
        target_bytes=5,
        routine_bytes=4,
        protected_bytes=3,
        blocked_bytes=2,
        reason="protected_evidence",
        current_chain_head_sha256="4" * 64,
    )


def _item(envelope: dict[str, object]) -> CoreEventV1:
    return envelope_module.decode_events_page(
        canonical_json(page_value(envelope))
    ).events[0]


def _bound_verifier(
    path: Path,
) -> tuple[AcceptanceCoordinator, SegmentStore, EnvelopeVerifier]:
    key = private_key(11)
    root = envelope_module.PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key), strict=True)
    )
    chain = envelope_module.AnchoredPublicKeyChain.from_value(
        root,
        metadata_value(key),
    )
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    coordinator.accept(_item(boot_boundary(key)))
    return coordinator, store, coordinator.verifier


def _bound_rotating_verifier(
    path: Path,
) -> tuple[SegmentStore, EnvelopeVerifier, tuple[dict[str, object], ...]]:
    old_key = private_key(11)
    new_key = private_key(12)
    rotation = rotation_pair(
        old_key,
        new_key,
        transition_sequence=2,
        transition_boot=BOOT_A,
        start_boot=BOOT_A,
        mode="same",
    )
    root = envelope_module.PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(old_key), strict=True)
    )
    chain = envelope_module.AnchoredPublicKeyChain.from_value(
        root,
        metadata_value(old_key, rotation=rotation),
    )
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    coordinator.accept(_item(boot_boundary(old_key)))
    return store, coordinator.verifier, rotation


def _page(
    *envelopes: dict[str, object],
    acked_through: int = 1,
    reserved_through: int | None = None,
) -> bytes:
    value = page_value(*envelopes)
    value["acked_through"] = acked_through
    if reserved_through is not None:
        value["reserved_through"] = reserved_through
    return canonical_json(value)


def _slot_clone(value: object) -> object:
    clone = object.__new__(type(value))
    for cls in type(value).__mro__:
        slots = getattr(cls, "__slots__", ())
        names = (slots,) if isinstance(slots, str) else slots
        for name in names:
            if name not in {"__dict__", "__weakref__"} and hasattr(value, name):
                object.__setattr__(clone, name, getattr(value, name))
    return clone


class _Clock:
    def live_receipt_monotonic(self) -> None:
        return None

    def decision_sample(self) -> object:
        raise AssertionError("retention preflight must not sample a decision clock")


class _RetentionTransport:
    def __init__(
        self,
        *,
        tombstone_direct: bytes | None = None,
        blocked_direct: bytes | None = None,
        pages: list[bytes] | None = None,
    ) -> None:
        self._tombstone_direct = tombstone_direct
        self._blocked_direct = blocked_direct
        self._pages = list(pages or ())
        self.posts: list[tuple[str, bytes]] = []
        self.fetches: list[tuple[int, int]] = []

    async def fetch_events(self, *, after: int, limit: int) -> bytes:
        self.fetches.append((after, limit))
        if not self._pages:
            raise AssertionError("unexpected retention fetch")
        return self._pages.pop(0)

    async def ack_event(self, body: bytes) -> None:
        raise AssertionError(f"retention preflight attempted ACK: {body!r}")

    async def publish_repair_authorization(self, canonical_body: bytes) -> bytes:
        raise AssertionError(
            f"retention preflight used repair authorization: {canonical_body!r}"
        )

    async def publish_repair_completion(self, canonical_body: bytes) -> bytes:
        raise AssertionError(
            f"retention preflight used repair completion: {canonical_body!r}"
        )

    async def publish_retention_tombstone(
        self,
        canonical_body: bytes,
    ) -> bytes:
        self.posts.append(("tombstone", canonical_body))
        if self._tombstone_direct is None:
            raise AssertionError("unexpected retention tombstone POST")
        return self._tombstone_direct

    async def publish_retention_blocked(self, canonical_body: bytes) -> bytes:
        self.posts.append(("blocked", canonical_body))
        if self._blocked_direct is None:
            raise AssertionError("unexpected retention blocked POST")
        return self._blocked_direct

    async def close(self) -> None:
        return None


def _bound_delivery(
    path: Path,
    transport: _RetentionTransport,
) -> tuple[DeliveryCoordinator, SegmentStore, EnvelopeVerifier, AckJournal]:
    key = private_key(11)
    root = envelope_module.PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key), strict=True)
    )
    chain = envelope_module.AnchoredPublicKeyChain.from_value(
        root,
        metadata_value(key),
    )
    store = SegmentStore(path)
    acceptance = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    acknowledgements = AckJournal.create_new(store)
    coverage = CoverageState.open_and_recover(store)
    boot_ref = acceptance.accept(_item(boot_boundary(key)))
    store.flush_security_boundary()
    coverage._apply_live_accepted(store, boot_ref, None)
    acknowledgements.record_pending(boot_ref)
    acknowledgements.record_confirmed(boot_ref)
    delivery = DeliveryCoordinator.create(
        acceptance,
        acknowledgements,
        transport,
        coverage=coverage,
        clock=_Clock(),
    )
    return delivery, store, acceptance.verifier, acknowledgements


class _OneChunk(httpx.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self._body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._body


@pytest.mark.asyncio
async def test_retention_transport_uses_exact_routes_bodies_and_request_bounds() -> None:
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
        return httpx.Response(
            200 if request.url.path.endswith("tombstone") else 201,
            headers={"Content-Type": "application/json"},
            stream=_OneChunk(b'{"ok":true}'),
        )

    transport = HTTPXObserverCoreTransport(
        "/unused",
        transport=httpx.MockTransport(handler),
    )
    tombstone_body = canonical_json(_tombstone().model_dump(mode="python"))
    blocked_body = canonical_json(_blocked().model_dump(mode="python"))

    assert (
        await transport.publish_retention_tombstone(tombstone_body)
        == b'{"ok":true}'
    )
    assert (
        await transport.publish_retention_blocked(blocked_body)
        == b'{"ok":true}'
    )
    assert seen == [
        (
            "POST",
            "/v1/events/retention-tombstone",
            tombstone_body,
            "application/json",
        ),
        (
            "POST",
            "/v1/events/retention-blocked",
            blocked_body,
            "application/json",
        ),
    ]
    with pytest.raises(DeliveryFatalError, match="16 KiB"):
        await transport.publish_retention_tombstone(b"x" * (16 * 1024 + 1))
    with pytest.raises(DeliveryFatalError, match="4 KiB"):
        await transport.publish_retention_blocked(b"x" * (4 * 1024 + 1))
    assert len(seen) == 2
    await transport.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "headers", "body", "error"),
    [
        (None, {}, b"", DeliveryRetryableError),
        (408, {}, b"timeout", DeliveryRetryableError),
        (503, {}, b"unavailable", DeliveryRetryableError),
        (409, {}, b"conflict", DeliveryFatalError),
        (202, {}, b"unexpected", DeliveryFatalError),
        (
            503,
            {"Content-Encoding": "identity"},
            b"unavailable",
            DeliveryFatalError,
        ),
        (
            200,
            {"Content-Type": "application/json; charset=utf-8"},
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
)
async def test_retention_transport_response_matrix_is_fail_closed(
    status: int | None,
    headers: dict[str, str],
    body: bytes,
    error: type[Exception],
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if status is None:
            raise httpx.ReadError("injected transport ambiguity", request=request)
        return httpx.Response(status, headers=headers, stream=_OneChunk(body))

    transport = HTTPXObserverCoreTransport(
        "/unused",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(error):
        await transport.publish_retention_tombstone(
            canonical_json(_tombstone().model_dump(mode="python"))
        )
    await transport.close()


@pytest.mark.parametrize("operation", ["tombstone", "blocked"])
def test_retention_simulation_excludes_valid_suffix_and_mints_exact_proof(
    tmp_path: Path,
    operation: Literal["tombstone", "blocked"],
) -> None:
    key = private_key(11)
    _coordinator, store, verifier = _bound_verifier(tmp_path)
    request = _tombstone() if operation == "tombstone" else _blocked()
    event_type = (
        "retention_tombstone"
        if operation == "tombstone"
        else "retention_blocked_priority_evidence"
    )
    ordinary = _item(
        envelope_value(
            key,
            sequence=2,
            normalized_fields={"kind": "intervening"},
        )
    )
    direct = _item(
        envelope_value(
            key,
            sequence=5,
            event_type=event_type,
            normalized_fields=request.model_dump(mode="python"),
        )
    )
    suffix_envelope = envelope_value(
        key,
        sequence=6,
        normalized_fields={"kind": "post-target-suffix"},
    )
    suffix_envelope["source_signature"] = "0" * 128
    suffix = _item(suffix_envelope)
    authority_before = verifier._authority
    stages_before = dict(verifier._staged)
    simulation = verifier._new_control_simulation()
    if operation == "tombstone":
        proof = simulation.verify_exact_retention_tombstone(
            request,
            direct,
            (ordinary, direct, suffix),
        )
        validator = verifier._validate_retention_tombstone_proof
        proof_type = envelope_module.SimulatedRetentionTombstone
    else:
        proof = simulation.verify_exact_retention_blocked(
            request,
            direct,
            (ordinary, direct, suffix),
        )
        validator = verifier._validate_retention_blocked_proof
        proof_type = envelope_module.SimulatedRetentionBlocked

    assert type(proof) is proof_type
    assert proof.request == request
    assert proof.target.sequence == 5
    assert proof.predicted_generation == proof.base_generation + 2
    with pytest.raises(TypeError, match="copied"):
        copy.copy(proof)
    with pytest.raises(TypeError, match="copied"):
        copy.deepcopy(proof)
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(proof)
    lookalike = _slot_clone(proof)
    with pytest.raises(VerifierCommitError, match="foreign"):
        validator(lookalike)
    predicted_generation = proof.predicted_generation
    object.__setattr__(
        proof,
        "_predicted_generation",
        predicted_generation + 1,
    )
    with pytest.raises(VerifierCommitError, match="foreign"):
        validator(proof)
    object.__setattr__(
        proof,
        "_predicted_generation",
        predicted_generation,
    )
    changed_request = (
        _tombstone(tombstone_id=OTHER_REQUEST_ID)
        if operation == "tombstone"
        else _blocked(blocked_id=OTHER_REQUEST_ID)
    )
    changed_canonical = canonical_json(
        changed_request.model_dump(mode="python")
    )
    original_request_canonical = proof._request_canonical
    original_normalized_fields = proof.target._normalized_fields_canonical
    original_target_binding = proof._target_binding
    changed_target_binding = list(original_target_binding)
    changed_target_binding[8] = changed_canonical
    object.__setattr__(proof, "_request_canonical", changed_canonical)
    object.__setattr__(
        proof.target,
        "_normalized_fields_canonical",
        changed_canonical,
    )
    object.__setattr__(
        proof,
        "_target_binding",
        tuple(changed_target_binding),
    )
    with pytest.raises(VerifierCommitError, match="foreign"):
        validator(proof)
    object.__setattr__(
        proof,
        "_request_canonical",
        original_request_canonical,
    )
    object.__setattr__(
        proof.target,
        "_normalized_fields_canonical",
        original_normalized_fields,
    )
    object.__setattr__(
        proof,
        "_target_binding",
        original_target_binding,
    )
    assert validator(proof) is proof
    foreign_path = tmp_path.parent / f"{tmp_path.name}-foreign"
    _other_coordinator, foreign_store, foreign_verifier = _bound_verifier(
        foreign_path
    )
    foreign_validator = (
        foreign_verifier._validate_retention_tombstone_proof
        if operation == "tombstone"
        else foreign_verifier._validate_retention_blocked_proof
    )
    with pytest.raises(VerifierCommitError, match="foreign"):
        foreign_validator(proof)
    assert verifier._authority is authority_before
    assert verifier._staged == stages_before
    assert verifier._authorizations == {}
    foreign_store.close(flush=False)
    store.close(flush=False)


@pytest.mark.parametrize(
    "case",
    ["absent", "same-sequence-mismatch", "overshoot", "wrong-signed-fields"],
)
def test_retention_simulation_rejects_inexact_target_paths_without_live_mutation(
    tmp_path: Path,
    case: str,
) -> None:
    key = private_key(11)
    _coordinator, store, verifier = _bound_verifier(tmp_path)
    request = _tombstone()
    direct_request = (
        _tombstone(tombstone_id=OTHER_REQUEST_ID)
        if case == "wrong-signed-fields"
        else request
    )
    direct = _item(
        envelope_value(
            key,
            sequence=3,
            event_type="retention_tombstone",
            normalized_fields=direct_request.model_dump(mode="python"),
        )
    )
    ordinary = _item(
        envelope_value(
            key,
            sequence=2,
            normalized_fields={"kind": "intervening"},
        )
    )
    if case == "absent":
        fetched = (ordinary,)
    elif case == "same-sequence-mismatch":
        different = _item(
            envelope_value(
                key,
                sequence=3,
                event_type="retention_tombstone",
                normalized_fields=_tombstone(
                    tombstone_id=OTHER_REQUEST_ID
                ).model_dump(mode="python"),
            )
        )
        fetched = (ordinary, different)
    elif case == "overshoot":
        fetched = (
            _item(
                envelope_value(
                    key,
                    sequence=4,
                    normalized_fields={"kind": "past-target"},
                )
            ),
        )
    else:
        fetched = (ordinary, direct)
    authority_before = verifier._authority
    stages_before = dict(verifier._staged)
    transients_before = verifier._repair_transient_generation

    with pytest.raises(envelope_module.RetentionSimulationError):
        verifier._new_control_simulation().verify_exact_retention_tombstone(
            request,
            direct,
            fetched,
        )

    assert verifier._authority is authority_before
    assert verifier._staged == stages_before
    assert verifier._authorizations == {}
    assert verifier._repair_transient_generation == transients_before
    store.close(flush=False)


def test_retention_simulation_privately_follows_anchored_key_transition(
    tmp_path: Path,
) -> None:
    new_key = private_key(12)
    store, verifier, rotation = _bound_rotating_verifier(tmp_path)
    request = _tombstone()
    direct = _item(
        envelope_value(
            new_key,
            sequence=4,
            key_epoch=2,
            event_type="retention_tombstone",
            normalized_fields=request.model_dump(mode="python"),
        )
    )
    suffix = _item(
        envelope_value(
            new_key,
            sequence=5,
            key_epoch=2,
            normalized_fields={"kind": "post-target-suffix"},
        )
    )
    authority_before = verifier._authority

    proof = (
        verifier._new_control_simulation().verify_exact_retention_tombstone(
            request,
            direct,
            (_item(rotation[1]), _item(rotation[2]), direct, suffix),
        )
    )

    assert proof.target.key_epoch == 2
    assert proof.predicted_generation == proof.base_generation + 3
    assert verifier.fsm.active_epoch == 1
    assert verifier._authority is authority_before
    assert verifier._staged == {}
    assert verifier._authorizations == {}
    store.close(flush=False)


@pytest.mark.asyncio
async def test_retention_preflight_uses_local_cursor_and_excludes_bound_suffix(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    request = _tombstone()
    body = canonical_json(request.model_dump(mode="python"))
    first = envelope_value(
        key,
        sequence=2,
        normalized_fields={"kind": "first-intervening"},
    )
    second = envelope_value(
        key,
        sequence=3,
        normalized_fields={"kind": "second-intervening"},
    )
    target = envelope_value(
        key,
        sequence=7,
        event_type="retention_tombstone",
        normalized_fields=request.model_dump(mode="python"),
    )
    suffix = envelope_value(
        key,
        sequence=8,
        normalized_fields={"kind": "post-target-suffix"},
    )
    direct = _item(target)
    transport = _RetentionTransport(
        tombstone_direct=canonical_json(direct.model_dump(mode="python")),
        pages=[
            _page(first, second, reserved_through=7),
            _page(target, suffix),
        ],
    )
    delivery, store, verifier, acknowledgements = _bound_delivery(
        tmp_path,
        transport,
    )
    authority_before = verifier._authority
    ack_before = acknowledgements.snapshot()

    with pytest.raises(TypeError, match="owner"):
        await delivery._preflight_retention_tombstone(
            request,
            body,
            _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
            _lock_authority=object(),
        )
    raw_lock_entered = asyncio.Event()
    release_raw_lock = asyncio.Event()

    async def hold_raw_lock_without_authority() -> None:
        async with delivery._lock:
            raw_lock_entered.set()
            await release_raw_lock.wait()

    raw_holder = asyncio.create_task(hold_raw_lock_without_authority())
    await raw_lock_entered.wait()
    try:
        with pytest.raises(TypeError, match="owner"):
            await delivery._preflight_retention_tombstone(
                request,
                body,
                _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
                _lock_authority=object(),
            )
    finally:
        release_raw_lock.set()
        await raw_holder
    async with delivery._retention_preflight_scope(
        _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
    ) as lock_authority:
        proof = await delivery._preflight_retention_tombstone(
            request,
            body,
            _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
            _lock_authority=lock_authority,
        )

    assert type(proof) is envelope_module.SimulatedRetentionTombstone
    assert proof.target.sequence == 7
    assert proof.predicted_generation == proof.base_generation + 3
    assert transport.posts == [("tombstone", body)]
    assert transport.fetches == [(1, 6), (3, 4)]
    assert verifier._authority is authority_before
    assert verifier._staged == {}
    assert verifier._authorizations == {}
    assert store.status().evidence_head == 1
    assert acknowledgements.snapshot() == ack_before
    await delivery.close()
    store.close(flush=False)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "same-sequence-mismatch",
        "overshoot",
        "page-bound",
        "event-bound-includes-suffix",
        "byte-bound-includes-suffix",
        "malformed-suffix-outer-binding",
    ],
)
async def test_retention_preflight_rejects_conflicts_and_full_page_bound_exhaustion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    key = private_key(11)
    request = _tombstone()
    body = canonical_json(request.model_dump(mode="python"))
    first = envelope_value(
        key,
        sequence=2,
        normalized_fields={"kind": "first-intervening"},
    )
    second = envelope_value(
        key,
        sequence=3,
        normalized_fields={"kind": "second-intervening"},
    )
    target = envelope_value(
        key,
        sequence=7,
        event_type="retention_tombstone",
        normalized_fields=request.model_dump(mode="python"),
    )
    suffix = envelope_value(
        key,
        sequence=8,
        normalized_fields={"kind": "post-target-suffix"},
    )
    direct = _item(target)
    page_one = _page(first, second, reserved_through=7)
    if case == "same-sequence-mismatch":
        different = envelope_value(
            key,
            sequence=7,
            event_type="retention_tombstone",
            normalized_fields=_tombstone(
                tombstone_id=OTHER_REQUEST_ID
            ).model_dump(mode="python"),
        )
        pages = [page_one, _page(different)]
    elif case == "overshoot":
        pages = [_page(suffix)]
    elif case == "malformed-suffix-outer-binding":
        malformed = page_value(target, suffix)
        malformed["acked_through"] = 1
        events = malformed["events"]
        assert isinstance(events, list)
        suffix_item = events[-1]
        assert isinstance(suffix_item, dict)
        suffix_item["content_sha256"] = "0" * 64
        pages = [page_one, canonical_json(malformed)]
    else:
        page_two = _page(target, suffix)
        pages = [page_one, page_two]
        if case == "page-bound":
            monkeypatch.setattr(
                service_module,
                "_MAX_RETENTION_PREFLIGHT_PAGES",
                1,
            )
        elif case == "event-bound-includes-suffix":
            monkeypatch.setattr(
                service_module,
                "_MAX_RETENTION_PREFLIGHT_EVENTS",
                3,
            )
        else:
            monkeypatch.setattr(
                service_module,
                "_MAX_RETENTION_PREFLIGHT_RESPONSE_BYTES",
                len(page_one) + len(page_two) - 1,
            )
    transport = _RetentionTransport(
        tombstone_direct=canonical_json(direct.model_dump(mode="python")),
        pages=pages,
    )
    delivery, store, verifier, acknowledgements = _bound_delivery(
        tmp_path,
        transport,
    )
    authority_before = verifier._authority
    ack_before = acknowledgements.snapshot()

    with pytest.raises(DeliveryFatalError):
        async with delivery._retention_preflight_scope(
            _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
        ) as lock_authority:
            await delivery._preflight_retention_tombstone(
                request,
                body,
                _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
                _lock_authority=lock_authority,
            )

    assert verifier._authority is authority_before
    assert verifier._staged == {}
    assert verifier._authorizations == {}
    assert store.status().evidence_head == 1
    assert acknowledgements.snapshot() == ack_before
    await delivery.close()
    store.close(flush=False)


@pytest.mark.asyncio
async def test_retention_preflight_fences_live_mutation_on_retryable_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = private_key(11)
    request = _tombstone()
    body = canonical_json(request.model_dump(mode="python"))
    target = _item(
        envelope_value(
            key,
            sequence=3,
            event_type="retention_tombstone",
            normalized_fields=request.model_dump(mode="python"),
        )
    )
    transport = _RetentionTransport(
        tombstone_direct=canonical_json(target.model_dump(mode="python")),
    )
    delivery, store, verifier, _acknowledgements = _bound_delivery(
        tmp_path,
        transport,
    )
    staged_events: list[object] = []
    intervening = _item(
        envelope_value(
            key,
            sequence=2,
            normalized_fields={"kind": "malicious-live-stage"},
        )
    )

    async def mutate_then_raise(_canonical_body: bytes) -> bytes:
        staged_events.append(
            verifier.verify(
                intervening.envelope,
                sequence=intervening.sequence,
                event_id=intervening.event_id,
                content_sha256=intervening.content_sha256,
            )
        )
        raise DeliveryRetryableError("injected retryable result")

    monkeypatch.setattr(
        transport,
        "publish_retention_tombstone",
        mutate_then_raise,
    )

    with pytest.raises(DeliveryFatalError, match="changed live authority"):
        async with delivery._retention_preflight_scope(
            _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
        ) as lock_authority:
            await delivery._preflight_retention_tombstone(
                request,
                body,
                _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
                _lock_authority=lock_authority,
            )

    assert staged_events
    assert delivery._fatal is not None
    await delivery.close()
    store.close(flush=False)


@pytest.mark.asyncio
async def test_retention_preflight_fences_reacquired_delivery_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _tombstone()
    body = canonical_json(request.model_dump(mode="python"))
    transport = _RetentionTransport(tombstone_direct=b"unreachable")
    delivery, store, _verifier, _acknowledgements = _bound_delivery(
        tmp_path,
        transport,
    )

    async def reacquire_lock_then_raise(_canonical_body: bytes) -> bytes:
        delivery._lock.release()
        await delivery._lock.acquire()
        raise DeliveryRetryableError("injected retryable result")

    monkeypatch.setattr(
        transport,
        "publish_retention_tombstone",
        reacquire_lock_then_raise,
    )

    with pytest.raises(DeliveryFatalError, match="changed live authority"):
        async with delivery._retention_preflight_scope(
            _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
        ) as lock_authority:
            await delivery._preflight_retention_tombstone(
                request,
                body,
                _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
                _lock_authority=lock_authority,
            )

    assert delivery._fatal is not None
    await delivery.close()
    store.close(flush=False)


@pytest.mark.asyncio
async def test_retention_preflight_freezes_request_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = private_key(11)
    request = _tombstone()
    body = canonical_json(request.model_dump(mode="python"))
    changed_request = _tombstone(tombstone_id=OTHER_REQUEST_ID)
    changed_target = envelope_value(
        key,
        sequence=2,
        event_type="retention_tombstone",
        normalized_fields=changed_request.model_dump(mode="python"),
    )
    changed_direct = _item(changed_target)
    transport = _RetentionTransport(
        tombstone_direct=canonical_json(
            changed_direct.model_dump(mode="python")
        ),
        pages=[_page(changed_target)],
    )
    delivery, store, _verifier, _acknowledgements = _bound_delivery(
        tmp_path,
        transport,
    )
    publish = transport.publish_retention_tombstone

    async def mutate_request_during_post(canonical_body: bytes) -> bytes:
        object.__setattr__(
            request,
            "tombstone_id",
            OTHER_REQUEST_ID,
        )
        return await publish(canonical_body)

    monkeypatch.setattr(
        transport,
        "publish_retention_tombstone",
        mutate_request_during_post,
    )

    with pytest.raises(DeliveryFatalError):
        async with delivery._retention_preflight_scope(
            _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
        ) as lock_authority:
            await delivery._preflight_retention_tombstone(
                request,
                body,
                _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
                _lock_authority=lock_authority,
            )

    assert transport.posts == [("tombstone", body)]
    await delivery.close()
    store.close(flush=False)


@pytest.mark.asyncio
async def test_retention_preflight_rejects_mutated_request_before_post(
    tmp_path: Path,
) -> None:
    request = _tombstone()
    object.__setattr__(request, "tombstone_id", "not-a-uuid")
    body = canonical_json(request.model_dump(mode="python"))
    transport = _RetentionTransport(tombstone_direct=b"unreachable")
    delivery, store, _verifier, _acknowledgements = _bound_delivery(
        tmp_path,
        transport,
    )

    with pytest.raises(DeliveryFatalError, match="exact request"):
        async with delivery._retention_preflight_scope(
            _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
        ) as lock_authority:
            await delivery._preflight_retention_tombstone(
                request,
                body,
                _factory=service_module._RETENTION_PREFLIGHT_FACTORY,
                _lock_authority=lock_authority,
            )

    assert transport.posts == []
    await delivery.close()
    store.close(flush=False)
