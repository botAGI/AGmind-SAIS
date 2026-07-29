from __future__ import annotations

import copy
import gc
import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.evidence import repair as repair_module
from agmind_immune.evidence.repair import (
    AuthenticatedRepairCompletion,
    RepairEventIdentity,
    RepairPreflightError,
    RepairProtocolError,
    RepairStateConflict,
    RepairStateCorrupt,
    RepairStateJournal,
    RepairStateV1,
    advance_authorization_appended,
    advance_authorized,
    advance_completion_appended,
    advance_truncated,
    authorization_request,
    complete_tail_repair,
    completion_request,
    decode_repair_state,
    detected_state,
    encode_repair_state,
    preflight_authorization,
    record_completion_target,
    repair_event_identity,
)
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    CoreEventV1,
    EnvelopeVerifier,
    PinnedObserverRoot,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.phase5b_helpers import (
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
)

REPAIR_ID = "11111111-1111-4111-8111-111111111111"
SEGMENT_ID = "22222222-2222-4222-8222-222222222222"
OPEN_PATH = (
    "segments/2026-07-29/00000000000000000042-"
    f"{SEGMENT_ID}.open"
)
AUTHORIZATION = RepairEventIdentity(
    sequence=81,
    event_id="evt_" + "a" * 64,
    content_sha256="b" * 64,
)
COMPLETION = RepairEventIdentity(
    sequence=82,
    event_id="evt_" + "c" * 64,
    content_sha256="d" * 64,
)


def _state(
    phase: str = "detected",
    *,
    authorization: RepairEventIdentity | None = None,
    completion: RepairEventIdentity | None = None,
) -> RepairStateV1:
    return RepairStateV1.model_validate(
        {
            "schema_version": "agmind.evidence-repair-state.v1",
            "phase": phase,
            "repair_id": REPAIR_ID,
            "segment_id": SEGMENT_ID,
            "open_relative_path": OPEN_PATH,
            "original_device": 7,
            "original_inode": 19,
            "original_bytes": 120,
            "verified_bytes": 100,
            "discarded_bytes": 20,
            "discarded_sha256": "1" * 64,
            "post_repair_prefix_sha256": "2" * 64,
            "last_verified_frame_sha256": "3" * 64,
            "current_chain_head_sha256": "4" * 64,
            "authorization": authorization,
            "completion": completion,
        },
        strict=True,
    )


@dataclass
class _MemoryRepairAuthority:
    raw: bytes | None = None

    def read_repair_state_bytes(self) -> bytes | None:
        return self.raw

    def publish_initial_repair_state(self, raw: bytes) -> None:
        if self.raw is not None:
            raise RepairStateConflict("state already exists")
        self.raw = raw

    def replace_repair_state(self, expected: bytes, raw: bytes) -> None:
        if self.raw != expected:
            raise RepairStateConflict("state CAS mismatch")
        self.raw = raw

    def remove_repair_state(
        self,
        expected: bytes,
        proof: AuthenticatedRepairCompletion,
    ) -> None:
        assert type(proof) is AuthenticatedRepairCompletion
        if self.raw != expected:
            raise RepairStateConflict("state CAS mismatch")
        self.raw = None


@dataclass
class _PreflightTransport:
    direct: bytes
    pages: list[bytes]
    expected_body: bytes
    during_publish: Callable[[], None] | None = None

    async def publish_repair_authorization(self, canonical_body: bytes) -> bytes:
        assert canonical_body == self.expected_body
        if self.during_publish is not None:
            self.during_publish()
        return self.direct

    async def publish_repair_completion(self, canonical_body: bytes) -> bytes:
        raise AssertionError(f"unexpected completion body: {canonical_body!r}")

    async def fetch_events(self, *, after: int, limit: int) -> bytes:
        assert after >= 1
        assert 1 <= limit <= 100
        if not self.pages:
            raise AssertionError("unexpected extra repair preflight page")
        return self.pages.pop(0)


class _RepairClock:
    def live_receipt_monotonic(self) -> None:
        return None

    def decision_sample(self) -> object:
        raise AssertionError("repair delivery must not sample the decision clock")


class _RepairLifecycleTransport:
    def __init__(self) -> None:
        self._key = private_key(11)
        self._authorization: CoreEventV1 | None = None
        self._completion: CoreEventV1 | None = None
        self.acked_through = 1
        self.closed = False

    @staticmethod
    def _item(envelope: dict[str, object]) -> CoreEventV1:
        return decode_events_page(
            canonical_json(page_value(envelope))
        ).events[0]

    async def publish_repair_authorization(self, canonical_body: bytes) -> bytes:
        fields = json.loads(canonical_body)
        if self._authorization is None:
            self._authorization = self._item(
                envelope_value(
                    self._key,
                    sequence=3,
                    event_type="evidence_repair_authorized",
                    normalized_fields=fields,
                )
            )
        assert canonical_json(self._authorization.envelope["normalized_fields"]) == (
            canonical_body
        )
        return canonical_json(self._authorization.model_dump(mode="python"))

    async def publish_repair_completion(self, canonical_body: bytes) -> bytes:
        fields = json.loads(canonical_body)
        if self._completion is None:
            self._completion = self._item(
                envelope_value(
                    self._key,
                    sequence=4,
                    event_type="evidence_repair_completed",
                    normalized_fields=fields,
                )
            )
        assert canonical_json(self._completion.envelope["normalized_fields"]) == (
            canonical_body
        )
        return canonical_json(self._completion.model_dump(mode="python"))

    async def fetch_events(self, *, after: int, limit: int) -> bytes:
        assert 1 <= limit <= 100
        items = [
            item
            for item in (self._authorization, self._completion)
            if item is not None and item.sequence > after
        ][:limit]
        assert items
        page = page_value(*(item.envelope for item in items))
        page["acked_through"] = self.acked_through
        page["reserved_through"] = max(item.sequence for item in items)
        return canonical_json(page)

    async def ack_event(self, body: bytes) -> None:
        value = json.loads(body)
        sequence = value["sequence"]
        assert sequence == self.acked_through + 1
        self.acked_through = sequence

    async def close(self) -> None:
        self.closed = True


def test_repair_state_is_exact_canonical_bounded_and_phase_coherent() -> None:
    detected = _state()
    raw = encode_repair_state(detected)
    assert len(raw) <= 4096
    assert b'"authorization":null' in raw
    assert b'"completion":null' in raw
    assert decode_repair_state(raw) == detected

    with pytest.raises(RepairStateCorrupt, match="canonical"):
        decode_repair_state(raw + b"\n")

    duplicate = raw[:-1] + b',"phase":"detected"}'
    with pytest.raises(RepairStateCorrupt, match="canonical"):
        decode_repair_state(duplicate)

    invalid = detected.model_dump(exclude_none=False)
    invalid["verified_bytes"] = True
    with pytest.raises(ValueError):
        RepairStateV1.model_validate(invalid, strict=True)

    forged_copy = detected.model_copy(update={"phase": "completion_appended"})
    with pytest.raises(RepairStateCorrupt, match="coherent"):
        encode_repair_state(forged_copy)

    with pytest.raises(ValueError, match="authorization"):
        _state("authorized")
    with pytest.raises(ValueError, match="completion"):
        _state("completion_appended", authorization=AUTHORIZATION)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    (
        ("open_relative_path", "../repair.open", "path"),
        (
            "open_relative_path",
            OPEN_PATH.replace(SEGMENT_ID, REPAIR_ID),
            "segment",
        ),
        ("discarded_bytes", 19, "byte"),
        ("original_bytes", 100, "byte"),
        ("last_verified_frame_sha256", "0" * 64, "frame"),
        ("original_inode", 0, "greater than"),
        ("original_device", -1, "greater than"),
    ),
)
def test_repair_state_rejects_derived_fact_mismatches(
    field: str,
    value: object,
    match: str,
) -> None:
    document = _state().model_dump(exclude_none=False)
    document[field] = value
    with pytest.raises(ValueError, match=match):
        RepairStateV1.model_validate(document, strict=True)


def test_repair_state_journal_enforces_exact_transition_graph_and_cas() -> None:
    authority = _MemoryRepairAuthority()
    journal = RepairStateJournal.open(authority)
    detected = _state()
    journal.publish_detected(detected)
    assert authority.raw == encode_repair_state(detected)

    authorized = _state("authorized", authorization=AUTHORIZATION)
    journal.transition(authorized)
    assert journal.state == authorized

    with pytest.raises(RepairProtocolError, match="transition"):
        journal.transition(
            _state(
                "completion_appended",
                authorization=AUTHORIZATION,
                completion=COMPLETION,
            )
        )

    truncated = _state("truncated", authorization=AUTHORIZATION)
    stale = copy.copy(journal)
    journal.transition(truncated)
    with pytest.raises(RepairStateConflict):
        stale.transition(truncated)

    with pytest.raises(RepairProtocolError, match="transition"):
        journal.transition(
            _state(
                "authorization_appended",
                authorization=AUTHORIZATION,
                completion=COMPLETION,
            )
        )
    appended = _state("authorization_appended", authorization=AUTHORIZATION)
    journal.transition(appended)
    with pytest.raises(RepairProtocolError, match="transition"):
        journal.transition(
            _state(
                "completion_appended",
                authorization=AUTHORIZATION,
                completion=COMPLETION,
            )
        )
    preflighted = _state(
        "authorization_appended",
        authorization=AUTHORIZATION,
        completion=COMPLETION,
    )
    journal.transition(preflighted)
    completed = _state(
        "completion_appended",
        authorization=AUTHORIZATION,
        completion=COMPLETION,
    )
    journal.transition(completed)
    with pytest.raises(RepairProtocolError, match="historical replay"):
        journal.clear_completed(object())  # type: ignore[arg-type]
    assert authority.raw == encode_repair_state(completed)
    assert journal.state == completed

    compromised = RepairStateJournal.open(
        _MemoryRepairAuthority(encode_repair_state(detected))
    )
    compromised._state = completed
    with pytest.raises(RepairStateCorrupt, match="durable bytes"):
        compromised.clear_completed(object())  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="opened from authority"):
        RepairStateJournal(
            authority,
            completed,
            encode_repair_state(detected),
            _factory=object(),
        )


def test_repair_requests_are_exact_derivations_of_durable_state() -> None:
    detected = _state()
    authorize = authorization_request(detected)
    assert authorize.repair_id == detected.repair_id
    assert authorize.segment_id == detected.segment_id
    assert authorize.verified_bytes == detected.verified_bytes
    assert authorize.discarded_bytes == detected.discarded_bytes
    assert authorize.discarded_sha256 == detected.discarded_sha256
    assert authorize.last_verified_frame_sha256 == detected.last_verified_frame_sha256
    assert (
        authorize.current_chain_head_sha256
        == detected.current_chain_head_sha256
    )

    with pytest.raises(RepairProtocolError, match="authorization"):
        completion_request(detected)

    appended = _state("authorization_appended", authorization=AUTHORIZATION)
    complete = completion_request(appended)
    assert complete.authorization_event_id == AUTHORIZATION.event_id
    assert complete.authorization_content_sha256 == AUTHORIZATION.content_sha256
    assert complete.post_repair_prefix_sha256 == appended.post_repair_prefix_sha256


def test_repair_transition_builders_never_bypass_state_validation() -> None:
    detected = _state()
    authorized = advance_authorized(detected, AUTHORIZATION)
    truncated = advance_truncated(authorized)
    appended = advance_authorization_appended(truncated)
    preflighted = record_completion_target(appended, COMPLETION)
    completed = advance_completion_appended(preflighted)

    assert (
        authorized.phase,
        truncated.phase,
        appended.phase,
        preflighted.phase,
        completed.phase,
    ) == (
        "authorized",
        "truncated",
        "authorization_appended",
        "authorization_appended",
        "completion_appended",
    )
    assert completed.authorization == AUTHORIZATION
    assert completed.completion == COMPLETION
    with pytest.raises(RepairProtocolError, match="transition"):
        advance_truncated(detected)


def test_detected_state_and_event_identity_bind_exact_external_facts() -> None:
    expected = _state()
    facts = SimpleNamespace(
        **{
            field: getattr(expected, field)
            for field in (
                "segment_id",
                "open_relative_path",
                "original_device",
                "original_inode",
                "original_bytes",
                "verified_bytes",
                "discarded_bytes",
                "discarded_sha256",
                "post_repair_prefix_sha256",
                "last_verified_frame_sha256",
                "current_chain_head_sha256",
            )
        }
    )
    assert detected_state(facts, REPAIR_ID) == expected

    envelope = {
        "source_sequence": AUTHORIZATION.sequence,
        "event_id": AUTHORIZATION.event_id,
    }
    content_sha256 = hashlib.sha256(canonical_json(envelope)).hexdigest()
    item = CoreEventV1(
        sequence=AUTHORIZATION.sequence,
        event_id=AUTHORIZATION.event_id,
        content_sha256=content_sha256,
        envelope=envelope,
    )
    assert repair_event_identity(item) == RepairEventIdentity(
        sequence=AUTHORIZATION.sequence,
        event_id=AUTHORIZATION.event_id,
        content_sha256=content_sha256,
    )
    with pytest.raises(TypeError, match="event"):
        repair_event_identity(SimpleNamespace(**AUTHORIZATION.model_dump()))


def _authorization_preflight_context(
    tmp_path: Path,
) -> tuple[
    EnvelopeVerifier,
    SegmentStore,
    AckJournal,
    object,
    dict[str, object],
    CoreEventV1,
]:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key), strict=True)
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(tmp_path)
    acceptance = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    boot = decode_events_page(
        canonical_json(page_value(boot_boundary(key)))
    ).events[0]
    boot_ref = acceptance.accept(boot)
    journal = AckJournal.create_new(store)
    journal.record_pending(boot_ref)
    journal.record_confirmed(boot_ref)
    opened = store.active_path
    assert opened is not None
    store.close(flush=False)
    with opened.open("ab") as stream:
        stream.write(b"AG")
        stream.flush()
        os.fsync(stream.fileno())

    verifier = EnvelopeVerifier(root, chain)
    store = SegmentStore.open_tail_repair(tmp_path, verifier)
    journal = store.ack_journal
    facts = store.repair_facts
    assert facts is not None
    request = authorization_request(detected_state(facts, REPAIR_ID))
    authorization = envelope_value(
        key,
        sequence=2,
        event_type="evidence_repair_authorized",
        normalized_fields=request.model_dump(),
    )
    direct = decode_events_page(
        canonical_json(page_value(authorization))
    ).events[0]
    return verifier, store, journal, request, authorization, direct


@pytest.mark.asyncio
async def test_authorization_preflight_binds_direct_page_ack_and_live_authority(
    tmp_path: Path,
) -> None:
    verifier, store, journal, request, authorization, direct = (
        _authorization_preflight_context(tmp_path)
    )
    page = page_value(
        authorization,
        envelope_value(private_key(11), sequence=3),
    )
    page["acked_through"] = 1
    page["reserved_through"] = 3
    transport = _PreflightTransport(
        direct=canonical_json(direct.model_dump(mode="python")),
        pages=[canonical_json(page)],
        expected_body=canonical_json(request),
    )

    proof = await preflight_authorization(
        verifier=verifier,
        store=store,
        acknowledgements=journal,
        transport=transport,
        request=request,
    )

    assert proof.target.sequence == 2
    assert proof.request == request
    assert journal.snapshot().confirmed_through == 1
    assert store.status().evidence_head == 1
    store.close(flush=False)


@pytest.mark.asyncio
async def test_authorization_preflight_rejects_page_over_requested_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier, store, journal, request, authorization, direct = (
        _authorization_preflight_context(tmp_path)
    )
    later = envelope_value(private_key(11), sequence=3)
    page = page_value(authorization, later)
    page["acked_through"] = 1
    monkeypatch.setattr(repair_module, "MAX_REPAIR_PREFLIGHT_EVENTS", 1)
    transport = _PreflightTransport(
        direct=canonical_json(direct.model_dump(mode="python")),
        pages=[canonical_json(page)],
        expected_body=canonical_json(request),
    )

    with pytest.raises(RepairPreflightError, match="event bound"):
        await preflight_authorization(
            verifier=verifier,
            store=store,
            acknowledgements=journal,
            transport=transport,
            request=request,
        )

    assert store.status().evidence_head == 1
    store.close(flush=False)


@pytest.mark.asyncio
async def test_authorization_preflight_rejects_transient_verifier_race(
    tmp_path: Path,
) -> None:
    verifier, store, journal, request, authorization, direct = (
        _authorization_preflight_context(tmp_path)
    )
    page = page_value(authorization)
    page["acked_through"] = 1

    def create_and_release_stage() -> None:
        staged = verifier.verify(
            direct.envelope,
            sequence=direct.sequence,
            event_id=direct.event_id,
            content_sha256=direct.content_sha256,
        )
        del staged
        gc.collect()
        verifier._prune_staged()

    transport = _PreflightTransport(
        direct=canonical_json(direct.model_dump(mode="python")),
        pages=[canonical_json(page)],
        expected_body=canonical_json(request),
        during_publish=create_and_release_stage,
    )

    with pytest.raises(RepairPreflightError, match="verifier changed"):
        await preflight_authorization(
            verifier=verifier,
            store=store,
            acknowledgements=journal,
            transport=transport,
            request=request,
        )

    assert store.status().evidence_head == 1
    store.close(flush=False)


@pytest.mark.asyncio
async def test_complete_tail_repair_runs_signed_two_phase_protocol_same_lock(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key), strict=True)
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(tmp_path)
    acceptance = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    journal = AckJournal.create_new(store)
    boot = decode_events_page(
        canonical_json(page_value(boot_boundary(key)))
    ).events[0]
    boot_ref = acceptance.accept(boot)
    store.flush_security_boundary()
    journal.record_pending(boot_ref)
    journal.record_confirmed(boot_ref)
    second = decode_events_page(
        canonical_json(
            page_value(
                envelope_value(
                    key,
                    sequence=2,
                    normalized_fields={"kind": "repair-prefix"},
                )
            )
        )
    ).events[0]
    acceptance.accept(second)
    opened = store.active_path
    assert opened is not None
    prefix = opened.read_bytes()
    store.close(flush=False)
    with opened.open("ab") as stream:
        stream.write(b"AG")
        stream.flush()
        os.fsync(stream.fileno())

    verifier = EnvelopeVerifier(root, chain)
    session = SegmentStore.open_tail_repair(tmp_path, verifier)
    transport = _RepairLifecycleTransport()
    identity = id(session)

    runtime = await complete_tail_repair(
        session=session,
        verifier=verifier,
        transport=transport,
        clock=_RepairClock(),
    )

    assert id(runtime.store) == identity
    assert runtime.store.status().healthy is True
    assert runtime.store.status().repair_pending is False
    assert runtime.acknowledgements is session.ack_journal
    assert runtime.acknowledgements.snapshot().confirmed_through == 4
    assert runtime.store.status().evidence_head == 4
    assert opened.with_suffix(".agseg").read_bytes() == prefix
    assert not (tmp_path / "repair-state.json").exists()
    assert transport.closed is True
    runtime.coverage.close()
    runtime.store.close(flush=False)


@pytest.mark.asyncio
async def test_complete_tail_repair_closes_transport_before_authority_exists() -> None:
    transport = _RepairLifecycleTransport()

    with pytest.raises(RepairProtocolError, match="same-lock"):
        await complete_tail_repair(
            session=object(),  # type: ignore[arg-type]
            verifier=object(),  # type: ignore[arg-type]
            transport=transport,
            clock=_RepairClock(),
        )

    assert transport.closed is True
