from __future__ import annotations

import hashlib
import os
import pickle
import uuid
from dataclasses import dataclass
from pathlib import Path

import agmind_immune.evidence.segments as segments_module
import agmind_immune.ingest.service as service_module
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import EvidenceRepairAuthorizeV1, ObserverTrustRootV1
from agmind_immune.evidence.frames import decode_frames
from agmind_immune.evidence.manifest import (
    GENESIS_MANIFEST_SHA256,
    chain_head_for,
)
from agmind_immune.evidence.repair import (
    _FINAL_REPAIR_COMPLETION_FACTORY,
    AuthenticatedRepairCompletion,
    RepairEventIdentity,
    RepairStateV1,
    encode_repair_state,
)
from agmind_immune.evidence.segments import (
    AuthenticatedRepairAuthorization,
    EvidenceCorrupt,
    EvidenceStoreBusy,
    EvidenceStoreError,
    RepairPhysicalState,
    RepairStateConflict,
    SegmentStore,
    TailRepairPending,
    TailRepairSession,
    TornTailRepairRequired,
)
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    CoreEventV1,
    EnvelopeVerifier,
    PinnedObserverRoot,
    VerifierCommitError,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.phase5b_helpers import (
    BOOT_A,
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
)

ZERO_SHA256 = "0" * 64


def _identity() -> tuple[PinnedObserverRoot, AnchoredPublicKeyChain]:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key), strict=True)
    )
    return root, AnchoredPublicKeyChain.from_value(root, metadata_value(key))


def _torn_later_frame(
    path: Path,
) -> tuple[PinnedObserverRoot, AnchoredPublicKeyChain, Path, bytes, str]:
    root, chain = _identity()
    key = private_key(11)
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    AckJournal.create_new(store)
    first = decode_events_page(canonical_json(page_value(boot_boundary(key)))).events[0]
    coordinator.accept(first)
    store.flush_security_boundary()
    manifest_sha256 = store.manifests[-1].manifest_sha256
    second = decode_events_page(
        canonical_json(
            page_value(
                envelope_value(
                    key,
                    sequence=2,
                    boot_id=BOOT_A,
                    normalized_fields={"kind": "second"},
                )
            )
        )
    ).events[0]
    coordinator.accept(second)
    opened = store.active_path
    assert opened is not None
    verified_prefix = opened.read_bytes()
    store.close(flush=False)
    with opened.open("ab") as stream:
        stream.write(b"AG")
        stream.flush()
        os.fsync(stream.fileno())
    return root, chain, opened, verified_prefix, manifest_sha256


def _torn_first_frame(
    path: Path,
) -> tuple[PinnedObserverRoot, AnchoredPublicKeyChain, Path]:
    root, chain = _identity()
    pristine = SegmentStore(path)
    AcceptanceCoordinator.create_empty(EnvelopeVerifier(root, chain), pristine)
    AckJournal.create_new(pristine)
    pristine.close()
    date_path = path / "segments" / "2026-07-29"
    date_path.mkdir(mode=0o700)
    opened = date_path / ("00000000000000000001-11111111-1111-4111-8111-111111111111.open")
    opened.write_bytes(b"AG")
    opened.chmod(0o600)
    return root, chain, opened


@dataclass(frozen=True)
class _ProofTarget:
    sequence: int
    event_id: str
    content_sha256: str
    event_type: str = "evidence_repair_authorized"
    evidence_priority: str = "protected"
    key_epoch: int = 1
    key_id: str = "1" * 32
    is_retry: bool = False


@dataclass(frozen=True)
class _Proof:
    request: EvidenceRepairAuthorizeV1
    target: _ProofTarget
    base_generation: int


def _proof_for(session: TailRepairSession) -> _Proof:
    facts = session.repair_facts
    assert facts is not None
    request = EvidenceRepairAuthorizeV1(
        schema_version="agmind.evidence-repair-authorize.v1",
        repair_id=str(uuid.uuid4()),
        segment_id=facts.segment_id,
        verified_bytes=facts.verified_bytes,
        discarded_bytes=facts.discarded_bytes,
        discarded_sha256=facts.discarded_sha256,
        last_verified_frame_sha256=facts.last_verified_frame_sha256,
        current_chain_head_sha256=facts.current_chain_head_sha256,
        reason="torn_open_tail",
    )
    return _Proof(
        request=request,
        target=_ProofTarget(
            sequence=max(1, session.status().evidence_head + 1),
            event_id="evt_" + "a" * 64,
            content_sha256="b" * 64,
        ),
        base_generation=session.verifier_generation,
    )


def _authorization_item_and_proof(
    session: TailRepairSession,
) -> tuple[CoreEventV1, _Proof]:
    facts = session.repair_facts
    assert facts is not None
    request = EvidenceRepairAuthorizeV1(
        schema_version="agmind.evidence-repair-authorize.v1",
        repair_id=str(uuid.uuid4()),
        segment_id=facts.segment_id,
        verified_bytes=facts.verified_bytes,
        discarded_bytes=facts.discarded_bytes,
        discarded_sha256=facts.discarded_sha256,
        last_verified_frame_sha256=facts.last_verified_frame_sha256,
        current_chain_head_sha256=facts.current_chain_head_sha256,
        reason="torn_open_tail",
    )
    item = decode_events_page(
        canonical_json(
            page_value(
                envelope_value(
                    private_key(11),
                    sequence=session.status().evidence_head + 1,
                    boot_id=BOOT_A,
                    event_type="evidence_repair_authorized",
                    normalized_fields=request.model_dump(exclude_none=True),
                )
            )
        )
    ).events[0]
    envelope = item.envelope
    return item, _Proof(
        request=request,
        target=_ProofTarget(
            sequence=item.sequence,
            event_id=item.event_id,
            content_sha256=item.content_sha256,
            event_type="evidence_repair_authorized",
            evidence_priority="protected",
            key_epoch=int(envelope["key_epoch"]),
            key_id=str(envelope["key_id"]),
            is_retry=bool(envelope.get("is_retry", False)),
        ),
        base_generation=session.verifier_generation,
    )


def _completion_item(
    session: SegmentStore,
    proof: _Proof,
    authorization: CoreEventV1,
) -> CoreEventV1:
    facts = session.repair_facts
    assert facts is not None
    return decode_events_page(
        canonical_json(
            page_value(
                envelope_value(
                    private_key(11),
                    sequence=authorization.sequence + 1,
                    boot_id=BOOT_A,
                    event_type="evidence_repair_completed",
                    normalized_fields={
                        "schema_version": "agmind.evidence-repair-complete.v1",
                        "repair_id": proof.request.repair_id,
                        "authorization_event_id": authorization.event_id,
                        "authorization_content_sha256": authorization.content_sha256,
                        "segment_id": facts.segment_id,
                        "verified_bytes": facts.verified_bytes,
                        "post_repair_prefix_sha256": facts.post_repair_prefix_sha256,
                        "last_verified_frame_sha256": facts.last_verified_frame_sha256,
                        "current_chain_head_sha256": facts.current_chain_head_sha256,
                        "reason": "torn_open_tail_completed",
                    },
                )
            )
        )
    ).events[0]


def _accept_test_proof(
    monkeypatch: pytest.MonkeyPatch,
    proof: _Proof,
) -> None:
    def validate(
        self: EnvelopeVerifier,
        candidate: object,
    ) -> object:
        del self
        if candidate is not proof:
            raise TypeError("not the exact simulated authorization")
        return candidate

    monkeypatch.setattr(
        EnvelopeVerifier,
        "_validate_repair_authorization_proof",
        validate,
    )


def _state_bytes(
    session: SegmentStore,
    proof: _Proof,
    phase: str,
    *,
    completion: CoreEventV1 | None = None,
) -> bytes:
    facts = session.repair_facts
    assert facts is not None
    authorization = (
        None
        if phase == "detected"
        else RepairEventIdentity(
            sequence=proof.target.sequence,
            event_id=proof.target.event_id,
            content_sha256=proof.target.content_sha256,
        )
    )
    return encode_repair_state(
        RepairStateV1.model_validate(
            {
                "schema_version": "agmind.evidence-repair-state.v1",
                "phase": phase,
                "repair_id": proof.request.repair_id,
                "segment_id": facts.segment_id,
                "open_relative_path": facts.open_relative_path,
                "original_device": facts.original_device,
                "original_inode": facts.original_inode,
                "original_bytes": facts.original_bytes,
                "verified_bytes": facts.verified_bytes,
                "discarded_bytes": facts.discarded_bytes,
                "discarded_sha256": facts.discarded_sha256,
                "post_repair_prefix_sha256": facts.post_repair_prefix_sha256,
                "last_verified_frame_sha256": facts.last_verified_frame_sha256,
                "current_chain_head_sha256": facts.current_chain_head_sha256,
                "authorization": (None if authorization is None else authorization.model_dump()),
                "completion": (
                    None
                    if completion is None
                    else RepairEventIdentity(
                        sequence=completion.sequence,
                        event_id=completion.event_id,
                        content_sha256=completion.content_sha256,
                    ).model_dump()
                ),
            },
            strict=True,
        )
    )


def test_repair_open_is_same_lock_and_reports_exact_torn_facts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "evidence"
    root, chain, opened, prefix, manifest_sha256 = _torn_later_frame(path)
    original = opened.stat()
    before = opened.read_bytes()

    with pytest.raises(TornTailRepairRequired):
        SegmentStore(path)
    assert opened.read_bytes() == before

    session = SegmentStore.open_tail_repair(
        path,
        EnvelopeVerifier(root, chain),
    )
    try:
        assert type(session) is TailRepairSession
        with pytest.raises(EvidenceStoreBusy):
            SegmentStore(path)
        facts = session.repair_facts
        assert facts is not None
        frame = decode_frames(prefix, max_frame=128 * 1024).records[-1]
        assert facts.segment_id == opened.stem.split("-", 1)[1]
        assert facts.open_relative_path == opened.relative_to(path).as_posix()
        assert (facts.original_device, facts.original_inode) == (
            original.st_dev,
            original.st_ino,
        )
        assert (facts.original_bytes, facts.verified_bytes) == (
            len(before),
            len(prefix),
        )
        assert facts.discarded_bytes == 2
        assert facts.discarded_sha256 == hashlib.sha256(b"AG").hexdigest()
        assert facts.post_repair_prefix_sha256 == hashlib.sha256(prefix).hexdigest()
        assert facts.last_verified_frame_sha256 == frame.record_hash.hex()
        assert (
            facts.current_chain_head_sha256
            == hashlib.sha256(canonical_json(chain_head_for(session.manifests[-1]))).hexdigest()
        )
        assert facts.manifest_predecessor_sha256 == manifest_sha256
        assert session.classify_repair_physical(facts) is RepairPhysicalState.ORIGINAL_TORN
        assert session.status().repair_pending is True
        assert session.status().healthy is False
    finally:
        session.close(flush=False)


def test_repair_open_rejects_invalid_prefix_namespace(
    tmp_path: Path,
) -> None:
    wrong_path = tmp_path / "wrong-sequence"
    root, chain, opened, _, _ = _torn_later_frame(wrong_path)
    replacement = opened.with_name("00000000000000000003-" + opened.name.split("-", 1)[1])
    os.rename(opened, replacement)
    with pytest.raises(EvidenceCorrupt):
        SegmentStore.open_tail_repair(wrong_path, EnvelopeVerifier(root, chain))

    multiple_path = tmp_path / "multiple"
    root, chain, opened, _, _ = _torn_later_frame(multiple_path)
    duplicate = opened.with_name("00000000000000000003-" + opened.name.split("-", 1)[1])
    duplicate.write_bytes(opened.read_bytes())
    duplicate.chmod(0o600)
    with pytest.raises(EvidenceCorrupt, match="multiple active"):
        SegmentStore.open_tail_repair(multiple_path, EnvelopeVerifier(root, chain))


def test_repair_state_root_authority_is_bounded_exact_cas(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state"
    root, chain, _, _, _ = _torn_later_frame(path)
    session = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    detected = b'{"phase":"detected"}'
    authorized = b'{"phase":"authorized"}'
    try:
        assert session.read_repair_state_bytes() is None
        session.publish_initial_repair_state(detected)
        assert session.read_repair_state_bytes() == detected
        with pytest.raises(FileExistsError):
            session.publish_initial_repair_state(detected)
        with pytest.raises(RepairStateConflict):
            session.replace_repair_state(b"wrong", authorized)
        session.replace_repair_state(detected, authorized)
        assert session.read_repair_state_bytes() == authorized
        with pytest.raises(EvidenceStoreError):
            session.replace_repair_state(authorized, b"x" * 4097)
        with pytest.raises(EvidenceStoreError):
            session.remove_repair_state(authorized, object())
        assert session.read_repair_state_bytes() == authorized
    finally:
        session.close(flush=False)


def test_repair_state_temporary_is_classified_and_conditionally_removed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "temporary"
    root, chain, _, _, _ = _torn_later_frame(path)
    raw = b""
    temporary = path / f".repair-state.json.{uuid.uuid4()}.tmp"
    temporary.write_bytes(raw)
    temporary.chmod(0o600)

    session = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    try:
        assert session.read_repair_state_temporary_bytes() == raw
        with pytest.raises(RepairStateConflict):
            session.remove_repair_state_temporary(b"wrong")
        session.remove_repair_state_temporary(raw)
        assert not temporary.exists()
        assert session.read_repair_state_temporary_bytes() is None
    finally:
        session.close(flush=False)


def test_repair_state_temporary_unlink_detects_namespace_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "temporary-swap"
    root, chain, _, _, _ = _torn_later_frame(path)
    raw = b'{"phase":"detected"}'
    temporary = path / f".repair-state.json.{uuid.uuid4()}.tmp"
    temporary.write_bytes(raw)
    temporary.chmod(0o600)
    stolen_name = f".stolen-{uuid.uuid4()}"
    real_unlink = os.unlink

    def swap_then_unlink(
        name: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        assert dir_fd is not None
        if name == temporary.name:
            os.rename(
                name,
                stolen_name,
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
            replacement = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=dir_fd,
            )
            try:
                os.write(replacement, raw)
                os.fsync(replacement)
            finally:
                os.close(replacement)
        real_unlink(name, dir_fd=dir_fd)

    session = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    monkeypatch.setattr(segments_module.os, "unlink", swap_then_unlink)
    try:
        with pytest.raises(EvidenceCorrupt, match="unlink.*uncertain"):
            session.remove_repair_state_temporary(raw)
    finally:
        session.close(flush=False)


def test_registered_authorization_is_nonserializable_exactly_once_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "truncate"
    root, chain, opened, prefix, _ = _torn_later_frame(path)
    session = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    proof = _proof_for(session)
    _accept_test_proof(monkeypatch, proof)
    try:
        before = opened.read_bytes()
        with pytest.raises(EvidenceStoreError):
            session.register_authorization(proof)
        assert opened.read_bytes() == before
        detected = _state_bytes(session, proof, "detected")
        authorized = _state_bytes(session, proof, "authorized")
        session.publish_initial_repair_state(detected)
        session.replace_repair_state(detected, authorized)
        with pytest.raises(EvidenceStoreError, match="final completion"):
            session.remove_repair_state(authorized, object())
        capability = session.register_authorization(proof)
        assert type(capability) is AuthenticatedRepairAuthorization
        with pytest.raises(AttributeError):
            capability._factory_marker = object()
        with pytest.raises(TypeError):
            pickle.dumps(capability)
        lookalike = object.__new__(AuthenticatedRepairAuthorization)
        with pytest.raises(EvidenceStoreError):
            session.truncate(lookalike)

        def reject_stale(
            self: EnvelopeVerifier,
            candidate: object,
        ) -> object:
            del self, candidate
            raise VerifierCommitError("stale transient proof")

        monkeypatch.setattr(
            EnvelopeVerifier,
            "_validate_repair_authorization_proof",
            reject_stale,
        )
        with pytest.raises(EvidenceStoreError, match="stale"):
            session.truncate(capability)
        assert opened.read_bytes() == before
        _accept_test_proof(monkeypatch, proof)
        assert session.truncate(capability) is RepairPhysicalState.CLEAN_OPEN
        assert opened.read_bytes() == prefix
        with pytest.raises(EvidenceStoreError):
            session.truncate(capability)
    finally:
        session.close(flush=False)


def test_gate_clear_rejects_synthetic_exact_type_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "synthetic-completion"
    root, chain, _, _, _ = _torn_later_frame(path)
    verifier = EnvelopeVerifier(root, chain)
    session = SegmentStore.open_tail_repair(path, verifier)
    authorization, proof = _authorization_item_and_proof(session)
    _accept_test_proof(monkeypatch, proof)
    detected = _state_bytes(session, proof, "detected")
    authorized = _state_bytes(session, proof, "authorized")
    truncated = _state_bytes(session, proof, "truncated")
    session.publish_initial_repair_state(detected)
    session.replace_repair_state(detected, authorized)
    session.truncate(session.register_authorization(proof))
    session.replace_repair_state(authorized, truncated)
    resumed = session.resume_store()
    resumed.flush_security_boundary()
    acceptance = AcceptanceCoordinator._from_repair_resume(
        verifier,
        resumed,
        _factory=service_module._REPAIR_ACCEPTANCE_FACTORY,
    )
    acceptance._accept_for_repair(
        authorization,
        _factory=service_module._REPAIR_DELIVERY_FACTORY,
    )
    resumed.flush_security_boundary()
    completion = _completion_item(resumed, proof, authorization)
    appended = _state_bytes(resumed, proof, "authorization_appended")
    preflighted = _state_bytes(
        resumed,
        proof,
        "authorization_appended",
        completion=completion,
    )
    completed = _state_bytes(
        resumed,
        proof,
        "completion_appended",
        completion=completion,
    )
    resumed.replace_repair_state(truncated, appended)
    resumed.replace_repair_state(appended, preflighted)
    acceptance._accept_for_repair(
        completion,
        _factory=service_module._REPAIR_DELIVERY_FACTORY,
    )
    resumed.flush_security_boundary()
    resumed.replace_repair_state(preflighted, completed)
    acknowledgements = resumed.ack_journal
    forged = AuthenticatedRepairCompletion(
        journal=object(),  # type: ignore[arg-type]
        journal_identity=object(),
        expected_raw=completed,
        store=resumed,
        verifier=verifier,
        acknowledgements=acknowledgements,
        status=resumed.status(),
        ack_snapshot=acknowledgements.snapshot(),
        verifier_generation=verifier._authority.generation,
        transient_generation=verifier._repair_transient_generation,
        _factory=_FINAL_REPAIR_COMPLETION_FACTORY,
    )
    try:
        with pytest.raises(EvidenceStoreError, match="issued"):
            resumed.remove_repair_state(completed, forged)
        assert resumed.read_repair_state_bytes() == completed
        assert resumed.status().repair_pending is True
    finally:
        resumed.close(flush=False)


def test_zero_prefix_is_held_then_conditionally_retired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "zero"
    root, chain, opened = _torn_first_frame(path)
    session = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    proof = _proof_for(session)
    _accept_test_proof(monkeypatch, proof)
    try:
        facts = session.repair_facts
        assert facts is not None
        assert facts.verified_bytes == 0
        assert facts.post_repair_prefix_sha256 == hashlib.sha256(b"").hexdigest()
        assert facts.last_verified_frame_sha256 == ZERO_SHA256
        assert facts.current_chain_head_sha256 == ZERO_SHA256
        assert facts.manifest_predecessor_sha256 == GENESIS_MANIFEST_SHA256

        detected = _state_bytes(session, proof, "detected")
        authorized = _state_bytes(session, proof, "authorized")
        truncated_state = _state_bytes(session, proof, "truncated")
        session.publish_initial_repair_state(detected)
        session.replace_repair_state(detected, authorized)
        capability = session.register_authorization(proof)
        assert session.truncate(capability) is RepairPhysicalState.ZERO_HELD
        assert opened.exists() and opened.read_bytes() == b""
        session.replace_repair_state(authorized, truncated_state)
        with pytest.raises(RepairStateConflict):
            session.retire_zero_prefix(b"wrong")
        session.retire_zero_prefix(truncated_state)
        assert not opened.exists()
        assert session.classify_repair_physical(facts) is RepairPhysicalState.ZERO_RETIRED
    finally:
        session.close(flush=False)


def test_zero_prefix_retirement_detects_namespace_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "zero-swap"
    root, chain, opened = _torn_first_frame(path)
    session = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    proof = _proof_for(session)
    _accept_test_proof(monkeypatch, proof)
    detected = _state_bytes(session, proof, "detected")
    authorized = _state_bytes(session, proof, "authorized")
    truncated = _state_bytes(session, proof, "truncated")
    session.publish_initial_repair_state(detected)
    session.replace_repair_state(detected, authorized)
    session.truncate(session.register_authorization(proof))
    session.replace_repair_state(authorized, truncated)
    stolen_name = f".stolen-{uuid.uuid4()}"
    real_unlink = os.unlink

    def swap_then_unlink(
        name: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        assert dir_fd is not None
        if name == opened.name:
            os.rename(
                name,
                stolen_name,
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
            replacement = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=dir_fd,
            )
            os.close(replacement)
        real_unlink(name, dir_fd=dir_fd)

    monkeypatch.setattr(segments_module.os, "unlink", swap_then_unlink)
    try:
        with pytest.raises(EvidenceCorrupt, match="retirement.*uncertain"):
            session.retire_zero_prefix(truncated)
        facts = session.repair_facts
        assert facts is not None
        assert session.classify_repair_physical(facts) is RepairPhysicalState.INVALID
        with pytest.raises(EvidenceStoreError):
            session.resume_store()
    finally:
        session.close(flush=False)


def test_resume_is_same_object_and_pending_close_never_implicitly_settles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "resume"
    root, chain, opened, prefix, _ = _torn_later_frame(path)
    opened_journals: list[AckJournal] = []
    open_and_recover = AckJournal.open_and_recover.__func__

    def tracked_open(
        cls: type[AckJournal],
        store: SegmentStore,
        **kwargs: object,
    ) -> AckJournal:
        journal = open_and_recover(cls, store, **kwargs)
        opened_journals.append(journal)
        return journal

    monkeypatch.setattr(
        AckJournal,
        "open_and_recover",
        classmethod(tracked_open),
    )
    session = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    proof = _proof_for(session)
    _accept_test_proof(monkeypatch, proof)
    detected = _state_bytes(session, proof, "detected")
    authorized = _state_bytes(session, proof, "authorized")
    truncated = _state_bytes(session, proof, "truncated")
    session.publish_initial_repair_state(detected)
    session.replace_repair_state(detected, authorized)
    capability = session.register_authorization(proof)
    session.truncate(capability)
    session.replace_repair_state(authorized, truncated)

    identity = id(session)
    journal = session.ack_journal
    resumed = session.resume_store()
    assert id(resumed) == identity
    assert type(resumed) is SegmentStore
    assert resumed.ack_journal is journal
    assert opened_journals == [journal]
    assert resumed.status().healthy is True
    assert resumed.status().repair_pending is True
    assert resumed.active_path == opened
    resumed.close()

    assert opened.read_bytes() == prefix
    assert len(list((path / "manifests").glob("*.json"))) == 1


def test_resume_reclassifies_manifested_open_after_crash_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "manifest-open"
    root, chain, _, _, _ = _torn_later_frame(path)
    session = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    proof = _proof_for(session)
    _accept_test_proof(monkeypatch, proof)
    detected = _state_bytes(session, proof, "detected")
    authorized = _state_bytes(session, proof, "authorized")
    truncated = _state_bytes(session, proof, "truncated")
    session.publish_initial_repair_state(detected)
    session.replace_repair_state(detected, authorized)
    session.truncate(session.register_authorization(proof))
    session.replace_repair_state(authorized, truncated)
    facts = session.repair_facts
    assert facts is not None
    resumed = session.resume_store()

    original_promote = segments_module._promote_authenticated_source

    def crash_before_promotion(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("simulated crash before open promotion")

    monkeypatch.setattr(
        segments_module,
        "_promote_authenticated_source",
        crash_before_promotion,
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        resumed.flush_security_boundary()
    resumed.close(flush=False)
    monkeypatch.setattr(
        segments_module,
        "_promote_authenticated_source",
        original_promote,
    )

    restarted = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    recovered = restarted.resume_store()
    try:
        assert recovered is restarted
        assert recovered.active_path is None
        assert recovered.classify_repair_physical(facts) is RepairPhysicalState.SETTLED_PREFIX
    finally:
        recovered.close(flush=False)


@pytest.mark.parametrize("phase", ("truncated", "authorization_appended"))
def test_resume_retains_post_h0_active_until_explicit_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    path = tmp_path / phase
    root, chain, _, _, _ = _torn_later_frame(path)
    verifier = EnvelopeVerifier(root, chain)
    session = SegmentStore.open_tail_repair(path, verifier)
    authorization, proof = _authorization_item_and_proof(session)
    _accept_test_proof(monkeypatch, proof)
    detected = _state_bytes(session, proof, "detected")
    authorized = _state_bytes(session, proof, "authorized")
    truncated = _state_bytes(session, proof, "truncated")
    session.publish_initial_repair_state(detected)
    session.replace_repair_state(detected, authorized)
    session.truncate(session.register_authorization(proof))
    session.replace_repair_state(authorized, truncated)
    resumed = session.resume_store()
    resumed.flush_security_boundary()
    acceptance = AcceptanceCoordinator._from_repair_resume(
        verifier,
        resumed,
        _factory=service_module._REPAIR_ACCEPTANCE_FACTORY,
    )

    if phase == "truncated":
        candidate = authorization
    else:
        acceptance._accept_for_repair(
            authorization,
            _factory=service_module._REPAIR_DELIVERY_FACTORY,
        )
        resumed.flush_security_boundary()
        completion = _completion_item(resumed, proof, authorization)
        appended = _state_bytes(resumed, proof, "authorization_appended")
        preflighted = _state_bytes(
            resumed,
            proof,
            "authorization_appended",
            completion=completion,
        )
        resumed.replace_repair_state(truncated, appended)
        resumed.replace_repair_state(appended, preflighted)
        candidate = completion

    acceptance._accept_for_repair(
        candidate,
        _factory=service_module._REPAIR_DELIVERY_FACTORY,
    )
    candidate_open = resumed.active_path
    assert candidate_open is not None
    manifest_count = len(resumed.manifests)
    resumed.close(flush=False)
    assert candidate_open.exists()

    restarted = SegmentStore.open_tail_repair(
        path,
        EnvelopeVerifier(root, chain),
    )
    recovered = restarted.resume_store()
    try:
        assert recovered.active_path == candidate_open
        assert recovered.status().evidence_head == candidate.sequence
        assert len(recovered.manifests) == manifest_count
        recovered.flush_security_boundary()
        assert recovered.active_path is None
        assert len(recovered.manifests) == manifest_count + 1
        assert not candidate_open.exists()
        assert candidate_open.with_suffix(".agseg").exists()
    finally:
        recovered.close(flush=False)


@pytest.mark.parametrize(
    ("target_kind", "expected"),
    (
        ("clean_open", RepairPhysicalState.CLEAN_OPEN),
        ("settled_prefix", RepairPhysicalState.SETTLED_PREFIX),
        ("zero_held", RepairPhysicalState.ZERO_HELD),
        ("zero_retired", RepairPhysicalState.ZERO_RETIRED),
    ),
)
def test_repair_restart_rederives_post_truncate_physical_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_kind: str,
    expected: RepairPhysicalState,
) -> None:
    path = tmp_path / target_kind
    if target_kind in {"clean_open", "settled_prefix"}:
        root, chain, _, _, _ = _torn_later_frame(path)
    else:
        root, chain, _ = _torn_first_frame(path)
    session = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    proof = _proof_for(session)
    _accept_test_proof(monkeypatch, proof)
    detected = _state_bytes(session, proof, "detected")
    authorized = _state_bytes(session, proof, "authorized")
    session.publish_initial_repair_state(detected)
    session.replace_repair_state(detected, authorized)
    capability = session.register_authorization(proof)
    session.truncate(capability)
    durable = authorized
    if target_kind in {"settled_prefix", "zero_retired"}:
        truncated = _state_bytes(session, proof, "truncated")
        session.replace_repair_state(authorized, truncated)
        durable = truncated
        if target_kind == "settled_prefix":
            session.resume_store().flush_security_boundary()
        else:
            session.retire_zero_prefix(truncated)
    facts = session.repair_facts
    assert facts is not None
    session.close(flush=False)

    with pytest.raises(TailRepairPending):
        SegmentStore(path)
    assert not (path / "health.json").exists()
    assert (path / "repair-state.json").read_bytes() == durable

    restarted = SegmentStore.open_tail_repair(
        path,
        EnvelopeVerifier(root, chain),
    )
    try:
        assert restarted.read_repair_state_bytes() == durable
        assert restarted.repair_facts == facts
        assert restarted.classify_repair_physical(facts) is expected
        assert restarted.status().repair_pending is True
    finally:
        restarted.close(flush=False)


@pytest.mark.parametrize("contradiction", ("detected_clean", "authorized_retired"))
def test_repair_restart_rejects_phase_physical_contradictions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contradiction: str,
) -> None:
    path = tmp_path / contradiction
    if contradiction == "detected_clean":
        root, chain, _, _, _ = _torn_later_frame(path)
    else:
        root, chain, _ = _torn_first_frame(path)
    session = SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
    proof = _proof_for(session)
    _accept_test_proof(monkeypatch, proof)
    detected = _state_bytes(session, proof, "detected")
    authorized = _state_bytes(session, proof, "authorized")
    truncated = _state_bytes(session, proof, "truncated")
    session.publish_initial_repair_state(detected)
    session.replace_repair_state(detected, authorized)
    session.truncate(session.register_authorization(proof))
    if contradiction == "detected_clean":
        session.replace_repair_state(authorized, detected)
    else:
        session.replace_repair_state(authorized, truncated)
        session.retire_zero_prefix(truncated)
        session.replace_repair_state(truncated, authorized)
    session.close(flush=False)

    with pytest.raises(EvidenceCorrupt, match="phase"):
        SegmentStore.open_tail_repair(path, EnvelopeVerifier(root, chain))
