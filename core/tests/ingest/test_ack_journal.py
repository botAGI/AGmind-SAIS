from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import agmind_immune.evidence.segments as segments_module
import agmind_immune.ingest.ack_journal as ack_journal_module
import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import MAX_UINT64, ObserverTrustRootV1
from agmind_immune.evidence.frames import encode_frame
from agmind_immune.evidence.segments import (
    EvidenceCorrupt,
    EvidenceReadOnly,
    EvidenceRef,
    EvidenceSealError,
    EvidenceStoreBusy,
    EvidenceStoreError,
    SegmentStore,
)
from agmind_immune.ingest.ack_journal import (
    AckJournal,
    AckJournalAuthorityError,
    AckJournalCorrupt,
    AckJournalStateError,
    AckJournalUnhealthy,
)
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeVerifier,
    PinnedObserverRoot,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
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

_ACK_SCHEMA = "agmind.core-ack-journal-record.v1"
_ACK_COMMITMENT_SCHEMA = "agmind.core-ack-commitment.v1"
_MAX_ACK_RECORD_BYTES = 1024
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _identity() -> tuple[PinnedObserverRoot, AnchoredPublicKeyChain]:
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    return root, AnchoredPublicKeyChain.from_value(root, metadata_value(key))


def _new_system(
    path: Path,
) -> tuple[AcceptanceCoordinator, SegmentStore]:
    root, chain = _identity()
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    return coordinator, store


def _reopen_system(
    path: Path,
) -> tuple[AcceptanceCoordinator, SegmentStore]:
    root, chain = _identity()
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.open_and_recover(
        EnvelopeVerifier(root, chain),
        store,
    )
    return coordinator, store


def _accept(
    coordinator: AcceptanceCoordinator,
    envelope: dict[str, object],
) -> EvidenceRef:
    item = decode_events_page(canonical_json(page_value(envelope))).events[0]
    return coordinator.accept(item)


def _two_refs(
    path: Path,
) -> tuple[AcceptanceCoordinator, SegmentStore, EvidenceRef, EvidenceRef]:
    coordinator, store = _new_system(path)
    key = private_key(11)
    first = _accept(coordinator, boot_boundary(key))
    second = _accept(
        coordinator,
        envelope_value(
            key,
            sequence=2,
            boot_id=BOOT_A,
            normalized_fields={"kind": "second"},
        ),
    )
    return coordinator, store, first, second


def _record_value(
    ref: EvidenceRef,
    kind: str,
) -> dict[str, object]:
    return {
        "schema_version": _ACK_SCHEMA,
        "kind": kind,
        "sequence": ref.source_sequence,
        "event_id": ref.event_id,
        "content_sha256": ref.content_sha256,
    }


def _frame_stream(*payloads: bytes) -> bytes:
    previous = bytes(32)
    frames: list[bytes] = []
    for payload in payloads:
        frame = encode_frame(
            payload,
            previous_hash=previous,
            max_frame=_MAX_ACK_RECORD_BYTES,
        )
        frames.append(frame)
        previous = frame[-32:]
    return b"".join(frames)


def _substitute_ack_journal(path: Path) -> None:
    replacement = path / "ack-journal.replacement"
    replacement.write_bytes(b"")
    replacement.chmod(0o600)
    os.replace(replacement, path / "ack-journal.agf")


def _genesis_commitment(phase: str) -> bytes:
    return canonical_json(
        {
            "schema_version": _ACK_COMMITMENT_SCHEMA,
            "phase": phase,
            "generation": 0,
            "confirmed": None,
            "journal_prefix_size": 0,
            "journal_prefix_sha256": _EMPTY_SHA256,
        }
    )


def test_ack_journal_recovers_exact_idempotent_pending_and_confirmed_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "evidence"
    _coordinator, store, first, second = _two_refs(path)
    journal = AckJournal.create_new(store)
    assert stat.S_IMODE((path / "ack-journal.agf").stat().st_mode) == 0o600
    assert journal.snapshot().confirmed_through == 0

    journal.record_pending(first)
    pending_size = (path / "ack-journal.agf").stat().st_size
    first_body = journal.pending_request_body()
    journal.record_pending(first)
    assert (path / "ack-journal.agf").stat().st_size == pending_size
    assert first_body == canonical_json(
        {
            "schema_version": "agmind.observer-ack.v1",
            "sequence": first.source_sequence,
            "event_id": first.event_id,
            "content_sha256": first.content_sha256,
        }
    )

    journal.record_confirmed(first)
    confirmed_size = (path / "ack-journal.agf").stat().st_size
    journal.record_confirmed(first)
    assert (path / "ack-journal.agf").stat().st_size == confirmed_size
    journal.record_pending(second)
    second_body = journal.pending_request_body()
    journal.close()
    store.close()

    _recovered_coordinator, recovered_store = _reopen_system(path)
    recovered = AckJournal.open_and_recover(recovered_store)
    snapshot = recovered.snapshot()
    assert snapshot.healthy is True
    assert snapshot.confirmed is not None
    assert snapshot.confirmed.sequence == 1
    assert snapshot.pending is not None
    assert snapshot.pending.sequence == 2
    assert snapshot.confirmed_through == 1
    assert recovered.pending_request_body() == second_body
    recovered.record_confirmed(second)
    assert recovered.snapshot().confirmed_through == 2
    assert recovered.snapshot().pending is None
    recovered_store.close()


@pytest.mark.parametrize("failure_point", ["recovery", "close"])
def test_ack_journal_wrapped_commitment_io_remains_restart_only(
    tmp_path: Path,
    failure_point: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / failure_point
    _coordinator, store, first, second = _two_refs(path)
    journal = AckJournal.create_new(store)
    journal.record_pending(first)
    journal.record_confirmed(first)
    journal.record_pending(second)

    if failure_point == "recovery":
        journal.close()
        store.close()
        _recovered_coordinator, uncertain_store = _reopen_system(path)
    else:
        uncertain_store = store

    read_regular = segments_module._read_regular_at

    def fail_commitment_read(
        parent_descriptor: int,
        name: str,
        display_path: Path,
        maximum: int,
    ) -> bytes:
        if name == "ack-commitment.json":
            raise OSError(f"injected wrapped commitment {failure_point} I/O")
        return read_regular(parent_descriptor, name, display_path, maximum)

    monkeypatch.setattr(
        segments_module,
        "_read_regular_at",
        fail_commitment_read,
    )
    with pytest.raises(Exception) as raised:
        if failure_point == "recovery":
            AckJournal.open_and_recover(uncertain_store)
        else:
            journal.close()
    uncertain_store.close(flush=False)

    assert isinstance(raised.value, OSError)
    assert f"wrapped commitment {failure_point}" in str(raised.value)
    assert not (path / "health.json").exists()

    monkeypatch.setattr(segments_module, "_read_regular_at", read_regular)
    _clean_coordinator, clean_store = _reopen_system(path)
    recovered = AckJournal.open_and_recover(clean_store)
    snapshot = recovered.snapshot()
    assert snapshot.healthy is True
    assert snapshot.confirmed == ack_journal_module.AckIdentity.from_ref(first)
    assert snapshot.pending == ack_journal_module.AckIdentity.from_ref(second)
    assert not (path / "health.json").exists()
    clean_store.close()


@pytest.mark.parametrize(
    "case",
    [
        "confirm_without_pending",
        "second_pending",
        "mismatched_confirm",
        "forged_complete_ref",
        "forged_pending_retry",
        "forged_confirmed_retry",
        "out_of_order",
        "signed_hole",
        "pending_verifier_commit",
        "bounded_authenticated_refs",
    ],
)
def test_ack_journal_enforces_authenticated_next_contiguous_ref(
    tmp_path: Path,
    case: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / case
    if case == "pending_verifier_commit":
        coordinator, store = _new_system(path)
        key = private_key(11)
        envelope = boot_boundary(key)
        commit_durable = coordinator.verifier._commit_durable
        failed = False

        def fail_once(
            authorization: Any,
            lifecycle: object,
            ref: object,
        ) -> None:
            nonlocal failed
            if not failed:
                failed = True
                raise RuntimeError("injected verifier commit failure")
            commit_durable(authorization, lifecycle, ref)

        monkeypatch.setattr(
            coordinator.verifier,
            "_commit_durable",
            fail_once,
        )
        with pytest.raises(RuntimeError, match="verifier commit"):
            _accept(coordinator, envelope)
        durable_ref = next(store.iter_records()).ref
        with pytest.raises(EvidenceStoreError):
            store.resolve_authenticated_ref(durable_ref)
        with pytest.raises(EvidenceStoreError):
            tuple(store.iter_authenticated_records())
        with pytest.raises(EvidenceReadOnly):
            store.authenticated_refs(
                after_sequence=0,
                through_sequence=1,
                limit=1,
            )

        assert _accept(coordinator, envelope) == durable_ref
        assert store.resolve_authenticated_ref(durable_ref).ref == durable_ref
        assert [record.ref for record in store.iter_authenticated_records()] == [
            durable_ref
        ]
        store.close()
        return

    if case == "bounded_authenticated_refs":
        coordinator, store, first, second = _two_refs(path)
        assert store.authenticated_refs(
            after_sequence=0,
            through_sequence=2,
            limit=1,
        ) == (first,)
        assert store.authenticated_refs(
            after_sequence=1,
            through_sequence=2,
            limit=100,
        ) == (second,)
        assert store.authenticated_refs(
            after_sequence=2,
            through_sequence=2,
            limit=1,
        ) == ()
        invalid = (
            (-1, 2, 1),
            (0, MAX_UINT64 + 1, 1),
            (2, 1, 1),
            (0, 2, 0),
            (0, 2, 101),
            (False, 2, 1),
            (0, 2, True),
        )
        for after_sequence, through_sequence, limit in invalid:
            with pytest.raises(ValueError):
                store.authenticated_refs(
                    after_sequence=after_sequence,
                    through_sequence=through_sequence,
                    limit=limit,
                )

        real_fsync = segments_module.os.fsync
        failed = False

        def fail_next_fsync(descriptor: int) -> None:
            nonlocal failed
            if not failed:
                failed = True
                raise OSError("injected evidence append uncertainty")
            real_fsync(descriptor)

        monkeypatch.setattr(segments_module.os, "fsync", fail_next_fsync)
        key = private_key(11)
        with pytest.raises(OSError, match="append uncertainty"):
            _accept(
                coordinator,
                envelope_value(
                    key,
                    sequence=3,
                    boot_id=BOOT_A,
                    normalized_fields={"kind": "uncertain"},
                ),
            )
        with pytest.raises(EvidenceReadOnly):
            store.authenticated_refs(
                after_sequence=0,
                through_sequence=2,
                limit=1,
            )
        store.close(flush=False)
        return

    if case == "signed_hole":
        coordinator, store = _new_system(path)
        key = private_key(11)
        first = _accept(coordinator, boot_boundary(key))
        fourth = _accept(
            coordinator,
            envelope_value(
                key,
                sequence=4,
                boot_id=BOOT_A,
                normalized_fields={"kind": "later"},
            ),
        )
        journal = AckJournal.create_new(store)
        journal.record_pending(first)
        journal.record_confirmed(first)
        assert store.acceptance_cursor == 1
        with pytest.raises(AckJournalAuthorityError):
            journal.record_pending(fourth)
        gap = _accept(
            coordinator,
            envelope_value(
                key,
                sequence=5,
                boot_id=BOOT_A,
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
            ),
        )
        assert store.acceptance_cursor == 5
        journal.record_pending(fourth)
        journal.record_confirmed(fourth)
        journal.record_pending(gap)
        store.close()
        return

    _coordinator, store, first, second = _two_refs(path)
    journal = AckJournal.create_new(store)
    if case == "confirm_without_pending":
        with pytest.raises(AckJournalStateError):
            journal.record_confirmed(first)
    elif case == "second_pending":
        journal.record_pending(first)
        with pytest.raises(AckJournalStateError):
            journal.record_pending(second)
    elif case == "mismatched_confirm":
        journal.record_pending(first)
        with pytest.raises(AckJournalStateError):
            journal.record_confirmed(second)
    elif case == "forged_complete_ref":
        forged = replace(first, segment_id="00000000-0000-4000-8000-000000000000")
        with pytest.raises(AckJournalAuthorityError):
            journal.record_pending(forged)
    elif case == "forged_pending_retry":
        journal.record_pending(first)
        forged = replace(first, frame_offset=first.frame_offset + 1)
        with pytest.raises(AckJournalAuthorityError):
            journal.record_pending(forged)
    elif case == "forged_confirmed_retry":
        journal.record_pending(first)
        journal.record_confirmed(first)
        forged = replace(first, frame_sha256="0" * 64)
        with pytest.raises(AckJournalAuthorityError):
            journal.record_confirmed(forged)
    else:
        with pytest.raises(AckJournalAuthorityError):
            journal.record_pending(second)
    store.close()


def _unknown_field_payload(first: EvidenceRef, _second: EvidenceRef) -> bytes:
    value = _record_value(first, "pending_ack")
    value["observer_cursor"] = 1
    return _frame_stream(canonical_json(value))


def _noncanonical_payload(first: EvidenceRef, _second: EvidenceRef) -> bytes:
    raw = json.dumps(
        _record_value(first, "pending_ack"),
        sort_keys=True,
    ).encode()
    return _frame_stream(raw)


def _complete_hash_corruption(first: EvidenceRef, _second: EvidenceRef) -> bytes:
    raw = bytearray(_frame_stream(canonical_json(_record_value(first, "pending_ack"))))
    raw[-1] ^= 1
    return bytes(raw)


def _duplicate_pending(first: EvidenceRef, _second: EvidenceRef) -> bytes:
    payload = canonical_json(_record_value(first, "pending_ack"))
    return _frame_stream(payload, payload)


def _evidence_identity_mismatch(first: EvidenceRef, _second: EvidenceRef) -> bytes:
    value = _record_value(first, "pending_ack")
    value["content_sha256"] = "0" * 64
    return _frame_stream(canonical_json(value))


@pytest.mark.parametrize(
    "raw_builder",
    [
        _unknown_field_payload,
        _noncanonical_payload,
        _complete_hash_corruption,
        _duplicate_pending,
        _evidence_identity_mismatch,
    ],
)
def test_ack_journal_complete_corruption_never_repairs_or_recovers(
    tmp_path: Path,
    raw_builder: Callable[[EvidenceRef, EvidenceRef], bytes],
) -> None:
    path = tmp_path / raw_builder.__name__
    _coordinator, store, first, second = _two_refs(path)
    journal = AckJournal.create_new(store)
    journal.close()
    store.close()
    journal_path = path / "ack-journal.agf"
    raw = raw_builder(first, second)
    journal_path.write_bytes(raw)

    _recovered_coordinator, recovered_store = _reopen_system(path)
    with pytest.raises(AckJournalCorrupt):
        AckJournal.open_and_recover(recovered_store)
    assert journal_path.read_bytes() == raw
    assert recovered_store.read_only_reason == "segment_corrupt"
    assert json.loads((path / "health.json").read_bytes())["reason"] == (
        "segment_corrupt"
    )
    recovered_store.close()


@pytest.mark.parametrize(
    "cut",
    [
        "partial_pending",
        "partial_confirmed",
        "ambiguous_file_fsync",
        "ambiguous_file_fsync_then_truncate",
        "same_inode_equal_size_rollback",
        "commitment_publication_confirmed_fsync",
        "commitment_publication_temp_fsync",
        "commitment_publication_replace",
        "commitment_publication_root_fsync",
        "commitment_publication_wrapped_rebind_io",
        "commitment_recovery_repeated_temp_fsync_crash",
        "commitment_floor_before_repair",
        "concurrent_extra_append",
        "create_file_fsync",
        "create_directory_fsync",
    ],
)
def test_ack_journal_repairs_only_torn_tail_and_latches_ambiguous_append(
    tmp_path: Path,
    cut: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / cut
    _coordinator, store, first, second = _two_refs(path)
    journal_path = path / "ack-journal.agf"

    if cut == "commitment_publication_wrapped_rebind_io":
        publication_root_synced = False
        injected = False
        read_regular = segments_module._read_regular_at

        def publication_hook(step: str) -> None:
            nonlocal publication_root_synced
            if step == "commitment_directory_fsync":
                publication_root_synced = True

        def fail_published_commitment_read(
            parent_descriptor: int,
            name: str,
            display_path: Path,
            maximum: int,
        ) -> bytes:
            nonlocal injected
            if (
                publication_root_synced
                and name == "ack-commitment.json"
                and not injected
            ):
                injected = True
                raise OSError("injected wrapped commitment rebind I/O")
            return read_regular(parent_descriptor, name, display_path, maximum)

        monkeypatch.setattr(
            segments_module,
            "_read_regular_at",
            fail_published_commitment_read,
        )
        uncertain = AckJournal.create_new(store, step_hook=publication_hook)
        uncertain.record_pending(first)
        with pytest.raises(OSError, match="wrapped commitment rebind"):
            uncertain.record_confirmed(first)
        assert uncertain.snapshot().healthy is False
        assert not (path / "health.json").exists()
        with pytest.raises(AckJournalUnhealthy):
            uncertain.record_pending(second)
        uncertain.close()
        store.close()

        monkeypatch.setattr(segments_module, "_read_regular_at", read_regular)
        _recovered_coordinator, recovered_store = _reopen_system(path)
        recovered = AckJournal.open_and_recover(recovered_store)
        assert recovered.snapshot().confirmed == ack_journal_module.AckIdentity.from_ref(
            first
        )
        assert not (path / "health.json").exists()
        recovered_store.close()
        return

    if cut == "commitment_recovery_repeated_temp_fsync_crash":
        confirmation_cut = False

        def confirmation_hook(step: str) -> None:
            nonlocal confirmation_cut
            if step == "commitment_temp_fsync" and not confirmation_cut:
                confirmation_cut = True
                raise OSError("injected initial commitment temp fsync cut")

        uncertain = AckJournal.create_new(store, step_hook=confirmation_hook)
        uncertain.record_pending(first)
        with pytest.raises(OSError, match="initial commitment temp"):
            uncertain.record_confirmed(first)
        uncertain.close()
        store.close()

        stale_name = (
            ".ack-commitment.json.12345678-1234-4234-8234-123456789abc.tmp"
        )
        stale_path = path / stale_name
        stale_path.write_bytes((path / "ack-commitment.json").read_bytes())
        stale_path.chmod(0o600)

        cleanup_private_publication = (
            segments_module._cleanup_private_publication
        )

        def preserve_crash_temporary(
            parent_descriptor: int,
            temporary_name: str | None,
            display_path: Path,
            *,
            descriptor: int,
            preserve_primary: bool,
        ) -> None:
            del parent_descriptor, temporary_name, display_path, preserve_primary
            if descriptor >= 0:
                os.close(descriptor)

        monkeypatch.setattr(
            segments_module,
            "_cleanup_private_publication",
            preserve_crash_temporary,
        )
        _recovered_coordinator, first_recovery_store = _reopen_system(path)
        recovery_cut = False

        def recovery_hook(step: str) -> None:
            nonlocal recovery_cut
            if step == "commitment_temp_fsync" and not recovery_cut:
                recovery_cut = True
                raise OSError("injected recovery commitment temp fsync cut")

        with pytest.raises(OSError, match="recovery commitment temp"):
            AckJournal.open_and_recover(
                first_recovery_store,
                step_hook=recovery_hook,
            )
        first_recovery_store.close()
        durable_temporaries = tuple(path.glob(".ack-commitment.json.*.tmp"))
        assert not stale_path.exists()
        assert len(durable_temporaries) == 1

        monkeypatch.setattr(
            segments_module,
            "_cleanup_private_publication",
            cleanup_private_publication,
        )
        _second_coordinator, second_recovery_store = _reopen_system(path)
        recovered = AckJournal.open_and_recover(second_recovery_store)
        assert recovered.snapshot().confirmed == ack_journal_module.AckIdentity.from_ref(
            first
        )
        assert not tuple(path.glob(".ack-commitment.json.*.tmp"))
        second_recovery_store.close()
        return

    if cut.startswith("commitment_publication_"):
        injected = False
        record_fsyncs = 0
        hook_step = {
            "commitment_publication_temp_fsync": "commitment_temp_fsync",
            "commitment_publication_replace": "commitment_atomic_replace",
            "commitment_publication_root_fsync": "commitment_directory_fsync",
        }.get(cut)

        def commitment_hook(step: str) -> None:
            nonlocal injected, record_fsyncs
            if step == "record_file_fsync":
                record_fsyncs += 1
            should_fail = (
                cut == "commitment_publication_confirmed_fsync"
                and step == "record_file_fsync"
                and record_fsyncs == 2
            ) or (hook_step is not None and step == hook_step)
            if should_fail and not injected:
                injected = True
                raise OSError(f"injected {cut}")

        uncertain = AckJournal.create_new(store, step_hook=commitment_hook)
        uncertain.record_pending(first)
        with pytest.raises(OSError, match=cut):
            uncertain.record_confirmed(first)
        assert uncertain.snapshot().healthy is False
        with pytest.raises(AckJournalUnhealthy):
            uncertain.record_pending(second)
        uncertain.close()
        store.close()

        _recovered_coordinator, recovered_store = _reopen_system(path)
        recovered = AckJournal.open_and_recover(recovered_store)
        commitment = json.loads((path / "ack-commitment.json").read_bytes())
        assert commitment["phase"] == "ready"
        assert commitment["generation"] == 1
        assert commitment["confirmed"] == {
            "sequence": first.source_sequence,
            "event_id": first.event_id,
            "content_sha256": first.content_sha256,
        }
        assert recovered.snapshot().confirmed == ack_journal_module.AckIdentity.from_ref(
            first
        )
        recovered.record_pending(second)
        recovered_store.close()
        return

    if cut == "commitment_floor_before_repair":
        journal = AckJournal.create_new(store)
        journal.record_pending(first)
        journal.record_confirmed(first)
        journal.record_pending(second)
        confirmed_one_prefix = journal_path.read_bytes()
        journal.record_confirmed(second)
        journal.close()
        store.close()

        torn = encode_frame(
            b"x" * _MAX_ACK_RECORD_BYTES,
            previous_hash=confirmed_one_prefix[-32:],
            max_frame=_MAX_ACK_RECORD_BYTES,
        )
        rewritten = confirmed_one_prefix + torn[:37]
        journal_path.write_bytes(rewritten)
        _recovered_coordinator, recovered_store = _reopen_system(path)
        with pytest.raises(AckJournalCorrupt):
            AckJournal.open_and_recover(recovered_store)
        assert journal_path.read_bytes() == rewritten
        assert recovered_store.read_only_reason == "segment_corrupt"
        recovered_store.close(flush=False)
        return

    if cut in {"create_file_fsync", "create_directory_fsync"}:
        injected = False

        def create_hook(step: str) -> None:
            nonlocal injected
            if step == cut and not injected:
                injected = True
                raise OSError(f"injected {cut}")

        with pytest.raises(OSError, match=cut):
            AckJournal.create_new(store, step_hook=create_hook)
        assert journal_path.exists()
        assert not (path / "health.json").exists()
        with pytest.raises(AckJournalStateError):
            AckJournal.create_new(store)
        with pytest.raises(AckJournalStateError):
            AckJournal.open_and_recover(store)
        store.close()

        _recovered_coordinator, recovered_store = _reopen_system(path)
        recovered = AckJournal.open_and_recover(recovered_store)
        assert recovered.snapshot().healthy is True
        assert recovered.snapshot().confirmed_through == 0
        recovered_store.close()
        return

    if cut == "concurrent_extra_append":
        injected = False

        def growth_hook(step: str) -> None:
            nonlocal injected
            if step == "record_file_fsync" and not injected:
                injected = True
                with journal_path.open("ab", buffering=0) as stream:
                    stream.write(b"x")
                    os.fsync(stream.fileno())

        growing = AckJournal.create_new(store, step_hook=growth_hook)
        with pytest.raises(AckJournalCorrupt):
            growing.record_pending(first)
        assert growing.snapshot().healthy is False
        store.close()
        return

    if cut == "same_inode_equal_size_rollback":
        journal = AckJournal.create_new(store)
        journal.record_pending(first)
        journal.record_confirmed(first)
        journal.record_pending(second)
        authenticated_prefix = journal_path.read_bytes()
        journal.record_confirmed(second)
        authenticated = journal_path.read_bytes()
        assert journal.snapshot().confirmed_through == 2

        remaining = len(authenticated) - len(authenticated_prefix)
        torn = encode_frame(
            b"x" * _MAX_ACK_RECORD_BYTES,
            previous_hash=authenticated_prefix[-32:],
            max_frame=_MAX_ACK_RECORD_BYTES,
        )
        assert 0 < remaining < len(torn)
        inode = journal_path.stat().st_ino
        rewritten = authenticated_prefix + torn[:remaining]
        journal_path.write_bytes(rewritten)
        assert journal_path.stat().st_ino == inode
        assert len(rewritten) == len(authenticated)

        with pytest.raises(AckJournalCorrupt):
            journal.close()
        assert journal_path.read_bytes() == rewritten
        assert json.loads((path / "health.json").read_bytes())["reason"] == (
            "segment_corrupt"
        )
        store.close(flush=False)
        restarted = SegmentStore(path)
        assert restarted.read_only_reason == "segment_corrupt"
        restarted.close(flush=False)
        return

    if cut in {
        "ambiguous_file_fsync",
        "ambiguous_file_fsync_then_truncate",
    }:
        injected = False
        fsync_count = 0

        def step_hook(step: str) -> None:
            nonlocal fsync_count, injected
            if step != "record_file_fsync":
                return
            fsync_count += 1
            fail_at = (
                2
                if cut == "ambiguous_file_fsync_then_truncate"
                else 1
            )
            if fsync_count == fail_at and not injected:
                injected = True
                raise OSError("injected ambiguous fsync")

        uncertain = AckJournal.create_new(store, step_hook=step_hook)
        if cut == "ambiguous_file_fsync_then_truncate":
            uncertain.record_pending(first)
        with pytest.raises(OSError, match="ambiguous fsync"):
            (
                uncertain.record_confirmed(first)
                if cut == "ambiguous_file_fsync_then_truncate"
                else uncertain.record_pending(first)
            )
        assert uncertain.snapshot().healthy is False
        assert not (path / "health.json").exists()
        with pytest.raises(AckJournalUnhealthy):
            uncertain.record_pending(first)
        uncertain.close()
        if cut == "ambiguous_file_fsync_then_truncate":
            journal_path.write_bytes(b"")
            store.close(flush=False)
            assert json.loads((path / "health.json").read_bytes())["reason"] == (
                "segment_corrupt"
            )
            restarted = SegmentStore(path)
            assert restarted.read_only_reason == "segment_corrupt"
            restarted.close(flush=False)
            return
        store.close()

        _recovered_coordinator, recovered_store = _reopen_system(path)
        recovered = AckJournal.open_and_recover(recovered_store)
        assert recovered.snapshot().healthy is True
        assert recovered.snapshot().pending is not None
        assert recovered.snapshot().pending.sequence == 1
        recovered_store.close()
        return

    journal = AckJournal.create_new(store)
    if cut == "partial_confirmed":
        journal.record_pending(first)
        journal.record_confirmed(first)
        journal.record_pending(second)
        prefix = journal_path.read_bytes()
        partial_record = _record_value(second, "confirmed_ack")
    else:
        prefix = journal_path.read_bytes()
        partial_record = _record_value(first, "pending_ack")
    journal.close()
    store.close()

    previous = prefix[-32:] if prefix else bytes(32)
    tail = encode_frame(
        canonical_json(partial_record),
        previous_hash=previous,
        max_frame=_MAX_ACK_RECORD_BYTES,
    )
    journal_path.write_bytes(prefix + tail[: len(tail) // 2])

    _recovered_coordinator, recovered_store = _reopen_system(path)
    recovered = AckJournal.open_and_recover(recovered_store)
    assert journal_path.read_bytes() == prefix
    if cut == "partial_confirmed":
        assert recovered.snapshot().pending is not None
        assert recovered.snapshot().pending.sequence == 2
        recovered.record_confirmed(second)
    else:
        assert recovered.snapshot().pending is None
        recovered.record_pending(first)
    recovered_store.close()


@pytest.mark.parametrize(
    "case",
    [
        "requires_authenticated_store",
        "open_missing_fails",
        "single_owner",
        "store_closes_owner",
        "replaced_after_open",
        "read_only_lookup",
        "delete_before_open",
        "confirmed_close_delete_recreate",
        "fence_failure_preserves_corrupt",
        "prefix_digest_close_failure",
        "substitute_after_startup_scan",
        "substitute_after_journal_close",
        "substitute_before_store_close",
        "post_unlock_commitment_rollback",
        "commitment_bootstrap_temp_only",
        "commitment_bootstrap_initializing_missing",
        "commitment_bootstrap_initializing_empty",
        "commitment_bootstrap_ready",
        "commitment_bootstrap_ready_missing",
        "commitment_duplicate_temp",
        "commitment_wrong_mode_temp",
        "commitment_wrong_mode_final",
        "commitment_journal_without_commitment",
        "commitment_final_deleted_before_torn_repair",
        "commitment_final_substituted_before_snapshot",
        "delivery_claim_lifecycle",
        "wrong_mode",
        "symlink",
        "hard_link",
    ],
)
def test_ack_journal_root_capability_and_artifact_identity_fail_closed(
    tmp_path: Path,
    case: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / case
    if case == "commitment_final_deleted_before_torn_repair":
        _coordinator, initial_store, first, _second = _two_refs(path)
        journal = AckJournal.create_new(initial_store)
        journal.record_pending(first)
        journal.close()
        initial_store.close()

        journal_path = path / "ack-journal.agf"
        prefix = journal_path.read_bytes()
        confirmed = encode_frame(
            canonical_json(_record_value(first, "confirmed_ack")),
            previous_hash=prefix[-32:],
            max_frame=_MAX_ACK_RECORD_BYTES,
        )
        before = prefix + confirmed[:37]
        journal_path.write_bytes(before)

        _recovered_coordinator, recovered_store = _reopen_system(path)
        (path / "ack-commitment.json").unlink()
        with pytest.raises(AckJournalCorrupt):
            AckJournal.open_and_recover(recovered_store)
        assert journal_path.read_bytes() == before
        assert recovered_store.read_only_reason == "segment_corrupt"
        recovered_store.close(flush=False)
        return

    if case == "commitment_final_substituted_before_snapshot":
        _coordinator, store, first, _second = _two_refs(path)
        journal = AckJournal.create_new(store)
        journal.record_pending(first)
        journal.record_confirmed(first)
        commitment_path = path / "ack-commitment.json"
        replacement = path / "ack-commitment.replacement"
        replacement.write_bytes(commitment_path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, commitment_path)

        with pytest.raises(AckJournalCorrupt):
            journal.snapshot()
        assert json.loads((path / "health.json").read_bytes())["reason"] == (
            "segment_corrupt"
        )
        store.close(flush=False)
        return

    if case.startswith("commitment_bootstrap_"):
        _coordinator, initial_store = _new_system(path)
        initial_store.close()
        commitment_path = path / "ack-commitment.json"
        journal_path = path / "ack-journal.agf"
        if case == "commitment_bootstrap_temp_only":
            temporary = (
                path
                / ".ack-commitment.json.12345678-1234-4234-8234-123456789abc.tmp"
            )
            temporary.write_bytes(_genesis_commitment("initializing"))
            temporary.chmod(0o600)
        elif case in {
            "commitment_bootstrap_initializing_missing",
            "commitment_bootstrap_initializing_empty",
        }:
            commitment_path.write_bytes(_genesis_commitment("initializing"))
            commitment_path.chmod(0o600)
            if case.endswith("_empty"):
                journal_path.write_bytes(b"")
                journal_path.chmod(0o600)
        elif case == "commitment_bootstrap_ready_missing":
            commitment_path.write_bytes(_genesis_commitment("ready"))
            commitment_path.chmod(0o600)
        else:
            _recovered_coordinator, recovered_store = _reopen_system(path)
            journal = AckJournal.create_new(recovered_store)
            journal.close()
            recovered_store.close()

        _recovered_coordinator, recovered_store = _reopen_system(path)
        if case == "commitment_bootstrap_ready_missing":
            before = commitment_path.read_bytes()
            with pytest.raises(AckJournalCorrupt):
                AckJournal.open_and_recover(recovered_store)
            assert commitment_path.read_bytes() == before
            assert not journal_path.exists()
            assert recovered_store.read_only_reason == "segment_corrupt"
            recovered_store.close(flush=False)
            return
        if case in {
            "commitment_bootstrap_temp_only",
            "commitment_bootstrap_ready",
        }:
            recovered = (
                AckJournal.create_new(recovered_store)
                if case == "commitment_bootstrap_temp_only"
                else AckJournal.open_and_recover(recovered_store)
            )
        else:
            recovered = AckJournal.open_and_recover(recovered_store)
        assert recovered.snapshot().confirmed_through == 0
        assert journal_path.read_bytes() == b""
        assert json.loads(commitment_path.read_bytes()) == json.loads(
            _genesis_commitment("ready")
        )
        assert not tuple(path.glob(".ack-commitment.json.*.tmp"))
        recovered_store.close()
        return

    if case in {
        "commitment_duplicate_temp",
        "commitment_wrong_mode_temp",
        "commitment_wrong_mode_final",
        "commitment_journal_without_commitment",
    }:
        _coordinator, initial_store = _new_system(path)
        if case == "commitment_journal_without_commitment":
            journal = AckJournal.create_new(initial_store)
            journal.close()
        else:
            initial_store.close()
            commitment = path / "ack-commitment.json"
            commitment.write_bytes(_genesis_commitment("ready"))
            commitment.chmod(0o600)
            first_temp = (
                path
                / ".ack-commitment.json.12345678-1234-4234-8234-123456789abc.tmp"
            )
            if case in {"commitment_duplicate_temp", "commitment_wrong_mode_temp"}:
                first_temp.write_bytes(_genesis_commitment("ready"))
                first_temp.chmod(
                    0o640 if case == "commitment_wrong_mode_temp" else 0o600
                )
            if case == "commitment_duplicate_temp":
                second_temp = (
                    path
                    / ".ack-commitment.json.87654321-4321-4432-8432-cba987654321.tmp"
                )
                second_temp.write_bytes(_genesis_commitment("ready"))
                second_temp.chmod(0o600)
            if case == "commitment_wrong_mode_final":
                commitment.chmod(0o640)
        if case != "commitment_journal_without_commitment":
            with pytest.raises(EvidenceCorrupt):
                SegmentStore(path)
            return
        initial_store.close()
        (path / "ack-commitment.json").unlink()
        _recovered_coordinator, recovered_store = _reopen_system(path)
        with pytest.raises(AckJournalCorrupt):
            AckJournal.open_and_recover(recovered_store)
        assert recovered_store.read_only_reason == "segment_corrupt"
        recovered_store.close(flush=False)
        return

    if case == "requires_authenticated_store":
        store = SegmentStore(path)
        with pytest.raises(EvidenceSealError):
            AckJournal.create_new(store)
        with pytest.raises(EvidenceSealError):
            AckJournal.open_and_recover(store)
        store.close()
        return

    if case == "delivery_claim_lifecycle":
        _coordinator, store = _new_system(path)
        _other_coordinator, other_store = _new_system(tmp_path / "other-store")
        journal = AckJournal.create_new(store)
        with pytest.raises(TypeError, match="claim_delivery"):
            ack_journal_module.AckDeliveryLease(journal, object())
        with pytest.raises(AckJournalAuthorityError):
            journal.claim_delivery(other_store)
        lease = journal.claim_delivery(store)
        assert isinstance(lease, ack_journal_module.AckDeliveryLease)
        with pytest.raises(AckJournalStateError):
            journal.claim_delivery(store)
        lease.release()
        lease.release()
        replacement = journal.claim_delivery(store)
        journal.close()
        replacement.release()
        with pytest.raises(AckJournalStateError):
            journal.claim_delivery(store)
        store.close()
        other_store.close()
        return

    if case == "delete_before_open":
        _coordinator, initial_store = _new_system(path)
        journal = AckJournal.create_new(initial_store)
        journal.close()
        initial_store.close()

        _recovered_coordinator, recovered_store = _reopen_system(path)
        (path / "ack-journal.agf").unlink()
        with pytest.raises(AckJournalCorrupt):
            AckJournal.open_and_recover(recovered_store)
        assert recovered_store.read_only_reason == "segment_corrupt"
        recovered_store.close(flush=False)
        return
    if case == "substitute_after_startup_scan":
        _coordinator, initial_store, first, _second = _two_refs(path)
        journal = AckJournal.create_new(initial_store)
        journal.record_pending(first)
        journal.record_confirmed(first)
        journal.close()
        initial_store.close()

        _recovered_coordinator, recovered_store = _reopen_system(path)
        _substitute_ack_journal(path)
        with pytest.raises(AckJournalCorrupt):
            AckJournal.open_and_recover(recovered_store)
        assert recovered_store.read_only_reason == "segment_corrupt"
        assert json.loads((path / "health.json").read_bytes())["reason"] == (
            "segment_corrupt"
        )
        recovered_store.close(flush=False)
        return
    if case == "substitute_after_journal_close":
        _coordinator, store, first, _second = _two_refs(path)
        journal = AckJournal.create_new(store)
        journal.record_pending(first)
        journal.record_confirmed(first)
        journal.close()
        _substitute_ack_journal(path)
        store.close(flush=False)
        assert json.loads((path / "health.json").read_bytes())["reason"] == (
            "segment_corrupt"
        )
        restarted = SegmentStore(path)
        assert restarted.read_only_reason == "segment_corrupt"
        restarted.close(flush=False)
        return
    if case == "substitute_before_store_close":
        _coordinator, store, first, _second = _two_refs(path)
        journal = AckJournal.create_new(store)
        journal.record_pending(first)
        journal.record_confirmed(first)
        _substitute_ack_journal(path)
        with pytest.raises(AckJournalCorrupt):
            store.close(flush=False)
        assert json.loads((path / "health.json").read_bytes())["reason"] == (
            "segment_corrupt"
        )
        restarted = SegmentStore(path)
        assert restarted.read_only_reason == "segment_corrupt"
        restarted.close(flush=False)
        return
    if case == "confirmed_close_delete_recreate":
        _coordinator, store, first, _second = _two_refs(path)
        journal = AckJournal.create_new(store)
        journal.record_pending(first)
        journal.record_confirmed(first)
        journal.close()
        (path / "ack-journal.agf").unlink()
        with pytest.raises(AckJournalCorrupt):
            AckJournal.create_new(store)
        assert store.read_only_reason == "segment_corrupt"
        store.close(flush=False)
        return
    if case == "fence_failure_preserves_corrupt":
        _coordinator, initial_store, first, _second = _two_refs(path)
        journal = AckJournal.create_new(initial_store)
        journal.close()
        initial_store.close()
        journal_path = path / "ack-journal.agf"
        corrupt = bytearray(
            _frame_stream(canonical_json(_record_value(first, "pending_ack")))
        )
        corrupt[-1] ^= 1
        journal_path.write_bytes(corrupt)
        injected = False

        def health_hook(step: str) -> None:
            nonlocal injected
            if step == "create" and not injected:
                injected = True
                raise OSError("injected fence persistence failure")

        root, chain = _identity()
        recovered_store = SegmentStore(path, health_step_hook=health_hook)
        AcceptanceCoordinator.open_and_recover(
            EnvelopeVerifier(root, chain),
            recovered_store,
        )
        release = recovered_store._release_ack_journal

        def release_then_fail(owner: object, lifecycle: object) -> None:
            release(owner, lifecycle)
            raise RuntimeError("injected failed-open cleanup failure")

        monkeypatch.setattr(
            recovered_store,
            "_release_ack_journal",
            release_then_fail,
        )
        with pytest.raises(AckJournalCorrupt) as raised:
            AckJournal.open_and_recover(recovered_store)
        assert any(
            "corruption-fence failure" in note
            for note in raised.value.__notes__
        )
        assert any(
            "failed-open cleanup failure" in note
            for note in raised.value.__notes__
        )
        assert bytes(corrupt) == journal_path.read_bytes()
        assert recovered_store.read_only_reason == "segment_corrupt"
        recovered_store.close(flush=False)
        return
    if case == "prefix_digest_close_failure":
        _coordinator, store = _new_system(path)
        journal = AckJournal.create_new(store)
        journal.close()
        real_close = segments_module.os.close
        injected = False

        def close_then_fail(descriptor: int) -> None:
            nonlocal injected
            real_close(descriptor)
            if not injected:
                injected = True
                raise OSError("injected ACK prefix descriptor close failure")

        monkeypatch.setattr(segments_module.os, "close", close_then_fail)
        store.close(flush=False)
        assert json.loads((path / "health.json").read_bytes())["reason"] == (
            "segment_corrupt"
        )
        return

    if case == "post_unlock_commitment_rollback":
        _coordinator, store, first, second = _two_refs(path)
        journal = AckJournal.create_new(store)
        journal.record_pending(first)
        journal.record_confirmed(first)
        journal.record_pending(second)
        confirmed_one_prefix = (path / "ack-journal.agf").read_bytes()
        journal.record_confirmed(second)
        confirmed_two = (path / "ack-journal.agf").read_bytes()
        journal.close()
        store.close()

        remaining = len(confirmed_two) - len(confirmed_one_prefix)
        torn = encode_frame(
            b"x" * _MAX_ACK_RECORD_BYTES,
            previous_hash=confirmed_one_prefix[-32:],
            max_frame=_MAX_ACK_RECORD_BYTES,
        )
        assert 0 < remaining < len(torn)
        journal_path = path / "ack-journal.agf"
        inode = journal_path.stat().st_ino
        rewritten = confirmed_one_prefix + torn[:remaining]
        journal_path.write_bytes(rewritten)
        assert journal_path.stat().st_ino == inode
        assert len(rewritten) == len(confirmed_two)

        _recovered_coordinator, recovered_store = _reopen_system(path)
        with pytest.raises(AckJournalCorrupt):
            AckJournal.open_and_recover(recovered_store)
        assert journal_path.read_bytes() == rewritten
        assert recovered_store.read_only_reason == "segment_corrupt"
        assert json.loads((path / "health.json").read_bytes())["reason"] == (
            "segment_corrupt"
        )
        recovered_store.close(flush=False)
        return

    if case == "replaced_after_open":
        _coordinator, store, first, _second = _two_refs(path)
        journal = AckJournal.create_new(store)
        journal.record_pending(first)
        _substitute_ack_journal(path)
        with pytest.raises(AckJournalCorrupt):
            journal.pending_request_body()
        assert journal.snapshot().healthy is False
        assert json.loads((path / "health.json").read_bytes())["reason"] == (
            "segment_corrupt"
        )
        store.close()
        restarted = SegmentStore(path)
        assert restarted.read_only_reason == "segment_corrupt"
        restarted.close(flush=False)
        return
    if case == "read_only_lookup":
        _coordinator, store, first, _second = _two_refs(path)
        store.enter_read_only("evidence_conflict")
        assert store.resolve_authenticated_ref(first).ref == first
        assert [record.ref for record in store.iter_authenticated_records()] == [
            first,
            _second,
        ]
        with pytest.raises(EvidenceReadOnly):
            AckJournal.create_new(store)
        with pytest.raises(EvidenceReadOnly):
            store.authenticated_refs(
                after_sequence=0,
                through_sequence=2,
                limit=1,
            )
        store.close(flush=False)
        return

    _coordinator, store = _new_system(path)
    if case == "open_missing_fails":
        with pytest.raises(AckJournalStateError):
            AckJournal.open_and_recover(store)
        assert not (path / "ack-journal.agf").exists()
        store.close()
        return
    journal = AckJournal.create_new(store)
    if case == "single_owner":
        with pytest.raises(EvidenceStoreBusy):
            AckJournal.create_new(store)
        store.close()
        return
    if case == "store_closes_owner":
        store.close()
        with pytest.raises(AckJournalStateError):
            journal.snapshot()
        _recovered_coordinator, recovered_store = _reopen_system(path)
        AckJournal.open_and_recover(recovered_store)
        recovered_store.close()
        return

    journal.close()
    store.close()
    journal_path = path / "ack-journal.agf"
    if case == "wrong_mode":
        journal_path.chmod(0o640)
    elif case == "symlink":
        journal_path.unlink()
        target = tmp_path / "target"
        target.write_bytes(b"")
        journal_path.symlink_to(target)
    else:
        os.link(journal_path, tmp_path / "ack-hard-link")
    with pytest.raises(EvidenceCorrupt):
        SegmentStore(path)
