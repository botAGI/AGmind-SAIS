from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib
import json
import os
import resource
import stat
from collections.abc import Callable
from dataclasses import fields
from datetime import datetime
from pathlib import Path
from threading import Event, Thread
from typing import Any

import pytest
from agmind_immune.canonicaljson import (
    canonical_json,
    pcc_detector_bundle_sha256,
)
from agmind_immune.correlation.pcc import CorrelationProjectionError
from agmind_immune.correlation.primitives import (
    ParsedSpecialUseRegistry,
    SpecialUseRegistry,
    load_pinned_special_use_registry,
    special_use_registry_is_issued,
)
from agmind_immune.coverage.historical import (
    _HistoricalReductionResult,
    _reduce_historical_coverage_result,
)
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.frames import decode_frames
from agmind_immune.evidence.projection import ProjectionAuthorityError
from agmind_immune.evidence.segments import (
    MAX_EVIDENCE_RECORD_BYTES,
    EvidencePriority,
    EvidenceRef,
    SegmentStore,
)
from agmind_immune.ingest import ack_journal as ack_journal_module
from agmind_immune.ingest.ack_journal import (
    AckJournal,
    AckJournalCorrupt,
)
from agmind_immune.ingest.envelope import EnvelopeVerifier
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.correlation.test_pcc import (
    _accepted_complete,
    _accepted_failed,
    _context,
)
from tests.coverage.test_historical import _self_close_records
from tests.coverage.test_state import T0, T1, _event, _stored
from tests.ingest.test_pcc_correlation_snapshot import _identity, _item
from tests.phase5b_helpers import (
    BOOT_A,
    HOST_ID,
    NOW,
    boot_boundary,
    envelope_value,
    private_key,
)

_PCC_CONTENT_HASHES = (
    "6f0db0a71c24c3a490f886bc3537a66826722e188d0557099f3b200876544e9f",
    "5db77018947a3a4163aa7e266060baaab36d48798e81937400e639bc01defa16",
    "a1384bae9bddfda5c876f0445705ccd8c63dc36849270d7b6301838f409518cc",
    "2499cb92e6358c9b0df96fefa49f87dc3f38ae8aaa0424bc33aa8d6cb2734211",
    "5b87ba53f9e0b73640689c625714de16dd2ef063d7688ccd175224d367e442fc",
    "a6bc229473ac99afadff93197592333e0841cd8cf87bde866174d7846bef7fb4",
    "6764d6251e5c2d314a9f768e3a97b4aa96087505e42990620971f3ee97604005",
    "58986446964c7f26eb5c2b44ef6a89a30c1c0836bea70a4c55bd1b9a5755e2f2",
)
_REGISTRY_PATH = Path("contracts/v1/ipv4-special-use.csv")
_DETECTOR_HASH = "1" * 64


def _correlation_modules() -> tuple[Any, Any]:
    return (
        importlib.import_module("agmind_immune.correlation.authority"),
        importlib.import_module("agmind_immune.correlation.pcc"),
    )


def _replace_first_serialized_fact(
    value: object,
    predicate: Callable[[object], bool],
    replacement: object,
) -> tuple[object, bool]:
    if predicate(value):
        return replacement, True
    if type(value) is list:
        changed: list[object] = []
        replaced = False
        for item in value:
            if replaced:
                changed.append(item)
                continue
            rewritten, replaced = _replace_first_serialized_fact(
                item,
                predicate,
                replacement,
            )
            changed.append(rewritten)
        return changed, replaced
    if type(value) is dict:
        changed_dict: dict[str, object] = {}
        replaced = False
        for key, item in value.items():
            if replaced:
                changed_dict[key] = item
                continue
            rewritten, replaced = _replace_first_serialized_fact(
                item,
                predicate,
                replacement,
            )
            changed_dict[key] = rewritten
        return changed_dict, replaced
    return value, False


def _mutated_canonical(
    canonical: bytes,
    predicate: Callable[[object], bool],
    replacement: object,
) -> bytes:
    domain, separator, payload = canonical.partition(b"\0")
    assert separator == b"\0"
    decoded = json.loads(payload)
    changed, replaced = _replace_first_serialized_fact(
        decoded,
        predicate,
        replacement,
    )
    assert replaced
    return domain + separator + canonical_json(changed)


def _build_registered_correlation_authority(
    store: SegmentStore,
) -> tuple[Any, Any, Any]:
    authority_module, _pcc_module = _correlation_modules()
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    predecessor = authority_module._ProjectionPredecessor(
        generation=0,
        host_id=None,
        source_sequence=0,
        event_id=None,
        content_sha256=None,
        frame_sha256=None,
    )
    detector_digest = pcc_detector_bundle_sha256(
        Path("deploy/falco/rules.d/agmind-pcc.yaml").read_bytes()
    )
    issued = authority_module._issue_correlation_projection_authority(
        store,
        registry,
        predecessor,
        detector_digest,
        authority_module._registry_facts(registry),
    )
    binding = authority_module._authority_binding(issued)
    return issued, binding, predecessor


def _drop_registered_correlation_authority(issued: object) -> None:
    authority_module, _pcc_module = _correlation_modules()
    authority_module._close_correlation_projection_authority(issued)
    with authority_module._ISSUED_AUTHORITIES_LOCK:
        authority_module._ISSUED_AUTHORITIES.pop(id(issued), None)


def _pcc_fixture(count: int) -> dict[str, object]:
    records = tuple(_self_close_records(count))
    assert tuple(record.ref.source_sequence for record in records) == tuple(
        range(1, count + 1)
    )
    assert tuple(record.ref.content_sha256 for record in records) == _PCC_CONTENT_HASHES[
        :count
    ]
    assert len({record.ref.event_id for record in records}) == count
    return {
        "records": records,
        "host_id": HOST_ID,
        "boot_id": BOOT_A,
        "trigger_event_id": "evt_" + "6" * 64,
        "trigger_source_sequence": count,
        "trigger_event_time": T0,
        "clock_uncertainty_ms": 0,
        "coverage_through_sequence": count,
        "window_end": T1,
    }


def four_pcc_fixture() -> dict[str, object]:
    return _pcc_fixture(4)


def eight_pcc_fixture() -> dict[str, object]:
    return _pcc_fixture(8)


def no_prefix_scan_pcc_fixture(count: int) -> dict[str, object]:
    key = private_key(11)
    records = tuple(
        _stored(_event(key, sequence, kind=f"ordinary_{sequence}"))
        for sequence in range(1, count + 1)
    )
    return {
        "records": records,
        "host_id": HOST_ID,
        "boot_id": BOOT_A,
        "trigger_event_id": "evt_" + "6" * 64,
        "trigger_source_sequence": count,
        "trigger_event_time": T0,
        "clock_uncertainty_ms": 0,
        "coverage_through_sequence": count,
        "window_end": T1,
    }


def _source_envelopes() -> tuple[dict[str, object], dict[str, object]]:
    key = private_key(11)
    return (
        boot_boundary(key),
        envelope_value(
            key,
            sequence=2,
            normalized_fields={"kind": "snapshot-source"},
        ),
    )


def _expected_record_literals() -> tuple[bytes, bytes]:
    protected, routine = _source_envelopes()
    return tuple(
        canonical_json(
            {
                "schema_version": "agmind.accepted-envelope.v1",
                "evidence_priority": priority.value,
                "accepted_at": NOW,
                "outer": {
                    "sequence": envelope["source_sequence"],
                    "event_id": envelope["event_id"],
                    "content_sha256": hashlib.sha256(
                        canonical_json(envelope)
                    ).hexdigest(),
                },
                "envelope": envelope,
            }
        )
        for envelope, priority in (
            (protected, EvidencePriority.PROTECTED),
            (routine, EvidencePriority.ROUTINE),
        )
    )  # type: ignore[return-value]


def _build_file_backed_source(
    path: Path,
    *,
    health_step_hook: Callable[[str], None] | None = None,
) -> tuple[AcceptanceCoordinator, SegmentStore, EvidenceRef]:
    key = private_key(11)
    root, chain = _identity(key)
    store = SegmentStore(
        path,
        wall_clock=lambda: datetime.fromisoformat(NOW),
    )
    coordinator = AcceptanceCoordinator.create_empty(
        EnvelopeVerifier(root, chain),
        store,
    )
    first, second = _source_envelopes()
    coordinator.accept(_item(first))
    terminal = coordinator.accept(_item(second))
    store.flush_security_boundary()
    store.close()

    recovered = SegmentStore(path, health_step_hook=health_step_hook)
    recovered_coordinator = AcceptanceCoordinator.open_and_recover(
        EnvelopeVerifier(root, chain),
        recovered,
    )
    return recovered_coordinator, recovered, terminal


def _decode_snapshot_records(snapshot: object) -> tuple[bytes, ...]:
    segments = snapshot.segments
    return tuple(
        decode_frames(
            os.pread(
                segments[record.segment_index].descriptor,
                record.ref.frame_size,
                record.ref.frame_offset,
            ),
            max_frame=MAX_EVIDENCE_RECORD_BYTES,
        ).records[0].payload
        for record in snapshot.records
    )


def _rename_and_unlink_source_paths(store: SegmentStore) -> None:
    first, second = store.manifests
    first_path = store.root / first.segment_relative_path
    first_path.rename(first_path.with_suffix(".moved"))
    (store.root / second.segment_relative_path).unlink()


def _append_next_signed_record(
    coordinator: AcceptanceCoordinator,
) -> EvidenceRef:
    return coordinator.accept(
        _item(
            envelope_value(
                private_key(11),
                sequence=3,
                normalized_fields={"kind": "post-snapshot"},
            )
        )
    )


def _force_real_second_descriptor_failure(
    path: Path,
) -> tuple[None, tuple[int, ...]]:
    coordinator, store, terminal = _build_file_backed_source(path)
    del coordinator
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    sentinel = os.open(os.devnull, os.O_RDONLY)
    expected_owned_descriptor = sentinel + 2
    try:
        resource.setrlimit(
            resource.RLIMIT_NOFILE,
            (sentinel + 3, hard_limit),
        )
        with (
            pytest.raises(OSError) as raised,
            store._replay_source_snapshot_gate(),
        ):
            store._capture_replay_source_locked(terminal)
        assert raised.value.errno == errno.EMFILE
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, hard_limit))
        os.close(sentinel)
        store.close()
    return None, (expected_owned_descriptor,)


def _all_descriptor_fstats_fail_with_ebadf(descriptors: tuple[int, ...]) -> bool:
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
        return False
    return True


def _build_ack_snapshot_journal(
    path: Path,
    *,
    health_step_hook: Callable[[str], None] | None = None,
) -> tuple[AckJournal, SegmentStore, tuple[EvidenceRef, ...]]:
    _coordinator, store, _terminal = _build_file_backed_source(
        path,
        health_step_hook=health_step_hook,
    )
    refs = tuple(record.ref for record in store.iter_authenticated_records())
    assert tuple(ref.source_sequence for ref in refs) == (1, 2)
    journal = AckJournal.create_new(store)
    journal.record_pending(refs[0])
    journal.record_confirmed(refs[0])
    return journal, store, refs


def test_ack_health_fence_hook_runs_after_replay_gate_is_released(
    tmp_path: Path,
) -> None:
    journal: AckJournal | None = None
    probes: list[Thread] = []
    gate_available_during_hook: list[bool] = []

    def health_step_hook(step: str) -> None:
        if step != "create":
            return
        assert journal is not None
        acquired = Event()

        def probe_gate() -> None:
            with journal._replay_ack_snapshot_gate():
                acquired.set()

        probe = Thread(target=probe_gate)
        probes.append(probe)
        probe.start()
        gate_available_during_hook.append(acquired.wait(1.0))

    journal, store, _refs = _build_ack_snapshot_journal(
        tmp_path / "health-hook",
        health_step_hook=health_step_hook,
    )
    try:
        replacement = tmp_path / "health-hook" / "ack-journal.replacement"
        replacement.write_bytes(b"")
        replacement.chmod(0o600)
        os.replace(
            replacement,
            tmp_path / "health-hook" / "ack-journal.agf",
        )
        with pytest.raises(AckJournalCorrupt):
            journal.snapshot()
    finally:
        for probe in probes:
            probe.join(1.0)
        journal.close()
        store.close(flush=False)

    assert gate_available_during_hook == [True]
    assert all(not probe.is_alive() for probe in probes)


@pytest.mark.parametrize(
    "writer",
    ("pending", "confirmed", "retention_acquire", "retention_release", "close", "health"),
)
def test_ack_snapshot_revision_changes_for_every_sanctioned_writer(
    tmp_path: Path,
    writer: str,
) -> None:
    journal, store, refs = _build_ack_snapshot_journal(tmp_path / writer)
    lease = None
    snapshot = None
    try:
        if writer == "confirmed":
            journal.record_pending(refs[1])
        elif writer == "retention_release":
            lease = store._acquire_retention_ack_boundary(
                journal,
                confirmed_through=refs[0].source_sequence,
            )

        with journal._replay_ack_snapshot_gate():
            snapshot = journal._capture_replay_ack_locked(
                refs[-1].source_sequence
            )

        if writer == "pending":
            journal.record_pending(refs[1])
        elif writer == "confirmed":
            journal.record_confirmed(refs[1])
        elif writer == "retention_acquire":
            lease = store._acquire_retention_ack_boundary(
                journal,
                confirmed_through=refs[0].source_sequence,
            )
        elif writer == "retention_release":
            assert lease is not None
            store._release_retention_ack_boundary(journal, lease)
            lease = None
        elif writer == "close":
            journal.close()
        else:
            replacement = tmp_path / writer / "ack-journal.replacement"
            replacement.write_bytes(b"")
            replacement.chmod(0o600)
            os.replace(replacement, tmp_path / writer / "ack-journal.agf")
            with pytest.raises(AckJournalCorrupt):
                journal.snapshot()

        with (
            journal._replay_ack_snapshot_gate(),
            pytest.raises(ProjectionAuthorityError),
        ):
            journal._revalidate_replay_ack_locked(snapshot)
    finally:
        if snapshot is not None:
            ack_journal_module._close_replay_ack_snapshot(snapshot)
        if lease is not None:
            store._release_retention_ack_boundary(journal, lease)
        journal.close()
        store.close(flush=False)


def test_ack_snapshot_has_no_callback_and_owns_exact_prefix_descriptor(
    tmp_path: Path,
) -> None:
    journal, store, refs = _build_ack_snapshot_journal(tmp_path / "ack")
    snapshot = None
    descriptor = -1
    try:
        with journal._replay_ack_snapshot_gate():
            snapshot = journal._capture_replay_ack_locked(
                refs[-1].source_sequence
            )
        descriptor = snapshot.descriptor
        descriptor_stat = os.fstat(descriptor)
        assert snapshot.committed_prefix_sha256 == bytes.fromhex(
            "916c45030c830eaf5665c9b8eef95ca5266c40fe4e0058e023ca1e128cce0acb"
        )
        assert tuple(
            field.name
            for field in fields(snapshot)
            if callable(getattr(snapshot, field.name))
        ) == ()
        assert stat.S_ISREG(descriptor_stat.st_mode)
        assert (
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
            descriptor_stat.st_size,
        ) == (snapshot.device, snapshot.inode, snapshot.size)
        assert (
            fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        ) == os.O_RDONLY
        assert hashlib.sha256(
            os.pread(descriptor, snapshot.committed_prefix_size, 0)
        ).digest() == snapshot.committed_prefix_sha256

        journal.close()
        assert len(
            os.pread(descriptor, snapshot.committed_prefix_size, 0)
        ) == snapshot.committed_prefix_size
    finally:
        if snapshot is not None:
            ack_journal_module._close_replay_ack_snapshot(snapshot)
        journal.close()
        store.close(flush=False)
    assert _all_descriptor_fstats_fail_with_ebadf((descriptor,))


def test_source_snapshot_reads_held_descriptors_without_path_reopen(
    tmp_path: Path,
) -> None:
    _coordinator, store, terminal = _build_file_backed_source(tmp_path / "source")
    snapshot = None
    try:
        with store._replay_source_snapshot_gate():
            snapshot = store._capture_replay_source_locked(terminal)
        _rename_and_unlink_source_paths(store)
        assert _decode_snapshot_records(snapshot) == _expected_record_literals()
    finally:
        if snapshot is not None:
            segments_module._close_replay_source_snapshot(snapshot)
        store.close()


def test_source_snapshot_revalidation_rejects_revision_or_descriptor_change(
    tmp_path: Path,
) -> None:
    coordinator, store, terminal = _build_file_backed_source(tmp_path / "source")
    snapshot = None
    try:
        with store._replay_source_snapshot_gate():
            snapshot = store._capture_replay_source_locked(terminal)
        _append_next_signed_record(coordinator)
        with (
            store._replay_source_snapshot_gate(),
            pytest.raises(ProjectionAuthorityError),
        ):
            store._revalidate_replay_source_locked(snapshot)
    finally:
        if snapshot is not None:
            segments_module._close_replay_source_snapshot(snapshot)
        store.close()


def test_source_snapshot_revalidation_rejects_real_descriptor_substitution(
    tmp_path: Path,
) -> None:
    _coordinator, store, terminal = _build_file_backed_source(tmp_path / "source")
    snapshot = None
    replacement_descriptor = -1
    owned_fds: tuple[int, ...] = ()
    try:
        with store._replay_source_snapshot_gate():
            snapshot = store._capture_replay_source_locked(terminal)
        owned_fds = tuple(segment.descriptor for segment in snapshot.segments)
        source_revision = snapshot.source_revision
        replacement_path = tmp_path / "different-source"
        replacement_path.write_bytes(b"not an AGF1 segment")
        replacement_descriptor = os.open(replacement_path, os.O_RDONLY)
        os.dup2(replacement_descriptor, snapshot.segments[0].descriptor)

        assert store._source_revision == source_revision
        with (
            store._replay_source_snapshot_gate(),
            pytest.raises(ProjectionAuthorityError),
        ):
            store._revalidate_replay_source_locked(snapshot)
    finally:
        if snapshot is not None:
            segments_module._close_replay_source_snapshot(snapshot)
        if replacement_descriptor >= 0:
            os.close(replacement_descriptor)
        store.close()
    assert _all_descriptor_fstats_fail_with_ebadf(
        (*owned_fds, replacement_descriptor)
    )


def test_partial_source_snapshot_failure_closes_every_owned_descriptor(
    tmp_path: Path,
) -> None:
    snapshot, owned_fds = _force_real_second_descriptor_failure(
        tmp_path / "source"
    )
    assert snapshot is None
    assert _all_descriptor_fstats_fail_with_ebadf(owned_fds)


def test_replay_reduction_returns_immutable_ordered_leaf_facts() -> None:
    result = _reduce_historical_coverage_result(**four_pcc_fixture())
    assert type(result) is _HistoricalReductionResult
    assert type(result.timeline.intersecting_intervals) is tuple
    assert type(result.timeline.coverage_event_ids) is tuple
    assert result.interval_count == len(result.timeline.intersecting_intervals)
    assert result.event_count == len(result.timeline.coverage_event_ids)
    assert len(result.assessment_digest) == 32
    assert len(result.interval_digest) == 32
    assert len(result.event_digest) == 32
    assert len(result.semantic_digest) == 32


def test_replay_reduction_reports_exact_admin_and_semantic_work_at_four_and_eight() -> None:
    four = _reduce_historical_coverage_result(**four_pcc_fixture())
    eight = _reduce_historical_coverage_result(**eight_pcc_fixture())
    no_prefix = _reduce_historical_coverage_result(**no_prefix_scan_pcc_fixture(4))
    assert no_prefix.diagnostics.semantic_prefix_visits == 4
    assert no_prefix.diagnostics.primary_checks == 4
    assert four.diagnostics.semantic_prefix_visits == 10
    assert four.diagnostics.primary_checks == 10
    assert eight.diagnostics.semantic_prefix_visits == 36
    assert eight.diagnostics.primary_checks == 36
    assert eight.diagnostics.prepared_records == 2 * four.diagnostics.prepared_records
    assert eight.diagnostics.leaf_materializations == 2 * four.diagnostics.leaf_materializations


def test_frozen_pcc_kernel_accepts_values_only_and_matches_live_result(
    tmp_path: Path,
) -> None:
    _authority_module, pcc_module = _correlation_modules()
    coordinator, proof = _accepted_complete(tmp_path / "frozen")
    context = _context(proof)
    try:
        expected = pcc_module._correlate_pcc_kernel(proof, context)
        frozen = pcc_module._freeze_pcc_correlation_input(proof, context)

        assert pcc_module._correlate_frozen_pcc(frozen) == expected
        assert tuple(
            field.name
            for field in fields(frozen)
            if callable(getattr(frozen, field.name))
        ) == ()
        assert pcc_module.authenticated_pcc_input_is_issued(frozen.proof) is False
        registry = frozen.context.special_use_registry
        assert type(registry) is ParsedSpecialUseRegistry
        assert not isinstance(registry, SpecialUseRegistry)
        assert special_use_registry_is_issued(registry) is False

        proof_value = frozen.proof_canonical.partition(b"\0")[2]
        context_value = frozen.context_canonical.partition(b"\0")[2]
        malformed = (
            (
                "proof_canonical",
                _mutated_canonical(
                    frozen.proof_canonical,
                    lambda value: value
                    == ["int", str(proof.source_sequence)],
                    ["bool", True],
                ),
            ),
            (
                "proof_canonical",
                _mutated_canonical(
                    frozen.proof_canonical,
                    lambda value: value
                    == ["int", str(proof.source_sequence)],
                    ["scalar-subclass", str(proof.source_sequence)],
                ),
            ),
            (
                "context_canonical",
                _mutated_canonical(
                    frozen.context_canonical,
                    lambda value: value == ["none"],
                    ["optional", "none"],
                ),
            ),
            (
                "context_canonical",
                _mutated_canonical(
                    frozen.context_canonical,
                    lambda value: value == ["str", _DETECTOR_HASH],
                    ["str", "3" * 64],
                ),
            ),
            (
                "context_canonical",
                _mutated_canonical(
                    frozen.context_canonical,
                    lambda value: value
                    == ["str", context.special_use_registry.entries[0].prefix],
                    ["str", "198.18.0.0/15"],
                ),
            ),
        )
        assert proof_value != context_value
        for field_name, canonical in malformed:
            arguments = {
                "proof_canonical": frozen.proof_canonical,
                "context_canonical": frozen.context_canonical,
            }
            arguments[field_name] = canonical
            with pytest.raises((TypeError, ValueError)):
                pcc_module._freeze_pcc_correlation_input(
                    proof,
                    context,
                    **arguments,
                )

        with pytest.raises(TypeError):
            pcc_module._freeze_pcc_correlation_input(
                frozen.proof,
                context,
            )
        with pytest.raises(TypeError):
            pcc_module._freeze_pcc_correlation_input(
                proof,
                frozen.context,
            )
    finally:
        coordinator.segment_store.close()

    failed_coordinator, failed_proof = _accepted_failed(
        tmp_path / "frozen-failed"
    )
    failed_context = pcc_module.CorrelationContext.failed_snapshot()
    try:
        expected_failed = pcc_module._correlate_pcc_kernel(
            failed_proof,
            failed_context,
        )
        frozen_failed = pcc_module._freeze_pcc_correlation_input(
            failed_proof,
            failed_context,
        )
        assert pcc_module._correlate_frozen_pcc(frozen_failed) == expected_failed
        assert frozen_failed.context.special_use_registry is None
    finally:
        failed_coordinator.segment_store.close()


def test_correlation_snapshot_rechecks_typed_predecessor_revision_and_pins(
    tmp_path: Path,
) -> None:
    authority_module, _pcc_module = _correlation_modules()
    _coordinator, store, terminal = _build_file_backed_source(
        tmp_path / "correlation"
    )
    issued = None
    try:
        issued, binding, expected = _build_registered_correlation_authority(
            store
        )
        with authority_module._correlation_projection_snapshot_gate(
            issued
        ) as held:
            assert held is binding
            snapshot = authority_module._capture_correlation_replay_locked(
                issued,
                held,
                expected,
            )
        assert type(snapshot.lifecycle_token) is bytes
        assert len(snapshot.lifecycle_token) == 32
        assert type(snapshot.predecessor_canonical) is bytes
        assert type(snapshot.registry_facts_canonical) is bytes
        assert tuple(
            field.name
            for field in fields(snapshot)
            if callable(getattr(snapshot, field.name))
        ) == ()

        successor = authority_module._ProjectionPredecessor(
            generation=0,
            host_id=HOST_ID,
            source_sequence=terminal.source_sequence,
            event_id=terminal.event_id,
            content_sha256=terminal.content_sha256,
            frame_sha256=terminal.frame_sha256,
        )
        authority_module._advance_correlation_projection_authority(
            issued,
            expected,
            successor,
        )
        with (
            authority_module._correlation_projection_snapshot_gate(
                issued
            ) as held,
            pytest.raises(CorrelationProjectionError),
        ):
            authority_module._revalidate_correlation_replay_locked(
                issued,
                held,
                snapshot,
            )
    finally:
        if issued is not None:
            _drop_registered_correlation_authority(issued)
        store.close()
