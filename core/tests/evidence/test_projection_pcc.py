from __future__ import annotations

import hashlib
import importlib
import os
import pickle
import sqlite3
import sys
from contextlib import contextmanager
from contextvars import copy_context
from copy import copy
from dataclasses import replace
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any, cast

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import RetentionTombstoneV2
from agmind_immune.correlation.pcc import CorrelationProjectionError
from agmind_immune.correlation.primitives import load_pinned_special_use_registry
from agmind_immune.evidence import retention as retention_module
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.projection import ProjectionAuthorityError
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    SegmentStore,
)
from agmind_immune.incidents.models import ContainmentCandidateV1
from agmind_immune.ingest.ack_journal import (
    AckIdentity,
    AckJournal,
    AckJournalSnapshot,
)
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import AuthenticatedPCCInput
from tests.correlation.test_pcc import (
    _accepted_complete,
    _accepted_direct_falco,
    _context,
)
from tests.correlation.test_pcc import (
    _resign as _resign_pcc_envelope,
)
from tests.coverage.test_historical import _counted_critical
from tests.coverage.test_state import (
    OTHER_HOST,
    T5,
    _falco_point,
    _gap_open,
    _generic_critical,
)
from tests.coverage.test_state import _reopen as _reopen_evidence
from tests.evidence.test_retention import (
    REQUEST_ID as RETENTION_REQUEST_ID,
)
from tests.evidence.test_retention import (
    _live_store_with_active_routine,
    _proof_clock,
    _retention_proof_case,
)
from tests.ingest.test_pcc_correlation_snapshot import (
    _accept,
    _candidate_trigger,
    _complete_snapshot,
    _coordinator,
    _failed_snapshot,
    _item,
    _request,
    _snapshot_envelope,
)
from tests.phase5b_helpers import (
    BOOT_A,
    BOOT_B,
    NOW,
    boot_boundary,
    envelope_value,
    private_key,
)

_REGISTRY_PATH = Path("contracts/v1/ipv4-special-use.csv")
_DETECTOR_HASH = "1" * 64
_BOOT_C = "423e4567-e89b-42d3-a456-426614174000"


class _EqualityLaunderedRef(EvidenceRef):
    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


class _NestedBombStr(str):
    def __eq__(self, other: object) -> bool:
        del other
        raise AssertionError("nested hostile equality executed")

    def __ne__(self, other: object) -> bool:
        del other
        raise AssertionError("nested hostile inequality executed")

    def __hash__(self) -> int:
        raise AssertionError("nested hostile hash executed")


class _Crash(RuntimeError):
    pass


class _CommitFailsBeforeDurable(sqlite3.Connection):
    fail_commit = False

    def execute(
        self,
        sql: str,
        parameters: tuple[object, ...] = (),
    ) -> sqlite3.Cursor:
        if self.fail_commit and sql == "COMMIT":
            raise sqlite3.OperationalError("injected pre-durable COMMIT failure")
        return super().execute(sql, parameters)


class _CloseFailsOnce(sqlite3.Connection):
    close_attempts = 0

    def close(self) -> None:
        self.close_attempts += 1
        if self.close_attempts == 1:
            raise OSError("injected first close failure")
        super().close()


def _subject() -> Any:
    return importlib.import_module("agmind_immune.evidence.projection_v2")


def _complete_journal(
    journal: CorrelationRequestJournal,
    proof: AuthenticatedPCCInput,
) -> None:
    store = journal._store
    trigger_ref = store._bound_verifier.accepted_ref(
        proof.snapshot.trigger.source_sequence
    )
    assert type(trigger_ref) is EvidenceRef
    selected = journal.select(trigger_ref, canonical_json(proof.request))
    snapshot_ref = cast(EvidenceRef, proof.evidence_ref)
    journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    journal.mark_completed(selected.request_sha256)


def _confirm_ack(journal: AckJournal, *refs: EvidenceRef) -> None:
    for ref in refs:
        journal.record_pending(ref)
        journal.record_confirmed(ref)


def _owner(
    subject: Any,
    coordinator: Any,
    journal: CorrelationRequestJournal,
    *,
    acknowledgements: AckJournal | None = None,
    registry: Any | None = None,
    step_hook: Any | None = None,
) -> tuple[Any, Any]:
    store = coordinator.segment_store
    if acknowledgements is None:
        acknowledgements = AckJournal.create_new(store)
        records = tuple(
            store.iter_authenticated_records(
                through=store.acceptance_cursor,
            )
        )
        _confirm_ack(
            acknowledgements,
            *[record.ref for record in records],
        )
    connection = subject._v2_connection_for_test()
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=(
            load_pinned_special_use_registry(_REGISTRY_PATH)
            if registry is None
            else registry
        ),
        step_hook=step_hook,
    )
    return owner, connection


def _accepted_failed_120(path: Path) -> tuple[Any, AuthenticatedPCCInput]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key)
    _accept(coordinator, trigger)
    request = _request(trigger, ttl_seconds=120)
    snapshot = _snapshot_envelope(
        key,
        _failed_snapshot(trigger, request),
    )
    proof = coordinator.accept_pcc_for_correlation(_item(snapshot), request)
    return coordinator, proof


def _accepted_two_complete(
    path: Path,
) -> tuple[Any, AuthenticatedPCCInput, AuthenticatedPCCInput]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))

    first_trigger = _candidate_trigger(key, sequence=2)
    _accept(coordinator, first_trigger)
    first_request = _request(first_trigger, ttl_seconds=120)
    first_snapshot = _snapshot_envelope(
        key,
        _complete_snapshot(first_trigger, first_request),
        sequence=3,
    )
    first = coordinator.accept_pcc_for_correlation(
        _item(first_snapshot),
        first_request,
    )

    _accept(coordinator, envelope_value(key, sequence=4))
    second_trigger = _candidate_trigger(key, sequence=5)
    _accept(coordinator, second_trigger)
    second_request = _request(second_trigger, ttl_seconds=120)
    second_fields = _complete_snapshot(second_trigger, second_request)
    second_fields["coverage_through_sequence"] = 5
    second_snapshot = _snapshot_envelope(
        key,
        second_fields,
        sequence=6,
    )
    second = coordinator.accept_pcc_for_correlation(
        _item(second_snapshot),
        second_request,
    )
    return coordinator, first, second


def _accepted_many_complete(
    path: Path,
    count: int,
) -> tuple[Any, tuple[AuthenticatedPCCInput, ...]]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    proofs: list[AuthenticatedPCCInput] = []
    sequence = 2
    for index in range(count):
        proofs.append(
            _append_unpublished_complete(
                coordinator,
                key,
                trigger_sequence=sequence,
                boot_id=BOOT_A,
                destination_ipv4=f"9.9.9.{index + 1}",
            )
        )
        sequence += 2
        if index + 1 < count:
            _accept(
                coordinator,
                _counted_critical(
                    sequence,
                    index + 1,
                    source_hash_digit=f"{index + 1:x}",
                ).envelope,
            )
            sequence += 1
    return coordinator, tuple(proofs)


def _accepted_two_complete_around_late_coverage(
    path: Path,
) -> tuple[Any, AuthenticatedPCCInput, EvidenceRef, AuthenticatedPCCInput]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))

    first_trigger = _candidate_trigger(key, sequence=2)
    _accept(coordinator, first_trigger)
    first_request = _request(first_trigger, ttl_seconds=120)
    first_snapshot = _snapshot_envelope(
        key,
        _complete_snapshot(first_trigger, first_request),
        sequence=3,
    )
    first = coordinator.accept_pcc_for_correlation(
        _item(first_snapshot),
        first_request,
    )

    coverage = _accept(
        coordinator,
        _generic_critical(
            key,
            4,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=NOW,
        ).envelope,
    )
    second_trigger = _candidate_trigger(key, sequence=5)
    second_fields = second_trigger["normalized_fields"]
    assert isinstance(second_fields, dict)
    second_fields["event_time"] = T5
    second_trigger["event_time"] = T5
    second_trigger["ingest_time"] = T5
    _resign_pcc_envelope(second_trigger, key)
    _accept(coordinator, second_trigger)
    second_request = _request(second_trigger, ttl_seconds=120)
    second_snapshot_fields = _complete_snapshot(second_trigger, second_request)
    second_snapshot_fields["coverage_through_sequence"] = 5
    second_snapshot_fields["decision_time"] = T5
    second_snapshot_fields["inventory_observed_at"] = T5
    second_snapshot = _snapshot_envelope(
        key,
        second_snapshot_fields,
        sequence=6,
    )
    second_snapshot["event_time"] = T5
    second_snapshot["ingest_time"] = T5
    _resign_pcc_envelope(second_snapshot, key)
    second = coordinator.accept_pcc_for_correlation(
        _item(second_snapshot),
        second_request,
    )
    return coordinator, first, coverage, second


def _accepted_three_complete_with_late_coverage(
    path: Path,
) -> tuple[Any, tuple[AuthenticatedPCCInput, ...], EvidenceRef]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    proofs: list[AuthenticatedPCCInput] = []
    destinations = ("8.8.8.8", "8.8.4.4", "1.1.1.1")
    for trigger_sequence, destination in zip((2, 4, 6), destinations, strict=True):
        trigger = _candidate_trigger(key, sequence=trigger_sequence)
        fields = trigger["normalized_fields"]
        assert isinstance(fields, dict)
        fields["destination_ipv4"] = destination
        _resign_pcc_envelope(trigger, key)
        _accept(coordinator, trigger)
        request = _request(trigger, ttl_seconds=120)
        snapshot_fields = _complete_snapshot(trigger, request)
        snapshot_fields["coverage_through_sequence"] = trigger_sequence
        snapshot = _snapshot_envelope(
            key,
            snapshot_fields,
            sequence=trigger_sequence + 1,
        )
        proofs.append(
            coordinator.accept_pcc_for_correlation(
                _item(snapshot),
                request,
            )
        )
    coverage = _accept(
        coordinator,
        _generic_critical(
            key,
            8,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=NOW,
        ).envelope,
    )
    return coordinator, tuple(proofs), coverage


def _accepted_complete_with_history(
    path: Path,
    *,
    history: str,
) -> tuple[Any, AuthenticatedPCCInput]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    trigger = _candidate_trigger(key, sequence=2)
    _accept(coordinator, trigger)
    request = _request(trigger, ttl_seconds=120)
    if history == "open-structural-gap":
        _accept(
            coordinator,
            _gap_open(
                key,
                5,
                start=3,
                end=4,
                opened_at=NOW,
            ).envelope,
        )
        snapshot_sequence = 6
    elif history == "closed-critical-episode":
        _accept(
            coordinator,
            _generic_critical(
                key,
                3,
                component="falco-adapter",
                kind="falco_heartbeat_gap",
                opened_at=NOW,
            ).envelope,
        )
        _accept(
            coordinator,
            _generic_critical(
                key,
                4,
                component="falco-adapter",
                kind="falco_heartbeat_gap",
                opened_at=NOW,
                closed_at=NOW,
            ).envelope,
        )
        snapshot_sequence = 5
    else:
        raise AssertionError("unknown historical fixture")
    fields = _complete_snapshot(trigger, request)
    fields["coverage_through_sequence"] = snapshot_sequence - 1
    snapshot = _snapshot_envelope(
        key,
        fields,
        sequence=snapshot_sequence,
    )
    proof = coordinator.accept_pcc_for_correlation(_item(snapshot), request)
    return coordinator, proof


def _append_unpublished_complete(
    coordinator: Any,
    key: Any,
    *,
    trigger_sequence: int,
    boot_id: str,
    destination_ipv4: str,
) -> AuthenticatedPCCInput:
    trigger = _candidate_trigger(
        key,
        sequence=trigger_sequence,
        boot_id=boot_id,
    )
    normalized = trigger["normalized_fields"]
    assert isinstance(normalized, dict)
    raw_sha256 = hashlib.sha256(
        f"unpublished-history-{trigger_sequence}".encode()
    ).hexdigest()
    normalized["destination_ipv4"] = destination_ipv4
    normalized["raw_event_sha256"] = raw_sha256
    trigger["source_payload_hash"] = raw_sha256
    _resign_pcc_envelope(trigger, key)
    _accept(coordinator, trigger)
    request = _request(trigger, ttl_seconds=120)
    fields = _complete_snapshot(trigger, request)
    fields["coverage_through_sequence"] = trigger_sequence
    snapshot = _snapshot_envelope(
        key,
        fields,
        sequence=trigger_sequence + 1,
        boot_id=boot_id,
    )
    return coordinator.accept_pcc_for_correlation(_item(snapshot), request)


def _accepted_unpublished_compact_history(
    path: Path,
) -> tuple[Any, tuple[AuthenticatedPCCInput, ...]]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    opened = _generic_critical(
        key,
        2,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=NOW,
    )
    replay = _generic_critical(
        key,
        3,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=NOW,
    )
    closed = _generic_critical(
        key,
        4,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=NOW,
        closed_at=NOW,
    )
    _accept(coordinator, opened.envelope)
    _accept(coordinator, replay.envelope)
    _accept(coordinator, closed.envelope)
    first = _append_unpublished_complete(
        coordinator,
        key,
        trigger_sequence=5,
        boot_id=BOOT_A,
        destination_ipv4="8.8.8.8",
    )
    _accept(
        coordinator,
        boot_boundary(
            key,
            sequence=7,
            boot_id=BOOT_B,
            previous_boot_id=BOOT_A,
            previous_source_sequence=6,
        ),
    )
    lease = _falco_point(
        key,
        8,
        kind="falco_heartbeat_lease",
        severity="INFO",
        at=NOW,
        reason="valid_heartbeat",
    ).envelope
    lease["boot_id"] = BOOT_B
    _resign_pcc_envelope(lease, key)
    _accept(coordinator, lease)
    second = _append_unpublished_complete(
        coordinator,
        key,
        trigger_sequence=9,
        boot_id=BOOT_B,
        destination_ipv4="1.1.1.1",
    )
    _accept(
        coordinator,
        boot_boundary(
            key,
            sequence=11,
            boot_id=_BOOT_C,
            previous_boot_id=BOOT_B,
            previous_source_sequence=10,
        ),
    )
    counted = (
        _counted_critical(12, 1).envelope,
        _counted_critical(13, 2, source_hash_digit="2").envelope,
        _counted_critical(
            14,
            2,
            closed_at=T5,
            source_hash_digit="3",
        ).envelope,
    )
    for event in counted:
        event["boot_id"] = _BOOT_C
        _resign_pcc_envelope(event, key)
        _accept(coordinator, event)
    third = _append_unpublished_complete(
        coordinator,
        key,
        trigger_sequence=15,
        boot_id=_BOOT_C,
        destination_ipv4="9.9.9.9",
    )
    return coordinator, (first, second, third)


def _accepted_unpublished_historical_conflict(
    path: Path,
    *,
    conflict: str,
) -> tuple[Any, AuthenticatedPCCInput]:
    key = private_key(11)
    coordinator = _coordinator(path, key)
    _accept(coordinator, boot_boundary(key))
    opened = _generic_critical(
        key,
        2,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=NOW,
    )
    closed = _generic_critical(
        key,
        3,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=NOW,
        closed_at=NOW,
    )
    _accept(coordinator, opened.envelope)
    _accept(coordinator, closed.envelope)
    if conflict == "second-close":
        terminal = _generic_critical(
            key,
            4,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=T5,
        ).envelope
    elif conflict == "reopen":
        terminal = _generic_critical(
            key,
            4,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
        ).envelope
        terminal["source_payload_hash"] = "c" * 64
        _resign_pcc_envelope(terminal, key)
    else:
        raise AssertionError("unknown historical conflict")
    _accept(coordinator, terminal)
    proof = _append_unpublished_complete(
        coordinator,
        key,
        trigger_sequence=5,
        boot_id=BOOT_A,
        destination_ipv4="8.8.4.4",
    )
    return coordinator, proof


def _unpublished_resources(
    coordinator: Any,
    proofs: tuple[AuthenticatedPCCInput, ...],
) -> tuple[
    Any,
    CorrelationRequestJournal,
    AckJournal,
    tuple[Any, ...],
]:
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    for proof in proofs:
        _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    return store, journal, acknowledgements, records


def _apply_all(owner: Any, coordinator: Any) -> None:
    for record in coordinator.segment_store.iter_authenticated_records():
        owner.apply(record.ref)


def _frozen_compute_pcc_input(
    proof: AuthenticatedPCCInput,
    records: tuple[Any, ...],
    *,
    foreign_active: bool = False,
) -> object:
    pcc = importlib.import_module("agmind_immune.correlation.pcc")
    historical = importlib.import_module("agmind_immune.coverage.historical")
    if proof.snapshot.outcome == "failed":
        return pcc._freeze_pcc_correlation_input(
            proof,
            pcc.CorrelationContext.failed_snapshot(),
        )
    entries = historical._build_frozen_replay_entries(
        records,
        tuple(historical._prepare_historical_record(record) for record in records),
    )
    compact = tuple(
        entry.record
        for entry in entries
        if entry.compact_member
        and entry.record.ref.source_sequence
        <= proof.snapshot.coverage_through_sequence
    )
    trigger = proof.snapshot.trigger
    reduction = historical._reduce_historical_coverage_result(
        compact,
        host_id=proof.host_id,
        boot_id=proof.boot_id,
        trigger_event_id=trigger.event_id,
        trigger_source_sequence=trigger.source_sequence,
        trigger_event_time=trigger.event_time,
        clock_uncertainty_ms=trigger.clock_uncertainty_ms,
        coverage_through_sequence=proof.snapshot.coverage_through_sequence,
        window_end=proof.snapshot.decision_time,
    )
    lookup_key = pcc._duplicate_key(proof, proof.snapshot)
    active = None
    if foreign_active:
        foreign_key = replace(lookup_key, host_id=OTHER_HOST)
        active = pcc.ActiveCandidateObservation(
            key=foreign_key,
            candidate_id="cand_" + "d" * 64,
            primary_source_sequence=1,
            primary_event_id="evt_" + "d" * 64,
        )
    context = pcc.CorrelationContext(
        pinned_detector_bundle_sha256=_DETECTOR_HASH,
        special_use_registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        coverage=reduction.timeline.assessment,
        lookup_key=lookup_key,
        active_duplicate=active,
    )
    return pcc._freeze_pcc_correlation_input(proof, context)


def _capture_compute_input(
    subject: Any,
    coordinator: Any,
    frozen_inputs: tuple[object, ...],
) -> tuple[object, dict[str, object]]:
    authority = importlib.import_module("agmind_immune.correlation.authority")
    store = coordinator.segment_store
    records = tuple(store.iter_authenticated_records())
    terminal = records[-1].ref
    acknowledgements = AckJournal.create_new(store)
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    source_snapshot = None
    ack_snapshot = None
    issued = None
    try:
        with store._replay_source_snapshot_gate():
            source_snapshot = store._capture_replay_source_locked(terminal)
        with acknowledgements._replay_ack_snapshot_gate():
            ack_snapshot = acknowledgements._capture_replay_ack_locked(
                terminal.source_sequence
            )
        predecessor = authority._ProjectionPredecessor(
            generation=1,
            host_id=None,
            source_sequence=0,
            event_id=None,
            content_sha256=None,
            frame_sha256=None,
        )
        registry = load_pinned_special_use_registry(_REGISTRY_PATH)
        issued = authority._issue_correlation_projection_authority(
            store,
            registry,
            predecessor,
            _DETECTOR_HASH,
            authority._registry_facts(registry),
        )
        binding = authority._authority_binding(issued)
        with authority._correlation_projection_snapshot_gate(issued) as held:
            assert held is binding
            correlation_snapshot = authority._capture_correlation_replay_locked(
                issued,
                held,
                predecessor,
            )
        snapshot = subject._ReplayInputSnapshot(
            source=source_snapshot,
            ack=ack_snapshot,
            correlation=correlation_snapshot,
            pcc_inputs=frozen_inputs,
            schema_domain=(
                b"AGMIND_PROJECTION_SCHEMA_V2\0"
                + Path("core/agmind_immune/evidence/schema_v2.sql").read_bytes()
            ),
            projection_generation=1,
        )
    except BaseException:
        if source_snapshot is not None:
            segments_module._close_replay_source_snapshot(source_snapshot)
        if ack_snapshot is not None:
            importlib.import_module(
                "agmind_immune.ingest.ack_journal"
            )._close_replay_ack_snapshot(ack_snapshot)
        if issued is not None:
            authority._close_correlation_projection_authority(issued)
        acknowledgements.close()
        store.close()
        raise
    authority._close_correlation_projection_authority(issued)
    return snapshot, {
        "source_snapshot": source_snapshot,
        "ack_snapshot": ack_snapshot,
        "acknowledgements": acknowledgements,
        "store": store,
    }


def _close_compute_input(resources: dict[str, object]) -> None:
    segments_module._close_replay_source_snapshot(resources["source_snapshot"])
    importlib.import_module(
        "agmind_immune.ingest.ack_journal"
    )._close_replay_ack_snapshot(resources["ack_snapshot"])
    resources["acknowledgements"].close()
    resources["store"].close()


def _with_conservative_sequence_gap(
    subject: Any,
    snapshot: object,
    resources: dict[str, object],
    path: Path,
    proof: AuthenticatedPCCInput,
    *,
    bind_ack_prefix: bool = True,
) -> object:
    frames = importlib.import_module("agmind_immune.evidence.frames")
    gap = _gap_open(
        private_key(11),
        4,
        start=proof.snapshot.trigger.source_sequence,
        end=proof.snapshot.trigger.source_sequence,
        opened_at=T5,
    )
    payload = canonical_json(
        {
            "schema_version": "agmind.accepted-envelope.v1",
            "evidence_priority": gap.priority.value,
            "accepted_at": gap.accepted_at,
            "outer": {
                "sequence": gap.ref.source_sequence,
                "event_id": gap.ref.event_id,
                "content_sha256": gap.ref.content_sha256,
            },
            "envelope": gap.envelope,
        }
    )
    frame = frames.encode_frame(
        payload,
        previous_hash=bytes(32),
        max_frame=segments_module.MAX_EVIDENCE_RECORD_BYTES,
    )
    framed = frames.decode_frames(
        frame,
        max_frame=segments_module.MAX_EVIDENCE_RECORD_BYTES,
    ).records[0]
    ref = replace(
        gap.ref,
        frame_offset=0,
        frame_size=len(frame),
        frame_sha256=framed.record_hash.hex(),
    )
    path.write_bytes(frame)
    descriptor = os.open(path, os.O_RDONLY)
    info = os.fstat(descriptor)
    source = snapshot.source
    source = replace(
        source,
        terminal_ref=ref,
        records=(
            *source.records,
            segments_module._ReplayRecordDescriptor(
                ref=ref,
                accepted_at=gap.accepted_at,
                canonical_record=payload,
                segment_index=len(source.segments),
            ),
        ),
        segments=(
            *source.segments,
            segments_module._ReplaySegmentDescriptor(
                descriptor=descriptor,
                device=info.st_dev,
                inode=info.st_ino,
                size=info.st_size,
                maximum_prefix_bytes=info.st_size,
                relative_path=ref.segment_relative_path,
            ),
        ),
    )
    ack = snapshot.ack
    if bind_ack_prefix:
        ack_module = importlib.import_module("agmind_immune.ingest.ack_journal")
        prefix = os.pread(ack.descriptor, ack.committed_prefix_size, 0)
        assert len(prefix) == ack.committed_prefix_size
        decoded_ack = frames.decode_frames(
            prefix,
            max_frame=ack_module._MAX_RECORD_BYTES,
        )
        assert not decoded_ack.torn_tail
        previous_hash = (
            bytes(32)
            if not decoded_ack.records
            else decoded_ack.records[-1].record_hash
        )
        appended: list[bytes] = []
        for kind in ("pending_ack", "confirmed_ack"):
            ack_payload = canonical_json(
                {
                    "schema_version": "agmind.core-ack-journal-record.v1",
                    "kind": kind,
                    "sequence": ref.source_sequence,
                    "event_id": ref.event_id,
                    "content_sha256": ref.content_sha256,
                }
            )
            ack_frame = frames.encode_frame(
                ack_payload,
                previous_hash=previous_hash,
                max_frame=ack_module._MAX_RECORD_BYTES,
            )
            previous_hash = ack_frame[-32:]
            appended.append(ack_frame)
        ack_bytes = prefix + b"".join(appended)
        ack_path = path.with_name(f"{path.stem}-ack.agf")
        ack_path.write_bytes(ack_bytes)
        ack_descriptor = os.open(ack_path, os.O_RDONLY)
        ack_info = os.fstat(ack_descriptor)
        os.close(ack.descriptor)
        ack = replace(
            ack,
            mutation_revision=ack.mutation_revision + 2,
            generation=ack.generation + 1,
            confirmed=(ref.source_sequence, ref.event_id, ref.content_sha256),
            pending=None,
            committed_prefix_size=len(ack_bytes),
            committed_prefix_sha256=hashlib.sha256(ack_bytes).digest(),
            descriptor=ack_descriptor,
            device=ack_info.st_dev,
            inode=ack_info.st_ino,
            size=ack_info.st_size,
        )
    else:
        ack = replace(
            ack,
            confirmed=(ref.source_sequence, ref.event_id, ref.content_sha256),
        )
    resources["source_snapshot"] = source
    resources["ack_snapshot"] = ack
    return replace(snapshot, source=source, ack=ack)


def test_compute_rejects_ack_tuple_not_bound_by_frozen_prefix(
    tmp_path: Path,
) -> None:
    subject = _subject()
    coordinator, proof = _accepted_complete(
        tmp_path / "unbound-ack-prefix",
        ttl_seconds=120,
    )
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    frozen_inputs = (_frozen_compute_pcc_input(proof, records),)
    snapshot, resources = _capture_compute_input(
        subject,
        coordinator,
        frozen_inputs,
    )
    snapshot = _with_conservative_sequence_gap(
        subject,
        snapshot,
        resources,
        tmp_path / "unbound-ack-prefix" / "conservative-gap.agf",
        proof,
        bind_ack_prefix=False,
    )
    try:
        with pytest.raises(ProjectionAuthorityError):
            subject._compute_replay(snapshot)
    finally:
        _close_compute_input(resources)


def test_compute_rejects_nested_pcc_fact_before_callback(
    tmp_path: Path,
) -> None:
    subject = _subject()
    coordinator, proof = _accepted_complete(
        tmp_path / "nested-pcc-fact",
        ttl_seconds=120,
    )
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    frozen = _frozen_compute_pcc_input(proof, records)
    hostile_proof = object.__new__(AuthenticatedPCCInput)
    for name in (
        "_boot_id",
        "_canonical",
        "_content_sha256",
        "_event_id",
        "_event_type",
        "_evidence_ref",
        "_host_id",
        "_request",
        "_snapshot",
        "_source_sequence",
    ):
        object.__setattr__(hostile_proof, name, getattr(frozen.proof, name))
    object.__setattr__(
        hostile_proof,
        "_event_id",
        _NestedBombStr(frozen.proof.event_id),
    )
    hostile_frozen = replace(frozen, proof=hostile_proof)
    snapshot, resources = _capture_compute_input(
        subject,
        coordinator,
        (hostile_frozen,),
    )
    try:
        with pytest.raises(TypeError):
            subject._compute_replay(snapshot)
    finally:
        _close_compute_input(resources)


@pytest.mark.parametrize(
    "case",
    (
        "direct-investigation",
        "safe-candidate",
        "failed-pcc",
        "compact-second-close",
        "compact-reopen",
        "late-critical",
        "different-host-observation",
        "sequence-range",
        "nonintersecting-window",
        "retry",
        "transport-duplicate",
    ),
)
def test_compute_projection_parity_scenarios(
    tmp_path: Path,
    case: str,
) -> None:
    subject = _subject()
    proof: AuthenticatedPCCInput | None = None
    foreign_active = False
    if case == "direct-investigation":
        coordinator, _authenticated = _accepted_direct_falco(
            tmp_path / case,
            investigation_only=True,
        )
    elif case == "failed-pcc":
        coordinator, proof = _accepted_failed_120(tmp_path / case)
    elif case.startswith("compact-"):
        conflict = case.removeprefix("compact-")
        coordinator, proof = _accepted_unpublished_historical_conflict(
            tmp_path / case,
            conflict=conflict,
        )
    else:
        coordinator, proof = _accepted_complete(
            tmp_path / case,
            ttl_seconds=120,
        )
        if case == "late-critical":
            _accept(
                coordinator,
                _generic_critical(
                    private_key(11),
                    4,
                    component="falco-adapter",
                    kind="falco_heartbeat_gap",
                    opened_at=NOW,
                    closed_at=NOW,
                ).envelope,
            )
        elif case == "different-host-observation":
            foreign_active = True
        elif case == "nonintersecting-window":
            _accept(
                coordinator,
                _generic_critical(
                    private_key(11),
                    4,
                    component="falco-adapter",
                    kind="falco_heartbeat_gap",
                    opened_at=T5,
                    closed_at=T5,
                ).envelope,
            )
        elif case == "transport-duplicate":
            for sequence in (4, 5):
                _accept(
                    coordinator,
                    _generic_critical(
                        private_key(11),
                        sequence,
                        component="falco-adapter",
                        kind="falco_heartbeat_gap",
                        opened_at=NOW,
                        closed_at=NOW,
                    ).envelope,
                )

    records = tuple(coordinator.segment_store.iter_authenticated_records())
    if proof is None:
        frozen_inputs: tuple[object, ...] = ()
    elif case.startswith("compact-"):
        pcc = importlib.import_module("agmind_immune.correlation.pcc")
        frozen_inputs = (
            pcc._freeze_pcc_correlation_input(proof, _context(proof)),
        )
    else:
        frozen_inputs = (
            _frozen_compute_pcc_input(
                proof,
                records,
                foreign_active=foreign_active,
            ),
        )
    snapshot, resources = _capture_compute_input(
        subject,
        coordinator,
        frozen_inputs,
    )
    if case == "sequence-range":
        assert proof is not None
        snapshot = _with_conservative_sequence_gap(
            subject,
            snapshot,
            resources,
            tmp_path / case / "conservative-gap.agf",
            proof,
        )
    try:
        if case.startswith("compact-"):
            with pytest.raises(subject.ProjectionConflict):
                subject._compute_replay(snapshot)
            return

        computation = subject._compute_replay(snapshot)
        if case == "retry":
            assert subject._compute_replay(snapshot) == computation
        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(computation.database_image)
            incident_kinds = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT result_kind FROM incidents ORDER BY incident_id"
                )
            )
            candidate_count = connection.execute(
                "SELECT count(*) FROM candidates"
            ).fetchone()[0]
            invalidation_count = connection.execute(
                "SELECT count(*) FROM candidate_invalidations"
            ).fetchone()[0]
            if case == "direct-investigation":
                assert (incident_kinds, candidate_count, invalidation_count) == (
                    ("investigation",),
                    0,
                    0,
                )
            elif case == "failed-pcc":
                assert (incident_kinds, candidate_count, invalidation_count) == (
                    ("rejected",),
                    0,
                    0,
                )
            else:
                assert incident_kinds == ("candidate",)
                assert candidate_count == 1
                expected_invalidations = (
                    1
                    if case
                    in {"late-critical", "sequence-range", "transport-duplicate"}
                    else 0
                )
                assert invalidation_count == expected_invalidations
                if case == "transport-duplicate":
                    duplicate_rows = connection.execute(
                        "SELECT count(*) FROM events "
                        "WHERE duplicate_of_event_id IS NOT NULL"
                    ).fetchone()[0]
                    assert duplicate_rows == 1
        finally:
            connection.close()
    finally:
        _close_compute_input(resources)


def _forge_later_logical_primary(
    connection: sqlite3.Connection,
    first: Any,
    second: Any,
) -> None:
    first_event_id = first.ref.event_id
    second_event_id = second.ref.event_id
    connection.execute(
        "UPDATE events SET duplicate_of_event_id=? WHERE event_id=?",
        (second_event_id, first_event_id),
    )
    connection.execute(
        "UPDATE events SET duplicate_of_event_id=NULL WHERE event_id=?",
        (second_event_id,),
    )
    connection.execute(
        "UPDATE projection_dedup SET primary_event_id=?,is_primary=0 "
        "WHERE event_id=?",
        (second_event_id, first_event_id),
    )
    connection.execute(
        "UPDATE projection_dedup SET primary_event_id=?,is_primary=1 "
        "WHERE event_id=?",
        (second_event_id, second_event_id),
    )
    for table in ("process_observations", "network_observations"):
        connection.execute(
            f"UPDATE {table} SET event_id=?,source_sequence=?,content_sha256=? "
            "WHERE event_id=?",
            (
                second_event_id,
                f"{second.ref.source_sequence:020d}",
                second.ref.content_sha256,
                first_event_id,
            ),
        )
    connection.execute(
        "UPDATE containers SET "
        "first_event_id=?,first_source_sequence=?,first_content_sha256=?,"
        "last_event_id=?,last_source_sequence=?,last_content_sha256=?",
        (
            second_event_id,
            f"{second.ref.source_sequence:020d}",
            second.ref.content_sha256,
            second_event_id,
            f"{second.ref.source_sequence:020d}",
            second.ref.content_sha256,
        ),
    )


def test_direct_investigation_incident_waits_only_for_no_pcc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, authenticated = _accepted_direct_falco(
        tmp_path / "evidence",
        investigation_only=True,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        _apply_all(owner, coordinator)
        rows = connection.execute(
            "SELECT result_kind,authority_event_id FROM incidents"
        ).fetchall()
        assert [tuple(row) for row in rows] == [
            ("investigation", authenticated.event_id)
        ]
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
    finally:
        owner.close()


def test_candidate_capable_falco_has_no_early_incident_then_failed_pcc_rejects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_failed_120(tmp_path / "evidence")
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        records = tuple(coordinator.segment_store.iter_authenticated_records())
        for record in records[:-1]:
            owner.apply(record.ref)
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0

        owner.apply(records[-1].ref)
        row = connection.execute(
            "SELECT result_kind,authority_event_id,reason_codes FROM incidents"
        ).fetchone()
        assert row is not None
        assert tuple(row) == (
            "rejected",
            proof.event_id,
            canonical_json(proof.snapshot.failure_reasons).decode("utf-8"),
        )
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
    finally:
        owner.close()


def test_completed_safe_pcc_persists_candidate_and_primary_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        _apply_all(owner, coordinator)
        incident = connection.execute(
            "SELECT result_kind,authority_event_id FROM incidents"
        ).fetchone()
        assert incident is not None
        assert tuple(incident) == ("candidate", proof.event_id)
        candidate = connection.execute(
            "SELECT candidate_id,primary_event_id,correlation_snapshot_event_id "
            "FROM candidates"
        ).fetchone()
        assert candidate is not None
        candidate_id = str(candidate["candidate_id"])
        assert tuple(candidate)[1:] == (
            proof.snapshot.trigger.event_id,
            proof.event_id,
        )
        evidence = connection.execute(
            "SELECT candidate_id,evidence_event_id,role,authority_snapshot_event_id "
            "FROM candidate_evidence ORDER BY role"
        ).fetchall()
        assert [tuple(row) for row in evidence] == [
            (
                candidate_id,
                proof.event_id,
                "correlation_snapshot",
                proof.event_id,
            ),
            (
                candidate_id,
                proof.snapshot.trigger.event_id,
                "primary_trigger",
                proof.event_id,
            ),
        ]
    finally:
        owner.close()


def test_late_critical_coverage_inclusively_invalidates_completed_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    coverage = _generic_critical(
        private_key(11),
        4,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=NOW,
        closed_at=NOW,
    ).envelope
    coverage_ref = _accept(coordinator, coverage)
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        _apply_all(owner, coordinator)

        candidate_id = connection.execute(
            "SELECT candidate_id FROM candidates"
        ).fetchone()[0]
        rows = connection.execute(
            "SELECT candidate_id,coverage_event_id,coverage_source_sequence,"
            "coverage_content_sha256,reason_code FROM candidate_invalidations"
        ).fetchall()
        assert [tuple(row) for row in rows] == [
            (
                candidate_id,
                coverage_ref.event_id,
                f"{coverage_ref.source_sequence:020d}",
                coverage_ref.content_sha256,
                "late_critical_coverage_gap",
            )
        ]
    finally:
        owner.close()


def test_fresh_unpublished_replay_reproduces_late_invalidation_rows_and_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    evidence_path = tmp_path / "evidence"
    coordinator, proof = _accepted_complete(evidence_path, ttl_seconds=120)
    coverage_ref = _accept(
        coordinator,
        _generic_critical(
            private_key(11),
            4,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=NOW,
        ).envelope,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    first_connection = subject._v2_connection_for_test()
    first_owner = subject._v2_projection_owner_for_test(
        first_connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    for record in records:
        first_owner.apply(record.ref)
    expected_rows = subject._v2_ordered_table_rows(
        first_connection,
        "candidate_invalidations",
    )
    expected_hash = first_owner.snapshot_hash()
    first_owner.close()

    _recovered_coordinator, recovered_store = _reopen_evidence(evidence_path)
    recovered_journal = CorrelationRequestJournal.open_and_recover(recovered_store)
    recovered_acknowledgements = AckJournal.open_and_recover(recovered_store)
    replay_owner, replay_connection, report = (
        subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=recovered_store,
            acknowledgements=recovered_acknowledgements,
            journal=recovered_journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=coverage_ref,
        )
    )
    try:
        assert report.cursor.source_sequence == coverage_ref.source_sequence
        assert subject._v2_ordered_table_rows(
            replay_connection,
            "candidate_invalidations",
        ) == expected_rows
        assert replay_owner.snapshot_hash() == expected_hash
    finally:
        replay_owner.close()


def test_unpublished_replay_uses_exact_compact_primary_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, stale_proofs = _accepted_unpublished_compact_history(
        tmp_path / "evidence"
    )
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        stale_proofs,
    )
    verifier = store._bound_verifier
    assert verifier is not None
    proofs = tuple(
        store._authenticated_pcc_input(
            verifier,
            cast(EvidenceRef, stale.evidence_ref),
            stale.request,
        )
        for stale in stale_proofs
    )
    full_assessments = {}
    for proof in proofs:
        path = store._historical_path_authority(proof)
        full_assessments[proof.event_id] = historical.derive_historical_coverage(
            proof,
            path,
        )
    assert full_assessments[proofs[0].event_id].coverage_snapshot_sha256 == (
        "37a68dcd759c369ff7f88db9d024e17c88ff95a6e7aee508639cc141923ae0d0"
    )
    assert full_assessments[proofs[1].event_id].coverage_snapshot_sha256 == (
        "e395ff4d61412ee74a43623e4bdc6c4c65edc5df1f6aa506d1c76c7904e47ef8"
    )
    assert full_assessments[proofs[2].event_id].coverage_snapshot_sha256 == (
        "5027ed17dc74a7f4b47495ae67ccf6cc3424a338222c6b8b91c5a04383d9350a"
    )
    real_reduce = historical._reduce_historical_coverage
    reduced_sequences: dict[str, list[tuple[int, ...]]] = {
        proof.snapshot.trigger.event_id: [] for proof in proofs
    }
    reduced_assessments: dict[str, list[object]] = {
        proof.snapshot.trigger.event_id: [] for proof in proofs
    }

    def capture_reduction(
        source_records: object,
        *args: object,
        **kwargs: object,
    ) -> object:
        selected = tuple(source_records)
        trigger_event_id = cast(str, kwargs["trigger_event_id"])
        result = real_reduce(selected, *args, **kwargs)
        if trigger_event_id in reduced_sequences:
            reduced_sequences[trigger_event_id].append(
                tuple(record.ref.source_sequence for record in selected)
            )
            reduced_assessments[trigger_event_id].append(result.assessment)
        return result

    monkeypatch.setattr(
        historical,
        "_reduce_historical_coverage",
        capture_reduction,
    )
    owner, connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[-1].ref,
    )
    try:
        assert report.cursor.source_sequence == records[-1].ref.source_sequence
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 3
        assert set(reduced_sequences[proofs[0].snapshot.trigger.event_id]) == {
            (1, 2, 4),
        }
        assert set(reduced_sequences[proofs[1].snapshot.trigger.event_id]) == {
            (1, 2, 4, 7, 8),
        }
        assert set(reduced_sequences[proofs[2].snapshot.trigger.event_id]) == {
            (1, 2, 4, 7, 8, 11, 12, 13, 14),
        }
        for proof in proofs:
            assert set(reduced_assessments[proof.snapshot.trigger.event_id]) == {
                full_assessments[proof.event_id]
            }
    finally:
        owner.close()


def test_frozen_replay_compact_selector_tracks_boot_transition_occurrences(
    tmp_path: Path,
) -> None:
    historical = importlib.import_module("agmind_immune.coverage.historical")
    coordinator, proofs = _accepted_unpublished_compact_history(
        tmp_path / "evidence"
    )
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        proofs,
    )
    try:
        prepared = [historical._prepare_historical_record(record) for record in records]
        return_index = 10
        prepared[return_index] = replace(
            prepared[return_index],
            envelope=prepared[return_index].envelope.model_copy(
                update={"boot_id": BOOT_A}
            ),
        )
        entries = historical._build_frozen_replay_entries(
            records,
            tuple(prepared),
        )
        compact_sequences = tuple(
            entry.record.ref.source_sequence
            for entry in entries
            if entry.compact_member
        )
        assert compact_sequences == (1, 2, 4, 7, 8, 11, 12, 13, 14)
    finally:
        store.close()
        journal.close()
        acknowledgements.close()


@pytest.mark.parametrize("conflict", ["second-close", "reopen"])
def test_unpublished_compact_history_preserves_prefix_conflicts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    conflict: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_unpublished_historical_conflict(
        tmp_path / conflict,
        conflict=conflict,
    )
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )

    assert artifact is None
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


def test_unpublished_historical_replay_is_linear_and_reduces_each_pcc_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counts = _measure_unpublished_historical_admin_work(
        tmp_path / "evidence",
        monkeypatch,
        2,
    )
    _assert_exact_unpublished_historical_admin_formulas(counts, 2)


def test_unpublished_historical_replay_retains_one_compact_ledger_without_prefix_copies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, stale_proofs = _accepted_unpublished_compact_history(
        tmp_path / "evidence"
    )
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        stale_proofs,
    )
    memo_leaves: dict[tuple[str, str], Any] = {}
    digest_visits: list[int] = []
    reducer_visits: list[int] = []
    final_snapshot: list[tuple[int, tuple[tuple[bool, bool, type, type], ...]]] = []
    real_memo_leaf = historical._build_replay_memo_leaf
    real_digest = historical._replay_compact_digest
    real_reduce = historical._reduce_historical_coverage
    real_final = subject._final_seal_replay_historical_session

    def capture_memo_leaf(*args: object, **kwargs: object) -> Any:
        leaf = real_memo_leaf(*args, **kwargs)
        memo_leaves.setdefault(leaf.key, leaf)
        return leaf

    def count_digest(records_value: object) -> object:
        selected = tuple(cast(Any, records_value))
        digest_visits.append(len(selected))
        return real_digest(selected)

    def count_reduce(records_value: object, *args: object, **kwargs: object) -> object:
        selected = tuple(cast(Any, records_value))
        reducer_visits.append(len(selected))
        return real_reduce(selected, *args, **kwargs)

    def capture_final(handle: Any, callback: Any) -> None:
        final_snapshot.append(
            (
                max(leaf.compact_count for leaf in memo_leaves.values()),
                tuple(
                    (
                        hasattr(leaf, "compact_records"),
                        hasattr(leaf, "compact_prepared"),
                        type(leaf.compact_count),
                        type(leaf.compact_digest),
                    )
                    for leaf in memo_leaves.values()
                ),
            )
        )
        real_final(handle, callback)

    monkeypatch.setattr(historical, "_build_replay_memo_leaf", capture_memo_leaf)
    monkeypatch.setattr(historical, "_replay_compact_digest", count_digest)
    monkeypatch.setattr(historical, "_reduce_historical_coverage", count_reduce)
    monkeypatch.setattr(subject, "_final_seal_replay_historical_session", capture_final)
    owner, _connection, report = (
        subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    )
    try:
        assert report.cursor.source_sequence == records[-1].ref.source_sequence
        assert len(memo_leaves) == len(stale_proofs)
        compact_count, memo_shapes = final_snapshot[0]
        assert len(reducer_visits) == 2 * len(stale_proofs)
        assert sum(reducer_visits) > compact_count
        assert digest_visits == []
        assert memo_shapes == ((False, False, int, str),) * len(stale_proofs)
    finally:
        owner.close()


def _measure_unpublished_historical_admin_work(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    pcc_count: int,
) -> dict[str, int]:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proofs = _accepted_many_complete(root, pcc_count)
    store, journal, acknowledgements, records = _unpublished_resources(coordinator, proofs)
    prepare_calls = 0
    digest_updates = 0
    reduction_calls = 0
    reducer_element_visits = 0
    projecting_record_appends = 0
    projecting_prepared_appends = 0
    validation_record_appends = 0
    validation_prepared_appends = 0
    boundary_validations = 0
    final_counts: list[tuple[int, int, int]] = []
    memo_leaves: dict[tuple[str, str], Any] = {}
    real_prepare = historical._prepare_historical_record
    real_update = historical._update_replay_compact_digest
    real_reduce = historical._reduce_historical_coverage
    real_ledger_init = historical._ReplayLedger.__init__
    real_ledger_append = historical._ReplayLedger.append
    real_memo_leaf = historical._build_replay_memo_leaf
    real_validation_visit = historical._replay_validation_compact_visit
    real_validate_boundary = historical._validate_replay_compact_boundary
    real_final = subject._final_seal_replay_historical_session
    real_scope = subject._replay_historical_session
    real_begin_validation = subject._begin_replay_historical_validation
    projecting_ledgers: list[Any] = []
    counting_source = False

    def count_prepare(record: object) -> object:
        nonlocal prepare_calls
        if counting_source:
            prepare_calls += 1
        return real_prepare(record)

    @contextmanager
    def count_initial_source(*args: object, **kwargs: object) -> Any:
        nonlocal counting_source
        counting_source = True
        try:
            with real_scope(*args, **kwargs) as handle:
                counting_source = False
                yield handle
        finally:
            counting_source = False

    def count_validation_source(handle: Any) -> None:
        nonlocal counting_source
        counting_source = True
        try:
            real_begin_validation(handle)
        finally:
            counting_source = False

    def count_ledger_init(ledger: Any) -> None:
        real_ledger_init(ledger)
        if len(projecting_ledgers) < 2:
            projecting_ledgers.append(ledger)

    def count_ledger_append(ledger: Any, value: object) -> None:
        nonlocal projecting_record_appends
        nonlocal projecting_prepared_appends
        nonlocal validation_record_appends
        nonlocal validation_prepared_appends
        if projecting_ledgers and ledger is projecting_ledgers[0]:
            projecting_record_appends += 1
        elif projecting_ledgers and ledger is projecting_ledgers[1]:
            projecting_prepared_appends += 1
        real_ledger_append(ledger, value)

    def count_validation_visit(kind: str) -> None:
        nonlocal validation_prepared_appends, validation_record_appends
        if kind == "record":
            validation_record_appends += 1
        elif kind == "prepared":
            validation_prepared_appends += 1
        real_validation_visit(kind)

    def capture_memo_leaf(*args: object, **kwargs: object) -> Any:
        leaf = real_memo_leaf(*args, **kwargs)
        memo_leaves.setdefault(leaf.key, leaf)
        return leaf

    def count_update(previous: str, record: object) -> str:
        nonlocal digest_updates
        digest_updates += 1
        return real_update(previous, record)

    def count_boundary(*args: object, **kwargs: object) -> None:
        nonlocal boundary_validations
        boundary_validations += 1
        real_validate_boundary(*args, **kwargs)

    def count_reduce(
        source_records: object,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal reducer_element_visits, reduction_calls
        reduction_calls += 1
        reducer_element_visits += len(cast(Any, source_records))
        return real_reduce(source_records, *args, **kwargs)

    def capture_final(handle: Any, callback: Any) -> None:
        compact_count = max(leaf.compact_count for leaf in memo_leaves.values())
        final_counts.append(
            (compact_count, len(memo_leaves), 0)
        )
        real_final(handle, callback)

    monkeypatch.setattr(historical, "_prepare_historical_record", count_prepare)
    monkeypatch.setattr(historical._ReplayLedger, "__init__", count_ledger_init)
    monkeypatch.setattr(historical._ReplayLedger, "append", count_ledger_append)
    monkeypatch.setattr(subject, "_replay_historical_session", count_initial_source)
    monkeypatch.setattr(
        subject,
        "_begin_replay_historical_validation",
        count_validation_source,
    )
    monkeypatch.setattr(historical, "_build_replay_memo_leaf", capture_memo_leaf)
    monkeypatch.setattr(
        historical,
        "_replay_validation_compact_visit",
        count_validation_visit,
    )
    monkeypatch.setattr(historical, "_update_replay_compact_digest", count_update)
    monkeypatch.setattr(historical, "_validate_replay_compact_boundary", count_boundary)
    monkeypatch.setattr(historical, "_reduce_historical_coverage", count_reduce)
    monkeypatch.setattr(subject, "_final_seal_replay_historical_session", capture_final)
    owner, _connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[-1].ref,
    )
    owner.close()
    compact_count, memo_count, stored_prefixes = final_counts[0]
    return {
        "records": len(records),
        "applied": report.applied_count,
        "source_preparations": prepare_calls,
        "projecting_record_appends": projecting_record_appends,
        "projecting_prepared_appends": projecting_prepared_appends,
        "validation_record_appends": validation_record_appends,
        "validation_prepared_appends": validation_prepared_appends,
        "digest_visits": digest_updates,
        "boundary_validations": boundary_validations,
        "compact_count": compact_count,
        "memo_count": memo_count,
        "reducer_calls": reduction_calls,
        "reducer_element_visits": reducer_element_visits,
        "stored_prefixes": stored_prefixes,
    }


def _assert_exact_unpublished_historical_admin_formulas(
    counts: dict[str, int],
    pcc_count: int,
) -> None:
    record_count = 3 * pcc_count
    compact_count = pcc_count
    assert counts == {
        "records": record_count,
        "applied": record_count,
        "source_preparations": 2 * record_count,
        "projecting_record_appends": compact_count,
        "projecting_prepared_appends": compact_count,
        "validation_record_appends": compact_count,
        "validation_prepared_appends": compact_count,
        "digest_visits": 2 * compact_count,
        "boundary_validations": pcc_count,
        "compact_count": compact_count,
        "memo_count": pcc_count,
        "reducer_calls": 2 * pcc_count,
        "reducer_element_visits": pcc_count * (pcc_count + 1),
        "stored_prefixes": 0,
    }


@pytest.mark.parametrize("pcc_count", [4, 8])
def test_unpublished_historical_admin_work_scales_linearly_on_alternating_trace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pcc_count: int,
) -> None:
    counts = _measure_unpublished_historical_admin_work(
        tmp_path / str(pcc_count),
        monkeypatch,
        pcc_count,
    )
    _assert_exact_unpublished_historical_admin_formulas(counts, pcc_count)


def test_unpublished_historical_admin_counters_scale_directly_from_four_to_eight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as four_patch:
        four = _measure_unpublished_historical_admin_work(
            tmp_path / "four",
            four_patch,
            4,
        )
    with monkeypatch.context() as eight_patch:
        eight = _measure_unpublished_historical_admin_work(
            tmp_path / "eight",
            eight_patch,
            8,
        )
    _assert_exact_unpublished_historical_admin_formulas(four, 4)
    _assert_exact_unpublished_historical_admin_formulas(eight, 8)
    administrative_counters = (
        "records",
        "applied",
        "source_preparations",
        "projecting_record_appends",
        "projecting_prepared_appends",
        "validation_record_appends",
        "validation_prepared_appends",
        "digest_visits",
        "boundary_validations",
        "compact_count",
        "memo_count",
        "reducer_calls",
        "stored_prefixes",
    )
    assert all(eight[key] <= 2 * four[key] for key in administrative_counters)
    assert eight["reducer_element_visits"] == 72
    assert four["reducer_element_visits"] == 20


@pytest.mark.parametrize("fail_at", [None, 2], ids=["success", "failure"])
def test_unpublished_multi_batch_sealing_uses_linear_prefix_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_at: int | None,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    monkeypatch.setattr(subject, "_UNPUBLISHED_PCC_CHUNK", 1)
    coordinator, proofs = _accepted_many_complete(tmp_path / "evidence", 4)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        proofs,
    )
    real_issue = subject._issue_completed_snapshot_batch
    real_seal = subject._seal_completed_snapshot_batch
    real_revoke = subject._revoke_completed_snapshot_batch
    issued: list[object] = []
    batch_indexes: dict[int, int] = {}
    seal_indexes: list[int] = []
    revoke_indexes: list[int] = []
    remove_calls = 0

    def capture_issue(*args: object, **kwargs: object) -> object:
        batch = real_issue(*args, **kwargs)
        batch_indexes[id(batch)] = len(issued)
        issued.append(batch)
        return batch

    def capture_seal(batch: object) -> None:
        index = batch_indexes[id(batch)]
        seal_indexes.append(index)
        if index == fail_at:
            raise _Crash("injected batch seal failure")
        real_seal(batch)

    def capture_revoke(batch: object) -> None:
        revoke_indexes.append(batch_indexes[id(batch)])
        real_revoke(batch)

    def profile(frame: Any, event: str, argument: object) -> None:
        nonlocal remove_calls
        if (
            event == "c_call"
            and frame.f_code.co_name == "_replay_unpublished_prefix"
            and getattr(argument, "__name__", None) == "remove"
            and isinstance(getattr(argument, "__self__", None), list)
        ):
            remove_calls += 1

    monkeypatch.setattr(subject, "_issue_completed_snapshot_batch", capture_issue)
    monkeypatch.setattr(subject, "_seal_completed_snapshot_batch", capture_seal)
    monkeypatch.setattr(subject, "_revoke_completed_snapshot_batch", capture_revoke)
    artifact: tuple[Any, Any, Any] | None = None
    previous_profile = sys.getprofile()
    try:
        sys.setprofile(profile)
        if fail_at is None:
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                through=records[-1].ref,
            )
        else:
            with pytest.raises(_Crash, match="injected batch seal failure"):
                subject._v2_unpublished_projection_from_prefix_for_test(
                    evidence=store,
                    acknowledgements=acknowledgements,
                    journal=journal,
                    registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                    through=records[-1].ref,
                )
    finally:
        sys.setprofile(previous_profile)

    assert len(issued) == 4
    assert remove_calls == 0
    if fail_at is None:
        assert seal_indexes == [0, 1, 2, 3]
        assert revoke_indexes == []
        assert artifact is not None
        artifact[0].close()
    else:
        assert seal_indexes == [0, 1, 2]
        assert revoke_indexes == [2, 3]
        assert artifact is None
        assert store._closed is True


def test_unpublished_historical_memo_revalidation_drift_returns_no_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    real_revalidate = authority._derive_replay_historical_coverage
    validations = 0

    def drift_between_live_validations(*args: object, **kwargs: object) -> object:
        nonlocal validations
        validations += 1
        if validations == 2:
            raise historical.HistoricalCoverageUnavailable(
                "injected live memo authority drift"
            )
        return real_revalidate(*args, **kwargs)

    monkeypatch.setattr(
        authority,
        "_derive_replay_historical_coverage",
        drift_between_live_validations,
    )
    artifact: object | None = None
    with pytest.raises(
        ProjectionAuthorityError,
        match="PCC authority could not be revalidated",
    ) as raised:
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )

    causes: list[BaseException] = []
    cause = raised.value.__cause__
    while cause is not None:
        causes.append(cause)
        cause = cause.__cause__
    assert any(
        isinstance(item, historical.HistoricalCoverageUnavailable)
        and str(item) == "injected live memo authority drift"
        for item in causes
    )
    assert validations == 2
    assert artifact is None
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


def test_unpublished_historical_dispatch_denies_cross_context_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    outer_coordinator, outer_stale = _accepted_complete(
        tmp_path / "outer",
        ttl_seconds=120,
    )
    outer_store, outer_journal, outer_ack, outer_records = _unpublished_resources(
        outer_coordinator,
        (outer_stale,),
    )
    outer_verifier = outer_store._bound_verifier
    assert outer_verifier is not None
    outer_proof = outer_store._authenticated_pcc_input(
        outer_verifier,
        cast(EvidenceRef, outer_stale.evidence_ref),
        outer_stale.request,
    )
    inner_coordinator, inner_stale = _accepted_complete(
        tmp_path / "inner",
        ttl_seconds=120,
    )
    inner_store, inner_journal, inner_ack, inner_records = _unpublished_resources(
        inner_coordinator,
        (inner_stale,),
    )
    inner_verifier = inner_store._bound_verifier
    assert inner_verifier is not None
    inner_proof = inner_store._authenticated_pcc_input(
        inner_verifier,
        cast(EvidenceRef, inner_stale.evidence_ref),
        inner_stale.request,
    )
    denials: dict[str, bool] = {}
    copied_active_context: object | None = None
    exercised = False

    def records_denial(name: str, operation: Any) -> None:
        try:
            operation()
        except historical.HistoricalCoverageUnavailable:
            denials[name] = True
        else:
            denials[name] = False

    def exercise_dispatch(step: str) -> None:
        nonlocal copied_active_context, exercised
        if step != "candidate" or exercised:
            return
        exercised = True
        copied_active_context = copy_context()

        without_context = Thread(
            target=lambda: records_denial(
                "same_store_without_context",
                lambda: outer_store._historical_path_authority(outer_proof),
            )
        )
        without_context.start()
        without_context.join()

        copied = copy_context()
        copied_thread = Thread(
            target=lambda: copied.run(
                records_denial,
                "same_store_wrong_thread",
                lambda: outer_store._historical_path_authority(outer_proof),
            )
        )
        copied_thread.start()
        copied_thread.join()

        records_denial(
            "foreign_store",
            lambda: inner_store._historical_path_authority(inner_proof),
        )
        records_denial(
            "same_store_same_thread_without_access",
            lambda: outer_store._historical_path_authority(outer_proof),
        )
        try:
            nested_owner, _nested_connection, _nested_report = (
                subject._v2_unpublished_projection_from_prefix_for_test(
                    evidence=inner_store,
                    acknowledgements=inner_ack,
                    journal=inner_journal,
                    registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                    through=inner_records[-1].ref,
                )
            )
        except ProjectionAuthorityError:
            denials["nested_factory"] = True
        else:
            denials["nested_factory"] = False
            nested_owner.close()

    owner, _connection, report = (
        subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=outer_store,
            acknowledgements=outer_ack,
            journal=outer_journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=outer_records[-1].ref,
            step_hook=exercise_dispatch,
        )
    )
    owner.close()
    assert report.cursor.source_sequence == outer_records[-1].ref.source_sequence
    assert copied_active_context is not None

    revoked_context = cast(Any, copied_active_context)
    revoked_thread = Thread(
        target=lambda: revoked_context.run(
            records_denial,
            "revoked_context",
            lambda: outer_store._historical_path_authority(outer_proof),
        )
    )
    revoked_thread.start()
    revoked_thread.join()
    assert denials == {
        "same_store_without_context": True,
        "same_store_wrong_thread": True,
        "same_store_same_thread_without_access": True,
        "foreign_store": True,
        "nested_factory": True,
        "revoked_context": True,
    }


def test_unpublished_replay_denies_preissued_slow_path_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, stale = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (stale,),
    )
    verifier = store._bound_verifier
    assert verifier is not None
    proof = store._authenticated_pcc_input(
        verifier,
        cast(EvidenceRef, stale.evidence_ref),
        stale.request,
    )
    preissued = store._historical_path_authority(proof)
    checked = False
    denied = False

    def reuse_slow_path_during_replay(step: str) -> None:
        nonlocal checked, denied
        if step != "candidate" or checked:
            return
        checked = True
        try:
            historical.derive_historical_coverage(proof, preissued)
        except historical.HistoricalCoverageUnavailable:
            denied = True

    owner, _connection, report = (
        subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
            step_hook=reuse_slow_path_during_replay,
        )
    )
    try:
        assert report.cursor.source_sequence == records[-1].ref.source_sequence
        assert checked is True
        assert denied is True
    finally:
        owner.close()


def test_slow_path_binding_finishes_before_replay_activation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, stale = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (stale,),
    )
    verifier = store._bound_verifier
    assert verifier is not None
    proof = store._authenticated_pcc_input(
        verifier,
        cast(EvidenceRef, stale.evidence_ref),
        stale.request,
    )
    binding_entered = Event()
    release_binding = Event()
    activation_started = Event()
    activation_completed = Event()
    failures: list[BaseException] = []
    real_new_binding = historical._new_path_binding
    real_scope = subject._replay_historical_session

    def block_slow_binding(candidate_store: Any, authenticated: Any) -> Any:
        if candidate_store is store and not binding_entered.is_set():
            binding_entered.set()
            if not release_binding.wait(5):
                raise AssertionError("slow binding release timed out")
        return real_new_binding(candidate_store, authenticated)

    @contextmanager
    def observe_activation(*args: object, **kwargs: object) -> Any:
        activation_started.set()
        with real_scope(*args, **kwargs) as handle:
            activation_completed.set()
            yield handle

    monkeypatch.setattr(historical, "_new_path_binding", block_slow_binding)
    monkeypatch.setattr(
        subject,
        "_replay_historical_session",
        observe_activation,
    )

    def issue_slow() -> None:
        try:
            store._historical_path_authority(proof)
        except BaseException as error:  # noqa: BLE001 - relayed to test thread
            failures.append(error)

    def build_replay() -> None:
        try:
            owner, _connection, _report = (
                subject._v2_unpublished_projection_from_prefix_for_test(
                    evidence=store,
                    acknowledgements=acknowledgements,
                    journal=journal,
                    registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                    through=records[-1].ref,
                )
            )
            owner.close()
        except BaseException as error:  # noqa: BLE001 - relayed to test thread
            failures.append(error)

    slow_thread = Thread(target=issue_slow)
    replay_thread = Thread(target=build_replay)
    slow_thread.start()
    assert binding_entered.wait(5)
    replay_thread.start()
    assert activation_started.wait(5)
    activation_overtook_binding = activation_completed.wait(1)
    release_binding.set()
    slow_thread.join(5)
    replay_thread.join(5)
    assert slow_thread.is_alive() is False
    assert replay_thread.is_alive() is False
    assert failures == []
    assert activation_overtook_binding is False


def test_registered_revoked_replay_denies_slow_path_until_atomic_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, stale = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (stale,),
    )
    verifier = store._bound_verifier
    assert verifier is not None
    proof = store._authenticated_pcc_input(
        verifier,
        cast(EvidenceRef, stale.evidence_ref),
        stale.request,
    )
    revoke_entered = Event()
    release_revoke = Event()
    real_cleanup_checkpoint = historical._replay_cleanup_checkpoint

    def block_after_revoke(stage: str) -> None:
        real_cleanup_checkpoint(stage)
        if stage != "broker-revoked":
            return
        revoke_entered.set()
        if not release_revoke.wait(5):
            raise AssertionError("session revoke release timed out")

    monkeypatch.setattr(
        historical,
        "_replay_cleanup_checkpoint",
        block_after_revoke,
    )
    failures: list[BaseException] = []

    def build_replay() -> None:
        try:
            owner, _connection, _report = (
                subject._v2_unpublished_projection_from_prefix_for_test(
                    evidence=store,
                    acknowledgements=acknowledgements,
                    journal=journal,
                    registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                    through=records[-1].ref,
                )
            )
            owner.close()
        except BaseException as error:  # noqa: BLE001 - relayed to test thread
            failures.append(error)

    replay_thread = Thread(target=build_replay)
    replay_thread.start()
    assert revoke_entered.wait(5)
    denied = False
    try:
        store._historical_path_authority(proof)
    except historical.HistoricalCoverageUnavailable:
        denied = True
    finally:
        release_revoke.set()
    replay_thread.join(5)
    assert replay_thread.is_alive() is False
    assert failures == []
    assert denied is True


def test_projecting_path_is_event_scoped_and_rejects_copied_context_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, first, second = _accepted_two_complete(tmp_path / "evidence")
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (first, second),
    )
    captured: list[tuple[AuthenticatedPCCInput, object]] = []
    real_issue = historical._issue_replay_historical_path_authority

    def capture_production_path(
        candidate_store: Any,
        authenticated: AuthenticatedPCCInput,
        access: object,
    ) -> object:
        path = real_issue(candidate_store, authenticated, access)
        if (
            candidate_store is store
            and authenticated.event_id == first.event_id
            and not captured
        ):
            captured.append((authenticated, path))
        return path

    monkeypatch.setattr(
        historical,
        "_issue_replay_historical_path_authority",
        capture_production_path,
    )
    monkeypatch.setattr(
        subject,
        "_issue_replay_historical_path_authority",
        capture_production_path,
    )
    copied_context_denied = False
    copied_helper_issue_denied = False
    copied_helper_derive_denied = False
    disclosed_accesses: list[object] = []
    stale_event_denied = False
    stale_path_unregistered = False
    first_candidate_seen = False

    def probe_path_epoch(step: str) -> None:
        nonlocal copied_context_denied, copied_helper_derive_denied
        nonlocal copied_helper_issue_denied, stale_event_denied
        nonlocal stale_path_unregistered
        nonlocal first_candidate_seen
        if step == "candidate" and not first_candidate_seen:
            first_candidate_seen = True
            assert captured
            proof, path = captured[0]
            copied = copy_context()
            binding = cast(Any, path)._binding
            context_value = historical._ACTIVE_REPLAY_MARKER.get()
            reachable = [
                getattr(binding, "access", None),
                getattr(context_value, "access", None),
                getattr(store, "_historical_replay_access", None),
            ]
            path_nonce = getattr(binding, "access_nonce", None)
            for module_value in vars(historical).values():
                try:
                    registry_items = tuple(module_value.items())
                except (AttributeError, RuntimeError, TypeError):
                    continue
                for registry_key, registry_value in registry_items:
                    if (
                        type(registry_key) is historical._ReplayAccess
                        and getattr(registry_value, "nonce", None) is path_nonce
                    ):
                        reachable.append(registry_key)
            disclosed_accesses.extend(
                value
                for value in reachable
                if type(value) is historical._ReplayAccess
            )
            leaked_access = disclosed_accesses[0] if disclosed_accesses else None
            try:
                copied.run(
                    historical.derive_historical_coverage,
                    proof,
                    path,
                )
            except historical.HistoricalCoverageUnavailable:
                copied_context_denied = True
            try:
                copied.run(
                    historical._issue_replay_historical_path_authority,
                    store,
                    proof,
                    leaked_access,
                )
            except historical.HistoricalCoverageUnavailable:
                copied_helper_issue_denied = True
            try:
                copied.run(
                    historical._derive_replay_historical_coverage,
                    proof,
                    path,
                    leaked_access,
                )
            except historical.HistoricalCoverageUnavailable:
                copied_helper_derive_denied = True
            return
        if step == "event" and first_candidate_seen and not stale_event_denied:
            proof, path = captured[0]
            stale_path_unregistered = path not in historical._ISSUED_PATHS
            try:
                historical.derive_historical_coverage(proof, path)
            except historical.HistoricalCoverageUnavailable:
                stale_event_denied = True

    owner, _connection, report = (
        subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
            step_hook=probe_path_epoch,
        )
    )
    try:
        assert report.cursor.source_sequence == records[-1].ref.source_sequence
        assert copied_context_denied is True
        assert copied_helper_issue_denied is True
        assert copied_helper_derive_denied is True
        assert disclosed_accesses == []
        assert stale_event_denied is True
        assert stale_path_unregistered is True
    finally:
        owner.close()


def test_enumerable_module_state_cannot_construct_or_drive_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(tmp_path / "enumerable", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    forged_authority_obtained = False
    probed = False

    def probe_enumerable_state(step: str) -> None:
        nonlocal forged_authority_obtained, probed
        if step != "candidate" or probed:
            return
        probed = True
        module_state = vars(historical)
        session_type = module_state.get("_ReplayHistoricalSession")
        factory = module_state.get("_REPLAY_SESSION_FACTORY")
        if not isinstance(session_type, type) or factory is None:
            return
        forged = object.__new__(session_type)
        try:
            forged.__init__(store, records[-1].ref, _factory=factory)
            for entry in forged.entries:
                token = forged.begin_event(entry.record.ref)
                if entry.record.ref is proof.evidence_ref:
                    replay_path = forged.issue(proof)
                    assessment = forged.reduce(replay_path)
                    forged.validate_binding(replay_path)
                    forged_authority_obtained = (
                        assessment.host_id == proof.host_id
                        and assessment.trigger_source_sequence
                        == proof.snapshot.trigger.source_sequence
                    )
                forged.compare_primary(
                    token,
                    entry.record.ref,
                    entry.expected_primary,
                )
                forged.begin_commit(token, entry.record.ref)
                forged.complete_event(token)
        finally:
            forged.revoke()

    owner, _connection, report = (
        subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
            step_hook=probe_enumerable_state,
        )
    )
    try:
        assert report.cursor.source_sequence == records[-1].ref.source_sequence
        assert probed is True
        assert forged_authority_obtained is False
    finally:
        owner.close()


def test_terminal_callback_cannot_open_fresh_replay_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "terminal-access", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    handles: list[Any] = []
    validation_proofs: list[AuthenticatedPCCInput] = []
    denied = False
    real_scope = subject._replay_historical_session
    real_final = subject._final_seal_replay_historical_session
    real_open = subject._open_replay_historical_access
    real_issue = subject._issue_replay_historical_path_authority

    @contextmanager
    def capture_scope(*args: object, **kwargs: object) -> Any:
        with real_scope(*args, **kwargs) as handle:
            handles.append(handle)
            yield handle

    def capture_validation_proof(handle: Any, authenticated: Any) -> Any:
        access = real_open(handle, authenticated)
        validation_proofs.append(authenticated)
        return access

    def probe_final(handle: Any, callback: Any) -> None:
        def callback_then_open() -> None:
            nonlocal denied
            callback()
            try:
                authenticated = validation_proofs[-1]
                access = real_open(handle, authenticated)
                path = real_issue(store, authenticated, access)
                historical._derive_replay_historical_coverage(
                    authenticated,
                    path,
                    access,
                )
            except historical.HistoricalCoverageUnavailable:
                denied = True

        real_final(handle, callback_then_open)

    monkeypatch.setattr(subject, "_replay_historical_session", capture_scope)
    monkeypatch.setattr(
        subject,
        "_open_replay_historical_access",
        capture_validation_proof,
    )
    monkeypatch.setattr(subject, "_final_seal_replay_historical_session", probe_final)
    owner, _connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[-1].ref,
    )
    try:
        assert handles
        assert denied is True
        assert report.cursor.source_sequence == records[-1].ref.source_sequence
    finally:
        owner.close()


@pytest.mark.parametrize(
    "probe_stage",
    ["final-before-source", "validation-before-source"],
)
def test_terminal_source_probe_runs_without_broker_lock_and_stale_access_fails_fast(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_stage: str,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / probe_stage, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    accesses: list[tuple[Any, Any]] = []
    real_open = subject._open_replay_historical_access
    real_issue = historical._issue_replay_historical_path_authority
    real_begin_validation = subject._begin_replay_historical_validation
    real_final = subject._final_seal_replay_historical_session
    real_iter = type(store).iter_authenticated_records
    worker_finished = Event()
    denied: list[bool] = []
    probed = False
    probe_active = False
    finished_during_probe: list[bool] = []
    workers: list[Thread] = []

    def capture_access(handle: Any, authenticated: Any) -> Any:
        access = real_open(handle, authenticated)
        if not accesses:
            accesses.append((authenticated, access))
        return access

    def retained_access_worker() -> None:
        authenticated, access = accesses[0]
        try:
            real_issue(store, authenticated, access)
        except historical.HistoricalCoverageUnavailable:
            denied.append(True)
        finally:
            worker_finished.set()

    def iter_during_external_probe(
        candidate_store: Any,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        nonlocal probed
        selected = tuple(real_iter(candidate_store, after=after, through=through))
        if candidate_store is not store or not probe_active or probed or not accesses:
            return iter(selected)
        probed = True
        copied = copy_context()
        worker = Thread(target=lambda: copied.run(retained_access_worker))
        workers.append(worker)
        worker.start()
        finished_during_probe.append(worker_finished.wait(0.25))
        return iter(selected)

    def begin_validation(handle: Any) -> None:
        nonlocal probe_active
        if probe_stage != "validation-before-source":
            real_begin_validation(handle)
            return
        probe_active = True
        try:
            real_begin_validation(handle)
        finally:
            probe_active = False

    def final_probe(handle: Any, callback: Any) -> None:
        nonlocal probe_active
        if probe_stage != "final-before-source":
            real_final(handle, callback)
            return
        probe_active = True
        try:
            real_final(handle, callback)
        finally:
            probe_active = False

    monkeypatch.setattr(subject, "_open_replay_historical_access", capture_access)
    monkeypatch.setattr(subject, "_begin_replay_historical_validation", begin_validation)
    monkeypatch.setattr(subject, "_final_seal_replay_historical_session", final_probe)
    monkeypatch.setattr(
        type(store),
        "iter_authenticated_records",
        iter_during_external_probe,
    )
    owner, _connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[-1].ref,
    )
    try:
        for worker in workers:
            worker.join(1)
            assert worker.is_alive() is False
        assert probed is True
        assert finished_during_probe == [True]
        assert denied == [True]
        assert report.cursor.source_sequence == records[-1].ref.source_sequence
    finally:
        owner.close()


def test_validation_rebuild_runs_without_broker_lock_and_denies_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The validation parameter above exercises the same bounded worker protocol
    # through the production validation-rebuild probe.
    test_terminal_source_probe_runs_without_broker_lock_and_stale_access_fails_fast(
        tmp_path,
        monkeypatch,
        "validation-before-source",
    )


def test_revocation_during_external_probe_invalidates_exact_ticket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "probe-revoke", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    handles: list[Any] = []
    accesses: list[tuple[Any, Any]] = []
    real_scope = subject._replay_historical_session
    real_open = subject._open_replay_historical_access
    real_issue = historical._issue_replay_historical_path_authority
    real_begin_validation = subject._begin_replay_historical_validation
    real_iter = type(store).iter_authenticated_records
    probe_active = False
    probed = False
    worker_finished = Event()
    finished_during_probe: list[bool] = []
    workers: list[Thread] = []

    class ProbeAbort(BaseException):
        pass

    @contextmanager
    def capture_scope(*args: object, **kwargs: object) -> Any:
        with real_scope(*args, **kwargs) as handle:
            handles.append(handle)
            yield handle

    def capture_access(handle: Any, authenticated: Any) -> Any:
        access = real_open(handle, authenticated)
        if not accesses:
            accesses.append((authenticated, access))
        return access

    def retained_access_worker() -> None:
        authenticated, access = accesses[0]
        try:
            real_issue(store, authenticated, access)
        except historical.HistoricalCoverageUnavailable:
            pass
        finally:
            worker_finished.set()

    def abort_during_probe_iteration(
        candidate_store: Any,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        nonlocal probed
        selected = tuple(real_iter(candidate_store, after=after, through=through))
        if candidate_store is store and probe_active and not probed and accesses:
            probed = True
            copied = copy_context()
            worker = Thread(target=lambda: copied.run(retained_access_worker))
            workers.append(worker)
            worker.start()
            finished_during_probe.append(worker_finished.wait(0.25))
            raise ProbeAbort("validation probe")
        return iter(selected)

    def begin_validation(handle: Any) -> None:
        nonlocal probe_active
        probe_active = True
        try:
            real_begin_validation(handle)
        finally:
            probe_active = False

    monkeypatch.setattr(subject, "_replay_historical_session", capture_scope)
    monkeypatch.setattr(subject, "_open_replay_historical_access", capture_access)
    monkeypatch.setattr(subject, "_begin_replay_historical_validation", begin_validation)
    monkeypatch.setattr(
        type(store),
        "iter_authenticated_records",
        abort_during_probe_iteration,
    )
    artifact: object | None = None
    with pytest.raises(ProbeAbort):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert artifact is None
    for worker in workers:
        worker.join(1)
        assert worker.is_alive() is False
    assert probed is True
    assert finished_during_probe == [True]
    assert handles
    with pytest.raises(historical.HistoricalCoverageUnavailable):
        historical._open_replay_historical_access(handles[0], proof)
    assert historical._ACTIVE_REPLAY_MARKER.get() is None
    assert store not in historical._REPLAY_STORE_RESERVATIONS


def test_probe_ticket_is_one_shot_and_identity_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "ticket", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    real_final = subject._final_seal_replay_historical_session
    nested_denied = False

    def reenter_final(handle: Any, callback: Any) -> None:
        def exact_outer_callback() -> None:
            nonlocal nested_denied
            callback()
            try:
                real_final(handle, lambda: None)
            except historical.HistoricalCoverageUnavailable:
                nested_denied = True

        real_final(handle, exact_outer_callback)

    monkeypatch.setattr(subject, "_final_seal_replay_historical_session", reenter_final)
    owner, _connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[-1].ref,
    )
    try:
        assert nested_denied is True
        assert report.cursor.source_sequence == records[-1].ref.source_sequence
    finally:
        owner.close()


def test_external_probe_baseexception_cleans_ticket_access_paths_and_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "probe-abort", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    captured: list[tuple[Any, Any, Any]] = []
    real_issue = subject._issue_replay_historical_path_authority
    real_final = subject._final_seal_replay_historical_session
    real_iter = type(store).iter_authenticated_records
    probe_active = False
    probed = False
    worker_finished = Event()
    finished_during_probe: list[bool] = []
    workers: list[Thread] = []

    class ProbeAbort(BaseException):
        pass

    def capture_path(candidate_store: Any, authenticated: Any, access: Any) -> Any:
        path = real_issue(candidate_store, authenticated, access)
        if not captured:
            captured.append((authenticated, path, access))
        return path

    def retained_path_worker() -> None:
        authenticated, _path, access = captured[0]
        try:
            historical._issue_replay_historical_path_authority(
                store,
                authenticated,
                access,
            )
        except historical.HistoricalCoverageUnavailable:
            pass
        finally:
            worker_finished.set()

    def abort_during_final_iteration(
        candidate_store: Any,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        nonlocal probed
        selected = tuple(real_iter(candidate_store, after=after, through=through))
        if candidate_store is store and probe_active and not probed and captured:
            probed = True
            copied = copy_context()
            worker = Thread(target=lambda: copied.run(retained_path_worker))
            workers.append(worker)
            worker.start()
            finished_during_probe.append(worker_finished.wait(0.25))
            raise ProbeAbort("final probe")
        return iter(selected)

    def final_probe(handle: Any, callback: Any) -> None:
        nonlocal probe_active
        probe_active = True
        try:
            real_final(handle, callback)
        finally:
            probe_active = False

    monkeypatch.setattr(subject, "_issue_replay_historical_path_authority", capture_path)
    monkeypatch.setattr(subject, "_final_seal_replay_historical_session", final_probe)
    monkeypatch.setattr(
        type(store),
        "iter_authenticated_records",
        abort_during_final_iteration,
    )
    artifact: object | None = None
    with pytest.raises(ProbeAbort):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert artifact is None
    for worker in workers:
        worker.join(1)
        assert worker.is_alive() is False
    assert probed is True
    assert finished_during_probe == [True]
    assert captured
    authenticated, path, access = captured[0]
    with pytest.raises(historical.HistoricalCoverageUnavailable):
        historical._derive_replay_historical_coverage(authenticated, path, access)
    assert historical._ACTIVE_REPLAY_MARKER.get() is None
    assert store not in historical._REPLAY_STORE_RESERVATIONS


@pytest.mark.parametrize(
    "mutation",
    ["replacement", "bool", "scalar-subclass", "in-place", "eq-bomb"],
)
def test_terminal_predecessor_seal_rejects_exact_mutation_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / mutation, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    real_evaluate = authority._evaluate_correlation_projection_terminal_authority
    injected = False
    eq_called = False

    class ScalarSubclass(int):
        pass

    class EqualInt(int):
        def __eq__(self, other: object) -> bool:
            del other
            return True

    def mutate_during_terminal(selected: Any, expected: Any, callback: Any) -> Any:
        def callback_then_mutate() -> Any:
            nonlocal eq_called, injected
            result = callback()
            binding = authority._authority_binding(selected)
            predecessor = binding.predecessor
            if mutation == "replacement":
                binding.predecessor = replace(predecessor)
            elif mutation == "bool":
                monkeypatch.setattr(authority, "_clone_predecessor", lambda value: value)
                object.__setattr__(expected, "generation", bool(expected.generation))
            elif mutation == "scalar-subclass":
                monkeypatch.setattr(authority, "_clone_predecessor", lambda value: value)
                object.__setattr__(
                    predecessor,
                    "generation",
                    ScalarSubclass(predecessor.generation),
                )
            elif mutation == "in-place":
                monkeypatch.setattr(authority, "_clone_predecessor", lambda value: value)
                object.__setattr__(
                    predecessor,
                    "generation",
                    EqualInt(predecessor.generation + 1),
                )
            else:
                def mark_eq(self: object, other: object) -> bool:
                    nonlocal eq_called
                    del self, other
                    eq_called = True
                    return True

                monkeypatch.setattr(authority._ProjectionPredecessor, "__eq__", mark_eq)
                binding.revision = object()
            injected = True
            return result

        return real_evaluate(selected, expected, callback_then_mutate)

    monkeypatch.setattr(
        subject,
        "_evaluate_correlation_projection_terminal_authority",
        mutate_during_terminal,
    )
    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert injected is True
    assert eq_called is False
    assert artifact is None


def test_cumulative_memo_leaf_seal_work_is_linear_at_four_and_eight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    historical = importlib.import_module("agmind_immune.coverage.historical")

    def measure(root: Path, pcc_count: int, patch: pytest.MonkeyPatch) -> dict[str, int]:
        subject = _subject()
        authority = importlib.import_module("agmind_immune.correlation.authority")
        patch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
        coordinator, proofs = _accepted_many_complete(root, pcc_count)
        store, journal, acknowledgements, records = _unpublished_resources(
            coordinator,
            proofs,
        )
        counts = {
            "entry": 0,
            "compact": 0,
            "pcc": 0,
            "memo": 0,
            "fold": 0,
            "semantic": 0,
        }
        real_reduce = historical._reduce_historical_coverage

        def count_seal(kind: str) -> None:
            counts[kind] += 1

        def count_fold(kind: str) -> None:
            del kind
            counts["fold"] += 1

        def count_reduce(source_records: Any, *args: object, **kwargs: object) -> Any:
            counts["semantic"] += len(source_records)
            return real_reduce(source_records, *args, **kwargs)

        patch.setattr(historical, "_replay_seal_visit", count_seal, raising=False)
        patch.setattr(historical, "_replay_leaf_fold_visit", count_fold)
        patch.setattr(historical, "_reduce_historical_coverage", count_reduce)
        owner, _connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
        owner.close()
        assert report.applied_count == 3 * pcc_count
        return counts

    with monkeypatch.context() as four_patch:
        four = measure(tmp_path / "four-leaves", 4, four_patch)
    with monkeypatch.context() as eight_patch:
        eight = measure(tmp_path / "eight-leaves", 8, eight_patch)
    assert four == {
        "entry": 72,
        "compact": 24,
        "pcc": 24,
        "memo": 24,
        "fold": 0,
        "semantic": 20,
    }
    assert eight == {
        "entry": 144,
        "compact": 48,
        "pcc": 48,
        "memo": 48,
        "fold": 0,
        "semantic": 72,
    }
    assert all(
        eight[key] <= 2 * four[key]
        for key in ("entry", "compact", "pcc", "memo", "fold")
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "before-interval",
        "before-event-reorder",
        "before-assessment-bool",
        "after-fresh-assessment",
        "after-key-reorder",
        "after-leaf-digest",
        "after-fresh-pcc",
    ],
)
def test_replay_leaf_replacement_reorder_and_fact_drift_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proofs = _accepted_unpublished_compact_history(tmp_path / mutation)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        proofs,
    )
    verifier = store._bound_verifier
    assert verifier is not None
    memo_leaves: list[Any] = []
    pcc_leaves: list[Any] = []
    folded_mutation_applied = False
    callback_mutation_applied = False
    real_memo_leaf = historical._build_replay_memo_leaf
    real_pcc_leaf = historical._build_replay_pcc_leaf
    real_final = subject._final_seal_replay_historical_session

    def capture_memo_leaf(
        key: Any,
        timeline: Any,
        count: int,
        digest: str,
    ) -> Any:
        nonlocal folded_mutation_applied
        if not folded_mutation_applied and mutation.startswith("before-"):
            folded_mutation_applied = True
            if mutation == "before-interval":
                interval = timeline.intersecting_intervals[0]
                object.__setattr__(interval, "component", interval.component + "-drift")
            elif mutation == "before-event-reorder":
                object.__setattr__(
                    timeline,
                    "coverage_event_ids",
                    tuple(reversed(timeline.coverage_event_ids)),
                )
            else:
                object.__setattr__(timeline.assessment, "complete", 1)
        leaf = real_memo_leaf(key, timeline, count, digest)
        if not memo_leaves:
            memo_leaves.append(leaf)
        return leaf

    def capture_pcc_leaf(key: Any, authenticated: Any) -> Any:
        leaf = real_pcc_leaf(key, authenticated)
        if not pcc_leaves:
            pcc_leaves.append(leaf)
        return leaf

    def mutate_after_callback(handle: Any, callback: Any) -> None:
        def callback_then_mutate_leaf() -> None:
            nonlocal callback_mutation_applied
            callback()
            callback_mutation_applied = True
            memo_leaf = memo_leaves[0]
            if mutation == "after-fresh-assessment":
                object.__setattr__(
                    memo_leaf,
                    "assessment",
                    replace(memo_leaf.assessment),
                )
            elif mutation == "after-key-reorder":
                object.__setattr__(memo_leaf, "key", tuple(reversed(memo_leaf.key)))
            elif mutation == "after-leaf-digest":
                object.__setattr__(memo_leaf, "interval_digest", b"0" * 32)
            else:
                pcc_leaf = pcc_leaves[0]
                fresh = store._authenticated_pcc_input(
                    verifier,
                    pcc_leaf.evidence_ref,
                    pcc_leaf.request,
                )
                object.__setattr__(pcc_leaf, "pcc", fresh)

        real_final(handle, callback_then_mutate_leaf)

    monkeypatch.setattr(historical, "_build_replay_memo_leaf", capture_memo_leaf)
    monkeypatch.setattr(historical, "_build_replay_pcc_leaf", capture_pcc_leaf)
    if mutation.startswith("after-"):
        monkeypatch.setattr(
            subject,
            "_final_seal_replay_historical_session",
            mutate_after_callback,
        )
    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert artifact is None
    assert folded_mutation_applied is mutation.startswith("before-")
    assert callback_mutation_applied is mutation.startswith("after-")


def test_opening_replay_access_b_permanently_revokes_access_a_and_its_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    first: list[tuple[object, AuthenticatedPCCInput, object, object]] = []
    replacement_checked = False
    real_open = subject._open_replay_historical_access
    real_issue = subject._issue_replay_historical_path_authority

    def capture_open(handle: object, authenticated: AuthenticatedPCCInput) -> object:
        access = real_open(handle, authenticated)
        if access is not None and not first:
            first.append((handle, authenticated, access, None))
        return access

    def capture_path(
        candidate_store: SegmentStore,
        authenticated: AuthenticatedPCCInput,
        access: object,
    ) -> object:
        path = real_issue(candidate_store, authenticated, access)
        if first and first[0][3] is None and access is first[0][2]:
            handle, saved, saved_access, _missing = first[0]
            first[0] = (handle, saved, saved_access, path)
        return path

    monkeypatch.setattr(subject, "_open_replay_historical_access", capture_open)
    monkeypatch.setattr(subject, "_issue_replay_historical_path_authority", capture_path)

    def replace_at_candidate(step: str) -> None:
        nonlocal replacement_checked
        if step != "candidate" or replacement_checked:
            return
        replacement_checked = True
        handle, authenticated, access_a, path_a = first[0]
        assert path_a is not None
        marker = cast(Any, path_a)._binding
        assert type(marker) is historical._ReplayPathBinding
        assert not hasattr(marker, "session")
        assert not hasattr(marker, "access_nonce")
        with pytest.raises(AttributeError):
            object.__setattr__(marker, "phase", "validating")

        access_b = real_open(handle, authenticated)
        assert access_b is not None and access_b is not access_a
        path_b = real_issue(store, authenticated, access_b)
        assessment_b = historical._derive_replay_historical_coverage(
            authenticated,
            path_b,
            access_b,
        )
        assert assessment_b is not None
        with pytest.raises(historical.HistoricalCoverageUnavailable):
            historical._derive_replay_historical_coverage(
                authenticated,
                path_a,
                access_a,
            )
        with pytest.raises(historical.HistoricalCoverageUnavailable):
            historical._issue_replay_historical_path_authority(
                store,
                authenticated,
                access_a,
            )
        assert (
            historical._derive_replay_historical_coverage(
                authenticated,
                path_b,
                access_b,
            )
            is assessment_b
        )

    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
            step_hook=replace_at_candidate,
        )
    assert artifact is None
    assert replacement_checked is True
    assert store._closed is True


@pytest.mark.parametrize(
    ("timing", "mutation"),
    [
        ("before", "compact_count_bool"),
        ("after", "compact_count_bool"),
        ("after", "memo_count_bool"),
        ("after", "assessment_true_int"),
        ("after", "assessment_false_int"),
        ("after", "digest_subclass"),
        ("after", "fresh_pcc"),
        ("after", "fresh_memo_timeline"),
        ("after", "reordered_memos"),
        ("after", "phase_subclass"),
        ("after", "pending_event"),
        ("after", "verifier_generation_bool"),
        ("after", "fresh_terminal_ref"),
        ("after", "fresh_status"),
        ("after", "fresh_entries"),
        ("after", "frozen_keys_subclass"),
    ],
)
def test_replay_strict_broker_seal_rejects_equality_laundering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timing: str,
    mutation: str,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, first, second = _accepted_two_complete(tmp_path / mutation)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (first, second),
    )
    memo_leaves: list[Any] = []
    pcc_leaves: list[Any] = []
    real_memo_leaf = historical._build_replay_memo_leaf
    real_pcc_leaf = historical._build_replay_pcc_leaf
    real_final = subject._final_seal_replay_historical_session

    def capture_memo_leaf(*args: object, **kwargs: object) -> Any:
        leaf = real_memo_leaf(*args, **kwargs)
        if not memo_leaves:
            memo_leaves.append(leaf)
        return leaf

    def capture_pcc_leaf(*args: object, **kwargs: object) -> Any:
        leaf = real_pcc_leaf(*args, **kwargs)
        if not pcc_leaves:
            pcc_leaves.append(leaf)
        return leaf

    def mutate_current_state() -> None:
        memo = memo_leaves[0]
        pcc = pcc_leaves[0]
        if mutation == "compact_count_bool":
            object.__setattr__(memo, "compact_count", bool(memo.compact_count))
            return
        if mutation in {"memo_count_bool", "pending_event"}:
            object.__setattr__(memo, "event_count", bool(memo.event_count))
        elif mutation == "assessment_true_int":
            object.__setattr__(memo.assessment, "complete", 1)
        elif mutation == "assessment_false_int":
            object.__setattr__(memo.assessment, "critical_gap", 0)
        elif mutation in {"digest_subclass", "phase_subclass"}:
            class DigestSubclass(bytes):
                pass

            object.__setattr__(memo, "semantic_digest", DigestSubclass(memo.semantic_digest))
        elif mutation == "fresh_pcc":
            verifier = store._bound_verifier
            assert verifier is not None
            fresh = store._authenticated_pcc_input(
                verifier,
                pcc.evidence_ref,
                pcc.request,
            )
            object.__setattr__(pcc, "pcc", fresh)
        elif mutation in {"fresh_memo_timeline", "fresh_status"}:
            object.__setattr__(memo, "assessment", replace(memo.assessment))
        elif mutation == "reordered_memos":
            object.__setattr__(memo, "key", tuple(reversed(memo.key)))
        elif mutation == "verifier_generation_bool":
            object.__setattr__(pcc, "request", pcc.request.model_copy(deep=True))
        elif mutation == "fresh_terminal_ref":
            object.__setattr__(pcc, "evidence_ref", replace(pcc.evidence_ref))
        elif mutation == "fresh_entries":
            object.__setattr__(pcc, "facts_digest", b"0" * 32)
        else:
            class KeysSubclass(tuple):
                pass

            object.__setattr__(memo, "key", KeysSubclass(memo.key))

    def mutate_around_external_check(handle: Any, callback: Any) -> None:
        if timing == "before":
            mutate_current_state()
            real_final(handle, callback)
            return

        def checked_then_mutated() -> None:
            callback()
            mutate_current_state()

        real_final(handle, checked_then_mutated)

    monkeypatch.setattr(historical, "_build_replay_memo_leaf", capture_memo_leaf)
    monkeypatch.setattr(historical, "_build_replay_pcc_leaf", capture_pcc_leaf)
    monkeypatch.setattr(
        subject,
        "_final_seal_replay_historical_session",
        mutate_around_external_check,
    )
    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert artifact is None
    assert memo_leaves
    assert pcc_leaves
    assert store._closed is True


def test_replay_broker_seal_ignores_enumerable_capture_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "capture", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    memo_leaves: list[Any] = []
    replacement_calls = 0
    matcher_replacement_calls = 0
    real_memo_leaf = historical._build_replay_memo_leaf
    real_final = subject._final_seal_replay_historical_session

    def capture_memo_leaf(*args: object, **kwargs: object) -> Any:
        leaf = real_memo_leaf(*args, **kwargs)
        if not memo_leaves:
            memo_leaves.append(leaf)
        return leaf

    def dishonest_capture(*args: object, **kwargs: object) -> Any:
        nonlocal replacement_calls
        del args, kwargs
        replacement_calls += 1
        raise AssertionError("enumerable seal capture replacement was invoked")

    def dishonest_match(*args: object, **kwargs: object) -> bool:
        nonlocal matcher_replacement_calls
        del args, kwargs
        matcher_replacement_calls += 1
        raise AssertionError("enumerable seal matcher replacement was invoked")

    def mutate_after_external_check(handle: Any, callback: Any) -> None:
        monkeypatch.setattr(
            historical,
            "_capture_replay_broker_seal",
            dishonest_capture,
        )
        monkeypatch.setattr(
            historical,
            "_replay_broker_state_matches_seal",
            dishonest_match,
        )

        def checked_then_mutated() -> None:
            callback()
            object.__setattr__(
                memo_leaves[0],
                "compact_count",
                bool(memo_leaves[0].compact_count),
            )

        real_final(handle, checked_then_mutated)

    monkeypatch.setattr(historical, "_build_replay_memo_leaf", capture_memo_leaf)
    monkeypatch.setattr(
        subject,
        "_final_seal_replay_historical_session",
        mutate_after_external_check,
    )
    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert artifact is None
    assert replacement_calls == 0
    assert matcher_replacement_calls == 0
    assert memo_leaves
    assert store._closed is True


@pytest.mark.parametrize(
    "failure_stage",
    [
        "handle-created",
        "store-reserved",
        "session-created",
        "context-set",
        "before-handle-yield",
        "first-caller-instruction",
    ],
)
def test_replay_activation_scope_cleans_every_baseexception_setup_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    historical = importlib.import_module("agmind_immune.coverage.historical")
    coordinator, proof = _accepted_complete(tmp_path / failure_stage, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    handles: list[Any] = []

    class ReplayAbort(BaseException):
        pass

    abort = ReplayAbort(failure_stage)

    def abort_setup(stage: str) -> None:
        expected_stage = (
            "broker-created" if failure_stage == "session-created" else failure_stage
        )
        if stage == expected_stage:
            raise abort

    monkeypatch.setattr(historical, "_replay_setup_checkpoint", abort_setup)
    try:
        with pytest.raises(ReplayAbort) as raised, historical._replay_historical_session(
            store,
            records[-1].ref,
        ) as handle:
            handles.append(handle)
            if failure_stage == "first-caller-instruction":
                raise abort
        assert raised.value is abort
        assert historical._ACTIVE_REPLAY_MARKER.get() is None
        assert store not in historical._REPLAY_STORE_RESERVATIONS
        if handles:
            with pytest.raises(historical.HistoricalCoverageUnavailable):
                historical._open_replay_historical_access(handles[0], proof)
        ordinary_path = store._historical_path_authority(proof)
        assert historical.derive_historical_coverage(proof, ordinary_path) is not None
    finally:
        journal.close()
        acknowledgements.close()
        store.close()


@pytest.mark.parametrize("cleanup_failure", ["revoke", "context", "reservation"])
def test_replay_cleanup_preserves_primary_and_finishes_later_substeps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_failure: str,
) -> None:
    historical = importlib.import_module("agmind_immune.coverage.historical")
    coordinator, proof = _accepted_complete(tmp_path / cleanup_failure, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    real_marker = historical._ACTIVE_REPLAY_MARKER
    cleanup_order: list[str] = []

    class ReplayAbort(BaseException):
        pass

    class CleanupAbort(BaseException):
        pass

    def fail_cleanup_checkpoint(stage: str) -> None:
        cleanup_order.append(stage)
        selected = {
            "revoke": "broker-revoked",
            "context": "context-reset",
            "reservation": "reservation-removed",
        }[cleanup_failure]
        if stage == selected:
            raise CleanupAbort(cleanup_failure)

    monkeypatch.setattr(
        historical,
        "_replay_cleanup_checkpoint",
        fail_cleanup_checkpoint,
    )
    primary = ReplayAbort("primary")
    try:
        with pytest.raises(ReplayAbort) as raised, historical._replay_historical_session(
            store,
            records[-1].ref,
        ):
            raise primary
        assert raised.value is primary
        assert any("cleanup failure" in note for note in getattr(primary, "__notes__", ()))
        assert real_marker.get() is None
        assert store not in historical._REPLAY_STORE_RESERVATIONS
        assert cleanup_order[0] == "broker-revoked"
        assert "context-reset" in cleanup_order
        assert "reservation-removed" in cleanup_order
        ordinary_path = store._historical_path_authority(proof)
        assert historical.derive_historical_coverage(proof, ordinary_path) is not None
    finally:
        journal.close()
        acknowledgements.close()
        store.close()


def test_foreign_thread_replay_close_cannot_poison_creator_context(
    tmp_path: Path,
) -> None:
    historical = importlib.import_module("agmind_immune.coverage.historical")
    coordinator, proof = _accepted_complete(tmp_path / "foreign-close", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    failures: list[BaseException] = []

    try:
        with historical._replay_historical_session(
            store,
            records[-1].ref,
        ) as handle:
            creator_marker = historical._ACTIVE_REPLAY_MARKER.get()
            assert creator_marker is not None

            def close_from_foreign_thread() -> None:
                try:
                    historical._complete_replay_historical_session(handle)
                except BaseException as error:  # noqa: BLE001 - inspect exact rejection
                    failures.append(error)

            thread = Thread(target=close_from_foreign_thread)
            thread.start()
            thread.join()

            assert len(failures) == 1
            assert type(failures[0]) is historical.HistoricalCoverageUnavailable
            assert historical._ACTIVE_REPLAY_MARKER.get() is creator_marker
            assert store in historical._REPLAY_STORE_RESERVATIONS
            historical._complete_replay_historical_session(handle)
            historical._complete_replay_historical_session(handle)
            assert historical._ACTIVE_REPLAY_MARKER.get() is None
            assert store not in historical._REPLAY_STORE_RESERVATIONS
        ordinary_path = store._historical_path_authority(proof)
        assert historical.derive_historical_coverage(proof, ordinary_path) is not None
    finally:
        journal.close()
        acknowledgements.close()
        store.close()


def test_replay_path_cleanup_baseexception_still_revokes_session_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "path-cleanup", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    captured: list[tuple[Any, Any, Any]] = []
    cleanup_visits = 0
    real_issue = subject._issue_replay_historical_path_authority
    real_cleanup_visit = historical._replay_path_cleanup_visit

    class CleanupAbort(BaseException):
        pass

    def capture_path(candidate_store: Any, authenticated: Any, access: Any) -> Any:
        path = real_issue(candidate_store, authenticated, access)
        if not captured:
            captured.append((authenticated, path, access))
        return path

    def fail_after_path_cleanup(path: Any) -> None:
        nonlocal cleanup_visits
        cleanup_visits += 1
        real_cleanup_visit(path)
        raise CleanupAbort("path cleanup")

    monkeypatch.setattr(
        subject,
        "_issue_replay_historical_path_authority",
        capture_path,
    )
    monkeypatch.setattr(historical, "_replay_path_cleanup_visit", fail_after_path_cleanup)
    artifact: object | None = None
    with pytest.raises(BaseExceptionGroup):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert artifact is None
    assert cleanup_visits >= 1
    assert captured
    authenticated, path, access = captured[0]
    with pytest.raises(historical.HistoricalCoverageUnavailable):
        historical._derive_replay_historical_coverage(authenticated, path, access)
    assert historical._ACTIVE_REPLAY_MARKER.get() is None
    assert store not in historical._REPLAY_STORE_RESERVATIONS
    assert store._closed is True


def test_two_replay_brokers_cleanup_only_their_own_four_and_eight_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator_a, proof_a = _accepted_complete(tmp_path / "source-a", ttl_seconds=120)
    coordinator_b, proof_b = _accepted_complete(tmp_path / "source-b", ttl_seconds=120)
    store_a, journal_a, acknowledgements_a, records_a = _unpublished_resources(
        coordinator_a,
        (proof_a,),
    )
    store_b, journal_b, acknowledgements_b, records_b = _unpublished_resources(
        coordinator_b,
        (proof_b,),
    )
    state_lock = Lock()
    ready = {store_a: Event(), store_b: Event()}
    release = Event()
    access_state: dict[SegmentStore, tuple[Any, AuthenticatedPCCInput, Any]] = {}
    pending_opens: list[tuple[Any, AuthenticatedPCCInput, Any]] = []
    projecting = {store_a: True, store_b: True}
    projecting_paths: dict[SegmentStore, list[Any]] = {store_a: [], store_b: []}
    cleanup_visits: dict[SegmentStore, list[Any]] = {store_a: [], store_b: []}
    real_open = subject._open_replay_historical_access
    real_issue = subject._issue_replay_historical_path_authority
    real_cleanup_visit = historical._replay_path_cleanup_visit

    def capture_open(handle: Any, authenticated: AuthenticatedPCCInput) -> Any:
        access = real_open(handle, authenticated)
        if access is not None:
            with state_lock:
                pending_opens.append((handle, authenticated, access))
        return access

    def capture_issue(
        candidate_store: SegmentStore,
        authenticated: AuthenticatedPCCInput,
        access: Any,
    ) -> Any:
        path = real_issue(candidate_store, authenticated, access)
        with state_lock:
            for handle, opened_proof, opened_access in reversed(pending_opens):
                if opened_access is access:
                    access_state[candidate_store] = (
                        handle,
                        opened_proof,
                        opened_access,
                    )
                    break
            if projecting[candidate_store]:
                projecting_paths[candidate_store].append(path)
        return path

    def count_local_cleanup(path: Any) -> None:
        candidate_store = path._store_ref()
        assert candidate_store in cleanup_visits
        with state_lock:
            projecting[candidate_store] = False
            cleanup_visits[candidate_store].append(path)
        real_cleanup_visit(path)

    monkeypatch.setattr(subject, "_open_replay_historical_access", capture_open)
    monkeypatch.setattr(subject, "_issue_replay_historical_path_authority", capture_issue)
    monkeypatch.setattr(authority, "_issue_replay_historical_path_authority", capture_issue)
    monkeypatch.setattr(historical, "_replay_path_cleanup_visit", count_local_cleanup)
    failures: dict[SegmentStore, BaseException] = {}
    reports: dict[SegmentStore, Any] = {}

    def run(
        store: SegmentStore,
        journal: CorrelationRequestJournal,
        acknowledgements: AckJournal,
        records: tuple[Any, ...],
        target_count: int,
        fail: bool,
    ) -> None:
        expanded = False

        def at_candidate(step: str) -> None:
            nonlocal expanded
            if step != "candidate" or expanded:
                return
            expanded = True
            with state_lock:
                _handle, authenticated, access = access_state[store]
                existing = len(projecting_paths[store])
            # The successful replay performs one more sanctioned issue during its
            # final transaction check; the failing replay stops at this hook.
            wanted_now = target_count - (0 if fail else 1)
            for _index in range(existing, wanted_now):
                capture_issue(store, authenticated, access)
            ready[store].set()
            assert release.wait(5)
            if fail:
                raise ProjectionAuthorityError("intentional local replay failure")

        try:
            owner, _connection, report = (
                subject._v2_unpublished_projection_from_prefix_for_test(
                    evidence=store,
                    acknowledgements=acknowledgements,
                    journal=journal,
                    registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                    through=records[-1].ref,
                    step_hook=at_candidate,
                )
            )
            reports[store] = report
            owner.close()
        except BaseException as error:  # noqa: BLE001 - relayed to parent thread
            failures[store] = error

    thread_a = Thread(
        target=run,
        args=(store_a, journal_a, acknowledgements_a, records_a, 4, True),
    )
    thread_b = Thread(
        target=run,
        args=(store_b, journal_b, acknowledgements_b, records_b, 8, False),
    )
    thread_a.start()
    thread_b.start()
    assert ready[store_a].wait(5)
    assert ready[store_b].wait(5)
    release.set()
    thread_a.join(5)
    thread_b.join(5)
    assert thread_a.is_alive() is False
    assert thread_b.is_alive() is False
    assert type(failures.get(store_a)) is ProjectionAuthorityError
    assert store_b not in failures
    assert reports[store_b].cursor.source_sequence == records_b[-1].ref.source_sequence
    assert len(projecting_paths[store_a]) == 4
    assert len(projecting_paths[store_b]) == 8
    assert cleanup_visits[store_a][:4] == projecting_paths[store_a]
    assert cleanup_visits[store_b][:8] == projecting_paths[store_b]
    assert all(path._store_ref() is store_a for path in cleanup_visits[store_a])
    assert all(path._store_ref() is store_b for path in cleanup_visits[store_b])


def test_issued_authority_weakref_cleanup_reenters_registry_lock_without_deadlock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "registry-reentry", ttl_seconds=120)
    store, journal, acknowledgements, _records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    predecessor = authority._ProjectionPredecessor(
        generation=0,
        host_id=None,
        source_sequence=0,
        event_id=None,
        content_sha256=None,
        frame_sha256=None,
    )
    issued = authority._create_correlation_projection_authority(
        store,
        registry,
        predecessor,
    )
    holder = [issued]
    del issued
    lock_acquired = Event()
    cleanup_finished = Event()
    failures: list[BaseException] = []

    def drop_last_owner_while_registry_locked() -> None:
        try:
            with authority._ISSUED_AUTHORITIES_LOCK:
                lock_acquired.set()
                holder.clear()
        except BaseException as error:  # noqa: BLE001 - record rescue fallout
            failures.append(error)
        finally:
            cleanup_finished.set()

    thread = Thread(target=drop_last_owner_while_registry_locked)
    try:
        thread.start()
        assert lock_acquired.wait(1)
        finished_without_rescue = cleanup_finished.wait(0.5)
        if not finished_without_rescue:
            authority._ISSUED_AUTHORITIES_LOCK.release()
        thread.join(timeout=2)

        assert thread.is_alive() is False
        assert finished_without_rescue is True
        assert failures == []
    finally:
        if thread.is_alive():
            try:
                authority._ISSUED_AUTHORITIES_LOCK.release()
            except RuntimeError:
                pass
            thread.join(timeout=2)
        journal.close()
        acknowledgements.close()
        store.close()


@pytest.mark.parametrize("mutation", ["generation", "descriptor"])
def test_ack_guard_rejects_mutation_after_inner_terminal_callback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / mutation, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    original_descriptor = acknowledgements._descriptor
    duplicated_descriptor: list[int] = []
    real_evaluate = AckJournal._evaluate_unpublished_anchor

    def mutate_after_inner_callback(
        selected: AckJournal,
        anchor: Any,
        callback: Any,
        *,
        _factory: object,
    ) -> Any:
        def checked_then_mutated() -> Any:
            report = callback()
            if mutation == "generation":
                selected._confirmed_generation += 1
            else:
                duplicated = os.dup(selected._descriptor)
                duplicated_descriptor.append(duplicated)
                selected._descriptor = duplicated
            return report

        return real_evaluate(
            selected,
            anchor,
            checked_then_mutated,
            _factory=_factory,
        )

    monkeypatch.setattr(
        AckJournal,
        "_evaluate_unpublished_anchor",
        mutate_after_inner_callback,
    )
    artifact: object | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                through=records[-1].ref,
            )
    finally:
        if duplicated_descriptor and original_descriptor >= 0:
            os.close(original_descriptor)
    assert artifact is None
    assert historical_marker_is_clear()
    assert store not in importlib.import_module(
        "agmind_immune.coverage.historical"
    )._REPLAY_STORE_RESERVATIONS
    assert store._source_terminal_token is None
    assert store._source_active_writers == 0
    assert mutation == "generation" or duplicated_descriptor


@pytest.mark.parametrize("mutation", ["predecessor", "revision", "close"])
def test_correlation_guard_rejects_mutation_after_inner_terminal_callback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / mutation, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    real_evaluate = authority._evaluate_correlation_projection_terminal_authority

    def mutate_after_inner_callback(
        selected_authority: Any,
        expected: Any,
        callback: Any,
    ) -> Any:
        def checked_then_mutated() -> Any:
            report = callback()
            binding = authority._authority_binding(selected_authority)
            if mutation == "predecessor":
                binding.predecessor = replace(
                    binding.predecessor,
                    generation=binding.predecessor.generation + 1,
                )
            elif mutation == "revision":
                binding.revision = object()
            else:
                authority._close_correlation_projection_authority(
                    selected_authority
                )
            return report

        return real_evaluate(
            selected_authority,
            expected,
            checked_then_mutated,
        )

    monkeypatch.setattr(
        subject,
        "_evaluate_correlation_projection_terminal_authority",
        mutate_after_inner_callback,
    )
    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert artifact is None
    assert store._source_terminal_token is None
    assert store._source_active_writers == 0


def test_source_terminal_fence_rejects_real_n_plus_one_append_before_mutation(
    tmp_path: Path,
) -> None:
    segments = importlib.import_module("agmind_immune.evidence.segments")
    coordinator, proof = _accepted_complete(tmp_path / "source", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    before_records = tuple(store.iter_authenticated_records())
    before_status = store.status()
    verifier = store._bound_verifier
    assert verifier is not None
    before_authority = verifier._authority
    failures: list[BaseException] = []

    def attempt_append() -> None:
        try:
            _accept(
                coordinator,
                envelope_value(
                    private_key(11),
                    sequence=records[-1].ref.source_sequence + 1,
                ),
            )
        except BaseException as error:  # noqa: BLE001 - asserted below
            failures.append(error)

    def while_terminal() -> None:
        writer = Thread(target=attempt_append)
        writer.start()
        writer.join(5)
        assert writer.is_alive() is False
        assert len(failures) == 1
        assert isinstance(failures[0], segments.EvidenceStoreError)
        assert tuple(store.iter_authenticated_records()) == before_records
        assert store.status() == before_status
        assert verifier._authority is before_authority
        assert tuple(store._authenticated_retired_ranges) == ()

    try:
        store._evaluate_source_terminal(
            store._lifecycle_identity,
            while_terminal,
            _factory=segments._SOURCE_TERMINAL_FACTORY,
        )
    finally:
        journal.close()
        acknowledgements.close()
        store.close()
    assert store._source_terminal_token is None
    assert store._source_active_writers == 0


def test_source_terminal_fence_rejects_real_retention_unlink_before_mutation(
    tmp_path: Path,
) -> None:
    segments = importlib.import_module("agmind_immune.evidence.segments")
    case = _retention_proof_case(tmp_path / "retention")
    acknowledgements = case.store._ack_journal_owner
    assert type(acknowledgements) is AckJournal
    capability = case.store._authenticate_retention_tombstone(
        case.journal,
        case.final_snapshot,
        case.target_ref,
        _factory=segments._RETENTION_PROOF_FACTORY,
    )
    state = case.journal.state
    assert state is not None and state.phase == "evidence_appended"
    state_canonical = canonical_json(state)
    selected_paths = tuple(
        case.store.root / entry.segment_relative_path for entry in state.entries
    )
    before_records = tuple(case.store.iter_authenticated_records())
    before_status = case.store.status()
    before_ranges = tuple(case.store._authenticated_retired_ranges)
    verifier = case.store._bound_verifier
    assert verifier is not None
    before_authority = verifier._authority

    def attempt_unlink() -> None:
        with pytest.raises(segments.EvidenceStoreError):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments._RETENTION_PROOF_FACTORY,
            )
        current_state = case.journal.state
        assert type(current_state) is type(state)
        assert canonical_json(current_state) == state_canonical
        assert all(path.exists() for path in selected_paths)
        assert tuple(case.store.iter_authenticated_records()) == before_records
        assert case.store.status() == before_status
        assert tuple(case.store._authenticated_retired_ranges) == before_ranges
        assert verifier._authority is before_authority

    try:
        case.store._evaluate_source_terminal(
            case.store._lifecycle_identity,
            attempt_unlink,
            _factory=segments._SOURCE_TERMINAL_FACTORY,
        )
        assert case.store._source_terminal_token is None
        assert case.store._source_active_writers == 0
    finally:
        case.coverage.close()
        case.store.close(flush=False)


def test_source_terminal_acquisition_rejects_active_real_writer_without_waiting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    segments = importlib.import_module("agmind_immune.evidence.segments")
    coordinator, proof = _accepted_complete(tmp_path / "active-writer", ttl_seconds=120)
    store, journal, acknowledgements, _records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    writer_entered = Event()
    release_writer = Event()
    failures: list[BaseException] = []
    real_checkpoint = segments._source_mutation_checkpoint

    def pause_writer(candidate_store: SegmentStore, stage: str) -> None:
        real_checkpoint(candidate_store, stage)
        if (
            candidate_store is store
            and stage == "writer-entered"
            and not writer_entered.is_set()
        ):
            writer_entered.set()
            assert release_writer.wait(5)

    def flush() -> None:
        try:
            store.flush_security_boundary()
        except BaseException as error:  # noqa: BLE001 - relayed below
            failures.append(error)

    monkeypatch.setattr(segments, "_source_mutation_checkpoint", pause_writer)
    writer = Thread(target=flush)
    writer.start()
    assert writer_entered.wait(5)
    assert store._source_active_writers == 1
    with pytest.raises(segments.EvidenceStoreError):
        store._evaluate_source_terminal(
            store._lifecycle_identity,
            lambda: None,
            _factory=segments._SOURCE_TERMINAL_FACTORY,
        )
    assert writer.is_alive() is True
    assert store._source_terminal_token is None
    release_writer.set()
    writer.join(5)
    try:
        assert writer.is_alive() is False
        assert failures == []
        assert store._source_active_writers == 0
    finally:
        journal.close()
        acknowledgements.close()
        store.close()


def test_read_only_health_writer_invalidates_source_terminal_revision(
    tmp_path: Path,
) -> None:
    segments = importlib.import_module("agmind_immune.evidence.segments")
    coordinator, proof = _accepted_complete(tmp_path / "health", ttl_seconds=120)
    store, journal, acknowledgements, _records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    before_revision = store._source_revision

    def trip_health() -> None:
        writer = Thread(target=store.enter_read_only, args=("evidence_conflict",))
        writer.start()
        writer.join(5)
        assert writer.is_alive() is False

    try:
        with pytest.raises(segments.EvidenceStoreError):
            store._evaluate_source_terminal(
                store._lifecycle_identity,
                trip_health,
                _factory=segments._SOURCE_TERMINAL_FACTORY,
            )
        assert store._source_revision > before_revision
        assert store._read_only_reason == "evidence_conflict"
        assert store._source_terminal_token is None
        assert store._source_active_writers == 0
    finally:
        journal.close()
        acknowledgements.close()
        store.close(flush=False)


def test_ack_and_correlation_writers_wait_for_report_and_full_replay_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "guards", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    captured_authority: list[Any] = []
    guard_order: list[str] = []
    issued_validations_under_binding = 0
    real_source_evaluate = SegmentStore._evaluate_source_terminal
    real_ack_evaluate = AckJournal._evaluate_unpublished_anchor
    real_evaluate = subject._evaluate_correlation_projection_terminal_authority
    real_require_authority = authority._require_authority_locked
    paused = Event()
    release = Event()
    ack_attempted = Event()
    correlation_attempted = Event()
    ack_entered = Event()
    correlation_entered = Event()
    report_constructed = Event()
    replay_closed = Event()
    worker_observations: list[tuple[bool, bool, bool]] = []
    worker_failures: list[BaseException] = []
    workers: list[Thread] = []

    def observe_source_evaluation(
        selected: SegmentStore,
        lifecycle: object,
        callback: Any,
        *,
        _factory: object,
    ) -> Any:
        def under_source_token() -> Any:
            assert selected._source_terminal_token is not None
            guard_order.append("source")
            return callback()

        return real_source_evaluate(
            selected,
            lifecycle,
            under_source_token,
            _factory=_factory,
        )

    def observe_ack_evaluation(
        selected: AckJournal,
        anchor: Any,
        callback: Any,
        *,
        _factory: object,
    ) -> Any:
        def under_ack_lock() -> Any:
            assert selected._retention_lock.acquire(False) is False
            guard_order.append("ack")
            return callback()

        return real_ack_evaluate(
            selected,
            anchor,
            under_ack_lock,
            _factory=_factory,
        )

    def capture_evaluation(selected: Any, expected: Any, callback: Any) -> Any:
        captured_authority.append(selected)
        binding = authority._authority_binding(selected)

        def under_correlation_lock() -> Any:
            assert binding.lock._is_owned() is True
            guard_order.append("correlation")
            return callback()

        return real_evaluate(selected, expected, under_correlation_lock)

    def observe_issued_validation(
        selected: Any,
        binding: Any,
        *,
        allow_closed: bool = False,
    ) -> None:
        nonlocal issued_validations_under_binding
        assert binding.lock._is_owned() is True
        real_require_authority(
            selected,
            binding,
            allow_closed=allow_closed,
        )
        issued_validations_under_binding += 1

    def ack_writer() -> None:
        ack_attempted.set()
        try:
            acknowledgements.close()
            worker_observations.append(
                (
                    store in historical._REPLAY_STORE_RESERVATIONS,
                    report_constructed.is_set(),
                    replay_closed.is_set(),
                )
            )
            ack_entered.set()
        except BaseException as error:  # noqa: BLE001 - relayed below
            worker_failures.append(error)

    def correlation_writer() -> None:
        correlation_attempted.set()
        try:
            authority._close_correlation_projection_authority(
                captured_authority[0]
            )
            worker_observations.append(
                (
                    store in historical._REPLAY_STORE_RESERVATIONS,
                    report_constructed.is_set(),
                    replay_closed.is_set(),
                )
            )
            correlation_entered.set()
        except BaseException as error:  # noqa: BLE001 - relayed below
            worker_failures.append(error)

    started_workers = False

    def terminal_steps(step: str) -> None:
        nonlocal started_workers
        if step == "historical_sealed" and not started_workers:
            started_workers = True
            assert store._source_terminal_token is not None
            assert store.status().healthy is True
            assert tuple(
                record.ref for record in store.iter_authenticated_records()
            ) == tuple(record.ref for record in records)
            workers.extend(
                [Thread(target=ack_writer), Thread(target=correlation_writer)]
            )
            for worker in workers:
                worker.start()
            paused.set()
            assert release.wait(5)
        elif step == "terminal_report_constructed":
            report_constructed.set()
        elif step == "terminal_replay_closed":
            replay_closed.set()

    monkeypatch.setattr(
        SegmentStore,
        "_evaluate_source_terminal",
        observe_source_evaluation,
    )
    monkeypatch.setattr(
        AckJournal,
        "_evaluate_unpublished_anchor",
        observe_ack_evaluation,
    )
    monkeypatch.setattr(
        subject,
        "_evaluate_correlation_projection_terminal_authority",
        capture_evaluation,
    )
    monkeypatch.setattr(
        authority,
        "_require_authority_locked",
        observe_issued_validation,
    )
    projection_failures: list[BaseException] = []
    reports: list[Any] = []

    def build() -> None:
        try:
            owner, _connection, report = (
                subject._v2_unpublished_projection_from_prefix_for_test(
                    evidence=store,
                    acknowledgements=acknowledgements,
                    journal=journal,
                    registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                    through=records[-1].ref,
                    step_hook=terminal_steps,
                )
            )
            reports.append(report)
            owner.close()
        except BaseException as error:  # noqa: BLE001 - relayed below
            projection_failures.append(error)

    projection = Thread(target=build)
    projection.start()
    assert paused.wait(5)
    assert ack_attempted.wait(5)
    assert correlation_attempted.wait(5)
    assert ack_entered.is_set() is False
    assert correlation_entered.is_set() is False
    assert store in historical._REPLAY_STORE_RESERVATIONS
    release.set()
    projection.join(5)
    for worker in workers:
        worker.join(5)
    assert projection.is_alive() is False
    assert all(worker.is_alive() is False for worker in workers)
    assert projection_failures == []
    assert worker_failures == []
    assert len(reports) == 1
    assert ack_entered.is_set() is True
    assert correlation_entered.is_set() is True
    assert worker_observations == [(False, True, True), (False, True, True)]
    assert guard_order == ["source", "ack", "correlation"]
    assert issued_validations_under_binding >= 2


@pytest.mark.parametrize("failure", ["report", "historical_close"])
def test_terminal_baseexception_releases_all_guards_and_replay_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / failure, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    captured_bindings: list[Any] = []
    real_evaluate = subject._evaluate_correlation_projection_terminal_authority

    class TerminalAbort(BaseException):
        pass

    def capture_binding(selected: Any, expected: Any, callback: Any) -> Any:
        captured_bindings.append(authority._authority_binding(selected))
        return real_evaluate(selected, expected, callback)

    def terminal_steps(step: str) -> None:
        if failure == "report" and step == "terminal_report_constructed":
            raise TerminalAbort("report")

    monkeypatch.setattr(
        subject,
        "_evaluate_correlation_projection_terminal_authority",
        capture_binding,
    )
    if failure == "historical_close":
        def close_then_abort(stage: str) -> None:
            if stage == "broker-revoked":
                raise TerminalAbort("historical close")

        monkeypatch.setattr(
            historical,
            "_replay_cleanup_checkpoint",
            close_then_abort,
        )
    artifact: object | None = None
    expected_error: type[BaseException] = (
        TerminalAbort if failure == "report" else BaseExceptionGroup
    )
    with pytest.raises(expected_error):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
            step_hook=terminal_steps,
        )
    assert artifact is None
    assert store._source_terminal_token is None
    assert store._source_active_writers == 0
    assert historical._ACTIVE_REPLAY_MARKER.get() is None
    assert store not in historical._REPLAY_STORE_RESERVATIONS
    assert acknowledgements._retention_lock.acquire(False) is True
    acknowledgements._retention_lock.release()
    assert captured_bindings
    assert captured_bindings[0].lock.acquire(False) is True
    captured_bindings[0].lock.release()


def historical_marker_is_clear() -> bool:
    historical = importlib.import_module("agmind_immune.coverage.historical")
    return historical._ACTIVE_REPLAY_MARKER.get() is None


def test_replay_session_runtime_capability_cannot_be_copied_pickled_or_subclassed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    captured_handle: list[object] = []
    captured_access: list[object] = []
    real_scope = subject._replay_historical_session
    real_open = subject._open_replay_historical_access

    @contextmanager
    def capture_handle(*args: object, **kwargs: object) -> Any:
        with real_scope(*args, **kwargs) as handle:
            captured_handle.append(handle)
            yield handle

    def capture_access(handle: Any, authenticated: Any) -> Any:
        access = real_open(handle, authenticated)
        captured_access.append(access)
        return access

    monkeypatch.setattr(
        subject,
        "_replay_historical_session",
        capture_handle,
    )
    monkeypatch.setattr(subject, "_open_replay_historical_access", capture_access)
    protections_checked = False
    subclass_denied = False

    def check_capability_protections(step: str) -> None:
        nonlocal protections_checked, subclass_denied
        if step != "candidate" or protections_checked:
            return
        protections_checked = True
        session = captured_handle[0]
        access = captured_access[0]
        assert not hasattr(historical, "_REPLAY_CAPABILITY_FACTORY")
        with pytest.raises(TypeError):
            historical._ReplayHandle(lambda *_args: None)
        with pytest.raises(TypeError):
            historical._ReplayAccess(lambda *_args: None)
        with pytest.raises(AttributeError):
            session._ReplayHandle__dispatch = lambda *_args: None
        with pytest.raises(AttributeError):
            access._ReplayAccess__dispatch = lambda *_args: None
        with pytest.raises(TypeError):
            copy(session)
        with pytest.raises(TypeError):
            pickle.dumps(session)
        try:
            type("ForgedReplaySession", (type(session),), {})
        except TypeError:
            subclass_denied = True

    owner, _connection, report = (
        subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
            step_hook=check_capability_protections,
        )
    )
    try:
        assert report.cursor.source_sequence == records[-1].ref.source_sequence
        assert protections_checked is True
        assert subclass_denied is True
    finally:
        owner.close()


def test_validation_replay_path_is_bound_to_one_exact_memo_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, first, second = _accepted_two_complete(tmp_path / "evidence")
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (first, second),
    )
    validation_paths: list[tuple[AuthenticatedPCCInput, object, object]] = []
    previous_denied = False
    previous_unregistered = False
    validation_started = False
    real_issue = subject._issue_replay_historical_path_authority
    real_begin_validation = subject._begin_replay_historical_validation

    def mark_validation(handle: Any) -> None:
        nonlocal validation_started
        real_begin_validation(handle)
        validation_started = True

    def capture_validation_path(
        candidate_store: Any,
        proof: AuthenticatedPCCInput,
        access: object,
    ) -> object:
        nonlocal previous_denied, previous_unregistered
        path = real_issue(candidate_store, proof, access)
        if validation_started:
            if validation_paths:
                old_proof, old_path, old_access = validation_paths[0]
                try:
                    historical._derive_replay_historical_coverage(
                        old_proof,
                        old_path,
                        old_access,
                    )
                except historical.HistoricalCoverageUnavailable:
                    previous_denied = True
                previous_unregistered = old_path not in historical._ISSUED_PATHS
            validation_paths.append((proof, path, access))
        return path

    monkeypatch.setattr(
        subject,
        "_issue_replay_historical_path_authority",
        capture_validation_path,
    )
    monkeypatch.setattr(
        authority,
        "_issue_replay_historical_path_authority",
        capture_validation_path,
    )
    monkeypatch.setattr(
        subject,
        "_begin_replay_historical_validation",
        mark_validation,
    )
    owner, _connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[-1].ref,
    )
    owner.close()
    assert report.cursor.source_sequence == records[-1].ref.source_sequence
    assert len(validation_paths) >= 2
    assert previous_denied is True
    assert previous_unregistered is True
    proof, path, access = validation_paths[-1]
    assert path not in historical._ISSUED_PATHS
    with pytest.raises(historical.HistoricalCoverageUnavailable):
        historical._derive_replay_historical_coverage(proof, path, access)


def test_projecting_replay_access_rejects_value_equal_pcc_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, stale = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (stale,),
    )
    verifier = store._bound_verifier
    assert verifier is not None
    substitute = store._authenticated_pcc_input(
        verifier,
        cast(EvidenceRef, stale.evidence_ref),
        stale.request,
    )
    captured_access: list[object] = []
    real_issue = subject._issue_replay_historical_path_authority

    def capture_access(store_value: Any, proof: Any, access: object) -> object:
        path = real_issue(store_value, proof, access)
        if not captured_access:
            captured_access.append(access)
        return path

    monkeypatch.setattr(subject, "_issue_replay_historical_path_authority", capture_access)
    denied = False

    def probe(step: str) -> None:
        nonlocal denied
        if step != "candidate" or denied:
            return
        assert captured_access
        try:
            historical._issue_replay_historical_path_authority(
                store,
                substitute,
                captured_access[0],
            )
        except historical.HistoricalCoverageUnavailable:
            denied = True

    owner, _connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[-1].ref,
        step_hook=probe,
    )
    owner.close()
    assert report.cursor.source_sequence == records[-1].ref.source_sequence
    assert denied is True


def test_validating_replay_access_rejects_value_equal_pcc_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "validation", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    verifier = store._bound_verifier
    assert verifier is not None
    substitute = store._authenticated_pcc_input(
        verifier,
        cast(EvidenceRef, proof.evidence_ref),
        proof.request,
    )
    validating = False
    denied = False
    real_begin = subject._begin_replay_historical_validation
    real_open = subject._open_replay_historical_access

    def mark_validation(handle: Any) -> None:
        nonlocal validating
        real_begin(handle)
        validating = True

    def reject_substitute(handle: Any, authenticated: Any) -> Any:
        nonlocal denied
        if validating and not denied:
            with pytest.raises(historical.HistoricalCoverageUnavailable):
                real_open(handle, substitute)
            denied = True
        return real_open(handle, authenticated)

    monkeypatch.setattr(subject, "_begin_replay_historical_validation", mark_validation)
    monkeypatch.setattr(subject, "_open_replay_historical_access", reject_substitute)
    owner, _connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[-1].ref,
    )
    owner.close()
    assert report.cursor.source_sequence == records[-1].ref.source_sequence
    assert denied is True


def test_projecting_replay_access_rejects_mutated_session_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, stale = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (stale,),
    )
    captured_path: list[tuple[Any, Any, Any]] = []
    real_issue = subject._issue_replay_historical_path_authority

    def capture_path(store_value: Any, proof: Any, access: Any) -> Any:
        path = real_issue(store_value, proof, access)
        if not captured_path:
            captured_path.append((proof, path, access))
        return path

    monkeypatch.setattr(subject, "_issue_replay_historical_path_authority", capture_path)
    denied = False

    def probe(step: str) -> None:
        nonlocal denied
        if step != "candidate" or denied:
            return
        _proof, path, _access = captured_path[0]
        binding = cast(Any, path)._binding
        assert not hasattr(binding, "session")
        assert not hasattr(binding, "access_epoch")
        assert not hasattr(binding, "access_nonce")
        with pytest.raises(AttributeError):
            object.__setattr__(binding, "access_epoch", 1)
        with pytest.raises(TypeError):
            historical._ReplayAccess(lambda *_args: None)
        denied = True

    owner, _connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[-1].ref,
        step_hook=probe,
    )
    owner.close()
    assert report.cursor.source_sequence == records[-1].ref.source_sequence
    assert denied is True


@pytest.mark.parametrize("phase", ["projecting", "validating"])
def test_replay_access_cannot_be_revived_after_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, stale = _accepted_complete(tmp_path / phase, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (stale,),
    )
    handles: list[Any] = []
    replaced = False
    revived = False
    validation_started = False
    real_open = subject._open_replay_historical_access
    real_issue = subject._issue_replay_historical_path_authority
    real_begin_validation = subject._begin_replay_historical_validation

    def mark_validation(handle: Any) -> None:
        nonlocal validation_started
        real_begin_validation(handle)
        validation_started = True

    def capture_handle(handle: Any, proof: Any) -> Any:
        handles.append(handle)
        return real_open(handle, proof)

    def replace_access(store_value: Any, proof: Any, access: Any) -> Any:
        nonlocal replaced, revived
        path = real_issue(store_value, proof, access)
        current_phase = "validating" if validation_started else "projecting"
        if current_phase != phase or replaced:
            return path
        replaced = True
        real_open(handles[-1], proof)
        try:
            historical._derive_replay_historical_coverage(proof, path, access)
        except historical.HistoricalCoverageUnavailable:
            pass
        else:
            revived = True
        return path

    monkeypatch.setattr(subject, "_open_replay_historical_access", capture_handle)
    monkeypatch.setattr(subject, "_issue_replay_historical_path_authority", replace_access)
    monkeypatch.setattr(authority, "_issue_replay_historical_path_authority", replace_access)
    monkeypatch.setattr(
        subject,
        "_begin_replay_historical_validation",
        mark_validation,
    )
    artifact: object | None = None
    with pytest.raises((ProjectionAuthorityError, CorrelationProjectionError)):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert replaced is True
    assert revived is False
    assert artifact is None
    assert store._closed is True


def test_replay_session_cleanup_clears_state_and_revokes_captured_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, stale = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (stale,),
    )
    captured_path: list[tuple[Any, Any, Any]] = []
    real_issue = subject._issue_replay_historical_path_authority

    def capture_path(store_value: Any, proof: Any, access: Any) -> Any:
        path = real_issue(store_value, proof, access)
        if not captured_path:
            captured_path.append((proof, path, access))
        return path

    monkeypatch.setattr(subject, "_issue_replay_historical_path_authority", capture_path)
    owner, _connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[-1].ref,
    )
    owner.close()
    assert report.cursor.source_sequence == records[-1].ref.source_sequence
    assert store not in historical._REPLAY_STORE_RESERVATIONS
    assert historical._ACTIVE_REPLAY_MARKER.get() is None
    assert not hasattr(historical, "_PENDING_REPLAY_HANDLES")
    assert not hasattr(historical, "_REPLAY_HANDLE_BINDINGS")
    assert not hasattr(historical, "_REPLAY_ACCESS_BINDINGS")
    proof, path, access = captured_path[0]
    with pytest.raises(historical.HistoricalCoverageUnavailable):
        historical._derive_replay_historical_coverage(proof, path, access)


@pytest.mark.parametrize("failure", ["before-handle", "after-handle"])
def test_replay_handle_acquisition_failure_cleans_activation_registries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / failure, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    failure_stage = (
        "handle-created" if failure == "before-handle" else "before-handle-yield"
    )

    def fail_handle_acquisition(stage: str) -> None:
        if stage == failure_stage:
            raise historical.HistoricalCoverageUnavailable(
                "injected handle failure"
            )

    monkeypatch.setattr(
        historical,
        "_replay_setup_checkpoint",
        fail_handle_acquisition,
    )
    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert artifact is None
    assert historical._ACTIVE_REPLAY_MARKER.get() is None
    assert store not in historical._REPLAY_STORE_RESERVATIONS
    assert not hasattr(historical, "_REPLAY_HANDLE_BINDINGS")
    assert not hasattr(historical, "_PENDING_REPLAY_HANDLES")


def test_replay_context_activation_failure_cleans_registries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "activation", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    def fail_after_context(stage: str) -> None:
        if stage == "context-set":
            raise RuntimeError("injected context activation failure")

    monkeypatch.setattr(
        historical,
        "_replay_setup_checkpoint",
        fail_after_context,
    )
    artifact: object | None = None
    with pytest.raises(RuntimeError, match="injected context activation failure"):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert artifact is None
    assert historical._ACTIVE_REPLAY_MARKER.get() is None
    assert store not in historical._REPLAY_STORE_RESERVATIONS


def test_explicit_replay_revoke_unregisters_access_handle_and_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "revoke", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    captured: list[tuple[Any, Any, Any]] = []
    handles: list[Any] = []
    revoked_clean = False
    real_open = subject._open_replay_historical_access
    real_issue = subject._issue_replay_historical_path_authority

    def capture_handle(handle: Any, proof_value: Any) -> Any:
        handles.append(handle)
        return real_open(handle, proof_value)

    def capture_path(store_value: Any, proof_value: Any, access: Any) -> Any:
        path = real_issue(store_value, proof_value, access)
        if not captured:
            captured.append((proof_value, path, access))
        return path

    def revoke_during_candidate(step: str) -> None:
        nonlocal revoked_clean
        if step != "candidate" or revoked_clean:
            return
        _proof, path, access = captured[0]
        historical._complete_replay_historical_session(handles[0])
        revoked_clean = (
            path not in historical._ISSUED_PATHS
            and store not in historical._REPLAY_STORE_RESERVATIONS
            and historical._ACTIVE_REPLAY_MARKER.get() is None
        )
        with pytest.raises(historical.HistoricalCoverageUnavailable):
            historical._derive_replay_historical_coverage(
                proof,
                path,
                access,
            )

    monkeypatch.setattr(subject, "_open_replay_historical_access", capture_handle)
    monkeypatch.setattr(subject, "_issue_replay_historical_path_authority", capture_path)
    artifact: object | None = None
    with pytest.raises((ProjectionAuthorityError, CorrelationProjectionError)):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
            step_hook=revoke_during_candidate,
        )
    assert artifact is None
    assert revoked_clean is True
    assert store._closed is True


def test_unpublished_rollback_restores_projected_head_before_path_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, first, second = _accepted_two_complete(tmp_path / "evidence")
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (first, second),
    )
    verifier = store._bound_verifier
    assert verifier is not None
    second_proof = store._authenticated_pcc_input(
        verifier,
        cast(EvidenceRef, second.evidence_ref),
        second.request,
    )
    captured_connections: list[sqlite3.Connection] = []
    real_connection_factory = subject._v2_connection_for_test

    def capture_connection() -> sqlite3.Connection:
        connection = real_connection_factory()
        captured_connections.append(connection)
        return connection

    monkeypatch.setattr(subject, "_v2_connection_for_test", capture_connection)
    real_iter = type(store).iter_authenticated_records
    slow_path_reads = 0
    check_dispatch = False

    def count_slow_path_reads(
        candidate_store: Any,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        nonlocal slow_path_reads
        if candidate_store is store and check_dispatch:
            slow_path_reads += 1
        return real_iter(candidate_store, after=after, through=through)

    monkeypatch.setattr(
        type(store),
        "iter_authenticated_records",
        count_slow_path_reads,
    )
    rollback_checked = False

    def crash_second_candidate_and_check_rollback(step: str) -> None:
        nonlocal rollback_checked, check_dispatch
        if step == "event" and captured_connections[-1].execute(
            "SELECT count(*) FROM events WHERE event_id=?",
            (second.event_id,),
        ).fetchone()[0] == 1:
            raise _Crash("injected second PCC rollback")
        if step != "rollback":
            return
        rollback_checked = True
        connection = captured_connections[-1]
        assert subject._current_v2_cursor(connection).source_sequence == 5
        assert connection.execute(
            "SELECT count(*) FROM events WHERE event_id=?",
            (second.event_id,),
        ).fetchone()[0] == 0
        check_dispatch = True
        try:
            path = store._historical_path_authority(second_proof)
            historical.derive_historical_coverage(second_proof, path)
        finally:
            check_dispatch = False

    artifact: object | None = None
    with pytest.raises(_Crash, match="second PCC rollback"):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
            step_hook=crash_second_candidate_and_check_rollback,
        )

    assert rollback_checked is True
    assert slow_path_reads == 0
    assert artifact is None
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


def test_unpublished_pcc_commit_phase_denies_historical_path_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, stale_proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (stale_proof,),
    )
    verifier = store._bound_verifier
    assert verifier is not None
    proof = store._authenticated_pcc_input(
        verifier,
        cast(EvidenceRef, stale_proof.evidence_ref),
        stale_proof.request,
    )
    captured_connections: list[sqlite3.Connection] = []
    real_connection_factory = subject._v2_connection_for_test

    def capture_connection() -> sqlite3.Connection:
        connection = real_connection_factory()
        captured_connections.append(connection)
        return connection

    monkeypatch.setattr(subject, "_v2_connection_for_test", capture_connection)
    commit_dispatch_checked = False
    commit_dispatch_denied = False

    def probe_commit_phase(step: str) -> None:
        nonlocal commit_dispatch_checked, commit_dispatch_denied
        if step != "commit" or commit_dispatch_checked:
            return
        cursor = subject._current_v2_cursor(captured_connections[-1])
        if cursor is None or cursor.event_id != proof.event_id:
            return
        commit_dispatch_checked = True
        try:
            path = store._historical_path_authority(proof)
            historical.derive_historical_coverage(proof, path)
        except historical.HistoricalCoverageUnavailable:
            commit_dispatch_denied = True

    owner, _connection, report = (
        subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
            step_hook=probe_commit_phase,
        )
    )
    try:
        assert report.cursor.source_sequence == records[-1].ref.source_sequence
        assert commit_dispatch_checked is True
        assert commit_dispatch_denied is True
    finally:
        owner.close()


@pytest.mark.parametrize(
    "drift",
    [
        "source_order",
        "memo_assessment",
        "verifier",
        "lifecycle",
        "repair",
        "retention",
        "registry_pin",
        "projected_head",
        "compact_transcript",
    ],
)
def test_unpublished_final_independent_rebuild_rejects_drift_without_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / drift,
        ttl_seconds=120,
    )
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    original_lifecycle = store._lifecycle_identity
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    captured_connections: list[sqlite3.Connection] = []
    real_connection_factory = subject._v2_connection_for_test

    def capture_connection() -> sqlite3.Connection:
        connection = real_connection_factory()
        captured_connections.append(connection)
        return connection

    monkeypatch.setattr(subject, "_v2_connection_for_test", capture_connection)
    real_iter = type(store).iter_authenticated_records
    full_reads = 0
    final_rebuild_started = False

    def drift_on_independent_full_read(
        candidate_store: Any,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        nonlocal full_reads, final_rebuild_started
        selected = tuple(real_iter(candidate_store, after=after, through=through))
        if (
            candidate_store is not store
            or after != 0
            or through != records[-1].ref.source_sequence
        ):
            return iter(selected)
        full_reads += 1
        if full_reads != 3:
            return iter(selected)
        final_rebuild_started = True
        if drift == "source_order":
            return iter((selected[1], selected[0], *selected[2:]))
        if drift == "verifier":
            object.__setattr__(store, "_bound_verifier", None)
        elif drift == "lifecycle":
            object.__setattr__(store, "_lifecycle_identity", object())
        elif drift == "repair":
            object.__setattr__(store, "_repair_pending", True)
        elif drift == "retention":
            object.__setattr__(store, "_retention_pending_latched", True)
        elif drift == "registry_pin":
            object.__setattr__(registry, "entries", ())
        elif drift == "projected_head":
            captured_connections[-1].execute(
                "UPDATE ingest_cursors SET source_sequence=?",
                (f"{records[-2].ref.source_sequence:020d}",),
            )
        return iter(selected)

    monkeypatch.setattr(
        type(store),
        "iter_authenticated_records",
        drift_on_independent_full_read,
    )
    if drift == "lifecycle":
        real_begin_validation = subject._begin_replay_historical_validation

        def restore_lifecycle_after_detection(session: Any) -> None:
            try:
                real_begin_validation(session)
            finally:
                object.__setattr__(
                    store,
                    "_lifecycle_identity",
                    original_lifecycle,
                )

        monkeypatch.setattr(
            subject,
            "_begin_replay_historical_validation",
            restore_lifecycle_after_detection,
        )
    if drift == "compact_transcript":
        real_begin_validation = subject._begin_replay_historical_validation

        def remove_accumulated_compact_record(session: Any) -> None:
            assert session.compact_records
            session.compact_records = session.compact_records.freeze()[:-1]
            session.compact_prepared = session.compact_prepared.freeze()[:-1]
            real_begin_validation(session)

        monkeypatch.setattr(
            subject,
            "_begin_replay_historical_validation",
            remove_accumulated_compact_record,
        )
    if drift == "memo_assessment":
        real_reduce = historical._reduce_historical_coverage

        def drift_final_assessment(*args: object, **kwargs: object) -> object:
            timeline = real_reduce(*args, **kwargs)
            if not final_rebuild_started:
                return timeline
            assessment = replace(
                timeline.assessment,
                critical_gap=not timeline.assessment.critical_gap,
            )
            return replace(timeline, assessment=assessment)

        monkeypatch.setattr(
            historical,
            "_reduce_historical_coverage",
            drift_final_assessment,
        )

    artifact: object | None = None
    with pytest.raises((ProjectionAuthorityError, subject.ProjectionConflict)):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=registry,
            through=records[-1].ref,
        )

    assert full_reads == 3
    assert final_rebuild_started is True
    assert artifact is None
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


@pytest.mark.parametrize("field", ["priority", "accepted_at"])
def test_unpublished_final_rebuild_binds_complete_stored_record_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(tmp_path / field, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    real_iter = type(store).iter_authenticated_records
    full_reads = 0

    def substitute_record_fact(
        candidate_store: Any,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        nonlocal full_reads
        selected = tuple(real_iter(candidate_store, after=after, through=through))
        if (
            candidate_store is not store
            or after != 0
            or through != records[-1].ref.source_sequence
        ):
            return iter(selected)
        full_reads += 1
        if full_reads != 3:
            return iter(selected)
        first = selected[0]
        if field == "priority":
            changed = replace(
                first,
                priority=(
                    EvidencePriority.PROTECTED
                    if first.priority is EvidencePriority.ROUTINE
                    else EvidencePriority.ROUTINE
                ),
            )
        else:
            changed = replace(first, accepted_at=T5)
        return iter((changed, *selected[1:]))

    monkeypatch.setattr(
        type(store),
        "iter_authenticated_records",
        substitute_record_fact,
    )
    artifact: tuple[Any, Any, Any] | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                through=records[-1].ref,
            )
    finally:
        if artifact is not None:
            artifact[0].close()

    assert full_reads == 3
    assert artifact is None
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


def test_unpublished_final_seal_binds_authenticated_retired_ranges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    original_ranges = store._authenticated_retired_ranges
    real_begin = subject._begin_replay_historical_validation
    injected = False

    def drift_after_independent_rebuild(session: Any) -> None:
        nonlocal injected
        real_begin(session)
        injected = True
        object.__setattr__(store, "_authenticated_retired_ranges", ((1, 1),))

    monkeypatch.setattr(
        subject,
        "_begin_replay_historical_validation",
        drift_after_independent_rebuild,
    )
    artifact: tuple[Any, Any, Any] | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                through=records[-1].ref,
            )
    finally:
        object.__setattr__(store, "_authenticated_retired_ranges", original_ranges)
        if artifact is not None:
            artifact[0].close()

    assert injected is True
    assert artifact is None
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


@pytest.mark.parametrize("drift", ["detector", "registry"])
def test_unpublished_post_batch_seal_revalidates_exact_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(tmp_path / drift, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    original_entries = registry.entries
    real_seal = subject._seal_completed_snapshot_batch
    injected = False

    def drift_after_batch_seal(batch: object) -> None:
        nonlocal injected
        real_seal(batch)
        injected = True
        if drift == "detector":
            monkeypatch.setattr(
                authority,
                "_load_pinned_detector_bundle",
                lambda: "2" * 64,
            )
        else:
            object.__setattr__(registry, "entries", ())

    monkeypatch.setattr(
        subject,
        "_seal_completed_snapshot_batch",
        drift_after_batch_seal,
    )
    artifact: tuple[Any, Any, Any] | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=registry,
                through=records[-1].ref,
            )
    finally:
        object.__setattr__(registry, "entries", original_entries)
        if artifact is not None:
            artifact[0].close()

    assert injected is True
    assert artifact is None
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


def test_unpublished_post_prefix_source_record_drift_returns_no_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    original = store._records[0]
    real_validate = subject._V2ProjectionOwner._validate_persisted_prefix
    injected = False

    def drift_after_persisted_prefix(owner: Any, *args: object, **kwargs: object) -> str:
        nonlocal injected
        digest = real_validate(owner, *args, **kwargs)
        if historical._ACTIVE_REPLAY_MARKER.get() is not None:
            injected = True
            store._records[0] = replace(original, accepted_at=T5)
        return digest

    monkeypatch.setattr(
        subject._V2ProjectionOwner,
        "_validate_persisted_prefix",
        drift_after_persisted_prefix,
    )
    artifact: tuple[Any, Any, Any] | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                through=records[-1].ref,
            )
    finally:
        store._records[0] = original
        if artifact is not None:
            artifact[0].close()

    assert injected is True
    assert artifact is None
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


@pytest.mark.parametrize("drift", ["lifecycle", "verifier", "repair", "retention"])
def test_unpublished_post_prefix_source_authority_drift_returns_no_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / drift, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    original_lifecycle = store._lifecycle_identity
    original_verifier = store._bound_verifier
    original_repair = store._repair_pending
    original_retention = store._retention_pending_latched
    real_validate = subject._V2ProjectionOwner._validate_persisted_prefix
    injected = False

    def drift_after_persisted_prefix(owner: Any, *args: object, **kwargs: object) -> str:
        nonlocal injected
        digest = real_validate(owner, *args, **kwargs)
        if historical._ACTIVE_REPLAY_MARKER.get() is not None:
            injected = True
            if drift == "lifecycle":
                object.__setattr__(store, "_lifecycle_identity", object())
            elif drift == "verifier":
                object.__setattr__(store, "_bound_verifier", None)
            elif drift == "repair":
                object.__setattr__(store, "_repair_pending", True)
            else:
                object.__setattr__(store, "_retention_pending_latched", True)
        return digest

    monkeypatch.setattr(
        subject._V2ProjectionOwner,
        "_validate_persisted_prefix",
        drift_after_persisted_prefix,
    )
    artifact: object | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                through=records[-1].ref,
            )
    finally:
        object.__setattr__(store, "_lifecycle_identity", original_lifecycle)
        object.__setattr__(store, "_bound_verifier", original_verifier)
        object.__setattr__(store, "_repair_pending", original_repair)
        object.__setattr__(store, "_retention_pending_latched", original_retention)
    assert injected is True
    assert artifact is None
    assert store._closed is True


@pytest.mark.parametrize("drift", ["strict_ack", "journal_cache"])
def test_unpublished_replay_failure_returns_no_artifact_and_closes_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / drift,
        ttl_seconds=120,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    confirmed_records = records[:-1] if drift == "strict_ack" else records
    _confirm_ack(
        acknowledgements,
        *[record.ref for record in confirmed_records],
    )
    tampered = False

    def step_hook(step: str) -> None:
        nonlocal tampered
        if drift == "journal_cache" and step == "candidate" and not tampered:
            tampered = True
            journal._states_by_operation = {}

    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
            step_hook=step_hook,
        )

    assert artifact is None
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


def test_unpublished_replay_rejects_swapped_completed_batch_items(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, first, second = _accepted_two_complete(tmp_path / "evidence")
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, first)
    _complete_journal(journal, second)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    real_items = subject._completed_snapshot_batch_items

    def swapped_items(batch: object) -> tuple[object, ...]:
        return tuple(reversed(real_items(batch)))

    monkeypatch.setattr(subject, "_completed_snapshot_batch_items", swapped_items)
    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )

    assert artifact is None
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


def test_unpublished_prefix_validation_rejects_missing_completed_batch_item(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, _connection = _owner(subject, coordinator, journal)
    try:
        _apply_all(owner, coordinator)
        live_connection, projection_authority = owner._require_usable()
        cursor = subject._current_v2_cursor(live_connection)
        predecessor = subject._predecessor_v2(owner._generation, cursor)

        with pytest.raises(
            ProjectionAuthorityError,
            match="missing completed PCC batch authority",
        ):
            owner._validate_persisted_prefix(
                live_connection,
                projection_authority,
                predecessor,
                cursor,
                {},
            )
    finally:
        owner.close()


def test_different_host_candidate_is_not_invalidated_by_committed_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    coverage_ref = _accept(
        coordinator,
        _generic_critical(
            private_key(11),
            4,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=NOW,
        ).envelope,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        for record in records[:3]:
            owner.apply(record.ref)
        row = connection.execute(
            f"SELECT {','.join(subject._CANDIDATE_COLUMNS)} FROM candidates"
        ).fetchone()
        assert row is not None
        candidate = subject._decode_candidate(row)
        other_host_candidate = ContainmentCandidateV1.model_validate(
            {
                **candidate.model_dump(mode="python"),
                "host_id": OTHER_HOST,
            },
            strict=True,
        )
        encoded = subject._encode_candidate(other_host_candidate)
        connection.execute(
            "UPDATE candidates SET "
            + ",".join(f"{column}=?" for column in subject._CANDIDATE_COLUMNS)
            + " WHERE candidate_id=?",
            (*encoded, candidate.candidate_id),
        )

        result = owner.apply(coverage_ref)

        assert result.cursor.source_sequence == coverage_ref.source_sequence
        assert connection.execute(
            "SELECT count(*) FROM events WHERE event_id=?",
            (coverage_ref.event_id,),
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT count(*) FROM coverage_intervals WHERE event_id=?",
            (coverage_ref.event_id,),
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT count(*) FROM candidate_invalidations"
        ).fetchone()[0] == 0
    finally:
        owner.close()


def test_late_sequence_range_invalidates_despite_later_report_timestamp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    coverage = _gap_open(
        private_key(11),
        4,
        start=proof.snapshot.trigger.source_sequence,
        end=proof.snapshot.trigger.source_sequence,
        opened_at=T5,
    )
    try:
        assert subject._late_coverage_invalidates_candidate(proof, coverage) is True
    finally:
        coordinator.segment_store.close()


def test_nonintersecting_late_window_and_range_do_not_invalidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    outside_time = _generic_critical(
        private_key(11),
        4,
        component="falco-adapter",
        kind="falco_heartbeat_gap",
        opened_at=T5,
        closed_at=T5,
    )
    outside_range = _gap_open(
        private_key(11),
        4,
        start=1,
        end=1,
        opened_at=T5,
    )
    try:
        assert subject._late_coverage_invalidates_candidate(proof, outside_time) is False
        assert subject._late_coverage_invalidates_candidate(proof, outside_range) is False
    finally:
        coordinator.segment_store.close()


def test_late_invalidation_survives_close_event_and_exact_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    opened = _accept(
        coordinator,
        _generic_critical(
            private_key(11),
            4,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
        ).envelope,
    )
    closed = _accept(
        coordinator,
        _generic_critical(
            private_key(11),
            5,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=NOW,
        ).envelope,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        _apply_all(owner, coordinator)
        before = subject._v2_ordered_table_rows(connection, "candidate_invalidations")

        retry = owner.apply(closed)

        assert retry.reducer_applied is False
        assert subject._v2_ordered_table_rows(
            connection,
            "candidate_invalidations",
        ) == before
        assert {row[1] for row in before} == {opened.event_id, closed.event_id}
    finally:
        owner.close()


def test_transport_duplicate_late_coverage_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    primary = _accept(
        coordinator,
        _generic_critical(
            private_key(11),
            4,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=NOW,
        ).envelope,
    )
    duplicate = _accept(
        coordinator,
        _generic_critical(
            private_key(11),
            5,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=NOW,
        ).envelope,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        _apply_all(owner, coordinator)

        rows = connection.execute(
            "SELECT coverage_event_id FROM candidate_invalidations"
        ).fetchall()
        assert [row[0] for row in rows] == [primary.event_id]
        dedup = connection.execute(
            "SELECT duplicate_of_event_id FROM events WHERE event_id=?",
            (duplicate.event_id,),
        ).fetchone()
        assert dedup is not None
        assert dedup[0] == primary.event_id
    finally:
        owner.close()


@pytest.mark.parametrize("crash_ordinal", [1, 2, 3], ids=["first", "middle", "last"])
def test_invalidation_write_crash_rolls_back_coverage_event_and_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_ordinal: int,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proofs, coverage = _accepted_three_complete_with_late_coverage(
        tmp_path / "evidence"
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    for proof in proofs:
        _complete_journal(journal, proof)
    armed = False
    invalidation_writes = 0

    def crash(step: str) -> None:
        nonlocal invalidation_writes
        if armed and step == "candidate_invalidation":
            invalidation_writes += 1
            if invalidation_writes == crash_ordinal:
                raise _Crash("injected invalidation write crash")

    owner, connection = _owner(
        subject,
        coordinator,
        journal,
        step_hook=crash,
    )
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        for record in records[:-1]:
            owner.apply(record.ref)

        armed = True
        with pytest.raises(_Crash):
            owner.apply(coverage)

        assert connection.execute(
            "SELECT count(*) FROM events WHERE event_id=?",
            (coverage.event_id,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM coverage_intervals WHERE event_id=?",
            (coverage.event_id,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM candidate_invalidations"
        ).fetchone()[0] == 0
        assert owner.status().cursor.source_sequence == proofs[-1].source_sequence

        armed = False
        owner.apply(coverage)
        assert connection.execute(
            "SELECT count(*) FROM candidate_invalidations"
        ).fetchone()[0] == 3
    finally:
        owner.close()


def _append_boundary_candidate(
    coordinator: Any,
    journal: CorrelationRequestJournal,
    *,
    number: int,
    trigger_sequence: int,
    at: str,
) -> AuthenticatedPCCInput:
    key = private_key(11)
    trigger = _candidate_trigger(key, sequence=trigger_sequence)
    fields = trigger["normalized_fields"]
    assert isinstance(fields, dict)
    raw_sha256 = hashlib.sha256(f"boundary-trigger-{number}".encode()).hexdigest()
    fields["destination_ipv4"] = (
        f"11.{number >> 16}.{number >> 8 & 255}.{number & 255}"
    )
    fields["raw_event_sha256"] = raw_sha256
    fields["event_time"] = at
    trigger["source_payload_hash"] = raw_sha256
    trigger["event_time"] = at
    trigger["ingest_time"] = at
    _resign_pcc_envelope(trigger, key)
    _accept(coordinator, trigger)
    request = _request(trigger, ttl_seconds=120)
    snapshot_fields = _complete_snapshot(trigger, request)
    snapshot_fields["coverage_through_sequence"] = trigger_sequence
    snapshot_fields["decision_time"] = at
    snapshot_fields["inventory_observed_at"] = at
    snapshot = _snapshot_envelope(
        key,
        snapshot_fields,
        sequence=trigger_sequence + 1,
    )
    snapshot["event_time"] = at
    snapshot["ingest_time"] = at
    _resign_pcc_envelope(snapshot, key)
    proof = coordinator.accept_pcc_for_correlation(_item(snapshot), request)
    _complete_journal(journal, proof)
    return proof


def _exercise_authenticated_late_boundary(
    subject: Any,
    root: Path,
    *,
    count: int,
    captured_connections: list[sqlite3.Connection],
) -> None:
    key = private_key(11)
    coordinator = _coordinator(root, key)
    _accept(coordinator, boot_boundary(key))
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    for number in range(count):
        _append_boundary_candidate(
            coordinator,
            journal,
            number=number,
            trigger_sequence=2 + number * 2,
            at=NOW,
        )
    first_coverage = _accept(
        coordinator,
        _generic_critical(
            key,
            2 + count * 2,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=NOW,
        ).envelope,
    )
    assert type(first_coverage) is EvidenceRef
    acknowledgements = AckJournal.create_new(coordinator.segment_store)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    owner, connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=coordinator.segment_store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=first_coverage,
    )
    assert report.cursor.source_sequence == first_coverage.source_sequence
    assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == count
    assert connection.execute(
        "SELECT count(*) FROM candidate_invalidations"
    ).fetchone()[0] == count
    owner.close()

    recovered_coordinator, recovered_store = _reopen_evidence(root)
    recovered_journal = CorrelationRequestJournal.open_and_recover(recovered_store)
    recovered_acknowledgements = AckJournal.open_and_recover(recovered_store)
    trigger_sequence = first_coverage.source_sequence + 1
    last_proof = _append_boundary_candidate(
        recovered_coordinator,
        recovered_journal,
        number=count,
        trigger_sequence=trigger_sequence,
        at=T5,
    )
    second_coverage = _accept(
        recovered_coordinator,
        _generic_critical(
            key,
            trigger_sequence + 2,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=T5,
            closed_at=T5,
        ).envelope,
    )
    assert type(second_coverage) is EvidenceRef
    appended = tuple(
        recovered_store.iter_authenticated_records(
            after=first_coverage.source_sequence,
        )
    )
    _confirm_ack(recovered_acknowledgements, *[record.ref for record in appended])
    assert last_proof.snapshot.trigger.event_time == T5
    rollback_checked = False

    def assert_failed_coverage_rolled_back(step: str) -> None:
        nonlocal rollback_checked
        if step != "rollback":
            return
        rollback_checked = True
        failed_connection = captured_connections[-1]
        assert failed_connection.in_transaction is False
        assert failed_connection.execute(
            "SELECT count(*) FROM events WHERE event_id=?",
            (second_coverage.event_id,),
        ).fetchone()[0] == 0
        assert failed_connection.execute(
            "SELECT count(*) FROM coverage_intervals WHERE event_id=?",
            (second_coverage.event_id,),
        ).fetchone()[0] == 0
        assert failed_connection.execute(
            "SELECT count(*) FROM candidate_invalidations"
        ).fetchone()[0] == count
        snapshot_ref = cast(EvidenceRef, last_proof.evidence_ref)
        assert subject._current_v2_cursor(failed_connection) == subject.ProjectionCursor(
            host_id=last_proof.snapshot.host_id,
            source_sequence=snapshot_ref.source_sequence,
            event_id=snapshot_ref.event_id,
            content_sha256=snapshot_ref.content_sha256,
            frame_sha256=snapshot_ref.frame_sha256,
        )

    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError, match="late coverage authority"):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=recovered_store,
            acknowledgements=recovered_acknowledgements,
            journal=recovered_journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=second_coverage,
            step_hook=assert_failed_coverage_rolled_back,
        )
    assert artifact is None
    assert rollback_checked is True
    assert recovered_store._closed is True
    assert recovered_journal._closed is True
    assert recovered_acknowledgements._closed is True


def test_authenticated_late_boundary_uses_production_source_replay_small(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    monkeypatch.setattr(subject, "_INVALIDATION_CANDIDATE_CAP_V2", 4)
    captured_connections: list[sqlite3.Connection] = []
    real_connection_factory = subject._v2_connection_for_test

    def captured_connection_factory() -> sqlite3.Connection:
        connection = real_connection_factory()
        captured_connections.append(connection)
        return connection

    monkeypatch.setattr(
        subject,
        "_v2_connection_for_test",
        captured_connection_factory,
    )
    _exercise_authenticated_late_boundary(
        subject,
        tmp_path / "small",
        count=4,
        captured_connections=captured_connections,
    )


def test_late_candidate_boundary_uses_authenticated_completed_pccs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    monkeypatch.setattr(os, "fsync", lambda _fd: None)
    captured_connections: list[sqlite3.Connection] = []
    real_connection_factory = subject._v2_connection_for_test

    def captured_connection_factory() -> sqlite3.Connection:
        connection = real_connection_factory()
        captured_connections.append(connection)
        return connection

    monkeypatch.setattr(
        subject,
        "_v2_connection_for_test",
        captured_connection_factory,
    )
    _exercise_authenticated_late_boundary(
        subject,
        tmp_path / "evidence",
        count=4_096,
        captured_connections=captured_connections,
    )


def test_complete_pcc_without_completed_journal_rolls_back_event_and_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        records = tuple(coordinator.segment_store.iter_authenticated_records())
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()

        with pytest.raises(ProjectionAuthorityError):
            owner.apply(cast(EvidenceRef, proof.evidence_ref))

        assert owner.snapshot_hash() == before
        assert connection.execute(
            "SELECT source_sequence FROM ingest_cursors"
        ).fetchone()[0] == "00000000000000000002"
        assert connection.execute(
            "SELECT count(*) FROM events WHERE event_id=?",
            (proof.event_id,),
        ).fetchone()[0] == 0
    finally:
        owner.close()


@pytest.mark.parametrize(
    ("detector_hash", "reason"),
    [
        (
            "2" * 64,
            "detector_bundle_not_pinned",
        ),
    ],
    ids=("detector-mismatch",),
)
def test_safe_pin_mismatch_persists_rejection_and_advances_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    detector_hash: str,
    reason: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: detector_hash,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        _apply_all(owner, coordinator)
        row = connection.execute(
            "SELECT result_kind,reason_codes FROM incidents"
        ).fetchone()
        assert row is not None
        assert tuple(row) == (
            "rejected",
            canonical_json((reason,)).decode("utf-8"),
        )
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == proof.source_sequence
    finally:
        owner.close()


def test_safely_loaded_special_use_hash_mismatch_persists_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    primitives = importlib.import_module("agmind_immune.correlation.primitives")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    monkeypatch.setattr(
        primitives,
        "PCC_SPECIAL_USE_REGISTRY_SHA256",
        "2" * 64,
    )
    owner, connection = _owner(
        subject,
        coordinator,
        journal,
        registry=registry,
    )
    try:
        _apply_all(owner, coordinator)
        row = connection.execute(
            "SELECT result_kind,reason_codes FROM incidents"
        ).fetchone()
        assert row is not None
        assert tuple(row) == (
            "rejected",
            canonical_json(("correlation_proof_mismatch",)).decode("utf-8"),
        )
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == proof.source_sequence
    finally:
        owner.close()


@pytest.mark.parametrize(
    ("history", "reason"),
    [
        ("open-structural-gap", "historical_coverage_incomplete"),
        ("closed-critical-episode", "critical_coverage_gap"),
    ],
)
def test_authenticated_historical_gap_persists_rejection_and_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    history: str,
    reason: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete_with_history(
        tmp_path / "evidence",
        history=history,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        _apply_all(owner, coordinator)
        row = connection.execute(
            "SELECT result_kind,reason_codes,authority_event_id FROM incidents"
        ).fetchone()
        assert row is not None
        assert tuple(row) == (
            "rejected",
            canonical_json((reason,)).decode("utf-8"),
            proof.event_id,
        )
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == proof.source_sequence
    finally:
        owner.close()


def test_safe_duplicate_keeps_primary_and_adds_supporting_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, first, coverage, second = _accepted_two_complete_around_late_coverage(
        tmp_path / "evidence"
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, first)
    _complete_journal(journal, second)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        records = tuple(coordinator.segment_store.iter_authenticated_records())
        for record in records[:4]:
            owner.apply(record.ref)
        candidates = connection.execute(
            "SELECT candidate_id,primary_event_id FROM candidates"
        ).fetchall()
        assert len(candidates) == 1
        candidate_id = str(candidates[0]["candidate_id"])
        assert candidates[0]["primary_event_id"] == first.snapshot.trigger.event_id
        invalidation = connection.execute(
            "SELECT coverage_event_id FROM candidate_invalidations"
        ).fetchone()
        assert invalidation is not None
        assert invalidation[0] == coverage.event_id
        for record in records[4:]:
            owner.apply(record.ref)
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 2
        roles = connection.execute(
            "SELECT evidence_event_id,role,authority_snapshot_event_id "
            "FROM candidate_evidence WHERE candidate_id=? ORDER BY role",
            (candidate_id,),
        ).fetchall()
        assert [tuple(row) for row in roles] == sorted(
            [
                (
                    first.event_id,
                    "correlation_snapshot",
                    first.event_id,
                ),
                (
                    first.snapshot.trigger.event_id,
                    "primary_trigger",
                    first.event_id,
                ),
                (
                    second.event_id,
                    "supporting_snapshot",
                    second.event_id,
                ),
                (
                    second.snapshot.trigger.event_id,
                    "supporting_trigger",
                    second.event_id,
                ),
            ],
            key=lambda item: item[1],
        )
    finally:
        owner.close()


@pytest.mark.parametrize(
    "revocation_step",
    ["candidate_evidence_snapshot", "cursor"],
)
def test_completed_capability_is_revalidated_after_all_write_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    revocation_step: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, first, second = _accepted_two_complete(tmp_path / "evidence")
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, first)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()
        second_trigger_ref = coordinator.verifier.accepted_ref(
            second.snapshot.trigger.source_sequence
        )
        assert type(second_trigger_ref) is EvidenceRef

        def revoke_after_candidate(step: str) -> None:
            if step == revocation_step:
                journal.select(
                    second_trigger_ref,
                    canonical_json(second.request),
                )

        owner._step_hook = revoke_after_candidate
        with pytest.raises(ProjectionAuthorityError):
            owner.apply(records[2].ref)

        assert owner.snapshot_hash() == before
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 2
    finally:
        owner.close()


def test_owner_factory_rejects_closed_journal_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, _authenticated = _accepted_direct_falco(
        tmp_path / "evidence",
        investigation_only=True,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    journal.close()
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = subject._v2_connection_for_test()
    try:
        with pytest.raises(ProjectionAuthorityError):
            subject._v2_projection_owner_for_test(
                connection,
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            )
    finally:
        connection.close()
        if not getattr(acknowledgements, "_closed", True):
            acknowledgements.close()
        if not getattr(store, "_closed", True):
            store.close()


@pytest.mark.parametrize("drift", ["detector", "registry"])
def test_terminal_source_iteration_rechecks_external_pins_before_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / drift, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    original_entries = registry.entries
    batches_sealed = False
    injected = False
    real_batch_seal = subject._seal_completed_snapshot_batch
    real_iter = type(store).iter_authenticated_records

    def mark_batch_sealed(batch: object) -> None:
        nonlocal batches_sealed
        real_batch_seal(batch)
        batches_sealed = True

    def drift_during_terminal_iteration(
        candidate_store: Any,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        nonlocal injected
        selected = tuple(real_iter(candidate_store, after=after, through=through))
        if candidate_store is store and batches_sealed and not injected:
            injected = True
            if drift == "detector":
                monkeypatch.setattr(
                    authority,
                    "_load_pinned_detector_bundle",
                    lambda: "2" * 64,
                )
            else:
                object.__setattr__(registry, "entries", ())
        return iter(selected)

    monkeypatch.setattr(subject, "_seal_completed_snapshot_batch", mark_batch_sealed)
    monkeypatch.setattr(type(store), "iter_authenticated_records", drift_during_terminal_iteration)
    artifact: object | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=registry,
                through=records[-1].ref,
            )
    finally:
        object.__setattr__(registry, "entries", original_entries)
    assert injected is True
    assert artifact is None
    assert store._closed is True


def test_terminal_source_iteration_rechecks_resident_append_before_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "evidence", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    batches_sealed = False
    injected = False
    real_batch_seal = subject._seal_completed_snapshot_batch
    real_iter = type(store).iter_authenticated_records

    def mark_batch_sealed(batch: object) -> None:
        nonlocal batches_sealed
        real_batch_seal(batch)
        batches_sealed = True

    def append_during_terminal_iteration(
        candidate_store: Any,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        nonlocal injected
        selected = tuple(real_iter(candidate_store, after=after, through=through))
        if candidate_store is store and batches_sealed and not injected:
            injected = True
            store._records.append(store._records[-1])
        return iter(selected)

    monkeypatch.setattr(subject, "_seal_completed_snapshot_batch", mark_batch_sealed)
    monkeypatch.setattr(type(store), "iter_authenticated_records", append_during_terminal_iteration)
    artifact: object | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                through=records[-1].ref,
            )
    finally:
        if len(store._records) > len(records):
            store._records.pop()
    assert injected is True
    assert artifact is None
    assert store._closed is True


def test_terminal_source_iteration_revalidates_exact_ack_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / "ack-touch", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    batches_sealed = False
    replaced = False
    original_descriptor = acknowledgements._descriptor
    real_batch_seal = subject._seal_completed_snapshot_batch
    real_iter = type(store).iter_authenticated_records

    def mark_batch_sealed(batch: object) -> None:
        nonlocal batches_sealed
        real_batch_seal(batch)
        batches_sealed = True

    def touch_ack_during_terminal_iteration(
        candidate_store: Any,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        nonlocal replaced
        selected = tuple(real_iter(candidate_store, after=after, through=through))
        if candidate_store is store and batches_sealed and not replaced:
            replaced = True
            acknowledgements._descriptor = os.dup(original_descriptor)
        return iter(selected)

    monkeypatch.setattr(subject, "_seal_completed_snapshot_batch", mark_batch_sealed)
    monkeypatch.setattr(type(store), "iter_authenticated_records", touch_ack_during_terminal_iteration)
    artifact: object | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                through=records[-1].ref,
            )
    finally:
        try:
            os.close(original_descriptor)
        except OSError:
            pass
    assert replaced is True
    assert artifact is None
    assert store._closed is True


@pytest.mark.parametrize("mutation", ["predecessor", "registry"])
def test_terminal_predecessor_and_pins_use_one_exact_authority_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    coordinator, proof = _accepted_complete(tmp_path / "authority", ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    original_entries = registry.entries
    captured_authority: list[Any] = []
    batches_sealed = False
    injected = False
    real_predecessor = subject._validate_correlation_projection_predecessor
    real_batch_seal = subject._seal_completed_snapshot_batch

    def capture_predecessor(authority_value: Any, expected: Any) -> None:
        if not captured_authority:
            captured_authority.append(authority_value)
        real_predecessor(authority_value, expected)

    def mark_batch_sealed(batch: object) -> None:
        nonlocal batches_sealed
        real_batch_seal(batch)
        batches_sealed = True

    def mutate_authority_while_loading_pins() -> str:
        nonlocal injected
        if batches_sealed and captured_authority and not injected:
            injected = True
            if mutation == "predecessor":
                binding = authority._authority_binding(captured_authority[0])
                binding.predecessor = replace(
                    binding.predecessor,
                    generation=binding.predecessor.generation + 1,
                )
            else:
                object.__setattr__(registry, "entries", ())
        return _DETECTOR_HASH

    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        mutate_authority_while_loading_pins,
    )
    monkeypatch.setattr(
        subject,
        "_validate_correlation_projection_predecessor",
        capture_predecessor,
    )
    monkeypatch.setattr(subject, "_seal_completed_snapshot_batch", mark_batch_sealed)
    artifact: object | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=registry,
                through=records[-1].ref,
            )
    finally:
        object.__setattr__(registry, "entries", original_entries)
    assert injected is True
    assert artifact is None
    assert store._closed is True


@pytest.mark.parametrize("drift", ["ack", "cursor", "hash", "predecessor", "status"])
def test_terminal_source_iteration_rechecks_external_authority_before_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proof = _accepted_complete(tmp_path / drift, ttl_seconds=120)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    connections: list[sqlite3.Connection] = []
    batches_sealed = False
    injected = False
    original_ack_generation = acknowledgements._confirmed_generation
    original_repair = store._repair_pending
    captured_authorities: list[Any] = []
    real_connection_factory = subject._v2_connection_for_test
    real_batch_seal = subject._seal_completed_snapshot_batch
    real_iter = type(store).iter_authenticated_records
    real_hash = subject._v2_snapshot_hash
    real_predecessor = subject._validate_correlation_projection_predecessor

    def capture_connection() -> sqlite3.Connection:
        connection = real_connection_factory()
        connections.append(connection)
        return connection

    def mark_batch_sealed(batch: object) -> None:
        nonlocal batches_sealed
        real_batch_seal(batch)
        batches_sealed = True

    def observed_hash(connection: sqlite3.Connection) -> str:
        if injected and drift == "hash":
            return "0" * 64
        return real_hash(connection)

    def validate_predecessor(*args: object, **kwargs: object) -> None:
        if not captured_authorities:
            captured_authorities.append(args[0])
        real_predecessor(*args, **kwargs)

    def drift_during_terminal_iteration(
        candidate_store: Any,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        nonlocal injected
        selected = tuple(real_iter(candidate_store, after=after, through=through))
        if candidate_store is store and batches_sealed and not injected:
            injected = True
            if drift == "ack":
                acknowledgements._confirmed_generation += 1
            elif drift == "cursor":
                connections[0].execute(
                    "UPDATE ingest_cursors SET source_sequence=?",
                    (f"{records[-2].ref.source_sequence:020d}",),
                )
            elif drift == "predecessor":
                binding = authority._authority_binding(
                    captured_authorities[0]
                )
                binding.predecessor = replace(
                    binding.predecessor,
                    generation=binding.predecessor.generation + 1,
                )
            elif drift == "status":
                object.__setattr__(store, "_repair_pending", True)
        return iter(selected)

    monkeypatch.setattr(subject, "_v2_connection_for_test", capture_connection)
    monkeypatch.setattr(subject, "_seal_completed_snapshot_batch", mark_batch_sealed)
    monkeypatch.setattr(subject, "_v2_snapshot_hash", observed_hash)
    monkeypatch.setattr(
        subject,
        "_validate_correlation_projection_predecessor",
        validate_predecessor,
    )
    monkeypatch.setattr(type(store), "iter_authenticated_records", drift_during_terminal_iteration)
    artifact: object | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                through=records[-1].ref,
            )
    finally:
        acknowledgements._confirmed_generation = original_ack_generation
        object.__setattr__(store, "_repair_pending", original_repair)
    assert injected is True
    assert artifact is None
    assert store._closed is True


@pytest.mark.parametrize(
    "drift",
    ["projected_head", "compact_order", "compact_count", "compact_digest", "memo_closure"],
)
def test_terminal_seal_rechecks_complete_session_state_after_batches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proofs = _accepted_unpublished_compact_history(tmp_path / drift)
    store, journal, acknowledgements, records = _unpublished_resources(coordinator, proofs)
    memo_leaves: list[Any] = []
    injected = False
    historical = importlib.import_module("agmind_immune.coverage.historical")
    real_memo_leaf = historical._build_replay_memo_leaf
    real_seal = subject._seal_completed_snapshot_batch

    def capture_memo(*args: object, **kwargs: object) -> Any:
        leaf = real_memo_leaf(*args, **kwargs)
        if not memo_leaves:
            memo_leaves.append(leaf)
        return leaf

    def mutate_after_batch(batch: object) -> None:
        nonlocal injected
        real_seal(batch)
        if injected:
            return
        injected = True
        memo = memo_leaves[0]
        if drift == "projected_head":
            object.__setattr__(memo, "compact_count", memo.compact_count - 1)
        elif drift == "compact_order":
            object.__setattr__(memo, "key", tuple(reversed(memo.key)))
        elif drift == "compact_count":
            object.__setattr__(memo, "compact_count", bool(memo.compact_count))
        elif drift == "compact_digest":
            object.__setattr__(memo, "compact_digest", "0" * 64)
        else:
            object.__setattr__(memo, "facts_digest", b"0" * 32)

    monkeypatch.setattr(historical, "_build_replay_memo_leaf", capture_memo)
    monkeypatch.setattr(subject, "_seal_completed_snapshot_batch", mutate_after_batch)
    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert artifact is None
    assert injected is True


@pytest.mark.parametrize(
    "mutation",
    [
        "reverse",
        "sort",
        "insert",
        "extend",
        "remove",
        "delitem",
        "iadd",
        "imul",
        "base_reverse",
    ],
)
def test_validated_compact_ledger_rejects_every_mutation_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proofs = _accepted_unpublished_compact_history(tmp_path / mutation)
    store, journal, acknowledgements, records = _unpublished_resources(coordinator, proofs)
    memo_leaves: list[Any] = []
    pcc_leaves: list[Any] = []
    injected = False
    historical = importlib.import_module("agmind_immune.coverage.historical")
    real_memo_leaf = historical._build_replay_memo_leaf
    real_pcc_leaf = historical._build_replay_pcc_leaf
    real_seal = subject._seal_completed_snapshot_batch

    def capture_memo(*args: object, **kwargs: object) -> Any:
        leaf = real_memo_leaf(*args, **kwargs)
        if not memo_leaves:
            memo_leaves.append(leaf)
        return leaf

    def capture_pcc(*args: object, **kwargs: object) -> Any:
        leaf = real_pcc_leaf(*args, **kwargs)
        if not pcc_leaves:
            pcc_leaves.append(leaf)
        return leaf

    def mutate_after_batch(batch: object) -> None:
        nonlocal injected
        real_seal(batch)
        if injected:
            return
        injected = True
        memo = memo_leaves[0]
        pcc = pcc_leaves[0]
        if mutation == "reverse":
            object.__setattr__(memo, "key", tuple(reversed(memo.key)))
        elif mutation == "sort":
            object.__setattr__(memo, "assessment", replace(memo.assessment))
        elif mutation == "insert":
            object.__setattr__(memo, "interval_count", memo.interval_count + 1)
        elif mutation == "extend":
            object.__setattr__(memo, "interval_digest", b"0" * 32)
        elif mutation == "remove":
            object.__setattr__(memo, "event_count", memo.event_count + 1)
        elif mutation == "delitem":
            object.__setattr__(memo, "facts_digest", b"0" * 32)
        elif mutation == "iadd":
            object.__setattr__(pcc, "request", pcc.request.model_copy(deep=True))
        elif mutation == "imul":
            object.__setattr__(memo, "compact_count", bool(memo.compact_count))
        else:
            class KeySubclass(tuple):
                pass

            object.__setattr__(memo, "key", KeySubclass(memo.key))

    monkeypatch.setattr(historical, "_build_replay_memo_leaf", capture_memo)
    monkeypatch.setattr(historical, "_build_replay_pcc_leaf", capture_pcc)
    monkeypatch.setattr(subject, "_seal_completed_snapshot_batch", mutate_after_batch)
    artifact: object | None = None
    with pytest.raises((ProjectionAuthorityError, AttributeError, TypeError)):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert injected is True
    assert artifact is None
    assert store._closed is True


@pytest.mark.parametrize(
    "mutation",
    [
        "projected_head",
        "compact_order",
        "compact_pairing",
        "compact_count",
        "compact_digest",
        "used_pcc",
        "memo",
        "validated_closure",
    ],
)
def test_terminal_callback_cannot_mutate_validated_session_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    coordinator, proofs = _accepted_unpublished_compact_history(tmp_path / mutation)
    store, journal, acknowledgements, records = _unpublished_resources(coordinator, proofs)
    verifier = store._bound_verifier
    assert verifier is not None
    substitute = store._authenticated_pcc_input(
        verifier,
        cast(EvidenceRef, proofs[0].evidence_ref),
        proofs[0].request,
    )
    injected = False
    historical = importlib.import_module("agmind_immune.coverage.historical")
    memo_leaves: list[Any] = []
    pcc_leaves: list[Any] = []
    real_memo_leaf = historical._build_replay_memo_leaf
    real_pcc_leaf = historical._build_replay_pcc_leaf
    real_final = subject._final_seal_replay_historical_session

    def capture_memo(*args: object, **kwargs: object) -> Any:
        leaf = real_memo_leaf(*args, **kwargs)
        if not memo_leaves:
            memo_leaves.append(leaf)
        return leaf

    def capture_pcc(*args: object, **kwargs: object) -> Any:
        leaf = real_pcc_leaf(*args, **kwargs)
        if not pcc_leaves:
            pcc_leaves.append(leaf)
        return leaf

    def mutate_after_external_check(handle: Any, callback: Any) -> None:
        def wrapped_callback() -> None:
            nonlocal injected
            callback()
            injected = True
            memo = memo_leaves[0]
            pcc = pcc_leaves[0]
            if mutation == "projected_head":
                object.__setattr__(memo, "compact_count", memo.compact_count - 1)
            elif mutation == "compact_order":
                object.__setattr__(memo, "key", tuple(reversed(memo.key)))
            elif mutation == "compact_pairing":
                class KeySubclass(tuple):
                    pass

                object.__setattr__(memo, "key", KeySubclass(memo.key))
            elif mutation == "compact_count":
                object.__setattr__(memo, "compact_count", bool(memo.compact_count))
            elif mutation == "compact_digest":
                object.__setattr__(memo, "compact_digest", "0" * 64)
            elif mutation == "used_pcc":
                object.__setattr__(pcc, "pcc", substitute)
            elif mutation == "memo":
                object.__setattr__(memo, "assessment", replace(memo.assessment))
            else:
                object.__setattr__(memo, "facts_digest", b"0" * 32)

        real_final(handle, wrapped_callback)

    monkeypatch.setattr(historical, "_build_replay_memo_leaf", capture_memo)
    monkeypatch.setattr(historical, "_build_replay_pcc_leaf", capture_pcc)
    monkeypatch.setattr(
        subject,
        "_final_seal_replay_historical_session",
        mutate_after_external_check,
    )
    artifact: object | None = None
    with pytest.raises(ProjectionAuthorityError):
        artifact = subject._v2_unpublished_projection_from_prefix_for_test(
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            through=records[-1].ref,
        )
    assert injected is True
    assert artifact is None
    assert store._closed is True


def test_unpublished_final_callback_contains_completed_authenticated_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    key, acceptance, store, coverage = _live_store_with_active_routine(
        tmp_path / "evidence"
    )
    acknowledgements = store._ack_journal_owner
    verifier = store._bound_verifier
    assert type(acknowledgements) is AckJournal
    assert verifier is not None
    journal = CorrelationRequestJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    assert tuple(record.ref.source_sequence for record in records) == (1, 2)
    before_authority = verifier._authority
    retention_journals: list[Any] = []
    retention_attempted = False
    real_final = subject._final_seal_replay_historical_session

    def complete_retention() -> None:
        nonlocal retention_attempted
        retention_attempted = True
        selected_snapshot = store._freeze_retention_snapshot(
            _proof_clock(),
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        decision = retention_module.select_retention(
            selected_snapshot,
            request_id=RETENTION_REQUEST_ID,
        )
        request = decision.request
        assert type(request) is RetentionTombstoneV2
        retention_journal = retention_module._open_retention_state_journal(store)
        retention_journals.append(retention_journal)
        retention_journal.prepare_publication(decision)
        state = retention_journal.state
        assert state is not None and state.phase == "selected"
        selected_paths = tuple(
            store.root / entry.segment_relative_path for entry in state.entries
        )
        target_item = _item(
            envelope_value(
                key,
                sequence=3,
                event_type="retention_tombstone",
                normalized_fields=request.model_dump(mode="python"),
            )
        )
        target_ref = acceptance.accept(target_item)
        appended_authority = verifier._authority
        coverage._apply_live_accepted(store, target_ref, None)
        acknowledgements.record_pending(target_ref)
        acknowledgements.record_confirmed(target_ref)
        target = retention_module.RetentionTargetV1(
            sequence=target_item.sequence,
            event_id=target_item.event_id,
            content_sha256=target_item.content_sha256,
        )
        retention_journal.bind_target(target)
        retention_journal.advance_evidence_appended(target)
        final_snapshot = store._freeze_retention_snapshot(
            _proof_clock(seconds=1),
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        proof = store._authenticate_retention_tombstone(
            retention_journal,
            final_snapshot,
            target_ref,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        completion = store._execute_authenticated_retention_unlink(
            proof,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        retired_authority = verifier._authority
        store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        raise AssertionError(
            "authenticated retention mutated beneath the terminal source fence: "
            f"{appended_authority!r} {retired_authority!r} {selected_paths!r}"
        )

    def final_with_retention(handle: Any, callback: Any) -> None:
        def checked_then_retained() -> None:
            callback()
            complete_retention()

        real_final(handle, checked_then_retained)

    monkeypatch.setattr(
        subject,
        "_final_seal_replay_historical_session",
        final_with_retention,
    )
    artifact: object | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = subject._v2_unpublished_projection_from_prefix_for_test(
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                through=records[-1].ref,
            )
    finally:
        if not getattr(coverage, "_closed", False):
            coverage.close()
    assert artifact is None
    assert retention_attempted is True
    assert retention_journals == []
    assert verifier._authority is before_authority
    assert set(before_authority.accepted) == {1, 2}
    assert tuple(record.ref.source_sequence for record in store._records) == (1, 2)
    assert tuple(store._authenticated_retired_ranges) == ()
    assert store._read_only_reason is None
    assert store._repair_pending is False
    assert store._retention_pending_latched is False
    assert historical._ACTIVE_REPLAY_MARKER.get() is None
    assert store not in historical._REPLAY_STORE_RESERVATIONS
    assert not hasattr(historical, "_REPLAY_HANDLE_BINDINGS")
    assert not hasattr(historical, "_REPLAY_ACCESS_BINDINGS")
    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True


def test_apply_rejects_equality_laundered_ref_before_source_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, _authenticated = _accepted_direct_falco(
        tmp_path / "evidence",
        investigation_only=True,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    owner, connection = _owner(subject, coordinator, journal)
    record = next(coordinator.segment_store.iter_authenticated_records())
    ref = record.ref
    laundered = _EqualityLaunderedRef(
        segment_id=ref.segment_id,
        segment_relative_path=ref.segment_relative_path,
        frame_offset=ref.frame_offset,
        frame_size=ref.frame_size,
        frame_sha256=ref.frame_sha256,
        event_id="evt_" + "f" * 64,
        source_sequence=ref.source_sequence,
        content_sha256="e" * 64,
    )
    try:
        with pytest.raises(ProjectionAuthorityError):
            owner.apply(laundered)
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        assert owner.status().cursor is None
    finally:
        owner.close()


def test_duplicate_primary_equal_to_current_trigger_order_is_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, first, second = _accepted_two_complete(tmp_path / "evidence")
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, first)
    _complete_journal(journal, second)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        for record in records[:5]:
            owner.apply(record.ref)
        row = connection.execute(
            f"SELECT {','.join(subject._CANDIDATE_COLUMNS)} FROM candidates"
        ).fetchone()
        assert row is not None
        candidate = subject._decode_candidate(row)
        altered = ContainmentCandidateV1.model_validate(
            {
                **candidate.model_dump(mode="python"),
                "primary_source_sequence": second.snapshot.trigger.source_sequence,
            },
            strict=True,
        )
        values = subject._encode_candidate(altered)
        assignments = ",".join(
            f"{column}=?" for column in subject._CANDIDATE_COLUMNS
        )
        connection.execute(
            f"UPDATE candidates SET {assignments} WHERE candidate_id=?",
            (*values, candidate.candidate_id),
        )
        key = subject._duplicate_key(second, second.snapshot)
        assert subject._candidate_key_tuple_v2(key) == subject._candidate_duplicate_key_from_row(
            connection.execute(
                f"SELECT {','.join(subject._CANDIDATE_COLUMNS)} FROM candidates"
            ).fetchone()
        )
        updated = subject._decode_candidate(
            connection.execute(
                f"SELECT {','.join(subject._CANDIDATE_COLUMNS)} FROM candidates"
            ).fetchone()
        )
        assert updated.primary_source_sequence == second.snapshot.trigger.source_sequence
        matches = connection.execute(
            "SELECT candidate_id FROM candidates WHERE "
            "host_id=? AND boot_id=? AND docker_container_id=? AND docker_started_at=? "
            "AND detector_bundle_sha256=? AND destination_ipv4=?",
            subject._candidate_key_tuple_v2(key),
        ).fetchall()
        assert matches, (
            subject._candidate_duplicate_key_from_row(
                connection.execute(
                    f"SELECT {','.join(subject._CANDIDATE_COLUMNS)} FROM candidates"
                ).fetchone()
            ),
            subject._candidate_key_tuple_v2(key),
        )
        with pytest.raises(subject.ProjectionConflict):
            subject._active_duplicate_v2(
                connection,
                key,
                current_trigger_order=(
                    second.snapshot.trigger.source_sequence,
                    second.snapshot.trigger.event_id,
                ),
            )
        before = owner.snapshot_hash()

        with pytest.raises(subject.ProjectionConflict):
            owner.apply(records[5].ref)

        assert owner.snapshot_hash() == before
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 5
    finally:
        owner.close()


def test_source_selection_cannot_jump_past_contiguous_acceptance_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    key = private_key(11)
    coordinator = _coordinator(tmp_path / "evidence", key)
    _accept(coordinator, boot_boundary(key))
    skipped_ref = _accept(coordinator, envelope_value(key, sequence=4))
    assert type(skipped_ref) is EvidenceRef
    assert coordinator.segment_store.acceptance_cursor == 1
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        owner.apply(records[0].ref)
        before = owner.snapshot_hash()

        with pytest.raises(ProjectionAuthorityError):
            owner.apply(skipped_ref)

        assert owner.snapshot_hash() == before
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 1
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 1
    finally:
        owner.close()


def test_acceptance_cursor_change_inside_transaction_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()

        def append_during_transaction(step: str) -> None:
            if step == "dedup":
                _accept(coordinator, envelope_value(private_key(11), sequence=4))

        owner._step_hook = append_during_transaction
        with pytest.raises(ProjectionAuthorityError):
            owner.apply(records[2].ref)

        assert subject._v2_snapshot_hash(connection) == before
        assert connection.execute(
            "SELECT count(*) FROM events WHERE event_id=?",
            (proof.event_id,),
        ).fetchone()[0] == 0
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 2
    finally:
        owner.close()


def test_predecessor_drift_during_transaction_rolls_back_and_latches_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()
        p0 = subject._predecessor_v2(1, owner.status().cursor)
        proof_ref = cast(EvidenceRef, proof.evidence_ref)
        p1 = authority._ProjectionPredecessor(
            generation=1,
            host_id=proof.host_id,
            source_sequence=proof.source_sequence,
            event_id=proof.event_id,
            content_sha256=proof.content_sha256,
            frame_sha256=proof_ref.frame_sha256,
        )

        def drift_after_dedup(step: str) -> None:
            if step == "dedup":
                authority._advance_correlation_projection_authority(
                    owner._authority,
                    p0,
                    p1,
                )

        owner._step_hook = drift_after_dedup
        with pytest.raises(ProjectionAuthorityError):
            owner.apply(records[2].ref)

        assert subject._v2_snapshot_hash(connection) == before
        assert owner.status().healthy is False
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 2
    finally:
        owner.close()


@pytest.mark.parametrize("mutation_step", ["candidate", "cursor"])
@pytest.mark.parametrize("mutation", ["detector", "registry"])
def test_live_pin_change_after_correlation_rolls_back_all_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation_step: str,
    mutation: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    owner, connection = _owner(
        subject,
        coordinator,
        journal,
        registry=registry,
    )
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()

        def mutate_pin(step: str) -> None:
            if step != mutation_step:
                return
            if mutation == "detector":
                monkeypatch.setattr(
                    authority,
                    "_load_pinned_detector_bundle",
                    lambda: "2" * 64,
                )
            else:
                object.__setattr__(registry, "entries", ())

        owner._step_hook = mutate_pin
        with pytest.raises(ProjectionAuthorityError):
            owner.apply(records[2].ref)

        assert subject._v2_snapshot_hash(connection) == before
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 2
    finally:
        owner.close()


@pytest.mark.parametrize(
    "crash_step",
    [
        "event",
        "dedup",
        "incident",
        "candidate",
        "candidate_evidence_trigger",
        "candidate_evidence_snapshot",
        "reducer",
        "cursor",
    ],
)
def test_candidate_write_crash_points_roll_back_and_retry_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_step: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()

        def crash(step: str) -> None:
            if step == crash_step:
                raise _Crash(crash_step)

        owner._step_hook = crash
        with pytest.raises(_Crash):
            owner.apply(records[2].ref)

        assert subject._v2_snapshot_hash(connection) == before
        assert owner.status().healthy is True
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 2
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM candidate_evidence"
        ).fetchone()[0] == 0

        owner._step_hook = lambda _step: None
        owner.apply(records[2].ref)
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 1
        assert connection.execute(
            "SELECT count(*) FROM candidate_evidence"
        ).fetchone()[0] == 2
    finally:
        owner.close()


@pytest.mark.parametrize("failure", ["commit-hook", "authority-advance"])
def test_postcommit_failure_latches_unhealthy_with_complete_atomic_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        if failure == "commit-hook":
            owner._step_hook = lambda step: (
                (_ for _ in ()).throw(_Crash("postcommit"))
                if step == "commit"
                else None
            )
        else:
            monkeypatch.setattr(
                subject,
                "_advance_correlation_projection_authority",
                lambda *_args: (_ for _ in ()).throw(_Crash("advance")),
            )

        with pytest.raises(_Crash):
            owner.apply(records[2].ref)

        assert owner.status().healthy is False
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == proof.source_sequence
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 1
        assert connection.execute(
            "SELECT count(*) FROM candidate_evidence"
        ).fetchone()[0] == 2
    finally:
        owner.close()


def test_predurable_commit_failure_proves_rollback_and_remains_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    connection = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        factory=_CommitFailsBeforeDurable,
    )
    subject._configure_v2_connection(connection, file_backed=False)
    subject._create_v2_schema(connection)
    subject._verify_v2_schema(connection)
    acknowledgements = AckJournal.create_new(coordinator.segment_store)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=coordinator.segment_store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()
        connection.fail_commit = True

        with pytest.raises(sqlite3.OperationalError):
            owner.apply(records[2].ref)

        connection.fail_commit = False
        assert subject._v2_snapshot_hash(connection) == before
        assert owner.status().healthy is True
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 2

        owner.apply(records[2].ref)
        assert owner.status().healthy is True
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == proof.source_sequence
    finally:
        owner.close()


def test_accepted_but_unconfirmed_completed_pcc_cannot_advance_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records[:2]])
    connection = subject._v2_connection_for_test()
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()

        with pytest.raises(ProjectionAuthorityError):
            owner.apply(records[2].ref)

        assert owner.snapshot_hash() == before
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 2
    finally:
        owner.close()


@pytest.mark.parametrize("mutation", ["rollback", "substitution"])
def test_ack_boundary_drift_inside_transaction_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    original_snapshot = acknowledgements.snapshot
    connection = subject._v2_connection_for_test()
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()
        changed = False

        def snapshot() -> AckJournalSnapshot:
            frozen = original_snapshot()
            if not changed:
                return frozen
            if mutation == "rollback":
                return AckJournalSnapshot(
                    AckIdentity.from_ref(records[1].ref),
                    frozen.pending,
                    True,
                )
            assert frozen.confirmed is not None
            return AckJournalSnapshot(
                AckIdentity(
                    frozen.confirmed.sequence,
                    "evt_" + "f" * 64,
                    frozen.confirmed.content_sha256,
                ),
                frozen.pending,
                True,
            )

        monkeypatch.setattr(acknowledgements, "snapshot", snapshot)

        def mutate_after_event(step: str) -> None:
            nonlocal changed
            if step == "event":
                changed = True

        owner._step_hook = mutate_after_event
        with pytest.raises(ProjectionAuthorityError):
            owner.apply(records[2].ref)

        assert subject._v2_snapshot_hash(connection) == before
        assert connection.execute(
            "SELECT count(*) FROM events WHERE event_id=?",
            (proof.event_id,),
        ).fetchone()[0] == 0
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 2
    finally:
        owner.close()


def test_ack_monotonic_extension_does_not_move_frozen_apply_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    extra_ref = _accept(
        coordinator,
        envelope_value(private_key(11), sequence=4),
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records[:3]])
    connection = subject._v2_connection_for_test()
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        extended = False

        def extend_after_event(step: str) -> None:
            nonlocal extended
            if step == "event" and not extended:
                extended = True
                _confirm_ack(acknowledgements, extra_ref)

        owner._step_hook = extend_after_event
        result = owner.apply(records[2].ref)

        assert result.cursor.source_sequence == proof.source_sequence
        assert acknowledgements.snapshot().confirmed_through == extra_ref.source_sequence
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 1
    finally:
        owner.close()


def test_forged_ack_cache_cannot_widen_durable_confirmed_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records[:2]])
    owner, connection = _owner(
        subject,
        coordinator,
        journal,
        acknowledgements=acknowledgements,
    )
    original_confirmed = acknowledgements._confirmed
    original_generation = acknowledgements._confirmed_generation
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()
        acknowledgements._confirmed = AckIdentity.from_ref(records[2].ref)
        acknowledgements._confirmed_generation = original_generation + 1

        with pytest.raises(ProjectionAuthorityError):
            owner.apply(records[2].ref)

        assert subject._v2_snapshot_hash(connection) == before
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 2
    finally:
        acknowledgements._confirmed = original_confirmed
        acknowledgements._confirmed_generation = original_generation
        owner.close()


def test_exact_retry_is_hash_stable_for_complete_candidate_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, _connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        for record in records:
            owner.apply(record.ref)
        before = owner.snapshot_hash()

        retried = owner.apply(records[-1].ref)

        assert retried.event_id == proof.event_id
        assert retried.reducer_applied is False
        assert owner.snapshot_hash() == before
        assert owner.status().healthy is True
    finally:
        owner.close()


def test_exact_retry_rejects_missing_candidate_evidence_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        for record in records:
            owner.apply(record.ref)
        connection.execute(
            "DELETE FROM candidate_evidence WHERE authority_snapshot_event_id=? "
            "AND role='primary_trigger'",
            (proof.event_id,),
        )

        with pytest.raises(subject.ProjectionConflict):
            owner.apply(records[-1].ref)

        assert owner.status().healthy is False
        assert connection.execute(
            "SELECT count(*) FROM candidate_evidence "
            "WHERE authority_snapshot_event_id=?",
            (proof.event_id,),
        ).fetchone()[0] == 1
    finally:
        owner.close()


def test_exact_retry_rejects_same_id_candidate_with_altered_facts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        for record in records:
            owner.apply(record.ref)
        row = connection.execute(
            f"SELECT {','.join(subject._CANDIDATE_COLUMNS)} FROM candidates"
        ).fetchone()
        assert row is not None
        candidate = subject._decode_candidate(row)
        altered = ContainmentCandidateV1.model_validate(
            {
                **candidate.model_dump(mode="python"),
                "ttl_seconds": candidate.ttl_seconds + 1,
            },
            strict=True,
        )
        values = subject._encode_candidate(altered)
        assignments = ",".join(
            f"{column}=?" for column in subject._CANDIDATE_COLUMNS
        )
        connection.execute(
            f"UPDATE candidates SET {assignments} WHERE candidate_id=?",
            (*values, candidate.candidate_id),
        )

        with pytest.raises(subject.ProjectionConflict):
            owner.apply(records[-1].ref)

        assert owner.status().healthy is False
        persisted = subject._decode_candidate(
            connection.execute(
                f"SELECT {','.join(subject._CANDIDATE_COLUMNS)} FROM candidates"
            ).fetchone()
        )
        assert persisted.candidate_id == candidate.candidate_id
        assert persisted.ttl_seconds == candidate.ttl_seconds + 1
    finally:
        owner.close()


@pytest.mark.parametrize("entrypoint", ["retry", "reopen"])
def test_invalidation_closure_is_rederived_from_authenticated_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    evidence_path = tmp_path / "evidence"
    projection_path = tmp_path / "projection.sqlite3"
    coordinator, proof = _accepted_complete(
        evidence_path,
        ttl_seconds=120,
    )
    coverage = _accept(
        coordinator,
        _generic_critical(
            private_key(11),
            4,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=NOW,
        ).envelope,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = subject._v2_connection_for_test(projection_path)
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    for record in records:
        owner.apply(record.ref)
    connection.execute(
        "UPDATE candidate_invalidations SET coverage_content_sha256=?",
        ("0" * 64,),
    )
    if entrypoint == "retry":
        try:
            with pytest.raises(subject.ProjectionConflict):
                owner.apply(coverage)
            assert owner.status().healthy is False
        finally:
            owner.close()
        return

    owner.close()
    _recovered_coordinator, recovered_store = _reopen_evidence(evidence_path)
    recovered_journal = CorrelationRequestJournal.open_and_recover(recovered_store)
    recovered_acknowledgements = AckJournal.open_and_recover(recovered_store)
    recovered_connection = subject._v2_connection_for_test(projection_path)
    with pytest.raises(subject.ProjectionConflict):
        subject._v2_projection_owner_for_test(
            recovered_connection,
            evidence=recovered_store,
            acknowledgements=recovered_acknowledgements,
            journal=recovered_journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        )


def test_exact_retry_rejects_live_registry_mutation_even_if_result_is_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    owner, _connection = _owner(
        subject,
        coordinator,
        journal,
        registry=registry,
    )
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        for record in records:
            owner.apply(record.ref)
        object.__setattr__(registry, "entries", ())

        with pytest.raises(ProjectionAuthorityError):
            owner.apply(records[-1].ref)

        assert owner.status().healthy is False
    finally:
        owner.close()


def test_clean_file_backed_reopen_preserves_rows_hash_and_exact_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    evidence_path = tmp_path / "evidence"
    projection_path = tmp_path / "projection.sqlite3"
    coordinator, proof = _accepted_complete(
        evidence_path,
        ttl_seconds=120,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = subject._v2_connection_for_test(projection_path)
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    for record in records:
        owner.apply(record.ref)
    before_hash = owner.snapshot_hash()
    before_rows = {
        table: subject._v2_ordered_table_rows(connection, table)
        for table, _columns, _primary_key in subject._TABLE_LAYOUT_V2
    }
    owner.close()

    _recovered_coordinator, recovered_store = _reopen_evidence(evidence_path)
    recovered_journal = CorrelationRequestJournal.open_and_recover(recovered_store)
    recovered_acknowledgements = AckJournal.open_and_recover(recovered_store)
    recovered_connection = subject._v2_connection_for_test(projection_path)
    recovered_owner = subject._v2_projection_owner_for_test(
        recovered_connection,
        evidence=recovered_store,
        acknowledgements=recovered_acknowledgements,
        journal=recovered_journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    recovered_records = tuple(recovered_store.iter_authenticated_records())
    try:
        assert recovered_owner.snapshot_hash() == before_hash
        assert {
            table: subject._v2_ordered_table_rows(recovered_connection, table)
            for table, _columns, _primary_key in subject._TABLE_LAYOUT_V2
        } == before_rows

        retry = recovered_owner.apply(recovered_records[-1].ref)

        assert retry.reducer_applied is False
        assert recovered_owner.snapshot_hash() == before_hash
        assert recovered_owner.status().healthy is True
    finally:
        recovered_owner.close()


def test_file_backed_reopen_preserves_authenticated_late_invalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    evidence_path = tmp_path / "evidence"
    projection_path = tmp_path / "projection.sqlite3"
    coordinator, proof = _accepted_complete(
        evidence_path,
        ttl_seconds=120,
    )
    _accept(
        coordinator,
        _generic_critical(
            private_key(11),
            4,
            component="falco-adapter",
            kind="falco_heartbeat_gap",
            opened_at=NOW,
            closed_at=NOW,
        ).envelope,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = subject._v2_connection_for_test(projection_path)
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    for record in records:
        owner.apply(record.ref)
    before = subject._v2_ordered_table_rows(connection, "candidate_invalidations")
    before_hash = owner.snapshot_hash()
    owner.close()

    _recovered_coordinator, recovered_store = _reopen_evidence(evidence_path)
    recovered_journal = CorrelationRequestJournal.open_and_recover(recovered_store)
    recovered_acknowledgements = AckJournal.open_and_recover(recovered_store)
    recovered_connection = subject._v2_connection_for_test(projection_path)
    recovered_owner = subject._v2_projection_owner_for_test(
        recovered_connection,
        evidence=recovered_store,
        acknowledgements=recovered_acknowledgements,
        journal=recovered_journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    try:
        assert subject._v2_ordered_table_rows(
            recovered_connection,
            "candidate_invalidations",
        ) == before
        assert recovered_owner.snapshot_hash() == before_hash
    finally:
        recovered_owner.close()


def test_file_backed_reopen_rejects_tampered_candidate_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    evidence_path = tmp_path / "evidence"
    projection_path = tmp_path / "projection.sqlite3"
    coordinator, proof = _accepted_complete(
        evidence_path,
        ttl_seconds=120,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = subject._v2_connection_for_test(projection_path)
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    for record in records:
        owner.apply(record.ref)
    connection.execute(
        "DELETE FROM candidate_evidence WHERE authority_snapshot_event_id=? "
        "AND role='primary_trigger'",
        (proof.event_id,),
    )
    owner.close()

    _recovered_coordinator, recovered_store = _reopen_evidence(evidence_path)
    recovered_journal = CorrelationRequestJournal.open_and_recover(recovered_store)
    recovered_acknowledgements = AckJournal.open_and_recover(recovered_store)
    recovered_connection = subject._v2_connection_for_test(projection_path)
    with pytest.raises(subject.ProjectionConflict):
        subject._v2_projection_owner_for_test(
            recovered_connection,
            evidence=recovered_store,
            acknowledgements=recovered_acknowledgements,
            journal=recovered_journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        )


def test_file_backed_reopen_rejects_ack_journal_from_another_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    evidence_path = tmp_path / "evidence"
    projection_path = tmp_path / "projection.sqlite3"
    coordinator, proof = _accepted_complete(
        evidence_path,
        ttl_seconds=120,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = subject._v2_connection_for_test(projection_path)
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    for record in records:
        owner.apply(record.ref)
    owner.close()

    _recovered_coordinator, recovered_store = _reopen_evidence(evidence_path)
    recovered_journal = CorrelationRequestJournal.open_and_recover(recovered_store)
    other_coordinator, _other_proof = _accepted_complete(
        tmp_path / "other-evidence",
        ttl_seconds=120,
    )
    other_store = other_coordinator.segment_store
    wrong_acknowledgements = AckJournal.create_new(other_store)
    other_records = tuple(other_store.iter_authenticated_records())
    _confirm_ack(
        wrong_acknowledgements,
        *[record.ref for record in other_records],
    )
    recovered_connection = subject._v2_connection_for_test(projection_path)
    try:
        with pytest.raises(ProjectionAuthorityError):
            subject._v2_projection_owner_for_test(
                recovered_connection,
                evidence=recovered_store,
                acknowledgements=wrong_acknowledgements,
                journal=recovered_journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            )
    finally:
        recovered_connection.close()
        recovered_journal.close()
        recovered_store.close()
        wrong_acknowledgements.close()
        other_store.close()


def test_owner_creation_loader_failure_closes_all_transferred_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    coordinator, _authenticated = _accepted_direct_falco(
        tmp_path / "evidence",
        investigation_only=True,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = subject._v2_connection_for_test()

    def unavailable() -> str:
        raise OSError("detector bundle unavailable")

    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", unavailable)
    with pytest.raises(ProjectionAuthorityError):
        subject._v2_projection_owner_for_test(
            connection,
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        )

    assert store._closed is True
    assert journal._closed is True
    assert acknowledgements._closed is True
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


@pytest.mark.parametrize("unavailable", ["detector", "history"])
def test_pcc_authority_unavailable_rolls_back_without_cursor_advance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unavailable: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        owner.apply(records[0].ref)
        owner.apply(records[1].ref)
        before = owner.snapshot_hash()

        if unavailable == "detector":
            def detector_unavailable() -> str:
                raise OSError("detector bundle unavailable")

            monkeypatch.setattr(
                authority,
                "_load_pinned_detector_bundle",
                detector_unavailable,
            )
        else:
            def history_unavailable(*_args: object) -> object:
                raise subject.HistoricalCoverageUnavailable(
                    "historical coverage unavailable"
                )

            monkeypatch.setattr(
                subject,
                "derive_historical_coverage",
                history_unavailable,
            )

        with pytest.raises(ProjectionAuthorityError):
            owner.apply(records[2].ref)

        assert subject._v2_snapshot_hash(connection) == before
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
        assert owner.status().healthy is True
        assert owner.status().cursor is not None
        assert owner.status().cursor.source_sequence == 2
    finally:
        owner.close()


@pytest.mark.parametrize("entrypoint", ["retry", "reopen"])
def test_authenticated_source_order_cannot_be_rewritten_to_later_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    evidence_path = tmp_path / "evidence"
    projection_path = tmp_path / "projection.sqlite3"
    key = private_key(11)
    coordinator = _coordinator(evidence_path, key)
    _accept(coordinator, boot_boundary(key))
    _accept(coordinator, _candidate_trigger(key, sequence=2))
    _accept(coordinator, _candidate_trigger(key, sequence=3))
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = subject._v2_connection_for_test(projection_path)
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    for record in records:
        owner.apply(record.ref)
    assert connection.execute(
        "SELECT duplicate_of_event_id FROM events WHERE event_id=?",
        (records[2].ref.event_id,),
    ).fetchone()[0] == records[1].ref.event_id
    _forge_later_logical_primary(connection, records[1], records[2])

    if entrypoint == "retry":
        try:
            with pytest.raises(subject.ProjectionConflict):
                owner.apply(records[2].ref)
            assert owner.status().healthy is False
        finally:
            owner.close()
        return

    owner.close()
    _recovered_coordinator, recovered_store = _reopen_evidence(evidence_path)
    recovered_journal = CorrelationRequestJournal.open_and_recover(recovered_store)
    recovered_acknowledgements = AckJournal.open_and_recover(recovered_store)
    recovered_connection = subject._v2_connection_for_test(projection_path)
    recovered_owner = None
    try:
        with pytest.raises(subject.ProjectionConflict):
            recovered_owner = subject._v2_projection_owner_for_test(
                recovered_connection,
                evidence=recovered_store,
                acknowledgements=recovered_acknowledgements,
                journal=recovered_journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            )
    finally:
        if recovered_owner is not None:
            recovered_owner.close()


def test_duplicate_retry_reauthenticates_rehashed_primary_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, first, second = _accepted_two_complete(tmp_path / "evidence")
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, first)
    _complete_journal(journal, second)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(coordinator.segment_store.iter_authenticated_records())
    try:
        _apply_all(owner, coordinator)
        row = connection.execute(
            f"SELECT {','.join(subject._CANDIDATE_COLUMNS)} FROM candidates"
        ).fetchone()
        assert row is not None
        candidate = subject._decode_candidate(row)
        altered = ContainmentCandidateV1.model_validate(
            {
                **candidate.model_dump(mode="python"),
                "ttl_seconds": candidate.ttl_seconds + 1,
            },
            strict=True,
        )
        values = subject._encode_candidate(altered)
        assignments = ",".join(
            f"{column}=?" for column in subject._CANDIDATE_COLUMNS
        )
        connection.execute(
            f"UPDATE candidates SET {assignments} WHERE candidate_id=?",
            (*values, candidate.candidate_id),
        )

        with pytest.raises(subject.ProjectionConflict):
            owner.apply(records[-1].ref)

        assert owner.status().healthy is False
    finally:
        owner.close()


@pytest.mark.parametrize("mutation", ["rollback", "substitution"])
def test_reopen_revalidates_ack_after_persisted_prefix_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    evidence_path = tmp_path / "evidence"
    projection_path = tmp_path / "projection.sqlite3"
    coordinator, proof = _accepted_complete(evidence_path, ttl_seconds=120)
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = subject._v2_connection_for_test(projection_path)
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    _apply_all(owner, coordinator)
    owner.close()

    _recovered_coordinator, recovered_store = _reopen_evidence(evidence_path)
    recovered_records = tuple(recovered_store.iter_authenticated_records())
    recovered_journal = CorrelationRequestJournal.open_and_recover(recovered_store)
    recovered_acknowledgements = AckJournal.open_and_recover(recovered_store)
    recovered_connection = subject._v2_connection_for_test(projection_path)
    original_snapshot = recovered_acknowledgements.snapshot
    original_completed = recovered_journal.completed_for_snapshot
    changed = False

    def completed_for_snapshot(ref: EvidenceRef) -> Any:
        nonlocal changed
        completed = original_completed(ref)
        changed = True
        return completed

    def snapshot() -> AckJournalSnapshot:
        frozen = original_snapshot()
        if not changed:
            return frozen
        if mutation == "rollback":
            return AckJournalSnapshot(
                AckIdentity.from_ref(recovered_records[-2].ref),
                frozen.pending,
                True,
            )
        assert frozen.confirmed is not None
        return AckJournalSnapshot(
            AckIdentity(
                frozen.confirmed.sequence,
                "evt_" + "f" * 64,
                frozen.confirmed.content_sha256,
            ),
            frozen.pending,
            True,
        )

    monkeypatch.setattr(
        recovered_journal,
        "completed_for_snapshot",
        completed_for_snapshot,
    )
    monkeypatch.setattr(recovered_acknowledgements, "snapshot", snapshot)
    recovered_owner = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            recovered_owner = subject._v2_projection_owner_for_test(
                recovered_connection,
                evidence=recovered_store,
                acknowledgements=recovered_acknowledgements,
                journal=recovered_journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            )
        assert changed is True
        assert recovered_store._closed is True
        assert recovered_journal._closed is True
        assert recovered_acknowledgements._closed is True
        with pytest.raises(sqlite3.ProgrammingError):
            recovered_connection.execute("SELECT 1")
    finally:
        if recovered_owner is not None:
            recovered_owner.close()


@pytest.mark.parametrize("transition", ["extension", "rollback", "substitution"])
def test_reopen_ack_stabilization_chains_each_observed_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transition: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    evidence_path = tmp_path / "evidence"
    projection_path = tmp_path / "projection.sqlite3"
    coordinator, proof = _accepted_complete(evidence_path, ttl_seconds=120)
    extra_ref = _accept(
        coordinator,
        envelope_value(private_key(11), sequence=4),
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records[:3]])
    connection = subject._v2_connection_for_test(projection_path)
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    for record in records[:3]:
        owner.apply(record.ref)
    owner.close()

    _recovered_coordinator, recovered_store = _reopen_evidence(evidence_path)
    recovered_journal = CorrelationRequestJournal.open_and_recover(recovered_store)
    recovered_acknowledgements = AckJournal.open_and_recover(recovered_store)
    recovered_connection = subject._v2_connection_for_test(projection_path)
    original_completed = recovered_journal.completed_for_snapshot
    original_current_ack = subject._V2ProjectionOwner._current_ack_boundary
    extended = False
    frozen_boundary: Any | None = None
    stabilization_reads = 0

    def completed_for_snapshot(ref: EvidenceRef) -> Any:
        nonlocal extended
        completed = original_completed(ref)
        if not extended:
            _confirm_ack(recovered_acknowledgements, extra_ref)
            extended = True
        return completed

    def current_ack(candidate: Any) -> Any:
        nonlocal frozen_boundary, stabilization_reads
        current = original_current_ack(candidate)
        if frozen_boundary is None:
            frozen_boundary = current
            return current
        if not extended or transition == "extension":
            return current
        stabilization_reads += 1
        if stabilization_reads == 1:
            return current
        if transition == "rollback":
            return frozen_boundary
        assert current.confirmed is not None
        return subject._ProjectionAckBoundaryV2(
            confirmed=AckIdentity(
                current.confirmed.sequence,
                "evt_" + "f" * 64,
                current.confirmed.content_sha256,
            ),
            pending=current.pending,
            generation=current.generation,
            prefix_size=current.prefix_size,
            prefix_sha256=current.prefix_sha256,
        )

    monkeypatch.setattr(
        recovered_journal,
        "completed_for_snapshot",
        completed_for_snapshot,
    )
    monkeypatch.setattr(
        subject._V2ProjectionOwner,
        "_current_ack_boundary",
        current_ack,
    )
    recovered_owner = None
    try:
        if transition == "extension":
            recovered_owner = subject._v2_projection_owner_for_test(
                recovered_connection,
                evidence=recovered_store,
                acknowledgements=recovered_acknowledgements,
                journal=recovered_journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            )
            assert recovered_owner.status().cursor is not None
            assert recovered_owner.status().cursor.source_sequence == 3
            assert recovered_acknowledgements.snapshot().confirmed_through == 4
        else:
            with pytest.raises(ProjectionAuthorityError):
                recovered_owner = subject._v2_projection_owner_for_test(
                    recovered_connection,
                    evidence=recovered_store,
                    acknowledgements=recovered_acknowledgements,
                    journal=recovered_journal,
                    registry=load_pinned_special_use_registry(_REGISTRY_PATH),
                )
            assert stabilization_reads == 2
    finally:
        if recovered_owner is not None:
            recovered_owner.close()


def test_owner_close_retries_a_failed_connection_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, _authenticated = _accepted_direct_falco(
        tmp_path / "evidence",
        investigation_only=True,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        factory=_CloseFailsOnce,
    )
    subject._configure_v2_connection(connection, file_backed=False)
    subject._create_v2_schema(connection)
    subject._verify_v2_schema(connection)
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    try:
        with pytest.raises(subject.ProjectionUnhealthy):
            owner.close()
        assert owner._connection is connection

        owner.close()

        assert connection.close_attempts == 2
        assert owner._connection is None
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
    finally:
        connection.close()


def test_unhealthy_latch_retains_authority_until_close_is_proven(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, _authenticated = _accepted_direct_falco(
        tmp_path / "evidence",
        investigation_only=True,
    )
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    owner, _connection = _owner(subject, coordinator, journal)
    saved_authority = owner._authority
    assert saved_authority is not None
    predecessor = subject._predecessor_v2(1, None)
    real_close = subject._close_correlation_projection_authority
    close_calls = 0

    def fail_once(candidate: Any) -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == 1:
            raise OSError("injected authority close failure")
        real_close(candidate)

    monkeypatch.setattr(
        subject,
        "_close_correlation_projection_authority",
        fail_once,
    )
    try:
        owner._latch_unhealthy(RuntimeError("primary failure"))
        assert owner._authority is saved_authority

        owner.close()

        assert close_calls == 2
        assert owner._authority is None
        with pytest.raises(authority.CorrelationProjectionError):
            authority._validate_correlation_projection_predecessor(
                saved_authority,
                predecessor,
            )
    finally:
        real_close(saved_authority)
        owner.close()


def test_factory_retries_cleanup_and_annotates_the_primary_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, _authenticated = _accepted_direct_falco(
        tmp_path / "evidence",
        investigation_only=True,
    )
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    acknowledgements = AckJournal.create_new(store)
    records = tuple(store.iter_authenticated_records())
    _confirm_ack(acknowledgements, *[record.ref for record in records])
    connection = subject._v2_connection_for_test()
    real_close = subject._close_correlation_projection_authority
    closed_authorities: list[Any] = []
    close_calls = 0

    def fail_validation(*_args: object, **_kwargs: object) -> None:
        raise subject.ProjectionConflict("injected prefix failure")

    def fail_once(candidate: Any) -> None:
        nonlocal close_calls
        close_calls += 1
        closed_authorities.append(candidate)
        if close_calls == 1:
            raise OSError("injected factory authority-close failure")
        real_close(candidate)

    monkeypatch.setattr(
        subject._V2ProjectionOwner,
        "_validate_persisted_prefix",
        fail_validation,
    )
    monkeypatch.setattr(
        subject,
        "_close_correlation_projection_authority",
        fail_once,
    )
    try:
        with pytest.raises(subject.ProjectionConflict) as raised:
            subject._v2_projection_owner_for_test(
                connection,
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=load_pinned_special_use_registry(_REGISTRY_PATH),
            )

        assert close_calls == 2
        assert closed_authorities[0] is closed_authorities[1]
        assert any(
            "factory cleanup failure" in note
            for note in getattr(raised.value, "__notes__", ())
        )
        assert store._closed is True
        assert journal._closed is True
        assert acknowledgements._closed is True
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        with pytest.raises(authority.CorrelationProjectionError):
            authority._validate_correlation_projection_predecessor(
                closed_authorities[0],
                subject._predecessor_v2(1, None),
            )
    finally:
        for candidate in closed_authorities:
            real_close(candidate)
