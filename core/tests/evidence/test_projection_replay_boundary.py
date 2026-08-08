from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib
import json
import os
import resource
import signal
import sqlite3
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, fields, replace
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
from typing import Any

import pytest
from agmind_immune.canonicaljson import (
    canonical_json,
    pcc_detector_bundle_sha256,
)
from agmind_immune.contracts import PCCCorrelationSnapshotRequestV1
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
from agmind_immune.evidence import retention as retention_module
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
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import EnvelopeVerifier
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.correlation.test_pcc import (
    _accepted_complete,
    _accepted_failed,
    _context,
)
from tests.correlation.test_pcc import _resign as _resign_pcc_envelope
from tests.coverage.test_historical import _self_close_records
from tests.coverage.test_state import T0, T1, _event, _generic_critical, _stored
from tests.evidence.test_retention import (
    REQUEST_ID as RETENTION_REQUEST_ID,
)
from tests.evidence.test_retention import (
    _live_store_with_active_routine,
    _proof_clock,
)
from tests.ingest.test_pcc_correlation_snapshot import (
    _accept,
    _candidate_trigger,
    _complete_snapshot,
    _coordinator,
    _identity,
    _item,
    _request,
    _snapshot_envelope,
)
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


class _NestedBombStr(str):
    def __eq__(self, other: object) -> bool:
        del other
        raise AssertionError("nested hostile equality executed")

    def __ne__(self, other: object) -> bool:
        del other
        raise AssertionError("nested hostile inequality executed")

    def __hash__(self) -> int:
        raise AssertionError("nested hostile hash executed")


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
    *,
    generation: int = 0,
) -> tuple[Any, Any, Any]:
    authority_module, _pcc_module = _correlation_modules()
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    predecessor = authority_module._ProjectionPredecessor(
        generation=generation,
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


def _build_complete_replay_input_snapshot(
    path: Path,
    *,
    base_projection_generation: int = 1,
    publish_generation: int | None = None,
) -> tuple[object, dict[str, object]]:
    subject = importlib.import_module("agmind_immune.evidence.projection_v2")
    authority_module, _pcc_module = _correlation_modules()
    coordinator, store, terminal = _build_file_backed_source(path)
    del coordinator
    records = tuple(store.iter_authenticated_records())
    acknowledgements = AckJournal.create_new(store)
    for record in records:
        acknowledgements.record_pending(record.ref)
        acknowledgements.record_confirmed(record.ref)
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
        issued, binding, predecessor = _build_registered_correlation_authority(
            store,
            generation=base_projection_generation,
        )
        with authority_module._correlation_projection_snapshot_gate(
            issued
        ) as held:
            assert held is binding
            correlation_snapshot = (
                authority_module._capture_correlation_replay_locked(
                    issued,
                    held,
                    predecessor,
                )
            )
        snapshot = subject._ReplayInputSnapshot(
            source=source_snapshot,
            ack=ack_snapshot,
            correlation=correlation_snapshot,
            pcc_inputs=(),
            schema_domain=(
                b"AGMIND_PROJECTION_SCHEMA_V2\0"
                + Path("core/agmind_immune/evidence/schema_v2.sql").read_bytes()
            ),
            base_projection_generation=base_projection_generation,
            publish_generation=(
                base_projection_generation + 1
                if publish_generation is None
                else publish_generation
            ),
        )
    except BaseException:
        if source_snapshot is not None:
            segments_module._close_replay_source_snapshot(source_snapshot)
        if ack_snapshot is not None:
            ack_journal_module._close_replay_ack_snapshot(ack_snapshot)
        if issued is not None:
            _drop_registered_correlation_authority(issued)
        acknowledgements.close()
        store.close()
        raise
    assert issued is not None
    _drop_registered_correlation_authority(issued)
    return snapshot, {
        "store": store,
        "acknowledgements": acknowledgements,
        "source_snapshot": source_snapshot,
        "ack_snapshot": ack_snapshot,
    }


def _close_complete_replay_input(resources: dict[str, object]) -> None:
    source_snapshot = resources["source_snapshot"]
    ack_snapshot = resources["ack_snapshot"]
    acknowledgements = resources["acknowledgements"]
    store = resources["store"]
    segments_module._close_replay_source_snapshot(source_snapshot)
    ack_journal_module._close_replay_ack_snapshot(ack_snapshot)
    acknowledgements.close()
    store.close()


def _build_replay_orchestration_case(
    path: Path,
    *,
    record_count: int = 48,
) -> dict[str, object]:
    subject = importlib.import_module("agmind_immune.evidence.projection_v2")
    key, acceptance, store, coverage = _live_store_with_active_routine(path)
    acknowledgements = store._ack_journal_owner
    assert type(acknowledgements) is AckJournal
    try:
        retention_snapshot = store._freeze_retention_snapshot(
            _proof_clock(),
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        retention_decision = retention_module.select_retention(
            retention_snapshot,
            request_id=RETENTION_REQUEST_ID,
        )
        assert retention_decision.request is not None
        for sequence in range(3, record_count + 1):
            ref = acceptance.accept(
                _item(envelope_value(key, sequence=sequence))
            )
            coverage._apply_live_accepted(store, ref, None)
            acknowledgements.record_pending(ref)
            acknowledgements.record_confirmed(ref)
        records = tuple(store.iter_authenticated_records())
        assert len(records) == record_count
        journal = CorrelationRequestJournal.create_new(store)
        connection = subject._v2_connection_for_test()
        owner = subject._v2_projection_owner_for_test(
            connection,
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        )
    except BaseException:
        coverage.close()
        store.close(flush=False)
        raise
    return {
        "subject": subject,
        "key": key,
        "acceptance": acceptance,
        "store": store,
        "coverage": coverage,
        "acknowledgements": acknowledgements,
        "journal": journal,
        "retention_decision": retention_decision,
        "connection": connection,
        "owner": owner,
        "records": records,
        "through": records[-1].ref,
    }


def _close_replay_orchestration_case(case: dict[str, object]) -> None:
    coverage = case["coverage"]
    owner = case["owner"]
    coverage.close()  # type: ignore[attr-defined]
    owner.close()  # type: ignore[attr-defined]


def _perform_replay_writer(case: dict[str, object], writer: str) -> None:
    authority = importlib.import_module("agmind_immune.correlation.authority")
    key = case["key"]
    acceptance = case["acceptance"]
    store = case["store"]
    coverage = case["coverage"]
    acknowledgements = case["acknowledgements"]
    journal = case["journal"]
    owner = case["owner"]
    through = case["through"]
    assert type(store) is SegmentStore
    assert type(acknowledgements) is AckJournal
    assert type(journal) is CorrelationRequestJournal
    assert type(through) is EvidenceRef
    if writer == "append":
        ref = acceptance.accept(  # type: ignore[attr-defined]
            _item(envelope_value(key, sequence=through.source_sequence + 1))
        )
        coverage._apply_live_accepted(store, ref, None)  # type: ignore[attr-defined]
    elif writer == "retention":
        retention_module._open_retention_state_journal(
            store
        ).prepare_publication(case["retention_decision"])
    elif writer == "ack":
        acknowledgements.close()
    elif writer == "correlation_authority":
        selected = owner._authority  # type: ignore[attr-defined]
        assert selected is not None
        authority._close_correlation_projection_authority(selected)
    elif writer == "journal":
        request = PCCCorrelationSnapshotRequestV1.model_validate(
            {
                "schema_version": (
                    "agmind.pcc-correlation-snapshot-request.v1"
                ),
                "trigger_event_id": through.event_id,
                "trigger_content_sha256": through.content_sha256,
                "trigger_source_sequence": through.source_sequence,
                "requested_ttl_seconds": 120,
            },
            strict=True,
        )
        journal.select(through, canonical_json(request))
    else:
        raise AssertionError("unknown replay writer")


def _start_replay_worker(
    case: dict[str, object],
    *,
    barrier_phase: str | None = None,
) -> tuple[Thread, list[object], list[BaseException]]:
    subject = case["subject"]
    owner = case["owner"]
    through = case["through"]
    reports: list[object] = []
    errors: list[BaseException] = []

    if barrier_phase is not None:
        owner._register_replay_status_barrier_for_test(  # type: ignore[attr-defined]
            subject._ReplayPhase(barrier_phase),  # type: ignore[attr-defined]
        )

    def replay() -> None:
        try:
            reports.append(
                owner._replay_unpublished_prefix(  # type: ignore[attr-defined]
                    through,
                    _factory=subject._UNPUBLISHED_REPLAY_FACTORY,  # type: ignore[attr-defined]
                )
            )
        except BaseException as error:  # noqa: BLE001 - asserted by caller
            errors.append(error)

    worker = Thread(target=replay)
    worker.start()
    return worker, reports, errors


def _release_replay_barrier(case: dict[str, object], phase: str) -> None:
    subject = case["subject"]
    owner = case["owner"]
    owner._release_replay_status_barrier_for_test(  # type: ignore[attr-defined]
        subject._ReplayPhase(phase),  # type: ignore[attr-defined]
    )


def _wait_for_replay_phase(
    case: dict[str, object],
    worker: Thread,
    phase: str,
    errors: list[BaseException] | None = None,
) -> object:
    owner = case["owner"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status = owner._replay_status_for_test()  # type: ignore[attr-defined]
        if status.phase.value == phase:
            return status
        if not worker.is_alive():
            break
        time.sleep(0.001)
    raise AssertionError(
        f"replay never exposed {phase!r} status; "
        f"last_status={status!r}; errors={errors!r}"
    )


def _drop_registered_correlation_authority(issued: object) -> None:
    authority_module, _pcc_module = _correlation_modules()
    authority_module._close_correlation_projection_authority(issued)
    with authority_module._ISSUED_AUTHORITIES_LOCK:
        authority_module._ISSUED_AUTHORITIES.pop(id(issued), None)


@dataclass(frozen=True, slots=True)
class _ControllerReplayReport:
    pcc_count: int
    projection_row_count: int


_CONTROLLER_PROJECTION_STATE_TABLES = (
    "events",
    "projection_dedup",
    "coverage_intervals",
    "containers",
    "process_observations",
    "network_observations",
    "incidents",
    "candidates",
    "candidate_evidence",
    "candidate_invalidations",
    "ingest_cursors",
)


def _drain_controller_cleanup(
    primary_error: BaseException | None,
    steps: tuple[tuple[str, Callable[[], None]], ...],
) -> None:
    cleanup_errors: list[tuple[str, BaseException]] = []
    for label, cleanup in steps:
        try:
            cleanup()
        except BaseException as error:  # noqa: BLE001 - cleanup must drain
            cleanup_errors.append((label, error))
    if not cleanup_errors:
        return
    if primary_error is not None:
        for label, error in cleanup_errors:
            primary_error.add_note(
                "secondary controller replay cleanup failure "
                f"({label}): {type(error).__name__}: {error}"
            )
        return
    raise BaseExceptionGroup(
        "controller replay cleanup failed",
        [error for _label, error in cleanup_errors],
    )


def _controller_projection_row_count(
    connection: sqlite3.Connection,
) -> int:
    total = 0
    for table in _CONTROLLER_PROJECTION_STATE_TABLES:
        value = connection.execute(
            f"SELECT count(*) FROM {table}"
        ).fetchone()[0]
        assert type(value) is int
        total += value
    return total


class _ControllerReplay:
    def __init__(
        self,
        temporary_root: TemporaryDirectory[str],
        owner: Any,
        connection: sqlite3.Connection,
        through: EvidenceRef,
        evidence_cursor: object,
    ) -> None:
        self._temporary_root: TemporaryDirectory[str] | None = temporary_root
        self._owner: Any | None = owner
        self._connection: sqlite3.Connection | None = connection
        self._through: EvidenceRef | None = through
        self._projection_state_observed = False
        self._projection_cursor: object | None = None
        self._projection_row_count: int | None = None
        self.evidence_cursor = evidence_cursor

    def run_public_replay(self) -> _ControllerReplayReport | None:
        owner = self._owner
        connection = self._connection
        through = self._through
        temporary_root = self._temporary_root
        if (
            owner is None
            or connection is None
            or through is None
            or temporary_root is None
        ):
            raise RuntimeError("controller replay ownership already consumed")
        self._owner = None
        self._connection = None
        self._through = None
        self._temporary_root = None

        primary_error: BaseException | None = None
        try:
            subject = importlib.import_module(
                "agmind_immune.evidence.projection_v2"
            )
            if owner._connection is not connection:
                raise AssertionError("controller replay owner lost its connection")
            try:
                report = owner._replay_unpublished_prefix(
                    through,
                    _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
                )
            except subject.ProjectionAuthorityError:
                report = None

            active_connection = owner._connection
            if not isinstance(active_connection, sqlite3.Connection):
                raise TypeError(
                    "controller replay owner lost its active database"
                )
            projection_cursor = subject._current_v2_cursor(active_connection)
            projection_row_count = _controller_projection_row_count(
                active_connection
            )
            pcc_count = active_connection.execute(
                "SELECT count(*) FROM candidates"
            ).fetchone()[0]
            assert type(pcc_count) is int
            self._projection_cursor = projection_cursor
            self._projection_row_count = projection_row_count
            self._projection_state_observed = True
            if report is None:
                return None
            if report.cursor != projection_cursor:
                raise AssertionError(
                    "controller replay report cursor differs from owner database"
                )
            return _ControllerReplayReport(
                pcc_count=pcc_count,
                projection_row_count=projection_row_count,
            )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            _drain_controller_cleanup(
                primary_error,
                (
                    ("owner", owner.close),
                    ("temporary root", temporary_root.cleanup),
                ),
            )

    @property
    def projection_cursor(self) -> object | None:
        if not self._projection_state_observed:
            raise RuntimeError("controller replay state was not observed")
        return self._projection_cursor

    @property
    def projection_row_count(self) -> int:
        if (
            not self._projection_state_observed
            or self._projection_row_count is None
        ):
            raise RuntimeError("controller replay state was not observed")
        return self._projection_row_count

    def has_partial_projection_artifact(self) -> bool:
        return self.projection_row_count > 0


def _append_controller_boundary_candidate(
    coordinator: Any,
    journal: CorrelationRequestJournal,
    *,
    detector_digest: str,
    number: int,
    trigger_sequence: int,
) -> None:
    key = private_key(11)
    trigger = _candidate_trigger(key, sequence=trigger_sequence)
    fields = trigger["normalized_fields"]
    assert isinstance(fields, dict)
    raw_sha256 = hashlib.sha256(
        f"controller-boundary-trigger-{number}".encode()
    ).hexdigest()
    fields["destination_ipv4"] = (
        f"11.{number >> 16}.{number >> 8 & 255}.{number & 255}"
    )
    fields["raw_event_sha256"] = raw_sha256
    fields["event_time"] = NOW
    trigger["source_payload_hash"] = raw_sha256
    trigger["event_time"] = NOW
    trigger["ingest_time"] = NOW
    _resign_pcc_envelope(trigger, key)
    _accept(coordinator, trigger)
    request = _request(trigger, ttl_seconds=120)
    snapshot_fields = _complete_snapshot(trigger, request)
    snapshot_fields["detector_bundle_sha256"] = detector_digest
    snapshot_fields["coverage_through_sequence"] = trigger_sequence
    snapshot_fields["decision_time"] = NOW
    snapshot_fields["inventory_observed_at"] = NOW
    snapshot = _snapshot_envelope(
        key,
        snapshot_fields,
        sequence=trigger_sequence + 1,
    )
    snapshot["event_time"] = NOW
    snapshot["ingest_time"] = NOW
    _resign_pcc_envelope(snapshot, key)
    proof = coordinator.accept_pcc_for_correlation(_item(snapshot), request)
    trigger_ref = coordinator.segment_store._bound_verifier.accepted_ref(
        proof.snapshot.trigger.source_sequence
    )
    assert type(trigger_ref) is EvidenceRef
    selected = journal.select(trigger_ref, canonical_json(proof.request))
    snapshot_ref = proof.evidence_ref
    assert type(snapshot_ref) is EvidenceRef
    journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    journal.mark_completed(selected.request_sha256)


def build_controller_replay_with_authenticated_pcc_count(
    count: int,
) -> _ControllerReplay:
    temporary_root = TemporaryDirectory(
        prefix=f"agmind-controller-cap-{count}-"
    )
    coordinator = None
    journal = None
    acknowledgements = None
    connection = None
    owner = None
    owner_resources_transferred = False
    try:
        key = private_key(11)
        detector_digest = pcc_detector_bundle_sha256(
            Path("deploy/falco/rules.d/agmind-pcc.yaml").read_bytes()
        )
        coordinator = _coordinator(Path(temporary_root.name) / "evidence", key)
        _accept(coordinator, boot_boundary(key))
        journal = CorrelationRequestJournal.create_new(
            coordinator.segment_store
        )
        for number in range(count):
            _append_controller_boundary_candidate(
                coordinator,
                journal,
                detector_digest=detector_digest,
                number=number,
                trigger_sequence=2 + number * 2,
            )
        terminal = _accept(
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
        assert type(terminal) is EvidenceRef
        store = coordinator.segment_store
        acknowledgements = AckJournal.create_new(store)
        for record in store.iter_authenticated_records():
            acknowledgements.record_pending(record.ref)
            acknowledgements.record_confirmed(record.ref)
        subject = importlib.import_module(
            "agmind_immune.evidence.projection_v2"
        )
        connection = subject._v2_connection_for_test()
        registry = load_pinned_special_use_registry(_REGISTRY_PATH)
        owner_factory = subject._v2_projection_owner_for_test
        # The factory owns all four resources even when its validation raises.
        # Do not close them a second time from this builder's failure path.
        owner_resources_transferred = True
        owner = owner_factory(
            connection,
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=registry,
        )
        evidence_cursor = subject.ProjectionCursor(
            host_id=HOST_ID,
            source_sequence=terminal.source_sequence,
            event_id=terminal.event_id,
            content_sha256=terminal.content_sha256,
            frame_sha256=terminal.frame_sha256,
        )
        return _ControllerReplay(
            temporary_root,
            owner,
            connection,
            terminal,
            evidence_cursor,
        )
    except BaseException as error:
        cleanup_steps: list[tuple[str, Callable[[], None]]] = []
        if owner is not None:
            cleanup_steps.append(("owner", owner.close))
        elif not owner_resources_transferred:
            if connection is not None:
                cleanup_steps.append(("connection", connection.close))
            if journal is not None:
                cleanup_steps.append(("journal", journal.close))
            if acknowledgements is not None:
                cleanup_steps.append(
                    ("acknowledgements", acknowledgements.close)
                )
            if coordinator is not None:
                cleanup_steps.append(
                    ("evidence store", coordinator.segment_store.close)
                )
        cleanup_steps.append(("temporary root", temporary_root.cleanup))
        _drain_controller_cleanup(error, tuple(cleanup_steps))
        raise


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

    def attribute_trap(observed: list[str]) -> object:
        class _WrongType:
            def __getattribute__(self, name: str) -> object:
                observed.append(name)
                raise AssertionError("wrong-type attribute access executed")

        return _WrongType()

    try:
        proof_accesses: list[str] = []
        context_accesses: list[str] = []
        with pytest.raises(TypeError):
            pcc_module._freeze_pcc_correlation_input(
                attribute_trap(proof_accesses),
                context,
            )
        with pytest.raises(TypeError):
            pcc_module._freeze_pcc_correlation_input(
                proof,
                attribute_trap(context_accesses),
            )
        assert proof_accesses == []
        assert context_accesses == []

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


def test_replay_pcc_seed_binds_only_compute_owned_coverage(
    tmp_path: Path,
) -> None:
    authority_module, pcc_module = _correlation_modules()
    coordinator, proof = _accepted_complete(tmp_path / "replay-seed")
    context = _context(proof)
    registry = context.special_use_registry
    assert type(registry) is SpecialUseRegistry
    try:
        seed = pcc_module._freeze_replay_pcc_seed(
            proof,
            detector_bundle_sha256=context.pinned_detector_bundle_sha256,
            registry=registry,
            registry_facts_canonical=authority_module._registry_facts_canonical(
                authority_module._registry_facts(registry)
            ),
        )
        assert seed.context.coverage is None
        rebound = pcc_module._rebind_frozen_pcc_projection_context(
            seed,
            context.coverage,
            None,
            None,
        )
        assert pcc_module._correlate_frozen_pcc(rebound) == (
            pcc_module._correlate_pcc_kernel(proof, context)
        )
    finally:
        coordinator.segment_store.close()


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


def test_compute_accepts_only_frozen_value_snapshot(
    tmp_path: Path,
) -> None:
    subject = importlib.import_module("agmind_immune.evidence.projection_v2")
    snapshot, resources = _build_complete_replay_input_snapshot(
        tmp_path / "compute-boundary"
    )

    class _WrongSource:
        def __getattribute__(self, name: str) -> object:
            raise AssertionError(f"wrong source attribute executed: {name}")

    try:
        computation = subject._compute_replay(snapshot)
        assert type(computation) is subject._ReplayComputation
        assert tuple(
            field.name
            for field in fields(snapshot)
            if callable(getattr(snapshot, field.name))
        ) == ()
        assert not any(
            isinstance(getattr(snapshot, field.name), (SegmentStore, AckJournal))
            for field in fields(snapshot)
        )
        with pytest.raises(TypeError):
            subject._compute_replay(
                replace(snapshot, source=resources["store"])
            )
        with pytest.raises(TypeError):
            subject._compute_replay(
                replace(snapshot, source=_WrongSource())
            )
    finally:
        _close_complete_replay_input(resources)


def test_compute_replay_uses_base_and_next_publish_generation(
    tmp_path: Path,
) -> None:
    subject = importlib.import_module("agmind_immune.evidence.projection_v2")
    snapshot, resources = _build_complete_replay_input_snapshot(
        tmp_path / "split-generation",
        base_projection_generation=7,
        publish_generation=8,
    )
    try:
        computation = subject._compute_replay(snapshot)
        assert snapshot.correlation.predecessor.generation == 7
        assert computation.terminal_predecessor.generation == 8
    finally:
        _close_complete_replay_input(resources)


@pytest.mark.parametrize("authority", ("ack", "correlation_journal"))
def test_replay_corruption_fence_drains_after_full_lock_unwind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority: str,
) -> None:
    correlation_authority = importlib.import_module(
        "agmind_immune.correlation.authority"
    )
    monkeypatch.setattr(
        correlation_authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    child = os.fork()
    if child == 0:
        exit_code = 2
        try:
            case = _build_replay_orchestration_case(
                tmp_path / authority,
                record_count=8,
            )
            subject = case["subject"]
            owner = case["owner"]
            store = case["store"]
            through = case["through"]
            assert type(store) is SegmentStore
            assert type(through) is EvidenceRef
            artifact_name = (
                "ack-journal.agf"
                if authority == "ack"
                else "correlation-requests.agf"
            )
            replacement = store.root / f"{artifact_name}.replacement"
            replacement.write_bytes(b"")
            replacement.chmod(0o600)
            os.replace(replacement, store.root / artifact_name)
            replay_error: BaseException | None = None
            try:
                owner._replay_unpublished_prefix(  # type: ignore[attr-defined]
                    through,
                    _factory=subject._UNPUBLISHED_REPLAY_FACTORY,  # type: ignore[attr-defined]
                )
            except BaseException as error:  # noqa: BLE001 - asserted below
                replay_error = error
            assert isinstance(replay_error, ProjectionAuthorityError)
            assert store.status().healthy is False
            assert (
                owner._replay_status_for_test().reservation_present  # type: ignore[attr-defined]
                is False
            )
            exit_code = 0
        finally:
            os._exit(exit_code)

    deadline = time.monotonic() + 5
    status: int | None = None
    while time.monotonic() < deadline:
        waited, child_status = os.waitpid(child, os.WNOHANG)
        if waited == child:
            status = child_status
            break
        time.sleep(0.001)
    if status is None:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        pytest.fail("replay corruption fence did not unwind before persistence")
    assert os.waitstatus_to_exitcode(status) == 0


def test_snapshot_cleanup_consumes_fd_ownership_before_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    correlation_authority = importlib.import_module(
        "agmind_immune.correlation.authority"
    )
    monkeypatch.setattr(
        correlation_authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    case = _build_replay_orchestration_case(
        tmp_path / "one-shot-close",
        record_count=8,
    )
    subject = case["subject"]
    owner = case["owner"]
    through = case["through"]
    assert type(through) is EvidenceRef
    real_close_snapshot = subject._close_replay_source_snapshot  # type: ignore[attr-defined]
    real_close = os.close
    close_attempts: dict[int, int] = {}
    owned_descriptors: tuple[int, ...] = ()
    unrelated_descriptor = -1
    call_count = 0

    def fail_after_partial_close(snapshot: object) -> None:
        nonlocal call_count, owned_descriptors, unrelated_descriptor
        call_count += 1
        owned_descriptors = tuple(
            segment.descriptor  # type: ignore[attr-defined]
            for segment in snapshot.segments  # type: ignore[attr-defined]
        )
        assert len(owned_descriptors) >= 2
        if call_count == 1:
            first, failing, *remaining = owned_descriptors
            close_attempts[first] = close_attempts.get(first, 0) + 1
            real_close(first)
            opened = os.open(os.devnull, os.O_RDONLY)
            os.dup2(opened, first)
            if opened != first:
                real_close(opened)
            unrelated_descriptor = first
            close_attempts[failing] = close_attempts.get(failing, 0) + 1
            for descriptor in remaining:
                close_attempts[descriptor] = close_attempts.get(descriptor, 0) + 1
                real_close(descriptor)
            raise OSError("injected source snapshot close failure")
        for descriptor in owned_descriptors:
            close_attempts[descriptor] = close_attempts.get(descriptor, 0) + 1
            try:
                real_close(descriptor)
            except OSError:
                pass

    monkeypatch.setattr(
        subject,
        "_close_replay_source_snapshot",
        fail_after_partial_close,
    )
    try:
        with pytest.raises(OSError, match="injected source snapshot close failure"):
            owner._replay_unpublished_prefix(  # type: ignore[attr-defined]
                through,
                _factory=subject._UNPUBLISHED_REPLAY_FACTORY,  # type: ignore[attr-defined]
            )
        assert close_attempts
        assert set(close_attempts.values()) == {1}
        assert unrelated_descriptor >= 0
        os.fstat(unrelated_descriptor)
    finally:
        monkeypatch.setattr(
            subject,
            "_close_replay_source_snapshot",
            real_close_snapshot,
        )
        if unrelated_descriptor >= 0:
            try:
                os.fstat(unrelated_descriptor)
            except OSError:
                pass
            else:
                real_close(unrelated_descriptor)
        for descriptor in owned_descriptors:
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            real_close(descriptor)
        _close_replay_orchestration_case(case)


@pytest.mark.parametrize(
    "writer",
    (
        "append",
        "retention",
        "ack",
        "correlation_authority",
        "journal",
    ),
)
def test_snapshot_revision_change_before_validate_rejects_no_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    writer: str,
) -> None:
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    case = _build_replay_orchestration_case(tmp_path / writer)
    subject = case["subject"]
    owner = case["owner"]
    connection = case["connection"]
    base_generation = owner._generation  # type: ignore[attr-defined]
    before_hash = subject._v2_snapshot_hash(connection)  # type: ignore[attr-defined]
    worker, reports, errors = _start_replay_worker(
        case,
        barrier_phase="computing",
    )
    barrier_released = False
    try:
        status = _wait_for_replay_phase(case, worker, "computing", errors)
        assert status.reservation_present is True  # type: ignore[attr-defined]
        with pytest.raises(ProjectionAuthorityError):
            owner.status()  # type: ignore[attr-defined]
        _perform_replay_writer(case, writer)
        _release_replay_barrier(case, "computing")
        barrier_released = True
        worker.join(5)
        assert worker.is_alive() is False
        assert reports == []
        assert len(errors) == 1
        assert isinstance(errors[0], ProjectionAuthorityError)
        assert owner._generation == base_generation  # type: ignore[attr-defined]
        assert owner._connection is connection  # type: ignore[attr-defined]
        assert subject._v2_snapshot_hash(connection) == before_hash  # type: ignore[attr-defined]
        final_status = owner._replay_status_for_test()  # type: ignore[attr-defined]
        assert final_status.phase.value == "failed"
        assert final_status.reservation_present is False
    finally:
        if not barrier_released:
            try:
                _release_replay_barrier(case, "computing")
            except ProjectionAuthorityError:
                pass
        if worker.is_alive():
            worker.join(5)
        _close_replay_orchestration_case(case)


@pytest.mark.parametrize(
    "writer",
    (
        "append",
        "retention",
        "ack",
        "correlation_authority",
        "journal",
    ),
)
def test_writer_started_during_validate_publish_cannot_make_mixed_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    writer: str,
) -> None:
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    case = _build_replay_orchestration_case(tmp_path / writer)
    owner = case["owner"]
    connection = case["connection"]
    through = case["through"]
    records = case["records"]
    assert type(through) is EvidenceRef
    assert type(records) is tuple
    base_generation = owner._generation  # type: ignore[attr-defined]
    worker, reports, errors = _start_replay_worker(
        case,
        barrier_phase="validating",
    )
    barrier_released = False
    writer_started = Event()
    writer_errors: list[BaseException] = []

    def write() -> None:
        writer_started.set()
        try:
            _perform_replay_writer(case, writer)
        except BaseException as error:  # noqa: BLE001 - asserted below
            writer_errors.append(error)

    writer_worker = Thread(target=write)
    try:
        validating = _wait_for_replay_phase(case, worker, "validating", errors)
        assert validating.reservation_present is True  # type: ignore[attr-defined]
        writer_worker.start()
        assert writer_started.wait(5)
        assert writer_worker.is_alive()
        _release_replay_barrier(case, "validating")
        barrier_released = True
        worker.join(5)
        writer_worker.join(5)
        assert worker.is_alive() is False
        assert writer_worker.is_alive() is False
        assert writer_errors == []
        assert errors == []
        assert len(reports) == 1
        report = reports[0]
        assert report.cursor.source_sequence == through.source_sequence  # type: ignore[attr-defined]
        assert report.cursor.event_id == through.event_id  # type: ignore[attr-defined]
        assert report.cursor.content_sha256 == through.content_sha256  # type: ignore[attr-defined]
        assert report.applied_count == len(records)  # type: ignore[attr-defined]
        assert owner._generation == base_generation + 1  # type: ignore[attr-defined]
        assert owner._connection is not connection  # type: ignore[attr-defined]
        published = owner._replay_status_for_test()  # type: ignore[attr-defined]
        assert published.phase.value == "published"
        assert published.reservation_present is False
    finally:
        if not barrier_released:
            try:
                _release_replay_barrier(case, "validating")
            except ProjectionAuthorityError:
                pass
        if worker.is_alive():
            worker.join(5)
        if writer_worker.is_alive():
            writer_worker.join(5)
        _close_replay_orchestration_case(case)


@pytest.mark.parametrize("phase", ("freeze", "compute", "publish"))
def test_baseexception_at_replay_phase_cleans_fds_reservation_and_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    case = _build_replay_orchestration_case(
        tmp_path / phase,
        record_count=8,
    )
    subject = case["subject"]
    owner = case["owner"]
    connection = case["connection"]
    through = case["through"]
    assert type(through) is EvidenceRef
    base_generation = owner._generation  # type: ignore[attr-defined]
    before_hash = subject._v2_snapshot_hash(connection)  # type: ignore[attr-defined]
    before_fds = frozenset(os.listdir("/dev/fd"))
    try:
        with pytest.raises(KeyboardInterrupt):
            owner._replay_unpublished_prefix(  # type: ignore[attr-defined]
                through,
                _factory=subject._UNPUBLISHED_REPLAY_FACTORY,  # type: ignore[attr-defined]
                _fault_phase=subject._ReplayFaultPhase(phase),  # type: ignore[attr-defined]
            )
        assert frozenset(os.listdir("/dev/fd")) == before_fds
        assert owner._generation == base_generation  # type: ignore[attr-defined]
        assert owner._connection is connection  # type: ignore[attr-defined]
        assert subject._v2_snapshot_hash(connection) == before_hash  # type: ignore[attr-defined]
        status = owner._replay_status_for_test()  # type: ignore[attr-defined]
        assert status.generation == base_generation
        assert status.phase.value == "failed"
        assert status.reservation_present is False
    finally:
        _close_replay_orchestration_case(case)


def test_compute_rejects_nested_evidence_ref_before_callback(
    tmp_path: Path,
) -> None:
    subject = importlib.import_module("agmind_immune.evidence.projection_v2")
    snapshot, resources = _build_complete_replay_input_snapshot(
        tmp_path / "compute-nested-ref"
    )
    source = snapshot.source
    first = source.records[0]
    hostile_ref = replace(
        first.ref,
        source_sequence=_NestedBombStr(str(first.ref.source_sequence)),
    )
    hostile_source = replace(
        source,
        records=(replace(first, ref=hostile_ref), *source.records[1:]),
    )
    try:
        with pytest.raises(TypeError):
            subject._compute_replay(replace(snapshot, source=hostile_source))
    finally:
        _close_complete_replay_input(resources)


def test_compute_is_deterministic_and_does_not_mutate_live_projection(
    tmp_path: Path,
) -> None:
    subject = importlib.import_module("agmind_immune.evidence.projection_v2")
    snapshot, resources = _build_complete_replay_input_snapshot(
        tmp_path / "compute-determinism"
    )
    owner_connection = subject._v2_connection_for_test()
    try:
        before = subject._v2_snapshot_hash(owner_connection)
        first = subject._compute_replay(snapshot)
        second = subject._compute_replay(snapshot)
        assert first == second
        assert subject._v2_snapshot_hash(owner_connection) == before
    finally:
        owner_connection.close()
        _close_complete_replay_input(resources)


def test_controller_late_candidate_limit_4096_accepts_4097_fails_closed() -> None:
    accepted = build_controller_replay_with_authenticated_pcc_count(4096)
    accepted_report = accepted.run_public_replay()
    assert accepted_report is not None
    assert accepted_report.pcc_count == 4096
    assert accepted_report.projection_row_count > 0
    assert accepted.projection_cursor == accepted.evidence_cursor
    assert accepted.has_partial_projection_artifact() is True
    with pytest.raises(RuntimeError, match="ownership already consumed"):
        accepted.run_public_replay()

    rejected = build_controller_replay_with_authenticated_pcc_count(4097)
    assert rejected.run_public_replay() is None
    assert rejected.projection_cursor is None
    assert rejected.has_partial_projection_artifact() is False
