from __future__ import annotations

import hashlib
import importlib
import os
import pickle
import sqlite3
from contextvars import copy_context
from copy import copy
from dataclasses import replace
from pathlib import Path
from threading import Event, Thread
from typing import Any, cast

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.correlation.primitives import load_pinned_special_use_registry
from agmind_immune.evidence.projection import ProjectionAuthorityError
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
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
    subject = _subject()
    historical = importlib.import_module("agmind_immune.coverage.historical")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator, first, second = _accepted_two_complete(tmp_path / "evidence")
    proofs = (first, second)
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        proofs,
    )
    real_prepare = historical._prepare_historical_record
    real_reduce = historical._reduce_historical_coverage
    real_derive = historical.derive_historical_coverage
    real_revalidate = historical._revalidate_authority
    prepare_calls = 0
    reduction_calls = 0
    derive_calls = 0
    revalidation_calls = 0

    def counted_prepare(record: object) -> object:
        nonlocal prepare_calls
        prepare_calls += 1
        return real_prepare(record)

    def counted_reduce(*args: object, **kwargs: object) -> object:
        nonlocal reduction_calls
        reduction_calls += 1
        return real_reduce(*args, **kwargs)

    def counted_derive(*args: object, **kwargs: object) -> object:
        nonlocal derive_calls
        derive_calls += 1
        return real_derive(*args, **kwargs)

    def counted_revalidate(*args: object, **kwargs: object) -> object:
        nonlocal revalidation_calls
        revalidation_calls += 1
        return real_revalidate(*args, **kwargs)

    monkeypatch.setattr(historical, "_prepare_historical_record", counted_prepare)
    monkeypatch.setattr(historical, "_reduce_historical_coverage", counted_reduce)
    monkeypatch.setattr(historical, "_revalidate_authority", counted_revalidate)
    monkeypatch.setattr(historical, "derive_historical_coverage", counted_derive)
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
        assert report.applied_count == len(records)
        assert prepare_calls == 2 * len(records)
        assert reduction_calls == 2 * len(proofs)
        assert revalidation_calls == 2 * derive_calls
    finally:
        owner.close()


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
    captured_sessions: list[Any] = []
    digest_visits: list[int] = []
    reducer_visits: list[int] = []
    real_activate = subject._activate_replay_historical_session
    real_digest = historical._replay_compact_digest
    real_reduce = historical._reduce_historical_coverage

    def capture_session(*args: object, **kwargs: object) -> object:
        session, token = real_activate(*args, **kwargs)
        captured_sessions.append(session)
        return session, token

    def count_digest(records_value: object) -> object:
        selected = tuple(cast(Any, records_value))
        digest_visits.append(len(selected))
        return real_digest(selected)

    def count_reduce(records_value: object, *args: object, **kwargs: object) -> object:
        selected = tuple(cast(Any, records_value))
        reducer_visits.append(len(selected))
        return real_reduce(selected, *args, **kwargs)

    monkeypatch.setattr(subject, "_activate_replay_historical_session", capture_session)
    monkeypatch.setattr(historical, "_replay_compact_digest", count_digest)
    monkeypatch.setattr(historical, "_reduce_historical_coverage", count_reduce)
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
        assert len(captured_sessions) == 1
        session = captured_sessions[0]
        compact_count = session.compact_count
        assert len(reducer_visits) == 2 * len(stale_proofs)
        assert sum(reducer_visits) > compact_count
        assert digest_visits == [compact_count]
        for memo in session.memo.values():
            assert not hasattr(memo, "compact_records")
            assert not hasattr(memo, "compact_prepared")
            assert type(memo.compact_count) is int
            assert type(memo.compact_digest) is str
    finally:
        owner.close()


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
    real_revalidate = historical._revalidate_authority
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
        historical,
        "_revalidate_authority",
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
    real_activate = subject._activate_replay_historical_session

    def block_slow_binding(candidate_store: Any, authenticated: Any) -> Any:
        if candidate_store is store and not binding_entered.is_set():
            binding_entered.set()
            if not release_binding.wait(5):
                raise AssertionError("slow binding release timed out")
        return real_new_binding(candidate_store, authenticated)

    def observe_activation(*args: object, **kwargs: object) -> Any:
        activation_started.set()
        result = real_activate(*args, **kwargs)
        activation_completed.set()
        return result

    monkeypatch.setattr(historical, "_new_path_binding", block_slow_binding)
    monkeypatch.setattr(
        subject,
        "_activate_replay_historical_session",
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
    real_revoke = historical._ReplayHistoricalSession.revoke

    def block_after_revoke(session: Any) -> None:
        real_revoke(session)
        revoke_entered.set()
        if not release_revoke.wait(5):
            raise AssertionError("session revoke release timed out")

    monkeypatch.setattr(
        historical._ReplayHistoricalSession,
        "revoke",
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
    real_issue = historical._issue_historical_path_authority

    def capture_production_path(
        candidate_store: Any,
        authenticated: AuthenticatedPCCInput,
    ) -> object:
        path = real_issue(candidate_store, authenticated)
        if (
            candidate_store is store
            and authenticated.event_id == first.event_id
            and not captured
        ):
            captured.append((authenticated, path))
        return path

    monkeypatch.setattr(
        historical,
        "_issue_historical_path_authority",
        capture_production_path,
    )
    copied_context_denied = False
    stale_event_denied = False
    first_candidate_seen = False

    def probe_path_epoch(step: str) -> None:
        nonlocal copied_context_denied, stale_event_denied, first_candidate_seen
        if step == "candidate" and not first_candidate_seen:
            first_candidate_seen = True
            assert captured
            proof, path = captured[0]
            copied = copy_context()
            try:
                copied.run(
                    historical.derive_historical_coverage,
                    proof,
                    path,
                )
            except historical.HistoricalCoverageUnavailable:
                copied_context_denied = True
            return
        if step == "event" and first_candidate_seen and not stale_event_denied:
            proof, path = captured[0]
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
        assert stale_event_denied is True
    finally:
        owner.close()


def test_replay_session_runtime_capability_cannot_be_copied_pickled_or_subclassed(
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
    captured_session: list[object] = []
    real_activate = subject._activate_replay_historical_session

    def capture_session(*args: object, **kwargs: object) -> Any:
        session, token = real_activate(*args, **kwargs)
        captured_session.append(session)
        return session, token

    monkeypatch.setattr(
        subject,
        "_activate_replay_historical_session",
        capture_session,
    )
    protections_checked = False
    subclass_denied = False

    def check_capability_protections(step: str) -> None:
        nonlocal protections_checked, subclass_denied
        if step != "event" or protections_checked:
            return
        protections_checked = True
        session = captured_session[0]
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
            session.compact_records.pop()
            session.compact_prepared.pop()
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
        if historical._ACTIVE_REPLAY_SESSION.get() is not None:
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
