from __future__ import annotations

import importlib
import sqlite3
from pathlib import Path
from typing import Any, cast

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.correlation.primitives import load_pinned_special_use_registry
from agmind_immune.evidence.projection import ProjectionAuthorityError
from agmind_immune.evidence.segments import EvidenceRef
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
from tests.coverage.test_state import _gap_open, _generic_critical
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
from tests.phase5b_helpers import NOW, boot_boundary, envelope_value, private_key

_REGISTRY_PATH = Path("contracts/v1/ipv4-special-use.csv")
_DETECTOR_HASH = "1" * 64


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
    coordinator, first, second = _accepted_two_complete(tmp_path / "evidence")
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    _complete_journal(journal, first)
    _complete_journal(journal, second)
    owner, connection = _owner(subject, coordinator, journal)
    try:
        records = tuple(coordinator.segment_store.iter_authenticated_records())
        for record in records[:3]:
            owner.apply(record.ref)
        candidates = connection.execute(
            "SELECT candidate_id,primary_event_id FROM candidates"
        ).fetchall()
        assert len(candidates) == 1
        candidate_id = str(candidates[0]["candidate_id"])
        assert candidates[0]["primary_event_id"] == first.snapshot.trigger.event_id
        connection.execute(
            "INSERT INTO candidate_invalidations VALUES(?,?,?,?,?)",
            (
                candidate_id,
                first.event_id,
                f"{first.source_sequence:020d}",
                first.content_sha256,
                "late_critical_coverage_gap",
            ),
        )
        for record in records[3:]:
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
