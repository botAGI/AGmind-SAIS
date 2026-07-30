from __future__ import annotations

import hashlib
import importlib
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from agmind_immune.canonicaljson import canonical_json, release_id
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    SegmentStore,
    StoredEvidenceRecord,
)
from agmind_immune.ingest import service as service_module
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeVerifier,
    PinnedObserverRoot,
    decode_events_page,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.phase5b_helpers import (
    BOOT_A,
    HOST_ID,
    NOW,
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    root_value,
)


def _projection() -> Any:
    try:
        return importlib.import_module("agmind_immune.evidence.projection")
    except ModuleNotFoundError:
        pytest.fail("projection slice is not implemented")


def _system(path: Path) -> tuple[AcceptanceCoordinator, SegmentStore, AckJournal]:
    path.parent.mkdir(parents=True, mode=0o700)
    path.parent.chmod(0o700)
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(EnvelopeVerifier(root, chain), store)
    return coordinator, store, AckJournal.create_new(store)


def _accept(
    coordinator: AcceptanceCoordinator,
    value: dict[str, object],
) -> EvidenceRef:
    item = decode_events_page(canonical_json(page_value(value))).events[0]
    return coordinator.accept(item)


def _confirm(journal: AckJournal, *refs: EvidenceRef) -> None:
    for ref in refs:
        journal.record_pending(ref)
        journal.record_confirmed(ref)


def _counts(path: Path) -> tuple[int, ...]:
    with sqlite3.connect(path) as connection:
        return tuple(
            int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in (
                "events",
                "projection_dedup",
                "coverage_intervals",
                "containers",
                "process_observations",
                "network_observations",
                "ingest_cursors",
            )
        )


def _falco_fields(raw_hash: str) -> dict[str, object]:
    container = "a" * 64
    return {
        "detector_rule": "Outbound connect",
        "detector_rule_version": "1",
        "falco_version": "0.41.3",
        "event_time": NOW,
        "evt_type": "connect",
        "evt_rawres": 0,
        "evt_res": "SUCCESS",
        "successful_connect": True,
        "investigation_only": False,
        "falco_container_id_prefix": container[:12],
        "falco_container_full_id": container,
        "falco_container_start_ts": 1,
        "docker_container_id": container,
        "docker_started_at": NOW,
        "image_id": f"sha256:{'b' * 64}",
        "repo_digests": [f"repo@sha256:{'c' * 64}"],
        "immutable_spec_sha256": "d" * 64,
        "inventory_revision": 2**63,
        "proc_name": "curl",
        "proc_exe_path": "/usr/bin/curl",
        "proc_parent_name": "sh",
        "destination_ipv4": "203.0.113.7",
        "destination_port": 443,
        "l4_protocol": "tcp",
        "missing_required_fields": [],
        "raw_event_sha256": raw_hash,
    }


@pytest.mark.parametrize(
    "case",
    ["unconfirmed", "non_next", "forged", "signed_gap", "uint64_text"],
)
def test_authority_order_and_uint64_text(tmp_path: Path, case: str) -> None:
    projection = _projection()
    if case == "uint64_text":
        encoded = [projection._uint64(value) for value in (2**63, 2**64 - 1)]
        assert encoded == ["09223372036854775808", "18446744073709551615"]
        assert encoded == sorted(encoded)
        return
    coordinator, store, journal = _system(tmp_path / case / "evidence")
    key = private_key(11)
    first = _accept(coordinator, boot_boundary(key))
    if case == "signed_gap":
        fourth = _accept(
            coordinator,
            envelope_value(
                key,
                sequence=4,
                boot_id=BOOT_A,
                normalized_fields={"kind": "after_reserved_gap"},
            ),
        )
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
        _confirm(journal, first, fourth, gap)
        cache = projection.ProjectionStore.open(
            tmp_path / case / "projection.sqlite3",
            evidence=store,
            acknowledgements=journal,
        )
        cache.apply(first)
        assert cache.apply(fourth).cursor.source_sequence == 4
        assert cache.apply(gap).cursor.source_sequence == 5
        cache.close()
        store.close()
        return
    second = _accept(
        coordinator,
        envelope_value(key, sequence=2, boot_id=BOOT_A, normalized_fields={"kind": "two"}),
    )
    _confirm(journal, first)
    cache = projection.ProjectionStore.open(
        tmp_path / case / "projection.sqlite3",
        evidence=store,
        acknowledgements=journal,
    )
    if case == "unconfirmed":
        with pytest.raises(projection.ProjectionAuthorityError):
            cache.apply(second)
    elif case == "non_next":
        _confirm(journal, second)
        with pytest.raises(projection.ProjectionAuthorityError):
            cache.apply(second)
    elif case == "forged":
        with pytest.raises(projection.ProjectionAuthorityError):
            cache.apply(replace(first, frame_sha256="0" * 64))
    else:
        cache.apply(first)
        assert cache.apply(first).reducer_applied is False
        with sqlite3.connect(cache.path) as connection:
            assert connection.execute(
                "SELECT source_sequence FROM events WHERE event_id=?", (first.event_id,)
            ).fetchone() == ("00000000000000000001",)
    cache.close()
    store.close()


@pytest.mark.parametrize(
    "failure_step",
    ["event", "dedup", "reducer", "cursor", "commit", "rollback", "dedup_order"],
)
@pytest.mark.parametrize("reducer_kind", ["falco", "coverage"])
def test_atomic_apply_retry_and_conflict(
    tmp_path: Path,
    failure_step: str,
    reducer_kind: str,
) -> None:
    projection = _projection()
    coordinator, store, journal = _system(tmp_path / failure_step / "evidence")
    key = private_key(11)
    first = _accept(coordinator, boot_boundary(key))
    if reducer_kind == "falco":
        raw_hash = hashlib.sha256(b"atomic reducer").hexdigest()
        second_value = envelope_value(
            key,
            sequence=2,
            event_type="falco_connect",
            normalized_fields=_falco_fields(raw_hash),
            source_payload_hash=raw_hash,
            container_id="a" * 64,
            container_start_time=NOW,
            release_id=release_id(f"sha256:{'b' * 64}", "d" * 64),
            inventory_revision=2**63,
        )
    else:
        second_value = envelope_value(
            key,
            sequence=2,
            event_type="coverage",
            normalized_fields={
                "component": "observer",
                "kind": "drop",
                "severity": "WARNING",
                "opened_at": NOW,
                "dropped_count": 1,
                "reason_code": "atomic_test",
            },
        )
    second = _accept(coordinator, second_value)
    _confirm(journal, first, second)
    injected: set[str] = set()
    armed = False

    def hook(step: str) -> None:
        if not armed:
            return
        if failure_step == "rollback" and step == "reducer":
            raise OSError("injected reducer primary")
        if step == failure_step and step not in injected:
            injected.add(step)
            raise OSError(f"injected {step}")

    path = tmp_path / failure_step / "projection.sqlite3"
    cache = projection.ProjectionStore.open(
        path, evidence=store, acknowledgements=journal, step_hook=hook
    )
    cache.apply(first)
    armed = True
    baseline = _counts(path)
    if failure_step == "dedup_order":
        statements: list[str] = []
        assert cache._connection is not None
        cache._connection.set_trace_callback(statements.append)
        cache.apply(second)
        begin = next(index for index, sql in enumerate(statements) if sql == "BEGIN IMMEDIATE")
        lookup = next(
            index
            for index, sql in enumerate(statements)
            if sql.startswith("SELECT primary_event_id FROM projection_dedup")
        )
        assert begin < lookup
        cache.close()
        store.close()
        return
    with pytest.raises(OSError, match="injected"):
        cache.apply(second)
    if failure_step in {"commit", "rollback"}:
        with pytest.raises(projection.ProjectionUnhealthy):
            cache.snapshot_hash()
        cache.close()
        store.close()
        return
    assert _counts(path) == baseline
    result = cache.apply(second)
    assert cache.apply(second) == replace(result, reducer_applied=False)
    if failure_step == "cursor":
        with sqlite3.connect(path) as connection:
            connection.execute(
                "UPDATE events SET event_type='tampered' WHERE event_id=?",
                (first.event_id,),
            )
        with pytest.raises(projection.ProjectionConflict):
            cache.apply(first)
        with pytest.raises(projection.ProjectionUnhealthy):
            cache.snapshot_hash()
    cache.close()
    store.close()


@pytest.mark.parametrize(
    "case",
    ["falco", "coverage", "coverage_changed", "falco_hash_mismatch"],
)
def test_projection_dedup_is_logical_and_provenanced(tmp_path: Path, case: str) -> None:
    projection = _projection()
    coordinator, store, journal = _system(tmp_path / case / "evidence")
    key = private_key(11)
    first = _accept(coordinator, boot_boundary(key))
    raw_hash = hashlib.sha256(b"same raw event").hexdigest()
    refs = [first]
    if case.startswith("falco"):
        fields = _falco_fields(raw_hash)
        payload_hash = "e" * 64 if case == "falco_hash_mismatch" else raw_hash
        falco_envelope = envelope_value(
            key,
            sequence=2,
            event_type="falco_connect",
            normalized_fields=fields,
            source_payload_hash=payload_hash,
            container_id="a" * 64,
            container_start_time=NOW,
            release_id=release_id(f"sha256:{'b' * 64}", "d" * 64),
            inventory_revision=2**63,
        )
        if case == "falco_hash_mismatch":
            with pytest.raises(ValueError):
                _accept(coordinator, falco_envelope)
            canonical = canonical_json(falco_envelope)
            controlled_ref = EvidenceRef(
                segment_id="00000000-0000-4000-8000-000000000001",
                segment_relative_path="segments/controlled.open",
                frame_offset=0,
                frame_size=1,
                frame_sha256="f" * 64,
                event_id=str(falco_envelope["event_id"]),
                source_sequence=2,
                content_sha256=hashlib.sha256(canonical).hexdigest(),
            )
            controlled = StoredEvidenceRecord(
                envelope=falco_envelope,
                canonical_envelope=canonical,
                priority=EvidencePriority.ROUTINE,
                accepted_at=NOW,
                ref=controlled_ref,
            )
            with pytest.raises(
                projection.ProjectionValidationError,
                match="raw hash",
            ):
                projection._prepare(controlled)
            store.close()
            return
        refs.append(_accept(coordinator, falco_envelope))
        if case == "falco":
            refs.append(
                _accept(
                    coordinator,
                    envelope_value(
                        key,
                        sequence=3,
                        event_type="falco_connect",
                        normalized_fields=fields,
                        source_payload_hash=raw_hash,
                        container_id="a" * 64,
                        container_start_time=NOW,
                        release_id=release_id(f"sha256:{'b' * 64}", "d" * 64),
                        inventory_revision=2**63,
                    ),
                )
            )
    else:
        fields = {
            "component": "observer",
            "kind": "drop",
            "severity": "WARNING",
            "opened_at": NOW,
            "dropped_count": 1,
            "reason_code": "test",
        }
        for sequence in (2, 3):
            current_fields = dict(fields)
            if case == "coverage_changed" and sequence == 3:
                current_fields["dropped_count"] = 2
            refs.append(
                _accept(
                    coordinator,
                    envelope_value(
                        key,
                        sequence=sequence,
                        event_type="coverage",
                        normalized_fields=current_fields,
                    ),
                )
            )
    _confirm(journal, *refs)
    cache = projection.ProjectionStore.open(
        tmp_path / case / "projection.sqlite3",
        evidence=store,
        acknowledgements=journal,
    )
    cache.apply(refs[0])
    for ref in refs[1:]:
        cache.apply(ref)
    with sqlite3.connect(cache.path) as connection:
        reduced_table = "network_observations" if case == "falco" else "coverage_intervals"
        expected = 2 if case == "coverage_changed" else 1
        assert connection.execute(f"SELECT count(*) FROM {reduced_table}").fetchone() == (
            expected,
        )
        assert connection.execute("SELECT count(*) FROM events").fetchone() == (3,)
    cache.close()
    store.close()


def test_projection_status_is_read_only_and_fail_closed(tmp_path: Path) -> None:
    projection = _projection()
    coordinator, store, journal = _system(tmp_path / "healthy" / "evidence")
    path = tmp_path / "healthy" / "projection.sqlite3"
    cache = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
    )
    empty_ack = journal.snapshot()
    empty_counts = _counts(path)
    assert cache.status() == projection.ProjectionStatus(True, None)
    assert journal.snapshot() == empty_ack
    assert _counts(path) == empty_counts

    key = private_key(11)
    first = _accept(coordinator, boot_boundary(key))
    _confirm(journal, first)
    applied = cache.apply(first)
    before_ack = journal.snapshot()
    before_counts = _counts(path)
    status = cache.status()
    assert type(status) is projection.ProjectionStatus
    assert status == projection.ProjectionStatus(
        True,
        projection.ProjectionCursor(
            host_id=HOST_ID,
            source_sequence=first.source_sequence,
            event_id=first.event_id,
            content_sha256=first.content_sha256,
            frame_sha256=first.frame_sha256,
        ),
    )
    assert status.cursor == applied.cursor
    assert type(status.cursor) is projection.ProjectionCursor
    assert journal.snapshot() == before_ack
    assert _counts(path) == before_counts

    retained_connection = cache._connection
    assert retained_connection is not None
    cache._connection = None
    assert cache.status() == projection.ProjectionStatus(False, None)
    cache._connection = retained_connection
    cache.close()
    assert cache.status() == projection.ProjectionStatus(False, None)
    store.close()

    _latched_coordinator, latched_store, latched_journal = _system(
        tmp_path / "latched" / "evidence"
    )
    latched_path = tmp_path / "latched" / "projection.sqlite3"
    latched = projection.ProjectionStore.open(
        latched_path,
        evidence=latched_store,
        acknowledgements=latched_journal,
    )
    latched._healthy = False
    latched_ack = latched_journal.snapshot()
    latched_counts = _counts(latched_path)
    assert latched.status() == projection.ProjectionStatus(False, None)
    assert latched_journal.snapshot() == latched_ack
    assert _counts(latched_path) == latched_counts
    latched.close()
    latched_store.close()

    for case in (
        "malformed_uint64",
        "malformed_host",
        "malformed_event",
        "malformed_content_hash",
        "malformed_frame_hash",
        "multiple",
    ):
        coordinator, candidate_store, candidate_journal = _system(
            tmp_path / case / "evidence"
        )
        candidate_path = tmp_path / case / "projection.sqlite3"
        candidate = projection.ProjectionStore.open(
            candidate_path,
            evidence=candidate_store,
            acknowledgements=candidate_journal,
        )
        candidate_ref = _accept(coordinator, boot_boundary(key))
        _confirm(candidate_journal, candidate_ref)
        candidate.apply(candidate_ref)
        assert candidate._connection is not None
        if case == "malformed_uint64":
            candidate._connection.execute(
                "UPDATE ingest_cursors SET source_sequence=?",
                ("18446744073709551616",),
            )
        elif case == "malformed_host":
            candidate._connection.execute(
                "UPDATE ingest_cursors SET host_id=?",
                ("not-a-host-id",),
            )
        elif case == "malformed_event":
            candidate._connection.execute("PRAGMA foreign_keys=OFF")
            candidate._connection.execute(
                "UPDATE ingest_cursors SET event_id=?",
                ("evt_" + "z" * 64,),
            )
        elif case == "malformed_content_hash":
            candidate._connection.execute(
                "UPDATE ingest_cursors SET content_sha256=?",
                ("g" * 64,),
            )
        elif case == "malformed_frame_hash":
            candidate._connection.execute(
                "UPDATE ingest_cursors SET frame_sha256=?",
                ("g" * 64,),
            )
        else:
            candidate._connection.execute(
                "INSERT INTO ingest_cursors("
                "host_id,source_sequence,event_id,content_sha256,segment_id,"
                "segment_relative_path,frame_offset,frame_size,frame_sha256"
                ") SELECT ?,source_sequence,event_id,content_sha256,segment_id,"
                "segment_relative_path,frame_offset,frame_size,frame_sha256 "
                "FROM ingest_cursors",
                ("423e4567-e89b-42d3-a456-426614174000",),
            )
        candidate_ack = candidate_journal.snapshot()
        candidate_counts = _counts(candidate_path)
        assert candidate.status() == projection.ProjectionStatus(False, None)
        assert not candidate._healthy
        assert candidate_journal.snapshot() == candidate_ack
        assert _counts(candidate_path) == candidate_counts
        candidate.close()
        candidate_store.close()

    _interrupt_coordinator, interrupt_store, interrupt_journal = _system(
        tmp_path / "interrupt" / "evidence"
    )
    interrupt = projection.ProjectionStore.open(
        tmp_path / "interrupt" / "projection.sqlite3",
        evidence=interrupt_store,
        acknowledgements=interrupt_journal,
    )

    def interrupt_cursor(_connection: sqlite3.Connection) -> object:
        raise KeyboardInterrupt

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(projection, "_current_cursor", interrupt_cursor)
        with pytest.raises(KeyboardInterrupt):
            interrupt.status()
    assert interrupt._healthy
    interrupt.close()
    interrupt_store.close()


def test_projection_open_rejects_corruption_without_retired_ranges(
    tmp_path: Path,
) -> None:
    projection = _projection()
    coordinator, store, acknowledgements = _system(
        tmp_path / "ordinary" / "evidence"
    )
    projection_path = tmp_path / "ordinary" / "projection.sqlite3"
    cache = None
    try:
        ref = _accept(coordinator, boot_boundary(private_key(11)))
        _confirm(acknowledgements, ref)
        cache = projection.ProjectionStore.open(
            projection_path,
            evidence=store,
            acknowledgements=acknowledgements,
        )
        cache.apply(ref)
        cache.close()
        cache = None

        with sqlite3.connect(projection_path) as connection:
            connection.execute(
                "UPDATE events SET event_type='tampered' WHERE event_id=?",
                (ref.event_id,),
            )

        with pytest.raises(
            projection.ProjectionConflict,
            match="does not match authenticated prefix",
        ):
            projection.ProjectionStore.open(
                projection_path,
                evidence=store,
                acknowledgements=acknowledgements,
            )
    finally:
        if cache is not None:
            cache.close()
        acknowledgements.close()
        store.close(flush=False)


def test_projection_open_rejects_surviving_tamper_after_retention(
    tmp_path: Path,
) -> None:
    from tests.evidence.test_retention_unlink import _issued_case

    projection = _projection()
    case, capability = _issued_case(tmp_path / "retained")
    acknowledgements = case.store._ack_journal_owner
    assert type(acknowledgements) is AckJournal
    projection_path = tmp_path / "retained" / "projection.sqlite3"
    cache = None
    try:
        refs = tuple(
            record.ref
            for record in case.store.iter_authenticated_records()
        )
        cache = projection.ProjectionStore.open(
            projection_path,
            evidence=case.store,
            acknowledgements=acknowledgements,
        )
        for ref in refs:
            cache.apply(ref)
        case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        assert cache._connection is not None
        cache._connection.execute(
            "UPDATE events SET event_type='tampered' WHERE source_sequence=?",
            (projection._uint64(1),),
        )
        cache.close()
        cache = None

        with pytest.raises(
            projection.ProjectionConflict,
            match="authenticated surviving evidence",
        ):
            projection.ProjectionStore.open(
                projection_path,
                evidence=case.store,
                acknowledgements=acknowledgements,
            )
    finally:
        if cache is not None:
            cache.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)


def _retention_case_with_surviving_falco(
    path: Path,
    *,
    raw_hash: str,
) -> tuple[Any, object, AckJournal, tuple[EvidenceRef, ...]]:
    from tests.evidence.test_retention import (
        _proof_clock,
        _retention_proof_case,
    )

    path.parent.mkdir(parents=True, mode=0o700)
    path.parent.chmod(0o700)
    case = _retention_proof_case(path, acknowledge=True)
    verifier = case.store._bound_verifier
    assert type(verifier) is EnvelopeVerifier
    acceptance = AcceptanceCoordinator(
        verifier,
        case.store,
        _factory=service_module._COORDINATOR_FACTORY,
    )
    survivor = _accept(
        acceptance,
        envelope_value(
            private_key(11),
            sequence=4,
            event_type="falco_connect",
            normalized_fields=_falco_fields(raw_hash),
            source_payload_hash=raw_hash,
            container_id="a" * 64,
            container_start_time=NOW,
            release_id=release_id(f"sha256:{'b' * 64}", "d" * 64),
            inventory_revision=2**63,
        ),
    )
    case.coverage._apply_live_accepted(case.store, survivor, None)
    acknowledgements = case.store._ack_journal_owner
    assert type(acknowledgements) is AckJournal
    _confirm(acknowledgements, survivor)
    final_snapshot = case.store._freeze_retention_snapshot(
        _proof_clock(seconds=2),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    capability = case.store._authenticate_retention_tombstone(
        case.journal,
        final_snapshot,
        case.target_ref,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    refs = tuple(
        record.ref
        for record in case.store.iter_authenticated_records()
    )
    assert [ref.source_sequence for ref in refs] == [1, 2, 3, 4]
    return case, capability, acknowledgements, refs


def test_projection_open_promotes_surviving_duplicate_after_primary_retired(
    tmp_path: Path,
) -> None:
    projection = _projection()
    raw_hash = hashlib.sha256(b"retention proof routine").hexdigest()
    case, capability, acknowledgements, refs = (
        _retention_case_with_surviving_falco(
            tmp_path / "dedup-promotion" / "evidence",
            raw_hash=raw_hash,
        )
    )
    projection_path = (
        tmp_path / "dedup-promotion" / "projection.sqlite3"
    )
    cache = None
    reopened = None
    try:
        cache = projection.ProjectionStore.open(
            projection_path,
            evidence=case.store,
            acknowledgements=acknowledgements,
        )
        for ref in refs:
            cache.apply(ref)
        assert cache._connection is not None
        assert tuple(
            cache._connection.execute(
                "SELECT duplicate_of_event_id FROM events "
                "WHERE source_sequence=?",
                (projection._uint64(4),),
            ).fetchone()
        ) == (refs[1].event_id,)

        case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        cache.close()
        cache = None
        reopened = projection.ProjectionStore.open(
            projection_path,
            evidence=case.store,
            acknowledgements=acknowledgements,
        )

        assert reopened._connection is not None
        assert tuple(
            reopened._connection.execute(
                "SELECT duplicate_of_event_id FROM events "
                "WHERE source_sequence=?",
                (projection._uint64(4),),
            ).fetchone()
        ) == (None,)
        assert tuple(
            reopened._connection.execute(
                "SELECT primary_event_id,is_primary FROM projection_dedup "
                "WHERE event_id=?",
                (refs[3].event_id,),
            ).fetchone()
        ) == (refs[3].event_id, 1)
        assert reopened.status().healthy is True
    finally:
        if reopened is not None:
            reopened.close()
        if cache is not None:
            cache.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)


def test_projection_open_rebuilds_container_with_retired_first_event(
    tmp_path: Path,
) -> None:
    projection = _projection()
    raw_hash = hashlib.sha256(b"post-retention survivor").hexdigest()
    case, capability, acknowledgements, refs = (
        _retention_case_with_surviving_falco(
            tmp_path / "container-rebuild" / "evidence",
            raw_hash=raw_hash,
        )
    )
    projection_path = (
        tmp_path / "container-rebuild" / "projection.sqlite3"
    )
    cache = None
    reopened = None
    try:
        cache = projection.ProjectionStore.open(
            projection_path,
            evidence=case.store,
            acknowledgements=acknowledgements,
        )
        for ref in refs:
            cache.apply(ref)
        assert cache._connection is not None
        assert tuple(
            cache._connection.execute(
                "SELECT first_source_sequence,last_source_sequence "
                "FROM containers",
            ).fetchone()
        ) == (
            projection._uint64(2),
            projection._uint64(4),
        )

        case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        cache.close()
        cache = None
        reopened = projection.ProjectionStore.open(
            projection_path,
            evidence=case.store,
            acknowledgements=acknowledgements,
        )

        assert reopened._connection is not None
        assert tuple(
            reopened._connection.execute(
                "SELECT first_event_id,first_source_sequence,"
                "last_event_id,last_source_sequence FROM containers",
            ).fetchone()
        ) == (
            refs[3].event_id,
            projection._uint64(4),
            refs[3].event_id,
            projection._uint64(4),
        )
        assert reopened.status().healthy is True
    finally:
        if reopened is not None:
            reopened.close()
        if cache is not None:
            cache.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)


def test_projection_open_rejects_container_tamper_with_retired_first_event(
    tmp_path: Path,
) -> None:
    projection = _projection()
    raw_hash = hashlib.sha256(b"post-retention tamper survivor").hexdigest()
    case, capability, acknowledgements, refs = (
        _retention_case_with_surviving_falco(
            tmp_path / "container-tamper" / "evidence",
            raw_hash=raw_hash,
        )
    )
    projection_path = (
        tmp_path / "container-tamper" / "projection.sqlite3"
    )
    cache = None
    try:
        cache = projection.ProjectionStore.open(
            projection_path,
            evidence=case.store,
            acknowledgements=acknowledgements,
        )
        for ref in refs:
            cache.apply(ref)
        case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        assert cache._connection is not None
        cache._connection.execute(
            "UPDATE containers SET image_id=?",
            (f"sha256:{'c' * 64}",),
        )
        cache.close()
        cache = None

        with pytest.raises(
            projection.ProjectionConflict,
            match="authenticated surviving evidence",
        ):
            projection.ProjectionStore.open(
                projection_path,
                evidence=case.store,
                acknowledgements=acknowledgements,
            )
    finally:
        if cache is not None:
            cache.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)
