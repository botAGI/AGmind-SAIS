from __future__ import annotations

import hashlib
import importlib
import os
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from agmind_immune.canonicaljson import canonical_json, release_id
from agmind_immune.contracts import ObserverTrustRootV1
from agmind_immune.correlation.primitives import (
    SpecialUseRegistry,
    load_pinned_special_use_registry,
    special_use_registry_is_issued,
)
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    SegmentStore,
    StoredEvidenceRecord,
)
from agmind_immune.ingest import service as service_module
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
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


@pytest.fixture(autouse=True)
def _fixed_detector_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: "1" * 64)


def _system(
    path: Path,
) -> tuple[
    AcceptanceCoordinator,
    SegmentStore,
    AckJournal,
    CorrelationRequestJournal,
    SpecialUseRegistry,
]:
    path.parent.mkdir(parents=True, mode=0o700)
    path.parent.chmod(0o700)
    key = private_key(11)
    root = PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key))
    )
    chain = AnchoredPublicKeyChain.from_value(root, metadata_value(key))
    store = SegmentStore(path)
    coordinator = AcceptanceCoordinator.create_empty(EnvelopeVerifier(root, chain), store)
    acknowledgements = AckJournal.create_new(store)
    correlation_requests = CorrelationRequestJournal.create_new(store)
    registry = load_pinned_special_use_registry(
        Path(__file__).resolve().parents[3] / "contracts/v1/ipv4-special-use.csv"
    )
    return coordinator, store, acknowledgements, correlation_requests, registry


def _projection_authorities(
    store: SegmentStore,
) -> tuple[CorrelationRequestJournal, SpecialUseRegistry]:
    current = getattr(store, "_correlation_journal_owner", None)
    correlation_requests = (
        current
        if type(current) is CorrelationRequestJournal and current._is_bound_to(store)
        else CorrelationRequestJournal.create_new(store)
    )
    registry = load_pinned_special_use_registry(
        Path(__file__).resolve().parents[3] / "contracts/v1/ipv4-special-use.csv"
    )
    return correlation_requests, registry


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
    ("new", "v1", "v2", "unknown", "v2-missing-security"),
)
def test_public_projection_open_activates_new_v1_v2_and_rejects_unknown_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    projection = _projection()
    projection_v2 = importlib.import_module("agmind_immune.evidence.projection_v2")
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: "1" * 64)
    (
        coordinator,
        store,
        acknowledgements,
        correlation_requests,
        registry,
    ) = _system(tmp_path / case / "evidence")
    first = _accept(coordinator, boot_boundary(private_key(11)))
    _confirm(acknowledgements, first)
    path = tmp_path / case / "projection.sqlite3"

    if case == "v1":
        with sqlite3.connect(path, isolation_level=None) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            projection._create_v1_schema(connection)
        path.chmod(0o600)
    elif case in {"v2", "v2-missing-security"}:
        bootstrap = projection.ProjectionStore.open(
            path,
            evidence=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation_requests,
            registry=registry,
        )
        bootstrap.close()
        second = _accept(
            coordinator,
            envelope_value(
                private_key(11),
                sequence=2,
                normalized_fields={"kind": "must-not-backfill-on-v2-open"},
            ),
        )
        _confirm(acknowledgements, second)
        if case == "v2-missing-security":
            with sqlite3.connect(path, isolation_level=None) as tampered:
                tampered.execute(
                    "DELETE FROM projection_dedup WHERE event_id=?",
                    (first.event_id,),
                )
    elif case == "unknown":
        path.write_bytes(b"")
        path.chmod(0o600)

    try:
        if case in {"unknown", "v2-missing-security"}:
            with pytest.raises(projection.ProjectionConflict):
                projection.ProjectionStore.open(
                    path,
                    evidence=store,
                    acknowledgements=acknowledgements,
                    correlation_requests=correlation_requests,
                    registry=registry,
                )
            return
        cache = projection.ProjectionStore.open(
            path,
            evidence=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation_requests,
            registry=registry,
        )
        assert cache.status().cursor is not None
        assert cache.status().cursor.source_sequence == first.source_sequence
        with sqlite3.connect(path) as observed:
            assert dict(observed.execute("SELECT key,value FROM schema_meta")) == (
                projection_v2._SCHEMA_META_V2
            )
        if case == "new":
            with pytest.raises(projection.ProjectionAuthorityError):
                cache.apply(object())  # type: ignore[arg-type]
            assert cache.status().healthy is True
            cache._healthy = False
            assert (
                cache._is_bound_to(
                    store,
                    acknowledgements,
                    correlation_requests,
                    registry,
                )
                is False
            )
            cache._healthy = True
        cache.close()
        assert acknowledgements.snapshot().healthy is True
        assert correlation_requests._is_bound_to(store) is True
        assert store.status().healthy is True
        assert special_use_registry_is_issued(registry) is True
    finally:
        correlation_requests.close()
        acknowledgements.close()
        store.close()


def test_public_rebuild_advances_an_exact_empty_v2_to_confirmed_evidence(
    tmp_path: Path,
) -> None:
    projection = _projection()
    coordinator, store, acknowledgements, correlation, registry = _system(
        tmp_path / "empty-v2-rebuild" / "evidence"
    )
    projection_path = tmp_path / "empty-v2-rebuild" / "projection.sqlite3"
    cache = None
    reopened = None
    try:
        cache = projection.ProjectionStore.open(
            projection_path,
            evidence=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation,
            registry=registry,
        )
        assert cache.status() == projection.ProjectionStatus(True, None)
        cache.close()
        cache = None

        ref = _accept(coordinator, boot_boundary(private_key(11)))
        _confirm(acknowledgements, ref)
        cache = projection.ProjectionStore.open(
            projection_path,
            evidence=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation,
            registry=registry,
        )
        assert cache.status() == projection.ProjectionStatus(True, None)

        report = cache.rebuild()

        assert report.cursor is not None
        assert report.cursor.source_sequence == ref.source_sequence
        assert report.source_record_count == 1
        cache.close()
        cache = None
        reopened = projection.ProjectionStore.open(
            projection_path,
            evidence=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation,
            registry=registry,
        )
        status = reopened.status()
        assert status.healthy is True
        assert status.cursor is not None
        assert status.cursor.source_sequence == ref.source_sequence
    finally:
        if reopened is not None:
            reopened.close()
        if cache is not None:
            cache.close()
        correlation.close()
        acknowledgements.close()
        store.close(flush=False)


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
    coordinator, store, journal, correlation, registry = _system(tmp_path / case / "evidence")
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
        # V2 open replays the confirmed ACK prefix, so confirm only the boot
        # boundary before open and drive the gap-signed advance live.
        _confirm(journal, first)
        cache = projection.ProjectionStore.open(
            tmp_path / case / "projection.sqlite3",
            evidence=store,
            acknowledgements=journal,
            correlation_requests=correlation,
            registry=registry,
        )
        opened = cache.status().cursor
        assert opened is not None
        assert opened.source_sequence == first.source_sequence
        _confirm(journal, fourth, gap)
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
        correlation_requests=correlation,
        registry=registry,
    )
    if case == "unconfirmed":
        with pytest.raises(projection.ProjectionAuthorityError):
            cache.apply(second)
    elif case == "non_next":
        # Open-time replay already consumed the confirmed prefix; the cursor
        # sits at the confirmed terminal, so non-next must be driven by
        # confirming further records after open and skipping one.
        opened = cache.status().cursor
        assert opened is not None
        assert opened.source_sequence == first.source_sequence
        third = _accept(
            coordinator,
            envelope_value(
                key,
                sequence=3,
                boot_id=BOOT_A,
                normalized_fields={"kind": "three"},
            ),
        )
        _confirm(journal, second, third)
        with pytest.raises(
            projection.ProjectionAuthorityError,
            match="not the next authenticated record",
        ):
            cache.apply(third)
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
    coordinator, store, journal, correlation, registry = _system(
        tmp_path / failure_step / "evidence"
    )
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
        # V2 validates live coverage through the closed historical grammar, so
        # the fixture must be an exact grammar form (counted Falco queue drop).
        second_value = envelope_value(
            key,
            sequence=2,
            event_type="coverage",
            normalized_fields={
                "component": "falco-adapter",
                "kind": "falco_queue_drop",
                "severity": "CRITICAL",
                "opened_at": NOW,
                "dropped_count": 1,
                "reason_code": "routine_capacity_exceeded",
            },
            coverage_flags=["falco_queue_drop"],
        )
    second = _accept(coordinator, second_value)
    # Confirm only the boot boundary before open: V2 open replays the confirmed
    # ACK prefix, so a record confirmed before open would be consumed by replay
    # and _apply_prepared (with its step hooks) would never run for it.
    _confirm(journal, first)
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
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
        step_hook=hook,
    )
    opened = cache.status().cursor
    assert opened is not None
    assert opened.source_sequence == first.source_sequence
    # The target record is confirmed only after open so it is applied live.
    _confirm(journal, second)
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
    coordinator, store, journal, correlation, registry = _system(tmp_path / case / "evidence")
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
        # V2 replay and live apply both validate coverage through the closed
        # historical grammar, so the fixture must be an exact grammar form.
        fields = {
            "component": "falco-adapter",
            "kind": "falco_queue_drop",
            "severity": "CRITICAL",
            "opened_at": NOW,
            "dropped_count": 1,
            "reason_code": "routine_capacity_exceeded",
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
                        coverage_flags=["falco_queue_drop"],
                    ),
                )
            )
    # Confirm only the first record before open; V2 open replays the confirmed
    # prefix, so the deduplicated records are confirmed after open and applied
    # live through the same _apply_prepared path V1 exercised.
    _confirm(journal, refs[0])
    cache = projection.ProjectionStore.open(
        tmp_path / case / "projection.sqlite3",
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
    )
    for ref in refs[1:]:
        _confirm(journal, ref)
        cache.apply(ref)
    with sqlite3.connect(cache.path) as connection:
        reduced_table = "network_observations" if case == "falco" else "coverage_intervals"
        expected = 2 if case == "coverage_changed" else 1
        assert connection.execute(f"SELECT count(*) FROM {reduced_table}").fetchone() == (expected,)
        assert connection.execute("SELECT count(*) FROM events").fetchone() == (3,)
    cache.close()
    store.close()


def test_projection_status_is_read_only_and_fail_closed(tmp_path: Path) -> None:
    projection = _projection()
    coordinator, store, journal, correlation, registry = _system(tmp_path / "healthy" / "evidence")
    path = tmp_path / "healthy" / "projection.sqlite3"
    cache = projection.ProjectionStore.open(
        path,
        evidence=store,
        acknowledgements=journal,
        correlation_requests=correlation,
        registry=registry,
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

    # V2 keeps its owner connection for the whole facade lifetime; the
    # fail-closed contract on a released connection is exercised through
    # close(), which detaches the owner entirely.
    cache.close()
    assert cache.status() == projection.ProjectionStatus(False, None)
    store.close()

    (
        _latched_coordinator,
        latched_store,
        latched_journal,
        latched_correlation,
        latched_registry,
    ) = _system(tmp_path / "latched" / "evidence")
    latched_path = tmp_path / "latched" / "projection.sqlite3"
    latched = projection.ProjectionStore.open(
        latched_path,
        evidence=latched_store,
        acknowledgements=latched_journal,
        correlation_requests=latched_correlation,
        registry=latched_registry,
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
        (
            coordinator,
            candidate_store,
            candidate_journal,
            candidate_correlation,
            candidate_registry,
        ) = _system(tmp_path / case / "evidence")
        candidate_path = tmp_path / case / "projection.sqlite3"
        candidate = projection.ProjectionStore.open(
            candidate_path,
            evidence=candidate_store,
            acknowledgements=candidate_journal,
            correlation_requests=candidate_correlation,
            registry=candidate_registry,
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

    (
        _interrupt_coordinator,
        interrupt_store,
        interrupt_journal,
        interrupt_correlation,
        interrupt_registry,
    ) = _system(tmp_path / "interrupt" / "evidence")
    interrupt = projection.ProjectionStore.open(
        tmp_path / "interrupt" / "projection.sqlite3",
        evidence=interrupt_store,
        acknowledgements=interrupt_journal,
        correlation_requests=interrupt_correlation,
        registry=interrupt_registry,
    )

    def interrupt_cursor(_connection: sqlite3.Connection) -> object:
        raise KeyboardInterrupt

    projection_v2 = importlib.import_module("agmind_immune.evidence.projection_v2")
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(projection_v2, "_current_v2_cursor", interrupt_cursor)
        with pytest.raises(KeyboardInterrupt):
            interrupt.status()
    assert interrupt._healthy
    interrupt.close()
    interrupt_store.close()


@pytest.mark.parametrize(
    "case",
    [
        "monotonic_extension",
        "frozen_pending_replacement",
        "rollback_after_rename",
        "source_prefix_mutation",
    ],
)
def test_rebuild_revalidates_frozen_ack_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    """V2 rebuild freezes the ACK and source authorities before computing the
    replay and revalidates the frozen facts before staging; any authority
    mutation in between must fail the rebuild closed and preserve the old
    projection (ADR 0006). The mutation is injected at the compute seam, which
    runs outside the freeze/revalidate gates.
    """
    projection = _projection()
    projection_v2 = importlib.import_module("agmind_immune.evidence.projection_v2")
    coordinator, store, acknowledgements, correlation, registry = _system(
        tmp_path / case / "evidence"
    )
    key = private_key(11)
    refs = (
        _accept(coordinator, boot_boundary(key)),
        _accept(
            coordinator,
            envelope_value(
                key,
                sequence=2,
                boot_id=BOOT_A,
                normalized_fields={"kind": "two"},
            ),
        ),
        _accept(
            coordinator,
            envelope_value(
                key,
                sequence=3,
                boot_id=BOOT_A,
                normalized_fields={"kind": "three"},
            ),
        ),
    )
    _confirm(acknowledgements, refs[0])
    acknowledgements.record_pending(refs[1])

    cache = projection.ProjectionStore.open(
        tmp_path / case / "projection.sqlite3",
        evidence=store,
        acknowledgements=acknowledgements,
        correlation_requests=correlation,
        registry=registry,
    )

    def mutate_authority() -> None:
        if case == "monotonic_extension":
            acknowledgements.record_confirmed(refs[1])
        elif case == "frozen_pending_replacement":
            acknowledgements.record_confirmed(refs[1])
            acknowledgements.record_pending(refs[2])
        elif case == "rollback_after_rename":
            replacement = tmp_path / case / "ack-journal.replacement"
            replacement.write_bytes(b"")
            replacement.chmod(0o600)
            journal_path = tmp_path / case / "evidence" / "ack-journal.agf"
            assert journal_path.is_file()
            os.replace(replacement, journal_path)
        else:
            assert case == "source_prefix_mutation"
            _accept(
                coordinator,
                envelope_value(
                    key,
                    sequence=4,
                    boot_id=BOOT_A,
                    normalized_fields={"kind": "four"},
                ),
            )

    mutated = False
    original_compute = projection_v2._compute_replay

    def mutating_compute(snapshot: object) -> object:
        nonlocal mutated
        if not mutated:
            mutated = True
            mutate_authority()
        return original_compute(snapshot)

    # Installed after open so the open-time replay runs unmutated.
    monkeypatch.setattr(projection_v2, "_compute_replay", mutating_compute)
    try:
        with pytest.raises(projection.ProjectionAuthorityError):
            cache.rebuild()
        assert mutated is True
        status = cache.status()
        assert status.healthy is True
        assert status.cursor is not None
        assert status.cursor.source_sequence == refs[0].source_sequence
        if case == "monotonic_extension":
            # The frozen boundary is rejected mid-flight; the monotonic ACK
            # extension is honored only by the next rebuild, which freezes the
            # new confirmed terminal.
            report = cache.rebuild()
            assert report.cursor is not None
            assert report.cursor.source_sequence == refs[1].source_sequence
            assert report.source_record_count == 2
        elif case == "rollback_after_rename":
            # The failed revalidation latched the rolled-back journal, so its
            # snapshot fails closed.
            assert acknowledgements.snapshot().healthy is False
    finally:
        cache.close()
        correlation.close()
        acknowledgements.close()
        store.close(flush=False)


def test_projection_open_rejects_corruption_without_retired_ranges(
    tmp_path: Path,
) -> None:
    projection = _projection()
    coordinator, store, acknowledgements, correlation, registry = _system(
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
            correlation_requests=correlation,
            registry=registry,
        )
        cache.apply(ref)
        cache.close()
        cache = None

        with sqlite3.connect(projection_path) as connection:
            connection.execute(
                "UPDATE events SET event_type='tampered' WHERE event_id=?",
                (ref.event_id,),
            )
        # Close the tampering connection so its sidecars disappear; otherwise
        # the image classifier fails closed on the sidecars before the prefix
        # validator can name the tamper.
        connection.close()

        with pytest.raises(
            projection.ProjectionConflict,
            match="Projection V2 persisted event facts changed",
        ):
            projection.ProjectionStore.open(
                projection_path,
                evidence=store,
                acknowledgements=acknowledgements,
                correlation_requests=correlation,
                registry=registry,
            )
    finally:
        if cache is not None:
            cache.close()
        correlation.close()
        acknowledgements.close()
        store.close(flush=False)


def test_projection_open_rejects_surviving_tamper_after_retention(
    tmp_path: Path,
) -> None:
    """After authenticated retention retires a range, tampering a SURVIVING
    event row must still be rejected at the next open. V2 requires the
    retention completion to be consumed by a rebuild before reopen, and its
    open-time prefix validation names the tampered persisted event."""
    projection = _projection()
    raw_hash = hashlib.sha256(b"post-retention surviving tamper").hexdigest()
    (
        case,
        capability,
        acknowledgements,
        correlation_requests,
        registry,
        refs,
        cache,
    ) = _retention_case_with_surviving_falco(
        tmp_path / "retained" / "evidence",
        raw_hash=raw_hash,
    )
    projection_path = tmp_path / "retained" / "projection.sqlite3"
    try:
        completion = case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        cache._rebuild_after_authenticated_retention(
            completion,
            _factory=projection._RETENTION_REBUILD_FACTORY,
        )
        case.store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        _confirm(acknowledgements, refs[3])
        cache.apply(refs[3])
        assert cache._connection is not None
        cache._connection.execute(
            "UPDATE events SET event_type='tampered' WHERE source_sequence=?",
            (projection._uint64(1),),
        )
        cache.close()
        cache = None

        with pytest.raises(
            projection.ProjectionConflict,
            match="Projection V2 persisted event facts changed",
        ):
            projection.ProjectionStore.open(
                projection_path,
                evidence=case.store,
                acknowledgements=acknowledgements,
                correlation_requests=correlation_requests,
                registry=registry,
            )
    finally:
        if cache is not None:
            cache.close()
        correlation_requests.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)


def _retention_case_with_surviving_falco(
    path: Path,
    *,
    raw_hash: str,
) -> tuple[
    Any,
    object,
    AckJournal,
    CorrelationRequestJournal,
    SpecialUseRegistry,
    tuple[EvidenceRef, ...],
    Any,
]:
    from tests.evidence.test_retention import (
        _proof_clock,
        _retention_proof_case,
    )

    projection = _projection()
    projection_path = path.parent / "projection.sqlite3"
    acknowledgements: AckJournal | None = None
    correlation_requests: CorrelationRequestJournal | None = None
    registry: SpecialUseRegistry | None = None
    cache: Any = None

    def open_projection_before_retention(store: SegmentStore) -> None:
        nonlocal acknowledgements, correlation_requests, registry, cache
        acknowledgements = AckJournal.create_new(store)
        correlation_requests, registry = _projection_authorities(store)
        initial_refs = tuple(record.ref for record in store.iter_authenticated_records())
        for ref in initial_refs:
            acknowledgements.record_pending(ref)
            acknowledgements.record_confirmed(ref)
        cache = projection.ProjectionStore.open(
            projection_path,
            evidence=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation_requests,
            registry=registry,
        )
        for ref in initial_refs:
            cache.apply(ref)

    path.parent.mkdir(parents=True, mode=0o700)
    path.parent.chmod(0o700)
    case = _retention_proof_case(
        path,
        acknowledge=False,
        before_retention_prepare=open_projection_before_retention,
    )
    assert type(acknowledgements) is AckJournal
    assert type(correlation_requests) is CorrelationRequestJournal
    assert type(registry) is SpecialUseRegistry
    assert cache is not None
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
    _confirm(acknowledgements, case.target_ref)
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
    refs = tuple(record.ref for record in case.store.iter_authenticated_records())
    assert [ref.source_sequence for ref in refs] == [1, 2, 3, 4]
    return (
        case,
        capability,
        acknowledgements,
        correlation_requests,
        registry,
        refs,
        cache,
    )


@pytest.mark.parametrize(
    "failure_seam",
    ["ack_revalidation", "pre_validation", "post_validation"],
)
def test_retention_rebuild_failure_preserves_last_good_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_seam: str,
) -> None:
    projection = _projection()
    raw_hash = hashlib.sha256(f"retention rebuild {failure_seam}".encode()).hexdigest()
    (
        case,
        capability,
        acknowledgements,
        correlation_requests,
        _registry,
        refs,
        cache,
    ) = _retention_case_with_surviving_falco(
        tmp_path / failure_seam / "evidence",
        raw_hash=raw_hash,
    )
    try:
        status = cache.status()
        assert status.cursor is not None
        assert status.cursor.source_sequence == refs[1].source_sequence
        before_hash = cache.snapshot_hash()
        completion = case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        if failure_seam == "ack_revalidation":

            def fail_ack_revalidation(_snapshot: object) -> None:
                raise projection.ProjectionAuthorityError("injected ACK revalidation failure")

            monkeypatch.setattr(
                acknowledgements,
                "_revalidate_replay_ack_locked",
                fail_ack_revalidation,
            )
        else:
            original_validation = case.store._validate_authenticated_retention_completion
            validation_calls = 0

            def fail_validation(candidate: object, binding: object) -> Any:
                nonlocal validation_calls
                validation_calls += 1
                target_call = 1 if failure_seam == "pre_validation" else 2
                if validation_calls == target_call:
                    raise segments_module.EvidenceSealError(f"injected {failure_seam}")
                return original_validation(candidate, binding)

            monkeypatch.setattr(
                case.store,
                "_validate_authenticated_retention_completion",
                fail_validation,
            )
        with pytest.raises(projection.ProjectionAuthorityError):
            cache._rebuild_after_authenticated_retention(
                completion,
                _factory=projection._RETENTION_REBUILD_FACTORY,
            )
        status = cache.status()
        assert status.healthy is True
        assert status.cursor is not None
        assert status.cursor.source_sequence == refs[1].source_sequence
        assert cache.snapshot_hash() == before_hash
    finally:
        cache.close()
        correlation_requests.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)


def test_authenticated_retention_rebuild_promotes_surviving_duplicate(
    tmp_path: Path,
) -> None:
    projection = _projection()
    raw_hash = hashlib.sha256(b"retention proof routine").hexdigest()
    (
        case,
        capability,
        acknowledgements,
        correlation_requests,
        registry,
        refs,
        cache,
    ) = _retention_case_with_surviving_falco(
        tmp_path / "dedup-promotion" / "evidence",
        raw_hash=raw_hash,
    )
    projection_path = tmp_path / "dedup-promotion" / "projection.sqlite3"
    reopened = None
    try:
        completion = case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        cache._rebuild_after_authenticated_retention(
            completion,
            _factory=projection._RETENTION_REBUILD_FACTORY,
        )
        case.store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        _confirm(acknowledgements, refs[3])
        cache.apply(refs[3])
        cache.close()
        cache = None
        reopened = projection.ProjectionStore.open(
            projection_path,
            evidence=case.store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation_requests,
            registry=registry,
        )

        assert reopened._connection is not None
        assert tuple(
            reopened._connection.execute(
                "SELECT duplicate_of_event_id FROM events WHERE source_sequence=?",
                (projection._uint64(4),),
            ).fetchone()
        ) == (None,)
        assert tuple(
            reopened._connection.execute(
                "SELECT primary_event_id,is_primary FROM projection_dedup WHERE event_id=?",
                (refs[3].event_id,),
            ).fetchone()
        ) == (refs[3].event_id, 1)
        assert reopened.status().healthy is True
    finally:
        if reopened is not None:
            reopened.close()
        if cache is not None:
            cache.close()
        correlation_requests.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)


def test_authenticated_retention_rebuilds_container_with_retired_first_event(
    tmp_path: Path,
) -> None:
    projection = _projection()
    raw_hash = hashlib.sha256(b"post-retention survivor").hexdigest()
    (
        case,
        capability,
        acknowledgements,
        correlation_requests,
        registry,
        refs,
        cache,
    ) = _retention_case_with_surviving_falco(
        tmp_path / "container-rebuild" / "evidence",
        raw_hash=raw_hash,
    )
    projection_path = tmp_path / "container-rebuild" / "projection.sqlite3"
    reopened = None
    try:
        assert cache._connection is not None
        assert tuple(
            cache._connection.execute(
                "SELECT first_source_sequence,last_source_sequence FROM containers",
            ).fetchone()
        ) == (
            projection._uint64(2),
            projection._uint64(2),
        )

        completion = case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        cache._rebuild_after_authenticated_retention(
            completion,
            _factory=projection._RETENTION_REBUILD_FACTORY,
        )
        case.store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        _confirm(acknowledgements, refs[3])
        cache.apply(refs[3])
        cache.close()
        cache = None
        reopened = projection.ProjectionStore.open(
            projection_path,
            evidence=case.store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation_requests,
            registry=registry,
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
        correlation_requests.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)


def test_projection_open_rejects_container_tamper_with_retired_first_event(
    tmp_path: Path,
) -> None:
    projection = _projection()
    raw_hash = hashlib.sha256(b"post-retention tamper survivor").hexdigest()
    (
        case,
        capability,
        acknowledgements,
        correlation_requests,
        registry,
        _refs,
        cache,
    ) = _retention_case_with_surviving_falco(
        tmp_path / "container-tamper" / "evidence",
        raw_hash=raw_hash,
    )
    projection_path = tmp_path / "container-tamper" / "projection.sqlite3"
    try:
        completion = case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        cache._rebuild_after_authenticated_retention(
            completion,
            _factory=projection._RETENTION_REBUILD_FACTORY,
        )
        case.store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        _confirm(acknowledgements, _refs[3])
        cache.apply(_refs[3])
        assert cache._connection is not None
        cache._connection.execute(
            "UPDATE containers SET image_id=?",
            (f"sha256:{'c' * 64}",),
        )
        cache.close()
        cache = None

        with pytest.raises(
            projection.ProjectionConflict,
            match="persisted container closure changed",
        ):
            projection.ProjectionStore.open(
                projection_path,
                evidence=case.store,
                acknowledgements=acknowledgements,
                correlation_requests=correlation_requests,
                registry=registry,
            )
    finally:
        if cache is not None:
            cache.close()
        correlation_requests.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)
