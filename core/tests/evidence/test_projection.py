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
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    SegmentStore,
    StoredEvidenceRecord,
)
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
