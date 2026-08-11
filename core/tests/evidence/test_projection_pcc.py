from __future__ import annotations

import copy
import hashlib
import importlib
import os
import pickle
import sqlite3
from dataclasses import replace
from pathlib import Path
from threading import Event, Thread
from typing import Any, cast

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import PCCCorrelationSnapshotV1
from agmind_immune.correlation.primitives import (
    load_pinned_special_use_registry,
    special_use_registry_is_issued,
)
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.projection import ProjectionAuthorityError
from agmind_immune.evidence.segments import EvidenceRef, EvidenceSealError
from agmind_immune.incidents.models import ContainmentCandidateV1
from agmind_immune.ingest.ack_journal import (
    AckIdentity,
    AckJournal,
    AckJournalSnapshot,
)
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import AuthenticatedPCCInput
from tests.correlation.test_authority import _FakeFilesystem
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
    trigger_ref = store._bound_verifier.accepted_ref(proof.snapshot.trigger.source_sequence)
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
            load_pinned_special_use_registry(_REGISTRY_PATH) if registry is None else registry
        ),
        step_hook=step_hook,
    )
    return owner, connection


def _durable_unpublished_case(
    subject: Any,
    path: Path,
) -> tuple[Any, sqlite3.Connection, Any, EvidenceRef]:
    coordinator, proof = _accepted_complete(path, ttl_seconds=120)
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    _complete_journal(journal, proof)
    owner, connection = _owner(subject, coordinator, journal)
    records = tuple(store.iter_authenticated_records())
    return owner, connection, store, records[-1].ref


def _durable_retention_case(
    subject: Any,
    path: Path,
) -> dict[str, Any]:
    retention = importlib.import_module("tests.evidence.test_retention")
    key, acceptance, store, coverage = retention._live_store_with_active_routine(path)
    journal = CorrelationRequestJournal.create_new(store)
    acknowledgements = store._ack_journal_owner
    assert type(acknowledgements) is AckJournal
    connection = subject._v2_connection_for_test()
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    selected_snapshot = store._freeze_retention_snapshot(
        retention._proof_clock(),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    decision = retention.select_retention(
        selected_snapshot,
        request_id=retention.REQUEST_ID,
    )
    request = decision.request
    assert request is not None
    retention_journal = retention.retention_module._open_retention_state_journal(store)
    retention_journal.prepare_publication(decision)
    target_item = retention._item(
        envelope_value(
            key,
            sequence=3,
            event_type="retention_tombstone",
            normalized_fields=request.model_dump(mode="python"),
        )
    )
    target_ref = acceptance.accept(target_item)
    coverage._apply_live_accepted(store, target_ref, None)
    acknowledgements.record_pending(target_ref)
    acknowledgements.record_confirmed(target_ref)
    target = retention.retention_module.RetentionTargetV1(
        sequence=target_item.sequence,
        event_id=target_item.event_id,
        content_sha256=target_item.content_sha256,
    )
    retention_journal.bind_target(target)
    retention_journal.advance_evidence_appended(target)
    final_snapshot = store._freeze_retention_snapshot(
        retention._proof_clock(seconds=1),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    tombstone = store._authenticate_retention_tombstone(
        retention_journal,
        final_snapshot,
        target_ref,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    completion = store._execute_authenticated_retention_unlink(
        tombstone,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    surviving = tuple(store.iter_authenticated_records(through=target_ref.source_sequence))
    return {
        "retention": retention,
        "store": store,
        "coverage": coverage,
        "owner": owner,
        "connection": connection,
        "completion": completion,
        "target_ref": target_ref,
        "surviving": surviving,
    }


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
    raw_sha256 = hashlib.sha256(f"unpublished-history-{trigger_sequence}".encode()).hexdigest()
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
    authority = importlib.import_module("agmind_immune.correlation.authority")
    del records, foreign_active
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    return pcc._freeze_replay_pcc_seed(
        proof,
        detector_bundle_sha256=_DETECTOR_HASH,
        registry=registry,
        registry_facts_canonical=authority._registry_facts_canonical(
            authority._registry_facts(registry)
        ),
    )


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
            ack_snapshot = acknowledgements._capture_replay_ack_locked(terminal.source_sequence)
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
                + Path("core/agmind_immune/evidence/schema.sql").read_bytes()
            ),
            base_projection_generation=1,
            publish_generation=2,
        )
    except BaseException:
        if source_snapshot is not None:
            segments_module._close_replay_source_snapshot(source_snapshot)
        if ack_snapshot is not None:
            importlib.import_module("agmind_immune.ingest.ack_journal")._close_replay_ack_snapshot(
                ack_snapshot
            )
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
    importlib.import_module("agmind_immune.ingest.ack_journal")._close_replay_ack_snapshot(
        resources["ack_snapshot"]
    )
    resources["acknowledgements"].close()
    resources["store"].close()


def _hermetic_detector_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route the fixed detector-bundle walk through hermetic fake nodes.

    The pytest container ships no /etc/falco/rules.d/agmind-pcc.yaml, so the
    loader is rebuilt around the authority module's own _Filesystem seam: the
    production O_NOFOLLOW walk still executes in full, only the nodes are
    fakes carrying the pinned root-owned facts.
    """
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        authority._detector_bundle_loader(
            _FakeFilesystem(b"- rule: hermetic pytest detector bundle\n")
        ),
    )


def test_unpublished_replay_supports_empty_confirmed_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches requiring a non-empty terminal instead of the confirmed prefix."""
    subject = _subject()
    _hermetic_detector_bundle(monkeypatch)
    coordinator = _coordinator(tmp_path / "evidence", private_key(11))
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    acknowledgements = AckJournal.create_new(store)

    owner, connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=None,
    )
    try:
        assert report.cursor is None
        assert report.applied_count == 0
        assert report.prefix_sha256 == (
            "d4fb5609251c092ebf1c26ac0b50e55ce12e6c4cd0e054b2c84d6cf2dc809e7f"
        )
        assert report.prefix_sha256 == owner.snapshot_hash()
        assert owner._generation == 2
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM ingest_cursors").fetchone()[0] == 0
    finally:
        owner.close()


def test_unpublished_replay_caps_at_lagged_confirmed_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches projecting the acceptance head or authenticated pending ACK."""
    subject = _subject()
    _hermetic_detector_bundle(monkeypatch)
    coordinator = _coordinator(tmp_path / "evidence", private_key(11))
    _accept(coordinator, boot_boundary(private_key(11)))
    pending_ref = cast(
        EvidenceRef,
        _accept(coordinator, envelope_value(private_key(11), sequence=2)),
    )
    store = coordinator.segment_store
    records = tuple(store.iter_authenticated_records())
    assert len(records) == 2
    journal = CorrelationRequestJournal.create_new(store)
    acknowledgements = AckJournal.create_new(store)
    _confirm_ack(acknowledgements, records[0].ref)
    acknowledgements.record_pending(pending_ref)

    owner, connection, report = subject._v2_unpublished_projection_from_prefix_for_test(
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
        through=records[0].ref,
    )
    try:
        assert report.cursor is not None
        assert report.cursor.source_sequence == 1
        assert report.applied_count == 1
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_id=?",
                (pending_ref.event_id,),
            ).fetchone()[0]
            == 0
        )
    finally:
        owner.close()


def test_unpublished_replay_requires_exact_retention_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches replacing the one-store completion proof with a pending Boolean."""
    subject = _subject()
    _hermetic_detector_bundle(monkeypatch)
    sparse_coordinator = _coordinator(
        tmp_path / "sparse-without-scope",
        private_key(11),
    )
    _accept(sparse_coordinator, boot_boundary(private_key(11)))
    sparse_snapshot, sparse_resources = _capture_compute_input(
        subject,
        sparse_coordinator,
        (),
    )
    try:
        sparse_source = replace(
            sparse_snapshot.source,
            retained_ranges=((1, 1),),
        )
        with pytest.raises(ProjectionAuthorityError):
            subject._validate_replay_snapshot_shape_v2(
                replace(sparse_snapshot, source=sparse_source)
            )
    finally:
        _close_compute_input(sparse_resources)

    retention = importlib.import_module("tests.evidence.test_retention")
    key, acceptance, store, coverage = retention._live_store_with_active_routine(
        tmp_path / "evidence"
    )
    journal = CorrelationRequestJournal.create_new(store)
    acknowledgements = store._ack_journal_owner
    assert type(acknowledgements) is AckJournal
    connection = subject._v2_connection_for_test()
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    selected_snapshot = store._freeze_retention_snapshot(
        retention._proof_clock(),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    decision = retention.select_retention(
        selected_snapshot,
        request_id=retention.REQUEST_ID,
    )
    request = decision.request
    assert request is not None
    retention_journal = retention.retention_module._open_retention_state_journal(store)
    retention_journal.prepare_publication(decision)
    target_item = retention._item(
        envelope_value(
            key,
            sequence=3,
            event_type="retention_tombstone",
            normalized_fields=request.model_dump(mode="python"),
        )
    )
    target_ref = acceptance.accept(target_item)
    coverage._apply_live_accepted(store, target_ref, None)
    acknowledgements.record_pending(target_ref)
    acknowledgements.record_confirmed(target_ref)
    target = retention.retention_module.RetentionTargetV1(
        sequence=target_item.sequence,
        event_id=target_item.event_id,
        content_sha256=target_item.content_sha256,
    )
    retention_journal.bind_target(target)
    retention_journal.advance_evidence_appended(target)
    final_snapshot = store._freeze_retention_snapshot(
        retention._proof_clock(seconds=1),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    tombstone = store._authenticate_retention_tombstone(
        retention_journal,
        final_snapshot,
        target_ref,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    completion = store._execute_authenticated_retention_unlink(
        tombstone,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    surviving = tuple(store.iter_authenticated_records(through=target_ref.source_sequence))
    assert store.status().retention_pending is True
    assert store._authenticated_retired_ranges
    wrong_terminal = surviving[0].ref
    assert wrong_terminal != target_ref

    try:
        with pytest.raises(EvidenceSealError):
            store._capture_authenticated_retention_replay_scope(
                completion,
                wrong_terminal,
            )

        from tests.evidence.test_retention_unlink import _completed_case

        foreign_case, foreign_completion = _completed_case(tmp_path / "foreign-evidence")
        try:
            with pytest.raises(EvidenceSealError):
                store._capture_authenticated_retention_replay_scope(
                    foreign_completion,
                    target_ref,
                )
        finally:
            foreign_case.coverage.close()
            foreign_case.store.close(flush=False)

        probe_scope = store._capture_authenticated_retention_replay_scope(
            completion,
            target_ref,
        )
        writer_started = Event()
        writer_finished = Event()
        writer_errors: list[BaseException] = []

        def bounded_retention_writer() -> None:
            writer_started.set()
            try:
                store._finalize_authenticated_retention_completion(
                    completion,
                    _factory=object(),
                )
            except BaseException as error:  # noqa: BLE001 - asserted below
                writer_errors.append(error)
            finally:
                writer_finished.set()

        with (
            store._authenticated_retention_replay_scope_gate(
                probe_scope,
                target_ref,
            ),
            store._replay_source_snapshot_gate(),
        ):
            writer = Thread(target=bounded_retention_writer)
            writer.start()
            assert writer_started.wait(5)
            assert writer_finished.is_set() is False
        writer.join(5)
        assert writer.is_alive() is False
        assert len(writer_errors) == 1
        assert isinstance(writer_errors[0], TypeError)

        store._release_authenticated_retention_replay_scope(cast(Any, True))
        with pytest.raises(EvidenceSealError):
            store._capture_authenticated_retention_replay_scope(
                completion,
                target_ref,
            )
        store._release_authenticated_retention_replay_scope(probe_scope)
        with (
            pytest.raises(EvidenceSealError),
            store._authenticated_retention_replay_scope_gate(
                probe_scope,
                target_ref,
            ),
        ):
            pass
        retry_scope = store._capture_authenticated_retention_replay_scope(
            completion,
            target_ref,
        )
        store._release_authenticated_retention_replay_scope(retry_scope)

        with pytest.raises(ProjectionAuthorityError):
            owner._replay_unpublished_prefix(
                target_ref,
                _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
            )
        assert owner._generation == 1
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 0

        owner._register_replay_status_barrier_for_test(subject._ReplayPhase.COMPUTING)
        replay_errors: list[BaseException] = []

        def fail_replay() -> None:
            try:
                owner._replay_unpublished_prefix(
                    target_ref,
                    retention_completion=completion,
                    _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
                    _fault_phase=subject._ReplayFaultPhase.COMPUTE,
                )
            except BaseException as error:  # noqa: BLE001 - asserted below
                replay_errors.append(error)

        replay_worker = Thread(target=fail_replay)
        replay_worker.start()
        with owner._replay_state_condition:
            assert owner._replay_state_condition.wait_for(
                lambda: owner._replay_status.phase is subject._ReplayPhase.COMPUTING,
                timeout=5,
            )
            failed_scope = store._authenticated_retention_replay_scope
            assert failed_scope is not None
        owner._release_replay_status_barrier_for_test(subject._ReplayPhase.COMPUTING)
        replay_worker.join(5)
        assert replay_worker.is_alive() is False
        assert len(replay_errors) == 1
        assert isinstance(replay_errors[0], KeyboardInterrupt)
        with (
            pytest.raises(EvidenceSealError),
            store._authenticated_retention_replay_scope_gate(
                failed_scope,
                target_ref,
            ),
        ):
            pass
        retry_after_failure = store._capture_authenticated_retention_replay_scope(
            completion,
            target_ref,
        )
        store._release_authenticated_retention_replay_scope(retry_after_failure)

        report = owner._replay_unpublished_prefix(
            target_ref,
            retention_completion=completion,
            _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
        )
        assert report.cursor is not None
        assert report.cursor.source_sequence == target_ref.source_sequence
        assert report.applied_count == len(surviving)
        published = owner._connection
        assert isinstance(published, sqlite3.Connection)
        projected_sequences = tuple(
            int(row[0])
            for row in published.execute(
                "SELECT source_sequence FROM events ORDER BY source_sequence"
            )
        )
        assert projected_sequences == tuple(record.ref.source_sequence for record in surviving)
        assert all(
            not start <= sequence <= end
            for sequence in projected_sequences
            for start, end in store._authenticated_retired_ranges
        )
        with pytest.raises(EvidenceSealError):
            store._capture_authenticated_retention_replay_scope(
                completion,
                target_ref,
            )
        assert store._authenticated_retention_replay_consumed is not None
        published_status = owner._replay_status_for_test()
        assert published_status.phase is subject._ReplayPhase.PUBLISHED
        assert published_status.reservation_present is False
        store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        assert store._authenticated_retention_replay_consumed is None
    finally:
        coverage.close()
        owner.close()

    _recovered_coordinator, recovered_store = _reopen_evidence(tmp_path / "evidence")
    try:
        with pytest.raises(EvidenceSealError):
            recovered_store._capture_authenticated_retention_replay_scope(
                completion,
                target_ref,
            )
    finally:
        recovered_store.close(flush=False)

    fault_key, fault_acceptance, fault_store, fault_coverage = (
        retention._live_store_with_active_routine(tmp_path / "pre-final-commit")
    )
    fault_journal = CorrelationRequestJournal.create_new(fault_store)
    fault_acknowledgements = fault_store._ack_journal_owner
    assert type(fault_acknowledgements) is AckJournal
    fault_connection = subject._v2_connection_for_test()
    fault_owner = subject._v2_projection_owner_for_test(
        fault_connection,
        evidence=fault_store,
        acknowledgements=fault_acknowledgements,
        journal=fault_journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    fault_selected_snapshot = fault_store._freeze_retention_snapshot(
        retention._proof_clock(),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    fault_decision = retention.select_retention(
        fault_selected_snapshot,
        request_id=retention.REQUEST_ID,
    )
    fault_request = fault_decision.request
    assert fault_request is not None
    fault_retention_journal = retention.retention_module._open_retention_state_journal(fault_store)
    fault_retention_journal.prepare_publication(fault_decision)
    fault_target_item = retention._item(
        envelope_value(
            fault_key,
            sequence=3,
            event_type="retention_tombstone",
            normalized_fields=fault_request.model_dump(mode="python"),
        )
    )
    fault_target_ref = fault_acceptance.accept(fault_target_item)
    fault_coverage._apply_live_accepted(fault_store, fault_target_ref, None)
    fault_acknowledgements.record_pending(fault_target_ref)
    fault_acknowledgements.record_confirmed(fault_target_ref)
    fault_target = retention.retention_module.RetentionTargetV1(
        sequence=fault_target_item.sequence,
        event_id=fault_target_item.event_id,
        content_sha256=fault_target_item.content_sha256,
    )
    fault_retention_journal.bind_target(fault_target)
    fault_retention_journal.advance_evidence_appended(fault_target)
    fault_final_snapshot = fault_store._freeze_retention_snapshot(
        retention._proof_clock(seconds=1),
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    fault_tombstone = fault_store._authenticate_retention_tombstone(
        fault_retention_journal,
        fault_final_snapshot,
        fault_target_ref,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    fault_completion = fault_store._execute_authenticated_retention_unlink(
        fault_tombstone,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    fault_surviving = tuple(
        fault_store.iter_authenticated_records(through=fault_target_ref.source_sequence)
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            fault_owner._replay_unpublished_prefix(
                fault_target_ref,
                retention_completion=fault_completion,
                _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
                _fault_phase=subject._ReplayFaultPhase.PRE_COMMIT,
            )
        fault_status = fault_owner._replay_status_for_test()
        assert fault_status.phase is subject._ReplayPhase.FAILED
        assert fault_status.failure_phase is subject._ReplayPhase.VALIDATING
        assert fault_status.reservation_present is False
        assert fault_owner._generation == 1
        assert fault_owner._connection is fault_connection
        assert fault_owner.status().cursor is None
        assert fault_connection.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        assert fault_connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
        assert fault_connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
        assert fault_store._authenticated_retention_replay_scope is None
        assert fault_store._authenticated_retention_replay_consumed is None
        fresh_after_precommit = fault_store._capture_authenticated_retention_replay_scope(
            fault_completion,
            fault_target_ref,
        )
        fault_store._release_authenticated_retention_replay_scope(fresh_after_precommit)
        fault_report = fault_owner._replay_unpublished_prefix(
            fault_target_ref,
            retention_completion=fault_completion,
            _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
        )
        assert fault_report.cursor is not None
        assert fault_report.cursor.source_sequence == fault_target_ref.source_sequence
        assert fault_report.applied_count == len(fault_surviving)
        assert fault_owner._generation == 2
        retried_status = fault_owner._replay_status_for_test()
        assert retried_status.phase is subject._ReplayPhase.PUBLISHED
        assert retried_status.reservation_present is False
        assert fault_store._authenticated_retention_replay_consumed is not None
        with pytest.raises(EvidenceSealError):
            fault_store._capture_authenticated_retention_replay_scope(
                fault_completion,
                fault_target_ref,
            )
        fault_store._finalize_authenticated_retention_completion(
            fault_completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        assert fault_store._authenticated_retention_replay_consumed is None
    finally:
        fault_coverage.close()
        fault_owner.close()


def test_durable_stage_does_not_publish_or_consume_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    case = _durable_retention_case(subject, tmp_path / "evidence")
    owner = case["owner"]
    connection = case["connection"]
    store = case["store"]
    target_ref = case["target_ref"]
    completion = case["completion"]
    authority_before = owner._authority
    predecessor_before = subject._predecessor_v2(1, None)
    stage = owner._stage_unpublished_prefix(
        target_ref,
        retention_completion=completion,
        _factory=subject._STAGED_REPLAY_FACTORY,
    )
    try:
        replay_status = owner._replay_status_for_test()
        assert replay_status.phase is subject._ReplayPhase.STAGED
        assert replay_status.generation == 1
        assert replay_status.reservation_present is True
        assert owner._generation == 1
        assert owner._connection is connection
        assert owner._authority is authority_before
        subject._validate_correlation_projection_predecessor(
            authority_before,
            predecessor_before,
        )
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        assert store._authenticated_retention_replay_scope is not None
        assert store._authenticated_retention_replay_consumed is None
        with pytest.raises(ProjectionAuthorityError):
            owner.status()
        with pytest.raises(ProjectionAuthorityError):
            owner.snapshot_hash()
        with pytest.raises(ProjectionAuthorityError):
            owner.apply(next(store.iter_authenticated_records()))
        with pytest.raises(ProjectionAuthorityError):
            owner._replay_unpublished_prefix(
                target_ref,
                _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
            )
        with pytest.raises(ProjectionAuthorityError):
            owner.close()
        with pytest.raises(EvidenceSealError):
            store._capture_authenticated_retention_replay_scope(
                completion,
                target_ref,
            )
    finally:
        owner._abort_staged_replay(
            stage,
            _factory=subject._STAGED_REPLAY_FACTORY,
        )

    assert owner._generation == 1
    assert owner._connection is connection
    assert owner._authority is authority_before
    subject._validate_correlation_projection_predecessor(
        authority_before,
        predecessor_before,
    )
    assert store._authenticated_retention_replay_scope is None
    assert store._authenticated_retention_replay_consumed is None
    report = owner._replay_unpublished_prefix(
        target_ref,
        retention_completion=completion,
        _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
    )
    assert report.applied_count == len(case["surviving"])
    store._finalize_authenticated_retention_completion(
        completion,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    case["coverage"].close()
    owner.close()


@pytest.mark.parametrize(
    "failure_kind",
    ("stage", "handoff", "materialize", "publisher"),
)
def test_durable_stage_abort_releases_exact_resources_and_allows_actual_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    case_root = tmp_path / failure_kind
    case_root.mkdir()
    owner, connection, _store, through = _durable_unpublished_case(
        subject,
        case_root / "evidence",
    )
    authority_before = owner._authority
    predecessor_before = subject._predecessor_v2(1, None)
    candidate: sqlite3.Connection | None = None
    stage: Any | None = None
    try:
        if failure_kind in ("stage", "handoff"):
            with pytest.raises(KeyboardInterrupt):
                owner._stage_unpublished_prefix(
                    through,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                    _fault_phase=(
                        subject._ReplayFaultPhase.COMPUTE
                        if failure_kind == "stage"
                        else subject._ReplayFaultPhase.STAGE_HANDOFF
                    ),
                )
        else:
            stage = owner._stage_unpublished_prefix(
                through,
                _factory=subject._STAGED_REPLAY_FACTORY,
            )
            candidate = sqlite3.connect(
                case_root / "candidate.sqlite3",
                isolation_level=None,
                check_same_thread=False,
            )
            # The physical-binding capture accepts only owner-private 0600
            # candidates, exactly as the production publisher creates them.
            (case_root / "candidate.sqlite3").chmod(0o600)
            if failure_kind == "materialize":
                candidate.execute("CREATE TABLE attacker(value TEXT)")
                with pytest.raises(subject.ProjectionConflict):
                    owner._copy_staged_replay_into(
                        stage,
                        candidate,
                        _factory=subject._STAGED_REPLAY_FACTORY,
                    )
            else:
                seal = owner._copy_staged_replay_into(
                    stage,
                    candidate,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )
                # Publication is only reachable from the prepared state: the
                # owner checkpoints and closes the candidate exactly as the
                # production publisher does before its callback runs.
                owner._prepare_staged_replay_for_publication(
                    stage,
                    seal,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )

                def crash_before_latch(_latch: Any) -> sqlite3.Connection:
                    raise KeyboardInterrupt("injected pre-latch publisher failure")

                with pytest.raises(KeyboardInterrupt):
                    owner._publish_staged_replay(
                        stage,
                        seal,
                        crash_before_latch,
                        _factory=subject._STAGED_REPLAY_FACTORY,
                    )

        status = owner._replay_status_for_test()
        assert owner._staged_replay is None
        assert status.phase is subject._ReplayPhase.FAILED
        assert status.reservation_present is False
        assert owner._generation == 1
        assert owner._connection is connection
        assert owner._authority is authority_before
        assert owner._healthy is True
        subject._validate_correlation_projection_predecessor(
            authority_before,
            predecessor_before,
        )
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        if candidate is not None:
            with pytest.raises(sqlite3.ProgrammingError):
                candidate.execute("SELECT 1")
        if stage is not None:
            with pytest.raises(ProjectionAuthorityError):
                owner._abort_staged_replay(
                    stage,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )

        report = owner._replay_unpublished_prefix(
            through,
            _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
        )
        assert report.cursor is not None
        assert report.cursor.source_sequence == through.source_sequence
        assert owner._generation == 2
        assert owner._authority is authority_before
        assert owner._replay_status_for_test().phase is subject._ReplayPhase.PUBLISHED
    finally:
        owner.close()


def test_durable_stage_materialization_is_exact_one_shot_and_unforgeable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)
    owner, _connection, _store, through = _durable_unpublished_case(
        subject,
        tmp_path / "evidence",
    )
    stage = owner._stage_unpublished_prefix(
        through,
        _factory=subject._STAGED_REPLAY_FACTORY,
    )
    target = sqlite3.connect(
        tmp_path / "candidate.sqlite3",
        isolation_level=None,
        check_same_thread=False,
    )
    # Candidates must carry the production publisher's owner-private 0600
    # mode so materialization fails only for the forgery under test.
    (tmp_path / "candidate.sqlite3").chmod(0o600)
    try:
        assert not hasattr(stage, "connection")
        assert not hasattr(stage, "database_image")
        assert not hasattr(stage, "__dict__")
        with pytest.raises(TypeError):
            copy.copy(stage)
        with pytest.raises(TypeError):
            copy.deepcopy(stage)
        with pytest.raises((TypeError, pickle.PicklingError)):
            pickle.dumps(stage)

        forged = object.__new__(type(stage))
        forged_target = sqlite3.connect(
            tmp_path / "forged.sqlite3",
            isolation_level=None,
            check_same_thread=False,
        )
        (tmp_path / "forged.sqlite3").chmod(0o600)
        with pytest.raises(ProjectionAuthorityError):
            owner._copy_staged_replay_into(
                forged,
                forged_target,
                _factory=subject._STAGED_REPLAY_FACTORY,
            )
        with pytest.raises(sqlite3.ProgrammingError):
            forged_target.execute("SELECT 1")

        seal = owner._copy_staged_replay_into(
            stage,
            target,
            _factory=subject._STAGED_REPLAY_FACTORY,
        )
        assert not hasattr(seal, "connection")
        assert not hasattr(seal, "database_image")
        assert not hasattr(seal, "__dict__")
        with pytest.raises(TypeError):
            copy.copy(seal)
        with pytest.raises(TypeError):
            copy.deepcopy(seal)
        with pytest.raises((TypeError, pickle.PicklingError)):
            pickle.dumps(seal)
        subject._verify_v2_schema(target)
        assert seal.cursor is not None
        assert seal.cursor.source_sequence == through.source_sequence
        assert seal.applied_count == through.source_sequence
        assert seal.prefix_sha256 == subject._v2_snapshot_hash(target)
        assert seal.table_counts == tuple(
            (table, target.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table, _columns, _primary_key in subject._TABLE_LAYOUT_V2
        )

        second_target = sqlite3.connect(
            tmp_path / "laundered.sqlite3",
            isolation_level=None,
            check_same_thread=False,
        )
        (tmp_path / "laundered.sqlite3").chmod(0o600)
        with pytest.raises(ProjectionAuthorityError):
            owner._copy_staged_replay_into(
                stage,
                second_target,
                _factory=subject._STAGED_REPLAY_FACTORY,
            )
        with pytest.raises(sqlite3.ProgrammingError):
            second_target.execute("SELECT 1")

        target.execute("DELETE FROM candidate_evidence")
        called = False

        def must_not_publish(_latch: Any) -> sqlite3.Connection:
            nonlocal called
            called = True
            raise AssertionError("mutated staged image reached publisher")

        # The prepared-publication protocol validates the materialized image
        # against its seal at the preparation edge, so the mutation must
        # conflict there, discard the stage, and starve the publisher.
        with pytest.raises(subject.ProjectionConflict):
            owner._prepare_staged_replay_for_publication(
                stage,
                seal,
                _factory=subject._STAGED_REPLAY_FACTORY,
            )
        with pytest.raises(ProjectionAuthorityError):
            owner._publish_staged_replay(
                stage,
                seal,
                must_not_publish,
                _factory=subject._STAGED_REPLAY_FACTORY,
            )
        assert called is False
        with pytest.raises(sqlite3.ProgrammingError):
            target.execute("SELECT 1")
        with pytest.raises(ProjectionAuthorityError):
            owner._abort_staged_replay(
                stage,
                _factory=subject._STAGED_REPLAY_FACTORY,
            )
    finally:
        owner.close()


@pytest.mark.parametrize(
    "commit_kind",
    (
        "missing_pcc",
        "unrelated_memory",
        "temp_shadow",
        "pre_commit",
        "post_callback",
        "post_latch",
        "armed_no_namespace",
        "fence_drain",
        "fd_close_interrupt",
        "valid_retention",
    ),
)
def test_durable_stage_commits_only_verified_reopened_image_at_final_edge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    commit_kind: str,
) -> None:
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: _DETECTOR_HASH)

    if commit_kind == "valid_retention":
        case = _durable_retention_case(subject, tmp_path / "evidence")
        owner = case["owner"]
        connection = case["connection"]
        through = case["target_ref"]
        completion = case["completion"]
    else:
        owner, connection, _store, through = _durable_unpublished_case(
            subject,
            tmp_path / "evidence",
        )
        case = None
        completion = None

    stage = owner._stage_unpublished_prefix(
        through,
        retention_completion=completion,
        _factory=subject._STAGED_REPLAY_FACTORY,
    )
    candidate_path = tmp_path / "candidate.sqlite3"
    published_path = tmp_path / "published.sqlite3"
    target = sqlite3.connect(
        candidate_path,
        isolation_level=None,
        check_same_thread=False,
    )
    # The physical-binding capture accepts only owner-private 0600
    # candidates, exactly as the production publisher creates them.
    candidate_path.chmod(0o600)
    seal = owner._copy_staged_replay_into(
        stage,
        target,
        _factory=subject._STAGED_REPLAY_FACTORY,
    )
    # Publication is only reachable from the prepared state: the owner
    # checkpoints and closes the candidate exactly as the production
    # publisher does, so callbacks below act on the file, not on target.
    owner._prepare_staged_replay_for_publication(
        stage,
        seal,
        _factory=subject._STAGED_REPLAY_FACTORY,
    )
    authority_before = owner._authority
    rebuild_calls: list[Any] = []
    original_rebuild = subject._rebuild_correlation_projection_authority

    def counted_rebuild(authority_handle: Any, successor: Any) -> None:
        assert owner._replay_state_lock.locked() is False
        rebuild_calls.append(authority_handle)
        original_rebuild(authority_handle, successor)

    monkeypatch.setattr(
        subject,
        "_rebuild_correlation_projection_authority",
        counted_rebuild,
    )
    reopened: list[sqlite3.Connection] = []
    try:
        if commit_kind == "missing_pcc":

            def publish_missing(latch: Any) -> sqlite3.Connection:
                mutating = sqlite3.connect(candidate_path, isolation_level=None)
                mutating.execute("DELETE FROM candidate_evidence")
                mutating.execute("DELETE FROM candidates")
                mutating.close()
                latch._arm_namespace_publication()
                os.replace(candidate_path, published_path)
                result = subject._v2_connection_for_test(published_path)
                reopened.append(result)
                return result

            with pytest.raises(subject.ProjectionConflict):
                owner._publish_staged_replay(
                    stage,
                    seal,
                    publish_missing,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )
            assert owner._healthy is False
            assert owner._authority is None
            assert rebuild_calls == []
            inspection = subject._v2_connection_for_test(published_path)
            try:
                assert (
                    inspection.execute("SELECT count(*) FROM candidate_evidence").fetchone()[0] == 0
                )
                assert inspection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
            finally:
                inspection.close()
        elif commit_kind == "unrelated_memory":

            def publish_unrelated(latch: Any) -> sqlite3.Connection:
                unrelated = subject._v2_connection_for_test()
                source = sqlite3.connect(candidate_path, isolation_level=None)
                source.backup(unrelated)
                source.close()
                latch._arm_namespace_publication()
                os.replace(candidate_path, published_path)
                reopened.append(unrelated)
                return unrelated

            with pytest.raises(subject.ProjectionConflict):
                owner._publish_staged_replay(
                    stage,
                    seal,
                    publish_unrelated,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )
            assert owner._healthy is False
            assert owner._authority is None
            assert rebuild_calls == []
        elif commit_kind == "temp_shadow":

            def publish_temp_shadow(latch: Any) -> sqlite3.Connection:
                latch._arm_namespace_publication()
                os.replace(candidate_path, published_path)
                result = subject._v2_connection_for_test(published_path)
                result.execute("CREATE TEMP TABLE attacker(value TEXT)")
                reopened.append(result)
                return result

            with pytest.raises(subject.ProjectionConflict):
                owner._publish_staged_replay(
                    stage,
                    seal,
                    publish_temp_shadow,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )
            assert owner._healthy is False
            assert owner._authority is None
            assert rebuild_calls == []
        elif commit_kind == "pre_commit":
            called = False

            def must_not_publish(_latch: Any) -> sqlite3.Connection:
                nonlocal called
                called = True
                raise AssertionError("pre-commit fault reached publisher")

            with pytest.raises(KeyboardInterrupt):
                owner._publish_staged_replay(
                    stage,
                    seal,
                    must_not_publish,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                    _fault_phase=subject._ReplayFaultPhase.PRE_COMMIT,
                )
            assert called is False
            assert owner._healthy is True
            assert owner._generation == 1
            assert owner._connection is connection
            assert owner.status().cursor is None
            report = owner._replay_unpublished_prefix(
                through,
                _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
            )
            assert report.cursor is not None
            assert owner._generation == 2
            assert owner._authority is authority_before
            assert rebuild_calls == [authority_before]
        elif commit_kind == "post_callback":

            def interrupt_after_callback(latch: Any) -> sqlite3.Connection:
                latch._arm_namespace_publication()
                os.replace(candidate_path, published_path)
                result = subject._v2_connection_for_test(published_path)
                reopened.append(result)
                return result

            with pytest.raises(KeyboardInterrupt):
                owner._publish_staged_replay(
                    stage,
                    seal,
                    interrupt_after_callback,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                    _fault_phase=subject._ReplayFaultPhase.POST_CALLBACK,
                )
            assert owner._healthy is False
            assert owner._authority is None
            assert owner._replay_status_for_test().reservation_present is False
            assert rebuild_calls == []
        elif commit_kind == "post_latch":

            def crash_after_latch(latch: Any) -> sqlite3.Connection:
                latch._arm_namespace_publication()
                os.replace(candidate_path, published_path)
                raise KeyboardInterrupt("injected post-latch failure")

            with pytest.raises(KeyboardInterrupt):
                owner._publish_staged_replay(
                    stage,
                    seal,
                    crash_after_latch,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )
            assert owner._healthy is False
            assert owner._authority is None
            assert owner._replay_status_for_test().reservation_present is False
            assert rebuild_calls == []
        elif commit_kind == "armed_no_namespace":

            def fail_namespace_without_mutation(latch: Any) -> sqlite3.Connection:
                latch._arm_namespace_publication()
                raise OSError("injected namespace syscall failure")

            with pytest.raises(OSError, match="namespace syscall failure"):
                owner._publish_staged_replay(
                    stage,
                    seal,
                    fail_namespace_without_mutation,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )
            assert candidate_path.exists()
            assert not published_path.exists()
            assert owner._healthy is False
            assert owner._authority is None
            assert owner._replay_status_for_test().reservation_present is False
            with pytest.raises(subject.ProjectionUnhealthy):
                owner._replay_unpublished_prefix(
                    through,
                    _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
                )
        elif commit_kind == "fence_drain":
            drain_calls = 0
            original_drain = owner._acknowledgements._drain_replay_corruption_fences

            def fail_drain_once(primary: BaseException | None) -> None:
                nonlocal drain_calls
                drain_calls += 1
                if drain_calls == 1:
                    raise KeyboardInterrupt("injected replay fence-drain failure")
                original_drain(primary)

            monkeypatch.setattr(
                owner._acknowledgements,
                "_drain_replay_corruption_fences",
                fail_drain_once,
            )
            callback_called = False

            def must_not_publish(latch: Any) -> sqlite3.Connection:
                nonlocal callback_called
                callback_called = True
                latch._arm_namespace_publication()
                os.replace(candidate_path, published_path)
                result = subject._v2_connection_for_test(published_path)
                reopened.append(result)
                return result

            with pytest.raises(KeyboardInterrupt):
                owner._publish_staged_replay(
                    stage,
                    seal,
                    must_not_publish,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )
            assert callback_called is False
            assert owner._healthy is True
            assert owner._generation == 1
            assert owner._connection is connection
            assert owner._replay_status_for_test().phase is subject._ReplayPhase.FAILED
            report = owner._replay_unpublished_prefix(
                through,
                _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
            )
            assert report.cursor is not None
            assert owner._generation == 2
        elif commit_kind == "fd_close_interrupt":
            staged_binding = owner._staged_replay
            assert staged_binding is not None
            physical = staged_binding.materialized_physical
            assert physical is not None
            physical_descriptor = physical.descriptor
            original_close = os.close
            injected = False
            reused_descriptor: int | None = None
            replacement_descriptors: list[int] = []

            def interrupt_after_physical_close(descriptor: int) -> None:
                nonlocal injected, reused_descriptor
                if descriptor == physical_descriptor and not injected:
                    injected = True
                    original_close(descriptor)
                    while reused_descriptor != descriptor:
                        reused_descriptor = os.open(os.devnull, os.O_RDONLY)
                        replacement_descriptors.append(reused_descriptor)
                        assert reused_descriptor <= descriptor
                    raise KeyboardInterrupt("injected post-fd-close interrupt")
                original_close(descriptor)

            monkeypatch.setattr(subject.os, "close", interrupt_after_physical_close)

            def publish_before_fd_interrupt(latch: Any) -> sqlite3.Connection:
                latch._arm_namespace_publication()
                os.replace(candidate_path, published_path)
                result = subject._v2_connection_for_test(published_path)
                reopened.append(result)
                return result

            with pytest.raises(KeyboardInterrupt, match="post-fd-close interrupt"):
                owner._publish_staged_replay(
                    stage,
                    seal,
                    publish_before_fd_interrupt,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )
            assert reused_descriptor is not None
            try:
                os.fstat(reused_descriptor)
            finally:
                for replacement_descriptor in replacement_descriptors:
                    try:
                        original_close(replacement_descriptor)
                    except OSError:
                        pass
            assert owner._healthy is False
            assert owner._authority is None
        else:

            def publish_exact(latch: Any) -> sqlite3.Connection:
                latch._arm_namespace_publication()
                os.replace(candidate_path, published_path)
                result = subject._v2_connection_for_test(published_path)
                reopened.append(result)
                return result

            report = owner._publish_staged_replay(
                stage,
                seal,
                publish_exact,
                _factory=subject._STAGED_REPLAY_FACTORY,
            )
            assert report.cursor is not None
            assert report.cursor.source_sequence == through.source_sequence
            assert owner._connection is reopened[0]
            assert owner._generation == 2
            assert owner._authority is authority_before
            assert rebuild_calls == [authority_before]
            published = owner._replay_status_for_test()
            assert published.phase is subject._ReplayPhase.PUBLISHED
            assert published.reservation_present is False
            assert case is not None
            assert case["store"]._authenticated_retention_replay_consumed is not None
            with pytest.raises(ProjectionAuthorityError):
                owner._abort_staged_replay(
                    stage,
                    _factory=subject._STAGED_REPLAY_FACTORY,
                )
            case["store"]._finalize_authenticated_retention_completion(
                completion,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )
    finally:
        if case is not None:
            case["coverage"].close()
        owner.close()


def test_historical_pin_mismatch_returns_no_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches reducing a protected PCC under replacement fixed pin authority."""
    subject = _subject()
    _hermetic_detector_bundle(monkeypatch)
    authority = importlib.import_module("agmind_immune.correlation.authority")
    detector_bundle_sha256 = authority._load_pinned_detector_bundle()
    assert detector_bundle_sha256 != "0" * 64

    def mismatch_snapshot(fields: dict[str, object]) -> None:
        fields["detector_bundle_sha256"] = "0" * 64

    coordinator, proof = _accepted_complete(
        tmp_path / "evidence",
        ttl_seconds=120,
        snapshot_change=mismatch_snapshot,
    )
    registry_mismatch = proof.snapshot.model_copy(update={"special_use_registry_sha256": "0" * 64})
    with pytest.raises(ValueError):
        PCCCorrelationSnapshotV1.model_validate_json(
            canonical_json(registry_mismatch),
            strict=True,
        )
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        (proof,),
    )
    connection = subject._v2_connection_for_test()
    owner = subject._v2_projection_owner_for_test(
        connection,
        evidence=store,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=load_pinned_special_use_registry(_REGISTRY_PATH),
    )
    artifact: object | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            artifact = owner._replay_unpublished_prefix(
                records[-1].ref,
                _factory=subject._UNPUBLISHED_REPLAY_FACTORY,
            )
        assert artifact is None
        assert owner._generation == 1
        replay_status = owner._replay_status_for_test()
        assert replay_status.phase is subject._ReplayPhase.FAILED
        assert replay_status.failure_phase is subject._ReplayPhase.FREEZING
        assert owner.status().cursor is None
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 0
    finally:
        owner.close()


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
            bytes(32) if not decoded_ack.records else decoded_ack.records[-1].record_hash
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
        frozen_inputs = (_frozen_compute_pcc_input(proof, records),)
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
            candidate_count = connection.execute("SELECT count(*) FROM candidates").fetchone()[0]
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
                    1 if case in {"late-critical", "sequence-range", "transport-duplicate"} else 0
                )
                assert invalidation_count == expected_invalidations
                if case == "transport-duplicate":
                    duplicate_rows = connection.execute(
                        "SELECT count(*) FROM events WHERE duplicate_of_event_id IS NOT NULL"
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
        "UPDATE projection_dedup SET primary_event_id=?,is_primary=0 WHERE event_id=?",
        (second_event_id, first_event_id),
    )
    connection.execute(
        "UPDATE projection_dedup SET primary_event_id=?,is_primary=1 WHERE event_id=?",
        (second_event_id, second_event_id),
    )
    for table in ("process_observations", "network_observations"):
        connection.execute(
            f"UPDATE {table} SET event_id=?,source_sequence=?,content_sha256=? WHERE event_id=?",
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
        rows = connection.execute("SELECT result_kind,authority_event_id FROM incidents").fetchall()
        assert [tuple(row) for row in rows] == [("investigation", authenticated.event_id)]
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
            "SELECT candidate_id,primary_event_id,correlation_snapshot_event_id FROM candidates"
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

        candidate_id = connection.execute("SELECT candidate_id FROM candidates").fetchone()[0]
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
        assert (
            subject._v2_ordered_table_rows(
                replay_connection,
                "candidate_invalidations",
            )
            == expected_rows
        )
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
    coordinator, stale_proofs = _accepted_unpublished_compact_history(tmp_path / "evidence")
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
    # The frozen replay calls _reduce_historical_coverage_result through the
    # projection module's own imported name, so the interception must live on
    # that seam: patching the historical-module wrapper would never observe
    # the reductions replay actually performs.
    real_reduce = subject._reduce_historical_coverage_result
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
            reduced_assessments[trigger_event_id].append(result.timeline.assessment)
        return result

    monkeypatch.setattr(
        subject,
        "_reduce_historical_coverage_result",
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
    coordinator, proofs = _accepted_unpublished_compact_history(tmp_path / "evidence")
    store, journal, acknowledgements, records = _unpublished_resources(
        coordinator,
        proofs,
    )
    try:
        prepared = [historical._prepare_historical_record(record) for record in records]
        return_index = 10
        prepared[return_index] = replace(
            prepared[return_index],
            envelope=prepared[return_index].envelope.model_copy(update={"boot_id": BOOT_A}),
        )
        entries = historical._build_frozen_replay_entries(
            records,
            tuple(prepared),
        )
        compact_sequences = tuple(
            entry.record.ref.source_sequence for entry in entries if entry.compact_member
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


def _assert_replay_rejects_real_public_writer(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    writer: str,
) -> None:
    from tests.evidence.test_projection_replay_boundary import (
        _build_replay_orchestration_case,
        _close_replay_orchestration_case,
        _perform_replay_writer,
        _release_replay_barrier,
        _start_replay_worker,
        _wait_for_replay_phase,
    )

    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    case = _build_replay_orchestration_case(path)
    owner = case["owner"]
    worker, reports, errors = _start_replay_worker(
        case,
        barrier_phase="computing",
    )
    barrier_released = False
    try:
        status = _wait_for_replay_phase(case, worker, "computing", errors)
        assert status.reservation_present is True
        _perform_replay_writer(case, writer)
        _release_replay_barrier(case, "computing")
        barrier_released = True
        worker.join(5)
        assert worker.is_alive() is False
        assert reports == []
        assert len(errors) == 1
        assert isinstance(errors[0], ProjectionAuthorityError)
        failed = owner._replay_status_for_test()  # type: ignore[attr-defined]
        assert failed.phase.value == "failed"
        assert failed.reservation_present is False
    finally:
        if not barrier_released:
            try:
                _release_replay_barrier(case, "computing")
            except ProjectionAuthorityError:
                pass
        if worker.is_alive():
            worker.join(5)
        _close_replay_orchestration_case(case)
    assert case["store"]._closed is True  # type: ignore[attr-defined]
    assert case["journal"]._closed is True  # type: ignore[attr-defined]
    assert case["acknowledgements"]._closed is True  # type: ignore[attr-defined]


def test_unpublished_final_seal_binds_authenticated_retired_ranges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_replay_rejects_real_public_writer(
        tmp_path / "retention",
        monkeypatch,
        "retention",
    )


def test_unpublished_replay_failure_returns_no_artifact_and_closes_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_replay_rejects_real_public_writer(
        tmp_path / "journal",
        monkeypatch,
        "journal",
    )


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
        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_id=?",
                (coverage_ref.event_id,),
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM coverage_intervals WHERE event_id=?",
                (coverage_ref.event_id,),
            ).fetchone()[0]
            == 1
        )
        assert connection.execute("SELECT count(*) FROM candidate_invalidations").fetchone()[0] == 0
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
        assert (
            subject._v2_ordered_table_rows(
                connection,
                "candidate_invalidations",
            )
            == before
        )
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

        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_id=?",
                (coverage.event_id,),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM coverage_intervals WHERE event_id=?",
                (coverage.event_id,),
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT count(*) FROM candidate_invalidations").fetchone()[0] == 0
        assert owner.status().cursor.source_sequence == proofs[-1].source_sequence

        armed = False
        owner.apply(coverage)
        assert connection.execute("SELECT count(*) FROM candidate_invalidations").fetchone()[0] == 3
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
        assert (
            connection.execute("SELECT source_sequence FROM ingest_cursors").fetchone()[0]
            == "00000000000000000002"
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_id=?",
                (proof.event_id,),
            ).fetchone()[0]
            == 0
        )
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
        row = connection.execute("SELECT result_kind,reason_codes FROM incidents").fetchone()
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
        row = connection.execute("SELECT result_kind,reason_codes FROM incidents").fetchone()
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


def test_borrowed_v2_owner_close_releases_only_projection_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches borrowed close poisoning caller authorities or leaking its owner slot."""
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    coordinator = _coordinator(tmp_path / "evidence", private_key(11))
    store = coordinator.segment_store
    journal = CorrelationRequestJournal.create_new(store)
    acknowledgements = AckJournal.create_new(store)
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    connection = subject._v2_connection_for_test()
    foreign_coordinator = _coordinator(
        tmp_path / "foreign-evidence",
        private_key(12),
    )
    foreign_store = foreign_coordinator.segment_store
    foreign_journal = CorrelationRequestJournal.create_new(foreign_store)
    mismatched_connection = subject._v2_connection_for_test()
    closed_connection: sqlite3.Connection | None = None
    owner: Any | None = None
    replacement: Any | None = None
    replacement_connection: sqlite3.Connection | None = None
    saved_authority: Any | None = None
    try:
        with pytest.raises(ProjectionAuthorityError):
            subject._V2ProjectionOwner._borrow_authorities(
                mismatched_connection,
                evidence=store,
                acknowledgements=acknowledgements,
                journal=foreign_journal,
                registry=registry,
                step_hook=None,
            )
        with pytest.raises(sqlite3.ProgrammingError):
            mismatched_connection.execute("SELECT 1")
        assert store.acceptance_cursor == 0
        assert acknowledgements.snapshot().healthy is True
        assert journal._is_bound_to(store) is True
        assert foreign_journal._is_bound_to(foreign_store) is True
        assert special_use_registry_is_issued(registry) is True

        journal.close()
        closed_connection = subject._v2_connection_for_test()
        with pytest.raises(ProjectionAuthorityError):
            subject._V2ProjectionOwner._borrow_authorities(
                closed_connection,
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=registry,
                step_hook=None,
            )
        with pytest.raises(sqlite3.ProgrammingError):
            closed_connection.execute("SELECT 1")
        assert store.acceptance_cursor == 0
        assert acknowledgements.snapshot().healthy is True
        assert special_use_registry_is_issued(registry) is True
        journal = CorrelationRequestJournal.open_and_recover(store)
        assert journal._is_bound_to(store) is True

        owner = subject._V2ProjectionOwner._borrow_authorities(
            connection,
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=registry,
            step_hook=None,
        )
        saved_authority = owner._authority
        assert saved_authority is not None

        owner.close()
        owner.close()

        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        with pytest.raises(authority.CorrelationProjectionError):
            authority._validate_correlation_projection_predecessor(
                saved_authority,
                subject._predecessor_v2(1, None),
            )
        assert store.acceptance_cursor == 0
        assert acknowledgements.snapshot().healthy is True
        assert journal._is_bound_to(store) is True
        assert store._closed is False
        assert acknowledgements._closed is False
        assert journal._closed is False

        replacement_connection = subject._v2_connection_for_test()
        replacement = subject._V2ProjectionOwner._borrow_authorities(
            replacement_connection,
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=registry,
            step_hook=None,
        )
        assert replacement.status().healthy is True
    finally:
        if replacement is not None:
            replacement.close()
        elif replacement_connection is not None:
            try:
                replacement_connection.close()
            except sqlite3.ProgrammingError:
                pass
        if owner is not None:
            owner.close()
        else:
            connection.close()
        mismatched_connection.close()
        if closed_connection is not None:
            closed_connection.close()
        if not journal._closed:
            journal.close()
        if not foreign_journal._closed:
            foreign_journal.close()
        if not acknowledgements._closed:
            acknowledgements.close()
        if not foreign_store._closed:
            foreign_store.close()
        if not store._closed:
            store.close()


def test_borrowed_v2_owner_reopen_rejects_missing_pcc_facts_without_backfill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches implicit security-fact repair during a borrowed V2 reopen."""
    subject = _subject()
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _DETECTOR_HASH,
    )
    projection_path = tmp_path / "projection.sqlite3"
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
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    connection = subject._v2_connection_for_test(projection_path)
    owner: Any | None = None
    failed_connection: sqlite3.Connection | None = None
    unexpected_owner: Any | None = None
    fresh_connection: sqlite3.Connection | None = None
    fresh_owner: Any | None = None
    try:
        owner = subject._V2ProjectionOwner._borrow_authorities(
            connection,
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=registry,
            step_hook=None,
        )
        for record in records:
            owner.apply(record.ref)
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 1
        owner.close()

        tamper = sqlite3.connect(projection_path, isolation_level=None)
        try:
            tamper.execute("PRAGMA foreign_keys=ON")
            tamper.execute("BEGIN IMMEDIATE")
            tamper.execute("DELETE FROM candidate_evidence")
            tamper.execute("DELETE FROM candidate_invalidations")
            tamper.execute("DELETE FROM candidates")
            tamper.execute("DELETE FROM incidents")
            tamper.execute("COMMIT")
        finally:
            tamper.close()
        missing_before = (0, 0, 0, 0)

        failed_connection = subject._v2_connection_for_test(projection_path)
        with pytest.raises(subject.ProjectionConflict):
            unexpected_owner = subject._V2ProjectionOwner._borrow_authorities(
                failed_connection,
                evidence=store,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=registry,
                step_hook=None,
            )
        with pytest.raises(sqlite3.ProgrammingError):
            failed_connection.execute("SELECT 1")
        assert store.acceptance_cursor == records[-1].ref.source_sequence
        assert acknowledgements.snapshot().healthy is True
        assert journal._is_bound_to(store) is True

        observed = sqlite3.connect(
            f"{projection_path.as_uri()}?mode=ro&immutable=1",
            uri=True,
        )
        try:
            missing_after = tuple(
                int(observed.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
                for table in (
                    "incidents",
                    "candidates",
                    "candidate_evidence",
                    "candidate_invalidations",
                )
            )
        finally:
            observed.close()
        assert missing_after == missing_before

        fresh_connection = subject._v2_connection_for_test()
        fresh_owner = subject._V2ProjectionOwner._borrow_authorities(
            fresh_connection,
            evidence=store,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=registry,
            step_hook=None,
        )
        assert fresh_owner.status().healthy is True
    finally:
        if fresh_owner is not None:
            fresh_owner.close()
        elif fresh_connection is not None:
            try:
                fresh_connection.close()
            except sqlite3.ProgrammingError:
                pass
        if unexpected_owner is not None:
            unexpected_owner.close()
        elif failed_connection is not None:
            try:
                failed_connection.close()
            except sqlite3.ProgrammingError:
                pass
        if owner is not None:
            owner.close()
        else:
            connection.close()
        if not journal._closed:
            journal.close()
        if not acknowledgements._closed:
            acknowledgements.close()
        if not store._closed:
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
        assignments = ",".join(f"{column}=?" for column in subject._CANDIDATE_COLUMNS)
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
        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_id=?",
                (proof.event_id,),
            ).fetchone()[0]
            == 0
        )
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
        assert connection.execute("SELECT count(*) FROM candidate_evidence").fetchone()[0] == 0

        owner._step_hook = lambda _step: None
        owner.apply(records[2].ref)
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM candidates").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM candidate_evidence").fetchone()[0] == 2
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
                (_ for _ in ()).throw(_Crash("postcommit")) if step == "commit" else None
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
        assert connection.execute("SELECT count(*) FROM candidate_evidence").fetchone()[0] == 2
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
        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_id=?",
                (proof.event_id,),
            ).fetchone()[0]
            == 0
        )
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
        assert (
            connection.execute(
                "SELECT count(*) FROM candidate_evidence WHERE authority_snapshot_event_id=?",
                (proof.event_id,),
            ).fetchone()[0]
            == 1
        )
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
        assignments = ",".join(f"{column}=?" for column in subject._CANDIDATE_COLUMNS)
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
        assert (
            subject._v2_ordered_table_rows(
                recovered_connection,
                "candidate_invalidations",
            )
            == before
        )
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
                raise subject.HistoricalCoverageUnavailable("historical coverage unavailable")

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
    assert (
        connection.execute(
            "SELECT duplicate_of_event_id FROM events WHERE event_id=?",
            (records[2].ref.event_id,),
        ).fetchone()[0]
        == records[1].ref.event_id
    )
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
        assignments = ",".join(f"{column}=?" for column in subject._CANDIDATE_COLUMNS)
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
            "factory cleanup failure" in note for note in getattr(raised.value, "__notes__", ())
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
