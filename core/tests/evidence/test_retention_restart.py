from __future__ import annotations

import hashlib
import importlib
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import ZERO_SHA256, ObserverTrustRootV1
from agmind_immune.correlation.primitives import (
    SpecialUseRegistry,
    load_pinned_special_use_registry,
)
from agmind_immune.evidence import retention as retention_module
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.manifest import (
    SegmentManifestV1,
    segment_manifest_hash,
)
from agmind_immune.evidence.retention import (
    _freeze_retention_fact,
    _freeze_retention_record,
    _freeze_retention_snapshot,
    select_retention,
)
from agmind_immune.evidence.segments import (
    EvidenceCorrupt,
    EvidenceReadOnly,
    EvidenceSealError,
    SegmentStore,
)
from agmind_immune.ingest import envelope as envelope_module
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import EnvelopeVerifier, VerifierCommitError
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.evidence.test_retention import (
    EXPIRED,
    REQUEST_ID,
    _clock,
    _FactSpec,
    _live_store_with_active_routine,
    _manifest,
    _record_outer,
    _retention_proof_case,
)
from tests.evidence.test_retention_unlink import (
    _completed_case,
    _issued_case,
)
from tests.phase5b_helpers import metadata_value, private_key, root_value


def _fresh_verifier() -> EnvelopeVerifier:
    key = private_key(11)
    root = envelope_module.PinnedObserverRoot.from_validated_contract_for_test(
        ObserverTrustRootV1.model_validate(root_value(key), strict=True)
    )
    chain = envelope_module.AnchoredPublicKeyChain.from_value(
        root,
        metadata_value(key),
    )
    return EnvelopeVerifier(root, chain)


@pytest.fixture(autouse=True)
def _fixed_detector_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    authority = importlib.import_module("agmind_immune.correlation.authority")
    monkeypatch.setattr(authority, "_load_pinned_detector_bundle", lambda: "1" * 64)


def _projection_authorities(
    store: SegmentStore,
    *,
    recover: bool = False,
) -> tuple[CorrelationRequestJournal, SpecialUseRegistry]:
    correlation_requests = (
        CorrelationRequestJournal.open_and_recover(store)
        if recover
        else CorrelationRequestJournal.create_new(store)
    )
    registry = load_pinned_special_use_registry(
        Path(__file__).resolve().parents[3] / "contracts/v1/ipv4-special-use.csv"
    )
    return correlation_requests, registry


def test_finalized_retention_run_restarts_with_fresh_verifier(
    tmp_path: Path,
) -> None:
    case, completion = _completed_case(tmp_path)
    try:
        case.store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        expected_last_sequence = case.target_ref.source_sequence
    finally:
        case.coverage.close()
        case.store.close(flush=False)

    fresh_verifier = _fresh_verifier()
    assert fresh_verifier.fsm.last_sequence == 0

    restarted_store = SegmentStore(tmp_path)
    try:
        restarted = AcceptanceCoordinator.open_and_recover(
            fresh_verifier,
            restarted_store,
        )

        assert restarted.verifier is fresh_verifier
        assert restarted.verifier.fsm.last_sequence == expected_last_sequence
        assert restarted_store.status().healthy is True
        with pytest.raises(
            VerifierCommitError,
            match="cannot begin",
        ):
            fresh_verifier._begin_retention_recovery(restarted_store._lifecycle_identity)
        with pytest.raises(
            VerifierCommitError,
            match="recovering verifier authority",
        ):
            fresh_verifier._recover_dense_routine_omission(
                manifest_sha256=ZERO_SHA256,
                first_sequence=expected_last_sequence + 1,
                last_sequence=expected_last_sequence + 1,
                record_count=1,
                lifecycle=restarted_store._lifecycle_identity,
            )
    finally:
        restarted_store.close(flush=False)


def test_missing_payload_without_signed_tombstone_rejects(
    tmp_path: Path,
) -> None:
    _key, _acceptance, store, coverage = _live_store_with_active_routine(tmp_path)
    try:
        store.flush_security_boundary()
        routine_manifest = next(
            manifest for manifest in store._manifests if manifest.evidence_priority == "routine"
        )
        payload_path = tmp_path / routine_manifest.segment_relative_path
    finally:
        coverage.close()
        store.close(flush=False)

    payload_path.unlink()

    restarted_store = SegmentStore(tmp_path)
    try:
        with pytest.raises(EvidenceCorrupt):
            AcceptanceCoordinator.open_and_recover(
                _fresh_verifier(),
                restarted_store,
            )
    finally:
        restarted_store.close(flush=False)


def test_sparse_routine_manifest_is_not_retention_removable() -> None:
    dense = _manifest(
        0,
        _FactSpec(
            EXPIRED,
            2,
            event_types=("falco_connect", "falco_connect"),
        ),
        ZERO_SHA256,
    )
    sparse_value = dense.model_dump(mode="python")
    sparse_value["last_source_sequence"] = dense.last_source_sequence + 1
    sparse_value["last_event_id"] = _record_outer(
        dense.last_source_sequence + 1,
        "falco_connect",
    )[0]
    sparse_value["manifest_sha256"] = ZERO_SHA256
    sparse_value["manifest_sha256"] = segment_manifest_hash(sparse_value)
    sparse = SegmentManifestV1.model_validate(sparse_value, strict=True)
    fact = _freeze_retention_fact(
        manifest=sparse,
        records=tuple(
            _freeze_retention_record(
                event_type="falco_connect",
                evidence_priority="routine",
                source_sequence=sequence,
                event_id=_record_outer(sequence, "falco_connect")[0],
                content_sha256=_record_outer(
                    sequence,
                    "falco_connect",
                )[1],
                frame_size=1,
            )
            for sequence in (
                dense.first_source_sequence,
                dense.last_source_sequence + 1,
            )
        ),
        original_device=100,
        original_inode=1_000,
    )
    snapshot = _freeze_retention_snapshot(
        facts=(fact,),
        clock=_clock(),
        prior_index_through_sequence=0,
    )

    decision = select_retention(snapshot, request_id=REQUEST_ID)

    assert decision.request is None


def test_restart_completed_state_rebuilds_cache_and_clears_state(
    tmp_path: Path,
) -> None:
    case, _completion = _completed_case(tmp_path)
    state_path = tmp_path / "retention-state.json"
    cache_path = tmp_path / "retention-boundary.json"
    completed = case.journal.state
    assert completed is not None
    assert completed.phase == "completed"
    selected_paths = tuple(tmp_path / entry.segment_relative_path for entry in completed.entries)
    expected_head = case.store.status().evidence_head
    expected_target = case.target_ref
    temporary_cache = tmp_path / ".retention-boundary.json.33333333-3333-4333-8333-333333333333.tmp"
    temporary_cache.write_bytes(b'{"partial":')
    temporary_cache.chmod(0o600)
    assert selected_paths
    assert all(not path.exists() for path in selected_paths)
    assert state_path.exists()
    assert not cache_path.exists()
    try:
        case.coverage.close()
    finally:
        case.store.close(flush=False)

    fresh_verifier = _fresh_verifier()
    restarted_store = SegmentStore(tmp_path)
    try:
        restarted = AcceptanceCoordinator.open_and_recover(
            fresh_verifier,
            restarted_store,
        )

        assert restarted.verifier is fresh_verifier
        assert restarted.verifier.fsm.last_sequence == (expected_target.source_sequence)
        assert restarted_store.status().healthy is True
        assert not state_path.exists()
        assert not temporary_cache.exists()
        assert cache_path.exists()
        boundary = retention_module.decode_retention_boundary(cache_path.read_bytes())
        assert boundary.source_evidence_head == expected_head
        assert [
            (
                entry.sequence,
                entry.event_id,
                entry.content_sha256,
                entry.tombstone_id,
            )
            for entry in boundary.tombstones
        ] == [
            (
                expected_target.source_sequence,
                expected_target.event_id,
                expected_target.content_sha256,
                case.request.tombstone_id,
            )
        ]
    finally:
        restarted_store.close(flush=False)


def test_retention_unlink_defers_when_ack_equals_selected_end(
    tmp_path: Path,
) -> None:
    case, capability = _issued_case(
        tmp_path,
        acknowledge=False,
    )
    acknowledgements = AckJournal.create_new(case.store)
    state = case.journal.state
    assert state is not None
    assert state.phase == "evidence_appended"
    selected_paths = tuple(tmp_path / entry.segment_relative_path for entry in state.entries)
    refs = tuple(record.ref for record in case.store.iter_authenticated_records())
    assert [ref.source_sequence for ref in refs] == [1, 2, 3]
    assert selected_paths
    assert all(path.exists() for path in selected_paths)
    try:
        for ref in refs[:2]:
            acknowledgements.record_pending(ref)
            acknowledgements.record_confirmed(ref)
        assert acknowledgements.snapshot().confirmed_through == 2
        assert acknowledgements.snapshot().pending is None

        with pytest.raises(EvidenceSealError, match="ACK|ack"):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )

        durable = case.journal.state
        assert durable is not None
        assert durable.phase == "evidence_appended"
        assert all(path.exists() for path in selected_paths)
    finally:
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)


def test_retention_unlink_permits_ack_strictly_after_selected_end(
    tmp_path: Path,
) -> None:
    case, capability = _issued_case(
        tmp_path,
        acknowledge=False,
    )
    acknowledgements = AckJournal.create_new(case.store)
    state = case.journal.state
    assert state is not None
    selected_paths = tuple(tmp_path / entry.segment_relative_path for entry in state.entries)
    refs = tuple(record.ref for record in case.store.iter_authenticated_records())
    assert [ref.source_sequence for ref in refs] == [1, 2, 3]
    try:
        for ref in refs:
            acknowledgements.record_pending(ref)
            acknowledgements.record_confirmed(ref)
        assert acknowledgements.snapshot().confirmed_through == 3
        assert acknowledgements.snapshot().pending is None

        case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )

        durable = case.journal.state
        assert durable is not None
        assert durable.phase == "completed"
        assert all(not path.exists() for path in selected_paths)
    finally:
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)


def test_authenticated_retention_rebuild_projects_survivors_and_reopens(
    tmp_path: Path,
) -> None:
    projection = importlib.import_module("agmind_immune.evidence.projection")
    evidence_path = tmp_path / "evidence"
    projection_path = tmp_path / "projection.sqlite3"
    acknowledgements: AckJournal | None = None
    correlation_requests: CorrelationRequestJournal | None = None
    registry: SpecialUseRegistry | None = None
    cache = None

    def open_projection_before_retention(store: SegmentStore) -> None:
        nonlocal acknowledgements, correlation_requests, registry, cache
        acknowledgements = AckJournal.create_new(store)
        correlation_requests, registry = _projection_authorities(store)
        refs = tuple(record.ref for record in store.iter_authenticated_records())
        for ref in refs:
            acknowledgements.record_pending(ref)
            acknowledgements.record_confirmed(ref)
        cache = projection.ProjectionStore.open(
            projection_path,
            evidence=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation_requests,
            registry=registry,
        )
        for ref in refs:
            cache.apply(ref)

    case = _retention_proof_case(
        evidence_path,
        acknowledge=False,
        before_retention_prepare=open_projection_before_retention,
    )
    capability = case.store._authenticate_retention_tombstone(
        case.journal,
        case.final_snapshot,
        case.target_ref,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    assert type(acknowledgements) is AckJournal
    assert type(correlation_requests) is CorrelationRequestJournal
    assert type(registry) is SpecialUseRegistry
    assert cache is not None
    reopened = None
    try:
        refs = tuple(record.ref for record in case.store.iter_authenticated_records())
        assert [ref.source_sequence for ref in refs] == [1, 2, 3]
        for ref in refs[2:]:
            acknowledgements.record_pending(ref)
            acknowledgements.record_confirmed(ref)
        confirmed_before = acknowledgements.snapshot()

        with closing(sqlite3.connect(projection_path)) as connection:
            assert connection.execute(
                "SELECT source_sequence FROM events ORDER BY source_sequence"
            ).fetchall() == [
                (projection._uint64(1),),
                (projection._uint64(2),),
            ]
            assert connection.execute("SELECT count(*) FROM network_observations").fetchone() == (
                1,
            )

        completion = case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        assert [
            record.ref.source_sequence for record in case.store.iter_authenticated_records()
        ] == [1, 3]

        cache._rebuild_after_authenticated_retention(
            completion,
            _factory=projection._RETENTION_REBUILD_FACTORY,
        )

        assert acknowledgements.snapshot() == confirmed_before
        assert cache.status().cursor is not None
        assert cache.status().cursor.source_sequence == 3
        with closing(sqlite3.connect(projection_path)) as connection:
            assert connection.execute(
                "SELECT source_sequence FROM events ORDER BY source_sequence"
            ).fetchall() == [
                (projection._uint64(1),),
                (projection._uint64(3),),
            ]
            assert connection.execute("SELECT count(*) FROM projection_dedup").fetchone() == (2,)
            assert connection.execute("SELECT count(*) FROM network_observations").fetchone() == (
                0,
            )

        case.store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        cache.close()
        cache = None
        reopened = projection.ProjectionStore.open(
            projection_path,
            evidence=case.store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation_requests,
            registry=registry,
        )
        reopened_status = reopened.status()
        assert reopened_status.healthy is True
        assert reopened_status.cursor is not None
        assert reopened_status.cursor.source_sequence == 3
        assert acknowledgements.snapshot() == confirmed_before
    finally:
        if reopened is not None:
            reopened.close()
        if cache is not None:
            cache.close()
        correlation_requests.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)


def test_projection_open_rejects_stale_v2_retention_crash_window_without_repair(
    tmp_path: Path,
) -> None:
    projection = importlib.import_module("agmind_immune.evidence.projection")
    evidence_path = tmp_path / "evidence"
    projection_path = tmp_path / "projection.sqlite3"
    acknowledgements: AckJournal | None = None
    correlation_requests: CorrelationRequestJournal | None = None
    registry: SpecialUseRegistry | None = None
    cache = None

    def open_projection_before_retention(store: SegmentStore) -> None:
        nonlocal acknowledgements, correlation_requests, registry, cache
        acknowledgements = AckJournal.create_new(store)
        correlation_requests, registry = _projection_authorities(store)
        refs = tuple(record.ref for record in store.iter_authenticated_records())
        for ref in refs:
            acknowledgements.record_pending(ref)
            acknowledgements.record_confirmed(ref)
        cache = projection.ProjectionStore.open(
            projection_path,
            evidence=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation_requests,
            registry=registry,
        )
        for ref in refs:
            cache.apply(ref)

    case = _retention_proof_case(
        evidence_path,
        acknowledge=False,
        before_retention_prepare=open_projection_before_retention,
    )
    capability = case.store._authenticate_retention_tombstone(
        case.journal,
        case.final_snapshot,
        case.target_ref,
        _factory=segments_module._RETENTION_PROOF_FACTORY,
    )
    assert type(acknowledgements) is AckJournal
    assert type(correlation_requests) is CorrelationRequestJournal
    assert type(registry) is SpecialUseRegistry
    assert cache is not None
    try:
        refs = tuple(record.ref for record in case.store.iter_authenticated_records())
        for ref in refs[2:]:
            acknowledgements.record_pending(ref)
            acknowledgements.record_confirmed(ref)
        case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        cache.close()
        cache = None
    finally:
        if cache is not None:
            cache.close()
        correlation_requests.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)

    restarted_store = SegmentStore(evidence_path)
    restarted_acknowledgements = None
    restarted_correlation = None
    try:
        AcceptanceCoordinator.open_and_recover(
            _fresh_verifier(),
            restarted_store,
        )
        restarted_acknowledgements = AckJournal.open_and_recover(restarted_store)
        restarted_correlation, restarted_registry = _projection_authorities(
            restarted_store,
            recover=True,
        )
        before_info = projection_path.stat()
        before_bytes = projection_path.read_bytes()
        before_files = {
            entry.name: (
                entry.stat().st_dev,
                entry.stat().st_ino,
                entry.stat().st_size,
            )
            for entry in projection_path.parent.iterdir()
            if entry.is_file()
        }

        with pytest.raises(projection.ProjectionAuthorityError):
            projection.ProjectionStore.open(
                projection_path,
                evidence=restarted_store,
                acknowledgements=restarted_acknowledgements,
                correlation_requests=restarted_correlation,
                registry=restarted_registry,
            )

        after_info = projection_path.stat()
        assert (
            after_info.st_dev,
            after_info.st_ino,
            after_info.st_size,
        ) == (
            before_info.st_dev,
            before_info.st_ino,
            before_info.st_size,
        )
        assert projection_path.read_bytes() == before_bytes
        assert {
            entry.name: (
                entry.stat().st_dev,
                entry.stat().st_ino,
                entry.stat().st_size,
            )
            for entry in projection_path.parent.iterdir()
            if entry.is_file()
        } == before_files
        assert restarted_store.status().healthy is True
        assert restarted_acknowledgements.snapshot().healthy is True
        assert restarted_correlation._is_bound_to(restarted_store) is True
    finally:
        if restarted_correlation is not None:
            restarted_correlation.close()
        if restarted_acknowledgements is not None:
            restarted_acknowledgements.close()
        restarted_store.close(flush=False)


def test_authenticated_rebuild_repairs_retired_projection_cursor_before_reopen(
    tmp_path: Path,
) -> None:
    from tests.evidence.test_projection import (
        _retention_case_with_surviving_falco,
    )

    projection = importlib.import_module("agmind_immune.evidence.projection")
    case_path = tmp_path / "retired-cursor"
    evidence_path = case_path / "evidence"
    projection_path = case_path / "projection.sqlite3"
    raw_hash = hashlib.sha256(b"survivor after retired cursor").hexdigest()
    (
        case,
        capability,
        acknowledgements,
        correlation_requests,
        _registry,
        refs,
        cache,
    ) = _retention_case_with_surviving_falco(
        evidence_path,
        raw_hash=raw_hash,
    )
    try:
        assert [ref.source_sequence for ref in refs] == [1, 2, 3, 4]
        status = cache.status()
        assert status.cursor is not None
        assert status.cursor.source_sequence == 2

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
        acknowledgements.record_pending(refs[3])
        acknowledgements.record_confirmed(refs[3])
        cache.apply(refs[3])
        cache.close()
        cache = None
    finally:
        if cache is not None:
            cache.close()
        correlation_requests.close()
        acknowledgements.close()
        case.coverage.close()
        case.store.close(flush=False)

    restarted_store = SegmentStore(evidence_path)
    restarted_acknowledgements = None
    restarted_correlation = None
    restarted_projection = None
    try:
        AcceptanceCoordinator.open_and_recover(
            _fresh_verifier(),
            restarted_store,
        )
        restarted_acknowledgements = AckJournal.open_and_recover(restarted_store)
        restarted_correlation, restarted_registry = _projection_authorities(
            restarted_store,
            recover=True,
        )
        restarted_projection = projection.ProjectionStore.open(
            projection_path,
            evidence=restarted_store,
            acknowledgements=restarted_acknowledgements,
            correlation_requests=restarted_correlation,
            registry=restarted_registry,
        )

        status = restarted_projection.status()
        assert status.healthy is True
        assert status.cursor is not None
        assert status.cursor.source_sequence == 4
        with closing(sqlite3.connect(projection_path)) as connection:
            assert connection.execute(
                "SELECT source_sequence FROM events ORDER BY source_sequence"
            ).fetchall() == [
                (projection._uint64(1),),
                (projection._uint64(3),),
                (projection._uint64(4),),
            ]
    finally:
        if restarted_projection is not None:
            restarted_projection.close()
        if restarted_correlation is not None:
            restarted_correlation.close()
        if restarted_acknowledgements is not None:
            restarted_acknowledgements.close()
        restarted_store.close(flush=False)


def test_restart_evidence_appended_with_ack_lag_is_ready_and_pending(
    tmp_path: Path,
) -> None:
    case, _capability = _issued_case(
        tmp_path,
        acknowledge=False,
    )
    acknowledgements = AckJournal.create_new(case.store)
    refs = tuple(record.ref for record in case.store.iter_authenticated_records())
    for ref in refs[:2]:
        acknowledgements.record_pending(ref)
        acknowledgements.record_confirmed(ref)
    state = case.journal.state
    assert state is not None
    assert state.phase == "evidence_appended"
    selected_paths = tuple(tmp_path / entry.segment_relative_path for entry in state.entries)
    ack_snapshot = acknowledgements.snapshot()
    assert ack_snapshot.confirmed_through == 2
    assert ack_snapshot.pending is None
    assert case.target_ref.source_sequence == 3
    expected_target = case.target_ref
    assert selected_paths
    assert all(path.exists() for path in selected_paths)
    try:
        case.coverage.close()
    finally:
        case.store.close(flush=False)

    fresh_verifier = _fresh_verifier()
    restarted_store = SegmentStore(tmp_path)
    try:
        restarted = AcceptanceCoordinator.open_and_recover(
            fresh_verifier,
            restarted_store,
        )

        assert restarted.verifier is fresh_verifier
        assert restarted.verifier.fsm.last_sequence == (expected_target.source_sequence)
        status = restarted_store.status()
        assert status.healthy is True
        assert status.retention_pending is True
        assert all(path.exists() for path in selected_paths)
        state_path = tmp_path / "retention-state.json"
        assert state_path.exists()
        durable = retention_module.decode_retention_state(state_path.read_bytes())
        assert durable.phase == "evidence_appended"
        assert fresh_verifier.accepted_ref(2) is not None
    finally:
        restarted_store.close(flush=False)


def test_restart_in_progress_with_payload_present_finishes_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case, capability = _issued_case(tmp_path)
    journal_type = type(case.journal)
    original_prove = journal_type._prove_publication
    binding = case.store._authenticated_retention_tombstone
    assert binding is not None
    in_progress_raw = binding.unlink_in_progress_state_raw

    def crash_after_in_progress_publication(
        owner: object,
        expected: bytes | None,
    ) -> None:
        original_prove(owner, expected)
        if expected == in_progress_raw:
            raise EvidenceSealError("injected crash after durable retention unlink intent")

    with monkeypatch.context() as crash_cut:
        crash_cut.setattr(
            journal_type,
            "_prove_publication",
            crash_after_in_progress_publication,
        )
        with pytest.raises(EvidenceSealError, match="injected crash"):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )

    state_path = tmp_path / "retention-state.json"
    in_progress = retention_module.decode_retention_state(state_path.read_bytes())
    assert in_progress.phase == "retention_unlink_in_progress"
    selected_paths = tuple(tmp_path / entry.segment_relative_path for entry in in_progress.entries)
    expected_target = case.target_ref
    assert selected_paths
    assert all(path.exists() for path in selected_paths)
    assert state_path.exists()
    assert not (tmp_path / "retention-boundary.json").exists()
    try:
        case.coverage.close()
    finally:
        case.store.close(flush=False)

    fresh_verifier = _fresh_verifier()
    restarted_store = SegmentStore(tmp_path)
    try:
        restarted = AcceptanceCoordinator.open_and_recover(
            fresh_verifier,
            restarted_store,
        )

        assert restarted.verifier is fresh_verifier
        assert restarted.verifier.fsm.last_sequence == (expected_target.source_sequence)
        assert restarted_store.status().healthy is True
        assert all(not path.exists() for path in selected_paths)
        assert not (tmp_path / "retention-state.json").exists()
        boundary = retention_module.decode_retention_boundary(
            (tmp_path / "retention-boundary.json").read_bytes()
        )
        assert [entry.sequence for entry in boundary.tombstones] == [
            expected_target.source_sequence
        ]
    finally:
        restarted_store.close(flush=False)


def test_restart_in_progress_rejects_ack_rollback_to_selected_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case, capability = _issued_case(
        tmp_path,
        acknowledge=False,
    )
    acknowledgements = AckJournal.create_new(case.store)
    refs = tuple(record.ref for record in case.store.iter_authenticated_records())
    assert [ref.source_sequence for ref in refs] == [1, 2, 3]
    for ref in refs[:2]:
        acknowledgements.record_pending(ref)
        acknowledgements.record_confirmed(ref)
    ack_rollback = {
        name: (tmp_path / name).read_bytes() for name in ("ack-commitment.json", "ack-journal.agf")
    }
    acknowledgements.record_pending(refs[2])
    acknowledgements.record_confirmed(refs[2])

    binding = case.store._authenticated_retention_tombstone
    assert binding is not None
    in_progress_raw = binding.unlink_in_progress_state_raw
    journal_type = type(case.journal)
    original_prove = journal_type._prove_publication

    def crash_after_in_progress_publication(
        owner: object,
        expected: bytes | None,
    ) -> None:
        original_prove(owner, expected)
        if expected == in_progress_raw:
            raise EvidenceSealError("injected crash after durable retention unlink intent")

    with monkeypatch.context() as crash_cut:
        crash_cut.setattr(
            journal_type,
            "_prove_publication",
            crash_after_in_progress_publication,
        )
        with pytest.raises(EvidenceSealError, match="injected crash"):
            case.store._execute_authenticated_retention_unlink(
                capability,
                _factory=segments_module._RETENTION_PROOF_FACTORY,
            )

    in_progress = retention_module.decode_retention_state(
        (tmp_path / "retention-state.json").read_bytes()
    )
    assert in_progress.phase == "retention_unlink_in_progress"
    selected_paths = tuple(tmp_path / entry.segment_relative_path for entry in in_progress.entries)
    assert selected_paths
    assert all(path.exists() for path in selected_paths)
    acknowledgements.close()
    case.coverage.close()
    case.store.close(flush=False)
    for name, raw in ack_rollback.items():
        (tmp_path / name).write_bytes(raw)

    restarted_store = SegmentStore(tmp_path)
    try:
        with pytest.raises(
            EvidenceCorrupt,
            match="retention|ACK|authenticated",
        ):
            AcceptanceCoordinator.open_and_recover(
                _fresh_verifier(),
                restarted_store,
            )

        assert all(path.exists() for path in selected_paths)
        durable = retention_module.decode_retention_state(
            (tmp_path / "retention-state.json").read_bytes()
        )
        assert durable.phase == "retention_unlink_in_progress"
        assert restarted_store.status().healthy is False
    finally:
        restarted_store.close(flush=False)


def test_restart_completed_state_with_selected_payload_present_rejects(
    tmp_path: Path,
) -> None:
    case, capability = _issued_case(tmp_path)
    issued = case.journal.state
    assert issued is not None
    selected_payloads = tuple(
        (
            tmp_path / entry.segment_relative_path,
            (tmp_path / entry.segment_relative_path).read_bytes(),
            (tmp_path / entry.segment_relative_path).stat().st_mode & 0o777,
        )
        for entry in issued.entries
    )
    assert selected_payloads
    try:
        case.store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        completed = case.journal.state
        assert completed is not None
        assert completed.phase == "completed"
        assert all(not path.exists() for path, _raw, _mode in selected_payloads)
        restored_path, restored_raw, restored_mode = selected_payloads[0]
        restored_path.write_bytes(restored_raw)
        restored_path.chmod(restored_mode)
    finally:
        case.coverage.close()
        case.store.close(flush=False)

    state_path = tmp_path / "retention-state.json"
    cache_path = tmp_path / "retention-boundary.json"
    fresh_verifier = _fresh_verifier()
    restarted_store = SegmentStore(tmp_path)
    try:
        with pytest.raises(EvidenceCorrupt, match="retention|completed|present"):
            AcceptanceCoordinator.open_and_recover(
                fresh_verifier,
                restarted_store,
            )

        assert state_path.exists()
        assert not cache_path.exists()
        assert restarted_store.status().healthy is False
    finally:
        restarted_store.close(flush=False)


@pytest.mark.parametrize(
    "artifact_name",
    [
        "retention-state.json",
        "retention-boundary.json",
    ],
)
def test_create_empty_rejects_retention_artifact_bearing_root(
    tmp_path: Path,
    artifact_name: str,
) -> None:
    pristine = SegmentStore(tmp_path)
    pristine.close(flush=False)
    artifact = tmp_path / artifact_name
    artifact.write_bytes(b"{}")
    artifact.chmod(0o600)

    store = SegmentStore(tmp_path)
    try:
        with pytest.raises(
            EvidenceReadOnly,
            match="nonempty evidence requires authenticated open-and-recover",
        ):
            AcceptanceCoordinator.create_empty(
                _fresh_verifier(),
                store,
            )

        assert store.status().healthy is False
        assert artifact.exists()
    finally:
        store.close(flush=False)


def test_restart_selected_state_naming_stale_manifests_rejects(
    tmp_path: Path,
) -> None:
    case, _capability = _issued_case(tmp_path)
    state = case.journal.state
    assert state is not None
    state_value = state.model_dump(mode="python", exclude_none=False)
    entries = state_value["entries"]
    request = state_value["request"]
    assert isinstance(entries, list)
    assert isinstance(request, dict)
    stale_hashes = [
        hashlib.sha256(f"stale-manifest-{index}".encode()).hexdigest()
        for index, _entry in enumerate(entries)
    ]
    assert stale_hashes
    for entry, stale_hash in zip(entries, stale_hashes, strict=True):
        assert isinstance(entry, dict)
        entry["manifest_sha256"] = stale_hash
    request["removed_manifest_hashes"] = stale_hashes
    request["first_removed_manifest_sha256"] = stale_hashes[0]
    request["last_removed_manifest_sha256"] = stale_hashes[-1]
    request["manifest_run_sha256"] = hashlib.sha256(
        b"AGMIND_RETENTION_RUN_V2\x00" + canonical_json(stale_hashes)
    ).hexdigest()
    state_value["phase"] = "selected"
    state_value["target"] = None
    stale_state = retention_module.RetentionStateV1.model_validate(
        state_value,
        strict=True,
    )
    stale_raw = retention_module.encode_retention_state(stale_state)
    try:
        case.coverage.close()
    finally:
        case.store.close(flush=False)
    state_path = tmp_path / "retention-state.json"
    state_path.write_bytes(stale_raw)
    state_path.chmod(0o600)

    restarted_store = SegmentStore(tmp_path)
    try:
        with pytest.raises(
            EvidenceCorrupt,
            match="unknown manifest",
        ):
            AcceptanceCoordinator.open_and_recover(
                _fresh_verifier(),
                restarted_store,
            )

        assert state_path.read_bytes() == stale_raw
        assert restarted_store.status().healthy is False
    finally:
        restarted_store.close(flush=False)


def test_restart_target_bound_to_conflicting_authenticated_event_rejects(
    tmp_path: Path,
) -> None:
    case, _capability = _issued_case(tmp_path)
    state = case.journal.state
    assert state is not None
    conflicting_ref = next(
        record.ref
        for record in case.store.iter_records()
        if record.ref.source_sequence < case.target_ref.source_sequence
        and record.envelope["event_type"] != "retention_tombstone"
    )
    state_value = state.model_dump(mode="python", exclude_none=False)
    state_value["phase"] = "target_bound"
    state_value["target"] = {
        "sequence": conflicting_ref.source_sequence,
        "event_id": conflicting_ref.event_id,
        "content_sha256": conflicting_ref.content_sha256,
    }
    conflicting_state = retention_module.RetentionStateV1.model_validate(
        state_value,
        strict=True,
    )
    conflicting_raw = retention_module.encode_retention_state(conflicting_state)
    try:
        case.coverage.close()
    finally:
        case.store.close(flush=False)
    state_path = tmp_path / "retention-state.json"
    state_path.write_bytes(conflicting_raw)
    state_path.chmod(0o600)

    restarted_store = SegmentStore(tmp_path)
    try:
        with pytest.raises(
            EvidenceCorrupt,
            match="target-bound retention state conflicts with evidence",
        ):
            AcceptanceCoordinator.open_and_recover(
                _fresh_verifier(),
                restarted_store,
            )

        assert state_path.read_bytes() == conflicting_raw
        assert restarted_store.status().healthy is False
    finally:
        restarted_store.close(flush=False)


def test_restart_unlink_rejects_canonical_date_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case, _capability = _issued_case(tmp_path)
    state = case.journal.state
    assert state is not None
    assert state.phase == "evidence_appended"
    assert state.entries
    binding = case.store._authenticated_retention_tombstone
    assert binding is not None
    case.journal._transition(
        retention_module.decode_retention_state(binding.unlink_in_progress_state_raw)
    )
    selected_entry = state.entries[0]
    _, date_name, selected_name = selected_entry.segment_relative_path.split("/")
    state_path = tmp_path / "retention-state.json"
    try:
        case.coverage.close()
    finally:
        case.store.close(flush=False)

    restarted_store = SegmentStore(tmp_path)
    canonical_date = tmp_path / "segments" / date_name
    displaced_date = tmp_path / "segments" / f".{date_name}.displaced"
    original_unlink = segments_module.os.unlink
    swapped = False

    def swap_directory_before_unlink(
        path: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        if not swapped and path == selected_name and dir_fd is not None:
            canonical_date.rename(displaced_date)
            canonical_date.mkdir(mode=0o700)
            for source in displaced_date.iterdir():
                if source.is_file():
                    replacement = canonical_date / source.name
                    replacement.write_bytes(source.read_bytes())
                    replacement.chmod(source.stat().st_mode & 0o777)
            swapped = True
        original_unlink(path, dir_fd=dir_fd)

    with monkeypatch.context() as attack:
        attack.setattr(
            segments_module.os,
            "unlink",
            swap_directory_before_unlink,
        )
        with pytest.raises(
            EvidenceCorrupt,
            match="retention date directory changed",
        ):
            AcceptanceCoordinator.open_and_recover(
                _fresh_verifier(),
                restarted_store,
            )

    try:
        assert swapped is True
        assert state_path.exists()
        durable = retention_module.decode_retention_state(state_path.read_bytes())
        assert durable.phase == "retention_commit_uncertain"
        assert restarted_store.status().healthy is False
    finally:
        restarted_store.close(flush=False)
