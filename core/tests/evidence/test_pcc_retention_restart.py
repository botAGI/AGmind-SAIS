from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from agmind_immune.contracts import (
    PCCCorrelationSnapshotRequestV1,
    RetentionTombstoneV2,
)
from agmind_immune.coverage import CoverageState
from agmind_immune.evidence import retention as retention_module
from agmind_immune.evidence import segments as segments_module
from agmind_immune.evidence.retention import (
    RetentionTargetV1,
    select_retention,
)
from agmind_immune.evidence.segments import (
    EvidenceCorrupt,
    EvidenceRef,
    SegmentStore,
)
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.envelope import CoreEventV1
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.evidence.test_retention import REQUEST_ID, _proof_clock
from tests.evidence.test_retention_restart import _fresh_verifier
from tests.ingest.test_pcc_correlation_snapshot import (
    _accept,
    _candidate_trigger,
    _coordinator,
    _failed_snapshot,
    _item,
    _request,
    _snapshot_envelope,
)
from tests.phase5b_helpers import boot_boundary, envelope_value, private_key


@dataclass(frozen=True)
class _PCCRetentionCase:
    item: CoreEventV1
    request: PCCCorrelationSnapshotRequestV1
    ref: EvidenceRef
    trigger_ref: EvidenceRef
    trigger_payload: Path
    last_sequence: int


def _build_pcc_retention_case(
    path: Path,
    *,
    finalize_retention: bool,
) -> _PCCRetentionCase:
    key = private_key(11)
    acceptance = _coordinator(path, key)
    store = acceptance.segment_store
    coverage: CoverageState | None = None
    acknowledgements: AckJournal | None = None
    try:
        _accept(acceptance, boot_boundary(key))
        coverage = CoverageState.open_and_recover(store)
        store.flush_security_boundary()

        trigger = _candidate_trigger(key)
        trigger_ref = cast(EvidenceRef, _accept(acceptance, trigger))
        coverage._apply_live_accepted(store, trigger_ref, None)
        request = _request(trigger)
        item = cast(
            CoreEventV1,
            _item(
                _snapshot_envelope(
                    key,
                    _failed_snapshot(trigger, request),
                )
            ),
        )
        pcc_ref = acceptance.accept_pcc(item, request)
        coverage._apply_live_accepted(store, pcc_ref, None)

        routine_manifest = next(
            manifest
            for manifest in store.manifests
            if (
                manifest.evidence_priority == "routine"
                and manifest.first_source_sequence
                <= trigger_ref.source_sequence
                <= manifest.last_source_sequence
            )
        )
        trigger_payload = path / routine_manifest.segment_relative_path
        store.flush_security_boundary()

        acknowledgements = AckJournal.create_new(store)
        for ref in store.authenticated_refs(
            after_sequence=0,
            through_sequence=pcc_ref.source_sequence,
            limit=100,
        ):
            acknowledgements.record_pending(ref)
            acknowledgements.record_confirmed(ref)

        if not finalize_retention:
            return _PCCRetentionCase(
                item=item,
                request=request,
                ref=pcc_ref,
                trigger_ref=trigger_ref,
                trigger_payload=trigger_payload,
                last_sequence=pcc_ref.source_sequence,
            )

        selected_snapshot = store._freeze_retention_snapshot(
            _proof_clock(),
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        decision = select_retention(
            selected_snapshot,
            request_id=REQUEST_ID,
        )
        assert type(decision.request) is RetentionTombstoneV2
        assert decision.request.removed_manifest_hashes == [
            routine_manifest.manifest_sha256
        ]
        assert (
            routine_manifest.first_source_sequence
            == routine_manifest.last_source_sequence
            == trigger_ref.source_sequence
        )
        journal = retention_module._open_retention_state_journal(store)
        journal.prepare_publication(decision)

        target_item = cast(
            CoreEventV1,
            _item(
                envelope_value(
                    key,
                    sequence=4,
                    event_type="retention_tombstone",
                    normalized_fields=decision.request.model_dump(
                        mode="python"
                    ),
                )
            ),
        )
        target_ref = acceptance.accept(target_item)
        coverage._apply_live_accepted(store, target_ref, None)
        acknowledgements.record_pending(target_ref)
        acknowledgements.record_confirmed(target_ref)

        target = RetentionTargetV1(
            sequence=target_item.sequence,
            event_id=target_item.event_id,
            content_sha256=target_item.content_sha256,
        )
        journal.bind_target(target)
        journal.advance_evidence_appended(target)
        final_snapshot = store._freeze_retention_snapshot(
            _proof_clock(seconds=1),
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        capability = store._authenticate_retention_tombstone(
            journal,
            final_snapshot,
            target_ref,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        completion = store._execute_authenticated_retention_unlink(
            capability,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        store._finalize_authenticated_retention_completion(
            completion,
            _factory=segments_module._RETENTION_PROOF_FACTORY,
        )
        store.flush_security_boundary()
        return _PCCRetentionCase(
            item=item,
            request=request,
            ref=pcc_ref,
            trigger_ref=trigger_ref,
            trigger_payload=trigger_payload,
            last_sequence=target_ref.source_sequence,
        )
    finally:
        try:
            if acknowledgements is not None:
                acknowledgements.close()
        finally:
            try:
                if coverage is not None:
                    coverage.close()
            finally:
                store.close(flush=False)


def test_retired_pcc_trigger_restarts_without_fabricated_trigger(
    tmp_path: Path,
) -> None:
    case = _build_pcc_retention_case(
        tmp_path,
        finalize_retention=True,
    )
    assert not case.trigger_payload.exists()

    verifier = _fresh_verifier()
    store = SegmentStore(tmp_path)
    try:
        recovered = AcceptanceCoordinator.open_and_recover(
            verifier,
            store,
        )

        assert recovered.verifier.fsm.last_sequence == case.last_sequence
        assert (
            recovered.verifier.accepted_ref(
                case.trigger_ref.source_sequence
            )
            is None
        )
        assert (
            recovered.verifier.accepted_ref(case.ref.source_sequence)
            == case.ref
        )
        assert recovered.accept_pcc(
            case.item,
            case.request,
        ) == case.ref
        capability = recovered.authenticated_pcc_input(
            case.ref,
            case.request,
        )
        assert capability.evidence_ref == case.ref
        assert capability.snapshot.trigger.source_sequence == (
            case.trigger_ref.source_sequence
        )
        assert all(
            record.ref.source_sequence
            != case.trigger_ref.source_sequence
            for record in store.iter_authenticated_records()
        )
        assert store.status().healthy is True
    finally:
        store.close(flush=False)


def test_uncovered_missing_trigger_never_promotes_deferred_pcc(
    tmp_path: Path,
) -> None:
    case = _build_pcc_retention_case(
        tmp_path,
        finalize_retention=False,
    )
    case.trigger_payload.unlink()

    verifier = _fresh_verifier()
    store = SegmentStore(tmp_path)
    try:
        with pytest.raises(EvidenceCorrupt):
            AcceptanceCoordinator.open_and_recover(
                verifier,
                store,
            )

        assert verifier.accepted_ref(case.ref.source_sequence) is None
        assert store.status().healthy is False
    finally:
        store.close(flush=False)
