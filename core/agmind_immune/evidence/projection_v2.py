"""Dormant Projection V2 schema identity and strict persisted-fact codecs."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
from _thread import LockType
from _thread import RLock as RLockType
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from threading import Condition, Lock, RLock
from typing import Never, SupportsIndex, cast, final

from pydantic import ValidationError

from agmind_immune.canonicaljson import candidate_facts_sha256, canonical_json
from agmind_immune.contracts import (
    MAX_UINT64,
    CoverageEventV1,
    EventEnvelopeV1,
    FalcoConnectV1,
    decode_strict,
)
from agmind_immune.correlation.authority import (
    _AUTHORITY_REPLACEMENT_FACTORY,
    CorrelationProjectionAuthority,
    _advance_correlation_projection_authority,
    _capture_correlation_replay_locked,
    _close_correlation_projection_authority,
    _commit_correlation_projection_authority_replacement,
    _correlation_projection_snapshot_gate,
    _CorrelationReplaySnapshot,
    _create_correlation_projection_authority,
    _fail_closed_correlation_projection_authority_replacement,
    _issue_correlation_context,
    _prepare_correlation_projection_authority_replacement,
    _PreparedProjectionAuthorityReplacement,
    _ProjectionAuthorityBinding,
    _ProjectionPredecessor,
    _rebuild_correlation_projection_authority,
    _revalidate_correlation_replay_locked,
    _same_exact_pcc,
    _seal_projection_predecessor,
    _validate_correlation_projection_predecessor,
)
from agmind_immune.correlation.pcc import (
    ActiveCandidateObservation,
    CandidateCreated,
    CandidateDuplicateKey,
    CorrelationContext,
    CorrelationProjectionError,
    Duplicate,
    HistoricalCoverageAssessment,
    InvestigationOnly,
    Rejected,
    _correlate_frozen_pcc,
    _duplicate_key,
    _freeze_replay_pcc_seed,
    _FrozenPCCCorrelationInput,
    _incident_from_frozen_falco,
    _rebind_frozen_pcc_projection_context,
    _validate_frozen_pcc_correlation_input,
    correlate_pcc,
    incident_from_verified_falco,
)
from agmind_immune.correlation.primitives import SpecialUseRegistry
from agmind_immune.coverage.historical import (
    HistoricalCoverageConflict,
    HistoricalCoverageUnavailable,
    _build_frozen_replay_entries,
    _build_replay_memo_leaf,
    _build_replay_pcc_leaf,
    _FrozenReplayEntry,
    _HistoricalReductionResult,
    _issue_historical_path_authority,
    _late_coverage_invalidates_candidate,
    _late_coverage_invalidates_candidate_values,
    _late_coverage_may_invalidate_candidate,
    _prepare_historical_record,
    _reduce_historical_coverage_result,
    _replay_compact_digest,
    _replay_exact_fact,
    _ReplayMemoLeaf,
    _ReplayPCCLeaf,
    derive_historical_coverage,
)
from agmind_immune.evidence.dedup import _logical_primary_identity_v2
from agmind_immune.evidence.frames import JournalCorrupt, decode_frames
from agmind_immune.evidence.projection import (
    ProjectionApplyResult,
    ProjectionAuthorityError,
    ProjectionConflict,
    ProjectionCursor,
    ProjectionStatus,
    ProjectionUnhealthy,
    ProjectionValidationError,
)
from agmind_immune.evidence.retention import (
    AuthenticatedRetentionUnlinkCompletion,
)
from agmind_immune.evidence.segments import (
    MAX_EVIDENCE_RECORD_BYTES,
    MAX_SEGMENT_BYTES,
    EvidencePriority,
    EvidenceRef,
    EvidenceStatus,
    EvidenceStoreError,
    SegmentStore,
    StoredEvidenceRecord,
    _AcceptedEnvelopeRecordV1,
    _AuthenticatedRetentionReplayGate,
    _AuthenticatedRetentionReplayScope,
    _close_replay_source_snapshot,
    _exact_coverage_record_key,
    _exact_coverage_ref_key,
    _ReplayRecordDescriptor,
    _ReplaySegmentDescriptor,
    _ReplaySourceSnapshot,
    _RetentionAcceptedAuthorityBinding,
    _RetentionAcceptedEnvelopeBinding,
)
from agmind_immune.incidents.models import ContainmentCandidateV1, IncidentV1
from agmind_immune.ingest.ack_journal import (
    _ACK_UNPUBLISHED_ANCHOR_FACTORY,
    AckIdentity,
    AckJournal,
    AckJournalError,
    AckJournalSnapshot,
    _AckJournalRecordV1,
    _AckReplaySnapshot,
    _AckUnpublishedAnchor,
    _close_replay_ack_snapshot,
)
from agmind_immune.ingest.ack_journal import (
    _MAX_RECORD_BYTES as _MAX_ACK_RECORD_BYTES,
)
from agmind_immune.ingest.correlation_journal import (
    CorrelationRequestJournal,
    CorrelationRequestJournalError,
    _capture_correlation_journal_replay_locked,
    _correlation_journal_replay_gate,
    _CorrelationJournalReplaySnapshot,
    _evaluate_completed_snapshot_batch,
    _revalidate_completed_snapshot,
    _revalidate_correlation_journal_replay_locked,
)
from agmind_immune.ingest.envelope import AuthenticatedPCCInput

_SCHEMA_V2_PATH = Path(__file__).with_name("schema.sql")
_SCHEMA_V2_SHA256 = "d4a5d563ca3964cbe4ed276882a4b4def95fb756fc67a6777fddf5de38b1619d"
_SCHEMA_META_V2 = {
    "schema_version": "agmind.projection-schema.v2",
    "reducer_version": "agmind.projection-reducer.v2",
    "dedup_version": "AGMIND_PROJECTION_DEDUP_V2",
    "snapshot_layout": "AGMIND_PROJECTION_SNAPSHOT_V2",
}
_SNAPSHOT_DOMAIN_V2 = b"AGMIND_PROJECTION_SNAPSHOT_V2\0"
_REPLAY_SCHEMA_DOMAIN_V2 = b"AGMIND_PROJECTION_SCHEMA_V2\0"
_REPLAY_TRANSCRIPT_DOMAIN_V2 = b"AGMIND_PROJECTION_REPLAY_TRANSCRIPT_V2\0"
_REPLAY_REPORT_DOMAIN_V2 = b"AGMIND_PROJECTION_REPLAY_REPORT_V2\0"
_UNPUBLISHED_REPLAY_FACTORY = object()
_STAGED_REPLAY_FACTORY = object()
_UINT64_V2 = re.compile(r"^[0-9]{20}$")
_EVENT_ID_V2 = re.compile(r"^evt_[0-9a-f]{64}$")
_CANDIDATE_ID_V2 = re.compile(r"^cand_[0-9a-f]{64}$")
_HEX64_V2 = re.compile(r"^[0-9a-f]{64}$")
_UUID4_V2 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_ACCEPTED_AT_V2 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
_MAX_CANONICAL_ENVELOPE_BYTES_V2 = 64 * 1024
_RESULT_KINDS_V2 = frozenset({"candidate", "investigation", "duplicate", "rejected"})
_EVIDENCE_ROLES_V2 = frozenset(
    {
        "primary_trigger",
        "correlation_snapshot",
        "supporting_trigger",
        "supporting_snapshot",
    }
)
_INVALIDATION_REASON_V2 = "late_critical_coverage_gap"
_INVALIDATION_CANDIDATE_CAP_V2 = 4_096
_INCIDENT_UINT64_FIELDS = frozenset({"primary_source_sequence"})
_INCIDENT_BOOL_FIELDS = frozenset({"successful_connect", "investigation_only"})
_INCIDENT_TUPLE_FIELDS = frozenset(
    {"missing_required_fields", "coverage_flags", "evidence_ids", "reason_codes"}
)
_INCIDENT_OPTIONAL_FIELDS_V2 = frozenset(
    {
        "docker_container_id",
        "docker_started_at",
        "proc_name",
        "proc_exe_path",
        "proc_parent_name",
        "destination_ipv4",
        "destination_port",
        "l4_protocol",
    }
)
_CANDIDATE_UINT64_FIELDS = frozenset(
    {"primary_source_sequence", "inventory_generation", "inventory_revision"}
)
_CANDIDATE_TUPLE_FIELDS = frozenset({"repo_digests", "evidence_ids"})
_INCIDENT_COLUMNS = tuple(IncidentV1.model_fields) + ("result_kind",)
_CANDIDATE_COLUMNS = tuple(ContainmentCandidateV1.model_fields) + ("candidate_facts_sha256",)
_TABLE_LAYOUT_V2: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("schema_meta", ("key", "value"), ("key",)),
    (
        "events",
        (
            "event_id",
            "host_id",
            "source_sequence",
            "event_type",
            "source_id",
            "source_version",
            "key_id",
            "key_epoch",
            "boot_id",
            "event_time",
            "ingest_time",
            "clock_uncertainty_ms",
            "container_id",
            "container_start_time",
            "release_id",
            "inventory_generation",
            "inventory_revision",
            "normalized_fields_json",
            "normalized_fields_sha256",
            "redaction_flags_json",
            "coverage_flags_json",
            "source_payload_hash",
            "source_signature",
            "segment_id",
            "segment_relative_path",
            "frame_offset",
            "frame_size",
            "frame_sha256",
            "canonical_sha256",
            "content_sha256",
            "duplicate_of_event_id",
        ),
        ("event_id",),
    ),
    (
        "projection_dedup",
        ("event_id", "dedup_kind", "logical_key_sha256", "primary_event_id", "is_primary"),
        ("event_id",),
    ),
    (
        "coverage_intervals",
        (
            "event_id",
            "host_id",
            "component",
            "kind",
            "severity",
            "opened_at",
            "closed_at",
            "affected_source_sequence_start",
            "affected_source_sequence_end",
            "dropped_count",
            "reason_code",
            "reconcile_generation",
            "source_sequence",
            "content_sha256",
        ),
        ("event_id",),
    ),
    (
        "containers",
        (
            "host_id",
            "container_id",
            "container_started_at",
            "image_id",
            "repo_digests_json",
            "immutable_spec_sha256",
            "inventory_revision",
            "first_event_id",
            "first_source_sequence",
            "first_content_sha256",
            "last_event_id",
            "last_source_sequence",
            "last_content_sha256",
        ),
        ("host_id", "container_id", "container_started_at"),
    ),
    (
        "process_observations",
        (
            "event_id",
            "host_id",
            "container_id",
            "container_started_at",
            "proc_name",
            "proc_exe_path",
            "proc_parent_name",
            "source_sequence",
            "content_sha256",
        ),
        ("event_id",),
    ),
    (
        "network_observations",
        (
            "event_id",
            "host_id",
            "container_id",
            "container_started_at",
            "successful_connect",
            "destination_ipv4",
            "destination_port",
            "l4_protocol",
            "investigation_only",
            "source_sequence",
            "content_sha256",
        ),
        ("event_id",),
    ),
    ("incidents", _INCIDENT_COLUMNS, ("incident_id",)),
    ("candidates", _CANDIDATE_COLUMNS, ("candidate_id",)),
    (
        "candidate_evidence",
        (
            "candidate_id",
            "evidence_event_id",
            "evidence_source_sequence",
            "evidence_content_sha256",
            "role",
            "authority_snapshot_event_id",
        ),
        ("candidate_id", "evidence_event_id", "role", "authority_snapshot_event_id"),
    ),
    (
        "candidate_invalidations",
        (
            "candidate_id",
            "coverage_event_id",
            "coverage_source_sequence",
            "coverage_content_sha256",
            "reason_code",
        ),
        ("candidate_id", "coverage_event_id"),
    ),
    (
        "ingest_cursors",
        (
            "host_id",
            "source_sequence",
            "event_id",
            "content_sha256",
            "segment_id",
            "segment_relative_path",
            "frame_offset",
            "frame_size",
            "frame_sha256",
        ),
        ("host_id",),
    ),
)
_TABLE_NAMES_V2 = frozenset(item[0] for item in _TABLE_LAYOUT_V2)
_APPLY_STEPS_V2 = ("event", "dedup", "reducer", "cursor")
_CANDIDATE_STEPS_V2 = (
    "incident",
    "candidate",
    "candidate_evidence_trigger",
    "candidate_evidence_snapshot",
)


@dataclass(frozen=True)
class _PreparedV2Record:
    record: StoredEvidenceRecord
    envelope: EventEnvelopeV1
    dedup_kind: str
    logical_key_sha256: str
    falco: FalcoConnectV1 | None
    coverage: CoverageEventV1 | None


@dataclass(frozen=True, slots=True)
class _LateCandidateV2:
    candidate: ContainmentCandidateV1
    snapshot_ref: EvidenceRef


@dataclass(frozen=True, slots=True)
class _CandidateAdmissionProjectionSnapshot:
    candidate: ContainmentCandidateV1
    candidate_facts_sha256: str
    authority_snapshot_event_id: str
    invalidation_event_ids: tuple[str, ...]
    cursor: ProjectionCursor
    terminal_ref: EvidenceRef


@dataclass(frozen=True, slots=True)
class _UnpublishedV2ReplayReport:
    cursor: ProjectionCursor | None
    applied_count: int
    prefix_sha256: str


class _ReplayPhase(StrEnum):
    IDLE = "idle"
    FREEZING = "freezing"
    COMPUTING = "computing"
    VALIDATING = "validating"
    STAGED = "staged"
    SUSPENDED = "suspended"
    PUBLISHED = "published"
    FAILED = "failed"


class _ReplayPurpose(StrEnum):
    INITIAL = "initial"
    V2_REBUILD = "v2_rebuild"


class _ReplayFaultPhase(StrEnum):
    FREEZE = "freeze"
    COMPUTE = "compute"
    STAGE_HANDOFF = "stage_handoff"
    PUBLISH = "publish"
    POST_CALLBACK = "post_callback"
    PRE_COMMIT = "pre_commit"
    REBUILD_CHECKPOINT = "rebuild_checkpoint"
    REBUILD_CLOSE = "rebuild_close"
    REBUILD_MATERIALIZE = "rebuild_materialize"
    REBUILD_STAGED_CHECKPOINT = "rebuild_staged_checkpoint"
    REBUILD_STAGED_CLOSE = "rebuild_staged_close"


@dataclass(frozen=True, slots=True)
class _ReplayStatus:
    generation: int
    phase: _ReplayPhase
    reservation_present: bool
    failure_phase: _ReplayPhase | None = None


@dataclass(frozen=True, slots=True)
class _ReplayReservation:
    token: object
    purpose: _ReplayPurpose
    base_generation: int
    publish_generation: int
    through_key: tuple[str, str, int, int, str, str, int, str] | None


@dataclass(frozen=True, slots=True)
class _RetentionReplayFacts:
    completed_state_sha256: bytes
    retained_ranges: tuple[tuple[int, int], ...]
    terminal_sequence: int


@dataclass(slots=True)
class _ReplayTestBarrier:
    phase: _ReplayPhase
    released: bool = False


@dataclass(frozen=True, slots=True)
class _ReplayInputSnapshot:
    source: _ReplaySourceSnapshot
    ack: _AckReplaySnapshot
    correlation: _CorrelationReplaySnapshot
    pcc_inputs: tuple[_FrozenPCCCorrelationInput, ...]
    schema_domain: bytes
    base_projection_generation: int
    publish_generation: int
    retention_facts: _RetentionReplayFacts | None = None
    purpose: _ReplayPurpose = _ReplayPurpose.INITIAL


@dataclass(frozen=True, slots=True)
class _ReplayComputation:
    database_image: bytes
    transcript_count: int
    transcript_digest: bytes
    pcc_leaves: tuple[_ReplayPCCLeaf, ...]
    memo_leaves: tuple[_ReplayMemoLeaf, ...]
    late_invalidations: tuple[object, ...]
    terminal_predecessor: _ProjectionPredecessor
    administrative_visits: int
    semantic_prefix_visits: int
    report_bytes: bytes
    prefix_sha256: str


@final
class _StagedV2Replay:
    """Identity-only owner capability; staged resources never escape through it."""

    __slots__ = ()

    def __init__(self) -> None:
        raise TypeError("staged Projection V2 capabilities are owner-issued")

    def __copy__(self) -> Never:
        raise TypeError("staged Projection V2 capabilities cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("staged Projection V2 capabilities cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("staged Projection V2 capabilities cannot be serialized")


@final
class _V2RebuildGuard:
    """Identity-only proof that one staged rebuild owns one live V2 namespace."""

    __slots__ = ()

    def __init__(self) -> None:
        raise TypeError("Projection V2 rebuild guards are owner-issued")

    def __copy__(self) -> Never:
        raise TypeError("Projection V2 rebuild guards cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Projection V2 rebuild guards cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Projection V2 rebuild guards cannot be serialized")


@final
class _StagedV2ImageSeal:
    """Immutable facts retained after the owner closes its staged target."""

    __slots__ = ("applied_count", "cursor", "prefix_sha256", "table_counts")

    cursor: ProjectionCursor | None
    applied_count: int
    prefix_sha256: str
    table_counts: tuple[tuple[str, int], ...]

    def __init__(self) -> None:
        raise TypeError("staged Projection V2 image seals are owner-issued")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("staged Projection V2 image seals are immutable")

    def __copy__(self) -> Never:
        raise TypeError("staged Projection V2 image seals cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("staged Projection V2 image seals cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("staged Projection V2 image seals cannot be serialized")


@dataclass(slots=True)
class _NamespacePublicationState:
    latch: _NamespacePublicationLatch | None = None
    marked: bool = False


@final
class _NamespacePublicationLatch:
    """Non-raising one-shot signal for the publisher's irreversible syscall."""

    __slots__ = ()

    def __init__(self) -> None:
        raise TypeError("namespace publication latches are owner-issued")

    def _arm_namespace_publication(self) -> None:
        state = _NAMESPACE_PUBLICATION_STATES.get(self)
        if type(state) is _NamespacePublicationState and state.latch is self:
            # Arm immediately before the namespace syscall. Once armed, every
            # failure is conservatively irreversible even if the syscall failed.
            state.marked = True

    def __copy__(self) -> Never:
        raise TypeError("namespace publication latches cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("namespace publication latches cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("namespace publication latches cannot be serialized")


_NAMESPACE_PUBLICATION_STATES: dict[
    _NamespacePublicationLatch,
    _NamespacePublicationState,
] = {}


@dataclass(slots=True)
class _StagedReplayBinding:
    capability: _StagedV2Replay
    purpose: _ReplayPurpose
    through: EvidenceRef | None
    through_key: tuple[str, str, int, int, str, str, int, str] | None
    retention_scope: _AuthenticatedRetentionReplayScope | None
    reservation: _ReplayReservation
    live_connection: sqlite3.Connection
    authority: CorrelationProjectionAuthority
    acceptance_cursor: int
    source_snapshot: _ReplaySourceSnapshot | None
    ack_snapshot: _AckReplaySnapshot | None
    journal_snapshot: _CorrelationJournalReplaySnapshot
    snapshot: _ReplayInputSnapshot
    computation: _ReplayComputation
    hydrated_connection: sqlite3.Connection | None
    report: _UnpublishedV2ReplayReport
    verified_old_cursor: ProjectionCursor | None
    verified_old_prefix_sha256: str | None
    verified_old_table_counts: tuple[tuple[str, int], ...] | None
    materialized_connection: sqlite3.Connection | None = None
    materialized_seal: _StagedV2ImageSeal | None = None
    materialized_physical: _StagedV2PhysicalBinding | None = None
    rebuild: _V2RebuildBinding | None = None


@dataclass(slots=True)
class _StagedV2PhysicalBinding:
    descriptor: int
    path: str
    device: int
    inode: int


@dataclass(slots=True)
class _ReopenedV2Old:
    connection: sqlite3.Connection
    physical: _StagedV2PhysicalBinding


@dataclass(slots=True)
class _V2RebuildBinding:
    guard: _V2RebuildGuard
    old_cursor: ProjectionCursor | None
    old_prefix_sha256: str
    old_table_counts: tuple[tuple[str, int], ...]
    old_physical: _StagedV2PhysicalBinding
    namespace_device: int
    namespace_inode: int
    authority_replacement: _PreparedProjectionAuthorityReplacement
    suspended: bool = False
    guard_consumed: bool = False


@dataclass(slots=True)
class _ReplayComputeCounters:
    administrative_visits: int = 0
    semantic_prefix_visits: int = 0


def _encode_uint64_v2(value: object) -> str:
    if type(value) is not int:
        raise TypeError("Projection V2 uint64 must be an exact integer")
    if not 0 <= value < 2**64:
        raise ValueError("Projection V2 uint64 is out of range")
    return f"{value:020d}"


def _decode_uint64_v2(value: object) -> int:
    if type(value) is not str or _UINT64_V2.fullmatch(value) is None:
        raise ProjectionConflict("Projection V2 row contains a non-canonical uint64")
    decoded = int(value)
    if decoded >= 2**64:
        raise ProjectionConflict("Projection V2 row contains an overflowing uint64")
    return decoded


def _decode_bool_v2(value: object) -> bool:
    if type(value) is not int or value not in (0, 1):
        raise ProjectionConflict("Projection V2 row contains a non-canonical Boolean")
    return bool(value)


def _encode_tuple_v2(value: object) -> str:
    if type(value) is not tuple:
        raise TypeError("Projection V2 tuple field must be an exact tuple")
    return canonical_json(value).decode("utf-8")


def _decode_tuple_v2(value: object) -> tuple[object, ...]:
    if type(value) is not str:
        raise ProjectionConflict("Projection V2 tuple JSON must be exact text")
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ProjectionConflict("Projection V2 tuple JSON is invalid") from error
    try:
        canonical = canonical_json(decoded).decode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ProjectionConflict("Projection V2 tuple JSON is invalid") from error
    if type(decoded) is not list or canonical != value:
        raise ProjectionConflict("Projection V2 tuple JSON is not canonical")
    return tuple(decoded)


def _row_values_v2(
    row: sqlite3.Row | Sequence[object],
    columns: tuple[str, ...],
) -> tuple[object, ...]:
    if isinstance(row, sqlite3.Row):
        if tuple(row.keys()) != columns:
            raise ProjectionConflict("Projection V2 row columns are not exact")
        values = tuple(row)
    elif type(row) is tuple:
        values = row
    else:
        raise ProjectionConflict("Projection V2 row type is not exact")
    if len(values) != len(columns):
        raise ProjectionConflict("Projection V2 row width is not exact")
    return values


def _validated_incident_for_encoding(incident: IncidentV1) -> IncidentV1:
    fields_set = incident.model_fields_set
    known_fields = frozenset(IncidentV1.model_fields)
    if type(fields_set) is not set or not fields_set <= known_fields:
        raise ValueError("Projection V2 incident fields-set is invalid")
    document = {field: getattr(incident, field) for field in fields_set}
    validated = IncidentV1.model_validate(document, strict=True)
    if validated.model_fields_set != fields_set:
        raise ValueError("Projection V2 incident fields-set changed during validation")
    for field in IncidentV1.model_fields:
        original_value = getattr(incident, field)
        validated_value = getattr(validated, field)
        if type(original_value) is not type(validated_value) or original_value != validated_value:
            raise ValueError("Projection V2 incident changed during strict reconstruction")
    return validated


def _validated_candidate_for_encoding(
    candidate: ContainmentCandidateV1,
) -> ContainmentCandidateV1:
    fields_set = candidate.model_fields_set
    known_fields = frozenset(ContainmentCandidateV1.model_fields)
    if type(fields_set) is not set or not fields_set <= known_fields:
        raise ValueError("Projection V2 candidate fields-set is invalid")
    document = {field: getattr(candidate, field) for field in fields_set}
    validated = ContainmentCandidateV1.model_validate(document, strict=True)
    if validated.model_fields_set != fields_set:
        raise ValueError("Projection V2 candidate fields-set changed during validation")
    for field in ContainmentCandidateV1.model_fields:
        original_value = getattr(candidate, field)
        validated_value = getattr(validated, field)
        if type(original_value) is not type(validated_value) or original_value != validated_value:
            raise ValueError("Projection V2 candidate changed during strict reconstruction")
    return validated


def _encode_incident(incident: IncidentV1, result_kind: str) -> tuple[object, ...]:
    if type(incident) is not IncidentV1:
        raise TypeError("Projection V2 incident must use the exact model type")
    if type(result_kind) is not str or result_kind not in _RESULT_KINDS_V2:
        raise ValueError("Projection V2 incident result kind is not closed")
    validated = _validated_incident_for_encoding(incident)
    document = validated.model_dump(mode="python", exclude_unset=True)
    encoded: list[object] = []
    for field in IncidentV1.model_fields:
        value = document.get(field)
        if field in _INCIDENT_UINT64_FIELDS:
            value = _encode_uint64_v2(value)
        elif field in _INCIDENT_BOOL_FIELDS:
            if type(value) is not bool:
                raise TypeError("Projection V2 incident Boolean is not exact")
            value = int(value)
        elif field in _INCIDENT_TUPLE_FIELDS:
            value = _encode_tuple_v2(value)
        encoded.append(value)
    encoded.append(result_kind)
    return tuple(encoded)


def _decode_incident(
    row: sqlite3.Row | Sequence[object],
) -> tuple[IncidentV1, str]:
    values = _row_values_v2(row, _INCIDENT_COLUMNS)
    result_kind = values[-1]
    if type(result_kind) is not str or result_kind not in _RESULT_KINDS_V2:
        raise ProjectionConflict("Projection V2 incident result kind is invalid")
    document: dict[str, object] = {}
    try:
        for field, value in zip(IncidentV1.model_fields, values[:-1], strict=True):
            if field in _INCIDENT_OPTIONAL_FIELDS_V2 and value is None:
                continue
            if value is None:
                raise ProjectionConflict("Projection V2 incident lost a required field")
            if field in _INCIDENT_UINT64_FIELDS:
                value = _decode_uint64_v2(value)
            elif field in _INCIDENT_BOOL_FIELDS:
                value = _decode_bool_v2(value)
            elif field in _INCIDENT_TUPLE_FIELDS:
                value = _decode_tuple_v2(value)
            document[field] = value
        incident = IncidentV1.model_validate(document, strict=True)
    except ProjectionConflict:
        raise
    except (TypeError, ValueError, ValidationError) as error:
        raise ProjectionConflict("Projection V2 incident row is invalid") from error
    return incident, result_kind


def _encode_candidate(candidate: ContainmentCandidateV1) -> tuple[object, ...]:
    if type(candidate) is not ContainmentCandidateV1:
        raise TypeError("Projection V2 candidate must use the exact model type")
    validated = _validated_candidate_for_encoding(candidate)
    document = validated.model_dump(mode="python")
    encoded: list[object] = []
    for field in ContainmentCandidateV1.model_fields:
        value = document[field]
        if field in _CANDIDATE_UINT64_FIELDS:
            value = _encode_uint64_v2(value)
        elif field in _CANDIDATE_TUPLE_FIELDS:
            value = _encode_tuple_v2(value)
        encoded.append(value)
    encoded.append(candidate_facts_sha256(validated))
    return tuple(encoded)


def _decode_candidate(row: sqlite3.Row | Sequence[object]) -> ContainmentCandidateV1:
    values = _row_values_v2(row, _CANDIDATE_COLUMNS)
    stored_hash = values[-1]
    if type(stored_hash) is not str or _HEX64_V2.fullmatch(stored_hash) is None:
        raise ProjectionConflict("Projection V2 candidate facts hash is invalid")
    document: dict[str, object] = {}
    try:
        for field, value in zip(ContainmentCandidateV1.model_fields, values[:-1], strict=True):
            if value is None:
                raise ProjectionConflict("Projection V2 candidate lost a required field")
            if field in _CANDIDATE_UINT64_FIELDS:
                value = _decode_uint64_v2(value)
            elif field in _CANDIDATE_TUPLE_FIELDS:
                value = _decode_tuple_v2(value)
            document[field] = value
        candidate = ContainmentCandidateV1.model_validate(document, strict=True)
    except ProjectionConflict:
        raise
    except (TypeError, ValueError, ValidationError) as error:
        raise ProjectionConflict("Projection V2 candidate row is invalid") from error
    if candidate_facts_sha256(candidate) != stored_hash:
        raise ProjectionConflict("Projection V2 candidate facts hash changed")
    return candidate


def _candidate_duplicate_key_from_row(
    row: sqlite3.Row | Sequence[object],
) -> tuple[str, str, str, str, str, str]:
    values = _row_values_v2(row, _CANDIDATE_COLUMNS)
    candidate = _decode_candidate(values)
    raw = dict(zip(_CANDIDATE_COLUMNS, values, strict=True))
    expected: tuple[tuple[str, object], ...] = (
        ("host_id", candidate.host_id),
        ("boot_id", candidate.boot_id),
        ("docker_container_id", candidate.docker_container_id),
        ("docker_started_at", candidate.docker_started_at),
        ("detector_bundle_sha256", candidate.detector_bundle_sha256),
        ("destination_ipv4", candidate.destination_ipv4),
        ("primary_source_sequence", _encode_uint64_v2(candidate.primary_source_sequence)),
        ("primary_event_id", candidate.primary_event_id),
        ("candidate_id", candidate.candidate_id),
    )
    if any(raw[field] != wanted for field, wanted in expected):
        raise ProjectionConflict("Projection V2 candidate lookup index values changed")
    return (
        candidate.host_id,
        candidate.boot_id,
        candidate.docker_container_id,
        candidate.docker_started_at,
        candidate.detector_bundle_sha256,
        candidate.destination_ipv4,
    )


def _validate_identity_v2(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str:
        raise TypeError(f"Projection V2 {label} must be exact text")
    if pattern.fullmatch(value) is None:
        raise ValueError(f"Projection V2 {label} is invalid")
    return value


def _encode_candidate_evidence(
    candidate_id: str,
    evidence_event_id: str,
    evidence_source_sequence: int,
    evidence_content_sha256: str,
    role: str,
    authority_snapshot_event_id: str,
) -> tuple[object, ...]:
    if type(role) is not str or role not in _EVIDENCE_ROLES_V2:
        raise ValueError("Projection V2 evidence role is not closed")
    return (
        _validate_identity_v2(candidate_id, _CANDIDATE_ID_V2, "candidate ID"),
        _validate_identity_v2(evidence_event_id, _EVENT_ID_V2, "evidence event ID"),
        _encode_uint64_v2(evidence_source_sequence),
        _validate_identity_v2(evidence_content_sha256, _HEX64_V2, "evidence hash"),
        role,
        _validate_identity_v2(
            authority_snapshot_event_id,
            _EVENT_ID_V2,
            "authority snapshot event ID",
        ),
    )


def _decode_candidate_evidence(
    row: sqlite3.Row | Sequence[object],
) -> tuple[str, str, int, str, str, str]:
    values = _row_values_v2(row, _TABLE_LAYOUT_V2[9][1])
    try:
        candidate_id = _validate_identity_v2(values[0], _CANDIDATE_ID_V2, "candidate ID")
        evidence_event_id = _validate_identity_v2(values[1], _EVENT_ID_V2, "evidence event ID")
        source_sequence = _decode_uint64_v2(values[2])
        content_hash = _validate_identity_v2(values[3], _HEX64_V2, "evidence hash")
        role = values[4]
        if type(role) is not str or role not in _EVIDENCE_ROLES_V2:
            raise ValueError("Projection V2 evidence role is invalid")
        authority_event_id = _validate_identity_v2(
            values[5], _EVENT_ID_V2, "authority snapshot event ID"
        )
    except ProjectionConflict:
        raise
    except (TypeError, ValueError) as error:
        raise ProjectionConflict("Projection V2 candidate evidence row is invalid") from error
    return (
        candidate_id,
        evidence_event_id,
        source_sequence,
        content_hash,
        role,
        authority_event_id,
    )


def _encode_candidate_invalidation(
    candidate_id: str,
    coverage_event_id: str,
    coverage_source_sequence: int,
    coverage_content_sha256: str,
    reason_code: str,
) -> tuple[object, ...]:
    if type(reason_code) is not str or reason_code != _INVALIDATION_REASON_V2:
        raise ValueError("Projection V2 invalidation reason is not closed")
    return (
        _validate_identity_v2(candidate_id, _CANDIDATE_ID_V2, "candidate ID"),
        _validate_identity_v2(coverage_event_id, _EVENT_ID_V2, "coverage event ID"),
        _encode_uint64_v2(coverage_source_sequence),
        _validate_identity_v2(coverage_content_sha256, _HEX64_V2, "coverage hash"),
        reason_code,
    )


def _decode_candidate_invalidation(
    row: sqlite3.Row | Sequence[object],
) -> tuple[str, str, int, str, str]:
    values = _row_values_v2(row, _TABLE_LAYOUT_V2[10][1])
    try:
        candidate_id = _validate_identity_v2(values[0], _CANDIDATE_ID_V2, "candidate ID")
        coverage_event_id = _validate_identity_v2(values[1], _EVENT_ID_V2, "coverage event ID")
        source_sequence = _decode_uint64_v2(values[2])
        content_hash = _validate_identity_v2(values[3], _HEX64_V2, "coverage hash")
        reason_code = values[4]
        if type(reason_code) is not str or reason_code != _INVALIDATION_REASON_V2:
            raise ValueError("Projection V2 invalidation reason is invalid")
    except ProjectionConflict:
        raise
    except (TypeError, ValueError) as error:
        raise ProjectionConflict("Projection V2 candidate invalidation row is invalid") from error
    return candidate_id, coverage_event_id, source_sequence, content_hash, reason_code


def _configure_v2_connection(connection: sqlite3.Connection, *, file_backed: bool) -> None:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
    connection.execute("PRAGMA synchronous=FULL")
    expected_mode = "wal" if file_backed else "memory"
    if mode != expected_mode:
        raise ProjectionConflict("Projection V2 did not enter its safe journal mode")


def _verify_v2_pragmas(
    connection: sqlite3.Connection,
    *,
    immutable_read_only: bool = False,
) -> None:
    database_path = str(connection.execute("PRAGMA database_list").fetchone()[2])
    expected: tuple[tuple[str, object], ...] = (
        (
            "journal_mode",
            "delete" if immutable_read_only else ("wal" if database_path else "memory"),
        ),
        ("synchronous", 2),
        ("foreign_keys", 1),
        ("trusted_schema", 0),
        ("busy_timeout", 5000),
        ("ignore_check_constraints", 0),
    )
    if immutable_read_only:
        expected += (("query_only", 1),)
    for pragma, wanted in expected:
        actual = connection.execute(f"PRAGMA {pragma}").fetchone()[0]
        if isinstance(wanted, str):
            actual = str(actual).lower()
        if actual != wanted:
            raise ProjectionConflict(f"Projection V2 PRAGMA {pragma} is unsafe")


def _create_v2_schema(connection: sqlite3.Connection) -> None:
    try:
        raw = _SCHEMA_V2_PATH.read_bytes()
    except OSError as error:
        raise ProjectionConflict("Projection V2 trusted schema bytes are unavailable") from error
    if hashlib.sha256(raw).hexdigest() != _SCHEMA_V2_SHA256:
        raise ProjectionConflict("Projection V2 trusted schema bytes changed")
    try:
        script = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ProjectionConflict("Projection V2 trusted schema is not UTF-8") from error
    connection.executescript(script)


def _schema_rows(connection: sqlite3.Connection) -> list[tuple[object, ...]]:
    return [
        tuple(row)
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE sql IS NOT NULL "
            "ORDER BY type COLLATE BINARY,name COLLATE BINARY"
        )
    ]


def _verify_v2_schema(
    connection: sqlite3.Connection,
    *,
    immutable_read_only: bool = False,
) -> None:
    try:
        actual_tables = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name COLLATE BINARY"
            )
        )
        if actual_tables != tuple(sorted(_TABLE_NAMES_V2)):
            raise ProjectionConflict("Projection V2 table set is not exact")
        expected = sqlite3.connect(":memory:", isolation_level=None)
        try:
            _configure_v2_connection(expected, file_backed=False)
            _create_v2_schema(expected)
            expected_schema = _schema_rows(expected)
        finally:
            expected.close()
        if _schema_rows(connection) != expected_schema:
            raise ProjectionConflict("Projection V2 schema definition is not exact")
        metadata = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT key,value FROM schema_meta ORDER BY key COLLATE BINARY"
            )
        )
        if metadata != tuple(sorted(_SCHEMA_META_V2.items())):
            raise ProjectionConflict("Projection V2 metadata is not exact")
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if [str(row[0]) for row in integrity] != ["ok"]:
            raise ProjectionConflict("Projection V2 integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ProjectionConflict("Projection V2 foreign-key check failed")
        _verify_v2_pragmas(
            connection,
            immutable_read_only=immutable_read_only,
        )
    except ProjectionConflict:
        raise
    except (sqlite3.DatabaseError, TypeError, ValueError) as error:
        raise ProjectionConflict("Projection V2 schema verification failed") from error


def _new_v2_connection(path: Path | None = None) -> sqlite3.Connection:
    connection = sqlite3.connect(
        ":memory:" if path is None else path,
        isolation_level=None,
        check_same_thread=False,
    )
    try:
        _configure_v2_connection(connection, file_backed=path is not None)
        existing_tables = connection.execute(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()[0]
        if existing_tables == 0:
            _create_v2_schema(connection)
        _verify_v2_schema(connection)
    except BaseException as primary:
        for attempt in (1, 2):
            try:
                connection.close()
            except BaseException as cleanup_error:  # noqa: BLE001
                primary.add_note(
                    "Projection V2 connection cleanup failure "
                    f"(attempt {attempt}): {type(cleanup_error).__name__}: "
                    f"{cleanup_error}"
                )
            else:
                break
        raise
    return connection


def _v2_connection_for_test(path: Path | None = None) -> sqlite3.Connection:
    return _new_v2_connection(path)


def _ordered_v2_rows_unverified(
    connection: sqlite3.Connection,
    table: str,
) -> list[tuple[object, ...]]:
    try:
        layout = next(item for item in _TABLE_LAYOUT_V2 if item[0] == table)
    except StopIteration as error:
        raise ProjectionConflict("Projection V2 table selection is not frozen") from error
    _table, columns, primary_key = layout
    selected = ",".join(columns)
    order = ",".join(f"{column} COLLATE BINARY" for column in primary_key)
    try:
        rows = connection.execute(f"SELECT {selected} FROM {table} ORDER BY {order}").fetchall()
        for row in rows:
            if table == "incidents":
                _decode_incident(row)
            elif table == "candidates":
                _candidate_duplicate_key_from_row(row)
            elif table == "candidate_evidence":
                _decode_candidate_evidence(row)
            elif table == "candidate_invalidations":
                _decode_candidate_invalidation(row)
        return [tuple(row) for row in rows]
    except ProjectionConflict:
        raise
    except (sqlite3.DatabaseError, TypeError, ValueError) as error:
        raise ProjectionConflict(f"Projection V2 {table} rows are invalid") from error


def _v2_ordered_table_rows(
    connection: sqlite3.Connection,
    table: str,
) -> list[tuple[object, ...]]:
    if type(table) is not str:
        raise ProjectionConflict("Projection V2 table selection is not exact text")
    _verify_v2_schema(connection)
    return _ordered_v2_rows_unverified(connection, table)


def _v2_snapshot_hash(connection: sqlite3.Connection) -> str:
    _verify_v2_schema(connection)
    digest = hashlib.sha256()
    digest.update(_SNAPSHOT_DOMAIN_V2)
    owns_transaction = not connection.in_transaction
    try:
        if owns_transaction:
            connection.execute("BEGIN")
        for table, columns, _primary_key in _TABLE_LAYOUT_V2:
            digest.update(canonical_json({"table": table, "columns": columns}))
            digest.update(b"\n")
            for row in _ordered_v2_rows_unverified(connection, table):
                digest.update(canonical_json({"row": list(row)}))
                digest.update(b"\n")
        if owns_transaction:
            connection.execute("COMMIT")
    except ProjectionConflict:
        if owns_transaction and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except (sqlite3.DatabaseError, TypeError, ValueError, UnicodeError) as error:
        if owns_transaction and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ProjectionConflict("Projection V2 logical snapshot is invalid") from error
    return digest.hexdigest()


def _v2_table_counts(
    connection: sqlite3.Connection,
) -> tuple[tuple[str, int], ...]:
    _verify_v2_schema(connection)
    try:
        return tuple(
            (
                table,
                int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]),
            )
            for table, _columns, _primary_key in _TABLE_LAYOUT_V2
        )
    except (sqlite3.DatabaseError, TypeError, ValueError) as error:
        raise ProjectionConflict("Projection V2 table counts are unavailable") from error


def _v2_exact_main_database_path(
    connection: sqlite3.Connection,
    *,
    require_file_backed: bool,
) -> str:
    try:
        rows = tuple(tuple(row) for row in connection.execute("PRAGMA database_list"))
        temp_schema = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT type,name,tbl_name,sql FROM temp.sqlite_schema ORDER BY type,name,tbl_name"
            )
        )
    except sqlite3.DatabaseError as error:
        raise ProjectionConflict("Projection V2 database binding is unavailable") from error
    if (
        len(rows) not in (1, 2)
        or len(rows[0]) != 3
        or rows[0][0] != 0
        or rows[0][1] != "main"
        or type(rows[0][2]) is not str
        or (len(rows) == 2 and rows[1] != (1, "temp", ""))
        or temp_schema
        or (require_file_backed and not rows[0][2])
    ):
        raise ProjectionConflict("Projection V2 connection is not bound to one exact main database")
    return rows[0][2]


def _capture_staged_v2_physical_binding(
    database_path: str,
) -> _StagedV2PhysicalBinding:
    if (
        type(database_path) is not str
        or not database_path
        or not Path(database_path).is_absolute()
        or Path(os.path.normpath(database_path)) != Path(database_path)
    ):
        raise ProjectionConflict("Projection V2 materialized database path is not exact")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(database_path, flags)
        info = os.fstat(descriptor)
        path_info = os.lstat(database_path)
        if (
            not stat.S_ISREG(info.st_mode)
            or not stat.S_ISREG(path_info.st_mode)
            or info.st_nlink != 1
            or path_info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or path_info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or stat.S_IMODE(path_info.st_mode) != 0o600
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
            or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        ):
            raise ProjectionConflict("Projection V2 materialized database binding is not exact")
        binding = _StagedV2PhysicalBinding(
            descriptor=descriptor,
            path=database_path,
            device=info.st_dev,
            inode=info.st_ino,
        )
        descriptor = -1
        return binding
    except ProjectionConflict:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise ProjectionConflict(
            "Projection V2 materialized database binding is unavailable"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _revalidate_staged_v2_physical_binding(
    binding: _StagedV2PhysicalBinding,
    *,
    published_path: str | None = None,
) -> None:
    if (
        type(binding) is not _StagedV2PhysicalBinding
        or type(binding.descriptor) is not int
        or binding.descriptor < 0
        or type(binding.path) is not str
        or type(binding.device) is not int
        or type(binding.inode) is not int
    ):
        raise ProjectionConflict("Projection V2 materialized physical binding changed")
    try:
        descriptor_info = os.fstat(binding.descriptor)
        path = binding.path if published_path is None else published_path
        path_info = os.lstat(path)
    except OSError as error:
        raise ProjectionConflict(
            "Projection V2 materialized physical binding is unavailable"
        ) from error
    if (
        not stat.S_ISREG(descriptor_info.st_mode)
        or not stat.S_ISREG(path_info.st_mode)
        or descriptor_info.st_nlink != 1
        or path_info.st_nlink != 1
        or descriptor_info.st_uid != os.geteuid()
        or path_info.st_uid != os.geteuid()
        or stat.S_IMODE(descriptor_info.st_mode) != 0o600
        or stat.S_IMODE(path_info.st_mode) != 0o600
        or (descriptor_info.st_dev, descriptor_info.st_ino) != (binding.device, binding.inode)
        or (path_info.st_dev, path_info.st_ino) != (binding.device, binding.inode)
        or fcntl.fcntl(binding.descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
    ):
        raise ProjectionConflict("Projection V2 materialized physical binding changed")


def _revalidate_v2_rebuild_old_physical(
    binding: _StagedV2PhysicalBinding,
    *,
    named: bool,
) -> None:
    if (
        type(binding) is not _StagedV2PhysicalBinding
        or type(named) is not bool
        or binding.descriptor < 0
    ):
        raise ProjectionConflict("Projection V2 rebuild old binding changed")
    try:
        descriptor_info = os.fstat(binding.descriptor)
        path_info = os.lstat(binding.path) if named else None
        access_mode = fcntl.fcntl(binding.descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    except OSError as error:
        raise ProjectionConflict("Projection V2 rebuild old binding is unavailable") from error
    expected_links = 1 if named else 0
    if (
        not stat.S_ISREG(descriptor_info.st_mode)
        or descriptor_info.st_uid != os.geteuid()
        or stat.S_IMODE(descriptor_info.st_mode) != 0o600
        or descriptor_info.st_nlink != expected_links
        or (descriptor_info.st_dev, descriptor_info.st_ino) != (binding.device, binding.inode)
        or access_mode != os.O_RDONLY
        or (
            path_info is not None
            and (
                not stat.S_ISREG(path_info.st_mode)
                or path_info.st_uid != os.geteuid()
                or stat.S_IMODE(path_info.st_mode) != 0o600
                or path_info.st_nlink != 1
                or (path_info.st_dev, path_info.st_ino) != (binding.device, binding.inode)
            )
        )
    ):
        raise ProjectionConflict("Projection V2 rebuild old binding changed")


def _revalidate_reopened_v2_old_physical(
    reopened: _StagedV2PhysicalBinding,
    expected: _StagedV2PhysicalBinding,
) -> None:
    if (
        type(reopened) is not _StagedV2PhysicalBinding
        or type(expected) is not _StagedV2PhysicalBinding
        or reopened.descriptor < 0
        or reopened.path != expected.path
        or (reopened.device, reopened.inode) != (expected.device, expected.inode)
    ):
        raise ProjectionConflict("Projection V2 reopened old descriptor was substituted")
    try:
        descriptor_info = os.fstat(reopened.descriptor)
        path_info = os.lstat(reopened.path)
        access_mode = fcntl.fcntl(reopened.descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    except OSError as error:
        raise ProjectionConflict("Projection V2 reopened old descriptor is unavailable") from error
    if (
        not stat.S_ISREG(descriptor_info.st_mode)
        or descriptor_info.st_uid != os.geteuid()
        or stat.S_IMODE(descriptor_info.st_mode) != 0o600
        or descriptor_info.st_nlink != 1
        or (descriptor_info.st_dev, descriptor_info.st_ino) != (expected.device, expected.inode)
        or access_mode != os.O_RDWR
        or not stat.S_ISREG(path_info.st_mode)
        or path_info.st_uid != os.geteuid()
        or stat.S_IMODE(path_info.st_mode) != 0o600
        or path_info.st_nlink != 1
        or (path_info.st_dev, path_info.st_ino) != (expected.device, expected.inode)
    ):
        raise ProjectionConflict("Projection V2 reopened old descriptor changed")


def _prepare_v2(record: StoredEvidenceRecord) -> _PreparedV2Record:
    if type(record) is not StoredEvidenceRecord or type(record.ref) is not EvidenceRef:
        raise ProjectionValidationError("Projection V2 record is not exact evidence")
    try:
        _exact_coverage_record_key(record)
        if _ACCEPTED_AT_V2.fullmatch(record.accepted_at) is None:
            raise ValueError("accepted_at is not exact UTC")
        datetime.fromisoformat(record.accepted_at)
        envelope = decode_strict(
            record.canonical_envelope,
            EventEnvelopeV1,
            _MAX_CANONICAL_ENVELOPE_BYTES_V2,
        )
        raw = envelope.model_dump(exclude_none=True)
        if raw != record.envelope:
            raise ValueError("typed envelope differs from stored envelope")
    except (TypeError, ValueError, ValidationError) as error:
        raise ProjectionValidationError("Projection V2 envelope cannot be reparsed") from error
    ref = record.ref
    if (
        type(record.envelope) is not dict
        or canonical_json(raw) != record.canonical_envelope
        or canonical_json(record.envelope) != record.canonical_envelope
        or envelope.event_id != ref.event_id
        or envelope.source_sequence != ref.source_sequence
        or hashlib.sha256(record.canonical_envelope).hexdigest() != ref.content_sha256
    ):
        raise ProjectionValidationError("Projection V2 record outer facts do not bind")
    falco: FalcoConnectV1 | None = None
    coverage: CoverageEventV1 | None = None
    if envelope.event_type == "falco_connect":
        if envelope.normalized_fields.get("raw_event_sha256") != envelope.source_payload_hash:
            raise ProjectionValidationError("Projection V2 Falco raw hash does not bind")
        try:
            falco = FalcoConnectV1.model_validate(envelope.normalized_fields, strict=True)
        except ValidationError as error:
            raise ProjectionValidationError("Projection V2 Falco input is invalid") from error
    elif envelope.event_type == "coverage":
        try:
            coverage = CoverageEventV1.model_validate(envelope.normalized_fields, strict=True)
        except ValidationError as error:
            raise ProjectionValidationError("Projection V2 coverage input is invalid") from error
    kind, identity = _logical_primary_identity_v2(envelope)
    return _PreparedV2Record(record, envelope, kind, identity, falco, coverage)


def _optional_uint64_v2(value: int | None) -> str | None:
    return None if value is None else _encode_uint64_v2(value)


def _event_values_v2(
    prepared: _PreparedV2Record,
    duplicate: str | None,
) -> tuple[object, ...]:
    envelope = prepared.envelope
    ref = prepared.record.ref
    canonical = prepared.record.canonical_envelope
    return (
        envelope.event_id,
        envelope.host_id,
        _encode_uint64_v2(envelope.source_sequence),
        envelope.event_type,
        envelope.source_id,
        envelope.source_version,
        envelope.key_id,
        _encode_uint64_v2(envelope.key_epoch),
        envelope.boot_id,
        envelope.event_time,
        envelope.ingest_time,
        envelope.clock_uncertainty_ms,
        envelope.container_id,
        envelope.container_start_time,
        envelope.release_id,
        _encode_uint64_v2(envelope.inventory_generation),
        _optional_uint64_v2(envelope.inventory_revision),
        canonical_json(envelope.normalized_fields).decode("utf-8"),
        envelope.normalized_fields_sha256,
        canonical_json(envelope.redaction_flags).decode("utf-8"),
        canonical_json(envelope.coverage_flags).decode("utf-8"),
        envelope.source_payload_hash,
        envelope.source_signature,
        ref.segment_id,
        ref.segment_relative_path,
        _encode_uint64_v2(ref.frame_offset),
        _encode_uint64_v2(ref.frame_size),
        ref.frame_sha256,
        hashlib.sha256(canonical).hexdigest(),
        ref.content_sha256,
        duplicate,
    )


def _v2_cursor_from_row(row: sqlite3.Row | None) -> ProjectionCursor | None:
    if row is None:
        return None
    if tuple(row.keys()) != (
        "host_id",
        "source_sequence",
        "event_id",
        "content_sha256",
        "frame_sha256",
    ):
        raise ProjectionConflict("Projection V2 cursor columns are not exact")
    host_id = row["host_id"]
    event_id = row["event_id"]
    content_sha256 = row["content_sha256"]
    frame_sha256 = row["frame_sha256"]
    if (
        type(host_id) is not str
        or _UUID4_V2.fullmatch(host_id) is None
        or type(event_id) is not str
        or _EVENT_ID_V2.fullmatch(event_id) is None
        or type(content_sha256) is not str
        or _HEX64_V2.fullmatch(content_sha256) is None
        or type(frame_sha256) is not str
        or _HEX64_V2.fullmatch(frame_sha256) is None
    ):
        raise ProjectionConflict("Projection V2 cursor identity is invalid")
    return ProjectionCursor(
        host_id=host_id,
        source_sequence=_decode_uint64_v2(row["source_sequence"]),
        event_id=event_id,
        content_sha256=content_sha256,
        frame_sha256=frame_sha256,
    )


def _current_v2_cursor(connection: sqlite3.Connection) -> ProjectionCursor | None:
    rows = connection.execute(
        "SELECT host_id,source_sequence,event_id,content_sha256,frame_sha256 "
        "FROM ingest_cursors ORDER BY host_id"
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict("Projection V2 has multiple single-host cursors")
    return _v2_cursor_from_row(rows[0] if rows else None)


def _current_v2_cursor_ref(connection: sqlite3.Connection) -> EvidenceRef | None:
    rows = connection.execute(
        "SELECT source_sequence,event_id,content_sha256,segment_id,"
        "segment_relative_path,frame_offset,frame_size,frame_sha256 "
        "FROM ingest_cursors ORDER BY host_id"
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict("Projection V2 has multiple single-host cursor refs")
    if not rows:
        return None
    row = rows[0]
    values = tuple(row)
    if len(values) != 8 or any(type(value) is not str for value in values):
        raise ProjectionConflict("Projection V2 cursor ref fields are not exact text")
    try:
        return EvidenceRef(
            segment_id=cast(str, row["segment_id"]),
            segment_relative_path=cast(str, row["segment_relative_path"]),
            frame_offset=_decode_uint64_v2(row["frame_offset"]),
            frame_size=_decode_uint64_v2(row["frame_size"]),
            frame_sha256=_validate_identity_v2(row["frame_sha256"], _HEX64_V2, "cursor frame hash"),
            event_id=_validate_identity_v2(row["event_id"], _EVENT_ID_V2, "cursor event ID"),
            source_sequence=_decode_uint64_v2(row["source_sequence"]),
            content_sha256=_validate_identity_v2(
                row["content_sha256"], _HEX64_V2, "cursor content hash"
            ),
        )
    except (TypeError, ValueError) as error:
        raise ProjectionConflict("Projection V2 cursor ref is invalid") from error


def _predecessor_v2(
    generation: int,
    cursor: ProjectionCursor | None,
) -> _ProjectionPredecessor:
    if type(generation) is not int or not 1 <= generation <= MAX_UINT64:
        raise ProjectionConflict("Projection V2 generation must be a positive uint64")
    if cursor is None:
        return _ProjectionPredecessor(
            generation=generation,
            host_id=None,
            source_sequence=0,
            event_id=None,
            content_sha256=None,
            frame_sha256=None,
        )
    return _ProjectionPredecessor(
        generation=generation,
        host_id=cursor.host_id,
        source_sequence=cursor.source_sequence,
        event_id=cursor.event_id,
        content_sha256=cursor.content_sha256,
        frame_sha256=cursor.frame_sha256,
    )


@dataclass(frozen=True)
class _ProjectionAckBoundaryV2:
    confirmed: AckIdentity | None
    pending: AckIdentity | None
    generation: int
    prefix_size: int
    prefix_sha256: str

    @property
    def confirmed_through(self) -> int:
        confirmed = self.confirmed
        return 0 if confirmed is None else confirmed.sequence


def _exact_ack_identity_v2(value: object) -> AckIdentity | None:
    if value is None:
        return None
    if (
        type(value) is not AckIdentity
        or type(value.sequence) is not int
        or not 1 <= value.sequence <= MAX_UINT64
        or type(value.event_id) is not str
        or _EVENT_ID_V2.fullmatch(value.event_id) is None
        or type(value.content_sha256) is not str
        or _HEX64_V2.fullmatch(value.content_sha256) is None
    ):
        raise ProjectionAuthorityError("Projection V2 ACK identity is not exact")
    return value


def _healthy_acceptance_cursor_v2(
    store: SegmentStore,
    lifecycle: object,
) -> int:
    try:
        status = store.status()
    except Exception as error:
        raise ProjectionAuthorityError("Projection V2 evidence status is unavailable") from error
    if (
        type(status) is not EvidenceStatus
        or store._lifecycle_identity is not lifecycle
        or getattr(store, "_closed", True)
        or status.healthy is not True
        or status.repair_pending is not False
        or status.retention_pending is not False
        or type(status.acceptance_cursor) is not int
        or not 0 <= status.acceptance_cursor <= MAX_UINT64
    ):
        raise ProjectionAuthorityError(
            "Projection V2 evidence acceptance cursor is not exact and healthy"
        )
    return status.acceptance_cursor


def _healthy_replay_acceptance_cursor_v2(
    store: SegmentStore,
    lifecycle: object,
    retention_scope: _AuthenticatedRetentionReplayScope | None,
) -> int:
    try:
        status = store.status()
    except Exception as error:
        raise ProjectionAuthorityError(
            "Projection V2 replay evidence status is unavailable"
        ) from error
    if (
        type(status) is not EvidenceStatus
        or store._lifecycle_identity is not lifecycle
        or getattr(store, "_closed", True)
        or status.healthy is not True
        or status.repair_pending is not False
        or status.retention_pending is not (retention_scope is not None)
        or type(status.acceptance_cursor) is not int
        or not 0 <= status.acceptance_cursor <= MAX_UINT64
    ):
        raise ProjectionAuthorityError("Projection V2 replay requires exact healthy source scope")
    return status.acceptance_cursor


def _capture_retention_replay_scope_v2(
    store: SegmentStore,
    capability: object,
    terminal: EvidenceRef | None,
) -> _AuthenticatedRetentionReplayScope:
    if (
        type(store) is not SegmentStore
        or type(capability) is not AuthenticatedRetentionUnlinkCompletion
        or type(terminal) is not EvidenceRef
    ):
        raise ProjectionAuthorityError(
            "Projection V2 retention replay requires exact completion authority"
        )
    try:
        return store._capture_authenticated_retention_replay_scope(
            capability,
            terminal,
        )
    except ProjectionAuthorityError:
        raise
    except Exception as error:
        raise ProjectionAuthorityError(
            "Projection V2 retention completion cannot be authenticated"
        ) from error


def _bind_retention_replay_scope_v2(
    store: SegmentStore,
    scope: _AuthenticatedRetentionReplayScope,
    source: _ReplaySourceSnapshot,
    gate: _AuthenticatedRetentionReplayGate | None,
) -> _RetentionReplayFacts:
    if (
        type(scope) is not _AuthenticatedRetentionReplayScope
        or type(source) is not _ReplaySourceSnapshot
        or type(gate) is not _AuthenticatedRetentionReplayGate
        or type(scope.capability) is not AuthenticatedRetentionUnlinkCompletion
    ):
        raise ProjectionAuthorityError("Projection V2 retention replay scope changed")
    try:
        store._bind_authenticated_retention_replay_scope_locked(
            scope,
            source,
            gate,
        )
    except EvidenceStoreError as error:
        raise ProjectionAuthorityError("Projection V2 retention replay scope changed") from error
    terminal_ref = source.terminal_ref
    if terminal_ref is None:
        raise ProjectionAuthorityError("Projection V2 retention replay lost its terminal")
    return _RetentionReplayFacts(
        completed_state_sha256=hashlib.sha256(scope.completed_state_raw).digest(),
        retained_ranges=scope.retained_ranges,
        terminal_sequence=terminal_ref.source_sequence,
    )


def _authenticated_retained_prefix_records_v2(
    scope: _AuthenticatedRetentionReplayScope,
    cursor: ProjectionCursor,
) -> tuple[StoredEvidenceRecord, ...]:
    """Rehydrate a retired prefix from the completion's verifier authority."""
    completion = scope.completion_binding
    authority = completion.tombstone.accepted_authority
    if (
        type(scope) is not _AuthenticatedRetentionReplayScope
        or type(cursor) is not ProjectionCursor
        or type(authority) is not _RetentionAcceptedAuthorityBinding
        or type(authority.entries) is not tuple
    ):
        raise ProjectionAuthorityError("Projection V2 retained prefix authority is not exact")
    records: list[StoredEvidenceRecord] = []
    expected_sequence = 1
    for entry in authority.entries:
        if type(entry) is not _RetentionAcceptedEnvelopeBinding:
            raise ProjectionAuthorityError("Projection V2 retained prefix entry is not exact")
        if entry.sequence > cursor.source_sequence:
            break
        ref = entry.evidence_ref
        accepted = entry.accepted
        try:
            envelope = decode_strict(
                entry.canonical,
                EventEnvelopeV1,
                _MAX_CANONICAL_ENVELOPE_BYTES_V2,
            )
            canonical = canonical_json(envelope.model_dump(exclude_none=True))
            priority = EvidencePriority(entry.evidence_priority)
            ref_key = _exact_coverage_ref_key(ref)
        except (AttributeError, TypeError, ValueError, ValidationError) as error:
            raise ProjectionAuthorityError(
                "Projection V2 retained prefix entry is malformed"
            ) from error
        if (
            type(ref) is not EvidenceRef
            or entry.sequence != expected_sequence
            or ref.source_sequence != entry.sequence
            or entry.evidence_ref_key != ref_key
            or canonical != entry.canonical
            or hashlib.sha256(canonical).hexdigest() != ref.content_sha256
            or envelope.source_sequence != ref.source_sequence
            or envelope.event_id != ref.event_id
            or getattr(accepted, "canonical", None) != entry.canonical
            or getattr(accepted, "evidence_ref", None) is not ref
            or getattr(accepted, "evidence_priority", None) != entry.evidence_priority
            or getattr(accepted, "key_epoch", None) != entry.key_epoch
            or getattr(accepted, "key_id", None) != entry.key_id
        ):
            raise ProjectionConflict("Projection V2 retained prefix authority changed")
        records.append(
            StoredEvidenceRecord(
                envelope=envelope.model_dump(exclude_none=True),
                canonical_envelope=canonical,
                priority=priority,
                # accepted_at is validated by the storage contract but is not a
                # persisted Projection V2 fact or reducer input.
                accepted_at="1970-01-01T00:00:00Z",
                ref=ref,
            )
        )
        expected_sequence += 1
    if (
        not records
        or expected_sequence != cursor.source_sequence + 1
        or records[-1].ref.source_sequence != cursor.source_sequence
        or records[-1].ref.event_id != cursor.event_id
        or records[-1].ref.content_sha256 != cursor.content_sha256
        or records[-1].ref.frame_sha256 != cursor.frame_sha256
    ):
        raise ProjectionConflict("Projection V2 retained prefix does not bind its old cursor")
    return tuple(records)


def _same_stored_record_v2(
    left: StoredEvidenceRecord,
    right: StoredEvidenceRecord,
) -> bool:
    try:
        left_key = _exact_coverage_record_key(left)
        right_key = _exact_coverage_record_key(right)
        return left_key == right_key
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return False


def _insert_v2_incident(
    connection: sqlite3.Connection,
    incident: IncidentV1,
    result_kind: str,
) -> None:
    placeholders = ",".join("?" for _ in _INCIDENT_COLUMNS)
    connection.execute(
        f"INSERT INTO incidents({','.join(_INCIDENT_COLUMNS)}) VALUES({placeholders})",
        _encode_incident(incident, result_kind),
    )


def _insert_v2_candidate(
    connection: sqlite3.Connection,
    candidate: ContainmentCandidateV1,
) -> None:
    placeholders = ",".join("?" for _ in _CANDIDATE_COLUMNS)
    connection.execute(
        f"INSERT INTO candidates({','.join(_CANDIDATE_COLUMNS)}) VALUES({placeholders})",
        _encode_candidate(candidate),
    )


def _candidate_key_tuple_v2(
    key: CandidateDuplicateKey,
) -> tuple[str, str, str, str, str, str]:
    if type(key) is not CandidateDuplicateKey:
        raise CorrelationProjectionError("candidate duplicate key is not exact")
    return (
        key.host_id,
        key.boot_id,
        key.docker_container_id,
        key.docker_started_at,
        key.detector_bundle_sha256,
        key.destination_ipv4,
    )


def _active_duplicate_v2(
    connection: sqlite3.Connection,
    key: CandidateDuplicateKey,
    *,
    current_trigger_order: tuple[int, str],
) -> ActiveCandidateObservation | None:
    if (
        type(current_trigger_order) is not tuple
        or len(current_trigger_order) != 2
        or type(current_trigger_order[0]) is not int
        or type(current_trigger_order[1]) is not str
    ):
        raise CorrelationProjectionError("current trigger order is not exact")
    columns = ",".join(_CANDIDATE_COLUMNS)
    rows = connection.execute(
        f"SELECT {columns} FROM candidates WHERE "
        "host_id=? AND boot_id=? AND docker_container_id=? AND docker_started_at=? "
        "AND detector_bundle_sha256=? AND destination_ipv4=? "
        "ORDER BY primary_source_sequence COLLATE BINARY,"
        "primary_event_id COLLATE BINARY,candidate_id COLLATE BINARY LIMIT 2",
        _candidate_key_tuple_v2(key),
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict(
            "Projection V2 has multiple active candidates for one duplicate key"
        )
    if not rows:
        return None
    row = rows[0]
    if _candidate_duplicate_key_from_row(row) != _candidate_key_tuple_v2(key):
        raise ProjectionConflict("Projection V2 duplicate lookup returned another key")
    candidate = _decode_candidate(row)
    if (
        candidate.primary_source_sequence,
        candidate.primary_event_id,
    ) >= current_trigger_order:
        raise ProjectionConflict("Projection V2 active primary is not before the current trigger")
    return ActiveCandidateObservation(
        key=key,
        candidate_id=candidate.candidate_id,
        primary_source_sequence=candidate.primary_source_sequence,
        primary_event_id=candidate.primary_event_id,
    )


def _historical_active_duplicate_v2(
    connection: sqlite3.Connection,
    key: CandidateDuplicateKey,
    *,
    current_trigger_order: tuple[int, str],
) -> ActiveCandidateObservation | None:
    if (
        type(current_trigger_order) is not tuple
        or len(current_trigger_order) != 2
        or type(current_trigger_order[0]) is not int
        or type(current_trigger_order[1]) is not str
    ):
        raise CorrelationProjectionError("historical trigger order is not exact")
    sequence, event_id = current_trigger_order
    columns = ",".join(_CANDIDATE_COLUMNS)
    rows = connection.execute(
        f"SELECT {columns} FROM candidates WHERE "
        "host_id=? AND boot_id=? AND docker_container_id=? AND docker_started_at=? "
        "AND detector_bundle_sha256=? AND destination_ipv4=? AND "
        "(primary_source_sequence<? OR "
        "(primary_source_sequence=? AND primary_event_id<?)) "
        "ORDER BY primary_source_sequence COLLATE BINARY,"
        "primary_event_id COLLATE BINARY,candidate_id COLLATE BINARY LIMIT 2",
        (
            *_candidate_key_tuple_v2(key),
            _encode_uint64_v2(sequence),
            _encode_uint64_v2(sequence),
            event_id,
        ),
    ).fetchall()
    if len(rows) > 1:
        raise ProjectionConflict("Projection V2 has multiple historical active candidates")
    if not rows:
        return None
    row = rows[0]
    if _candidate_duplicate_key_from_row(row) != _candidate_key_tuple_v2(key):
        raise ProjectionConflict("Projection V2 historical lookup returned another key")
    candidate = _decode_candidate(row)
    if (
        candidate.primary_source_sequence,
        candidate.primary_event_id,
    ) >= current_trigger_order:
        raise ProjectionConflict(
            "Projection V2 historical active primary is not before its trigger"
        )
    return ActiveCandidateObservation(
        key=key,
        candidate_id=candidate.candidate_id,
        primary_source_sequence=candidate.primary_source_sequence,
        primary_event_id=candidate.primary_event_id,
    )


def _replay_pread_v2(
    descriptor: int,
    size: int,
    *,
    maximum: int,
    counters: _ReplayComputeCounters,
) -> bytes:
    if (
        type(descriptor) is not int
        or descriptor < 0
        or type(size) is not int
        or not 0 <= size <= maximum
        or type(maximum) is not int
        or maximum < 0
        or type(counters) is not _ReplayComputeCounters
    ):
        raise TypeError("Projection V2 replay descriptor bounds are not exact")
    parts: list[bytes] = []
    offset = 0
    while offset < size:
        counters.administrative_visits += 1
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise ProjectionConflict("Projection V2 replay descriptor shortened")
        parts.append(chunk)
        offset += len(chunk)
    return b"".join(parts)


def _validate_replay_snapshot_shape_v2(
    snapshot: _ReplayInputSnapshot,
) -> tuple[
    _ReplaySourceSnapshot,
    _AckReplaySnapshot,
    _CorrelationReplaySnapshot,
    tuple[_FrozenPCCCorrelationInput, ...],
    bytes,
    int,
    int,
]:
    if type(snapshot) is not _ReplayInputSnapshot:
        raise TypeError("Projection V2 compute requires an exact replay snapshot")
    purpose = snapshot.purpose
    source = snapshot.source
    ack = snapshot.ack
    correlation = snapshot.correlation
    pcc_inputs = snapshot.pcc_inputs
    schema_domain = snapshot.schema_domain
    base_generation = snapshot.base_projection_generation
    publish_generation = snapshot.publish_generation
    if (
        type(purpose) is not _ReplayPurpose
        or type(source) is not _ReplaySourceSnapshot
        or type(ack) is not _AckReplaySnapshot
        or type(correlation) is not _CorrelationReplaySnapshot
        or type(pcc_inputs) is not tuple
        or type(schema_domain) is not bytes
        or type(base_generation) is not int
        or not 1 <= base_generation < MAX_UINT64
        or type(publish_generation) is not int
        or publish_generation != base_generation + 1
        or not 1 <= publish_generation <= MAX_UINT64
    ):
        raise TypeError("Projection V2 replay snapshot fields are not exact")
    if any(type(item) is not _FrozenPCCCorrelationInput for item in pcc_inputs):
        raise TypeError("Projection V2 replay PCC inputs are not exact")
    if (
        type(source.lifecycle_token) is not bytes
        or len(source.lifecycle_token) != 32
        or type(source.source_revision) is not int
        or source.source_revision < 0
        or (source.terminal_ref is not None and type(source.terminal_ref) is not EvidenceRef)
        or type(source.retained_ranges) is not tuple
        or type(source.records) is not tuple
        or type(source.segments) is not tuple
        or any(type(item) is not _ReplayRecordDescriptor for item in source.records)
        or any(type(item) is not _ReplaySegmentDescriptor for item in source.segments)
    ):
        raise TypeError("Projection V2 replay source facts are not exact")
    if any(
        type(item) is not tuple
        or len(item) != 2
        or type(item[0]) is not int
        or type(item[1]) is not int
        or not 1 <= item[0] <= item[1] <= MAX_UINT64
        for item in source.retained_ranges
    ):
        raise TypeError("Projection V2 replay retained ranges are not exact")
    retention_facts = snapshot.retention_facts
    if source.retained_ranges and retention_facts is None:
        raise ProjectionAuthorityError(
            "Projection V2 sparse replay lacks authenticated retention facts"
        )
    if retention_facts is not None and (
        type(retention_facts) is not _RetentionReplayFacts
        or type(retention_facts.completed_state_sha256) is not bytes
        or len(retention_facts.completed_state_sha256) != 32
        or retention_facts.retained_ranges != source.retained_ranges
        or type(retention_facts.terminal_sequence) is not int
        or source.terminal_ref is None
        or retention_facts.terminal_sequence != source.terminal_ref.source_sequence
    ):
        raise TypeError("Projection V2 retention replay facts are not exact")
    if ack.retention_pending is not (retention_facts is not None):
        raise ProjectionAuthorityError(
            "Projection V2 retention pending lacks its exact frozen scope"
        )
    if source.terminal_ref is not None:
        try:
            _exact_coverage_ref_key(source.terminal_ref)
        except ValueError as error:
            raise TypeError("Projection V2 replay terminal ref is malformed") from error
    elif source.records or source.segments:
        raise TypeError("Projection V2 empty replay source has persisted facts")
    if (
        type(ack.lifecycle_token) is not bytes
        or len(ack.lifecycle_token) != 32
        or type(ack.mutation_revision) is not int
        or ack.mutation_revision < 0
        or type(ack.generation) is not int
        or not 0 <= ack.generation <= MAX_UINT64
        or (ack.confirmed is not None and type(ack.confirmed) is not tuple)
        or (ack.pending is not None and type(ack.pending) is not tuple)
        or type(ack.committed_prefix_size) is not int
        or type(ack.committed_prefix_sha256) is not bytes
        or len(ack.committed_prefix_sha256) != 32
        or type(ack.retention_pending) is not bool
        or type(ack.descriptor) is not int
        or type(ack.device) is not int
        or type(ack.inode) is not int
        or type(ack.size) is not int
    ):
        raise TypeError("Projection V2 replay ACK facts are not exact")
    predecessor = correlation.predecessor
    if (
        type(correlation.lifecycle_token) is not bytes
        or len(correlation.lifecycle_token) != 32
        or callable(correlation.revision)
        or type(predecessor) is not _ProjectionPredecessor
        or type(correlation.predecessor_canonical) is not bytes
        or type(correlation.detector_bundle_sha256) is not str
        or _HEX64_V2.fullmatch(correlation.detector_bundle_sha256) is None
        or type(correlation.registry_facts_canonical) is not bytes
    ):
        raise TypeError("Projection V2 replay correlation facts are not exact")
    try:
        predecessor_seal = _seal_projection_predecessor(predecessor)
    except (AttributeError, TypeError, ValueError) as error:
        raise TypeError("Projection V2 replay predecessor is malformed") from error
    empty_predecessor = _ProjectionPredecessor(
        base_generation,
        None,
        0,
        None,
        None,
        None,
    )
    if (
        predecessor_seal.canonical != correlation.predecessor_canonical
        or predecessor.generation != base_generation
        or (purpose is _ReplayPurpose.INITIAL and predecessor != empty_predecessor)
        or (
            purpose is _ReplayPurpose.V2_REBUILD
            and predecessor != empty_predecessor
            and (
                predecessor.source_sequence == 0
                or predecessor.host_id is None
                or predecessor.event_id is None
                or predecessor.content_sha256 is None
            )
        )
    ):
        raise ProjectionConflict("Projection V2 replay predecessor is not exact")
    return (
        source,
        ack,
        correlation,
        pcc_inputs,
        schema_domain,
        base_generation,
        publish_generation,
    )


def _decode_replay_records_v2(
    source: _ReplaySourceSnapshot,
    counters: _ReplayComputeCounters,
) -> tuple[StoredEvidenceRecord, ...]:
    if source.terminal_ref is None:
        if source.records or source.segments:
            raise ProjectionConflict("Projection V2 empty replay source changed")
        return ()
    retained_ranges = source.retained_ranges
    retained_index = 0
    expected_sequence = 1
    records_by_segment: list[list[_ReplayRecordDescriptor]] = [[] for _segment in source.segments]
    for record in source.records:
        counters.administrative_visits += 1
        try:
            _exact_coverage_ref_key(record.ref)
        except ValueError as error:
            raise TypeError("Projection V2 replay record ref is malformed") from error
        if (
            type(record.ref) is not EvidenceRef
            or type(record.accepted_at) is not str
            or type(record.canonical_record) is not bytes
            or type(record.segment_index) is not int
            or not 0 <= record.segment_index < len(source.segments)
        ):
            raise TypeError("Projection V2 replay record descriptor is not exact")
        sequence = record.ref.source_sequence
        while retained_index < len(retained_ranges) and (
            retained_ranges[retained_index][1] < expected_sequence
        ):
            raise ProjectionConflict("Projection V2 replay retained prefix overlaps live evidence")
        while expected_sequence < sequence:
            if retained_index >= len(retained_ranges):
                raise ProjectionConflict("Projection V2 replay source has an unauthenticated gap")
            start, end = retained_ranges[retained_index]
            if start != expected_sequence or end >= sequence:
                raise ProjectionConflict("Projection V2 replay retained range is not an exact gap")
            expected_sequence = end + 1
            retained_index += 1
        if sequence != expected_sequence:
            raise ProjectionConflict("Projection V2 replay live sequence overlaps retention")
        expected_sequence += 1
        records_by_segment[record.segment_index].append(record)
    for segment_index, segment in enumerate(source.segments):
        counters.administrative_visits += 1
        if (
            type(segment.descriptor) is not int
            or segment.descriptor < 0
            or type(segment.device) is not int
            or type(segment.inode) is not int
            or type(segment.size) is not int
            or not 0 < segment.size <= MAX_SEGMENT_BYTES
            or type(segment.maximum_prefix_bytes) is not int
            or not 0 < segment.maximum_prefix_bytes <= segment.size
            or type(segment.relative_path) is not str
        ):
            raise TypeError("Projection V2 replay segment descriptor is not exact")
        info = os.fstat(segment.descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino, info.st_size)
            != (segment.device, segment.inode, segment.size)
            or fcntl.fcntl(segment.descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        ):
            raise ProjectionConflict("Projection V2 replay segment binding changed")
        prefix = _replay_pread_v2(
            segment.descriptor,
            segment.maximum_prefix_bytes,
            maximum=MAX_SEGMENT_BYTES,
            counters=counters,
        )
        try:
            decoded = decode_frames(prefix, max_frame=MAX_EVIDENCE_RECORD_BYTES)
        except (JournalCorrupt, ValueError) as error:
            raise ProjectionConflict("Projection V2 replay segment is corrupt") from error
        expected = records_by_segment[segment_index]
        if (
            decoded.torn_tail
            or decoded.verified_bytes != segment.maximum_prefix_bytes
            or len(decoded.records) != len(expected)
        ):
            raise ProjectionConflict("Projection V2 replay frames differ from snapshot")
        for frame, descriptor in zip(decoded.records, expected, strict=True):
            counters.administrative_visits += 1
            if (
                frame.offset != descriptor.ref.frame_offset
                or frame.size != descriptor.ref.frame_size
                or frame.record_hash.hex() != descriptor.ref.frame_sha256
                or frame.payload != descriptor.canonical_record
            ):
                raise ProjectionConflict("Projection V2 replay frame binding changed")

    records: list[StoredEvidenceRecord] = []
    for descriptor in source.records:
        counters.administrative_visits += 1
        try:
            accepted = decode_strict(
                descriptor.canonical_record,
                _AcceptedEnvelopeRecordV1,
                MAX_EVIDENCE_RECORD_BYTES,
            )
            envelope = accepted.envelope
            canonical_envelope = canonical_json(envelope)
            priority = EvidencePriority(accepted.evidence_priority)
        except (TypeError, ValueError, ValidationError) as error:
            raise ProjectionValidationError(
                "Projection V2 replay accepted record is invalid"
            ) from error
        ref = descriptor.ref
        if (
            accepted.accepted_at != descriptor.accepted_at
            or accepted.outer.sequence != ref.source_sequence
            or accepted.outer.event_id != ref.event_id
            or accepted.outer.content_sha256 != ref.content_sha256
        ):
            raise ProjectionValidationError("Projection V2 replay accepted outer facts changed")
        records.append(
            StoredEvidenceRecord(
                envelope=envelope,
                canonical_envelope=canonical_envelope,
                priority=priority,
                accepted_at=descriptor.accepted_at,
                ref=ref,
            )
        )
    if (
        not records
        or records[-1].ref != source.terminal_ref
        or expected_sequence != source.terminal_ref.source_sequence + 1
        or retained_index != len(retained_ranges)
    ):
        raise ProjectionConflict("Projection V2 replay source is not contiguous")
    return tuple(records)


def _exact_replay_ack_identity_v2(
    value: object,
) -> tuple[int, str, str] | None:
    if value is None:
        return None
    if (
        type(value) is not tuple
        or len(value) != 3
        or type(value[0]) is not int
        or not 1 <= value[0] <= MAX_UINT64
        or type(value[1]) is not str
        or _EVENT_ID_V2.fullmatch(value[1]) is None
        or type(value[2]) is not str
        or _HEX64_V2.fullmatch(value[2]) is None
    ):
        raise TypeError("Projection V2 replay ACK identity is not exact")
    return value


def _verify_replay_ack_v2(
    ack: _AckReplaySnapshot,
    terminal: EvidenceRef | None,
    counters: _ReplayComputeCounters,
) -> None:
    terminal_identity: tuple[int, str, str] | None = None
    if terminal is not None:
        try:
            terminal_key = _exact_coverage_ref_key(terminal)
        except ValueError as error:
            raise TypeError("Projection V2 replay ACK terminal is malformed") from error
        terminal_identity = (terminal_key[6], terminal_key[5], terminal_key[7])
    confirmed = _exact_replay_ack_identity_v2(ack.confirmed)
    _exact_replay_ack_identity_v2(ack.pending)
    if confirmed != terminal_identity or not 0 <= ack.committed_prefix_size <= ack.size:
        raise ProjectionAuthorityError("Projection V2 replay ACK boundary is not strict")
    info = os.fstat(ack.descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or (info.st_dev, info.st_ino, info.st_size) != (ack.device, ack.inode, ack.size)
        or fcntl.fcntl(ack.descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
    ):
        raise ProjectionAuthorityError("Projection V2 replay ACK descriptor changed")
    prefix = _replay_pread_v2(
        ack.descriptor,
        ack.committed_prefix_size,
        maximum=ack.size,
        counters=counters,
    )
    if hashlib.sha256(prefix).digest() != ack.committed_prefix_sha256:
        raise ProjectionAuthorityError("Projection V2 replay ACK prefix changed")
    try:
        decoded = decode_frames(prefix, max_frame=_MAX_ACK_RECORD_BYTES)
    except (JournalCorrupt, ValueError) as error:
        raise ProjectionAuthorityError("Projection V2 replay ACK prefix is corrupt") from error
    if decoded.torn_tail or decoded.verified_bytes != len(prefix):
        raise ProjectionAuthorityError("Projection V2 replay ACK prefix is incomplete")
    reduced_confirmed: tuple[int, str, str] | None = None
    reduced_pending: tuple[int, str, str] | None = None
    reduced_generation = 0
    for frame in decoded.records:
        counters.administrative_visits += 1
        try:
            record = decode_strict(
                frame.payload,
                _AckJournalRecordV1,
                _MAX_ACK_RECORD_BYTES,
            )
            if frame.payload != canonical_json(record):
                raise ValueError("ACK record is not canonical")
            identity = _exact_replay_ack_identity_v2(
                (record.sequence, record.event_id, record.content_sha256)
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise ProjectionAuthorityError("Projection V2 replay ACK record is invalid") from error
        assert identity is not None
        if record.kind == "pending_ack":
            expected_sequence = 1 if reduced_confirmed is None else reduced_confirmed[0] + 1
            if reduced_pending is not None or identity[0] != expected_sequence:
                raise ProjectionAuthorityError(
                    "Projection V2 replay ACK pending transition is invalid"
                )
            reduced_pending = identity
            continue
        if reduced_pending is None or identity != reduced_pending:
            raise ProjectionAuthorityError("Projection V2 replay ACK confirmation is invalid")
        reduced_confirmed = identity
        reduced_pending = None
        reduced_generation += 1
    if (
        reduced_confirmed != confirmed
        or reduced_pending is not None
        or reduced_generation != ack.generation
    ):
        raise ProjectionAuthorityError("Projection V2 replay ACK prefix facts changed")


def _replay_connection_v2(schema_domain: bytes) -> sqlite3.Connection:
    if type(schema_domain) is not bytes or not schema_domain.startswith(_REPLAY_SCHEMA_DOMAIN_V2):
        raise TypeError("Projection V2 replay schema domain is not exact")
    raw = schema_domain[len(_REPLAY_SCHEMA_DOMAIN_V2) :]
    if hashlib.sha256(raw).hexdigest() != _SCHEMA_V2_SHA256:
        raise ProjectionConflict("Projection V2 frozen schema bytes changed")
    try:
        script = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ProjectionConflict("Projection V2 frozen schema is not UTF-8") from error
    connection = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        check_same_thread=False,
    )
    try:
        _configure_v2_connection(connection, file_backed=False)
        connection.executescript(script)
        actual_tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        metadata = dict(connection.execute("SELECT key,value FROM schema_meta ORDER BY key"))
        if actual_tables != _TABLE_NAMES_V2 or metadata != _SCHEMA_META_V2:
            raise ProjectionConflict("Projection V2 frozen schema is not exact")
        if [str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()] != [
            "ok"
        ]:
            raise ProjectionConflict("Projection V2 frozen schema integrity failed")
        _verify_v2_pragmas(connection)
    except BaseException:
        connection.close()
        raise
    return connection


def _compute_reduce_base_v2(
    connection: sqlite3.Connection,
    prepared: _PreparedV2Record,
) -> None:
    envelope = prepared.envelope
    ref = prepared.record.ref
    sequence = _encode_uint64_v2(ref.source_sequence)
    coverage = prepared.coverage
    if coverage is not None:
        connection.execute(
            "INSERT INTO coverage_intervals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                envelope.event_id,
                envelope.host_id,
                coverage.component,
                coverage.kind,
                coverage.severity,
                coverage.opened_at,
                coverage.closed_at,
                _optional_uint64_v2(coverage.affected_source_sequence_start),
                _optional_uint64_v2(coverage.affected_source_sequence_end),
                _optional_uint64_v2(coverage.dropped_count),
                coverage.reason_code,
                _optional_uint64_v2(coverage.reconcile_generation),
                sequence,
                ref.content_sha256,
            ),
        )
        return
    falco = prepared.falco
    if falco is None:
        return
    if falco.docker_container_id is not None and falco.docker_started_at is not None:
        connection.execute(
            "INSERT INTO containers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(host_id,container_id,container_started_at) DO UPDATE SET "
            "image_id=excluded.image_id,repo_digests_json=excluded.repo_digests_json,"
            "immutable_spec_sha256=excluded.immutable_spec_sha256,"
            "inventory_revision=excluded.inventory_revision,"
            "last_event_id=excluded.last_event_id,"
            "last_source_sequence=excluded.last_source_sequence,"
            "last_content_sha256=excluded.last_content_sha256 "
            "WHERE excluded.last_source_sequence > containers.last_source_sequence",
            (
                envelope.host_id,
                falco.docker_container_id,
                falco.docker_started_at,
                falco.image_id,
                canonical_json(falco.repo_digests).decode("utf-8"),
                falco.immutable_spec_sha256,
                _optional_uint64_v2(falco.inventory_revision),
                envelope.event_id,
                sequence,
                ref.content_sha256,
                envelope.event_id,
                sequence,
                ref.content_sha256,
            ),
        )
    connection.execute(
        "INSERT INTO process_observations VALUES(?,?,?,?,?,?,?,?,?)",
        (
            envelope.event_id,
            envelope.host_id,
            falco.docker_container_id,
            falco.docker_started_at,
            falco.proc_name,
            falco.proc_exe_path,
            falco.proc_parent_name,
            sequence,
            ref.content_sha256,
        ),
    )
    connection.execute(
        "INSERT INTO network_observations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            envelope.event_id,
            envelope.host_id,
            falco.docker_container_id,
            falco.docker_started_at,
            int(falco.successful_connect),
            falco.destination_ipv4,
            falco.destination_port,
            falco.l4_protocol,
            int(falco.investigation_only),
            sequence,
            ref.content_sha256,
        ),
    )
    if not falco.successful_connect or falco.missing_required_fields or falco.investigation_only:
        incident = _incident_from_frozen_falco(
            falco,
            event_id=envelope.event_id,
            source_sequence=envelope.source_sequence,
            host_id=envelope.host_id,
            boot_id=envelope.boot_id,
            event_time=envelope.event_time,
            ingest_time=envelope.ingest_time,
            coverage_flags=tuple(envelope.coverage_flags),
        )
        _insert_v2_incident(connection, incident, "investigation")


def _persist_compute_pcc_result_v2(
    connection: sqlite3.Connection,
    result: object,
    proof: AuthenticatedPCCInput,
    active: ActiveCandidateObservation | None,
) -> None:
    if isinstance(result, CandidateCreated):
        candidate = result.candidate
        _insert_v2_incident(connection, result.incident, "candidate")
        _insert_v2_candidate(connection, candidate)
        roles = (
            ("primary_trigger", proof.snapshot.trigger),
            ("correlation_snapshot", proof),
        )
        for role, evidence in roles:
            connection.execute(
                "INSERT INTO candidate_evidence VALUES(?,?,?,?,?,?)",
                _encode_candidate_evidence(
                    candidate.candidate_id,
                    evidence.event_id,
                    evidence.source_sequence,
                    evidence.content_sha256,
                    role,
                    proof.event_id,
                ),
            )
        return
    if isinstance(result, Duplicate):
        if active is None or result.existing_candidate_id != active.candidate_id:
            raise ProjectionConflict("Projection V2 replay duplicate changed its active candidate")
        _insert_v2_incident(connection, result.incident, "duplicate")
        roles = (
            ("supporting_trigger", proof.snapshot.trigger),
            ("supporting_snapshot", proof),
        )
        for role, evidence in roles:
            connection.execute(
                "INSERT INTO candidate_evidence VALUES(?,?,?,?,?,?)",
                _encode_candidate_evidence(
                    result.existing_candidate_id,
                    evidence.event_id,
                    evidence.source_sequence,
                    evidence.content_sha256,
                    role,
                    proof.event_id,
                ),
            )
        return
    if isinstance(result, InvestigationOnly):
        _insert_v2_incident(connection, result.incident, "investigation")
        return
    if isinstance(result, Rejected):
        _insert_v2_incident(connection, result.incident, "rejected")
        return
    raise ProjectionConflict("Projection V2 replay correlation result is not exact")


def _compute_history_reduction_v2(
    frozen: _FrozenPCCCorrelationInput,
    entries: tuple[_FrozenReplayEntry, ...],
    counters: _ReplayComputeCounters,
) -> tuple[_HistoricalReductionResult, _ReplayMemoLeaf]:
    proof = frozen.proof
    if type(proof) is not AuthenticatedPCCInput:
        raise TypeError("Projection V2 replay PCC proof is not exact")
    snapshot = proof.snapshot
    trigger = snapshot.trigger
    compact_records: list[StoredEvidenceRecord] = []
    for entry in entries:
        counters.administrative_visits += 1
        if (
            entry.compact_member
            and entry.record.ref.source_sequence <= snapshot.coverage_through_sequence
        ):
            compact_records.append(entry.record)
    compact = tuple(compact_records)
    compact_count, compact_digest = _replay_compact_digest(compact)
    reduction = _reduce_historical_coverage_result(
        compact,
        host_id=proof.host_id,
        boot_id=proof.boot_id,
        trigger_event_id=trigger.event_id,
        trigger_source_sequence=trigger.source_sequence,
        trigger_event_time=trigger.event_time,
        clock_uncertainty_ms=trigger.clock_uncertainty_ms,
        coverage_through_sequence=snapshot.coverage_through_sequence,
        window_end=snapshot.decision_time,
    )
    counters.semantic_prefix_visits += reduction.diagnostics.semantic_prefix_visits
    key = (proof.event_id, proof.content_sha256)
    return reduction, _build_replay_memo_leaf(
        key,
        reduction,
        compact_count,
        compact_digest,
    )


def _compute_late_invalidations_v2(
    connection: sqlite3.Connection,
    prepared: _PreparedV2Record,
    proofs_by_event: dict[str, AuthenticatedPCCInput],
    counters: _ReplayComputeCounters,
) -> None:
    if prepared.coverage is None or not _late_coverage_may_invalidate_candidate(prepared.record):
        return
    rows = connection.execute(
        f"SELECT {','.join(_CANDIDATE_COLUMNS)} FROM candidates "
        "WHERE host_id=? ORDER BY candidate_id COLLATE BINARY LIMIT ?",
        (prepared.envelope.host_id, _INVALIDATION_CANDIDATE_CAP_V2 + 1),
    ).fetchall()
    if len(rows) > _INVALIDATION_CANDIDATE_CAP_V2:
        raise ProjectionConflict("Projection V2 replay invalidation cap exceeded")
    for row in rows:
        counters.administrative_visits += 1
        candidate = _decode_candidate(row)
        proof = proofs_by_event.get(candidate.correlation_snapshot_event_id)
        if type(proof) is not AuthenticatedPCCInput:
            raise ProjectionConflict("Projection V2 replay candidate lost PCC leaf")
        if _late_coverage_invalidates_candidate_values(proof, prepared.record):
            connection.execute(
                "INSERT INTO candidate_invalidations VALUES(?,?,?,?,?)",
                _encode_candidate_invalidation(
                    candidate.candidate_id,
                    prepared.envelope.event_id,
                    prepared.record.ref.source_sequence,
                    prepared.record.ref.content_sha256,
                    _INVALIDATION_REASON_V2,
                ),
            )


def _compute_replay(snapshot: _ReplayInputSnapshot) -> _ReplayComputation:
    """Project one immutable replay snapshot without consulting live authority."""
    (
        source,
        ack,
        correlation,
        frozen_inputs,
        schema_domain,
        _base_generation,
        publish_generation,
    ) = _validate_replay_snapshot_shape_v2(snapshot)
    counters = _ReplayComputeCounters()
    connection: sqlite3.Connection | None = None
    try:
        records = _decode_replay_records_v2(source, counters)
        _verify_replay_ack_v2(ack, source.terminal_ref, counters)
        prepared_records = tuple(_prepare_v2(record) for record in records)
        historical_prepared = tuple(_prepare_historical_record(record) for record in records)
        entries = _build_frozen_replay_entries(records, historical_prepared)

        frozen_by_event: dict[str, _FrozenPCCCorrelationInput] = {}
        pcc_leaves: list[_ReplayPCCLeaf] = []
        proofs_by_event: dict[str, AuthenticatedPCCInput] = {}
        for frozen_input in frozen_inputs:
            counters.administrative_visits += 1
            proof, _context = _validate_frozen_pcc_correlation_input(frozen_input)
            evidence_ref = proof.evidence_ref
            try:
                _exact_coverage_ref_key(evidence_ref)
            except ValueError as error:
                raise TypeError("Projection V2 replay PCC ref is malformed") from error
            key = (proof.event_id, proof.content_sha256)
            if proof.event_id in frozen_by_event:
                raise ProjectionConflict("Projection V2 replay PCC input is duplicated")
            frozen_by_event[proof.event_id] = frozen_input
            proofs_by_event[proof.event_id] = proof
            pcc_leaves.append(_build_replay_pcc_leaf(key, proof))

        connection = _replay_connection_v2(schema_domain)
        transcript = hashlib.sha256(_REPLAY_TRANSCRIPT_DOMAIN_V2)
        memo_leaves: list[_ReplayMemoLeaf] = []
        consumed_pcc: set[str] = set()
        connection.execute("BEGIN IMMEDIATE")
        for prepared in prepared_records:
            counters.administrative_visits += 1
            envelope = prepared.envelope
            ref = prepared.record.ref
            duplicate_row = connection.execute(
                "SELECT primary_event_id FROM projection_dedup "
                "WHERE dedup_kind=? AND logical_key_sha256=? AND is_primary=1",
                (prepared.dedup_kind, prepared.logical_key_sha256),
            ).fetchone()
            duplicate = None if duplicate_row is None else duplicate_row[0]
            if duplicate is not None and (
                type(duplicate) is not str or _EVENT_ID_V2.fullmatch(duplicate) is None
            ):
                raise ProjectionConflict("Projection V2 replay logical primary is invalid")
            primary_event_id = envelope.event_id if duplicate is None else duplicate
            placeholders = ",".join("?" for _ in _TABLE_LAYOUT_V2[1][1])
            connection.execute(
                f"INSERT INTO events({','.join(_TABLE_LAYOUT_V2[1][1])}) VALUES({placeholders})",
                _event_values_v2(prepared, duplicate),
            )
            connection.execute(
                "INSERT INTO projection_dedup("
                "event_id,dedup_kind,logical_key_sha256,primary_event_id,is_primary"
                ") VALUES(?,?,?,?,?)",
                (
                    envelope.event_id,
                    prepared.dedup_kind,
                    prepared.logical_key_sha256,
                    primary_event_id,
                    int(duplicate is None),
                ),
            )
            if duplicate is None:
                _compute_reduce_base_v2(connection, prepared)
                if prepared.coverage is not None:
                    _compute_late_invalidations_v2(
                        connection,
                        prepared,
                        proofs_by_event,
                        counters,
                    )
                elif envelope.event_type == "pcc_correlation_snapshot":
                    event_frozen = frozen_by_event.get(envelope.event_id)
                    if event_frozen is None:
                        raise ProjectionConflict("Projection V2 replay lacks frozen PCC facts")
                    proof = event_frozen.proof
                    if (
                        type(proof) is not AuthenticatedPCCInput
                        or type(proof.evidence_ref) is not EvidenceRef
                        or proof.evidence_ref != ref
                        or proof.source_sequence != ref.source_sequence
                        or proof.event_id != ref.event_id
                        or proof.content_sha256 != ref.content_sha256
                    ):
                        raise ProjectionConflict("Projection V2 replay PCC does not bind source")
                    active: ActiveCandidateObservation | None = None
                    coverage: HistoricalCoverageAssessment | None = None
                    if proof.snapshot.outcome == "complete":
                        reduction, memo = _compute_history_reduction_v2(
                            event_frozen,
                            entries,
                            counters,
                        )
                        context = event_frozen.context
                        expected_key = _duplicate_key(proof, proof.snapshot)
                        if (
                            context.pinned_detector_bundle_sha256
                            != correlation.detector_bundle_sha256
                            or context.lookup_key != expected_key
                        ):
                            raise ProjectionConflict(
                                "Projection V2 replay frozen PCC context changed"
                            )
                        active = _active_duplicate_v2(
                            connection,
                            expected_key,
                            current_trigger_order=(
                                proof.snapshot.trigger.source_sequence,
                                proof.snapshot.trigger.event_id,
                            ),
                        )
                        memo_leaves.append(memo)
                        coverage = reduction.timeline.assessment
                    rebound = _rebind_frozen_pcc_projection_context(
                        event_frozen,
                        coverage,
                        active,
                        None,
                    )
                    result = _correlate_frozen_pcc(rebound)
                    _persist_compute_pcc_result_v2(
                        connection,
                        result,
                        proof,
                        active,
                    )
                    consumed_pcc.add(envelope.event_id)
            connection.execute(
                "INSERT INTO ingest_cursors("
                "host_id,source_sequence,event_id,content_sha256,segment_id,"
                "segment_relative_path,frame_offset,frame_size,frame_sha256"
                ") VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET "
                "source_sequence=excluded.source_sequence,event_id=excluded.event_id,"
                "content_sha256=excluded.content_sha256,segment_id=excluded.segment_id,"
                "segment_relative_path=excluded.segment_relative_path,"
                "frame_offset=excluded.frame_offset,frame_size=excluded.frame_size,"
                "frame_sha256=excluded.frame_sha256",
                (
                    envelope.host_id,
                    _encode_uint64_v2(ref.source_sequence),
                    ref.event_id,
                    ref.content_sha256,
                    ref.segment_id,
                    ref.segment_relative_path,
                    _encode_uint64_v2(ref.frame_offset),
                    _encode_uint64_v2(ref.frame_size),
                    ref.frame_sha256,
                ),
            )
            transcript.update(
                canonical_json(
                    _replay_exact_fact(
                        (
                            ref,
                            prepared.record.canonical_envelope,
                            duplicate,
                            duplicate is None,
                        )
                    )
                )
            )
        if consumed_pcc != set(frozen_by_event):
            raise ProjectionConflict("Projection V2 replay has unused PCC facts")
        connection.execute("COMMIT")

        for validation_frozen, expected_memo in zip(
            (
                frozen_by_event[leaf.key[0]]
                for leaf in pcc_leaves
                if frozen_by_event[leaf.key[0]].proof.snapshot.outcome == "complete"
            ),
            memo_leaves,
            strict=True,
        ):
            counters.administrative_visits += 1
            _reduction, rebuilt = _compute_history_reduction_v2(
                validation_frozen,
                entries,
                counters,
            )
            if rebuilt != expected_memo:
                raise ProjectionConflict(
                    "Projection V2 replay independent history validation changed"
                )

        cursor = _current_v2_cursor(connection)
        terminal_ref = source.terminal_ref
        if terminal_ref is None:
            if cursor is not None or records:
                raise ProjectionConflict("Projection V2 empty replay cursor changed")
        elif cursor is None or cursor.source_sequence != terminal_ref.source_sequence:
            raise ProjectionConflict("Projection V2 replay terminal cursor changed")
        terminal_predecessor = _predecessor_v2(publish_generation, cursor)
        prefix_sha256 = _v2_snapshot_hash(connection)
        late_invalidations = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT candidate_id,coverage_event_id,coverage_source_sequence,"
                "coverage_content_sha256,reason_code FROM candidate_invalidations "
                "ORDER BY candidate_id,coverage_event_id"
            ).fetchall()
        )
        for _row in late_invalidations:
            counters.administrative_visits += 1
        database_image = connection.serialize()
        transcript_digest = transcript.digest()
        report_payload = (
            hashlib.sha256(database_image).digest(),
            hashlib.sha256(schema_domain).digest(),
            publish_generation,
            len(records),
            transcript_digest,
            tuple(leaf.facts_digest for leaf in pcc_leaves),
            tuple(leaf.facts_digest for leaf in memo_leaves),
            hashlib.sha256(canonical_json(_replay_exact_fact(late_invalidations))).digest(),
            _seal_projection_predecessor(terminal_predecessor).canonical,
            counters.administrative_visits,
            counters.semantic_prefix_visits,
            prefix_sha256,
        )
        report_bytes = _REPLAY_REPORT_DOMAIN_V2 + canonical_json(_replay_exact_fact(report_payload))
        return _ReplayComputation(
            database_image=database_image,
            transcript_count=len(records),
            transcript_digest=transcript_digest,
            pcc_leaves=tuple(pcc_leaves),
            memo_leaves=tuple(memo_leaves),
            late_invalidations=late_invalidations,
            terminal_predecessor=terminal_predecessor,
            administrative_visits=counters.administrative_visits,
            semantic_prefix_visits=counters.semantic_prefix_visits,
            report_bytes=report_bytes,
            prefix_sha256=prefix_sha256,
        )
    except (HistoricalCoverageConflict, HistoricalCoverageUnavailable) as error:
        raise ProjectionConflict("Projection V2 replay historical facts conflict") from error
    except sqlite3.IntegrityError as error:
        raise ProjectionConflict("Projection V2 replay facts conflict") from error
    finally:
        if connection is not None:
            connection.close()


def _validate_and_hydrate_replay(
    snapshot: _ReplayInputSnapshot,
    computation: _ReplayComputation,
) -> tuple[sqlite3.Connection, _UnpublishedV2ReplayReport]:
    """Validate one sealed computation into an unpublished private image."""
    (
        source,
        _ack,
        _correlation,
        _pcc_inputs,
        schema_domain,
        _base_generation,
        publish_generation,
    ) = _validate_replay_snapshot_shape_v2(snapshot)
    if (
        type(computation) is not _ReplayComputation
        or type(computation.database_image) is not bytes
        or not computation.database_image
        or type(computation.transcript_count) is not int
        or computation.transcript_count != len(source.records)
        or type(computation.transcript_digest) is not bytes
        or len(computation.transcript_digest) != 32
        or type(computation.pcc_leaves) is not tuple
        or type(computation.memo_leaves) is not tuple
        or type(computation.late_invalidations) is not tuple
        or type(computation.terminal_predecessor) is not _ProjectionPredecessor
        or type(computation.administrative_visits) is not int
        or computation.administrative_visits < 0
        or type(computation.semantic_prefix_visits) is not int
        or computation.semantic_prefix_visits < 0
        or type(computation.report_bytes) is not bytes
        or type(computation.prefix_sha256) is not str
        or _HEX64_V2.fullmatch(computation.prefix_sha256) is None
    ):
        raise ProjectionConflict("Projection V2 replay computation is not exact")
    expected_report_payload = (
        hashlib.sha256(computation.database_image).digest(),
        hashlib.sha256(schema_domain).digest(),
        publish_generation,
        computation.transcript_count,
        computation.transcript_digest,
        tuple(leaf.facts_digest for leaf in computation.pcc_leaves),
        tuple(leaf.facts_digest for leaf in computation.memo_leaves),
        hashlib.sha256(canonical_json(_replay_exact_fact(computation.late_invalidations))).digest(),
        _seal_projection_predecessor(computation.terminal_predecessor).canonical,
        computation.administrative_visits,
        computation.semantic_prefix_visits,
        computation.prefix_sha256,
    )
    expected_report_bytes = _REPLAY_REPORT_DOMAIN_V2 + canonical_json(
        _replay_exact_fact(expected_report_payload)
    )
    if computation.report_bytes != expected_report_bytes:
        raise ProjectionConflict("Projection V2 replay report seal changed")

    connection: sqlite3.Connection | None = None
    try:
        connection = _replay_connection_v2(schema_domain)
        connection.deserialize(computation.database_image)
        _verify_v2_schema(connection)
        if [str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()] != [
            "ok"
        ]:
            raise ProjectionConflict("Projection V2 replay image is not integral")
        cursor = _current_v2_cursor(connection)
        cursor_ref = _current_v2_cursor_ref(connection)
        terminal_ref = source.terminal_ref
        expected_predecessor = _predecessor_v2(publish_generation, cursor)
        invalidations = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT candidate_id,coverage_event_id,coverage_source_sequence,"
                "coverage_content_sha256,reason_code FROM candidate_invalidations "
                "ORDER BY candidate_id,coverage_event_id"
            ).fetchall()
        )
        if (
            (cursor is None) != (terminal_ref is None)
            or cursor_ref != terminal_ref
            or expected_predecessor != computation.terminal_predecessor
            or _seal_projection_predecessor(expected_predecessor).canonical
            != _seal_projection_predecessor(computation.terminal_predecessor).canonical
            or invalidations != computation.late_invalidations
            or _v2_snapshot_hash(connection) != computation.prefix_sha256
            or connection.serialize() != computation.database_image
        ):
            raise ProjectionConflict("Projection V2 hydrated replay facts changed")
        if terminal_ref is not None and (
            cursor is None
            or cursor.source_sequence != terminal_ref.source_sequence
            or cursor.event_id != terminal_ref.event_id
            or cursor.content_sha256 != terminal_ref.content_sha256
        ):
            raise ProjectionConflict("Projection V2 hydrated replay cursor changed")
        report = _UnpublishedV2ReplayReport(
            cursor=cursor,
            applied_count=computation.transcript_count,
            prefix_sha256=computation.prefix_sha256,
        )
        hydrated = connection
        connection = None
        return hydrated, report
    finally:
        if connection is not None:
            connection.close()


class _V2ProjectionOwner:
    """Dormant single-owner reducer for exact authenticated V2 projection tests."""

    _connection: sqlite3.Connection | None
    _evidence: SegmentStore
    _acknowledgements: AckJournal
    _journal: CorrelationRequestJournal
    _registry: SpecialUseRegistry
    _evidence_lifecycle: object
    _ack_lifecycle: object
    _authority: CorrelationProjectionAuthority | None
    _generation: int
    _step_hook: Callable[[str], None]
    _mutex: RLockType
    _replay_state_lock: LockType
    _replay_state_condition: Condition
    _replay_reservation: _ReplayReservation | None
    _staged_replay: _StagedReplayBinding | None
    _replay_status: _ReplayStatus
    _replay_test_barrier: _ReplayTestBarrier | None
    _healthy: bool
    _closed: bool
    _owns_authorities: bool

    def __init__(self) -> None:
        raise TypeError("use the module-private Projection V2 owner factory")

    @classmethod
    def _take_ownership(
        cls,
        connection: sqlite3.Connection,
        *,
        evidence: SegmentStore,
        acknowledgements: AckJournal,
        journal: CorrelationRequestJournal,
        registry: SpecialUseRegistry,
        step_hook: Callable[[str], None] | None,
    ) -> _V2ProjectionOwner:
        return cls._open_owner(
            connection,
            evidence=evidence,
            acknowledgements=acknowledgements,
            journal=journal,
            registry=registry,
            step_hook=step_hook,
            owns_authorities=True,
        )

    @classmethod
    def _borrow_authorities(
        cls,
        connection: sqlite3.Connection,
        *,
        evidence: SegmentStore,
        acknowledgements: AckJournal,
        journal: CorrelationRequestJournal,
        registry: SpecialUseRegistry,
        step_hook: Callable[[str], None] | None,
    ) -> _V2ProjectionOwner:
        try:
            return cls._open_owner(
                connection,
                evidence=evidence,
                acknowledgements=acknowledgements,
                journal=journal,
                registry=registry,
                step_hook=step_hook,
                owns_authorities=False,
            )
        except BaseException as primary:
            if isinstance(connection, sqlite3.Connection):
                for attempt in (1, 2):
                    try:
                        connection.close()
                    except BaseException as error:  # noqa: BLE001 - adopted resource
                        primary.add_note(
                            "borrowed Projection V2 connection cleanup failure "
                            f"(attempt {attempt}): {type(error).__name__}: {error}"
                        )
                    else:
                        break
            raise

    @classmethod
    def _open_owner(
        cls,
        connection: sqlite3.Connection,
        *,
        evidence: SegmentStore,
        acknowledgements: AckJournal,
        journal: CorrelationRequestJournal,
        registry: SpecialUseRegistry,
        step_hook: Callable[[str], None] | None,
        owns_authorities: bool,
    ) -> _V2ProjectionOwner:
        if (
            not isinstance(connection, sqlite3.Connection)
            or type(evidence) is not SegmentStore
            or type(acknowledgements) is not AckJournal
            or type(journal) is not CorrelationRequestJournal
            or type(registry) is not SpecialUseRegistry
            or getattr(acknowledgements, "_store", None) is not evidence
            or getattr(journal, "_store", None) is not evidence
            or (step_hook is not None and not callable(step_hook))
            or type(owns_authorities) is not bool
        ):
            raise ProjectionAuthorityError(
                "Projection V2 owner requires exact same-lifecycle resources"
            )
        try:
            journal_is_live = journal._is_bound_to(evidence)
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 journal lifecycle cannot be validated"
            ) from error
        if journal_is_live is not True:
            raise ProjectionAuthorityError(
                "Projection V2 journal is not live on the evidence lifecycle"
            )
        generation = 1
        owner = object.__new__(cls)
        owner._connection = connection
        owner._evidence = evidence
        owner._acknowledgements = acknowledgements
        owner._journal = journal
        owner._registry = registry
        owner._evidence_lifecycle = evidence._lifecycle_identity
        owner._ack_lifecycle = acknowledgements._lifecycle_identity
        owner._authority = None
        owner._generation = generation
        owner._step_hook = step_hook or (lambda _step: None)
        owner._mutex = RLock()
        owner._replay_state_lock = Lock()
        owner._replay_state_condition = Condition(owner._replay_state_lock)
        owner._replay_reservation = None
        owner._staged_replay = None
        owner._replay_status = _ReplayStatus(
            generation=generation,
            phase=_ReplayPhase.IDLE,
            reservation_present=False,
        )
        owner._replay_test_barrier = None
        owner._healthy = True
        owner._closed = False
        owner._owns_authorities = owns_authorities
        try:
            if connection.in_transaction:
                raise ProjectionConflict("Projection V2 owner cannot adopt an active transaction")
            _verify_v2_schema(connection)
            cursor = _current_v2_cursor(connection)
            acceptance_cursor = owner._healthy_acceptance_cursor()
            ack_boundary = owner._freeze_ack_boundary(acceptance_cursor)
            if cursor is not None and cursor.source_sequence > acceptance_cursor:
                raise ProjectionConflict("Projection V2 cursor exceeds authenticated acceptance")
            if cursor is not None and cursor.source_sequence > ack_boundary.confirmed_through:
                raise ProjectionConflict(
                    "Projection V2 cursor exceeds authenticated ACK confirmation"
                )
            owner._validate_cursor_evidence(connection, cursor)
            predecessor = _predecessor_v2(generation, cursor)
            created_authority = _create_correlation_projection_authority(
                evidence,
                registry,
                predecessor,
            )
            owner._authority = created_authority
            prefix_sha256 = owner._validate_persisted_prefix(
                connection,
                created_authority,
                predecessor,
                cursor,
            )
            owner._revalidate_reopen_authority(
                connection,
                created_authority,
                predecessor,
                cursor,
                acceptance_cursor,
                ack_boundary,
                prefix_sha256,
            )
        except ProjectionConflict as error:
            owner._healthy = False
            owner._close_after_factory_failure(error)
            raise
        except Exception as error:
            owner._healthy = False
            owner._close_after_factory_failure(error)
            raise ProjectionAuthorityError(
                "Projection V2 owner authority could not be created"
            ) from error
        except BaseException as error:
            owner._healthy = False
            owner._close_after_factory_failure(error)
            raise
        return owner

    def _revalidate_reopen_authority(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        cursor: ProjectionCursor | None,
        acceptance_cursor: int,
        ack_boundary: _ProjectionAckBoundaryV2,
        prefix_sha256: str,
    ) -> None:
        observed_ack_boundary = ack_boundary
        for _pass in range(2):
            if self._healthy_acceptance_cursor() != acceptance_cursor:
                raise ProjectionAuthorityError("Projection V2 acceptance changed during reopen")
            current_cursor = _current_v2_cursor(connection)
            if current_cursor != cursor:
                raise ProjectionConflict("Projection V2 cursor changed during reopen")
            self._validate_cursor_evidence(connection, current_cursor)
            if _v2_snapshot_hash(connection) != prefix_sha256:
                raise ProjectionConflict("Projection V2 persisted prefix changed during reopen")
            _validate_correlation_projection_predecessor(
                authority,
                predecessor,
            )
            observed_ack_boundary = self._revalidate_ack_boundary(
                observed_ack_boundary,
                acceptance_cursor,
            )

    def _healthy_acceptance_cursor(self) -> int:
        return _healthy_acceptance_cursor_v2(
            self._evidence,
            self._evidence_lifecycle,
        )

    def _current_ack_boundary(self) -> _ProjectionAckBoundaryV2:
        acknowledgements = self._acknowledgements
        if (
            type(acknowledgements) is not AckJournal
            or acknowledgements._store is not self._evidence
            or acknowledgements._lifecycle_identity is not self._ack_lifecycle
            or self._ack_lifecycle is not self._evidence_lifecycle
            or getattr(self._evidence, "_ack_journal_owner", None) is not acknowledgements
        ):
            raise ProjectionAuthorityError("Projection V2 ACK journal changed lifecycle")
        try:
            snapshot = acknowledgements.snapshot()
            self._evidence._validate_ack_journal_owner(
                acknowledgements,
                self._ack_lifecycle,
            )
            commitment = self._evidence._validate_ack_commitment_binding()
        except Exception as error:
            raise ProjectionAuthorityError("Projection V2 ACK authority is unavailable") from error
        if type(snapshot) is not AckJournalSnapshot or snapshot.healthy is not True:
            raise ProjectionAuthorityError("Projection V2 ACK snapshot is not exact and healthy")
        confirmed = _exact_ack_identity_v2(snapshot.confirmed)
        pending = _exact_ack_identity_v2(snapshot.pending)
        private_confirmed = _exact_ack_identity_v2(getattr(acknowledgements, "_confirmed", None))
        private_pending = _exact_ack_identity_v2(getattr(acknowledgements, "_pending", None))
        generation = getattr(acknowledgements, "_confirmed_generation", None)
        prefix_size = getattr(acknowledgements, "_committed_prefix_size", None)
        prefix_sha256 = getattr(
            acknowledgements,
            "_committed_prefix_sha256",
            None,
        )
        if (
            confirmed != private_confirmed
            or pending != private_pending
            or type(generation) is not int
            or not 0 <= generation <= MAX_UINT64
            or type(prefix_size) is not int
            or prefix_size < 0
            or type(prefix_sha256) is not str
            or _HEX64_V2.fullmatch(prefix_sha256) is None
            or (confirmed is None) != (generation == 0)
        ):
            raise ProjectionAuthorityError("Projection V2 ACK committed boundary is inconsistent")
        durable_confirmed = getattr(commitment, "confirmed", None)
        if confirmed is None:
            durable_identity_matches = durable_confirmed is None
        else:
            durable_identity_matches = (
                durable_confirmed is not None
                and getattr(durable_confirmed, "sequence", None) == confirmed.sequence
                and getattr(durable_confirmed, "event_id", None) == confirmed.event_id
                and getattr(durable_confirmed, "content_sha256", None) == confirmed.content_sha256
            )
        if (
            getattr(commitment, "phase", None) != "ready"
            or getattr(commitment, "generation", None) != generation
            or getattr(commitment, "journal_prefix_size", None) != prefix_size
            or getattr(commitment, "journal_prefix_sha256", None) != prefix_sha256
            or not durable_identity_matches
        ):
            raise ProjectionAuthorityError(
                "Projection V2 ACK cache differs from durable commitment"
            )
        try:
            if acknowledgements._hash_held_prefix(prefix_size).hex() != prefix_sha256:
                raise ProjectionAuthorityError("Projection V2 ACK committed prefix changed")
            if confirmed is not None:
                self._evidence._validate_ack_identity(
                    acknowledgements,
                    self._ack_lifecycle,
                    sequence=confirmed.sequence,
                    event_id=confirmed.event_id,
                    content_sha256=confirmed.content_sha256,
                )
            if pending is not None:
                next_record = next(
                    self._evidence.iter_authenticated_records(
                        after=0 if confirmed is None else confirmed.sequence,
                    ),
                    None,
                )
                if next_record is None or AckIdentity.from_ref(next_record.ref) != pending:
                    raise ProjectionAuthorityError(
                        "Projection V2 pending ACK is not the next evidence ref"
                    )
        except ProjectionAuthorityError:
            raise
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 ACK boundary does not bind evidence"
            ) from error
        return _ProjectionAckBoundaryV2(
            confirmed=confirmed,
            pending=pending,
            generation=generation,
            prefix_size=prefix_size,
            prefix_sha256=prefix_sha256,
        )

    def _freeze_ack_boundary(
        self,
        acceptance_cursor: int,
    ) -> _ProjectionAckBoundaryV2:
        boundary = self._current_ack_boundary()
        if boundary.confirmed_through > acceptance_cursor:
            raise ProjectionAuthorityError(
                "Projection V2 ACK confirmation exceeds authenticated acceptance"
            )
        return boundary

    def _freeze_unpublished_ack_anchor(
        self,
        acceptance_cursor: int,
    ) -> _AckUnpublishedAnchor:
        boundary = self._freeze_ack_boundary(acceptance_cursor)
        acknowledgements = self._acknowledgements
        try:
            anchor = acknowledgements._capture_unpublished_anchor(
                acceptance_cursor,
                _factory=_ACK_UNPUBLISHED_ANCHOR_FACTORY,
            )
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 unpublished ACK lost its authenticated anchor"
            ) from error
        if (
            anchor.lifecycle is not self._ack_lifecycle
            or anchor.confirmed != boundary.confirmed
            or anchor.pending != boundary.pending
            or anchor.generation != boundary.generation
            or anchor.prefix_size != boundary.prefix_size
            or anchor.prefix_sha256 != boundary.prefix_sha256
        ):
            raise ProjectionAuthorityError(
                "Projection V2 unpublished ACK boundary changed during capture"
            )
        return anchor

    def _revalidate_unpublished_ack_anchor(
        self,
        anchor: _AckUnpublishedAnchor,
        acceptance_cursor: int,
    ) -> None:
        acknowledgements = self._acknowledgements
        try:
            if (
                type(anchor) is not _AckUnpublishedAnchor
                or type(acceptance_cursor) is not int
                or acceptance_cursor != anchor.acceptance_cursor
                or self._healthy_acceptance_cursor() != acceptance_cursor
            ):
                raise ProjectionAuthorityError("Projection V2 unpublished ACK acceptance changed")
            acknowledgements._revalidate_unpublished_anchor(anchor)
        except ProjectionAuthorityError:
            raise
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 unpublished ACK anchor changed"
            ) from error

    def _revalidate_ack_boundary(
        self,
        frozen: _ProjectionAckBoundaryV2,
        acceptance_cursor: int,
    ) -> _ProjectionAckBoundaryV2:
        if type(frozen) is not _ProjectionAckBoundaryV2:
            raise ProjectionAuthorityError("Projection V2 frozen ACK boundary is not exact")
        current = self._freeze_ack_boundary(acceptance_cursor)
        if (
            current.confirmed_through < frozen.confirmed_through
            or current.generation < frozen.generation
            or current.prefix_size < frozen.prefix_size
        ):
            raise ProjectionAuthorityError("Projection V2 ACK boundary moved backwards")
        if current.confirmed_through == frozen.confirmed_through:
            if (
                current.confirmed != frozen.confirmed
                or current.generation != frozen.generation
                or current.prefix_size != frozen.prefix_size
                or current.prefix_sha256 != frozen.prefix_sha256
            ):
                raise ProjectionAuthorityError("Projection V2 ACK boundary was substituted")
            if frozen.pending is not None and current.pending != frozen.pending:
                raise ProjectionAuthorityError("Projection V2 frozen pending ACK was replaced")
        try:
            if (
                self._acknowledgements._hash_held_prefix(frozen.prefix_size).hex()
                != frozen.prefix_sha256
            ):
                raise ProjectionAuthorityError("Projection V2 frozen ACK prefix changed")
            if frozen.confirmed is not None:
                self._evidence._validate_ack_identity(
                    self._acknowledgements,
                    self._ack_lifecycle,
                    sequence=frozen.confirmed.sequence,
                    event_id=frozen.confirmed.event_id,
                    content_sha256=frozen.confirmed.content_sha256,
                )
        except ProjectionAuthorityError:
            raise
        except Exception as error:
            raise ProjectionAuthorityError(
                "Projection V2 frozen ACK prefix is unavailable"
            ) from error
        return current

    def _require_usable(self) -> tuple[sqlite3.Connection, CorrelationProjectionAuthority]:
        with self._replay_state_lock:
            if self._replay_reservation is not None:
                raise ProjectionAuthorityError("Projection V2 replay reservation is active")
        if self._closed:
            raise ProjectionUnhealthy("Projection V2 owner is closed")
        if not self._healthy:
            raise ProjectionUnhealthy("Projection V2 owner is unhealthy")
        connection = self._connection
        authority = self._authority
        if connection is None or authority is None:
            self._healthy = False
            raise ProjectionUnhealthy("Projection V2 owner lost its resources")
        return connection, authority

    def _replay_status_for_test(self) -> _ReplayStatus:
        with self._replay_state_lock:
            status = self._replay_status
            return _ReplayStatus(
                generation=status.generation,
                phase=status.phase,
                reservation_present=status.reservation_present,
                failure_phase=status.failure_phase,
            )

    def _register_replay_status_barrier_for_test(
        self,
        phase: _ReplayPhase,
    ) -> None:
        if type(phase) is not _ReplayPhase or phase not in (
            _ReplayPhase.COMPUTING,
            _ReplayPhase.VALIDATING,
        ):
            raise ProjectionAuthorityError("Projection V2 replay barrier phase is invalid")
        with self._replay_state_condition:
            if self._replay_test_barrier is not None:
                raise ProjectionAuthorityError("Projection V2 replay barrier is already registered")
            self._replay_test_barrier = _ReplayTestBarrier(phase=phase)

    def _release_replay_status_barrier_for_test(
        self,
        phase: _ReplayPhase,
    ) -> None:
        with self._replay_state_condition:
            barrier = self._replay_test_barrier
            if barrier is None or barrier.phase is not phase:
                raise ProjectionAuthorityError("Projection V2 replay barrier does not match")
            barrier.released = True
            self._replay_state_condition.notify_all()

    def _set_replay_status_locked(self, status: _ReplayStatus) -> None:
        self._replay_status = status
        barrier = self._replay_test_barrier
        if barrier is None or barrier.phase is not status.phase:
            return
        self._replay_state_condition.notify_all()
        self._replay_state_condition.wait_for(
            lambda: barrier.released,
            timeout=5.0,
        )
        if self._replay_test_barrier is barrier:
            self._replay_test_barrier = None

    def _validate_cursor_evidence(
        self,
        connection: sqlite3.Connection,
        cursor: ProjectionCursor | None,
    ) -> None:
        cursor_ref = _current_v2_cursor_ref(connection)
        if (cursor is None) != (cursor_ref is None):
            raise ProjectionConflict("Projection V2 cursor identity is incomplete")
        if cursor is None:
            return
        assert cursor_ref is not None
        if (
            cursor_ref.source_sequence != cursor.source_sequence
            or cursor_ref.event_id != cursor.event_id
            or cursor_ref.content_sha256 != cursor.content_sha256
            or cursor_ref.frame_sha256 != cursor.frame_sha256
        ):
            raise ProjectionConflict("Projection V2 cursor ref changed")
        try:
            resolved = self._evidence.resolve_authenticated_ref(cursor_ref)
        except EvidenceStoreError as error:
            raise ProjectionAuthorityError(
                "Projection V2 cursor is outside authenticated evidence"
            ) from error
        if resolved.ref != cursor_ref:
            raise ProjectionAuthorityError(
                "Projection V2 cursor does not bind exact authenticated evidence"
            )

    def _validate_v2_rebuild_cursor_evidence(
        self,
        connection: sqlite3.Connection,
        cursor: ProjectionCursor | None,
        retention_scope: _AuthenticatedRetentionReplayScope | None,
    ) -> None:
        if retention_scope is None:
            self._validate_cursor_evidence(connection, cursor)
            return
        if cursor is None:
            raise ProjectionConflict("Projection V2 retained rebuild lost its old cursor")
        cursor_ref = _current_v2_cursor_ref(connection)
        if (
            cursor_ref is None
            or cursor_ref.source_sequence != cursor.source_sequence
            or cursor_ref.event_id != cursor.event_id
            or cursor_ref.content_sha256 != cursor.content_sha256
            or cursor_ref.frame_sha256 != cursor.frame_sha256
            or sum(
                1
                for start, end in retention_scope.retained_ranges
                if start <= cursor.source_sequence <= end
            )
            != 1
        ):
            raise ProjectionConflict("Projection V2 retained rebuild old cursor is not exact")
        try:
            resolved = self._evidence._resolve_recovered_ack_identity(
                self._acknowledgements,
                self._ack_lifecycle,
                sequence=cursor.source_sequence,
                event_id=cursor.event_id,
                content_sha256=cursor.content_sha256,
            )
        except EvidenceStoreError as error:
            raise ProjectionAuthorityError(
                "Projection V2 retained rebuild cursor lost authority"
            ) from error
        if resolved is not None:
            raise ProjectionConflict("Projection V2 retained rebuild cursor was not retired")

    def _latch_unhealthy(self, primary: BaseException | None = None) -> None:
        self._healthy = False
        authority = self._authority
        if authority is None:
            return
        try:
            _close_correlation_projection_authority(authority)
        except BaseException as error:  # noqa: BLE001 - retain ambiguous handle
            if primary is not None:
                primary.add_note(
                    "secondary Projection V2 authority-close failure: "
                    f"{type(error).__name__}: {error}"
                )
        else:
            self._authority = None

    @staticmethod
    def _retry_rows_for_authority(
        connection: sqlite3.Connection,
        table: str,
        columns: tuple[str, ...],
        authority_column: str,
        authority_event_id: str,
        *,
        limit: int,
    ) -> list[sqlite3.Row]:
        selected = ",".join(columns)
        primary_key = next(item[2] for item in _TABLE_LAYOUT_V2 if item[0] == table)
        order = ",".join(f"{column} COLLATE BINARY" for column in primary_key)
        return connection.execute(
            f"SELECT {selected} FROM {table} WHERE {authority_column}=? "
            f"ORDER BY {order} LIMIT {limit}",
            (authority_event_id,),
        ).fetchall()

    def _validate_retry_base_closure(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedV2Record,
        *,
        is_primary: bool,
    ) -> None:
        event_id = prepared.envelope.event_id
        coverage_rows = connection.execute(
            "SELECT host_id,component,kind,severity,opened_at,closed_at,"
            "affected_source_sequence_start,affected_source_sequence_end,"
            "dropped_count,reason_code,reconcile_generation,source_sequence,"
            "content_sha256 FROM coverage_intervals WHERE event_id=? LIMIT 2",
            (event_id,),
        ).fetchall()
        process_rows = connection.execute(
            "SELECT host_id,container_id,container_started_at,proc_name,"
            "proc_exe_path,proc_parent_name,source_sequence,content_sha256 "
            "FROM process_observations WHERE event_id=? LIMIT 2",
            (event_id,),
        ).fetchall()
        network_rows = connection.execute(
            "SELECT host_id,container_id,container_started_at,successful_connect,"
            "destination_ipv4,destination_port,l4_protocol,investigation_only,"
            "source_sequence,content_sha256 FROM network_observations "
            "WHERE event_id=? LIMIT 2",
            (event_id,),
        ).fetchall()
        if not is_primary:
            if coverage_rows or process_rows or network_rows:
                raise ProjectionConflict("Projection V2 duplicate retry has reducer side effects")
            return
        ref = prepared.record.ref
        sequence = _encode_uint64_v2(ref.source_sequence)
        if prepared.coverage is not None:
            coverage = prepared.coverage
            expected_coverage = (
                prepared.envelope.host_id,
                coverage.component,
                coverage.kind,
                coverage.severity,
                coverage.opened_at,
                coverage.closed_at,
                _optional_uint64_v2(coverage.affected_source_sequence_start),
                _optional_uint64_v2(coverage.affected_source_sequence_end),
                _optional_uint64_v2(coverage.dropped_count),
                coverage.reason_code,
                _optional_uint64_v2(coverage.reconcile_generation),
                sequence,
                ref.content_sha256,
            )
            if (
                len(coverage_rows) != 1
                or tuple(coverage_rows[0]) != expected_coverage
                or process_rows
                or network_rows
            ):
                raise ProjectionConflict("Projection V2 coverage retry closure changed")
            return
        falco = prepared.falco
        if falco is None:
            if coverage_rows or process_rows or network_rows:
                raise ProjectionConflict("Projection V2 generic retry has reducer side effects")
            return
        expected_process = (
            prepared.envelope.host_id,
            falco.docker_container_id,
            falco.docker_started_at,
            falco.proc_name,
            falco.proc_exe_path,
            falco.proc_parent_name,
            sequence,
            ref.content_sha256,
        )
        expected_network = (
            prepared.envelope.host_id,
            falco.docker_container_id,
            falco.docker_started_at,
            int(falco.successful_connect),
            falco.destination_ipv4,
            falco.destination_port,
            falco.l4_protocol,
            int(falco.investigation_only),
            sequence,
            ref.content_sha256,
        )
        if (
            coverage_rows
            or len(process_rows) != 1
            or tuple(process_rows[0]) != expected_process
            or len(network_rows) != 1
            or tuple(network_rows[0]) != expected_network
        ):
            raise ProjectionConflict("Projection V2 Falco retry closure changed")

    def _retry_pcc_result(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
    ) -> tuple[
        AuthenticatedPCCInput,
        CandidateCreated | Duplicate | InvestigationOnly | Rejected,
    ]:
        completed = self._journal.completed_for_snapshot(prepared.record.ref)
        proof = _revalidate_completed_snapshot(completed)
        if (
            type(proof) is not AuthenticatedPCCInput
            or not self._evidence._authenticated_pcc_input_is_exact(proof)
            or type(proof.evidence_ref) is not EvidenceRef
            or proof.evidence_ref != prepared.record.ref
        ):
            raise ProjectionAuthorityError("Projection V2 retry lost completed PCC authority")
        if proof.snapshot.outcome == "failed":
            result = correlate_pcc(proof, CorrelationContext.failed_snapshot())
        else:
            key = _duplicate_key(proof, proof.snapshot)
            trigger = proof.snapshot.trigger
            active = _historical_active_duplicate_v2(
                connection,
                key,
                current_trigger_order=(
                    trigger.source_sequence,
                    trigger.event_id,
                ),
            )
            issued_proof, context = _issue_correlation_context(
                authority,
                completed,
                expected_predecessor=predecessor,
                active_duplicate=active,
            )
            if not _same_exact_pcc(proof, issued_proof):
                raise ProjectionAuthorityError("Projection V2 retry issued a changed PCC")
            result = correlate_pcc(issued_proof, context)
        final = _revalidate_completed_snapshot(completed)
        if not _same_exact_pcc(proof, final):
            raise ProjectionAuthorityError("Projection V2 completed PCC changed during retry")
        if not isinstance(
            result,
            (CandidateCreated, Duplicate, InvestigationOnly, Rejected),
        ):
            raise ProjectionAuthorityError("Projection V2 retry correlation result is not closed")
        return proof, result

    def _validate_retry_security_closure(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        *,
        is_primary: bool,
        retained_authority: bool,
    ) -> None:
        event_id = prepared.envelope.event_id
        self._validate_coverage_invalidation_closure(
            connection,
            prepared,
            is_primary=is_primary,
        )
        incident_rows = self._retry_rows_for_authority(
            connection,
            "incidents",
            _INCIDENT_COLUMNS,
            "authority_event_id",
            event_id,
            limit=2,
        )
        candidate_rows = self._retry_rows_for_authority(
            connection,
            "candidates",
            _CANDIDATE_COLUMNS,
            "correlation_snapshot_event_id",
            event_id,
            limit=2,
        )
        evidence_rows = self._retry_rows_for_authority(
            connection,
            "candidate_evidence",
            _TABLE_LAYOUT_V2[9][1],
            "authority_snapshot_event_id",
            event_id,
            limit=3,
        )
        if not is_primary:
            if incident_rows or candidate_rows or evidence_rows:
                raise ProjectionConflict("Projection V2 duplicate retry has security side effects")
            return
        if prepared.envelope.event_type == "pcc_correlation_snapshot":
            proof, result = self._retry_pcc_result(
                connection,
                authority,
                predecessor,
                prepared,
            )
            if isinstance(result, CandidateCreated):
                result_kind = "candidate"
            elif isinstance(result, Duplicate):
                result_kind = "duplicate"
            elif isinstance(result, InvestigationOnly):
                result_kind = "investigation"
            else:
                result_kind = "rejected"
            if len(incident_rows) != 1 or tuple(incident_rows[0]) != _encode_incident(
                result.incident, result_kind
            ):
                raise ProjectionConflict("Projection V2 PCC retry incident closure changed")
            if isinstance(result, CandidateCreated):
                candidate_id = result.candidate.candidate_id
                expected_roles = (
                    ("primary_trigger", proof.snapshot.trigger),
                    ("correlation_snapshot", proof),
                )
                if len(candidate_rows) != 1 or tuple(candidate_rows[0]) != _encode_candidate(
                    result.candidate
                ):
                    raise ProjectionConflict("Projection V2 PCC retry candidate closure changed")
            elif isinstance(result, Duplicate):
                candidate_id = result.existing_candidate_id
                expected_roles = (
                    ("supporting_trigger", proof.snapshot.trigger),
                    ("supporting_snapshot", proof),
                )
                if candidate_rows:
                    raise ProjectionConflict("Projection V2 duplicate retry created a candidate")
                retained = connection.execute(
                    f"SELECT {','.join(_CANDIDATE_COLUMNS)} FROM candidates "
                    "WHERE candidate_id=? LIMIT 2",
                    (candidate_id,),
                ).fetchall()
                if len(retained) != 1:
                    raise ProjectionConflict("Projection V2 duplicate retry lost its candidate")
                _decode_candidate(retained[0])
            else:
                if candidate_rows or evidence_rows:
                    raise ProjectionConflict(
                        "Projection V2 non-candidate retry has candidate facts"
                    )
                return
            expected_evidence = sorted(
                _encode_candidate_evidence(
                    candidate_id,
                    evidence.event_id,
                    evidence.source_sequence,
                    evidence.content_sha256,
                    role,
                    proof.event_id,
                )
                for role, evidence in expected_roles
            )
            actual_evidence = sorted(tuple(row) for row in evidence_rows)
            if actual_evidence != expected_evidence:
                raise ProjectionConflict("Projection V2 PCC retry evidence closure changed")
            return
        if candidate_rows or evidence_rows:
            raise ProjectionConflict("Projection V2 non-PCC retry has candidate facts")
        falco = prepared.falco
        incident_expected = falco is not None and (
            not falco.successful_connect
            or bool(falco.missing_required_fields)
            or falco.investigation_only
        )
        if not incident_expected:
            if incident_rows:
                raise ProjectionConflict("Projection V2 retry has an unexpected incident")
            return
        if retained_authority:
            assert falco is not None
            incident = _incident_from_frozen_falco(
                falco,
                event_id=prepared.envelope.event_id,
                source_sequence=prepared.envelope.source_sequence,
                host_id=prepared.envelope.host_id,
                boot_id=prepared.envelope.boot_id,
                event_time=prepared.envelope.event_time,
                ingest_time=prepared.envelope.ingest_time,
                coverage_flags=tuple(prepared.envelope.coverage_flags),
            )
        else:
            verifier = self._evidence._bound_verifier
            if verifier is None:
                raise ProjectionAuthorityError("Projection V2 retry lost Falco verifier authority")
            try:
                authenticated = self._evidence._authenticated_falco_input(
                    verifier,
                    prepared.record.ref,
                )
                incident = incident_from_verified_falco(authenticated)
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 retry Falco authority is unavailable"
                ) from error
        if len(incident_rows) != 1 or tuple(incident_rows[0]) != _encode_incident(
            incident, "investigation"
        ):
            raise ProjectionConflict("Projection V2 direct-incident retry closure changed")

    def _validate_retry_closure(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        *,
        is_primary: bool,
        retained_authority: bool = False,
    ) -> None:
        self._validate_retry_base_closure(
            connection,
            prepared,
            is_primary=is_primary,
        )
        self._validate_retry_security_closure(
            connection,
            authority,
            predecessor,
            prepared,
            is_primary=is_primary,
            retained_authority=retained_authority,
        )

    def _validate_persisted_prefix(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        cursor: ProjectionCursor | None,
        *,
        authenticated_records: tuple[StoredEvidenceRecord, ...] | None = None,
    ) -> str:
        prefix_sha256 = _v2_snapshot_hash(connection)
        if cursor is None:
            nonempty = tuple(
                table
                for table, _columns, _primary_key in _TABLE_LAYOUT_V2[1:]
                if connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] != 0
            )
            if nonempty:
                raise ProjectionConflict("Projection V2 has facts without a cursor")
            return prefix_sha256
        if authenticated_records is None:
            try:
                records = tuple(
                    self._evidence.iter_authenticated_records(
                        after=0,
                        through=cursor.source_sequence,
                    )
                )
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 persisted prefix is unavailable"
                ) from error
        else:
            if type(authenticated_records) is not tuple or any(
                type(record) is not StoredEvidenceRecord for record in authenticated_records
            ):
                raise ProjectionAuthorityError(
                    "Projection V2 supplied prefix authority is not exact"
                )
            records = authenticated_records
        if (
            not records
            or records[-1].ref.source_sequence != cursor.source_sequence
            or records[-1].ref.event_id != cursor.event_id
            or records[-1].ref.content_sha256 != cursor.content_sha256
            or records[-1].ref.frame_sha256 != cursor.frame_sha256
            or connection.execute("SELECT count(*) FROM events").fetchone()[0] != len(records)
            or connection.execute("SELECT count(*) FROM projection_dedup").fetchone()[0]
            != len(records)
        ):
            raise ProjectionConflict("Projection V2 persisted prefix does not match its cursor")
        expected_containers: dict[
            tuple[str, str, str],
            tuple[_PreparedV2Record, _PreparedV2Record],
        ] = {}
        logical_primaries: dict[tuple[str, str], str] = {}
        selected = ",".join(_TABLE_LAYOUT_V2[1][1])
        for record in records:
            prepared = _prepare_v2(record)
            logical_key = (
                prepared.dedup_kind,
                prepared.logical_key_sha256,
            )
            source_primary = logical_primaries.setdefault(
                logical_key,
                prepared.envelope.event_id,
            )
            expected_duplicate = (
                None if source_primary == prepared.envelope.event_id else source_primary
            )
            row = connection.execute(
                f"SELECT {selected} FROM events WHERE event_id=?",
                (prepared.envelope.event_id,),
            ).fetchone()
            if row is None:
                raise ProjectionConflict("Projection V2 persisted prefix lost an event")
            duplicate = row["duplicate_of_event_id"]
            if duplicate is not None and (
                type(duplicate) is not str or _EVENT_ID_V2.fullmatch(duplicate) is None
            ):
                raise ProjectionConflict("Projection V2 persisted duplicate identity is invalid")
            if duplicate != expected_duplicate:
                raise ProjectionConflict(
                    "Projection V2 persisted logical primary differs from "
                    "authenticated source order"
                )
            if tuple(row) != _event_values_v2(prepared, expected_duplicate):
                raise ProjectionConflict("Projection V2 persisted event facts changed")
            is_primary = expected_duplicate is None
            dedup = connection.execute(
                "SELECT dedup_kind,logical_key_sha256,primary_event_id,is_primary "
                "FROM projection_dedup WHERE event_id=?",
                (prepared.envelope.event_id,),
            ).fetchone()
            if dedup is None or tuple(dedup) != (
                prepared.dedup_kind,
                prepared.logical_key_sha256,
                source_primary,
                int(is_primary),
            ):
                raise ProjectionConflict("Projection V2 persisted dedup facts changed")
            if expected_duplicate is not None:
                primary = connection.execute(
                    "SELECT dedup_kind,logical_key_sha256,primary_event_id,is_primary "
                    "FROM projection_dedup WHERE event_id=?",
                    (source_primary,),
                ).fetchone()
                if primary is None or tuple(primary) != (
                    prepared.dedup_kind,
                    prepared.logical_key_sha256,
                    source_primary,
                    1,
                ):
                    raise ProjectionConflict("Projection V2 persisted logical primary changed")
            self._validate_retry_closure(
                connection,
                authority,
                predecessor,
                prepared,
                is_primary=is_primary,
                retained_authority=authenticated_records is not None,
            )
            falco = prepared.falco
            if (
                is_primary
                and falco is not None
                and falco.docker_container_id is not None
                and falco.docker_started_at is not None
            ):
                key = (
                    prepared.envelope.host_id,
                    falco.docker_container_id,
                    falco.docker_started_at,
                )
                first = expected_containers.get(key, (prepared, prepared))[0]
                expected_containers[key] = (first, prepared)
        actual_containers = _ordered_v2_rows_unverified(
            connection,
            "containers",
        )
        expected_rows: list[tuple[object, ...]] = []
        for key, (first, last) in expected_containers.items():
            first_falco = first.falco
            last_falco = last.falco
            if first_falco is None or last_falco is None:
                raise AssertionError("Projection V2 container facts lost Falco input")
            expected_rows.append(
                (
                    *key,
                    last_falco.image_id,
                    canonical_json(last_falco.repo_digests).decode("utf-8"),
                    last_falco.immutable_spec_sha256,
                    _optional_uint64_v2(last_falco.inventory_revision),
                    first.envelope.event_id,
                    _encode_uint64_v2(first.record.ref.source_sequence),
                    first.record.ref.content_sha256,
                    last.envelope.event_id,
                    _encode_uint64_v2(last.record.ref.source_sequence),
                    last.record.ref.content_sha256,
                )
            )
        if actual_containers != sorted(expected_rows):
            raise ProjectionConflict("Projection V2 persisted container closure changed")
        return prefix_sha256

    def _exact_retry(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
    ) -> ProjectionApplyResult | None:
        selected = ",".join(_TABLE_LAYOUT_V2[1][1])
        row = connection.execute(
            f"SELECT {selected} FROM events WHERE event_id=?",
            (prepared.envelope.event_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            _v2_snapshot_hash(connection)
        except ProjectionConflict:
            self._latch_unhealthy()
            raise
        duplicate = row["duplicate_of_event_id"]
        if duplicate is not None and (
            type(duplicate) is not str or _EVENT_ID_V2.fullmatch(duplicate) is None
        ):
            self._latch_unhealthy()
            raise ProjectionConflict("Projection V2 retry duplicate identity is invalid")
        if tuple(row) != _event_values_v2(prepared, duplicate):
            self._latch_unhealthy()
            raise ProjectionConflict("Projection V2 event retry facts changed")
        dedup = connection.execute(
            "SELECT dedup_kind,logical_key_sha256,primary_event_id,is_primary "
            "FROM projection_dedup WHERE event_id=?",
            (prepared.envelope.event_id,),
        ).fetchone()
        expected_primary = prepared.envelope.event_id if duplicate is None else duplicate
        if dedup is None or tuple(dedup) != (
            prepared.dedup_kind,
            prepared.logical_key_sha256,
            expected_primary,
            int(duplicate is None),
        ):
            self._latch_unhealthy()
            raise ProjectionConflict("Projection V2 retry dedup facts changed")
        cursor = _current_v2_cursor(connection)
        if cursor is None or cursor.source_sequence < prepared.envelope.source_sequence:
            self._latch_unhealthy()
            raise ProjectionConflict("Projection V2 retry is ahead of its cursor")
        try:
            prefix_sha256 = self._validate_persisted_prefix(
                connection,
                authority,
                predecessor,
                cursor,
            )
            if (
                _current_v2_cursor(connection) != cursor
                or _v2_snapshot_hash(connection) != prefix_sha256
            ):
                raise ProjectionConflict("Projection V2 persisted prefix changed during retry")
            self._validate_cursor_evidence(connection, cursor)
            _validate_correlation_projection_predecessor(
                authority,
                predecessor,
            )
        except ProjectionConflict:
            self._latch_unhealthy()
            raise
        except (
            ProjectionAuthorityError,
            CorrelationProjectionError,
            CorrelationRequestJournalError,
            EvidenceStoreError,
            HistoricalCoverageConflict,
            HistoricalCoverageUnavailable,
            AttributeError,
            TypeError,
            ValueError,
        ) as error:
            self._latch_unhealthy(error)
            raise ProjectionAuthorityError(
                "Projection V2 retry authority could not be revalidated"
            ) from error
        return ProjectionApplyResult(
            event_id=prepared.envelope.event_id,
            duplicate_of_event_id=duplicate,
            reducer_applied=False,
            cursor=cursor,
        )

    def apply(self, ref: EvidenceRef) -> ProjectionApplyResult:
        with self._mutex:
            connection, authority = self._require_usable()
            if type(ref) is not EvidenceRef:
                raise ProjectionAuthorityError("Projection V2 apply requires an exact evidence ref")
            try:
                _verify_v2_schema(connection)
                record = self._evidence.resolve_authenticated_ref(ref)
            except ProjectionConflict:
                self._latch_unhealthy()
                raise
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 ref is not exact authenticated evidence"
                ) from error
            prepared = _prepare_v2(record)
            acceptance_cursor = self._healthy_acceptance_cursor()
            ack_boundary = self._freeze_ack_boundary(acceptance_cursor)
            if prepared.record.ref.source_sequence > acceptance_cursor:
                raise ProjectionAuthorityError(
                    "Projection V2 ref exceeds contiguous authenticated acceptance"
                )
            if prepared.record.ref.source_sequence > ack_boundary.confirmed_through:
                raise ProjectionAuthorityError(
                    "Projection V2 ref exceeds authenticated ACK confirmation"
                )
            cursor = _current_v2_cursor(connection)
            self._validate_cursor_evidence(connection, cursor)
            if cursor is not None and cursor.host_id != prepared.envelope.host_id:
                self._latch_unhealthy()
                raise ProjectionConflict("Projection V2 cursor host changed")
            predecessor = _predecessor_v2(self._generation, cursor)
            _validate_correlation_projection_predecessor(authority, predecessor)
            retry = self._exact_retry(
                connection,
                authority,
                predecessor,
                prepared,
            )
            if retry is not None:
                self._revalidate_ack_boundary(ack_boundary, acceptance_cursor)
                _validate_correlation_projection_predecessor(authority, predecessor)
                return retry
            after = 0 if cursor is None else cursor.source_sequence
            try:
                records = self._evidence.iter_authenticated_records(
                    after=after,
                    through=ack_boundary.confirmed_through,
                )
                next_record = next(records, None)
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 source-order authority is unavailable"
                ) from error
            if next_record is None or next_record.ref != prepared.record.ref:
                raise ProjectionAuthorityError(
                    "Projection V2 ref is not the next authenticated record"
                )
            return self._apply_prepared(
                connection,
                authority,
                predecessor,
                prepared,
                acceptance_cursor,
                ack_boundary,
            )

    def _stage_replay_prefix(
        self,
        through: EvidenceRef | None,
        *,
        purpose: _ReplayPurpose,
        _factory: object,
        retention_completion: AuthenticatedRetentionUnlinkCompletion | None = None,
        _fault_phase: _ReplayFaultPhase | None = None,
    ) -> _StagedV2Replay:
        if (
            _factory is not _STAGED_REPLAY_FACTORY
            or type(purpose) is not _ReplayPurpose
            or (through is not None and type(through) is not EvidenceRef)
            or (
                retention_completion is not None
                and type(retention_completion) is not AuthenticatedRetentionUnlinkCompletion
            )
            or (
                _fault_phase is not None
                and (
                    type(_fault_phase) is not _ReplayFaultPhase
                    or _fault_phase
                    not in (
                        _ReplayFaultPhase.FREEZE,
                        _ReplayFaultPhase.COMPUTE,
                        _ReplayFaultPhase.STAGE_HANDOFF,
                    )
                )
            )
        ):
            raise ProjectionAuthorityError("Projection V2 unpublished replay is factory-only")
        try:
            through_key = None if through is None else _exact_coverage_ref_key(through)
        except ValueError as error:
            raise ProjectionAuthorityError(
                "Projection V2 unpublished terminal is not exact"
            ) from error
        retention_scope: _AuthenticatedRetentionReplayScope | None = None
        reservation: _ReplayReservation | None = None
        source_snapshot: _ReplaySourceSnapshot | None = None
        ack_snapshot: _AckReplaySnapshot | None = None
        journal_snapshot: _CorrelationJournalReplaySnapshot | None = None
        hydrated_connection: sqlite3.Connection | None = None
        staged_binding: _StagedReplayBinding | None = None
        primary_error: BaseException | None = None
        staged = False
        base_generation = self._generation
        acceptance_cursor = 0
        verified_old_cursor: ProjectionCursor | None = None
        verified_old_prefix_sha256: str | None = None
        verified_old_table_counts: tuple[tuple[str, int], ...] | None = None
        try:
            if purpose is _ReplayPurpose.V2_REBUILD:
                with self._mutex:
                    self._require_usable()
                    if self._generation >= MAX_UINT64:
                        raise ProjectionAuthorityError(
                            "Projection V2 rebuild generation is exhausted"
                        )
            if retention_completion is not None:
                retention_scope = _capture_retention_replay_scope_v2(
                    self._evidence,
                    retention_completion,
                    through,
                )
            with self._mutex:
                connection, authority = self._require_usable()
                if self._generation >= MAX_UINT64:
                    raise ProjectionAuthorityError("Projection V2 replay generation is exhausted")
                _verify_v2_schema(connection)
                acceptance_cursor = _healthy_replay_acceptance_cursor_v2(
                    self._evidence,
                    self._evidence_lifecycle,
                    retention_scope,
                )
                live_cursor = _current_v2_cursor(connection)
                if purpose is _ReplayPurpose.INITIAL:
                    if live_cursor is not None or any(
                        connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                        for table, _columns, _primary_key in _TABLE_LAYOUT_V2[1:]
                    ):
                        raise ProjectionConflict(
                            "Projection V2 unpublished replay requires an empty database"
                        )
                elif through is None:
                    raise ProjectionConflict("Projection V2 rebuild requires an exact terminal")
                base_generation = self._generation
                reservation = _ReplayReservation(
                    token=object(),
                    purpose=purpose,
                    base_generation=base_generation,
                    publish_generation=base_generation + 1,
                    through_key=through_key,
                )
                with self._replay_state_lock:
                    if self._replay_reservation is not None:
                        raise ProjectionAuthorityError(
                            "Projection V2 replay reservation is already active"
                        )
                    self._replay_reservation = reservation
                    self._set_replay_status_locked(
                        _ReplayStatus(
                            generation=base_generation,
                            phase=_ReplayPhase.FREEZING,
                            reservation_present=True,
                        )
                    )

                expected_predecessor = _predecessor_v2(
                    base_generation,
                    (None if purpose is _ReplayPurpose.INITIAL else live_cursor),
                )
                if purpose is _ReplayPurpose.V2_REBUILD:
                    self._validate_v2_rebuild_cursor_evidence(
                        connection,
                        live_cursor,
                        retention_scope,
                    )
                    verified_old_cursor = live_cursor
                    retained_records = (
                        None
                        if retention_scope is None
                        else _authenticated_retained_prefix_records_v2(
                            retention_scope,
                            cast(ProjectionCursor, verified_old_cursor),
                        )
                    )
                    verified_old_prefix_sha256 = self._validate_persisted_prefix(
                        connection,
                        authority,
                        expected_predecessor,
                        verified_old_cursor,
                        authenticated_records=retained_records,
                    )
                    verified_old_table_counts = _v2_table_counts(connection)
                retention_gate_context = (
                    nullcontext(None)
                    if retention_scope is None
                    else self._evidence._authenticated_retention_replay_scope_gate(
                        retention_scope,
                        cast(EvidenceRef, through),
                    )
                )
                with (
                    retention_gate_context as retention_gate,
                    self._evidence._replay_source_snapshot_gate(),
                    self._acknowledgements._replay_ack_snapshot_gate(),
                    _correlation_projection_snapshot_gate(authority) as correlation_binding,
                    _correlation_journal_replay_gate(self._journal),
                ):
                    if (
                        self._connection is not connection
                        or self._authority is not authority
                        or self._generation != base_generation
                    ):
                        raise ProjectionAuthorityError(
                            "Projection V2 replay owner changed during freeze"
                        )
                    source_snapshot = self._evidence._capture_replay_source_locked(through)
                    retention_facts = (
                        None
                        if retention_scope is None
                        else _bind_retention_replay_scope_v2(
                            self._evidence,
                            retention_scope,
                            source_snapshot,
                            retention_gate,
                        )
                    )
                    if purpose is _ReplayPurpose.V2_REBUILD and (
                        verified_old_prefix_sha256 is None
                        or verified_old_table_counts is None
                        or _current_v2_cursor(connection) != verified_old_cursor
                        or _v2_snapshot_hash(connection) != verified_old_prefix_sha256
                        or _v2_table_counts(connection) != verified_old_table_counts
                    ):
                        raise ProjectionConflict(
                            "Projection V2 rebuild old base changed during freeze"
                        )
                    ack_snapshot = self._acknowledgements._capture_replay_ack_locked(
                        acceptance_cursor
                    )
                    expected_ack = (
                        None
                        if through is None
                        else (
                            through.source_sequence,
                            through.event_id,
                            through.content_sha256,
                        )
                    )
                    if (
                        ack_snapshot.confirmed != expected_ack
                        or ack_snapshot.retention_pending is not (retention_scope is not None)
                    ):
                        raise ProjectionAuthorityError(
                            "Projection V2 replay requires its confirmed ACK boundary"
                        )
                    correlation_snapshot = _capture_correlation_replay_locked(
                        authority,
                        correlation_binding,
                        expected_predecessor,
                    )
                    journal_snapshot, issued_proofs = _capture_correlation_journal_replay_locked(
                        self._journal,
                        through_sequence=(0 if through is None else through.source_sequence),
                        retention_scope=retention_scope,
                        retention_gate=retention_gate,
                    )
                    try:
                        pcc_inputs = tuple(
                            _freeze_replay_pcc_seed(
                                proof,
                                detector_bundle_sha256=(
                                    correlation_snapshot.detector_bundle_sha256
                                ),
                                registry=correlation_binding.registry,
                                registry_facts_canonical=(
                                    correlation_snapshot.registry_facts_canonical
                                ),
                            )
                            for proof in issued_proofs
                        )
                    except (TypeError, ValueError) as error:
                        raise ProjectionAuthorityError(
                            "Projection V2 historical PCC pin authority changed"
                        ) from error
                    issued_proofs = ()
                    snapshot = _ReplayInputSnapshot(
                        purpose=purpose,
                        source=source_snapshot,
                        ack=ack_snapshot,
                        correlation=correlation_snapshot,
                        pcc_inputs=pcc_inputs,
                        schema_domain=(_REPLAY_SCHEMA_DOMAIN_V2 + _SCHEMA_V2_PATH.read_bytes()),
                        base_projection_generation=base_generation,
                        publish_generation=base_generation + 1,
                        retention_facts=retention_facts,
                    )
                    if _fault_phase is _ReplayFaultPhase.FREEZE:
                        raise KeyboardInterrupt("injected replay freeze failure")

            assert reservation is not None
            with self._replay_state_lock:
                if self._replay_reservation is not reservation:
                    raise ProjectionAuthorityError(
                        "Projection V2 replay reservation changed after freeze"
                    )
                self._set_replay_status_locked(
                    _ReplayStatus(
                        generation=base_generation,
                        phase=_ReplayPhase.COMPUTING,
                        reservation_present=True,
                    )
                )
            if _fault_phase is _ReplayFaultPhase.COMPUTE:
                raise KeyboardInterrupt("injected replay compute failure")
            try:
                computation = _compute_replay(snapshot)
                hydrated_connection, report = _validate_and_hydrate_replay(
                    snapshot,
                    computation,
                )
            except ProjectionConflict as error:
                raise ProjectionAuthorityError(
                    "Projection V2 replay frozen authority changed"
                ) from error

            with self._mutex:
                if (
                    self._closed
                    or not self._healthy
                    or self._connection is not connection
                    or self._authority is not authority
                    or self._generation != base_generation
                ):
                    raise ProjectionAuthorityError(
                        "Projection V2 replay owner changed before publication"
                    )
                retention_gate_context = (
                    nullcontext(None)
                    if retention_scope is None
                    else self._evidence._authenticated_retention_replay_scope_gate(
                        retention_scope,
                        cast(EvidenceRef, through),
                    )
                )
                with (
                    retention_gate_context as retention_gate,
                    self._evidence._replay_source_snapshot_gate(),
                    self._acknowledgements._replay_ack_snapshot_gate(),
                    _correlation_projection_snapshot_gate(authority) as correlation_binding,
                    _correlation_journal_replay_gate(self._journal),
                ):
                    with self._replay_state_lock:
                        if (
                            self._replay_reservation is not reservation
                            or reservation.base_generation != base_generation
                            or reservation.publish_generation != base_generation + 1
                            or reservation.through_key != through_key
                        ):
                            raise ProjectionAuthorityError(
                                "Projection V2 replay reservation changed"
                            )
                        self._set_replay_status_locked(
                            _ReplayStatus(
                                generation=base_generation,
                                phase=_ReplayPhase.VALIDATING,
                                reservation_present=True,
                            )
                        )
                    self._evidence._revalidate_replay_source_locked(source_snapshot)
                    if retention_scope is not None:
                        current_retention_facts = _bind_retention_replay_scope_v2(
                            self._evidence,
                            retention_scope,
                            source_snapshot,
                            retention_gate,
                        )
                        if current_retention_facts != snapshot.retention_facts:
                            raise ProjectionAuthorityError(
                                "Projection V2 retention replay facts changed"
                            )
                    self._acknowledgements._revalidate_replay_ack_locked(ack_snapshot)
                    _revalidate_correlation_replay_locked(
                        authority,
                        correlation_binding,
                        snapshot.correlation,
                    )
                    if journal_snapshot is None:
                        raise ProjectionAuthorityError("Projection V2 replay lost journal facts")
                    _revalidate_correlation_journal_replay_locked(
                        self._journal,
                        journal_snapshot,
                    )
                    if purpose is _ReplayPurpose.V2_REBUILD:
                        if verified_old_prefix_sha256 is None or verified_old_table_counts is None:
                            raise ProjectionAuthorityError(
                                "Projection V2 rebuild lost its verified old base"
                            )
                        self._validate_v2_rebuild_cursor_evidence(
                            connection,
                            verified_old_cursor,
                            retention_scope,
                        )
                        if (
                            _current_v2_cursor(connection) != verified_old_cursor
                            or _v2_snapshot_hash(connection) != verified_old_prefix_sha256
                            or _v2_table_counts(connection) != verified_old_table_counts
                        ):
                            raise ProjectionConflict(
                                "Projection V2 rebuild verified old base changed"
                            )
                    if computation.terminal_predecessor.generation != base_generation + 1 or (
                        report.cursor is None
                    ) != (through is None):
                        raise ProjectionConflict("Projection V2 replay publication seal changed")
                    if through is not None and (
                        report.cursor is None
                        or report.cursor.source_sequence != through.source_sequence
                        or report.cursor.event_id != through.event_id
                        or report.cursor.content_sha256 != through.content_sha256
                    ):
                        raise ProjectionConflict("Projection V2 replay publication cursor changed")
                    if (
                        source_snapshot is None
                        or ack_snapshot is None
                        or journal_snapshot is None
                        or hydrated_connection is None
                    ):
                        raise ProjectionAuthorityError("Projection V2 replay lost staged resources")
                    capability = object.__new__(_StagedV2Replay)
                    binding = _StagedReplayBinding(
                        capability=capability,
                        purpose=purpose,
                        through=through,
                        through_key=through_key,
                        retention_scope=retention_scope,
                        reservation=reservation,
                        live_connection=connection,
                        authority=authority,
                        acceptance_cursor=acceptance_cursor,
                        source_snapshot=source_snapshot,
                        ack_snapshot=ack_snapshot,
                        journal_snapshot=journal_snapshot,
                        snapshot=snapshot,
                        computation=computation,
                        hydrated_connection=hydrated_connection,
                        report=report,
                        verified_old_cursor=verified_old_cursor,
                        verified_old_prefix_sha256=(verified_old_prefix_sha256),
                        verified_old_table_counts=verified_old_table_counts,
                    )
                    staged_binding = binding
                    with self._replay_state_lock:
                        if (
                            self._replay_reservation is not reservation
                            or self._staged_replay is not None
                        ):
                            raise ProjectionAuthorityError(
                                "Projection V2 replay reservation changed before staging"
                            )
                        self._staged_replay = binding
                        if _fault_phase is _ReplayFaultPhase.STAGE_HANDOFF:
                            raise KeyboardInterrupt("injected replay stage handoff failure")
                        self._set_replay_status_locked(
                            _ReplayStatus(
                                generation=base_generation,
                                phase=_ReplayPhase.STAGED,
                                reservation_present=True,
                            )
                        )
                    # The owner binding, not the returned capability, now owns all
                    # staged connections, descriptors, snapshots and retention.
                    hydrated_connection = None
                    ack_snapshot = None
                    source_snapshot = None
                    retention_scope = None
                    staged = True
                    return capability
        except (
            AckJournalError,
            CorrelationProjectionError,
            CorrelationRequestJournalError,
            EvidenceStoreError,
        ) as error:
            converted = ProjectionAuthorityError("Projection V2 replay authority changed")
            primary_error = converted
            raise converted from error
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_errors: list[BaseException] = []
            # Installing the binding is the ownership handoff. Detect that
            # owner-side fact directly: an asynchronous exception may arrive
            # after the install but before the local ``staged`` marker or any
            # individual local reference is cleared.
            if primary_error is not None and staged_binding is not None:
                with self._mutex:
                    if self._staged_replay is staged_binding:
                        hydrated_connection = None
                        ack_snapshot = None
                        source_snapshot = None
                        retention_scope = None
                        reservation = None
                        self._discard_staged_replay_locked(
                            staged_binding,
                            primary_error,
                            unhealthy=False,
                        )
                        staged_binding = None
                        staged = False
            try:
                self._acknowledgements._drain_replay_corruption_fences(primary_error)
            except BaseException as error:  # noqa: BLE001
                cleanup_errors.append(error)
            try:
                self._journal._drain_replay_corruption_fences(primary_error)
            except BaseException as error:  # noqa: BLE001
                cleanup_errors.append(error)
            if hydrated_connection is not None:
                try:
                    hydrated_connection.close()
                except BaseException as error:  # noqa: BLE001
                    cleanup_errors.append(error)
            if ack_snapshot is not None:
                owned_ack_snapshot = ack_snapshot
                ack_snapshot = None
                try:
                    _close_replay_ack_snapshot(owned_ack_snapshot)
                except BaseException as error:  # noqa: BLE001
                    cleanup_errors.append(error)
            if source_snapshot is not None:
                owned_source_snapshot = source_snapshot
                source_snapshot = None
                try:
                    _close_replay_source_snapshot(owned_source_snapshot)
                except BaseException as error:  # noqa: BLE001
                    cleanup_errors.append(error)
            if (
                retention_scope is not None
                and self._evidence._authenticated_retention_replay_scope_is_active(retention_scope)
            ):
                try:
                    self._evidence._release_authenticated_retention_replay_scope(retention_scope)
                except BaseException as error:  # noqa: BLE001
                    cleanup_errors.append(error)
            if not staged:
                with self._replay_state_lock:
                    if reservation is not None:
                        failure_phase = self._replay_status.phase
                        if self._replay_reservation is reservation:
                            self._replay_reservation = None
                        self._set_replay_status_locked(
                            _ReplayStatus(
                                generation=base_generation,
                                phase=_ReplayPhase.FAILED,
                                reservation_present=False,
                                failure_phase=failure_phase,
                            )
                        )
                    if self._replay_test_barrier is not None:
                        self._replay_test_barrier = None
                        self._replay_state_condition.notify_all()
            if cleanup_errors:
                if primary_error is not None:
                    with self._mutex:
                        self._latch_unhealthy(primary_error)
                    for cleanup_error in cleanup_errors:
                        primary_error.add_note(
                            "Projection V2 replay cleanup failure: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                else:
                    cleanup_group = BaseExceptionGroup(
                        "Projection V2 replay cleanup failed",
                        cleanup_errors,
                    )
                    if staged and staged_binding is not None:
                        with self._mutex:
                            if self._staged_replay is staged_binding:
                                self._discard_staged_replay_locked(
                                    staged_binding,
                                    cleanup_group,
                                    unhealthy=True,
                                )
                    raise cleanup_group

    def _stage_unpublished_prefix(
        self,
        through: EvidenceRef | None,
        *,
        _factory: object,
        retention_completion: AuthenticatedRetentionUnlinkCompletion | None = None,
        _fault_phase: _ReplayFaultPhase | None = None,
    ) -> _StagedV2Replay:
        return self._stage_replay_prefix(
            through,
            purpose=_ReplayPurpose.INITIAL,
            _factory=_factory,
            retention_completion=retention_completion,
            _fault_phase=_fault_phase,
        )

    def _stage_v2_rebuild_prefix(
        self,
        through: EvidenceRef,
        *,
        _factory: object,
        retention_completion: AuthenticatedRetentionUnlinkCompletion | None = None,
        _fault_phase: _ReplayFaultPhase | None = None,
    ) -> _StagedV2Replay:
        if type(through) is not EvidenceRef:
            raise ProjectionAuthorityError("Projection V2 rebuild terminal is not exact")
        return self._stage_replay_prefix(
            through,
            purpose=_ReplayPurpose.V2_REBUILD,
            _factory=_factory,
            retention_completion=retention_completion,
            _fault_phase=_fault_phase,
        )

    def _bind_staged_v2_rebuild_namespace(
        self,
        capability: _StagedV2Replay,
        *,
        device: int,
        inode: int,
        _factory: object,
    ) -> _V2RebuildGuard:
        if (
            _factory is not _STAGED_REPLAY_FACTORY
            or type(device) is not int
            or type(inode) is not int
        ):
            raise ProjectionAuthorityError(
                "Projection V2 rebuild namespace binding is factory-only"
            )
        binding: _StagedReplayBinding | None = None
        physical: _StagedV2PhysicalBinding | None = None
        try:
            with self._mutex:
                binding = self._require_staged_replay_locked(capability)
                if binding.purpose is not _ReplayPurpose.V2_REBUILD or binding.rebuild is not None:
                    raise ProjectionAuthorityError("Projection V2 rebuild guard is not available")
                connection = binding.live_connection
                cursor = _current_v2_cursor(connection)
                _verify_v2_schema(connection)
                self._validate_v2_rebuild_cursor_evidence(
                    connection,
                    cursor,
                    binding.retention_scope,
                )
                prefix_sha256 = _v2_snapshot_hash(connection)
                table_counts = _v2_table_counts(connection)
                if (
                    binding.verified_old_prefix_sha256 is None
                    or binding.verified_old_table_counts is None
                    or cursor != binding.verified_old_cursor
                    or prefix_sha256 != binding.verified_old_prefix_sha256
                    or table_counts != binding.verified_old_table_counts
                ):
                    raise ProjectionConflict(
                        "Projection V2 rebuild old base differs from verified stage"
                    )
                database_path = _v2_exact_main_database_path(
                    connection,
                    require_file_backed=True,
                )
                physical = _capture_staged_v2_physical_binding(database_path)
                if (physical.device, physical.inode) != (device, inode):
                    raise ProjectionConflict(
                        "Projection V2 rebuild namespace inode was substituted"
                    )
                current_predecessor = _predecessor_v2(
                    binding.reservation.base_generation,
                    cursor,
                )
                _validate_correlation_projection_predecessor(
                    binding.authority,
                    current_predecessor,
                )
                fallback_successor = _predecessor_v2(
                    binding.reservation.publish_generation,
                    cursor,
                )
                replacement = _prepare_correlation_projection_authority_replacement(
                    binding.authority,
                    binding.computation.terminal_predecessor,
                    fallback_successor,
                    _factory=_AUTHORITY_REPLACEMENT_FACTORY,
                )
                _revalidate_staged_v2_physical_binding(physical)
                if (
                    _current_v2_cursor(connection) != cursor
                    or _v2_snapshot_hash(connection) != prefix_sha256
                    or _v2_table_counts(connection) != table_counts
                ):
                    raise ProjectionConflict(
                        "Projection V2 rebuild old image changed during binding"
                    )
                guard = object.__new__(_V2RebuildGuard)
                installed = _V2RebuildBinding(
                    guard=guard,
                    old_cursor=cursor,
                    old_prefix_sha256=prefix_sha256,
                    old_table_counts=table_counts,
                    old_physical=physical,
                    namespace_device=device,
                    namespace_inode=inode,
                    authority_replacement=replacement,
                )
                binding.rebuild = installed
                return guard
        finally:
            adopted = (
                physical is not None
                and binding is not None
                and binding.rebuild is not None
                and binding.rebuild.old_physical is physical
            )
            if physical is not None and not adopted and physical.descriptor >= 0:
                descriptor = physical.descriptor
                physical.descriptor = -1
                os.close(descriptor)

    def _require_staged_replay_locked(
        self,
        capability: _StagedV2Replay,
    ) -> _StagedReplayBinding:
        binding = self._staged_replay
        with self._replay_state_lock:
            if (
                type(capability) is not _StagedV2Replay
                or binding is None
                or binding.capability is not capability
                or self._replay_reservation is not binding.reservation
                or self._replay_status.phase is not _ReplayPhase.STAGED
                or not self._replay_status.reservation_present
            ):
                raise ProjectionAuthorityError(
                    "Projection V2 staged replay capability is not current"
                )
        if self._closed or not self._healthy:
            raise ProjectionUnhealthy("Projection V2 owner is not usable")
        return binding

    def _v2_rebuild_fallback_completed(
        self,
        capability: _StagedV2Replay,
        guard: _V2RebuildGuard,
        generation: int,
        *,
        _factory: object,
    ) -> bool:
        if (
            _factory is not _STAGED_REPLAY_FACTORY
            or type(capability) is not _StagedV2Replay
            or type(guard) is not _V2RebuildGuard
            or type(generation) is not int
        ):
            raise ProjectionAuthorityError("Projection V2 fallback observation is factory-only")
        with self._mutex, self._replay_state_lock:
            return (
                self._healthy
                and self._generation == generation
                and self._staged_replay is None
                and self._replay_reservation is None
                and self._replay_status.generation == generation
                and self._replay_status.phase is _ReplayPhase.FAILED
                and self._replay_status.reservation_present is False
            )

    def _require_v2_rebuild_guard_locked(
        self,
        capability: _StagedV2Replay,
        guard: _V2RebuildGuard,
        *,
        permit_suspended: bool,
    ) -> tuple[_StagedReplayBinding, _V2RebuildBinding]:
        binding = self._staged_replay
        with self._replay_state_lock:
            phase = self._replay_status.phase
            if (
                type(capability) is not _StagedV2Replay
                or type(guard) is not _V2RebuildGuard
                or binding is None
                or binding.capability is not capability
                or binding.purpose is not _ReplayPurpose.V2_REBUILD
                or binding.rebuild is None
                or binding.rebuild.guard is not guard
                or self._replay_reservation is not binding.reservation
                or binding.reservation.purpose is not _ReplayPurpose.V2_REBUILD
                or not self._replay_status.reservation_present
                or (
                    phase is not _ReplayPhase.STAGED
                    and not (
                        permit_suspended
                        and phase is _ReplayPhase.SUSPENDED
                        and binding.rebuild.suspended
                    )
                )
            ):
                raise ProjectionAuthorityError("Projection V2 rebuild guard is not current")
        if self._closed or not self._healthy:
            raise ProjectionUnhealthy("Projection V2 owner is not usable")
        return binding, binding.rebuild

    def _validate_v2_rebuild_old_locked(
        self,
        binding: _StagedReplayBinding,
        rebuild: _V2RebuildBinding,
        connection: sqlite3.Connection,
    ) -> None:
        if (
            type(connection) is not sqlite3.Connection
            or connection.in_transaction
            or _v2_exact_main_database_path(
                connection,
                require_file_backed=True,
            )
            != rebuild.old_physical.path
        ):
            raise ProjectionConflict("Projection V2 rebuild old connection is not exact")
        _revalidate_v2_rebuild_old_physical(
            rebuild.old_physical,
            named=True,
        )
        _verify_v2_schema(connection)
        cursor = _current_v2_cursor(connection)
        self._validate_v2_rebuild_cursor_evidence(
            connection,
            cursor,
            binding.retention_scope,
        )
        if (
            cursor != rebuild.old_cursor
            or cursor != binding.verified_old_cursor
            or _v2_snapshot_hash(connection) != rebuild.old_prefix_sha256
            or rebuild.old_prefix_sha256 != binding.verified_old_prefix_sha256
            or _v2_table_counts(connection) != rebuild.old_table_counts
            or rebuild.old_table_counts != binding.verified_old_table_counts
            or (rebuild.old_physical.device, rebuild.old_physical.inode)
            != (rebuild.namespace_device, rebuild.namespace_inode)
            or self._generation != binding.reservation.base_generation
        ):
            raise ProjectionConflict("Projection V2 rebuild old seal changed")

    def _revalidate_staged_replay_locked(
        self,
        binding: _StagedReplayBinding,
        retention_gate: _AuthenticatedRetentionReplayGate | None,
        correlation_binding: _ProjectionAuthorityBinding,
    ) -> None:
        source_snapshot = binding.source_snapshot
        ack_snapshot = binding.ack_snapshot
        hydrated = binding.hydrated_connection
        rebuild_suspended = (
            binding.purpose is _ReplayPurpose.V2_REBUILD
            and binding.rebuild is not None
            and binding.rebuild.suspended
            and self._connection is None
        )
        if (
            type(binding) is not _StagedReplayBinding
            or self._staged_replay is not binding
            or (self._connection is not binding.live_connection and not rebuild_suspended)
            or self._authority is not binding.authority
            or self._generation != binding.reservation.base_generation
            or binding.purpose is not binding.reservation.purpose
            or binding.snapshot.purpose is not binding.purpose
            or source_snapshot is None
            or ack_snapshot is None
            or hydrated is None
        ):
            raise ProjectionAuthorityError("Projection V2 staged replay owner binding changed")
        with self._replay_state_lock:
            if (
                self._replay_reservation is not binding.reservation
                or binding.reservation.publish_generation != binding.reservation.base_generation + 1
                or binding.reservation.through_key != binding.through_key
            ):
                raise ProjectionAuthorityError("Projection V2 staged replay reservation changed")
        if (
            _healthy_replay_acceptance_cursor_v2(
                self._evidence,
                self._evidence_lifecycle,
                binding.retention_scope,
            )
            != binding.acceptance_cursor
        ):
            raise ProjectionAuthorityError("Projection V2 staged replay acceptance changed")
        self._evidence._revalidate_replay_source_locked(source_snapshot)
        if binding.retention_scope is not None:
            current_retention_facts = _bind_retention_replay_scope_v2(
                self._evidence,
                binding.retention_scope,
                source_snapshot,
                retention_gate,
            )
            if current_retention_facts != binding.snapshot.retention_facts:
                raise ProjectionAuthorityError("Projection V2 staged retention facts changed")
        elif retention_gate is not None:
            raise ProjectionAuthorityError("Projection V2 staged retention gate was substituted")
        self._acknowledgements._revalidate_replay_ack_locked(ack_snapshot)
        _revalidate_correlation_replay_locked(
            binding.authority,
            correlation_binding,
            binding.snapshot.correlation,
        )
        _revalidate_correlation_journal_replay_locked(
            self._journal,
            binding.journal_snapshot,
        )
        report = binding.report
        computation = binding.computation
        cursor = _current_v2_cursor(hydrated)
        if (
            computation.terminal_predecessor.generation != binding.reservation.publish_generation
            or report.applied_count != computation.transcript_count
            or report.prefix_sha256 != computation.prefix_sha256
            or report.cursor != cursor
            or (cursor is None) != (binding.through is None)
            or _v2_snapshot_hash(hydrated) != computation.prefix_sha256
            or hydrated.serialize() != computation.database_image
        ):
            raise ProjectionConflict("Projection V2 staged replay facts changed")
        through = binding.through
        if through is not None and (
            cursor is None
            or cursor.source_sequence != through.source_sequence
            or cursor.event_id != through.event_id
            or cursor.content_sha256 != through.content_sha256
        ):
            raise ProjectionConflict("Projection V2 staged replay cursor changed")

    def _close_v2_rebuild_stage_resources_locked(
        self,
        binding: _StagedReplayBinding,
    ) -> list[BaseException]:
        errors: list[BaseException] = []
        materialized = binding.materialized_connection
        binding.materialized_connection = None
        if materialized is not None:
            try:
                materialized.close()
            except BaseException as error:  # noqa: BLE001 - drain exact target
                errors.append(error)
        for physical in (
            binding.materialized_physical,
            None if binding.rebuild is None else binding.rebuild.old_physical,
        ):
            if physical is None or physical.descriptor < 0:
                continue
            descriptor = physical.descriptor
            physical.descriptor = -1
            try:
                os.close(descriptor)
            except BaseException as error:  # noqa: BLE001 - drain exact fd
                errors.append(error)
        binding.materialized_physical = None
        hydrated = binding.hydrated_connection
        binding.hydrated_connection = None
        if hydrated is not None and hydrated is not materialized:
            try:
                hydrated.close()
            except BaseException as error:  # noqa: BLE001 - exact staged image
                errors.append(error)
        ack_snapshot = binding.ack_snapshot
        binding.ack_snapshot = None
        if ack_snapshot is not None:
            try:
                _close_replay_ack_snapshot(ack_snapshot)
            except BaseException as error:  # noqa: BLE001 - exact snapshot
                errors.append(error)
        source_snapshot = binding.source_snapshot
        binding.source_snapshot = None
        if source_snapshot is not None:
            try:
                _close_replay_source_snapshot(source_snapshot)
            except BaseException as error:  # noqa: BLE001 - exact snapshot
                errors.append(error)
        binding.materialized_seal = None
        return errors

    def _rebase_failed_staged_v2_rebuild(
        self,
        capability: _StagedV2Replay,
        guard: _V2RebuildGuard,
        *,
        reopened_old: _ReopenedV2Old | None = None,
        primary: BaseException,
        _factory: object,
    ) -> None:
        if (
            _factory is not _STAGED_REPLAY_FACTORY
            or not isinstance(primary, BaseException)
            or (reopened_old is not None and type(reopened_old) is not _ReopenedV2Old)
        ):
            raise ProjectionAuthorityError("Projection V2 rebuild rebase is factory-only")
        selected: sqlite3.Connection | None = (
            None if reopened_old is None else reopened_old.connection
        )
        reopened_physical = None if reopened_old is None else reopened_old.physical
        binding: _StagedReplayBinding | None = None
        replacement_attempted = False
        try:
            with self._mutex:
                candidate_binding = self._staged_replay
                if (
                    candidate_binding is not None
                    and candidate_binding.capability is capability
                    and candidate_binding.rebuild is not None
                    and candidate_binding.rebuild.guard is guard
                ):
                    binding = candidate_binding
                binding, rebuild = self._require_v2_rebuild_guard_locked(
                    capability,
                    guard,
                    permit_suspended=True,
                )
                rebuild.guard_consumed = True
                if rebuild.suspended:
                    if selected is None or reopened_physical is None:
                        raise ProjectionConflict(
                            "Projection V2 rebuild suspended without exact reopen"
                        )
                    _revalidate_reopened_v2_old_physical(
                        reopened_physical,
                        rebuild.old_physical,
                    )
                else:
                    if selected is not None or reopened_physical is not None:
                        raise ProjectionConflict(
                            "Projection V2 rebuild old connection was duplicated"
                        )
                    selected = binding.live_connection
                retention_gate_context = (
                    nullcontext(None)
                    if binding.retention_scope is None
                    else self._evidence._authenticated_retention_replay_scope_gate(
                        binding.retention_scope,
                        cast(EvidenceRef, binding.through),
                    )
                )
                with (
                    retention_gate_context as retention_gate,
                    self._evidence._replay_source_snapshot_gate(),
                    self._acknowledgements._replay_ack_snapshot_gate(),
                    _correlation_projection_snapshot_gate(binding.authority) as correlation_binding,
                    _correlation_journal_replay_gate(self._journal),
                ):
                    self._revalidate_staged_replay_locked(
                        binding,
                        retention_gate,
                        correlation_binding,
                    )
                    assert selected is not None
                    self._validate_v2_rebuild_old_locked(
                        binding,
                        rebuild,
                        selected,
                    )
                    if reopened_physical is not None:
                        _revalidate_reopened_v2_old_physical(
                            reopened_physical,
                            rebuild.old_physical,
                        )
                        descriptor = reopened_physical.descriptor
                        reopened_physical.descriptor = -1
                        os.close(descriptor)
                    cleanup_errors = self._close_v2_rebuild_stage_resources_locked(binding)
                    if cleanup_errors:
                        raise BaseExceptionGroup(
                            "Projection V2 rebuild fallback cleanup failed",
                            cleanup_errors,
                        )
                    failed_status = _ReplayStatus(
                        generation=binding.reservation.publish_generation,
                        phase=_ReplayPhase.FAILED,
                        reservation_present=False,
                        failure_phase=(
                            _ReplayPhase.SUSPENDED if rebuild.suspended else _ReplayPhase.STAGED
                        ),
                    )
                    with self._replay_state_lock:
                        if (
                            self._staged_replay is not binding
                            or self._replay_reservation is not binding.reservation
                        ):
                            raise ProjectionAuthorityError(
                                "Projection V2 rebuild changed at fallback edge"
                            )
                    replacement_attempted = True
                    fresh_authority = _commit_correlation_projection_authority_replacement(
                        rebuild.authority_replacement,
                        success=False,
                        _factory=_AUTHORITY_REPLACEMENT_FACTORY,
                    )
                    self._authority = fresh_authority
                    with self._replay_state_lock:
                        if (
                            self._staged_replay is not binding
                            or self._replay_reservation is not binding.reservation
                        ):
                            raise ProjectionAuthorityError(
                                "Projection V2 rebuild changed after fallback edge"
                            )
                        self._connection = selected
                        self._generation = binding.reservation.publish_generation
                        self._staged_replay = None
                        self._replay_reservation = None
                        binding.rebuild = None
                        self._replay_status = failed_status
                    scope = binding.retention_scope
                    if scope is not None:
                        self._evidence._release_authenticated_retention_replay_scope(scope)
                        binding.retention_scope = None
        except BaseException as rebase_error:
            if reopened_physical is not None and reopened_physical.descriptor >= 0:
                descriptor = reopened_physical.descriptor
                reopened_physical.descriptor = -1
                try:
                    os.close(descriptor)
                except BaseException as cleanup_error:  # noqa: BLE001
                    primary.add_note(
                        "Projection V2 fallback fd-proof cleanup failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            if selected is not None and selected is not (
                None if binding is None else binding.live_connection
            ):
                try:
                    selected.close()
                except BaseException as cleanup_error:  # noqa: BLE001
                    primary.add_note(
                        "Projection V2 fallback reopen cleanup failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            primary.add_note(
                "Projection V2 exact fallback rebase failed: "
                f"{type(rebase_error).__name__}: {rebase_error}"
            )
            with self._mutex:
                retained_binding = binding
                scope = None if retained_binding is None else retained_binding.retention_scope
                if (
                    retained_binding is not None
                    and scope is not None
                    and self._evidence._authenticated_retention_replay_scope_is_active(scope)
                ):
                    try:
                        self._evidence._release_authenticated_retention_replay_scope(scope)
                        retained_binding.retention_scope = None
                    except BaseException as cleanup_error:  # noqa: BLE001
                        primary.add_note(
                            "Projection V2 fallback retention release failed: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                if replacement_attempted and binding is not None:
                    try:
                        fresh_closed = _fail_closed_correlation_projection_authority_replacement(
                            binding.rebuild.authority_replacement
                            if binding.rebuild is not None
                            else rebuild.authority_replacement,
                            primary,
                            _factory=_AUTHORITY_REPLACEMENT_FACTORY,
                        )
                    except BaseException as cleanup_error:  # noqa: BLE001
                        primary.add_note(
                            "Projection V2 fallback authority fail-shut failed: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                    else:
                        if fresh_closed:
                            self._authority = None
                self._latch_unhealthy(primary)
                if binding is not None and self._staged_replay is binding:
                    self._discard_staged_replay_locked(
                        binding,
                        primary,
                        unhealthy=True,
                    )
            raise primary from rebase_error

    def _discard_staged_replay_locked(
        self,
        binding: _StagedReplayBinding,
        primary: BaseException | None,
        *,
        unhealthy: bool,
    ) -> None:
        errors: list[BaseException] = []
        with self._replay_state_lock:
            failure_phase = self._replay_status.phase
            if self._staged_replay is binding:
                self._staged_replay = None
            if self._replay_reservation is binding.reservation:
                self._replay_reservation = None
            self._set_replay_status_locked(
                _ReplayStatus(
                    generation=binding.reservation.base_generation,
                    phase=_ReplayPhase.FAILED,
                    reservation_present=False,
                    failure_phase=failure_phase,
                )
            )
            if self._replay_test_barrier is not None:
                self._replay_test_barrier = None
                self._replay_state_condition.notify_all()

        materialized = binding.materialized_connection
        binding.materialized_connection = None
        if materialized is not None:
            try:
                materialized.close()
            except BaseException as error:  # noqa: BLE001 - exact owned target
                errors.append(error)
        physical = binding.materialized_physical
        binding.materialized_physical = None
        if physical is not None and physical.descriptor >= 0:
            descriptor = physical.descriptor
            physical.descriptor = -1
            try:
                os.close(descriptor)
            except BaseException as error:  # noqa: BLE001 - exact owned descriptor
                errors.append(error)
        rebuild = binding.rebuild
        binding.rebuild = None
        if rebuild is not None and rebuild.old_physical.descriptor >= 0:
            descriptor = rebuild.old_physical.descriptor
            rebuild.old_physical.descriptor = -1
            try:
                os.close(descriptor)
            except BaseException as error:  # noqa: BLE001 - exact old inode
                errors.append(error)
        hydrated = binding.hydrated_connection
        binding.hydrated_connection = None
        if hydrated is not None and hydrated is not materialized:
            try:
                hydrated.close()
            except BaseException as error:  # noqa: BLE001 - exact staged image
                errors.append(error)
        ack_snapshot = binding.ack_snapshot
        binding.ack_snapshot = None
        if ack_snapshot is not None:
            try:
                _close_replay_ack_snapshot(ack_snapshot)
            except BaseException as error:  # noqa: BLE001 - exact snapshot
                errors.append(error)
        source_snapshot = binding.source_snapshot
        binding.source_snapshot = None
        if source_snapshot is not None:
            try:
                _close_replay_source_snapshot(source_snapshot)
            except BaseException as error:  # noqa: BLE001 - exact snapshot
                errors.append(error)
        scope = binding.retention_scope
        if scope is not None and self._evidence._authenticated_retention_replay_scope_is_active(
            scope
        ):
            try:
                self._evidence._release_authenticated_retention_replay_scope(scope)
            except BaseException as error:  # noqa: BLE001 - exact active scope
                errors.append(error)
        try:
            self._acknowledgements._drain_replay_corruption_fences(primary)
        except BaseException as error:  # noqa: BLE001
            errors.append(error)
        try:
            self._journal._drain_replay_corruption_fences(primary)
        except BaseException as error:  # noqa: BLE001
            errors.append(error)
        if unhealthy or errors:
            self._latch_unhealthy(
                primary if primary is not None else (errors[0] if errors else None)
            )
        if errors:
            if primary is not None:
                for cleanup_issue in errors:
                    primary.add_note(
                        "Projection V2 staged cleanup failure: "
                        f"{type(cleanup_issue).__name__}: {cleanup_issue}"
                    )
            else:
                raise BaseExceptionGroup(
                    "Projection V2 staged cleanup failed",
                    errors,
                )

    def _abort_staged_replay(
        self,
        capability: _StagedV2Replay,
        *,
        _factory: object,
    ) -> None:
        if _factory is not _STAGED_REPLAY_FACTORY:
            raise ProjectionAuthorityError("Projection V2 staged abort is factory-only")
        with self._mutex:
            binding = self._require_staged_replay_locked(capability)
            if binding.rebuild is not None:
                raise ProjectionAuthorityError(
                    "guarded Projection V2 rebuild requires exact fallback"
                )
            self._discard_staged_replay_locked(
                binding,
                None,
                unhealthy=False,
            )

    def _copy_staged_replay_into(
        self,
        capability: _StagedV2Replay,
        target: sqlite3.Connection,
        *,
        _factory: object,
        _fault_phase: _ReplayFaultPhase | None = None,
    ) -> _StagedV2ImageSeal:
        if (
            _factory is not _STAGED_REPLAY_FACTORY
            or type(target) is not sqlite3.Connection
            or (
                _fault_phase is not None
                and _fault_phase is not _ReplayFaultPhase.REBUILD_MATERIALIZE
            )
        ):
            raise ProjectionAuthorityError("Projection V2 staged materialization is factory-only")
        binding: _StagedReplayBinding | None = None
        physical: _StagedV2PhysicalBinding | None = None
        materialization_started = False
        close_target_on_error = True
        try:
            with self._mutex:
                binding = self._require_staged_replay_locked(capability)
                if (
                    binding.materialized_connection is not None
                    or binding.materialized_seal is not None
                ):
                    if target is binding.materialized_connection:
                        close_target_on_error = False
                    raise ProjectionAuthorityError(
                        "Projection V2 staged image is already materialized"
                    )
                if target is binding.live_connection or target is binding.hydrated_connection:
                    close_target_on_error = False
                    raise ProjectionConflict(
                        "Projection V2 materialization target is not exact empty"
                    )
                if target.in_transaction:
                    raise ProjectionConflict(
                        "Projection V2 materialization target is not exact empty"
                    )
                materialization_started = True
                database_path = _v2_exact_main_database_path(
                    target,
                    require_file_backed=True,
                )
                existing = target.execute(
                    "SELECT type,name FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
                ).fetchall()
                if existing:
                    raise ProjectionConflict("Projection V2 materialization target is not empty")
                source = binding.hydrated_connection
                if source is None:
                    raise ProjectionAuthorityError("Projection V2 staged image was lost")
                source.backup(target)
                if _fault_phase is _ReplayFaultPhase.REBUILD_MATERIALIZE:
                    raise KeyboardInterrupt("injected Projection V2 staged materialization failure")
                _configure_v2_connection(
                    target,
                    file_backed=bool(database_path),
                )
                _verify_v2_schema(target)
                cursor = _current_v2_cursor(target)
                prefix_sha256 = _v2_snapshot_hash(target)
                table_counts = _v2_table_counts(target)
                if (
                    cursor != binding.report.cursor
                    or prefix_sha256 != binding.report.prefix_sha256
                    or table_counts != _v2_table_counts(source)
                ):
                    raise ProjectionConflict("Projection V2 materialized image changed")
                physical = _capture_staged_v2_physical_binding(database_path)
                seal = object.__new__(_StagedV2ImageSeal)
                object.__setattr__(seal, "cursor", cursor)
                object.__setattr__(
                    seal,
                    "applied_count",
                    binding.report.applied_count,
                )
                object.__setattr__(seal, "prefix_sha256", prefix_sha256)
                object.__setattr__(seal, "table_counts", table_counts)
                binding.materialized_connection = target
                binding.materialized_seal = seal
                binding.materialized_physical = physical
                physical = None
                return seal
        except BaseException as primary:
            target_cleanup_failed = False
            if physical is not None and physical.descriptor >= 0:
                descriptor = physical.descriptor
                physical.descriptor = -1
                try:
                    os.close(descriptor)
                except BaseException as error:  # noqa: BLE001 - adopted descriptor
                    target_cleanup_failed = True
                    primary.add_note(
                        "Projection V2 target descriptor cleanup failure: "
                        f"{type(error).__name__}: {error}"
                    )
            if close_target_on_error:
                try:
                    target.close()
                except BaseException as error:  # noqa: BLE001 - adopted target
                    target_cleanup_failed = True
                    primary.add_note(
                        f"Projection V2 target cleanup failure: {type(error).__name__}: {error}"
                    )
            if binding is not None and materialization_started:
                with self._mutex:
                    if self._staged_replay is binding:
                        if (
                            binding.purpose is _ReplayPurpose.V2_REBUILD
                            and binding.rebuild is not None
                        ):
                            if binding.materialized_connection is target:
                                binding.materialized_connection = None
                            binding.materialized_seal = None
                            if target_cleanup_failed:
                                self._latch_unhealthy(primary)
                        else:
                            self._discard_staged_replay_locked(
                                binding,
                                primary,
                                unhealthy=target_cleanup_failed,
                            )
            raise

    def _validate_materialized_replay_locked(
        self,
        binding: _StagedReplayBinding,
        seal: _StagedV2ImageSeal,
    ) -> None:
        target = binding.materialized_connection
        hydrated = binding.hydrated_connection
        physical = binding.materialized_physical
        if (
            type(seal) is not _StagedV2ImageSeal
            or binding.materialized_seal is not seal
            or target is None
            or hydrated is None
            or physical is None
            or target.in_transaction
        ):
            raise ProjectionAuthorityError("Projection V2 staged image seal is not current")
        _verify_v2_schema(target)
        _revalidate_staged_v2_physical_binding(physical)
        expected_counts = _v2_table_counts(hydrated)
        if (
            seal.cursor != binding.report.cursor
            or seal.applied_count != binding.report.applied_count
            or seal.prefix_sha256 != binding.report.prefix_sha256
            or seal.table_counts != expected_counts
            or _current_v2_cursor(target) != seal.cursor
            or _v2_snapshot_hash(target) != seal.prefix_sha256
            or _v2_table_counts(target) != seal.table_counts
        ):
            raise ProjectionConflict("Projection V2 staged materialization seal changed")

    def _validate_prepared_replay_locked(
        self,
        binding: _StagedReplayBinding,
        seal: _StagedV2ImageSeal,
    ) -> None:
        hydrated = binding.hydrated_connection
        physical = binding.materialized_physical
        if (
            type(seal) is not _StagedV2ImageSeal
            or binding.materialized_seal is not seal
            or binding.materialized_connection is not None
            or hydrated is None
            or physical is None
        ):
            raise ProjectionAuthorityError(
                "Projection V2 staged image is not prepared for publication"
            )
        _revalidate_staged_v2_physical_binding(physical)
        expected_counts = _v2_table_counts(hydrated)
        if (
            seal.cursor != binding.report.cursor
            or seal.applied_count != binding.report.applied_count
            or seal.prefix_sha256 != binding.report.prefix_sha256
            or seal.table_counts != expected_counts
            or _current_v2_cursor(hydrated) != seal.cursor
            or _v2_snapshot_hash(hydrated) != seal.prefix_sha256
        ):
            raise ProjectionConflict("Projection V2 prepared materialization seal changed")

    def _prepare_staged_replay_for_publication(
        self,
        capability: _StagedV2Replay,
        seal: _StagedV2ImageSeal,
        *,
        _factory: object,
        _fault_phase: _ReplayFaultPhase | None = None,
    ) -> None:
        if (
            _factory is not _STAGED_REPLAY_FACTORY
            or type(seal) is not _StagedV2ImageSeal
            or (
                _fault_phase is not None
                and _fault_phase
                not in (
                    _ReplayFaultPhase.REBUILD_STAGED_CHECKPOINT,
                    _ReplayFaultPhase.REBUILD_STAGED_CLOSE,
                )
            )
        ):
            raise ProjectionAuthorityError("Projection V2 staged preparation is factory-only")
        binding: _StagedReplayBinding | None = None
        target: sqlite3.Connection | None = None
        target_handoff_started = False
        target_close_attempted = False
        target_close_completed = False
        with self._mutex:
            try:
                binding = self._require_staged_replay_locked(capability)
                self._validate_materialized_replay_locked(binding, seal)
                target = binding.materialized_connection
                if target is None or target.in_transaction:
                    raise ProjectionAuthorityError(
                        "Projection V2 staged target is not transaction-free"
                    )
                if _fault_phase is _ReplayFaultPhase.REBUILD_STAGED_CHECKPOINT:
                    raise KeyboardInterrupt("injected Projection V2 staged checkpoint failure")
                checkpoint = target.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if (
                    type(checkpoint) not in (tuple, sqlite3.Row)
                    or len(checkpoint) != 3
                    or any(type(value) is not int for value in checkpoint)
                    or tuple(checkpoint) != (0, 0, 0)
                ):
                    raise ProjectionConflict(
                        "Projection V2 staged checkpoint did not truncate exactly"
                    )
                self._validate_materialized_replay_locked(binding, seal)
                target = binding.materialized_connection
                if target is None:
                    raise ProjectionAuthorityError(
                        "Projection V2 staged target disappeared before close"
                    )
                # From this marker onward any interruption is conservative. Keep
                # the local owner alias until either the binding or this frame has
                # made the target's single close attempt.
                target_handoff_started = True
                binding.materialized_connection = None
                target_close_attempted = True
                target.close()
                if _fault_phase is _ReplayFaultPhase.REBUILD_STAGED_CLOSE:
                    raise KeyboardInterrupt("injected ambiguous Projection V2 staged close")
                target_close_completed = True
                self._validate_prepared_replay_locked(binding, seal)
            except BaseException as primary:
                if binding is not None and self._staged_replay is binding:
                    if (
                        target_handoff_started
                        and not target_close_attempted
                        and binding.materialized_connection is None
                        and target is not None
                    ):
                        target_close_attempted = True
                        try:
                            target.close()
                        except BaseException as cleanup_error:  # noqa: BLE001
                            primary.add_note(
                                "Projection V2 detached target cleanup failure: "
                                f"{type(cleanup_error).__name__}: {cleanup_error}"
                            )
                    if not (
                        binding.purpose is _ReplayPurpose.V2_REBUILD and binding.rebuild is not None
                    ):
                        self._discard_staged_replay_locked(
                            binding,
                            primary,
                            unhealthy=target_handoff_started,
                        )
                    elif target_close_attempted and not target_close_completed:
                        self._latch_unhealthy(primary)
                raise

    def _validate_reopened_replay_locked(
        self,
        binding: _StagedReplayBinding,
        seal: _StagedV2ImageSeal,
        reopened: sqlite3.Connection,
    ) -> None:
        hydrated = binding.hydrated_connection
        physical = binding.materialized_physical
        if (
            type(reopened) is not sqlite3.Connection
            or binding.materialized_seal is not seal
            or hydrated is None
            or physical is None
            or reopened is binding.live_connection
            or reopened is hydrated
            or reopened is binding.materialized_connection
            or reopened.in_transaction
        ):
            raise ProjectionConflict("Projection V2 publisher did not return one reopened image")
        published_path = _v2_exact_main_database_path(
            reopened,
            require_file_backed=True,
        )
        _revalidate_staged_v2_physical_binding(
            physical,
            published_path=published_path,
        )
        _verify_v2_schema(reopened)
        cursor = _current_v2_cursor(reopened)
        self._validate_cursor_evidence(reopened, cursor)
        expected_counts = _v2_table_counts(hydrated)
        if (
            cursor != seal.cursor
            or cursor != binding.report.cursor
            or seal.applied_count != binding.report.applied_count
            or seal.prefix_sha256 != binding.report.prefix_sha256
            or seal.table_counts != expected_counts
            or _v2_snapshot_hash(reopened) != binding.report.prefix_sha256
            or _v2_table_counts(reopened) != expected_counts
        ):
            raise ProjectionConflict("Projection V2 reopened image differs from its staged seal")

    def _commit_staged_replay(
        self,
        capability: _StagedV2Replay,
        *,
        seal: _StagedV2ImageSeal | None,
        publisher: Callable[[_NamespacePublicationLatch], sqlite3.Connection] | None,
        direct: bool,
        _fault_phase: _ReplayFaultPhase | None,
    ) -> _UnpublishedV2ReplayReport:
        candidate: sqlite3.Connection | None = None
        committed = False
        owner_irreversible = False
        namespace_state: _NamespacePublicationState | None = None
        namespace_latch: _NamespacePublicationLatch | None = None
        with self._mutex:
            binding = self._require_staged_replay_locked(capability)
            if binding.purpose is _ReplayPurpose.V2_REBUILD:
                raise ProjectionAuthorityError(
                    "Projection V2 rebuild requires its guarded publisher"
                )
            try:
                # Corruption fences are documented to drain outside the ordered
                # replay gate stack. No fallible drain remains after publication.
                self._acknowledgements._drain_replay_corruption_fences(None)
                self._journal._drain_replay_corruption_fences(None)
                retention_gate_context = (
                    nullcontext(None)
                    if binding.retention_scope is None
                    else self._evidence._authenticated_retention_replay_scope_gate(
                        binding.retention_scope,
                        cast(EvidenceRef, binding.through),
                    )
                )
                with (
                    retention_gate_context as retention_gate,
                    self._evidence._replay_source_snapshot_gate(),
                    self._acknowledgements._replay_ack_snapshot_gate(),
                    _correlation_projection_snapshot_gate(binding.authority) as correlation_binding,
                    _correlation_journal_replay_gate(self._journal),
                ):
                    with self._replay_state_lock:
                        if (
                            self._staged_replay is not binding
                            or self._replay_reservation is not binding.reservation
                        ):
                            raise ProjectionAuthorityError(
                                "Projection V2 staged replay changed before commit"
                            )
                        self._set_replay_status_locked(
                            _ReplayStatus(
                                generation=binding.reservation.base_generation,
                                phase=_ReplayPhase.VALIDATING,
                                reservation_present=True,
                            )
                        )
                    self._revalidate_staged_replay_locked(
                        binding,
                        retention_gate,
                        correlation_binding,
                    )
                    if direct:
                        if seal is not None or publisher is not None:
                            raise ProjectionAuthorityError(
                                "Projection V2 direct staged commit was substituted"
                            )
                    else:
                        if seal is None or publisher is None:
                            raise ProjectionAuthorityError(
                                "Projection V2 durable publisher is incomplete"
                            )
                        self._validate_prepared_replay_locked(binding, seal)
                    if _fault_phase is _ReplayFaultPhase.PUBLISH:
                        raise KeyboardInterrupt("injected replay publish failure")
                    if _fault_phase is _ReplayFaultPhase.PRE_COMMIT:
                        raise KeyboardInterrupt("injected replay pre-commit failure")

                    if direct:
                        candidate = binding.hydrated_connection
                        if candidate is None:
                            raise ProjectionAuthorityError(
                                "Projection V2 direct staged image was lost"
                            )
                    else:
                        assert seal is not None
                        assert publisher is not None
                        namespace_state = _NamespacePublicationState()
                        latch = object.__new__(_NamespacePublicationLatch)
                        namespace_state.latch = latch
                        namespace_latch = latch
                        _NAMESPACE_PUBLICATION_STATES[latch] = namespace_state
                        candidate = publisher(latch)
                        if _fault_phase is _ReplayFaultPhase.POST_CALLBACK:
                            raise KeyboardInterrupt("injected replay post-callback failure")
                        observed_latch_state = _NAMESPACE_PUBLICATION_STATES.pop(
                            latch,
                            None,
                        )
                        namespace_latch = None
                        self._revalidate_staged_replay_locked(
                            binding,
                            retention_gate,
                            correlation_binding,
                        )
                        if (
                            observed_latch_state is not namespace_state
                            or namespace_state.latch is not latch
                            or namespace_state.marked is not True
                        ):
                            raise ProjectionAuthorityError(
                                "Projection V2 publisher did not latch namespace"
                            )
                        self._validate_reopened_replay_locked(
                            binding,
                            seal,
                            candidate,
                        )

                    retention_consumption = None
                    if binding.retention_scope is not None:
                        retention_consumption = self._evidence._prepare_authenticated_retention_replay_consumption_locked(
                            binding.retention_scope,
                            cast(
                                _AuthenticatedRetentionReplayGate,
                                retention_gate,
                            ),
                        )
                    published_status = _ReplayStatus(
                        generation=binding.reservation.publish_generation,
                        phase=_ReplayPhase.PUBLISHED,
                        reservation_present=False,
                    )

                    # Ownership must transfer before close: if a close raises, the
                    # unwind sweeps the binding again, and a descriptor number the OS
                    # already reassigned would be closed out from under another thread.
                    ack_snapshot = binding.ack_snapshot
                    if ack_snapshot is None:
                        raise ProjectionAuthorityError("Projection V2 staged ACK snapshot was lost")
                    binding.ack_snapshot = None
                    _close_replay_ack_snapshot(ack_snapshot)
                    source_snapshot = binding.source_snapshot
                    if source_snapshot is None:
                        raise ProjectionAuthorityError(
                            "Projection V2 staged source snapshot was lost"
                        )
                    binding.source_snapshot = None
                    _close_replay_source_snapshot(source_snapshot)
                    if not direct:
                        hydrated = binding.hydrated_connection
                        if hydrated is not None:
                            hydrated.close()
                            binding.hydrated_connection = None
                        physical = binding.materialized_physical
                        if physical is None or physical.descriptor < 0:
                            raise ProjectionAuthorityError(
                                "Projection V2 materialized descriptor was lost"
                            )
                        descriptor = physical.descriptor
                        physical.descriptor = -1
                        binding.materialized_physical = None
                        os.close(descriptor)

                    with self._replay_state_lock:
                        if (
                            self._staged_replay is not binding
                            or self._replay_reservation is not binding.reservation
                        ):
                            raise ProjectionAuthorityError(
                                "Projection V2 staged replay changed at final edge"
                            )
                    # Every fallible and higher-lock preparation is complete
                    # before the final replay-state edge. Any failure from here
                    # is irreversible and revokes the owner.
                    owner_irreversible = True
                    binding.live_connection.close()
                    _rebuild_correlation_projection_authority(
                        binding.authority,
                        binding.computation.terminal_predecessor,
                    )
                    with self._replay_state_lock:
                        if retention_consumption is not None:
                            self._evidence._commit_prevalidated_retention_replay_consumption_locked(
                                retention_consumption
                            )
                        if direct:
                            binding.hydrated_connection = None
                        self._connection = candidate
                        candidate = None
                        self._generation = binding.reservation.publish_generation
                        self._staged_replay = None
                        self._replay_reservation = None
                        binding.materialized_seal = None
                        committed = True
                        # Observable publication is deliberately the last write.
                        self._replay_status = published_status
                        return binding.report
            except (
                AckJournalError,
                CorrelationProjectionError,
                CorrelationRequestJournalError,
                EvidenceStoreError,
            ) as error:
                converted = ProjectionAuthorityError(
                    "Projection V2 staged publication authority changed"
                )
                if committed:
                    self._latch_unhealthy(converted)
                else:
                    post_namespace = namespace_state is not None and namespace_state.marked is True
                    latch_cleanup_failed = False
                    if namespace_latch is not None:
                        try:
                            observed = _NAMESPACE_PUBLICATION_STATES.pop(
                                namespace_latch,
                                None,
                            )
                            if observed is not namespace_state:
                                latch_cleanup_failed = True
                        except BaseException as cleanup_error:  # noqa: BLE001
                            latch_cleanup_failed = True
                            converted.add_note(
                                "Projection V2 latch cleanup failure: "
                                f"{type(cleanup_error).__name__}: {cleanup_error}"
                            )
                    candidate_cleanup_failed = False
                    if (
                        candidate is not None
                        and candidate is not binding.live_connection
                        and candidate is not binding.hydrated_connection
                        and candidate is not binding.materialized_connection
                    ):
                        try:
                            candidate.close()
                        except BaseException as cleanup_error:  # noqa: BLE001
                            candidate_cleanup_failed = True
                            converted.add_note(
                                "Projection V2 reopened cleanup failure: "
                                f"{type(cleanup_error).__name__}: {cleanup_error}"
                            )
                    self._discard_staged_replay_locked(
                        binding,
                        converted,
                        unhealthy=(
                            owner_irreversible
                            or post_namespace
                            or latch_cleanup_failed
                            or candidate_cleanup_failed
                        ),
                    )
                raise converted from error
            except BaseException as error:
                if committed:
                    self._latch_unhealthy(error)
                else:
                    post_namespace = namespace_state is not None and namespace_state.marked is True
                    latch_cleanup_failed = False
                    if namespace_latch is not None:
                        try:
                            observed = _NAMESPACE_PUBLICATION_STATES.pop(
                                namespace_latch,
                                None,
                            )
                            if observed is not namespace_state:
                                latch_cleanup_failed = True
                        except BaseException as cleanup_error:  # noqa: BLE001
                            latch_cleanup_failed = True
                            error.add_note(
                                "Projection V2 latch cleanup failure: "
                                f"{type(cleanup_error).__name__}: {cleanup_error}"
                            )
                    candidate_cleanup_failed = False
                    if (
                        candidate is not None
                        and candidate is not binding.live_connection
                        and candidate is not binding.hydrated_connection
                        and candidate is not binding.materialized_connection
                    ):
                        try:
                            candidate.close()
                        except BaseException as cleanup_error:  # noqa: BLE001
                            candidate_cleanup_failed = True
                            error.add_note(
                                "Projection V2 reopened cleanup failure: "
                                f"{type(cleanup_error).__name__}: {cleanup_error}"
                            )
                    self._discard_staged_replay_locked(
                        binding,
                        error,
                        unhealthy=(
                            owner_irreversible
                            or post_namespace
                            or latch_cleanup_failed
                            or candidate_cleanup_failed
                        ),
                    )
                raise

    def _publish_staged_v2_rebuild(
        self,
        capability: _StagedV2Replay,
        seal: _StagedV2ImageSeal,
        guard: _V2RebuildGuard,
        publisher: Callable[[_NamespacePublicationLatch], sqlite3.Connection],
        reopen_old: Callable[[], _ReopenedV2Old],
        *,
        _factory: object,
        _fault_phase: _ReplayFaultPhase | None = None,
    ) -> _UnpublishedV2ReplayReport:
        if (
            _factory is not _STAGED_REPLAY_FACTORY
            or type(seal) is not _StagedV2ImageSeal
            or type(guard) is not _V2RebuildGuard
            or not callable(publisher)
            or not callable(reopen_old)
            or (
                _fault_phase is not None
                and _fault_phase
                not in (
                    _ReplayFaultPhase.PRE_COMMIT,
                    _ReplayFaultPhase.REBUILD_CHECKPOINT,
                    _ReplayFaultPhase.REBUILD_CLOSE,
                )
            )
        ):
            raise ProjectionAuthorityError("Projection V2 rebuild publication is factory-only")
        binding: _StagedReplayBinding | None = None
        rebuild: _V2RebuildBinding | None = None
        candidate: sqlite3.Connection | None = None
        namespace_state: _NamespacePublicationState | None = None
        namespace_latch: _NamespacePublicationLatch | None = None
        close_attempted = False
        close_completed = False
        committed = False
        replacement_attempted = False
        try:
            with self._mutex:
                binding, rebuild = self._require_v2_rebuild_guard_locked(
                    capability,
                    guard,
                    permit_suspended=False,
                )
                if rebuild.guard_consumed:
                    raise ProjectionAuthorityError(
                        "Projection V2 rebuild guard was already consumed"
                    )
                rebuild.guard_consumed = True
                self._acknowledgements._drain_replay_corruption_fences(None)
                self._journal._drain_replay_corruption_fences(None)
                retention_gate_context = (
                    nullcontext(None)
                    if binding.retention_scope is None
                    else self._evidence._authenticated_retention_replay_scope_gate(
                        binding.retention_scope,
                        cast(EvidenceRef, binding.through),
                    )
                )
                with (
                    retention_gate_context as retention_gate,
                    self._evidence._replay_source_snapshot_gate(),
                    self._acknowledgements._replay_ack_snapshot_gate(),
                    _correlation_projection_snapshot_gate(binding.authority) as correlation_binding,
                    _correlation_journal_replay_gate(self._journal),
                ):
                    self._revalidate_staged_replay_locked(
                        binding,
                        retention_gate,
                        correlation_binding,
                    )
                    self._validate_prepared_replay_locked(binding, seal)
                    old_connection = binding.live_connection
                    self._validate_v2_rebuild_old_locked(
                        binding,
                        rebuild,
                        old_connection,
                    )
                    if _fault_phase is _ReplayFaultPhase.REBUILD_CHECKPOINT:
                        raise KeyboardInterrupt("injected Projection V2 rebuild checkpoint failure")
                    checkpoint = old_connection.execute(
                        "PRAGMA wal_checkpoint(TRUNCATE)"
                    ).fetchone()
                    checkpoint_values = () if checkpoint is None else tuple(checkpoint)
                    if (
                        len(checkpoint_values) != 3
                        or any(type(value) is not int for value in checkpoint_values)
                        or checkpoint_values != (0, 0, 0)
                    ):
                        raise ProjectionConflict(
                            "Projection V2 rebuild old checkpoint was not exact"
                        )
                    self._validate_v2_rebuild_old_locked(
                        binding,
                        rebuild,
                        old_connection,
                    )
                    os.fsync(rebuild.old_physical.descriptor)
                    self._validate_v2_rebuild_old_locked(
                        binding,
                        rebuild,
                        old_connection,
                    )
                    # Detach before the sole close attempt. A raised close is
                    # ambiguous and therefore cannot enter fallback rebase.
                    self._connection = None
                    close_attempted = True
                    old_connection.close()
                    if _fault_phase is _ReplayFaultPhase.REBUILD_CLOSE:
                        raise KeyboardInterrupt("injected ambiguous Projection V2 old close")
                    rebuild.suspended = True
                    close_completed = True
                    with self._replay_state_lock:
                        self._set_replay_status_locked(
                            _ReplayStatus(
                                generation=binding.reservation.base_generation,
                                phase=_ReplayPhase.SUSPENDED,
                                reservation_present=True,
                            )
                        )
                    if _fault_phase is _ReplayFaultPhase.PRE_COMMIT:
                        raise KeyboardInterrupt("injected Projection V2 rebuild pre-arm failure")

                    namespace_state = _NamespacePublicationState()
                    latch = object.__new__(_NamespacePublicationLatch)
                    namespace_state.latch = latch
                    namespace_latch = latch
                    _NAMESPACE_PUBLICATION_STATES[latch] = namespace_state
                    candidate = publisher(latch)
                    observed = _NAMESPACE_PUBLICATION_STATES.pop(latch, None)
                    namespace_latch = None
                    if (
                        observed is not namespace_state
                        or namespace_state.latch is not latch
                        or namespace_state.marked is not True
                    ):
                        raise ProjectionAuthorityError(
                            "Projection V2 rebuild publisher did not arm namespace"
                        )
                    self._validate_reopened_replay_locked(
                        binding,
                        seal,
                        candidate,
                    )
                    _revalidate_v2_rebuild_old_physical(
                        rebuild.old_physical,
                        named=False,
                    )
                    retention_consumption = None
                    if binding.retention_scope is not None:
                        retention_consumption = self._evidence._prepare_authenticated_retention_replay_consumption_locked(
                            binding.retention_scope,
                            cast(
                                _AuthenticatedRetentionReplayGate,
                                retention_gate,
                            ),
                        )
                    cleanup_errors = self._close_v2_rebuild_stage_resources_locked(binding)
                    if cleanup_errors:
                        raise BaseExceptionGroup(
                            "Projection V2 rebuild final resource cleanup failed",
                            cleanup_errors,
                        )
                    published_status = _ReplayStatus(
                        generation=binding.reservation.publish_generation,
                        phase=_ReplayPhase.PUBLISHED,
                        reservation_present=False,
                    )
                    with self._replay_state_lock:
                        if (
                            self._staged_replay is not binding
                            or self._replay_reservation is not binding.reservation
                        ):
                            raise ProjectionAuthorityError(
                                "Projection V2 rebuild changed at final edge"
                            )
                    replacement_attempted = True
                    fresh_authority = _commit_correlation_projection_authority_replacement(
                        rebuild.authority_replacement,
                        success=True,
                        _factory=_AUTHORITY_REPLACEMENT_FACTORY,
                    )
                    self._authority = fresh_authority
                    with self._replay_state_lock:
                        if (
                            self._staged_replay is not binding
                            or self._replay_reservation is not binding.reservation
                        ):
                            raise ProjectionAuthorityError(
                                "Projection V2 rebuild changed after final edge"
                            )
                        self._connection = candidate
                        self._generation = binding.reservation.publish_generation
                        if retention_consumption is not None:
                            self._evidence._commit_prevalidated_retention_replay_consumption_locked(
                                retention_consumption
                            )
                        self._staged_replay = None
                        self._replay_reservation = None
                        binding.rebuild = None
                        committed = True
                        self._replay_status = published_status
                        return binding.report
        except BaseException as error:
            if replacement_attempted and rebuild is not None:
                try:
                    fresh_closed = _fail_closed_correlation_projection_authority_replacement(
                        rebuild.authority_replacement,
                        error,
                        _factory=_AUTHORITY_REPLACEMENT_FACTORY,
                    )
                except BaseException as cleanup_error:  # noqa: BLE001
                    error.add_note(
                        "Projection V2 published authority fail-shut failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
                else:
                    if fresh_closed:
                        self._authority = None
            armed = namespace_state is not None and namespace_state.marked is True
            if namespace_latch is not None:
                try:
                    observed = _NAMESPACE_PUBLICATION_STATES.pop(
                        namespace_latch,
                        None,
                    )
                    if observed is not namespace_state:
                        armed = True
                except BaseException as cleanup_error:  # noqa: BLE001
                    armed = True
                    error.add_note(
                        "Projection V2 rebuild latch cleanup failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            if candidate is not None:
                try:
                    candidate.close()
                except BaseException as cleanup_error:  # noqa: BLE001
                    armed = True
                    error.add_note(
                        "Projection V2 rebuild reopened cleanup failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            if (
                binding is not None
                and rebuild is not None
                and not committed
                and not armed
                and (not close_attempted or close_completed)
            ):
                reopened: _ReopenedV2Old | None = None
                if close_completed:
                    try:
                        reopened = reopen_old()
                    except BaseException as reopen_error:
                        error.add_note(
                            "Projection V2 rebuild old reopen failure: "
                            f"{type(reopen_error).__name__}: {reopen_error}"
                        )
                        with self._mutex:
                            self._latch_unhealthy(error)
                            if self._staged_replay is binding:
                                self._discard_staged_replay_locked(
                                    binding,
                                    error,
                                    unhealthy=True,
                                )
                        raise error from reopen_error
                self._rebase_failed_staged_v2_rebuild(
                    capability,
                    guard,
                    reopened_old=reopened,
                    primary=error,
                    _factory=_STAGED_REPLAY_FACTORY,
                )
                raise
            with self._mutex:
                self._latch_unhealthy(error)
                if binding is not None and self._staged_replay is binding:
                    self._discard_staged_replay_locked(
                        binding,
                        error,
                        unhealthy=True,
                    )
            raise

    def _publish_staged_replay(
        self,
        capability: _StagedV2Replay,
        seal: _StagedV2ImageSeal,
        publisher: Callable[[_NamespacePublicationLatch], sqlite3.Connection],
        *,
        _factory: object,
        _fault_phase: _ReplayFaultPhase | None = None,
    ) -> _UnpublishedV2ReplayReport:
        if (
            _factory is not _STAGED_REPLAY_FACTORY
            or type(seal) is not _StagedV2ImageSeal
            or not callable(publisher)
            or (
                _fault_phase is not None
                and (
                    type(_fault_phase) is not _ReplayFaultPhase
                    or _fault_phase
                    not in (
                        _ReplayFaultPhase.PUBLISH,
                        _ReplayFaultPhase.POST_CALLBACK,
                        _ReplayFaultPhase.PRE_COMMIT,
                    )
                )
            )
        ):
            raise ProjectionAuthorityError("Projection V2 durable publication is factory-only")
        return self._commit_staged_replay(
            capability,
            seal=seal,
            publisher=publisher,
            direct=False,
            _fault_phase=_fault_phase,
        )

    def _replay_unpublished_prefix(
        self,
        through: EvidenceRef | None,
        *,
        _factory: object,
        retention_completion: AuthenticatedRetentionUnlinkCompletion | None = None,
        _fault_phase: _ReplayFaultPhase | None = None,
    ) -> _UnpublishedV2ReplayReport:
        if (
            _factory is not _UNPUBLISHED_REPLAY_FACTORY
            or (through is not None and type(through) is not EvidenceRef)
            or (
                retention_completion is not None
                and type(retention_completion) is not AuthenticatedRetentionUnlinkCompletion
            )
            or (_fault_phase is not None and type(_fault_phase) is not _ReplayFaultPhase)
        ):
            raise ProjectionAuthorityError("Projection V2 unpublished replay is factory-only")
        stage_fault = (
            _fault_phase
            if _fault_phase in (_ReplayFaultPhase.FREEZE, _ReplayFaultPhase.COMPUTE)
            else None
        )
        commit_fault = (
            _fault_phase
            if _fault_phase in (_ReplayFaultPhase.PUBLISH, _ReplayFaultPhase.PRE_COMMIT)
            else None
        )
        capability = self._stage_unpublished_prefix(
            through,
            retention_completion=retention_completion,
            _factory=_STAGED_REPLAY_FACTORY,
            _fault_phase=stage_fault,
        )
        return self._commit_staged_replay(
            capability,
            seal=None,
            publisher=None,
            direct=True,
            _fault_phase=commit_fault,
        )

    def _revalidate_transaction_predecessor(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        acceptance_cursor: int,
        ack_boundary: _ProjectionAckBoundaryV2,
        unpublished_ack: _AckUnpublishedAnchor | None = None,
    ) -> None:
        if self._healthy_acceptance_cursor() != acceptance_cursor:
            raise ProjectionAuthorityError(
                "Projection V2 acceptance cursor changed inside transaction"
            )
        if unpublished_ack is None:
            self._revalidate_ack_boundary(ack_boundary, acceptance_cursor)
        else:
            self._revalidate_unpublished_ack_anchor(
                unpublished_ack,
                acceptance_cursor,
            )
        current = _current_v2_cursor(connection)
        if _predecessor_v2(self._generation, current) != predecessor:
            raise ProjectionConflict("Projection V2 predecessor changed inside its transaction")
        self._validate_cursor_evidence(connection, current)
        _validate_correlation_projection_predecessor(authority, predecessor)
        if unpublished_ack is None:
            self._revalidate_ack_boundary(ack_boundary, acceptance_cursor)
        else:
            self._revalidate_unpublished_ack_anchor(
                unpublished_ack,
                acceptance_cursor,
            )
        if self._healthy_acceptance_cursor() != acceptance_cursor:
            raise ProjectionAuthorityError(
                "Projection V2 acceptance cursor changed during validation"
            )
        try:
            current_record = self._evidence.resolve_authenticated_ref(prepared.record.ref)
        except EvidenceStoreError as error:
            raise ProjectionAuthorityError(
                "Projection V2 input lost authenticated evidence authority"
            ) from error
        if not _same_stored_record_v2(current_record, prepared.record):
            raise ProjectionAuthorityError(
                "Projection V2 authenticated input changed during transaction"
            )
        _validate_correlation_projection_predecessor(authority, predecessor)

    def _apply_prepared(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        acceptance_cursor: int,
        ack_boundary: _ProjectionAckBoundaryV2,
        unpublished_ack: _AckUnpublishedAnchor | None = None,
    ) -> ProjectionApplyResult:
        envelope = prepared.envelope
        ref = prepared.record.ref
        duplicate: str | None = None
        is_primary = False
        transaction_started = False
        commit_attempted = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction_started = True
            self._revalidate_transaction_predecessor(
                connection,
                authority,
                predecessor,
                prepared,
                acceptance_cursor,
                ack_boundary,
                unpublished_ack,
            )
            duplicate_row = connection.execute(
                "SELECT primary_event_id FROM projection_dedup "
                "WHERE dedup_kind=? AND logical_key_sha256=? AND is_primary=1",
                (prepared.dedup_kind, prepared.logical_key_sha256),
            ).fetchone()
            if duplicate_row is not None:
                duplicate_value = duplicate_row["primary_event_id"]
                if (
                    type(duplicate_value) is not str
                    or _EVENT_ID_V2.fullmatch(duplicate_value) is None
                ):
                    raise ProjectionConflict("Projection V2 logical primary identity is invalid")
                duplicate = duplicate_value
            is_primary = duplicate is None
            primary_event_id = envelope.event_id if is_primary else duplicate
            placeholders = ",".join("?" for _ in _TABLE_LAYOUT_V2[1][1])
            connection.execute(
                f"INSERT INTO events({','.join(_TABLE_LAYOUT_V2[1][1])}) VALUES({placeholders})",
                _event_values_v2(prepared, duplicate),
            )
            self._step_hook(_APPLY_STEPS_V2[0])
            connection.execute(
                "INSERT INTO projection_dedup("
                "event_id,dedup_kind,logical_key_sha256,primary_event_id,is_primary"
                ") VALUES(?,?,?,?,?)",
                (
                    envelope.event_id,
                    prepared.dedup_kind,
                    prepared.logical_key_sha256,
                    primary_event_id,
                    int(is_primary),
                ),
            )
            self._step_hook(_APPLY_STEPS_V2[1])
            final_authority_check: Callable[[], None] | None = None
            if is_primary:
                final_authority_check = self._reduce_primary(
                    connection,
                    authority,
                    predecessor,
                    prepared,
                    acceptance_cursor,
                )
            self._step_hook(_APPLY_STEPS_V2[2])
            self._revalidate_transaction_predecessor(
                connection,
                authority,
                predecessor,
                prepared,
                acceptance_cursor,
                ack_boundary,
                unpublished_ack,
            )
            connection.execute(
                "INSERT INTO ingest_cursors("
                "host_id,source_sequence,event_id,content_sha256,segment_id,"
                "segment_relative_path,frame_offset,frame_size,frame_sha256"
                ") VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(host_id) DO UPDATE SET "
                "source_sequence=excluded.source_sequence,event_id=excluded.event_id,"
                "content_sha256=excluded.content_sha256,segment_id=excluded.segment_id,"
                "segment_relative_path=excluded.segment_relative_path,"
                "frame_offset=excluded.frame_offset,frame_size=excluded.frame_size,"
                "frame_sha256=excluded.frame_sha256",
                (
                    envelope.host_id,
                    _encode_uint64_v2(ref.source_sequence),
                    ref.event_id,
                    ref.content_sha256,
                    ref.segment_id,
                    ref.segment_relative_path,
                    _encode_uint64_v2(ref.frame_offset),
                    _encode_uint64_v2(ref.frame_size),
                    ref.frame_sha256,
                ),
            )
            self._step_hook(_APPLY_STEPS_V2[3])
            if final_authority_check is not None:
                final_authority_check()
            try:
                final_record = self._evidence.resolve_authenticated_ref(ref)
            except EvidenceStoreError as error:
                raise ProjectionAuthorityError(
                    "Projection V2 input authority disappeared before commit"
                ) from error
            if not _same_stored_record_v2(final_record, prepared.record):
                raise ProjectionAuthorityError("Projection V2 input changed before commit")
            if self._healthy_acceptance_cursor() != acceptance_cursor:
                raise ProjectionAuthorityError(
                    "Projection V2 acceptance cursor changed before commit"
                )
            if unpublished_ack is None:
                self._revalidate_ack_boundary(ack_boundary, acceptance_cursor)
            else:
                self._revalidate_unpublished_ack_anchor(
                    unpublished_ack,
                    acceptance_cursor,
                )
            _validate_correlation_projection_predecessor(
                authority,
                predecessor,
            )
            commit_attempted = True
            connection.execute("COMMIT")
            transaction_started = False
            self._step_hook("commit")
            successor = _ProjectionPredecessor(
                generation=self._generation,
                host_id=envelope.host_id,
                source_sequence=ref.source_sequence,
                event_id=ref.event_id,
                content_sha256=ref.content_sha256,
                frame_sha256=ref.frame_sha256,
            )
            _advance_correlation_projection_authority(
                authority,
                predecessor,
                successor,
            )
        except sqlite3.IntegrityError as error:
            self._settle_failed_transaction(
                connection,
                error,
                transaction_started=transaction_started,
                commit_attempted=commit_attempted,
            )
            self._latch_unhealthy(error)
            raise ProjectionConflict(
                "Projection V2 facts conflict with authenticated evidence"
            ) from error
        except BaseException as error:
            rollback_proven = self._settle_failed_transaction(
                connection,
                error,
                transaction_started=transaction_started,
                commit_attempted=commit_attempted,
            )
            if not rollback_proven:
                self._latch_unhealthy(error)
            else:
                try:
                    _validate_correlation_projection_predecessor(
                        authority,
                        predecessor,
                    )
                except Exception:  # noqa: BLE001 - any authority drift is fatal
                    self._latch_unhealthy(error)
            raise
        cursor = ProjectionCursor(
            host_id=envelope.host_id,
            source_sequence=ref.source_sequence,
            event_id=ref.event_id,
            content_sha256=ref.content_sha256,
            frame_sha256=ref.frame_sha256,
        )
        return ProjectionApplyResult(
            event_id=envelope.event_id,
            duplicate_of_event_id=duplicate,
            reducer_applied=is_primary,
            cursor=cursor,
        )

    def _settle_failed_transaction(
        self,
        connection: sqlite3.Connection,
        primary: BaseException,
        *,
        transaction_started: bool,
        commit_attempted: bool,
    ) -> bool:
        try:
            in_transaction = connection.in_transaction
        except BaseException as error:  # noqa: BLE001 - health ambiguity
            self._latch_unhealthy(primary)
            primary.add_note(f"transaction state could not be read: {error!r}")
            return False
        if commit_attempted and not in_transaction:
            self._latch_unhealthy(primary)
            primary.add_note("Projection V2 COMMIT may have completed")
            return False
        if not transaction_started and not in_transaction:
            return True
        if not in_transaction:
            self._latch_unhealthy(primary)
            primary.add_note("Projection V2 transaction ended without proven rollback")
            return False
        try:
            connection.execute("ROLLBACK")
            self._step_hook("rollback")
            return True
        except BaseException as error:  # noqa: BLE001 - preserve primary
            self._latch_unhealthy(primary)
            primary.add_note(f"Projection V2 rollback could not be proven: {error!r}")
            return False

    def _reduce_primary(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        acceptance_cursor: int,
    ) -> Callable[[], None] | None:
        self._reduce_base(connection, prepared)
        if prepared.coverage is not None:
            try:
                expected = self._expected_coverage_invalidations(
                    connection,
                    prepared,
                )
                for row in expected:
                    connection.execute(
                        "INSERT INTO candidate_invalidations VALUES(?,?,?,?,?)",
                        row,
                    )
                    self._step_hook("candidate_invalidation")
            except ProjectionConflict:
                raise
            except (
                CorrelationRequestJournalError,
                EvidenceStoreError,
                HistoricalCoverageConflict,
                HistoricalCoverageUnavailable,
                AttributeError,
                TypeError,
                ValueError,
            ) as error:
                raise ProjectionAuthorityError(
                    "Projection V2 late coverage authority is unavailable"
                ) from error

            def final_coverage_authority_check() -> None:
                try:
                    self._validate_coverage_invalidation_closure(
                        connection,
                        prepared,
                        is_primary=True,
                    )
                except (ProjectionConflict, ProjectionAuthorityError):
                    raise
                except (
                    CorrelationRequestJournalError,
                    EvidenceStoreError,
                    HistoricalCoverageConflict,
                    HistoricalCoverageUnavailable,
                    AttributeError,
                    TypeError,
                    ValueError,
                ) as error:
                    raise ProjectionAuthorityError(
                        "Projection V2 late coverage authority changed after persistence"
                    ) from error

            return final_coverage_authority_check
        if prepared.envelope.event_type != "pcc_correlation_snapshot":
            return None
        try:
            return self._reduce_pcc(
                connection,
                authority,
                predecessor,
                prepared,
                acceptance_cursor,
            )
        except ProjectionConflict:
            raise
        except ProjectionAuthorityError:
            raise
        except (
            CorrelationProjectionError,
            CorrelationRequestJournalError,
            EvidenceStoreError,
            HistoricalCoverageConflict,
            HistoricalCoverageUnavailable,
            AttributeError,
            TypeError,
            ValueError,
        ) as error:
            raise ProjectionAuthorityError(
                "Projection V2 PCC authority could not be revalidated"
            ) from error

    def _expected_coverage_invalidations(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedV2Record,
    ) -> list[tuple[object, ...]]:
        if prepared.coverage is None:
            return []
        candidate_columns = ",".join(f"c.{column}" for column in _CANDIDATE_COLUMNS)
        rows = connection.execute(
            f"SELECT {candidate_columns} FROM candidates AS c "
            "JOIN events AS snapshot "
            "ON snapshot.event_id=c.correlation_snapshot_event_id "
            "WHERE c.host_id=? AND snapshot.source_sequence<? "
            "ORDER BY c.candidate_id COLLATE BINARY LIMIT ?",
            (
                prepared.envelope.host_id,
                _encode_uint64_v2(prepared.record.ref.source_sequence),
                _INVALIDATION_CANDIDATE_CAP_V2 + 1,
            ),
        ).fetchall()
        if len(rows) > _INVALIDATION_CANDIDATE_CAP_V2:
            raise HistoricalCoverageUnavailable("late coverage candidate matches exceed 4096")
        if not _late_coverage_may_invalidate_candidate(prepared.record):
            return []
        verifier = self._evidence._bound_verifier
        if verifier is None:
            raise ProjectionAuthorityError("Projection V2 late coverage lost verifier authority")
        candidates: list[_LateCandidateV2] = []
        for row in rows:
            _candidate_duplicate_key_from_row(row)
            candidate = _decode_candidate(row)
            snapshot_rows = connection.execute(
                "SELECT candidate_id,evidence_event_id,evidence_source_sequence,"
                "evidence_content_sha256,role,authority_snapshot_event_id "
                "FROM candidate_evidence WHERE candidate_id=? AND "
                "evidence_event_id=? AND role='correlation_snapshot' AND "
                "authority_snapshot_event_id=? LIMIT 2",
                (
                    candidate.candidate_id,
                    candidate.correlation_snapshot_event_id,
                    candidate.correlation_snapshot_event_id,
                ),
            ).fetchall()
            if len(snapshot_rows) != 1:
                raise ProjectionConflict("Projection V2 late candidate lost snapshot evidence")
            (
                evidence_candidate_id,
                evidence_event_id,
                snapshot_sequence,
                evidence_hash,
                role,
                authority_event_id,
            ) = _decode_candidate_evidence(snapshot_rows[0])
            if (
                evidence_candidate_id != candidate.candidate_id
                or evidence_event_id != candidate.correlation_snapshot_event_id
                or authority_event_id != candidate.correlation_snapshot_event_id
                or role != "correlation_snapshot"
                or snapshot_sequence >= prepared.record.ref.source_sequence
            ):
                raise ProjectionConflict("Projection V2 late candidate snapshot binding changed")
            snapshot_ref = verifier.accepted_ref(snapshot_sequence)
            if (
                type(snapshot_ref) is not EvidenceRef
                or snapshot_ref.event_id != evidence_event_id
                or snapshot_ref.content_sha256 != evidence_hash
            ):
                raise ProjectionAuthorityError(
                    "Projection V2 late candidate snapshot is not authenticated"
                )
            candidates.append(_LateCandidateV2(candidate, snapshot_ref))
        if not candidates:
            return []

        def evaluate(
            proofs: tuple[AuthenticatedPCCInput, ...],
        ) -> tuple[tuple[object, ...], ...]:
            if len(proofs) != len(candidates):
                raise ProjectionAuthorityError("Projection V2 late candidate batch length changed")
            expected: list[tuple[object, ...]] = []
            for selected, proof in zip(candidates, proofs, strict=True):
                candidate = selected.candidate
                trigger = proof.snapshot.trigger
                if (
                    type(proof) is not AuthenticatedPCCInput
                    or type(proof.evidence_ref) is not EvidenceRef
                    or proof.evidence_ref != selected.snapshot_ref
                    or proof.event_id != candidate.correlation_snapshot_event_id
                    or proof.host_id != candidate.host_id
                    or proof.boot_id != candidate.boot_id
                    or trigger.event_id != candidate.primary_event_id
                    or trigger.source_sequence != candidate.primary_source_sequence
                ):
                    raise ProjectionAuthorityError(
                        "Projection V2 late candidate PCC binding changed"
                    )
                if _late_coverage_invalidates_candidate(proof, prepared.record):
                    expected.append(
                        _encode_candidate_invalidation(
                            candidate.candidate_id,
                            prepared.envelope.event_id,
                            prepared.record.ref.source_sequence,
                            prepared.record.ref.content_sha256,
                            _INVALIDATION_REASON_V2,
                        )
                    )
            return tuple(expected)

        return list(
            _evaluate_completed_snapshot_batch(
                self._journal,
                tuple(selected.snapshot_ref for selected in candidates),
                evaluate,
            )
        )

    def _validate_coverage_invalidation_closure(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedV2Record,
        *,
        is_primary: bool,
    ) -> None:
        rows = connection.execute(
            "SELECT candidate_id,coverage_event_id,coverage_source_sequence,"
            "coverage_content_sha256,reason_code FROM candidate_invalidations "
            "WHERE coverage_event_id=? ORDER BY candidate_id COLLATE BINARY LIMIT ?",
            (
                prepared.envelope.event_id,
                _INVALIDATION_CANDIDATE_CAP_V2 + 1,
            ),
        ).fetchall()
        if len(rows) > _INVALIDATION_CANDIDATE_CAP_V2:
            raise ProjectionConflict("Projection V2 coverage invalidation closure exceeds 4096")
        for row in rows:
            _decode_candidate_invalidation(row)
        actual = [tuple(row) for row in rows]
        expected = (
            self._expected_coverage_invalidations(connection, prepared)
            if is_primary and prepared.coverage is not None
            else []
        )
        if actual != expected:
            raise ProjectionConflict("Projection V2 coverage invalidation closure changed")

    def _reduce_base(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedV2Record,
    ) -> None:
        envelope = prepared.envelope
        ref = prepared.record.ref
        sequence = _encode_uint64_v2(ref.source_sequence)
        if prepared.coverage is not None:
            coverage = prepared.coverage
            connection.execute(
                "INSERT INTO coverage_intervals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    envelope.event_id,
                    envelope.host_id,
                    coverage.component,
                    coverage.kind,
                    coverage.severity,
                    coverage.opened_at,
                    coverage.closed_at,
                    _optional_uint64_v2(coverage.affected_source_sequence_start),
                    _optional_uint64_v2(coverage.affected_source_sequence_end),
                    _optional_uint64_v2(coverage.dropped_count),
                    coverage.reason_code,
                    _optional_uint64_v2(coverage.reconcile_generation),
                    sequence,
                    ref.content_sha256,
                ),
            )
            return
        falco = prepared.falco
        if falco is None:
            return
        if falco.docker_container_id is not None and falco.docker_started_at is not None:
            connection.execute(
                "INSERT INTO containers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(host_id,container_id,container_started_at) DO UPDATE SET "
                "image_id=excluded.image_id,repo_digests_json=excluded.repo_digests_json,"
                "immutable_spec_sha256=excluded.immutable_spec_sha256,"
                "inventory_revision=excluded.inventory_revision,"
                "last_event_id=excluded.last_event_id,"
                "last_source_sequence=excluded.last_source_sequence,"
                "last_content_sha256=excluded.last_content_sha256 "
                "WHERE excluded.last_source_sequence > containers.last_source_sequence",
                (
                    envelope.host_id,
                    falco.docker_container_id,
                    falco.docker_started_at,
                    falco.image_id,
                    canonical_json(falco.repo_digests).decode("utf-8"),
                    falco.immutable_spec_sha256,
                    _optional_uint64_v2(falco.inventory_revision),
                    envelope.event_id,
                    sequence,
                    ref.content_sha256,
                    envelope.event_id,
                    sequence,
                    ref.content_sha256,
                ),
            )
        connection.execute(
            "INSERT INTO process_observations VALUES(?,?,?,?,?,?,?,?,?)",
            (
                envelope.event_id,
                envelope.host_id,
                falco.docker_container_id,
                falco.docker_started_at,
                falco.proc_name,
                falco.proc_exe_path,
                falco.proc_parent_name,
                sequence,
                ref.content_sha256,
            ),
        )
        connection.execute(
            "INSERT INTO network_observations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                envelope.event_id,
                envelope.host_id,
                falco.docker_container_id,
                falco.docker_started_at,
                int(falco.successful_connect),
                falco.destination_ipv4,
                falco.destination_port,
                falco.l4_protocol,
                int(falco.investigation_only),
                sequence,
                ref.content_sha256,
            ),
        )
        if (
            not falco.successful_connect
            or falco.missing_required_fields
            or falco.investigation_only
        ):
            verifier = self._evidence._bound_verifier
            if verifier is None:
                raise ProjectionAuthorityError(
                    "Projection V2 direct incident lacks verifier authority"
                )
            try:
                authenticated = self._evidence._authenticated_falco_input(
                    verifier,
                    ref,
                )
                incident = incident_from_verified_falco(authenticated)
                revalidated = self._evidence.resolve_authenticated_ref(ref)
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 direct incident lost Falco authority"
                ) from error
            if not _same_stored_record_v2(revalidated, prepared.record):
                raise ProjectionAuthorityError("Projection V2 direct Falco evidence changed")
            _insert_v2_incident(connection, incident, "investigation")

    def _reduce_pcc(
        self,
        connection: sqlite3.Connection,
        authority: CorrelationProjectionAuthority,
        predecessor: _ProjectionPredecessor,
        prepared: _PreparedV2Record,
        acceptance_cursor: int,
    ) -> Callable[[], None]:
        if self._healthy_acceptance_cursor() != acceptance_cursor:
            raise ProjectionAuthorityError("Projection V2 acceptance changed before PCC history")
        ref = prepared.record.ref
        completed = self._journal.completed_for_snapshot(ref)
        initial = _revalidate_completed_snapshot(completed)
        if (
            type(initial) is not AuthenticatedPCCInput
            or not self._evidence._authenticated_pcc_input_is_exact(initial)
            or type(initial.evidence_ref) is not EvidenceRef
            or initial.evidence_ref != ref
            or initial.event_id != ref.event_id
            or initial.source_sequence != ref.source_sequence
            or initial.content_sha256 != ref.content_sha256
        ):
            raise CorrelationProjectionError("completed PCC is not exact same-store authority")
        active: ActiveCandidateObservation | None = None
        if initial.snapshot.outcome == "failed":
            result = correlate_pcc(initial, CorrelationContext.failed_snapshot())
        else:
            path = _issue_historical_path_authority(
                self._evidence,
                initial,
            )
            coverage_before = derive_historical_coverage(
                initial,
                path,
            )
            if (
                derive_historical_coverage(
                    initial,
                    path,
                )
                != coverage_before
            ):
                raise CorrelationProjectionError(
                    "historical coverage changed before duplicate lookup"
                )
            revalidated = _revalidate_completed_snapshot(completed)
            if not _same_exact_pcc(initial, revalidated):
                raise CorrelationProjectionError("completed PCC changed before duplicate lookup")
            key = _duplicate_key(initial, initial.snapshot)
            if self._healthy_acceptance_cursor() != acceptance_cursor:
                raise ProjectionAuthorityError(
                    "Projection V2 acceptance changed before duplicate lookup"
                )
            _validate_correlation_projection_predecessor(
                authority,
                predecessor,
            )
            trigger = initial.snapshot.trigger
            active = _active_duplicate_v2(
                connection,
                key,
                current_trigger_order=(
                    trigger.source_sequence,
                    trigger.event_id,
                ),
            )
            proof, context = _issue_correlation_context(
                authority,
                completed,
                expected_predecessor=predecessor,
                active_duplicate=active,
            )
            if not _same_exact_pcc(initial, proof):
                raise CorrelationProjectionError("issued PCC changed after duplicate lookup")
            result = correlate_pcc(proof, context)
            if self._healthy_acceptance_cursor() != acceptance_cursor:
                raise ProjectionAuthorityError(
                    "Projection V2 acceptance changed during correlation"
                )
        final = _revalidate_completed_snapshot(completed)
        if not _same_exact_pcc(initial, final):
            raise CorrelationProjectionError("completed PCC changed during correlation")

        def final_authority_check() -> None:
            try:
                persisted = _revalidate_completed_snapshot(completed)
                if not _same_exact_pcc(initial, persisted):
                    raise CorrelationProjectionError(
                        "completed PCC changed after result persistence"
                    )
                if self._healthy_acceptance_cursor() != acceptance_cursor:
                    raise CorrelationProjectionError(
                        "evidence acceptance changed after result persistence"
                    )
                if initial.snapshot.outcome == "complete":
                    fresh_proof, _fresh_context = _issue_correlation_context(
                        authority,
                        completed,
                        expected_predecessor=predecessor,
                        active_duplicate=active,
                    )
                    if not _same_exact_pcc(initial, fresh_proof):
                        raise CorrelationProjectionError(
                            "PCC authority changed during final live validation"
                        )
            except ProjectionAuthorityError:
                raise
            except Exception as error:
                raise ProjectionAuthorityError(
                    "Projection V2 PCC authority changed after persistence"
                ) from error

        if isinstance(result, CandidateCreated):
            self._persist_candidate_created(connection, result, initial)
            return final_authority_check
        if isinstance(result, Duplicate):
            if active is None or result.existing_candidate_id != active.candidate_id:
                raise ProjectionConflict(
                    "Projection V2 duplicate result changed its active primary"
                )
            self._persist_duplicate(connection, result, initial)
            return final_authority_check
        if isinstance(result, InvestigationOnly):
            _insert_v2_incident(connection, result.incident, "investigation")
            self._step_hook(_CANDIDATE_STEPS_V2[0])
            return final_authority_check
        if isinstance(result, Rejected):
            _insert_v2_incident(connection, result.incident, "rejected")
            self._step_hook(_CANDIDATE_STEPS_V2[0])
            return final_authority_check
        raise CorrelationProjectionError("correlation returned an unknown result type")

    def _persist_candidate_created(
        self,
        connection: sqlite3.Connection,
        result: CandidateCreated,
        proof: AuthenticatedPCCInput,
    ) -> None:
        candidate = result.candidate
        _insert_v2_incident(connection, result.incident, "candidate")
        self._step_hook(_CANDIDATE_STEPS_V2[0])
        _insert_v2_candidate(connection, candidate)
        self._step_hook(_CANDIDATE_STEPS_V2[1])
        self._insert_candidate_evidence(
            connection,
            candidate.candidate_id,
            proof,
            trigger_role="primary_trigger",
            snapshot_role="correlation_snapshot",
        )

    def _persist_duplicate(
        self,
        connection: sqlite3.Connection,
        result: Duplicate,
        proof: AuthenticatedPCCInput,
    ) -> None:
        _insert_v2_incident(connection, result.incident, "duplicate")
        self._step_hook(_CANDIDATE_STEPS_V2[0])
        self._insert_candidate_evidence(
            connection,
            result.existing_candidate_id,
            proof,
            trigger_role="supporting_trigger",
            snapshot_role="supporting_snapshot",
        )

    def _insert_candidate_evidence(
        self,
        connection: sqlite3.Connection,
        candidate_id: str,
        proof: AuthenticatedPCCInput,
        *,
        trigger_role: str,
        snapshot_role: str,
    ) -> None:
        trigger = proof.snapshot.trigger
        connection.execute(
            "INSERT INTO candidate_evidence VALUES(?,?,?,?,?,?)",
            _encode_candidate_evidence(
                candidate_id,
                trigger.event_id,
                trigger.source_sequence,
                trigger.content_sha256,
                trigger_role,
                proof.event_id,
            ),
        )
        self._step_hook(_CANDIDATE_STEPS_V2[2])
        connection.execute(
            "INSERT INTO candidate_evidence VALUES(?,?,?,?,?,?)",
            _encode_candidate_evidence(
                candidate_id,
                proof.event_id,
                proof.source_sequence,
                proof.content_sha256,
                snapshot_role,
                proof.event_id,
            ),
        )
        self._step_hook(_CANDIDATE_STEPS_V2[3])

    def _candidate_admission_snapshot(
        self,
        candidate_id: str,
    ) -> _CandidateAdmissionProjectionSnapshot | None:
        """Reauthenticate one candidate against one coherent persisted prefix."""
        with self._mutex:
            connection, authority = self._require_usable()
            if type(candidate_id) is not str or _CANDIDATE_ID_V2.fullmatch(candidate_id) is None:
                raise ProjectionAuthorityError("Projection V2 candidate admission ID is invalid")
            if connection.in_transaction:
                error = ProjectionConflict(
                    "Projection V2 candidate admission found an active transaction"
                )
                self._latch_unhealthy(error)
                raise error

            evidence_lifecycle = self._evidence._lifecycle_identity
            ack_lifecycle = self._acknowledgements._lifecycle_identity
            journal_lifecycle = self._journal._lifecycle_identity
            journal_revision = self._journal._mutation_revision
            verifier = self._evidence._bound_verifier
            verifier_authority = None if verifier is None else getattr(verifier, "_authority", None)
            verifier_generation = (
                None
                if verifier_authority is None
                else getattr(verifier_authority, "generation", None)
            )
            generation = self._generation
            acceptance_cursor = self._healthy_acceptance_cursor()
            ack_boundary = self._freeze_ack_boundary(acceptance_cursor)
            if (
                evidence_lifecycle is not self._evidence_lifecycle
                or ack_lifecycle is not self._ack_lifecycle
                or journal_lifecycle is not self._evidence_lifecycle
                or verifier is None
                or type(verifier_generation) is not int
                or verifier_generation < 0
                or not self._journal._is_bound_to(self._evidence)
            ):
                lifecycle_error = ProjectionAuthorityError(
                    "Projection V2 candidate admission lifecycle is unavailable"
                )
                self._latch_unhealthy(lifecycle_error)
                raise lifecycle_error

            transaction_started = False
            commit_attempted = False
            try:
                connection.execute("BEGIN")
                transaction_started = True
                _verify_v2_schema(connection)
                cursor = _current_v2_cursor(connection)
                cursor_ref = _current_v2_cursor_ref(connection)
                self._validate_cursor_evidence(connection, cursor)
                predecessor = _predecessor_v2(generation, cursor)
                _validate_correlation_projection_predecessor(
                    authority,
                    predecessor,
                )
                prefix_sha256 = self._validate_persisted_prefix(
                    connection,
                    authority,
                    predecessor,
                    cursor,
                )

                candidate_snapshot = None
                rows = connection.execute(
                    f"SELECT {','.join(_CANDIDATE_COLUMNS)} FROM candidates "
                    "WHERE candidate_id=? LIMIT 2",
                    (candidate_id,),
                ).fetchall()
                if len(rows) > 1:
                    raise ProjectionConflict(
                        "Projection V2 candidate admission identity is ambiguous"
                    )
                if rows:
                    candidate = _decode_candidate(rows[0])
                    stored_hash = rows[0]["candidate_facts_sha256"]
                    if (
                        cursor is None
                        or cursor_ref is None
                        or type(stored_hash) is not str
                        or candidate.candidate_id != candidate_id
                        or candidate_facts_sha256(candidate) != stored_hash
                    ):
                        raise ProjectionConflict("Projection V2 candidate admission facts changed")
                    evidence_rows = connection.execute(
                        "SELECT candidate_id,evidence_event_id,"
                        "evidence_source_sequence,evidence_content_sha256,role,"
                        "authority_snapshot_event_id FROM candidate_evidence "
                        "WHERE candidate_id=? ORDER BY evidence_event_id "
                        "COLLATE BINARY,role COLLATE BINARY",
                        (candidate_id,),
                    ).fetchall()
                    decoded_evidence = tuple(
                        _decode_candidate_evidence(row) for row in evidence_rows
                    )
                    if (
                        any(row[0] != candidate_id for row in decoded_evidence)
                        or not any(
                            row[1] == candidate.primary_event_id
                            and row[4] == "primary_trigger"
                            and row[5] == candidate.correlation_snapshot_event_id
                            for row in decoded_evidence
                        )
                        or not any(
                            row[1] == candidate.correlation_snapshot_event_id
                            and row[4] == "correlation_snapshot"
                            and row[5] == candidate.correlation_snapshot_event_id
                            for row in decoded_evidence
                        )
                    ):
                        raise ProjectionConflict("Projection V2 candidate admission proof changed")
                    invalidation_rows = connection.execute(
                        "SELECT candidate_id,coverage_event_id,"
                        "coverage_source_sequence,coverage_content_sha256,"
                        "reason_code FROM candidate_invalidations "
                        "WHERE candidate_id=? ORDER BY coverage_event_id "
                        "COLLATE BINARY",
                        (candidate_id,),
                    ).fetchall()
                    invalidations = tuple(
                        _decode_candidate_invalidation(row) for row in invalidation_rows
                    )
                    if any(row[0] != candidate_id for row in invalidations):
                        raise ProjectionConflict(
                            "Projection V2 candidate admission invalidation changed"
                        )
                    candidate_snapshot = _CandidateAdmissionProjectionSnapshot(
                        candidate=candidate,
                        candidate_facts_sha256=stored_hash,
                        authority_snapshot_event_id=(candidate.correlation_snapshot_event_id),
                        invalidation_event_ids=tuple(row[1] for row in invalidations),
                        cursor=cursor,
                        terminal_ref=cursor_ref,
                    )

                _verify_v2_schema(connection)
                if (
                    _current_v2_cursor(connection) != cursor
                    or _current_v2_cursor_ref(connection) != cursor_ref
                    or _v2_snapshot_hash(connection) != prefix_sha256
                ):
                    raise ProjectionConflict("Projection V2 candidate admission prefix changed")
                commit_attempted = True
                connection.execute("COMMIT")
                transaction_started = False

                if (
                    self._generation != generation
                    or self._evidence._lifecycle_identity is not evidence_lifecycle
                    or self._acknowledgements._lifecycle_identity is not ack_lifecycle
                    or self._journal._lifecycle_identity is not journal_lifecycle
                    or self._journal._mutation_revision is not journal_revision
                    or self._evidence._bound_verifier is not verifier
                    or verifier._authority is not verifier_authority
                    or verifier._authority.generation != verifier_generation
                    or self._healthy_acceptance_cursor() != acceptance_cursor
                    or self._freeze_ack_boundary(acceptance_cursor) != ack_boundary
                    or not self._journal._is_bound_to(self._evidence)
                    or _current_v2_cursor(connection) != cursor
                    or _current_v2_cursor_ref(connection) != cursor_ref
                    or _v2_snapshot_hash(connection) != prefix_sha256
                ):
                    raise ProjectionAuthorityError(
                        "Projection V2 candidate admission authority changed"
                    )
                _verify_v2_schema(connection)
                _validate_correlation_projection_predecessor(
                    authority,
                    predecessor,
                )
                return candidate_snapshot
            except BaseException as error:
                if transaction_started or connection.in_transaction:
                    self._settle_failed_transaction(
                        connection,
                        error,
                        transaction_started=transaction_started,
                        commit_attempted=commit_attempted,
                    )
                self._latch_unhealthy(error)
                if isinstance(error, ProjectionConflict):
                    raise
                if isinstance(error, sqlite3.DatabaseError):
                    raise ProjectionConflict(
                        "Projection V2 candidate admission database changed"
                    ) from error
                if isinstance(error, ProjectionAuthorityError):
                    raise
                raise ProjectionAuthorityError(
                    "Projection V2 candidate admission could not be reauthenticated"
                ) from error

    def status(self) -> ProjectionStatus:
        with self._mutex:
            with self._replay_state_lock:
                if self._replay_reservation is not None:
                    raise ProjectionAuthorityError("Projection V2 replay reservation is active")
            connection = self._connection
            cursor: ProjectionCursor | None = None
            if connection is not None:
                try:
                    cursor = _current_v2_cursor(connection)
                except (ProjectionConflict, sqlite3.DatabaseError):
                    self._latch_unhealthy()
            return ProjectionStatus(healthy=self._healthy and not self._closed, cursor=cursor)

    def _candidate_ids(
        self,
        *,
        after: str | None,
        limit: int,
    ) -> tuple[str, ...]:
        """Return one validated, keyset-ordered candidate page."""
        with self._mutex:
            connection, _authority = self._require_usable()
            if (
                (
                    after is not None
                    and (type(after) is not str or _CANDIDATE_ID_V2.fullmatch(after) is None)
                )
                or type(limit) is not int
                or not 1 <= limit <= 100
            ):
                raise ProjectionAuthorityError("Projection V2 candidate page arguments are invalid")
            columns = ",".join(_CANDIDATE_COLUMNS)
            if after is None:
                rows = connection.execute(
                    f"SELECT {columns} FROM candidates "
                    "ORDER BY candidate_id COLLATE BINARY LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    f"SELECT {columns} FROM candidates "
                    "WHERE candidate_id COLLATE BINARY>? "
                    "ORDER BY candidate_id COLLATE BINARY LIMIT ?",
                    (after, limit),
                ).fetchall()
            candidates = tuple(_decode_candidate(row) for row in rows)
            identifiers = tuple(candidate.candidate_id for candidate in candidates)
            if identifiers != tuple(sorted(set(identifiers))):
                error = ProjectionConflict("Projection V2 candidate page is not canonical")
                self._latch_unhealthy(error)
                raise error
            return identifiers

    def _hunter_bundle(self, candidate_id: str) -> object:
        """Build one redacted observation bundle from validated projection rows."""
        from agmind_immune.hunter import (
            HunterBundleV1,
            HunterEvidenceFactV1,
            build_hunter_bundle,
        )

        with self._mutex:
            connection, _authority = self._require_usable()
            if type(candidate_id) is not str or _CANDIDATE_ID_V2.fullmatch(candidate_id) is None:
                raise ProjectionAuthorityError("Projection V2 hunter candidate ID is invalid")
            candidate_rows = connection.execute(
                f"SELECT {','.join(_CANDIDATE_COLUMNS)} FROM candidates "
                "WHERE candidate_id=? LIMIT 2",
                (candidate_id,),
            ).fetchall()
            if len(candidate_rows) != 1:
                raise ProjectionAuthorityError("Projection V2 hunter candidate is unavailable")
            candidate = _decode_candidate(candidate_rows[0])
            incident_rows = connection.execute(
                f"SELECT {','.join(_INCIDENT_COLUMNS)} FROM incidents WHERE incident_id=? LIMIT 2",
                (candidate.incident_id,),
            ).fetchall()
            if len(incident_rows) != 1:
                raise ProjectionConflict("Projection V2 hunter incident binding is unavailable")
            incident, result_kind = _decode_incident(incident_rows[0])
            if (
                result_kind != "candidate"
                or incident.incident_id != candidate.incident_id
                or incident.primary_event_id != candidate.primary_event_id
            ):
                raise ProjectionConflict("Projection V2 hunter incident binding changed")

            def basename(value: str | None) -> str | None:
                if value is None:
                    return None
                selected = value.rsplit("/", 1)[-1]
                return None if selected in {"", ".", ".."} else selected

            fact = HunterEvidenceFactV1(
                evidence_id=incident.primary_event_id,
                detector_rule=incident.detector_rule,
                detector_rule_version=incident.detector_rule_version,
                event_time=incident.event_time,
                proc_name=incident.proc_name,
                proc_exe_basename=basename(incident.proc_exe_path),
                proc_parent_basename=basename(incident.proc_parent_name),
                destination_ipv4=incident.destination_ipv4,
                destination_port=incident.destination_port,
                l4_protocol=incident.l4_protocol,
                image_id=candidate.image_id,
                coverage_flags=incident.coverage_flags[:32],
            )
            primary_bundle = build_hunter_bundle(incident, (fact,))
            omitted = tuple(
                identifier for identifier in incident.evidence_ids if identifier != fact.evidence_id
            )
            if not omitted:
                return primary_bundle
            return HunterBundleV1(
                schema_version="agmind.hunter-bundle.v1",
                evidence=primary_bundle.evidence,
                omitted_evidence_ids=omitted,
                limitations=("Correlation proof retained for deterministic validation only",),
            )

    def snapshot_hash(self) -> str:
        with self._mutex:
            connection, _authority = self._require_usable()
            return _v2_snapshot_hash(connection)

    def _close_resources(self) -> list[BaseException]:
        errors: list[BaseException] = []
        authority = self._authority
        if authority is not None:
            try:
                _close_correlation_projection_authority(authority)
            except BaseException as error:  # noqa: BLE001 - close all owned resources
                errors.append(error)
            else:
                self._authority = None
        connection = self._connection
        if connection is not None:
            try:
                connection.close()
            except BaseException as error:  # noqa: BLE001 - close all owned resources
                errors.append(error)
            else:
                self._connection = None
        if self._owns_authorities:
            if not getattr(self._journal, "_closed", True):
                try:
                    self._journal.close()
                except BaseException as error:  # noqa: BLE001 - close all owned resources
                    errors.append(error)
            if not getattr(self._acknowledgements, "_closed", True):
                try:
                    self._acknowledgements.close()
                except BaseException as error:  # noqa: BLE001 - close all owned resources
                    errors.append(error)
            if not getattr(self._evidence, "_closed", True):
                try:
                    self._evidence.close()
                except BaseException as error:  # noqa: BLE001 - close all owned resources
                    errors.append(error)
        return errors

    def _resources_released(self) -> bool:
        return (
            self._authority is None
            and self._connection is None
            and (
                not self._owns_authorities
                or (
                    getattr(self._journal, "_closed", False) is True
                    and getattr(self._acknowledgements, "_closed", False) is True
                    and getattr(self._evidence, "_closed", False) is True
                )
            )
        )

    def _close_after_factory_failure(self, primary: BaseException) -> None:
        errors = self._close_resources()
        for error in errors:
            primary.add_note(
                "Projection V2 factory cleanup failure (attempt 1): "
                f"{type(error).__name__}: {error}"
            )
        if not errors:
            return
        retry_errors = self._close_resources()
        for error in retry_errors:
            primary.add_note(
                "Projection V2 factory cleanup failure (attempt 2): "
                f"{type(error).__name__}: {error}"
            )

    def close(self) -> None:
        with self._mutex:
            with self._replay_state_lock:
                if self._replay_reservation is not None:
                    raise ProjectionAuthorityError("Projection V2 replay reservation is active")
            if self._closed and self._resources_released():
                return
            self._closed = True
            errors = self._close_resources()
            if errors:
                self._healthy = False
                primary = errors[0]
                for error in errors[1:]:
                    primary.add_note(
                        f"secondary Projection V2 close failure: {type(error).__name__}: {error}"
                    )
                raise ProjectionUnhealthy(
                    "Projection V2 owner close could not be proven"
                ) from primary


def _v2_projection_owner_for_test(
    connection: sqlite3.Connection,
    *,
    evidence: SegmentStore,
    acknowledgements: AckJournal,
    journal: CorrelationRequestJournal,
    registry: SpecialUseRegistry,
    step_hook: Callable[[str], None] | None = None,
) -> _V2ProjectionOwner:
    """Transfer exact test resources into one dormant V2 projection owner."""
    return _V2ProjectionOwner._take_ownership(
        connection,
        evidence=evidence,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=registry,
        step_hook=step_hook,
    )


def _v2_unpublished_projection_from_prefix_for_test(
    *,
    evidence: SegmentStore,
    acknowledgements: AckJournal,
    journal: CorrelationRequestJournal,
    registry: SpecialUseRegistry,
    through: EvidenceRef | None,
    retention_completion: AuthenticatedRetentionUnlinkCompletion | None = None,
    step_hook: Callable[[str], None] | None = None,
) -> tuple[_V2ProjectionOwner, sqlite3.Connection, _UnpublishedV2ReplayReport]:
    """Build one fresh dormant V2 projection from an exact ACKed source prefix."""
    if (
        type(evidence) is not SegmentStore
        or type(acknowledgements) is not AckJournal
        or type(journal) is not CorrelationRequestJournal
        or type(registry) is not SpecialUseRegistry
        or (through is not None and type(through) is not EvidenceRef)
        or (
            retention_completion is not None
            and type(retention_completion) is not AuthenticatedRetentionUnlinkCompletion
        )
    ):
        raise ProjectionAuthorityError("unpublished Projection V2 replay requires exact resources")
    connection = _v2_connection_for_test()
    owner = _V2ProjectionOwner._take_ownership(
        connection,
        evidence=evidence,
        acknowledgements=acknowledgements,
        journal=journal,
        registry=registry,
        step_hook=step_hook,
    )
    try:
        report = owner._replay_unpublished_prefix(
            through,
            _factory=_UNPUBLISHED_REPLAY_FACTORY,
            retention_completion=retention_completion,
        )
        published_connection = owner._connection
        if not isinstance(published_connection, sqlite3.Connection):
            raise ProjectionAuthorityError(
                "unpublished Projection V2 replay lost its published database"
            )
        return owner, published_connection, report
    except BaseException as error:
        owner._close_after_factory_failure(error)
        raise


__all__: list[str] = []
