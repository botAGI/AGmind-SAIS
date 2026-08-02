"""Authoritative single-host AGF1 evidence segments and immutable manifest chain."""

from __future__ import annotations

import copy
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import time
import uuid
import weakref
from bisect import bisect_right
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from enum import StrEnum
from itertools import pairwise
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Literal,
    Never,
    SupportsIndex,
    cast,
    final,
)

from pydantic import Field, ValidationError, field_validator, model_validator

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.clock import CoreClockSample
from agmind_immune.contracts import (
    MAX_UINT64,
    ContractModel,
    EventEnvelopeV1,
    PCCCorrelationSnapshotRequestV1,
    PCCCorrelationSnapshotV1,
    RetentionBlockedV1,
    RetentionTombstoneV2,
    decode_strict,
)
from agmind_immune.evidence.frames import (
    FrameRecord,
    JournalCorrupt,
    TornTail,
    encode_frame,
    iter_frames,
)
from agmind_immune.evidence.manifest import (
    GENESIS_MANIFEST_SHA256,
    SegmentChainHeadV1,
    SegmentManifestV1,
    chain_head_for,
    segment_manifest_hash,
)
from agmind_immune.evidence.repair import (
    _FINAL_REPAIR_COMPLETION_FACTORY,
    AuthenticatedRepairCompletion,
    RepairStateConflict,
    RepairStateCorrupt,
    RepairStateJournal,
    RepairStateV1,
    decode_repair_state,
)
from agmind_immune.ingest.envelope import (
    AuthenticatedFalcoInput,
    AuthenticatedPCCInput,
    EnvelopeVerifier,
    IngestVerificationError,
    PCCCorrelationVerificationContext,
    SimulatedRepairAuthorization,
    VerifiedEnvelope,
    VerifierCommitError,
    _AppendAuthorization,
)

if TYPE_CHECKING:
    from agmind_immune.coverage.historical import HistoricalPathAuthority
    from agmind_immune.evidence.retention import (
        AcceptedRetentionBlocked,
        AcceptedRetentionTombstone,
        AuthenticatedRetentionTombstone,
        AuthenticatedRetentionUnlinkCompletion,
        FrozenRetentionFact,
        FrozenRetentionRecord,
        RetentionSnapshot,
        RetentionStateJournal,
    )
    from agmind_immune.ingest.ack_journal import (
        AckJournal,
        _AckRetentionBoundaryLease,
    )

MAX_EVIDENCE_RECORD_BYTES = 128 * 1024
MAX_SEGMENT_BYTES = 64 * 1024 * 1024
MAX_SEGMENT_AGE_SECONDS = 600.0
MAX_CONTRACT_FILE_BYTES = 256 * 1024
_EVENT = re.compile(r"^evt_[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OPEN_NAME = re.compile(
    r"^(?P<sequence>[0-9]{20})-(?P<segment>[0-9a-f]{8}-[0-9a-f]{4}-"
    r"4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.open$"
)
_DATE_NAME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_CREATE_TEMP_NAME = re.compile(
    r"^\.agmind-create-(?P<sequence>[0-9]{20})-"
    r"(?P<segment>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.tmp$"
)
_UUID4_TEXT = (
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_EVIDENCE_REF_SEGMENT_ID = re.compile(rf"^{_UUID4_TEXT}$")
_EVIDENCE_REF_SEGMENT_PATH = re.compile(
    rf"^segments/(?P<date>[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})/"
    rf"(?P<first_sequence>[0-9]{{20}})-(?P<segment>{_UUID4_TEXT})\.agseg$"
)
_MANIFEST_NAME = re.compile(rf"^(?P<segment>{_UUID4_TEXT})\.json$")
_MANIFEST_TEMP_NAME = re.compile(
    rf"^\.(?P<segment>{_UUID4_TEXT})\.json\.{_UUID4_TEXT}\.tmp$"
)
_ROOT_TEMP_NAME = re.compile(rf"^\.chain-head\.json\.{_UUID4_TEXT}\.tmp$")
_HEALTH_FINAL_TEMP_NAME = re.compile(
    rf"^\.health\.json\.{_UUID4_TEXT}\.tmp$"
)
_CORRELATION_JOURNAL_NAME = "correlation-requests.agf"
_ACK_COMMITMENT_NAME = "ack-commitment.json"
_ACK_COMMITMENT_TEMP_NAME = re.compile(
    rf"^\.ack-commitment\.json\.{_UUID4_TEXT}\.tmp$"
)
_MAX_ACK_COMMITMENT_BYTES = 4096
_REPAIR_STATE_NAME = "repair-state.json"
_REPAIR_STATE_TEMP_NAME = re.compile(
    rf"^\.repair-state\.json\.{_UUID4_TEXT}\.tmp$"
)
_MAX_REPAIR_STATE_BYTES = 4096
_RETENTION_STATE_NAME = "retention-state.json"
_RETENTION_STATE_TEMP_NAME = re.compile(
    rf"^\.retention-state\.json\.{_UUID4_TEXT}\.tmp$"
)
_MAX_RETENTION_STATE_BYTES = 128 * 1024
_RETENTION_BOUNDARY_NAME = "retention-boundary.json"
_RETENTION_BOUNDARY_TEMP_NAME = re.compile(
    rf"^\.retention-boundary\.json\.{_UUID4_TEXT}\.tmp$"
)
_RETENTION_STATE_AUTHORITY_FACTORY = object()
_RETENTION_PROOF_FACTORY = object()
_RETENTION_BLOCKED_CLEAR_FACTORY = object()
_RETENTION_ACK_RECOVERY_FACTORY = object()
_RETENTION_ACK_GATE_FACTORY = object()
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_ZERO_SHA256 = "0" * 64
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
_ATOMIC_RENAME_UNAVAILABLE = frozenset(
    {
        errno.EINVAL,
        errno.ENOSYS,
        errno.ENOTSUP,
        errno.EOPNOTSUPP,
    }
)


class EvidenceStoreError(RuntimeError):
    """Base class for evidence-store failures."""


class EvidenceSealError(EvidenceStoreError):
    """An unsealed caller-created value reached the evidence boundary."""


class EvidenceStoreBusy(EvidenceStoreError):
    """Another process already owns this evidence root."""


class EvidenceConflict(EvidenceStoreError):
    """One host-global sequence maps to different canonical evidence."""


class EvidenceCorrupt(EvidenceStoreError):
    """Evidence bytes, facts, or immutable chain structure are corrupt."""


class EvidenceReadOnly(EvidenceStoreError):
    """A persistent health marker prevents evidence mutation."""


class _AckAuthorityError(EvidenceStoreError):
    """An ACK identity is not the next authenticated contiguous evidence ref."""


class _AckLifecycleStateError(EvidenceStoreError):
    """The requested ACK-journal operation is illegal in this store lifecycle."""


class _AckLifecycleCorrupt(EvidenceStoreError):
    """An expected ACK-journal artifact disappeared or was substituted."""


class _AckLifecycleIoUncertain(EvidenceStoreError):
    """ACK authority I/O may have completed but could not be authenticated."""


class _CorrelationJournalLifecycleStateError(EvidenceStoreError):
    """The requested correlation-journal operation is illegal in this lifecycle."""


class _CorrelationJournalLifecycleCorrupt(EvidenceStoreError):
    """An expected correlation-journal artifact disappeared or was substituted."""


class _CorrelationJournalLifecycleIoUncertain(EvidenceStoreError):
    """Correlation-journal I/O could not be authenticated conclusively."""


class TornTailRepairRequired(EvidenceStoreError):
    """An active segment ends in an incomplete frame and requires signed repair."""

    def __init__(self, path: Path, verified_bytes: int, actual_bytes: int) -> None:
        super().__init__(f"torn active tail requires signed repair: {path}")
        self.path = path
        self.verified_bytes = verified_bytes
        self.actual_bytes = actual_bytes


class TailRepairPending(EvidenceStoreError):
    """A durable/in-flight repair gate requires the repair-aware factory."""


class RepairPhysicalState(StrEnum):
    """Exact held-namespace classification for one signed tail repair."""

    ORIGINAL_TORN = "original_torn"
    CLEAN_OPEN = "clean_open"
    SETTLED_PREFIX = "settled_prefix"
    ZERO_HELD = "zero_held"
    ZERO_RETIRED = "zero_retired"
    INVALID = "invalid"


@dataclass(frozen=True)
class TailRepairFacts:
    """Immutable physical facts derived from one retained active-segment inode."""

    segment_id: str
    open_relative_path: str
    original_device: int
    original_inode: int
    original_bytes: int
    verified_bytes: int
    discarded_bytes: int
    discarded_sha256: str
    post_repair_prefix_sha256: str
    last_verified_frame_sha256: str
    current_chain_head_sha256: str
    manifest_predecessor_sha256: str


_AUTHENTICATED_REPAIR_FACTORY = object()


@final
class AuthenticatedRepairAuthorization:
    """Nonserializable, one-use destructive authority retained by one session."""

    __slots__ = ("_factory_marker",)
    _factory_marker: object

    def __init__(self, *, _factory: object) -> None:
        if _factory is not _AUTHENTICATED_REPAIR_FACTORY:
            raise TypeError(
                "AuthenticatedRepairAuthorization is issued only by a tail session"
            )
        object.__setattr__(self, "_factory_marker", _factory)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("repair authorization capabilities are immutable")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("AuthenticatedRepairAuthorization is final")

    def __copy__(self) -> AuthenticatedRepairAuthorization:
        raise TypeError("repair authorization capabilities cannot be copied")

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> AuthenticatedRepairAuthorization:
        del memo
        raise TypeError("repair authorization capabilities cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("repair authorization capabilities cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("repair authorization capabilities cannot be serialized")


@contextmanager
def _post_authentication_namespace(display_path: Path) -> Iterator[None]:
    try:
        yield
    except EvidenceCorrupt:
        raise
    except EvidenceStoreError:
        raise
    except OSError as error:
        raise EvidenceCorrupt(
            f"authenticated evidence namespace became uncertain: {display_path}"
        ) from error


class EvidencePriority(StrEnum):
    ROUTINE = "routine"
    PROTECTED = "protected"


@dataclass(frozen=True)
class EvidenceRef:
    segment_id: str
    segment_relative_path: str
    frame_offset: int
    frame_size: int
    frame_sha256: str
    event_id: str
    source_sequence: int
    content_sha256: str


@dataclass(frozen=True)
class EvidenceStatus:
    healthy: bool
    host_id: str | None
    evidence_head: int
    acceptance_cursor: int
    key_healthy: bool
    repair_pending: bool = False
    retention_pending: bool = False


@dataclass(frozen=True)
class _StoreIssuedPCCBinding:
    lifecycle: object
    verifier: EnvelopeVerifier
    verifier_authority: object
    verifier_generation: int
    evidence_ref: tuple[str, str, int, int, str, str, int, str]
    canonical: bytes
    request_canonical: bytes
    request_fields_set: frozenset[str]
    snapshot_canonical: bytes
    snapshot_fields_set: frozenset[str]


def _exact_coverage_ref_key(
    value: object,
) -> tuple[str, str, int, int, str, str, int, str]:
    if type(value) is not EvidenceRef:
        raise ValueError("coverage evidence ref must use the exact runtime type")
    if (
        type(value.segment_id) is not str
        or _EVIDENCE_REF_SEGMENT_ID.fullmatch(value.segment_id) is None
    ):
        raise ValueError("coverage evidence ref segment_id is invalid")
    if type(value.segment_relative_path) is not str:
        raise ValueError("coverage evidence ref path is not an exact string")
    path_match = _EVIDENCE_REF_SEGMENT_PATH.fullmatch(value.segment_relative_path)
    if path_match is None or path_match.group("segment") != value.segment_id:
        raise ValueError("coverage evidence ref path is invalid")
    date_text = path_match.group("date")
    try:
        path_date = date.fromisoformat(date_text)
    except ValueError as error:
        raise ValueError("coverage evidence ref path date is invalid") from error
    if path_date.isoformat() != date_text:
        raise ValueError("coverage evidence ref path date is not canonical")
    if (
        type(value.frame_offset) is not int
        or type(value.frame_size) is not int
        or type(value.source_sequence) is not int
    ):
        raise ValueError("coverage evidence ref numeric fields are not exact integers")
    first_sequence = int(path_match.group("first_sequence"))
    if (
        not 1 <= first_sequence <= value.source_sequence <= MAX_UINT64
        or value.frame_offset < 0
        or not 76 < value.frame_size <= MAX_EVIDENCE_RECORD_BYTES + 76
        or value.frame_offset + value.frame_size > MAX_SEGMENT_BYTES
    ):
        raise ValueError("coverage evidence ref numeric bounds are invalid")
    if (
        type(value.frame_sha256) is not str
        or _HEX64.fullmatch(value.frame_sha256) is None
        or type(value.event_id) is not str
        or _EVENT.fullmatch(value.event_id) is None
        or type(value.content_sha256) is not str
        or _HEX64.fullmatch(value.content_sha256) is None
    ):
        raise ValueError("coverage evidence ref identity fields are invalid")
    return (
        value.segment_id,
        value.segment_relative_path,
        value.frame_offset,
        value.frame_size,
        value.frame_sha256,
        value.event_id,
        value.source_sequence,
        value.content_sha256,
    )


def _same_exact_coverage_ref(left: object, right: object) -> bool:
    return _exact_coverage_ref_key(left) == _exact_coverage_ref_key(right)


@dataclass(frozen=True)
class StoredEvidenceRecord:
    envelope: dict[str, Any]
    canonical_envelope: bytes
    priority: EvidencePriority
    accepted_at: str
    ref: EvidenceRef


def _exact_coverage_record_key(
    value: object,
) -> tuple[
    bytes,
    EvidencePriority,
    str,
    tuple[str, str, int, int, str, str, int, str],
]:
    if type(value) is not StoredEvidenceRecord:
        raise ValueError("coverage record must use the exact runtime type")
    if (
        type(value.envelope) is not dict
        or type(value.canonical_envelope) is not bytes
        or type(value.priority) is not EvidencePriority
        or type(value.accepted_at) is not str
    ):
        raise ValueError("coverage record fields do not use exact runtime types")
    try:
        encoded_envelope = canonical_json(value.envelope)
    except (TypeError, ValueError) as error:
        raise ValueError("coverage record envelope is not canonicalizable") from error
    if encoded_envelope != value.canonical_envelope:
        raise ValueError("coverage record envelope differs from its canonical bytes")
    return (
        value.canonical_envelope,
        value.priority,
        value.accepted_at,
        _exact_coverage_ref_key(value.ref),
    )


def _same_exact_coverage_record(left: object, right: object) -> bool:
    return _exact_coverage_record_key(left) == _exact_coverage_record_key(right)


class _AcceptedOuterV1(ContractModel):
    sequence: int = Field(ge=1, le=MAX_UINT64)
    event_id: str
    content_sha256: str

    @field_validator("event_id")
    @classmethod
    def event_is_exact(cls, value: str) -> str:
        if not _EVENT.fullmatch(value):
            raise ValueError("accepted outer event_id is invalid")
        return value

    @field_validator("content_sha256")
    @classmethod
    def digest_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("accepted outer digest is invalid")
        return value


class _AcceptedEnvelopeRecordV1(ContractModel):
    schema_version: Literal["agmind.accepted-envelope.v1"]
    evidence_priority: Literal["routine", "protected"]
    accepted_at: str
    outer: _AcceptedOuterV1
    envelope: dict[str, Any]

    @model_validator(mode="after")
    def outer_binds_envelope(self) -> _AcceptedEnvelopeRecordV1:
        canonical = canonical_json(self.envelope)
        if len(canonical) > 64 * 1024:
            raise ValueError("stored canonical envelope exceeds 64 KiB")
        try:
            envelope = EventEnvelopeV1.model_validate(self.envelope, strict=True)
        except ValidationError as error:
            raise ValueError("stored envelope contract is invalid") from error
        if (
            self.outer.sequence != envelope.source_sequence
            or self.outer.event_id != envelope.event_id
            or self.outer.content_sha256 != hashlib.sha256(canonical).hexdigest()
        ):
            raise ValueError("stored outer facts do not bind envelope")
        if not _UTC_TIMESTAMP.fullmatch(self.accepted_at):
            raise ValueError("accepted_at must be UTC")
        datetime.fromisoformat(self.accepted_at)
        return self


class _EvidenceHealthV1(ContractModel):
    schema_version: Literal["agmind.evidence-health.v1"]
    mode: Literal["read_only"]
    reason: Literal["segment_corrupt", "evidence_conflict"]


class _EvidenceHealthIntentV1(ContractModel):
    schema_version: Literal["agmind.evidence-health-intent.v1"]
    mode: Literal["read_only_pending"]
    reason: Literal["segment_corrupt", "evidence_conflict"]


class _AckCommitmentIdentityV1(ContractModel):
    sequence: int = Field(ge=1, le=MAX_UINT64)
    event_id: str
    content_sha256: str

    @field_validator("event_id")
    @classmethod
    def event_id_is_exact(cls, value: str) -> str:
        if not _EVENT.fullmatch(value):
            raise ValueError("ACK commitment event_id is invalid")
        return value

    @field_validator("content_sha256")
    @classmethod
    def content_hash_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("ACK commitment content hash is invalid")
        return value


class _AckCommitmentV1(ContractModel):
    schema_version: Literal["agmind.core-ack-commitment.v1"]
    phase: Literal["initializing", "ready"]
    generation: int = Field(ge=0, le=MAX_UINT64)
    confirmed: _AckCommitmentIdentityV1 | None
    journal_prefix_size: int = Field(ge=0, le=MAX_UINT64)
    journal_prefix_sha256: str

    @field_validator("journal_prefix_sha256")
    @classmethod
    def prefix_hash_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("ACK commitment prefix hash is invalid")
        return value

    @model_validator(mode="after")
    def state_is_coherent(self) -> _AckCommitmentV1:
        genesis = (
            self.generation == 0
            and self.confirmed is None
            and self.journal_prefix_size == 0
            and self.journal_prefix_sha256 == _EMPTY_SHA256
        )
        if self.phase == "initializing":
            if not genesis:
                raise ValueError("initializing ACK commitment must be exact genesis")
        elif not genesis and (
            self.generation == 0
            or self.confirmed is None
            or self.journal_prefix_size == 0
        ):
            raise ValueError("ready ACK commitment state is incoherent")
        return self


@dataclass(frozen=True)
class _AckCommitmentRecoveryView:
    commitment: _AckCommitmentV1 | None
    journal_present: bool
    temporary_name: str | None


@dataclass(frozen=True)
class _AckCommitmentTemporaryBinding:
    name: str
    commitment: _AckCommitmentV1
    raw: bytes
    identity: _FileIdentity


def _canonical_ack_commitment(commitment: _AckCommitmentV1) -> bytes:
    return canonical_json(commitment.model_dump(exclude_none=False))


def _decode_ack_commitment(raw: bytes) -> _AckCommitmentV1:
    if not raw or len(raw) > _MAX_ACK_COMMITMENT_BYTES:
        raise ValueError("ACK commitment exceeds its explicit byte limit")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate ACK commitment property: {key}")
            value[key] = item
        return value

    def reject_number(value: str) -> object:
        raise ValueError(f"invalid ACK commitment number: {value}")

    value = json.loads(
        raw.decode("utf-8", "strict"),
        object_pairs_hook=unique_object,
        parse_float=reject_number,
        parse_constant=reject_number,
    )
    if not isinstance(value, dict):
        raise TypeError("ACK commitment must be one JSON object")
    return _AckCommitmentV1.model_validate(value)


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    mode: int
    owner: int
    link_count: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class _RepairStateArtifactBinding:
    name: str
    raw: bytes
    identity: _FileIdentity


@dataclass(frozen=True)
class _RetentionStateArtifactBinding:
    name: str
    raw: bytes
    identity: _FileIdentity


@dataclass(frozen=True)
class _MissingManifestPayload:
    chain_index: int
    manifest: SegmentManifestV1
    manifest_canonical: bytes
    date_name: str
    closed_name: str


@dataclass(frozen=True)
class _AuthenticatedRetentionRecovery:
    state: object | None
    tombstones: tuple[
        tuple[StoredEvidenceRecord, RetentionTombstoneV2],
        ...,
    ]
    current_target_ref: EvidenceRef | None
    boundary_raw: bytes | None


@dataclass(frozen=True)
class _RetentionAcceptedEnvelopeBinding:
    sequence: int
    accepted: object
    canonical: bytes
    evidence_ref: EvidenceRef
    evidence_ref_key: tuple[str, str, int, int, str, str, int, str]
    evidence_priority: Literal["routine", "protected"]
    key_epoch: int
    key_id: str


@dataclass(frozen=True)
class _RetentionAcceptedAuthorityBinding:
    accepted: object
    entries: tuple[_RetentionAcceptedEnvelopeBinding, ...]


@dataclass(frozen=True)
class _RetentionSnapshotBinding:
    snapshot: object
    snapshot_binding: bytes
    lifecycle_identity: object
    verifier: EnvelopeVerifier
    verifier_authority: object
    verifier_generation: int
    transient_generation: int
    accepted_authority: _RetentionAcceptedAuthorityBinding
    status: EvidenceStatus
    manifest_canonical: tuple[bytes, ...]
    payload_identities: tuple[_FileIdentity, ...]


@dataclass(frozen=True)
class _AuthenticatedRetentionTombstoneBinding:
    capability: object
    journal: object
    journal_identity: object
    snapshot: object
    lifecycle_identity: object
    state_raw: bytes
    unlink_in_progress_state_raw: bytes
    commit_uncertain_state_raw: bytes
    completed_state_raw: bytes
    completion_capability: object
    target_ref: EvidenceRef
    coverage: object
    coverage_snapshot: object
    coverage_token: object
    verifier: EnvelopeVerifier
    verifier_authority: object
    verifier_generation: int
    transient_generation: int
    accepted_authority: _RetentionAcceptedAuthorityBinding
    status: EvidenceStatus


@dataclass
class _HeldRetentionPayload:
    state_entry: object
    manifest: SegmentManifestV1
    date_name: str
    basename: str
    display_path: Path
    descriptor: int
    identity: _FileIdentity


@dataclass
class _HeldRetentionDirectory:
    date_name: str
    display_path: Path
    descriptor: int
    identity: tuple[int, int, int, int]
    payloads: tuple[_HeldRetentionPayload, ...]


@dataclass(frozen=True)
class _RetentionUnlinkLease:
    binding: _AuthenticatedRetentionTombstoneBinding
    groups: tuple[_HeldRetentionDirectory, ...]


@dataclass(frozen=True)
class _AuthenticatedRetentionUnlinkCompletionBinding:
    capability: object
    tombstone: _AuthenticatedRetentionTombstoneBinding
    journal: object
    journal_identity: object
    lifecycle_identity: object
    completed_state_raw: bytes
    manifest_canonical: tuple[bytes, ...]
    verifier_authority: object
    verifier_generation: int
    transient_generation: int
    accepted_authority: _RetentionAcceptedAuthorityBinding
    status: EvidenceStatus


def _retention_accepted_authority_binding(
    verifier: EnvelopeVerifier,
) -> _RetentionAcceptedAuthorityBinding:
    accepted_authority = verifier._authority.accepted
    entries: list[_RetentionAcceptedEnvelopeBinding] = []
    try:
        for sequence, accepted in sorted(accepted_authority.items()):
            evidence_ref = accepted.evidence_ref
            if type(evidence_ref) is not EvidenceRef:
                raise ValueError(
                    "accepted verifier evidence ref is not exact"
                )
            exact_ref = evidence_ref
            evidence_ref_key = _exact_coverage_ref_key(evidence_ref)
            if (
                type(sequence) is not int
                or exact_ref.source_sequence != sequence
                or type(accepted.canonical) is not bytes
                or type(accepted.evidence_priority) is not str
                or accepted.evidence_priority not in {"routine", "protected"}
                or type(accepted.key_epoch) is not int
                or type(accepted.key_id) is not str
            ):
                raise ValueError(
                    "accepted verifier authority is not exact"
                )
            entries.append(
                _RetentionAcceptedEnvelopeBinding(
                    sequence=sequence,
                    accepted=accepted,
                    canonical=accepted.canonical,
                    evidence_ref=exact_ref,
                    evidence_ref_key=evidence_ref_key,
                    evidence_priority=accepted.evidence_priority,
                    key_epoch=accepted.key_epoch,
                    key_id=accepted.key_id,
                )
            )
    except (AttributeError, TypeError, ValueError) as error:
        raise EvidenceSealError(
            "retention verifier accepted authority is malformed"
        ) from error
    return _RetentionAcceptedAuthorityBinding(
        accepted=accepted_authority,
        entries=tuple(entries),
    )


def _same_retention_accepted_authority(
    verifier: EnvelopeVerifier,
    binding: _RetentionAcceptedAuthorityBinding,
) -> bool:
    accepted_authority = verifier._authority.accepted
    if (
        accepted_authority is not binding.accepted
        or len(accepted_authority) != len(binding.entries)
    ):
        return False
    for (sequence, accepted), expected in zip(
        sorted(accepted_authority.items()),
        binding.entries,
        strict=True,
    ):
        try:
            evidence_ref_key = _exact_coverage_ref_key(
                accepted.evidence_ref
            )
        except (AttributeError, TypeError, ValueError):
            return False
        if (
            type(sequence) is not int
            or sequence != expected.sequence
            or accepted is not expected.accepted
            or type(accepted.canonical) is not bytes
            or accepted.canonical != expected.canonical
            or accepted.evidence_ref is not expected.evidence_ref
            or evidence_ref_key != expected.evidence_ref_key
            or type(accepted.evidence_priority) is not str
            or accepted.evidence_priority != expected.evidence_priority
            or type(accepted.key_epoch) is not int
            or accepted.key_epoch != expected.key_epoch
            or type(accepted.key_id) is not str
            or accepted.key_id != expected.key_id
        ):
            return False
    return True


@dataclass(frozen=True)
class _SegmentScan:
    records: tuple[StoredEvidenceRecord, ...]
    frames: tuple[FrameRecord, ...]
    torn_verified: int | None
    size: int
    sha256: str
    identity: _FileIdentity


@dataclass(frozen=True)
class _ValidatedActiveScan:
    records: tuple[StoredEvidenceRecord, ...]
    frames: tuple[FrameRecord, ...]
    segment_id: str
    open_name: str
    closed_name: str
    closed_relative_path: str
    date_name: str
    priority: EvidencePriority
    host_id: str
    first_source_sequence: int
    opened_at: str
    verified_bytes: int


@dataclass(frozen=True)
class _RepairTarget:
    date_name: str
    open_name: str
    path: Path
    directory_descriptor: int
    descriptor: int
    original_identity: _FileIdentity
    scan: _SegmentScan


@dataclass(frozen=True)
class _RepairAuthorizationBinding:
    capability: AuthenticatedRepairAuthorization
    simulated_proof: SimulatedRepairAuthorization
    session_identity: object
    descriptor_identity: _FileIdentity
    facts: TailRepairFacts
    request_canonical: bytes
    target_identity: tuple[object, ...]
    verifier_generation: int
    repair_state_raw: bytes


@dataclass(frozen=True)
class _RepairCompletionAuthorizationBinding:
    capability: AuthenticatedRepairCompletion
    journal: RepairStateJournal
    session_identity: object
    repair_state_raw: bytes


@dataclass(frozen=True)
class _Promotion:
    date_name: str
    open_name: str
    closed_name: str
    identity: _FileIdentity
    sha256: str


@dataclass(frozen=True)
class _PendingDurableCommit:
    canonical: bytes
    content_sha256: str
    event_id: str
    evidence_priority: Literal["routine", "protected"]
    host_id: str
    source_sequence: int
    ref: EvidenceRef


@dataclass(frozen=True)
class _RecoveryPlan:
    promotions: tuple[_Promotion, ...] = ()
    delete_private_temporaries: tuple[tuple[str, str], ...] = ()
    delete_manifest_temporaries: tuple[str, ...] = ()
    delete_root_temporaries: tuple[str, ...] = ()
    delete_retention_state_temporaries: tuple[
        _RetentionStateArtifactBinding,
        ...,
    ] = ()
    head_raw: bytes | None = None


@dataclass
class _ActiveSegment:
    segment_id: str
    open_path: Path
    open_name: str
    closed_name: str
    closed_relative_path: str
    directory_descriptor: int
    priority: EvidencePriority
    host_id: str
    first_source_sequence: int
    opened_at: str
    opened_monotonic: float
    descriptor: int
    size: int = 0
    record_count: int = 0
    previous_frame_hash: bytes = bytes(32)


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("evidence wall clock must be timezone-aware")
    current = value.astimezone(UTC)
    text = current.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return text.replace(".000000Z", "Z")


def _full_write(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("short evidence write")
        written += count


class _HashingReader:
    def __init__(
        self,
        stream: BinaryIO,
        *,
        maximum: int,
        expected_size: int,
    ) -> None:
        if maximum < 0 or expected_size < 0 or expected_size > maximum:
            raise ValueError("invalid bounded evidence stream size")
        self._stream = stream
        self._digest = hashlib.sha256()
        self._limit = expected_size
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self._limit - self.total
        if remaining <= 0:
            return b""
        if size < 0 or size > remaining:
            size = remaining
        raw = self._stream.read(size)
        if len(raw) > remaining:
            raise EvidenceCorrupt("bounded evidence reader exceeded its hard limit")
        self._digest.update(raw)
        self.total += len(raw)
        return raw

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _validate_directory(
    descriptor: int,
    display_path: Path,
    *,
    exact_mode: bool,
) -> os.stat_result:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or (
            exact_mode
            and (
                info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            )
        )
    ):
        raise EvidenceCorrupt(f"unsafe evidence directory: {display_path}")
    return info


def _directory_authority_identity(
    descriptor: int,
    display_path: Path,
    *,
    exact_mode: bool,
) -> tuple[int, int, int, int]:
    info = _validate_directory(
        descriptor,
        display_path,
        exact_mode=exact_mode,
    )
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
    )


def _reopen_root_directory(path: Path) -> int:
    """Open one existing absolute root without creating a missing component."""
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise EvidenceCorrupt("evidence root must be an absolute clean path")
    descriptor = os.open("/", _directory_flags())
    try:
        components = path.parts[1:]
        for index, component in enumerate(components):
            try:
                child = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
            except OSError as error:
                raise EvidenceCorrupt(
                    f"unsafe evidence root path component: {component}"
                ) from error
            _validate_directory(
                child,
                Path(*path.parts[: index + 2]),
                exact_mode=index == len(components) - 1,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_root_directory(path: Path) -> int:
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise EvidenceCorrupt("evidence root must be an absolute clean path")
    descriptor = os.open("/", _directory_flags())
    try:
        for index, component in enumerate(path.parts[1:]):
            last = index == len(path.parts[1:]) - 1
            try:
                child = os.open(component, _directory_flags(), dir_fd=descriptor)
            except FileNotFoundError:
                if not last:
                    raise EvidenceCorrupt(
                        f"evidence root parent is missing: {path}"
                    ) from None
                os.mkdir(component, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(component, _directory_flags(), dir_fd=descriptor)
            except OSError as error:
                raise EvidenceCorrupt(
                    f"unsafe evidence root path component: {component}"
                ) from error
            _validate_directory(
                child,
                Path(*path.parts[: index + 2]),
                exact_mode=last,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_or_create_directory_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
) -> int:
    if "/" in name or name in {"", ".", ".."}:
        raise EvidenceCorrupt(f"unsafe evidence directory name: {name}")
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    except FileNotFoundError:
        os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    try:
        _validate_directory(descriptor, display_path, exact_mode=True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_directory_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
) -> int:
    if "/" in name or name in {"", ".", ".."}:
        raise EvidenceCorrupt(f"unsafe evidence directory name: {name}")
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    except FileNotFoundError as error:
        raise EvidenceCorrupt(f"managed evidence directory is missing: {display_path}") from error
    try:
        _validate_directory(descriptor, display_path, exact_mode=True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _entry_stat_at(parent_descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _regular_stat_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
) -> os.stat_result:
    info = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise EvidenceCorrupt(f"unsafe evidence file: {display_path}")
    return info


def _file_identity(info: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=info.st_dev,
        inode=info.st_ino,
        size=info.st_size,
        mode=info.st_mode,
        owner=info.st_uid,
        link_count=info.st_nlink,
        modified_ns=info.st_mtime_ns,
        changed_ns=info.st_ctime_ns,
    )


def _validate_identity(
    actual: os.stat_result,
    expected: _FileIdentity,
    display_path: Path,
) -> None:
    if _file_identity(actual) != expected:
        raise EvidenceCorrupt(f"evidence source identity changed: {display_path}")


def _validate_post_rename_identity(
    actual: _FileIdentity,
    authenticated: _FileIdentity,
    display_path: Path,
) -> None:
    stable_facts = (
        actual.device == authenticated.device,
        actual.inode == authenticated.inode,
        actual.size == authenticated.size,
        actual.mode == authenticated.mode,
        actual.owner == authenticated.owner,
        actual.link_count == authenticated.link_count,
        actual.modified_ns == authenticated.modified_ns,
        actual.changed_ns >= authenticated.changed_ns,
    )
    if not all(stable_facts):
        raise EvidenceCorrupt(
            f"published evidence drifted from authenticated facts: {display_path}"
        )


def _hash_held_descriptor(
    descriptor: int,
    identity: _FileIdentity,
    display_path: Path,
) -> tuple[str, _FileIdentity]:
    if identity.size > MAX_SEGMENT_BYTES:
        raise EvidenceCorrupt(f"published evidence exceeds hard bound: {display_path}")
    before = _file_identity(os.fstat(descriptor))
    digest = hashlib.sha256()
    offset = 0
    while offset < identity.size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, identity.size - offset),
            offset,
        )
        if not chunk:
            raise EvidenceCorrupt(
                f"published evidence shortened during verification: {display_path}"
            )
        digest.update(chunk)
        offset += len(chunk)
    after = _file_identity(os.fstat(descriptor))
    if after != before:
        raise EvidenceCorrupt(
            f"published evidence changed during digest verification: {display_path}"
        )
    return digest.hexdigest(), after


def _held_range_bytes(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    descriptor: int,
    identity: _FileIdentity,
    start: int,
    end: int,
) -> bytes:
    if (
        type(start) is not int
        or type(end) is not int
        or not 0 <= start <= end <= identity.size <= MAX_SEGMENT_BYTES
    ):
        raise EvidenceCorrupt(f"invalid held evidence byte range: {display_path}")
    _bind_held_source(
        parent_descriptor,
        name,
        display_path,
        descriptor=descriptor,
        identity=identity,
    )
    chunks: list[bytes] = []
    offset = start
    while offset < end:
        chunk = os.pread(descriptor, min(1024 * 1024, end - offset), offset)
        if not chunk:
            raise EvidenceCorrupt(
                f"held evidence shortened during range verification: {display_path}"
            )
        chunks.append(chunk)
        offset += len(chunk)
    _bind_held_source(
        parent_descriptor,
        name,
        display_path,
        descriptor=descriptor,
        identity=identity,
    )
    return b"".join(chunks)


def _hash_held_range(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    descriptor: int,
    identity: _FileIdentity,
    start: int,
    end: int,
) -> str:
    if (
        type(start) is not int
        or type(end) is not int
        or not 0 <= start <= end <= identity.size <= MAX_SEGMENT_BYTES
    ):
        raise EvidenceCorrupt(f"invalid held evidence byte range: {display_path}")
    _bind_held_source(
        parent_descriptor,
        name,
        display_path,
        descriptor=descriptor,
        identity=identity,
    )
    digest = hashlib.sha256()
    offset = start
    while offset < end:
        chunk = os.pread(descriptor, min(1024 * 1024, end - offset), offset)
        if not chunk:
            raise EvidenceCorrupt(
                f"held evidence shortened during range verification: {display_path}"
            )
        digest.update(chunk)
        offset += len(chunk)
    _bind_held_source(
        parent_descriptor,
        name,
        display_path,
        descriptor=descriptor,
        identity=identity,
    )
    return digest.hexdigest()


def _validate_incomplete_frame_suffix(
    raw: bytes,
    *,
    expected_previous: bytes,
) -> None:
    magic = b"AGF1"
    if not raw or len(expected_previous) != 32:
        raise EvidenceCorrupt("repair target has no exact incomplete final frame")
    magic_prefix = raw[: min(len(raw), len(magic))]
    if magic_prefix != magic[: len(magic_prefix)]:
        raise EvidenceCorrupt("repair target suffix is not an incomplete AGF1 frame")
    if len(raw) < 8:
        return
    payload_size = int.from_bytes(raw[4:8], "big")
    if payload_size > MAX_EVIDENCE_RECORD_BYTES:
        raise EvidenceCorrupt("repair target suffix declares an oversized AGF1 frame")
    header_previous = raw[8 : min(len(raw), 40)]
    if header_previous != expected_previous[: len(header_previous)]:
        raise EvidenceCorrupt("repair target suffix has the wrong frame predecessor")
    if len(raw) >= payload_size + 76:
        raise EvidenceCorrupt("repair target suffix contains a complete AGF1 frame")


def _read_stable_repair_artifact(
    parent_descriptor: int,
    name: str,
    display_path: Path,
) -> _RepairStateArtifactBinding:
    before = _file_identity(
        _regular_stat_at(parent_descriptor, name, display_path)
    )
    if before.size > _MAX_REPAIR_STATE_BYTES:
        raise EvidenceCorrupt(f"repair state exceeds 4096 bytes: {display_path}")
    raw = _read_regular_at(
        parent_descriptor,
        name,
        display_path,
        _MAX_REPAIR_STATE_BYTES,
    )
    after = _file_identity(
        _regular_stat_at(parent_descriptor, name, display_path)
    )
    if before != after:
        raise EvidenceCorrupt(f"repair state changed during held scan: {display_path}")
    return _RepairStateArtifactBinding(name=name, raw=raw, identity=after)


def _read_stable_retention_artifact(
    parent_descriptor: int,
    name: str,
    display_path: Path,
) -> _RetentionStateArtifactBinding:
    before = _file_identity(
        _regular_stat_at(parent_descriptor, name, display_path)
    )
    if before.size > _MAX_RETENTION_STATE_BYTES:
        raise EvidenceCorrupt(
            f"retention state exceeds 128 KiB: {display_path}"
        )
    raw = _read_regular_at(
        parent_descriptor,
        name,
        display_path,
        _MAX_RETENTION_STATE_BYTES,
    )
    after = _file_identity(
        _regular_stat_at(parent_descriptor, name, display_path)
    )
    if before != after:
        raise EvidenceCorrupt(
            f"retention state changed during held scan: {display_path}"
        )
    return _RetentionStateArtifactBinding(
        name=name,
        raw=raw,
        identity=after,
    )


def _open_regular_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    maximum: int | None = None,
) -> tuple[int, os.stat_result]:
    expected = _regular_stat_at(parent_descriptor, name, display_path)
    if maximum is not None and expected.st_size > maximum:
        raise EvidenceCorrupt(f"evidence file exceeds bound: {display_path}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_ino != expected.st_ino
            or opened.st_dev != expected.st_dev
            or opened.st_size != expected.st_size
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise EvidenceCorrupt(f"evidence file changed during open: {display_path}")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _open_regular_read_write_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    maximum: int,
) -> tuple[int, _FileIdentity]:
    expected = _regular_stat_at(parent_descriptor, name, display_path)
    if expected.st_size > maximum:
        raise EvidenceCorrupt(f"evidence file exceeds bound: {display_path}")
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    identity = _file_identity(expected)
    try:
        _bind_held_source(
            parent_descriptor,
            name,
            display_path,
            descriptor=descriptor,
            identity=identity,
        )
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    maximum: int,
) -> bytes:
    descriptor, expected = _open_regular_at(
        parent_descriptor,
        name,
        display_path,
        maximum=maximum,
    )
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise EvidenceCorrupt(f"evidence contract exceeds bound: {display_path}")
        if total != expected.st_size:
            raise EvidenceCorrupt(f"evidence file size changed while reading: {display_path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _rename_noreplace(
    source_name: str,
    destination_name: str,
    *,
    source_dir_fd: int,
    destination_dir_fd: int,
) -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int
            result = renameat2(
                source_dir_fd,
                os.fsencode(source_name),
                destination_dir_fd,
                os.fsencode(destination_name),
                1,
            )
            if result == 0:
                return
            error_number = ctypes.get_errno()
            if error_number in _ATOMIC_RENAME_UNAVAILABLE:
                raise EvidenceStoreError(
                    "atomic no-replace rename is unavailable on Linux"
                )
            raise OSError(
                error_number,
                os.strerror(error_number),
                destination_name,
            )
        raise EvidenceStoreError(
            "atomic no-replace rename is unavailable on Linux"
        )
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renameatx_np = getattr(libc, "renameatx_np", None)
        if renameatx_np is not None:
            renameatx_np.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameatx_np.restype = ctypes.c_int
            result = renameatx_np(
                source_dir_fd,
                os.fsencode(source_name),
                destination_dir_fd,
                os.fsencode(destination_name),
                4,
            )
            if result == 0:
                return
            error_number = ctypes.get_errno()
            if error_number in _ATOMIC_RENAME_UNAVAILABLE:
                raise EvidenceStoreError(
                    "atomic no-replace rename is unavailable on Darwin"
                )
            raise OSError(error_number, os.strerror(error_number), destination_name)
        raise EvidenceStoreError("atomic no-replace rename is unavailable on Darwin")
    raise EvidenceStoreError(
        f"atomic no-replace rename is unavailable on {sys.platform}"
    )


def _rename_exchange(
    left_name: str,
    right_name: str,
    *,
    parent_descriptor: int,
) -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int
            result = renameat2(
                parent_descriptor,
                os.fsencode(left_name),
                parent_descriptor,
                os.fsencode(right_name),
                2,
            )
            if result == 0:
                return
            error_number = ctypes.get_errno()
            if error_number in _ATOMIC_RENAME_UNAVAILABLE:
                raise EvidenceStoreError(
                    "atomic exchange rename is unavailable on Linux"
                )
            raise OSError(
                error_number,
                os.strerror(error_number),
                right_name,
            )
        raise EvidenceStoreError(
            "atomic exchange rename is unavailable on Linux"
        )
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renameatx_np = getattr(libc, "renameatx_np", None)
        if renameatx_np is not None:
            renameatx_np.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameatx_np.restype = ctypes.c_int
            result = renameatx_np(
                parent_descriptor,
                os.fsencode(left_name),
                parent_descriptor,
                os.fsencode(right_name),
                2,
            )
            if result == 0:
                return
            error_number = ctypes.get_errno()
            if error_number in _ATOMIC_RENAME_UNAVAILABLE:
                raise EvidenceStoreError(
                    "atomic exchange rename is unavailable on Darwin"
                )
            raise OSError(
                error_number,
                os.strerror(error_number),
                right_name,
            )
        raise EvidenceStoreError(
            "atomic exchange rename is unavailable on Darwin"
        )
    raise EvidenceStoreError(
        f"atomic exchange rename is unavailable on {sys.platform}"
    )


def _bind_held_source(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    descriptor: int,
    identity: _FileIdentity,
) -> None:
    _validate_identity(os.fstat(descriptor), identity, display_path)
    _validate_identity(
        _regular_stat_at(parent_descriptor, name, display_path),
        identity,
        display_path,
    )


def _validate_published_from_held(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    descriptor: int,
    identity: _FileIdentity,
    expected_sha256: str,
) -> None:
    held_before = _file_identity(os.fstat(descriptor))
    _validate_post_rename_identity(held_before, identity, display_path)
    published_before = _file_identity(
        _regular_stat_at(parent_descriptor, name, display_path)
    )
    if published_before != held_before:
        raise EvidenceCorrupt(
            f"published evidence is not the authenticated source: {display_path}"
        )
    actual_sha256, held_after = _hash_held_descriptor(
        descriptor,
        held_before,
        display_path,
    )
    published_after = _file_identity(
        _regular_stat_at(parent_descriptor, name, display_path)
    )
    if (
        actual_sha256 != expected_sha256
        or held_after != held_before
        or published_after != held_after
    ):
        raise EvidenceCorrupt(
            f"published evidence bytes changed after authentication: {display_path}"
        )


def _publish_held_without_replacement(
    source_parent_descriptor: int,
    source_name: str,
    destination_parent_descriptor: int,
    destination_name: str,
    display_path: Path,
    *,
    descriptor: int,
    identity: _FileIdentity,
    expected_sha256: str,
) -> None:
    with _post_authentication_namespace(display_path):
        _bind_held_source(
            source_parent_descriptor,
            source_name,
            display_path,
            descriptor=descriptor,
            identity=identity,
        )
        _rename_noreplace(
            source_name,
            destination_name,
            source_dir_fd=source_parent_descriptor,
            destination_dir_fd=destination_parent_descriptor,
        )
        _validate_published_from_held(
            destination_parent_descriptor,
            destination_name,
            display_path,
            descriptor=descriptor,
            identity=identity,
            expected_sha256=expected_sha256,
        )
        os.fsync(destination_parent_descriptor)


def _promote_authenticated_source(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
    display_path: Path,
    *,
    identity: _FileIdentity,
    expected_sha256: str,
) -> None:
    source_path = display_path.with_name(source_name)
    with _post_authentication_namespace(source_path):
        descriptor, opened = _open_regular_at(
            parent_descriptor,
            source_name,
            source_path,
            maximum=MAX_SEGMENT_BYTES,
        )
    try:
        _validate_identity(opened, identity, source_path)
        _publish_held_without_replacement(
            parent_descriptor,
            source_name,
            parent_descriptor,
            destination_name,
            display_path,
            descriptor=descriptor,
            identity=identity,
            expected_sha256=expected_sha256,
        )
    finally:
        os.close(descriptor)


def _write_temporary_at(
    parent_descriptor: int,
    temporary_name: str,
    raw: bytes,
) -> tuple[int, _FileIdentity]:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_descriptor)
    try:
        os.fchmod(descriptor, 0o600)
        _full_write(descriptor, raw)
        os.fsync(descriptor)
        return descriptor, _file_identity(os.fstat(descriptor))
    except BaseException:
        os.close(descriptor)
        raise


def _cleanup_private_publication(
    parent_descriptor: int,
    temporary_name: str | None,
    display_path: Path,
    *,
    descriptor: int,
    preserve_primary: bool,
) -> None:
    cleanup_error: OSError | None = None
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except OSError as error:
            cleanup_error = error
    if temporary_name is not None:
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        except OSError as error:
            if cleanup_error is None:
                cleanup_error = error
    if cleanup_error is not None and not preserve_primary:
        raise EvidenceCorrupt(
            f"authenticated evidence cleanup became uncertain: {display_path}"
        ) from cleanup_error


def _atomic_replace_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    raw: bytes,
    *,
    step_hook: Callable[[str], None] | None = None,
) -> None:
    hook = step_hook or (lambda _step: None)
    temporary_name = f".{name}.{uuid.uuid4()}.tmp"
    expected_sha256 = hashlib.sha256(raw).hexdigest()
    descriptor = -1
    try:
        descriptor, identity = _write_temporary_at(
            parent_descriptor,
            temporary_name,
            raw,
        )
        hook("commitment_temp_fsync")
        with _post_authentication_namespace(display_path):
            _bind_held_source(
                parent_descriptor,
                temporary_name,
                display_path,
                descriptor=descriptor,
                identity=identity,
            )
            os.replace(
                temporary_name,
                name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            hook("commitment_atomic_replace")
            _validate_published_from_held(
                parent_descriptor,
                name,
                display_path,
                descriptor=descriptor,
                identity=identity,
                expected_sha256=expected_sha256,
            )
            os.fsync(parent_descriptor)
            hook("commitment_directory_fsync")
    except BaseException:
        _cleanup_private_publication(
            parent_descriptor,
            temporary_name,
            display_path,
            descriptor=descriptor,
            preserve_primary=True,
        )
        raise
    else:
        _cleanup_private_publication(
            parent_descriptor,
            temporary_name,
            display_path,
            descriptor=descriptor,
            preserve_primary=False,
        )


def _moved_held_identity(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    descriptor: int,
    identity: _FileIdentity,
) -> _FileIdentity:
    held = _file_identity(os.fstat(descriptor))
    _validate_post_rename_identity(held, identity, display_path)
    named = _file_identity(
        _regular_stat_at(parent_descriptor, name, display_path)
    )
    if named != held:
        raise EvidenceCorrupt(
            f"moved evidence is not the held source: {display_path}"
        )
    return held


def _publish_retention_boundary_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    raw: bytes,
    *,
    existing_descriptor: int,
    existing_identity: _FileIdentity | None,
) -> tuple[int, _FileIdentity]:
    if (existing_descriptor >= 0) != (existing_identity is not None):
        raise EvidenceSealError(
            "retention boundary replacement lost its held source"
        )
    temporary_name = f".{name}.{uuid.uuid4()}.tmp"
    temporary_path = display_path.with_name(temporary_name)
    expected_sha256 = hashlib.sha256(raw).hexdigest()
    descriptor = -1
    old_descriptor = existing_descriptor
    try:
        descriptor, identity = _write_temporary_at(
            parent_descriptor,
            temporary_name,
            raw,
        )
        with _post_authentication_namespace(display_path):
            _bind_held_source(
                parent_descriptor,
                temporary_name,
                temporary_path,
                descriptor=descriptor,
                identity=identity,
            )
            moved_old_identity: _FileIdentity | None = None
            if existing_identity is None:
                _rename_noreplace(
                    temporary_name,
                    name,
                    source_dir_fd=parent_descriptor,
                    destination_dir_fd=parent_descriptor,
                )
            else:
                _bind_held_source(
                    parent_descriptor,
                    name,
                    display_path,
                    descriptor=old_descriptor,
                    identity=existing_identity,
                )
                _rename_exchange(
                    temporary_name,
                    name,
                    parent_descriptor=parent_descriptor,
                )
                try:
                    moved_old_identity = _moved_held_identity(
                        parent_descriptor,
                        temporary_name,
                        temporary_path,
                        descriptor=old_descriptor,
                        identity=existing_identity,
                    )
                except BaseException as error:
                    try:
                        _validate_published_from_held(
                            parent_descriptor,
                            name,
                            display_path,
                            descriptor=descriptor,
                            identity=identity,
                            expected_sha256=expected_sha256,
                        )
                        os.fsync(parent_descriptor)
                    except BaseException as publication_error:
                        raise EvidenceCorrupt(
                            "retention boundary publication is uncertain"
                        ) from publication_error
                    raise EvidenceCorrupt(
                        "retention boundary source changed at exchange"
                    ) from error
            _validate_published_from_held(
                parent_descriptor,
                name,
                display_path,
                descriptor=descriptor,
                identity=identity,
                expected_sha256=expected_sha256,
            )
            published_identity = _file_identity(os.fstat(descriptor))
            os.fsync(parent_descriptor)
            if existing_identity is not None:
                if moved_old_identity is None:
                    raise EvidenceSealError(
                        "retention boundary old source is unbound"
                    )
                _bind_held_source(
                    parent_descriptor,
                    temporary_name,
                    temporary_path,
                    descriptor=old_descriptor,
                    identity=moved_old_identity,
                )
                os.unlink(temporary_name, dir_fd=parent_descriptor)
                unlinked = os.fstat(old_descriptor)
                if (
                    unlinked.st_dev != existing_identity.device
                    or unlinked.st_ino != existing_identity.inode
                    or unlinked.st_size != existing_identity.size
                    or unlinked.st_mode != existing_identity.mode
                    or unlinked.st_uid != existing_identity.owner
                    or unlinked.st_nlink != 0
                    or _entry_stat_at(parent_descriptor, temporary_name)
                    is not None
                ):
                    raise EvidenceCorrupt(
                        "retention boundary old source unlink is uncertain"
                    )
                closed = old_descriptor
                old_descriptor = -1
                os.close(closed)
                os.fsync(parent_descriptor)
            elif (
                _entry_stat_at(parent_descriptor, temporary_name)
                is not None
            ):
                raise EvidenceCorrupt(
                    "retention boundary temporary survived publication"
                )
        published = descriptor
        descriptor = -1
        return published, published_identity
    except BaseException as error:
        if descriptor >= 0:
            closing = descriptor
            descriptor = -1
            try:
                os.close(closing)
            except BaseException as close_error:  # noqa: BLE001
                error.add_note(
                    "retention boundary publication descriptor close failed: "
                    f"{close_error}"
                )
        if old_descriptor >= 0:
            closing = old_descriptor
            old_descriptor = -1
            try:
                os.close(closing)
            except BaseException as close_error:  # noqa: BLE001
                error.add_note(
                    "retention boundary old descriptor close failed: "
                    f"{close_error}"
                )
        raise


def _conditionally_unlink_held_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    descriptor: int,
    identity: _FileIdentity,
) -> None:
    temporary_name = f".{name}.{uuid.uuid4()}.tmp"
    temporary_path = display_path.with_name(temporary_name)
    moved = False
    held_descriptor = descriptor
    try:
        with _post_authentication_namespace(display_path):
            _bind_held_source(
                parent_descriptor,
                name,
                display_path,
                descriptor=held_descriptor,
                identity=identity,
            )
            _rename_noreplace(
                name,
                temporary_name,
                source_dir_fd=parent_descriptor,
                destination_dir_fd=parent_descriptor,
            )
            moved = True
            moved_identity = _moved_held_identity(
                parent_descriptor,
                temporary_name,
                temporary_path,
                descriptor=held_descriptor,
                identity=identity,
            )
            if _entry_stat_at(parent_descriptor, name) is not None:
                raise EvidenceCorrupt(
                    f"retention finalization source reappeared: {display_path}"
                )
            _bind_held_source(
                parent_descriptor,
                temporary_name,
                temporary_path,
                descriptor=held_descriptor,
                identity=moved_identity,
            )
            os.unlink(temporary_name, dir_fd=parent_descriptor)
            unlinked = os.fstat(held_descriptor)
            if (
                unlinked.st_dev != identity.device
                or unlinked.st_ino != identity.inode
                or unlinked.st_size != identity.size
                or unlinked.st_mode != identity.mode
                or unlinked.st_uid != identity.owner
                or unlinked.st_nlink != 0
                or _entry_stat_at(parent_descriptor, temporary_name)
                is not None
                or _entry_stat_at(parent_descriptor, name) is not None
            ):
                raise EvidenceCorrupt(
                    f"retention finalization unlink is uncertain: {display_path}"
                )
        closing = held_descriptor
        held_descriptor = -1
        os.close(closing)
        os.fsync(parent_descriptor)
    except BaseException as error:
        if held_descriptor >= 0:
            closing = held_descriptor
            held_descriptor = -1
            try:
                os.close(closing)
            except BaseException as close_error:  # noqa: BLE001
                error.add_note(
                    "retention finalization descriptor close failed: "
                    f"{close_error}"
                )
        if moved:
            try:
                os.fsync(parent_descriptor)
            except BaseException as fsync_error:  # noqa: BLE001
                error.add_note(
                    "retention finalization move fsync failed: "
                    f"{fsync_error}"
                )
        raise


def _publish_without_replacement_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    raw: bytes,
) -> None:
    temporary_name = f".{name}.{uuid.uuid4()}.tmp"
    expected_sha256 = hashlib.sha256(raw).hexdigest()
    descriptor = -1
    try:
        descriptor, identity = _write_temporary_at(
            parent_descriptor,
            temporary_name,
            raw,
        )
        _publish_held_without_replacement(
            parent_descriptor,
            temporary_name,
            parent_descriptor,
            name,
            display_path,
            descriptor=descriptor,
            identity=identity,
            expected_sha256=expected_sha256,
        )
    except BaseException:
        _cleanup_private_publication(
            parent_descriptor,
            temporary_name,
            display_path,
            descriptor=descriptor,
            preserve_primary=True,
        )
        raise
    else:
        _cleanup_private_publication(
            parent_descriptor,
            temporary_name,
            display_path,
            descriptor=descriptor,
            preserve_primary=False,
        )


@final
class _RetentionStateAuthority:
    """Factory-only held-root retention-state I/O capability."""

    __slots__ = (
        "_lifecycle_identity",
        "_retention_journal",
        "_store",
    )

    def __init__(
        self,
        store: SegmentStore,
        *,
        _factory: object,
    ) -> None:
        if _factory is not _RETENTION_STATE_AUTHORITY_FACTORY:
            raise TypeError(
                "retention-state authority is issued only by SegmentStore"
            )
        self._store = store
        self._lifecycle_identity = store._lifecycle_identity
        self._retention_journal: object | None = None

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("_RetentionStateAuthority is final")

    def __copy__(self) -> _RetentionStateAuthority:
        raise TypeError("retention-state capabilities cannot be copied")

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> _RetentionStateAuthority:
        del memo
        raise TypeError("retention-state capabilities cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("retention-state capabilities cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("retention-state capabilities cannot be serialized")

    def _require(self) -> SegmentStore:
        store = self._store
        if (
            store._closed
            or store._lifecycle_identity is not self._lifecycle_identity
            or store._retention_state_authority is not self
            or store._retention_state_namespace_uncertain
        ):
            raise EvidenceSealError(
                "retention-state authority lost its exact store lifecycle"
            )
        return store

    def read_retention_state_bytes(self) -> bytes | None:
        return self._require()._read_retention_state_bytes(self)

    def read_retention_state_temporary_bytes(self) -> bytes | None:
        return self._require()._read_retention_state_temporary_bytes(self)

    def publish_initial_retention_state(self, raw: bytes) -> None:
        self._require()._publish_initial_retention_state(self, raw)

    def replace_retention_state_bytes(
        self,
        expected: bytes,
        raw: bytes,
    ) -> None:
        self._require()._replace_retention_state_bytes(
            self,
            expected,
            raw,
        )

    def _bind_retention_journal(
        self,
        journal: object,
        *,
        _factory: object,
    ) -> None:
        from agmind_immune.evidence.retention import RetentionStateJournal

        self._require()
        if (
            _factory is not _RETENTION_STATE_AUTHORITY_FACTORY
            or type(journal) is not RetentionStateJournal
            or journal._authority is not self
        ):
            raise EvidenceSealError(
                "retention journal is not bound to exact store authority"
            )
        if self._retention_journal is not None:
            raise EvidenceSealError(
                "retention journal is already bound in this lifecycle"
            )
        self._retention_journal = journal


class SegmentStore:
    """One lifetime-locked authoritative AGF1 evidence root."""

    def __init__(
        self,
        root: Path,
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        health_step_hook: Callable[[str], None] | None = None,
        segment_create_step_hook: Callable[[str], None] | None = None,
    ) -> None:
        self._repair_mode = bool(getattr(self, "_repair_mode", False))
        self._repair_pending = self._repair_mode
        self._repair_pretruncate = self._repair_mode
        self._repair_resumed = False
        self._repair_prefix_needs_settlement = False
        self._repair_session_identity: object | None = (
            object() if self._repair_mode else None
        )
        self._repair_target: _RepairTarget | None = None
        self._repair_post_h0_active: _RepairTarget | None = None
        self._repair_facts: TailRepairFacts | None = None
        self._repair_physical_state = RepairPhysicalState.INVALID
        self._repair_namespace_uncertain = False
        self._repair_recovery_plan: _RecoveryPlan | None = None
        self._repair_state_binding: _RepairStateArtifactBinding | None = None
        self._repair_state_temporary: _RepairStateArtifactBinding | None = None
        self._retention_state_binding: (
            _RetentionStateArtifactBinding | None
        ) = None
        self._retention_state_temporary: (
            _RetentionStateArtifactBinding | None
        ) = None
        self._retention_state_authority: (
            _RetentionStateAuthority | None
        ) = None
        self._retention_snapshot_binding: (
            _RetentionSnapshotBinding | None
        ) = None
        self._authenticated_retention_tombstone: (
            _AuthenticatedRetentionTombstoneBinding | None
        ) = None
        self._authenticated_retention_unlink_completion: (
            _AuthenticatedRetentionUnlinkCompletionBinding | None
        ) = None
        self._retention_tombstone_lock = Lock()
        self._retention_commit_uncertain_latched = False
        self._retention_finalization_uncertain_latched = False
        self._retention_state_namespace_uncertain = False
        self._retention_pending_latched = False
        self._repair_authorization: _RepairAuthorizationBinding | None = None
        self._repair_completion_authorization: (
            _RepairCompletionAuthorizationBinding | None
        ) = None
        self._repair_base_verifier_generation: int | None = None
        self._repair_ack_journal: AckJournal | None = None
        self._repair_ack_snapshot: object | None = None
        self.root = root
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic_clock or time.monotonic
        self._health_step_hook = health_step_hook or (lambda _step: None)
        self._segment_create_step_hook = (
            segment_create_step_hook or (lambda _step: None)
        )
        self._closed = False
        self._active: _ActiveSegment | None = None
        self._manifests: list[SegmentManifestV1] = []
        self._manifest_replay_records: dict[
            str,
            tuple[StoredEvidenceRecord, ...] | None,
        ] = {}
        self._missing_manifest_payloads: tuple[
            _MissingManifestPayload,
            ...,
        ] = ()
        self._authenticated_retired_ranges: tuple[
            tuple[int, int],
            ...,
        ] = ()
        self._projection_reconciliation_completed_state_raw: (
            bytes | None
        ) = None
        self._chain_head: SegmentChainHeadV1 | None = None
        self._records: list[StoredEvidenceRecord] = []
        self._index: dict[tuple[str, int], tuple[bytes, EvidenceRef]] = {}
        self._record_positions: dict[tuple[str, int], int] = {}
        self._sequences_by_host: dict[str, list[int]] = {}
        self._last_sequence_by_host: dict[str, int] = {}
        self._read_only_reason: str | None = None
        self._append_uncertain = False
        self._pending_durable_commit: _PendingDurableCommit | None = None
        self._date_descriptors: dict[str, int] = {}
        self._lifecycle_identity = object()
        self._bound_verifier: EnvelopeVerifier | None = None
        self._issued_pcc_inputs: weakref.WeakKeyDictionary[
            AuthenticatedPCCInput,
            _StoreIssuedPCCBinding,
        ] = weakref.WeakKeyDictionary()
        self._authority_state: Literal[
            "unbound",
            "recovering",
            "ready",
            "retention_uncertain",
        ] = "unbound"
        self._coverage_state_owner: object | None = None
        self._correlation_journal_owner: object | None = None
        self._correlation_journal_state: Literal[
            "unknown",
            "fresh",
            "present",
            "creating",
            "recovering",
            "initialization_uncertain",
            "initialized",
            "append_uncertain",
            "io_uncertain",
        ] = "unknown"
        self._correlation_journal_operation: (
            Literal["create", "recover"] | None
        ) = None
        self._correlation_journal_identity: _FileIdentity | None = None
        self._correlation_journal_digest: bytes | None = None
        self._ack_journal_owner: object | None = None
        self._retention_ack_recovery_permitted = False
        self._ack_journal_is_retention_recovery = False
        self._ack_journal_state: Literal[
            "unknown",
            "fresh",
            "present",
            "bootstrap",
            "creating",
            "recovering",
            "initialization_uncertain",
            "initialized",
            "append_uncertain",
            "commitment_uncertain",
            "io_uncertain",
        ] = "unknown"
        self._ack_journal_operation: Literal["create", "recover"] | None = None
        self._ack_journal_identity: _FileIdentity | None = None
        self._ack_journal_digest: bytes | None = None
        self._ack_commitment: _AckCommitmentV1 | None = None
        self._ack_commitment_raw: bytes | None = None
        self._ack_commitment_identity: _FileIdentity | None = None
        self._ack_commitment_temporary: _AckCommitmentTemporaryBinding | None = None
        self.fail_next_append: BaseException | None = None
        self._segments_path = root / "segments"
        self._manifests_path = root / "manifests"
        self._root_descriptor = _open_root_directory(root)
        try:
            fcntl.flock(self._root_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(self._root_descriptor)
            raise EvidenceStoreBusy(f"evidence root is already locked: {root}") from error
        try:
            self._load_health_state()
            root_names = set(os.listdir(self._root_descriptor))
            managed_names = {"segments", "manifests"}
            present_managed = root_names & managed_names
            if present_managed == managed_names:
                self._segments_descriptor = _open_directory_at(
                    self._root_descriptor,
                    "segments",
                    self._segments_path,
                )
                self._manifests_descriptor = _open_directory_at(
                    self._root_descriptor,
                    "manifests",
                    self._manifests_path,
                )
            elif not root_names and self._read_only_reason is None:
                self._segments_descriptor = _open_or_create_directory_at(
                    self._root_descriptor,
                    "segments",
                    self._segments_path,
                )
                self._manifests_descriptor = _open_or_create_directory_at(
                    self._root_descriptor,
                    "manifests",
                    self._manifests_path,
                )
            else:
                raise EvidenceCorrupt(
                    "nonpristine evidence root is missing a managed directory"
                )
            self._startup()
        except BaseException:
            for repair_target in (
                self._repair_target,
                self._repair_post_h0_active,
            ):
                if repair_target is not None and repair_target.descriptor >= 0:
                    os.close(repair_target.descriptor)
            for descriptor in self._date_descriptors.values():
                os.close(descriptor)
            if hasattr(self, "_manifests_descriptor"):
                os.close(self._manifests_descriptor)
            if hasattr(self, "_segments_descriptor"):
                os.close(self._segments_descriptor)
            fcntl.flock(self._root_descriptor, fcntl.LOCK_UN)
            os.close(self._root_descriptor)
            self._closed = True
            raise

    @classmethod
    def open_tail_repair(
        cls,
        root: Path,
        verifier: EnvelopeVerifier,
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        health_step_hook: Callable[[str], None] | None = None,
        segment_create_step_hook: Callable[[str], None] | None = None,
    ) -> TailRepairSession:
        """Open one torn-tail repair lifecycle without releasing the root lock."""
        if cls is not SegmentStore or type(verifier) is not EnvelopeVerifier:
            raise TypeError(
                "tail repair requires the exact SegmentStore and EnvelopeVerifier"
            )
        return TailRepairSession(
            root,
            verifier,
            wall_clock=wall_clock,
            monotonic_clock=monotonic_clock,
            health_step_hook=health_step_hook,
            segment_create_step_hook=segment_create_step_hook,
        )

    @property
    def manifests(self) -> tuple[SegmentManifestV1, ...]:
        return tuple(manifest.model_copy(deep=True) for manifest in self._manifests)

    @property
    def chain_head(self) -> SegmentChainHeadV1 | None:
        return (
            None
            if self._chain_head is None
            else self._chain_head.model_copy(deep=True)
        )

    @property
    def active_path(self) -> Path | None:
        return None if self._active is None else self._active.open_path

    @property
    def read_only_reason(self) -> str | None:
        return self._read_only_reason

    @property
    def repair_facts(self) -> TailRepairFacts | None:
        facts = self._repair_facts
        return None if facts is None else copy.copy(facts)

    @property
    def verifier_generation(self) -> int:
        verifier = self._require_authenticated_recovered()
        generation = verifier._authority.generation
        if type(generation) is not int or generation < 0:
            raise EvidenceCorrupt("verifier generation is not an exact integer")
        return generation

    @property
    def ack_journal(self) -> AckJournal:
        self._require_repair_lifecycle()
        journal = self._repair_ack_journal
        if journal is None:
            raise EvidenceSealError("repair ACK journal has not been recovered")
        return journal

    def _is_bound_verifier(self, verifier: EnvelopeVerifier) -> bool:
        return (
            not self._closed
            and self._authority_state == "ready"
            and self._bound_verifier is verifier
            and verifier._bound_lifecycle is self._lifecycle_identity
        )

    def _retention_pending_snapshot(self) -> bool:
        """Return a conservative lock-free snapshot of the retention deny gate."""
        latched_before = self._retention_pending_latched
        pending_source = (
            self._retention_state_binding is not None
            or self._retention_state_temporary is not None
            or self._retention_state_namespace_uncertain
            or self._retention_commit_uncertain_latched
            or self._retention_finalization_uncertain_latched
        )
        latched_after = self._retention_pending_latched
        return latched_before or pending_source or latched_after

    def _clear_retention_pending_latch(self) -> None:
        if (
            self._retention_state_binding is not None
            or self._retention_state_temporary is not None
            or self._retention_state_namespace_uncertain
            or self._retention_commit_uncertain_latched
            or self._retention_finalization_uncertain_latched
        ):
            raise EvidenceSealError(
                "retention pending latch cannot clear before exact settlement"
            )
        self._retention_pending_latched = False

    def status(self) -> EvidenceStatus:
        retention_pending = self._retention_pending_snapshot()
        if self._closed:
            return EvidenceStatus(
                False,
                None,
                0,
                0,
                False,
                self._repair_pending,
                retention_pending,
            )
        verifier = self._bound_verifier
        if verifier is None:
            return EvidenceStatus(
                False,
                None,
                0,
                0,
                False,
                self._repair_pending,
                retention_pending,
            )
        fsm = verifier.fsm
        evidence_head = fsm.last_sequence
        holes = fsm.unresolved_holes
        acceptance_cursor = holes[0][0] - 1 if holes else evidence_head
        if (
            type(fsm.host_id) is not str
            or type(evidence_head) is not int
            or type(acceptance_cursor) is not int
            or not 0 <= acceptance_cursor <= evidence_head <= MAX_UINT64
        ):
            return EvidenceStatus(
                False,
                None,
                0,
                0,
                False,
                self._repair_pending,
                retention_pending,
            )
        active = self._active
        active_descriptor = None if active is None else active.descriptor
        base_healthy = (
            self._read_only_reason is None
            and not self._append_uncertain
            and self._pending_durable_commit is None
            and (
                active is None
                or (
                    type(active_descriptor) is int
                    and active_descriptor >= 0
                )
            )
        )
        stable = (
            self._is_bound_verifier(verifier)
            and self._bound_verifier is verifier
            and verifier.fsm is fsm
            and self._active is active
            and (
                active is None
                or active.descriptor == active_descriptor
            )
        )
        healthy = base_healthy and stable and not self._repair_pretruncate
        key_healthy = (
            type(fsm.mutation_read_only) is bool
            and not fsm.mutation_read_only
            and fsm.pending_rotation is None
        )
        return EvidenceStatus(
            healthy,
            fsm.host_id,
            evidence_head,
            acceptance_cursor,
            key_healthy,
            self._repair_pending,
            retention_pending,
        )

    def _require_retention_directory_bindings(self) -> None:
        """Rebind every retained directory FD to its canonical parent name."""
        retained_root = _directory_authority_identity(
            self._root_descriptor,
            self.root,
            exact_mode=True,
        )
        canonical_root = _reopen_root_directory(self.root)
        canonical_segments = -1
        try:
            if (
                _directory_authority_identity(
                    canonical_root,
                    self.root,
                    exact_mode=True,
                )
                != retained_root
            ):
                raise EvidenceCorrupt(
                    "retention evidence root changed after startup"
                )
            for name, retained, display_path in (
                (
                    "manifests",
                    self._manifests_descriptor,
                    self._manifests_path,
                ),
                (
                    "segments",
                    self._segments_descriptor,
                    self._segments_path,
                ),
            ):
                expected = _directory_authority_identity(
                    retained,
                    display_path,
                    exact_mode=True,
                )
                reopened = _open_directory_at(
                    canonical_root,
                    name,
                    display_path,
                )
                try:
                    if (
                        _directory_authority_identity(
                            reopened,
                            display_path,
                            exact_mode=True,
                        )
                        != expected
                    ):
                        raise EvidenceCorrupt(
                            "retention evidence directory changed: "
                            f"{display_path}"
                        )
                    if name == "segments":
                        canonical_segments = reopened
                        reopened = -1
                finally:
                    if reopened >= 0:
                        os.close(reopened)

            if canonical_segments < 0:
                raise EvidenceCorrupt(
                    "retention segments directory is unavailable"
                )
            for date_name, retained in tuple(
                sorted(self._date_descriptors.items())
            ):
                display_path = self._segments_path / date_name
                expected = _directory_authority_identity(
                    retained,
                    display_path,
                    exact_mode=True,
                )
                reopened = _open_directory_at(
                    canonical_segments,
                    date_name,
                    display_path,
                )
                try:
                    if (
                        _directory_authority_identity(
                            reopened,
                            display_path,
                            exact_mode=True,
                        )
                        != expected
                    ):
                        raise EvidenceCorrupt(
                            "retention date directory changed: "
                            f"{display_path}"
                        )
                finally:
                    os.close(reopened)

            final_root = _reopen_root_directory(self.root)
            try:
                if (
                    _directory_authority_identity(
                        final_root,
                        self.root,
                        exact_mode=True,
                    )
                    != retained_root
                ):
                    raise EvidenceCorrupt(
                        "retention evidence root changed during rebinding"
                    )
            finally:
                os.close(final_root)
        finally:
            if canonical_segments >= 0:
                os.close(canonical_segments)
            os.close(canonical_root)

    def _read_retention_manifest_chain(
        self,
    ) -> tuple[
        tuple[SegmentManifestV1, ...],
        tuple[bytes, ...],
    ]:
        manifests: list[SegmentManifestV1] = []
        raw_by_hash: dict[str, bytes] = {}
        for name in sorted(os.listdir(self._manifests_descriptor)):
            match = _MANIFEST_NAME.fullmatch(name)
            if match is None:
                raise EvidenceCorrupt(
                    f"unexpected retention manifest artifact: {name}"
                )
            raw = _read_regular_at(
                self._manifests_descriptor,
                name,
                self._manifests_path / name,
                MAX_CONTRACT_FILE_BYTES,
            )
            try:
                manifest = decode_strict(
                    raw,
                    SegmentManifestV1,
                    MAX_CONTRACT_FILE_BYTES,
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise EvidenceCorrupt(
                    "retention manifest is not exact canonical authority"
                ) from error
            if (
                raw != canonical_json(manifest)
                or name != f"{manifest.segment_id}.json"
                or manifest.manifest_sha256 in raw_by_hash
            ):
                raise EvidenceCorrupt(
                    "retention manifest namespace is not canonical"
                )
            manifests.append(manifest)
            raw_by_hash[manifest.manifest_sha256] = raw
        chain = tuple(self._order_manifest_chain(manifests))
        canonical = tuple(
            raw_by_hash[manifest.manifest_sha256]
            for manifest in chain
        )
        in_memory = tuple(
            canonical_json(manifest)
            for manifest in self._manifests
        )
        if canonical != in_memory:
            raise EvidenceCorrupt(
                "retention manifest authority differs from recovered chain"
            )
        return chain, canonical

    def _require_retention_payload_namespace(
        self,
        chain: tuple[SegmentManifestV1, ...],
    ) -> None:
        expected: dict[str, set[str]] = {}
        for manifest in chain:
            parts = manifest.segment_relative_path.split("/")
            if len(parts) != 3 or parts[0] != "segments":
                raise EvidenceCorrupt(
                    "retention manifest payload path is not canonical"
                )
            date_name, closed_name = parts[1], parts[2]
            expected.setdefault(date_name, set()).add(closed_name)

        actual_dates = tuple(sorted(os.listdir(self._segments_descriptor)))
        for date_name in actual_dates:
            try:
                if (
                    not _DATE_NAME.fullmatch(date_name)
                    or date.fromisoformat(date_name).isoformat()
                    != date_name
                ):
                    raise ValueError
            except ValueError as error:
                raise EvidenceCorrupt(
                    f"unexpected retention segment directory: {date_name}"
                ) from error
            descriptor = self._date_descriptor(date_name)
            actual_names = set(os.listdir(descriptor))
            expected_names = expected.get(date_name, set())
            if actual_names != expected_names:
                raise EvidenceCorrupt(
                    "retention payload namespace differs from manifests"
                )
        if set(expected) - set(actual_dates):
            raise EvidenceCorrupt(
                "retention manifest payload directory is missing"
            )

    def _retention_scanned_record(
        self,
        record: StoredEvidenceRecord,
        verifier: EnvelopeVerifier,
    ) -> EventEnvelopeV1:
        if type(record) is not StoredEvidenceRecord:
            raise EvidenceCorrupt(
                "retention payload produced an inexact record"
            )
        try:
            resolved = self.resolve_authenticated_ref(record.ref)
            same_record = _same_exact_coverage_record(
                resolved,
                record,
            )
            envelope = decode_strict(
                record.canonical_envelope,
                EventEnvelopeV1,
                MAX_EVIDENCE_RECORD_BYTES,
            )
        except (EvidenceStoreError, TypeError, ValueError) as error:
            raise EvidenceCorrupt(
                "retention payload record is not authenticated"
            ) from error
        accepted = verifier._authority.accepted.get(
            record.ref.source_sequence
        )
        if (
            same_record is not True
            or canonical_json(envelope.model_dump(exclude_none=True))
            != record.canonical_envelope
            or accepted is None
            or accepted.canonical != record.canonical_envelope
            or accepted.evidence_priority != record.priority.value
            or record.ref != resolved.ref
            or accepted.evidence_ref is not resolved.ref
            or verifier.accepted_ref(record.ref.source_sequence)
            is not resolved.ref
        ):
            raise EvidenceCorrupt(
                "retention payload record differs from verifier authority"
            )
        return envelope

    def _verify_retention_payload(
        self,
        manifest: SegmentManifestV1,
    ) -> _SegmentScan:
        _, date_name, closed_name = (
            manifest.segment_relative_path.split("/")
        )
        try:
            return self._verify_segment_against_manifest(
                self._date_descriptor(date_name),
                closed_name,
                self.root / manifest.segment_relative_path,
                manifest,
            )
        except EvidenceCorrupt as error:
            raise EvidenceCorrupt(
                "retention segment payload verification failed"
            ) from error

    def _retention_prior_controls(
        self,
        verifier: EnvelopeVerifier,
        *,
        through_sequence: int,
    ) -> tuple[
        tuple[AcceptedRetentionTombstone, ...],
        tuple[AcceptedRetentionBlocked, ...],
    ]:
        from agmind_immune.evidence.retention import (
            _freeze_accepted_retention_blocked,
            _freeze_accepted_retention_tombstone,
        )

        accepted_tombstones: list[AcceptedRetentionTombstone] = []
        accepted_blocked: list[AcceptedRetentionBlocked] = []
        for record in self.iter_authenticated_records(
            after=0,
            through=through_sequence,
        ):
            envelope = self._retention_scanned_record(
                record,
                verifier,
            )
            if envelope.event_type == "retention_tombstone":
                if record.priority is not EvidencePriority.PROTECTED:
                    raise EvidenceCorrupt(
                        "retention tombstone is not protected evidence"
                    )
                try:
                    request = RetentionTombstoneV2.model_validate(
                        envelope.normalized_fields,
                        strict=True,
                    )
                except (TypeError, ValueError, ValidationError) as error:
                    raise EvidenceCorrupt(
                        "authenticated retention tombstone is invalid"
                    ) from error
                if (
                    request.model_dump(mode="python")
                    != envelope.normalized_fields
                ):
                    raise EvidenceCorrupt(
                        "authenticated retention tombstone is not exact"
                    )
                accepted_tombstones.append(
                    _freeze_accepted_retention_tombstone(
                        sequence=record.ref.source_sequence,
                        event_id=record.ref.event_id,
                        content_sha256=record.ref.content_sha256,
                        request=request,
                    )
                )
            elif (
                envelope.event_type
                == "retention_blocked_priority_evidence"
            ):
                if record.priority is not EvidencePriority.PROTECTED:
                    raise EvidenceCorrupt(
                        "retention blocked record is not protected evidence"
                    )
                try:
                    blocked = RetentionBlockedV1.model_validate(
                        envelope.normalized_fields,
                        strict=True,
                    )
                except (TypeError, ValueError, ValidationError) as error:
                    raise EvidenceCorrupt(
                        "authenticated retention blocked record is invalid"
                    ) from error
                if (
                    blocked.model_dump(mode="python")
                    != envelope.normalized_fields
                ):
                    raise EvidenceCorrupt(
                        "authenticated retention blocked record is not exact"
                    )
                accepted_blocked.append(
                    _freeze_accepted_retention_blocked(
                        sequence=record.ref.source_sequence,
                        event_id=record.ref.event_id,
                        content_sha256=record.ref.content_sha256,
                        request=blocked,
                    )
                )
        return tuple(accepted_tombstones), tuple(accepted_blocked)

    def _retention_prior_tombstones(
        self,
        verifier: EnvelopeVerifier,
        *,
        through_sequence: int,
    ) -> tuple[AcceptedRetentionTombstone, ...]:
        prior, _blocked = self._retention_prior_controls(
            verifier,
            through_sequence=through_sequence,
        )
        return prior

    def _freeze_retention_snapshot(
        self,
        clock: CoreClockSample,
        *,
        _factory: object,
    ) -> RetentionSnapshot:
        """Settle and JIT-reverify one immutable store-issued snapshot."""
        from agmind_immune.evidence.retention import (
            _freeze_retention_fact,
            _freeze_retention_record,
            _freeze_retention_snapshot,
            _prior_index_commitment,
            _snapshot_binding,
        )

        if (
            _factory is not _RETENTION_PROOF_FACTORY
            or type(self) is not SegmentStore
        ):
            raise TypeError(
                "retention snapshot requires the exact store factory"
            )
        if type(clock) is not CoreClockSample:
            raise TypeError(
                "retention snapshot requires an exact Core clock sample"
            )
        verifier = self._require_authenticated_recovered()
        status_before = self.status()
        authority_before = verifier._authority
        generation_before = authority_before.generation
        transient_before = verifier._repair_transient_generation
        accepted_before = _retention_accepted_authority_binding(verifier)
        if (
            type(status_before) is not EvidenceStatus
            or not status_before.healthy
            or not status_before.key_healthy
            or status_before.repair_pending
            or self._repair_mode
            or self._retention_state_namespace_uncertain
            or verifier._staged
            or verifier._authorizations
        ):
            raise EvidenceSealError(
                "retention snapshot requires a healthy ordinary lifecycle"
            )
        self._require_retention_directory_bindings()
        self.flush_security_boundary()
        self._require_retention_directory_bindings()
        chain_before, canonical_before = (
            self._read_retention_manifest_chain()
        )
        for manifest in chain_before:
            _, date_name, _closed_name = (
                manifest.segment_relative_path.split("/")
            )
            self._date_descriptor(date_name)
        self._require_retention_directory_bindings()
        self._require_retention_payload_namespace(chain_before)

        facts: list[FrozenRetentionFact] = []
        payload_identities: list[_FileIdentity] = []
        for manifest in chain_before:
            scan = self._verify_retention_payload(manifest)
            records: list[FrozenRetentionRecord] = []
            for record in scan.records:
                envelope = self._retention_scanned_record(
                    record,
                    verifier,
                )
                records.append(
                    _freeze_retention_record(
                        event_type=envelope.event_type,
                        evidence_priority=record.priority.value,
                        source_sequence=record.ref.source_sequence,
                        event_id=record.ref.event_id,
                        content_sha256=record.ref.content_sha256,
                        frame_size=record.ref.frame_size,
                    )
                )
            facts.append(
                _freeze_retention_fact(
                    manifest=manifest,
                    records=tuple(records),
                    original_device=scan.identity.device,
                    original_inode=scan.identity.inode,
                )
            )
            payload_identities.append(scan.identity)

        prior, prior_blocked = self._retention_prior_controls(
            verifier,
            through_sequence=status_before.evidence_head,
        )
        _prior_index_commitment(prior)
        snapshot = _freeze_retention_snapshot(
            facts=tuple(facts),
            clock=clock,
            prior_tombstones=prior,
            prior_blocked=prior_blocked,
            prior_index_through_sequence=status_before.evidence_head,
        )
        binding_digest = _snapshot_binding(snapshot)

        chain_after, canonical_after = (
            self._read_retention_manifest_chain()
        )
        self._require_retention_payload_namespace(chain_after)
        if len(chain_after) != len(payload_identities):
            raise EvidenceSealError(
                "retention snapshot authority changed during JIT verification"
            )
        for manifest, identity in zip(
            chain_after,
            payload_identities,
            strict=True,
        ):
            _, date_name, closed_name = (
                manifest.segment_relative_path.split("/")
            )
            _validate_identity(
                _regular_stat_at(
                    self._date_descriptor(date_name),
                    closed_name,
                    self.root / manifest.segment_relative_path,
                ),
                identity,
                self.root / manifest.segment_relative_path,
            )
        self._require_retention_directory_bindings()
        status_after = self.status()
        if (
            self._active is not None
            or chain_after != chain_before
            or canonical_after != canonical_before
            or status_after != status_before
            or verifier is not self._bound_verifier
            or verifier._authority is not authority_before
            or verifier._authority.generation != generation_before
            or verifier._repair_transient_generation
            != transient_before
            or not _same_retention_accepted_authority(
                verifier,
                accepted_before,
            )
            or verifier._staged
            or verifier._authorizations
        ):
            raise EvidenceSealError(
                "retention snapshot authority changed during JIT verification"
            )
        self._retention_snapshot_binding = _RetentionSnapshotBinding(
            snapshot=snapshot,
            snapshot_binding=binding_digest,
            lifecycle_identity=self._lifecycle_identity,
            verifier=verifier,
            verifier_authority=authority_before,
            verifier_generation=generation_before,
            transient_generation=transient_before,
            accepted_authority=accepted_before,
            status=status_after,
            manifest_canonical=canonical_after,
            payload_identities=tuple(payload_identities),
        )
        return snapshot

    def _require_retention_snapshot(
        self,
        snapshot: object,
    ) -> _RetentionSnapshotBinding:
        from agmind_immune.evidence.retention import (
            RetentionSnapshot,
            _snapshot_binding,
        )

        if type(snapshot) is not RetentionSnapshot:
            raise TypeError(
                "retention proof requires an exact retention snapshot"
            )
        binding = self._retention_snapshot_binding
        if (
            binding is None
            or binding.snapshot is not snapshot
            or binding.lifecycle_identity is not self._lifecycle_identity
            or self._closed
        ):
            raise EvidenceSealError(
                "retention snapshot is stale, foreign, or unregistered"
            )
        digest = _snapshot_binding(snapshot)
        verifier = self._require_authenticated_recovered()
        if (
            digest != binding.snapshot_binding
            or verifier is not binding.verifier
            or verifier is not self._bound_verifier
            or verifier._authority is not binding.verifier_authority
            or verifier._authority.generation
            != binding.verifier_generation
            or verifier._repair_transient_generation
            != binding.transient_generation
            or not _same_retention_accepted_authority(
                verifier,
                binding.accepted_authority,
            )
            or verifier._staged
            or verifier._authorizations
            or self.status() != binding.status
            or self._active is not None
        ):
            raise EvidenceSealError(
                "retention snapshot lost exact live authority"
            )
        self._require_retention_directory_bindings()
        chain, canonical = self._read_retention_manifest_chain()
        if canonical != binding.manifest_canonical:
            raise EvidenceSealError(
                "retention snapshot manifest authority changed"
            )
        self._require_retention_payload_namespace(chain)
        if len(chain) != len(binding.payload_identities):
            raise EvidenceSealError(
                "retention snapshot payload authority changed"
            )
        for manifest, identity in zip(
            chain,
            binding.payload_identities,
            strict=True,
        ):
            scan = self._verify_retention_payload(manifest)
            if scan.identity != identity:
                raise EvidenceSealError(
                    "retention snapshot payload authority changed"
                )
            for record in scan.records:
                self._retention_scanned_record(record, verifier)
        self._require_retention_directory_bindings()
        if (
            _snapshot_binding(snapshot) != binding.snapshot_binding
            or self.status() != binding.status
            or verifier._authority is not binding.verifier_authority
            or verifier._repair_transient_generation
            != binding.transient_generation
            or not _same_retention_accepted_authority(
                verifier,
                binding.accepted_authority,
            )
            or verifier._staged
            or verifier._authorizations
        ):
            raise EvidenceSealError(
                "retention snapshot authority changed during revalidation"
            )
        return binding

    def _authenticate_retention_tombstone(
        self,
        journal: RetentionStateJournal,
        snapshot: RetentionSnapshot,
        target_ref: EvidenceRef,
        *,
        _factory: object,
    ) -> AuthenticatedRetentionTombstone:
        from agmind_immune.evidence.retention import (
            _authenticate_store_retention_tombstone,
        )

        if (
            _factory is not _RETENTION_PROOF_FACTORY
            or type(self) is not SegmentStore
        ):
            raise TypeError(
                "retention proof authentication requires the exact factory"
            )
        return _authenticate_store_retention_tombstone(
            self,
            journal,
            snapshot,
            target_ref,
            _factory=_factory,
        )

    def _validate_authenticated_retention_tombstone(
        self,
        capability: object,
        binding: _AuthenticatedRetentionTombstoneBinding,
        *,
        allow_in_progress: bool = False,
    ) -> Literal[
        "evidence_appended",
        "retention_unlink_in_progress",
    ]:
        from agmind_immune.coverage.state import CoverageState
        from agmind_immune.evidence.retention import (
            _AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY,
            _AUTHENTICATED_RETENTION_UNLINK_COMPLETION_FACTORY,
            RetentionStateJournal,
            _retention_execution_states,
            decode_retention_state,
            encode_retention_state,
        )

        try:
            base_state = decode_retention_state(binding.state_raw)
            in_progress, uncertain, completed = (
                _retention_execution_states(base_state)
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise EvidenceSealError(
                "retention proof has invalid execution-state authority"
            ) from error
        if (
            binding.capability is not capability
            or getattr(capability, "_factory_marker", None)
            is not _AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY
            or type(binding.journal) is not RetentionStateJournal
            or binding.journal_identity is not binding.journal._identity
            or type(binding.state_raw) is not bytes
            or type(binding.unlink_in_progress_state_raw) is not bytes
            or type(binding.commit_uncertain_state_raw) is not bytes
            or type(binding.completed_state_raw) is not bytes
            or getattr(binding.completion_capability, "_factory_marker", None)
            is not _AUTHENTICATED_RETENTION_UNLINK_COMPLETION_FACTORY
            or encode_retention_state(in_progress)
            != binding.unlink_in_progress_state_raw
            or encode_retention_state(uncertain)
            != binding.commit_uncertain_state_raw
            or encode_retention_state(completed)
            != binding.completed_state_raw
            or type(binding.target_ref) is not EvidenceRef
            or type(binding.coverage) is not CoverageState
            or type(binding.verifier) is not EnvelopeVerifier
            or type(binding.status) is not EvidenceStatus
            or binding.lifecycle_identity is not self._lifecycle_identity
            or not _same_retention_accepted_authority(
                binding.verifier,
                binding.accepted_authority,
            )
        ):
            raise EvidenceSealError(
                "retention proof is not the exact issued store authority"
            )
        journal = binding.journal
        authority = journal._authority
        coverage = binding.coverage
        verifier = self._require_authenticated_recovered()
        current_raw = journal._raw
        if current_raw == binding.state_raw:
            current_phase: Literal[
                "evidence_appended",
                "retention_unlink_in_progress",
            ] = "evidence_appended"
        elif (
            allow_in_progress
            and current_raw == binding.unlink_in_progress_state_raw
        ):
            current_phase = "retention_unlink_in_progress"
        else:
            raise EvidenceSealError(
                "retention proof lost its exact execution-state authority"
            )
        if (
            type(authority) is not _RetentionStateAuthority
            or authority._store is not self
            or authority._lifecycle_identity
            is not self._lifecycle_identity
            or authority._retention_journal is not journal
            or self._retention_state_authority is not authority
            or authority.read_retention_state_bytes() != current_raw
            or type(coverage) is not CoverageState
            or self._coverage_state_owner is not coverage
            or coverage._evidence is not self
            or coverage._lifecycle_identity
            is not self._lifecycle_identity
            or coverage._snapshot is not binding.coverage_snapshot
            or coverage._capability_token is not binding.coverage_token
            or coverage._healthy is not True
            or coverage._closed is not False
            or verifier is not binding.verifier
            or verifier is not self._bound_verifier
            or verifier._authority is not binding.verifier_authority
            or verifier._authority.generation
            != binding.verifier_generation
            or verifier._repair_transient_generation
            != binding.transient_generation
            or not _same_retention_accepted_authority(
                verifier,
                binding.accepted_authority,
            )
            or verifier._staged
            or verifier._authorizations
            or self.status() != binding.status
        ):
            raise EvidenceSealError(
                "retention proof lost its exact registered authority"
            )
        self._require_retention_snapshot(binding.snapshot)
        try:
            resolved = self.resolve_authenticated_ref(
                binding.target_ref
            )
            self._validate_coverage_state_owner(
                coverage,
                self._lifecycle_identity,
                reducer_head=coverage._snapshot.head_ref,
            )
        except EvidenceStoreError as error:
            raise EvidenceSealError(
                "retention proof target or coverage is no longer authenticated"
            ) from error
        if (
            resolved.ref is not binding.target_ref
            or coverage._snapshot.head_sequence
            != binding.status.evidence_head
            or coverage._snapshot.head_ref is None
            or binding.target_ref.source_sequence
            > coverage._snapshot.head_sequence
        ):
            raise EvidenceSealError(
                "retention proof target or coverage authority changed"
            )
        self._require_retention_snapshot(binding.snapshot)
        return current_phase

    def _register_authenticated_retention_tombstone(
        self,
        capability: object,
        *,
        journal: object,
        journal_identity: object,
        state_raw: bytes,
        unlink_in_progress_state_raw: bytes,
        commit_uncertain_state_raw: bytes,
        completed_state_raw: bytes,
        completion_capability: object,
        snapshot: object,
        target_ref: object,
        coverage: object,
        coverage_snapshot: object,
        coverage_token: object,
        verifier: object,
        verifier_authority: object,
        verifier_generation: int,
        transient_generation: int,
        status: object,
        _factory: object,
    ) -> None:
        from agmind_immune.coverage.state import CoverageState
        from agmind_immune.evidence.retention import (
            _AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY,
            AuthenticatedRetentionTombstone,
            RetentionStateJournal,
        )

        if (
            _factory is not _RETENTION_PROOF_FACTORY
            or type(self) is not SegmentStore
        ):
            raise TypeError(
                "retention proof registration requires the exact factory"
            )
        if type(capability) is not AuthenticatedRetentionTombstone:
            raise EvidenceSealError(
                "retention proof registration requires exact issued authority"
            )
        if (
            getattr(capability, "_factory_marker", None)
            is not _AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY
            or type(journal) is not RetentionStateJournal
            or journal_identity is not journal._identity
            or type(state_raw) is not bytes
            or type(unlink_in_progress_state_raw) is not bytes
            or type(commit_uncertain_state_raw) is not bytes
            or type(completed_state_raw) is not bytes
            or type(target_ref) is not EvidenceRef
            or type(coverage) is not CoverageState
            or type(verifier) is not EnvelopeVerifier
            or type(verifier_generation) is not int
            or type(transient_generation) is not int
            or type(status) is not EvidenceStatus
        ):
            raise EvidenceSealError(
                "retention proof registration requires exact issued authority"
            )
        snapshot_binding = self._require_retention_snapshot(snapshot)
        binding = _AuthenticatedRetentionTombstoneBinding(
            capability=capability,
            journal=journal,
            journal_identity=journal_identity,
            snapshot=snapshot,
            lifecycle_identity=self._lifecycle_identity,
            state_raw=state_raw,
            unlink_in_progress_state_raw=unlink_in_progress_state_raw,
            commit_uncertain_state_raw=commit_uncertain_state_raw,
            completed_state_raw=completed_state_raw,
            completion_capability=completion_capability,
            target_ref=target_ref,
            coverage=coverage,
            coverage_snapshot=coverage_snapshot,
            coverage_token=coverage_token,
            verifier=verifier,
            verifier_authority=verifier_authority,
            verifier_generation=verifier_generation,
            transient_generation=transient_generation,
            accepted_authority=snapshot_binding.accepted_authority,
            status=status,
        )
        with self._retention_tombstone_lock:
            if self._authenticated_retention_tombstone is not None:
                raise EvidenceSealError(
                    "an authenticated retention tombstone is already registered"
                )
            self._validate_authenticated_retention_tombstone(
                capability,
                binding,
            )
            self._authenticated_retention_tombstone = binding

    def _consume_authenticated_retention_tombstone(
        self,
        capability: object,
        *,
        _factory: object,
    ) -> None:
        from agmind_immune.evidence.retention import (
            _AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY,
            AuthenticatedRetentionTombstone,
        )

        if (
            _factory is not _RETENTION_PROOF_FACTORY
            or type(self) is not SegmentStore
        ):
            raise TypeError(
                "retention proof consumption requires the exact factory"
            )
        if (
            type(capability) is not AuthenticatedRetentionTombstone
            or getattr(capability, "_factory_marker", None)
            is not _AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY
        ):
            raise EvidenceSealError(
                "retention proof is not the exact registered store authority"
            )
        with self._retention_tombstone_lock:
            binding = self._authenticated_retention_tombstone
            if binding is None or binding.capability is not capability:
                raise EvidenceSealError(
                    "retention proof is not the exact registered "
                    "store authority"
                )
            self._authenticated_retention_tombstone = None
        self._validate_authenticated_retention_tombstone(
            capability,
            binding,
        )

    def _prepare_retention_unlink_lease(
        self,
        binding: _AuthenticatedRetentionTombstoneBinding,
    ) -> _RetentionUnlinkLease:
        from agmind_immune.evidence.retention import (
            RetentionStateEntryV1,
            RetentionStateV1,
            decode_retention_state,
        )

        state = decode_retention_state(binding.state_raw)
        snapshot_binding = self._retention_snapshot_binding
        if (
            type(state) is not RetentionStateV1
            or not state.entries
            or snapshot_binding is None
            or snapshot_binding.snapshot is not binding.snapshot
        ):
            raise EvidenceSealError(
                "retention unlink lacks exact selected payload authority"
            )
        self._require_retention_directory_bindings()
        chain, canonical = self._read_retention_manifest_chain()
        if canonical != snapshot_binding.manifest_canonical:
            raise EvidenceCorrupt(
                "retention unlink manifest authority changed"
            )
        by_hash = {
            manifest.manifest_sha256: manifest for manifest in chain
        }
        if len(by_hash) != len(chain):
            raise EvidenceCorrupt(
                "retention unlink manifest authority is not unique"
            )

        directory_builders: dict[
            str,
            tuple[
                int,
                tuple[int, int, int, int],
                list[_HeldRetentionPayload],
            ],
        ] = {}
        payloads: list[_HeldRetentionPayload] = []
        seen_paths: set[str] = set()
        try:
            for state_entry in state.entries:
                if type(state_entry) is not RetentionStateEntryV1:
                    raise EvidenceCorrupt(
                        "retention unlink state entry is not exact"
                    )
                relative_path = state_entry.segment_relative_path
                if relative_path in seen_paths:
                    raise EvidenceCorrupt(
                        "retention unlink state repeats a payload path"
                    )
                seen_paths.add(relative_path)
                try:
                    manifest = by_hash[state_entry.manifest_sha256]
                except KeyError as error:
                    raise EvidenceCorrupt(
                        "retention unlink state manifest is absent"
                    ) from error
                parts = relative_path.split("/")
                if len(parts) != 3 or parts[0] != "segments":
                    raise EvidenceCorrupt(
                        "retention unlink payload path is not canonical"
                    )
                date_name, basename = parts[1], parts[2]
                if (
                    manifest.manifest_sha256
                    != state_entry.manifest_sha256
                    or manifest.segment_id != state_entry.segment_id
                    or manifest.segment_relative_path != relative_path
                    or manifest.segment_size_bytes
                    != state_entry.segment_size_bytes
                    or manifest.segment_sha256
                    != state_entry.segment_sha256
                    or manifest.evidence_priority != "routine"
                ):
                    raise EvidenceCorrupt(
                        "retention unlink state differs from immutable manifest"
                    )
                builder = directory_builders.get(date_name)
                if builder is None:
                    retained = self._date_descriptor(date_name)
                    descriptor = -1
                    try:
                        descriptor = os.dup(retained)
                        display_directory = self._segments_path / date_name
                        directory_identity = (
                            _directory_authority_identity(
                                descriptor,
                                display_directory,
                                exact_mode=True,
                            )
                        )
                        if (
                            directory_identity
                            != _directory_authority_identity(
                                retained,
                                display_directory,
                                exact_mode=True,
                            )
                        ):
                            raise EvidenceCorrupt(
                                "retention unlink date directory changed"
                            )
                        builder = (
                            descriptor,
                            directory_identity,
                            [],
                        )
                        directory_builders[date_name] = builder
                    except BaseException:
                        if (
                            descriptor >= 0
                            and directory_builders.get(date_name) is None
                        ):
                            os.close(descriptor)
                        raise
                directory_descriptor = builder[0]
                display_path = self.root / relative_path
                descriptor = -1
                held: _HeldRetentionPayload | None = None
                try:
                    descriptor, opened = _open_regular_at(
                        directory_descriptor,
                        basename,
                        display_path,
                        maximum=MAX_SEGMENT_BYTES,
                    )
                    payload_identity = _file_identity(opened)
                    held = _HeldRetentionPayload(
                        state_entry=state_entry,
                        manifest=manifest,
                        date_name=date_name,
                        basename=basename,
                        display_path=display_path,
                        descriptor=descriptor,
                        identity=payload_identity,
                    )
                    payloads.append(held)
                except BaseException:
                    if descriptor >= 0 and (
                        held is None
                        or not any(
                            candidate is held for candidate in payloads
                        )
                    ):
                        os.close(descriptor)
                    raise
                assert held is not None
                builder[2].append(held)
                if (
                    payload_identity.device
                    != state_entry.original_device
                    or payload_identity.inode != state_entry.original_inode
                    or payload_identity.size
                    != state_entry.segment_size_bytes
                ):
                    raise EvidenceCorrupt(
                        "retention unlink payload identity changed"
                    )
                _bind_held_source(
                    directory_descriptor,
                    basename,
                    display_path,
                    descriptor=descriptor,
                    identity=payload_identity,
                )
                scan = self._scan_held_segment_descriptor(
                    descriptor,
                    payload_identity,
                    display_path,
                    allow_torn=False,
                )
                verified = self._validate_segment_scan_against_manifest(
                    scan,
                    basename,
                    display_path,
                    manifest,
                )
                if (
                    verified.identity != payload_identity
                    or verified.sha256 != state_entry.segment_sha256
                ):
                    raise EvidenceCorrupt(
                        "retention unlink held payload is not manifest-exact"
                    )
                for record in verified.records:
                    envelope = self._retention_scanned_record(
                        record,
                        binding.verifier,
                    )
                    if (
                        record.priority is not EvidencePriority.ROUTINE
                        or envelope.event_type != "falco_connect"
                    ):
                        raise EvidenceCorrupt(
                            "retention unlink payload is not removable routine evidence"
                        )
                _bind_held_source(
                    directory_descriptor,
                    basename,
                    display_path,
                    descriptor=descriptor,
                    identity=payload_identity,
                )
            groups = tuple(
                _HeldRetentionDirectory(
                    date_name=date_name,
                    display_path=self._segments_path / date_name,
                    descriptor=descriptor,
                    identity=identity,
                    payloads=tuple(group_payloads),
                )
                for date_name, (
                    descriptor,
                    identity,
                    group_payloads,
                ) in directory_builders.items()
            )
            lease = _RetentionUnlinkLease(
                binding=binding,
                groups=groups,
            )
            self._bind_retention_unlink_lease(lease)
            return lease
        except BaseException as error:
            close_error: BaseException | None = None
            for payload in payloads:
                descriptor = payload.descriptor
                payload.descriptor = -1
                if descriptor < 0:
                    continue
                try:
                    os.close(descriptor)
                except OSError as candidate:
                    if close_error is None:
                        close_error = candidate
            for descriptor, _identity, _payloads in directory_builders.values():
                try:
                    os.close(descriptor)
                except OSError as candidate:
                    if close_error is None:
                        close_error = candidate
            if close_error is not None:
                error.add_note(
                    f"retention unlink descriptor cleanup failed: {close_error}"
                )
            raise

    def _require_retention_unlink_directory(
        self,
        group: _HeldRetentionDirectory,
    ) -> None:
        if group.descriptor < 0:
            raise EvidenceCorrupt(
                "retention unlink date descriptor is already closed"
            )
        self._require_retention_directory_bindings()
        retained = self._date_descriptor(group.date_name)
        if (
            _directory_authority_identity(
                group.descriptor,
                group.display_path,
                exact_mode=True,
            )
            != group.identity
            or _directory_authority_identity(
                retained,
                group.display_path,
                exact_mode=True,
            )
            != group.identity
        ):
            raise EvidenceCorrupt(
                "retention unlink date directory lost canonical authority"
            )

    def _bind_retention_unlink_lease(
        self,
        lease: _RetentionUnlinkLease,
    ) -> None:
        if lease.binding.lifecycle_identity is not self._lifecycle_identity:
            raise EvidenceSealError(
                "retention unlink lease is outside the store lifecycle"
            )
        for group in lease.groups:
            self._require_retention_unlink_directory(group)
            for payload in group.payloads:
                if payload.descriptor < 0:
                    raise EvidenceCorrupt(
                        "retention unlink payload descriptor is already closed"
                    )
                _bind_held_source(
                    group.descriptor,
                    payload.basename,
                    payload.display_path,
                    descriptor=payload.descriptor,
                    identity=payload.identity,
                )
                digest, identity = _hash_held_descriptor(
                    payload.descriptor,
                    payload.identity,
                    payload.display_path,
                )
                if (
                    digest != payload.manifest.segment_sha256
                    or identity != payload.identity
                ):
                    raise EvidenceCorrupt(
                        "retention unlink held payload bytes changed"
                    )
                _bind_held_source(
                    group.descriptor,
                    payload.basename,
                    payload.display_path,
                    descriptor=payload.descriptor,
                    identity=payload.identity,
                )

    @staticmethod
    def _close_retention_unlink_lease(
        lease: _RetentionUnlinkLease,
    ) -> None:
        close_error: OSError | None = None
        for group in lease.groups:
            for payload in group.payloads:
                descriptor = payload.descriptor
                payload.descriptor = -1
                if descriptor < 0:
                    continue
                try:
                    os.close(descriptor)
                except OSError as error:
                    if close_error is None:
                        close_error = error
            descriptor = group.descriptor
            group.descriptor = -1
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as error:
                    if close_error is None:
                        close_error = error
        if close_error is not None:
            raise EvidenceCorrupt(
                "retention unlink held descriptor close is uncertain"
            ) from close_error

    @staticmethod
    def _require_retention_unlinked_payload(
        group: _HeldRetentionDirectory,
        payload: _HeldRetentionPayload,
    ) -> None:
        current = os.fstat(payload.descriptor)
        expected = payload.identity
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != expected.device
            or current.st_ino != expected.inode
            or current.st_size != expected.size
            or current.st_mode != expected.mode
            or current.st_uid != expected.owner
            or current.st_nlink != 0
            or _entry_stat_at(group.descriptor, payload.basename)
            is not None
        ):
            raise EvidenceCorrupt(
                "retention unlink payload postcondition is uncertain"
            )

    def _require_retention_post_unlink_paths(
        self,
        binding: _AuthenticatedRetentionTombstoneBinding,
        selected: frozenset[str],
        completion: (
            _AuthenticatedRetentionUnlinkCompletionBinding | None
        ) = None,
    ) -> tuple[bytes, ...]:
        snapshot_binding = self._retention_snapshot_binding
        if (
            snapshot_binding is None
            or snapshot_binding.snapshot is not binding.snapshot
            or not selected
        ):
            raise EvidenceSealError(
                "retention unlink snapshot authority disappeared"
            )
        self._require_retention_directory_bindings()
        chain, canonical = self._read_retention_manifest_chain()
        if canonical != snapshot_binding.manifest_canonical:
            raise EvidenceCorrupt(
                "retention unlink changed immutable manifests"
            )
        chain_paths = {
            manifest.segment_relative_path for manifest in chain
        }
        if not selected.issubset(chain_paths):
            raise EvidenceCorrupt(
                "retention unlink selected paths left the manifest chain"
            )
        expected: dict[str, set[str]] = {}
        for manifest in chain:
            parts = manifest.segment_relative_path.split("/")
            if len(parts) != 3 or parts[0] != "segments":
                raise EvidenceCorrupt(
                    "retention manifest payload path is not canonical"
                )
            date_name, basename = parts[1], parts[2]
            expected.setdefault(date_name, set())
            if manifest.segment_relative_path not in selected:
                expected[date_name].add(basename)
                scan = self._verify_retention_payload(manifest)
                for record in scan.records:
                    self._retention_scanned_record(
                        record,
                        binding.verifier,
                    )
        actual_dates = tuple(sorted(os.listdir(self._segments_descriptor)))
        for date_name in actual_dates:
            try:
                if (
                    not _DATE_NAME.fullmatch(date_name)
                    or date.fromisoformat(date_name).isoformat()
                    != date_name
                ):
                    raise ValueError
            except ValueError as error:
                raise EvidenceCorrupt(
                    f"unexpected retention segment directory: {date_name}"
                ) from error
            actual_names = set(
                os.listdir(self._date_descriptor(date_name))
            )
            if actual_names != expected.get(date_name, set()):
                raise EvidenceCorrupt(
                    "retention post-unlink payload namespace is not exact"
                )
        if set(expected) != set(actual_dates):
            raise EvidenceCorrupt(
                "retention post-unlink date namespace is not exact"
            )
        verifier = self._require_authenticated_recovered()
        coverage = binding.coverage
        expected_status = (
            binding.status if completion is None else completion.status
        )
        expected_authority = (
            binding.verifier_authority
            if completion is None
            else completion.verifier_authority
        )
        expected_generation = (
            binding.verifier_generation
            if completion is None
            else completion.verifier_generation
        )
        expected_transient_generation = (
            binding.transient_generation
            if completion is None
            else completion.transient_generation
        )
        expected_accepted_authority = (
            binding.accepted_authority
            if completion is None
            else completion.accepted_authority
        )
        if (
            self.status() != expected_status
            or self._active is not None
            or verifier is not binding.verifier
            or verifier._authority is not expected_authority
            or verifier._authority.generation
            != expected_generation
            or verifier._repair_transient_generation
            != expected_transient_generation
            or not _same_retention_accepted_authority(
                verifier,
                expected_accepted_authority,
            )
            or self._coverage_state_owner is not coverage
            or getattr(coverage, "_snapshot", None)
            is not binding.coverage_snapshot
            or getattr(coverage, "_capability_token", None)
            is not binding.coverage_token
            or getattr(coverage, "_healthy", None) is not True
            or getattr(coverage, "_closed", None) is not False
        ):
            raise EvidenceSealError(
                "retention unlink changed live authenticated authority"
            )
        self._require_retention_directory_bindings()
        return canonical

    def _require_retention_post_unlink_namespace(
        self,
        lease: _RetentionUnlinkLease,
    ) -> tuple[bytes, ...]:
        return self._require_retention_post_unlink_paths(
            lease.binding,
            frozenset(
                payload.manifest.segment_relative_path
                for group in lease.groups
                for payload in group.payloads
            ),
        )

    def _attempt_retention_commit_uncertain(
        self,
        binding: _AuthenticatedRetentionTombstoneBinding,
    ) -> None:
        from agmind_immune.evidence.retention import (
            RetentionStateJournal,
            decode_retention_state,
        )

        journal = binding.journal
        if type(journal) is not RetentionStateJournal:
            raise EvidenceSealError(
                "retention uncertainty lost its exact journal"
            )
        if journal._raw == binding.commit_uncertain_state_raw:
            journal._prove_publication(binding.commit_uncertain_state_raw)
            return
        if journal._raw != binding.unlink_in_progress_state_raw:
            raise EvidenceSealError(
                "retention uncertainty lost durable in-progress intent"
            )
        journal._transition(
            decode_retention_state(binding.commit_uncertain_state_raw)
        )

    def _execute_authenticated_retention_unlink(
        self,
        capability: object,
        *,
        _factory: object,
    ) -> AuthenticatedRetentionUnlinkCompletion:
        from agmind_immune.evidence.retention import (
            _AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY,
            AuthenticatedRetentionTombstone,
            AuthenticatedRetentionUnlinkCompletion,
            RetentionStateJournal,
            decode_retention_state,
        )

        if (
            _factory is not _RETENTION_PROOF_FACTORY
            or type(self) is not SegmentStore
        ):
            raise TypeError(
                "retention unlink requires the exact private factory"
            )
        if (
            type(capability) is not AuthenticatedRetentionTombstone
            or getattr(capability, "_factory_marker", None)
            is not _AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY
        ):
            raise EvidenceSealError(
                "retention unlink requires exact authenticated authority"
            )

        lease: _RetentionUnlinkLease | None = None
        lease_closed = False
        payload_unlink_attempted = False
        binding: _AuthenticatedRetentionTombstoneBinding | None = None
        attempted_groups: list[_HeldRetentionDirectory] = []
        ack_boundary_owner: object | None = None
        ack_boundary_lease: _AckRetentionBoundaryLease | None = None
        primary_error: BaseException | None = None
        try:
            with self._retention_tombstone_lock:
                if self._retention_commit_uncertain_latched:
                    raise EvidenceSealError(
                        "retention unlink is latched uncertain"
                    )
                if (
                    self._authenticated_retention_unlink_completion
                    is not None
                ):
                    raise EvidenceSealError(
                        "retention unlink is already completed"
                    )
                binding = self._authenticated_retention_tombstone
                if (
                    binding is None
                    or binding.capability is not capability
                ):
                    raise EvidenceSealError(
                        "retention unlink authority is not registered"
                    )
                phase = self._validate_authenticated_retention_tombstone(
                    capability,
                    binding,
                    allow_in_progress=True,
                )
                lease = self._prepare_retention_unlink_lease(binding)
                journal = binding.journal
                if type(journal) is not RetentionStateJournal:
                    raise EvidenceSealError(
                        "retention unlink lost its exact journal"
                    )
                selected_max_sequence = (
                    self._retention_selected_max_sequence(
                        journal.state
                    )
                )
                if selected_max_sequence >= MAX_UINT64:
                    raise EvidenceSealError(
                        "retention unlink has no surviving ACK position"
                    )
                candidate_ack_owner = self._ack_journal_owner
                ack_boundary_lease = self._acquire_retention_ack_boundary(
                    candidate_ack_owner,
                    confirmed_through=selected_max_sequence + 1,
                )
                ack_boundary_owner = candidate_ack_owner
                if phase == "evidence_appended":
                    in_progress_state = decode_retention_state(
                        binding.unlink_in_progress_state_raw
                    )
                    try:
                        journal._transition(in_progress_state)
                    except BaseException as transition_error:
                        try:
                            journal._prove_publication(
                                binding.unlink_in_progress_state_raw
                            )
                            journal._state = in_progress_state.model_copy(
                                deep=True
                            )
                            journal._raw = (
                                binding.unlink_in_progress_state_raw
                            )
                            journal._assert_consistent()
                        except BaseException as recovery_error:  # noqa: BLE001
                            transition_error.add_note(
                                "retention in-progress transition could "
                                f"not be reconciled: {recovery_error}"
                            )
                        raise
                else:
                    journal._prove_publication(
                        binding.unlink_in_progress_state_raw
                    )
                if (
                    self._validate_authenticated_retention_tombstone(
                        capability,
                        binding,
                        allow_in_progress=True,
                    )
                    != "retention_unlink_in_progress"
                ):
                    raise EvidenceSealError(
                        "retention unlink intent is not durable"
                    )
                self._bind_retention_unlink_lease(lease)
                manifest_canonical = (
                    self._retention_snapshot_binding.manifest_canonical
                    if self._retention_snapshot_binding is not None
                    else ()
                )
                completion = binding.completion_capability
                if type(completion) is not AuthenticatedRetentionUnlinkCompletion:
                    raise EvidenceSealError(
                        "preallocated retention completion is inexact"
                    )

                first = True
                for group in lease.groups:
                    attempted_groups.append(group)
                    for payload in group.payloads:
                        self._require_retention_unlink_directory(group)
                        _bind_held_source(
                            group.descriptor,
                            payload.basename,
                            payload.display_path,
                            descriptor=payload.descriptor,
                            identity=payload.identity,
                        )
                        if first:
                            first = False
                            payload_unlink_attempted = True
                            self._authenticated_retention_tombstone = None
                        os.unlink(
                            payload.basename,
                            dir_fd=group.descriptor,
                        )
                        self._require_retention_unlinked_payload(
                            group,
                            payload,
                        )
                    os.fsync(group.descriptor)
                    self._require_retention_unlink_directory(group)
                if first:
                    raise EvidenceCorrupt(
                        "retention unlink has no selected payload"
                    )
                canonical = self._require_retention_post_unlink_namespace(
                    lease
                )
                if canonical != manifest_canonical:
                    raise EvidenceCorrupt(
                        "retention unlink completion manifest changed"
                    )
                self._retire_authenticated_retention_records(
                    journal.state
                )
                verifier = self._require_authenticated_recovered()
                completion_binding = (
                    _AuthenticatedRetentionUnlinkCompletionBinding(
                        capability=completion,
                        tombstone=binding,
                        journal=journal,
                        journal_identity=binding.journal_identity,
                        lifecycle_identity=self._lifecycle_identity,
                        completed_state_raw=binding.completed_state_raw,
                        manifest_canonical=manifest_canonical,
                        verifier_authority=verifier._authority,
                        verifier_generation=(
                            verifier._authority.generation
                        ),
                        transient_generation=(
                            verifier._repair_transient_generation
                        ),
                        accepted_authority=(
                            _retention_accepted_authority_binding(
                                verifier
                            )
                        ),
                        status=self.status(),
                    )
                )
                self._close_retention_unlink_lease(lease)
                lease_closed = True
                journal._transition(
                    decode_retention_state(binding.completed_state_raw)
                )
                self._authenticated_retention_unlink_completion = (
                    completion_binding
                )
                self._retention_commit_uncertain_latched = False
                return completion
        except BaseException as error:
            primary_error = error
            if payload_unlink_attempted and binding is not None:
                self._retention_commit_uncertain_latched = True
                self._authority_state = "retention_uncertain"
                self._authenticated_retention_tombstone = None
                for group in attempted_groups:
                    if group.descriptor < 0:
                        continue
                    try:
                        os.fsync(group.descriptor)
                    except BaseException as cleanup_error:  # noqa: BLE001
                        error.add_note(
                            "retention uncertainty directory fsync failed: "
                            f"{cleanup_error}"
                        )
                if lease is not None and not lease_closed:
                    try:
                        self._close_retention_unlink_lease(lease)
                        lease_closed = True
                    except BaseException as cleanup_error:  # noqa: BLE001
                        error.add_note(
                            "retention uncertainty descriptor close failed: "
                            f"{cleanup_error}"
                        )
                try:
                    self._attempt_retention_commit_uncertain(binding)
                except BaseException as persistence_error:  # noqa: BLE001
                    error.add_note(
                        "retention uncertain-state persistence failed: "
                        f"{persistence_error}"
                    )
            if lease is not None and not lease_closed:
                try:
                    self._close_retention_unlink_lease(lease)
                except BaseException as cleanup_error:  # noqa: BLE001
                    error.add_note(
                        f"retention unlink descriptor cleanup failed: {cleanup_error}"
                    )
            if isinstance(error, EvidenceStoreError):
                raise
            if not isinstance(error, Exception):
                raise
            raise EvidenceCorrupt(
                "retention unlink execution is uncertain"
            ) from error
        finally:
            if (
                ack_boundary_owner is not None
                and ack_boundary_lease is not None
            ):
                try:
                    self._release_retention_ack_boundary(
                        ack_boundary_owner,
                        ack_boundary_lease,
                    )
                except BaseException as cleanup_error:
                    if primary_error is None:
                        self._retention_commit_uncertain_latched = True
                        self._authority_state = "retention_uncertain"
                        raise
                    primary_error.add_note(
                        "retention ACK-boundary release failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )

    def _validate_authenticated_retention_completion(
        self,
        capability: object,
        binding: _AuthenticatedRetentionUnlinkCompletionBinding,
    ) -> tuple[frozenset[str], bytes | None]:
        from agmind_immune.evidence.retention import (
            _AUTHENTICATED_RETENTION_UNLINK_COMPLETION_FACTORY,
            AuthenticatedRetentionUnlinkCompletion,
            RetentionCorruption,
            RetentionSnapshot,
            RetentionStateJournal,
            RetentionStateV1,
            _retention_boundary_cache_bytes,
            decode_retention_state,
        )

        tombstone = binding.tombstone
        journal = binding.journal
        snapshot = tombstone.snapshot
        authority = getattr(journal, "_authority", None)
        state_binding = self._retention_state_binding
        snapshot_binding = self._retention_snapshot_binding
        if (
            type(capability) is not AuthenticatedRetentionUnlinkCompletion
            or getattr(capability, "_factory_marker", None)
            is not _AUTHENTICATED_RETENTION_UNLINK_COMPLETION_FACTORY
            or self._authenticated_retention_unlink_completion is not binding
            or binding.capability is not capability
            or tombstone.completion_capability is not capability
            or type(journal) is not RetentionStateJournal
            or binding.journal is not tombstone.journal
            or binding.journal_identity is not tombstone.journal_identity
            or binding.journal_identity is not journal._identity
            or binding.lifecycle_identity is not self._lifecycle_identity
            or tombstone.lifecycle_identity is not self._lifecycle_identity
            or binding.completed_state_raw != tombstone.completed_state_raw
            or type(binding.completed_state_raw) is not bytes
            or type(snapshot) is not RetentionSnapshot
            or snapshot_binding is None
            or snapshot_binding.snapshot is not snapshot
            or binding.manifest_canonical
            != snapshot_binding.manifest_canonical
            or state_binding is None
            or state_binding.name != _RETENTION_STATE_NAME
            or state_binding.raw != binding.completed_state_raw
            or self._retention_state_temporary is not None
            or self._authenticated_retention_tombstone is not None
            or self._retention_commit_uncertain_latched
            or self._retention_finalization_uncertain_latched
            or self._retention_state_namespace_uncertain
            or type(authority) is not _RetentionStateAuthority
            or authority._store is not self
            or authority._lifecycle_identity is not self._lifecycle_identity
            or authority._retention_journal is not journal
            or self._retention_state_authority is not authority
            or self._closed
        ):
            raise EvidenceSealError(
                "retention completion is not exact live store authority"
            )
        try:
            journal._assert_consistent()
            completed = decode_retention_state(
                binding.completed_state_raw
            )
            journal._prove_publication(binding.completed_state_raw)
        except (
            AttributeError,
            TypeError,
            ValueError,
        ) as error:
            raise EvidenceSealError(
                "retention completion lost exact durable state"
            ) from error
        if (
            type(completed) is not RetentionStateV1
            or journal._raw != binding.completed_state_raw
            or journal._state != completed
            or completed.operation != "tombstone"
            or completed.phase != "completed"
            or completed.target is None
            or completed.target.sequence
            != tombstone.target_ref.source_sequence
            or completed.target.event_id != tombstone.target_ref.event_id
            or completed.target.content_sha256
            != tombstone.target_ref.content_sha256
            or not completed.entries
        ):
            raise EvidenceSealError(
                "retention completion state is not exact"
            )
        selected = frozenset(
            entry.segment_relative_path for entry in completed.entries
        )
        if len(selected) != len(completed.entries):
            raise EvidenceCorrupt(
                "retention completion selected paths are not unique"
            )
        canonical = self._require_retention_post_unlink_paths(
            tombstone,
            selected,
            binding,
        )
        if canonical != binding.manifest_canonical:
            raise EvidenceCorrupt(
                "retention completion manifest authority changed"
            )
        verifier = self._require_authenticated_recovered()
        through = tombstone.status.evidence_head
        if snapshot.prior_index_through_sequence != through:
            raise EvidenceSealError(
                "retention completion snapshot prefix changed"
            )
        try:
            current_prior = self._retention_prior_tombstones(
                verifier,
                through_sequence=through,
            )
            frozen_prior = snapshot.prior_tombstones
            current_projection = tuple(
                (
                    item.sequence,
                    item.event_id,
                    item.content_sha256,
                    item.request_canonical,
                )
                for item in current_prior
            )
            frozen_projection = tuple(
                (
                    item.sequence,
                    item.event_id,
                    item.content_sha256,
                    item.request_canonical,
                )
                for item in frozen_prior
            )
            if current_projection != frozen_projection:
                raise RetentionCorruption(
                    "retention boundary source prefix changed"
                )
            boundary_raw = _retention_boundary_cache_bytes(
                snapshot,
                source_evidence_head=through,
            )
        except RetentionCorruption as error:
            raise EvidenceCorrupt(
                "retention completion cache authority is corrupt"
            ) from error
        return selected, boundary_raw

    def _finalize_authenticated_retention_completion(
        self,
        capability: object,
        *,
        _factory: object,
    ) -> None:
        from agmind_immune.evidence.retention import (
            MAX_RETENTION_BOUNDARY_BYTES,
            RetentionCorruption,
        )

        if (
            _factory is not _RETENTION_PROOF_FACTORY
            or type(self) is not SegmentStore
        ):
            raise TypeError(
                "retention completion requires the exact private factory"
            )

        state_descriptor = -1
        boundary_descriptor = -1
        mutation_started = False
        state_unlink_attempted = False
        binding: _AuthenticatedRetentionUnlinkCompletionBinding | None = None
        try:
            with self._retention_tombstone_lock:
                if self._retention_finalization_uncertain_latched:
                    raise EvidenceSealError(
                        "retention completion finalization is uncertain"
                    )
                binding = self._authenticated_retention_unlink_completion
                if binding is None or binding.capability is not capability:
                    raise EvidenceSealError(
                        "retention completion is not the exact registered authority"
                    )
                _selected, boundary_raw = (
                    self._validate_authenticated_retention_completion(
                        capability,
                        binding,
                    )
                )
                journal = cast("RetentionStateJournal", binding.journal)
                authority = journal._authority
                state_binding = self._retention_state_binding
                if state_binding is None:
                    raise EvidenceSealError(
                        "retention completion lost its durable state binding"
                    )
                state_descriptor, state_opened = _open_regular_at(
                    self._root_descriptor,
                    _RETENTION_STATE_NAME,
                    self.root / _RETENTION_STATE_NAME,
                    maximum=_MAX_RETENTION_STATE_BYTES,
                )
                _validate_identity(
                    state_opened,
                    state_binding.identity,
                    self.root / _RETENTION_STATE_NAME,
                )
                _validate_published_from_held(
                    self._root_descriptor,
                    _RETENTION_STATE_NAME,
                    self.root / _RETENTION_STATE_NAME,
                    descriptor=state_descriptor,
                    identity=state_binding.identity,
                    expected_sha256=hashlib.sha256(
                        binding.completed_state_raw
                    ).hexdigest(),
                )

                boundary_path = self.root / _RETENTION_BOUNDARY_NAME
                boundary_info = _entry_stat_at(
                    self._root_descriptor,
                    _RETENTION_BOUNDARY_NAME,
                )
                boundary_identity: _FileIdentity | None = None
                if boundary_info is not None:
                    boundary_identity = _file_identity(
                        _regular_stat_at(
                            self._root_descriptor,
                            _RETENTION_BOUNDARY_NAME,
                            boundary_path,
                        )
                    )
                    boundary_descriptor, boundary_opened = _open_regular_at(
                        self._root_descriptor,
                        _RETENTION_BOUNDARY_NAME,
                        boundary_path,
                    )
                    _validate_identity(
                        boundary_opened,
                        boundary_identity,
                        boundary_path,
                    )

                if boundary_raw is not None:
                    mutation_started = True
                    self._retention_finalization_uncertain_latched = True
                    existing_descriptor = boundary_descriptor
                    boundary_descriptor = -1
                    boundary_descriptor, boundary_identity = (
                        _publish_retention_boundary_at(
                            self._root_descriptor,
                            _RETENTION_BOUNDARY_NAME,
                            boundary_path,
                            boundary_raw,
                            existing_descriptor=existing_descriptor,
                            existing_identity=boundary_identity,
                        )
                    )
                elif boundary_identity is not None:
                    mutation_started = True
                    self._retention_finalization_uncertain_latched = True
                    existing_descriptor = boundary_descriptor
                    boundary_descriptor = -1
                    _conditionally_unlink_held_at(
                        self._root_descriptor,
                        _RETENTION_BOUNDARY_NAME,
                        boundary_path,
                        descriptor=existing_descriptor,
                        identity=boundary_identity,
                    )
                    boundary_identity = None

                if boundary_raw is None:
                    if (
                        _entry_stat_at(
                            self._root_descriptor,
                            _RETENTION_BOUNDARY_NAME,
                        )
                        is not None
                    ):
                        raise EvidenceCorrupt(
                            "oversize retention boundary was not omitted"
                        )
                else:
                    if (
                        boundary_identity is None
                        or boundary_descriptor < 0
                    ):
                        raise EvidenceSealError(
                            "retention boundary publication lost its binding"
                        )
                    _validate_published_from_held(
                        self._root_descriptor,
                        _RETENTION_BOUNDARY_NAME,
                        boundary_path,
                        descriptor=boundary_descriptor,
                        identity=boundary_identity,
                        expected_sha256=hashlib.sha256(
                            boundary_raw
                        ).hexdigest(),
                    )
                    if (
                        _read_regular_at(
                            self._root_descriptor,
                            _RETENTION_BOUNDARY_NAME,
                            boundary_path,
                            MAX_RETENTION_BOUNDARY_BYTES,
                        )
                        != boundary_raw
                    ):
                        raise EvidenceCorrupt(
                            "retention boundary publication changed"
                        )
                    descriptor = boundary_descriptor
                    boundary_descriptor = -1
                    os.close(descriptor)

                _bind_held_source(
                    self._root_descriptor,
                    _RETENTION_STATE_NAME,
                    self.root / _RETENTION_STATE_NAME,
                    descriptor=state_descriptor,
                    identity=state_binding.identity,
                )
                mutation_started = True
                state_unlink_attempted = True
                self._retention_finalization_uncertain_latched = True
                self._retention_state_namespace_uncertain = True
                descriptor = state_descriptor
                state_descriptor = -1
                _conditionally_unlink_held_at(
                    self._root_descriptor,
                    _RETENTION_STATE_NAME,
                    self.root / _RETENTION_STATE_NAME,
                    descriptor=descriptor,
                    identity=state_binding.identity,
                )

                authority._retention_journal = None
                journal._state = None
                journal._raw = None
                self._retention_state_binding = None
                self._retention_state_temporary = None
                self._retention_state_authority = None
                self._retention_snapshot_binding = None
                self._authenticated_retention_unlink_completion = None
                self._retention_finalization_uncertain_latched = False
                self._retention_state_namespace_uncertain = False
                self._clear_retention_pending_latch()
                return
        except BaseException as error:
            if mutation_started:
                self._retention_finalization_uncertain_latched = True
            if state_unlink_attempted:
                self._retention_state_namespace_uncertain = True
            if boundary_descriptor >= 0:
                descriptor = boundary_descriptor
                boundary_descriptor = -1
                try:
                    os.close(descriptor)
                except BaseException as close_error:  # noqa: BLE001
                    error.add_note(
                        "retention boundary descriptor close failed: "
                        f"{close_error}"
                    )
            if state_descriptor >= 0:
                descriptor = state_descriptor
                state_descriptor = -1
                try:
                    os.close(descriptor)
                except BaseException as close_error:  # noqa: BLE001
                    error.add_note(
                        "retention state descriptor close failed: "
                        f"{close_error}"
                    )
            if state_unlink_attempted:
                try:
                    os.fsync(self._root_descriptor)
                except BaseException as fsync_error:  # noqa: BLE001
                    error.add_note(
                        "retention state uncertainty root fsync failed: "
                        f"{fsync_error}"
                    )
            if isinstance(error, EvidenceStoreError):
                raise
            if isinstance(error, RetentionCorruption):
                raise EvidenceCorrupt(
                    "retention completion authority is corrupt"
                ) from error
            if not isinstance(error, Exception):
                raise
            raise EvidenceCorrupt(
                "retention completion finalization is uncertain"
            ) from error

    def _clear_authenticated_retention_blocked(
        self,
        journal: object,
        target_ref: object,
        *,
        _factory: object,
    ) -> None:
        """Clear only a fully authenticated blocked-retention state gate."""
        from agmind_immune.coverage.state import CoverageState
        from agmind_immune.evidence.retention import (
            RetentionStateJournal,
            RetentionStateV1,
            RetentionTargetV1,
            encode_retention_state,
        )
        from agmind_immune.ingest.envelope import (
            CoreEventV1,
            IngestVerificationError,
            VerifierCommitError,
        )

        if (
            _factory is not _RETENTION_BLOCKED_CLEAR_FACTORY
            or type(self) is not SegmentStore
        ):
            raise TypeError(
                "retention blocked clear requires its exact private factory"
            )
        if type(journal) is not RetentionStateJournal:
            raise TypeError(
                "retention blocked clear requires the exact state journal"
            )
        if type(target_ref) is not EvidenceRef:
            raise TypeError(
                "retention blocked clear requires the exact evidence ref"
            )

        state_descriptor = -1
        mutation_started = False
        state_unlink_attempted = False
        try:
            with self._retention_tombstone_lock:
                authority = journal._authority
                state = journal._state
                state_raw = journal._raw
                state_binding = self._retention_state_binding
                verifier = self._require_authenticated_recovered()
                status = self.status()
                coverage = self._coverage_state_owner
                if (
                    type(authority) is not _RetentionStateAuthority
                    or authority._store is not self
                    or authority._lifecycle_identity
                    is not self._lifecycle_identity
                    or authority._retention_journal is not journal
                    or self._retention_state_authority is not authority
                    or type(state) is not RetentionStateV1
                    or type(state_raw) is not bytes
                    or state_binding is None
                    or state_binding.name != _RETENTION_STATE_NAME
                    or state_binding.raw != state_raw
                    or self._retention_state_temporary is not None
                    or self._retention_commit_uncertain_latched
                    or self._retention_finalization_uncertain_latched
                    or self._retention_state_namespace_uncertain
                    or self._authenticated_retention_tombstone is not None
                    or self._authenticated_retention_unlink_completion
                    is not None
                ):
                    raise EvidenceSealError(
                        "retention blocked state is not exact live authority"
                    )
                if (
                    state.operation != "blocked"
                    or state.phase != "evidence_appended"
                    or type(state.request) is not RetentionBlockedV1
                    or type(state.target) is not RetentionTargetV1
                    or state.entries
                    or encode_retention_state(state) != state_raw
                ):
                    raise EvidenceSealError(
                        "retention blocked clear requires exact "
                        "evidence-appended state"
                    )
                target = state.target
                if (
                    target.sequence != target_ref.source_sequence
                    or target.event_id != target_ref.event_id
                    or target.content_sha256
                    != target_ref.content_sha256
                ):
                    raise EvidenceSealError(
                        "retention blocked target differs from durable authority"
                    )
                if (
                    type(status) is not EvidenceStatus
                    or status.healthy is not True
                    or status.key_healthy is not True
                    or status.repair_pending is not False
                    or status.retention_pending is not True
                    or self._closed
                    or self._authority_state != "ready"
                    or self._repair_mode
                    or self._repair_pending
                    or self._read_only_reason is not None
                    or self._append_uncertain
                    or self._pending_durable_commit is not None
                    or verifier is not self._bound_verifier
                    or verifier._bound_lifecycle
                    is not self._lifecycle_identity
                    or verifier._staged
                    or verifier._authorizations
                ):
                    raise EvidenceSealError(
                        "retention blocked clear requires one healthy "
                        "ordinary lifecycle"
                    )
                if (
                    type(coverage) is not CoverageState
                    or coverage._evidence is not self
                    or coverage._lifecycle_identity
                    is not self._lifecycle_identity
                    or coverage._capability_token is None
                    or coverage._healthy is not True
                    or coverage._closed is not False
                ):
                    raise EvidenceSealError(
                        "retention blocked clear requires exact live coverage"
                    )
                coverage_snapshot = coverage._snapshot
                coverage_head = self._validate_coverage_state_owner(
                    coverage,
                    coverage._lifecycle_identity,
                    reducer_head=coverage_snapshot.head_ref,
                )
                if (
                    coverage_head is not coverage_snapshot.head_ref
                    or coverage_snapshot.head_sequence
                    != status.evidence_head
                    or coverage_snapshot.head_sequence
                    < target_ref.source_sequence
                ):
                    raise EvidenceSealError(
                        "retention blocked coverage does not include target"
                    )

                try:
                    record = self.resolve_authenticated_ref(target_ref)
                    item = CoreEventV1.model_validate(
                        {
                            "sequence": target_ref.source_sequence,
                            "event_id": target_ref.event_id,
                            "content_sha256": target_ref.content_sha256,
                            "envelope": record.envelope,
                        },
                        strict=True,
                    )
                    canonical_envelope = canonical_json(item.envelope)
                    request_canonical = canonical_json(
                        state.request.model_dump(mode="python")
                    )
                    normalized_canonical = canonical_json(
                        item.envelope.get("normalized_fields")
                    )
                except (
                    EvidenceStoreError,
                    TypeError,
                    ValueError,
                    ValidationError,
                ) as error:
                    raise EvidenceSealError(
                        "retention blocked target is not exact authenticated "
                        "evidence"
                    ) from error
                if (
                    record.ref is not target_ref
                    or record.priority is not EvidencePriority.PROTECTED
                    or record.canonical_envelope != canonical_envelope
                    or hashlib.sha256(canonical_envelope).hexdigest()
                    != target_ref.content_sha256
                    or item.envelope.get("source_sequence")
                    != target_ref.source_sequence
                    or item.envelope.get("event_id")
                    != target_ref.event_id
                    or item.envelope.get("event_type")
                    != "retention_blocked_priority_evidence"
                    or normalized_canonical != request_canonical
                    or verifier.accepted_ref(target_ref.source_sequence)
                    is not target_ref
                ):
                    raise EvidenceSealError(
                        "retention blocked target differs from exact "
                        "authenticated evidence"
                    )

                accepted_before = _retention_accepted_authority_binding(
                    verifier
                )
                verifier_authority_before = verifier._authority
                verifier_generation_before = (
                    verifier._authority.generation
                )
                transient_before = verifier._repair_transient_generation
                coverage_token = coverage._capability_token
                journal_identity = journal._identity
                try:
                    replayed = (
                        verifier._restricted_historical_retention_replay(
                            (item, target_ref),
                            state.request,
                        )
                    )
                except (
                    IngestVerificationError,
                    VerifierCommitError,
                    TypeError,
                    ValueError,
                ) as error:
                    raise EvidenceSealError(
                        "retention blocked historical replay failed"
                    ) from error
                if (
                    replayed.event_type
                    != "retention_blocked_priority_evidence"
                    or replayed.evidence_priority != "protected"
                    or replayed.is_retry is not True
                    or replayed.sequence != target_ref.source_sequence
                    or replayed.event_id != target_ref.event_id
                    or replayed.content_sha256
                    != target_ref.content_sha256
                    or replayed._normalized_fields_canonical
                    != request_canonical
                    or journal._identity is not journal_identity
                    or journal._state is not state
                    or journal._raw is not state_raw
                    or self._retention_state_binding is not state_binding
                    or verifier is not self._bound_verifier
                    or verifier._authority is not verifier_authority_before
                    or verifier._authority.generation
                    != verifier_generation_before
                    or verifier._repair_transient_generation
                    != transient_before
                    or not _same_retention_accepted_authority(
                        verifier,
                        accepted_before,
                    )
                    or self.status() != status
                    or self._coverage_state_owner is not coverage
                    or coverage._snapshot is not coverage_snapshot
                    or coverage._capability_token is not coverage_token
                    or coverage._healthy is not True
                    or coverage._closed is not False
                ):
                    raise EvidenceSealError(
                        "retention blocked replay changed live authority"
                    )

                journal._prove_publication(state_raw)
                state_descriptor, state_opened = _open_regular_at(
                    self._root_descriptor,
                    _RETENTION_STATE_NAME,
                    self.root / _RETENTION_STATE_NAME,
                    maximum=_MAX_RETENTION_STATE_BYTES,
                )
                _validate_identity(
                    state_opened,
                    state_binding.identity,
                    self.root / _RETENTION_STATE_NAME,
                )
                _validate_published_from_held(
                    self._root_descriptor,
                    _RETENTION_STATE_NAME,
                    self.root / _RETENTION_STATE_NAME,
                    descriptor=state_descriptor,
                    identity=state_binding.identity,
                    expected_sha256=hashlib.sha256(state_raw).hexdigest(),
                )
                journal._prove_publication(state_raw)

                mutation_started = True
                state_unlink_attempted = True
                self._retention_finalization_uncertain_latched = True
                self._retention_state_namespace_uncertain = True
                descriptor = state_descriptor
                state_descriptor = -1
                _conditionally_unlink_held_at(
                    self._root_descriptor,
                    _RETENTION_STATE_NAME,
                    self.root / _RETENTION_STATE_NAME,
                    descriptor=descriptor,
                    identity=state_binding.identity,
                )

                authority._retention_journal = None
                journal._state = None
                journal._raw = None
                self._retention_state_binding = None
                self._retention_state_temporary = None
                self._retention_state_authority = None
                self._retention_snapshot_binding = None
                self._retention_finalization_uncertain_latched = False
                self._retention_state_namespace_uncertain = False
                self._clear_retention_pending_latch()
                return
        except BaseException as error:
            if mutation_started:
                self._retention_finalization_uncertain_latched = True
            if state_unlink_attempted:
                self._retention_state_namespace_uncertain = True
            if state_descriptor >= 0:
                descriptor = state_descriptor
                state_descriptor = -1
                try:
                    os.close(descriptor)
                except BaseException as close_error:  # noqa: BLE001
                    error.add_note(
                        "retention blocked state descriptor close failed: "
                        f"{close_error}"
                    )
            if state_unlink_attempted:
                try:
                    os.fsync(self._root_descriptor)
                except BaseException as fsync_error:  # noqa: BLE001
                    error.add_note(
                        "retention blocked uncertainty root fsync failed: "
                        f"{fsync_error}"
                    )
            if isinstance(error, EvidenceStoreError):
                raise
            if not isinstance(error, Exception):
                raise
            if mutation_started:
                raise EvidenceCorrupt(
                    "retention blocked finalization is uncertain"
                ) from error
            raise EvidenceSealError(
                "retention blocked clear authority is invalid"
            ) from error

    def _require_repair_lifecycle(self) -> None:
        if (
            self._closed
            or self._repair_session_identity is None
        ):
            raise EvidenceSealError("no live signed tail-repair lifecycle exists")

    def _require_repair_pending(self) -> None:
        self._require_repair_lifecycle()
        if not self._repair_pending:
            raise EvidenceSealError("signed tail-repair lifecycle is already cleared")

    def _latch_repair_namespace_uncertain(self) -> None:
        self._repair_namespace_uncertain = True
        self._repair_physical_state = RepairPhysicalState.INVALID
        self._append_uncertain = True

    def _require_authenticated_recovered(self) -> EnvelopeVerifier:
        if self._closed:
            raise EvidenceStoreError("evidence store is closed")
        verifier = self._bound_verifier
        if verifier is None or self._authority_state != "ready":
            raise EvidenceSealError(
                "authenticated evidence is unavailable before verifier recovery"
            )
        return verifier

    def _require_ack_mutation_ready(self) -> EnvelopeVerifier:
        verifier = self._require_authenticated_recovered()
        if self._read_only_reason is not None:
            raise EvidenceReadOnly(
                f"evidence root is read-only: {self._read_only_reason}"
            )
        if self._append_uncertain or self._pending_durable_commit is not None:
            raise EvidenceReadOnly("evidence durability is not settled")
        return verifier

    def _open_retention_state_authority(
        self,
        *,
        _factory: object,
    ) -> _RetentionStateAuthority:
        if (
            _factory is not _RETENTION_STATE_AUTHORITY_FACTORY
            or type(self) is not SegmentStore
        ):
            raise TypeError(
                "retention state requires the exact SegmentStore factory"
            )
        if self._closed:
            raise EvidenceStoreError("evidence store is closed")
        authority = self._retention_state_authority
        if authority is None:
            authority = _RetentionStateAuthority(
                self,
                _factory=_RETENTION_STATE_AUTHORITY_FACTORY,
            )
            self._retention_state_authority = authority
        else:
            authority._require()
        return authority

    def _require_retention_state_authority(
        self,
        authority: _RetentionStateAuthority,
    ) -> None:
        if (
            type(authority) is not _RetentionStateAuthority
            or self._retention_state_authority is not authority
            or authority._store is not self
            or authority._lifecycle_identity is not self._lifecycle_identity
            or self._closed
        ):
            raise EvidenceSealError(
                "retention state requires exact held-root authority"
            )
        if self._retention_state_namespace_uncertain:
            raise EvidenceSealError(
                "retention-state namespace is uncertain"
            )

    def _require_retention_state_mutation(
        self,
        authority: _RetentionStateAuthority,
    ) -> None:
        self._require_retention_state_authority(authority)
        if self._repair_mode or self._repair_pending:
            raise EvidenceSealError(
                "retention state is unavailable during signed tail repair"
            )
        if self._read_only_reason is not None:
            raise EvidenceReadOnly(
                f"evidence root is read-only: {self._read_only_reason}"
            )
        if self._append_uncertain or self._pending_durable_commit is not None:
            raise EvidenceReadOnly("evidence durability is not settled")

    @staticmethod
    def _validate_retention_state_raw(raw: bytes) -> None:
        if (
            type(raw) is not bytes
            or not raw
            or len(raw) > _MAX_RETENTION_STATE_BYTES
        ):
            raise EvidenceStoreError(
                "retention state must contain at most 128 KiB"
            )

    def _read_bound_retention_artifact(
        self,
        binding: _RetentionStateArtifactBinding | None,
        *,
        final: bool,
    ) -> bytes | None:
        if final:
            name = _RETENTION_STATE_NAME
            if binding is None:
                if _entry_stat_at(self._root_descriptor, name) is not None:
                    raise EvidenceCorrupt(
                        "unbound retention-state final appeared"
                    )
                return None
        else:
            names = tuple(
                entry
                for entry in os.listdir(self._root_descriptor)
                if _RETENTION_STATE_TEMP_NAME.fullmatch(entry)
            )
            if binding is None:
                if names:
                    raise EvidenceCorrupt(
                        "unbound retention-state temporary appeared"
                    )
                return None
            if names != (binding.name,):
                raise EvidenceCorrupt(
                    "retention-state temporary namespace changed"
                )
            name = binding.name
        if binding is None:
            raise EvidenceCorrupt("retention-state binding is invalid")
        current = _read_stable_retention_artifact(
            self._root_descriptor,
            name,
            self.root / name,
        )
        if current != binding:
            raise EvidenceCorrupt(
                "retention-state artifact changed after startup"
            )
        return current.raw

    def _read_retention_state_bytes(
        self,
        authority: _RetentionStateAuthority,
    ) -> bytes | None:
        self._require_retention_state_authority(authority)
        return self._read_bound_retention_artifact(
            self._retention_state_binding,
            final=True,
        )

    def _read_retention_state_temporary_bytes(
        self,
        authority: _RetentionStateAuthority,
    ) -> bytes | None:
        self._require_retention_state_authority(authority)
        return self._read_bound_retention_artifact(
            self._retention_state_temporary,
            final=False,
        )

    def _require_clean_retention_state_temporary_namespace(
        self,
        authority: _RetentionStateAuthority,
    ) -> None:
        if self._read_retention_state_temporary_bytes(authority) is not None:
            raise EvidenceCorrupt(
                "retention-state temporary requires startup recovery"
            )

    def _commit_retention_state_bytes(
        self,
        raw: bytes,
        *,
        replace: bool,
        expected_binding: _RetentionStateArtifactBinding | None = None,
    ) -> _RetentionStateArtifactBinding:
        if replace != (expected_binding is not None):
            raise EvidenceSealError(
                "retention-state commit lost its CAS binding"
            )
        temporary_name = f".{_RETENTION_STATE_NAME}.{uuid.uuid4()}.tmp"
        display_path = self.root / _RETENTION_STATE_NAME
        expected_sha256 = hashlib.sha256(raw).hexdigest()
        descriptor = -1
        identity: _FileIdentity | None = None
        old_descriptor = -1
        old_exchange_identity: _FileIdentity | None = None
        if expected_binding is not None:
            old_descriptor, opened = _open_regular_at(
                self._root_descriptor,
                _RETENTION_STATE_NAME,
                display_path,
                maximum=_MAX_RETENTION_STATE_BYTES,
            )
            try:
                _validate_identity(
                    opened,
                    expected_binding.identity,
                    display_path,
                )
                _validate_published_from_held(
                    self._root_descriptor,
                    _RETENTION_STATE_NAME,
                    display_path,
                    descriptor=old_descriptor,
                    identity=expected_binding.identity,
                    expected_sha256=hashlib.sha256(
                        expected_binding.raw
                    ).hexdigest(),
                )
            except BaseException:
                os.close(old_descriptor)
                raise
        self._retention_pending_latched = True
        self._retention_state_namespace_uncertain = True
        try:
            descriptor, identity = _write_temporary_at(
                self._root_descriptor,
                temporary_name,
                raw,
            )
            with _post_authentication_namespace(display_path):
                _bind_held_source(
                    self._root_descriptor,
                    temporary_name,
                    display_path,
                    descriptor=descriptor,
                    identity=identity,
                )
                if replace:
                    if expected_binding is None or old_descriptor < 0:
                        raise EvidenceSealError(
                            "retention-state CAS source is absent"
                        )
                    _bind_held_source(
                        self._root_descriptor,
                        _RETENTION_STATE_NAME,
                        display_path,
                        descriptor=old_descriptor,
                        identity=expected_binding.identity,
                    )
                    _rename_exchange(
                        temporary_name,
                        _RETENTION_STATE_NAME,
                        parent_descriptor=self._root_descriptor,
                    )
                    try:
                        _validate_published_from_held(
                            self._root_descriptor,
                            temporary_name,
                            self.root / temporary_name,
                            descriptor=old_descriptor,
                            identity=expected_binding.identity,
                            expected_sha256=hashlib.sha256(
                                expected_binding.raw
                            ).hexdigest(),
                        )
                    except BaseException as error:
                        try:
                            _validate_published_from_held(
                                self._root_descriptor,
                                _RETENTION_STATE_NAME,
                                display_path,
                                descriptor=descriptor,
                                identity=identity,
                                expected_sha256=expected_sha256,
                            )
                            os.fsync(self._root_descriptor)
                        except BaseException as final_error:
                            raise EvidenceCorrupt(
                                "retention-state CAS final is uncertain"
                            ) from final_error
                        raise EvidenceCorrupt(
                            "retention-state CAS source changed at exchange"
                        ) from error
                    old_exchange_identity = _file_identity(
                        os.fstat(old_descriptor)
                    )
                else:
                    _rename_noreplace(
                        temporary_name,
                        _RETENTION_STATE_NAME,
                        source_dir_fd=self._root_descriptor,
                        destination_dir_fd=self._root_descriptor,
                    )
                _validate_published_from_held(
                    self._root_descriptor,
                    _RETENTION_STATE_NAME,
                    display_path,
                    descriptor=descriptor,
                    identity=identity,
                    expected_sha256=expected_sha256,
                )
                os.fsync(self._root_descriptor)
                if replace:
                    if expected_binding is None or old_descriptor < 0:
                        raise EvidenceSealError(
                            "retention-state CAS cleanup source is absent"
                        )
                    if old_exchange_identity is None:
                        raise EvidenceSealError(
                            "retention-state CAS old inode is unbound"
                        )
                    _bind_held_source(
                        self._root_descriptor,
                        temporary_name,
                        self.root / temporary_name,
                        descriptor=old_descriptor,
                        identity=old_exchange_identity,
                    )
                    os.unlink(
                        temporary_name,
                        dir_fd=self._root_descriptor,
                    )
                    unlinked = os.fstat(old_descriptor)
                    if (
                        unlinked.st_dev
                        != expected_binding.identity.device
                        or unlinked.st_ino
                        != expected_binding.identity.inode
                        or unlinked.st_size
                        != expected_binding.identity.size
                        or unlinked.st_nlink != 0
                        or _entry_stat_at(
                            self._root_descriptor,
                            temporary_name,
                        )
                        is not None
                    ):
                        raise EvidenceCorrupt(
                            "retention-state old CAS inode was not unlinked"
                        )
                    os.fsync(self._root_descriptor)
                elif (
                    _entry_stat_at(
                        self._root_descriptor,
                        temporary_name,
                    )
                    is not None
                ):
                    raise EvidenceCorrupt(
                        "retention-state temporary survived atomic rename"
                    )
            binding = _read_stable_retention_artifact(
                self._root_descriptor,
                _RETENTION_STATE_NAME,
                display_path,
            )
            if binding.raw != raw:
                raise EvidenceCorrupt(
                    "retention-state commit did not bind exact bytes"
                )
        except BaseException:
            capture_error: BaseException | None = None
            try:
                if (
                    _entry_stat_at(
                        self._root_descriptor,
                        temporary_name,
                    )
                    is not None
                ):
                    retained_identity = _file_identity(
                        _regular_stat_at(
                            self._root_descriptor,
                            temporary_name,
                            self.root / temporary_name,
                        )
                    )
                    current_new_identity = (
                        _file_identity(os.fstat(descriptor))
                        if descriptor >= 0
                        else None
                    )
                    current_old_identity = (
                        _file_identity(os.fstat(old_descriptor))
                        if old_descriptor >= 0
                        else None
                    )
                    if (
                        descriptor >= 0
                        and current_new_identity is not None
                        and retained_identity == current_new_identity
                    ):
                        _bind_held_source(
                            self._root_descriptor,
                            temporary_name,
                            self.root / temporary_name,
                            descriptor=descriptor,
                            identity=current_new_identity,
                        )
                    elif (
                        old_descriptor >= 0
                        and expected_binding is not None
                        and retained_identity
                        == current_old_identity
                    ):
                        _bind_held_source(
                            self._root_descriptor,
                            temporary_name,
                            self.root / temporary_name,
                            descriptor=old_descriptor,
                            identity=retained_identity,
                        )
                    else:
                        raise EvidenceCorrupt(
                            "retention-state temporary has foreign identity"
                        )
                    retained = _read_stable_retention_artifact(
                        self._root_descriptor,
                        temporary_name,
                        self.root / temporary_name,
                    )
                    if retained.identity != retained_identity:
                        raise EvidenceCorrupt(
                            "retention-state temporary lost held identity"
                        )
                    self._retention_state_temporary = retained
            except (OSError, EvidenceStoreError) as error:
                capture_error = error
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as error:
                    if capture_error is None:
                        capture_error = error
            if old_descriptor >= 0:
                try:
                    os.close(old_descriptor)
                except OSError as error:
                    if capture_error is None:
                        capture_error = error
            if capture_error is not None:
                raise EvidenceCorrupt(
                    "retention-state commit namespace is uncertain"
                ) from capture_error
            raise
        try:
            os.close(descriptor)
        except OSError as error:
            raise EvidenceCorrupt(
                "retention-state held descriptor close is uncertain"
            ) from error
        if old_descriptor >= 0:
            try:
                os.close(old_descriptor)
            except OSError as error:
                raise EvidenceCorrupt(
                    "retention-state old CAS descriptor close is uncertain"
                ) from error
        self._retention_state_binding = binding
        self._retention_state_temporary = None
        self._retention_state_namespace_uncertain = False
        return binding

    def _publish_initial_retention_state(
        self,
        authority: _RetentionStateAuthority,
        raw: bytes,
    ) -> None:
        self._require_retention_state_mutation(authority)
        self._validate_retention_state_raw(raw)
        self._require_clean_retention_state_temporary_namespace(authority)
        if self._retention_state_binding is not None:
            raise FileExistsError(_RETENTION_STATE_NAME)
        binding = self._commit_retention_state_bytes(
            raw,
            replace=False,
        )
        if binding.raw != raw:
            raise EvidenceCorrupt("retention state publication is uncertain")

    def _replace_retention_state_bytes(
        self,
        authority: _RetentionStateAuthority,
        expected: bytes,
        raw: bytes,
    ) -> None:
        from agmind_immune.evidence.retention import RetentionStateConflict

        self._require_retention_state_mutation(authority)
        self._validate_retention_state_raw(expected)
        self._validate_retention_state_raw(raw)
        self._require_clean_retention_state_temporary_namespace(authority)
        expected_binding = self._retention_state_binding
        if expected_binding is None:
            raise RetentionStateConflict(
                "retention state CAS source is absent"
            )
        if (
            expected_binding.raw != expected
            or self._read_bound_retention_artifact(
                expected_binding,
                final=True,
            )
            != expected
        ):
            raise RetentionStateConflict(
                "retention state CAS mismatch"
            )
        replacement = self._commit_retention_state_bytes(
            raw,
            replace=True,
            expected_binding=expected_binding,
        )
        if replacement.raw != raw:
            raise EvidenceCorrupt(
                "retention state replacement did not bind exact bytes"
            )

    @staticmethod
    def _validate_repair_state_raw(raw: bytes) -> None:
        if type(raw) is not bytes or not raw or len(raw) > _MAX_REPAIR_STATE_BYTES:
            raise EvidenceStoreError("repair state must contain at most 4096 bytes")

    def _read_bound_repair_artifact(
        self,
        binding: _RepairStateArtifactBinding | None,
        *,
        final: bool,
    ) -> bytes | None:
        self._require_repair_lifecycle()
        if binding is None:
            if final:
                actual = _entry_stat_at(
                    self._root_descriptor,
                    _REPAIR_STATE_NAME,
                )
                if actual is not None:
                    raise EvidenceCorrupt(
                        "unbound repair-state final appeared after startup"
                    )
            return None
        current = _read_stable_repair_artifact(
            self._root_descriptor,
            binding.name,
            self.root / binding.name,
        )
        if current != binding:
            raise EvidenceCorrupt("repair-state artifact changed after startup")
        return current.raw

    def read_repair_state_bytes(self) -> bytes | None:
        return self._read_bound_repair_artifact(
            self._repair_state_binding,
            final=True,
        )

    def _decode_current_repair_state(self) -> tuple[RepairStateV1, bytes]:
        raw = self.read_repair_state_bytes()
        if raw is None:
            raise EvidenceSealError("durable repair state is absent")
        try:
            return decode_repair_state(raw), raw
        except RepairStateCorrupt as error:
            raise EvidenceCorrupt("durable repair state is invalid") from error

    def read_repair_state_temporary_bytes(self) -> bytes | None:
        return self._read_bound_repair_artifact(
            self._repair_state_temporary,
            final=False,
        )

    def _require_clean_repair_state_publication_namespace(self) -> None:
        if self._repair_state_temporary is not None:
            raise EvidenceCorrupt(
                "repair-state temporary must be classified before publication"
            )

    def publish_initial_repair_state(self, raw: bytes) -> None:
        self._require_repair_pending()
        self._validate_repair_state_raw(raw)
        self._require_clean_repair_state_publication_namespace()
        if self._repair_state_binding is not None:
            raise FileExistsError(_REPAIR_STATE_NAME)
        _publish_without_replacement_at(
            self._root_descriptor,
            _REPAIR_STATE_NAME,
            self.root / _REPAIR_STATE_NAME,
            raw,
        )
        self._repair_state_binding = _read_stable_repair_artifact(
            self._root_descriptor,
            _REPAIR_STATE_NAME,
            self.root / _REPAIR_STATE_NAME,
        )

    def replace_repair_state(self, expected: bytes, raw: bytes) -> None:
        self._require_repair_pending()
        self._validate_repair_state_raw(expected)
        self._validate_repair_state_raw(raw)
        self._require_clean_repair_state_publication_namespace()
        if self.read_repair_state_bytes() != expected:
            raise RepairStateConflict("repair state compare-and-swap mismatch")
        _atomic_replace_at(
            self._root_descriptor,
            _REPAIR_STATE_NAME,
            self.root / _REPAIR_STATE_NAME,
            raw,
        )
        replacement = _read_stable_repair_artifact(
            self._root_descriptor,
            _REPAIR_STATE_NAME,
            self.root / _REPAIR_STATE_NAME,
        )
        if replacement.raw != raw:
            raise EvidenceCorrupt("repair state replacement did not bind exact bytes")
        self._repair_state_binding = replacement

    def _remove_bound_repair_artifact(
        self,
        binding: _RepairStateArtifactBinding | None,
        expected: bytes,
    ) -> None:
        if binding is None:
            raise RepairStateConflict("repair state artifact is absent")
        current = _read_stable_repair_artifact(
            self._root_descriptor,
            binding.name,
            self.root / binding.name,
        )
        if current != binding or current.raw != expected:
            raise RepairStateConflict("repair state compare-and-swap mismatch")
        descriptor, opened = _open_regular_at(
            self._root_descriptor,
            binding.name,
            self.root / binding.name,
            maximum=_MAX_REPAIR_STATE_BYTES,
        )
        try:
            _bind_held_source(
                self._root_descriptor,
                binding.name,
                self.root / binding.name,
                descriptor=descriptor,
                identity=binding.identity,
            )
            os.unlink(binding.name, dir_fd=self._root_descriptor)
            unlinked = os.fstat(descriptor)
            if (
                unlinked.st_dev != opened.st_dev
                or unlinked.st_ino != opened.st_ino
                or unlinked.st_size != opened.st_size
                or unlinked.st_nlink != 0
                or _entry_stat_at(self._root_descriptor, binding.name)
                is not None
            ):
                self._latch_repair_namespace_uncertain()
                raise EvidenceCorrupt(
                    "repair-state conditional unlink became uncertain"
                )
            os.fsync(self._root_descriptor)
        finally:
            os.close(descriptor)

    def _validate_repair_completion_authority(
        self,
        expected: bytes,
        proof: AuthenticatedRepairCompletion,
        repair_journal: RepairStateJournal,
        *,
        used: bool,
    ) -> None:
        self._require_repair_pending()
        self._validate_repair_state_raw(expected)
        state, state_raw = self._decode_current_repair_state()
        facts = self._repair_facts
        ack_journal = self._repair_ack_journal
        verifier = (
            None
            if type(proof) is not AuthenticatedRepairCompletion
            else proof._verifier
        )
        if (
            type(proof) is not AuthenticatedRepairCompletion
            or type(repair_journal) is not RepairStateJournal
            or proof._factory_marker is not _FINAL_REPAIR_COMPLETION_FACTORY
            or proof._journal is not repair_journal
            or proof._journal_identity is not repair_journal._identity
            or repair_journal._authority is not self
            or repair_journal._clear_authorization is not proof
            or proof._used is not used
            or state.phase != "completion_appended"
            or state_raw != expected
            or proof._expected_raw != expected
            or proof._store is not self
            or ack_journal is None
            or ack_journal is not self._ack_journal_owner
            or proof._acknowledgements is not ack_journal
            or proof._ack_snapshot != ack_journal.snapshot()
            or proof._status != self.status()
            or verifier is not self._bound_verifier
            or not self._is_bound_verifier(verifier)
            or proof._verifier_generation != verifier._authority.generation
            or proof._transient_generation
            != verifier._repair_transient_generation
            or verifier._staged
            or verifier._authorizations
            or facts is None
            or self._active is not None
            or self.classify_repair_physical(facts)
            not in {
                RepairPhysicalState.SETTLED_PREFIX,
                RepairPhysicalState.ZERO_RETIRED,
            }
        ):
            raise EvidenceSealError(
                "repair state removal requires exact issued final completion authority"
            )

    def _register_repair_completion_authorization(
        self,
        proof: AuthenticatedRepairCompletion,
        journal: RepairStateJournal,
    ) -> None:
        expected = proof._expected_raw
        self._validate_repair_completion_authority(
            expected,
            proof,
            journal,
            used=False,
        )
        if self._repair_completion_authorization is not None:
            raise EvidenceSealError(
                "final repair completion authority is already registered"
            )
        self._repair_completion_authorization = (
            _RepairCompletionAuthorizationBinding(
                capability=proof,
                journal=journal,
                session_identity=self._repair_session_identity,
                repair_state_raw=expected,
            )
        )

    def remove_repair_state(
        self,
        expected: bytes,
        proof: AuthenticatedRepairCompletion,
    ) -> None:
        completion_binding = self._repair_completion_authorization
        if (
            completion_binding is None
            or completion_binding.capability is not proof
            or completion_binding.session_identity
            is not self._repair_session_identity
            or completion_binding.repair_state_raw != expected
        ):
            raise EvidenceSealError(
                "repair state removal requires exact issued final completion authority"
            )
        self._validate_repair_completion_authority(
            expected,
            proof,
            completion_binding.journal,
            used=True,
        )
        self._repair_completion_authorization = None
        artifact_binding = self._repair_state_binding
        self._remove_bound_repair_artifact(artifact_binding, expected)
        self._repair_state_binding = None
        self._repair_pending = False

    def remove_repair_state_temporary(self, expected: bytes) -> None:
        self._require_repair_pending()
        if (
            type(expected) is not bytes
            or len(expected) > _MAX_REPAIR_STATE_BYTES
        ):
            raise EvidenceStoreError(
                "repair-state temporary expectation exceeds 4096 bytes"
            )
        binding = self._repair_state_temporary
        self._remove_bound_repair_artifact(binding, expected)
        self._repair_state_temporary = None

    def register_authorization(
        self,
        proof: SimulatedRepairAuthorization,
    ) -> AuthenticatedRepairAuthorization:
        self._require_repair_pending()
        if not self._repair_pretruncate:
            raise EvidenceSealError("repair truncate authority has ended")
        verifier = self._require_authenticated_recovered()
        validated = verifier._validate_repair_authorization_proof(proof)
        facts = self._repair_facts
        target = self._repair_target
        if facts is None or target is None:
            raise EvidenceCorrupt("repair target has no original torn facts")
        request = validated.request
        expected_request = (
            request.segment_id == facts.segment_id
            and request.verified_bytes == facts.verified_bytes
            and request.discarded_bytes == facts.discarded_bytes
            and request.discarded_sha256 == facts.discarded_sha256
            and request.last_verified_frame_sha256
            == facts.last_verified_frame_sha256
            and request.current_chain_head_sha256
            == facts.current_chain_head_sha256
            and request.reason == "torn_open_tail"
        )
        if not expected_request:
            raise EvidenceSealError(
                "simulated authorization does not bind held repair facts"
            )
        if (
            self.classify_repair_physical(facts)
            is not RepairPhysicalState.ORIGINAL_TORN
        ):
            raise EvidenceCorrupt(
                "repair target changed before authorization registration"
            )
        _bind_held_source(
            target.directory_descriptor,
            target.open_name,
            target.path,
            descriptor=target.descriptor,
            identity=target.original_identity,
        )
        generation = verifier._authority.generation
        if (
            type(validated.base_generation) is not int
            or validated.base_generation != generation
            or generation != self._repair_base_verifier_generation
        ):
            raise EvidenceSealError(
                "simulated authorization verifier generation is stale"
            )
        target_identity = (
            validated.target.sequence,
            validated.target.event_id,
            validated.target.content_sha256,
            validated.target.event_type,
            validated.target.evidence_priority,
            validated.target.key_epoch,
            validated.target.key_id,
            validated.target.is_retry,
        )
        state, state_raw = self._decode_current_repair_state()
        authorization = state.authorization
        if (
            state.phase != "authorized"
            or authorization is None
            or self._repair_facts_from_state(state) != facts
            or state.repair_id != request.repair_id
            or authorization.sequence != validated.target.sequence
            or authorization.event_id != validated.target.event_id
            or authorization.content_sha256
            != validated.target.content_sha256
        ):
            raise EvidenceSealError(
                "durable authorized state does not bind the exact proof"
            )
        capability = AuthenticatedRepairAuthorization(
            _factory=_AUTHENTICATED_REPAIR_FACTORY
        )
        self._repair_authorization = _RepairAuthorizationBinding(
            capability=capability,
            simulated_proof=validated,
            session_identity=self._repair_session_identity,
            descriptor_identity=target.original_identity,
            facts=facts,
            request_canonical=canonical_json(request),
            target_identity=target_identity,
            verifier_generation=generation,
            repair_state_raw=state_raw,
        )
        return capability

    def truncate(
        self,
        proof: AuthenticatedRepairAuthorization,
    ) -> RepairPhysicalState:
        self._require_repair_pending()
        binding = self._repair_authorization
        facts = self._repair_facts
        target = self._repair_target
        verifier = self._require_authenticated_recovered()
        if (
            type(proof) is not AuthenticatedRepairAuthorization
            or binding is None
            or binding.capability is not proof
            or proof._factory_marker is not _AUTHENTICATED_REPAIR_FACTORY
            or binding.session_identity is not self._repair_session_identity
            or binding.facts is not facts
            or target is None
            or facts is None
            or binding.descriptor_identity != target.original_identity
            or binding.verifier_generation != verifier._authority.generation
            or self.read_repair_state_bytes() != binding.repair_state_raw
            or self.classify_repair_physical(facts)
            is not RepairPhysicalState.ORIGINAL_TORN
        ):
            raise EvidenceSealError(
                "truncate requires the exact live registered authorization"
            )
        _bind_held_source(
            target.directory_descriptor,
            target.open_name,
            target.path,
            descriptor=target.descriptor,
            identity=target.original_identity,
        )
        try:
            live_proof = verifier._validate_repair_authorization_proof(
                binding.simulated_proof
            )
            live_target_identity = (
                live_proof.target.sequence,
                live_proof.target.event_id,
                live_proof.target.content_sha256,
                live_proof.target.event_type,
                live_proof.target.evidence_priority,
                live_proof.target.key_epoch,
                live_proof.target.key_id,
                live_proof.target.is_retry,
            )
            live_request_canonical = canonical_json(live_proof.request)
        except (
            AttributeError,
            IngestVerificationError,
            TypeError,
            ValueError,
            VerifierCommitError,
        ) as error:
            raise EvidenceSealError(
                "registered repair authorization proof is stale"
            ) from error
        if (
            live_proof is not binding.simulated_proof
            or live_request_canonical != binding.request_canonical
            or live_target_identity != binding.target_identity
            or binding.verifier_generation != verifier._authority.generation
        ):
            raise EvidenceSealError(
                "registered repair authorization proof is stale"
            )
        self._repair_authorization = None
        os.ftruncate(target.descriptor, facts.verified_bytes)
        os.fsync(target.descriptor)
        current = _file_identity(os.fstat(target.descriptor))
        current_path = _file_identity(
            _regular_stat_at(
                target.directory_descriptor,
                target.open_name,
                target.path,
            )
        )
        if (
            current != current_path
            or current.device != facts.original_device
            or current.inode != facts.original_inode
            or current.size != facts.verified_bytes
            or _hash_held_range(
                target.directory_descriptor,
                target.open_name,
                target.path,
                descriptor=target.descriptor,
                identity=current,
                start=0,
                end=current.size,
            )
            != facts.post_repair_prefix_sha256
        ):
            self._repair_physical_state = RepairPhysicalState.INVALID
            raise EvidenceCorrupt("authorized repair truncate has uncertain facts")
        state = (
            RepairPhysicalState.ZERO_HELD
            if facts.verified_bytes == 0
            else RepairPhysicalState.CLEAN_OPEN
        )
        self._repair_physical_state = state
        return state

    def retire_zero_prefix(self, expected_repair_state: bytes) -> None:
        self._require_repair_pending()
        if self.read_repair_state_bytes() != expected_repair_state:
            raise RepairStateConflict("zero retirement state CAS mismatch")
        facts = self._repair_facts
        target = self._repair_target
        state, state_raw = self._decode_current_repair_state()
        if (
            facts is None
            or target is None
            or facts.verified_bytes != 0
            or state_raw != expected_repair_state
            or state.phase
            not in {
                "truncated",
                "authorization_appended",
                "completion_appended",
            }
            or self._repair_facts_from_state(state) != facts
            or self.classify_repair_physical(facts)
            is not RepairPhysicalState.ZERO_HELD
        ):
            raise EvidenceCorrupt("repair target is not the exact held zero inode")
        held = _file_identity(os.fstat(target.descriptor))
        published = _file_identity(
            _regular_stat_at(
                target.directory_descriptor,
                target.open_name,
                target.path,
            )
        )
        if (
            held != published
            or held.device != facts.original_device
            or held.inode != facts.original_inode
            or held.size != 0
        ):
            raise EvidenceCorrupt("zero repair inode changed before retirement")
        os.unlink(target.open_name, dir_fd=target.directory_descriptor)
        os.fsync(target.directory_descriptor)
        retired = os.fstat(target.descriptor)
        if (
            retired.st_dev != facts.original_device
            or retired.st_ino != facts.original_inode
            or retired.st_size != 0
            or retired.st_nlink != 0
            or _entry_stat_at(target.directory_descriptor, target.open_name)
            is not None
        ):
            self._latch_repair_namespace_uncertain()
            raise EvidenceCorrupt("zero repair inode retirement is uncertain")
        self._repair_physical_state = RepairPhysicalState.ZERO_RETIRED

    def _activate_held_repair_open(
        self,
        target: _RepairTarget,
        *,
        original_facts: TailRepairFacts | None,
    ) -> None:
        scan = self._read_segment(
            target.directory_descriptor,
            target.open_name,
            target.path,
            allow_torn=False,
        )
        validated = self._validated_active_scan(
            target.date_name,
            target.open_name,
            scan,
        )
        if original_facts is None:
            state, _state_raw = self._decode_current_repair_state()
            self._validate_post_h0_active_state(state, validated)
            if (
                scan.identity != target.original_identity
                or scan.size != target.scan.size
                or scan.sha256 != target.scan.sha256
            ):
                raise EvidenceCorrupt(
                    "post-H0 active tail changed before handoff"
                )
        elif (
            scan.size != original_facts.verified_bytes
            or scan.sha256 != original_facts.post_repair_prefix_sha256
            or scan.identity.device != original_facts.original_device
            or scan.identity.inode != original_facts.original_inode
            or validated.frames[-1].record_hash.hex()
            != original_facts.last_verified_frame_sha256
        ):
            raise EvidenceCorrupt("repaired prefix changed before handoff")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            target.open_name,
            flags,
            dir_fd=target.directory_descriptor,
        )
        try:
            _bind_held_source(
                target.directory_descriptor,
                target.open_name,
                target.path,
                descriptor=descriptor,
                identity=scan.identity,
            )
        except BaseException:
            os.close(descriptor)
            raise
        os.close(target.descriptor)
        self._active = _ActiveSegment(
            segment_id=validated.segment_id,
            open_path=target.path,
            open_name=target.open_name,
            closed_name=validated.closed_name,
            closed_relative_path=validated.closed_relative_path,
            directory_descriptor=target.directory_descriptor,
            priority=validated.priority,
            host_id=validated.host_id,
            first_source_sequence=validated.first_source_sequence,
            opened_at=validated.opened_at,
            opened_monotonic=self._monotonic() - MAX_SEGMENT_AGE_SECONDS,
            descriptor=descriptor,
            size=scan.size,
            record_count=len(validated.records),
            previous_frame_hash=validated.frames[-1].record_hash,
        )
        self._repair_prefix_needs_settlement = True

    def resume_store(self) -> SegmentStore:
        self._require_repair_pending()
        facts = self._repair_facts
        verifier = self._require_authenticated_recovered()
        state, _state_raw = self._decode_current_repair_state()
        if (
            facts is None
            or state.phase
            not in {
                "truncated",
                "authorization_appended",
                "completion_appended",
            }
            or self._repair_facts_from_state(state) != facts
        ):
            raise EvidenceSealError(
                "repair resume requires exact durable state and physical facts"
            )
        if verifier._authority.generation != self._repair_base_verifier_generation:
            raise EvidenceSealError("live verifier changed before repair resume")
        journal = self._repair_ack_journal
        if (
            journal is None
            or journal is not self._ack_journal_owner
            or journal.snapshot() != self._repair_ack_snapshot
        ):
            raise EvidenceSealError("retained repair ACK authority changed")
        startup_physical = self.classify_repair_physical(facts)
        if startup_physical is RepairPhysicalState.ZERO_HELD:
            raise EvidenceSealError(
                "zero repair prefix must be retired before store resume"
            )
        if startup_physical not in {
            RepairPhysicalState.CLEAN_OPEN,
            RepairPhysicalState.SETTLED_PREFIX,
            RepairPhysicalState.ZERO_RETIRED,
        }:
            raise EvidenceCorrupt("repair target is not durably resumable")
        plan = self._repair_recovery_plan
        if plan is None:
            raise EvidenceSealError("repair startup recovery plan was already consumed")
        self._apply_recovery_plan(plan)
        self._repair_recovery_plan = None
        physical = self.classify_repair_physical(facts)
        if physical not in {
            RepairPhysicalState.CLEAN_OPEN,
            RepairPhysicalState.SETTLED_PREFIX,
            RepairPhysicalState.ZERO_RETIRED,
        }:
            raise EvidenceCorrupt(
                "repair target changed while startup recovery was applied"
            )
        self._repair_physical_state = physical

        target = self._repair_target
        if physical is RepairPhysicalState.CLEAN_OPEN:
            if target is None:
                raise EvidenceCorrupt("clean repaired prefix has no held target")
            self._activate_held_repair_open(
                target,
                original_facts=facts,
            )
            self._repair_target = None
        elif target is not None:
            os.close(target.descriptor)
            self._repair_target = None

        post_h0_active = self._repair_post_h0_active
        if post_h0_active is not None:
            if self._active is not None:
                raise EvidenceCorrupt(
                    "repair resume found multiple active evidence tails"
                )
            self._activate_held_repair_open(
                post_h0_active,
                original_facts=None,
            )
            self._repair_post_h0_active = None

        self._repair_mode = False
        self._repair_pretruncate = False
        self._repair_resumed = True
        self.__class__ = SegmentStore
        return self

    @property
    def acceptance_cursor(self) -> int:
        """Highest source cursor made contiguous by signed-or-covered evidence."""
        verifier = self._require_authenticated_recovered()
        holes = verifier.fsm.unresolved_holes
        return holes[0][0] - 1 if holes else verifier.fsm.last_sequence

    def resolve_authenticated_ref(self, ref: EvidenceRef) -> StoredEvidenceRecord:
        """Resolve one complete ref only after verifier-authenticated recovery."""
        verifier = self._require_authenticated_recovered()
        key = (verifier.fsm.host_id, ref.source_sequence)
        indexed = self._index.get(key)
        if (
            indexed is None
            or indexed[1] != ref
            or verifier.accepted_ref(ref.source_sequence) != ref
        ):
            raise _AckAuthorityError(
                "ACK ref does not match one complete authenticated evidence ref"
            )
        position = self._record_positions.get(key)
        if position is None:
            raise EvidenceCorrupt("authenticated evidence index has no record position")
        record = self._records[position]
        if record.ref != ref:
            raise EvidenceCorrupt("authenticated evidence position changed")
        return StoredEvidenceRecord(
            envelope=copy.deepcopy(record.envelope),
            canonical_envelope=record.canonical_envelope,
            priority=record.priority,
            accepted_at=record.accepted_at,
            ref=record.ref,
        )

    def _authenticated_pcc_input(
        self,
        verifier: EnvelopeVerifier,
        ref: EvidenceRef,
        request: PCCCorrelationSnapshotRequestV1,
    ) -> AuthenticatedPCCInput:
        if (
            self._closed
            or self._authority_state != "ready"
            or self._bound_verifier is not verifier
            or type(ref) is not EvidenceRef
            or type(request) is not PCCCorrelationSnapshotRequestV1
        ):
            raise EvidenceSealError(
                "PCC correlation input requires exact recovered store authority"
            )
        record = self.resolve_authenticated_ref(ref)
        if (
            record.priority is not EvidencePriority.PROTECTED
            or record.envelope.get("event_type")
            != "pcc_correlation_snapshot"
        ):
            raise EvidenceSealError(
                "PCC correlation input does not name protected PCC evidence"
            )
        try:
            authenticated = verifier._issue_authenticated_pcc_input(
                record.ref,
                request,
                self._lifecycle_identity,
            )
        except VerifierCommitError as error:
            raise EvidenceSealError(
                "PCC correlation input lacks committed verifier authority"
            ) from error
        self._issued_pcc_inputs[authenticated] = _StoreIssuedPCCBinding(
            lifecycle=self._lifecycle_identity,
            verifier=verifier,
            verifier_authority=verifier._authority,
            verifier_generation=verifier._authority.generation,
            evidence_ref=_exact_coverage_ref_key(record.ref),
            canonical=authenticated.canonical,
            request_canonical=canonical_json(authenticated.request),
            request_fields_set=frozenset(
                authenticated.request.model_fields_set
            ),
            snapshot_canonical=canonical_json(authenticated.snapshot),
            snapshot_fields_set=frozenset(
                authenticated.snapshot.model_fields_set
            ),
        )
        return authenticated

    def _authenticated_pcc_input_is_exact(
        self,
        authenticated: object,
    ) -> bool:
        if type(authenticated) is not AuthenticatedPCCInput:
            return False
        binding = self._issued_pcc_inputs.get(authenticated)
        verifier = self._bound_verifier
        if binding is None or verifier is None:
            return False
        try:
            return (
                not self._closed
                and self._authority_state == "ready"
                and self._lifecycle_identity is binding.lifecycle
                and verifier is binding.verifier
                and self._is_bound_verifier(verifier)
                and verifier._authority is binding.verifier_authority
                and verifier._authority.generation
                == binding.verifier_generation
                and _exact_coverage_ref_key(authenticated.evidence_ref)
                == binding.evidence_ref
                and authenticated.canonical == binding.canonical
                and canonical_json(authenticated.request)
                == binding.request_canonical
                and frozenset(authenticated.request.model_fields_set)
                == binding.request_fields_set
                and canonical_json(authenticated.snapshot)
                == binding.snapshot_canonical
                and frozenset(authenticated.snapshot.model_fields_set)
                == binding.snapshot_fields_set
            )
        except (AttributeError, TypeError, UnicodeError, ValueError):
            return False

    def _historical_path_authority(
        self,
        authenticated: AuthenticatedPCCInput,
    ) -> HistoricalPathAuthority:
        """Issue one opaque exact-store path capability for a committed PCC."""
        from agmind_immune.coverage.historical import (
            _issue_historical_path_authority,
        )

        return _issue_historical_path_authority(self, authenticated)

    def _authenticated_falco_input(
        self,
        verifier: EnvelopeVerifier,
        ref: EvidenceRef,
    ) -> AuthenticatedFalcoInput:
        if (
            self._closed
            or self._authority_state != "ready"
            or self._bound_verifier is not verifier
            or type(ref) is not EvidenceRef
        ):
            raise EvidenceSealError(
                "Falco input requires exact recovered store authority"
            )
        record = self.resolve_authenticated_ref(ref)
        if (
            record.priority is not EvidencePriority.ROUTINE
            or record.envelope.get("event_type") != "falco_connect"
        ):
            raise EvidenceSealError(
                "Falco input does not name routine Falco evidence"
            )
        try:
            return verifier._issue_authenticated_falco_input(
                record.ref,
                self._lifecycle_identity,
            )
        except VerifierCommitError as error:
            raise EvidenceSealError(
                "Falco input lacks committed verifier authority"
            ) from error

    def iter_authenticated_records(
        self,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Iterator[StoredEvidenceRecord]:
        """Iterate authenticated records in evidence order within explicit bounds."""
        verifier = self._require_authenticated_recovered()
        if not 0 <= after <= MAX_UINT64:
            raise ValueError("authenticated evidence lower bound is invalid")
        if through is not None and not 0 <= through <= MAX_UINT64:
            raise ValueError("authenticated evidence upper bound is invalid")
        host_id = verifier.fsm.host_id
        sequences = self._sequences_by_host.get(host_id, [])
        start = bisect_right(sequences, after)
        stop = len(sequences) if through is None else bisect_right(sequences, through)
        for position in range(start, stop):
            sequence = sequences[position]
            indexed = self._index.get((host_id, sequence))
            if indexed is None:
                raise EvidenceCorrupt("authenticated evidence sequence index changed")
            yield self.resolve_authenticated_ref(indexed[1])

    def _acquire_coverage_state(self, owner: object) -> object:
        self._require_authenticated_recovered()
        if self._coverage_state_owner is not None:
            raise EvidenceStoreBusy("evidence root already has one coverage-state owner")
        self._coverage_state_owner = owner
        return self._lifecycle_identity

    def _resolve_next_coverage_record(
        self,
        owner: object,
        lifecycle_identity: object,
        record: StoredEvidenceRecord,
        *,
        after_ref: EvidenceRef | None,
    ) -> StoredEvidenceRecord:
        verifier = self._require_authenticated_recovered()
        if (
            owner is not self._coverage_state_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise EvidenceSealError("coverage state is outside this evidence lifecycle")
        try:
            _exact_coverage_record_key(record)
            if after_ref is not None:
                _exact_coverage_ref_key(after_ref)
        except ValueError as error:
            raise EvidenceSealError("coverage apply record is not exact") from error
        host_id = verifier.fsm.host_id
        sequences = self._sequences_by_host.get(host_id, [])
        if after_ref is None:
            position = 0
        else:
            self.resolve_authenticated_ref(after_ref)
            position = bisect_right(sequences, after_ref.source_sequence)
        if position >= len(sequences):
            raise EvidenceSealError(
                "coverage apply has no next authenticated real evidence ref"
            )
        next_ref = self._index[(host_id, sequences[position])][1]
        try:
            _exact_coverage_ref_key(next_ref)
        except ValueError as error:
            raise EvidenceCorrupt(
                "next authenticated coverage ref is invalid"
            ) from error
        if not _same_exact_coverage_ref(record.ref, next_ref):
            raise EvidenceSealError(
                "coverage apply skipped the next authenticated real evidence ref"
            )
        resolved = self.resolve_authenticated_ref(next_ref)
        try:
            same_resolved_record = _same_exact_coverage_record(resolved, record)
        except ValueError as error:
            raise EvidenceCorrupt(
                "resolved authenticated coverage record is invalid"
            ) from error
        if not same_resolved_record:
            raise EvidenceSealError(
                "coverage apply record differs from authenticated evidence"
            )
        return resolved

    def _validate_coverage_state_owner(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        reducer_head: EvidenceRef | None,
    ) -> EvidenceRef | None:
        verifier = self._require_authenticated_recovered()
        if (
            owner is not self._coverage_state_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise EvidenceSealError("coverage state is outside this evidence lifecycle")
        sequence = verifier.fsm.last_sequence
        authenticated_head: EvidenceRef | None = None
        if reducer_head is not None:
            try:
                _exact_coverage_ref_key(reducer_head)
            except ValueError as error:
                raise EvidenceSealError("coverage reducer head is invalid") from error
        if sequence != 0:
            ref = verifier.accepted_ref(sequence)
            if type(ref) is not EvidenceRef:
                raise EvidenceCorrupt(
                    "authenticated evidence head has no exact ref"
                )
            try:
                _exact_coverage_ref_key(ref)
            except ValueError as error:
                raise EvidenceCorrupt(
                    "authenticated evidence head has no exact ref"
                ) from error
            self.resolve_authenticated_ref(ref)
            authenticated_head = ref
        same_head = authenticated_head is reducer_head
        if authenticated_head is not None and reducer_head is not None:
            same_head = _same_exact_coverage_ref(authenticated_head, reducer_head)
        if not same_head:
            raise EvidenceSealError(
                "coverage reducer head differs from authenticated evidence head"
            )
        return authenticated_head

    def _release_coverage_state(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._coverage_state_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise EvidenceSealError("coverage state release has the wrong lifecycle")
        self._coverage_state_owner = None

    def authenticated_refs(
        self,
        *,
        after_sequence: int,
        through_sequence: int,
        limit: int,
    ) -> tuple[EvidenceRef, ...]:
        """Return one mutation-safe bounded batch of exact committed refs."""
        verifier = self._require_ack_mutation_ready()
        if (
            isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or not 0 <= after_sequence <= MAX_UINT64
            or isinstance(through_sequence, bool)
            or not isinstance(through_sequence, int)
            or not 0 <= through_sequence <= MAX_UINT64
            or through_sequence < after_sequence
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("authenticated ref bounds are invalid")

        host_id = verifier.fsm.host_id
        sequences = self._sequences_by_host.get(host_id, [])
        start = bisect_right(sequences, after_sequence)
        stop = bisect_right(sequences, through_sequence)
        refs: list[EvidenceRef] = []
        previous = after_sequence
        for position in range(start, stop):
            sequence = sequences[position]
            if sequence <= previous:
                raise EvidenceCorrupt(
                    "authenticated evidence refs are not strictly ascending"
                )
            indexed = self._index.get((host_id, sequence))
            if indexed is None:
                raise EvidenceCorrupt(
                    "authenticated evidence sequence index changed"
                )
            ref = indexed[1]
            self.resolve_authenticated_ref(ref)
            refs.append(ref)
            previous = sequence
            if len(refs) == limit:
                break
        return tuple(refs)

    def _correlation_journal_artifact_identity(self) -> _FileIdentity | None:
        try:
            if (
                _entry_stat_at(
                    self._root_descriptor,
                    _CORRELATION_JOURNAL_NAME,
                )
                is None
            ):
                return None
            return _file_identity(
                _regular_stat_at(
                    self._root_descriptor,
                    _CORRELATION_JOURNAL_NAME,
                    self.root / _CORRELATION_JOURNAL_NAME,
                )
            )
        except EvidenceCorrupt as error:
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal root artifact is unsafe or unstable"
            ) from error
        except OSError as error:
            raise _CorrelationJournalLifecycleIoUncertain(
                "correlation-journal root artifact I/O is uncertain"
            ) from error

    def _correlation_journal_prefix_digest(
        self,
        prefix_size: int,
    ) -> tuple[_FileIdentity, bytes]:
        if (
            isinstance(prefix_size, bool)
            or not isinstance(prefix_size, int)
            or prefix_size < 0
        ):
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal prefix size is invalid"
            )
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                _CORRELATION_JOURNAL_NAME,
                flags,
                dir_fd=self._root_descriptor,
            )
        except FileNotFoundError as error:
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal authority disappeared during content binding"
            ) from error
        except OSError as error:
            raise _CorrelationJournalLifecycleIoUncertain(
                "correlation-journal content binding I/O is uncertain"
            ) from error
        primary_error: BaseException | None = None
        try:
            try:
                opened_identity = _file_identity(os.fstat(descriptor))
                published_identity = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        _CORRELATION_JOURNAL_NAME,
                        self.root / _CORRELATION_JOURNAL_NAME,
                    )
                )
                if (
                    opened_identity != published_identity
                    or opened_identity.size < prefix_size
                ):
                    raise _CorrelationJournalLifecycleCorrupt(
                        "correlation-journal prefix identity changed"
                    )
                digest = hashlib.sha256()
                offset = 0
                while offset < prefix_size:
                    chunk = os.pread(
                        descriptor,
                        min(1024 * 1024, prefix_size - offset),
                        offset,
                    )
                    if not chunk:
                        raise _CorrelationJournalLifecycleCorrupt(
                            "correlation-journal prefix shortened during hashing"
                        )
                    digest.update(chunk)
                    offset += len(chunk)
                after_identity = _file_identity(os.fstat(descriptor))
                published_after = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        _CORRELATION_JOURNAL_NAME,
                        self.root / _CORRELATION_JOURNAL_NAME,
                    )
                )
                if (
                    after_identity != opened_identity
                    or published_after != opened_identity
                ):
                    raise _CorrelationJournalLifecycleCorrupt(
                        "correlation-journal identity changed during prefix hashing"
                    )
                return opened_identity, digest.digest()
            except FileNotFoundError as error:
                raise _CorrelationJournalLifecycleCorrupt(
                    "correlation-journal prefix disappeared during binding"
                ) from error
            except EvidenceCorrupt as error:
                raise _CorrelationJournalLifecycleCorrupt(
                    "correlation-journal prefix is unsafe or unstable"
                ) from error
            except OSError as error:
                raise _CorrelationJournalLifecycleIoUncertain(
                    "correlation-journal prefix I/O is uncertain"
                ) from error
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                os.close(descriptor)
            except OSError as close_error:
                if primary_error is None:
                    raise _CorrelationJournalLifecycleIoUncertain(
                        "correlation-journal prefix descriptor close became uncertain"
                    ) from close_error
                primary_error.add_note(
                    "secondary correlation-journal prefix descriptor close failure: "
                    f"{type(close_error).__name__}: {close_error}"
                )

    @staticmethod
    def _same_correlation_journal_inode(
        actual: _FileIdentity,
        expected: _FileIdentity,
    ) -> bool:
        return (
            actual.device == expected.device
            and actual.inode == expected.inode
        )

    def _acquire_correlation_journal(
        self,
        owner: object,
        *,
        operation: Literal["create", "recover"],
    ) -> tuple[int, object]:
        self._require_ack_mutation_ready()
        if self._correlation_journal_owner is not None:
            raise EvidenceStoreBusy(
                "evidence root already has one correlation-journal owner"
            )
        state = self._correlation_journal_state
        if state == "unknown":
            raise _CorrelationJournalLifecycleStateError(
                "correlation-journal startup presence was not authenticated"
            )
        if state == "initialization_uncertain":
            raise _CorrelationJournalLifecycleStateError(
                "correlation-journal initialization is uncertain until store restart"
            )
        if state in {"append_uncertain", "io_uncertain"}:
            raise _CorrelationJournalLifecycleStateError(
                "correlation-journal publication is uncertain until store restart"
            )
        if state in {"creating", "recovering"}:
            raise _CorrelationJournalLifecycleStateError(
                "correlation-journal initialization did not settle"
            )

        actual_identity = self._correlation_journal_artifact_identity()
        if state in {"present", "initialized"}:
            expected_identity = self._correlation_journal_identity
            if actual_identity is None:
                raise _CorrelationJournalLifecycleCorrupt(
                    "expected correlation-journal authority disappeared"
                )
            if expected_identity is None or actual_identity != expected_identity:
                raise _CorrelationJournalLifecycleCorrupt(
                    "expected correlation-journal authority changed identity"
                )
        elif state == "fresh" and actual_identity is not None:
            raise _CorrelationJournalLifecycleCorrupt(
                "unexpected correlation journal appeared in a fresh store lifecycle"
            )

        if operation == "create":
            if state != "fresh":
                raise _CorrelationJournalLifecycleStateError(
                    "correlation journal may be created only in a fresh store lifecycle"
                )
            next_state: Literal["creating", "recovering"] = "creating"
        elif operation == "recover":
            if state != "present":
                raise _CorrelationJournalLifecycleStateError(
                    "correlation journal may be recovered only from startup presence"
                )
            next_state = "recovering"
        else:
            raise _CorrelationJournalLifecycleStateError(
                "correlation journal operation is invalid"
            )

        duplicate_command = getattr(fcntl, "F_DUPFD_CLOEXEC", None)
        if duplicate_command is None:
            root_descriptor = os.dup(self._root_descriptor)
            try:
                os.set_inheritable(root_descriptor, False)
            except BaseException as error:
                try:
                    os.close(root_descriptor)
                except OSError as cleanup_error:
                    error.add_note(
                        "secondary correlation root descriptor cleanup failure: "
                        f"{cleanup_error}"
                    )
                raise
        else:
            root_descriptor = fcntl.fcntl(
                self._root_descriptor,
                duplicate_command,
                0,
            )
        self._correlation_journal_owner = owner
        self._correlation_journal_operation = operation
        self._correlation_journal_state = next_state
        return root_descriptor, self._lifecycle_identity

    def _correlation_journal_final_name_created(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._correlation_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._correlation_journal_operation != "create"
            or self._correlation_journal_state
            not in {"creating", "initialization_uncertain"}
        ):
            raise _CorrelationJournalLifecycleStateError(
                "correlation-journal create publication has the wrong lifecycle"
            )
        self._correlation_journal_state = "initialization_uncertain"

    def _complete_correlation_journal_initialization(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated: os.stat_result,
        authenticated_digest: bytes,
    ) -> None:
        if (
            owner is not self._correlation_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise _CorrelationJournalLifecycleStateError(
                "correlation-journal completion has the wrong lifecycle"
            )
        operation = self._correlation_journal_operation
        state = self._correlation_journal_state
        if not (
            (operation == "create" and state == "initialization_uncertain")
            or (operation == "recover" and state == "recovering")
        ):
            raise _CorrelationJournalLifecycleStateError(
                "correlation-journal completion did not follow create or recovery"
            )
        actual_identity = self._correlation_journal_artifact_identity()
        authenticated_identity = _file_identity(authenticated)
        if actual_identity is None:
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal authority disappeared before initialization completed"
            )
        if actual_identity != authenticated_identity:
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal authority changed before initialization completed"
            )
        if len(authenticated_digest) != hashlib.sha256().digest_size:
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal authenticated digest is invalid"
            )
        expected_identity = self._correlation_journal_identity
        if (
            operation == "recover"
            and (
                expected_identity is None
                or authenticated_identity != expected_identity
            )
        ):
            raise _CorrelationJournalLifecycleCorrupt(
                "recovered correlation journal differs from startup identity"
            )
        self._correlation_journal_identity = authenticated_identity
        self._correlation_journal_digest = authenticated_digest
        self._correlation_journal_state = "initialized"

    def _validate_correlation_journal_owner(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        self._require_ack_mutation_ready()
        if (
            owner is not self._correlation_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._correlation_journal_state
            not in {"recovering", "initialization_uncertain", "initialized"}
        ):
            raise EvidenceSealError(
                "correlation journal is outside this evidence lifecycle"
            )

    def _seal_correlation_journal_identity(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated: os.stat_result,
        authenticated_digest: bytes,
    ) -> None:
        if (
            owner is not self._correlation_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._correlation_journal_state != "initialized"
        ):
            raise _CorrelationJournalLifecycleStateError(
                "correlation-journal seal has the wrong lifecycle"
            )
        authenticated_identity = _file_identity(authenticated)
        if len(authenticated_digest) != hashlib.sha256().digest_size:
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal seal digest is invalid"
            )
        actual_identity = self._correlation_journal_artifact_identity()
        expected_identity = self._correlation_journal_identity
        if (
            actual_identity is None
            or actual_identity != authenticated_identity
            or expected_identity is None
            or not self._same_correlation_journal_inode(
                authenticated_identity,
                expected_identity,
            )
        ):
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal authority changed before seal"
            )
        self._correlation_journal_identity = authenticated_identity
        self._correlation_journal_digest = authenticated_digest

    def _mark_correlation_journal_append_uncertain(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated_before: os.stat_result,
        authenticated_digest_before: bytes,
    ) -> None:
        if (
            owner is not self._correlation_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._correlation_journal_state
            not in {"initialized", "append_uncertain"}
        ):
            raise _CorrelationJournalLifecycleStateError(
                "correlation-journal uncertainty has the wrong lifecycle"
            )
        retained_identity = _file_identity(authenticated_before)
        if len(authenticated_digest_before) != hashlib.sha256().digest_size:
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal pre-append digest is invalid"
            )
        expected_identity = self._correlation_journal_identity
        if (
            expected_identity is None
            or not self._same_correlation_journal_inode(
                retained_identity,
                expected_identity,
            )
        ):
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal pre-append identity changed"
            )
        self._correlation_journal_identity = retained_identity
        self._correlation_journal_digest = authenticated_digest_before
        self._correlation_journal_state = "append_uncertain"

    def _mark_correlation_journal_io_uncertain(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated: os.stat_result | None,
        authenticated_digest: bytes | None,
    ) -> None:
        if (
            owner is not self._correlation_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._correlation_journal_state
            not in {
                "recovering",
                "initialization_uncertain",
                "initialized",
                "io_uncertain",
            }
        ):
            raise _CorrelationJournalLifecycleStateError(
                "correlation-journal I/O uncertainty has the wrong lifecycle"
            )
        if (authenticated is None) != (authenticated_digest is None):
            raise _CorrelationJournalLifecycleCorrupt(
                "correlation-journal I/O uncertainty has an incomplete content anchor"
            )
        if authenticated is not None and authenticated_digest is not None:
            retained_identity = _file_identity(authenticated)
            if len(authenticated_digest) != hashlib.sha256().digest_size:
                raise _CorrelationJournalLifecycleCorrupt(
                    "correlation-journal I/O uncertainty digest is invalid"
                )
            expected_identity = self._correlation_journal_identity
            if expected_identity is not None:
                if not self._same_correlation_journal_inode(
                    retained_identity,
                    expected_identity,
                ):
                    raise _CorrelationJournalLifecycleCorrupt(
                        "correlation-journal I/O uncertainty identity changed"
                    )
            elif self._correlation_journal_state != "initialization_uncertain":
                raise _CorrelationJournalLifecycleCorrupt(
                    "correlation-journal I/O uncertainty has no identity anchor"
                )
            actual_identity = self._correlation_journal_artifact_identity()
            if (
                actual_identity is None
                or not self._same_correlation_journal_inode(
                    actual_identity,
                    retained_identity,
                )
                or actual_identity.size < retained_identity.size
            ):
                raise _CorrelationJournalLifecycleCorrupt(
                    "correlation-journal I/O uncertainty lost its content anchor"
                )
            self._correlation_journal_identity = retained_identity
            self._correlation_journal_digest = authenticated_digest
        if self._correlation_journal_state != "initialization_uncertain":
            self._correlation_journal_state = "io_uncertain"

    def _release_correlation_journal(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._correlation_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise EvidenceSealError(
                "correlation journal release has the wrong lifecycle"
            )
        state = self._correlation_journal_state
        if state == "creating":
            self._correlation_journal_state = "fresh"
        elif state in {"recovering", "initialized"}:
            self._correlation_journal_state = "present"
        self._correlation_journal_owner = None
        self._correlation_journal_operation = None

    def _ack_journal_artifact_identity(self) -> _FileIdentity | None:
        name = "ack-journal.agf"
        try:
            if _entry_stat_at(self._root_descriptor, name) is None:
                return None
            return _file_identity(
                _regular_stat_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                )
            )
        except EvidenceCorrupt as error:
            raise _AckLifecycleCorrupt(
                "ACK-journal root artifact is unsafe or unstable"
            ) from error
        except OSError as error:
            raise _AckLifecycleIoUncertain(
                "ACK-journal root artifact I/O is uncertain"
            ) from error

    def _ack_journal_prefix_digest(
        self,
        prefix_size: int,
    ) -> tuple[_FileIdentity, bytes]:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                "ack-journal.agf",
                flags,
                dir_fd=self._root_descriptor,
            )
        except FileNotFoundError as error:
            raise _AckLifecycleCorrupt(
                "ACK-journal authority disappeared during content binding"
            ) from error
        except OSError as error:
            raise _AckLifecycleIoUncertain(
                "ACK-journal content binding I/O is uncertain"
            ) from error
        primary_error: BaseException | None = None
        try:
            try:
                opened_identity = _file_identity(os.fstat(descriptor))
                published_identity = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        "ack-journal.agf",
                        self.root / "ack-journal.agf",
                    )
                )
                if (
                    opened_identity != published_identity
                    or opened_identity.size < prefix_size
                ):
                    raise _AckLifecycleCorrupt(
                        "ACK-journal prefix identity changed"
                    )
                digest = hashlib.sha256()
                offset = 0
                while offset < prefix_size:
                    chunk = os.pread(
                        descriptor,
                        min(1024 * 1024, prefix_size - offset),
                        offset,
                    )
                    if not chunk:
                        raise _AckLifecycleCorrupt(
                            "ACK-journal prefix shortened during hashing"
                        )
                    digest.update(chunk)
                    offset += len(chunk)
                after_identity = _file_identity(os.fstat(descriptor))
                published_after = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        "ack-journal.agf",
                        self.root / "ack-journal.agf",
                    )
                )
                if (
                    after_identity != opened_identity
                    or published_after != opened_identity
                ):
                    raise _AckLifecycleCorrupt(
                        "ACK-journal identity changed during prefix hashing"
                    )
                return opened_identity, digest.digest()
            except FileNotFoundError as error:
                raise _AckLifecycleCorrupt(
                    "ACK-journal prefix disappeared during binding"
                ) from error
            except EvidenceCorrupt as error:
                raise _AckLifecycleCorrupt(
                    "ACK-journal prefix is unsafe or unstable"
                ) from error
            except OSError as error:
                raise _AckLifecycleIoUncertain(
                    "ACK-journal prefix I/O is uncertain"
                ) from error
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                os.close(descriptor)
            except OSError as close_error:
                if primary_error is None:
                    raise _AckLifecycleIoUncertain(
                        "ACK-journal prefix descriptor close became uncertain"
                    ) from close_error
                primary_error.add_note(
                    "secondary ACK-journal prefix descriptor close failure: "
                    f"{type(close_error).__name__}: {close_error}"
                )

    @staticmethod
    def _same_ack_journal_inode(
        actual: _FileIdentity,
        expected: _FileIdentity,
    ) -> bool:
        return (
            actual.device == expected.device
            and actual.inode == expected.inode
        )

    @staticmethod
    def _ack_genesis_commitment(
        phase: Literal["initializing", "ready"],
    ) -> _AckCommitmentV1:
        return _AckCommitmentV1(
            schema_version="agmind.core-ack-commitment.v1",
            phase=phase,
            generation=0,
            confirmed=None,
            journal_prefix_size=0,
            journal_prefix_sha256=_EMPTY_SHA256,
        )

    def _read_ack_commitment(
        self,
    ) -> tuple[_AckCommitmentV1, bytes, _FileIdentity]:
        try:
            raw = _read_regular_at(
                self._root_descriptor,
                _ACK_COMMITMENT_NAME,
                self.root / _ACK_COMMITMENT_NAME,
                _MAX_ACK_COMMITMENT_BYTES,
            )
            commitment = _decode_ack_commitment(raw)
            if raw != _canonical_ack_commitment(commitment):
                raise EvidenceCorrupt("ACK commitment is not canonical JSON")
            identity = _file_identity(
                _regular_stat_at(
                    self._root_descriptor,
                    _ACK_COMMITMENT_NAME,
                    self.root / _ACK_COMMITMENT_NAME,
                )
            )
            return commitment, raw, identity
        except FileNotFoundError as error:
            raise _AckLifecycleCorrupt(
                "ACK commitment artifact disappeared"
            ) from error
        except OSError as error:
            raise _AckLifecycleIoUncertain(
                "ACK commitment artifact I/O is uncertain"
            ) from error
        except (
            EvidenceCorrupt,
            RecursionError,
            TypeError,
            ValueError,
            ValidationError,
        ) as error:
            raise _AckLifecycleCorrupt(
                "ACK commitment artifact is invalid or unstable"
            ) from error

    def _rebind_ack_commitment(
        self,
        *,
        expected: _AckCommitmentV1 | None = None,
    ) -> _AckCommitmentV1:
        commitment, raw, identity = self._read_ack_commitment()
        if expected is not None and commitment != expected:
            raise _AckLifecycleCorrupt(
                "published ACK commitment differs from the requested state"
            )
        self._ack_commitment = commitment
        self._ack_commitment_raw = raw
        self._ack_commitment_identity = identity
        return commitment

    def _validate_ack_commitment_binding(self) -> _AckCommitmentV1:
        expected = self._ack_commitment
        expected_raw = self._ack_commitment_raw
        expected_identity = self._ack_commitment_identity
        if (
            expected is None
            or expected_raw is None
            or expected_identity is None
        ):
            raise _AckLifecycleCorrupt("ACK commitment binding is absent")
        actual, raw, identity = self._read_ack_commitment()
        if (
            actual != expected
            or raw != expected_raw
            or identity != expected_identity
        ):
            raise _AckLifecycleCorrupt(
                "ACK commitment changed outside its durable publisher"
            )
        return actual

    def _ack_commitment_recovery_view(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> _AckCommitmentRecoveryView:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {
                "creating",
                "recovering",
                "initialization_uncertain",
                "initialized",
            }
        ):
            raise _AckLifecycleStateError(
                "ACK commitment recovery has the wrong lifecycle"
            )
        commitment = (
            None
            if self._ack_commitment is None
            else self._validate_ack_commitment_binding()
        )
        return _AckCommitmentRecoveryView(
            commitment=(
                None if commitment is None else commitment.model_copy(deep=True)
            ),
            journal_present=self._ack_journal_identity is not None,
            temporary_name=(
                None
                if self._ack_commitment_temporary is None
                else self._ack_commitment_temporary.name
            ),
        )

    def _remove_ack_commitment_temporary(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {
                "creating",
                "recovering",
                "initialization_uncertain",
                "initialized",
            }
        ):
            raise _AckLifecycleStateError(
                "ACK commitment temporary cleanup has the wrong lifecycle"
            )
        binding = self._ack_commitment_temporary
        if binding is None:
            return
        try:
            raw = _read_regular_at(
                self._root_descriptor,
                binding.name,
                self.root / binding.name,
                _MAX_ACK_COMMITMENT_BYTES,
            )
            commitment = _decode_ack_commitment(raw)
            identity = _file_identity(
                _regular_stat_at(
                    self._root_descriptor,
                    binding.name,
                    self.root / binding.name,
                )
            )
            if (
                raw != binding.raw
                or commitment != binding.commitment
                or identity != binding.identity
                or raw != _canonical_ack_commitment(commitment)
            ):
                raise _AckLifecycleCorrupt(
                    "ACK commitment temporary changed after startup"
                )
            os.unlink(binding.name, dir_fd=self._root_descriptor)
            os.fsync(self._root_descriptor)
        except (_AckLifecycleCorrupt, _AckLifecycleIoUncertain):
            raise
        except (
            EvidenceCorrupt,
            RecursionError,
            TypeError,
            ValueError,
            ValidationError,
        ) as error:
            raise _AckLifecycleCorrupt(
                "ACK commitment temporary is no longer authenticated"
            ) from error
        except FileNotFoundError as error:
            raise _AckLifecycleCorrupt(
                "ACK commitment temporary disappeared after startup"
            ) from error
        except OSError as error:
            raise _AckLifecycleIoUncertain(
                "ACK commitment temporary cleanup I/O is uncertain"
            ) from error
        self._ack_commitment_temporary = None

    def _publish_ack_initializing_genesis(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_operation != "create"
            or self._ack_journal_state != "creating"
            or self._ack_commitment is not None
            or self._ack_journal_identity is not None
        ):
            raise _AckLifecycleStateError(
                "ACK initializing commitment has the wrong lifecycle"
            )
        self._remove_ack_commitment_temporary(owner, lifecycle_identity)
        commitment = self._ack_genesis_commitment("initializing")
        try:
            _publish_without_replacement_at(
                self._root_descriptor,
                _ACK_COMMITMENT_NAME,
                self.root / _ACK_COMMITMENT_NAME,
                _canonical_ack_commitment(commitment),
            )
        except (EvidenceCorrupt, OSError) as error:
            raise _AckLifecycleCorrupt(
                "ACK initializing commitment publication failed"
            ) from error
        self._rebind_ack_commitment(expected=commitment)
        self._ack_journal_state = "initialization_uncertain"

    def _publish_ack_ready_genesis(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        step_hook: Callable[[str], None] | None = None,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {"initialization_uncertain", "recovering"}
        ):
            raise _AckLifecycleStateError(
                "ACK ready-genesis publication has the wrong lifecycle"
            )
        current = self._validate_ack_commitment_binding()
        if current != self._ack_genesis_commitment("initializing"):
            raise _AckLifecycleCorrupt(
                "ACK ready genesis does not follow initializing genesis"
            )
        journal_identity, digest = self._ack_journal_prefix_digest(0)
        if journal_identity.size != 0 or digest.hex() != _EMPTY_SHA256:
            raise _AckLifecycleCorrupt(
                "ACK initializing commitment does not bind an empty journal"
            )
        self._remove_ack_commitment_temporary(owner, lifecycle_identity)
        commitment = self._ack_genesis_commitment("ready")
        try:
            _atomic_replace_at(
                self._root_descriptor,
                _ACK_COMMITMENT_NAME,
                self.root / _ACK_COMMITMENT_NAME,
                _canonical_ack_commitment(commitment),
                step_hook=step_hook,
            )
        except EvidenceCorrupt as error:
            if isinstance(error.__cause__, OSError):
                raise error.__cause__
            raise _AckLifecycleCorrupt(
                "ACK ready-genesis publication failed"
            ) from error
        self._rebind_ack_commitment(expected=commitment)

    def _publish_ack_ready_generation(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        generation: int,
        sequence: int,
        event_id: str,
        content_sha256: str,
        journal_prefix_size: int,
        journal_prefix_sha256: str,
        step_hook: Callable[[str], None] | None = None,
    ) -> _AckCommitmentV1:
        self._validate_ack_journal_owner(owner, lifecycle_identity)
        current = self._validate_ack_commitment_binding()
        if (
            current.phase != "ready"
            or generation != current.generation + 1
        ):
            raise _AckLifecycleCorrupt(
                "ACK commitment generation is not one exact transition ahead"
            )
        try:
            if (
                self._ack_journal_operation == "recover"
                and self._ack_journal_state
                in {"recovering", "initialization_uncertain"}
            ):
                ref = self._resolve_recovered_ack_identity(
                    owner,
                    lifecycle_identity,
                    sequence=sequence,
                    event_id=event_id,
                    content_sha256=content_sha256,
                )
            else:
                ref = self._validate_ack_identity(
                    owner,
                    lifecycle_identity,
                    sequence=sequence,
                    event_id=event_id,
                    content_sha256=content_sha256,
                )
        except _AckAuthorityError as error:
            raise _AckLifecycleCorrupt(
                "ACK commitment does not bind authenticated evidence"
            ) from error
        if ref is not None and (
            ref.source_sequence != sequence
            or ref.event_id != event_id
            or ref.content_sha256 != content_sha256
        ):
            raise _AckLifecycleCorrupt(
                "ACK commitment evidence identity changed"
            )
        journal_identity, digest = self._ack_journal_prefix_digest(
            journal_prefix_size
        )
        if (
            journal_identity.size < journal_prefix_size
            or digest.hex() != journal_prefix_sha256
        ):
            raise _AckLifecycleCorrupt(
                "ACK commitment prefix differs from the held journal"
            )
        self._remove_ack_commitment_temporary(owner, lifecycle_identity)
        commitment = _AckCommitmentV1(
            schema_version="agmind.core-ack-commitment.v1",
            phase="ready",
            generation=generation,
            confirmed=_AckCommitmentIdentityV1(
                sequence=sequence,
                event_id=event_id,
                content_sha256=content_sha256,
            ),
            journal_prefix_size=journal_prefix_size,
            journal_prefix_sha256=journal_prefix_sha256,
        )
        try:
            _atomic_replace_at(
                self._root_descriptor,
                _ACK_COMMITMENT_NAME,
                self.root / _ACK_COMMITMENT_NAME,
                _canonical_ack_commitment(commitment),
                step_hook=step_hook,
            )
        except EvidenceCorrupt as error:
            if isinstance(error.__cause__, OSError):
                raise error.__cause__
            raise _AckLifecycleCorrupt(
                "ACK commitment publication failed"
            ) from error
        self._rebind_ack_commitment(expected=commitment)
        rebound_identity, rebound_digest = self._ack_journal_prefix_digest(
            journal_prefix_size
        )
        if (
            rebound_identity != journal_identity
            or rebound_digest.hex() != journal_prefix_sha256
        ):
            raise _AckLifecycleCorrupt(
                "ACK journal changed after commitment publication"
            )
        return commitment.model_copy(deep=True)

    def _mark_ack_commitment_uncertain(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {"initialized", "append_uncertain", "commitment_uncertain"}
        ):
            raise _AckLifecycleStateError(
                "ACK commitment uncertainty has the wrong lifecycle"
            )
        self._ack_journal_state = "commitment_uncertain"

    def _mark_ack_io_uncertain(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated: os.stat_result | None,
        authenticated_digest: bytes | None,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {
                "recovering",
                "initialization_uncertain",
                "initialized",
                "io_uncertain",
            }
        ):
            raise _AckLifecycleStateError(
                "ACK I/O uncertainty has the wrong lifecycle"
            )
        if (authenticated is None) != (authenticated_digest is None):
            raise _AckLifecycleCorrupt(
                "ACK I/O uncertainty has an incomplete content anchor"
            )
        if authenticated is not None and authenticated_digest is not None:
            retained_identity = _file_identity(authenticated)
            expected_identity = self._ack_journal_identity
            if (
                len(authenticated_digest) != hashlib.sha256().digest_size
                or expected_identity is None
                or not self._same_ack_journal_inode(
                    retained_identity,
                    expected_identity,
                )
            ):
                raise _AckLifecycleCorrupt(
                    "ACK I/O uncertainty has an invalid content anchor"
                )
            self._ack_journal_identity = retained_identity
            self._ack_journal_digest = authenticated_digest
        if self._ack_journal_state != "initialization_uncertain":
            self._ack_journal_state = "io_uncertain"

    def _acquire_ack_journal(
        self,
        owner: object,
        *,
        operation: Literal["create", "recover"],
        _factory: object | None = None,
    ) -> tuple[int, object]:
        retention_recovery = (
            _factory is _RETENTION_ACK_RECOVERY_FACTORY
            and operation == "recover"
            and self._retention_ack_recovery_permitted
            and self._authority_state == "recovering"
            and self._bound_verifier is not None
            and self._read_only_reason is None
            and not self._append_uncertain
            and self._pending_durable_commit is None
        )
        if not retention_recovery:
            if _factory is not None:
                raise _AckLifecycleStateError(
                    "ACK journal has an invalid recovery factory"
                )
            self._require_ack_mutation_ready()
        if self._ack_journal_owner is not None:
            raise EvidenceStoreBusy("evidence root already has one ACK-journal owner")
        state = self._ack_journal_state
        if state == "unknown":
            raise _AckLifecycleStateError(
                "ACK-journal startup presence was not authenticated"
            )
        if state == "initialization_uncertain":
            raise _AckLifecycleStateError(
                "ACK-journal initialization is uncertain until store restart"
            )
        if state in {
            "append_uncertain",
            "commitment_uncertain",
            "io_uncertain",
        }:
            raise _AckLifecycleStateError(
                "ACK authority publication is uncertain until store restart"
            )
        if state in {"creating", "recovering"}:
            raise _AckLifecycleStateError(
                "ACK-journal initialization did not settle"
            )

        actual_identity = self._ack_journal_artifact_identity()
        if state in {"present", "initialized"}:
            expected_identity = self._ack_journal_identity
            if actual_identity is None:
                raise _AckLifecycleCorrupt(
                    "expected ACK-journal authority disappeared"
                )
            if (
                expected_identity is None
                or actual_identity != expected_identity
            ):
                raise _AckLifecycleCorrupt(
                    "expected ACK-journal authority changed identity"
                )
        if state == "bootstrap":
            expected_identity = self._ack_journal_identity
            if (
                (expected_identity is None) != (actual_identity is None)
                or (
                    expected_identity is not None
                    and actual_identity != expected_identity
                )
            ):
                raise _AckLifecycleCorrupt(
                    "bootstrap ACK journal changed after startup"
                )
        if state == "fresh" and actual_identity is not None:
            raise _AckLifecycleCorrupt(
                "unexpected ACK journal appeared in a fresh store lifecycle"
            )
        if operation == "create":
            if state != "fresh":
                raise _AckLifecycleStateError(
                    "ACK journal may be created only in a fresh store lifecycle"
                )
            next_state: Literal["creating", "recovering"] = "creating"
        else:
            if state not in {"present", "bootstrap"}:
                raise _AckLifecycleStateError(
                    "ACK journal may be recovered only once from startup presence"
                )
            next_state = "recovering"

        duplicate_command = getattr(fcntl, "F_DUPFD_CLOEXEC", None)
        if duplicate_command is None:
            root_descriptor = os.dup(self._root_descriptor)
            try:
                os.set_inheritable(root_descriptor, False)
            except BaseException as error:
                try:
                    os.close(root_descriptor)
                except OSError as cleanup_error:
                    error.add_note(
                        "secondary ACK root descriptor cleanup failure: "
                        f"{cleanup_error}"
                    )
                raise
        else:
            root_descriptor = fcntl.fcntl(
                self._root_descriptor,
                duplicate_command,
                0,
            )
        self._ack_journal_owner = owner
        self._ack_journal_operation = operation
        self._ack_journal_state = next_state
        self._ack_journal_is_retention_recovery = retention_recovery
        return root_descriptor, self._lifecycle_identity

    def _ack_journal_final_name_created(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or not (
                (
                    self._ack_journal_operation == "create"
                    and self._ack_journal_state
                    in {"creating", "initialization_uncertain"}
                )
                or (
                    self._ack_journal_operation == "recover"
                    and self._ack_journal_state == "recovering"
                    and self._ack_journal_identity is None
                )
            )
        ):
            raise _AckLifecycleStateError(
                "ACK-journal create publication has the wrong lifecycle"
            )
        self._ack_journal_state = "initialization_uncertain"

    def _complete_ack_journal_initialization(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated: os.stat_result,
        authenticated_digest: bytes,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise _AckLifecycleStateError(
                "ACK-journal completion has the wrong lifecycle"
            )
        operation = self._ack_journal_operation
        state = self._ack_journal_state
        if not (
            (operation == "create" and state == "initialization_uncertain")
            or (
                operation == "recover"
                and state in {"recovering", "initialization_uncertain"}
            )
        ):
            raise _AckLifecycleStateError(
                "ACK-journal completion did not follow create or recovery"
            )
        actual_identity = self._ack_journal_artifact_identity()
        authenticated_identity = _file_identity(authenticated)
        if actual_identity is None:
            raise _AckLifecycleCorrupt(
                "ACK-journal authority disappeared before initialization completed"
            )
        if actual_identity != authenticated_identity:
            raise _AckLifecycleCorrupt(
                "ACK-journal authority changed before initialization completed"
            )
        if len(authenticated_digest) != hashlib.sha256().digest_size:
            raise _AckLifecycleCorrupt(
                "ACK-journal authenticated digest is invalid"
            )
        commitment = self._validate_ack_commitment_binding()
        if commitment.phase != "ready":
            raise _AckLifecycleCorrupt(
                "ACK journal cannot initialize under a non-ready commitment"
            )
        expected_identity = self._ack_journal_identity
        if (
            operation == "recover"
            and (
                (
                    expected_identity is not None
                    and not self._same_ack_journal_inode(
                        authenticated_identity,
                        expected_identity,
                    )
                )
                or (
                    expected_identity is None
                    and self._ack_commitment is not None
                    and self._ack_commitment.phase != "ready"
                    and authenticated_identity.size != 0
                )
            )
        ):
            raise _AckLifecycleCorrupt(
                "recovered ACK journal differs from startup identity"
            )
        self._ack_journal_identity = authenticated_identity
        self._ack_journal_digest = authenticated_digest
        self._ack_journal_state = "initialized"

    def _seal_ack_journal_identity(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated: os.stat_result,
        authenticated_digest: bytes,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state != "initialized"
        ):
            raise _AckLifecycleStateError(
                "ACK-journal close has the wrong lifecycle"
            )
        authenticated_identity = _file_identity(authenticated)
        if len(authenticated_digest) != hashlib.sha256().digest_size:
            raise _AckLifecycleCorrupt(
                "ACK-journal close digest is invalid"
            )
        commitment = self._validate_ack_commitment_binding()
        if commitment.phase != "ready":
            raise _AckLifecycleCorrupt(
                "ACK journal cannot close under a non-ready commitment"
            )
        actual_identity = self._ack_journal_artifact_identity()
        expected_identity = self._ack_journal_identity
        if (
            actual_identity is None
            or actual_identity != authenticated_identity
            or expected_identity is None
            or not self._same_ack_journal_inode(
                authenticated_identity,
                expected_identity,
            )
        ):
            raise _AckLifecycleCorrupt(
                "ACK-journal authority changed before healthy close"
            )
        self._ack_journal_identity = authenticated_identity
        self._ack_journal_digest = authenticated_digest

    def _mark_ack_journal_append_uncertain(
        self,
        owner: object,
        lifecycle_identity: object,
        authenticated_before: os.stat_result,
        authenticated_digest_before: bytes,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {"initialized", "append_uncertain"}
        ):
            raise _AckLifecycleStateError(
                "ACK-journal uncertainty has the wrong lifecycle"
            )
        retained_identity = _file_identity(authenticated_before)
        if len(authenticated_digest_before) != hashlib.sha256().digest_size:
            raise _AckLifecycleCorrupt(
                "ACK-journal pre-append digest is invalid"
            )
        expected_identity = self._ack_journal_identity
        if (
            expected_identity is None
            or not self._same_ack_journal_inode(
                retained_identity,
                expected_identity,
            )
        ):
            raise _AckLifecycleCorrupt(
                "ACK-journal pre-append identity changed"
            )
        self._ack_journal_identity = retained_identity
        self._ack_journal_digest = authenticated_digest_before
        self._ack_journal_state = "append_uncertain"

    def _validate_ack_journal_owner(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        internal_recovery = (
            self._ack_journal_is_retention_recovery
            and self._retention_ack_recovery_permitted
            and self._authority_state == "recovering"
            and self._bound_verifier is not None
            and self._read_only_reason is None
            and not self._append_uncertain
            and self._pending_durable_commit is None
        )
        if not internal_recovery:
            self._require_ack_mutation_ready()
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
            or self._ack_journal_state
            not in {"recovering", "initialization_uncertain", "initialized"}
        ):
            raise EvidenceSealError("ACK journal is outside this evidence lifecycle")
        if self._ack_journal_state == "initialized":
            commitment = self._validate_ack_commitment_binding()
            if commitment.phase != "ready":
                raise _AckLifecycleCorrupt(
                    "initialized ACK journal has no ready commitment"
                )

    def _release_ack_journal(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> None:
        if (
            owner is not self._ack_journal_owner
            or lifecycle_identity is not self._lifecycle_identity
        ):
            raise EvidenceSealError("ACK journal release has the wrong lifecycle")
        state = self._ack_journal_state
        if (
            self._ack_journal_is_retention_recovery
            and state == "initialized"
        ):
            self._ack_journal_state = "present"
        elif state == "creating":
            self._ack_journal_state = "fresh"
        elif state == "recovering":
            self._ack_journal_state = "present"
        self._ack_journal_owner = None
        self._ack_journal_operation = None
        self._ack_journal_is_retention_recovery = False

    def _ack_recovery_verifier(
        self,
        owner: object,
        lifecycle_identity: object,
    ) -> EnvelopeVerifier:
        self._validate_ack_journal_owner(owner, lifecycle_identity)
        verifier = self._bound_verifier
        if verifier is None or self._authority_state not in {
            "recovering",
            "ready",
        }:
            raise _AckLifecycleStateError(
                "ACK recovery has no authenticated verifier"
            )
        if (
            self._authority_state == "recovering"
            and not self._ack_journal_is_retention_recovery
        ):
            raise _AckLifecycleStateError(
                "ACK recovery cannot enter an unready evidence lifecycle"
            )
        return verifier

    def _resolve_recovered_ack_identity(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        sequence: int,
        event_id: str,
        content_sha256: str,
    ) -> EvidenceRef | None:
        verifier = self._ack_recovery_verifier(
            owner,
            lifecycle_identity,
        )
        indexed = self._index.get((verifier.fsm.host_id, sequence))
        if indexed is not None:
            ref = indexed[1]
            position = self._record_positions.get(
                (verifier.fsm.host_id, sequence)
            )
            if (
                ref.event_id != event_id
                or ref.content_sha256 != content_sha256
            ):
                raise _AckAuthorityError(
                    "recovered ACK identity differs from live evidence"
                )
            if (
                position is None
                or position >= len(self._records)
                or self._records[position].ref is not ref
                or verifier.accepted_ref(sequence) is not ref
            ):
                raise EvidenceCorrupt(
                    "recovered ACK live evidence authority changed"
                )
            return ref

        matches = sum(
            1
            for start, end in self._authenticated_retired_ranges
            if start <= sequence <= end
        )
        if matches != 1:
            raise _AckAuthorityError(
                "recovered ACK identity is outside authenticated evidence"
            )
        return None

    def _validate_next_recovered_ack_identity(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        sequence: int,
        event_id: str,
        content_sha256: str,
        confirmed_through: int,
    ) -> None:
        verifier = self._ack_recovery_verifier(
            owner,
            lifecycle_identity,
        )
        self._resolve_recovered_ack_identity(
            owner,
            lifecycle_identity,
            sequence=sequence,
            event_id=event_id,
            content_sha256=content_sha256,
        )
        candidates: list[int] = []
        sequences = self._sequences_by_host.get(verifier.fsm.host_id, [])
        live_position = bisect_right(sequences, confirmed_through)
        if live_position < len(sequences):
            candidates.append(sequences[live_position])
        for start, end in self._authenticated_retired_ranges:
            if end > confirmed_through:
                candidates.append(max(start, confirmed_through + 1))
        if not candidates or sequence != min(candidates):
            raise _AckAuthorityError(
                "recovered ACK is not the next live-or-retired position"
            )
        holes = verifier.fsm.unresolved_holes
        acceptance_cursor = (
            holes[0][0] - 1 if holes else verifier.fsm.last_sequence
        )
        if sequence > acceptance_cursor:
            raise _AckAuthorityError(
                "recovered ACK exceeds authenticated acceptance"
            )

    def _validate_recovered_ack_terminal(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        confirmed_through: int,
    ) -> None:
        self._ack_recovery_verifier(owner, lifecycle_identity)
        for _start, end in self._authenticated_retired_ranges:
            if end >= MAX_UINT64:
                raise _AckAuthorityError(
                    "authenticated retired evidence has no surviving ACK position"
                )
            if confirmed_through < end + 1:
                raise _AckAuthorityError(
                    "ACK confirmation lags authenticated retired evidence"
                )

    def _acquire_retention_ack_boundary(
        self,
        journal: object,
        *,
        confirmed_through: int,
    ) -> _AckRetentionBoundaryLease:
        from agmind_immune.ingest.ack_journal import (
            AckJournal,
            AckJournalError,
        )

        if (
            type(journal) is not AckJournal
            or journal is not self._ack_journal_owner
        ):
            raise EvidenceSealError(
                "retention unlink has no exact ACK-journal owner"
            )
        try:
            return journal._acquire_retention_boundary(
                self,
                confirmed_through=confirmed_through,
                _factory=_RETENTION_ACK_GATE_FACTORY,
            )
        except AckJournalError as error:
            raise EvidenceSealError(
                "retention unlink lacks a settled ACK prefix"
            ) from error

    def _release_retention_ack_boundary(
        self,
        journal: object,
        lease: _AckRetentionBoundaryLease,
    ) -> None:
        from agmind_immune.ingest.ack_journal import AckJournal

        if type(journal) is not AckJournal:
            raise EvidenceSealError(
                "retention ACK boundary owner changed"
            )
        journal._release_retention_boundary(
            self,
            lease=lease,
            _factory=_RETENTION_ACK_GATE_FACTORY,
        )

    def _open_retention_ack_recovery(
        self,
    ) -> AckJournal:
        from agmind_immune.ingest.ack_journal import (
            AckJournal,
            AckJournalError,
        )

        if (
            self._authority_state != "recovering"
            or self._ack_journal_owner is not None
            or self._retention_ack_recovery_permitted
        ):
            raise EvidenceCorrupt(
                "retention ACK recovery has the wrong lifecycle"
            )
        self._retention_ack_recovery_permitted = True
        try:
            return AckJournal._open_for_retention_recovery(
                self,
                _factory=_RETENTION_ACK_RECOVERY_FACTORY,
            )
        except (AckJournalError, EvidenceStoreError) as error:
            self._retention_ack_recovery_permitted = False
            raise EvidenceCorrupt(
                "retention recovery lacks authenticated ACK history"
            ) from error
        except BaseException:
            self._retention_ack_recovery_permitted = False
            raise

    def _close_retention_ack_recovery(
        self,
        journal: object,
    ) -> None:
        from agmind_immune.ingest.ack_journal import AckJournal

        try:
            if (
                type(journal) is not AckJournal
                or journal is not self._ack_journal_owner
                or not self._ack_journal_is_retention_recovery
            ):
                raise EvidenceCorrupt(
                    "retention ACK recovery owner changed"
                )
            journal.close()
        except BaseException as error:
            try:
                self._trip_read_only("segment_corrupt")
            except BaseException as fence_error:  # noqa: BLE001
                error.add_note(
                    "secondary retention ACK recovery fence failure: "
                    f"{type(fence_error).__name__}: {fence_error}"
                )
            raise
        finally:
            self._retention_ack_recovery_permitted = False

    def _validate_ack_identity(
        self,
        owner: object,
        lifecycle_identity: object,
        *,
        sequence: int,
        event_id: str,
        content_sha256: str,
    ) -> EvidenceRef:
        self._validate_ack_journal_owner(owner, lifecycle_identity)
        verifier = self._require_authenticated_recovered()
        indexed = self._index.get((verifier.fsm.host_id, sequence))
        if indexed is None:
            raise _AckAuthorityError("ACK identity has no authenticated evidence")
        ref = indexed[1]
        if ref.event_id != event_id or ref.content_sha256 != content_sha256:
            raise _AckAuthorityError("ACK identity differs from authenticated evidence")
        self.resolve_authenticated_ref(ref)
        return ref

    def _validate_next_ack_ref(
        self,
        owner: object,
        lifecycle_identity: object,
        ref: EvidenceRef,
        *,
        confirmed_through: int,
    ) -> None:
        self._validate_ack_journal_owner(owner, lifecycle_identity)
        self.resolve_authenticated_ref(ref)
        verifier = self._require_authenticated_recovered()
        host_id = verifier.fsm.host_id
        sequences = self._sequences_by_host.get(host_id, [])
        position = bisect_right(sequences, confirmed_through)
        if position >= len(sequences):
            raise _AckAuthorityError(
                "pending ACK has no next authenticated evidence ref"
            )
        next_ref = self._index[(host_id, sequences[position])][1]
        if next_ref != ref:
            raise _AckAuthorityError(
                "pending ACK is not the next authenticated evidence ref"
            )
        if ref.source_sequence > self.acceptance_cursor:
            raise _AckAuthorityError(
                "pending ACK exceeds the signed-or-covered acceptance cursor"
            )

    def _date_descriptor(self, date_name: str, *, create: bool = False) -> int:
        if (
            not _DATE_NAME.fullmatch(date_name)
            or date.fromisoformat(date_name).isoformat() != date_name
        ):
            raise EvidenceCorrupt(f"invalid evidence UTC date directory: {date_name}")
        retained = self._date_descriptors.get(date_name)
        if retained is not None:
            return retained
        display_path = self._segments_path / date_name
        if create:
            descriptor = _open_or_create_directory_at(
                self._segments_descriptor,
                date_name,
                display_path,
            )
        else:
            try:
                descriptor = os.open(
                    date_name,
                    _directory_flags(),
                    dir_fd=self._segments_descriptor,
                )
            except FileNotFoundError as error:
                raise EvidenceCorrupt(
                    f"evidence date directory disappeared: {display_path}"
                ) from error
            try:
                _validate_directory(descriptor, display_path, exact_mode=True)
            except BaseException:
                os.close(descriptor)
                raise
        self._date_descriptors[date_name] = descriptor
        return descriptor

    def _startup(self) -> None:
        if self._repair_mode:
            self._startup_tail_repair()
            return
        try:
            plan, manifested_open = self._scan_manifests_and_segments()
            if (
                self._repair_state_binding is not None
                or self._repair_state_temporary is not None
            ):
                raise TailRepairPending(
                    "evidence root has a pending signed tail repair"
                )
            active_cleanup = self._scan_unsettled_open(manifested_open)
            plan = _RecoveryPlan(
                promotions=plan.promotions,
                delete_private_temporaries=(
                    plan.delete_private_temporaries + active_cleanup
                ),
                delete_manifest_temporaries=plan.delete_manifest_temporaries,
                delete_root_temporaries=plan.delete_root_temporaries,
                delete_retention_state_temporaries=(),
                head_raw=plan.head_raw,
            )
            if self._read_only_reason is None:
                self._apply_recovery_plan(plan)
        except TornTailRepairRequired:
            raise
        except EvidenceCorrupt:
            if self._read_only_reason is None:
                self._trip_read_only("segment_corrupt")
            raise
        except (JournalCorrupt, OSError, ValidationError, ValueError) as error:
            if self._read_only_reason is None:
                self._trip_read_only("segment_corrupt")
            raise EvidenceCorrupt("evidence startup verification failed") from error

    def _startup_tail_repair(self) -> None:
        try:
            plan, manifested_open = self._scan_manifests_and_segments()
            self._repair_recovery_plan = plan
            self._scan_tail_repair_target(manifested_open)
            self._bind_durable_repair_facts()
            if (
                self._repair_target is None
                and self._repair_state_binding is None
                and self._repair_state_temporary is None
            ):
                raise EvidenceStoreError("evidence root has no tail-repair candidate")
        except EvidenceCorrupt:
            if self._read_only_reason is None:
                self._trip_read_only("segment_corrupt")
            raise
        except (JournalCorrupt, OSError, ValidationError, ValueError) as error:
            if self._read_only_reason is None:
                self._trip_read_only("segment_corrupt")
            raise EvidenceCorrupt("repair startup verification failed") from error

    def _load_health_state(self) -> None:
        names = set(os.listdir(self._root_descriptor))
        pending_names = {
            name
            for name in names
            if (
                name.startswith(".health-intent.")
                and name.endswith(".pending")
            )
            or _HEALTH_FINAL_TEMP_NAME.fullmatch(name)
        }
        if pending_names:
            for name in pending_names:
                _regular_stat_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                )
            self._read_only_reason = "segment_corrupt"
        if "health.intent.json" in names:
            raw = _read_regular_at(
                self._root_descriptor,
                "health.intent.json",
                self.root / "health.intent.json",
                MAX_CONTRACT_FILE_BYTES,
            )
            try:
                intent = decode_strict(
                    raw,
                    _EvidenceHealthIntentV1,
                    MAX_CONTRACT_FILE_BYTES,
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise EvidenceCorrupt("evidence health intent is malformed") from error
            if raw != canonical_json(intent):
                raise EvidenceCorrupt("evidence health intent is not canonical")
            self._read_only_reason = intent.reason
        if "health.json" in names:
            raw = _read_regular_at(
                self._root_descriptor,
                "health.json",
                self.root / "health.json",
                MAX_CONTRACT_FILE_BYTES,
            )
            try:
                marker = decode_strict(
                    raw,
                    _EvidenceHealthV1,
                    MAX_CONTRACT_FILE_BYTES,
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise EvidenceCorrupt("evidence health marker is malformed") from error
            if raw != canonical_json(marker):
                raise EvidenceCorrupt("evidence health marker is not canonical")
            if (
                self._read_only_reason is not None
                and self._read_only_reason != marker.reason
            ):
                raise EvidenceCorrupt("health intent and final marker disagree")
            self._read_only_reason = marker.reason

    def _trip_read_only(self, reason: str) -> None:
        if reason not in {"segment_corrupt", "evidence_conflict"}:
            raise ValueError("unsupported evidence read-only reason")
        self._read_only_reason = reason
        final_raw = canonical_json(
            {
                "schema_version": "agmind.evidence-health.v1",
                "mode": "read_only",
                "reason": reason,
            }
        )
        final_stat = _entry_stat_at(self._root_descriptor, "health.json")
        if final_stat is not None:
            raw = _read_regular_at(
                self._root_descriptor,
                "health.json",
                self.root / "health.json",
                MAX_CONTRACT_FILE_BYTES,
            )
            marker = decode_strict(raw, _EvidenceHealthV1, MAX_CONTRACT_FILE_BYTES)
            if raw != canonical_json(marker) or marker.reason != reason:
                raise EvidenceCorrupt("existing health marker conflicts with trip reason")
            return

        intent_raw = canonical_json(
            {
                "schema_version": "agmind.evidence-health-intent.v1",
                "mode": "read_only_pending",
                "reason": reason,
            }
        )
        intent_sha256 = hashlib.sha256(intent_raw).hexdigest()
        if _entry_stat_at(self._root_descriptor, "health.intent.json") is None:
            temporary_name = f".health-intent.{uuid.uuid4()}.pending"
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=self._root_descriptor,
            )
            try:
                self._health_step_hook("create")
                os.fchmod(descriptor, 0o600)
                os.fsync(self._root_descriptor)
                self._health_step_hook("create_directory_fsync")
                _full_write(descriptor, intent_raw)
                self._health_step_hook("write")
                os.fsync(descriptor)
                self._health_step_hook("file_fsync")
                identity = _file_identity(os.fstat(descriptor))
                _bind_held_source(
                    self._root_descriptor,
                    temporary_name,
                    self.root / "health.intent.json",
                    descriptor=descriptor,
                    identity=identity,
                )
                _rename_noreplace(
                    temporary_name,
                    "health.intent.json",
                    source_dir_fd=self._root_descriptor,
                    destination_dir_fd=self._root_descriptor,
                )
                self._health_step_hook("rename")
                _validate_published_from_held(
                    self._root_descriptor,
                    "health.intent.json",
                    self.root / "health.intent.json",
                    descriptor=descriptor,
                    identity=identity,
                    expected_sha256=intent_sha256,
                )
                os.fsync(self._root_descriptor)
                self._health_step_hook("rename_directory_fsync")
            finally:
                os.close(descriptor)
        else:
            raw = _read_regular_at(
                self._root_descriptor,
                "health.intent.json",
                self.root / "health.intent.json",
                MAX_CONTRACT_FILE_BYTES,
            )
            intent = decode_strict(
                raw,
                _EvidenceHealthIntentV1,
                MAX_CONTRACT_FILE_BYTES,
            )
            if raw != canonical_json(intent) or intent.reason != reason:
                raise EvidenceCorrupt("existing health intent conflicts with trip reason")
        _atomic_replace_at(
            self._root_descriptor,
            "health.json",
            self.root / "health.json",
            final_raw,
        )
        os.unlink("health.intent.json", dir_fd=self._root_descriptor)
        for name in os.listdir(self._root_descriptor):
            if name.startswith(".health-intent.") and name.endswith(".pending"):
                os.unlink(name, dir_fd=self._root_descriptor)
        os.fsync(self._root_descriptor)

    def enter_read_only(self, reason: Literal["evidence_conflict"]) -> None:
        """Persist a verifier-detected critical conflict before returning it."""
        self._trip_read_only(reason)

    def _trip_ack_journal_corrupt(self) -> None:
        """Persist a root-wide fence without rewriting corrupt ACK bytes."""
        self._trip_read_only("segment_corrupt")

    def _trip_correlation_journal_corrupt(self) -> None:
        """Persist a root-wide fence without rewriting corrupt correlation bytes."""
        self._trip_read_only("segment_corrupt")

    def _fence_missing_expected_correlation_journal(self) -> None:
        state = self._correlation_journal_state
        if state not in {
            "present",
            "initialized",
            "append_uncertain",
            "io_uncertain",
        }:
            return
        try:
            actual_identity = self._correlation_journal_artifact_identity()
        except (
            _CorrelationJournalLifecycleCorrupt,
            _CorrelationJournalLifecycleIoUncertain,
        ):
            actual_identity = None
        expected_identity = self._correlation_journal_identity
        identity_changed = actual_identity is None or expected_identity is None
        if (
            not identity_changed
            and actual_identity is not None
            and expected_identity is not None
        ):
            if state in {"append_uncertain", "io_uncertain"}:
                identity_changed = (
                    not self._same_correlation_journal_inode(
                        actual_identity,
                        expected_identity,
                    )
                    or actual_identity.size < expected_identity.size
                )
            else:
                identity_changed = actual_identity != expected_identity

        content_changed = False
        expected_digest = self._correlation_journal_digest
        if (
            not identity_changed
            and expected_identity is not None
            and expected_digest is not None
        ):
            try:
                hashed_identity, actual_digest = (
                    self._correlation_journal_prefix_digest(
                        expected_identity.size
                    )
                )
            except (
                _CorrelationJournalLifecycleCorrupt,
                _CorrelationJournalLifecycleIoUncertain,
            ):
                content_changed = True
            else:
                content_changed = (
                    actual_identity is None
                    or not self._same_correlation_journal_inode(
                        hashed_identity,
                        actual_identity,
                    )
                    or actual_digest != expected_digest
                )
        elif state in {"initialized", "append_uncertain"}:
            content_changed = True

        if identity_changed or content_changed:
            self._trip_read_only("segment_corrupt")

    def _fence_missing_expected_ack_journal(self) -> None:
        state = self._ack_journal_state
        if state not in {
            "present",
            "initialized",
            "append_uncertain",
            "commitment_uncertain",
            "io_uncertain",
        }:
            return
        try:
            actual_identity = self._ack_journal_artifact_identity()
        except _AckLifecycleCorrupt:
            actual_identity = None
        expected_identity = self._ack_journal_identity
        identity_changed = actual_identity is None or expected_identity is None
        if not identity_changed and actual_identity is not None:
            if state in {"append_uncertain", "commitment_uncertain"}:
                identity_changed = (
                    expected_identity is None
                    or not self._same_ack_journal_inode(
                        actual_identity,
                        expected_identity,
                    )
                    or actual_identity.size < expected_identity.size
                )
            else:
                identity_changed = actual_identity != expected_identity

        content_changed = False
        if (
            not identity_changed
            and state in {
                "initialized",
                "append_uncertain",
                "commitment_uncertain",
                "io_uncertain",
            }
            and expected_identity is not None
        ):
            expected_digest = self._ack_journal_digest
            if expected_digest is None:
                content_changed = state != "io_uncertain"
            else:
                try:
                    hashed_identity, actual_digest = (
                        self._ack_journal_prefix_digest(
                            expected_identity.size
                        )
                    )
                except (_AckLifecycleCorrupt, _AckLifecycleIoUncertain):
                    content_changed = True
                else:
                    content_changed = (
                        actual_identity is None
                        or not self._same_ack_journal_inode(
                            hashed_identity,
                            actual_identity,
                        )
                        or actual_digest != expected_digest
                    )
        commitment_changed = False
        if state in {"present", "initialized", "append_uncertain"}:
            try:
                self._validate_ack_commitment_binding()
            except (_AckLifecycleCorrupt, _AckLifecycleIoUncertain):
                commitment_changed = True
        elif state == "io_uncertain":
            try:
                self._validate_ack_commitment_binding()
            except _AckLifecycleCorrupt:
                commitment_changed = True
            except _AckLifecycleIoUncertain:
                commitment_changed = False
        elif state == "commitment_uncertain":
            expected_commitment = self._ack_commitment
            try:
                actual_commitment, _raw, _identity = self._read_ack_commitment()
            except _AckLifecycleCorrupt:
                commitment_changed = True
            except _AckLifecycleIoUncertain:
                commitment_changed = False
            else:
                commitment_changed = (
                    expected_commitment is None
                    or actual_commitment.phase != "ready"
                    or actual_commitment.generation
                    not in {
                        expected_commitment.generation,
                        expected_commitment.generation + 1,
                    }
                )
        if identity_changed or content_changed or commitment_changed:
            self._trip_read_only("segment_corrupt")

    def _scan_manifests_and_segments(
        self,
    ) -> tuple[_RecoveryPlan, set[tuple[str, str]]]:
        manifests: list[SegmentManifestV1] = []
        manifest_raw_by_hash: dict[str, bytes] = {}
        manifest_temporaries: list[str] = []
        for name in sorted(os.listdir(self._manifests_descriptor)):
            if _MANIFEST_TEMP_NAME.fullmatch(name):
                _regular_stat_at(
                    self._manifests_descriptor,
                    name,
                    self._manifests_path / name,
                )
                manifest_temporaries.append(name)
                continue
            match = _MANIFEST_NAME.fullmatch(name)
            if match is None:
                raise EvidenceCorrupt(f"unexpected manifest artifact: {name}")
            raw = _read_regular_at(
                self._manifests_descriptor,
                name,
                self._manifests_path / name,
                MAX_CONTRACT_FILE_BYTES,
            )
            manifest = decode_strict(raw, SegmentManifestV1, MAX_CONTRACT_FILE_BYTES)
            if raw != canonical_json(manifest):
                raise EvidenceCorrupt("immutable manifest is not canonical JSON")
            if name != f"{manifest.segment_id}.json":
                raise EvidenceCorrupt("manifest filename does not match segment_id")
            if manifest.manifest_sha256 in manifest_raw_by_hash:
                raise EvidenceCorrupt("duplicate immutable manifest digest")
            manifests.append(manifest)
            manifest_raw_by_hash[manifest.manifest_sha256] = raw
        chain = self._order_manifest_chain(manifests)
        referenced_closed: set[tuple[str, str]] = set()
        manifested_open: set[tuple[str, str]] = set()
        promotions: list[_Promotion] = []
        missing_payloads: list[_MissingManifestPayload] = []
        replay_records: dict[
            str,
            tuple[StoredEvidenceRecord, ...] | None,
        ] = {}
        for chain_index, manifest in enumerate(chain):
            _, date_name, closed_name = manifest.segment_relative_path.split("/")
            open_name = closed_name.removesuffix(".agseg") + ".open"
            date_descriptor = self._date_descriptor(date_name)
            closed_stat = _entry_stat_at(date_descriptor, closed_name)
            open_stat = _entry_stat_at(date_descriptor, open_name)
            if closed_stat is not None and open_stat is not None:
                raise EvidenceCorrupt("manifest segment has both open and closed payloads")
            if open_stat is not None:
                scan = self._verify_segment_against_manifest(
                    date_descriptor,
                    open_name,
                    self._segments_path / date_name / open_name,
                    manifest,
                )
                promotions.append(
                    _Promotion(
                        date_name=date_name,
                        open_name=open_name,
                        closed_name=closed_name,
                        identity=scan.identity,
                        sha256=scan.sha256,
                    )
                )
                manifested_open.add((date_name, open_name))
            elif closed_stat is None:
                replay_records[manifest.manifest_sha256] = None
                missing_payloads.append(
                    _MissingManifestPayload(
                        chain_index=chain_index,
                        manifest=manifest,
                        manifest_canonical=manifest_raw_by_hash[
                            manifest.manifest_sha256
                        ],
                        date_name=date_name,
                        closed_name=closed_name,
                    )
                )
                referenced_closed.add((date_name, closed_name))
                continue
            else:
                scan = self._verify_segment_against_manifest(
                    date_descriptor,
                    closed_name,
                    self._segments_path / date_name / closed_name,
                    manifest,
                )
            self._add_records(list(scan.records))
            replay_records[manifest.manifest_sha256] = scan.records
            referenced_closed.add((date_name, closed_name))
        if promotions:
            final_closed_name = chain[-1].segment_relative_path.rsplit(
                "/",
                1,
            )[-1]
            if (
                len(promotions) != 1
                or promotions[0].closed_name != final_closed_name
            ):
                raise EvidenceCorrupt(
                    "only one final manifested-open promotion is recoverable"
                )

        private_temporaries: list[tuple[str, str]] = []
        for date_name in sorted(os.listdir(self._segments_descriptor)):
            date_descriptor = self._date_descriptor(date_name)
            for name in sorted(os.listdir(date_descriptor)):
                if name.endswith(".agseg"):
                    if (date_name, name) not in referenced_closed:
                        raise EvidenceCorrupt("closed segment has no immutable manifest")
                elif name.endswith(".open"):
                    continue
                elif _CREATE_TEMP_NAME.fullmatch(name):
                    info = _regular_stat_at(
                        date_descriptor,
                        name,
                        self._segments_path / date_name / name,
                    )
                    if info.st_size > MAX_EVIDENCE_RECORD_BYTES + 76:
                        raise EvidenceCorrupt("private create temporary exceeds bound")
                    if info.st_size:
                        temporary_scan = self._read_segment(
                            date_descriptor,
                            name,
                            self._segments_path / date_name / name,
                            allow_torn=True,
                        )
                        if (
                            temporary_scan.torn_verified not in {None, 0}
                            or (
                                temporary_scan.torn_verified is None
                                and (
                                    len(temporary_scan.frames) != 1
                                    or len(temporary_scan.records) != 1
                                )
                            )
                        ):
                            raise EvidenceCorrupt(
                                "private create temporary has impossible contents"
                            )
                    private_temporaries.append((date_name, name))
                else:
                    raise EvidenceCorrupt(f"unexpected segment artifact: {name}")
        self._manifests = chain
        self._manifest_replay_records = replay_records
        self._missing_manifest_payloads = tuple(missing_payloads)
        head_raw = self._scan_chain_head()

        root_temporaries: list[str] = []
        allowed_root = {
            "ack-journal.agf",
            _CORRELATION_JOURNAL_NAME,
            _ACK_COMMITMENT_NAME,
            "chain-head.json",
            "health.intent.json",
            "health.json",
            "manifests",
            "segments",
        }
        root_entries = tuple(os.listdir(self._root_descriptor))
        correlation_journal_identity: _FileIdentity | None = None
        ack_journal_identity: _FileIdentity | None = None
        ack_commitment: _AckCommitmentV1 | None = None
        ack_commitment_raw: bytes | None = None
        ack_commitment_identity: _FileIdentity | None = None
        ack_commitment_temporaries: list[_AckCommitmentTemporaryBinding] = []
        repair_state_bindings: list[_RepairStateArtifactBinding] = []
        repair_state_temporaries: list[_RepairStateArtifactBinding] = []
        retention_state_bindings: list[
            _RetentionStateArtifactBinding
        ] = []
        retention_state_temporaries: list[
            _RetentionStateArtifactBinding
        ] = []
        retention_boundary_names: list[str] = []
        retention_boundary_temporary_names: list[str] = []
        for name in root_entries:
            if name == _CORRELATION_JOURNAL_NAME:
                correlation_journal_identity = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        name,
                        self.root / name,
                    )
                )
                continue
            if name == _RETENTION_BOUNDARY_NAME:
                _regular_stat_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                )
                retention_boundary_names.append(name)
                continue
            if _RETENTION_BOUNDARY_TEMP_NAME.fullmatch(name):
                _regular_stat_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                )
                retention_boundary_temporary_names.append(name)
                continue
            if name == _RETENTION_STATE_NAME:
                retention_state_bindings.append(
                    _read_stable_retention_artifact(
                        self._root_descriptor,
                        name,
                        self.root / name,
                    )
                )
                continue
            if _RETENTION_STATE_TEMP_NAME.fullmatch(name):
                retention_state_temporaries.append(
                    _read_stable_retention_artifact(
                        self._root_descriptor,
                        name,
                        self.root / name,
                    )
                )
                continue
            if name == _REPAIR_STATE_NAME:
                repair_state_bindings.append(
                    _read_stable_repair_artifact(
                        self._root_descriptor,
                        name,
                        self.root / name,
                    )
                )
                continue
            if _REPAIR_STATE_TEMP_NAME.fullmatch(name):
                repair_state_temporaries.append(
                    _read_stable_repair_artifact(
                        self._root_descriptor,
                        name,
                        self.root / name,
                    )
                )
                continue
            if name == "ack-journal.agf":
                ack_journal_identity = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        name,
                        self.root / name,
                    )
                )
                continue
            if name == _ACK_COMMITMENT_NAME:
                try:
                    (
                        ack_commitment,
                        ack_commitment_raw,
                        ack_commitment_identity,
                    ) = self._read_ack_commitment()
                except _AckLifecycleCorrupt as error:
                    raise EvidenceCorrupt(
                        "ACK commitment is invalid at startup"
                    ) from error
                continue
            if _ACK_COMMITMENT_TEMP_NAME.fullmatch(name):
                info = _regular_stat_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                )
                if info.st_size > _MAX_ACK_COMMITMENT_BYTES:
                    raise EvidenceCorrupt(
                        "ACK commitment temporary exceeds its bound"
                    )
                raw = _read_regular_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                    _MAX_ACK_COMMITMENT_BYTES,
                )
                try:
                    temporary = _decode_ack_commitment(raw)
                except (
                    RecursionError,
                    TypeError,
                    ValueError,
                    ValidationError,
                ) as error:
                    raise EvidenceCorrupt(
                        "ACK commitment temporary schema is invalid"
                    ) from error
                if raw != _canonical_ack_commitment(temporary):
                    raise EvidenceCorrupt(
                        "ACK commitment temporary is not canonical JSON"
                    )
                after = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        name,
                        self.root / name,
                    )
                )
                before = _file_identity(info)
                if after != before:
                    raise EvidenceCorrupt(
                        "ACK commitment temporary changed during startup scan"
                    )
                ack_commitment_temporaries.append(
                    _AckCommitmentTemporaryBinding(
                        name=name,
                        commitment=temporary,
                        raw=raw,
                        identity=after,
                    )
                )
                continue
            if name in allowed_root or (
                name.startswith(".health-intent.") and name.endswith(".pending")
            ) or _HEALTH_FINAL_TEMP_NAME.fullmatch(name):
                continue
            if _ROOT_TEMP_NAME.fullmatch(name):
                _regular_stat_at(
                    self._root_descriptor,
                    name,
                    self.root / name,
                )
                root_temporaries.append(name)
                continue
            raise EvidenceCorrupt(f"unexpected evidence-root artifact: {name}")
        if len(ack_commitment_temporaries) > 1:
            raise EvidenceCorrupt("multiple ACK commitment temporaries exist")
        if len(repair_state_bindings) > 1:
            raise EvidenceCorrupt("multiple final repair-state artifacts exist")
        if len(repair_state_temporaries) > 1:
            raise EvidenceCorrupt("multiple repair-state temporaries exist")
        if len(retention_state_bindings) > 1:
            raise EvidenceCorrupt(
                "multiple final retention-state artifacts exist"
            )
        if len(retention_state_temporaries) > 1:
            raise EvidenceCorrupt(
                "multiple retention-state temporaries exist"
            )
        if len(retention_boundary_names) > 1:
            raise EvidenceCorrupt(
                "multiple retention-boundary artifacts exist"
            )
        if len(retention_boundary_temporary_names) > 1:
            raise EvidenceCorrupt(
                "multiple retention-boundary temporaries exist"
            )
        self._repair_state_binding = (
            repair_state_bindings[0] if repair_state_bindings else None
        )
        self._repair_state_temporary = (
            repair_state_temporaries[0] if repair_state_temporaries else None
        )
        self._retention_state_binding = (
            retention_state_bindings[0]
            if retention_state_bindings
            else None
        )
        self._retention_state_temporary = (
            retention_state_temporaries[0]
            if retention_state_temporaries
            else None
        )
        self._retention_pending_latched = (
            self._retention_state_binding is not None
            or self._retention_state_temporary is not None
        )
        self._correlation_journal_identity = correlation_journal_identity
        self._correlation_journal_digest = None
        self._correlation_journal_state = (
            "fresh"
            if correlation_journal_identity is None
            else "present"
        )
        self._ack_journal_identity = ack_journal_identity
        self._ack_commitment = ack_commitment
        self._ack_commitment_raw = ack_commitment_raw
        self._ack_commitment_identity = ack_commitment_identity
        self._ack_commitment_temporary = (
            ack_commitment_temporaries[0]
            if ack_commitment_temporaries
            else None
        )
        if ack_commitment is not None and ack_commitment.phase == "initializing":
            self._ack_journal_state = "bootstrap"
        elif ack_journal_identity is None and ack_commitment is None:
            self._ack_journal_state = "fresh"
        else:
            self._ack_journal_state = "present"
        return (
            _RecoveryPlan(
                promotions=tuple(promotions),
                delete_private_temporaries=tuple(private_temporaries),
                delete_manifest_temporaries=tuple(manifest_temporaries),
                delete_root_temporaries=tuple(root_temporaries),
                delete_retention_state_temporaries=tuple(
                    retention_state_temporaries
                ),
                head_raw=head_raw,
            ),
            manifested_open,
        )

    @staticmethod
    def _order_manifest_chain(
        manifests: list[SegmentManifestV1],
    ) -> list[SegmentManifestV1]:
        if not manifests:
            return []
        by_previous: dict[str, SegmentManifestV1] = {}
        for manifest in manifests:
            if manifest.previous_manifest_sha256 in by_previous:
                raise EvidenceCorrupt("manifest chain fork detected")
            by_previous[manifest.previous_manifest_sha256] = manifest
        ordered: list[SegmentManifestV1] = []
        cursor = GENESIS_MANIFEST_SHA256
        seen: set[str] = set()
        while cursor in by_previous:
            manifest = by_previous[cursor]
            if manifest.manifest_sha256 in seen:
                raise EvidenceCorrupt("manifest chain cycle detected")
            ordered.append(manifest)
            seen.add(manifest.manifest_sha256)
            cursor = manifest.manifest_sha256
        if len(ordered) != len(manifests):
            raise EvidenceCorrupt("manifest chain is disconnected or lacks genesis")
        return ordered

    def _scan_chain_head(self) -> bytes | None:
        head_name = "chain-head.json"
        head_path = self.root / head_name
        if not self._manifests:
            if _entry_stat_at(self._root_descriptor, head_name) is not None:
                raise EvidenceCorrupt("chain head exists without manifests")
            self._chain_head = None
            return None
        expected = chain_head_for(self._manifests[-1])
        if _entry_stat_at(self._root_descriptor, head_name) is None:
            self._chain_head = expected
            return canonical_json(expected)
        raw = _read_regular_at(
            self._root_descriptor,
            head_name,
            head_path,
            MAX_CONTRACT_FILE_BYTES,
        )
        actual = decode_strict(
            raw,
            SegmentChainHeadV1,
            MAX_CONTRACT_FILE_BYTES,
        )
        if raw != canonical_json(actual):
            raise EvidenceCorrupt("chain-head cache is not canonical JSON")
        if actual == expected:
            self._chain_head = actual
            return None
        immediate_prior = (
            len(self._manifests) >= 2
            and actual == chain_head_for(self._manifests[-2])
        )
        if not immediate_prior:
            raise EvidenceCorrupt("chain-head cache references unknown or conflicting facts")
        self._chain_head = expected
        return canonical_json(expected)

    def _validated_active_scan(
        self,
        date_name: str,
        open_name: str,
        scan: _SegmentScan,
    ) -> _ValidatedActiveScan:
        match = _OPEN_NAME.fullmatch(open_name)
        if match is None:
            raise EvidenceCorrupt("active segment filename is not canonical")
        filename_sequence = int(match.group("sequence"))
        if not 1 <= filename_sequence <= MAX_UINT64:
            raise EvidenceCorrupt("active filename first sequence is out of range")
        verified_bytes = (
            scan.size if scan.torn_verified is None else scan.torn_verified
        )
        records = list(scan.records)
        frames = list(scan.frames)
        if (
            verified_bytes <= 0
            or not records
            or not frames
            or len(records) != len(frames)
            or frames[-1].offset + frames[-1].size != verified_bytes
        ):
            raise EvidenceCorrupt("active complete prefix cannot establish exact facts")
        priorities = {record.priority for record in records}
        hosts = {str(record.envelope["host_id"]) for record in records}
        if len(priorities) != 1 or len(hosts) != 1:
            raise EvidenceCorrupt("active segment mixes host or priority")
        if filename_sequence != records[0].ref.source_sequence:
            raise EvidenceCorrupt("active filename first sequence mismatch")
        if records[0].accepted_at[:10] != date_name:
            raise EvidenceCorrupt(
                "active segment date differs from opened_at UTC date"
            )
        segment_id = match.group("segment")
        closed_name = open_name.removesuffix(".open") + ".agseg"
        closed_relative = f"segments/{date_name}/{closed_name}"
        rebuilt: list[StoredEvidenceRecord] = []
        for record, frame in zip(records, frames, strict=True):
            ref = replace_ref(
                record.ref,
                segment_id=segment_id,
                segment_relative_path=closed_relative,
                frame=frame,
            )
            rebuilt.append(
                StoredEvidenceRecord(
                    envelope=record.envelope,
                    canonical_envelope=record.canonical_envelope,
                    priority=record.priority,
                    accepted_at=record.accepted_at,
                    ref=ref,
                )
            )
        return _ValidatedActiveScan(
            records=tuple(rebuilt),
            frames=tuple(frames),
            segment_id=segment_id,
            open_name=open_name,
            closed_name=closed_name,
            closed_relative_path=closed_relative,
            date_name=date_name,
            priority=records[0].priority,
            host_id=str(records[0].envelope["host_id"]),
            first_source_sequence=records[0].ref.source_sequence,
            opened_at=records[0].accepted_at,
            verified_bytes=verified_bytes,
        )

    @staticmethod
    def _validate_post_h0_active_state(
        state: RepairStateV1,
        active: _ValidatedActiveScan,
    ) -> None:
        if len(active.records) != 1:
            raise EvidenceCorrupt(
                "post-repair active tail must contain exactly one unsettled record"
            )
        record = active.records[0]
        ref = record.ref
        authorization = state.authorization
        if state.phase == "truncated":
            if authorization is None or ref.source_sequence > authorization.sequence:
                raise EvidenceCorrupt(
                    "post-repair active tail passed the authorization target"
                )
            expected = authorization
            expected_type = "evidence_repair_authorized"
        elif state.phase == "authorization_appended":
            completion = state.completion
            if (
                authorization is None
                or completion is None
                or not authorization.sequence
                < ref.source_sequence
                <= completion.sequence
            ):
                raise EvidenceCorrupt(
                    "post-repair active tail is outside the completion drain"
                )
            expected = completion
            expected_type = "evidence_repair_completed"
        else:
            raise EvidenceCorrupt(
                "durable repair phase cannot retain a post-H0 active tail"
            )
        if ref.source_sequence == expected.sequence and (
            ref.event_id != expected.event_id
            or ref.content_sha256 != expected.content_sha256
            or record.envelope.get("event_type") != expected_type
        ):
            raise EvidenceCorrupt(
                "post-repair active tail differs from the exact repair target"
            )

    def _scan_tail_repair_target(
        self,
        manifested_open: set[tuple[str, str]],
    ) -> None:
        open_entries: list[tuple[str, str]] = []
        for date_name in sorted(os.listdir(self._segments_descriptor)):
            date_descriptor = self._date_descriptor(date_name)
            for name in sorted(os.listdir(date_descriptor)):
                if name.endswith(".open") and (date_name, name) not in manifested_open:
                    open_entries.append((date_name, name))
        if len(open_entries) > 1:
            raise EvidenceCorrupt("multiple active evidence segments exist")
        if not open_entries:
            if (
                self._repair_state_binding is None
                and self._repair_state_temporary is not None
            ):
                raise EvidenceCorrupt(
                    "repair-state temporary has no original torn target"
                )
            if self._repair_state_binding is not None:
                self._repair_physical_state = RepairPhysicalState.ZERO_RETIRED
            return

        date_name, open_name = open_entries[0]
        match = _OPEN_NAME.fullmatch(open_name)
        if (
            match is None
            or not 1 <= int(match.group("sequence")) <= MAX_UINT64
        ):
            raise EvidenceCorrupt("active segment filename is not canonical")
        path = self._segments_path / date_name / open_name
        date_descriptor = self._date_descriptor(date_name)
        scan = self._read_segment(
            date_descriptor,
            open_name,
            path,
            allow_torn=True,
        )
        descriptor, identity = _open_regular_read_write_at(
            date_descriptor,
            open_name,
            path,
            maximum=MAX_SEGMENT_BYTES,
        )
        if identity != scan.identity:
            os.close(descriptor)
            raise EvidenceCorrupt(
                "repair target changed between scan and retained open"
            )
        target = _RepairTarget(
            date_name=date_name,
            open_name=open_name,
            path=path,
            directory_descriptor=date_descriptor,
            descriptor=descriptor,
            original_identity=identity,
            scan=scan,
        )
        self._repair_target = target
        binding = self._repair_state_binding
        if binding is not None:
            try:
                durable_state = decode_repair_state(binding.raw)
            except RepairStateCorrupt as error:
                raise EvidenceCorrupt("durable repair state is invalid") from error
            relative_path = path.relative_to(self.root).as_posix()
            if relative_path != durable_state.open_relative_path:
                if scan.size == 0 or scan.torn_verified is not None:
                    raise EvidenceCorrupt(
                        "post-repair active tail is empty or torn"
                    )
                validated = self._validated_active_scan(
                    date_name,
                    open_name,
                    scan,
                )
                self._validate_post_h0_active_state(
                    durable_state,
                    validated,
                )
                self._add_records(list(validated.records))
                self._repair_post_h0_active = target
                self._repair_target = None
                return

        if scan.size == 0:
            if self._repair_state_binding is None:
                raise EvidenceCorrupt(
                    "zero-byte active segment lacks durable repair state"
                )
            self._repair_physical_state = RepairPhysicalState.ZERO_HELD
            return

        if scan.torn_verified is None:
            if self._repair_state_binding is None:
                if self._repair_state_temporary is not None:
                    raise EvidenceCorrupt(
                        "post-truncate prefix has no final repair state"
                    )
                raise EvidenceStoreError(
                    "active segment is complete and needs no tail repair"
                )
            validated = self._validated_active_scan(date_name, open_name, scan)
            self._add_records(list(validated.records))
            self._repair_physical_state = RepairPhysicalState.CLEAN_OPEN
            return

        verified_bytes = scan.torn_verified
        if not 0 <= verified_bytes < scan.size:
            raise EvidenceCorrupt("torn repair byte range is invalid")
        discarded_bytes = scan.size - verified_bytes
        if discarded_bytes > MAX_EVIDENCE_RECORD_BYTES + 75:
            raise EvidenceCorrupt("incomplete AGF1 suffix exceeds one frame")
        suffix = _held_range_bytes(
            date_descriptor,
            open_name,
            path,
            descriptor=descriptor,
            identity=identity,
            start=verified_bytes,
            end=scan.size,
        )
        previous_hash = (
            scan.frames[-1].record_hash if scan.frames else bytes(32)
        )
        _validate_incomplete_frame_suffix(
            suffix,
            expected_previous=previous_hash,
        )

        if verified_bytes == 0:
            if scan.frames or scan.records:
                raise EvidenceCorrupt(
                    "zero-prefix repair target contains a complete frame"
                )
            segment_id = match.group("segment")
        else:
            validated = self._validated_active_scan(date_name, open_name, scan)
            self._add_records(list(validated.records))
            segment_id = validated.segment_id

        prefix_sha256 = _hash_held_range(
            date_descriptor,
            open_name,
            path,
            descriptor=descriptor,
            identity=identity,
            start=0,
            end=verified_bytes,
        )
        discarded_sha256 = hashlib.sha256(suffix).hexdigest()
        expected_head = (
            chain_head_for(self._manifests[-1]) if self._manifests else None
        )
        current_chain_head_sha256 = (
            _ZERO_SHA256
            if expected_head is None
            else hashlib.sha256(canonical_json(expected_head)).hexdigest()
        )
        manifest_predecessor_sha256 = (
            self._manifests[-1].manifest_sha256
            if self._manifests
            else GENESIS_MANIFEST_SHA256
        )
        self._repair_facts = TailRepairFacts(
            segment_id=segment_id,
            open_relative_path=path.relative_to(self.root).as_posix(),
            original_device=identity.device,
            original_inode=identity.inode,
            original_bytes=identity.size,
            verified_bytes=verified_bytes,
            discarded_bytes=discarded_bytes,
            discarded_sha256=discarded_sha256,
            post_repair_prefix_sha256=prefix_sha256,
            last_verified_frame_sha256=(
                scan.frames[-1].record_hash.hex()
                if scan.frames
                else _ZERO_SHA256
            ),
            current_chain_head_sha256=current_chain_head_sha256,
            manifest_predecessor_sha256=manifest_predecessor_sha256,
        )
        self._repair_physical_state = RepairPhysicalState.ORIGINAL_TORN

    def _manifest_predecessor_for_h0(self, h0: str) -> str:
        matches: list[str] = []
        if h0 == _ZERO_SHA256:
            matches.append(GENESIS_MANIFEST_SHA256)
        for manifest in self._manifests:
            digest = hashlib.sha256(
                canonical_json(chain_head_for(manifest))
            ).hexdigest()
            if digest == h0:
                matches.append(manifest.manifest_sha256)
        if len(matches) != 1:
            raise EvidenceCorrupt(
                "repair H0 does not select one historical manifest prefix"
            )
        return matches[0]

    def _repair_facts_from_state(
        self,
        state: RepairStateV1,
    ) -> TailRepairFacts:
        return TailRepairFacts(
            segment_id=state.segment_id,
            open_relative_path=state.open_relative_path,
            original_device=state.original_device,
            original_inode=state.original_inode,
            original_bytes=state.original_bytes,
            verified_bytes=state.verified_bytes,
            discarded_bytes=state.discarded_bytes,
            discarded_sha256=state.discarded_sha256,
            post_repair_prefix_sha256=state.post_repair_prefix_sha256,
            last_verified_frame_sha256=state.last_verified_frame_sha256,
            current_chain_head_sha256=state.current_chain_head_sha256,
            manifest_predecessor_sha256=self._manifest_predecessor_for_h0(
                state.current_chain_head_sha256
            ),
        )

    def _bind_durable_repair_facts(self) -> None:
        binding = self._repair_state_binding
        if binding is None:
            if (
                self._repair_physical_state
                is not RepairPhysicalState.ORIGINAL_TORN
                and self._repair_state_temporary is not None
            ):
                raise EvidenceCorrupt(
                    "repair temporary cannot authorize post-truncate bytes"
                )
            return
        try:
            state = decode_repair_state(binding.raw)
        except RepairStateCorrupt as error:
            raise EvidenceCorrupt("durable repair state is invalid") from error
        durable_facts = self._repair_facts_from_state(state)
        detected_facts = self._repair_facts
        if (
            self._repair_physical_state is RepairPhysicalState.ORIGINAL_TORN
            and detected_facts != durable_facts
        ):
            raise EvidenceCorrupt(
                "durable repair state differs from the original torn bytes"
            )
        self._repair_facts = durable_facts
        physical = self.classify_repair_physical(durable_facts)
        if physical is RepairPhysicalState.INVALID:
            raise EvidenceCorrupt(
                "durable repair state does not match the held physical namespace"
            )
        if not self._repair_phase_matches_physical(state, physical):
            raise EvidenceCorrupt(
                "durable repair phase contradicts the held physical namespace"
            )
        if (
            self._repair_post_h0_active is not None
            and physical
            not in {
                RepairPhysicalState.SETTLED_PREFIX,
                RepairPhysicalState.ZERO_RETIRED,
            }
        ):
            raise EvidenceCorrupt(
                "post-H0 active tail precedes original repair settlement"
            )
        self._repair_physical_state = physical

    @staticmethod
    def _repair_phase_matches_physical(
        state: RepairStateV1,
        physical: RepairPhysicalState,
    ) -> bool:
        if state.phase == "detected":
            return physical is RepairPhysicalState.ORIGINAL_TORN
        if state.phase == "authorized":
            return physical in {
                RepairPhysicalState.ORIGINAL_TORN,
                RepairPhysicalState.CLEAN_OPEN,
                RepairPhysicalState.ZERO_HELD,
            }
        return physical in {
            RepairPhysicalState.CLEAN_OPEN,
            RepairPhysicalState.SETTLED_PREFIX,
            RepairPhysicalState.ZERO_HELD,
            RepairPhysicalState.ZERO_RETIRED,
        }

    def _historical_h0_matches(self, facts: TailRepairFacts) -> bool:
        try:
            return (
                self._manifest_predecessor_for_h0(
                    facts.current_chain_head_sha256
                )
                == facts.manifest_predecessor_sha256
            )
        except EvidenceCorrupt:
            return False

    def classify_repair_physical(
        self,
        facts: TailRepairFacts,
    ) -> RepairPhysicalState:
        self._require_repair_lifecycle()
        if self._repair_namespace_uncertain:
            return RepairPhysicalState.INVALID
        if type(facts) is not TailRepairFacts or not self._historical_h0_matches(facts):
            return RepairPhysicalState.INVALID
        path_match = _OPEN_NAME.fullmatch(
            facts.open_relative_path.rsplit("/", 1)[-1]
        )
        path_parts = facts.open_relative_path.split("/")
        if (
            path_match is None
            or len(path_parts) != 3
            or path_parts[0] != "segments"
            or path_match.group("segment") != facts.segment_id
            or not 1 <= int(path_match.group("sequence")) <= MAX_UINT64
        ):
            return RepairPhysicalState.INVALID
        date_name = path_parts[1]
        open_name = path_parts[2]
        try:
            date_descriptor = self._date_descriptor(date_name)
            open_info = _entry_stat_at(date_descriptor, open_name)
            if open_info is not None:
                descriptor, identity = _open_regular_read_write_at(
                    date_descriptor,
                    open_name,
                    self.root / facts.open_relative_path,
                    maximum=MAX_SEGMENT_BYTES,
                )
                try:
                    if (
                        identity.device != facts.original_device
                        or identity.inode != facts.original_inode
                    ):
                        return RepairPhysicalState.INVALID
                    scan = self._read_segment(
                        date_descriptor,
                        open_name,
                        self.root / facts.open_relative_path,
                        allow_torn=True,
                    )
                    if scan.identity != identity:
                        return RepairPhysicalState.INVALID
                    if (
                        identity.size == facts.original_bytes
                        and scan.torn_verified == facts.verified_bytes
                        and facts.discarded_bytes
                        == facts.original_bytes - facts.verified_bytes
                    ):
                        suffix = _held_range_bytes(
                            date_descriptor,
                            open_name,
                            self.root / facts.open_relative_path,
                            descriptor=descriptor,
                            identity=identity,
                            start=facts.verified_bytes,
                            end=facts.original_bytes,
                        )
                        prefix_sha256 = _hash_held_range(
                            date_descriptor,
                            open_name,
                            self.root / facts.open_relative_path,
                            descriptor=descriptor,
                            identity=identity,
                            start=0,
                            end=facts.verified_bytes,
                        )
                        last_frame_sha256 = (
                            scan.frames[-1].record_hash.hex()
                            if scan.frames
                            else _ZERO_SHA256
                        )
                        if (
                            hashlib.sha256(suffix).hexdigest()
                            == facts.discarded_sha256
                            and prefix_sha256
                            == facts.post_repair_prefix_sha256
                            and last_frame_sha256
                            == facts.last_verified_frame_sha256
                        ):
                            _validate_incomplete_frame_suffix(
                                suffix,
                                expected_previous=(
                                    scan.frames[-1].record_hash
                                    if scan.frames
                                    else bytes(32)
                                ),
                            )
                            return RepairPhysicalState.ORIGINAL_TORN
                    if (
                        facts.verified_bytes == 0
                        and identity.size == 0
                        and not scan.frames
                        and not scan.records
                        and scan.torn_verified is None
                    ):
                        return RepairPhysicalState.ZERO_HELD
                    if (
                        facts.verified_bytes > 0
                        and identity.size == facts.verified_bytes
                        and scan.torn_verified is None
                        and scan.frames
                        and scan.frames[-1].record_hash.hex()
                        == facts.last_verified_frame_sha256
                        and _hash_held_range(
                            date_descriptor,
                            open_name,
                            self.root / facts.open_relative_path,
                            descriptor=descriptor,
                            identity=identity,
                            start=0,
                            end=identity.size,
                        )
                        == facts.post_repair_prefix_sha256
                    ):
                        self._validated_active_scan(date_name, open_name, scan)
                        return RepairPhysicalState.CLEAN_OPEN
                    return RepairPhysicalState.INVALID
                finally:
                    os.close(descriptor)

            matching = [
                manifest
                for manifest in self._manifests
                if manifest.segment_id == facts.segment_id
            ]
            if facts.verified_bytes == 0:
                return (
                    RepairPhysicalState.ZERO_RETIRED
                    if not matching
                    else RepairPhysicalState.INVALID
                )
            if len(matching) != 1:
                return RepairPhysicalState.INVALID
            manifest = matching[0]
            expected_relative = facts.open_relative_path.removesuffix(
                ".open"
            ) + ".agseg"
            if (
                manifest.segment_relative_path != expected_relative
                or manifest.previous_manifest_sha256
                != facts.manifest_predecessor_sha256
                or manifest.segment_size_bytes != facts.verified_bytes
                or manifest.segment_sha256
                != facts.post_repair_prefix_sha256
                or manifest.last_frame_sha256
                != facts.last_verified_frame_sha256
            ):
                return RepairPhysicalState.INVALID
            _, manifest_date, closed_name = expected_relative.split("/")
            closed_descriptor = self._date_descriptor(manifest_date)
            closed_scan = self._verify_segment_against_manifest(
                closed_descriptor,
                closed_name,
                self.root / expected_relative,
                manifest,
            )
            if (
                closed_scan.identity.device == facts.original_device
                and closed_scan.identity.inode == facts.original_inode
            ):
                return RepairPhysicalState.SETTLED_PREFIX
            return RepairPhysicalState.INVALID
        except (EvidenceCorrupt, OSError, ValueError):
            return RepairPhysicalState.INVALID

    def _scan_unsettled_open(
        self,
        manifested_open: set[tuple[str, str]],
    ) -> tuple[tuple[str, str], ...]:
        open_entries: list[tuple[str, str]] = []
        for date_name in sorted(os.listdir(self._segments_descriptor)):
            date_descriptor = self._date_descriptor(date_name)
            for name in sorted(os.listdir(date_descriptor)):
                if name.endswith(".open") and (date_name, name) not in manifested_open:
                    open_entries.append((date_name, name))
        if len(open_entries) > 1:
            raise EvidenceCorrupt("multiple active evidence segments exist")
        if not open_entries:
            return ()
        date_name, open_name = open_entries[0]
        path = self._segments_path / date_name / open_name
        match = _OPEN_NAME.fullmatch(open_name)
        if match is None:
            raise EvidenceCorrupt("active segment filename is not canonical")
        date_descriptor = self._date_descriptor(date_name)
        scan = self._read_segment(
            date_descriptor,
            open_name,
            path,
            allow_torn=True,
        )
        if scan.size == 0:
            raise EvidenceCorrupt("zero-byte active segment is impossible")
        if scan.torn_verified is not None:
            raise TornTailRepairRequired(path, scan.torn_verified, scan.size)
        validated = self._validated_active_scan(date_name, open_name, scan)
        self._add_records(list(validated.records))
        descriptor = -1
        if self._read_only_reason is None:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(open_name, flags, dir_fd=date_descriptor)
            try:
                _bind_held_source(
                    date_descriptor,
                    open_name,
                    path,
                    descriptor=descriptor,
                    identity=scan.identity,
                )
            except BaseException:
                os.close(descriptor)
                raise
        self._active = _ActiveSegment(
            segment_id=validated.segment_id,
            open_path=path,
            open_name=open_name,
            closed_name=validated.closed_name,
            closed_relative_path=validated.closed_relative_path,
            directory_descriptor=date_descriptor,
            priority=validated.priority,
            host_id=validated.host_id,
            first_source_sequence=validated.first_source_sequence,
            opened_at=validated.opened_at,
            opened_monotonic=self._monotonic() - MAX_SEGMENT_AGE_SECONDS,
            descriptor=descriptor,
            size=scan.size,
            record_count=len(validated.records),
            previous_frame_hash=validated.frames[-1].record_hash,
        )
        return ()

    def _discard_retention_state_temporary(
        self,
        binding: _RetentionStateArtifactBinding,
    ) -> None:
        current = _read_stable_retention_artifact(
            self._root_descriptor,
            binding.name,
            self.root / binding.name,
        )
        if current != binding:
            raise EvidenceCorrupt(
                "retention-state temporary changed before discard"
            )
        descriptor, opened = _open_regular_at(
            self._root_descriptor,
            binding.name,
            self.root / binding.name,
            maximum=_MAX_RETENTION_STATE_BYTES,
        )
        try:
            with _post_authentication_namespace(self.root / binding.name):
                _bind_held_source(
                    self._root_descriptor,
                    binding.name,
                    self.root / binding.name,
                    descriptor=descriptor,
                    identity=binding.identity,
                )
                self._retention_state_namespace_uncertain = True
                os.unlink(binding.name, dir_fd=self._root_descriptor)
                unlinked = os.fstat(descriptor)
                if (
                    unlinked.st_dev != opened.st_dev
                    or unlinked.st_ino != opened.st_ino
                    or unlinked.st_size != opened.st_size
                    or unlinked.st_nlink != 0
                    or _entry_stat_at(
                        self._root_descriptor,
                        binding.name,
                    )
                    is not None
                ):
                    raise EvidenceCorrupt(
                        "retention-state temporary discard became uncertain"
                    )
                os.fsync(self._root_descriptor)
        finally:
            os.close(descriptor)
        if self._retention_state_temporary != binding:
            raise EvidenceCorrupt(
                "retention-state temporary binding changed after discard"
            )
        self._retention_state_temporary = None
        self._retention_state_namespace_uncertain = False
        if self._retention_state_binding is None:
            self._clear_retention_pending_latch()

    def _discard_retention_boundary_temporary(
        self,
        name: str,
    ) -> None:
        if _RETENTION_BOUNDARY_TEMP_NAME.fullmatch(name) is None:
            raise EvidenceCorrupt(
                "retention-boundary temporary name is invalid"
            )
        path = self.root / name
        identity = _file_identity(
            _regular_stat_at(
                self._root_descriptor,
                name,
                path,
            )
        )
        descriptor, opened = _open_regular_at(
            self._root_descriptor,
            name,
            path,
        )
        try:
            _validate_identity(opened, identity, path)
            with _post_authentication_namespace(path):
                _bind_held_source(
                    self._root_descriptor,
                    name,
                    path,
                    descriptor=descriptor,
                    identity=identity,
                )
                os.unlink(name, dir_fd=self._root_descriptor)
                unlinked = os.fstat(descriptor)
                if (
                    unlinked.st_dev != identity.device
                    or unlinked.st_ino != identity.inode
                    or unlinked.st_size != identity.size
                    or unlinked.st_mode != identity.mode
                    or unlinked.st_uid != identity.owner
                    or unlinked.st_nlink != 0
                    or _entry_stat_at(self._root_descriptor, name) is not None
                ):
                    raise EvidenceCorrupt(
                        "retention-boundary temporary discard became uncertain"
                    )
                os.fsync(self._root_descriptor)
        finally:
            os.close(descriptor)

    def _apply_recovery_plan(self, plan: _RecoveryPlan) -> None:
        for promotion in plan.promotions:
            date_descriptor = self._date_descriptor(promotion.date_name)
            try:
                _promote_authenticated_source(
                    date_descriptor,
                    promotion.open_name,
                    promotion.closed_name,
                    self._segments_path
                    / promotion.date_name
                    / promotion.closed_name,
                    identity=promotion.identity,
                    expected_sha256=promotion.sha256,
                )
            except FileExistsError as error:
                raise EvidenceCorrupt(
                    "segment recovery promotion target already exists"
                ) from error
        if plan.head_raw is not None:
            _atomic_replace_at(
                self._root_descriptor,
                "chain-head.json",
                self.root / "chain-head.json",
                plan.head_raw,
            )
        for date_name, name in plan.delete_private_temporaries:
            os.unlink(name, dir_fd=self._date_descriptor(date_name))
            os.fsync(self._date_descriptor(date_name))
        for name in plan.delete_manifest_temporaries:
            os.unlink(name, dir_fd=self._manifests_descriptor)
        if plan.delete_manifest_temporaries:
            os.fsync(self._manifests_descriptor)
        for name in plan.delete_root_temporaries:
            os.unlink(name, dir_fd=self._root_descriptor)
        if plan.delete_root_temporaries:
            os.fsync(self._root_descriptor)
        for binding in plan.delete_retention_state_temporaries:
            self._discard_retention_state_temporary(binding)

    def _scan_held_segment_descriptor(
        self,
        descriptor: int,
        identity: _FileIdentity,
        path: Path,
        *,
        allow_torn: bool,
    ) -> _SegmentScan:
        duplicate = -1
        frames: list[FrameRecord] = []
        torn_verified: int | None = None
        digest = ""
        total = 0
        after: os.stat_result | None = None
        try:
            duplicate = os.dup(descriptor)
            os.lseek(duplicate, 0, os.SEEK_SET)
            try:
                with os.fdopen(
                    duplicate,
                    "rb",
                    buffering=0,
                    closefd=True,
                ) as stream:
                    duplicate = -1
                    hashing_stream = _HashingReader(
                        cast(BinaryIO, stream),
                        maximum=MAX_SEGMENT_BYTES,
                        expected_size=identity.size,
                    )
                    _validate_identity(
                        os.fstat(descriptor),
                        identity,
                        path,
                    )
                    try:
                        frames.extend(
                            iter_frames(
                                cast(BinaryIO, hashing_stream),
                                max_frame=MAX_EVIDENCE_RECORD_BYTES,
                            )
                        )
                    except TornTail as error:
                        if not allow_torn:
                            raise EvidenceCorrupt(
                                "closed segment has a torn frame"
                            ) from error
                        torn_verified = error.verified_bytes
                    digest = hashing_stream.hexdigest()
                    total = hashing_stream.total
                    after = os.fstat(stream.fileno())
            except JournalCorrupt as error:
                raise EvidenceCorrupt(
                    "complete AGF1 frame is corrupt"
                ) from error
        finally:
            if duplicate >= 0:
                os.close(duplicate)
        if total != identity.size:
            raise EvidenceCorrupt("segment size changed during streaming verification")
        assert after is not None
        held_after = os.fstat(descriptor)
        if (
            after.st_size > MAX_SEGMENT_BYTES
            or held_after.st_size > MAX_SEGMENT_BYTES
        ):
            raise EvidenceCorrupt("segment growth exceeded cumulative scan bound")
        if (
            _file_identity(after) != identity
            or _file_identity(held_after) != identity
        ):
            raise EvidenceCorrupt("segment changed during held-descriptor verification")
        records: list[StoredEvidenceRecord] = []
        for frame in frames:
            try:
                value = decode_strict(
                    frame.payload,
                    _AcceptedEnvelopeRecordV1,
                    MAX_EVIDENCE_RECORD_BYTES,
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise EvidenceCorrupt("evidence frame payload is invalid") from error
            if frame.payload != canonical_json(value):
                raise EvidenceCorrupt("evidence frame payload is not canonical JSON")
            canonical_envelope = canonical_json(value.envelope)
            records.append(
                StoredEvidenceRecord(
                    envelope=value.envelope,
                    canonical_envelope=canonical_envelope,
                    priority=EvidencePriority(value.evidence_priority),
                    accepted_at=value.accepted_at,
                    ref=EvidenceRef(
                        segment_id="00000000-0000-4000-8000-000000000000",
                        segment_relative_path="",
                        frame_offset=frame.offset,
                        frame_size=frame.size,
                        frame_sha256=frame.record_hash.hex(),
                        event_id=value.outer.event_id,
                        source_sequence=value.outer.sequence,
                        content_sha256=value.outer.content_sha256,
                    ),
                )
            )
        return _SegmentScan(
            records=tuple(records),
            frames=tuple(frames),
            torn_verified=torn_verified,
            size=total,
            sha256=digest,
            identity=identity,
        )

    def _read_segment(
        self,
        parent_descriptor: int,
        name: str,
        path: Path,
        *,
        allow_torn: bool,
    ) -> _SegmentScan:
        descriptor = -1
        try:
            descriptor, expected = _open_regular_at(
                parent_descriptor,
                name,
                path,
                maximum=MAX_SEGMENT_BYTES,
            )
            identity = _file_identity(expected)
            scan = self._scan_held_segment_descriptor(
                descriptor,
                identity,
                path,
                allow_torn=allow_torn,
            )
            _bind_held_source(
                parent_descriptor,
                name,
                path,
                descriptor=descriptor,
                identity=identity,
            )
            return scan
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _verify_segment_against_manifest(
        self,
        parent_descriptor: int,
        name: str,
        path: Path,
        manifest: SegmentManifestV1,
    ) -> _SegmentScan:
        scan = self._read_segment(
            parent_descriptor,
            name,
            path,
            allow_torn=False,
        )
        return self._validate_segment_scan_against_manifest(
            scan,
            name,
            path,
            manifest,
        )

    def _validate_segment_scan_against_manifest(
        self,
        scan: _SegmentScan,
        name: str,
        path: Path,
        manifest: SegmentManifestV1,
    ) -> _SegmentScan:
        records = list(scan.records)
        frames = list(scan.frames)
        if scan.torn_verified is not None or not records or not frames:
            raise EvidenceCorrupt("settled segment is empty or torn")
        priorities = {record.priority.value for record in records}
        hosts = {str(record.envelope["host_id"]) for record in records}
        logical_name = (
            name.removesuffix(".open") + ".agseg"
            if name.endswith(".open")
            else name
        )
        logical_path = path.with_name(logical_name)
        facts_match = (
            len(priorities) == 1
            and priorities == {manifest.evidence_priority}
            and hosts == {manifest.host_id}
            and len(records) == manifest.record_count
            and scan.size == manifest.segment_size_bytes
            and scan.sha256 == manifest.segment_sha256
            and records[0].ref.event_id == manifest.first_event_id
            and records[-1].ref.event_id == manifest.last_event_id
            and records[0].ref.source_sequence == manifest.first_source_sequence
            and records[-1].ref.source_sequence == manifest.last_source_sequence
            and frames[0].record_hash.hex() == manifest.first_frame_sha256
            and frames[-1].record_hash.hex() == manifest.last_frame_sha256
            and logical_path.relative_to(self.root).as_posix()
            == manifest.segment_relative_path
        )
        if not facts_match:
            raise EvidenceCorrupt("segment facts do not match immutable manifest")
        rebuilt: list[StoredEvidenceRecord] = []
        for record, frame in zip(records, frames, strict=True):
            ref = replace_ref(
                record.ref,
                segment_id=manifest.segment_id,
                segment_relative_path=manifest.segment_relative_path,
                frame=frame,
            )
            rebuilt.append(
                StoredEvidenceRecord(
                    envelope=record.envelope,
                    canonical_envelope=record.canonical_envelope,
                    priority=record.priority,
                    accepted_at=record.accepted_at,
                    ref=ref,
                )
            )
        return _SegmentScan(
            records=tuple(rebuilt),
            frames=scan.frames,
            torn_verified=None,
            size=scan.size,
            sha256=scan.sha256,
            identity=scan.identity,
        )

    def _add_records(self, records: list[StoredEvidenceRecord]) -> None:
        for record in records:
            host_id = str(record.envelope["host_id"])
            key = (host_id, record.ref.source_sequence)
            prior = self._index.get(key)
            if prior is not None:
                if prior[0] != record.canonical_envelope:
                    raise EvidenceCorrupt("stored same-sequence evidence conflict")
                raise EvidenceCorrupt("stored duplicate evidence frame")
            prior_sequence = self._last_sequence_by_host.get(host_id, 0)
            if record.ref.source_sequence <= prior_sequence:
                raise EvidenceCorrupt("stored evidence is not in host-global sequence order")
            self._record_positions[key] = len(self._records)
            self._sequences_by_host.setdefault(host_id, []).append(
                record.ref.source_sequence
            )
            self._index[key] = (record.canonical_envelope, record.ref)
            self._last_sequence_by_host[host_id] = record.ref.source_sequence
            self._records.append(record)

    def _bind_empty(self, verifier: EnvelopeVerifier) -> None:
        if self._closed:
            raise EvidenceStoreError("evidence store is closed")
        if self._bound_verifier is not None or self._authority_state != "unbound":
            raise EvidenceSealError("evidence store already has verifier authority")
        if (
            self._records
            or self._manifests
            or self._chain_head is not None
            or self._active is not None
            or self._retention_state_binding is not None
            or self._retention_state_temporary is not None
            or any(
                name == _RETENTION_BOUNDARY_NAME
                or _RETENTION_BOUNDARY_TEMP_NAME.fullmatch(name)
                for name in os.listdir(self._root_descriptor)
            )
        ):
            raise EvidenceReadOnly(
                "nonempty evidence requires authenticated open-and-recover"
            )
        try:
            verifier._bind_lifecycle(self._lifecycle_identity)
            verifier._seal_retention_recovery(
                self._lifecycle_identity
            )
        except VerifierCommitError as error:
            raise EvidenceSealError("verifier belongs to another store lifecycle") from error
        self._bound_verifier = verifier
        self._authority_state = "ready"

    def _replay_recovered_record(
        self,
        verifier: EnvelopeVerifier,
        record: StoredEvidenceRecord,
    ) -> None:
        if record.envelope.get("event_type") == "pcc_correlation_snapshot":
            self._replay_recovered_pcc_record(verifier, record)
            return
        ref = record.ref
        verified = verifier.verify(
            record.envelope,
            sequence=ref.source_sequence,
            event_id=ref.event_id,
            content_sha256=ref.content_sha256,
        )
        authorization = verifier._authorize_append(
            verified,
            self._lifecycle_identity,
            record.priority.value,
        )
        if authorization.canonical != record.canonical_envelope:
            raise EvidenceCorrupt("replay canonical bytes changed")
        verifier._commit_durable(
            authorization,
            self._lifecycle_identity,
            ref,
        )

    def _replay_recovered_pcc_record(
        self,
        verifier: EnvelopeVerifier,
        record: StoredEvidenceRecord,
    ) -> None:
        if (
            self._bound_verifier is not verifier
            or self._authority_state != "recovering"
        ):
            raise EvidenceSealError(
                "PCC recovery requires the bound recovering verifier lifecycle"
            )
        try:
            envelope = EventEnvelopeV1.model_validate_json(
                record.canonical_envelope,
                strict=True,
            )
            snapshot = PCCCorrelationSnapshotV1.model_validate(
                envelope.normalized_fields,
                strict=True,
            )
            request = PCCCorrelationSnapshotRequestV1.model_validate(
                {
                    "schema_version": (
                        "agmind.pcc-correlation-snapshot-request.v1"
                    ),
                    "trigger_event_id": snapshot.trigger.event_id,
                    "trigger_content_sha256": (
                        snapshot.trigger.content_sha256
                    ),
                    "trigger_source_sequence": (
                        snapshot.trigger.source_sequence
                    ),
                    "requested_ttl_seconds": (
                        snapshot.requested_ttl_seconds
                    ),
                },
                strict=True,
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise EvidenceCorrupt(
                "recovered PCC snapshot cannot reconstruct its exact request"
            ) from error
        ref = record.ref
        if verifier.accepted_ref(snapshot.trigger.source_sequence) is None:
            verifier._recover_deferred_pcc(
                record.envelope,
                sequence=ref.source_sequence,
                event_id=ref.event_id,
                content_sha256=ref.content_sha256,
                request=request,
                evidence_ref=ref,
                evidence_priority=record.priority.value,
                lifecycle=self._lifecycle_identity,
            )
            return
        verified = verifier.verify(
            record.envelope,
            sequence=ref.source_sequence,
            event_id=ref.event_id,
            content_sha256=ref.content_sha256,
            pcc_context=PCCCorrelationVerificationContext(
                request=request,
            ),
        )
        authorization = verifier._authorize_append(
            verified,
            self._lifecycle_identity,
            record.priority.value,
        )
        if authorization.canonical != record.canonical_envelope:
            raise EvidenceCorrupt("PCC replay canonical bytes changed")
        verifier._commit_durable(
            authorization,
            self._lifecycle_identity,
            ref,
        )

    def _replay_manifest_chain(
        self,
        verifier: EnvelopeVerifier,
    ) -> None:
        replayed: set[tuple[str, int]] = set()
        prior_last = 0
        for manifest in self._manifests:
            if (
                manifest.host_id != verifier.root.host_id
                or manifest.first_source_sequence <= prior_last
                or manifest.record_count
                > manifest.last_source_sequence
                - manifest.first_source_sequence
                + 1
            ):
                raise EvidenceCorrupt(
                    "retention replay manifest order is invalid"
                )
            records = self._manifest_replay_records.get(
                manifest.manifest_sha256
            )
            if records is None:
                if (
                    manifest.evidence_priority != "routine"
                    or manifest.record_count
                    != manifest.last_source_sequence
                    - manifest.first_source_sequence
                    + 1
                ):
                    raise EvidenceCorrupt(
                        "missing retention payload has no dense routine replay shape"
                    )
                verifier._recover_dense_routine_omission(
                    manifest_sha256=manifest.manifest_sha256,
                    first_sequence=manifest.first_source_sequence,
                    last_sequence=manifest.last_source_sequence,
                    record_count=manifest.record_count,
                    lifecycle=self._lifecycle_identity,
                )
            else:
                if len(records) != manifest.record_count:
                    raise EvidenceCorrupt(
                        "manifest replay record count changed"
                    )
                for record in records:
                    self._replay_recovered_record(verifier, record)
                    replayed.add(
                        (
                            str(record.envelope["host_id"]),
                            record.ref.source_sequence,
                        )
                    )
            prior_last = manifest.last_source_sequence

        for record in self._records:
            key = (
                str(record.envelope["host_id"]),
                record.ref.source_sequence,
            )
            if key in replayed:
                continue
            self._replay_recovered_record(verifier, record)

    def _authenticated_retention_tombstones_for_recovery(
        self,
        verifier: EnvelopeVerifier,
    ) -> tuple[tuple[StoredEvidenceRecord, RetentionTombstoneV2], ...]:
        result: list[
            tuple[StoredEvidenceRecord, RetentionTombstoneV2]
        ] = []
        for record in self._records:
            if record.envelope.get("event_type") != "retention_tombstone":
                continue
            accepted = verifier._authority.accepted.get(
                record.ref.source_sequence
            )
            try:
                envelope = EventEnvelopeV1.model_validate_json(
                    record.canonical_envelope,
                    strict=True,
                )
                request = RetentionTombstoneV2.model_validate(
                    envelope.normalized_fields,
                    strict=True,
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise EvidenceCorrupt(
                    "retention recovery tombstone is malformed"
                ) from error
            if (
                record.priority is not EvidencePriority.PROTECTED
                or accepted is None
                or accepted.canonical != record.canonical_envelope
                or accepted.evidence_ref is not record.ref
                or accepted.evidence_priority != "protected"
                or verifier.accepted_ref(record.ref.source_sequence)
                is not record.ref
                or envelope.event_type != "retention_tombstone"
                or envelope.normalized_fields
                != request.model_dump(mode="python")
            ):
                raise EvidenceCorrupt(
                    "retention recovery tombstone is not exact authenticated evidence"
                )
            result.append((record, request))
        return tuple(result)

    def _authenticate_retention_recovery(
        self,
        verifier: EnvelopeVerifier,
    ) -> _AuthenticatedRetentionRecovery:
        from agmind_immune.evidence.retention import (
            MAX_RETENTION_BOUNDARY_BYTES,
            RetentionBoundaryV1,
            RetentionStateCorrupt,
            RetentionStateV1,
            decode_retention_state,
        )

        positions = {
            manifest.manifest_sha256: index
            for index, manifest in enumerate(self._manifests)
        }
        h0_tips = {
            hashlib.sha256(
                canonical_json(chain_head_for(manifest))
            ).hexdigest(): index
            for index, manifest in enumerate(self._manifests)
        }
        covered_by: dict[str, tuple[int, RetentionTombstoneV2]] = {}
        accepted_by_outer: dict[
            tuple[int, str, str],
            RetentionTombstoneV2,
        ] = {}
        record_by_outer: dict[
            tuple[int, str, str],
            StoredEvidenceRecord,
        ] = {}
        seen_ids: dict[str, tuple[bytes, tuple[int, str, str]]] = {}
        previous_sequence = 0
        previous_end = -1
        previous_tip = -1

        authenticated_tombstones = (
            self._authenticated_retention_tombstones_for_recovery(
                verifier
            )
        )
        for record, request in authenticated_tombstones:
            outer = (
                record.ref.source_sequence,
                record.ref.event_id,
                record.ref.content_sha256,
            )
            request_raw = canonical_json(
                request.model_dump(mode="python")
            )
            prior_id = seen_ids.get(request.tombstone_id)
            if prior_id is not None:
                if prior_id != (request_raw, outer):
                    raise EvidenceCorrupt(
                        "retention recovery tombstone identity conflicts"
                    )
                continue
            if record.ref.source_sequence <= previous_sequence:
                raise EvidenceCorrupt(
                    "retention recovery tombstones are out of evidence order"
                )
            tip = h0_tips.get(request.current_chain_head_sha256)
            if tip is None:
                raise EvidenceCorrupt(
                    "retention recovery tombstone H0 is not a manifest prefix"
                )
            try:
                run_positions = tuple(
                    positions[value]
                    for value in request.removed_manifest_hashes
                )
            except KeyError as error:
                raise EvidenceCorrupt(
                    "retention recovery tombstone names an unknown manifest"
                ) from error
            if (
                not run_positions
                or any(
                    right != left + 1
                    for left, right in pairwise(run_positions)
                )
            ):
                raise EvidenceCorrupt(
                    "retention recovery run is not manifest-adjacent"
                )
            start = run_positions[0]
            end = run_positions[-1]
            if (
                end > tip
                or start <= previous_end
                or tip < previous_tip
                or record.ref.source_sequence
                <= self._manifests[tip].last_source_sequence
            ):
                raise EvidenceCorrupt(
                    "retention recovery run is outside ordered H0 authority"
                )
            successor = (
                self._manifests[end + 1].manifest_sha256
                if end < tip
                else _ZERO_SHA256
            )
            if request.first_retained_manifest_sha256 != successor:
                raise EvidenceCorrupt(
                    "retention recovery successor differs from H0"
                )
            removed_bytes = 0
            for position in run_positions:
                manifest = self._manifests[position]
                if (
                    manifest.evidence_priority != "routine"
                    or manifest.record_count
                    != manifest.last_source_sequence
                    - manifest.first_source_sequence
                    + 1
                ):
                    raise EvidenceCorrupt(
                        "retention recovery covers protected or sparse evidence"
                    )
                removed_bytes += manifest.segment_size_bytes
                if removed_bytes > MAX_UINT64:
                    raise EvidenceCorrupt(
                        "retention recovery byte sum overflows"
                    )
                if manifest.manifest_sha256 in covered_by:
                    raise EvidenceCorrupt(
                        "authenticated retention recovery runs overlap"
                    )
                covered_by[manifest.manifest_sha256] = (
                    record.ref.source_sequence,
                    request,
                )
            if removed_bytes != request.removed_bytes:
                raise EvidenceCorrupt(
                    "retention recovery removed byte sum differs"
                )
            seen_ids[request.tombstone_id] = (request_raw, outer)
            accepted_by_outer[outer] = request
            record_by_outer[outer] = record
            previous_sequence = record.ref.source_sequence
            previous_end = end
            previous_tip = tip

        try:
            state: RetentionStateV1 | None = (
                None
                if self._retention_state_binding is None
                else decode_retention_state(
                    self._retention_state_binding.raw
                )
            )
        except (RetentionStateCorrupt, TypeError, ValueError) as error:
            raise EvidenceCorrupt(
                "retention recovery state is malformed"
            ) from error
        if (
            state is not None
            and state.operation == "tombstone"
        ):
            self._retention_state_selected_manifests(state)

        current_hashes: frozenset[str] = frozenset()
        current_authenticated = False
        current_target_ref: EvidenceRef | None = None
        if (
            state is not None
            and state.operation == "tombstone"
            and type(state.request) is RetentionTombstoneV2
        ):
            target = state.target
            if target is not None:
                authenticated = accepted_by_outer.get(
                    (
                        target.sequence,
                        target.event_id,
                        target.content_sha256,
                    )
                )
                current_authenticated = authenticated == state.request
                if current_authenticated:
                    current_target_ref = record_by_outer[
                        (
                            target.sequence,
                            target.event_id,
                            target.content_sha256,
                        )
                    ].ref
            if current_authenticated:
                current_hashes = frozenset(
                    state.request.removed_manifest_hashes
                )
            if (
                state.phase
                in {
                    "evidence_appended",
                    "retention_unlink_in_progress",
                    "retention_commit_uncertain",
                    "completed",
                }
                and not current_authenticated
            ):
                raise EvidenceCorrupt(
                    "advanced retention state lacks its authenticated target"
                )
            if (
                state.phase == "target_bound"
                and target is not None
                and target.sequence <= verifier.fsm.last_sequence
                and not current_authenticated
            ):
                raise EvidenceCorrupt(
                    "target-bound retention state conflicts with evidence"
                )

        missing_hashes = {
            item.manifest.manifest_sha256
            for item in self._missing_manifest_payloads
        }
        if not missing_hashes.issubset(covered_by):
            raise EvidenceCorrupt(
                "manifest payload is missing without retention authority"
            )
        if (
            state is not None
            and state.operation == "tombstone"
            and type(state.request) is RetentionTombstoneV2
        ):
            selected_hashes = set(
                state.request.removed_manifest_hashes
            )
            selected_missing = selected_hashes & missing_hashes
            if (
                state.phase
                in {"selected", "target_bound", "evidence_appended"}
                and selected_missing
            ) or (
                state.phase == "completed"
                and selected_missing != selected_hashes
            ):
                raise EvidenceCorrupt(
                    "durable retention phase has an impossible payload set"
                )

        for manifest_hash in covered_by:
            is_missing = manifest_hash in missing_hashes
            is_current = manifest_hash in current_hashes
            if state is None:
                legal = is_missing
            elif is_current:
                if state.phase in {
                    "selected",
                    "target_bound",
                    "evidence_appended",
                }:
                    legal = not is_missing
                elif state.phase in {
                    "retention_unlink_in_progress",
                    "retention_commit_uncertain",
                }:
                    legal = True
                else:
                    legal = is_missing
            else:
                legal = is_missing
            if not legal:
                raise EvidenceCorrupt(
                    "retention state and physical payloads are inconsistent"
                )

        authenticated_omissions = tuple(
            (
                item.manifest.manifest_sha256,
                item.manifest.first_source_sequence,
                item.manifest.last_source_sequence,
                item.manifest.record_count,
            )
            for item in self._missing_manifest_payloads
        )
        authenticated_retired_ranges = tuple(
            (first_sequence, last_sequence)
            for (
                _manifest_sha256,
                first_sequence,
                last_sequence,
                _record_count,
            ) in authenticated_omissions
        )
        verifier._commit_retention_recovery(
            authenticated_omissions,
            self._lifecycle_identity,
        )
        self._authenticated_retired_ranges = (
            authenticated_retired_ranges
        )
        boundary_raw: bytes | None
        if authenticated_tombstones:
            try:
                boundary = RetentionBoundaryV1.model_validate(
                    {
                        "schema_version": "agmind.retention-boundary.v1",
                        "source_evidence_head": verifier.fsm.last_sequence,
                        "tombstones": [
                            {
                                "sequence": record.ref.source_sequence,
                                "event_id": record.ref.event_id,
                                "content_sha256": record.ref.content_sha256,
                                "tombstone_id": request.tombstone_id,
                                "h0": request.current_chain_head_sha256,
                                "first_removed_manifest_sha256": (
                                    request.first_removed_manifest_sha256
                                ),
                                "last_removed_manifest_sha256": (
                                    request.last_removed_manifest_sha256
                                ),
                                "first_retained_manifest_sha256": (
                                    request.first_retained_manifest_sha256
                                ),
                                "removed_manifest_count": len(
                                    request.removed_manifest_hashes
                                ),
                                "removed_bytes": request.removed_bytes,
                                "manifest_run_sha256": (
                                    request.manifest_run_sha256
                                ),
                            }
                            for record, request in authenticated_tombstones
                        ],
                    },
                    strict=True,
                )
                encoded_boundary = canonical_json(
                    boundary.model_dump(mode="python")
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise EvidenceCorrupt(
                    "authenticated retention boundary cannot be rebuilt"
                ) from error
            boundary_raw = (
                encoded_boundary
                if len(encoded_boundary)
                <= MAX_RETENTION_BOUNDARY_BYTES
                else None
            )
        else:
            boundary_raw = None
        return _AuthenticatedRetentionRecovery(
            state=state,
            tombstones=authenticated_tombstones,
            current_target_ref=current_target_ref,
            boundary_raw=boundary_raw,
        )

    def _reconcile_retention_boundary_cache(
        self,
        raw: bytes | None,
    ) -> None:
        boundary_path = self.root / _RETENTION_BOUNDARY_NAME
        descriptor = -1
        try:
            info = _entry_stat_at(
                self._root_descriptor,
                _RETENTION_BOUNDARY_NAME,
            )
            identity: _FileIdentity | None = None
            current_raw: bytes | None = None
            if info is not None:
                identity = _file_identity(
                    _regular_stat_at(
                        self._root_descriptor,
                        _RETENTION_BOUNDARY_NAME,
                        boundary_path,
                    )
                )
                descriptor, opened = _open_regular_at(
                    self._root_descriptor,
                    _RETENTION_BOUNDARY_NAME,
                    boundary_path,
                )
                _validate_identity(opened, identity, boundary_path)
                if identity.size <= MAX_CONTRACT_FILE_BYTES:
                    current_raw = os.pread(
                        descriptor,
                        identity.size,
                        0,
                    )
                    if len(current_raw) != identity.size:
                        raise EvidenceCorrupt(
                            "retention boundary cache shortened during recovery"
                        )
                    _bind_held_source(
                        self._root_descriptor,
                        _RETENTION_BOUNDARY_NAME,
                        boundary_path,
                        descriptor=descriptor,
                        identity=identity,
                    )

            if raw is None:
                if identity is not None:
                    closing = descriptor
                    descriptor = -1
                    _conditionally_unlink_held_at(
                        self._root_descriptor,
                        _RETENTION_BOUNDARY_NAME,
                        boundary_path,
                        descriptor=closing,
                        identity=identity,
                    )
            elif current_raw != raw:
                existing_descriptor = descriptor
                descriptor = -1
                descriptor, _published_identity = (
                    _publish_retention_boundary_at(
                        self._root_descriptor,
                        _RETENTION_BOUNDARY_NAME,
                        boundary_path,
                        raw,
                        existing_descriptor=existing_descriptor,
                        existing_identity=identity,
                    )
                )
            if descriptor >= 0:
                closing = descriptor
                descriptor = -1
                os.close(closing)

            temporary_names = tuple(
                name
                for name in os.listdir(self._root_descriptor)
                if _RETENTION_BOUNDARY_TEMP_NAME.fullmatch(name)
            )
            if len(temporary_names) > 1:
                raise EvidenceCorrupt(
                    "multiple retention-boundary temporaries appeared"
                )
            for name in temporary_names:
                self._discard_retention_boundary_temporary(name)
        except BaseException as error:
            if descriptor >= 0:
                closing = descriptor
                descriptor = -1
                try:
                    os.close(closing)
                except BaseException as close_error:  # noqa: BLE001
                    error.add_note(
                        "retention recovery cache close failed: "
                        f"{close_error}"
                    )
            raise

    def _clear_recovered_retention_state(
        self,
        journal: object,
    ) -> None:
        from agmind_immune.evidence.retention import RetentionStateJournal

        binding = self._retention_state_binding
        if (
            type(journal) is not RetentionStateJournal
            or binding is None
            or journal._raw != binding.raw
            or journal._state is None
            or self._retention_state_temporary is not None
        ):
            raise EvidenceCorrupt(
                "retention recovery cannot clear inexact durable state"
            )
        journal._prove_publication(binding.raw)
        descriptor, opened = _open_regular_at(
            self._root_descriptor,
            _RETENTION_STATE_NAME,
            self.root / _RETENTION_STATE_NAME,
            maximum=_MAX_RETENTION_STATE_BYTES,
        )
        _validate_identity(
            opened,
            binding.identity,
            self.root / _RETENTION_STATE_NAME,
        )
        _conditionally_unlink_held_at(
            self._root_descriptor,
            _RETENTION_STATE_NAME,
            self.root / _RETENTION_STATE_NAME,
            descriptor=descriptor,
            identity=binding.identity,
        )
        authority = journal._authority
        authority._retention_journal = None
        journal._state = None
        journal._raw = None
        self._retention_state_binding = None
        self._retention_state_authority = None
        self._clear_retention_pending_latch()

    def _retention_state_selected_manifests(
        self,
        state: object,
    ) -> tuple[SegmentManifestV1, ...]:
        from agmind_immune.evidence.retention import (
            RetentionStateEntryV1,
            RetentionStateV1,
        )

        if (
            type(state) is not RetentionStateV1
            or state.operation != "tombstone"
            or type(state.request) is not RetentionTombstoneV2
            or not state.entries
        ):
            raise EvidenceCorrupt(
                "retention state has no exact selected manifest run"
            )
        request = state.request
        positions = {
            manifest.manifest_sha256: index
            for index, manifest in enumerate(self._manifests)
        }
        try:
            run_positions = tuple(
                positions[value]
                for value in request.removed_manifest_hashes
            )
        except KeyError as error:
            raise EvidenceCorrupt(
                "retention state names an unknown manifest"
            ) from error
        h0_positions = {
            hashlib.sha256(
                canonical_json(chain_head_for(manifest))
            ).hexdigest(): index
            for index, manifest in enumerate(self._manifests)
        }
        tip = h0_positions.get(request.current_chain_head_sha256)
        if (
            tip is None
            or not run_positions
            or len(run_positions) != len(state.entries)
            or any(
                right != left + 1
                for left, right in pairwise(run_positions)
            )
            or run_positions[-1] > tip
        ):
            raise EvidenceCorrupt(
                "retention state run is outside its immutable H0"
            )
        manifests = tuple(
            self._manifests[position]
            for position in run_positions
        )
        successor = (
            self._manifests[run_positions[-1] + 1].manifest_sha256
            if run_positions[-1] < tip
            else _ZERO_SHA256
        )
        removed_bytes = 0
        for entry, manifest in zip(
            state.entries,
            manifests,
            strict=True,
        ):
            if (
                type(entry) is not RetentionStateEntryV1
                or manifest.evidence_priority != "routine"
                or manifest.record_count
                != manifest.last_source_sequence
                - manifest.first_source_sequence
                + 1
                or entry.manifest_sha256 != manifest.manifest_sha256
                or entry.segment_id != manifest.segment_id
                or entry.segment_relative_path
                != manifest.segment_relative_path
                or entry.segment_size_bytes
                != manifest.segment_size_bytes
                or entry.segment_sha256 != manifest.segment_sha256
            ):
                raise EvidenceCorrupt(
                    "retention state entry differs from immutable manifest"
                )
            if removed_bytes > MAX_UINT64 - manifest.segment_size_bytes:
                raise EvidenceCorrupt(
                    "retention state removed byte sum overflows"
                )
            removed_bytes += manifest.segment_size_bytes
        hashes = [manifest.manifest_sha256 for manifest in manifests]
        if (
            request.first_removed_manifest_sha256 != hashes[0]
            or request.last_removed_manifest_sha256 != hashes[-1]
            or request.first_retained_manifest_sha256 != successor
            or request.removed_bytes != removed_bytes
            or request.manifest_run_sha256
            != hashlib.sha256(
                b"AGMIND_RETENTION_RUN_V2\x00"
                + canonical_json(hashes)
            ).hexdigest()
        ):
            raise EvidenceCorrupt(
                "retention state request differs from immutable manifest run"
            )
        return manifests

    def _retention_selected_max_sequence(
        self,
        state: object,
    ) -> int:
        manifests = self._retention_state_selected_manifests(state)
        return max(
            manifest.last_source_sequence
            for manifest in manifests
        )

    def _merge_authenticated_retired_ranges(
        self,
        manifests: tuple[SegmentManifestV1, ...],
    ) -> None:
        intervals = sorted(
            [
                (start, end)
                for start, end in self._authenticated_retired_ranges
            ]
            + [
                (
                    manifest.first_source_sequence,
                    manifest.last_source_sequence,
                )
                for manifest in manifests
            ]
        )
        merged: list[tuple[int, int]] = []
        for start, end in intervals:
            if (
                type(start) is not int
                or type(end) is not int
                or not 1 <= start <= end <= MAX_UINT64
            ):
                raise EvidenceCorrupt(
                    "authenticated retired range is invalid"
                )
            if not merged or start > merged[-1][1] + 1:
                merged.append((start, end))
            else:
                merged[-1] = (
                    merged[-1][0],
                    max(merged[-1][1], end),
                )
        self._authenticated_retired_ranges = tuple(merged)

    def _retire_authenticated_retention_records(
        self,
        state: object,
    ) -> None:
        manifests = self._retention_state_selected_manifests(state)
        verifier = self._bound_verifier
        if (
            verifier is None
            or self._authority_state not in {"ready", "recovering"}
        ):
            raise EvidenceCorrupt(
                "retention record retirement has no authenticated verifier"
            )
        recovering = self._authority_state == "recovering"
        selected_sequences: set[int] = set()
        for manifest in manifests:
            manifest_records = tuple(
                record
                for record in self._records
                if (
                    record.envelope["host_id"] == manifest.host_id
                    and manifest.first_source_sequence
                    <= record.ref.source_sequence
                    <= manifest.last_source_sequence
                )
            )
            replay_records = self._manifest_replay_records.get(
                manifest.manifest_sha256
            )
            expected_count = (
                0
                if recovering and replay_records is None
                else manifest.record_count
            )
            if len(manifest_records) != expected_count:
                raise EvidenceCorrupt(
                    "retention record retirement lost manifest records"
                )
            records_by_sequence = {
                record.ref.source_sequence: record
                for record in manifest_records
            }
            if len(records_by_sequence) != len(manifest_records):
                raise EvidenceCorrupt(
                    "retention record retirement found duplicate evidence"
                )
            for sequence in range(
                manifest.first_source_sequence,
                manifest.last_source_sequence + 1,
            ):
                selected_sequences.add(sequence)
                record = records_by_sequence.get(sequence)
                accepted_ref = verifier.accepted_ref(sequence)
                if record is None:
                    if accepted_ref is not None:
                        raise EvidenceCorrupt(
                            "retired omission retained verifier authority"
                        )
                    continue
                indexed = self._index.get((manifest.host_id, sequence))
                if (
                    record.priority is not EvidencePriority.ROUTINE
                    or indexed is None
                    or indexed[1] is not record.ref
                    or accepted_ref is not record.ref
                ):
                    raise EvidenceCorrupt(
                        "retention record retirement found protected evidence"
                    )
            self._manifest_replay_records[manifest.manifest_sha256] = None

        authority = verifier._authority
        accepted = {
            sequence: value
            for sequence, value in authority.accepted.items()
            if not any(
                manifest.first_source_sequence
                <= sequence
                <= manifest.last_source_sequence
                for manifest in manifests
            )
        }
        verifier._authority = replace(
            authority,
            accepted=MappingProxyType(accepted),
        )
        remaining = [
            record
            for record in self._records
            if not (
                record.envelope["host_id"] == verifier.fsm.host_id
                and record.ref.source_sequence in selected_sequences
            )
        ]
        self._records = []
        self._index = {}
        self._record_positions = {}
        self._sequences_by_host = {}
        self._last_sequence_by_host = {}
        self._add_records(remaining)
        self._merge_authenticated_retired_ranges(manifests)

    def _prepare_recovered_retention_payloads(
        self,
        state: object,
    ) -> tuple[
        tuple[_HeldRetentionPayload, ...],
        tuple[tuple[str, int], ...],
    ]:
        from agmind_immune.evidence.retention import (
            RetentionStateEntryV1,
            RetentionStateV1,
        )

        if (
            type(state) is not RetentionStateV1
            or state.operation != "tombstone"
            or type(state.request) is not RetentionTombstoneV2
            or not state.entries
        ):
            raise EvidenceCorrupt(
                "retention recovery unlink state is not exact"
            )
        manifests = {
            manifest.manifest_sha256: manifest
            for manifest in self._manifests
        }
        held: list[_HeldRetentionPayload] = []
        directories: dict[str, int] = {}
        opened: list[int] = []
        try:
            self._require_retention_directory_bindings()
            for entry in state.entries:
                if type(entry) is not RetentionStateEntryV1:
                    raise EvidenceCorrupt(
                        "retention recovery state entry is inexact"
                    )
                manifest = manifests.get(entry.manifest_sha256)
                if (
                    manifest is None
                    or manifest.segment_id != entry.segment_id
                    or manifest.segment_relative_path
                    != entry.segment_relative_path
                    or manifest.segment_size_bytes
                    != entry.segment_size_bytes
                    or manifest.segment_sha256
                    != entry.segment_sha256
                    or manifest.evidence_priority != "routine"
                    or manifest.record_count
                    != manifest.last_source_sequence
                    - manifest.first_source_sequence
                    + 1
                ):
                    raise EvidenceCorrupt(
                        "retention recovery entry differs from its manifest"
                    )
                _, date_name, basename = (
                    manifest.segment_relative_path.split("/")
                )
                directory_descriptor = self._date_descriptor(date_name)
                directories[date_name] = directory_descriptor
                if (
                    _entry_stat_at(
                        directory_descriptor,
                        basename,
                    )
                    is None
                ):
                    continue
                display_path = self.root / manifest.segment_relative_path
                descriptor, opened_stat = _open_regular_at(
                    directory_descriptor,
                    basename,
                    display_path,
                    maximum=MAX_SEGMENT_BYTES,
                )
                opened.append(descriptor)
                identity = _file_identity(opened_stat)
                if (
                    identity.device != entry.original_device
                    or identity.inode != entry.original_inode
                    or identity.size != entry.segment_size_bytes
                ):
                    raise EvidenceCorrupt(
                        "retention recovery payload identity changed"
                    )
                scan = self._scan_held_segment_descriptor(
                    descriptor,
                    identity,
                    display_path,
                    allow_torn=False,
                )
                validated = self._validate_segment_scan_against_manifest(
                    scan,
                    basename,
                    display_path,
                    manifest,
                )
                for record in validated.records:
                    try:
                        envelope = EventEnvelopeV1.model_validate_json(
                            record.canonical_envelope,
                            strict=True,
                        )
                    except (TypeError, ValueError, ValidationError) as error:
                        raise EvidenceCorrupt(
                            "retention recovery payload record is malformed"
                        ) from error
                    if (
                        record.priority is not EvidencePriority.ROUTINE
                        or envelope.event_type != "falco_connect"
                    ):
                        raise EvidenceCorrupt(
                            "retention recovery payload is not removable evidence"
                        )
                held.append(
                    _HeldRetentionPayload(
                        state_entry=entry,
                        manifest=manifest,
                        date_name=date_name,
                        basename=basename,
                        display_path=display_path,
                        descriptor=descriptor,
                        identity=identity,
                    )
                )
            self._require_retention_directory_bindings()
            return (
                tuple(held),
                tuple(sorted(directories.items())),
            )
        except BaseException as error:
            for descriptor in reversed(opened):
                try:
                    os.close(descriptor)
                except BaseException as close_error:  # noqa: BLE001
                    error.add_note(
                        "retention recovery payload close failed: "
                        f"{close_error}"
                    )
            raise

    @staticmethod
    def _close_recovered_retention_payloads(
        payloads: tuple[_HeldRetentionPayload, ...],
    ) -> None:
        close_errors: list[OSError] = []
        for payload in payloads:
            if payload.descriptor >= 0:
                descriptor = payload.descriptor
                payload.descriptor = -1
                try:
                    os.close(descriptor)
                except OSError as error:
                    close_errors.append(error)
        if close_errors:
            primary = EvidenceCorrupt(
                "retention recovery payload cleanup is uncertain"
            )
            for secondary in close_errors[1:]:
                primary.add_note(
                    "secondary retention payload close failure: "
                    f"{secondary}"
                )
            raise primary from close_errors[0]

    def _resume_recovered_retention_unlink(
        self,
        journal: object,
        ack_journal: object,
    ) -> None:
        from agmind_immune.evidence.retention import (
            RetentionStateJournal,
            RetentionStateV1,
            _derived_retention_state,
            _retention_execution_states,
        )

        if type(journal) is not RetentionStateJournal:
            raise EvidenceCorrupt(
                "retention recovery has no exact state journal"
            )
        state = journal.state
        if (
            type(state) is not RetentionStateV1
            or state.operation != "tombstone"
            or state.target is None
            or state.phase
            not in {
                "evidence_appended",
                "retention_unlink_in_progress",
                "retention_commit_uncertain",
            }
        ):
            raise EvidenceCorrupt(
                "retention recovery phase cannot resume unlink"
            )
        target = state.target
        payloads, directories = (
            self._prepare_recovered_retention_payloads(state)
        )
        present_paths = {
            payload.manifest.segment_relative_path
            for payload in payloads
        }
        all_paths = {
            entry.segment_relative_path
            for entry in state.entries
        }
        if (
            len(all_paths) != len(state.entries)
            or (
                state.phase == "evidence_appended"
                and present_paths != all_paths
            )
        ):
            self._close_recovered_retention_payloads(payloads)
            raise EvidenceCorrupt(
                "retention recovery phase has an impossible payload set"
            )

        unlink_started = False
        ack_boundary_lease: _AckRetentionBoundaryLease | None = None
        primary_error: BaseException | None = None
        try:
            selected_max_sequence = (
                self._retention_selected_max_sequence(state)
            )
            if selected_max_sequence >= MAX_UINT64:
                raise EvidenceCorrupt(
                    "retention recovery has no surviving ACK position"
                )
            ack_boundary_lease = self._acquire_retention_ack_boundary(
                ack_journal,
                confirmed_through=selected_max_sequence + 1,
            )
            if state.phase == "evidence_appended":
                in_progress, _uncertain, _completed = (
                    _retention_execution_states(state)
                )
                journal._transition(in_progress)
                state = in_progress
            for payload in payloads:
                self._require_retention_directory_bindings()
                _bind_held_source(
                    self._date_descriptor(payload.date_name),
                    payload.basename,
                    payload.display_path,
                    descriptor=payload.descriptor,
                    identity=payload.identity,
                )
            for payload in payloads:
                self._require_retention_directory_bindings()
                directory_descriptor = self._date_descriptor(
                    payload.date_name
                )
                _bind_held_source(
                    directory_descriptor,
                    payload.basename,
                    payload.display_path,
                    descriptor=payload.descriptor,
                    identity=payload.identity,
                )
                unlink_started = True
                os.unlink(
                    payload.basename,
                    dir_fd=directory_descriptor,
                )
                if (
                    _entry_stat_at(
                        directory_descriptor,
                        payload.basename,
                    )
                    is not None
                    or os.fstat(payload.descriptor).st_nlink != 0
                ):
                    raise EvidenceCorrupt(
                        "retention recovery payload unlink is uncertain"
                    )
                self._require_retention_directory_bindings()
            for _date_name, descriptor in directories:
                self._require_retention_directory_bindings()
                os.fsync(descriptor)
                self._require_retention_directory_bindings()
            self._require_retention_directory_bindings()
            for entry in state.entries:
                _, date_name, basename = (
                    entry.segment_relative_path.split("/")
                )
                if (
                    _entry_stat_at(
                        self._date_descriptor(date_name),
                        basename,
                    )
                    is not None
                ):
                    raise EvidenceCorrupt(
                        "retention recovery selected payload survived unlink"
                    )
            self._require_retention_directory_bindings()
            self._retire_authenticated_retention_records(state)
            completed = _derived_retention_state(
                state,
                phase="completed",
                target=target,
            )
            journal._transition(completed)
            self._require_retention_directory_bindings()
        except BaseException as error:
            primary_error = error
            if unlink_started:
                try:
                    current = journal.state
                    if (
                        type(current) is RetentionStateV1
                        and current.phase
                        == "retention_unlink_in_progress"
                        and current.target is not None
                    ):
                        journal._transition(
                            _derived_retention_state(
                                current,
                                phase="retention_commit_uncertain",
                                target=current.target,
                            )
                        )
                except BaseException as persistence_error:  # noqa: BLE001
                    error.add_note(
                        "retention recovery uncertainty persistence failed: "
                        f"{persistence_error}"
                    )
            raise
        finally:
            try:
                if ack_boundary_lease is not None:
                    try:
                        self._release_retention_ack_boundary(
                            ack_journal,
                            ack_boundary_lease,
                        )
                    except BaseException as cleanup_error:
                        if primary_error is None:
                            raise
                        primary_error.add_note(
                            "retention recovery ACK-boundary release failed: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
            finally:
                try:
                    self._close_recovered_retention_payloads(payloads)
                except BaseException as cleanup_error:
                    if primary_error is None:
                        raise
                    primary_error.add_note(
                        "retention recovery payload cleanup failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )

    def _reconcile_authenticated_retention_recovery(
        self,
        recovery: _AuthenticatedRetentionRecovery,
        ack_journal: object | None,
    ) -> None:
        from agmind_immune.evidence.retention import (
            RetentionStateJournal,
            RetentionStateV1,
            _open_retention_state_journal,
        )

        temporary = self._retention_state_temporary
        if temporary is not None:
            self._discard_retention_state_temporary(temporary)

        state = recovery.state
        if state is None:
            self._reconcile_retention_boundary_cache(
                recovery.boundary_raw
            )
            return
        if type(state) is not RetentionStateV1:
            raise EvidenceCorrupt(
                "authenticated retention recovery state type changed"
            )
        journal = _open_retention_state_journal(self)
        if (
            type(journal) is not RetentionStateJournal
            or journal.state != state
        ):
            raise EvidenceCorrupt(
                "retention recovery journal changed after authentication"
            )
        if state.operation != "tombstone":
            self._reconcile_retention_boundary_cache(
                recovery.boundary_raw
            )
            return

        if state.phase == "target_bound":
            target = state.target
            if (
                target is not None
                and recovery.current_target_ref is not None
            ):
                journal.advance_evidence_appended(target)
                state = journal.state
                if type(state) is not RetentionStateV1:
                    raise EvidenceCorrupt(
                        "retention recovery lost advanced state"
                    )
        if state.phase in {
            "retention_unlink_in_progress",
            "retention_commit_uncertain",
        }:
            self._resume_recovered_retention_unlink(
                journal,
                ack_journal,
            )
            state = journal.state
            if type(state) is not RetentionStateV1:
                raise EvidenceCorrupt(
                    "retention recovery lost completed state"
                )
        if state.phase == "completed":
            self._require_retention_directory_bindings()
            self._reconcile_retention_boundary_cache(
                recovery.boundary_raw
            )
            state_binding = self._retention_state_binding
            if state_binding is None:
                raise EvidenceCorrupt(
                    "completed retention recovery lost durable state"
                )
            self._projection_reconciliation_completed_state_raw = (
                state_binding.raw
            )
            self._clear_recovered_retention_state(journal)
            self._require_retention_directory_bindings()
        elif state.phase in {
            "selected",
            "target_bound",
            "evidence_appended",
        }:
            payloads, _directories = (
                self._prepare_recovered_retention_payloads(state)
            )
            try:
                if len(payloads) != len(state.entries):
                    raise EvidenceCorrupt(
                        "pre-target retention state has an absent payload"
                    )
            finally:
                self._close_recovered_retention_payloads(payloads)
            self._reconcile_retention_boundary_cache(
                recovery.boundary_raw
            )
        else:
            raise EvidenceCorrupt(
                "retention recovery ended in an impossible phase"
            )

    def _retention_recovery_needs_ack(
        self,
        recovery: _AuthenticatedRetentionRecovery,
    ) -> bool:
        from agmind_immune.evidence.retention import RetentionStateV1

        if self._authenticated_retired_ranges:
            return True
        state = recovery.state
        return (
            type(state) is RetentionStateV1
            and state.operation == "tombstone"
            and (
                state.phase
                in {
                    "retention_unlink_in_progress",
                    "retention_commit_uncertain",
                    "completed",
                }
            )
        )

    def _bind_and_recover(self, verifier: EnvelopeVerifier) -> None:
        if self._closed:
            raise EvidenceStoreError("evidence store is closed")
        if self._bound_verifier is not None or self._authority_state != "unbound":
            raise EvidenceSealError("evidence store already has verifier authority")
        try:
            verifier._bind_lifecycle(self._lifecycle_identity)
            verifier._begin_retention_recovery(
                self._lifecycle_identity
            )
        except VerifierCommitError as error:
            raise EvidenceSealError("verifier belongs to another store lifecycle") from error
        self._bound_verifier = verifier
        self._authority_state = "recovering"
        retention_ack_journal: object | None = None
        recovery_error: BaseException | None = None
        try:
            try:
                self._replay_manifest_chain(verifier)
                retention_recovery = (
                    self._authenticate_retention_recovery(verifier)
                )
                if self._retention_recovery_needs_ack(
                    retention_recovery
                ):
                    retention_ack_journal = (
                        self._open_retention_ack_recovery()
                    )
                self._reconcile_authenticated_retention_recovery(
                    retention_recovery,
                    retention_ack_journal,
                )
            except BaseException as error:
                recovery_error = error
                raise
            finally:
                if retention_ack_journal is not None:
                    try:
                        self._close_retention_ack_recovery(
                            retention_ack_journal
                        )
                    except BaseException as close_error:
                        if recovery_error is None:
                            raise
                        recovery_error.add_note(
                            "secondary retention ACK recovery close failure: "
                            f"{type(close_error).__name__}: {close_error}"
                        )
            self._require_retention_directory_bindings()
        except (
            EvidenceCorrupt,
            IngestVerificationError,
            VerifierCommitError,
        ) as error:
            try:
                self._trip_read_only("segment_corrupt")
            except BaseException as fence_error:  # noqa: BLE001
                error.add_note(
                    "secondary retention recovery fence failure: "
                    f"{type(fence_error).__name__}: {fence_error}"
                )
            raise
        except Exception as error:
            wrapped = EvidenceCorrupt(
                "authenticated retention recovery failed"
            )
            try:
                self._trip_read_only("segment_corrupt")
            except BaseException as fence_error:  # noqa: BLE001
                wrapped.add_note(
                    "secondary retention recovery fence failure: "
                    f"{type(fence_error).__name__}: {fence_error}"
                )
            raise wrapped from error
        except BaseException as error:
            try:
                self._trip_read_only("segment_corrupt")
            except BaseException as fence_error:  # noqa: BLE001
                error.add_note(
                    "secondary retention recovery fence failure: "
                    f"{type(fence_error).__name__}: {fence_error}"
                )
            raise
        self._authority_state = "ready"

    def append(
        self,
        envelope: VerifiedEnvelope,
        priority: EvidencePriority,
    ) -> EvidenceRef:
        if self._closed:
            raise EvidenceStoreError("evidence store is closed")
        verifier = self._bound_verifier
        if verifier is None or self._authority_state != "ready":
            raise EvidenceSealError(
                "append requires one factory-bound recovered verifier lifecycle"
            )
        if self._repair_pretruncate:
            raise EvidenceReadOnly(
                "evidence append is disabled before authorized tail truncation"
            )
        if self._repair_prefix_needs_settlement:
            raise EvidenceReadOnly(
                "repaired prefix must be explicitly settled before evidence append"
            )
        if self._read_only_reason is not None:
            raise EvidenceReadOnly(
                f"evidence root is read-only: {self._read_only_reason}"
            )
        if self._append_uncertain:
            raise EvidenceReadOnly("prior evidence append has uncertain durability")
        if not isinstance(priority, EvidencePriority):
            raise EvidenceSealError("evidence priority must be verifier-derived")
        pending = self._pending_durable_commit
        if pending is not None:
            presented = (
                getattr(envelope, "canonical", None),
                getattr(envelope, "content_sha256", None),
                getattr(envelope, "event_id", None),
                getattr(envelope, "evidence_priority", None),
                getattr(envelope, "source_sequence", None),
                priority.value,
            )
            expected = (
                pending.canonical,
                pending.content_sha256,
                pending.event_id,
                pending.evidence_priority,
                pending.source_sequence,
                pending.evidence_priority,
            )
            if presented != expected:
                raise EvidenceReadOnly(
                    "exact durable verifier commit must be repaired before append"
                )
            try:
                authorization = verifier._authorize_append(
                    envelope,
                    self._lifecycle_identity,
                    priority.value,
                )
            except (AttributeError, TypeError, VerifierCommitError) as error:
                raise EvidenceSealError(
                    "pending commit requires one exact verifier-staged envelope"
                ) from error
            if (
                authorization.canonical != pending.canonical
                or authorization.content_sha256 != pending.content_sha256
                or authorization.event_id != pending.event_id
                or authorization.evidence_priority != pending.evidence_priority
                or authorization.host_id != pending.host_id
                or authorization.source_sequence != pending.source_sequence
                or self._index.get((pending.host_id, pending.source_sequence))
                != (pending.canonical, pending.ref)
            ):
                raise EvidenceReadOnly(
                    "pending durable commit no longer matches exact stored facts"
                )
            verifier._commit_durable(
                authorization,
                self._lifecycle_identity,
                pending.ref,
            )
            self._pending_durable_commit = None
            return pending.ref
        try:
            authorization = verifier._authorize_append(
                envelope,
                self._lifecycle_identity,
                priority.value,
            )
        except (AttributeError, TypeError, VerifierCommitError) as error:
            raise EvidenceSealError(
                "SegmentStore accepts one exact verifier-staged envelope only"
            ) from error
        if self.fail_next_append is not None:
            failure = self.fail_next_append
            self.fail_next_append = None
            raise failure
        host_id = authorization.host_id
        key = (host_id, authorization.source_sequence)
        prior = self._index.get(key)
        if prior is not None:
            if prior[0] == authorization.canonical:
                verifier._commit_durable(
                    authorization,
                    self._lifecycle_identity,
                    prior[1],
                )
                return prior[1]
            self._trip_read_only("segment_corrupt")
            raise EvidenceConflict("different canonical evidence reused a host sequence")
        if authorization.source_sequence <= self._last_sequence_by_host.get(host_id, 0):
            self._trip_read_only("segment_corrupt")
            raise EvidenceConflict("sealed evidence is not in host-global sequence order")
        try:
            envelope_value = EventEnvelopeV1.model_validate_json(
                authorization.canonical,
                strict=True,
            )
        except ValidationError as error:
            raise EvidenceSealError("authorized canonical envelope no longer decodes") from error
        accepted_at = _utc_timestamp(self._wall_clock())
        payload = canonical_json(
            {
                "schema_version": "agmind.accepted-envelope.v1",
                "evidence_priority": priority.value,
                "accepted_at": accepted_at,
                "outer": {
                    "sequence": authorization.source_sequence,
                    "event_id": authorization.event_id,
                    "content_sha256": authorization.content_sha256,
                },
                "envelope": envelope_value.model_dump(exclude_none=True),
            }
        )
        if len(payload) > MAX_EVIDENCE_RECORD_BYTES:
            raise EvidenceStoreError("canonical evidence record exceeds frame bound")
        if self._must_rotate(authorization, priority, len(payload)):
            self.flush_security_boundary()
        if self._active is None:
            try:
                active, frame = self._create_active_with_first_frame(
                    authorization,
                    priority,
                    accepted_at,
                    payload,
                )
            except EvidenceCorrupt:
                self._trip_read_only("segment_corrupt")
                raise
            offset = 0
        else:
            active = self._active
            frame = encode_frame(
                payload,
                previous_hash=active.previous_frame_hash,
                max_frame=MAX_EVIDENCE_RECORD_BYTES,
            )
            offset = active.size
            try:
                _full_write(active.descriptor, frame)
                os.fsync(active.descriptor)
            except BaseException:
                self._append_uncertain = True
                os.close(active.descriptor)
                active.descriptor = -1
                raise
            active.size += len(frame)
            active.record_count += 1
            active.previous_frame_hash = frame[-32:]
        ref = EvidenceRef(
            segment_id=active.segment_id,
            segment_relative_path=active.closed_relative_path,
            frame_offset=offset,
            frame_size=len(frame),
            frame_sha256=frame[-32:].hex(),
            event_id=authorization.event_id,
            source_sequence=authorization.source_sequence,
            content_sha256=authorization.content_sha256,
        )
        record = StoredEvidenceRecord(
            envelope=envelope_value.model_dump(exclude_none=True),
            canonical_envelope=authorization.canonical,
            priority=priority,
            accepted_at=accepted_at,
            ref=ref,
        )
        self._record_positions[key] = len(self._records)
        self._sequences_by_host.setdefault(host_id, []).append(
            authorization.source_sequence
        )
        self._index[key] = (authorization.canonical, ref)
        self._last_sequence_by_host[host_id] = authorization.source_sequence
        self._records.append(record)
        self._pending_durable_commit = _PendingDurableCommit(
            canonical=authorization.canonical,
            content_sha256=authorization.content_sha256,
            event_id=authorization.event_id,
            evidence_priority=authorization.evidence_priority,
            host_id=authorization.host_id,
            source_sequence=authorization.source_sequence,
            ref=ref,
        )
        verifier._commit_durable(
            authorization,
            self._lifecycle_identity,
            ref,
        )
        self._pending_durable_commit = None
        return ref

    def _must_rotate(
        self,
        envelope: _AppendAuthorization,
        priority: EvidencePriority,
        payload_size: int,
    ) -> bool:
        active = self._active
        if active is None:
            return False
        projected_frame = payload_size + 76
        return (
            active.priority != priority
            or active.host_id != envelope.host_id
            or active.size + projected_frame > MAX_SEGMENT_BYTES
            or self._monotonic() - active.opened_monotonic >= MAX_SEGMENT_AGE_SECONDS
        )

    def _create_active_with_first_frame(
        self,
        envelope: _AppendAuthorization,
        priority: EvidencePriority,
        accepted_at: str,
        payload: bytes,
    ) -> tuple[_ActiveSegment, bytes]:
        opened_at = datetime.fromisoformat(accepted_at)
        date_name = opened_at.date().isoformat()
        date_path = self._segments_path / date_name
        date_descriptor = self._date_descriptor(date_name, create=True)
        segment_id = str(uuid.uuid4())
        basename = f"{envelope.source_sequence:020d}-{segment_id}"
        open_name = f"{basename}.open"
        closed_name = f"{basename}.agseg"
        temporary_name = (
            f".agmind-create-{envelope.source_sequence:020d}-{segment_id}.tmp"
        )
        open_path = date_path / open_name
        frame = encode_frame(
            payload,
            previous_hash=bytes(32),
            max_frame=MAX_EVIDENCE_RECORD_BYTES,
        )
        frame_sha256 = hashlib.sha256(frame).hexdigest()
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_APPEND
            | os.O_CLOEXEC
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        published = False
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=date_descriptor,
            )
            self._segment_create_step_hook("create")
            os.fchmod(descriptor, 0o600)
            _full_write(descriptor, frame)
            self._segment_create_step_hook("write")
            os.fsync(descriptor)
            self._segment_create_step_hook("file_fsync")
            self._segment_create_step_hook("before_publish")
            identity = _file_identity(os.fstat(descriptor))
            with _post_authentication_namespace(open_path):
                _bind_held_source(
                    date_descriptor,
                    temporary_name,
                    open_path,
                    descriptor=descriptor,
                    identity=identity,
                )
                _rename_noreplace(
                    temporary_name,
                    open_name,
                    source_dir_fd=date_descriptor,
                    destination_dir_fd=date_descriptor,
                )
            published = True
            self._segment_create_step_hook("publish")
            with _post_authentication_namespace(open_path):
                _validate_published_from_held(
                    date_descriptor,
                    open_name,
                    open_path,
                    descriptor=descriptor,
                    identity=identity,
                    expected_sha256=frame_sha256,
                )
                os.fsync(date_descriptor)
        except BaseException:
            _cleanup_private_publication(
                date_descriptor,
                None if published else temporary_name,
                open_path,
                descriptor=descriptor,
                preserve_primary=True,
            )
            if published:
                self._append_uncertain = True
            raise
        closed_relative = f"segments/{date_name}/{closed_name}"
        active = _ActiveSegment(
            segment_id=segment_id,
            open_path=open_path,
            open_name=open_name,
            closed_name=closed_name,
            closed_relative_path=closed_relative,
            directory_descriptor=date_descriptor,
            priority=priority,
            host_id=envelope.host_id,
            first_source_sequence=envelope.source_sequence,
            opened_at=accepted_at,
            opened_monotonic=self._monotonic(),
            descriptor=descriptor,
            size=len(frame),
            record_count=1,
            previous_frame_hash=frame[-32:],
        )
        self._active = active
        return active, frame

    def flush_security_boundary(self) -> None:
        if (
            self._authority_state == "retention_uncertain"
            or self._retention_commit_uncertain_latched
        ):
            raise EvidenceReadOnly(
                "retention unlink is uncertain until restart recovery"
            )
        if self._read_only_reason is not None:
            raise EvidenceReadOnly(
                f"evidence root is read-only: {self._read_only_reason}"
            )
        if self._pending_durable_commit is not None:
            raise EvidenceReadOnly(
                "pending durable verifier commit must be repaired before flush"
            )
        active = self._active
        if active is None:
            return
        if self._append_uncertain or active.descriptor < 0:
            raise EvidenceReadOnly("uncertain active tail cannot be settled automatically")
        if active.record_count == 0:
            raise EvidenceStoreError("cannot settle an empty active segment")
        os.fsync(active.descriptor)
        os.close(active.descriptor)
        active.descriptor = -1
        try:
            scan = self._read_segment(
                active.directory_descriptor,
                active.open_name,
                active.open_path,
                allow_torn=False,
            )
            records = list(scan.records)
            frames = list(scan.frames)
            if (
                scan.torn_verified is not None
                or not records
                or not frames
                or len(records) != active.record_count
                or scan.size != active.size
                or frames[-1].record_hash != active.previous_frame_hash
                or records[0].ref.source_sequence != active.first_source_sequence
                or {record.priority for record in records} != {active.priority}
                or {str(record.envelope["host_id"]) for record in records}
                != {active.host_id}
            ):
                raise EvidenceCorrupt("active segment facts changed before close")
        except (EvidenceCorrupt, JournalCorrupt, OSError, ValidationError, ValueError):
            self._trip_read_only("segment_corrupt")
            raise
        closed_at = _utc_timestamp(self._wall_clock())
        previous_hash = (
            self._manifests[-1].manifest_sha256
            if self._manifests
            else GENESIS_MANIFEST_SHA256
        )
        document: dict[str, object] = {
            "schema_version": "agmind.segment-manifest.v1",
            "segment_id": active.segment_id,
            "segment_relative_path": active.closed_relative_path,
            "host_id": active.host_id,
            "evidence_priority": active.priority.value,
            "first_event_id": records[0].ref.event_id,
            "last_event_id": records[-1].ref.event_id,
            "first_source_sequence": records[0].ref.source_sequence,
            "last_source_sequence": records[-1].ref.source_sequence,
            "record_count": len(records),
            "opened_at": active.opened_at,
            "closed_at": closed_at,
            "segment_size_bytes": scan.size,
            "segment_sha256": scan.sha256,
            "first_frame_sha256": frames[0].record_hash.hex(),
            "last_frame_sha256": frames[-1].record_hash.hex(),
            "previous_manifest_sha256": previous_hash,
        }
        document["manifest_sha256"] = segment_manifest_hash(document)
        manifest = SegmentManifestV1.model_validate(document, strict=True)
        manifest_name = f"{active.segment_id}.json"
        manifest_path = self._manifests_path / manifest_name
        try:
            _publish_without_replacement_at(
                self._manifests_descriptor,
                manifest_name,
                manifest_path,
                canonical_json(manifest),
            )
            _promote_authenticated_source(
                active.directory_descriptor,
                active.open_name,
                active.closed_name,
                self.root / active.closed_relative_path,
                identity=scan.identity,
                expected_sha256=scan.sha256,
            )
        except FileExistsError as error:
            self._trip_read_only("segment_corrupt")
            raise EvidenceCorrupt(
                "immutable close destination already exists"
            ) from error
        except EvidenceCorrupt:
            self._trip_read_only("segment_corrupt")
            raise
        head = chain_head_for(manifest)
        try:
            _atomic_replace_at(
                self._root_descriptor,
                "chain-head.json",
                self.root / "chain-head.json",
                canonical_json(head),
            )
        except EvidenceCorrupt:
            self._trip_read_only("segment_corrupt")
            raise
        self._manifests.append(manifest)
        self._chain_head = head
        self._active = None
        self._repair_prefix_needs_settlement = False

    def iter_records(self) -> Iterator[StoredEvidenceRecord]:
        for record in tuple(self._records):
            yield StoredEvidenceRecord(
                envelope=copy.deepcopy(record.envelope),
                canonical_envelope=record.canonical_envelope,
                priority=record.priority,
                accepted_at=record.accepted_at,
                ref=record.ref,
            )

    def close(self, *, flush: bool = True) -> None:
        if self._closed:
            return
        try:
            if (
                flush
                and self._active is not None
                and self._read_only_reason is None
                and not self._append_uncertain
                and self._pending_durable_commit is None
                and not self._repair_pending
            ):
                self.flush_security_boundary()
            elif self._active is not None and self._active.descriptor >= 0:
                os.close(self._active.descriptor)
                self._active.descriptor = -1
        finally:
            try:
                try:
                    coverage_close_error: BaseException | None = None
                    coverage_owner = self._coverage_state_owner
                    if coverage_owner is not None:
                        try:
                            close_from_store = getattr(
                                coverage_owner,
                                "_close_from_segment_store",
                                None,
                            )
                            if not callable(close_from_store):
                                raise EvidenceStoreError(
                                    "coverage-state owner cannot close "
                                    "before evidence unlock"
                                )
                            cast(Callable[[object], None], close_from_store)(
                                self._lifecycle_identity
                            )
                        except BaseException as error:  # noqa: BLE001
                            coverage_close_error = error
                    if self._coverage_state_owner is not None:
                        self._coverage_state_owner = None
                        survivor_error = EvidenceStoreError(
                            "coverage-state owner survived evidence shutdown"
                        )
                        if coverage_close_error is not None:
                            raise survivor_error from coverage_close_error
                        raise survivor_error
                    if coverage_close_error is not None:
                        raise coverage_close_error
                finally:
                    try:
                        correlation_owner = self._correlation_journal_owner
                        if correlation_owner is not None:
                            close_from_store = getattr(
                                correlation_owner,
                                "_close_from_segment_store",
                                None,
                            )
                            if not callable(close_from_store):
                                raise EvidenceStoreError(
                                    "correlation-journal owner cannot close "
                                    "before evidence unlock"
                                )
                            cast(Callable[[object], None], close_from_store)(
                                self._lifecycle_identity
                            )
                        if self._correlation_journal_owner is not None:
                            raise EvidenceStoreError(
                                "correlation-journal owner survived evidence shutdown"
                            )
                        self._fence_missing_expected_correlation_journal()
                    finally:
                        owner = self._ack_journal_owner
                        if owner is not None:
                            close_from_store = getattr(
                                owner,
                                "_close_from_segment_store",
                                None,
                            )
                            if not callable(close_from_store):
                                raise EvidenceStoreError(
                                    "ACK-journal owner cannot close before evidence unlock"
                                )
                            cast(Callable[[object], None], close_from_store)(
                                self._lifecycle_identity
                            )
                        if self._ack_journal_owner is not None:
                            raise EvidenceStoreError(
                                "ACK-journal owner survived evidence shutdown"
                            )
                        self._fence_missing_expected_ack_journal()
            finally:
                for repair_target in (
                    self._repair_target,
                    self._repair_post_h0_active,
                ):
                    if repair_target is not None and repair_target.descriptor >= 0:
                        os.close(repair_target.descriptor)
                self._repair_target = None
                self._repair_post_h0_active = None
                for descriptor in self._date_descriptors.values():
                    os.close(descriptor)
                os.close(self._manifests_descriptor)
                os.close(self._segments_descriptor)
                fcntl.flock(self._root_descriptor, fcntl.LOCK_UN)
                os.close(self._root_descriptor)
                self._closed = True


@final
class TailRepairSession(SegmentStore):
    """Pre-truncate, same-lock evidence store with one retained ACK authority."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("TailRepairSession is final")

    def __init__(
        self,
        root: Path,
        verifier: EnvelopeVerifier,
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        health_step_hook: Callable[[str], None] | None = None,
        segment_create_step_hook: Callable[[str], None] | None = None,
    ) -> None:
        if type(verifier) is not EnvelopeVerifier:
            raise TypeError("tail repair requires the exact EnvelopeVerifier")
        self._repair_mode = True
        try:
            super().__init__(
                root,
                wall_clock=wall_clock,
                monotonic_clock=monotonic_clock,
                health_step_hook=health_step_hook,
                segment_create_step_hook=segment_create_step_hook,
            )
            self._bind_and_recover(verifier)
            self._repair_base_verifier_generation = verifier._authority.generation
            from agmind_immune.ingest.ack_journal import AckJournal

            journal = AckJournal.open_and_recover(self)
            self._repair_ack_journal = journal
            self._repair_ack_snapshot = journal.snapshot()
        except BaseException:
            if hasattr(self, "_closed") and not self._closed:
                self.close(flush=False)
            raise


def replace_ref(
    ref: EvidenceRef,
    *,
    segment_id: str,
    segment_relative_path: str,
    frame: FrameRecord,
) -> EvidenceRef:
    return EvidenceRef(
        segment_id=segment_id,
        segment_relative_path=segment_relative_path,
        frame_offset=frame.offset,
        frame_size=frame.size,
        frame_sha256=frame.record_hash.hex(),
        event_id=ref.event_id,
        source_sequence=ref.source_sequence,
        content_sha256=ref.content_sha256,
    )
