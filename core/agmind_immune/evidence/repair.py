"""Crash-safe durable state for signed evidence-tail repair."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING, Any, Literal, Never, Protocol, SupportsIndex, cast, final

from pydantic import Field, ValidationError, field_validator, model_validator

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import (
    EMPTY_SHA256,
    HEX64,
    MAX_EVIDENCE_SEGMENT_BYTES,
    MAX_UINT64,
    UUID4,
    ZERO_SHA256,
    ContractModel,
    EvidenceRepairAuthorizeV1,
    EvidenceRepairCompleteV1,
)

if TYPE_CHECKING:
    from agmind_immune.clock import CoreClockProvider
    from agmind_immune.coverage import CoverageState
    from agmind_immune.evidence.segments import SegmentStore, TailRepairSession
    from agmind_immune.ingest.ack_journal import AckJournal
    from agmind_immune.ingest.envelope import CoreEventV1, EnvelopeVerifier
    from agmind_immune.ingest.service import (
        AcceptanceCoordinator,
        ObserverCoreTransport,
    )

MAX_REPAIR_STATE_BYTES = 4096
MAX_REPAIR_PREFLIGHT_EVENTS = 4096
MAX_REPAIR_PREFLIGHT_PAGES = 64
MAX_REPAIR_PREFLIGHT_RESPONSE_BYTES = 64 * 1024 * 1024
_REPAIR_STATE_JOURNAL_FACTORY = object()
_FINAL_REPAIR_COMPLETION_FACTORY = object()
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_OPEN_RELATIVE_PATH = re.compile(
    r"^segments/(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})/"
    r"(?P<sequence>[0-9]{20})-"
    r"(?P<segment>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.open$"
)

RepairPhase = Literal[
    "detected",
    "authorized",
    "truncated",
    "authorization_appended",
    "completion_appended",
]


class RepairError(RuntimeError):
    """Base class for signed evidence-tail repair failures."""


class RepairStateCorrupt(RepairError):
    """The durable repair gate is malformed, noncanonical, or contradictory."""


class RepairStateConflict(RepairError):
    """The exact durable repair state changed across a CAS boundary."""


class RepairProtocolError(RepairError):
    """The caller requested a transition outside the locked repair protocol."""


class RepairPreflightError(RepairProtocolError):
    """A bounded observer path did not prove one exact signed repair event."""


@dataclass(frozen=True)
class RepairedEvidenceRuntime:
    """Same-lock authorities returned after the repair gate is proven and cleared."""

    store: SegmentStore
    verifier: EnvelopeVerifier
    acceptance: AcceptanceCoordinator
    acknowledgements: AckJournal
    coverage: CoverageState


class RepairEventIdentity(ContractModel):
    """One exact outer observer identity retained in durable repair state."""

    sequence: int = Field(ge=1, le=MAX_UINT64)
    event_id: str
    content_sha256: str

    @field_validator("event_id")
    @classmethod
    def event_id_is_exact(cls, value: str) -> str:
        if _EVENT_ID.fullmatch(value) is None:
            raise ValueError("repair event_id must be exact")
        return value

    @field_validator("content_sha256")
    @classmethod
    def content_hash_is_exact(cls, value: str) -> str:
        if HEX64.fullmatch(value) is None:
            raise ValueError("repair event content_sha256 must be lowercase hex")
        return value


class RepairStateV1(ContractModel):
    """Canonical 4 KiB durable gate; never signature or truncate authority."""

    schema_version: Literal["agmind.evidence-repair-state.v1"]
    phase: RepairPhase
    repair_id: str
    segment_id: str
    open_relative_path: str
    original_device: int = Field(ge=0, le=MAX_UINT64)
    original_inode: int = Field(ge=1, le=MAX_UINT64)
    original_bytes: int = Field(ge=1, le=MAX_EVIDENCE_SEGMENT_BYTES)
    verified_bytes: int = Field(ge=0, le=MAX_EVIDENCE_SEGMENT_BYTES)
    discarded_bytes: int = Field(gt=0, le=MAX_EVIDENCE_SEGMENT_BYTES)
    discarded_sha256: str
    post_repair_prefix_sha256: str
    last_verified_frame_sha256: str
    current_chain_head_sha256: str
    authorization: RepairEventIdentity | None
    completion: RepairEventIdentity | None

    @field_validator("repair_id", "segment_id")
    @classmethod
    def uuid_is_exact(cls, value: str) -> str:
        if UUID4.fullmatch(value) is None:
            raise ValueError("repair identity must be a lowercase UUIDv4")
        return value

    @field_validator(
        "discarded_sha256",
        "post_repair_prefix_sha256",
        "last_verified_frame_sha256",
        "current_chain_head_sha256",
    )
    @classmethod
    def digest_is_exact(cls, value: str) -> str:
        if HEX64.fullmatch(value) is None:
            raise ValueError("repair digest must be 64 lowercase hex")
        return value

    @field_validator("open_relative_path")
    @classmethod
    def path_is_canonical(cls, value: str) -> str:
        match = _OPEN_RELATIVE_PATH.fullmatch(value)
        if match is None:
            raise ValueError("repair open path is not canonical")
        date_text = match.group("date")
        try:
            parsed = date.fromisoformat(date_text)
        except ValueError as error:
            raise ValueError("repair open path date is invalid") from error
        sequence = int(match.group("sequence"))
        if parsed.isoformat() != date_text or not 1 <= sequence <= MAX_UINT64:
            raise ValueError("repair open path date or sequence is not canonical")
        return value

    @model_validator(mode="after")
    def facts_and_phase_are_coherent(self) -> RepairStateV1:
        path_match = _OPEN_RELATIVE_PATH.fullmatch(self.open_relative_path)
        if path_match is None or path_match.group("segment") != self.segment_id:
            raise ValueError("repair path does not bind segment identity")
        if (
            self.verified_bytes >= self.original_bytes
            or self.discarded_bytes != self.original_bytes - self.verified_bytes
        ):
            raise ValueError("repair byte facts are inconsistent")
        no_verified_frame = self.last_verified_frame_sha256 == ZERO_SHA256
        if (self.verified_bytes == 0) != no_verified_frame:
            raise ValueError("last verified frame must be zero iff the prefix is empty")
        if self.verified_bytes == 0 and self.post_repair_prefix_sha256 != EMPTY_SHA256:
            raise ValueError("empty repair prefix must use SHA256(empty)")

        authorization_required = self.phase != "detected"
        completion_required = self.phase == "completion_appended"
        completion_allowed = self.phase in {
            "authorization_appended",
            "completion_appended",
        }
        if authorization_required != (self.authorization is not None):
            raise ValueError("repair authorization identity contradicts phase")
        if completion_required and self.completion is None:
            raise ValueError("repair completion identity contradicts phase")
        if not completion_allowed and self.completion is not None:
            raise ValueError("repair completion identity precedes append phase")
        if (
            self.authorization is not None
            and self.completion is not None
            and self.completion.sequence <= self.authorization.sequence
        ):
            raise ValueError("repair completion must follow authorization")
        return self


class RepairStateAuthority(Protocol):
    """Held-root operations supplied only by a lock-owning tail session."""

    def read_repair_state_bytes(self) -> bytes | None: ...

    def publish_initial_repair_state(self, raw: bytes) -> None: ...

    def replace_repair_state(self, expected: bytes, raw: bytes) -> None: ...

    def remove_repair_state(
        self,
        expected: bytes,
        proof: AuthenticatedRepairCompletion,
    ) -> None: ...


class TailRepairFactsView(Protocol):
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


class _RepairPreflightTransport(Protocol):
    async def fetch_events(self, *, after: int, limit: int) -> bytes: ...

    async def publish_repair_authorization(
        self,
        canonical_body: bytes,
    ) -> bytes: ...

    async def publish_repair_completion(
        self,
        canonical_body: bytes,
    ) -> bytes: ...


class _RepairSimulationView(Protocol):
    def verify_exact_authorization(
        self,
        request: EvidenceRepairAuthorizeV1,
        direct: object,
        fetched: object,
    ) -> object: ...

    def verify_exact_completion(
        self,
        request: EvidenceRepairCompleteV1,
        direct: object,
        fetched: object,
    ) -> object: ...


class _RepairVerifierView(Protocol):
    def _new_repair_simulation(self) -> _RepairSimulationView: ...

    def _validate_repair_authorization_proof(self, proof: object) -> object: ...

    def _validate_repair_completion_proof(self, proof: object) -> object: ...


class _SnapshotAuthority(Protocol):
    def snapshot(self) -> object: ...


def detected_state(
    facts: TailRepairFactsView,
    repair_id: str,
) -> RepairStateV1:
    try:
        return RepairStateV1.model_validate(
            {
                "schema_version": "agmind.evidence-repair-state.v1",
                "phase": "detected",
                "repair_id": repair_id,
                "segment_id": facts.segment_id,
                "open_relative_path": facts.open_relative_path,
                "original_device": facts.original_device,
                "original_inode": facts.original_inode,
                "original_bytes": facts.original_bytes,
                "verified_bytes": facts.verified_bytes,
                "discarded_bytes": facts.discarded_bytes,
                "discarded_sha256": facts.discarded_sha256,
                "post_repair_prefix_sha256": facts.post_repair_prefix_sha256,
                "last_verified_frame_sha256": (facts.last_verified_frame_sha256),
                "current_chain_head_sha256": (facts.current_chain_head_sha256),
                "authorization": None,
                "completion": None,
            },
            strict=True,
        )
    except (AttributeError, TypeError, ValueError, ValidationError) as error:
        raise RepairProtocolError("tail-repair detection facts are invalid") from error


def repair_event_identity(value: object) -> RepairEventIdentity:
    from agmind_immune.ingest.envelope import (
        CoreEventV1,
        SimulatedEvent,
        decode_core_event,
    )

    if type(value) is CoreEventV1:
        try:
            exact = decode_core_event(canonical_json(value.model_dump(mode="python")))
        except (TypeError, ValueError) as error:
            raise RepairProtocolError("repair event outer identity is invalid") from error
        sequence = exact.sequence
        event_id = exact.event_id
        content_sha256 = exact.content_sha256
    elif type(value) is SimulatedEvent:
        sequence = value.sequence
        event_id = value.event_id
        content_sha256 = value.content_sha256
    else:
        raise TypeError("repair event identity requires an exact event type")
    try:
        return RepairEventIdentity(
            sequence=sequence,
            event_id=event_id,
            content_sha256=content_sha256,
        )
    except (TypeError, ValueError, ValidationError) as error:
        raise RepairProtocolError("repair event identity is invalid") from error


def _validated_state(state: RepairStateV1) -> RepairStateV1:
    if type(state) is not RepairStateV1:
        raise TypeError("repair state must use the exact runtime type")
    try:
        return RepairStateV1.model_validate(
            state.model_dump(exclude_none=False),
            strict=True,
        )
    except (TypeError, ValueError, ValidationError) as error:
        raise RepairStateCorrupt("repair state is not coherent") from error


def encode_repair_state(state: RepairStateV1) -> bytes:
    validated = _validated_state(state)
    raw = canonical_json(validated.model_dump(exclude_none=False))
    if not raw or len(raw) > MAX_REPAIR_STATE_BYTES:
        raise RepairStateCorrupt("canonical repair state exceeds 4096 bytes")
    return raw


def decode_repair_state(raw: bytes) -> RepairStateV1:
    if type(raw) is not bytes or not raw or len(raw) > MAX_REPAIR_STATE_BYTES:
        raise RepairStateCorrupt("repair state exceeds its exact byte bound")
    try:
        value = json.loads(raw)
        if type(value) is not dict:
            raise ValueError("repair state is not an object")
        state = RepairStateV1.model_validate(value, strict=True)
        if encode_repair_state(state) != raw:
            raise ValueError("repair state is not canonical")
        return state
    except (
        UnicodeError,
        ValueError,
        TypeError,
        RecursionError,
        ValidationError,
    ) as error:
        raise RepairStateCorrupt("repair state is not canonical or coherent") from error


def _immutable_facts(state: RepairStateV1) -> tuple[object, ...]:
    return (
        state.schema_version,
        state.repair_id,
        state.segment_id,
        state.open_relative_path,
        state.original_device,
        state.original_inode,
        state.original_bytes,
        state.verified_bytes,
        state.discarded_bytes,
        state.discarded_sha256,
        state.post_repair_prefix_sha256,
        state.last_verified_frame_sha256,
        state.current_chain_head_sha256,
    )


def _validate_transition(current: RepairStateV1, next_state: RepairStateV1) -> None:
    if _immutable_facts(current) != _immutable_facts(next_state):
        raise RepairProtocolError("repair transition changed immutable facts")
    if current.authorization is not None and next_state.authorization != current.authorization:
        raise RepairProtocolError("repair transition changed authorization identity")
    if current.completion is not None and next_state.completion != current.completion:
        raise RepairProtocolError("repair transition changed completion identity")

    if current.phase == "detected" and next_state.phase == "authorized":
        return
    if current.phase == "authorized" and next_state.phase == "truncated":
        return
    if (
        current.phase == "truncated"
        and next_state.phase == "authorization_appended"
        and next_state.completion is None
    ):
        return
    if (
        current.phase == "authorization_appended"
        and next_state.phase == "authorization_appended"
        and current.completion is None
        and next_state.completion is not None
    ):
        return
    if (
        current.phase == "authorization_appended"
        and next_state.phase == "completion_appended"
        and current.completion is not None
        and next_state.completion == current.completion
    ):
        return
    raise RepairProtocolError(
        f"repair transition {current.phase!r} -> {next_state.phase!r} is illegal"
    )


def _validated_identity(identity: RepairEventIdentity) -> RepairEventIdentity:
    if type(identity) is not RepairEventIdentity:
        raise TypeError("repair transition requires exact event identity")
    try:
        return RepairEventIdentity.model_validate(
            identity.model_dump(),
            strict=True,
        )
    except (TypeError, ValueError, ValidationError) as error:
        raise RepairProtocolError("repair event identity is invalid") from error


def _derived_transition(
    state: RepairStateV1,
    *,
    phase: RepairPhase,
    authorization: RepairEventIdentity | None,
    completion: RepairEventIdentity | None,
) -> RepairStateV1:
    current = _validated_state(state)
    document = current.model_dump(exclude_none=False)
    document.update(
        phase=phase,
        authorization=authorization,
        completion=completion,
    )
    try:
        next_state = RepairStateV1.model_validate(document, strict=True)
    except (TypeError, ValueError, ValidationError) as error:
        raise RepairProtocolError("repair transition target is invalid") from error
    _validate_transition(current, next_state)
    return next_state


def advance_authorized(
    state: RepairStateV1,
    identity: RepairEventIdentity,
) -> RepairStateV1:
    return _derived_transition(
        state,
        phase="authorized",
        authorization=_validated_identity(identity),
        completion=None,
    )


def advance_truncated(state: RepairStateV1) -> RepairStateV1:
    current = _validated_state(state)
    return _derived_transition(
        current,
        phase="truncated",
        authorization=current.authorization,
        completion=None,
    )


def advance_authorization_appended(state: RepairStateV1) -> RepairStateV1:
    current = _validated_state(state)
    return _derived_transition(
        current,
        phase="authorization_appended",
        authorization=current.authorization,
        completion=None,
    )


def record_completion_target(
    state: RepairStateV1,
    identity: RepairEventIdentity,
) -> RepairStateV1:
    current = _validated_state(state)
    return _derived_transition(
        current,
        phase="authorization_appended",
        authorization=current.authorization,
        completion=_validated_identity(identity),
    )


def advance_completion_appended(state: RepairStateV1) -> RepairStateV1:
    current = _validated_state(state)
    return _derived_transition(
        current,
        phase="completion_appended",
        authorization=current.authorization,
        completion=current.completion,
    )


@final
class AuthenticatedRepairCompletion:
    """One-use live authority issued only after final historical replay."""

    __slots__ = (
        "_ack_snapshot",
        "_acknowledgements",
        "_expected_raw",
        "_factory_marker",
        "_journal",
        "_journal_identity",
        "_status",
        "_store",
        "_transient_generation",
        "_used",
        "_verifier",
        "_verifier_generation",
    )
    _ack_snapshot: object
    _acknowledgements: Any
    _expected_raw: bytes
    _factory_marker: object
    _journal: RepairStateJournal
    _journal_identity: object
    _status: object
    _store: Any
    _transient_generation: int
    _used: bool
    _verifier: Any
    _verifier_generation: int

    def __init__(
        self,
        *,
        journal: RepairStateJournal,
        journal_identity: object,
        expected_raw: bytes,
        store: object,
        verifier: object,
        acknowledgements: object,
        status: object,
        ack_snapshot: object,
        verifier_generation: int,
        transient_generation: int,
        _factory: object,
    ) -> None:
        if _factory is not _FINAL_REPAIR_COMPLETION_FACTORY:
            raise TypeError("AuthenticatedRepairCompletion is issued only by final replay")
        object.__setattr__(self, "_factory_marker", _factory)
        object.__setattr__(self, "_journal", journal)
        object.__setattr__(self, "_journal_identity", journal_identity)
        object.__setattr__(self, "_expected_raw", expected_raw)
        object.__setattr__(self, "_store", store)
        object.__setattr__(self, "_verifier", verifier)
        object.__setattr__(self, "_acknowledgements", acknowledgements)
        object.__setattr__(self, "_status", status)
        object.__setattr__(self, "_ack_snapshot", ack_snapshot)
        object.__setattr__(self, "_verifier_generation", verifier_generation)
        object.__setattr__(
            self,
            "_transient_generation",
            transient_generation,
        )
        object.__setattr__(self, "_used", False)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("final repair authority is immutable")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("AuthenticatedRepairCompletion is final")

    def __copy__(self) -> AuthenticatedRepairCompletion:
        raise TypeError("final repair authority cannot be copied")

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> AuthenticatedRepairCompletion:
        del memo
        raise TypeError("final repair authority cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("final repair authority cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("final repair authority cannot be serialized")

    def _clear_under_delivery_fence(self, *, _factory: object) -> None:
        from agmind_immune.ingest.service import _REPAIR_DELIVERY_FACTORY

        if _factory is not _REPAIR_DELIVERY_FACTORY:
            raise TypeError("final repair authority requires the exact delivery fence")
        if self._used:
            raise RepairProtocolError("final repair authority has already been consumed")
        journal = self._journal
        if (
            type(journal) is not RepairStateJournal
            or journal._identity is not self._journal_identity
            or journal._clear_authorization is not self
        ):
            raise RepairProtocolError("final repair authority is not bound to its exact journal")
        object.__setattr__(self, "_used", True)
        journal.clear_completed(self)


@final
class RepairStateJournal:
    """Exact in-memory view of one CAS-published durable repair gate."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("RepairStateJournal is final")

    def __init__(
        self,
        authority: RepairStateAuthority,
        state: RepairStateV1 | None,
        raw: bytes | None,
        *,
        _factory: object,
    ) -> None:
        if _factory is not _REPAIR_STATE_JOURNAL_FACTORY:
            raise TypeError("RepairStateJournal must be opened from authority")
        self._authority = authority
        self._state = state
        self._raw = raw
        self._identity = object()
        self._clear_authorization: AuthenticatedRepairCompletion | None = None
        self._assert_consistent()

    def _assert_consistent(self) -> None:
        state = self._state
        raw = self._raw
        if state is None and raw is None:
            return
        if state is None or raw is None or decode_repair_state(raw) != _validated_state(state):
            raise RepairStateCorrupt("repair journal state does not match its exact durable bytes")

    @classmethod
    def open(cls, authority: RepairStateAuthority) -> RepairStateJournal:
        for name in (
            "read_repair_state_bytes",
            "publish_initial_repair_state",
            "replace_repair_state",
            "remove_repair_state",
        ):
            if not callable(getattr(authority, name, None)):
                raise TypeError("repair state requires held-root authority")
        raw = authority.read_repair_state_bytes()
        if raw is None:
            return cls(
                authority,
                None,
                None,
                _factory=_REPAIR_STATE_JOURNAL_FACTORY,
            )
        if type(raw) is not bytes:
            raise RepairStateCorrupt("repair authority returned non-byte state")
        return cls(
            authority,
            decode_repair_state(raw),
            raw,
            _factory=_REPAIR_STATE_JOURNAL_FACTORY,
        )

    @property
    def state(self) -> RepairStateV1 | None:
        return None if self._state is None else self._state.model_copy(deep=True)

    def _prove_publication(self, expected: bytes | None) -> None:
        actual = self._authority.read_repair_state_bytes()
        if actual != expected:
            raise RepairStateConflict("repair state publication is ambiguous")

    def publish_detected(self, state: RepairStateV1) -> None:
        self._assert_consistent()
        if self._state is not None or self._raw is not None:
            raise RepairProtocolError("repair detected state already exists")
        validated = _validated_state(state)
        if validated.phase != "detected":
            raise RepairProtocolError("initial repair state must be exact detected")
        raw = encode_repair_state(validated)
        self._authority.publish_initial_repair_state(raw)
        self._prove_publication(raw)
        self._state = validated.model_copy(deep=True)
        self._raw = raw

    def transition(self, next_state: RepairStateV1) -> None:
        self._assert_consistent()
        current = self._state
        expected = self._raw
        if current is None or expected is None:
            raise RepairProtocolError("repair transition has no durable detected state")
        if type(next_state) is not RepairStateV1:
            raise TypeError("repair transition requires exact state type")
        validated = _validated_state(next_state)
        if validated == current:
            self._prove_publication(expected)
            return
        _validate_transition(current, validated)
        raw = encode_repair_state(validated)
        self._authority.replace_repair_state(expected, raw)
        self._prove_publication(raw)
        self._state = validated.model_copy(deep=True)
        self._raw = raw

    def clear_completed(self, proof: AuthenticatedRepairCompletion) -> None:
        self._assert_consistent()
        authority = cast(Any, self._authority)
        current = self._state
        expected = self._raw
        if current is None or expected is None or current.phase != "completion_appended":
            raise RepairProtocolError("only completed repair state can be cleared")
        if type(proof) is not AuthenticatedRepairCompletion:
            raise RepairProtocolError("final repair clear lacks exact historical replay authority")
        proof_acknowledgements = cast(
            _SnapshotAuthority,
            proof._acknowledgements,
        )
        if (
            proof._factory_marker is not _FINAL_REPAIR_COMPLETION_FACTORY
            or self._clear_authorization is not proof
            or proof._journal_identity is not self._identity
            or proof._expected_raw != expected
            or proof._store is not self._authority
            or proof_acknowledgements is not getattr(authority, "ack_journal", None)
            or proof._status != authority.status()
            or proof._ack_snapshot != proof_acknowledgements.snapshot()
            or proof._verifier_generation != proof._verifier._authority.generation
            or proof._transient_generation != proof._verifier._repair_transient_generation
            or proof._verifier._staged
            or proof._verifier._authorizations
            or not authority._is_bound_verifier(proof._verifier)
        ):
            raise RepairProtocolError("final repair clear lacks exact historical replay authority")
        self._prove_publication(expected)
        self._authority.remove_repair_state(expected, proof)
        self._clear_authorization = None
        self._state = None
        self._raw = None


def authorization_request(state: RepairStateV1) -> EvidenceRepairAuthorizeV1:
    state = _validated_state(state)
    return EvidenceRepairAuthorizeV1(
        schema_version="agmind.evidence-repair-authorize.v1",
        repair_id=state.repair_id,
        segment_id=state.segment_id,
        verified_bytes=state.verified_bytes,
        discarded_bytes=state.discarded_bytes,
        discarded_sha256=state.discarded_sha256,
        last_verified_frame_sha256=state.last_verified_frame_sha256,
        current_chain_head_sha256=state.current_chain_head_sha256,
        reason="torn_open_tail",
    )


def completion_request(state: RepairStateV1) -> EvidenceRepairCompleteV1:
    state = _validated_state(state)
    authorization = state.authorization
    if authorization is None or state.phase not in {
        "authorization_appended",
        "completion_appended",
    }:
        raise RepairProtocolError("completion request requires authenticated authorization append")
    return EvidenceRepairCompleteV1(
        schema_version="agmind.evidence-repair-complete.v1",
        repair_id=state.repair_id,
        authorization_event_id=authorization.event_id,
        authorization_content_sha256=authorization.content_sha256,
        segment_id=state.segment_id,
        verified_bytes=state.verified_bytes,
        post_repair_prefix_sha256=state.post_repair_prefix_sha256,
        last_verified_frame_sha256=state.last_verified_frame_sha256,
        current_chain_head_sha256=state.current_chain_head_sha256,
        reason="torn_open_tail_completed",
    )


def _exact_authenticated_repair_event(
    *,
    store: object,
    identity: RepairEventIdentity,
    event_type: str,
    request: EvidenceRepairAuthorizeV1 | EvidenceRepairCompleteV1,
) -> tuple[CoreEventV1, object]:
    from agmind_immune.ingest.envelope import decode_core_event

    typed_store = cast(Any, store)
    refs = typed_store.authenticated_refs(
        after_sequence=identity.sequence - 1,
        through_sequence=identity.sequence,
        limit=1,
    )
    if len(refs) != 1:
        raise RepairProtocolError("final repair identity lacks one authenticated evidence ref")
    ref = refs[0]
    record = typed_store.resolve_authenticated_ref(ref)
    try:
        item = decode_core_event(
            canonical_json(
                {
                    "sequence": ref.source_sequence,
                    "event_id": ref.event_id,
                    "content_sha256": ref.content_sha256,
                    "envelope": record.envelope,
                }
            )
        )
    except (TypeError, ValueError) as error:
        raise RepairProtocolError(
            "final repair evidence record is not one exact Core event"
        ) from error
    if (
        repair_event_identity(item) != identity
        or item.envelope.get("event_type") != event_type
        or canonical_json(item.envelope.get("normalized_fields")) != canonical_json(request)
    ):
        raise RepairProtocolError("final repair evidence does not bind its exact request")
    return item, ref


def finalize_completed_repair(
    *,
    journal: RepairStateJournal,
    verifier: object,
    store: object,
) -> AuthenticatedRepairCompletion:
    """Replay both authenticated records and mint the only gate-clear proof."""
    from agmind_immune.evidence.segments import (
        EvidenceStatus,
        RepairPhysicalState,
        SegmentStore,
    )
    from agmind_immune.ingest.ack_journal import (
        AckJournal,
        AckJournalSnapshot,
    )
    from agmind_immune.ingest.envelope import (
        EnvelopeVerifier,
        SimulatedEvent,
    )

    if (
        type(journal) is not RepairStateJournal
        or type(store) is not SegmentStore
        or type(verifier) is not EnvelopeVerifier
        or journal._authority is not store
        or not store._is_bound_verifier(verifier)
    ):
        raise RepairProtocolError("final repair replay lacks exact live authorities")
    state = journal.state
    expected_raw = journal._raw
    facts = store.repair_facts
    acknowledgements = store.ack_journal
    status_before = store.status()
    snapshot_before = acknowledgements.snapshot()
    if facts is None:
        raise RepairProtocolError("final repair state has no retained physical facts")
    facts_view = cast(TailRepairFactsView, facts)
    if (
        state is None
        or state.phase != "completion_appended"
        or state.authorization is None
        or state.completion is None
        or expected_raw is None
        or type(acknowledgements) is not AckJournal
        or type(status_before) is not EvidenceStatus
        or type(snapshot_before) is not AckJournalSnapshot
        or status_before.repair_pending is not True
        or not status_before.healthy
        or snapshot_before.pending is not None
        or snapshot_before.confirmed_through != state.completion.sequence
        or status_before.evidence_head != state.completion.sequence
        or store.active_path is not None
        or _immutable_facts(detected_state(facts_view, state.repair_id)) != _immutable_facts(state)
        or store.classify_repair_physical(facts)
        not in {
            RepairPhysicalState.SETTLED_PREFIX,
            RepairPhysicalState.ZERO_RETIRED,
        }
    ):
        raise RepairProtocolError("final repair state is not durably settled and ACK-confirmed")
    authorization_item, authorization_ref = _exact_authenticated_repair_event(
        store=store,
        identity=state.authorization,
        event_type="evidence_repair_authorized",
        request=authorization_request(state),
    )
    completion_item, completion_ref = _exact_authenticated_repair_event(
        store=store,
        identity=state.completion,
        event_type="evidence_repair_completed",
        request=completion_request(state),
    )
    replayed = verifier._restricted_historical_replay(
        (
            (authorization_item, authorization_ref),
            (completion_item, completion_ref),
        )
    )
    if (
        len(replayed) != 2
        or type(replayed[0]) is not SimulatedEvent
        or type(replayed[1]) is not SimulatedEvent
        or replayed[0].event_type != "evidence_repair_authorized"
        or replayed[1].event_type != "evidence_repair_completed"
        or replayed[0].sequence != state.authorization.sequence
        or replayed[1].sequence != state.completion.sequence
    ):
        raise RepairProtocolError("final historical repair replay returned an inexact proof")
    if (
        journal._raw != expected_raw
        or store.status() != status_before
        or acknowledgements.snapshot() != snapshot_before
    ):
        raise RepairStateConflict("repair authority changed during final historical replay")
    capability = AuthenticatedRepairCompletion(
        journal=journal,
        journal_identity=journal._identity,
        expected_raw=expected_raw,
        store=store,
        verifier=verifier,
        acknowledgements=acknowledgements,
        status=status_before,
        ack_snapshot=snapshot_before,
        verifier_generation=verifier._authority.generation,
        transient_generation=verifier._repair_transient_generation,
        _factory=_FINAL_REPAIR_COMPLETION_FACTORY,
    )
    journal._clear_authorization = capability
    store._register_repair_completion_authorization(capability, journal)
    return capability


def _preflight_authorities(
    *,
    verifier: object,
    store: object,
    acknowledgements: object,
    transport: object,
) -> tuple[object, object, int, set[int]]:
    from agmind_immune.evidence.segments import (
        EvidenceStatus,
        SegmentStore,
    )
    from agmind_immune.ingest.ack_journal import (
        AckJournal,
        AckJournalSnapshot,
    )
    from agmind_immune.ingest.envelope import EnvelopeVerifier

    if (
        not isinstance(store, SegmentStore)
        or type(verifier) is not EnvelopeVerifier
        or type(acknowledgements) is not AckJournal
        or acknowledgements._store is not store
        or not store._is_bound_verifier(verifier)
    ):
        raise RepairPreflightError("repair preflight authorities are not exactly bound")
    for method_name in (
        "fetch_events",
        "publish_repair_authorization",
        "publish_repair_completion",
    ):
        if not callable(getattr(transport, method_name, None)):
            raise RepairPreflightError("repair preflight transport lacks a fixed method")
    status = store.status()
    snapshot = acknowledgements.snapshot()
    try:
        retained_journal = store.ack_journal
    except Exception as error:
        raise RepairPreflightError(
            "repair preflight lacks the retained repair lifecycle"
        ) from error
    if (
        type(status) is not EvidenceStatus
        or type(snapshot) is not AckJournalSnapshot
        or not snapshot.healthy
        or status.repair_pending is not True
        or retained_journal is not acknowledgements
        or status.evidence_head != verifier.fsm.last_sequence
    ):
        raise RepairPreflightError("repair preflight local authority is inconsistent")
    evidence_head = status.evidence_head
    confirmed = snapshot.confirmed_through
    if not 0 <= confirmed <= evidence_head:
        raise RepairPreflightError("repair preflight confirmed ACK is invalid")
    allowed_acks = {confirmed}
    pending = snapshot.pending
    if pending is not None:
        if not confirmed < pending.sequence <= evidence_head:
            raise RepairPreflightError("repair preflight pending ACK is outside evidence")
        refs = store.authenticated_refs(
            after_sequence=pending.sequence - 1,
            through_sequence=pending.sequence,
            limit=1,
        )
        if (
            len(refs) != 1
            or refs[0].source_sequence != pending.sequence
            or refs[0].event_id != pending.event_id
            or refs[0].content_sha256 != pending.content_sha256
        ):
            raise RepairPreflightError("repair preflight pending ACK lacks authenticated evidence")
        allowed_acks.add(pending.sequence)
    return status, snapshot, evidence_head, allowed_acks


async def _preflight_exact_repair(
    *,
    verifier: object,
    store: object,
    acknowledgements: object,
    transport: object,
    request: EvidenceRepairAuthorizeV1 | EvidenceRepairCompleteV1,
) -> object:
    from agmind_immune.ingest.envelope import (
        PageDecodeError,
        RepairSimulationError,
        VerifierCommitError,
        decode_core_event,
        decode_events_page,
    )

    status_before, snapshot_before, evidence_head, allowed_acks = _preflight_authorities(
        verifier=verifier,
        store=store,
        acknowledgements=acknowledgements,
        transport=transport,
    )
    typed_transport = cast(_RepairPreflightTransport, transport)
    typed_verifier = cast(_RepairVerifierView, verifier)
    try:
        simulation = typed_verifier._new_repair_simulation()
    except VerifierCommitError as error:
        raise RepairPreflightError(
            "repair preflight could not freeze verifier authority"
        ) from error
    captured_status, captured_snapshot, captured_head, captured_acks = _preflight_authorities(
        verifier=verifier,
        store=store,
        acknowledgements=acknowledgements,
        transport=transport,
    )
    if (
        captured_status != status_before
        or captured_snapshot != snapshot_before
        or captured_head != evidence_head
        or captured_acks != allowed_acks
    ):
        raise RepairPreflightError("local authority changed while repair preflight was frozen")
    request_type = type(request)
    if request_type not in {
        EvidenceRepairAuthorizeV1,
        EvidenceRepairCompleteV1,
    }:
        raise TypeError("repair preflight request has the wrong exact type")
    try:
        normalized_request = request_type.model_validate(
            request.model_dump(),
            strict=True,
        )
        body = canonical_json(normalized_request)
    except (TypeError, ValueError, ValidationError) as error:
        raise RepairPreflightError("repair preflight request is invalid") from error

    publish = (
        typed_transport.publish_repair_authorization
        if request_type is EvidenceRepairAuthorizeV1
        else typed_transport.publish_repair_completion
    )
    direct_raw = await publish(body)
    if type(direct_raw) is not bytes:
        raise RepairPreflightError("repair POST returned a non-exact byte response")
    try:
        direct = decode_core_event(direct_raw)
    except (TypeError, ValueError) as error:
        raise RepairPreflightError("repair POST response is not one exact Core event") from error
    if direct.sequence <= evidence_head:
        raise RepairPreflightError("repair preflight target does not follow authenticated evidence")

    after = evidence_head
    fetched: list[CoreEventV1] = []
    selected_page_ack: int | None = None
    total_response_bytes = 0
    target_found = False
    for _page_number in range(MAX_REPAIR_PREFLIGHT_PAGES):
        remaining = MAX_REPAIR_PREFLIGHT_EVENTS - len(fetched)
        if remaining <= 0:
            raise RepairPreflightError("repair preflight event bound exhausted")
        requested_limit = min(100, remaining)
        raw = await typed_transport.fetch_events(
            after=after,
            limit=requested_limit,
        )
        if type(raw) is not bytes:
            raise RepairPreflightError("repair preflight page is not exact bytes")
        total_response_bytes += len(raw)
        if total_response_bytes > MAX_REPAIR_PREFLIGHT_RESPONSE_BYTES:
            raise RepairPreflightError("repair preflight response-byte bound exhausted")
        try:
            page = decode_events_page(raw)
        except PageDecodeError as error:
            raise RepairPreflightError("repair preflight page is invalid") from error
        if selected_page_ack is None:
            if page.acked_through not in allowed_acks:
                raise RepairPreflightError(
                    "repair preflight ACK cursor is not locally authenticated"
                )
            selected_page_ack = page.acked_through
        elif page.acked_through != selected_page_ack:
            raise RepairPreflightError("repair preflight ACK cursor changed between pages")
        if (
            page.acked_through > evidence_head
            or page.reserved_through < direct.sequence
            or not page.events
        ):
            raise RepairPreflightError("repair preflight page cannot reach the exact target")
        if (
            len(page.events) > requested_limit
            or len(fetched) + len(page.events) > MAX_REPAIR_PREFLIGHT_EVENTS
        ):
            raise RepairPreflightError("repair preflight event bound exhausted")
        page_previous = after
        page_target_found = False
        for item in page.events:
            if item.sequence <= page_previous:
                raise RepairPreflightError("repair preflight path is not strictly forward")
            if item.sequence == direct.sequence:
                if canonical_json(item.model_dump(mode="python")) != canonical_json(
                    direct.model_dump(mode="python")
                ):
                    raise RepairPreflightError("repair preflight fetched a different exact target")
                page_target_found = True
            elif item.sequence > direct.sequence and not page_target_found:
                raise RepairPreflightError("repair preflight passed the exact target")
            page_previous = item.sequence
        for item in page.events:
            fetched.append(item)
            if item.sequence == direct.sequence:
                target_found = True
                break
            after = item.sequence
        if target_found:
            break
        after = page.events[-1].sequence
    if not target_found:
        raise RepairPreflightError("repair preflight page bound exhausted")

    try:
        if request_type is EvidenceRepairAuthorizeV1:
            proof = simulation.verify_exact_authorization(
                cast(EvidenceRepairAuthorizeV1, normalized_request),
                direct,
                tuple(fetched),
            )
        else:
            proof = simulation.verify_exact_completion(
                cast(EvidenceRepairCompleteV1, normalized_request),
                direct,
                tuple(fetched),
            )
    except (RepairSimulationError, VerifierCommitError) as error:
        raise RepairPreflightError("repair preflight simulation rejected the exact path") from error
    status_after, snapshot_after, after_head, after_acks = _preflight_authorities(
        verifier=verifier,
        store=store,
        acknowledgements=acknowledgements,
        transport=transport,
    )
    if (
        status_after != status_before
        or snapshot_after != snapshot_before
        or after_head != evidence_head
        or after_acks != allowed_acks
    ):
        raise RepairPreflightError("local authority changed during repair preflight")
    return proof


async def preflight_authorization(
    *,
    verifier: object,
    store: object,
    acknowledgements: object,
    transport: object,
    request: EvidenceRepairAuthorizeV1,
) -> object:
    from agmind_immune.ingest.envelope import VerifierCommitError

    proof = await _preflight_exact_repair(
        verifier=verifier,
        store=store,
        acknowledgements=acknowledgements,
        transport=transport,
        request=request,
    )
    typed_verifier = cast(_RepairVerifierView, verifier)
    try:
        return typed_verifier._validate_repair_authorization_proof(proof)
    except VerifierCommitError as error:
        raise RepairPreflightError(
            "live verifier changed during authorization preflight"
        ) from error


async def preflight_completion(
    *,
    verifier: object,
    store: object,
    acknowledgements: object,
    transport: object,
    request: EvidenceRepairCompleteV1,
) -> object:
    from agmind_immune.ingest.envelope import VerifierCommitError

    proof = await _preflight_exact_repair(
        verifier=verifier,
        store=store,
        acknowledgements=acknowledgements,
        transport=transport,
        request=request,
    )
    typed_verifier = cast(_RepairVerifierView, verifier)
    try:
        return typed_verifier._validate_repair_completion_proof(proof)
    except VerifierCommitError as error:
        raise RepairPreflightError("live verifier changed during completion preflight") from error


def _core_event_from_simulated_proof(proof: object) -> CoreEventV1:
    from agmind_immune.ingest.envelope import (
        SimulatedRepairAuthorization,
        SimulatedRepairCompletion,
        decode_core_event,
    )

    if type(proof) not in {
        SimulatedRepairAuthorization,
        SimulatedRepairCompletion,
    }:
        raise TypeError("repair preview must use one exact simulated proof")
    target = cast(Any, proof).target
    try:
        envelope = json.loads(target._canonical_envelope)
        item = decode_core_event(
            canonical_json(
                {
                    "sequence": target.sequence,
                    "event_id": target.event_id,
                    "content_sha256": target.content_sha256,
                    "envelope": envelope,
                }
            )
        )
    except (TypeError, ValueError, ValidationError) as error:
        raise RepairProtocolError(
            "simulated repair target cannot form one exact Core event"
        ) from error
    if repair_event_identity(item) != repair_event_identity(target):
        raise RepairProtocolError(
            "simulated repair target changed during Core-event reconstruction"
        )
    return item


async def _complete_tail_repair(
    *,
    session: TailRepairSession,
    verifier: EnvelopeVerifier,
    transport: ObserverCoreTransport,
    clock: CoreClockProvider,
) -> RepairedEvidenceRuntime:
    """Complete or resume one signed two-phase repair under the retained root lock."""
    from agmind_immune.coverage import CoverageState
    from agmind_immune.evidence.segments import (
        RepairPhysicalState,
        SegmentStore,
        TailRepairFacts,
        TailRepairSession,
    )
    from agmind_immune.ingest.ack_journal import AckJournal
    from agmind_immune.ingest.envelope import (
        EnvelopeVerifier,
        SimulatedRepairAuthorization,
        SimulatedRepairCompletion,
    )
    from agmind_immune.ingest.service import (
        _REPAIR_ACCEPTANCE_FACTORY,
        _REPAIR_DELIVERY_FACTORY,
        AcceptanceCoordinator,
        DeliveryCoordinator,
    )

    if (
        type(session) is not TailRepairSession
        or type(verifier) is not EnvelopeVerifier
        or not session._is_bound_verifier(verifier)
        or type(session.ack_journal) is not AckJournal
    ):
        raise RepairProtocolError("tail repair requires one exact same-lock recovered lifecycle")
    journal = RepairStateJournal.open(session)
    facts = session.repair_facts
    if type(facts) is not TailRepairFacts:
        raise RepairProtocolError("tail repair has no exact retained facts")

    temporary = session.read_repair_state_temporary_bytes()
    if temporary is not None:
        if (
            journal.state is None
            and session.classify_repair_physical(facts) is not RepairPhysicalState.ORIGINAL_TORN
        ):
            raise RepairStateCorrupt("phase-neutral repair temporary cannot cover changed evidence")
        session.remove_repair_state_temporary(temporary)

    state = journal.state
    if state is None:
        if session.classify_repair_physical(facts) is not RepairPhysicalState.ORIGINAL_TORN:
            raise RepairStateCorrupt("post-truncate evidence lacks durable repair state")
        state = detected_state(
            cast(TailRepairFactsView, facts),
            str(uuid.uuid4()),
        )
        journal.publish_detected(state)
    if _immutable_facts(
        detected_state(
            cast(TailRepairFactsView, facts),
            state.repair_id,
        )
    ) != _immutable_facts(state):
        raise RepairStateCorrupt("durable repair state differs from retained physical facts")

    if state.phase in {"detected", "authorized"}:
        entry_phase = state.phase
        proof = await preflight_authorization(
            verifier=verifier,
            store=session,
            acknowledgements=session.ack_journal,
            transport=transport,
            request=authorization_request(state),
        )
        if type(proof) is not SimulatedRepairAuthorization:
            raise RepairProtocolError("authorization preflight returned an inexact proof")
        identity = repair_event_identity(proof.target)
        physical = session.classify_repair_physical(facts)
        if entry_phase == "detected":
            if physical is not RepairPhysicalState.ORIGINAL_TORN:
                raise RepairStateCorrupt(
                    "new repair target changed before authorization registration"
                )
            state = advance_authorized(state, identity)
            journal.transition(state)
        elif state.authorization != identity:
            raise RepairProtocolError("authorization retry returned a different exact target")

        if physical is RepairPhysicalState.ORIGINAL_TORN:
            capability = session.register_authorization(proof)
            physical = session.truncate(capability)
        elif physical not in {
            RepairPhysicalState.CLEAN_OPEN,
            RepairPhysicalState.ZERO_HELD,
        }:
            raise RepairStateCorrupt("durable authorization contradicts repair target bytes")
        if physical not in {
            RepairPhysicalState.CLEAN_OPEN,
            RepairPhysicalState.ZERO_HELD,
        }:
            raise RepairStateCorrupt("authorized truncate did not reach one exact clean prefix")
        state = advance_truncated(state)
        journal.transition(state)

    state = journal.state
    if state is None or state.phase not in {
        "truncated",
        "authorization_appended",
        "completion_appended",
    }:
        raise RepairStateCorrupt("repair did not reach a resumable durable phase")
    physical = session.classify_repair_physical(facts)
    if physical is RepairPhysicalState.ZERO_HELD:
        session.retire_zero_prefix(encode_repair_state(state))
    store = session.resume_store()
    if type(store) is not SegmentStore or store is not session:
        raise RepairProtocolError("repair did not resume the exact same store")
    if store.active_path is not None:
        store.flush_security_boundary()

    acceptance = AcceptanceCoordinator._from_repair_resume(
        verifier,
        store,
        _factory=_REPAIR_ACCEPTANCE_FACTORY,
    )
    coverage: CoverageState | None = None
    delivery: DeliveryCoordinator | None = None
    try:
        coverage = CoverageState.open_and_recover(store)
        delivery = DeliveryCoordinator._create_for_repair(
            acceptance,
            store.ack_journal,
            transport,
            coverage=coverage,
            clock=clock,
            _factory=_REPAIR_DELIVERY_FACTORY,
        )

        async def expected_event(
            request: EvidenceRepairAuthorizeV1 | EvidenceRepairCompleteV1,
            identity: RepairEventIdentity,
        ) -> CoreEventV1:
            status = store.status()
            if status.evidence_head > identity.sequence:
                raise RepairProtocolError("authenticated evidence advanced beyond repair target")
            if status.evidence_head == identity.sequence:
                item, _ref = _exact_authenticated_repair_event(
                    store=store,
                    identity=identity,
                    event_type=(
                        "evidence_repair_authorized"
                        if type(request) is EvidenceRepairAuthorizeV1
                        else "evidence_repair_completed"
                    ),
                    request=request,
                )
                return item
            proof = (
                await preflight_authorization(
                    verifier=verifier,
                    store=store,
                    acknowledgements=store.ack_journal,
                    transport=transport,
                    request=request,
                )
                if type(request) is EvidenceRepairAuthorizeV1
                else await preflight_completion(
                    verifier=verifier,
                    store=store,
                    acknowledgements=store.ack_journal,
                    transport=transport,
                    request=cast(EvidenceRepairCompleteV1, request),
                )
            )
            item = _core_event_from_simulated_proof(proof)
            if repair_event_identity(item) != identity:
                raise RepairProtocolError("repair retry returned a different exact target")
            return item

        state = journal.state
        assert state is not None
        if state.phase == "truncated":
            authorization = state.authorization
            if authorization is None:
                raise RepairStateCorrupt("truncated repair lacks authorization identity")
            item = await expected_event(
                authorization_request(state),
                authorization,
            )
            ref = await delivery.drain_until_exact(item, settle_each=True)
            if (
                ref.source_sequence != authorization.sequence
                or ref.event_id != authorization.event_id
                or ref.content_sha256 != authorization.content_sha256
            ):
                raise RepairProtocolError(
                    "authorization delivery returned a different evidence ref"
                )
            state = advance_authorization_appended(state)
            journal.transition(state)

        state = journal.state
        assert state is not None
        if state.phase == "authorization_appended":
            authorization = state.authorization
            if authorization is None:
                raise RepairStateCorrupt("appended authorization identity is absent")
            _exact_authenticated_repair_event(
                store=store,
                identity=authorization,
                event_type="evidence_repair_authorized",
                request=authorization_request(state),
            )
            authorization_status = store.status()
            authorization_ack = store.ack_journal.snapshot()
            if state.completion is None:
                if (
                    authorization_status.evidence_head != authorization.sequence
                    or authorization_ack.confirmed_through != authorization.sequence
                    or authorization_ack.pending is not None
                ):
                    raise RepairStateCorrupt(
                        "authorization-appended phase lacks its exact "
                        "settled and confirmed evidence head"
                    )
                completion_proof = await preflight_completion(
                    verifier=verifier,
                    store=store,
                    acknowledgements=store.ack_journal,
                    transport=transport,
                    request=completion_request(state),
                )
                if type(completion_proof) is not SimulatedRepairCompletion:
                    raise RepairProtocolError("completion preflight returned an inexact proof")
                completion_identity = repair_event_identity(completion_proof.target)
                state = record_completion_target(
                    state,
                    completion_identity,
                )
                journal.transition(state)
            elif not (
                authorization.sequence
                <= authorization_ack.confirmed_through
                <= authorization_status.evidence_head
                <= state.completion.sequence
            ):
                raise RepairStateCorrupt("completion delivery prefix contradicts durable phase")
            completion = state.completion
            assert completion is not None
            item = await expected_event(
                completion_request(state),
                completion,
            )
            ref = await delivery.drain_until_exact(item, settle_each=True)
            if (
                ref.source_sequence != completion.sequence
                or ref.event_id != completion.event_id
                or ref.content_sha256 != completion.content_sha256
            ):
                raise RepairProtocolError("completion delivery returned a different evidence ref")
            state = advance_completion_appended(state)
            journal.transition(state)

        state = journal.state
        if (
            state is None
            or state.phase != "completion_appended"
            or state.completion is None
            or state.authorization is None
        ):
            raise RepairStateCorrupt("repair did not reach exact durable completion")
        _exact_authenticated_repair_event(
            store=store,
            identity=state.authorization,
            event_type="evidence_repair_authorized",
            request=authorization_request(state),
        )
        _exact_authenticated_repair_event(
            store=store,
            identity=state.completion,
            event_type="evidence_repair_completed",
            request=completion_request(state),
        )
        completion_status = store.status()
        completion_ack = store.ack_journal.snapshot()
        if (
            completion_status.evidence_head != state.completion.sequence
            or completion_ack.confirmed_through != state.completion.sequence
            or completion_ack.pending is not None
        ):
            raise RepairStateCorrupt("completion-appended phase lacks exact confirmed evidence")

        final_clear = finalize_completed_repair(
            journal=journal,
            verifier=verifier,
            store=store,
        )
        runtime = RepairedEvidenceRuntime(
            store=store,
            verifier=verifier,
            acceptance=acceptance,
            acknowledgements=store.ack_journal,
            coverage=coverage,
        )
        await delivery.finalize_repair(
            final_clear,
            _factory=_REPAIR_DELIVERY_FACTORY,
        )
        delivery = None
        return runtime
    except BaseException as primary:
        if delivery is not None:
            try:
                await delivery.close()
            except BaseException as cleanup_error:  # noqa: BLE001
                primary.add_note(
                    f"secondary repair delivery cleanup failure ({type(cleanup_error).__name__})"
                )
        if coverage is not None:
            try:
                coverage.close()
            except BaseException as cleanup_error:  # noqa: BLE001
                primary.add_note(
                    f"secondary repair coverage cleanup failure ({type(cleanup_error).__name__})"
                )
        raise


async def complete_tail_repair(
    *,
    session: TailRepairSession,
    verifier: EnvelopeVerifier,
    transport: ObserverCoreTransport,
    clock: CoreClockProvider,
) -> RepairedEvidenceRuntime:
    """Own transport cleanup while the crash-safe repair remains restartable."""
    try:
        return await _complete_tail_repair(
            session=session,
            verifier=verifier,
            transport=transport,
            clock=clock,
        )
    except BaseException as primary:
        try:
            await transport.close()
        except BaseException as cleanup_error:  # noqa: BLE001
            primary.add_note(
                f"secondary repair transport cleanup failure ({type(cleanup_error).__name__})"
            )
        raise
