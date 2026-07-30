"""Strict observer page decoding and immutable-root-anchored stream verification."""

from __future__ import annotations

import hashlib
import re
import weakref
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from itertools import pairwise
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Never, SupportsIndex, final

from cryptography.exceptions import InvalidSignature
from pydantic import Field, ValidationError, field_validator, model_validator

from agmind_immune.canonicaljson import (
    canonical_json,
    verify_event_signature,
    verify_key_transition,
)
from agmind_immune.canonicaljson import (
    release_id as derive_release_id,
)
from agmind_immune.contracts import (
    MAX_UINT64,
    ContractModel,
    CoverageEventV1,
    EventEnvelopeV1,
    EvidenceRepairAuthorizeV1,
    EvidenceRepairCompleteV1,
    FalcoConnectV1,
    KeyTransitionV1,
    ObserverBootBoundaryV1,
    ObserverTrustRootV1,
    RetentionBlockedV1,
    RetentionTombstoneV2,
    decode_strict,
)

MAX_EVENTS_PAGE_BYTES = 4 * 1024 * 1024
MAX_CANONICAL_ENVELOPE_BYTES = 64 * 1024
MAX_PUBLIC_KEY_METADATA_BYTES = 64 * 1024
MAX_CORE_EVENT_RESPONSE_BYTES = 128 * 1024
MAX_PAGE_EVENTS = 100
MAX_PAGE_GAPS = 100
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")


class IngestVerificationError(ValueError):
    """Base class for fail-closed observer verification failures."""


class PageDecodeError(IngestVerificationError):
    """The transport page is not one exact bounded v1 object."""


class OuterBindingError(IngestVerificationError):
    """Outer transport identity does not bind the canonical envelope."""


class EnvelopeSignatureError(IngestVerificationError):
    """The selected anchored observer key did not verify the envelope."""


class EnvelopeIdentityError(IngestVerificationError):
    """The signed envelope does not match the pinned observer identity."""


class KeyMetadataError(IngestVerificationError):
    """Untrusted key metadata does not prove one root-anchored chain."""


class SequenceError(IngestVerificationError):
    """The host-global source sequence cannot extend the accepted stream."""


class BootBoundaryError(IngestVerificationError):
    """The event violates the closed A/B/C boot-boundary state machine."""


class EnvelopeConflict(IngestVerificationError):
    """A different valid signed envelope reused an accepted host sequence."""


class VerifierCommitError(RuntimeError):
    """A staged verifier transition is stale or otherwise uncommittable."""


class RepairSimulationError(IngestVerificationError):
    """A restricted repair proof did not bind one exact authenticated path."""


class RetentionSimulationError(IngestVerificationError):
    """A retention proof did not bind one exact authenticated control path."""


class CoreSequenceGapV1(ContractModel):
    start: int = Field(ge=1, le=MAX_UINT64)
    end: int = Field(ge=1, le=MAX_UINT64)

    @model_validator(mode="after")
    def range_is_ordered(self) -> CoreSequenceGapV1:
        if self.end < self.start:
            raise ValueError("transport gap range is reversed")
        return self


class CoreEventV1(ContractModel):
    sequence: int = Field(ge=1, le=MAX_UINT64)
    event_id: str
    content_sha256: str
    envelope: dict[str, Any]

    @field_validator("event_id")
    @classmethod
    def event_id_is_exact(cls, value: str) -> str:
        if not _EVENT_ID.fullmatch(value):
            raise ValueError("invalid outer event_id")
        return value

    @field_validator("content_sha256")
    @classmethod
    def content_hash_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("invalid outer content_sha256")
        return value

    @field_validator("envelope")
    @classmethod
    def envelope_is_bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(canonical_json(value)) > MAX_CANONICAL_ENVELOPE_BYTES:
            raise ValueError("canonical envelope exceeds 64 KiB")
        return value


def decode_core_event(raw: bytes) -> CoreEventV1:
    """Decode one bounded direct observer response and bind its complete outer item."""
    item = decode_strict(raw, CoreEventV1, MAX_CORE_EVENT_RESPONSE_BYTES)
    envelope_sequence = item.envelope.get("source_sequence")
    envelope_event_id = item.envelope.get("event_id")
    canonical_envelope = canonical_json(item.envelope)
    if (
        type(envelope_sequence) is not int
        or envelope_sequence != item.sequence
        or type(envelope_event_id) is not str
        or envelope_event_id != item.event_id
        or hashlib.sha256(canonical_envelope).hexdigest() != item.content_sha256
    ):
        raise OuterBindingError("direct observer item does not bind its canonical envelope")
    return item


class CoreEventsPageV1(ContractModel):
    schema_version: Literal["agmind.observer-events-page.v1"]
    events: list[CoreEventV1] = Field(max_length=MAX_PAGE_EVENTS)
    uncovered_gaps: list[CoreSequenceGapV1] = Field(max_length=MAX_PAGE_GAPS)
    gaps_truncated: bool
    acked_through: int = Field(ge=0, le=MAX_UINT64)
    reserved_through: int = Field(ge=0, le=MAX_UINT64)

    @model_validator(mode="after")
    def page_shape_is_consistent(self) -> CoreEventsPageV1:
        if self.acked_through > self.reserved_through:
            raise ValueError("acked_through exceeds reserved_through")
        previous = 0
        for event in self.events:
            if event.sequence <= previous:
                raise ValueError("page events must be strictly sequence ordered")
            if event.sequence > self.reserved_through:
                raise ValueError("page event exceeds reserved_through")
            previous = event.sequence
        previous_end = 0
        for gap in self.uncovered_gaps:
            if gap.start <= previous_end:
                raise ValueError("transport gaps must be sorted and disjoint")
            if gap.end > self.reserved_through:
                raise ValueError("transport gap exceeds reserved_through")
            previous_end = gap.end
        return self


def decode_events_page(raw: bytes) -> CoreEventsPageV1:
    """Decode one exact bounded observer page; page gap fields remain diagnostic."""
    try:
        return decode_strict(raw, CoreEventsPageV1, MAX_EVENTS_PAGE_BYTES)
    except (TypeError, UnicodeError, ValueError, ValidationError) as error:
        raise PageDecodeError("invalid observer events page") from error


@dataclass(frozen=True)
class PinnedObserverRoot:
    """Independently provisioned epoch-1 observer identity."""

    host_id: str
    key_id: str
    key_epoch: Literal[1]
    public_key: bytes

    @classmethod
    def load(cls, path: Path) -> PinnedObserverRoot:
        """Load the production trust anchor through the hardened root loader."""
        from agmind_immune.observer_trust_root import load_observer_trust_root

        return cls._from_validated_contract(load_observer_trust_root(path))

    @classmethod
    def from_validated_contract_for_test(
        cls,
        contract: ObserverTrustRootV1,
    ) -> PinnedObserverRoot:
        """Construct from an already validated contract in isolated tests only."""
        return cls._from_validated_contract(contract)

    @classmethod
    def _from_validated_contract(
        cls,
        contract: ObserverTrustRootV1,
    ) -> PinnedObserverRoot:
        return cls(
            host_id=contract.host_id,
            key_id=contract.key_id,
            key_epoch=1,
            public_key=bytes.fromhex(contract.public_key),
        )

    def __post_init__(self) -> None:
        if len(self.public_key) != 32:
            raise KeyMetadataError("pinned observer public key is not Ed25519")
        derived = hashlib.sha256(self.public_key).hexdigest()[:32]
        if (
            not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                self.host_id,
            )
            or not re.fullmatch(r"[0-9a-f]{32}", self.key_id)
            or derived != self.key_id
            or self.key_epoch != 1
        ):
            raise KeyMetadataError("pinned observer identity is inconsistent")


class _PublicKeyEpochV1(ContractModel):
    key_id: str
    epoch: int = Field(ge=1, le=MAX_UINT64)
    public_key: str
    transition: KeyTransitionV1 | None = None
    transition_envelope: EventEnvelopeV1 | None = None
    epoch_start_envelope: EventEnvelopeV1 | None = None

    @field_validator("key_id")
    @classmethod
    def key_id_is_exact(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{32}", value):
            raise ValueError("invalid metadata key_id")
        return value

    @field_validator("public_key")
    @classmethod
    def public_key_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("invalid metadata public_key")
        return value


class _PublicKeyMetadataV1(ContractModel):
    schema_version: Literal["agmind.observer-public-keys.v1"]
    host_id: str
    current_key_id: str
    current_epoch: int = Field(ge=1, le=MAX_UINT64)
    keys: list[_PublicKeyEpochV1] = Field(min_length=1, max_length=16)


@dataclass(frozen=True)
class _RotationProof:
    new_epoch: int
    new_key_id: str
    start_event_id: str
    transition_canonical: bytes
    start_canonical: bytes


@dataclass(frozen=True)
class AnchoredPublicKeyChain:
    """A strict metadata proof carrier anchored at the immutable epoch-1 root."""

    root: PinnedObserverRoot
    current_epoch: int
    current_key_id: str
    _keys: tuple[tuple[int, str, bytes], ...]
    _proofs: tuple[tuple[int, _RotationProof], ...]

    @classmethod
    def from_value(
        cls,
        root: PinnedObserverRoot,
        value: bytes | dict[str, object],
        *,
        minimum_epoch: int = 1,
    ) -> AnchoredPublicKeyChain:
        try:
            raw = value if isinstance(value, bytes) else canonical_json(value)
            metadata = decode_strict(
                raw,
                _PublicKeyMetadataV1,
                MAX_PUBLIC_KEY_METADATA_BYTES,
            )
            if raw != canonical_json(metadata):
                raise KeyMetadataError("observer public-key metadata is not canonical JSON")
            return cls._validate(root, metadata, minimum_epoch=minimum_epoch)
        except KeyMetadataError:
            raise
        except (InvalidSignature, TypeError, UnicodeError, ValueError, ValidationError) as error:
            raise KeyMetadataError("observer public-key metadata is not anchored") from error

    @classmethod
    def _validate(
        cls,
        root: PinnedObserverRoot,
        metadata: _PublicKeyMetadataV1,
        *,
        minimum_epoch: int,
    ) -> AnchoredPublicKeyChain:
        if metadata.host_id != root.host_id:
            raise KeyMetadataError("metadata host does not match immutable root")
        keys: list[tuple[int, str, bytes]] = []
        proofs: list[tuple[int, _RotationProof]] = []
        prior_entry: _PublicKeyEpochV1 | None = None
        prior_public: bytes | None = None
        prior_start_sequence = 0
        for index, entry in enumerate(metadata.keys):
            if entry.epoch != index + 1:
                raise KeyMetadataError("metadata epochs are not a complete prefix")
            public_key = bytes.fromhex(entry.public_key)
            if hashlib.sha256(public_key).hexdigest()[:32] != entry.key_id:
                raise KeyMetadataError("metadata key_id does not bind public_key")
            if index == 0:
                if (
                    entry.key_id != root.key_id
                    or entry.public_key != root.public_key.hex()
                    or entry.transition is not None
                    or entry.transition_envelope is not None
                    or entry.epoch_start_envelope is not None
                ):
                    raise KeyMetadataError("epoch 1 does not exactly equal immutable root")
            else:
                if (
                    prior_entry is None
                    or prior_public is None
                    or entry.transition is None
                    or entry.transition_envelope is None
                    or entry.epoch_start_envelope is None
                ):
                    raise KeyMetadataError("later epoch lacks its complete transition proof")
                transition = entry.transition
                transition_envelope = entry.transition_envelope
                start_envelope = entry.epoch_start_envelope
                if (
                    transition.host_id != root.host_id
                    or transition.old_key_id != prior_entry.key_id
                    or transition.new_key_id != entry.key_id
                    or transition.old_epoch != prior_entry.epoch
                    or transition.new_epoch != entry.epoch
                    or transition.new_public_key != entry.public_key
                ):
                    raise KeyMetadataError("transition identity does not bind adjacent epochs")
                verify_key_transition(transition, prior_public)
                cls._validate_transition_envelope(
                    root,
                    prior_entry,
                    transition,
                    transition_envelope,
                    prior_public,
                )
                cls._validate_start_envelope(
                    root,
                    entry,
                    transition_envelope,
                    start_envelope,
                    public_key,
                )
                if (
                    prior_start_sequence != 0
                    and transition_envelope.source_sequence <= prior_start_sequence
                ):
                    raise KeyMetadataError("metadata transition sequence rolled back")
                prior_start_sequence = start_envelope.source_sequence
                proofs.append(
                    (
                        entry.epoch,
                        _RotationProof(
                            new_epoch=transition.new_epoch,
                            new_key_id=transition.new_key_id,
                            start_event_id=start_envelope.event_id,
                            transition_canonical=canonical_json(transition_envelope),
                            start_canonical=canonical_json(start_envelope),
                        ),
                    )
                )
                if (
                    len(canonical_json(transition_envelope)) > MAX_CANONICAL_ENVELOPE_BYTES
                    or len(canonical_json(start_envelope)) > MAX_CANONICAL_ENVELOPE_BYTES
                ):
                    raise KeyMetadataError("metadata proof envelope exceeds 64 KiB")
            keys.append((entry.epoch, entry.key_id, public_key))
            prior_entry = entry
            prior_public = public_key
        final = metadata.keys[-1]
        if metadata.current_epoch != final.epoch or metadata.current_key_id != final.key_id:
            raise KeyMetadataError("metadata current key is not its final proven epoch")
        if minimum_epoch < 1 or metadata.current_epoch < minimum_epoch:
            raise KeyMetadataError("metadata rolled back behind accepted evidence")
        return cls(
            root=root,
            current_epoch=metadata.current_epoch,
            current_key_id=metadata.current_key_id,
            _keys=tuple(keys),
            _proofs=tuple(proofs),
        )

    @staticmethod
    def _empty_security_context(envelope: EventEnvelopeV1) -> bool:
        return (
            envelope.container_id is None
            and envelope.container_start_time is None
            and envelope.release_id is None
            and envelope.inventory_generation == 0
            and envelope.inventory_revision is None
            and envelope.redaction_flags == []
            and envelope.source_payload_hash == envelope.normalized_fields_sha256
        )

    @classmethod
    def _validate_transition_envelope(
        cls,
        root: PinnedObserverRoot,
        prior: _PublicKeyEpochV1,
        transition: KeyTransitionV1,
        envelope: EventEnvelopeV1,
        prior_public: bytes,
    ) -> None:
        if (
            envelope.host_id != root.host_id
            or envelope.event_type != "observer_key_transition"
            or envelope.source_id != "agmind-observerd"
            or envelope.key_id != prior.key_id
            or envelope.key_epoch != prior.epoch
            or envelope.source_sequence < 1
            or canonical_json(envelope.normalized_fields) != canonical_json(transition)
            or not cls._empty_security_context(envelope)
        ):
            raise KeyMetadataError("transition envelope does not bind transition proof")
        verify_event_signature(envelope, prior_public)

    @classmethod
    def _validate_start_envelope(
        cls,
        root: PinnedObserverRoot,
        entry: _PublicKeyEpochV1,
        transition_envelope: EventEnvelopeV1,
        start: EventEnvelopeV1,
        public_key: bytes,
    ) -> None:
        exact_fields = {
            "kind": "observer_key_epoch_start",
            "key_id": entry.key_id,
            "key_epoch": entry.epoch,
        }
        if (
            start.host_id != root.host_id
            or start.event_type != "observer_key_epoch_start"
            or start.source_id != "agmind-observerd"
            or start.key_id != entry.key_id
            or start.key_epoch != entry.epoch
            or start.source_sequence != transition_envelope.source_sequence + 1
            or canonical_json(start.normalized_fields) != canonical_json(exact_fields)
            or not cls._empty_security_context(start)
        ):
            raise KeyMetadataError("epoch-start envelope does not bind candidate key")
        verify_event_signature(start, public_key)
        same_boot = transition_envelope.boot_id == start.boot_id
        same = (
            same_boot
            and transition_envelope.coverage_flags == ["key_rotation"]
            and start.coverage_flags == ["key_rotation"]
        )
        boundary_b = (
            same_boot
            and transition_envelope.coverage_flags == ["boot_transition", "key_rotation"]
            and start.coverage_flags == ["key_rotation"]
        )
        boundary_c = (
            not same_boot
            and transition_envelope.coverage_flags == ["key_rotation"]
            and start.coverage_flags == ["boot_transition", "key_rotation"]
        )
        if not (same or boundary_b or boundary_c):
            raise KeyMetadataError("rotation proof is not exact same-boot, B, or C")

    def key(self, epoch: int, key_id: str) -> bytes:
        for candidate_epoch, candidate_id, public_key in self._keys:
            if candidate_epoch == epoch and candidate_id == key_id:
                return public_key
        raise KeyMetadataError("envelope key is absent from anchored metadata")

    def proof(self, epoch: int) -> _RotationProof:
        for candidate_epoch, proof in self._proofs:
            if candidate_epoch == epoch:
                return proof
        raise KeyMetadataError("candidate epoch has no anchored transition proof")


@dataclass(frozen=True)
class _PendingRotation:
    transition_sequence: int
    transition_boot_id: str
    new_epoch: int
    new_key_id: str
    transition_event_id: str
    expected_start_event_id: str
    mode: Literal["b", "same_or_c"]


@dataclass(frozen=True)
class ObserverStreamFSM:
    """Pure host-global source/key/boot state advanced only after durable append."""

    host_id: str
    active_key_id: str
    active_epoch: int = 1
    current_boot_id: str | None = None
    seen_boot_ids: tuple[str, ...] = ()
    last_sequence: int = 0
    unresolved_holes: tuple[tuple[int, int], ...] = ()
    pending_rotation: _PendingRotation | None = None
    mutation_read_only: bool = False

    def __post_init__(self) -> None:
        if (
            not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                self.host_id,
            )
            or not re.fullmatch(r"[0-9a-f]{32}", self.active_key_id)
            or not 1 <= self.active_epoch <= MAX_UINT64
            or not 0 <= self.last_sequence <= MAX_UINT64
            or len(set(self.seen_boot_ids)) != len(self.seen_boot_ids)
        ):
            raise ValueError("observer stream FSM identity/state is invalid")
        if self.current_boot_id is None:
            if self.seen_boot_ids:
                raise ValueError("observer FSM has history without a current boot")
        elif self.current_boot_id not in self.seen_boot_ids or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            self.current_boot_id,
        ):
            raise ValueError("observer FSM current boot is not in history")
        prior_end = 0
        for start, end in self.unresolved_holes:
            if start <= prior_end or end < start or end > self.last_sequence:
                raise ValueError("observer FSM structural holes are invalid")
            prior_end = end
        pending = self.pending_rotation
        if pending is not None and (
            pending.transition_sequence != self.last_sequence
            or pending.new_epoch != self.active_epoch + 1
            or pending.new_key_id == self.active_key_id
            or pending.transition_boot_id != self.current_boot_id
        ):
            raise ValueError("observer FSM pending rotation is inconsistent")

    def enter_read_only(self) -> ObserverStreamFSM:
        return replace(self, mutation_read_only=True)

    def advance(
        self,
        envelope: EventEnvelopeV1,
        canonical: bytes,
        chain: AnchoredPublicKeyChain,
    ) -> ObserverStreamFSM:
        if self.mutation_read_only:
            raise SequenceError("observer stream is persistently read-only")
        if envelope.source_sequence <= self.last_sequence:
            raise SequenceError("source sequence is not a forward extension")
        if self.pending_rotation is not None:
            return self._finish_rotation(envelope, canonical, chain)

        holes = list(self.unresolved_holes)
        if envelope.source_sequence > self.last_sequence + 1:
            holes.append((self.last_sequence + 1, envelope.source_sequence - 1))

        if envelope.event_type == "observer_key_epoch_start":
            raise BootBoundaryError("epoch start has no immediately preceding transition")

        current_boot = self.current_boot_id
        seen = list(self.seen_boot_ids)
        if envelope.event_type == "observer_key_transition":
            proof = chain.proof(envelope.key_epoch + 1)
            if canonical != proof.transition_canonical:
                raise KeyMetadataError("stream transition differs from anchored proof")
            flags = envelope.coverage_flags
            if flags == ["boot_transition", "key_rotation"]:
                if envelope.boot_id in seen or envelope.boot_id == current_boot:
                    raise BootBoundaryError("B transition did not introduce an unseen boot")
                seen.append(envelope.boot_id)
                current_boot = envelope.boot_id
                mode: Literal["b", "same_or_c"] = "b"
            elif flags == ["key_rotation"]:
                if current_boot is None or envelope.boot_id != current_boot:
                    raise BootBoundaryError("same/C transition is not in the current boot")
                mode = "same_or_c"
            else:
                raise BootBoundaryError("transition flags are not exact B or same/C")
            pending = _PendingRotation(
                transition_sequence=envelope.source_sequence,
                transition_boot_id=envelope.boot_id,
                new_epoch=proof.new_epoch,
                new_key_id=proof.new_key_id,
                transition_event_id=envelope.event_id,
                expected_start_event_id=proof.start_event_id,
                mode=mode,
            )
            return replace(
                self,
                current_boot_id=current_boot,
                seen_boot_ids=tuple(seen),
                last_sequence=envelope.source_sequence,
                unresolved_holes=tuple(holes),
                pending_rotation=pending,
            )

        if current_boot is None or envelope.boot_id != current_boot:
            if envelope.boot_id in seen:
                raise BootBoundaryError("historical boot ID was reused")
            if envelope.event_type != "observer_boot_boundary":
                raise BootBoundaryError("unseen boot did not begin with boundary A, B, or C")
            boundary = ObserverBootBoundaryV1.model_validate(envelope.normalized_fields)
            if current_boot is None:
                if (
                    boundary.reason_code != "observer_genesis"
                    or boundary.previous_boot_id is not None
                    or boundary.previous_source_sequence != 0
                ):
                    raise BootBoundaryError("initial boot boundary is not genesis")
            elif (
                boundary.reason_code != "kernel_boot_id_changed"
                or boundary.previous_boot_id != current_boot
                or not (
                    self.last_sequence
                    <= boundary.previous_source_sequence
                    < envelope.source_sequence
                )
            ):
                raise BootBoundaryError("changed-boot boundary predecessor mismatch")
            seen.append(envelope.boot_id)
            current_boot = envelope.boot_id
        elif "boot_transition" in envelope.coverage_flags:
            raise BootBoundaryError("current-boot event falsely claims a boot transition")

        holes = self._apply_gap_proof(envelope, holes)
        return replace(
            self,
            current_boot_id=current_boot,
            seen_boot_ids=tuple(seen),
            last_sequence=envelope.source_sequence,
            unresolved_holes=tuple(holes),
        )

    def _finish_rotation(
        self,
        envelope: EventEnvelopeV1,
        canonical: bytes,
        chain: AnchoredPublicKeyChain,
    ) -> ObserverStreamFSM:
        pending = self.pending_rotation
        assert pending is not None
        if (
            envelope.source_sequence != pending.transition_sequence + 1
            or envelope.event_type != "observer_key_epoch_start"
            or envelope.key_epoch != pending.new_epoch
            or envelope.key_id != pending.new_key_id
        ):
            raise SequenceError("no event or gap may intervene in key activation")
        proof = chain.proof(pending.new_epoch)
        if (
            envelope.event_id != pending.expected_start_event_id
            or canonical != proof.start_canonical
        ):
            raise KeyMetadataError("stream epoch start differs from anchored proof")
        current_boot = self.current_boot_id
        seen = list(self.seen_boot_ids)
        if pending.mode == "b":
            if envelope.boot_id != pending.transition_boot_id or envelope.coverage_flags != [
                "key_rotation"
            ]:
                raise BootBoundaryError("B epoch start must remain adjacent in its new boot")
        elif envelope.boot_id == pending.transition_boot_id:
            if envelope.coverage_flags != ["key_rotation"]:
                raise BootBoundaryError("same-boot epoch start has incorrect flags")
        else:
            if (
                envelope.coverage_flags != ["boot_transition", "key_rotation"]
                or envelope.boot_id in seen
            ):
                raise BootBoundaryError("C epoch start did not introduce one unseen boot")
            seen.append(envelope.boot_id)
            current_boot = envelope.boot_id
        return replace(
            self,
            active_key_id=pending.new_key_id,
            active_epoch=pending.new_epoch,
            current_boot_id=current_boot,
            seen_boot_ids=tuple(seen),
            last_sequence=envelope.source_sequence,
            pending_rotation=None,
        )

    @staticmethod
    def _apply_gap_proof(
        envelope: EventEnvelopeV1,
        holes: list[tuple[int, int]],
    ) -> list[tuple[int, int]]:
        fields = envelope.normalized_fields
        if (
            envelope.event_type == "coverage"
            and fields.get("kind") == "observer_sequence_gap"
            and fields.get("severity") == "CRITICAL"
            and fields.get("reason_code") == "reserved_sequence_not_published"
            and set(fields)
            == {
                "component",
                "kind",
                "severity",
                "opened_at",
                "affected_source_sequence_start",
                "affected_source_sequence_end",
                "reason_code",
            }
            and envelope.event_time == fields.get("opened_at")
            and envelope.inventory_generation == 0
            and envelope.container_id is None
            and envelope.container_start_time is None
            and envelope.release_id is None
            and envelope.inventory_revision is None
            and envelope.redaction_flags == []
            and envelope.coverage_flags == ["reconcile_required", "sequence_gap"]
            and envelope.source_payload_hash == envelope.normalized_fields_sha256
        ):
            candidate = (
                fields.get("affected_source_sequence_start"),
                fields.get("affected_source_sequence_end"),
            )
            if candidate not in holes:
                raise SequenceError("signed gap proof does not exactly cover one structural hole")
            holes.remove(candidate)
        return holes


class VerifiedEnvelope:
    """Immutable presentation of a verifier-owned staged acceptance."""

    _canonical: bytes
    _content_sha256: str
    _event_id: str
    _evidence_priority: Literal["routine", "protected"]
    _is_retry: bool
    _key_epoch: int
    _key_id: str
    _source_sequence: int

    __slots__ = (
        "__weakref__",
        "_canonical",
        "_content_sha256",
        "_event_id",
        "_evidence_priority",
        "_is_retry",
        "_key_epoch",
        "_key_id",
        "_source_sequence",
    )

    def __init__(
        self,
        *,
        canonical: bytes,
        content_sha256: str,
        event_id: str,
        evidence_priority: Literal["routine", "protected"],
        is_retry: bool = False,
        key_epoch: int,
        key_id: str,
        source_sequence: int,
    ) -> None:
        object.__setattr__(self, "_canonical", canonical)
        object.__setattr__(self, "_content_sha256", content_sha256)
        object.__setattr__(self, "_event_id", event_id)
        object.__setattr__(self, "_evidence_priority", evidence_priority)
        object.__setattr__(self, "_is_retry", is_retry)
        object.__setattr__(self, "_key_epoch", key_epoch)
        object.__setattr__(self, "_key_id", key_id)
        object.__setattr__(self, "_source_sequence", source_sequence)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("VerifiedEnvelope is immutable")

    @property
    def canonical(self) -> bytes:
        return self._canonical

    @property
    def content_sha256(self) -> str:
        return self._content_sha256

    @property
    def event_id(self) -> str:
        return self._event_id

    @property
    def evidence_priority(self) -> Literal["routine", "protected"]:
        return self._evidence_priority

    @property
    def is_retry(self) -> bool:
        return self._is_retry

    @property
    def key_epoch(self) -> int:
        return self._key_epoch

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def source_sequence(self) -> int:
        return self._source_sequence


@dataclass(frozen=True)
class _AcceptedEnvelope:
    canonical: bytes
    evidence_ref: object
    evidence_priority: Literal["routine", "protected"]
    key_epoch: int
    key_id: str


@dataclass(frozen=True)
class _VerifierAuthorityState:
    fsm: ObserverStreamFSM
    accepted: Mapping[int, _AcceptedEnvelope]
    generation: int


@dataclass(frozen=True)
class _StagedEnvelope:
    owner: weakref.ReferenceType[VerifiedEnvelope]
    canonical: bytes
    content_sha256: str
    event_id: str
    evidence_priority: Literal["routine", "protected"]
    is_retry: bool
    key_epoch: int
    key_id: str
    source_sequence: int
    base_generation: int
    next_fsm: ObserverStreamFSM
    existing_ref: object | None


@dataclass(frozen=True)
class _AppendAuthorization:
    stage_id: int
    canonical: bytes
    content_sha256: str
    event_id: str
    evidence_priority: Literal["routine", "protected"]
    host_id: str
    is_retry: bool
    source_sequence: int


@dataclass(frozen=True)
class _SimulationAcceptedEnvelope:
    canonical: bytes
    content_sha256: str
    evidence_priority: Literal["routine", "protected"]
    event_id: str
    event_type: str
    key_epoch: int
    key_id: str


@dataclass(frozen=True)
class _RepairAuthoritySnapshot:
    root: PinnedObserverRoot
    key_chain: AnchoredPublicKeyChain
    fsm: ObserverStreamFSM
    accepted: tuple[tuple[int, _SimulationAcceptedEnvelope], ...]
    generation: int


_CONTROL_SIMULATION_FACTORY = object()
_REPAIR_SIMULATION_FACTORY = _CONTROL_SIMULATION_FACTORY
_MAX_CONTROL_SIMULATION_EVENTS = 4096
_MAX_REPAIR_SIMULATION_EVENTS = _MAX_CONTROL_SIMULATION_EVENTS


@final
class SimulatedEvent:
    """Non-appendable result of one private repair verifier transition."""

    _canonical_envelope: bytes
    _content_sha256: str
    _event_id: str
    _event_type: str
    _evidence_priority: Literal["routine", "protected"]
    _is_retry: bool
    _key_epoch: int
    _key_id: str
    _normalized_fields_canonical: bytes
    _sequence: int
    _simulation_identity: object

    __slots__ = (
        "_canonical_envelope",
        "_content_sha256",
        "_event_id",
        "_event_type",
        "_evidence_priority",
        "_is_retry",
        "_key_epoch",
        "_key_id",
        "_normalized_fields_canonical",
        "_sequence",
        "_simulation_identity",
    )

    def __init__(
        self,
        *,
        canonical_envelope: bytes,
        content_sha256: str,
        event_id: str,
        event_type: str,
        evidence_priority: Literal["routine", "protected"],
        is_retry: bool,
        key_epoch: int,
        key_id: str,
        normalized_fields_canonical: bytes,
        sequence: int,
        simulation_identity: object,
        _factory: object,
    ) -> None:
        if _factory is not _REPAIR_SIMULATION_FACTORY:
            raise TypeError("SimulatedEvent is factory-only")
        object.__setattr__(self, "_canonical_envelope", canonical_envelope)
        object.__setattr__(self, "_content_sha256", content_sha256)
        object.__setattr__(self, "_event_id", event_id)
        object.__setattr__(self, "_event_type", event_type)
        object.__setattr__(self, "_evidence_priority", evidence_priority)
        object.__setattr__(self, "_is_retry", is_retry)
        object.__setattr__(self, "_key_epoch", key_epoch)
        object.__setattr__(self, "_key_id", key_id)
        object.__setattr__(
            self,
            "_normalized_fields_canonical",
            normalized_fields_canonical,
        )
        object.__setattr__(self, "_sequence", sequence)
        object.__setattr__(self, "_simulation_identity", simulation_identity)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("SimulatedEvent is final")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SimulatedEvent is immutable")

    @property
    def content_sha256(self) -> str:
        return self._content_sha256

    @property
    def event_id(self) -> str:
        return self._event_id

    @property
    def event_type(self) -> str:
        return self._event_type

    @property
    def evidence_priority(self) -> Literal["routine", "protected"]:
        return self._evidence_priority

    @property
    def is_retry(self) -> bool:
        return self._is_retry

    @property
    def key_epoch(self) -> int:
        return self._key_epoch

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def source_sequence(self) -> int:
        return self._sequence


def _simulated_event_binding(
    target: SimulatedEvent,
) -> tuple[object, ...]:
    return (
        target._canonical_envelope,
        target.content_sha256,
        target.event_id,
        target.event_type,
        target.evidence_priority,
        target.is_retry,
        target.key_epoch,
        target.key_id,
        target._normalized_fields_canonical,
        target.sequence,
        target._simulation_identity,
    )


def _control_path_sha256(path_canonical: tuple[bytes, ...]) -> str:
    digest = hashlib.sha256(b"agmind.control-simulation-path.v1\0")
    for raw in path_canonical:
        if type(raw) is not bytes:
            raise VerifierCommitError(
                "control simulation path has a non-exact byte item"
            )
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


class _SimulatedControlProof:
    _base_authorization_ids: tuple[int, ...]
    _base_authority: _RepairAuthoritySnapshot
    _base_generation: int
    _base_stage_ids: tuple[int, ...]
    _base_transient_generation: int
    _factory_marker: object
    _lifecycle_identity: object
    _owner: object
    _owner_identity: object
    _path_sha256: str | None
    _predicted_generation: int
    _request_canonical: bytes
    _target: SimulatedEvent
    _target_binding: tuple[object, ...]
    _verifier_identity: object

    __slots__ = (
        "_base_authority",
        "_base_authorization_ids",
        "_base_generation",
        "_base_stage_ids",
        "_base_transient_generation",
        "_factory_marker",
        "_lifecycle_identity",
        "_owner",
        "_owner_identity",
        "_path_sha256",
        "_predicted_generation",
        "_request_canonical",
        "_target",
        "_target_binding",
        "_verifier_identity",
    )

    _request_type: type[
        EvidenceRepairAuthorizeV1
        | EvidenceRepairCompleteV1
        | RetentionTombstoneV2
        | RetentionBlockedV1
    ]

    def __init__(
        self,
        *,
        base_authorization_ids: tuple[int, ...],
        base_authority: _RepairAuthoritySnapshot,
        base_stage_ids: tuple[int, ...],
        base_transient_generation: int,
        lifecycle_identity: object,
        owner: object,
        owner_identity: object,
        path_sha256: str | None,
        predicted_generation: int,
        request_canonical: bytes,
        target: SimulatedEvent,
        verifier_identity: object,
        _factory: object,
    ) -> None:
        if _factory is not _REPAIR_SIMULATION_FACTORY:
            raise TypeError(f"{type(self).__name__} is factory-only")
        object.__setattr__(
            self,
            "_base_authorization_ids",
            base_authorization_ids,
        )
        object.__setattr__(self, "_base_authority", base_authority)
        object.__setattr__(self, "_base_generation", base_authority.generation)
        object.__setattr__(self, "_base_stage_ids", base_stage_ids)
        object.__setattr__(
            self,
            "_base_transient_generation",
            base_transient_generation,
        )
        object.__setattr__(self, "_factory_marker", _factory)
        object.__setattr__(self, "_lifecycle_identity", lifecycle_identity)
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_owner_identity", owner_identity)
        object.__setattr__(self, "_path_sha256", path_sha256)
        object.__setattr__(
            self,
            "_predicted_generation",
            predicted_generation,
        )
        object.__setattr__(self, "_request_canonical", request_canonical)
        object.__setattr__(self, "_target", target)
        object.__setattr__(
            self,
            "_target_binding",
            _simulated_event_binding(target),
        )
        object.__setattr__(self, "_verifier_identity", verifier_identity)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __copy__(self) -> Never:
        raise TypeError("control simulation proofs cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        del memo
        raise TypeError("control simulation proofs cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("control simulation proofs cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("control simulation proofs cannot be serialized")

    @property
    def base_generation(self) -> int:
        return self._base_generation

    @property
    def predicted_generation(self) -> int:
        return self._predicted_generation

    @property
    def request(
        self,
    ) -> (
        EvidenceRepairAuthorizeV1
        | EvidenceRepairCompleteV1
        | RetentionTombstoneV2
        | RetentionBlockedV1
    ):
        return self._request_type.model_validate_json(
            self._request_canonical,
            strict=True,
        )

    @property
    def target(self) -> SimulatedEvent:
        return self._target


@final
class SimulatedRepairAuthorization(_SimulatedControlProof):
    """Exact signed authorization preview with no evidence append authority."""

    __slots__ = ()
    _request_type = EvidenceRepairAuthorizeV1

    @property
    def request(self) -> EvidenceRepairAuthorizeV1:
        value = super().request
        assert isinstance(value, EvidenceRepairAuthorizeV1)
        return value


@final
class SimulatedRepairCompletion(_SimulatedControlProof):
    """Exact signed completion preview with no evidence append authority."""

    __slots__ = ()
    _request_type = EvidenceRepairCompleteV1

    @property
    def request(self) -> EvidenceRepairCompleteV1:
        value = super().request
        assert isinstance(value, EvidenceRepairCompleteV1)
        return value


@final
class SimulatedRetentionTombstone(_SimulatedControlProof):
    """Exact signed tombstone preview with no evidence append authority."""

    __slots__ = ()
    _request_type = RetentionTombstoneV2

    @property
    def request(self) -> RetentionTombstoneV2:
        value = super().request
        assert isinstance(value, RetentionTombstoneV2)
        return value


@final
class SimulatedRetentionBlocked(_SimulatedControlProof):
    """Exact signed blocked preview with no evidence append authority."""

    __slots__ = ()
    _request_type = RetentionBlockedV1

    @property
    def request(self) -> RetentionBlockedV1:
        value = super().request
        assert isinstance(value, RetentionBlockedV1)
        return value


@dataclass(frozen=True)
class _IssuedControlProofBinding:
    proof: _SimulatedControlProof
    target: SimulatedEvent
    path_canonical: tuple[bytes, ...] | None
    path_sha256: str | None
    factory_marker: object
    base_authority: _RepairAuthoritySnapshot
    base_authorization_ids: tuple[int, ...]
    base_generation: int
    base_stage_ids: tuple[int, ...]
    base_transient_generation: int
    lifecycle_identity: object
    owner: object
    owner_identity: object
    predicted_generation: int
    request_canonical: bytes
    target_binding: tuple[object, ...]
    target_presentation: tuple[object, ...]
    verifier_identity: object


_PROTECTED_EVENT_TYPES = frozenset(
    {
        "corruption",
        "coverage",
        "incident_action_mirror",
        "observer_boot_boundary",
        "observer_key_epoch_start",
        "observer_key_transition",
        "observer_start",
        "evidence_repair_authorized",
        "evidence_repair_completed",
        "retention_blocked_priority_evidence",
        "retention_tombstone",
    }
)


class EnvelopeVerifier:
    """Stages signed stream transitions and commits them only after durable evidence."""

    def __init__(
        self,
        root: PinnedObserverRoot,
        key_chain: AnchoredPublicKeyChain,
    ) -> None:
        if key_chain.root != root:
            raise KeyMetadataError("key chain is not bound to supplied immutable root")
        self.root = root
        self.key_chain = key_chain
        self._authority = _VerifierAuthorityState(
            fsm=ObserverStreamFSM(
                host_id=root.host_id,
                active_key_id=root.key_id,
            ),
            accepted=MappingProxyType({}),
            generation=0,
        )
        self._staged: dict[int, _StagedEnvelope] = {}
        self._authorizations: dict[int, _AppendAuthorization] = {}
        self._bound_lifecycle: object | None = None
        self._repair_lifecycle_identity: object | None = None
        self._repair_owner_identity = object()
        self._repair_transient_generation = 0
        self._retention_recovery_open = False
        self._retention_recovery_consumed = False
        self._provisional_retention_omissions: tuple[
            tuple[str, int, int, int],
            ...,
        ] = ()

    @property
    def fsm(self) -> ObserverStreamFSM:
        return self._authority.fsm

    def _bind_lifecycle(self, lifecycle: object) -> None:
        if self._bound_lifecycle is not None:
            raise VerifierCommitError("verifier is already bound to one store lifecycle")
        genesis = ObserverStreamFSM(
            host_id=self.root.host_id,
            active_key_id=self.root.key_id,
        )
        if (
            self._authority.generation != 0
            or self._authority.accepted
            or self._staged
            or self._authorizations
            or self._authority.fsm != genesis
        ):
            raise VerifierCommitError("store factories require a pristine epoch-1 verifier")
        self._bound_lifecycle = lifecycle
        self._repair_lifecycle_identity = object()

    def _begin_retention_recovery(self, lifecycle: object) -> None:
        if (
            lifecycle is not self._bound_lifecycle
            or self._bound_lifecycle is None
            or self._retention_recovery_open
            or self._retention_recovery_consumed
            or self._provisional_retention_omissions
            or self._staged
            or self._authorizations
        ):
            raise VerifierCommitError(
                "retention recovery cannot begin in this verifier lifecycle"
            )
        self._retention_recovery_open = True

    def _recover_dense_routine_omission(
        self,
        *,
        manifest_sha256: str,
        first_sequence: int,
        last_sequence: int,
        record_count: int,
        lifecycle: object,
    ) -> None:
        """Provisionally replay one dense routine manifest without fake records."""
        authority = self._authority
        fsm = authority.fsm
        if (
            lifecycle is not self._bound_lifecycle
            or self._bound_lifecycle is None
            or not self._retention_recovery_open
            or self._staged
            or self._authorizations
            or type(manifest_sha256) is not str
            or _HEX64.fullmatch(manifest_sha256) is None
            or type(first_sequence) is not int
            or type(last_sequence) is not int
            or type(record_count) is not int
            or not 1 <= first_sequence <= last_sequence <= MAX_UINT64
            or record_count != last_sequence - first_sequence + 1
            or first_sequence <= fsm.last_sequence
            or fsm.current_boot_id is None
            or fsm.pending_rotation is not None
            or fsm.mutation_read_only
            or authority.generation > MAX_UINT64 - record_count
        ):
            raise VerifierCommitError(
                "dense retention omission is outside recovering verifier authority"
            )
        holes = list(fsm.unresolved_holes)
        if first_sequence > fsm.last_sequence + 1:
            holes.append((fsm.last_sequence + 1, first_sequence - 1))
        self._authority = _VerifierAuthorityState(
            fsm=replace(
                fsm,
                last_sequence=last_sequence,
                unresolved_holes=tuple(holes),
            ),
            accepted=authority.accepted,
            generation=authority.generation + record_count,
        )
        self._provisional_retention_omissions += (
            (
                manifest_sha256,
                first_sequence,
                last_sequence,
                record_count,
            ),
        )

    def _commit_retention_recovery(
        self,
        omissions: tuple[tuple[str, int, int, int], ...],
        lifecycle: object,
    ) -> None:
        if (
            lifecycle is not self._bound_lifecycle
            or self._bound_lifecycle is None
            or not self._retention_recovery_open
            or type(omissions) is not tuple
            or omissions != self._provisional_retention_omissions
            or self._staged
            or self._authorizations
        ):
            raise VerifierCommitError(
                "retention recovery did not consume exact provisional omissions"
            )
        self._provisional_retention_omissions = ()
        self._retention_recovery_open = False
        self._retention_recovery_consumed = True

    def _seal_retention_recovery(self, lifecycle: object) -> None:
        if (
            lifecycle is not self._bound_lifecycle
            or self._bound_lifecycle is None
            or self._retention_recovery_open
            or self._retention_recovery_consumed
            or self._provisional_retention_omissions
            or self._staged
            or self._authorizations
        ):
            raise VerifierCommitError(
                "retention recovery cannot be sealed in this verifier lifecycle"
            )
        self._retention_recovery_consumed = True

    def verify(
        self,
        envelope_value: object,
        *,
        sequence: int,
        event_id: str,
        content_sha256: str,
    ) -> VerifiedEnvelope:
        if not isinstance(envelope_value, dict):
            raise OuterBindingError("outer envelope is not an object")
        if any(value is None for value in envelope_value.values()):
            raise OuterBindingError("top-level envelope null is forbidden")
        try:
            canonical = canonical_json(envelope_value)
        except (TypeError, ValueError) as error:
            raise OuterBindingError("envelope is not canonicalizable") from error
        if len(canonical) > MAX_CANONICAL_ENVELOPE_BYTES:
            raise OuterBindingError("canonical envelope exceeds 64 KiB")
        digest = hashlib.sha256(canonical).hexdigest()
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or not 1 <= sequence <= MAX_UINT64
            or envelope_value.get("source_sequence") != sequence
            or envelope_value.get("event_id") != event_id
            or digest != content_sha256
        ):
            raise OuterBindingError("outer item does not exactly bind canonical envelope")

        accepted = self._authority.accepted.get(sequence)
        if accepted is not None and accepted.canonical == canonical:
            try:
                envelope = EventEnvelopeV1.model_validate(envelope_value, strict=True)
            except ValidationError as error:
                raise OuterBindingError("accepted retry no longer decodes identically") from error
            return self._stage(
                canonical=canonical,
                content_sha256=digest,
                envelope=envelope,
                evidence_priority=accepted.evidence_priority,
                is_retry=True,
                next_fsm=self._authority.fsm,
                existing_ref=accepted.evidence_ref,
            )

        self._precheck_signed_content(envelope_value)
        event_type = envelope_value["event_type"]
        source_sequence = envelope_value["source_sequence"]
        key_epoch = envelope_value["key_epoch"]
        key_id = envelope_value["key_id"]
        if (
            not isinstance(event_type, str)
            or not isinstance(source_sequence, int)
            or isinstance(source_sequence, bool)
            or not isinstance(key_epoch, int)
            or isinstance(key_epoch, bool)
            or not isinstance(key_id, str)
        ):
            raise EnvelopeIdentityError("envelope key/sequence identity has invalid types")
        public_key = self._select_verification_key(
            event_type=event_type,
            source_sequence=source_sequence,
            key_epoch=key_epoch,
            key_id=key_id,
            historical=accepted,
        )
        try:
            verify_event_signature(envelope_value, public_key)
        except (InvalidSignature, TypeError, ValueError) as error:
            raise EnvelopeSignatureError("observer envelope signature is invalid") from error

        try:
            envelope = EventEnvelopeV1.model_validate(envelope_value, strict=True)
        except ValidationError as error:
            raise OuterBindingError("signed envelope contract is invalid") from error
        if envelope.host_id != self.root.host_id or envelope.source_id != "agmind-observerd":
            raise EnvelopeIdentityError("envelope is not from the pinned observer host/source")

        self._validate_special_semantics(envelope)

        if accepted is not None:
            raise EnvelopeConflict(f"valid signed conflict at ({self.root.host_id}, {sequence})")
        next_fsm = self._authority.fsm.advance(envelope, canonical, self.key_chain)
        evidence_priority: Literal["routine", "protected"] = (
            "protected" if envelope.event_type in _PROTECTED_EVENT_TYPES else "routine"
        )
        return self._stage(
            canonical=canonical,
            content_sha256=digest,
            envelope=envelope,
            evidence_priority=evidence_priority,
            next_fsm=next_fsm,
        )

    def _stage(
        self,
        *,
        canonical: bytes,
        content_sha256: str,
        envelope: EventEnvelopeV1,
        evidence_priority: Literal["routine", "protected"],
        next_fsm: ObserverStreamFSM,
        is_retry: bool = False,
        existing_ref: object | None = None,
    ) -> VerifiedEnvelope:
        verified = VerifiedEnvelope(
            canonical=canonical,
            content_sha256=content_sha256,
            event_id=envelope.event_id,
            evidence_priority=evidence_priority,
            is_retry=is_retry,
            key_epoch=envelope.key_epoch,
            key_id=envelope.key_id,
            source_sequence=envelope.source_sequence,
        )
        stage_id = id(verified)
        self._repair_transient_generation += 1
        self._staged[stage_id] = _StagedEnvelope(
            owner=weakref.ref(verified),
            canonical=canonical,
            content_sha256=content_sha256,
            event_id=envelope.event_id,
            evidence_priority=evidence_priority,
            is_retry=is_retry,
            key_epoch=envelope.key_epoch,
            key_id=envelope.key_id,
            source_sequence=envelope.source_sequence,
            base_generation=self._authority.generation,
            next_fsm=next_fsm,
            existing_ref=existing_ref,
        )
        self._prune_staged()
        return verified

    def _prune_staged(self) -> None:
        dead = [
            stage_id
            for stage_id, stage in self._staged.items()
            if (stage.owner() is None or stage.base_generation != self._authority.generation)
        ]
        for stage_id in dead:
            self._staged.pop(stage_id, None)
        if len(self._staged) > 128:
            for stage_id in tuple(self._staged)[: len(self._staged) - 128]:
                self._staged.pop(stage_id, None)

    @staticmethod
    def _precheck_signed_content(envelope_value: dict[str, Any]) -> None:
        allowed = set(EventEnvelopeV1.model_fields)
        required = {
            name for name, field in EventEnvelopeV1.model_fields.items() if field.is_required()
        }
        actual = set(envelope_value)
        if actual - allowed or required - actual:
            raise OuterBindingError("signed envelope does not have the exact v1 shape")
        if envelope_value.get("schema_version") != "agmind.event-envelope.v1":
            raise OuterBindingError("unsupported signed envelope version")
        fields = envelope_value.get("normalized_fields")
        digest = envelope_value.get("normalized_fields_sha256")
        if not isinstance(fields, dict) or not isinstance(digest, str):
            raise OuterBindingError("normalized signed fields have invalid types")
        normalized = canonical_json(fields)
        if (
            len(normalized) > 32 * 1024
            or not _HEX64.fullmatch(digest)
            or hashlib.sha256(normalized).hexdigest() != digest
        ):
            raise OuterBindingError("normalized signed fields do not match their digest")

    def _select_verification_key(
        self,
        *,
        event_type: str,
        source_sequence: int,
        key_epoch: int,
        key_id: str,
        historical: _AcceptedEnvelope | None,
    ) -> bytes:
        pending = self._authority.fsm.pending_rotation
        if (
            pending is not None
            and event_type == "observer_key_epoch_start"
            and source_sequence == pending.transition_sequence + 1
        ):
            expected_epoch = pending.new_epoch
            expected_key_id = pending.new_key_id
        elif historical is not None:
            expected_epoch = historical.key_epoch
            expected_key_id = historical.key_id
        else:
            expected_epoch = self._authority.fsm.active_epoch
            expected_key_id = self._authority.fsm.active_key_id
        if key_epoch != expected_epoch or key_id != expected_key_id:
            raise EnvelopeIdentityError("envelope key is not active at this stream position")
        return self.key_chain.key(expected_epoch, expected_key_id)

    @staticmethod
    def _empty_security_context(envelope: EventEnvelopeV1) -> bool:
        return (
            envelope.container_id is None
            and envelope.container_start_time is None
            and envelope.release_id is None
            and envelope.inventory_generation == 0
            and envelope.inventory_revision is None
            and envelope.redaction_flags == []
            and envelope.source_payload_hash == envelope.normalized_fields_sha256
        )

    @classmethod
    def _empty_core_operation_context(cls, envelope: EventEnvelopeV1) -> bool:
        return (
            envelope.source_id == "agmind-observerd"
            and envelope.clock_uncertainty_ms == 0
            and envelope.coverage_flags == []
            and not {
                "container_id",
                "container_start_time",
                "release_id",
                "inventory_revision",
            }
            & envelope.model_fields_set
            and cls._empty_security_context(envelope)
        )

    @classmethod
    def _validate_special_semantics(cls, envelope: EventEnvelopeV1) -> None:
        try:
            if envelope.event_type == "evidence_repair_authorized":
                EvidenceRepairAuthorizeV1.model_validate(
                    envelope.normalized_fields,
                    strict=True,
                )
                if not cls._empty_core_operation_context(envelope):
                    raise ValueError("invalid evidence-repair authorization context")
            elif envelope.event_type == "evidence_repair_completed":
                EvidenceRepairCompleteV1.model_validate(
                    envelope.normalized_fields,
                    strict=True,
                )
                if not cls._empty_core_operation_context(envelope):
                    raise ValueError("invalid evidence-repair completion context")
            elif envelope.event_type == "retention_tombstone":
                RetentionTombstoneV2.model_validate(
                    envelope.normalized_fields,
                    strict=True,
                )
                if not cls._empty_core_operation_context(envelope):
                    raise ValueError("invalid retention-tombstone context")
            elif envelope.event_type == "retention_blocked_priority_evidence":
                RetentionBlockedV1.model_validate(
                    envelope.normalized_fields,
                    strict=True,
                )
                if not cls._empty_core_operation_context(envelope):
                    raise ValueError("invalid retention-blocked context")
            elif envelope.event_type == "observer_boot_boundary":
                ObserverBootBoundaryV1.model_validate(envelope.normalized_fields, strict=True)
                if not cls._empty_security_context(envelope) or envelope.coverage_flags != [
                    "boot_transition",
                    "reconcile_required",
                ]:
                    raise ValueError("invalid dedicated boot-boundary context")
            elif envelope.event_type == "observer_key_transition":
                KeyTransitionV1.model_validate(envelope.normalized_fields, strict=True)
                if not cls._empty_security_context(envelope):
                    raise ValueError("invalid key-transition context")
            elif envelope.event_type == "observer_key_epoch_start":
                if (
                    set(envelope.normalized_fields) != {"kind", "key_id", "key_epoch"}
                    or envelope.normalized_fields.get("kind") != "observer_key_epoch_start"
                    or envelope.normalized_fields.get("key_id") != envelope.key_id
                    or envelope.normalized_fields.get("key_epoch") != envelope.key_epoch
                    or not cls._empty_security_context(envelope)
                ):
                    raise ValueError("invalid epoch-start context")
            elif envelope.event_type == "coverage":
                coverage = CoverageEventV1.model_validate(
                    envelope.normalized_fields,
                    strict=True,
                )
                if coverage.kind == "observer_sequence_gap":
                    open_required = {
                        "component",
                        "kind",
                        "severity",
                        "opened_at",
                        "affected_source_sequence_start",
                        "affected_source_sequence_end",
                        "reason_code",
                    }
                    close_required = open_required | {
                        "closed_at",
                        "reconcile_generation",
                    }
                    common = (
                        coverage.component == "observer"
                        and coverage.affected_source_sequence_start is not None
                        and coverage.affected_source_sequence_end is not None
                        and envelope.container_id is None
                        and envelope.container_start_time is None
                        and envelope.release_id is None
                        and envelope.inventory_revision is None
                        and envelope.redaction_flags == []
                        and envelope.coverage_flags == ["reconcile_required", "sequence_gap"]
                        and envelope.source_payload_hash == envelope.normalized_fields_sha256
                    )
                    exact_open = (
                        set(envelope.normalized_fields) == open_required
                        and coverage.severity == "CRITICAL"
                        and coverage.reason_code == "reserved_sequence_not_published"
                        and coverage.closed_at is None
                        and coverage.reconcile_generation is None
                        and envelope.event_time == coverage.opened_at
                        and envelope.inventory_generation == 0
                    )
                    exact_close = (
                        set(envelope.normalized_fields) == close_required
                        and coverage.severity == "INFO"
                        and coverage.reason_code == "reserved_sequence_reconciled"
                        and coverage.closed_at is not None
                        and coverage.reconcile_generation is not None
                        and coverage.reconcile_generation > 0
                        and envelope.event_time == coverage.closed_at
                        and envelope.inventory_generation == coverage.reconcile_generation
                    )
                    if not common or not (exact_open or exact_close):
                        raise ValueError("invalid signed sequence-gap proof")
            elif envelope.event_type == "observer_start":
                if (
                    envelope.normalized_fields
                    != {"kind": "observer_start", "reconcile_required": True}
                    or envelope.coverage_flags != ["reconcile_required"]
                    or not cls._empty_security_context(envelope)
                ):
                    raise ValueError("invalid observer-start semantics")
            elif envelope.event_type == "falco_connect":
                falco = FalcoConnectV1.model_validate(
                    envelope.normalized_fields,
                    strict=True,
                )
                if falco.raw_event_sha256 != envelope.source_payload_hash:
                    raise ValueError("Falco raw event hash is not source_payload_hash")
                if falco.docker_container_id != envelope.container_id:
                    raise ValueError("Falco Docker identity is not bound to envelope")
                if falco.docker_started_at != envelope.container_start_time:
                    raise ValueError("Falco container start is not bound to envelope")
                if falco.inventory_revision != envelope.inventory_revision:
                    raise ValueError("Falco inventory revision is not bound to envelope")
                if falco.image_id is not None and falco.immutable_spec_sha256 is not None:
                    if envelope.release_id != derive_release_id(
                        falco.image_id,
                        falco.immutable_spec_sha256,
                    ):
                        raise ValueError("Falco release identity is not bound to envelope")
                elif envelope.release_id is not None:
                    raise ValueError("Falco envelope has an ungrounded release identity")
        except (TypeError, ValueError, ValidationError) as error:
            raise OuterBindingError("event-specific signed semantics are invalid") from error

    def _authorize_append(
        self,
        verified: VerifiedEnvelope,
        lifecycle: object,
        evidence_priority: str,
    ) -> _AppendAuthorization:
        if lifecycle is not self._bound_lifecycle:
            raise VerifierCommitError("staged envelope belongs to another store lifecycle")
        stage = self._staged.get(id(verified))
        if stage is None or stage.owner() is not verified:
            raise VerifierCommitError("envelope is not an exact live staged object")
        presentation = (
            verified.canonical,
            verified.content_sha256,
            verified.event_id,
            verified.evidence_priority,
            verified.is_retry,
            verified.key_epoch,
            verified.key_id,
            verified.source_sequence,
        )
        authoritative = (
            stage.canonical,
            stage.content_sha256,
            stage.event_id,
            stage.evidence_priority,
            stage.is_retry,
            stage.key_epoch,
            stage.key_id,
            stage.source_sequence,
        )
        if presentation != authoritative:
            raise VerifierCommitError("staged envelope presentation was mutated")
        if stage.base_generation != self._authority.generation:
            raise VerifierCommitError("staged verifier transition is stale")
        if evidence_priority != stage.evidence_priority:
            raise VerifierCommitError("evidence priority is not verifier-derived")
        envelope = EventEnvelopeV1.model_validate_json(stage.canonical, strict=True)
        authorization = _AppendAuthorization(
            stage_id=id(verified),
            canonical=stage.canonical,
            content_sha256=stage.content_sha256,
            event_id=stage.event_id,
            evidence_priority=stage.evidence_priority,
            host_id=envelope.host_id,
            is_retry=stage.is_retry,
            source_sequence=stage.source_sequence,
        )
        self._authorizations[id(authorization)] = authorization
        return authorization

    def _commit_durable(
        self,
        authorization: _AppendAuthorization,
        lifecycle: object,
        evidence_ref: object,
    ) -> None:
        if (
            lifecycle is not self._bound_lifecycle
            or self._authorizations.get(id(authorization)) is not authorization
        ):
            raise VerifierCommitError("append authorization is not live for this store")
        authority = self._authority
        stage = self._staged.get(authorization.stage_id)
        if (
            stage is None
            or stage.owner() is None
            or stage.base_generation != authority.generation
            or authorization.canonical != stage.canonical
        ):
            raise VerifierCommitError("durable commit does not match a live stage")
        if (
            getattr(evidence_ref, "source_sequence", None) != stage.source_sequence
            or getattr(evidence_ref, "event_id", None) != stage.event_id
            or getattr(evidence_ref, "content_sha256", None) != stage.content_sha256
        ):
            raise VerifierCommitError("durable evidence reference changed staged facts")
        if stage.is_retry:
            accepted = authority.accepted.get(stage.source_sequence)
            expected_accepted = _AcceptedEnvelope(
                canonical=stage.canonical,
                evidence_ref=evidence_ref,
                evidence_priority=stage.evidence_priority,
                key_epoch=stage.key_epoch,
                key_id=stage.key_id,
            )
            if (
                stage.existing_ref != evidence_ref
                or accepted != expected_accepted
                or stage.next_fsm != authority.fsm
            ):
                raise VerifierCommitError("retry does not exactly match committed verifier history")
            next_staged = {
                stage_id: candidate
                for stage_id, candidate in self._staged.items()
                if (
                    stage_id != authorization.stage_id
                    and candidate.owner() is not None
                    and candidate.base_generation == authority.generation
                )
            }
            next_authorizations = {
                authorization_id: candidate
                for authorization_id, candidate in self._authorizations.items()
                if (authorization_id != id(authorization) and candidate.stage_id in next_staged)
            }
            self._staged = next_staged
            self._authorizations = next_authorizations
        else:
            if stage.source_sequence in authority.accepted:
                raise VerifierCommitError("source sequence already committed")
            next_accepted = dict(authority.accepted)
            next_accepted[stage.source_sequence] = _AcceptedEnvelope(
                canonical=stage.canonical,
                evidence_ref=evidence_ref,
                evidence_priority=stage.evidence_priority,
                key_epoch=stage.key_epoch,
                key_id=stage.key_id,
            )
            next_authority = _VerifierAuthorityState(
                fsm=stage.next_fsm,
                accepted=MappingProxyType(next_accepted),
                generation=authority.generation + 1,
            )
            cleared_staged: dict[int, _StagedEnvelope] = {}
            cleared_authorizations: dict[int, _AppendAuthorization] = {}
            self._authority = next_authority
            self._staged = cleared_staged
            self._authorizations = cleared_authorizations

    def _enter_read_only_after_durable_fence(self) -> None:
        authority = self._authority
        next_authority = _VerifierAuthorityState(
            fsm=authority.fsm.enter_read_only(),
            accepted=authority.accepted,
            generation=authority.generation,
        )
        self._authority = next_authority

    def _repair_authority_snapshot(self) -> _RepairAuthoritySnapshot:
        authority = self._authority
        accepted_values: list[tuple[int, _SimulationAcceptedEnvelope]] = []
        for sequence, value in sorted(authority.accepted.items()):
            envelope = EventEnvelopeV1.model_validate_json(
                value.canonical,
                strict=True,
            )
            accepted_values.append(
                (
                    sequence,
                    _SimulationAcceptedEnvelope(
                        canonical=value.canonical,
                        content_sha256=hashlib.sha256(
                            value.canonical
                        ).hexdigest(),
                        evidence_priority=value.evidence_priority,
                        event_id=envelope.event_id,
                        event_type=envelope.event_type,
                        key_epoch=value.key_epoch,
                        key_id=value.key_id,
                    ),
                )
            )
        return _RepairAuthoritySnapshot(
            root=self.root,
            key_chain=self.key_chain,
            fsm=authority.fsm,
            accepted=tuple(accepted_values),
            generation=authority.generation,
        )

    def _new_control_simulation(self) -> EnvelopeSimulation:
        """Copy only recovered verifier authority into a private simulation."""
        lifecycle_identity = self._repair_lifecycle_identity
        if self._bound_lifecycle is None or lifecycle_identity is None:
            raise VerifierCommitError(
                "control simulation requires one recovered store lifecycle"
            )
        if self._staged or self._authorizations:
            raise VerifierCommitError(
                "control simulation requires no live verifier transients"
            )
        transient_generation = self._repair_transient_generation
        authority = self._repair_authority_snapshot()
        simulation = EnvelopeSimulation(
            authority=authority,
            base_authorization_ids=tuple(self._authorizations),
            base_stage_ids=tuple(self._staged),
            base_transient_generation=transient_generation,
            lifecycle_identity=lifecycle_identity,
            verifier_identity=self._repair_owner_identity,
            _factory=_CONTROL_SIMULATION_FACTORY,
        )
        if (
            transient_generation != self._repair_transient_generation
            or self._staged
            or self._authorizations
            or authority != self._repair_authority_snapshot()
            or lifecycle_identity is not self._repair_lifecycle_identity
        ):
            raise VerifierCommitError(
                "live verifier changed while control simulation was created"
            )
        return simulation

    def _new_repair_simulation(self) -> EnvelopeSimulation:
        """Compatibility wrapper for the existing repair proof flow."""
        return self._new_control_simulation()

    def _validate_simulated_control_proof(
        self,
        proof: _SimulatedControlProof,
        *,
        proof_type: type[_SimulatedControlProof],
        event_type: str,
    ) -> None:
        if type(proof) is not proof_type:
            raise VerifierCommitError(
                "control simulation proof is stale, foreign, or inexact"
            )
        owner = getattr(proof, "_owner", None)
        target = getattr(proof, "_target", None)
        if type(owner) is not EnvelopeSimulation or type(target) is not SimulatedEvent:
            raise VerifierCommitError(
                "control simulation proof is stale, foreign, or inexact"
            )
        issued = owner._issued_proofs.get(id(proof))
        if (
            issued is None
            or issued.proof is not proof
            or issued.target is not target
        ):
            raise VerifierCommitError(
                "control simulation proof is stale, foreign, or inexact"
            )
        target_presentation = _simulated_event_binding(target)
        issued_path_sha256 = (
            None
            if issued.path_canonical is None
            else _control_path_sha256(issued.path_canonical)
        )
        if (
            proof._factory_marker is not _CONTROL_SIMULATION_FACTORY
            or proof._factory_marker is not issued.factory_marker
            or proof._base_authority != issued.base_authority
            or proof._base_authorization_ids
            != issued.base_authorization_ids
            or proof._base_generation != issued.base_generation
            or proof._base_stage_ids != issued.base_stage_ids
            or proof._base_transient_generation
            != issued.base_transient_generation
            or proof._lifecycle_identity
            is not issued.lifecycle_identity
            or proof._owner is not issued.owner
            or proof._owner_identity is not issued.owner_identity
            or proof._path_sha256 != issued.path_sha256
            or issued.path_sha256 != issued_path_sha256
            or proof._predicted_generation
            != issued.predicted_generation
            or proof._request_canonical != issued.request_canonical
            or proof._target is not issued.target
            or proof._target_binding != issued.target_binding
            or proof._verifier_identity is not issued.verifier_identity
            or target_presentation != issued.target_presentation
            or proof._verifier_identity is not self._repair_owner_identity
            or owner._verifier_identity is not self._repair_owner_identity
            or self._bound_lifecycle is None
            or proof._lifecycle_identity is not self._repair_lifecycle_identity
            or owner._lifecycle_identity is not proof._lifecycle_identity
            or proof._base_stage_ids != tuple(self._staged)
            or proof._base_authorization_ids != tuple(self._authorizations)
            or proof._base_transient_generation
            != self._repair_transient_generation
            or owner._base_stage_ids != proof._base_stage_ids
            or owner._base_authorization_ids
            != proof._base_authorization_ids
            or owner._base_transient_generation
            != proof._base_transient_generation
            or owner._identity is not proof._owner_identity
            or target._simulation_identity is not proof._owner_identity
            or target.event_type != event_type
            or target.evidence_priority != "protected"
            or target_presentation != proof._target_binding
            or proof.base_generation != self._authority.generation
            or type(proof._predicted_generation) is not int
            or not (
                proof.base_generation
                <= proof.predicted_generation
                <= MAX_UINT64
            )
            or proof.predicted_generation
            != (
                owner._base_authority.generation
                + len(owner._accepted)
                - len(owner._base_authority.accepted)
            )
            or proof._base_authority != self._repair_authority_snapshot()
            or owner._base_authority != proof._base_authority
        ):
            raise VerifierCommitError(
                "control simulation proof is stale, foreign, or inexact"
            )
        request_canonical = canonical_json(proof.request)
        if request_canonical != proof._request_canonical:
            raise VerifierCommitError("control simulation request binding changed")
        if target._normalized_fields_canonical != request_canonical:
            raise VerifierCommitError(
                "control simulation target no longer binds the exact request"
            )

    def _validate_repair_authorization_proof(
        self,
        proof: SimulatedRepairAuthorization,
    ) -> SimulatedRepairAuthorization:
        """Purely recheck an authorization preview against current authority."""
        self._validate_simulated_control_proof(
            proof,
            proof_type=SimulatedRepairAuthorization,
            event_type="evidence_repair_authorized",
        )
        return proof

    def _validate_repair_completion_proof(
        self,
        proof: SimulatedRepairCompletion,
    ) -> SimulatedRepairCompletion:
        """Purely recheck a completion preview against current authority."""
        self._validate_simulated_control_proof(
            proof,
            proof_type=SimulatedRepairCompletion,
            event_type="evidence_repair_completed",
        )
        return proof

    def _validate_retention_tombstone_proof(
        self,
        proof: SimulatedRetentionTombstone,
    ) -> SimulatedRetentionTombstone:
        """Purely recheck a tombstone preview against current authority."""
        self._validate_simulated_control_proof(
            proof,
            proof_type=SimulatedRetentionTombstone,
            event_type="retention_tombstone",
        )
        return proof

    def _validate_retention_blocked_proof(
        self,
        proof: SimulatedRetentionBlocked,
    ) -> SimulatedRetentionBlocked:
        """Purely recheck a blocked preview against current authority."""
        self._validate_simulated_control_proof(
            proof,
            proof_type=SimulatedRetentionBlocked,
            event_type="retention_blocked_priority_evidence",
        )
        return proof

    def _consume_retention_proof(
        self,
        proof: _SimulatedControlProof,
        *,
        proof_type: type[_SimulatedControlProof],
        event_type: str,
    ) -> tuple[CoreEventV1, ...]:
        """Atomically consume one issued proof and return its exact prefix."""
        self._validate_simulated_control_proof(
            proof,
            proof_type=proof_type,
            event_type=event_type,
        )
        owner = proof._owner
        if type(owner) is not EnvelopeSimulation:
            raise VerifierCommitError(
                "retention proof has no exact simulation owner"
            )
        issued = owner._issued_proofs.get(id(proof))
        if (
            issued is None
            or issued.proof is not proof
            or issued.path_canonical is None
            or not issued.path_canonical
        ):
            raise VerifierCommitError(
                "retention proof has no exact consumable path"
            )
        try:
            path = tuple(
                decode_core_event(bytes(raw))
                for raw in issued.path_canonical
            )
            canonical = tuple(
                canonical_json(item.model_dump(mode="python"))
                for item in path
            )
        except (
            IngestVerificationError,
            RecursionError,
            TypeError,
            UnicodeError,
            ValueError,
            ValidationError,
        ) as error:
            raise VerifierCommitError(
                "retention proof path is no longer exact"
            ) from error
        target = path[-1]
        target_binding = proof.target
        if (
            canonical != issued.path_canonical
            or len(path)
            != proof.predicted_generation - proof.base_generation
            or any(
                left.sequence >= right.sequence
                for left, right in pairwise(path)
            )
            or target.sequence != target_binding.sequence
            or target.event_id != target_binding.event_id
            or target.content_sha256 != target_binding.content_sha256
            or canonical_json(target.envelope)
            != target_binding._canonical_envelope
        ):
            raise VerifierCommitError(
                "retention proof path differs from its issued prefix"
            )
        consumed = owner._issued_proofs.pop(id(proof), None)
        if consumed is not issued:
            raise VerifierCommitError(
                "retention proof consumption lost exact issuer authority"
            )
        return path

    def _consume_retention_tombstone_proof(
        self,
        proof: SimulatedRetentionTombstone,
    ) -> tuple[CoreEventV1, ...]:
        return self._consume_retention_proof(
            proof,
            proof_type=SimulatedRetentionTombstone,
            event_type="retention_tombstone",
        )

    def _consume_retention_blocked_proof(
        self,
        proof: SimulatedRetentionBlocked,
    ) -> tuple[CoreEventV1, ...]:
        return self._consume_retention_proof(
            proof,
            proof_type=SimulatedRetentionBlocked,
            event_type="retention_blocked_priority_evidence",
        )

    def _restricted_historical_replay(
        self,
        accepted_items: Sequence[tuple[CoreEventV1, object]],
    ) -> tuple[SimulatedEvent, ...]:
        """Freshly reverify exact accepted repair records without live staging."""
        if (
            not isinstance(accepted_items, Sequence)
            or isinstance(accepted_items, (bytes, bytearray, str))
            or not 1 <= len(accepted_items) <= 2
        ):
            raise RepairSimulationError(
                "historical repair replay requires one or two exact records"
            )
        authority_object = self._authority
        authority_before = self._repair_authority_snapshot()
        stages_before = dict(self._staged)
        authorizations_before = dict(self._authorizations)
        simulation = self._new_repair_simulation()
        replayed: list[SimulatedEvent] = []
        previous_sequence = 0
        for pair in accepted_items:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or type(pair[0]) is not CoreEventV1
            ):
                raise RepairSimulationError(
                    "historical repair replay item is not an exact item/ref pair"
                )
            item, evidence_ref = pair
            normalized, _outer_canonical = EnvelopeSimulation._normalize_item(item)
            if normalized.sequence <= previous_sequence:
                raise RepairSimulationError(
                    "historical repair records are not strictly increasing"
                )
            previous_sequence = normalized.sequence
            accepted = authority_object.accepted.get(normalized.sequence)
            canonical_envelope = canonical_json(normalized.envelope)
            if (
                accepted is None
                or accepted.canonical != canonical_envelope
                or accepted.evidence_ref != evidence_ref
                or getattr(evidence_ref, "source_sequence", None)
                != normalized.sequence
                or getattr(evidence_ref, "event_id", None) != normalized.event_id
                or getattr(evidence_ref, "content_sha256", None)
                != normalized.content_sha256
            ):
                raise RepairSimulationError(
                    "historical repair record is outside exact accepted evidence"
                )
            result = simulation.advance(normalized)
            if result.event_type not in {
                "evidence_repair_authorized",
                "evidence_repair_completed",
            } or result.evidence_priority != "protected":
                raise RepairSimulationError(
                    "historical replay is restricted to protected repair records"
                )
            replayed.append(result)
        if (
            self._authority is not authority_object
            or self._repair_authority_snapshot() != authority_before
            or self._staged != stages_before
            or self._authorizations != authorizations_before
        ):
            raise VerifierCommitError(
                "live verifier changed during restricted historical replay"
            )
        return tuple(replayed)

    def _restricted_historical_retention_replay(
        self,
        accepted_item: tuple[CoreEventV1, object],
        request: RetentionTombstoneV2 | RetentionBlockedV1,
    ) -> SimulatedEvent:
        """Freshly reverify one exact accepted retention record."""
        if (
            not isinstance(accepted_item, tuple)
            or len(accepted_item) != 2
            or type(accepted_item[0]) is not CoreEventV1
        ):
            raise RetentionSimulationError(
                "historical retention replay requires one exact item/ref pair"
            )
        if type(request) is RetentionTombstoneV2:
            event_type = "retention_tombstone"
            _normalized_tombstone, request_canonical = (
                EnvelopeSimulation._normalize_retention_request(
                    request,
                    RetentionTombstoneV2,
                )
            )
        elif type(request) is RetentionBlockedV1:
            event_type = "retention_blocked_priority_evidence"
            _normalized_blocked, request_canonical = (
                EnvelopeSimulation._normalize_retention_request(
                    request,
                    RetentionBlockedV1,
                )
            )
        else:
            raise RetentionSimulationError(
                "historical retention replay has the wrong request type"
            )
        item, evidence_ref = accepted_item
        normalized, _outer_canonical = EnvelopeSimulation._normalize_item(
            item
        )
        authority_object = self._authority
        authority_before = self._repair_authority_snapshot()
        stages_before = dict(self._staged)
        authorizations_before = dict(self._authorizations)
        transient_before = self._repair_transient_generation
        bound_lifecycle_before = self._bound_lifecycle
        lifecycle_before = self._repair_lifecycle_identity
        owner_before = self._repair_owner_identity
        accepted = authority_object.accepted.get(normalized.sequence)
        canonical_envelope = canonical_json(normalized.envelope)
        if (
            accepted is None
            or accepted.canonical != canonical_envelope
            or accepted.evidence_ref != evidence_ref
            or getattr(evidence_ref, "source_sequence", None)
            != normalized.sequence
            or getattr(evidence_ref, "event_id", None)
            != normalized.event_id
            or getattr(evidence_ref, "content_sha256", None)
            != normalized.content_sha256
        ):
            raise RetentionSimulationError(
                "historical retention record is outside exact accepted evidence"
            )
        simulation = self._new_control_simulation()
        result = simulation.advance(normalized)
        if (
            result.is_retry is not True
            or result.event_type != event_type
            or result.evidence_priority != "protected"
            or result._normalized_fields_canonical != request_canonical
        ):
            raise RetentionSimulationError(
                "historical retention record differs from the exact request"
            )
        if (
            self._authority is not authority_object
            or self._repair_authority_snapshot() != authority_before
            or self._staged != stages_before
            or self._authorizations != authorizations_before
            or self._repair_transient_generation != transient_before
            or self._bound_lifecycle is not bound_lifecycle_before
            or self._repair_lifecycle_identity is not lifecycle_before
            or self._repair_owner_identity is not owner_before
        ):
            raise VerifierCommitError(
                "live verifier changed during historical retention replay"
            )
        return result

    def accepted_ref(self, source_sequence: int) -> object | None:
        accepted = self._authority.accepted.get(source_sequence)
        return None if accepted is None else accepted.evidence_ref


@final
class EnvelopeSimulation:
    """Private verifier replay with no store lifecycle, stage, or append result."""

    _accepted: dict[int, _SimulationAcceptedEnvelope]
    _base_authorization_ids: tuple[int, ...]
    _base_authority: _RepairAuthoritySnapshot
    _base_stage_ids: tuple[int, ...]
    _base_transient_generation: int
    _fsm: ObserverStreamFSM
    _identity: object
    _issued_proofs: dict[int, _IssuedControlProofBinding]
    _key_chain: AnchoredPublicKeyChain
    _lifecycle_identity: object
    _root: PinnedObserverRoot
    _verifier_identity: object

    __slots__ = (
        "__weakref__",
        "_accepted",
        "_base_authority",
        "_base_authorization_ids",
        "_base_stage_ids",
        "_base_transient_generation",
        "_fsm",
        "_identity",
        "_issued_proofs",
        "_key_chain",
        "_lifecycle_identity",
        "_root",
        "_verifier_identity",
    )

    def __init__(
        self,
        *,
        authority: _RepairAuthoritySnapshot,
        base_authorization_ids: tuple[int, ...],
        base_stage_ids: tuple[int, ...],
        base_transient_generation: int,
        lifecycle_identity: object,
        verifier_identity: object,
        _factory: object,
    ) -> None:
        if _factory is not _REPAIR_SIMULATION_FACTORY:
            raise TypeError("EnvelopeSimulation is factory-only")
        self._base_authorization_ids = base_authorization_ids
        self._verifier_identity = verifier_identity
        self._base_authority = authority
        self._base_stage_ids = base_stage_ids
        self._base_transient_generation = base_transient_generation
        self._lifecycle_identity = lifecycle_identity
        self._root = authority.root
        self._key_chain = authority.key_chain
        self._fsm = authority.fsm
        self._accepted = dict(authority.accepted)
        self._identity = object()
        self._issued_proofs = {}

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("EnvelopeSimulation is final")

    @staticmethod
    def _normalize_item(item: CoreEventV1) -> tuple[CoreEventV1, bytes]:
        if type(item) is not CoreEventV1:
            raise RepairSimulationError(
                "repair simulation accepts exact CoreEventV1 items only"
            )
        try:
            outer_canonical = canonical_json(item.model_dump())
            normalized = decode_core_event(outer_canonical)
        except (
            IngestVerificationError,
            RecursionError,
            TypeError,
            UnicodeError,
            ValueError,
            ValidationError,
        ) as error:
            raise OuterBindingError(
                "repair simulation Core item is not exact"
            ) from error
        return normalized, outer_canonical

    def _select_verification_key(
        self,
        *,
        event_type: str,
        source_sequence: int,
        key_epoch: int,
        key_id: str,
        historical: _SimulationAcceptedEnvelope | None,
    ) -> bytes:
        pending = self._fsm.pending_rotation
        if (
            pending is not None
            and event_type == "observer_key_epoch_start"
            and source_sequence == pending.transition_sequence + 1
        ):
            expected_epoch = pending.new_epoch
            expected_key_id = pending.new_key_id
        elif historical is not None:
            expected_epoch = historical.key_epoch
            expected_key_id = historical.key_id
        else:
            expected_epoch = self._fsm.active_epoch
            expected_key_id = self._fsm.active_key_id
        if key_epoch != expected_epoch or key_id != expected_key_id:
            raise EnvelopeIdentityError(
                "envelope key is not active at this simulated stream position"
            )
        return self._key_chain.key(expected_epoch, expected_key_id)

    def advance(self, item: CoreEventV1) -> SimulatedEvent:
        """Reverify and privately advance one canonical observer item."""
        normalized, _outer_canonical = self._normalize_item(item)
        envelope_value = normalized.envelope
        canonical = canonical_json(envelope_value)
        accepted = self._accepted.get(normalized.sequence)

        EnvelopeVerifier._precheck_signed_content(envelope_value)
        event_type = envelope_value["event_type"]
        source_sequence = envelope_value["source_sequence"]
        key_epoch = envelope_value["key_epoch"]
        key_id = envelope_value["key_id"]
        if (
            not isinstance(event_type, str)
            or not isinstance(source_sequence, int)
            or isinstance(source_sequence, bool)
            or not isinstance(key_epoch, int)
            or isinstance(key_epoch, bool)
            or not isinstance(key_id, str)
        ):
            raise EnvelopeIdentityError(
                "simulated envelope key/sequence identity has invalid types"
            )
        public_key = self._select_verification_key(
            event_type=event_type,
            source_sequence=source_sequence,
            key_epoch=key_epoch,
            key_id=key_id,
            historical=accepted,
        )
        try:
            verify_event_signature(envelope_value, public_key)
        except (InvalidSignature, TypeError, ValueError) as error:
            raise EnvelopeSignatureError(
                "simulated observer envelope signature is invalid"
            ) from error
        try:
            envelope = EventEnvelopeV1.model_validate(envelope_value, strict=True)
        except ValidationError as error:
            raise OuterBindingError(
                "simulated signed envelope contract is invalid"
            ) from error
        if (
            envelope.host_id != self._root.host_id
            or envelope.source_id != "agmind-observerd"
        ):
            raise EnvelopeIdentityError(
                "simulated envelope is not from the pinned observer host/source"
            )
        EnvelopeVerifier._validate_special_semantics(envelope)

        if accepted is not None:
            if accepted.canonical != canonical:
                raise EnvelopeConflict(
                    f"valid signed simulated conflict at "
                    f"({self._root.host_id}, {normalized.sequence})"
                )
            is_retry = True
            evidence_priority = accepted.evidence_priority
        else:
            is_retry = False
            next_fsm = self._fsm.advance(envelope, canonical, self._key_chain)
            evidence_priority = (
                "protected"
                if envelope.event_type in _PROTECTED_EVENT_TYPES
                else "routine"
            )
            self._fsm = next_fsm
            self._accepted[normalized.sequence] = _SimulationAcceptedEnvelope(
                canonical=canonical,
                content_sha256=normalized.content_sha256,
                evidence_priority=evidence_priority,
                event_id=normalized.event_id,
                event_type=envelope.event_type,
                key_epoch=envelope.key_epoch,
                key_id=envelope.key_id,
            )
        return SimulatedEvent(
            canonical_envelope=canonical,
            content_sha256=normalized.content_sha256,
            event_id=normalized.event_id,
            event_type=envelope.event_type,
            evidence_priority=evidence_priority,
            is_retry=is_retry,
            key_epoch=envelope.key_epoch,
            key_id=envelope.key_id,
            normalized_fields_canonical=canonical_json(
                envelope.normalized_fields
            ),
            sequence=normalized.sequence,
            simulation_identity=self._identity,
            _factory=_REPAIR_SIMULATION_FACTORY,
        )

    @staticmethod
    def _normalize_request[
        RequestT: (EvidenceRepairAuthorizeV1, EvidenceRepairCompleteV1)
    ](
        request: RequestT,
        request_type: type[RequestT],
    ) -> tuple[RequestT, bytes]:
        if type(request) is not request_type:
            raise RepairSimulationError(
                "repair simulation request has the wrong exact contract type"
            )
        try:
            canonical = canonical_json(request)
            normalized = request_type.model_validate_json(
                canonical,
                strict=True,
            )
        except (RecursionError, TypeError, ValueError, ValidationError) as error:
            raise RepairSimulationError(
                "repair simulation request is not exact canonical authority"
            ) from error
        return normalized, canonical

    def _validate_completion_causality(
        self,
        request: EvidenceRepairCompleteV1,
        target: SimulatedEvent,
    ) -> None:
        matches = [
            (sequence, accepted)
            for sequence, accepted in self._accepted.items()
            if (
                sequence < target.sequence
                and accepted.event_id == request.authorization_event_id
                and accepted.content_sha256
                == request.authorization_content_sha256
            )
        ]
        if len(matches) != 1 or matches[0][1].event_type != (
            "evidence_repair_authorized"
        ):
            raise RepairSimulationError(
                "completion does not reference one exact simulated authorization"
            )
        try:
            authorization_envelope = EventEnvelopeV1.model_validate_json(
                matches[0][1].canonical,
                strict=True,
            )
            authorization = EvidenceRepairAuthorizeV1.model_validate(
                authorization_envelope.normalized_fields,
                strict=True,
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise RepairSimulationError(
                "referenced simulated authorization is not exact"
            ) from error
        if (
            authorization.repair_id != request.repair_id
            or authorization.segment_id != request.segment_id
            or authorization.verified_bytes != request.verified_bytes
            or authorization.last_verified_frame_sha256
            != request.last_verified_frame_sha256
            or authorization.current_chain_head_sha256
            != request.current_chain_head_sha256
        ):
            raise RepairSimulationError(
                "completion facts differ from the simulated authorization"
            )

    def _issue_proof(
        self,
        *,
        proof_type: type[_SimulatedControlProof],
        request_canonical: bytes,
        target: SimulatedEvent,
        path_canonical: tuple[bytes, ...] | None = None,
    ) -> _SimulatedControlProof:
        added = len(self._accepted) - len(self._base_authority.accepted)
        predicted_generation = self._base_authority.generation + added
        if (
            added < 0
            or predicted_generation < self._base_authority.generation
            or predicted_generation > MAX_UINT64
        ):
            raise VerifierCommitError(
                "control simulation generation arithmetic is invalid"
            )
        path_sha256 = (
            None
            if path_canonical is None
            else _control_path_sha256(path_canonical)
        )
        proof = proof_type(
            base_authorization_ids=self._base_authorization_ids,
            base_authority=self._base_authority,
            base_stage_ids=self._base_stage_ids,
            base_transient_generation=self._base_transient_generation,
            lifecycle_identity=self._lifecycle_identity,
            owner=self,
            owner_identity=self._identity,
            path_sha256=path_sha256,
            predicted_generation=predicted_generation,
            request_canonical=request_canonical,
            target=target,
            verifier_identity=self._verifier_identity,
            _factory=_CONTROL_SIMULATION_FACTORY,
        )
        self._issued_proofs[id(proof)] = _IssuedControlProofBinding(
            proof=proof,
            target=target,
            path_canonical=path_canonical,
            path_sha256=path_sha256,
            factory_marker=proof._factory_marker,
            base_authority=proof._base_authority,
            base_authorization_ids=tuple(proof._base_authorization_ids),
            base_generation=proof._base_generation,
            base_stage_ids=tuple(proof._base_stage_ids),
            base_transient_generation=proof._base_transient_generation,
            lifecycle_identity=proof._lifecycle_identity,
            owner=proof._owner,
            owner_identity=proof._owner_identity,
            predicted_generation=proof._predicted_generation,
            request_canonical=bytes(proof._request_canonical),
            target_binding=tuple(proof._target_binding),
            target_presentation=_simulated_event_binding(target),
            verifier_identity=proof._verifier_identity,
        )
        return proof

    def _verify_exact_repair_path[
        RequestT: (EvidenceRepairAuthorizeV1, EvidenceRepairCompleteV1)
    ](
        self,
        request: RequestT,
        direct: CoreEventV1,
        fetched: Sequence[CoreEventV1],
        *,
        request_type: type[RequestT],
        event_type: str,
        proof_type: type[_SimulatedControlProof],
    ) -> _SimulatedControlProof:
        normalized_request, request_canonical = self._normalize_request(
            request,
            request_type,
        )
        normalized_direct, direct_canonical = self._normalize_item(direct)
        if (
            not isinstance(fetched, Sequence)
            or isinstance(fetched, (bytes, bytearray, str))
            or not 1 <= len(fetched) <= _MAX_REPAIR_SIMULATION_EVENTS
        ):
            raise RepairSimulationError(
                "repair simulation path has invalid event bounds"
            )
        fsm_before = self._fsm
        accepted_before = dict(self._accepted)
        previous = self._fsm.last_sequence
        target: SimulatedEvent | None = None
        try:
            for candidate in fetched:
                normalized, candidate_canonical = self._normalize_item(candidate)
                if normalized.sequence <= previous:
                    raise RepairSimulationError(
                        "repair simulation path is not strictly forward"
                    )
                if normalized.sequence > normalized_direct.sequence:
                    raise RepairSimulationError(
                        "repair simulation path advanced beyond its exact target"
                    )
                result = self.advance(normalized)
                if candidate_canonical == direct_canonical:
                    if target is not None:
                        raise RepairSimulationError(
                            "repair simulation path repeated its exact target"
                        )
                    target = result
                elif normalized.sequence == normalized_direct.sequence:
                    raise RepairSimulationError(
                        "fetched repair target differs from direct response"
                    )
                previous = normalized.sequence
            if target is None or previous != normalized_direct.sequence:
                raise RepairSimulationError(
                    "direct repair response is absent from the fetched path"
                )
            if (
                target.event_type != event_type
                or target.evidence_priority != "protected"
                or target._normalized_fields_canonical != request_canonical
            ):
                raise RepairSimulationError(
                    "repair target does not exactly bind the sent request"
                )
            if isinstance(normalized_request, EvidenceRepairCompleteV1):
                self._validate_completion_causality(
                    normalized_request,
                    target,
                )
        except BaseException:
            self._fsm = fsm_before
            self._accepted = accepted_before
            raise
        return self._issue_proof(
            proof_type=proof_type,
            request_canonical=request_canonical,
            target=target,
        )

    @staticmethod
    def _normalize_retention_request[
        RequestT: (RetentionTombstoneV2, RetentionBlockedV1)
    ](
        request: RequestT,
        request_type: type[RequestT],
    ) -> tuple[RequestT, bytes]:
        if type(request) is not request_type:
            raise RetentionSimulationError(
                "retention simulation request has the wrong exact contract type"
            )
        try:
            canonical = canonical_json(request)
            normalized = request_type.model_validate_json(
                canonical,
                strict=True,
            )
        except (RecursionError, TypeError, ValueError, ValidationError) as error:
            raise RetentionSimulationError(
                "retention simulation request is not exact canonical authority"
            ) from error
        return normalized, canonical

    def _verify_exact_retention_path[
        RequestT: (RetentionTombstoneV2, RetentionBlockedV1)
    ](
        self,
        request: RequestT,
        direct: CoreEventV1,
        fetched: Sequence[CoreEventV1],
        *,
        request_type: type[RequestT],
        event_type: str,
        proof_type: type[_SimulatedControlProof],
    ) -> _SimulatedControlProof:
        _normalized_request, request_canonical = (
            self._normalize_retention_request(request, request_type)
        )
        normalized_direct, direct_canonical = self._normalize_item(direct)
        if (
            not isinstance(fetched, Sequence)
            or isinstance(fetched, (bytes, bytearray, str))
            or not 1 <= len(fetched) <= _MAX_CONTROL_SIMULATION_EVENTS
        ):
            raise RetentionSimulationError(
                "retention simulation path has invalid event bounds"
            )
        fsm_before = self._fsm
        accepted_before = dict(self._accepted)
        previous = self._fsm.last_sequence
        target: SimulatedEvent | None = None
        prefix_canonical: list[bytes] = []
        try:
            for candidate in fetched:
                normalized, candidate_canonical = self._normalize_item(candidate)
                if normalized.sequence <= previous:
                    raise RetentionSimulationError(
                        "retention simulation path is not strictly forward"
                    )
                if target is None:
                    if normalized.sequence > normalized_direct.sequence:
                        raise RetentionSimulationError(
                            "retention simulation path overshot its exact target"
                        )
                    result = self.advance(normalized)
                    prefix_canonical.append(candidate_canonical)
                    if candidate_canonical == direct_canonical:
                        target = result
                    elif normalized.sequence == normalized_direct.sequence:
                        raise RetentionSimulationError(
                            "fetched retention target differs from direct response"
                        )
                previous = normalized.sequence
            if target is None:
                raise RetentionSimulationError(
                    "direct retention response is absent from the fetched path"
                )
            if (
                target.event_type != event_type
                or target.evidence_priority != "protected"
                or target._normalized_fields_canonical != request_canonical
            ):
                raise RetentionSimulationError(
                    "retention target does not exactly bind the sent request"
                )
        except BaseException:
            self._fsm = fsm_before
            self._accepted = accepted_before
            raise
        return self._issue_proof(
            proof_type=proof_type,
            request_canonical=request_canonical,
            target=target,
            path_canonical=tuple(prefix_canonical),
        )

    def verify_exact_authorization(
        self,
        request: EvidenceRepairAuthorizeV1,
        direct: CoreEventV1,
        fetched: Sequence[CoreEventV1],
    ) -> SimulatedRepairAuthorization:
        """Verify one bounded fetched path through the exact authorization."""
        proof = self._verify_exact_repair_path(
            request,
            direct,
            fetched,
            request_type=EvidenceRepairAuthorizeV1,
            event_type="evidence_repair_authorized",
            proof_type=SimulatedRepairAuthorization,
        )
        assert isinstance(proof, SimulatedRepairAuthorization)
        return proof

    def verify_exact_completion(
        self,
        request: EvidenceRepairCompleteV1,
        direct: CoreEventV1,
        fetched: Sequence[CoreEventV1],
    ) -> SimulatedRepairCompletion:
        """Verify one bounded fetched path through the exact completion."""
        proof = self._verify_exact_repair_path(
            request,
            direct,
            fetched,
            request_type=EvidenceRepairCompleteV1,
            event_type="evidence_repair_completed",
            proof_type=SimulatedRepairCompletion,
        )
        assert isinstance(proof, SimulatedRepairCompletion)
        return proof

    def verify_exact_retention_tombstone(
        self,
        request: RetentionTombstoneV2,
        direct: CoreEventV1,
        fetched: Sequence[CoreEventV1],
    ) -> SimulatedRetentionTombstone:
        """Verify a bounded path through one exact retention tombstone."""
        proof = self._verify_exact_retention_path(
            request,
            direct,
            fetched,
            request_type=RetentionTombstoneV2,
            event_type="retention_tombstone",
            proof_type=SimulatedRetentionTombstone,
        )
        assert isinstance(proof, SimulatedRetentionTombstone)
        return proof

    def verify_exact_retention_blocked(
        self,
        request: RetentionBlockedV1,
        direct: CoreEventV1,
        fetched: Sequence[CoreEventV1],
    ) -> SimulatedRetentionBlocked:
        """Verify a bounded path through one exact retention blocked event."""
        proof = self._verify_exact_retention_path(
            request,
            direct,
            fetched,
            request_type=RetentionBlockedV1,
            event_type="retention_blocked_priority_evidence",
            proof_type=SimulatedRetentionBlocked,
        )
        assert isinstance(proof, SimulatedRetentionBlocked)
        return proof
