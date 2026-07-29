"""Strict observer page decoding and immutable-root-anchored stream verification."""

from __future__ import annotations

import hashlib
import re
import weakref
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

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
    FalcoConnectV1,
    KeyTransitionV1,
    ObserverBootBoundaryV1,
    ObserverTrustRootV1,
    decode_strict,
)

MAX_EVENTS_PAGE_BYTES = 4 * 1024 * 1024
MAX_CANONICAL_ENVELOPE_BYTES = 64 * 1024
MAX_PUBLIC_KEY_METADATA_BYTES = 64 * 1024
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


_PROTECTED_EVENT_TYPES = frozenset(
    {
        "corruption",
        "coverage",
        "incident_action_mirror",
        "observer_boot_boundary",
        "observer_key_epoch_start",
        "observer_key_transition",
        "observer_start",
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
    def _validate_special_semantics(cls, envelope: EventEnvelopeV1) -> None:
        try:
            if envelope.event_type == "observer_boot_boundary":
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

    def accepted_ref(self, source_sequence: int) -> object | None:
        accepted = self._authority.accepted.get(source_sequence)
        return None if accepted is None else accepted.evidence_ref
