"""Pure, fail-closed retention selection over a frozen evidence snapshot."""

from __future__ import annotations

import hashlib
import json
import re
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from itertools import pairwise
from threading import Lock
from typing import Any, Literal, Never, Protocol, SupportsIndex, cast, final

from pydantic import Field, ValidationError, field_validator, model_validator

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.clock import CoreClockSample, CoreClockValidationError
from agmind_immune.contracts import (
    HEX64,
    MAX_EVIDENCE_SEGMENT_BYTES,
    MAX_UINT64,
    UUID4,
    ContractModel,
    RetentionBlockedV1,
    RetentionTombstoneV2,
    _parse_integer,
    _reject_constant,
    _reject_float,
    _unique_object,
    _validate_json_depth,
    _validate_unicode,
    decode_strict,
)
from agmind_immune.evidence.manifest import (
    SegmentManifestV1,
    chain_head_for,
)

RETENTION_TARGET_BYTES = 5 * 1024**3
RETENTION_MAX_AGE_NS = 7 * 24 * 60 * 60 * 1_000_000_000
RETENTION_MAX_RUN_MANIFESTS = 128
RETENTION_POLICY_VERSION: Literal["agmind-retention-v1"] = "agmind-retention-v1"
RETENTION_REMOVABLE_EVENT_TYPES = frozenset({"falco_connect"})

_MANIFEST_MAX_BYTES = 16 * 1024
_TOMBSTONE_MAX_BYTES = 16 * 1024
_RUN_DOMAIN = b"AGMIND_RETENTION_RUN_V2\x00"
_RECORD_BINDING_DOMAIN = b"agmind.retention-record-binding.v1\x00"
_FACT_BINDING_DOMAIN = b"agmind.retention-fact-binding.v1\x00"
_ACCEPTED_BINDING_DOMAIN = b"agmind.retention-accepted-binding.v1\x00"
_SNAPSHOT_BINDING_DOMAIN = b"agmind.retention-snapshot-binding.v1\x00"
_RUN_BINDING_DOMAIN = b"agmind.retention-run-binding.v1\x00"
_DECISION_BINDING_DOMAIN = b"agmind.retention-decision-binding.v1\x00"
_PRIOR_INDEX_DOMAIN = b"agmind.retention-prior-index.v1\x00"
_RETENTION_STATE_JOURNAL_FACTORY = object()
MAX_RETENTION_STATE_BYTES = 128 * 1024
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_SEGMENT_RELATIVE_PATH = re.compile(
    r"^segments/(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})/"
    r"(?P<sequence>[0-9]{20})-"
    r"(?P<segment>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.agseg$"
)
_RFC3339_NANO = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?Z$"
)

EvidencePriorityName = Literal["routine", "protected"]
RetentionRequest = RetentionTombstoneV2 | RetentionBlockedV1
_RequestKind = Literal["tombstone", "blocked"]
_RECORD_FACTORY = object()
_FACT_FACTORY = object()
_ACCEPTED_FACTORY = object()
_SNAPSHOT_FACTORY = object()
_RUN_FACTORY = object()
_DECISION_FACTORY = object()
_AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY = object()
_AUTHENTICATED_RETENTION_UNLINK_COMPLETION_FACTORY = object()


class RetentionError(RuntimeError):
    """Base class for retention-selection failures."""


class RetentionCorruption(RetentionError):
    """Frozen facts or prior authenticated authority are contradictory."""


class RetentionStateCorrupt(RetentionError):
    """The durable retention gate is malformed or contradictory."""


class RetentionStateConflict(RetentionError):
    """The exact durable retention state changed across a CAS boundary."""


class RetentionProtocolError(RetentionError):
    """A requested retention-state transition is outside the frozen graph."""


@final
class AuthenticatedRetentionTombstone:
    """Opaque one-use proof identity; all authority remains store-side."""

    _factory_marker: object

    __slots__ = ("_factory_marker",)

    def __init__(
        self,
        *,
        _factory: object,
    ) -> None:
        if _factory is not _AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY:
            raise TypeError(
                "AuthenticatedRetentionTombstone is factory-only"
            )
        object.__setattr__(self, "_factory_marker", _factory)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("AuthenticatedRetentionTombstone is final")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError(
            "authenticated retention tombstones are immutable"
        )

    def __copy__(self) -> AuthenticatedRetentionTombstone:
        raise TypeError(
            "authenticated retention tombstones cannot be copied"
        )

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> AuthenticatedRetentionTombstone:
        del memo
        raise TypeError(
            "authenticated retention tombstones cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TypeError(
            "authenticated retention tombstones cannot be serialized"
        )

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError(
            "authenticated retention tombstones cannot be serialized"
        )


@final
class AuthenticatedRetentionUnlinkCompletion:
    """Opaque same-lifecycle proof that every selected payload was synced."""

    _factory_marker: object

    __slots__ = ("_factory_marker",)

    def __init__(
        self,
        *,
        _factory: object,
    ) -> None:
        if (
            _factory
            is not _AUTHENTICATED_RETENTION_UNLINK_COMPLETION_FACTORY
        ):
            raise TypeError(
                "AuthenticatedRetentionUnlinkCompletion is factory-only"
            )
        object.__setattr__(self, "_factory_marker", _factory)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("AuthenticatedRetentionUnlinkCompletion is final")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError(
            "authenticated retention unlink completions are immutable"
        )

    def __copy__(self) -> AuthenticatedRetentionUnlinkCompletion:
        raise TypeError(
            "authenticated retention unlink completions cannot be copied"
        )

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> AuthenticatedRetentionUnlinkCompletion:
        del memo
        raise TypeError(
            "authenticated retention unlink completions cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TypeError(
            "authenticated retention unlink completions cannot be serialized"
        )

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError(
            "authenticated retention unlink completions cannot be serialized"
        )


def _identity_registry() -> tuple[
    Callable[[object, bytes], None],
    Callable[[object, bytes, str], None],
]:
    records: dict[
        int,
        tuple[weakref.ReferenceType[object], bytes],
    ] = {}
    lock = Lock()

    def register(value: object, binding: bytes) -> None:
        identity = id(value)

        def cleanup(reference: weakref.ReferenceType[object]) -> None:
            with lock:
                current = records.get(identity)
                if current is not None and current[0] is reference:
                    records.pop(identity, None)

        reference = weakref.ref(value, cleanup)
        with lock:
            records[identity] = (reference, binding)

    def require(value: object, binding: bytes, kind: str) -> None:
        with lock:
            registered = records.get(id(value))
        if (
            registered is None
            or registered[0]() is not value
            or registered[1] != binding
        ):
            raise RetentionCorruption(f"{kind} lost its construction authority")

    return register, require


_register_identity, _require_identity = _identity_registry()


def _is_printable_ascii(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        raw = value.encode("ascii", "strict")
    except UnicodeEncodeError:
        return False
    return 1 <= len(raw) <= 64 and all(0x20 <= byte <= 0x7E for byte in raw)


def _checked_add(left: int, right: int, field: str) -> int:
    if (
        type(left) is not int
        or type(right) is not int
        or not 0 <= left <= MAX_UINT64
        or not 0 <= right <= MAX_UINT64
        or left > MAX_UINT64 - right
    ):
        raise RetentionCorruption(f"{field} exceeds checked uint64 arithmetic")
    return left + right


def _checked_sub(left: int, right: int, field: str) -> int:
    if (
        type(left) is not int
        or type(right) is not int
        or not 0 <= right <= left <= MAX_UINT64
    ):
        raise RetentionCorruption(f"{field} exceeds checked uint64 arithmetic")
    return left - right


def _timestamp_ns(value: str) -> int:
    if type(value) is not str:
        raise RetentionCorruption("retention timestamp is not an exact string")
    match = _RFC3339_NANO.fullmatch(value)
    if match is None:
        raise RetentionCorruption("retention timestamp is not canonical RFC3339 UTC")
    try:
        parsed_date = date(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
        )
        hour = int(match.group("hour"))
        minute = int(match.group("minute"))
        second = int(match.group("second"))
    except ValueError as error:
        raise RetentionCorruption("retention timestamp calendar date is invalid") from error
    if not 0 <= hour <= 23 or not 0 <= minute <= 59 or not 0 <= second <= 59:
        raise RetentionCorruption("retention timestamp clock fields are invalid")
    fraction = match.group("fraction") or ""
    fraction_ns = int(fraction.ljust(9, "0")) if fraction else 0
    days_and_hours = parsed_date.toordinal() * 24 + hour
    return ((days_and_hours * 60 + minute) * 60 + second) * 1_000_000_000 + fraction_ns


def _datetime_ns(value: datetime) -> int:
    if type(value) is not datetime:
        raise RetentionCorruption("retention decision UTC is not an exact datetime")
    try:
        offset = value.utcoffset()
        exact_utc = (
            value.tzinfo == UTC
            and offset == timedelta(0)
            and value.fold == 0
        )
    except Exception as error:
        raise RetentionCorruption("retention decision UTC validation failed") from error
    if not exact_utc:
        raise RetentionCorruption("retention decision UTC is not canonical UTC")
    days_and_hours = value.toordinal() * 24 + value.hour
    seconds = (days_and_hours * 60 + value.minute) * 60 + value.second
    return seconds * 1_000_000_000 + value.microsecond * 1_000


def _decision_utc_text(value: datetime) -> str:
    timespec = "microseconds" if value.microsecond else "seconds"
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def _prefix_chain_head_sha256(manifest: SegmentManifestV1) -> str:
    return hashlib.sha256(canonical_json(chain_head_for(manifest))).hexdigest()


def _record_binding_values(
    event_type: object,
    evidence_priority: object,
) -> bytes:
    try:
        document = canonical_json(
            {
                "event_type": event_type,
                "evidence_priority": evidence_priority,
            }
        )
    except (TypeError, ValueError) as error:
        raise RetentionCorruption("retention record binding is invalid") from error
    return hashlib.sha256(_RECORD_BINDING_DOMAIN + document).digest()


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class FrozenRetentionRecord:
    """One verifier-classified record retained as immutable scalar facts."""

    event_type: str
    evidence_priority: EvidencePriorityName

    def __init__(
        self,
        *,
        event_type: str,
        evidence_priority: EvidencePriorityName,
        _factory: object,
    ) -> None:
        if _factory is not _RECORD_FACTORY:
            raise TypeError("retention records are factory-only")
        if not _is_printable_ascii(event_type):
            raise RetentionCorruption("retention record event type is invalid")
        if type(evidence_priority) is not str or evidence_priority not in {
            "routine",
            "protected",
        }:
            raise RetentionCorruption("retention record priority is invalid")
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "evidence_priority", evidence_priority)
        _register_identity(
            self,
            _record_binding_values(event_type, evidence_priority),
        )


def _freeze_retention_record(
    *,
    event_type: str,
    evidence_priority: EvidencePriorityName,
) -> FrozenRetentionRecord:
    return FrozenRetentionRecord(
        event_type=event_type,
        evidence_priority=evidence_priority,
        _factory=_RECORD_FACTORY,
    )


def _record_binding(record: FrozenRetentionRecord) -> bytes:
    if type(record) is not FrozenRetentionRecord:
        raise RetentionCorruption("retention record runtime type changed")
    binding = _record_binding_values(
        record.event_type,
        record.evidence_priority,
    )
    _require_identity(record, binding, "retention record")
    return binding


def _framed(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _fact_binding_values(
    *,
    manifest_canonical: object,
    manifest_sha256: object,
    previous_manifest_sha256: object,
    prefix_chain_head_sha256: object,
    segment_id: object,
    segment_relative_path: object,
    segment_sha256: object,
    evidence_priority: object,
    closed_at: object,
    segment_size_bytes: object,
    record_count: object,
    original_device: object,
    original_inode: object,
    records: object,
) -> bytes:
    if type(manifest_canonical) is not bytes or type(records) is not tuple:
        raise RetentionCorruption("retention fact binding fields changed")
    preimage = bytearray(_FACT_BINDING_DOMAIN)
    preimage.extend(_framed(manifest_canonical))
    try:
        projections = canonical_json(
            {
                "manifest_sha256": manifest_sha256,
                "previous_manifest_sha256": previous_manifest_sha256,
                "prefix_chain_head_sha256": prefix_chain_head_sha256,
                "segment_id": segment_id,
                "segment_relative_path": segment_relative_path,
                "segment_sha256": segment_sha256,
                "evidence_priority": evidence_priority,
                "closed_at": closed_at,
                "segment_size_bytes": segment_size_bytes,
                "record_count": record_count,
                "original_device": original_device,
                "original_inode": original_inode,
            }
        )
    except (TypeError, ValueError) as error:
        raise RetentionCorruption(
            "retention fact scalar binding is invalid"
        ) from error
    preimage.extend(_framed(projections))
    for record in records:
        if type(record) is not FrozenRetentionRecord:
            raise RetentionCorruption("retention fact record identity changed")
        preimage.extend(id(record).to_bytes(8, "big", signed=False))
        preimage.extend(_record_binding(record))
    return hashlib.sha256(preimage).digest()


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class FrozenRetentionFact:
    """Deep-frozen manifest and verifier classification facts."""

    manifest_canonical: bytes
    manifest_sha256: str
    previous_manifest_sha256: str
    prefix_chain_head_sha256: str
    segment_id: str
    segment_relative_path: str
    segment_sha256: str
    evidence_priority: EvidencePriorityName
    closed_at: str
    segment_size_bytes: int
    record_count: int
    original_device: int
    original_inode: int
    records: tuple[FrozenRetentionRecord, ...]

    def __init__(
        self,
        *,
        manifest: SegmentManifestV1,
        records: tuple[FrozenRetentionRecord, ...],
        original_device: int,
        original_inode: int,
        _factory: object,
    ) -> None:
        if _factory is not _FACT_FACTORY:
            raise TypeError("retention facts are factory-only")
        if type(manifest) is not SegmentManifestV1:
            raise RetentionCorruption("retention fact requires an exact manifest")
        if type(records) is not tuple or any(
            type(record) is not FrozenRetentionRecord for record in records
        ):
            raise RetentionCorruption("retention fact records are not an exact tuple")
        if (
            type(original_device) is not int
            or type(original_inode) is not int
            or not 0 <= original_device <= MAX_UINT64
            or not 1 <= original_inode <= MAX_UINT64
        ):
            raise RetentionCorruption("retention fact payload identity is invalid")
        try:
            validated = SegmentManifestV1.model_validate(
                manifest.model_dump(mode="python"),
                strict=True,
            )
            raw = canonical_json(validated.model_dump(mode="python"))
        except (TypeError, ValueError) as error:
            raise RetentionCorruption("retention fact manifest is invalid") from error
        if len(raw) > _MANIFEST_MAX_BYTES:
            raise RetentionCorruption("retention fact manifest exceeds its byte bound")
        if validated.record_count != len(records):
            raise RetentionCorruption("retention record count differs from manifest")
        object.__setattr__(self, "manifest_canonical", raw)
        object.__setattr__(self, "manifest_sha256", validated.manifest_sha256)
        object.__setattr__(
            self,
            "previous_manifest_sha256",
            validated.previous_manifest_sha256,
        )
        object.__setattr__(
            self,
            "prefix_chain_head_sha256",
            _prefix_chain_head_sha256(validated),
        )
        object.__setattr__(self, "segment_id", validated.segment_id)
        object.__setattr__(
            self,
            "segment_relative_path",
            validated.segment_relative_path,
        )
        object.__setattr__(self, "segment_sha256", validated.segment_sha256)
        object.__setattr__(self, "evidence_priority", validated.evidence_priority)
        object.__setattr__(self, "closed_at", validated.closed_at)
        object.__setattr__(
            self,
            "segment_size_bytes",
            validated.segment_size_bytes,
        )
        object.__setattr__(self, "record_count", validated.record_count)
        object.__setattr__(self, "original_device", original_device)
        object.__setattr__(self, "original_inode", original_inode)
        object.__setattr__(self, "records", records)
        _register_identity(
            self,
            _fact_binding_values(
                manifest_canonical=raw,
                manifest_sha256=validated.manifest_sha256,
                previous_manifest_sha256=validated.previous_manifest_sha256,
                prefix_chain_head_sha256=_prefix_chain_head_sha256(validated),
                segment_id=validated.segment_id,
                segment_relative_path=validated.segment_relative_path,
                segment_sha256=validated.segment_sha256,
                evidence_priority=validated.evidence_priority,
                closed_at=validated.closed_at,
                segment_size_bytes=validated.segment_size_bytes,
                record_count=validated.record_count,
                original_device=original_device,
                original_inode=original_inode,
                records=records,
            ),
        )


def _freeze_retention_fact(
    *,
    manifest: SegmentManifestV1,
    records: tuple[FrozenRetentionRecord, ...],
    original_device: int,
    original_inode: int,
) -> FrozenRetentionFact:
    return FrozenRetentionFact(
        manifest=manifest,
        records=records,
        original_device=original_device,
        original_inode=original_inode,
        _factory=_FACT_FACTORY,
    )


def _fact_binding(fact: FrozenRetentionFact) -> bytes:
    if type(fact) is not FrozenRetentionFact:
        raise RetentionCorruption("retention fact runtime type changed")
    binding = _fact_binding_values(
        manifest_canonical=fact.manifest_canonical,
        manifest_sha256=fact.manifest_sha256,
        previous_manifest_sha256=fact.previous_manifest_sha256,
        prefix_chain_head_sha256=fact.prefix_chain_head_sha256,
        segment_id=fact.segment_id,
        segment_relative_path=fact.segment_relative_path,
        segment_sha256=fact.segment_sha256,
        evidence_priority=fact.evidence_priority,
        closed_at=fact.closed_at,
        segment_size_bytes=fact.segment_size_bytes,
        record_count=fact.record_count,
        original_device=fact.original_device,
        original_inode=fact.original_inode,
        records=fact.records,
    )
    _require_identity(fact, binding, "retention fact")
    return binding


def _accepted_binding_values(
    sequence: object,
    event_id: object,
    content_sha256: object,
    request_canonical: object,
) -> bytes:
    if type(request_canonical) is not bytes:
        raise RetentionCorruption("prior tombstone request binding changed")
    try:
        outer = canonical_json(
            {
                "sequence": sequence,
                "event_id": event_id,
                "content_sha256": content_sha256,
            }
        )
    except (TypeError, ValueError) as error:
        raise RetentionCorruption("prior tombstone outer binding is invalid") from error
    return hashlib.sha256(
        _ACCEPTED_BINDING_DOMAIN
        + _framed(outer)
        + _framed(request_canonical)
    ).digest()


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class AcceptedRetentionTombstone:
    """Deep-frozen authenticated outer identity plus its exact request body."""

    sequence: int
    event_id: str
    content_sha256: str
    request_canonical: bytes

    def __init__(
        self,
        *,
        sequence: int,
        event_id: str,
        content_sha256: str,
        request: RetentionTombstoneV2,
        _factory: object,
    ) -> None:
        if _factory is not _ACCEPTED_FACTORY:
            raise TypeError("accepted retention tombstones are factory-only")
        if type(sequence) is not int or not 1 <= sequence <= MAX_UINT64:
            raise RetentionCorruption("prior tombstone sequence is invalid")
        if type(event_id) is not str or _EVENT_ID.fullmatch(event_id) is None:
            raise RetentionCorruption("prior tombstone event identity is invalid")
        if type(content_sha256) is not str or HEX64.fullmatch(content_sha256) is None:
            raise RetentionCorruption("prior tombstone content identity is invalid")
        if type(request) is not RetentionTombstoneV2:
            raise RetentionCorruption("prior tombstone request type is invalid")
        try:
            validated = RetentionTombstoneV2.model_validate(
                request.model_dump(mode="python"),
                strict=True,
            )
            raw = canonical_json(validated.model_dump(mode="python"))
        except (TypeError, ValueError) as error:
            raise RetentionCorruption("prior tombstone request is invalid") from error
        if len(raw) > _TOMBSTONE_MAX_BYTES:
            raise RetentionCorruption("prior tombstone request exceeds its byte bound")
        object.__setattr__(self, "sequence", sequence)
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "content_sha256", content_sha256)
        object.__setattr__(self, "request_canonical", raw)
        _register_identity(
            self,
            _accepted_binding_values(
                sequence,
                event_id,
                content_sha256,
                raw,
            ),
        )

    @property
    def request(self) -> RetentionTombstoneV2:
        binding = _accepted_binding_values(
            self.sequence,
            self.event_id,
            self.content_sha256,
            self.request_canonical,
        )
        _require_identity(self, binding, "accepted retention tombstone")
        request = decode_strict(
            self.request_canonical,
            RetentionTombstoneV2,
            _TOMBSTONE_MAX_BYTES,
        )
        if canonical_json(request.model_dump(mode="python")) != self.request_canonical:
            raise RetentionCorruption("prior tombstone request is not canonical")
        return request


def _freeze_accepted_retention_tombstone(
    *,
    sequence: int,
    event_id: str,
    content_sha256: str,
    request: RetentionTombstoneV2,
) -> AcceptedRetentionTombstone:
    return AcceptedRetentionTombstone(
        sequence=sequence,
        event_id=event_id,
        content_sha256=content_sha256,
        request=request,
        _factory=_ACCEPTED_FACTORY,
    )


def _accepted_binding(accepted: AcceptedRetentionTombstone) -> bytes:
    if type(accepted) is not AcceptedRetentionTombstone:
        raise RetentionCorruption("accepted retention tombstone type changed")
    binding = _accepted_binding_values(
        accepted.sequence,
        accepted.event_id,
        accepted.content_sha256,
        accepted.request_canonical,
    )
    _require_identity(accepted, binding, "accepted retention tombstone")
    return binding


def _decimal_document(value: Decimal) -> dict[str, object]:
    parts = value.as_tuple()
    if type(parts.exponent) is not int:
        raise RetentionCorruption("retention decimal binding is non-finite")
    return {
        "sign": parts.sign,
        "digits": list(parts.digits),
        "exponent": parts.exponent,
    }


def _clock_binding(clock: CoreClockSample) -> bytes:
    if type(clock) is not CoreClockSample:
        raise RetentionCorruption("retention snapshot clock type changed")
    uncertainty: dict[str, object] | None = None
    if clock.uncertainty_seconds is not None:
        uncertainty = _decimal_document(clock.uncertainty_seconds)
    try:
        document = canonical_json(
            {
                "decision_utc": _decision_utc_text(clock.decision_utc),
                "decision_monotonic_hex": clock.decision_monotonic.hex(),
                "healthy": clock.healthy,
                "uncertainty": uncertainty,
                "maximum_uncertainty": _decimal_document(
                    clock.max_uncertainty_seconds
                ),
            }
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise RetentionCorruption("retention snapshot clock binding changed") from error
    return hashlib.sha256(document).digest()


def _snapshot_binding_values(
    facts: object,
    clock: object,
    prior_tombstones: object,
    prior_index_through_sequence: object,
) -> bytes:
    if (
        type(facts) is not tuple
        or type(clock) is not CoreClockSample
        or type(prior_tombstones) is not tuple
        or type(prior_index_through_sequence) is not int
        or not 0 <= prior_index_through_sequence <= MAX_UINT64
    ):
        raise RetentionCorruption("retention snapshot binding fields changed")
    preimage = bytearray(_SNAPSHOT_BINDING_DOMAIN)
    preimage.extend(_clock_binding(clock))
    preimage.extend(len(facts).to_bytes(8, "big"))
    for fact in facts:
        if type(fact) is not FrozenRetentionFact:
            raise RetentionCorruption("retention snapshot fact identity changed")
        preimage.extend(id(fact).to_bytes(8, "big", signed=False))
        preimage.extend(_fact_binding(fact))
    preimage.extend(len(prior_tombstones).to_bytes(8, "big"))
    for accepted in prior_tombstones:
        if type(accepted) is not AcceptedRetentionTombstone:
            raise RetentionCorruption("retention snapshot prior identity changed")
        preimage.extend(id(accepted).to_bytes(8, "big", signed=False))
        preimage.extend(_accepted_binding(accepted))
    preimage.extend(prior_index_through_sequence.to_bytes(8, "big"))
    return hashlib.sha256(preimage).digest()


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class RetentionSnapshot:
    """One immutable chain/clock/prior-authority input to the pure selector."""

    facts: tuple[FrozenRetentionFact, ...]
    clock: CoreClockSample
    prior_tombstones: tuple[AcceptedRetentionTombstone, ...] = ()
    prior_index_through_sequence: int = 0

    def __init__(
        self,
        *,
        facts: tuple[FrozenRetentionFact, ...],
        clock: CoreClockSample,
        prior_tombstones: tuple[AcceptedRetentionTombstone, ...] = (),
        prior_index_through_sequence: int,
        _factory: object,
    ) -> None:
        if _factory is not _SNAPSHOT_FACTORY:
            raise TypeError("retention snapshots are factory-only")
        if type(facts) is not tuple or any(
            type(fact) is not FrozenRetentionFact for fact in facts
        ):
            raise RetentionCorruption("retention snapshot facts are not exact")
        if type(clock) is not CoreClockSample:
            raise RetentionCorruption("retention snapshot clock is not exact")
        if type(prior_tombstones) is not tuple or any(
            type(item) is not AcceptedRetentionTombstone
            for item in prior_tombstones
        ):
            raise RetentionCorruption("retention prior authority is not exact")
        if (
            type(prior_index_through_sequence) is not int
            or not 0 <= prior_index_through_sequence <= MAX_UINT64
        ):
            raise RetentionCorruption(
                "retention prior-index prefix is not exact"
            )
        if prior_tombstones and max(
            item.sequence for item in prior_tombstones
        ) > prior_index_through_sequence:
            raise RetentionCorruption(
                "retention prior-index prefix precedes prior authority"
            )
        try:
            frozen_clock = CoreClockSample(
                decision_utc=clock.decision_utc,
                decision_monotonic=clock.decision_monotonic,
                healthy=clock.healthy,
                uncertainty_seconds=clock.uncertainty_seconds,
                max_uncertainty_seconds=clock.max_uncertainty_seconds,
            )
        except CoreClockValidationError as error:
            raise RetentionCorruption("retention snapshot clock is invalid") from error
        frozen_facts = tuple(facts)
        frozen_prior = tuple(prior_tombstones)
        object.__setattr__(self, "facts", frozen_facts)
        object.__setattr__(self, "clock", frozen_clock)
        object.__setattr__(self, "prior_tombstones", frozen_prior)
        object.__setattr__(
            self,
            "prior_index_through_sequence",
            prior_index_through_sequence,
        )
        _register_identity(
            self,
            _snapshot_binding_values(
                frozen_facts,
                frozen_clock,
                frozen_prior,
                prior_index_through_sequence,
            ),
        )

    @property
    def current_chain_head_sha256(self) -> str:
        _require_identity(
            self,
            _snapshot_binding_values(
                self.facts,
                self.clock,
                self.prior_tombstones,
                self.prior_index_through_sequence,
            ),
            "retention snapshot",
        )
        if not self.facts:
            return "0" * 64
        return self.facts[-1].prefix_chain_head_sha256


def _freeze_retention_snapshot(
    *,
    facts: tuple[FrozenRetentionFact, ...],
    clock: CoreClockSample,
    prior_tombstones: tuple[AcceptedRetentionTombstone, ...] = (),
    prior_index_through_sequence: int,
) -> RetentionSnapshot:
    return RetentionSnapshot(
        facts=facts,
        clock=clock,
        prior_tombstones=prior_tombstones,
        prior_index_through_sequence=prior_index_through_sequence,
        _factory=_SNAPSHOT_FACTORY,
    )


def _snapshot_binding(snapshot: RetentionSnapshot) -> bytes:
    if type(snapshot) is not RetentionSnapshot:
        raise RetentionCorruption("retention snapshot runtime type changed")
    binding = _snapshot_binding_values(
        snapshot.facts,
        snapshot.clock,
        snapshot.prior_tombstones,
        snapshot.prior_index_through_sequence,
    )
    _require_identity(snapshot, binding, "retention snapshot")
    return binding


def _run_binding_values(
    start_index: object,
    manifest_hashes: object,
    removed_bytes: object,
    first_retained_manifest_sha256: object,
) -> bytes:
    try:
        document = canonical_json(
            {
                "start_index": start_index,
                "manifest_hashes": manifest_hashes,
                "removed_bytes": removed_bytes,
                "first_retained_manifest_sha256": (
                    first_retained_manifest_sha256
                ),
            }
        )
    except (TypeError, ValueError) as error:
        raise RetentionCorruption("retention run binding is invalid") from error
    return hashlib.sha256(_RUN_BINDING_DOMAIN + document).digest()


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class RetentionRun:
    _start_index: int
    _manifest_hashes: tuple[str, ...]
    _removed_bytes: int
    _first_retained_manifest_sha256: str

    def __init__(
        self,
        *,
        start_index: int,
        manifest_hashes: tuple[str, ...],
        removed_bytes: int,
        first_retained_manifest_sha256: str,
        _factory: object,
    ) -> None:
        if _factory is not _RUN_FACTORY:
            raise TypeError("retention runs are factory-only")
        if type(start_index) is not int or not 0 <= start_index <= MAX_UINT64:
            raise RetentionCorruption("retention run start is invalid")
        if (
            type(manifest_hashes) is not tuple
            or not 1 <= len(manifest_hashes) <= 128
            or any(
                type(value) is not str or HEX64.fullmatch(value) is None
                for value in manifest_hashes
            )
            or len(set(manifest_hashes)) != len(manifest_hashes)
        ):
            raise RetentionCorruption("retention run manifest hashes are invalid")
        if type(removed_bytes) is not int or not 1 <= removed_bytes <= MAX_UINT64:
            raise RetentionCorruption("retention run byte sum is invalid")
        if (
            type(first_retained_manifest_sha256) is not str
            or HEX64.fullmatch(first_retained_manifest_sha256) is None
        ):
            raise RetentionCorruption("retention run successor is invalid")
        hashes = tuple(manifest_hashes)
        object.__setattr__(self, "_start_index", start_index)
        object.__setattr__(self, "_manifest_hashes", hashes)
        object.__setattr__(self, "_removed_bytes", removed_bytes)
        object.__setattr__(
            self,
            "_first_retained_manifest_sha256",
            first_retained_manifest_sha256,
        )
        _register_identity(
            self,
            _run_binding_values(
                start_index,
                hashes,
                removed_bytes,
                first_retained_manifest_sha256,
            ),
        )

    def _require(self) -> None:
        _require_identity(
            self,
            _run_binding_values(
                self._start_index,
                self._manifest_hashes,
                self._removed_bytes,
                self._first_retained_manifest_sha256,
            ),
            "retention run",
        )

    @property
    def start_index(self) -> int:
        self._require()
        return self._start_index

    @property
    def manifest_hashes(self) -> tuple[str, ...]:
        self._require()
        return self._manifest_hashes

    @property
    def removed_bytes(self) -> int:
        self._require()
        return self._removed_bytes

    @property
    def first_retained_manifest_sha256(self) -> str:
        self._require()
        return self._first_retained_manifest_sha256


def _freeze_retention_run(
    *,
    start_index: int,
    manifest_hashes: tuple[str, ...],
    removed_bytes: int,
    first_retained_manifest_sha256: str,
) -> RetentionRun:
    return RetentionRun(
        start_index=start_index,
        manifest_hashes=manifest_hashes,
        removed_bytes=removed_bytes,
        first_retained_manifest_sha256=first_retained_manifest_sha256,
        _factory=_RUN_FACTORY,
    )


def _run_binding(run: RetentionRun) -> bytes:
    if type(run) is not RetentionRun:
        raise RetentionCorruption("retention run runtime type changed")
    binding = _run_binding_values(
        run._start_index,
        run._manifest_hashes,
        run._removed_bytes,
        run._first_retained_manifest_sha256,
    )
    _require_identity(run, binding, "retention run")
    return binding


def _decision_binding_values(
    *,
    snapshot: object,
    request_kind: object,
    request_canonical: object,
    run: object,
    decision_utc: object,
    clock_healthy: object,
    age_selection_enabled: object,
    uncertainty_ns: object,
    routine_bytes: object,
    protected_bytes: object,
    total_bytes: object,
    age_pressure: object,
    size_pressure: object,
    target_bytes: object,
    maximum_age_ns: object,
    maximum_run_manifests: object,
    removable_event_types: object,
    policy_version: object,
    run_domain: object,
    zero_sha256: object,
    prior_index_count: object,
    prior_index_through_sequence: object,
    prior_index_sha256: object,
) -> bytes:
    if request_canonical is not None and type(request_canonical) is not bytes:
        raise RetentionCorruption("retention decision request bytes changed")
    if run is not None and type(run) is not RetentionRun:
        raise RetentionCorruption("retention decision run identity changed")
    if type(snapshot) is not RetentionSnapshot:
        raise RetentionCorruption("retention decision snapshot identity changed")
    if type(removable_event_types) is not tuple or type(run_domain) is not bytes:
        raise RetentionCorruption("retention decision policy identity changed")
    run_identity = None
    run_binding = b""
    if run is not None:
        run_identity = id(run)
        run_binding = _run_binding(run)
    try:
        document = canonical_json(
            {
                "snapshot_identity": id(snapshot),
                "request_kind": request_kind,
                "request_sha256": (
                    hashlib.sha256(request_canonical).hexdigest()
                    if request_canonical is not None
                    else None
                ),
                "run_identity": run_identity,
                "decision_utc": decision_utc,
                "clock_healthy": clock_healthy,
                "age_selection_enabled": age_selection_enabled,
                "uncertainty_ns": uncertainty_ns,
                "routine_bytes": routine_bytes,
                "protected_bytes": protected_bytes,
                "total_bytes": total_bytes,
                "age_pressure": age_pressure,
                "size_pressure": size_pressure,
                "target_bytes": target_bytes,
                "maximum_age_ns": maximum_age_ns,
                "maximum_run_manifests": maximum_run_manifests,
                "removable_event_types": removable_event_types,
                "policy_version": policy_version,
                "run_domain_sha256": hashlib.sha256(run_domain).hexdigest(),
                "zero_sha256": zero_sha256,
                "prior_index_count": prior_index_count,
                "prior_index_through_sequence": (
                    prior_index_through_sequence
                ),
                "prior_index_sha256": prior_index_sha256,
            }
        )
    except (TypeError, ValueError) as error:
        raise RetentionCorruption("retention decision binding is invalid") from error
    return hashlib.sha256(
        _DECISION_BINDING_DOMAIN
        + _framed(document)
        + _snapshot_binding(snapshot)
        + _framed(request_canonical or b"")
        + _framed(run_domain)
        + run_binding
    ).digest()


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class RetentionDecision:
    """Factory-only, cross-bound selector output."""

    _snapshot: RetentionSnapshot
    _request_kind: _RequestKind | None
    _request_canonical: bytes | None
    _run: RetentionRun | None
    _decision_utc: str
    _clock_healthy: bool
    _age_selection_enabled: bool
    _uncertainty_ns: int | None
    _routine_bytes: int
    _protected_bytes: int
    _total_bytes: int
    _age_pressure: bool
    _size_pressure: bool
    _target_bytes: int
    _maximum_age_ns: int
    _maximum_run_manifests: int
    _removable_event_types: tuple[str, ...]
    _policy_version: Literal["agmind-retention-v1"]
    _run_domain: bytes
    _zero_sha256: str
    _prior_index_count: int
    _prior_index_through_sequence: int
    _prior_index_sha256: str

    def __init__(
        self,
        *,
        snapshot: RetentionSnapshot,
        request_kind: _RequestKind | None,
        request_canonical: bytes | None,
        run: RetentionRun | None,
        decision_utc: str,
        clock_healthy: bool,
        age_selection_enabled: bool,
        uncertainty_ns: int | None,
        routine_bytes: int,
        protected_bytes: int,
        total_bytes: int,
        age_pressure: bool,
        size_pressure: bool,
        target_bytes: int,
        maximum_age_ns: int,
        maximum_run_manifests: int,
        removable_event_types: tuple[str, ...],
        policy_version: Literal["agmind-retention-v1"],
        run_domain: bytes,
        zero_sha256: str,
        prior_index_count: int,
        prior_index_through_sequence: int,
        prior_index_sha256: str,
        _factory: object,
    ) -> None:
        if _factory is not _DECISION_FACTORY:
            raise TypeError("retention decisions are factory-only")
        values: tuple[tuple[str, object], ...] = (
            ("clock_healthy", clock_healthy),
            ("age_selection_enabled", age_selection_enabled),
            ("age_pressure", age_pressure),
            ("size_pressure", size_pressure),
        )
        if any(type(value) is not bool for _, value in values):
            raise RetentionCorruption("retention decision boolean is invalid")
        if type(snapshot) is not RetentionSnapshot:
            raise RetentionCorruption("retention decision snapshot is invalid")
        object.__setattr__(self, "_snapshot", snapshot)
        object.__setattr__(self, "_request_kind", request_kind)
        object.__setattr__(self, "_request_canonical", request_canonical)
        object.__setattr__(self, "_run", run)
        object.__setattr__(self, "_decision_utc", decision_utc)
        object.__setattr__(self, "_clock_healthy", clock_healthy)
        object.__setattr__(
            self,
            "_age_selection_enabled",
            age_selection_enabled,
        )
        object.__setattr__(self, "_uncertainty_ns", uncertainty_ns)
        object.__setattr__(self, "_routine_bytes", routine_bytes)
        object.__setattr__(self, "_protected_bytes", protected_bytes)
        object.__setattr__(self, "_total_bytes", total_bytes)
        object.__setattr__(self, "_age_pressure", age_pressure)
        object.__setattr__(self, "_size_pressure", size_pressure)
        object.__setattr__(self, "_target_bytes", target_bytes)
        object.__setattr__(self, "_maximum_age_ns", maximum_age_ns)
        object.__setattr__(
            self,
            "_maximum_run_manifests",
            maximum_run_manifests,
        )
        object.__setattr__(
            self,
            "_removable_event_types",
            tuple(removable_event_types),
        )
        object.__setattr__(self, "_policy_version", policy_version)
        object.__setattr__(self, "_run_domain", run_domain)
        object.__setattr__(self, "_zero_sha256", zero_sha256)
        object.__setattr__(self, "_prior_index_count", prior_index_count)
        object.__setattr__(
            self,
            "_prior_index_through_sequence",
            prior_index_through_sequence,
        )
        object.__setattr__(
            self,
            "_prior_index_sha256",
            prior_index_sha256,
        )
        _register_identity(self, _decision_binding(self, require=False))

    def _request(self) -> RetentionRequest | None:
        return _validated_decision_request(self)

    @property
    def request(self) -> RetentionRequest | None:
        return self._request()

    @property
    def run(self) -> RetentionRun | None:
        self._request()
        return self._run

    @property
    def decision_utc(self) -> str:
        self._request()
        return self._decision_utc

    @property
    def clock_healthy(self) -> bool:
        self._request()
        return self._clock_healthy

    @property
    def age_selection_enabled(self) -> bool:
        self._request()
        return self._age_selection_enabled

    @property
    def uncertainty_ns(self) -> int | None:
        self._request()
        return self._uncertainty_ns

    @property
    def routine_bytes(self) -> int:
        self._request()
        return self._routine_bytes

    @property
    def protected_bytes(self) -> int:
        self._request()
        return self._protected_bytes

    @property
    def total_bytes(self) -> int:
        self._request()
        return self._total_bytes

    @property
    def age_pressure(self) -> bool:
        self._request()
        return self._age_pressure

    @property
    def size_pressure(self) -> bool:
        self._request()
        return self._size_pressure

    @property
    def target_bytes(self) -> int:
        self._request()
        return self._target_bytes

    @property
    def prior_index_count(self) -> int:
        self._request()
        return self._prior_index_count

    @property
    def prior_index_through_sequence(self) -> int:
        self._request()
        return self._prior_index_through_sequence

    @property
    def prior_index_sha256(self) -> str:
        self._request()
        return self._prior_index_sha256


def _decision_binding(
    decision: RetentionDecision,
    *,
    require: bool,
) -> bytes:
    if type(decision) is not RetentionDecision:
        raise RetentionCorruption("retention decision runtime type changed")
    binding = _decision_binding_values(
        snapshot=decision._snapshot,
        request_kind=decision._request_kind,
        request_canonical=decision._request_canonical,
        run=decision._run,
        decision_utc=decision._decision_utc,
        clock_healthy=decision._clock_healthy,
        age_selection_enabled=decision._age_selection_enabled,
        uncertainty_ns=decision._uncertainty_ns,
        routine_bytes=decision._routine_bytes,
        protected_bytes=decision._protected_bytes,
        total_bytes=decision._total_bytes,
        age_pressure=decision._age_pressure,
        size_pressure=decision._size_pressure,
        target_bytes=decision._target_bytes,
        maximum_age_ns=decision._maximum_age_ns,
        maximum_run_manifests=decision._maximum_run_manifests,
        removable_event_types=decision._removable_event_types,
        policy_version=decision._policy_version,
        run_domain=decision._run_domain,
        zero_sha256=decision._zero_sha256,
        prior_index_count=decision._prior_index_count,
        prior_index_through_sequence=(
            decision._prior_index_through_sequence
        ),
        prior_index_sha256=decision._prior_index_sha256,
    )
    if require:
        _require_identity(decision, binding, "retention decision")
    return binding


def _validated_decision_request(
    decision: RetentionDecision,
) -> RetentionRequest | None:
    _decision_binding(decision, require=True)
    if (
        type(decision._decision_utc) is not str
        or type(decision._clock_healthy) is not bool
        or type(decision._age_selection_enabled) is not bool
        or type(decision._age_pressure) is not bool
        or type(decision._size_pressure) is not bool
        or type(decision._routine_bytes) is not int
        or type(decision._protected_bytes) is not int
        or type(decision._total_bytes) is not int
        or type(decision._target_bytes) is not int
        or not 1 <= decision._target_bytes <= MAX_UINT64
        or type(decision._maximum_age_ns) is not int
        or not 0 <= decision._maximum_age_ns <= MAX_UINT64
        or type(decision._maximum_run_manifests) is not int
        or not 1 <= decision._maximum_run_manifests <= 128
        or type(decision._removable_event_types) is not tuple
        or not decision._removable_event_types
        or any(
            not _is_printable_ascii(value)
            for value in decision._removable_event_types
        )
        or type(decision._policy_version) is not str
        or decision._policy_version != "agmind-retention-v1"
        or type(decision._run_domain) is not bytes
        or not decision._run_domain
        or type(decision._zero_sha256) is not str
        or HEX64.fullmatch(decision._zero_sha256) is None
        or type(decision._prior_index_count) is not int
        or not 0 <= decision._prior_index_count <= MAX_UINT64
        or type(decision._prior_index_through_sequence) is not int
        or not 0 <= decision._prior_index_through_sequence <= MAX_UINT64
        or type(decision._prior_index_sha256) is not str
        or HEX64.fullmatch(decision._prior_index_sha256) is None
    ):
        raise RetentionCorruption("retention decision scalar type changed")
    _snapshot_binding(decision._snapshot)
    prior_count, prior_last_sequence, prior_sha256 = (
        _prior_index_commitment(decision._snapshot.prior_tombstones)
    )
    if (
        decision._snapshot.prior_index_through_sequence
        != decision._prior_index_through_sequence
        or prior_last_sequence > decision._prior_index_through_sequence
        or prior_count != decision._prior_index_count
        or prior_sha256 != decision._prior_index_sha256
    ):
        raise RetentionCorruption(
            "retention decision prior-index witness changed"
        )
    _timestamp_ns(decision._decision_utc)
    total = _checked_add(
        decision._routine_bytes,
        decision._protected_bytes,
        "decision closed payload bytes",
    )
    if total != decision._total_bytes:
        raise RetentionCorruption("retention decision total bytes are inconsistent")
    if decision._size_pressure != (total > decision._target_bytes):
        raise RetentionCorruption("retention decision size pressure is inconsistent")
    if decision._age_selection_enabled:
        if (
            not decision._clock_healthy
            or type(decision._uncertainty_ns) is not int
            or not 0 <= decision._uncertainty_ns <= MAX_UINT64
        ):
            raise RetentionCorruption("retention decision clock witness is inconsistent")
    elif decision._uncertainty_ns is not None:
        raise RetentionCorruption("disabled retention age has uncertainty bytes")

    raw = decision._request_canonical
    if decision._request_kind is None:
        if (
            raw is not None
            or decision._run is not None
            or decision._age_pressure
            or decision._size_pressure
        ):
            raise RetentionCorruption("empty retention decision is inconsistent")
        return None
    if type(raw) is not bytes or not raw or len(raw) > _TOMBSTONE_MAX_BYTES:
        raise RetentionCorruption("retention decision request bytes are invalid")
    try:
        if decision._request_kind == "tombstone":
            request: RetentionRequest = decode_strict(
                raw,
                RetentionTombstoneV2,
                _TOMBSTONE_MAX_BYTES,
            )
        elif decision._request_kind == "blocked":
            request = decode_strict(
                raw,
                RetentionBlockedV1,
                _TOMBSTONE_MAX_BYTES,
            )
        else:
            raise RetentionCorruption("retention decision request kind changed")
    except (TypeError, ValueError) as error:
        raise RetentionCorruption("retention decision request is invalid") from error
    if canonical_json(request.model_dump(mode="python")) != raw:
        raise RetentionCorruption("retention decision request is not canonical")
    if (
        request.current_chain_head_sha256
        != decision._snapshot.current_chain_head_sha256
    ):
        raise RetentionCorruption(
            "retention decision request changed its snapshot H0"
        )

    if type(request) is RetentionTombstoneV2:
        run = decision._run
        if run is None:
            raise RetentionCorruption("retention tombstone decision lost its run")
        _run_binding(run)
        if (
            request.removed_manifest_hashes != list(run._manifest_hashes)
            or request.removed_bytes != run._removed_bytes
            or request.first_retained_manifest_sha256
            != run._first_retained_manifest_sha256
            or run._removed_bytes > total
        ):
            raise RetentionCorruption("retention request and run differ")
        expected_reason = (
            "retention_age_and_size_limit"
            if decision._age_pressure and decision._size_pressure
            else (
                "retention_age_limit"
                if decision._age_pressure
                else "retention_size_limit"
            )
        )
        if (
            not decision._age_pressure
            and not decision._size_pressure
            or request.reason != expected_reason
        ):
            raise RetentionCorruption("retention tombstone reason is inconsistent")
        return request

    if type(request) is not RetentionBlockedV1:
        raise RetentionCorruption("retention blocked request type changed")
    blocked_request = request
    if (
        decision._run is not None
        or decision._age_pressure
        or not decision._size_pressure
        or blocked_request.target_bytes != decision._target_bytes
        or blocked_request.routine_bytes != decision._routine_bytes
        or blocked_request.protected_bytes != decision._protected_bytes
        or blocked_request.blocked_bytes != total - decision._target_bytes
    ):
        raise RetentionCorruption("retention blocked decision is inconsistent")
    return blocked_request


def _freeze_retention_decision(
    *,
    snapshot: RetentionSnapshot,
    request_kind: _RequestKind | None,
    request_canonical: bytes | None,
    run: RetentionRun | None,
    decision_utc: str,
    clock_healthy: bool,
    age_selection_enabled: bool,
    uncertainty_ns: int | None,
    routine_bytes: int,
    protected_bytes: int,
    total_bytes: int,
    age_pressure: bool,
    size_pressure: bool,
    target_bytes: int,
    maximum_age_ns: int,
    maximum_run_manifests: int,
    removable_event_types: tuple[str, ...],
    policy_version: Literal["agmind-retention-v1"],
    run_domain: bytes,
    zero_sha256: str,
    prior_index_count: int,
    prior_index_through_sequence: int,
    prior_index_sha256: str,
) -> RetentionDecision:
    decision = RetentionDecision(
        snapshot=snapshot,
        request_kind=request_kind,
        request_canonical=request_canonical,
        run=run,
        decision_utc=decision_utc,
        clock_healthy=clock_healthy,
        age_selection_enabled=age_selection_enabled,
        uncertainty_ns=uncertainty_ns,
        routine_bytes=routine_bytes,
        protected_bytes=protected_bytes,
        total_bytes=total_bytes,
        age_pressure=age_pressure,
        size_pressure=size_pressure,
        target_bytes=target_bytes,
        maximum_age_ns=maximum_age_ns,
        maximum_run_manifests=maximum_run_manifests,
        removable_event_types=removable_event_types,
        policy_version=policy_version,
        run_domain=run_domain,
        zero_sha256=zero_sha256,
        prior_index_count=prior_index_count,
        prior_index_through_sequence=prior_index_through_sequence,
        prior_index_sha256=prior_index_sha256,
        _factory=_DECISION_FACTORY,
    )
    _validated_decision_request(decision)
    return decision


@dataclass(frozen=True, slots=True)
class _ValidatedFact:
    manifest_sha256: str
    previous_manifest_sha256: str
    prefix_chain_head_sha256: str
    segment_id: str
    segment_relative_path: str
    segment_sha256: str
    evidence_priority: EvidencePriorityName
    segment_size_bytes: int
    original_device: int
    original_inode: int
    closed_ns: int
    removable: bool


def _validate_clock(sample: CoreClockSample) -> CoreClockSample:
    if type(sample) is not CoreClockSample:
        raise RetentionCorruption("retention clock type is invalid")
    try:
        return CoreClockSample(
            decision_utc=sample.decision_utc,
            decision_monotonic=sample.decision_monotonic,
            healthy=sample.healthy,
            uncertainty_seconds=sample.uncertainty_seconds,
            max_uncertainty_seconds=sample.max_uncertainty_seconds,
        )
    except CoreClockValidationError as error:
        raise RetentionCorruption("retention clock sample is invalid") from error


def _validate_fact(
    fact: FrozenRetentionFact,
    *,
    removable_event_types: frozenset[str],
) -> _ValidatedFact:
    if type(fact) is not FrozenRetentionFact:
        raise RetentionCorruption("retention fact type is invalid")
    _fact_binding(fact)
    try:
        manifest = decode_strict(
            fact.manifest_canonical,
            SegmentManifestV1,
            _MANIFEST_MAX_BYTES,
        )
        expected_raw = canonical_json(manifest.model_dump(mode="python"))
    except (TypeError, ValueError) as error:
        raise RetentionCorruption("retention fact manifest bytes are invalid") from error
    expected = (
        manifest.manifest_sha256,
        manifest.previous_manifest_sha256,
        _prefix_chain_head_sha256(manifest),
        manifest.segment_id,
        manifest.segment_relative_path,
        manifest.segment_sha256,
        manifest.evidence_priority,
        manifest.closed_at,
        manifest.segment_size_bytes,
        manifest.record_count,
    )
    observed = (
        fact.manifest_sha256,
        fact.previous_manifest_sha256,
        fact.prefix_chain_head_sha256,
        fact.segment_id,
        fact.segment_relative_path,
        fact.segment_sha256,
        fact.evidence_priority,
        fact.closed_at,
        fact.segment_size_bytes,
        fact.record_count,
    )
    if expected_raw != fact.manifest_canonical or observed != expected:
        raise RetentionCorruption("retention fact differs from canonical manifest")
    if (
        type(fact.original_device) is not int
        or type(fact.original_inode) is not int
        or not 0 <= fact.original_device <= MAX_UINT64
        or not 1 <= fact.original_inode <= MAX_UINT64
    ):
        raise RetentionCorruption("retention fact payload identity changed")
    if type(fact.records) is not tuple or any(
        type(record) is not FrozenRetentionRecord for record in fact.records
    ):
        raise RetentionCorruption("retention fact record tuple is invalid")
    if len(fact.records) != fact.record_count:
        raise RetentionCorruption("retention fact record count changed")
    for record in fact.records:
        if not _is_printable_ascii(record.event_type):
            raise RetentionCorruption("retention record event type changed")
        if (
            type(record.evidence_priority) is not str
            or record.evidence_priority not in {"routine", "protected"}
        ):
            raise RetentionCorruption("retention record priority changed")
        if fact.evidence_priority == "routine" and record.evidence_priority == "protected":
            raise RetentionCorruption(
                "protected event appears in a purported routine payload"
            )
        if record.evidence_priority != fact.evidence_priority:
            raise RetentionCorruption("record priority differs from manifest priority")
    removable = (
        fact.evidence_priority == "routine"
        and all(
            record.event_type in removable_event_types
            for record in fact.records
        )
    )
    return _ValidatedFact(
        manifest_sha256=fact.manifest_sha256,
        previous_manifest_sha256=fact.previous_manifest_sha256,
        prefix_chain_head_sha256=fact.prefix_chain_head_sha256,
        segment_id=fact.segment_id,
        segment_relative_path=fact.segment_relative_path,
        segment_sha256=fact.segment_sha256,
        evidence_priority=fact.evidence_priority,
        segment_size_bytes=fact.segment_size_bytes,
        original_device=fact.original_device,
        original_inode=fact.original_inode,
        closed_ns=_timestamp_ns(fact.closed_at),
        removable=removable,
    )


def _validate_snapshot(
    snapshot: RetentionSnapshot,
    *,
    removable_event_types: frozenset[str],
    genesis_manifest_sha256: str,
) -> tuple[
    tuple[_ValidatedFact, ...],
    CoreClockSample,
    tuple[AcceptedRetentionTombstone, ...],
]:
    if type(snapshot) is not RetentionSnapshot:
        raise RetentionCorruption("retention snapshot type is invalid")
    _snapshot_binding(snapshot)
    if type(snapshot.facts) is not tuple or type(snapshot.prior_tombstones) is not tuple:
        raise RetentionCorruption("retention snapshot collections changed")
    clock = _validate_clock(snapshot.clock)
    validated: list[_ValidatedFact] = []
    previous = genesis_manifest_sha256
    manifest_hashes: set[str] = set()
    prefix_heads: set[str] = set()
    segment_ids: set[str] = set()
    segment_paths: set[str] = set()
    for fact in snapshot.facts:
        item = _validate_fact(
            fact,
            removable_event_types=removable_event_types,
        )
        if item.previous_manifest_sha256 != previous:
            raise RetentionCorruption("retention manifest chain is not contiguous")
        if item.manifest_sha256 in manifest_hashes:
            raise RetentionCorruption("retention manifest hash is not unique")
        if item.prefix_chain_head_sha256 in prefix_heads:
            raise RetentionCorruption("retention historical chain head is not unique")
        if item.segment_id in segment_ids:
            raise RetentionCorruption("retention segment identity is not unique")
        if item.segment_relative_path in segment_paths:
            raise RetentionCorruption("retention segment path is not unique")
        manifest_hashes.add(item.manifest_sha256)
        prefix_heads.add(item.prefix_chain_head_sha256)
        segment_ids.add(item.segment_id)
        segment_paths.add(item.segment_relative_path)
        previous = item.manifest_sha256
        validated.append(item)
    if any(
        type(item) is not AcceptedRetentionTombstone
        for item in snapshot.prior_tombstones
    ):
        raise RetentionCorruption("retention prior authority changed")
    return tuple(validated), clock, tuple(snapshot.prior_tombstones)


def _validated_prior(
    accepted: AcceptedRetentionTombstone,
) -> tuple[RetentionTombstoneV2, bytes, tuple[int, str, str]]:
    if type(accepted) is not AcceptedRetentionTombstone:
        raise RetentionCorruption("prior tombstone runtime type changed")
    _accepted_binding(accepted)
    if (
        type(accepted.sequence) is not int
        or not 1 <= accepted.sequence <= MAX_UINT64
        or type(accepted.event_id) is not str
        or _EVENT_ID.fullmatch(accepted.event_id) is None
        or type(accepted.content_sha256) is not str
        or HEX64.fullmatch(accepted.content_sha256) is None
        or type(accepted.request_canonical) is not bytes
    ):
        raise RetentionCorruption("prior tombstone outer identity changed")
    try:
        request = decode_strict(
            accepted.request_canonical,
            RetentionTombstoneV2,
            _TOMBSTONE_MAX_BYTES,
        )
    except (TypeError, ValueError) as error:
        raise RetentionCorruption("prior tombstone request bytes changed") from error
    if canonical_json(request.model_dump(mode="python")) != accepted.request_canonical:
        raise RetentionCorruption("prior tombstone request is not canonical")
    return (
        request,
        accepted.request_canonical,
        (accepted.sequence, accepted.event_id, accepted.content_sha256),
    )


def _prior_index_commitment(
    prior: tuple[AcceptedRetentionTombstone, ...],
) -> tuple[int, int, str]:
    preimage = bytearray(_PRIOR_INDEX_DOMAIN)
    by_id: dict[str, tuple[bytes, tuple[int, str, str]]] = {}
    count = 0
    previous_sequence = 0
    for accepted in prior:
        request, request_raw, outer = _validated_prior(accepted)
        existing = by_id.get(request.tombstone_id)
        if existing is not None:
            existing_raw, existing_outer = existing
            if existing_raw != request_raw:
                raise RetentionCorruption(
                    "same tombstone ID has a body conflict"
                )
            if existing_outer != outer:
                raise RetentionCorruption(
                    "same tombstone body has another authenticated outer identity"
                )
            continue
        if accepted.sequence <= previous_sequence:
            raise RetentionCorruption(
                "prior tombstone evidence order is invalid"
            )
        record = canonical_json(
            {
                "sequence": accepted.sequence,
                "event_id": accepted.event_id,
                "content_sha256": accepted.content_sha256,
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
                "manifest_run_sha256": request.manifest_run_sha256,
            }
        )
        preimage.extend(len(record).to_bytes(8, "big"))
        preimage.extend(record)
        count = _checked_add(count, 1, "prior tombstone index count")
        previous_sequence = accepted.sequence
        by_id[request.tombstone_id] = (request_raw, outer)
    return count, previous_sequence, hashlib.sha256(preimage).hexdigest()


def _prior_coverage(
    facts: tuple[_ValidatedFact, ...],
    prior: tuple[AcceptedRetentionTombstone, ...],
    *,
    zero_sha256: str,
) -> frozenset[int]:
    positions = {
        item.manifest_sha256: index for index, item in enumerate(facts)
    }
    prefix_tips = {
        item.prefix_chain_head_sha256: index for index, item in enumerate(facts)
    }
    covered: set[int] = set()
    by_id: dict[str, tuple[bytes, tuple[int, str, str]]] = {}
    previous_sequence = 0
    previous_end = -1
    previous_tip = -1

    for accepted in prior:
        request, request_raw, outer = _validated_prior(accepted)
        existing = by_id.get(request.tombstone_id)
        if existing is not None:
            existing_raw, existing_outer = existing
            if request_raw != existing_raw:
                raise RetentionCorruption("same tombstone ID has a body conflict")
            if outer != existing_outer:
                raise RetentionCorruption(
                    "same tombstone body has another authenticated outer identity"
                )
            continue
        if accepted.sequence <= previous_sequence:
            raise RetentionCorruption("prior tombstone evidence order is invalid")
        tip = prefix_tips.get(request.current_chain_head_sha256)
        if tip is None:
            raise RetentionCorruption("prior tombstone H0 is not a historical prefix")
        try:
            run_positions = tuple(
                positions[manifest_hash]
                for manifest_hash in request.removed_manifest_hashes
            )
        except KeyError as error:
            raise RetentionCorruption("prior tombstone names an unknown manifest") from error
        if not run_positions or any(
            right != left + 1
            for left, right in pairwise(run_positions)
        ):
            raise RetentionCorruption("prior tombstone run is not chain-adjacent")
        start = run_positions[0]
        end = run_positions[-1]
        if end > tip:
            raise RetentionCorruption("prior tombstone run is outside its H0 prefix")
        expected_successor = (
            facts[end + 1].manifest_sha256 if end < tip else zero_sha256
        )
        if request.first_retained_manifest_sha256 != expected_successor:
            raise RetentionCorruption(
                "prior tombstone successor differs from its historical prefix"
            )
        removed_bytes = 0
        for position in run_positions:
            if not facts[position].removable:
                raise RetentionCorruption("prior tombstone covers non-removable evidence")
            removed_bytes = _checked_add(
                removed_bytes,
                facts[position].segment_size_bytes,
                "prior removed bytes",
            )
        if removed_bytes != request.removed_bytes:
            raise RetentionCorruption("prior tombstone removed byte sum is wrong")
        intersection = covered.intersection(run_positions)
        if intersection:
            raise RetentionCorruption("different prior tombstones overlap")
        if start <= previous_end or tip < previous_tip:
            raise RetentionCorruption("prior tombstone runs are out of order")
        covered.update(run_positions)
        by_id[request.tombstone_id] = (request_raw, outer)
        previous_sequence = accepted.sequence
        previous_end = end
        previous_tip = tip

    return frozenset(covered)


def _clock_selection(
    clock: CoreClockSample,
) -> tuple[int, bool, int | None]:
    decision_ns = _datetime_ns(clock.decision_utc)
    uncertainty = clock.uncertainty_seconds
    enabled = (
        clock.healthy
        and uncertainty is not None
        and uncertainty <= clock.max_uncertainty_seconds
    )
    if not enabled or uncertainty is None:
        return decision_ns, False, None
    uncertainty_ns = _exact_ceil_nanoseconds(uncertainty)
    return decision_ns, True, uncertainty_ns


def _exact_ceil_nanoseconds(value: Decimal) -> int:
    parts = value.as_tuple()
    exponent_value: object = parts.exponent
    if type(exponent_value) is not int:
        raise RetentionCorruption("retention uncertainty is non-finite")
    exponent = int(exponent_value)
    digits = tuple(int(digit) for digit in parts.digits)
    first_nonzero = next(
        (index for index, digit in enumerate(digits) if digit != 0),
        None,
    )
    if first_nonzero is None:
        return 0
    if parts.sign != 0:
        raise RetentionCorruption("retention uncertainty is negative")
    significant = digits[first_nonzero:]
    power = exponent + 9
    result: int
    if power >= 0:
        if len(significant) + power > 20:
            raise RetentionCorruption(
                "retention uncertainty nanoseconds exceed uint64"
            )
        coefficient = 0
        for digit in significant:
            coefficient = coefficient * 10 + digit
        result = coefficient * 10**power
    else:
        scale = -power
        quotient_length = len(significant) - scale
        if quotient_length <= 0:
            result = 1
        else:
            if quotient_length > 20:
                raise RetentionCorruption(
                    "retention uncertainty nanoseconds exceed uint64"
                )
            quotient = 0
            for digit in significant[:quotient_length]:
                quotient = quotient * 10 + digit
            remainder = any(
                digit != 0 for digit in significant[quotient_length:]
            )
            result = quotient + int(remainder)
    if result > MAX_UINT64:
        raise RetentionCorruption("retention uncertainty nanoseconds exceed uint64")
    return result


def _request_bytes(request: RetentionRequest | None) -> tuple[_RequestKind | None, bytes | None]:
    if request is None:
        return None, None
    kind: _RequestKind = (
        "tombstone" if type(request) is RetentionTombstoneV2 else "blocked"
    )
    return kind, canonical_json(request.model_dump(mode="python"))


def _decision(
    *,
    snapshot: RetentionSnapshot,
    request: RetentionRequest | None,
    run: RetentionRun | None,
    clock: CoreClockSample,
    age_enabled: bool,
    uncertainty_ns: int | None,
    routine_bytes: int,
    protected_bytes: int,
    total_bytes: int,
    age_pressure: bool,
    size_pressure: bool,
    target_bytes: int,
    maximum_age_ns: int,
    maximum_run_manifests: int,
    removable_event_types: frozenset[str],
    policy_version: Literal["agmind-retention-v1"],
    run_domain: bytes,
    zero_sha256: str,
    prior_index_count: int,
    prior_index_sha256: str,
) -> RetentionDecision:
    kind, raw = _request_bytes(request)
    return _freeze_retention_decision(
        snapshot=snapshot,
        request_kind=kind,
        request_canonical=raw,
        run=run,
        decision_utc=_decision_utc_text(clock.decision_utc),
        clock_healthy=clock.healthy,
        age_selection_enabled=age_enabled,
        uncertainty_ns=uncertainty_ns,
        routine_bytes=routine_bytes,
        protected_bytes=protected_bytes,
        total_bytes=total_bytes,
        age_pressure=age_pressure,
        size_pressure=size_pressure,
        target_bytes=target_bytes,
        maximum_age_ns=maximum_age_ns,
        maximum_run_manifests=maximum_run_manifests,
        removable_event_types=tuple(sorted(removable_event_types)),
        policy_version=policy_version,
        run_domain=run_domain,
        zero_sha256=zero_sha256,
        prior_index_count=prior_index_count,
        prior_index_through_sequence=(
            snapshot.prior_index_through_sequence
        ),
        prior_index_sha256=prior_index_sha256,
    )


def _select_retention(
    snapshot: RetentionSnapshot,
    *,
    request_id: str,
    target_bytes: int,
    maximum_age_ns: int,
    maximum_run_manifests: int,
    removable_event_types: frozenset[str],
    policy_version: Literal["agmind-retention-v1"],
    run_domain: bytes,
    zero_sha256: str,
) -> RetentionDecision:
    if type(request_id) is not str or UUID4.fullmatch(request_id) is None:
        raise RetentionCorruption("retention request ID must be lowercase UUIDv4")
    facts, clock, prior = _validate_snapshot(
        snapshot,
        removable_event_types=removable_event_types,
        genesis_manifest_sha256=zero_sha256,
    )
    covered = _prior_coverage(
        facts,
        prior,
        zero_sha256=zero_sha256,
    )
    prior_index_count, prior_last_sequence, prior_index_sha256 = (
        _prior_index_commitment(prior)
    )
    if prior_last_sequence > snapshot.prior_index_through_sequence:
        raise RetentionCorruption(
            "retention prior-index prefix precedes prior authority"
        )
    current_head = (
        facts[-1].prefix_chain_head_sha256 if facts else zero_sha256
    )
    decision_ns, age_enabled, uncertainty_ns = _clock_selection(clock)
    cutoff_ns = (
        decision_ns - maximum_age_ns - uncertainty_ns
        if age_enabled and uncertainty_ns is not None
        else None
    )

    routine_bytes = 0
    protected_bytes = 0
    for index, item in enumerate(facts):
        if index in covered:
            continue
        if item.evidence_priority == "routine":
            routine_bytes = _checked_add(
                routine_bytes,
                item.segment_size_bytes,
                "routine bytes",
            )
        else:
            protected_bytes = _checked_add(
                protected_bytes,
                item.segment_size_bytes,
                "protected bytes",
            )
    total_bytes = _checked_add(routine_bytes, protected_bytes, "closed payload bytes")
    size_pressure = total_bytes > target_bytes

    selected: set[int] = set()
    for index, item in enumerate(facts):
        if (
            index not in covered
            and item.removable
            and cutoff_ns is not None
            and item.closed_ns < cutoff_ns
        ):
            selected.add(index)
    age_pressure = bool(selected)

    projected_bytes = total_bytes
    for index in selected:
        projected_bytes = _checked_sub(
            projected_bytes,
            facts[index].segment_size_bytes,
            "age-selected bytes",
        )
    if projected_bytes > target_bytes:
        for index, item in enumerate(facts):
            if index in covered or index in selected or not item.removable:
                continue
            selected.add(index)
            projected_bytes = _checked_sub(
                projected_bytes,
                item.segment_size_bytes,
                "size-selected bytes",
            )
            if projected_bytes <= target_bytes:
                break

    if selected:
        start = min(selected)
        run_positions: list[int] = []
        position = start
        while (
            position < len(facts)
            and position in selected
            and len(run_positions) < maximum_run_manifests
        ):
            run_positions.append(position)
            position += 1
        manifest_hashes = tuple(
            facts[index].manifest_sha256 for index in run_positions
        )
        removed_bytes = 0
        for index in run_positions:
            removed_bytes = _checked_add(
                removed_bytes,
                facts[index].segment_size_bytes,
                "selected removed bytes",
            )
        successor = (
            facts[position].manifest_sha256
            if position < len(facts)
            else zero_sha256
        )
        run = _freeze_retention_run(
            start_index=start,
            manifest_hashes=manifest_hashes,
            removed_bytes=removed_bytes,
            first_retained_manifest_sha256=successor,
        )
        if age_pressure and size_pressure:
            reason: Literal[
                "retention_age_limit",
                "retention_size_limit",
                "retention_age_and_size_limit",
            ] = "retention_age_and_size_limit"
        elif age_pressure:
            reason = "retention_age_limit"
        else:
            reason = "retention_size_limit"
        hash_list = list(manifest_hashes)
        request = RetentionTombstoneV2(
            schema_version="agmind.retention-tombstone.v2",
            tombstone_id=request_id,
            removed_manifest_hashes=hash_list,
            first_removed_manifest_sha256=hash_list[0],
            last_removed_manifest_sha256=hash_list[-1],
            first_retained_manifest_sha256=successor,
            removed_bytes=removed_bytes,
            reason=reason,
            policy_version=policy_version,
            current_chain_head_sha256=current_head,
            manifest_run_sha256=hashlib.sha256(
                run_domain + canonical_json(hash_list)
            ).hexdigest(),
        )
        return _decision(
            snapshot=snapshot,
            request=request,
            run=run,
            clock=clock,
            age_enabled=age_enabled,
            uncertainty_ns=uncertainty_ns,
            routine_bytes=routine_bytes,
            protected_bytes=protected_bytes,
            total_bytes=total_bytes,
            age_pressure=age_pressure,
            size_pressure=size_pressure,
            target_bytes=target_bytes,
            maximum_age_ns=maximum_age_ns,
            maximum_run_manifests=maximum_run_manifests,
            removable_event_types=removable_event_types,
            policy_version=policy_version,
            run_domain=run_domain,
            zero_sha256=zero_sha256,
            prior_index_count=prior_index_count,
            prior_index_sha256=prior_index_sha256,
        )

    blocked: RetentionBlockedV1 | None = None
    if total_bytes > target_bytes:
        blocked = RetentionBlockedV1(
            schema_version="agmind.retention-blocked.v1",
            blocked_id=request_id,
            target_bytes=target_bytes,
            routine_bytes=routine_bytes,
            protected_bytes=protected_bytes,
            blocked_bytes=_checked_sub(
                total_bytes,
                target_bytes,
                "blocked bytes",
            ),
            reason="protected_evidence",
            current_chain_head_sha256=current_head,
        )
    return _decision(
        snapshot=snapshot,
        request=blocked,
        run=None,
        clock=clock,
        age_enabled=age_enabled,
        uncertainty_ns=uncertainty_ns,
        routine_bytes=routine_bytes,
        protected_bytes=protected_bytes,
        total_bytes=total_bytes,
        age_pressure=age_pressure,
        size_pressure=size_pressure,
        target_bytes=target_bytes,
        maximum_age_ns=maximum_age_ns,
        maximum_run_manifests=maximum_run_manifests,
        removable_event_types=removable_event_types,
        policy_version=policy_version,
        run_domain=run_domain,
        zero_sha256=zero_sha256,
        prior_index_count=prior_index_count,
        prior_index_sha256=prior_index_sha256,
    )


class _RetentionSelector(Protocol):
    def __call__(
        self,
        snapshot: RetentionSnapshot,
        *,
        request_id: str,
    ) -> RetentionDecision: ...


def _make_retention_selector(
    *,
    target_bytes: int,
    maximum_age_ns: int,
    maximum_run_manifests: int,
    removable_event_types: frozenset[str],
    policy_version: Literal["agmind-retention-v1"],
    run_domain: bytes,
    zero_sha256: str,
) -> _RetentionSelector:
    if (
        type(target_bytes) is not int
        or not 1 <= target_bytes <= MAX_UINT64
        or type(maximum_age_ns) is not int
        or not 0 <= maximum_age_ns <= MAX_UINT64
        or type(maximum_run_manifests) is not int
        or not 1 <= maximum_run_manifests <= 128
        or type(removable_event_types) is not frozenset
        or not removable_event_types
        or any(not _is_printable_ascii(value) for value in removable_event_types)
        or type(run_domain) is not bytes
        or not run_domain
        or type(zero_sha256) is not str
        or HEX64.fullmatch(zero_sha256) is None
    ):
        raise RetentionCorruption("retention selector policy is invalid")
    frozen_events = frozenset(removable_event_types)

    def selector(
        snapshot: RetentionSnapshot,
        *,
        request_id: str,
    ) -> RetentionDecision:
        return _select_retention(
            snapshot,
            request_id=request_id,
            target_bytes=target_bytes,
            maximum_age_ns=maximum_age_ns,
            maximum_run_manifests=maximum_run_manifests,
            removable_event_types=frozen_events,
            policy_version=policy_version,
            run_domain=run_domain,
            zero_sha256=zero_sha256,
        )

    return selector


select_retention: _RetentionSelector = _make_retention_selector(
    target_bytes=5 * 1024**3,
    maximum_age_ns=7 * 24 * 60 * 60 * 1_000_000_000,
    maximum_run_manifests=128,
    removable_event_types=frozenset({"falco_connect"}),
    policy_version="agmind-retention-v1",
    run_domain=b"AGMIND_RETENTION_RUN_V2\x00",
    zero_sha256="0" * 64,
)


RetentionPhase = Literal[
    "selected",
    "target_bound",
    "evidence_appended",
    "retention_unlink_in_progress",
    "retention_commit_uncertain",
    "completed",
]
RetentionOperation = Literal["tombstone", "blocked"]


class RetentionTargetV1(ContractModel):
    """Exact outer identity of one signed retention control event."""

    sequence: int = Field(ge=1, le=MAX_UINT64)
    event_id: str
    content_sha256: str

    @field_validator("event_id")
    @classmethod
    def event_id_is_exact(cls, value: str) -> str:
        if _EVENT_ID.fullmatch(value) is None:
            raise ValueError("retention target event_id is invalid")
        return value

    @field_validator("content_sha256")
    @classmethod
    def content_sha256_is_exact(cls, value: str) -> str:
        if HEX64.fullmatch(value) is None:
            raise ValueError("retention target content hash is invalid")
        return value


class RetentionStateEntryV1(ContractModel):
    """One selected closed payload bound into durable retention state."""

    manifest_sha256: str
    segment_id: str
    segment_relative_path: str
    segment_size_bytes: int = Field(
        gt=0,
        le=MAX_EVIDENCE_SEGMENT_BYTES,
    )
    segment_sha256: str
    original_device: int = Field(ge=0, le=MAX_UINT64)
    original_inode: int = Field(gt=0, le=MAX_UINT64)

    @field_validator("manifest_sha256", "segment_sha256")
    @classmethod
    def digest_is_exact(cls, value: str) -> str:
        if HEX64.fullmatch(value) is None:
            raise ValueError("retention state entry digest is invalid")
        return value

    @field_validator("segment_id")
    @classmethod
    def segment_id_is_exact(cls, value: str) -> str:
        if UUID4.fullmatch(value) is None:
            raise ValueError("retention state segment_id is invalid")
        return value

    @field_validator("segment_relative_path")
    @classmethod
    def segment_path_is_canonical(cls, value: str) -> str:
        match = _SEGMENT_RELATIVE_PATH.fullmatch(value)
        if match is None:
            raise ValueError("retention state segment path is invalid")
        try:
            parsed = date.fromisoformat(match.group("date"))
        except ValueError as error:
            raise ValueError(
                "retention state segment path date is invalid"
            ) from error
        if (
            parsed.isoformat() != match.group("date")
            or not 1 <= int(match.group("sequence")) <= MAX_UINT64
        ):
            raise ValueError("retention state segment path is not canonical")
        return value

    @model_validator(mode="after")
    def path_binds_segment(self) -> RetentionStateEntryV1:
        match = _SEGMENT_RELATIVE_PATH.fullmatch(self.segment_relative_path)
        if match is None or match.group("segment") != self.segment_id:
            raise ValueError(
                "retention state path does not bind segment identity"
            )
        return self


class RetentionSelectionWitnessV1(ContractModel):
    """Complete fixed-policy and prior-index witness for one selection."""

    policy_version: Literal["agmind-retention-v1"]
    maximum_age_ns: int = Field(ge=0, le=MAX_UINT64)
    target_bytes: int = Field(gt=0, le=MAX_UINT64)
    maximum_run_manifests: int = Field(ge=1, le=128)
    removable_event_types: list[str] = Field(min_length=1, max_length=1)
    decision_utc: str
    clock_healthy: bool
    age_selection_enabled: bool
    uncertainty_ns: int | None = Field(default=None, ge=0, le=MAX_UINT64)
    routine_bytes: int = Field(ge=0, le=MAX_UINT64)
    protected_bytes: int = Field(ge=0, le=MAX_UINT64)
    total_bytes: int = Field(ge=0, le=MAX_UINT64)
    age_pressure: bool
    size_pressure: bool
    prior_index_count: int = Field(ge=0, le=MAX_UINT64)
    prior_index_through_sequence: int = Field(ge=0, le=MAX_UINT64)
    prior_index_sha256: str

    @field_validator("decision_utc")
    @classmethod
    def decision_utc_is_exact(cls, value: str) -> str:
        try:
            _timestamp_ns(value)
        except RetentionCorruption as error:
            raise ValueError(
                "retention witness decision UTC is invalid"
            ) from error
        return value

    @field_validator("prior_index_sha256")
    @classmethod
    def prior_index_digest_is_exact(cls, value: str) -> str:
        if HEX64.fullmatch(value) is None:
            raise ValueError("retention prior-index digest is invalid")
        return value

    @model_validator(mode="after")
    def fixed_policy_and_arithmetic_are_exact(
        self,
    ) -> RetentionSelectionWitnessV1:
        if (
            self.maximum_age_ns
            != 7 * 24 * 60 * 60 * 1_000_000_000
            or self.target_bytes != 5 * 1024**3
            or self.maximum_run_manifests != 128
            or self.removable_event_types != ["falco_connect"]
        ):
            raise ValueError("retention witness policy is not production")
        if self.routine_bytes > MAX_UINT64 - self.protected_bytes:
            raise ValueError("retention witness total bytes overflow")
        if self.total_bytes != self.routine_bytes + self.protected_bytes:
            raise ValueError("retention witness total bytes are inconsistent")
        if self.size_pressure != (self.total_bytes > self.target_bytes):
            raise ValueError("retention witness size pressure is inconsistent")
        if self.age_selection_enabled:
            if not self.clock_healthy or self.uncertainty_ns is None:
                raise ValueError(
                    "retention witness age clock is inconsistent"
                )
        elif self.uncertainty_ns is not None:
            raise ValueError(
                "retention witness disabled age has uncertainty"
            )
        if self.age_pressure and not self.age_selection_enabled:
            raise ValueError(
                "retention witness age pressure lacks a healthy clock"
            )
        return self


class RetentionStateV1(ContractModel):
    """Canonical durable pre-POST state; never unlink authority."""

    schema_version: Literal["agmind.retention-state.v1"]
    operation: RetentionOperation
    phase: RetentionPhase
    request: RetentionTombstoneV2 | RetentionBlockedV1
    target: RetentionTargetV1 | None
    h0: str
    entries: list[RetentionStateEntryV1] = Field(max_length=128)
    selection_witness: RetentionSelectionWitnessV1

    @field_validator("h0")
    @classmethod
    def h0_is_exact(cls, value: str) -> str:
        if HEX64.fullmatch(value) is None:
            raise ValueError("retention state H0 is invalid")
        return value

    @model_validator(mode="after")
    def request_phase_and_entries_are_coherent(self) -> RetentionStateV1:
        request = self.request
        if self.h0 != request.current_chain_head_sha256:
            raise ValueError("retention state H0 differs from request")
        if self.phase == "selected":
            if self.target is not None:
                raise ValueError("selected retention state cannot bind a target")
        elif self.target is None:
            raise ValueError("advanced retention state requires a target")

        witness = self.selection_witness
        if type(request) is RetentionTombstoneV2:
            if self.operation != "tombstone":
                raise ValueError("retention operation differs from request")
            hashes = [entry.manifest_sha256 for entry in self.entries]
            if hashes != request.removed_manifest_hashes:
                raise ValueError(
                    "retention entries differ from the selected run"
                )
            removed_bytes = 0
            for entry in self.entries:
                if removed_bytes > MAX_UINT64 - entry.segment_size_bytes:
                    raise ValueError("retention entry byte sum overflows")
                removed_bytes += entry.segment_size_bytes
            if removed_bytes != request.removed_bytes:
                raise ValueError("retention entry byte sum is inconsistent")
            expected_reason = (
                "retention_age_and_size_limit"
                if witness.age_pressure and witness.size_pressure
                else (
                    "retention_age_limit"
                    if witness.age_pressure
                    else "retention_size_limit"
                )
            )
            if (
                not witness.age_pressure
                and not witness.size_pressure
                or request.reason != expected_reason
                or request.policy_version != witness.policy_version
            ):
                raise ValueError(
                    "retention tombstone differs from selection witness"
                )
        else:
            blocked_request = cast(RetentionBlockedV1, request)
            if self.operation != "blocked" or self.entries:
                raise ValueError(
                    "blocked retention state cannot contain unlink entries"
                )
            if self.phase in {
                "retention_unlink_in_progress",
                "retention_commit_uncertain",
                "completed",
            }:
                raise ValueError(
                    "blocked retention state cannot enter unlink phases"
                )
            if (
                witness.age_pressure
                or not witness.size_pressure
                or blocked_request.target_bytes != witness.target_bytes
                or blocked_request.routine_bytes != witness.routine_bytes
                or blocked_request.protected_bytes
                != witness.protected_bytes
                or blocked_request.blocked_bytes
                != witness.total_bytes - witness.target_bytes
            ):
                raise ValueError(
                    "retention blocked request differs from witness"
                )
        return self


def _validated_retention_state(state: RetentionStateV1) -> RetentionStateV1:
    if type(state) is not RetentionStateV1:
        raise TypeError("retention state must use the exact runtime type")
    try:
        return RetentionStateV1.model_validate(
            state.model_dump(exclude_none=False),
            strict=True,
        )
    except (TypeError, ValueError, ValidationError) as error:
        raise RetentionStateCorrupt(
            "retention state is not coherent"
        ) from error


def encode_retention_state(state: RetentionStateV1) -> bytes:
    validated = _validated_retention_state(state)
    raw = canonical_json(validated.model_dump(exclude_none=False))
    if not raw or len(raw) > MAX_RETENTION_STATE_BYTES:
        raise RetentionStateCorrupt(
            "canonical retention state exceeds 128 KiB"
        )
    return raw


def decode_retention_state(raw: bytes) -> RetentionStateV1:
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > MAX_RETENTION_STATE_BYTES
    ):
        raise RetentionStateCorrupt(
            "retention state exceeds its exact 128 KiB bound"
        )
    try:
        text = raw.decode("utf-8", "strict")
        _validate_json_depth(text)
        decoder = json.JSONDecoder(
            object_pairs_hook=_unique_object,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
        start = 0
        while start < len(text) and text[start] in " \t\r\n":
            start += 1
        value, end = decoder.raw_decode(text, start)
        while end < len(text) and text[end] in " \t\r\n":
            end += 1
        if end != len(text) or type(value) is not dict:
            raise ValueError("retention state must be exactly one object")
        _validate_unicode(value)
        state = RetentionStateV1.model_validate(value, strict=True)
        if encode_retention_state(state) != raw:
            raise ValueError("retention state is not canonical")
        return state
    except RetentionStateCorrupt:
        raise
    except (
        RecursionError,
        TypeError,
        ValueError,
        ValidationError,
    ) as error:
        raise RetentionStateCorrupt(
            "retention state is not canonical or coherent"
        ) from error


def _require_production_decision(
    decision: RetentionDecision,
) -> RetentionRequest:
    if type(decision) is not RetentionDecision:
        raise TypeError(
            "retention publication requires an exact retention decision"
        )
    request = _validated_decision_request(decision)
    if request is None:
        raise RetentionProtocolError(
            "empty retention decision has no publication"
        )
    if (
        decision._target_bytes != 5 * 1024**3
        or decision._maximum_age_ns
        != 7 * 24 * 60 * 60 * 1_000_000_000
        or decision._maximum_run_manifests != 128
        or decision._removable_event_types != ("falco_connect",)
        or decision._policy_version != "agmind-retention-v1"
        or decision._run_domain != b"AGMIND_RETENTION_RUN_V2\x00"
        or decision._zero_sha256 != "0" * 64
    ):
        raise RetentionProtocolError(
            "retention publication requires production policy"
        )
    return request


def selected_retention_state(
    decision: RetentionDecision,
) -> RetentionStateV1:
    request = _require_production_decision(decision)
    snapshot = decision._snapshot
    facts, _, _ = _validate_snapshot(
        snapshot,
        removable_event_types=frozenset({"falco_connect"}),
        genesis_manifest_sha256="0" * 64,
    )
    entries: list[dict[str, object]] = []
    if type(request) is RetentionTombstoneV2:
        by_hash = {fact.manifest_sha256: fact for fact in facts}
        try:
            selected = [
                by_hash[manifest_sha256]
                for manifest_sha256 in request.removed_manifest_hashes
            ]
        except KeyError as error:
            raise RetentionCorruption(
                "retention decision selected an unknown manifest"
            ) from error
        entries = [
            {
                "manifest_sha256": fact.manifest_sha256,
                "segment_id": fact.segment_id,
                "segment_relative_path": fact.segment_relative_path,
                "segment_size_bytes": fact.segment_size_bytes,
                "segment_sha256": fact.segment_sha256,
                "original_device": fact.original_device,
                "original_inode": fact.original_inode,
            }
            for fact in selected
        ]
    document = {
        "schema_version": "agmind.retention-state.v1",
        "operation": (
            "tombstone"
            if type(request) is RetentionTombstoneV2
            else "blocked"
        ),
        "phase": "selected",
        "request": request.model_dump(mode="python"),
        "target": None,
        "h0": request.current_chain_head_sha256,
        "entries": entries,
        "selection_witness": {
            "policy_version": decision._policy_version,
            "maximum_age_ns": decision._maximum_age_ns,
            "target_bytes": decision._target_bytes,
            "maximum_run_manifests": (
                decision._maximum_run_manifests
            ),
            "removable_event_types": list(
                decision._removable_event_types
            ),
            "decision_utc": decision._decision_utc,
            "clock_healthy": decision._clock_healthy,
            "age_selection_enabled": (
                decision._age_selection_enabled
            ),
            "uncertainty_ns": decision._uncertainty_ns,
            "routine_bytes": decision._routine_bytes,
            "protected_bytes": decision._protected_bytes,
            "total_bytes": decision._total_bytes,
            "age_pressure": decision._age_pressure,
            "size_pressure": decision._size_pressure,
            "prior_index_count": decision._prior_index_count,
            "prior_index_through_sequence": (
                decision._prior_index_through_sequence
            ),
            "prior_index_sha256": decision._prior_index_sha256,
        },
    }
    try:
        state = RetentionStateV1.model_validate(document, strict=True)
    except (TypeError, ValueError, ValidationError) as error:
        raise RetentionStateCorrupt(
            "selected retention state is invalid"
        ) from error
    encode_retention_state(state)
    return state


def _validated_target(target: RetentionTargetV1) -> RetentionTargetV1:
    if type(target) is not RetentionTargetV1:
        raise TypeError("retention target must use the exact runtime type")
    try:
        return RetentionTargetV1.model_validate(
            target.model_dump(),
            strict=True,
        )
    except (TypeError, ValueError, ValidationError) as error:
        raise RetentionProtocolError("retention target is invalid") from error


def _derived_retention_state(
    state: RetentionStateV1,
    *,
    phase: RetentionPhase,
    target: RetentionTargetV1,
) -> RetentionStateV1:
    current = _validated_retention_state(state)
    exact_target = _validated_target(target)
    if current.target is not None and current.target != exact_target:
        raise RetentionProtocolError(
            "retention transition changed its bound target"
        )
    legal = (
        (current.phase == "selected" and phase == "target_bound")
        or (
            current.phase in {"selected", "target_bound"}
            and phase == "evidence_appended"
        )
        or (
            current.operation == "tombstone"
            and current.phase == "evidence_appended"
            and phase == "retention_unlink_in_progress"
        )
        or (
            current.operation == "tombstone"
            and current.phase == "retention_unlink_in_progress"
            and phase
            in {"retention_commit_uncertain", "completed"}
        )
        or (
            current.operation == "tombstone"
            and current.phase == "retention_commit_uncertain"
            and phase == "completed"
        )
    )
    if not legal:
        raise RetentionProtocolError(
            f"retention transition {current.phase!r} -> {phase!r} is illegal"
        )
    document = current.model_dump(exclude_none=False)
    document.update(
        phase=phase,
        target=exact_target.model_dump(),
    )
    try:
        return RetentionStateV1.model_validate(document, strict=True)
    except (TypeError, ValueError, ValidationError) as error:
        raise RetentionProtocolError(
            "retention transition target is invalid"
        ) from error


def bind_retention_target(
    state: RetentionStateV1,
    target: RetentionTargetV1,
) -> RetentionStateV1:
    return _derived_retention_state(
        state,
        phase="target_bound",
        target=target,
    )


def advance_retention_evidence_appended(
    state: RetentionStateV1,
    target: RetentionTargetV1,
) -> RetentionStateV1:
    return _derived_retention_state(
        state,
        phase="evidence_appended",
        target=target,
    )


def _retention_execution_states(
    state: RetentionStateV1,
) -> tuple[RetentionStateV1, RetentionStateV1, RetentionStateV1]:
    """Derive the only exact destructive states from accepted evidence."""
    exact = _validated_retention_state(state)
    if (
        exact.operation != "tombstone"
        or exact.phase != "evidence_appended"
        or type(exact.request) is not RetentionTombstoneV2
        or type(exact.target) is not RetentionTargetV1
        or not exact.entries
    ):
        raise RetentionProtocolError(
            "retention execution requires exact evidence-appended authority"
        )
    target = exact.target
    in_progress = _derived_retention_state(
        exact,
        phase="retention_unlink_in_progress",
        target=target,
    )
    uncertain = _derived_retention_state(
        in_progress,
        phase="retention_commit_uncertain",
        target=target,
    )
    completed = _derived_retention_state(
        in_progress,
        phase="completed",
        target=target,
    )
    return in_progress, uncertain, completed


def _validate_retention_transition(
    current: RetentionStateV1,
    next_state: RetentionStateV1,
) -> None:
    exact_current = _validated_retention_state(current)
    exact_next = _validated_retention_state(next_state)
    current_document = exact_current.model_dump(exclude_none=False)
    next_document = exact_next.model_dump(exclude_none=False)
    current_target = current_document.pop("target")
    next_target = next_document.pop("target")
    current_phase = current_document.pop("phase")
    next_phase = next_document.pop("phase")
    if current_document != next_document:
        raise RetentionProtocolError(
            "retention transition changed immutable selected authority"
        )
    if current_target is not None and next_target != current_target:
        raise RetentionProtocolError(
            "retention transition changed its bound target"
        )
    if current_target is None and next_target is None:
        raise RetentionProtocolError(
            "retention transition did not bind a target"
        )
    legal = (
        (current_phase == "selected" and next_phase == "target_bound")
        or (
            current_phase in {"selected", "target_bound"}
            and next_phase == "evidence_appended"
        )
        or (
            exact_current.operation == "tombstone"
            and current_phase == "evidence_appended"
            and next_phase == "retention_unlink_in_progress"
        )
        or (
            exact_current.operation == "tombstone"
            and current_phase == "retention_unlink_in_progress"
            and next_phase
            in {"retention_commit_uncertain", "completed"}
        )
        or (
            exact_current.operation == "tombstone"
            and current_phase == "retention_commit_uncertain"
            and next_phase == "completed"
        )
    )
    if not legal:
        raise RetentionProtocolError(
            f"retention transition {current_phase!r} -> {next_phase!r} is illegal"
        )


class _RetentionStateAuthorityView(Protocol):
    def read_retention_state_bytes(self) -> bytes | None: ...

    def read_retention_state_temporary_bytes(self) -> bytes | None: ...

    def publish_initial_retention_state(self, raw: bytes) -> None: ...

    def replace_retention_state_bytes(
        self,
        expected: bytes,
        raw: bytes,
    ) -> None: ...


@final
class RetentionStateJournal:
    """Store-bound exact in-memory view of one durable retention gate."""

    __slots__ = ("_authority", "_identity", "_raw", "_state")

    def __init__(
        self,
        authority: _RetentionStateAuthorityView,
        state: RetentionStateV1 | None,
        raw: bytes | None,
        *,
        _factory: object,
    ) -> None:
        from agmind_immune.evidence.segments import _RetentionStateAuthority

        if (
            _factory is not _RETENTION_STATE_JOURNAL_FACTORY
            or type(authority) is not _RetentionStateAuthority
        ):
            raise TypeError(
                "RetentionStateJournal is factory-only and store-bound"
            )
        self._authority = authority
        self._state = state
        self._raw = raw
        self._identity = object()
        self._assert_consistent()

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("RetentionStateJournal is final")

    def __copy__(self) -> RetentionStateJournal:
        raise TypeError("retention journal capabilities cannot be copied")

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> RetentionStateJournal:
        del memo
        raise TypeError("retention journal capabilities cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("retention journal capabilities cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("retention journal capabilities cannot be serialized")

    @property
    def state(self) -> RetentionStateV1 | None:
        return (
            None
            if self._state is None
            else self._state.model_copy(deep=True)
        )

    def _assert_consistent(self) -> None:
        if self._state is None and self._raw is None:
            return
        if (
            self._state is None
            or self._raw is None
            or decode_retention_state(self._raw)
            != _validated_retention_state(self._state)
        ):
            raise RetentionStateCorrupt(
                "retention journal differs from exact durable bytes"
            )

    def _prove_publication(self, expected: bytes | None) -> None:
        if (
            self._authority.read_retention_state_temporary_bytes()
            is not None
        ):
            raise RetentionStateConflict(
                "retention state publication has a temporary"
            )
        actual = self._authority.read_retention_state_bytes()
        if actual != expected:
            raise RetentionStateConflict(
                "retention state publication CAS is ambiguous"
            )

    def prepare_publication(self, decision: RetentionDecision) -> bytes:
        if type(decision) is not RetentionDecision:
            raise TypeError(
                "retention publication requires an exact decision"
            )
        selected = selected_retention_state(decision)
        raw = encode_retention_state(selected)
        self._assert_consistent()
        if self._state is None and self._raw is None:
            self._authority.publish_initial_retention_state(raw)
            self._prove_publication(raw)
            self._state = selected.model_copy(deep=True)
            self._raw = raw
        elif self._state is not None and self._state.phase != "selected":
            raise RetentionProtocolError(
                f"retention transition {self._state.phase!r} -> 'selected' is illegal"
            )
        elif self._raw != raw:
            raise RetentionStateConflict(
                "retention request conflicts with durable selected state"
            )
        else:
            self._prove_publication(raw)
        request = selected.request
        return canonical_json(request.model_dump(mode="python"))

    def _transition(self, next_state: RetentionStateV1) -> None:
        self._assert_consistent()
        current = self._state
        expected = self._raw
        if current is None or expected is None:
            raise RetentionProtocolError(
                "retention transition has no durable selected state"
            )
        validated = _validated_retention_state(next_state)
        if validated == current:
            self._prove_publication(expected)
            return
        _validate_retention_transition(current, validated)
        raw = encode_retention_state(validated)
        self._authority.replace_retention_state_bytes(expected, raw)
        self._prove_publication(raw)
        self._state = validated.model_copy(deep=True)
        self._raw = raw

    def bind_target(self, target: RetentionTargetV1) -> None:
        current = self.state
        if current is None:
            raise RetentionProtocolError(
                "retention target has no selected state"
            )
        if current.phase == "target_bound" and current.target == target:
            self._prove_publication(self._raw)
            return
        self._transition(bind_retention_target(current, target))

    def advance_evidence_appended(
        self,
        target: RetentionTargetV1,
    ) -> None:
        current = self.state
        if current is None:
            raise RetentionProtocolError(
                "retention evidence has no selected state"
            )
        if current.phase == "evidence_appended" and current.target == target:
            self._prove_publication(self._raw)
            return
        self._transition(
            advance_retention_evidence_appended(current, target)
        )


def _open_retention_state_journal(store: object) -> RetentionStateJournal:
    from agmind_immune.evidence.segments import (
        _RETENTION_STATE_AUTHORITY_FACTORY,
        SegmentStore,
        _RetentionStateAuthority,
    )

    if type(store) is not SegmentStore:
        raise TypeError(
            "retention journal requires the exact SegmentStore lifecycle"
        )
    authority = store._open_retention_state_authority(
        _factory=_RETENTION_STATE_AUTHORITY_FACTORY,
    )
    if type(authority) is not _RetentionStateAuthority:
        raise TypeError("retention journal authority type is invalid")
    cached = authority._retention_journal
    if cached is not None:
        if (
            type(cached) is not RetentionStateJournal
            or cached._authority is not authority
        ):
            raise RetentionStateCorrupt(
                "retention journal cache lost exact identity"
            )
        return cached
    if authority.read_retention_state_temporary_bytes() is not None:
        raise RetentionStateConflict(
            "retention-state temporary requires recovery"
        )
    raw = authority.read_retention_state_bytes()
    state = None if raw is None else decode_retention_state(raw)
    journal = RetentionStateJournal(
        authority,
        state,
        raw,
        _factory=_RETENTION_STATE_JOURNAL_FACTORY,
    )
    authority._bind_retention_journal(
        journal,
        _factory=_RETENTION_STATE_AUTHORITY_FACTORY,
    )
    return journal


def _decimal_nanoseconds(value: int) -> Decimal:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise RetentionCorruption(
            "retention witness uncertainty is not exact uint64"
        )
    if value == 0:
        return Decimal(0)
    return Decimal((0, tuple(int(digit) for digit in str(value)), -9))


def _selection_clock_from_witness(
    witness: RetentionSelectionWitnessV1,
) -> CoreClockSample:
    try:
        decision_utc = datetime.fromisoformat(witness.decision_utc)
        if _decision_utc_text(decision_utc) != witness.decision_utc:
            raise ValueError("decision UTC is not canonical")
        uncertainty = (
            None
            if witness.uncertainty_ns is None
            else _decimal_nanoseconds(witness.uncertainty_ns)
        )
        maximum = Decimal(0) if uncertainty is None else uncertainty
        clock = CoreClockSample(
            decision_utc=decision_utc,
            decision_monotonic=0.0,
            healthy=witness.clock_healthy,
            uncertainty_seconds=uncertainty,
            max_uncertainty_seconds=maximum,
        )
    except (
        CoreClockValidationError,
        RetentionCorruption,
        TypeError,
        ValueError,
    ) as error:
        raise RetentionCorruption(
            "retention selector witness clock is invalid"
        ) from error
    _decision_ns, enabled, uncertainty_ns = _clock_selection(clock)
    if (
        enabled != witness.age_selection_enabled
        or uncertainty_ns != witness.uncertainty_ns
    ):
        raise RetentionCorruption(
            "retention selector witness clock cannot be reconstructed"
        )
    return clock


def _final_retention_invariant(
    store: Any,
    journal: RetentionStateJournal,
    snapshot: RetentionSnapshot,
    target_ref: object,
) -> tuple[object, ...]:
    verifier = store._bound_verifier
    authority = None if verifier is None else verifier._authority
    accepted = (
        ()
        if authority is None
        else tuple(
            (
                sequence,
                id(value),
                value.canonical,
                id(value.evidence_ref),
                value.evidence_ref,
                value.evidence_priority,
                value.key_epoch,
                value.key_id,
            )
            for sequence, value in sorted(authority.accepted.items())
        )
    )
    coverage = store._coverage_state_owner
    coverage_snapshot = (
        None if coverage is None else coverage._snapshot
    )
    return (
        id(store),
        store._closed,
        store._authority_state,
        id(store._lifecycle_identity),
        id(store._bound_verifier),
        store.status(),
        id(verifier),
        None if verifier is None else id(verifier.root),
        None if verifier is None else id(verifier.key_chain),
        id(authority),
        None if authority is None else authority.generation,
        None if authority is None else id(authority.fsm),
        accepted,
        () if verifier is None else tuple(verifier._staged.items()),
        () if verifier is None else tuple(verifier._authorizations.items()),
        (
            None
            if verifier is None
            else verifier._repair_transient_generation
        ),
        None if verifier is None else id(verifier._bound_lifecycle),
        (
            None
            if verifier is None
            else id(verifier._repair_lifecycle_identity)
        ),
        (
            None
            if verifier is None
            else id(verifier._repair_owner_identity)
        ),
        id(journal),
        id(journal._identity),
        id(journal._authority),
        journal._raw,
        journal._state,
        id(snapshot),
        _snapshot_binding(snapshot),
        id(target_ref),
        target_ref,
        id(coverage),
        id(coverage_snapshot),
        coverage_snapshot,
        None if coverage is None else id(coverage._evidence),
        (
            None
            if coverage is None
            else id(coverage._lifecycle_identity)
        ),
        None if coverage is None else id(coverage._capability_token),
        None if coverage is None else coverage._healthy,
        None if coverage is None else coverage._closed,
    )


def _authenticate_store_retention_tombstone(
    store: object,
    journal: RetentionStateJournal,
    snapshot: RetentionSnapshot,
    target_ref: object,
    *,
    _factory: object,
) -> AuthenticatedRetentionTombstone:
    from agmind_immune.coverage import CoverageState
    from agmind_immune.evidence.segments import (
        _RETENTION_PROOF_FACTORY,
        EvidencePriority,
        EvidenceRef,
        EvidenceSealError,
        SegmentStore,
    )
    from agmind_immune.ingest.envelope import (
        CoreEventV1,
        EnvelopeVerifier,
        IngestVerificationError,
        VerifierCommitError,
    )

    if _factory is not _RETENTION_PROOF_FACTORY:
        raise TypeError("final retention proof requires its exact factory")
    if type(store) is not SegmentStore:
        raise TypeError("final retention proof requires the exact SegmentStore")
    if type(journal) is not RetentionStateJournal:
        raise TypeError("final retention proof requires the exact journal")
    if type(snapshot) is not RetentionSnapshot:
        raise TypeError("final retention proof requires an exact snapshot")
    if type(target_ref) is not EvidenceRef:
        raise TypeError("final retention proof requires an exact target ref")

    exact_store: Any = store
    exact_store._require_retention_snapshot(snapshot)
    authority = journal._authority
    if (
        getattr(authority, "_store", None) is not store
        or getattr(authority, "_lifecycle_identity", None)
        is not exact_store._lifecycle_identity
        or getattr(authority, "_retention_journal", None) is not journal
        or exact_store._retention_state_authority is not authority
    ):
        raise EvidenceSealError(
            "final retention proof journal is outside the exact store"
        )
    journal._assert_consistent()
    state = journal._state
    state_raw = journal._raw
    if (
        type(state) is not RetentionStateV1
        or type(state_raw) is not bytes
        or state.operation != "tombstone"
        or state.phase != "evidence_appended"
        or type(state.request) is not RetentionTombstoneV2
        or type(state.target) is not RetentionTargetV1
        or encode_retention_state(state) != state_raw
    ):
        raise EvidenceSealError(
            "final retention proof requires exact evidence-appended state"
        )
    journal._prove_publication(state_raw)
    target = state.target
    if (
        target.sequence != target_ref.source_sequence
        or target.event_id != target_ref.event_id
        or target.content_sha256 != target_ref.content_sha256
    ):
        raise EvidenceSealError(
            "final retention proof target differs from durable authority"
        )

    verifier = exact_store._bound_verifier
    status = exact_store.status()
    if (
        type(verifier) is not EnvelopeVerifier
        or verifier._bound_lifecycle is not exact_store._lifecycle_identity
        or status.healthy is not True
        or status.key_healthy is not True
        or status.repair_pending is not False
        or verifier._staged
        or verifier._authorizations
    ):
        raise EvidenceSealError(
            "final retention proof requires one healthy verifier lifecycle"
        )
    coverage = exact_store._coverage_state_owner
    if (
        type(coverage) is not CoverageState
        or coverage._evidence is not store
        or coverage._lifecycle_identity is not exact_store._lifecycle_identity
        or coverage._capability_token is None
        or coverage._healthy is not True
        or coverage._closed is not False
    ):
        raise EvidenceSealError(
            "final retention proof requires exact live coverage authority"
        )
    exact_coverage: Any = coverage
    coverage_snapshot = exact_coverage._snapshot
    coverage_head = exact_store._validate_coverage_state_owner(
        exact_coverage,
        exact_coverage._lifecycle_identity,
        reducer_head=coverage_snapshot.head_ref,
    )
    if (
        coverage_head != coverage_snapshot.head_ref
        or coverage_snapshot.head_sequence != status.evidence_head
        or coverage_snapshot.head_sequence < target.sequence
    ):
        raise EvidenceSealError(
            "final retention proof coverage does not include the target"
        )

    try:
        record = exact_store.resolve_authenticated_ref(target_ref)
    except Exception as error:
        raise EvidenceSealError(
            "final retention proof target is not authenticated"
        ) from error
    if (
        record.ref is not target_ref
        or record.priority is not EvidencePriority.PROTECTED
        or type(record.envelope) is not dict
        or type(record.canonical_envelope) is not bytes
        or canonical_json(record.envelope) != record.canonical_envelope
        or hashlib.sha256(record.canonical_envelope).hexdigest()
        != target_ref.content_sha256
    ):
        raise EvidenceSealError(
            "final retention proof target record is not exact protected evidence"
        )
    try:
        item = CoreEventV1.model_validate(
            {
                "sequence": target_ref.source_sequence,
                "event_id": target_ref.event_id,
                "content_sha256": target_ref.content_sha256,
                "envelope": record.envelope,
            },
            strict=True,
        )
    except ValidationError as error:
        raise EvidenceSealError(
            "final retention proof target envelope is invalid"
        ) from error

    facts, final_clock, current_prior = _validate_snapshot(
        snapshot,
        removable_event_types=frozenset({"falco_connect"}),
        genesis_manifest_sha256="0" * 64,
    )
    h0_matches = tuple(
        index
        for index, fact in enumerate(facts)
        if fact.prefix_chain_head_sha256 == state.h0
    )
    if len(h0_matches) != 1:
        raise RetentionCorruption(
            "final retention proof H0 is not one exact historical prefix"
        )
    h0_tip = h0_matches[0]
    request = state.request
    request_raw = canonical_json(request.model_dump(mode="python"))
    request_hashes = frozenset(request.removed_manifest_hashes)
    positions = {
        fact.manifest_sha256: index for index, fact in enumerate(facts)
    }
    try:
        current_positions = tuple(
            positions[manifest_hash]
            for manifest_hash in request.removed_manifest_hashes
        )
    except KeyError as error:
        raise RetentionCorruption(
            "final retention proof target run is absent from H0"
        ) from error
    if (
        not current_positions
        or max(current_positions) > h0_tip
        or any(
            right != left + 1
            for left, right in pairwise(sorted(current_positions))
        )
    ):
        raise RetentionCorruption(
            "final retention proof target run is not H0-adjacent"
        )
    current_start = min(current_positions)
    current_end = max(current_positions)
    selector_prior: list[AcceptedRetentionTombstone] = []
    other_prior: list[AcceptedRetentionTombstone] = []
    self_matches = 0
    through = state.selection_witness.prior_index_through_sequence
    if (
        through > snapshot.prior_index_through_sequence
        or through >= target_ref.source_sequence
        or through > status.evidence_head
        or (
            through != 0
            and verifier.accepted_ref(through) is None
        )
    ):
        raise RetentionCorruption(
            "retention prior-index sequence is not an authenticated prefix"
        )
    for accepted in current_prior:
        prior_request, prior_raw, outer = _validated_prior(accepted)
        exact_self = (
            outer
            == (
                target_ref.source_sequence,
                target_ref.event_id,
                target_ref.content_sha256,
            )
            and prior_raw == request_raw
        )
        if exact_self:
            self_matches += 1
            if accepted.sequence <= through:
                raise RetentionCorruption(
                    "retention target appears inside its prior-index witness"
                )
            continue
        if (
            prior_request.tombstone_id == request.tombstone_id
            or prior_raw == request_raw
        ):
            raise RetentionCorruption(
                "final retention proof has a conflicting tombstone identity"
            )
        prior_hashes = frozenset(
            prior_request.removed_manifest_hashes
        )
        if prior_hashes.intersection(request_hashes):
            raise RetentionCorruption(
                "final retention proof overlaps another tombstone"
            )
        try:
            prior_positions = tuple(
                positions[manifest_hash]
                for manifest_hash in prior_request.removed_manifest_hashes
            )
        except KeyError as error:
            raise RetentionCorruption(
                "final retention proof prior run is outside the chain"
            ) from error
        if (
            accepted.sequence < target_ref.source_sequence
            and max(prior_positions, default=-1) >= current_start
            or accepted.sequence > target_ref.source_sequence
            and min(prior_positions, default=len(facts)) <= current_end
        ):
            raise RetentionCorruption(
                "final retention proof tombstone runs are out of order"
            )
        other_prior.append(accepted)
        if accepted.sequence <= through:
            selector_prior.append(accepted)
    if self_matches != 1:
        raise EvidenceSealError(
            "final retention proof target lacks one authenticated tombstone"
        )
    _prior_coverage(
        facts,
        tuple(other_prior),
        zero_sha256="0" * 64,
    )
    prior_count, _prior_last, prior_sha256 = _prior_index_commitment(
        tuple(selector_prior)
    )
    witness = state.selection_witness
    if (
        prior_count != witness.prior_index_count
        or prior_sha256 != witness.prior_index_sha256
    ):
        raise RetentionCorruption(
            "final retention selector prior-index witness changed"
        )
    persisted_clock = _selection_clock_from_witness(witness)
    if _datetime_ns(final_clock.decision_utc) < _datetime_ns(
        persisted_clock.decision_utc
    ):
        raise RetentionCorruption(
            "final retention proof clock regressed before selection"
        )
    selector_snapshot = _freeze_retention_snapshot(
        facts=tuple(snapshot.facts[: h0_tip + 1]),
        clock=persisted_clock,
        prior_tombstones=tuple(selector_prior),
        prior_index_through_sequence=through,
    )
    rerun = _select_retention(
        selector_snapshot,
        request_id=request.tombstone_id,
        target_bytes=5 * 1024**3,
        maximum_age_ns=7 * 24 * 60 * 60 * 1_000_000_000,
        maximum_run_manifests=128,
        removable_event_types=frozenset({"falco_connect"}),
        policy_version="agmind-retention-v1",
        run_domain=b"AGMIND_RETENTION_RUN_V2\x00",
        zero_sha256="0" * 64,
    )
    try:
        rerun_state = selected_retention_state(rerun)
        _validate_retention_transition(rerun_state, state)
    except RetentionError as error:
        raise RetentionCorruption(
            "final retention selector witness does not reproduce state"
        ) from error
    if rerun.request != request:
        raise RetentionCorruption(
            "final retention selector request changed"
        )

    invariant = _final_retention_invariant(
        exact_store,
        journal,
        snapshot,
        target_ref,
    )
    try:
        replayed = verifier._restricted_historical_retention_replay(
            (item, target_ref),
            request,
        )
    except (
        IngestVerificationError,
        VerifierCommitError,
        TypeError,
        ValueError,
    ) as error:
        raise EvidenceSealError(
            "final retention target historical replay failed"
        ) from error
    if (
        replayed.event_type != "retention_tombstone"
        or replayed.evidence_priority != "protected"
        or replayed.is_retry is not True
        or replayed.sequence != target_ref.source_sequence
        or replayed.event_id != target_ref.event_id
        or replayed.content_sha256 != target_ref.content_sha256
        or _final_retention_invariant(
            exact_store,
            journal,
            snapshot,
            target_ref,
        )
        != invariant
    ):
        raise EvidenceSealError(
            "final retention proof changed live authenticated authority"
        )
    exact_store._require_retention_snapshot(snapshot)
    journal._prove_publication(state_raw)
    in_progress, uncertain, completed = _retention_execution_states(state)
    in_progress_raw = encode_retention_state(in_progress)
    uncertain_raw = encode_retention_state(uncertain)
    completed_raw = encode_retention_state(completed)
    capability = AuthenticatedRetentionTombstone(
        _factory=_AUTHENTICATED_RETENTION_TOMBSTONE_FACTORY,
    )
    completion = AuthenticatedRetentionUnlinkCompletion(
        _factory=_AUTHENTICATED_RETENTION_UNLINK_COMPLETION_FACTORY,
    )
    exact_store._register_authenticated_retention_tombstone(
        capability,
        journal=journal,
        journal_identity=journal._identity,
        state_raw=state_raw,
        unlink_in_progress_state_raw=in_progress_raw,
        commit_uncertain_state_raw=uncertain_raw,
        completed_state_raw=completed_raw,
        completion_capability=completion,
        snapshot=snapshot,
        target_ref=target_ref,
        coverage=exact_coverage,
        coverage_snapshot=coverage_snapshot,
        coverage_token=exact_coverage._capability_token,
        verifier=verifier,
        verifier_authority=verifier._authority,
        verifier_generation=verifier._authority.generation,
        transient_generation=verifier._repair_transient_generation,
        status=status,
        _factory=_factory,
    )
    return capability
