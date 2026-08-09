"""Fixed-endpoint, bounded OPA client for candidate policy evaluation."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, Decimal
from pathlib import Path
from typing import Any, cast

import httpx

from agmind_immune.canonicaljson import candidate_facts_sha256, canonical_json
from agmind_immune.clock import (
    CoreClockProvider,
    CoreClockSample,
)
from agmind_immune.contracts import MAX_UINT64, decode_strict
from agmind_immune.policy.models import (
    PolicyBundleIdentity,
    PolicyDecisionV1,
    PolicyError,
    PolicyEvaluation,
    PolicyInputV1,
    PolicyResponseInvalid,
    PolicyUnavailable,
    _OPAResponseV1,
    _policy_decision_sha256,
    _policy_input_sha256,
)

POLICY_BUNDLE_SHA256 = (
    "472ca6f13cee7962693c68c95688a49242300109b136640817f37c43bc27f1f7"
)
POLICY_BUNDLE = PolicyBundleIdentity(
    version="pcc-policy-v1",
    sha256=POLICY_BUNDLE_SHA256,
)

_CLIENT_FACTORY = object()
_TEST_CLIENT_FACTORY = object()
_POLICY_PATH = Path("/usr/share/agmind-sais/pcc.rego")
_POLICY_COMPONENTS = ("usr", "share", "agmind-sais")
_POLICY_NAME = "pcc.rego"
_OPA_BASE_URL = "http://opa:8181"
_OPA_ROUTE = "/v1/data/agmind/pcc/decision"
_MAX_POLICY_BYTES = 65_536
_MAX_REQUEST_BYTES = 65_536
_MAX_RESPONSE_BYTES = 65_536
_MAX_RESPONSE_HEADER_COUNT = 32
_MAX_RESPONSE_HEADER_BYTES = 8_192
_MAX_RESPONSE_HEADER_NAME_BYTES = 256
_MAX_RESPONSE_HEADER_VALUE_BYTES = 4_096
_MAX_EVIDENCE_AGE_MS = 120_000
_CONNECT_TIMEOUT_SECONDS = 1.0
_TOTAL_TIMEOUT_SECONDS = 2.0
_NANOSECONDS_PER_SECOND = 1_000_000_000
_NANOSECONDS_PER_MILLISECOND = 1_000_000
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_TIMESTAMP = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?Z$"
)


@dataclass(frozen=True, slots=True)
class _FileBinding:
    device: int
    inode: int
    mode: int
    links: int
    owner: int
    group: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _HeldDirectory:
    parent_fd: int | None
    name: str
    fd: int
    binding: _FileBinding


@dataclass(frozen=True, slots=True)
class _ViewSnapshot:
    candidate: Any
    public_seal: bytes


def _binding(info: os.stat_result) -> _FileBinding:
    return _FileBinding(
        device=info.st_dev,
        inode=info.st_ino,
        mode=info.st_mode,
        links=info.st_nlink,
        owner=info.st_uid,
        group=info.st_gid,
        size=info.st_size,
        modified_ns=info.st_mtime_ns,
        changed_ns=info.st_ctime_ns,
    )


def _protected_directory(info: os.stat_result) -> _FileBinding:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink < 1
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise PolicyUnavailable(
            "policy bundle parent is not a protected root-owned directory"
        )
    return _binding(info)


def _protected_policy(info: os.stat_result) -> _FileBinding:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o444
        or not 1 <= info.st_size <= _MAX_POLICY_BYTES
    ):
        raise PolicyUnavailable(
            "policy bundle is not a protected root-owned read-only file"
        )
    return _binding(info)


def _read_exact_fd(fd: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = _MAX_POLICY_BYTES + 1
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 16_384))
        if type(chunk) is not bytes:
            raise PolicyUnavailable("policy bundle read returned an inexact value")
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) != expected_size or not 1 <= len(raw) <= _MAX_POLICY_BYTES:
        raise PolicyUnavailable("policy bundle read was short, extra, or oversized")
    return raw


def _verify_policy_digest(raw: bytes) -> bytes:
    if type(raw) is not bytes or not hmac.compare_digest(
        hashlib.sha256(raw).hexdigest(),
        POLICY_BUNDLE_SHA256,
    ):
        raise PolicyUnavailable("policy bundle bytes differ from the compiled pin")
    return raw


def _load_pinned_policy() -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if nofollow == 0 or directory == 0:
        raise PolicyUnavailable(
            "policy bundle loading requires O_NOFOLLOW and O_DIRECTORY"
        )
    common_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    directory_flags = common_flags | directory
    descriptors: list[int] = []
    held_directories: list[_HeldDirectory] = []
    raw: bytes | None = None
    failure: BaseException | None = None
    try:
        named_root = _protected_directory(os.stat("/", follow_symlinks=False))
        root_fd = os.open("/", directory_flags)
        descriptors.append(root_fd)
        opened_root = _protected_directory(os.fstat(root_fd))
        if opened_root != named_root:
            raise PolicyUnavailable("policy root changed while opening")
        held_directories.append(_HeldDirectory(None, "/", root_fd, opened_root))

        parent_fd = root_fd
        for component in _POLICY_COMPONENTS:
            named = _protected_directory(
                os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            )
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            descriptors.append(child_fd)
            opened = _protected_directory(os.fstat(child_fd))
            if opened != named:
                raise PolicyUnavailable("policy directory changed while opening")
            held_directories.append(
                _HeldDirectory(parent_fd, component, child_fd, opened)
            )
            parent_fd = child_fd

        named_policy = _protected_policy(
            os.stat(_POLICY_NAME, dir_fd=parent_fd, follow_symlinks=False)
        )
        policy_fd = os.open(_POLICY_NAME, common_flags, dir_fd=parent_fd)
        descriptors.append(policy_fd)
        opened_policy = _protected_policy(os.fstat(policy_fd))
        if opened_policy != named_policy:
            raise PolicyUnavailable("policy file changed while opening")
        raw = _read_exact_fd(policy_fd, opened_policy.size)
        if _protected_policy(os.fstat(policy_fd)) != opened_policy:
            raise PolicyUnavailable("policy file changed while reading")

        for held in held_directories:
            named_info = (
                os.stat("/", follow_symlinks=False)
                if held.parent_fd is None
                else os.stat(
                    held.name,
                    dir_fd=held.parent_fd,
                    follow_symlinks=False,
                )
            )
            if (
                _protected_directory(named_info) != held.binding
                or _protected_directory(os.fstat(held.fd)) != held.binding
            ):
                raise PolicyUnavailable("policy directory changed while loading")
        if (
            _protected_policy(
                os.stat(_POLICY_NAME, dir_fd=parent_fd, follow_symlinks=False)
            )
            != opened_policy
        ):
            raise PolicyUnavailable("policy file path changed while loading")
    except BaseException as error:  # noqa: BLE001 - descriptors close first
        failure = error

    close_error: OSError | None = None
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError as error:
            if close_error is None:
                close_error = error
    if failure is not None:
        if isinstance(failure, PolicyError):
            raise failure
        if isinstance(failure, (OSError, OverflowError, TypeError, ValueError)):
            raise PolicyUnavailable("policy bundle loading failed") from failure
        raise failure
    if close_error is not None:
        raise PolicyUnavailable("policy bundle descriptor close failed") from close_error
    if raw is None:
        raise PolicyUnavailable("policy bundle loading produced no bytes")
    return _verify_policy_digest(raw)


def _load_test_policy(path: Path) -> bytes:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or Path(os.path.normpath(path)) != path
        or path.name != _POLICY_NAME
    ):
        raise PolicyUnavailable("test policy path is not exact")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PolicyUnavailable("test policy bundle is unavailable") from error
    if not 1 <= len(raw) <= _MAX_POLICY_BYTES:
        raise PolicyUnavailable("test policy bundle size is invalid")
    return _verify_policy_digest(raw)


def _is_leap_year(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _days_from_civil(year: int, month: int, day: int) -> int:
    adjusted_year = year - (1 if month <= 2 else 0)
    era = adjusted_year // 400
    year_of_era = adjusted_year - era * 400
    shifted_month = month + (-3 if month > 2 else 9)
    day_of_year = (153 * shifted_month + 2) // 5 + day - 1
    day_of_era = (
        year_of_era * 365
        + year_of_era // 4
        - year_of_era // 100
        + day_of_year
    )
    return era * 146_097 + day_of_era - 719_468


def _timestamp_ns(value: str) -> int:
    if type(value) is not str:
        raise PolicyError("candidate creation time is not exact text")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise PolicyError("candidate creation time is not canonical RFC3339Nano")
    year = int(match["year"])
    month = int(match["month"])
    day = int(match["day"])
    hour = int(match["hour"])
    minute = int(match["minute"])
    second = int(match["second"])
    if not 1 <= year <= 9_999 or not 1 <= month <= 12:
        raise PolicyError("candidate creation time is invalid")
    month_lengths = (
        31,
        29 if _is_leap_year(year) else 28,
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    )
    if (
        not 1 <= day <= month_lengths[month - 1]
        or not 0 <= hour <= 23
        or not 0 <= minute <= 59
        or not 0 <= second <= 59
    ):
        raise PolicyError("candidate creation time is invalid")
    fraction = match["fraction"]
    nanoseconds = 0 if fraction is None else int(fraction.ljust(9, "0"))
    days = _days_from_civil(year, month, day)
    seconds = ((days * 24 + hour) * 60 + minute) * 60 + second
    return seconds * _NANOSECONDS_PER_SECOND + nanoseconds


def _datetime_ns(value: datetime) -> int:
    if type(value) is not datetime:
        raise PolicyUnavailable("policy clock returned an inexact datetime")
    try:
        exact = (
            value.tzinfo == UTC
            and value.utcoffset() == timedelta(0)
            and value.fold == 0
        )
    except Exception as error:
        raise PolicyUnavailable("policy clock UTC validation failed") from error
    if not exact:
        raise PolicyUnavailable("policy clock is not exact UTC")
    epoch_ordinal = datetime(1970, 1, 1, tzinfo=UTC).toordinal()
    days = value.toordinal() - epoch_ordinal
    seconds = ((days * 24 + value.hour) * 60 + value.minute) * 60 + value.second
    return seconds * _NANOSECONDS_PER_SECOND + value.microsecond * 1_000


def _utc_text(value: datetime) -> str:
    timespec = "microseconds" if value.microsecond else "seconds"
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def _clock_observation(clock: CoreClockProvider) -> tuple[CoreClockSample, int]:
    try:
        observed = clock.decision_sample()
        if type(observed) is not CoreClockSample:
            raise TypeError("policy clock sample is not exact")
        sample = CoreClockSample(
            decision_utc=observed.decision_utc,
            decision_monotonic=observed.decision_monotonic,
            healthy=observed.healthy,
            uncertainty_seconds=observed.uncertainty_seconds,
            max_uncertainty_seconds=observed.max_uncertainty_seconds,
        )
        uncertainty = sample.uncertainty_seconds
        if (
            sample.healthy is not True
            or type(uncertainty) is not Decimal
            or uncertainty > sample.max_uncertainty_seconds
            or uncertainty
            > Decimal(MAX_UINT64) / Decimal(_NANOSECONDS_PER_SECOND)
        ):
            raise PolicyUnavailable("policy decision clock is not safely bounded")
        uncertainty_ns_decimal = uncertainty * Decimal(_NANOSECONDS_PER_SECOND)
        uncertainty_ns = int(
            uncertainty_ns_decimal.to_integral_value(rounding=ROUND_CEILING)
        )
        if not 0 <= uncertainty_ns <= MAX_UINT64:
            raise PolicyUnavailable("policy clock uncertainty is outside uint64")
    except PolicyUnavailable:
        raise
    except Exception as error:
        raise PolicyUnavailable("policy decision clock is unavailable") from error
    return sample, uncertainty_ns


def _capture_view(view: object) -> _ViewSnapshot:
    # Local imports keep the observation-only policy package independently
    # importable without entering the incidents/correlation package cycle.
    from agmind_immune.coverage import MutationReadiness
    from agmind_immune.evidence.projection import ProjectionCursor
    from agmind_immune.evidence.segments import EvidenceRef, _exact_coverage_ref_key
    from agmind_immune.incidents.admission import CandidateAdmissionView
    from agmind_immune.incidents.models import ContainmentCandidateV1

    if type(view) is not CandidateAdmissionView:
        raise PolicyError("policy evaluation requires an exact admission view")
    try:
        candidate = view.candidate
        if type(candidate) is not ContainmentCandidateV1:
            raise PolicyError("policy candidate is not exact")
        detached = ContainmentCandidateV1.model_validate(
            candidate.model_dump(mode="python"),
            strict=True,
        )
        candidate_bytes = canonical_json(detached)
        facts_sha256 = candidate_facts_sha256(detached)
        claimed_facts_sha256 = view.candidate_facts_sha256
        cursor = view.projection_cursor
        terminal = view.terminal_ref
        readiness = view.readiness
        authority_event_id = view.authority_snapshot_event_id
        epoch = view.admission_rebuild_epoch
        revision = view.authority_revision
    except PolicyError:
        raise
    except Exception as error:
        raise PolicyError("policy admission view could not be detached") from error
    try:
        if (
            detached != candidate
            or type(claimed_facts_sha256) is not str
            or _HEX64.fullmatch(claimed_facts_sha256) is None
            or claimed_facts_sha256 != facts_sha256
            or type(authority_event_id) is not str
            or _EVENT_ID.fullmatch(authority_event_id) is None
            or authority_event_id != detached.correlation_snapshot_event_id
            or type(cursor) is not ProjectionCursor
            or type(terminal) is not EvidenceRef
            or type(readiness) is not MutationReadiness
            or type(epoch) is not int
            or not 1 <= epoch <= MAX_UINT64
            or type(revision) is not int
            or not 1 <= revision <= MAX_UINT64
        ):
            raise PolicyError("policy admission view binding is invalid")
        if (
            type(cursor.host_id) is not str
            or _UUID4.fullmatch(cursor.host_id) is None
            or type(cursor.source_sequence) is not int
            or not 0 <= cursor.source_sequence <= MAX_UINT64
            or type(cursor.event_id) is not str
            or _EVENT_ID.fullmatch(cursor.event_id) is None
            or type(cursor.content_sha256) is not str
            or _HEX64.fullmatch(cursor.content_sha256) is None
            or type(cursor.frame_sha256) is not str
            or _HEX64.fullmatch(cursor.frame_sha256) is None
        ):
            raise PolicyError("policy projection cursor is not exact")
        detached_cursor = ProjectionCursor(
            host_id=cursor.host_id,
            source_sequence=cursor.source_sequence,
            event_id=cursor.event_id,
            content_sha256=cursor.content_sha256,
            frame_sha256=cursor.frame_sha256,
        )
        detached_terminal = EvidenceRef(*_exact_coverage_ref_key(terminal))
        if (
            type(readiness.ready) is not bool
            or readiness.ready is not True
            or type(readiness.reason_codes) is not tuple
            or readiness.reason_codes != ()
            or not (
                type(readiness.observer_reconcile_generation) is int
                and 1 <= readiness.observer_reconcile_generation <= MAX_UINT64
            )
            or type(readiness.coverage_snapshot_sha256) is not str
            or _HEX64.fullmatch(readiness.coverage_snapshot_sha256) is None
            or readiness.coverage_snapshot_sha256
            != detached.coverage_snapshot_sha256
        ):
            raise PolicyError("policy admission readiness is not exact")
        readiness_cursors = (
            readiness.evidence_head,
            readiness.acceptance_cursor,
            readiness.confirmed_through,
            readiness.projection_cursor,
        )
        if (
            any(
                type(value) is not int or not 0 <= value <= MAX_UINT64
                for value in readiness_cursors
            )
            or len(set(readiness_cursors)) != 1
            or readiness.projection_cursor != detached_cursor.source_sequence
            or detached_terminal.source_sequence != detached_cursor.source_sequence
            or detached_cursor.host_id != detached.host_id
            or detached_terminal.event_id != detached_cursor.event_id
            or detached_terminal.content_sha256 != detached_cursor.content_sha256
            or detached_terminal.frame_sha256 != detached_cursor.frame_sha256
        ):
            raise PolicyError("policy admission cursors are not exact")
        detached_readiness = MutationReadiness(
            ready=readiness.ready,
            reason_codes=readiness.reason_codes,
            evidence_head=readiness.evidence_head,
            acceptance_cursor=readiness.acceptance_cursor,
            confirmed_through=readiness.confirmed_through,
            projection_cursor=readiness.projection_cursor,
            observer_reconcile_generation=(
                readiness.observer_reconcile_generation
            ),
            coverage_snapshot_sha256=readiness.coverage_snapshot_sha256,
        )
        seal = canonical_json(
            {
                "admission_rebuild_epoch": epoch,
                "authority_revision": revision,
                "authority_snapshot_event_id": authority_event_id,
                "candidate_canonical_sha256": hashlib.sha256(
                    candidate_bytes
                ).hexdigest(),
                "candidate_facts_sha256": facts_sha256,
                "projection_cursor": {
                    "content_sha256": detached_cursor.content_sha256,
                    "event_id": detached_cursor.event_id,
                    "frame_sha256": detached_cursor.frame_sha256,
                    "host_id": detached_cursor.host_id,
                    "source_sequence": detached_cursor.source_sequence,
                },
                "readiness": {
                    "acceptance_cursor": detached_readiness.acceptance_cursor,
                    "confirmed_through": detached_readiness.confirmed_through,
                    "coverage_snapshot_sha256": (
                        detached_readiness.coverage_snapshot_sha256
                    ),
                    "evidence_head": detached_readiness.evidence_head,
                    "observer_reconcile_generation": (
                        detached_readiness.observer_reconcile_generation
                    ),
                    "projection_cursor": detached_readiness.projection_cursor,
                    "ready": detached_readiness.ready,
                    "reason_codes": detached_readiness.reason_codes,
                },
                "terminal_ref": {
                    "content_sha256": detached_terminal.content_sha256,
                    "event_id": detached_terminal.event_id,
                    "frame_offset": detached_terminal.frame_offset,
                    "frame_sha256": detached_terminal.frame_sha256,
                    "frame_size": detached_terminal.frame_size,
                    "segment_id": detached_terminal.segment_id,
                    "segment_relative_path": (
                        detached_terminal.segment_relative_path
                    ),
                    "source_sequence": detached_terminal.source_sequence,
                },
            }
        )
    except PolicyError:
        raise
    except Exception as error:
        raise PolicyError("policy admission view could not be sealed") from error
    return _ViewSnapshot(candidate=detached, public_seal=seal)


def _evidence_age_ms(
    created_at: str,
    sample: CoreClockSample,
    uncertainty_ns: int,
) -> int:
    decision_ns = _datetime_ns(sample.decision_utc)
    created_ns = _timestamp_ns(created_at)
    if decision_ns < created_ns:
        raise PolicyError("policy candidate creation time is in the future")
    age_ns = decision_ns - created_ns + uncertainty_ns
    age_ms = (age_ns + _NANOSECONDS_PER_MILLISECOND - 1) // (
        _NANOSECONDS_PER_MILLISECOND
    )
    if not 0 <= age_ms <= MAX_UINT64:
        raise PolicyError("policy evidence age is outside uint64")
    return age_ms


def _policy_input_for_candidate(
    candidate: object,
    evidence_age_ms: int,
) -> PolicyInputV1:
    from agmind_immune.incidents.models import ContainmentCandidateV1

    if (
        type(candidate) is not ContainmentCandidateV1
        or type(evidence_age_ms) is not int
        or not 0 <= evidence_age_ms <= MAX_UINT64
    ):
        raise PolicyError("policy input requires exact candidate facts and age")
    base: dict[str, object] = {
        "schema_version": "agmind.policy-input.v1",
        "candidate_id": candidate.candidate_id,
        "candidate_facts_sha256": candidate_facts_sha256(candidate),
        "host_id": candidate.host_id,
        "boot_id": candidate.boot_id,
        "docker_container_id": candidate.docker_container_id,
        "docker_started_at": candidate.docker_started_at,
        "image_id": candidate.image_id,
        "repo_digests": candidate.repo_digests,
        "immutable_spec_sha256": candidate.immutable_spec_sha256,
        "inventory_generation": candidate.inventory_generation,
        "inventory_revision": candidate.inventory_revision,
        "destination_ipv4": candidate.destination_ipv4,
        "destination_port": candidate.destination_port,
        "l4_protocol": candidate.l4_protocol,
        "requested_ttl_seconds": candidate.ttl_seconds,
        "detector_rule": candidate.detector_rule,
        "detector_rule_version": candidate.detector_rule_version,
        "detector_bundle_sha256": candidate.detector_bundle_sha256,
        "coverage_ready": True,
        "coverage_snapshot_sha256": candidate.coverage_snapshot_sha256,
        "docker_network_snapshot_sha256": (
            candidate.docker_network_snapshot_sha256
        ),
        "special_use_registry_sha256": candidate.special_use_registry_sha256,
        "operator_denylist_sha256": candidate.operator_denylist_sha256,
        "management_denylist_sha256": candidate.management_denylist_sha256,
        "evidence_ids": candidate.evidence_ids,
        "evidence_age_ms": evidence_age_ms,
        "policy_bundle_version": POLICY_BUNDLE.version,
        "policy_bundle_sha256": POLICY_BUNDLE.sha256,
    }
    base["policy_input_sha256"] = _policy_input_sha256(base)
    try:
        value = PolicyInputV1.model_validate(base, strict=True)
    except Exception as error:
        raise PolicyError("policy input could not be constructed exactly") from error
    if type(value) is not PolicyInputV1:
        raise PolicyError("policy input construction returned an inexact value")
    return value


def _policy_input(
    snapshot: _ViewSnapshot,
    sample: CoreClockSample,
    uncertainty_ns: int,
) -> PolicyInputV1:
    candidate = snapshot.candidate
    age_ms = _evidence_age_ms(candidate.created_at, sample, uncertainty_ns)
    return _policy_input_for_candidate(candidate, age_ms)


def _new_http_client(
    transport: httpx.AsyncBaseTransport | None,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=_OPA_BASE_URL,
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Content-Type": "application/json",
        },
        timeout=httpx.Timeout(
            _TOTAL_TIMEOUT_SECONDS,
            connect=_CONNECT_TIMEOUT_SECONDS,
            read=_TOTAL_TIMEOUT_SECONDS,
            write=_TOTAL_TIMEOUT_SECONDS,
            pool=_CONNECT_TIMEOUT_SECONDS,
        ),
        follow_redirects=False,
        max_redirects=0,
        limits=httpx.Limits(
            max_connections=1,
            max_keepalive_connections=1,
            keepalive_expiry=2.0,
        ),
        http1=True,
        http2=False,
        transport=transport,
        trust_env=False,
    )


def _validate_response_headers(headers: httpx.Headers) -> None:
    raw_headers = headers.raw
    if len(raw_headers) > _MAX_RESPONSE_HEADER_COUNT:
        raise PolicyResponseInvalid("OPA returned too many response headers")
    total = 0
    for name, value in raw_headers:
        if (
            type(name) is not bytes
            or type(value) is not bytes
            or not 1 <= len(name) <= _MAX_RESPONSE_HEADER_NAME_BYTES
            or len(value) > _MAX_RESPONSE_HEADER_VALUE_BYTES
            or _HEADER_NAME.fullmatch(name) is None
            or b"\x00" in value
            or b"\r" in value
            or b"\n" in value
        ):
            raise PolicyResponseInvalid("OPA response header is not bounded ASCII")
        total += len(name) + len(value) + 4
        if total > _MAX_RESPONSE_HEADER_BYTES:
            raise PolicyResponseInvalid("OPA response headers exceed the byte limit")


def _content_length(headers: httpx.Headers) -> int | None:
    values = headers.get_list("content-length")
    if not values:
        return None
    if len(values) != 1:
        raise PolicyResponseInvalid("OPA returned duplicate Content-Length")
    value = values[0]
    if (
        type(value) is not str
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise PolicyResponseInvalid("OPA Content-Length is not canonical decimal")
    length = int(value)
    if not 0 <= length <= _MAX_RESPONSE_BYTES:
        raise PolicyResponseInvalid("OPA response exceeds the byte limit")
    return length


async def _read_response(response: httpx.Response) -> bytes:
    _validate_response_headers(response.headers)
    if 300 <= response.status_code <= 399:
        raise PolicyResponseInvalid("OPA redirects are forbidden")
    if response.status_code != 200:
        raise PolicyUnavailable("OPA did not return HTTP 200")
    if response.headers.get_list("content-type") != ["application/json"]:
        raise PolicyResponseInvalid("OPA content type is not exact JSON")
    if response.headers.get_list("content-encoding"):
        raise PolicyResponseInvalid("OPA response content encoding is forbidden")
    declared_length = _content_length(response.headers)
    if response.is_stream_consumed:
        raw = response.content
        if type(raw) is not bytes or len(raw) > _MAX_RESPONSE_BYTES:
            raise PolicyResponseInvalid("OPA response exceeds the byte limit")
    else:
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_raw():
            if type(chunk) is not bytes:
                raise PolicyResponseInvalid(
                    "OPA response stream yielded inexact bytes"
                )
            total += len(chunk)
            if total > _MAX_RESPONSE_BYTES:
                raise PolicyResponseInvalid("OPA response exceeds the byte limit")
            chunks.append(chunk)
        raw = b"".join(chunks)
    if declared_length is not None and declared_length != len(raw):
        raise PolicyResponseInvalid("OPA Content-Length differs from response bytes")
    return raw


def _narrow_decision(
    decision: PolicyDecisionV1,
    policy_input: PolicyInputV1,
) -> None:
    if (
        decision.candidate_id != policy_input.candidate_id
        or decision.candidate_facts_sha256
        != policy_input.candidate_facts_sha256
        or decision.policy_input_sha256 != policy_input.policy_input_sha256
        or decision.policy_bundle_version != POLICY_BUNDLE.version
        or decision.policy_bundle_sha256 != POLICY_BUNDLE.sha256
    ):
        raise PolicyResponseInvalid("OPA response changed policy bindings")
    if decision.effect == "manual_approval_required" and (
        policy_input.l4_protocol != "tcp"
        or policy_input.evidence_age_ms > _MAX_EVIDENCE_AGE_MS
        or not 30
        <= decision.max_ttl_seconds
        <= min(policy_input.requested_ttl_seconds, 120)
        or decision.allowed_evidence_ids != policy_input.evidence_ids
    ):
        raise PolicyResponseInvalid("OPA response widened manual policy authority")


def _exact_model_state(
    value: object,
    model_type: type[PolicyInputV1 | PolicyDecisionV1 | PolicyEvaluation],
) -> bool:
    return (
        type(value) is model_type
        and set(value.__dict__) == set(model_type.model_fields)
        and value.model_fields_set == set(model_type.model_fields)
        and value.__pydantic_extra__ in (None, {})
    )


def _detach_policy_evaluation(value: object) -> PolicyEvaluation:
    if not _exact_model_state(value, PolicyEvaluation):
        raise PolicyResponseInvalid("policy evaluation runtime shape is not exact")
    evaluation = cast(PolicyEvaluation, value)
    if (
        not _exact_model_state(evaluation.policy_input, PolicyInputV1)
        or not _exact_model_state(evaluation.decision, PolicyDecisionV1)
        or type(evaluation.policy_bundle) is not PolicyBundleIdentity
    ):
        raise PolicyResponseInvalid("policy evaluation runtime shape is not exact")
    try:
        policy_input = PolicyInputV1.model_validate(
            evaluation.policy_input.model_dump(mode="python"),
            strict=True,
        )
        decision = PolicyDecisionV1.model_validate(
            evaluation.decision.model_dump(mode="python"),
            strict=True,
        )
        bundle = PolicyBundleIdentity(
            version=evaluation.policy_bundle.version,
            sha256=evaluation.policy_bundle.sha256,
        )
        detached = PolicyEvaluation.model_validate(
            {
                "policy_input": policy_input,
                "decision": decision,
                "candidate_id": evaluation.candidate_id,
                "candidate_facts_sha256": evaluation.candidate_facts_sha256,
                "policy_input_sha256": evaluation.policy_input_sha256,
                "policy_decision_sha256": evaluation.policy_decision_sha256,
                "policy_bundle": bundle,
                "evaluated_at": evaluation.evaluated_at,
                "evidence_age_ms": evaluation.evidence_age_ms,
            },
            strict=True,
        )
    except Exception as error:
        raise PolicyResponseInvalid("policy evaluation cannot be detached") from error
    if (
        type(detached) is not PolicyEvaluation
        or not hmac.compare_digest(
            canonical_json(detached),
            canonical_json(evaluation),
        )
    ):
        raise PolicyResponseInvalid("policy evaluation changed while detaching")
    return detached


def _validate_policy_evaluation_for_candidate(
    value: object,
    candidate: object,
) -> PolicyEvaluation:
    detached = _detach_policy_evaluation(value)
    expected_input = _policy_input_for_candidate(
        candidate,
        detached.evidence_age_ms,
    )
    if not hmac.compare_digest(
        canonical_json(detached.policy_input),
        canonical_json(expected_input),
    ):
        raise PolicyResponseInvalid(
            "policy evaluation does not bind the reauthenticated candidate"
        )
    _narrow_decision(detached.decision, detached.policy_input)
    return detached


class PolicyClient:
    """Concurrency-one evaluator with immutable production configuration."""

    __slots__ = ("_clock", "_closed", "_http", "_lock", "_policy_bytes")

    def __init__(
        self,
        clock: CoreClockProvider,
        http: httpx.AsyncClient,
        policy_bytes: bytes,
        *,
        _factory: object,
    ) -> None:
        if _factory not in {_CLIENT_FACTORY, _TEST_CLIENT_FACTORY}:
            raise TypeError("use PolicyClient.create()")
        if (
            not callable(getattr(clock, "decision_sample", None))
            or type(http) is not httpx.AsyncClient
            or type(policy_bytes) is not bytes
            or hashlib.sha256(policy_bytes).hexdigest() != POLICY_BUNDLE.sha256
        ):
            raise PolicyUnavailable("policy client authorities are invalid")
        self._clock = clock
        self._http = http
        self._policy_bytes = policy_bytes
        self._lock = asyncio.Lock()
        self._closed = False

    @classmethod
    def create(cls, clock: CoreClockProvider) -> PolicyClient:
        policy_bytes = _load_pinned_policy()
        return cls(
            clock,
            _new_http_client(None),
            policy_bytes,
            _factory=_CLIENT_FACTORY,
        )

    async def _evaluate_locked(self, view: object) -> PolicyEvaluation:
        if self._closed:
            raise PolicyUnavailable("policy client is closed")
        before = _capture_view(view)
        sample, uncertainty_ns = _clock_observation(self._clock)
        policy_input = _policy_input(before, sample, uncertainty_ns)
        request_body = canonical_json({"input": policy_input})
        if not 1 <= len(request_body) <= _MAX_REQUEST_BYTES:
            raise PolicyError("policy request exceeds the byte limit")
        try:
            async with self._http.stream(
                "POST",
                _OPA_ROUTE,
                content=request_body,
            ) as response:
                raw = await _read_response(response)
        except PolicyError:
            raise
        except httpx.RequestError as error:
            raise PolicyUnavailable("OPA transport is unavailable") from error
        except Exception as error:
            raise PolicyUnavailable("OPA response transport failed") from error
        try:
            wrapper = decode_strict(raw, _OPAResponseV1, _MAX_RESPONSE_BYTES)
        except (TypeError, ValueError) as error:
            raise PolicyResponseInvalid("OPA response is not strict JSON") from error
        if type(wrapper) is not _OPAResponseV1 or type(wrapper.result) is not PolicyDecisionV1:
            raise PolicyResponseInvalid("OPA response value is not exact")
        decision = wrapper.result
        _narrow_decision(decision, policy_input)
        after = _capture_view(view)
        if not hmac.compare_digest(before.public_seal, after.public_seal):
            raise PolicyError("admission view changed during policy evaluation")
        try:
            evaluation = PolicyEvaluation.model_validate(
                {
                    "policy_input": policy_input,
                    "decision": decision,
                    "candidate_id": policy_input.candidate_id,
                    "candidate_facts_sha256": (
                        policy_input.candidate_facts_sha256
                    ),
                    "policy_input_sha256": policy_input.policy_input_sha256,
                    "policy_decision_sha256": _policy_decision_sha256(decision),
                    "policy_bundle": POLICY_BUNDLE,
                    "evaluated_at": _utc_text(sample.decision_utc),
                    "evidence_age_ms": policy_input.evidence_age_ms,
                },
                strict=True,
            )
        except Exception as error:
            raise PolicyResponseInvalid(
                "policy evaluation bindings could not be sealed"
            ) from error
        if type(evaluation) is not PolicyEvaluation:
            raise PolicyResponseInvalid("policy evaluation is not exact")
        return evaluation

    async def evaluate(self, view: object) -> PolicyEvaluation:
        try:
            async with asyncio.timeout(_TOTAL_TIMEOUT_SECONDS):
                async with self._lock:
                    return await self._evaluate_locked(view)
        except TimeoutError as error:
            raise PolicyUnavailable("OPA whole-call deadline expired") from error

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                await self._http.aclose()
            except Exception as error:
                raise PolicyUnavailable("policy HTTP client close failed") from error


def _policy_client_for_test(
    *,
    clock: CoreClockProvider,
    transport: httpx.AsyncBaseTransport,
    policy_path: Path,
) -> PolicyClient:
    if not isinstance(transport, httpx.AsyncBaseTransport):
        raise TypeError("policy test transport is not exact")
    return PolicyClient(
        clock,
        _new_http_client(transport),
        _load_test_policy(policy_path),
        _factory=_TEST_CLIENT_FACTORY,
    )
