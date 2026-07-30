"""Strict immutable inputs and exact time arithmetic for pure correlation."""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import re
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Self

from agmind_immune.contracts import PCC_SPECIAL_USE_REGISTRY_SHA256

_IANA_HEADER = (
    "Address Block",
    "Name",
    "RFC",
    "Allocation Date",
    "Termination Date",
    "Source",
    "Destination",
    "Forwardable",
    "Globally Reachable",
    "Reserved-by-Protocol",
)
_ADDRESS_BLOCK_COLUMN = 0
_GLOBAL_REACHABILITY_COLUMN = 8
_MAX_REGISTRY_BYTES = 64 * 1024
_MAX_REGISTRY_ROWS = 1_024
_MAX_REGISTRY_PREFIXES = 2_048
_FOOTNOTE_SUFFIX = re.compile(r"(?: \[[0-9]+\])+$")
_TIMESTAMP = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?Z$"
)
_NANOSECONDS_PER_SECOND = 1_000_000_000


class GlobalReachability(str, Enum):
    """Closed values present in the pinned IANA global-reachability column."""

    TRUE = "True"
    FALSE = "False"
    UNSPECIFIED = ""


@dataclass(frozen=True, slots=True)
class SpecialUseEntry:
    """One immutable, canonical IPv4 prefix from the pinned registry."""

    prefix: str
    globally_reachable: GlobalReachability

    def __post_init__(self) -> None:
        if type(self.prefix) is not str:
            raise TypeError("special-use prefix must be an exact string")
        if type(self.globally_reachable) is not GlobalReachability:
            raise TypeError("reachability must be an exact GlobalReachability")
        try:
            network = ipaddress.ip_network(self.prefix, strict=True)
        except ValueError as error:
            raise ValueError("special-use prefix must be canonical IPv4") from error
        if type(network) is not ipaddress.IPv4Network or str(network) != self.prefix:
            raise ValueError("special-use prefix must be canonical IPv4")


@dataclass(frozen=True, slots=True, init=False, weakref_slot=True)
class ParsedSpecialUseRegistry:
    """Deeply immutable parsed entries with no candidate authority."""

    entries: tuple[SpecialUseEntry, ...]
    _index: tuple[tuple[int, int, GlobalReachability], ...]

    def __init__(
        self,
        entries: tuple[SpecialUseEntry, ...],
    ) -> None:
        if type(entries) is not tuple:
            raise TypeError("special-use entries must be an exact tuple")
        index: list[tuple[int, int, GlobalReachability]] = []
        seen_prefixes: set[str] = set()
        for entry in entries:
            if type(entry) is not SpecialUseEntry:
                raise TypeError(
                    "special-use entries must contain exact SpecialUseEntry values"
                )
            if entry.prefix in seen_prefixes:
                raise ValueError("special-use entries contain a duplicate IPv4 prefix")
            seen_prefixes.add(entry.prefix)
            network = ipaddress.IPv4Network(entry.prefix)
            index.append(
                (
                    int(network.network_address),
                    network.prefixlen,
                    entry.globally_reachable,
                )
            )
        index.sort(key=lambda item: item[1], reverse=True)
        object.__setattr__(self, "entries", entries)
        object.__setattr__(self, "_index", tuple(index))

    @property
    def authority_sha256(self) -> str | None:
        """Parsed bytes never carry candidate authority."""
        return None

    def reachability_for(self, address: str) -> GlobalReachability | None:
        """Return the most-specific registry value, or ``None`` when unmatched."""
        value = _canonical_ipv4_address(address)
        address_int = int(value)
        for network_int, prefix_length, reachability in self._index:
            host_bits = 32 - prefix_length
            if (address_int >> host_bits) == (network_int >> host_bits):
                return reachability
        return None

    def is_globally_reachable(self, address: str) -> bool:
        """Allow unmatched IPv4 and only explicit ``True`` special-use matches."""
        reachability = self.reachability_for(address)
        return reachability is None or reachability is GlobalReachability.TRUE


class SpecialUseRegistry(ParsedSpecialUseRegistry):
    """Registry issued only after the fixed digest-checked loader succeeds."""

    __slots__ = ()

    def __new__(cls, *args: object, **kwargs: object) -> Self:
        del cls, args, kwargs
        raise TypeError(
            "SpecialUseRegistry is available only from the pinned loader"
        )

    @property
    def authority_sha256(self) -> str:
        return PCC_SPECIAL_USE_REGISTRY_SHA256


def _canonical_ipv4_address(value: str) -> ipaddress.IPv4Address:
    if type(value) is not str:
        raise TypeError("IPv4 address must be an exact string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("IPv4 address must be canonical dotted decimal") from error
    if type(address) is not ipaddress.IPv4Address or str(address) != value:
        raise ValueError("IPv4 address must be canonical dotted decimal")
    return address


def _without_footnote(value: str) -> str:
    return _FOOTNOTE_SUFFIX.sub("", value)


def _parse_reachability(value: str, row_number: int) -> GlobalReachability:
    if value == "":
        return GlobalReachability.UNSPECIFIED
    match = re.fullmatch(r"(?P<value>True|False)(?: \[[0-9]+\])*", value)
    if match is None:
        raise ValueError(f"row {row_number} has unrecognized global reachability")
    return GlobalReachability(match["value"])


def _parse_prefix(value: str, row_number: int) -> ipaddress.IPv4Network:
    normalized = _without_footnote(value.strip())
    if not normalized:
        raise ValueError(f"row {row_number} contains an empty address block")
    try:
        network = ipaddress.ip_network(normalized, strict=True)
    except ValueError as error:
        raise ValueError(
            f"row {row_number} address block is not a canonical IPv4 prefix"
        ) from error
    if type(network) is not ipaddress.IPv4Network or str(network) != normalized:
        raise ValueError(
            f"row {row_number} address block is not a canonical IPv4 prefix"
        )
    return network


def _parse_special_use_registry_bytes(
    raw: bytes,
) -> ParsedSpecialUseRegistry:
    """Strict parser separated from the digest-enforcing authority entry point."""
    if type(raw) is not bytes:
        raise TypeError("registry content must be exact bytes")
    if len(raw) > _MAX_REGISTRY_BYTES:
        raise ValueError("special-use registry exceeds the bounded byte limit")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ValueError("special-use registry must be valid UTF-8") from error
    if "\x00" in text:
        raise ValueError("special-use registry must not contain NUL")

    try:
        records = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(records, None)
        if header != list(_IANA_HEADER):
            raise ValueError("special-use registry must use the exact IANA header")

        entries: list[SpecialUseEntry] = []
        seen_prefixes: set[str] = set()
        row_count = 0
        for row_number, row in enumerate(records, start=2):
            row_count += 1
            if row_count > _MAX_REGISTRY_ROWS:
                raise ValueError("special-use registry exceeds the bounded row limit")
            if len(row) != len(_IANA_HEADER):
                raise ValueError(
                    f"row {row_number} must contain exactly 10 columns"
                )
            reachability = _parse_reachability(
                row[_GLOBAL_REACHABILITY_COLUMN],
                row_number,
            )
            raw_blocks = row[_ADDRESS_BLOCK_COLUMN].split(",")
            if any(not block.strip() for block in raw_blocks):
                raise ValueError(
                    f"row {row_number} contains an empty address block"
                )
            for raw_block in raw_blocks:
                network = _parse_prefix(raw_block, row_number)
                prefix = str(network)
                if prefix in seen_prefixes:
                    raise ValueError(
                        f"row {row_number} contains duplicate IPv4 prefix {prefix}"
                    )
                seen_prefixes.add(prefix)
                if len(seen_prefixes) > _MAX_REGISTRY_PREFIXES:
                    raise ValueError(
                        "special-use registry exceeds the bounded prefix limit"
                    )
                entries.append(SpecialUseEntry(prefix, reachability))
    except csv.Error as error:
        raise ValueError("special-use registry contains malformed CSV") from error

    if row_count == 0:
        raise ValueError("special-use registry must contain at least one row")

    return ParsedSpecialUseRegistry(tuple(entries))


def _pinned_registry_loader() -> tuple[
    Callable[[Path], SpecialUseRegistry],
    Callable[[object], bool],
]:
    issued: weakref.WeakSet[SpecialUseRegistry] = weakref.WeakSet()

    def load(path: Path) -> SpecialUseRegistry:
        """Load the fixed digest-pinned IANA snapshot before parsing."""
        if not isinstance(path, Path):
            raise TypeError("special-use registry path must be a Path")
        with path.open("rb") as handle:
            raw = handle.read(_MAX_REGISTRY_BYTES + 1)
        if len(raw) > _MAX_REGISTRY_BYTES:
            raise ValueError(
                "special-use registry exceeds the bounded byte limit"
            )
        if hashlib.sha256(raw).hexdigest() != PCC_SPECIAL_USE_REGISTRY_SHA256:
            raise ValueError(
                "special-use registry digest does not match pinned SHA-256"
            )
        parsed = _parse_special_use_registry_bytes(raw)
        registry = object.__new__(SpecialUseRegistry)
        ParsedSpecialUseRegistry.__init__(registry, parsed.entries)
        issued.add(registry)
        return registry

    def is_issued(value: object) -> bool:
        return type(value) is SpecialUseRegistry and value in issued

    return load, is_issued


(
    load_pinned_special_use_registry,
    special_use_registry_is_issued,
) = _pinned_registry_loader()
del _pinned_registry_loader


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


def parse_rfc3339nano_utc_ns(value: str) -> int:
    """Parse canonical RFC3339Nano UTC into exact Unix-epoch nanoseconds."""
    if type(value) is not str:
        raise TypeError("RFC3339Nano UTC timestamp must be an exact string")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise ValueError("timestamp must be canonical RFC3339Nano UTC ending in Z")

    year = int(match["year"])
    month = int(match["month"])
    day = int(match["day"])
    hour = int(match["hour"])
    minute = int(match["minute"])
    second = int(match["second"])
    if not 1 <= year <= 9_999 or not 1 <= month <= 12:
        raise ValueError("timestamp must be canonical RFC3339Nano UTC ending in Z")
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
        raise ValueError("timestamp must be canonical RFC3339Nano UTC ending in Z")

    fraction = match["fraction"]
    nanosecond = 0 if fraction is None else int(fraction.ljust(9, "0"))
    days = _days_from_civil(year, month, day)
    seconds = ((days * 24 + hour) * 60 + minute) * 60 + second
    return seconds * _NANOSECONDS_PER_SECOND + nanosecond
