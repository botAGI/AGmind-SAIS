from __future__ import annotations

import dataclasses
import importlib
from pathlib import Path
from types import ModuleType

import pytest
from agmind_immune.contracts import PCC_SPECIAL_USE_REGISTRY_SHA256

_HEADER = (
    "Address Block,Name,RFC,Allocation Date,Termination Date,Source,"
    "Destination,Forwardable,Globally Reachable,Reserved-by-Protocol\r\n"
)


def _subject() -> ModuleType:
    try:
        return importlib.import_module("agmind_immune.correlation.primitives")
    except ModuleNotFoundError:
        pytest.fail("correlation primitives are not implemented")


def _row(address_block: str, reachability: str) -> str:
    return (
        f'{address_block},name,[RFC1],2026-01,N/A,True,True,True,'
        f'{reachability},False\r\n'
    )


def _parse(raw: bytes) -> object:
    return _subject()._parse_special_use_registry_bytes(raw)


def test_pinned_registry_loads_and_uses_the_most_specific_ipv4_prefix() -> None:
    primitives = _subject()

    registry = primitives.load_pinned_special_use_registry(
        Path("contracts/v1/ipv4-special-use.csv")
    )

    assert registry.authority_sha256 == PCC_SPECIAL_USE_REGISTRY_SHA256
    assert registry.is_globally_reachable("1.1.1.1")
    assert not registry.is_globally_reachable("10.0.0.1")
    assert not registry.is_globally_reachable("192.0.0.8")
    assert registry.is_globally_reachable("192.0.0.9")
    assert not registry.is_globally_reachable("192.0.2.1")


def test_registry_parses_every_comma_separated_block_and_footnote_suffix() -> None:
    raw = (
        _HEADER
        + _row('"192.0.0.170/32, 192.0.0.171/32"', "False [1]")
        + _row("192.0.0.0/24 [2]", "True")
    ).encode()

    registry = _parse(raw)

    assert registry.authority_sha256 is None
    assert tuple(entry.prefix for entry in registry.entries) == (
        "192.0.0.170/32",
        "192.0.0.171/32",
        "192.0.0.0/24",
    )
    assert tuple(entry.globally_reachable.value for entry in registry.entries) == (
        "False",
        "False",
        "True",
    )


def test_parser_cannot_upgrade_arbitrary_bytes_with_an_authority_digest() -> None:
    raw = (_HEADER + _row("10.0.0.0/8", "False")).encode()

    with pytest.raises(TypeError):
        _subject()._parse_special_use_registry_bytes(
            raw,
            _authority_sha256=PCC_SPECIAL_USE_REGISTRY_SHA256,
        )


def test_imported_registry_marker_cannot_upgrade_parsed_entries() -> None:
    primitives = _subject()
    parsed = _parse((_HEADER + _row("10.0.0.0/8", "False")).encode())

    assert not hasattr(primitives, "_SPECIAL_USE_REGISTRY_FACTORY")
    with pytest.raises(TypeError, match="pinned loader"):
        primitives.SpecialUseRegistry(parsed.entries)
    assert type(parsed) is not primitives.SpecialUseRegistry


def test_registry_and_entries_are_deeply_immutable() -> None:
    primitives = _subject()
    registry = _parse((_HEADER + _row("10.0.0.0/8", "False")).encode())

    assert type(registry.entries) is tuple
    with pytest.raises(dataclasses.FrozenInstanceError):
        registry.entries = ()  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        registry.entries[0].prefix = "0.0.0.0/0"  # type: ignore[misc]
    with pytest.raises(TypeError, match="pinned loader"):
        primitives.SpecialUseRegistry(registry.entries)
    with pytest.raises(TypeError, match="pinned loader"):
        primitives.SpecialUseRegistry(list(registry.entries))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="exact GlobalReachability"):
        primitives.SpecialUseEntry("10.0.0.0/8", "False")  # type: ignore[arg-type]

    assert registry.is_globally_reachable("1.1.1.1")
    assert not registry.is_globally_reachable("10.0.0.1")


def test_loader_rejects_digest_mismatch_before_decoding_or_parsing(tmp_path: Path) -> None:
    path = tmp_path / "ipv4-special-use.csv"
    path.write_bytes(b"\xffnot UTF-8 or CSV")

    with pytest.raises(ValueError, match="digest does not match pinned SHA-256"):
        _subject().load_pinned_special_use_registry(path)


def test_loader_rejects_an_oversized_registry_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "ipv4-special-use.csv"
    path.write_bytes(b"x" * (1024 * 1024))

    with pytest.raises(ValueError, match="exceeds"):
        _subject().load_pinned_special_use_registry(path)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (
            b"wrong,header\r\n",
            "exact IANA header",
        ),
        (
            (_HEADER + "10.0.0.0/8,too,few,columns\r\n").encode(),
            "exactly 10 columns",
        ),
        (
            (_HEADER + _row("10.0.0.1/8", "False")).encode(),
            "canonical IPv4 prefix",
        ),
        (
            (_HEADER + _row("2001:db8::/32", "False")).encode(),
            "canonical IPv4 prefix",
        ),
        (
            (_HEADER + _row('"10.0.0.0/8, "', "False")).encode(),
            "empty address block",
        ),
        (
            (
                _HEADER
                + _row("10.0.0.0/8", "False")
                + _row("10.0.0.0/8", "False")
            ).encode(),
            "duplicate IPv4 prefix",
        ),
        (
            (_HEADER + _row("10.0.0.0/8", "TRUE")).encode(),
            "unrecognized global reachability",
        ),
        (
            (_HEADER + _row("10.0.0.0/8", "False [x]")).encode(),
            "unrecognized global reachability",
        ),
        (
            (_HEADER + _row("10.0.0.0/8", " [1]")).encode(),
            "unrecognized global reachability",
        ),
        (
            b"\xff",
            "valid UTF-8",
        ),
    ],
)
def test_parser_rejects_malformed_input_without_skipping_rows(
    raw: bytes,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _parse(raw)


def test_parser_rejects_unclosed_or_malformed_csv_records() -> None:
    raw = (
        _HEADER
        + _row("10.0.0.0/8", "False")
        + '"192.0.2.0/24,unterminated\r\n'
    ).encode()

    with pytest.raises(ValueError, match="malformed CSV"):
        _parse(raw)


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        ("1969-12-31T23:59:59Z", -1_000_000_000),
        ("1970-01-01T00:00:00Z", 0),
        ("1970-01-01T00:00:00.0Z", 0),
        ("1970-01-01T00:00:00.1234567Z", 123_456_700),
        ("1970-01-01T00:00:00.12345678Z", 123_456_780),
        ("1970-01-01T00:00:00.123456789Z", 123_456_789),
        ("1970-01-01T00:00:00.999999999Z", 999_999_999),
        ("1970-01-01T00:00:01Z", 1_000_000_000),
        ("2000-02-29T00:00:00Z", 951_782_400_000_000_000),
    ],
)
def test_rfc3339nano_parser_preserves_integer_nanoseconds(
    timestamp: str,
    expected: int,
) -> None:
    result = _subject().parse_rfc3339nano_utc_ns(timestamp)

    assert type(result) is int
    assert result == expected


@pytest.mark.parametrize(
    "timestamp",
    [
        "",
        "0000-01-01T00:00:00Z",
        "2025-02-29T00:00:00Z",
        "2024-02-30T00:00:00Z",
        "2024-01-01T24:00:00Z",
        "2024-01-01T00:60:00Z",
        "2024-01-01T00:00:60Z",
        "2024-01-01T00:00:00.Z",
        "2024-01-01T00:00:00.1234567890Z",
        "2024-01-01T00:00:00+00:00",
        "2024-01-01T00:00:00z",
        "2024-01-01 00:00:00Z",
        "２０２４-01-01T00:00:00Z",
    ],
)
def test_rfc3339nano_parser_rejects_noncanonical_or_invalid_values(
    timestamp: str,
) -> None:
    with pytest.raises(ValueError, match="RFC3339Nano UTC"):
        _subject().parse_rfc3339nano_utc_ns(timestamp)


def test_rfc3339nano_parser_rejects_non_string_inputs() -> None:
    with pytest.raises(TypeError, match="exact string"):
        _subject().parse_rfc3339nano_utc_ns(0)  # type: ignore[arg-type]
