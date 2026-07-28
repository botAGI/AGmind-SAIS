"""Allowlist-only normalization of the pinned Falco connect rule."""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
from collections.abc import Mapping

from agmind_immune.contracts import MAX_INT64, MIN_INT64, FalcoConnectV1

FALCO_VERSION = "0.44.1"
CONNECT_RULE = "AGmind PCC Suspicious Process Outbound Connect"
CONNECT_RULE_TAG = "agmind-pcc-rules-v1"
CONNECT_SOURCE = "syscall"
NONBLOCKING_RESULTS = {"EINPROGRESS", "EINPROGRESS(115)"}
HEX_12_TO_64 = re.compile(r"^[0-9a-f]{12,64}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
FALCO_TIMESTAMP = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})"
    r"T(?P<clock>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?P<fraction>\.[0-9]{1,9})?"
    r"(?P<zone>Z|[+-][0-9]{2}:?[0-9]{2})$"
)

SENSOR_FIELD_MAP = {
    "container.id": "falco_container_id_prefix",
    "container.start_ts": "falco_container_start_ts",
    "proc.name": "proc_name",
    "proc.exepath": "proc_exe_path",
    "proc.pname": "proc_parent_name",
    "fd.rip": "destination_ipv4",
    "fd.rport": "destination_port",
    "fd.l4proto": "l4_protocol",
}


def normalize_falco_time(value: object) -> str:
    """Normalize a bounded RFC3339 timestamp to UTC with nanoseconds intact."""
    if not isinstance(value, str):
        raise TypeError("Falco time must be a string")
    match = FALCO_TIMESTAMP.fullmatch(value)
    if match is None or value.startswith("0000-"):
        raise ValueError("invalid Falco event time")
    zone = match.group("zone")
    if zone == "Z":
        offset = dt.UTC
    else:
        sign = 1 if zone[0] == "+" else -1
        zone_digits = zone[1:].replace(":", "")
        hours = int(zone_digits[:2])
        minutes = int(zone_digits[2:])
        if hours > 23 or minutes > 59:
            raise ValueError("invalid Falco event time offset")
        offset = dt.timezone(sign * dt.timedelta(hours=hours, minutes=minutes))
    try:
        parsed = dt.datetime.fromisoformat(f"{match.group('date')}T{match.group('clock')}").replace(
            tzinfo=offset
        )
    except ValueError as error:
        raise ValueError("invalid Falco event time") from error
    utc = parsed.astimezone(dt.UTC)
    fraction = (match.group("fraction") or "")[1:].rstrip("0")
    suffix = f".{fraction}" if fraction else ""
    return utc.strftime("%Y-%m-%dT%H:%M:%S") + suffix + "Z"


def _is_missing(value: object) -> bool:
    return value is None or value == "<NA>"


def _bounded_text(value: object, field: str, maximum: int = 512) -> str | None:
    if _is_missing(value):
        return None
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    size = len(value.encode("utf-8", "strict"))
    if size < 1 or size > maximum:
        raise ValueError(f"{field} exceeds its UTF-8 bound")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError(f"{field} contains a surrogate")
    return value


def _bounded_ascii(value: object, field: str, maximum: int = 64) -> str | None:
    text = _bounded_text(value, field, maximum)
    if text is None:
        return None
    try:
        encoded = text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field} must be ASCII") from error
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise ValueError(f"{field} must be printable ASCII")
    return text


def _required_ascii(value: object, field: str) -> str:
    result = _bounded_ascii(value, field)
    if result is None:
        raise ValueError(f"{field} is required")
    return result


def _int64(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    if not MIN_INT64 <= value <= MAX_INT64:
        raise ValueError(f"{field} exceeds int64")
    return value


def _optional_int64(value: object, field: str) -> int | None:
    if _is_missing(value):
        return None
    return _int64(value, field)


def _container_prefix(value: object) -> str | None:
    text = _bounded_ascii(value, "container.id")
    if text is not None and HEX_12_TO_64.fullmatch(text) is None:
        raise ValueError("container.id must be 12..64 lowercase hex")
    return text


def _container_full_id(value: object) -> str | None:
    text = _bounded_ascii(value, "container.full_id")
    if text is not None and HEX_64.fullmatch(text) is None:
        raise ValueError("container.full_id must be 64 lowercase hex")
    return text


def _container_start(value: object) -> int | str | None:
    if _is_missing(value):
        return None
    if isinstance(value, bool):
        raise TypeError("container.start_ts must be an integer or ASCII string")
    if isinstance(value, int):
        return _int64(value, "container.start_ts")
    return _bounded_ascii(value, "container.start_ts")


def _destination_ipv4(value: object) -> str | None:
    text = _bounded_ascii(value, "fd.rip")
    if text is None:
        return None
    try:
        parsed = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError as error:
        raise ValueError("fd.rip must be canonical IPv4") from error
    if str(parsed) != text:
        raise ValueError("fd.rip must be canonical IPv4")
    return text


def _destination_port(value: object) -> int | None:
    if _is_missing(value):
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("fd.rport must be an integer")
    if not 1 <= value <= 65_535:
        raise ValueError("fd.rport must be 1..65535")
    return value


def _output_fields(event: Mapping[str, object]) -> Mapping[str, object]:
    output_fields = event.get("output_fields")
    if not isinstance(output_fields, dict):
        raise TypeError("Falco output_fields must be an object")
    return output_fields


def redact_falco_event(
    event: Mapping[str, object],
    raw_event_sha256: str,
) -> FalcoConnectV1:
    """Return only candidate-relevant bounded facts from the exact pinned rule."""
    if event.get("rule") != CONNECT_RULE:
        raise ValueError("unexpected Falco rule")
    if event.get("source") != CONNECT_SOURCE:
        raise ValueError("unexpected Falco source")
    if event.get("priority") != "Notice":
        raise ValueError("unexpected Falco priority")
    tags = event.get("tags")
    if tags != [CONNECT_RULE_TAG]:
        raise ValueError("unexpected Falco rule tags")
    fields = _output_fields(event)
    evt_type = _required_ascii(fields.get("evt.type"), "evt.type")
    if evt_type != "connect":
        raise ValueError("unexpected Falco event type")
    rawres = _optional_int64(fields.get("evt.rawres"), "evt.rawres")
    result = _required_ascii(fields.get("evt.res"), "evt.res")
    completed_success = result == "SUCCESS" and rawres is not None and rawres >= 0
    nonblocking_success = result in NONBLOCKING_RESULTS and (rawres is None or rawres < 0)
    hard_error = result not in {"SUCCESS", *NONBLOCKING_RESULTS}
    if result == "SUCCESS" and not completed_success:
        raise ValueError("contradictory completed result tuple")
    if result in NONBLOCKING_RESULTS and not nonblocking_success:
        raise ValueError("contradictory nonblocking result tuple")
    if hard_error and rawres is not None and rawres >= 0:
        raise ValueError("contradictory hard-error result tuple")

    container_id_prefix = _container_prefix(fields.get("container.id"))
    container_start_ts = _container_start(fields.get("container.start_ts"))
    proc_name = _bounded_text(fields.get("proc.name"), "proc.name")
    proc_exe_path = _bounded_text(fields.get("proc.exepath"), "proc.exepath")
    proc_parent_name = _bounded_text(fields.get("proc.pname"), "proc.pname")
    destination_ipv4 = _destination_ipv4(fields.get("fd.rip"))
    destination_port = _destination_port(fields.get("fd.rport"))
    l4_protocol = _bounded_ascii(fields.get("fd.l4proto"), "fd.l4proto")
    sensor_values = {
        "falco_container_id_prefix": container_id_prefix,
        "falco_container_start_ts": container_start_ts,
        "proc_name": proc_name,
        "proc_exe_path": proc_exe_path,
        "proc_parent_name": proc_parent_name,
        "destination_ipv4": destination_ipv4,
        "destination_port": destination_port,
        "l4_protocol": l4_protocol,
    }
    missing = sorted(field_name for field_name, value in sensor_values.items() if value is None)
    return FalcoConnectV1(
        detector_rule=CONNECT_RULE,
        detector_rule_version=CONNECT_RULE_TAG,
        falco_version=FALCO_VERSION,
        event_time=normalize_falco_time(event.get("time")),
        evt_type="connect",
        evt_rawres=rawres,
        evt_res=result,
        successful_connect=completed_success or nonblocking_success,
        investigation_only=True,
        falco_container_id_prefix=container_id_prefix,
        falco_container_full_id=_container_full_id(fields.get("container.full_id")),
        falco_container_start_ts=container_start_ts,
        repo_digests=[],
        proc_name=proc_name,
        proc_exe_path=proc_exe_path,
        proc_parent_name=proc_parent_name,
        destination_ipv4=destination_ipv4,
        destination_port=destination_port,
        l4_protocol=l4_protocol,
        missing_required_fields=missing,
        raw_event_sha256=raw_event_sha256,
    )
