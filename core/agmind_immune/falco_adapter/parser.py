"""Strict one-body parser for Falco 0.44.1 HTTP output."""

from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

from agmind_immune.contracts import (
    MAX_UINT64,
    FalcoConnectV1,
    _parse_integer,
    _reject_constant,
    _unique_object,
    _validate_json_depth,
    _validate_unicode,
)

from .redaction import normalize_falco_time, redact_falco_event

FALCO_MAX_BODY_BYTES = 65_536
METRICS_RULE = "Falco internal: metrics snapshot"
METRICS_SOURCE = "internal"
METRICS_PRIORITY = "Informational"
CONFIG_HASH_FIELD = "falco.sha256_config_file.falco_yaml"
RULES_HASH_FIELD = "falco.sha256_rules_file.agmind_pcc_yaml"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_FLOAT_TOKEN_CHARACTERS = 128
MAX_FLOAT_DECIMAL_EXPONENT = 308


class FalcoMetricsHeartbeat(BaseModel):
    """The only metrics fields allowed to affect adapter coverage state."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    event_time: str
    raw_event_sha256: str
    falco_version: str
    engine_name: str
    config_sha256: str
    rules_sha256: str
    outputs_queue_num_drops: int
    scap_n_drops: int

    @field_validator("raw_event_sha256", "config_sha256", "rules_sha256")
    @classmethod
    def digest_is_hex(cls, value: str) -> str:
        if HEX64.fullmatch(value) is None:
            raise ValueError("heartbeat digest must be lowercase SHA-256")
        return value

    @field_validator("outputs_queue_num_drops", "scap_n_drops")
    @classmethod
    def counter_is_uint64(cls, value: int) -> int:
        if isinstance(value, bool) or not 0 <= value <= MAX_UINT64:
            raise ValueError("heartbeat counter must be uint64")
        return value


def _parse_bounded_decimal(token: str) -> Decimal:
    if len(token) > MAX_FLOAT_TOKEN_CHARACTERS:
        raise ValueError("floating-point JSON token exceeds bound")
    try:
        value = Decimal(token)
    except InvalidOperation as error:
        raise ValueError("invalid floating-point JSON token") from error
    exponent = value.as_tuple().exponent
    if (
        not value.is_finite()
        or not isinstance(exponent, int)
        or abs(exponent) > MAX_FLOAT_DECIMAL_EXPONENT
        or not value.is_zero()
        and abs(value.adjusted()) > MAX_FLOAT_DECIMAL_EXPONENT
    ):
        raise ValueError("floating-point JSON token exceeds bound")
    return value


def _contains_decimal(value: object) -> bool:
    if isinstance(value, Decimal):
        return True
    if isinstance(value, list):
        return any(_contains_decimal(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_decimal(item) for item in value.values())
    return False


def _decode_raw_object(raw: bytes) -> dict[str, Any]:
    if len(raw) > FALCO_MAX_BODY_BYTES:
        raise ValueError("Falco body exceeds 65536 bytes")
    text = raw.decode("utf-8", "strict")
    _validate_json_depth(text)
    decoder = json.JSONDecoder(
        object_pairs_hook=_unique_object,
        parse_int=_parse_integer,
        parse_float=_parse_bounded_decimal,
        parse_constant=_reject_constant,
    )
    start = 0
    while start < len(text) and text[start] in " \t\r\n":
        start += 1
    try:
        value, end = decoder.raw_decode(text, start)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid Falco JSON: {error.msg}") from error
    while end < len(text) and text[end] in " \t\r\n":
        end += 1
    if end != len(text):
        raise ValueError("trailing Falco JSON data is forbidden")
    if not isinstance(value, dict):
        raise TypeError("Falco body must be a JSON object")
    _validate_unicode(value)
    return value


def _required_string(fields: dict[str, Any], name: str) -> str:
    value = fields.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"metrics field {name} must be a nonempty string")
    return value


def _required_counter(fields: dict[str, Any], name: str) -> int:
    value = fields.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"metrics field {name} must be an integer")
    if not 0 <= value <= MAX_UINT64:
        raise ValueError(f"metrics field {name} must be uint64")
    return value


def _parse_metrics(
    document: dict[str, Any],
    raw_event_sha256: str,
) -> FalcoMetricsHeartbeat:
    if document.get("source") != METRICS_SOURCE:
        raise ValueError("unexpected Falco metrics source")
    if document.get("priority") != METRICS_PRIORITY:
        raise ValueError("unexpected Falco metrics priority")
    fields = document.get("output_fields")
    if not isinstance(fields, dict):
        raise TypeError("Falco metrics output_fields must be an object")
    return FalcoMetricsHeartbeat(
        event_time=normalize_falco_time(document.get("time")),
        raw_event_sha256=raw_event_sha256,
        falco_version=_required_string(fields, "falco.version"),
        engine_name=_required_string(fields, "scap.engine_name"),
        config_sha256=_required_string(fields, CONFIG_HASH_FIELD),
        rules_sha256=_required_string(fields, RULES_HASH_FIELD),
        outputs_queue_num_drops=_required_counter(
            fields,
            "falco.outputs_queue_num_drops",
        ),
        scap_n_drops=_required_counter(fields, "scap.n_drops"),
    )


def parse_falco_body(raw: bytes) -> FalcoConnectV1 | FalcoMetricsHeartbeat:
    """Hash and decode exactly one raw Falco HTTP body, then discard raw fields."""
    raw_event_sha256 = hashlib.sha256(raw).hexdigest()
    document = _decode_raw_object(raw)
    if document.get("rule") == METRICS_RULE:
        return _parse_metrics(document, raw_event_sha256)
    if _contains_decimal(document):
        raise ValueError("floating-point JSON is forbidden outside Falco metrics")
    return redact_falco_event(document, raw_event_sha256)
