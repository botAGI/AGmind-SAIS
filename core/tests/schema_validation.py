"""Fail-closed JSON Schema validation for shared contract tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agmind_immune.contracts import _valid_timestamp
from jsonschema import Draft202012Validator, FormatChecker

CONTRACT_FORMAT_CHECKER = FormatChecker()


@CONTRACT_FORMAT_CHECKER.checks("date-time")
def _strict_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    try:
        _valid_timestamp(value)
    except ValueError:
        return False
    return True


def contract_schema_validator(
    schema: Mapping[str, Any],
) -> Draft202012Validator:
    """Build a Draft 2020-12 validator with the pinned strict formats."""
    return Draft202012Validator(
        schema,
        format_checker=CONTRACT_FORMAT_CHECKER,
    )
