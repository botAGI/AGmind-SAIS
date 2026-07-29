"""Fail-closed JSON Schema validation for shared contract tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agmind_immune import contracts
from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators

_CONTRACT_SEMANTIC_MODELS = {
    "EvidenceRepairAuthorizeV1": contracts.EvidenceRepairAuthorizeV1,
    "EvidenceRepairCompleteV1": contracts.EvidenceRepairCompleteV1,
    "RetentionTombstoneV2": contracts.RetentionTombstoneV2,
    "RetentionBlockedV1": contracts.RetentionBlockedV1,
}


def _validate_agmind_semantic(
    _validator: Any,
    model_name: object,
    instance: object,
    _schema: Mapping[str, Any],
) -> Any:
    if not isinstance(model_name, str):
        yield ValidationError("x-agmind-semantic must name a contract model")
        return
    model: Any = _CONTRACT_SEMANTIC_MODELS.get(model_name)
    if model is None:
        yield ValidationError(f"unknown x-agmind-semantic model: {model_name}")
        return
    try:
        model.model_validate(instance, strict=True)
    except ValueError as exc:
        yield ValidationError(f"{model_name} semantic validation failed: {exc}")


StrictDraft202012Validator = validators.extend(
    Draft202012Validator,
    {"x-agmind-semantic": _validate_agmind_semantic},
)

CONTRACT_FORMAT_CHECKER = FormatChecker()


@CONTRACT_FORMAT_CHECKER.checks("date-time")
def _strict_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    try:
        contracts._valid_timestamp(value)
    except ValueError:
        return False
    return True


def contract_schema_validator(
    schema: Mapping[str, Any],
) -> Draft202012Validator:
    """Build a Draft 2020-12 validator with the pinned strict formats."""
    return StrictDraft202012Validator(
        schema,
        format_checker=CONTRACT_FORMAT_CHECKER,
    )
