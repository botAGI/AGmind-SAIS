from __future__ import annotations

import copy
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

import pytest
from agmind_immune import canonicaljson, contracts
from jsonschema import Draft202012Validator
from jsonschema.exceptions import FormatError
from pydantic import BaseModel

from tests.schema_validation import (
    CONTRACT_FORMAT_CHECKER,
    contract_schema_validator,
)

FIXTURES = Path("contracts/fixtures/v1")
SCHEMAS = Path("contracts/v1")


def _fixture(name: str) -> dict[str, Any]:
    value = json.loads((FIXTURES / name).read_text())
    assert isinstance(value, dict)
    return value


def _schema(name: str) -> dict[str, Any]:
    value = json.loads((SCHEMAS / name).read_text())
    assert isinstance(value, dict)
    Draft202012Validator.check_schema(value)
    return value


def _validator(schema_name: str) -> Draft202012Validator:
    return contract_schema_validator(_schema(schema_name))


def _wire(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


def _rebind_plan(document: dict[str, Any]) -> dict[str, Any]:
    rebound = copy.deepcopy(document)
    plan = contracts.PreparedTemporaryEgressDenyPlanV1.model_construct(**rebound)
    rebound["plan_hash"] = canonicaljson.plan_hash(plan)
    return rebound


def _rebind_action(document: dict[str, Any]) -> dict[str, Any]:
    rebound = copy.deepcopy(document)
    record = contracts.ActionRecordV1.model_construct(**rebound)
    rebound["record_sha256"] = canonicaljson.action_record_hash(record)
    rebound["record_id"] = canonicaljson.action_record_id(rebound["record_sha256"])
    return rebound


def _shift_timestamp(value: str, minutes: int) -> str:
    parsed = dt.datetime.fromisoformat(value)
    shifted = parsed + dt.timedelta(minutes=minutes)
    return shifted.isoformat().replace("+00:00", "Z")


def _timestamp_document(
    fixture_name: str,
    field: str,
    value: str,
    accepted: bool,
) -> dict[str, Any]:
    document = _fixture(fixture_name)
    document[field] = value
    if fixture_name == "coverage.valid.json":
        if field == "opened_at" and accepted:
            document.pop("closed_at", None)
        elif field == "closed_at":
            document["opened_at"] = value
    elif fixture_name == "plan.valid.json":
        if field == "prepared_at" and accepted:
            document["approval_expires_at"] = _shift_timestamp(value, 5)
        elif field == "approval_expires_at" and accepted:
            document["prepared_at"] = _shift_timestamp(value, -5)
        document = _rebind_plan(document)
    elif fixture_name == "action-record.valid.json":
        document = _rebind_action(document)
    return document


TIMESTAMP_TARGETS: tuple[
    tuple[str, str, str, type[BaseModel]],
    ...,
] = (
    (
        "event/event_time",
        "envelope.valid.json",
        "event-envelope.schema.json",
        contracts.EventEnvelopeV1,
    ),
    (
        "event/ingest_time",
        "envelope.valid.json",
        "event-envelope.schema.json",
        contracts.EventEnvelopeV1,
    ),
    (
        "event/container_start_time",
        "envelope.valid.json",
        "event-envelope.schema.json",
        contracts.EventEnvelopeV1,
    ),
    (
        "falco/docker_started_at",
        "falco.candidate.valid.json",
        "falco-connect.schema.json",
        contracts.FalcoConnectV1,
    ),
    (
        "coverage/opened_at",
        "coverage.valid.json",
        "coverage-event.schema.json",
        contracts.CoverageEventV1,
    ),
    (
        "coverage/closed_at",
        "coverage.valid.json",
        "coverage-event.schema.json",
        contracts.CoverageEventV1,
    ),
    (
        "intent/docker_started_at",
        "intent.valid.json",
        "temporary-egress-deny-intent.schema.json",
        contracts.TemporaryEgressDenyIntentV1,
    ),
    (
        "intent/created_at",
        "intent.valid.json",
        "temporary-egress-deny-intent.schema.json",
        contracts.TemporaryEgressDenyIntentV1,
    ),
    (
        "plan/docker_started_at",
        "plan.valid.json",
        "prepared-temporary-egress-deny-plan.schema.json",
        contracts.PreparedTemporaryEgressDenyPlanV1,
    ),
    (
        "plan/created_at",
        "plan.valid.json",
        "prepared-temporary-egress-deny-plan.schema.json",
        contracts.PreparedTemporaryEgressDenyPlanV1,
    ),
    (
        "plan/prepared_at",
        "plan.valid.json",
        "prepared-temporary-egress-deny-plan.schema.json",
        contracts.PreparedTemporaryEgressDenyPlanV1,
    ),
    (
        "plan/approval_expires_at",
        "plan.valid.json",
        "prepared-temporary-egress-deny-plan.schema.json",
        contracts.PreparedTemporaryEgressDenyPlanV1,
    ),
    (
        "action/observed_at",
        "action-record.valid.json",
        "action-record.schema.json",
        contracts.ActionRecordV1,
    ),
    (
        "transition/occurred_at",
        "key-transition.valid.json",
        "key-transition.schema.json",
        contracts.KeyTransitionV1,
    ),
)


def _timestamp_vectors() -> list[dict[str, Any]]:
    values = json.loads((FIXTURES / "timestamp-vectors.json").read_text())
    assert isinstance(values, list)
    return values


def test_explicit_date_time_checker_is_registered_and_fails_closed() -> None:
    assert "date-time" in CONTRACT_FORMAT_CHECKER.checkers
    for invalid in ("0000-01-01T00:00:00Z", "2026-02-29T00:00:00Z"):
        with pytest.raises(FormatError):
            CONTRACT_FORMAT_CHECKER.check(invalid, "date-time")


def test_all_seven_timestamp_schemas_exclude_year_zero_and_assert_date_time() -> None:
    schema_names = {
        schema_name for _, _, schema_name, _ in TIMESTAMP_TARGETS
    }
    assert len(schema_names) == 7
    year_zero = "0000-01-01T00:00:00Z"
    for schema_name in schema_names:
        schema = _schema(schema_name)
        timestamp_schema = (
            schema["properties"]["occurred_at"]
            if schema_name == "key-transition.schema.json"
            else schema["$defs"]["timestamp"]
        )
        assert timestamp_schema["format"] == "date-time"
        assert re.fullmatch(timestamp_schema["pattern"], year_zero) is None


@pytest.mark.parametrize(
    ("target", "fixture_name", "schema_name", "model"),
    TIMESTAMP_TARGETS,
    ids=[case[0] for case in TIMESTAMP_TARGETS],
)
@pytest.mark.parametrize(
    "vector",
    _timestamp_vectors(),
    ids=[case["name"] for case in _timestamp_vectors()],
)
def test_shared_timestamp_matrix_matches_schema_and_python_runtime(
    target: str,
    fixture_name: str,
    schema_name: str,
    model: type[BaseModel],
    vector: dict[str, Any],
) -> None:
    field = target.split("/", 1)[1]
    accepted = bool(vector["accepted"])
    document = _timestamp_document(
        fixture_name,
        field,
        str(vector["value"]),
        accepted,
    )
    schema_accepts = _validator(schema_name).is_valid(document)
    try:
        contracts.decode_strict(_wire(document), model, 65_536)
    except ValueError:
        runtime_accepts = False
    else:
        runtime_accepts = True
    assert schema_accepts is accepted
    assert runtime_accepts is accepted


def test_python_byte_policy_matches_go_byte_array_as_list_of_integers() -> None:
    assert canonicaljson.canonical_json([1, 2]) == b"[1,2]"
    for value in (bytes([1, 2]), bytearray([1, 2]), memoryview(bytes([1, 2]))):
        with pytest.raises(ValueError, match="unsupported canonical JSON type"):
            canonicaljson.canonical_json(value)


def test_exact_identifier_helper_preconditions() -> None:
    intent_id = "int_875f0f15c0ddb3aed2ad402b38423b6b"
    for nonce in (b"", bytes(31), bytes(33)):
        with pytest.raises(ValueError, match="32 bytes"):
            canonicaljson.plan_id(intent_id, nonce)
    assert canonicaljson.plan_id(intent_id, bytes(32)).startswith("plan_")

    for digest in (
        "",
        "0" * 63,
        "0" * 65,
        "A" + "0" * 63,
        "g" + "0" * 63,
    ):
        with pytest.raises(ValueError, match="record_sha256"):
            canonicaljson.action_record_id(digest)
    assert canonicaljson.action_record_id("0" * 64) == "ar_" + "0" * 32
