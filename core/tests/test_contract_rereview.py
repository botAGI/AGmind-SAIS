from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from agmind_immune import canonicaljson, contracts
from cryptography.exceptions import InvalidSignature
from pydantic import BaseModel, ConfigDict

from tests.schema_validation import contract_schema_validator

FIXTURES = Path("contracts/fixtures/v1")
SCHEMAS = Path("contracts/v1")
MIN_CANONICAL_INTEGER = -(2**63)
MAX_CANONICAL_INTEGER = 2**64 - 1


class _Probe(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    x: object


FAMILIES = [
    (
        "event",
        "envelope.valid.json",
        "event-envelope.schema.json",
        contracts.EventEnvelopeV1,
    ),
    (
        "falco-candidate",
        "falco.candidate.valid.json",
        "falco-connect.schema.json",
        contracts.FalcoConnectV1,
    ),
    (
        "falco-investigation",
        "falco.investigation.valid.json",
        "falco-connect.schema.json",
        contracts.FalcoConnectV1,
    ),
    (
        "coverage",
        "coverage.valid.json",
        "coverage-event.schema.json",
        contracts.CoverageEventV1,
    ),
    (
        "intent",
        "intent.valid.json",
        "temporary-egress-deny-intent.schema.json",
        contracts.TemporaryEgressDenyIntentV1,
    ),
    (
        "plan",
        "plan.valid.json",
        "prepared-temporary-egress-deny-plan.schema.json",
        contracts.PreparedTemporaryEgressDenyPlanV1,
    ),
    (
        "hunter",
        "hunter.valid.json",
        "hunter-output.schema.json",
        contracts.HunterOutputV1,
    ),
    (
        "action",
        "action-record.valid.json",
        "action-record.schema.json",
        contracts.ActionRecordV1,
    ),
    (
        "key-transition",
        "key-transition.valid.json",
        "key-transition.schema.json",
        contracts.KeyTransitionV1,
    ),
]


def _fixture(name: str) -> dict[str, Any]:
    value = json.loads((FIXTURES / name).read_text())
    assert isinstance(value, dict)
    return value


def _schema(name: str) -> dict[str, Any]:
    value = json.loads((SCHEMAS / name).read_text())
    assert isinstance(value, dict)
    return value


def _wire(document: dict[str, Any]) -> bytes:
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode()


def _rebind_event(document: dict[str, Any]) -> dict[str, Any]:
    rebound = copy.deepcopy(document)
    rebound["normalized_fields_sha256"] = hashlib.sha256(
        canonicaljson.canonical_json(rebound["normalized_fields"])
    ).hexdigest()
    rebound["event_id"] = canonicaljson.event_id(SimpleNamespace(**rebound))
    return rebound


@pytest.mark.parametrize(
    ("family", "fixture_name", "schema_name", "model"),
    FAMILIES,
    ids=[case[0] for case in FAMILIES],
)
def test_every_required_property_is_checked_before_runtime_unmarshal(
    family: str,
    fixture_name: str,
    schema_name: str,
    model: type[BaseModel],
) -> None:
    del family
    document = _fixture(fixture_name)
    schema = _schema(schema_name)
    required = schema["required"]
    assert isinstance(required, list)
    for field in required:
        mutated = copy.deepcopy(document)
        del mutated[field]
        assert not contract_schema_validator(schema).is_valid(mutated), field
        with pytest.raises(ValueError, match=field):
            contracts.decode_strict(_wire(mutated), model, 65_536)


@pytest.mark.parametrize(
    ("family", "fixture_name", "schema_name", "model"),
    FAMILIES,
    ids=[case[0] for case in FAMILIES],
)
def test_omitted_optional_fields_are_allowed_but_explicit_top_level_null_is_rejected(
    family: str,
    fixture_name: str,
    schema_name: str,
    model: type[BaseModel],
) -> None:
    document = _fixture(fixture_name)
    schema = _schema(schema_name)
    required = set(schema["required"])
    optional = sorted(set(schema["properties"]) - required)
    if family == "falco-candidate":
        # These wire-optional fields are conditionally required for a
        # candidate-capable event. The investigation fixture below exercises
        # omission versus null for every Falco optional field.
        return
    for field in optional:
        omitted = copy.deepcopy(document)
        omitted.pop(field, None)
        if family == "action":
            omitted = _rebind_action(omitted)
        if field in contracts.FALCO_SENSOR_REQUIRED_FIELDS:
            # Dropping a sensor fact is permitted ONLY when the omission is declared: the model
            # requires missing_required_fields to equal the set of absent sensor facts, so a
            # blind spot can never be silently indistinguishable from an observation. Declaring
            # it here keeps the document coherent, which is what makes this test about
            # OPTIONALITY rather than about the sensor-omission rule. The undeclared case is a
            # separate invariant with its own coverage below.
            omitted["missing_required_fields"] = sorted(
                {*omitted.get("missing_required_fields", []), field}
            )
        contracts.decode_strict(_wire(omitted), model, 65_536)

        explicit_null = copy.deepcopy(document)
        explicit_null[field] = None
        assert not contract_schema_validator(schema).is_valid(explicit_null), field
        with pytest.raises(ValueError, match="null"):
            contracts.decode_strict(_wire(explicit_null), model, 65_536)


def test_undeclared_sensor_omission_is_rejected() -> None:
    """A sensor blind spot must be declared, never silently indistinguishable from a fact.

    The optionality test above keeps its documents coherent on purpose, so this is where the
    security-relevant half of the invariant lives: dropping a sensor fact WITHOUT listing it in
    missing_required_fields has to fail. Without this, an event that observed nothing would be
    accepted as an event that observed everything.
    """
    document = _fixture("falco.investigation.valid.json")
    checked = 0
    for field in sorted(contracts.FALCO_SENSOR_REQUIRED_FIELDS):
        if field not in document:
            continue
        undeclared = copy.deepcopy(document)
        undeclared.pop(field)
        undeclared["missing_required_fields"] = []
        with pytest.raises(ValueError, match="missing_required_fields"):
            contracts.decode_strict(_wire(undeclared), contracts.FalcoConnectV1, 65_536)
        checked += 1
    assert checked > 0, (
        "the fixture carries no sensor facts, so this test proved nothing — "
        "fix the fixture, do not delete the assertion"
    )


def test_shared_contradictory_falco_result_is_rejected_everywhere() -> None:
    raw = (FIXTURES / "falco.contradictory.invalid.json").read_bytes()
    document = json.loads(raw)
    schema = contract_schema_validator(_schema("falco-connect.schema.json"))
    assert not schema.is_valid(document)
    with pytest.raises(ValueError, match="Falco result"):
        contracts.decode_strict(raw, contracts.FalcoConnectV1, 65_536)


@pytest.mark.parametrize(
    ("rawres", "result", "successful", "accepted"),
    [
        (0, "SUCCESS", True, True),
        (1, "SUCCESS", True, True),
        (-1, "SUCCESS", False, False),
        (None, "SUCCESS", False, False),
        (-115, "EINPROGRESS", True, True),
        (None, "EINPROGRESS(115)", True, True),
        (0, "EINPROGRESS", True, False),
        (-111, "ECONNREFUSED", False, True),
        (None, "ECONNREFUSED", False, True),
        (0, "ECONNREFUSED", False, False),
        (-111, "ECONNREFUSED", True, False),
    ],
)
def test_falco_result_tuple_matrix_is_exact(
    rawres: int | None,
    result: str,
    successful: bool,
    accepted: bool,
) -> None:
    document = _fixture("falco.investigation.valid.json")
    document["evt_res"] = result
    document["successful_connect"] = successful
    document["investigation_only"] = True
    if rawres is None:
        document.pop("evt_rawres", None)
    else:
        document["evt_rawres"] = rawres
    schema_accepts = contract_schema_validator(
        _schema("falco-connect.schema.json")
    ).is_valid(document)
    assert schema_accepts is accepted
    if accepted:
        contracts.decode_strict(_wire(document), contracts.FalcoConnectV1, 65_536)
    else:
        with pytest.raises(ValueError):
            contracts.decode_strict(
                _wire(document), contracts.FalcoConnectV1, 65_536
            )


@pytest.mark.parametrize(
    ("token", "accepted"),
    [
        (str(MIN_CANONICAL_INTEGER), True),
        (str(MAX_CANONICAL_INTEGER), True),
        (str(MIN_CANONICAL_INTEGER - 1), False),
        (str(MAX_CANONICAL_INTEGER + 1), False),
        ("-0", False),
    ],
)
def test_strict_decoder_enforces_canonical_integer_domain(
    token: str, accepted: bool
) -> None:
    raw = b'{"x":' + token.encode() + b"}"
    if accepted:
        contracts.decode_strict(raw, _Probe, 65_536)
    else:
        with pytest.raises(ValueError):
            contracts.decode_strict(raw, _Probe, 65_536)


@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        (MIN_CANONICAL_INTEGER, True),
        (MAX_CANONICAL_INTEGER, True),
        (MIN_CANONICAL_INTEGER - 1, False),
        (MAX_CANONICAL_INTEGER + 1, False),
    ],
)
def test_canonical_writer_enforces_integer_domain(value: int, accepted: bool) -> None:
    if accepted:
        assert canonicaljson.canonical_json({"x": value})
    else:
        with pytest.raises(ValueError, match="integer"):
            canonicaljson.canonical_json({"x": value})


def _nested_arrays(container_depth: int) -> object:
    value: object = None
    for _ in range(container_depth):
        value = [value]
    return value


def test_nesting_depth_64_is_accepted_and_65_is_cleanly_rejected() -> None:
    at_limit = {"x": _nested_arrays(63)}
    over_limit = {"x": _nested_arrays(64)}
    contracts.decode_strict(_wire(at_limit), _Probe, 65_536)
    assert canonicaljson.canonical_json(at_limit)
    with pytest.raises(ValueError, match="nesting depth"):
        contracts.decode_strict(_wire(over_limit), _Probe, 65_536)
    with pytest.raises(ValueError, match="nesting depth"):
        canonicaljson.canonical_json(over_limit)

    much_too_deep = b'{"x":' + (b"[" * 1_500) + b"null" + (b"]" * 1_500) + b"}"
    with pytest.raises(ValueError, match="nesting depth"):
        contracts.decode_strict(much_too_deep, _Probe, 65_536)


def test_event_normalized_fields_recursive_bounds_and_total_size() -> None:
    base = _fixture("envelope.valid.json")
    valid_values = [
        {"x": "a" * 8_192},
        {"x": [None] * 128},
        {f"k{i}": None for i in range(128)},
        {"k" * 512: None},
        {"x": MIN_CANONICAL_INTEGER},
        {"x": MAX_CANONICAL_INTEGER},
        {"x": ["a" * 8_192, "a" * 8_192, "a" * 8_192, "a" * 8_173]},
        {"x": None},
    ]
    invalid_values = [
        {"x": "a" * 8_193},
        {"x": [None] * 129},
        {f"k{i}": None for i in range(129)},
        {"k" * 513: None},
        {"x": MIN_CANONICAL_INTEGER - 1},
        {"x": MAX_CANONICAL_INTEGER + 1},
        {"x": ["a" * 8_192, "a" * 8_192, "a" * 8_192, "a" * 8_174]},
    ]
    schema = contract_schema_validator(_schema("event-envelope.schema.json"))
    for value in valid_values:
        document = _rebind_event({**base, "normalized_fields": value})
        assert schema.is_valid(document)
        contracts.decode_strict(_wire(document), contracts.EventEnvelopeV1, 65_536)
    for index, value in enumerate(invalid_values):
        if index in (4, 5):
            document = {**base, "normalized_fields": value}
        else:
            document = _rebind_event({**base, "normalized_fields": value})
        assert not schema.is_valid(document) or len(
            canonicaljson.canonical_json(value)
        ) > 32 * 1024
        with pytest.raises(ValueError):
            contracts.decode_strict(
                _wire(document), contracts.EventEnvelopeV1, 65_536
            )


def _rebind_action(document: dict[str, Any]) -> dict[str, Any]:
    rebound = copy.deepcopy(document)
    provisional = contracts.ActionRecordV1.model_construct(**rebound)
    rebound["record_sha256"] = canonicaljson.action_record_hash(provisional)
    rebound["record_id"] = canonicaljson.action_record_id(rebound["record_sha256"])
    return rebound


def test_action_details_recursive_bounds_and_total_size() -> None:
    base = _fixture("action-record.valid.json")
    valid_values = [
        {"x": "a" * 1_024},
        {"x": [None] * 64},
        {f"k{i}": None for i in range(64)},
        {"k" * 64: None},
        {"x": MIN_CANONICAL_INTEGER},
        {"x": MAX_CANONICAL_INTEGER},
        {"x": ["a" * 1_024] * 31 + ["a" * 921]},
        {"x": None},
    ]
    invalid_values = [
        {"x": "a" * 1_025},
        {"x": [None] * 65},
        {f"k{i}": None for i in range(65)},
        {"k" * 65: None},
        {"x": MIN_CANONICAL_INTEGER - 1},
        {"x": MAX_CANONICAL_INTEGER + 1},
        {"x": ["a" * 1_024] * 31 + ["a" * 922]},
    ]
    schema = contract_schema_validator(_schema("action-record.schema.json"))
    for value in valid_values:
        document = _rebind_action({**base, "details": value})
        assert schema.is_valid(document)
        contracts.decode_strict(_wire(document), contracts.ActionRecordV1, 65_536)
    for index, value in enumerate(invalid_values):
        if index in (4, 5):
            document = {**base, "details": value}
        else:
            document = _rebind_action({**base, "details": value})
        assert not schema.is_valid(document) or len(
            canonicaljson.canonical_json(value)
        ) > 32 * 1024
        with pytest.raises(ValueError):
            contracts.decode_strict(_wire(document), contracts.ActionRecordV1, 65_536)


def test_ascii_contract_fields_require_printable_ascii() -> None:
    for fixture_name, schema_name, model, field in [
        (
            "envelope.valid.json",
            "event-envelope.schema.json",
            contracts.EventEnvelopeV1,
            "event_type",
        ),
        (
            "falco.candidate.valid.json",
            "falco-connect.schema.json",
            contracts.FalcoConnectV1,
            "evt_res",
        ),
        (
            "coverage.valid.json",
            "coverage-event.schema.json",
            contracts.CoverageEventV1,
            "component",
        ),
        (
            "intent.valid.json",
            "temporary-egress-deny-intent.schema.json",
            contracts.TemporaryEgressDenyIntentV1,
            "policy_bundle_version",
        ),
        (
            "action-record.valid.json",
            "action-record.schema.json",
            contracts.ActionRecordV1,
            "reason_code",
        ),
    ]:
        document = _fixture(fixture_name)
        document[field] = "bad\nvalue"
        assert not contract_schema_validator(_schema(schema_name)).is_valid(document)
        with pytest.raises(ValueError):
            contracts.decode_strict(_wire(document), model, 65_536)


def test_event_content_digest_and_id_are_recomputed() -> None:
    document = _fixture("envelope.valid.json")
    document["normalized_fields"]["destination_ipv4"] = "1.1.1.2"
    with pytest.raises(ValueError, match="normalized_fields_sha256"):
        contracts.decode_strict(_wire(document), contracts.EventEnvelopeV1, 65_536)

    digest_mutation = _fixture("envelope.valid.json")
    digest_mutation["normalized_fields_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="normalized_fields_sha256"):
        contracts.decode_strict(
            _wire(digest_mutation), contracts.EventEnvelopeV1, 65_536
        )

    id_mutation = _fixture("envelope.valid.json")
    id_mutation["event_id"] = "evt_" + "0" * 64
    with pytest.raises(ValueError, match="event_id"):
        contracts.decode_strict(_wire(id_mutation), contracts.EventEnvelopeV1, 65_536)


def test_bad_signature_fixture_remains_content_valid_but_cryptographically_invalid() -> None:
    event = contracts.decode_strict(
        (FIXTURES / "envelope.bad-signature.json").read_bytes(),
        contracts.EventEnvelopeV1,
        65_536,
    )
    public = bytes.fromhex(
        _fixture("derivation-vectors.json")["keys"]["event_public_key_hex"]
    )
    with pytest.raises(InvalidSignature):
        canonicaljson.verify_event_signature(event, public)


def test_structured_near_valid_wrong_type_bound_and_semantic_mutations() -> None:
    mutation_cases = [
        (
            "event",
            "envelope.valid.json",
            "event-envelope.schema.json",
            contracts.EventEnvelopeV1,
            {"source_sequence": "7"},
            {"normalized_fields": {"x": "a" * 8_193}},
            {"normalized_fields": {"destination_ipv4": "1.1.1.2", "evt_type": "connect"}},
        ),
        (
            "falco-candidate",
            "falco.candidate.valid.json",
            "falco-connect.schema.json",
            contracts.FalcoConnectV1,
            {"destination_port": "443"},
            {"destination_port": 65_536},
            {"evt_res": "ECONNREFUSED"},
        ),
        (
            "falco-investigation",
            "falco.investigation.valid.json",
            "falco-connect.schema.json",
            contracts.FalcoConnectV1,
            {"destination_port": "443"},
            {"missing_required_fields": [f"field_{i:02}" for i in range(33)]},
            {"evt_rawres": 0},
        ),
        (
            "coverage",
            "coverage.valid.json",
            "coverage-event.schema.json",
            contracts.CoverageEventV1,
            {"dropped_count": "2"},
            {"component": "a" * 65},
            {"closed_at": "2026-07-27T11:59:59Z"},
        ),
        (
            "intent",
            "intent.valid.json",
            "temporary-egress-deny-intent.schema.json",
            contracts.TemporaryEgressDenyIntentV1,
            {"ttl_seconds": "120"},
            {"ttl_seconds": 301},
            {"repo_digests": ["z", "a"]},
        ),
        (
            "plan",
            "plan.valid.json",
            "prepared-temporary-egress-deny-plan.schema.json",
            contracts.PreparedTemporaryEgressDenyPlanV1,
            {"init_pid": "123"},
            {"ttl_seconds": 301},
            {"approval_expires_at": "2026-07-27T12:05:03Z"},
        ),
        (
            "hunter",
            "hunter.valid.json",
            "hunter-output.schema.json",
            contracts.HunterOutputV1,
            {"narrative": 7},
            {"hypotheses": ["x"] * 9},
            {
                "supporting_evidence_ids": [
                    "evt_" + "f" * 64,
                    "evt_" + "0" * 64,
                ]
            },
        ),
        (
            "action",
            "action-record.valid.json",
            "action-record.schema.json",
            contracts.ActionRecordV1,
            {"details": []},
            {"details": {f"k{i}": None for i in range(65)}},
            {"record_sha256": "0" * 64},
        ),
        (
            "key-transition",
            "key-transition.valid.json",
            "key-transition.schema.json",
            contracts.KeyTransitionV1,
            {"old_epoch": "1"},
            {"old_epoch": MAX_CANONICAL_INTEGER + 1},
            {"new_epoch": 3},
        ),
    ]
    for name, fixture, schema_name, model, wrong_type, over_bound, semantic in mutation_cases:
        base = _fixture(fixture)
        schema = contract_schema_validator(_schema(schema_name))
        for category, patch in [
            ("wrong-type", wrong_type),
            ("one-over", over_bound),
            ("semantic", semantic),
        ]:
            mutated = {**base, **patch}
            if name == "event" and category == "one-over":
                mutated = _rebind_event(mutated)
            if category != "semantic":
                assert not schema.is_valid(mutated), (name, category)
            else:
                assert schema.is_valid(mutated) is (not name.startswith("falco"))
            with pytest.raises(ValueError):
                contracts.decode_strict(_wire(mutated), model, 65_536)
