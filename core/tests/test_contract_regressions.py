from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agmind_immune import canonicaljson, contracts
from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict

FIXTURES = Path("contracts/fixtures/v1")
SCHEMAS = Path("contracts/v1")
MAX_UINT64 = 2**64 - 1


class _Probe(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    x: object


def _fixture(name: str) -> dict[str, Any]:
    value = json.loads((FIXTURES / name).read_text())
    assert isinstance(value, dict)
    return value


def _schema(name: str) -> dict[str, Any]:
    value = json.loads((SCHEMAS / name).read_text())
    assert isinstance(value, dict)
    Draft202012Validator.check_schema(value)
    return value


def test_prepared_plan_is_a_standalone_valid_closed_contract() -> None:
    raw = (FIXTURES / "plan.valid.json").read_bytes()
    instance = json.loads(raw)
    Draft202012Validator(_schema("prepared-temporary-egress-deny-plan.schema.json")).validate(
        instance
    )
    plan = contracts.decode_strict(
        raw, contracts.PreparedTemporaryEgressDenyPlanV1, 65_536
    )
    assert canonicaljson.plan_id(plan.intent_id, bytes.fromhex(plan.nonce)) == plan.plan_id
    assert canonicaljson.plan_hash(plan) == plan.plan_hash


@pytest.mark.parametrize(
    "nonce",
    [
        "0" * 62,
        "0" * 66,
        "A" * 64,
        "g" * 64,
    ],
)
def test_plan_nonce_is_exactly_32_bytes_of_lowercase_hex(nonce: str) -> None:
    document = _fixture("plan.valid.json")
    document["nonce"] = nonce
    assert not Draft202012Validator(
        _schema("prepared-temporary-egress-deny-plan.schema.json")
    ).is_valid(document)
    with pytest.raises(ValueError, match="nonce"):
        contracts.PreparedTemporaryEgressDenyPlanV1.model_validate(
            document, strict=True
        )


@pytest.mark.parametrize(
    ("model_name", "fixture_name"),
    [
        ("EventEnvelopeV1", "envelope.valid.json"),
        ("FalcoConnectV1", "falco.candidate.valid.json"),
        ("FalcoConnectV1", "falco.investigation.valid.json"),
        ("CoverageEventV1", "coverage.valid.json"),
        ("TemporaryEgressDenyIntentV1", "intent.valid.json"),
        ("PreparedTemporaryEgressDenyPlanV1", "plan.valid.json"),
        ("HunterOutputV1", "hunter.valid.json"),
        ("ActionRecordV1", "action-record.valid.json"),
        ("KeyTransitionV1", "key-transition.valid.json"),
    ],
)
def test_every_runtime_contract_family_accepts_its_positive_fixture(
    model_name: str, fixture_name: str
) -> None:
    model = getattr(contracts, model_name)
    contracts.decode_strict((FIXTURES / fixture_name).read_bytes(), model, 65_536)


@pytest.mark.parametrize(
    "model_name",
    [
        "EventEnvelopeV1",
        "FalcoConnectV1",
        "CoverageEventV1",
        "TemporaryEgressDenyIntentV1",
        "PreparedTemporaryEgressDenyPlanV1",
        "HunterOutputV1",
        "ActionRecordV1",
        "KeyTransitionV1",
    ],
)
def test_every_runtime_contract_family_rejects_empty_object(model_name: str) -> None:
    model = getattr(contracts, model_name)
    with pytest.raises(ValueError):
        contracts.decode_strict(b"{}", model, 65_536)


@pytest.mark.parametrize(
    ("fixture_name", "schema_name"),
    [
        ("envelope.valid.json", "event-envelope.schema.json"),
        ("falco.candidate.valid.json", "falco-connect.schema.json"),
        ("falco.investigation.valid.json", "falco-connect.schema.json"),
        ("coverage.valid.json", "coverage-event.schema.json"),
        ("intent.valid.json", "temporary-egress-deny-intent.schema.json"),
        ("plan.valid.json", "prepared-temporary-egress-deny-plan.schema.json"),
        ("hunter.valid.json", "hunter-output.schema.json"),
        ("action-record.valid.json", "action-record.schema.json"),
        ("key-transition.valid.json", "key-transition.schema.json"),
    ],
)
def test_every_schema_accepts_its_positive_fixture(
    fixture_name: str, schema_name: str
) -> None:
    Draft202012Validator(_schema(schema_name)).validate(_fixture(fixture_name))


@pytest.mark.parametrize(
    ("schema_name", "fixture_name", "field", "invalid"),
    [
        ("event-envelope.schema.json", "envelope.valid.json", "event_id", 7),
        ("event-envelope.schema.json", "envelope.valid.json", "key_epoch", MAX_UINT64 + 1),
        ("event-envelope.schema.json", "envelope.valid.json", "event_time", "Z"),
        (
            "temporary-egress-deny-intent.schema.json",
            "intent.valid.json",
            "destination_ipv4",
            "999.999.999.999",
        ),
        (
            "temporary-egress-deny-intent.schema.json",
            "intent.valid.json",
            "inventory_generation",
            MAX_UINT64 + 1,
        ),
        (
            "key-transition.schema.json",
            "key-transition.valid.json",
            "host_id",
            "not-a-uuid",
        ),
    ],
)
def test_schemas_reject_wrong_types_overflow_and_impossible_wire_values(
    schema_name: str, fixture_name: str, field: str, invalid: object
) -> None:
    instance = _fixture(fixture_name)
    instance[field] = invalid
    assert not Draft202012Validator(_schema(schema_name)).is_valid(instance)


def test_falco_schema_and_runtime_cover_candidate_investigation_and_hard_error() -> None:
    schema = Draft202012Validator(_schema("falco-connect.schema.json"))
    model = contracts.FalcoConnectV1

    candidate = _fixture("falco.candidate.valid.json")
    missing_identity = copy.deepcopy(candidate)
    del missing_identity["docker_container_id"]
    assert not schema.is_valid(missing_identity)
    with pytest.raises(ValueError):
        model.model_validate(missing_identity, strict=True)

    hard_error = _fixture("falco.investigation.valid.json")
    hard_error["successful_connect"] = True
    assert not schema.is_valid(hard_error)
    with pytest.raises(ValueError):
        model.model_validate(hard_error, strict=True)

    injected = _fixture("falco.investigation.valid.json")
    injected["command"] = "curl 1.1.1.1"
    assert not schema.is_valid(injected)
    with pytest.raises(ValueError):
        model.model_validate(injected, strict=True)


def test_shared_json_edge_corpus_has_identical_strict_and_canonical_results() -> None:
    cases = json.loads((FIXTURES / "json-edge-vectors.json").read_text())
    for case in cases:
        raw = bytes.fromhex(case["input_hex"])
        if not case["accepted"]:
            with pytest.raises((UnicodeDecodeError, ValueError)):
                contracts.decode_strict(raw, _Probe, 65_536)
            continue
        value = contracts.decode_strict(raw, _Probe, 65_536)
        assert canonicaljson.canonical_json(value) == bytes.fromhex(case["canonical_hex"])


def test_canonical_json_rejects_integral_python_float() -> None:
    with pytest.raises(ValueError, match="floating-point"):
        canonicaljson.canonical_json({"x": 1.0})


def test_locked_derivations_match_independent_shared_vectors() -> None:
    vectors = _fixture("derivation-vectors.json")
    assert (
        canonicaljson.release_id(
            vectors["release"]["image_id"],
            vectors["release"]["immutable_spec_sha256"],
        )
        == vectors["release"]["expected"]
    )
    assert (
        canonicaljson.candidate_id(
            vectors["candidate"]["event_id"],
            vectors["candidate"]["docker_container_id"],
            vectors["candidate"]["docker_started_at"],
            vectors["candidate"]["destination_ipv4"],
            vectors["candidate"]["detector_bundle_sha256"],
        )
        == vectors["candidate"]["expected"]
    )
    assert (
        canonicaljson.intent_id(
            vectors["intent"]["candidate_id"],
            vectors["intent"]["policy_bundle_sha256"],
            vectors["intent"]["ttl_seconds"],
        )
        == vectors["intent"]["expected"]
    )
    assert (
        canonicaljson.plan_id(
            vectors["plan"]["intent_id"],
            bytes.fromhex(vectors["plan"]["nonce_hex"]),
        )
        == vectors["plan"]["expected"]
    )
    assert (
        canonicaljson.action_id(vectors["action"]["plan_hash"])
        == vectors["action"]["expected"]
    )
    for public_name, key_id_name in (
        ("event_public_key_hex", "event_key_id"),
        ("new_public_key_hex", "new_key_id"),
        ("actuator_public_key_hex", "actuator_key_id"),
    ):
        assert (
            canonicaljson.key_id(bytes.fromhex(vectors["keys"][public_name]))
            == vectors["keys"][key_id_name]
        )


def test_signatures_bind_the_declared_key_and_exact_record_content() -> None:
    vectors = _fixture("derivation-vectors.json")
    envelope = contracts.decode_strict(
        (FIXTURES / "envelope.valid.json").read_bytes(),
        contracts.EventEnvelopeV1,
        65_536,
    )
    event_public = bytes.fromhex(vectors["keys"]["event_public_key_hex"])
    canonicaljson.verify_event_signature(envelope, event_public)
    wrong_public = bytes.fromhex(vectors["keys"]["new_public_key_hex"])
    with pytest.raises(ValueError, match="key_id"):
        canonicaljson.verify_event_signature(envelope, wrong_public)

    record = contracts.decode_strict(
        (FIXTURES / "action-record.valid.json").read_bytes(),
        contracts.ActionRecordV1,
        65_536,
    )
    actuator_public = bytes.fromhex(vectors["keys"]["actuator_public_key_hex"])
    canonicaljson.verify_action_record(record, actuator_public)
    assert canonicaljson.action_record_hash(record) == record.record_sha256
    assert canonicaljson.action_record_id(record.record_sha256) == record.record_id
    with pytest.raises(ValueError, match="action_id"):
        contracts.ActionRecordV1.model_validate(
            {
                **_fixture("action-record.valid.json"),
                "action_id": "act_" + "0" * 32,
            },
            strict=True,
        )

    transition = contracts.decode_strict(
        (FIXTURES / "key-transition.valid.json").read_bytes(),
        contracts.KeyTransitionV1,
        65_536,
    )
    canonicaljson.verify_key_transition(transition, event_public)


def test_key_transition_rejects_missing_signature_nonconsecutive_epoch_and_tampering() -> None:
    document = _fixture("key-transition.valid.json")
    schema = Draft202012Validator(_schema("key-transition.schema.json"))

    missing_signature = copy.deepcopy(document)
    del missing_signature["new_signature"]
    assert not schema.is_valid(missing_signature)
    with pytest.raises(ValueError):
        contracts.KeyTransitionV1.model_validate(missing_signature, strict=True)

    nonconsecutive = copy.deepcopy(document)
    nonconsecutive["new_epoch"] = 3
    with pytest.raises(ValueError, match="consecutive"):
        contracts.KeyTransitionV1.model_validate(nonconsecutive, strict=True)

    mismatched_key = copy.deepcopy(document)
    mismatched_key["new_key_id"] = "0" * 32
    with pytest.raises(ValueError, match="new_key_id"):
        contracts.KeyTransitionV1.model_validate(mismatched_key, strict=True)

    transition = contracts.KeyTransitionV1.model_validate(document, strict=True)
    tampered = transition.model_copy(update={"old_signature": "0" * 128})
    old_public = bytes.fromhex(
        _fixture("derivation-vectors.json")["keys"]["event_public_key_hex"]
    )
    with pytest.raises(InvalidSignature):
        canonicaljson.verify_key_transition(tampered, old_public)


def test_runtime_byte_ascii_collection_and_hash_bounds() -> None:
    hunter = _fixture("hunter.valid.json")
    hunter["narrative"] = "€" * 3_000
    with pytest.raises(ValueError):
        contracts.HunterOutputV1.model_validate(hunter, strict=True)

    intent = _fixture("intent.valid.json")
    intent["policy_bundle_version"] = "é"
    with pytest.raises(ValueError):
        contracts.TemporaryEgressDenyIntentV1.model_validate(intent, strict=True)

    intent = _fixture("intent.valid.json")
    intent["evidence_ids"] *= 2
    with pytest.raises(ValueError):
        contracts.TemporaryEgressDenyIntentV1.model_validate(intent, strict=True)

    envelope = _fixture("envelope.valid.json")
    envelope["normalized_fields"] = {"oversized": "a" * (32 * 1024)}
    with pytest.raises(ValueError, match="32 KiB"):
        contracts.EventEnvelopeV1.model_validate(envelope, strict=True)


def test_make_contract_gate_uses_only_locked_images_and_both_fuzz_targets() -> None:
    makefile = Path("Makefile").read_text()
    assert "include deploy/versions.env" in makefile
    assert "$(UV_IMAGE)" in makefile
    assert "$(GO_IMAGE)" in makefile
    assert "golang:1.26.5-bookworm " not in makefile
    assert "-fuzz=FuzzDecodeStrict -fuzztime=10s" in makefile
    assert "-fuzz=FuzzCanonicalJSON -fuzztime=10s" in makefile


def test_special_use_registry_parses_every_prefix_from_multi_prefix_rows() -> None:
    registry = contracts.load_special_use_registry(Path("contracts/v1/ipv4-special-use.csv"))
    prefixes = {str(entry.network) for entry in registry}
    assert {"192.0.0.170/32", "192.0.0.171/32"} <= prefixes


def test_plan_fixture_hash_is_the_locked_domain_separated_hash() -> None:
    plan = _fixture("plan.valid.json")
    document = {key: value for key, value in plan.items() if key != "plan_hash"}
    expected = hashlib.sha256(
        b"AGMIND_PLAN_HASH_V1\0" + canonicaljson.canonical_json(document)
    ).hexdigest()
    assert plan["plan_hash"] == expected
