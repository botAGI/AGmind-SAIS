import json
from pathlib import Path

import pytest
from agmind_immune import canonicaljson, contracts
from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

FIXTURES = Path("contracts/fixtures/v1")


def test_valid_envelope_round_trips_to_locked_event_id() -> None:
    raw = (FIXTURES / "envelope.valid.json").read_bytes()
    envelope = contracts.decode_strict(raw, contracts.EventEnvelopeV1, 65_536)
    assert canonicaljson.event_id(envelope) == envelope.event_id
    assert canonicaljson.canonical_json(envelope.model_dump(exclude_none=True))


def test_duplicate_key_is_rejected_before_pydantic() -> None:
    raw = b'{"schema_version":"agmind.event-envelope.v1","schema_version":"evil"}'
    with pytest.raises(ValueError, match="duplicate JSON key"):
        contracts.decode_strict(raw, contracts.EventEnvelopeV1, 65_536)


def test_hunter_action_field_is_rejected() -> None:
    raw = (FIXTURES / "hunter.action-field.invalid.json").read_bytes()
    with pytest.raises(ValueError):
        contracts.decode_strict(raw, contracts.HunterOutputV1, 16_384)


def test_event_signature_uses_committed_golden_message() -> None:
    envelope = contracts.decode_strict(
        (FIXTURES / "envelope.valid.json").read_bytes(), contracts.EventEnvelopeV1, 65_536
    )
    public_key = bytes.fromhex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
    assert (
        canonicaljson.event_signing_message(envelope)
        == (FIXTURES / "signing-message-v1.bin").read_bytes()
    )
    canonicaljson.verify_event_signature(envelope, public_key)
    invalid = contracts.decode_strict(
        (FIXTURES / "envelope.bad-signature.json").read_bytes(), contracts.EventEnvelopeV1, 65_536
    )
    with pytest.raises(InvalidSignature):
        canonicaljson.verify_event_signature(invalid, public_key)


def test_python_rejects_non_nanosecond_timestamps_and_uint64_overflow() -> None:
    document = (FIXTURES / "envelope.valid.json").read_text()
    with pytest.raises(ValueError):
        contracts.decode_strict(
            document.replace("12:00:00Z", "12:00:00.1234567890Z").encode(),
            contracts.EventEnvelopeV1,
            65_536,
        )
    with pytest.raises(ValueError):
        contracts.decode_strict(
            document.replace(
                '"source_sequence": 7', '"source_sequence": 18446744073709551616'
            ).encode(),
            contracts.EventEnvelopeV1,
            65_536,
        )


def test_schemas_accept_positive_fixtures_and_reject_hunter_actions() -> None:
    pairs = [
        ("event-envelope.schema.json", "envelope.valid.json"),
        ("hunter-output.schema.json", "hunter.valid.json"),
        ("temporary-egress-deny-intent.schema.json", "intent.valid.json"),
    ]
    for schema_name, fixture_name in pairs:
        schema = json.loads((Path("contracts/v1") / schema_name).read_text())
        instance = json.loads((FIXTURES / fixture_name).read_text())
        Draft202012Validator(schema).validate(instance)
    hunter_schema = json.loads((Path("contracts/v1") / "hunter-output.schema.json").read_text())
    invalid = json.loads((FIXTURES / "hunter.action-field.invalid.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(hunter_schema).validate(invalid)


@pytest.mark.parametrize(
    ("address", "allowed"),
    [
        ("1.1.1.1", True),
        ("8.8.8.8", True),
        ("10.0.0.1", False),
        ("100.64.0.1", False),
        ("127.0.0.1", False),
        ("169.254.1.1", False),
        ("172.16.0.1", False),
        ("192.0.0.9", True),
        ("192.0.2.1", False),
        ("192.168.1.1", False),
        ("198.18.0.1", False),
        ("198.51.100.1", False),
        ("203.0.113.1", False),
        ("224.0.0.1", False),
        ("240.0.0.1", False),
        ("255.255.255.255", False),
    ],
)
def test_special_use_registry_uses_most_specific_prefix(address: str, allowed: bool) -> None:
    registry = contracts.load_special_use_registry(Path("contracts/v1/ipv4-special-use.csv"))
    assert contracts.is_permitted_public_ipv4(address, registry, [], []) is allowed


def test_special_use_registry_honors_operator_and_docker_denies() -> None:
    registry = contracts.load_special_use_registry(Path("contracts/v1/ipv4-special-use.csv"))
    assert not contracts.is_permitted_public_ipv4("1.1.1.1", registry, ["1.1.1.0/24"], [])
    assert not contracts.is_permitted_public_ipv4("8.8.8.8", registry, [], ["8.8.8.8"])
