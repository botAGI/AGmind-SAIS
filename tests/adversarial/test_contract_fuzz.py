import hashlib
import json
from pathlib import Path

import pytest
from agmind_immune import contracts
from agmind_immune.canonicaljson import canonical_json, event_id
from hypothesis import example, given, settings
from hypothesis import strategies as st
from tests.schema_validation import contract_schema_validator

FIXTURES = Path("contracts/fixtures/v1")
EVENT_SCHEMA = json.loads(Path("contracts/v1/event-envelope.schema.json").read_text())


@settings(max_examples=100, deadline=200)
@given(st.binary(max_size=70_000))
@example((FIXTURES / "envelope.valid.json").read_bytes())
def test_arbitrary_bytes_are_validated_or_cleanly_rejected(raw: bytes) -> None:
    try:
        event = contracts.decode_strict(raw, contracts.EventEnvelopeV1, 65_536)
    except (UnicodeDecodeError, ValueError):
        return
    document = event.model_dump(exclude_none=True)
    contract_schema_validator(EVENT_SCHEMA).validate(document)
    assert event_id(event) == event.event_id
    assert hashlib.sha256(canonical_json(event.normalized_fields)).hexdigest() == (
        event.normalized_fields_sha256
    )


integer_json = st.integers(min_value=-(2**63), max_value=2**64 - 1)
json_scalars = st.none() | st.booleans() | integer_json | st.text(
    alphabet=st.characters(exclude_categories=("Cs",))
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.lists(children, max_size=8)
    | st.dictionaries(
        st.text(alphabet=st.characters(exclude_categories=("Cs",)), max_size=32),
        children,
        max_size=8,
    ),
    max_leaves=32,
)


@settings(max_examples=150, deadline=200)
@given(json_values)
@example({"control": "\x01", "line_separators": "\u2028\u2029"})
@example({"\ue000": 1, "\U0001f600": [True, None, -7]})
def test_canonical_json_is_idempotent_for_non_float_json(value: object) -> None:
    encoded = canonical_json(value)
    decoded = json.loads(encoded)
    assert canonical_json(decoded) == encoded


@pytest.mark.parametrize("value", [1.0, -2.0, float("inf"), float("nan")])
def test_canonical_json_rejects_all_floats(value: float) -> None:
    with pytest.raises(ValueError):
        canonical_json({"value": value})
