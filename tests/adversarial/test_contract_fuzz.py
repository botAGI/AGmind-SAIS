from agmind_immune import contracts
from hypothesis import given, settings
from hypothesis import strategies as st


@settings(max_examples=100, deadline=200)
@given(st.binary(max_size=70_000))
def test_arbitrary_bytes_are_validated_or_cleanly_rejected(raw: bytes) -> None:
    try:
        contracts.decode_strict(raw, contracts.EventEnvelopeV1, 65_536)
    except (UnicodeDecodeError, ValueError):
        pass
