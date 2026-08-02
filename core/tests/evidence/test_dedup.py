from __future__ import annotations

import importlib
from typing import Any

import pytest
from agmind_immune.contracts import EventEnvelopeV1
from tests.phase5b_helpers import BOOT_A, BOOT_B, envelope_value, private_key


def _subject() -> Any:
    try:
        return importlib.import_module("agmind_immune.evidence.dedup")
    except ModuleNotFoundError:
        pytest.fail("Task 2B logical-primary identity is not implemented")


def _envelope(*, boot_id: str, sequence: int) -> EventEnvelopeV1:
    key = private_key(11)
    return EventEnvelopeV1.model_validate(
        envelope_value(
            key,
            sequence=sequence,
            boot_id=boot_id,
            event_type="falco_connect",
            normalized_fields={"raw_event_sha256": "a" * 64},
            source_payload_hash="a" * 64,
        ),
        strict=True,
    )


def test_v1_remains_boot_blind_while_v2_binds_boot_id() -> None:
    subject = _subject()
    first = _envelope(boot_id=BOOT_A, sequence=1)
    prior_boot_replay = _envelope(boot_id=BOOT_B, sequence=2)

    assert subject._logical_primary_identity_v1(first) == (
        "falco_connect",
        "2bdf715d183f292c6d916257f2ee5de8936511ca34408aaeaa32863745f0428f",
    )
    assert subject._logical_primary_identity_v1(prior_boot_replay) == (
        "falco_connect",
        "2bdf715d183f292c6d916257f2ee5de8936511ca34408aaeaa32863745f0428f",
    )
    assert subject._logical_primary_identity_v2(first) == (
        "falco_connect",
        "2a50db5780b743e6f52a6f3d051cd414433e90334967f3c0a7c0b8a758874d75",
    )
    assert subject._logical_primary_identity_v2(prior_boot_replay) == (
        "falco_connect",
        "27db25d36b75de4e65b11a4befedea9db4f306da0a044e4e70330e8faf85530f",
    )


def test_other_events_are_identified_only_by_event_id_in_both_versions() -> None:
    subject = _subject()
    key = private_key(11)
    envelope = EventEnvelopeV1.model_validate(
        envelope_value(key, sequence=1, normalized_fields={"kind": "ordinary"}),
        strict=True,
    )

    v1 = subject._logical_primary_identity_v1(envelope)
    v2 = subject._logical_primary_identity_v2(envelope)

    assert v1[0] == v2[0] == "other"
    assert v1[1] != v2[1]
