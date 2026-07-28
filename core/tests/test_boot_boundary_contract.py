from __future__ import annotations

import json
from pathlib import Path

import pytest
from agmind_immune import contracts

from tests.schema_validation import contract_schema_validator


@pytest.mark.parametrize(
    ("document", "accepted"),
    [
        (
            {
                "schema_version": "agmind.observer-boot-boundary.v1",
                "kind": "observer_boot_boundary",
                "reason_code": "observer_genesis",
                "previous_source_sequence": 0,
            },
            True,
        ),
        (
            {
                "schema_version": "agmind.observer-boot-boundary.v1",
                "kind": "observer_boot_boundary",
                "reason_code": "kernel_boot_id_changed",
                "previous_boot_id": "123e4567-e89b-42d3-b456-426614174001",
                "previous_source_sequence": 7,
            },
            True,
        ),
        (
            {
                "schema_version": "agmind.observer-boot-boundary.v1",
                "kind": "observer_boot_boundary",
                "reason_code": "observer_genesis",
                "previous_boot_id": "123e4567-e89b-42d3-b456-426614174001",
                "previous_source_sequence": 0,
            },
            False,
        ),
        (
            {
                "schema_version": "agmind.observer-boot-boundary.v1",
                "kind": "observer_boot_boundary",
                "reason_code": "kernel_boot_id_changed",
                "previous_source_sequence": 7,
            },
            False,
        ),
    ],
)
def test_observer_boot_boundary_contract_matrix(
    document: dict[str, object],
    accepted: bool,
) -> None:
    schema = json.loads(Path("contracts/v1/observer-boot-boundary.schema.json").read_text())
    schema_accepts = contract_schema_validator(schema).is_valid(document)
    try:
        contracts.decode_strict(
            json.dumps(document, separators=(",", ":")).encode(),
            contracts.ObserverBootBoundaryV1,
            65_536,
        )
    except ValueError:
        runtime_accepts = False
    else:
        runtime_accepts = True
    assert schema_accepts is accepted
    assert runtime_accepts is accepted
