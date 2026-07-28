from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from agmind_immune import contracts
from agmind_immune.observer_trust_root import load_observer_trust_root

from tests.schema_validation import contract_schema_validator


def test_observer_trust_root_fixture_binds_exact_initial_key() -> None:
    raw = Path("contracts/fixtures/v1/observer-trust-root.valid.json").read_bytes()
    document = json.loads(raw)
    schema = json.loads(Path("contracts/v1/observer-trust-root.schema.json").read_text())
    assert contract_schema_validator(schema).is_valid(document)
    root = contracts.decode_strict(raw, contracts.ObserverTrustRootV1, 4_096)
    assert root.key_id == "24f6ed6acbfe1009c030d7ca567c33ca"
    assert (
        root.public_key
        == "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
    )


def test_observer_trust_root_rejects_mismatched_key_id() -> None:
    document = {
        "schema_version": "agmind.observer-trust-root.v1",
        "host_id": "123e4567-e89b-42d3-a456-426614174000",
        "key_id": "0" * 32,
        "key_epoch": 1,
        "public_key": "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7",
    }
    raw = json.dumps(document, separators=(",", ":")).encode()
    schema = json.loads(Path("contracts/v1/observer-trust-root.schema.json").read_text())
    assert contract_schema_validator(schema).is_valid(document)
    with pytest.raises(ValueError):
        contracts.decode_strict(raw, contracts.ObserverTrustRootV1, 4_096)


def test_core_loader_requires_root_owned_regular_single_link(tmp_path: Path) -> None:
    if os.geteuid() != 0:
        pytest.skip("root ownership boundary requires the pinned test container")
    raw = Path("contracts/fixtures/v1/observer-trust-root.valid.json").read_bytes()
    valid = tmp_path / "observer-trust-root.json"
    valid.write_bytes(raw)
    valid.chmod(0o600)
    assert load_observer_trust_root(valid).key_epoch == 1

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(valid)
    with pytest.raises(ValueError):
        load_observer_trust_root(symlink)

    hardlink = tmp_path / "hardlink.json"
    os.link(valid, hardlink)
    with pytest.raises(ValueError):
        load_observer_trust_root(valid)
    hardlink.unlink()

    os.chown(valid, 65534, 65534)
    with pytest.raises(ValueError):
        load_observer_trust_root(valid)
