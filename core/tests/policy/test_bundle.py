from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path

import pytest
from agmind_immune.canonicaljson import canonical_json


def test_policy_bundle_digest_and_runtime_bytes_are_exact() -> None:
    policy = importlib.import_module("agmind_immune.policy")
    client = importlib.import_module("agmind_immune.policy.client")
    root = Path(__file__).resolve().parents[3]
    policy_path = root / "policies/pcc.rego"
    tests_path = root / "policies/pcc_test.rego"
    vector_path = root / "policies/policy_input_hash_vector.json"
    raw = policy_path.read_bytes()

    assert hashlib.sha256(raw).hexdigest() == client.POLICY_BUNDLE_SHA256
    assert policy.PolicyBundleIdentity(
        version="pcc-policy-v1",
        sha256=client.POLICY_BUNDLE_SHA256,
    ) == client.POLICY_BUNDLE
    assert b"package agmind.pcc" in raw
    assert b"default decision" in raw
    assert b'manual_approval_required' in raw
    assert b'"allow"' not in raw
    assert b"automatic_approval" not in raw
    assert tests_path.is_file()
    vector = json.loads(vector_path.read_bytes())
    assert type(vector) is dict
    assert vector["expected_sha256"] == hashlib.sha256(
        b"AGMIND_POLICY_INPUT_V1\0"
        + canonical_json(vector["input_without_hash"])
    ).hexdigest()
    hostile_input = dict(vector["input_without_hash"])
    hostile_input["repo_digests"] = [vector["hostile_repo_digest"]]
    hostile_input["policy_input_sha256"] = hashlib.sha256(
        b"AGMIND_POLICY_INPUT_V1\0" + canonical_json(hostile_input)
    ).hexdigest()
    models = importlib.import_module("agmind_immune.policy.models")
    with pytest.raises(ValueError):
        models.PolicyInputV1.model_validate(hostile_input, strict=True)

    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    copy_marker = (
        "COPY --chown=0:0 --chmod=0444 policies/pcc.rego "
        "/usr/share/agmind-sais/pcc.rego"
    )
    assert copy_marker in dockerfile
    assert dockerfile.index(copy_marker) < dockerfile.index("USER sais")
