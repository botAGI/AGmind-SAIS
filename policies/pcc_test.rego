package agmind.pcc_test

import data.agmind.pcc
import rego.v1

valid_base := data.input_without_hash

bind_hash(document) := object.union(document, {
    "policy_input_sha256": crypto.sha256(concat("", [
        "AGMIND_POLICY_INPUT_V1\u0000",
        json.marshal(document),
    ])),
})

valid_input := bind_hash(valid_base)

test_manual_only_and_ttl_narrowing if {
    result := pcc.decision with input as valid_input
    result.effect == "manual_approval_required"
    result.reason_codes == ["manual_approval_required"]
    result.max_ttl_seconds == 120
    result.allowed_evidence_ids == valid_input.evidence_ids
    result.candidate_id == valid_input.candidate_id
    result.candidate_facts_sha256 == valid_input.candidate_facts_sha256
    result.policy_input_sha256 == valid_input.policy_input_sha256
}

test_stale_input_denies if {
    stale := bind_hash(object.union(valid_base, {"evidence_age_ms": 120001}))
    result := pcc.decision with input as stale
    result.effect == "deny"
    result.reason_codes == ["policy_default_deny"]
    result.max_ttl_seconds == 0
    result.allowed_evidence_ids == []
}

test_malformed_hash_denies if {
    malformed := object.union(valid_input, {"policy_input_sha256": "0000000000000000000000000000000000000000000000000000000000000000"})
    result := pcc.decision with input as malformed
    result.effect == "deny"
}

test_unknown_authority_field_denies if {
    injected := bind_hash(object.union(valid_base, {"command": "nft add rule"}))
    result := pcc.decision with input as injected
    result.effect == "deny"
}

test_hostile_repo_digest_denies if {
    hostile := bind_hash(object.union(valid_base, {"repo_digests": [data.hostile_repo_digest]}))
    result := pcc.decision with input as hostile
    result.effect == "deny"
}

test_policy_input_hash_vector if {
    valid_input.policy_input_sha256 == data.expected_sha256
}
