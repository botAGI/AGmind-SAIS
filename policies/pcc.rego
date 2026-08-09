package agmind.pcc

import rego.v1

default decision := {}

expected_input_keys := {
    "boot_id",
    "candidate_facts_sha256",
    "candidate_id",
    "coverage_ready",
    "coverage_snapshot_sha256",
    "destination_ipv4",
    "destination_port",
    "detector_bundle_sha256",
    "detector_rule",
    "detector_rule_version",
    "docker_container_id",
    "docker_network_snapshot_sha256",
    "docker_started_at",
    "evidence_age_ms",
    "evidence_ids",
    "host_id",
    "image_id",
    "immutable_spec_sha256",
    "inventory_generation",
    "inventory_revision",
    "l4_protocol",
    "management_denylist_sha256",
    "operator_denylist_sha256",
    "policy_bundle_sha256",
    "policy_bundle_version",
    "policy_input_sha256",
    "repo_digests",
    "requested_ttl_seconds",
    "schema_version",
    "special_use_registry_sha256",
}

is_sha256(value) if {
    is_string(value)
    regex.match("^[0-9a-f]{64}$", value)
}

is_uuid4(value) if {
    is_string(value)
    regex.match("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", value)
}

is_event_id(value) if {
    is_string(value)
    regex.match("^evt_[0-9a-f]{64}$", value)
}

is_repo_digest(value) if {
    is_string(value)
    count(value) <= 256
    regex.match("^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$", value)
}

input_without_hash := object.remove(input, {"policy_input_sha256"})

expected_input_hash := crypto.sha256(concat("", [
    "AGMIND_POLICY_INPUT_V1\u0000",
    json.marshal(input_without_hash),
]))

valid_input if {
    is_object(input)
    object.keys(input) == expected_input_keys
    input.schema_version == "agmind.policy-input.v1"
    is_string(input.candidate_id)
    regex.match("^cand_[0-9a-f]{64}$", input.candidate_id)
    is_sha256(input.candidate_facts_sha256)
    is_uuid4(input.host_id)
    is_uuid4(input.boot_id)
    is_string(input.docker_container_id)
    regex.match("^[0-9a-f]{64}$", input.docker_container_id)
    is_string(input.docker_started_at)
    regex.match("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?Z$", input.docker_started_at)
    is_string(input.image_id)
    regex.match("^sha256:[0-9a-f]{64}$", input.image_id)
    is_array(input.repo_digests)
    count(input.repo_digests) <= 16
    input.repo_digests == sort(input.repo_digests)
    count(input.repo_digests) == count({digest | some digest in input.repo_digests})
    every digest in input.repo_digests {
        is_repo_digest(digest)
    }
    is_sha256(input.immutable_spec_sha256)
    is_number(input.inventory_generation)
    input.inventory_generation >= 1
    is_number(input.inventory_revision)
    input.inventory_revision >= 1
    is_string(input.destination_ipv4)
    is_number(input.destination_port)
    input.destination_port >= 1
    input.destination_port <= 65535
    input.l4_protocol == "tcp"
    is_number(input.requested_ttl_seconds)
    input.requested_ttl_seconds >= 30
    input.requested_ttl_seconds <= 300
    input.detector_rule == "AGmind PCC Suspicious Process Outbound Connect"
    input.detector_rule_version == "agmind-pcc-rules-v1"
    is_sha256(input.detector_bundle_sha256)
    input.coverage_ready == true
    is_sha256(input.coverage_snapshot_sha256)
    is_sha256(input.docker_network_snapshot_sha256)
    is_sha256(input.special_use_registry_sha256)
    is_sha256(input.operator_denylist_sha256)
    is_sha256(input.management_denylist_sha256)
    is_array(input.evidence_ids)
    count(input.evidence_ids) == 2
    input.evidence_ids == sort(input.evidence_ids)
    input.evidence_ids[0] != input.evidence_ids[1]
    is_event_id(input.evidence_ids[0])
    is_event_id(input.evidence_ids[1])
    is_number(input.evidence_age_ms)
    input.evidence_age_ms >= 0
    input.evidence_age_ms <= 120000
    input.policy_bundle_version == "pcc-policy-v1"
    is_sha256(input.policy_bundle_sha256)
    is_sha256(input.policy_input_sha256)
    input.policy_input_sha256 == expected_input_hash
}

manual_ttl := input.requested_ttl_seconds if {
    input.requested_ttl_seconds <= 120
}

manual_ttl := 120 if {
    input.requested_ttl_seconds > 120
}

manual_decision := {
    "allowed_evidence_ids": input.evidence_ids,
    "candidate_facts_sha256": input.candidate_facts_sha256,
    "candidate_id": input.candidate_id,
    "effect": "manual_approval_required",
    "max_ttl_seconds": manual_ttl,
    "policy_bundle_sha256": input.policy_bundle_sha256,
    "policy_bundle_version": "pcc-policy-v1",
    "policy_input_sha256": input.policy_input_sha256,
    "reason_codes": ["manual_approval_required"],
    "schema_version": "agmind.policy-decision.v1",
}

deny_decision := {
    "allowed_evidence_ids": [],
    "candidate_facts_sha256": object.get(input, "candidate_facts_sha256", "0000000000000000000000000000000000000000000000000000000000000000"),
    "candidate_id": object.get(input, "candidate_id", "cand_0000000000000000000000000000000000000000000000000000000000000000"),
    "effect": "deny",
    "max_ttl_seconds": 0,
    "policy_bundle_sha256": object.get(input, "policy_bundle_sha256", "0000000000000000000000000000000000000000000000000000000000000000"),
    "policy_bundle_version": "pcc-policy-v1",
    "policy_input_sha256": object.get(input, "policy_input_sha256", "0000000000000000000000000000000000000000000000000000000000000000"),
    "reason_codes": ["policy_default_deny"],
    "schema_version": "agmind.policy-decision.v1",
}

decision := manual_decision if {
    valid_input
}

decision := deny_decision if {
    not valid_input
}
