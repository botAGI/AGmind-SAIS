from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agmind_immune import contracts
from agmind_immune.canonicaljson import (
    canonical_json,
    event_signing_message,
    verify_event_signature,
)
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.ingest import envelope as ingest_envelope
from agmind_immune.ingest.service import AcceptanceCoordinator
from jsonschema import Draft202012Validator
from tests.phase5b_helpers import (
    boot_boundary,
    envelope_value,
    metadata_value,
    page_value,
    private_key,
    public_bytes,
    root_value,
)
from tests.schema_validation import contract_schema_validator

FIXTURES_V1 = Path("contracts/fixtures/v1")
FIXTURES_V2 = Path("contracts/fixtures/v2")
SCHEMAS_V1 = Path("contracts/v1")
SCHEMAS_V2 = Path("contracts/v2")
MAX_UINT64 = 2**64 - 1
MAX_SEGMENT_BYTES = 64 * 1024 * 1024
ZERO_SHA256 = "0" * 64
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

CONTRACT_CASES = (
    (
        "EvidenceRepairAuthorizeV1",
        FIXTURES_V1 / "evidence-repair-authorize.valid.json",
        SCHEMAS_V1 / "evidence-repair-authorize.schema.json",
    ),
    (
        "EvidenceRepairCompleteV1",
        FIXTURES_V1 / "evidence-repair-complete.valid.json",
        SCHEMAS_V1 / "evidence-repair-complete.schema.json",
    ),
    (
        "RetentionTombstoneV2",
        FIXTURES_V2 / "retention-tombstone.valid.json",
        SCHEMAS_V2 / "retention-tombstone.schema.json",
    ),
    (
        "RetentionBlockedV1",
        FIXTURES_V1 / "retention-blocked.valid.json",
        SCHEMAS_V1 / "retention-blocked.schema.json",
    ),
)

EVENT_CASES = (
    (
        "evidence_repair_authorized",
        "EvidenceRepairAuthorizeV1",
        FIXTURES_V1 / "evidence-repair-authorize.valid.json",
    ),
    (
        "evidence_repair_completed",
        "EvidenceRepairCompleteV1",
        FIXTURES_V1 / "evidence-repair-complete.valid.json",
    ),
    (
        "retention_tombstone",
        "RetentionTombstoneV2",
        FIXTURES_V2 / "retention-tombstone.valid.json",
    ),
    (
        "retention_blocked_priority_evidence",
        "RetentionBlockedV1",
        FIXTURES_V1 / "retention-blocked.valid.json",
    ),
)


def _json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    assert isinstance(value, dict)
    return value


def _schema(path: Path) -> dict[str, Any]:
    value = _json_object(path)
    Draft202012Validator.check_schema(value)
    return value


def _manifest_run_sha256(values: list[str]) -> str:
    encoded = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(b"AGMIND_RETENTION_RUN_V2\x00" + encoded).hexdigest()


def _identity() -> tuple[
    ingest_envelope.PinnedObserverRoot,
    ingest_envelope.AnchoredPublicKeyChain,
]:
    key = private_key(11)
    root = ingest_envelope.PinnedObserverRoot.from_validated_contract_for_test(
        contracts.ObserverTrustRootV1.model_validate(root_value(key), strict=True)
    )
    return root, ingest_envelope.AnchoredPublicKeyChain.from_value(
        root,
        metadata_value(key),
    )


def _coordinator(path: Path) -> AcceptanceCoordinator:
    root, chain = _identity()
    return AcceptanceCoordinator.create_empty(
        ingest_envelope.EnvelopeVerifier(root, chain),
        SegmentStore(path),
    )


def _direct_item(envelope: dict[str, object]) -> dict[str, object]:
    value = page_value(envelope)["events"][0]
    assert isinstance(value, dict)
    return value


@pytest.mark.parametrize(
    ("model_name", "fixture_path", "schema_path"),
    CONTRACT_CASES,
    ids=("repair-authorize", "repair-complete", "tombstone-v2", "retention-blocked"),
)
def test_c2a_shared_runtime_and_schema_accept_golden_requests(
    model_name: str,
    fixture_path: Path,
    schema_path: Path,
) -> None:
    raw = fixture_path.read_bytes()
    model = getattr(contracts, model_name)
    decoded = contracts.decode_strict(raw, model, 16 * 1024)
    document = _json_object(fixture_path)
    assert decoded.model_dump() == document
    contract_schema_validator(_schema(schema_path)).validate(document)


@pytest.mark.parametrize(
    ("model_name", "fixture_path", "schema_path", "mutate"),
    (
        (
            "EvidenceRepairAuthorizeV1",
            FIXTURES_V1 / "evidence-repair-authorize.valid.json",
            SCHEMAS_V1 / "evidence-repair-authorize.schema.json",
            lambda value: value.update(
                repair_id="AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
            ),
        ),
        (
            "EvidenceRepairCompleteV1",
            FIXTURES_V1 / "evidence-repair-complete.valid.json",
            SCHEMAS_V1 / "evidence-repair-complete.schema.json",
            lambda value: value.update(verified_bytes=True),
        ),
        (
            "RetentionTombstoneV2",
            FIXTURES_V2 / "retention-tombstone.valid.json",
            SCHEMAS_V2 / "retention-tombstone.schema.json",
            lambda value: value.update(extra_authority="forbidden"),
        ),
        (
            "RetentionBlockedV1",
            FIXTURES_V1 / "retention-blocked.valid.json",
            SCHEMAS_V1 / "retention-blocked.schema.json",
            lambda value: value.update(target_bytes=MAX_UINT64 + 1),
        ),
    ),
    ids=("uppercase-uuid", "boolean-integer", "unknown-field", "uint64-overflow"),
)
def test_c2a_shared_runtime_and_schema_reject_strict_shape_violations(
    model_name: str,
    fixture_path: Path,
    schema_path: Path,
    mutate: Any,
) -> None:
    document = _json_object(fixture_path)
    mutate(document)
    model = getattr(contracts, model_name)
    with pytest.raises(ValueError):
        contracts.decode_strict(canonical_json(document), model, 16 * 1024)
    assert not contract_schema_validator(_schema(schema_path)).is_valid(document)


def test_c2a_strict_decoder_rejects_duplicate_null_missing_and_v1_tombstone() -> None:
    authorize = _json_object(FIXTURES_V1 / "evidence-repair-authorize.valid.json")
    authorize_model = contracts.EvidenceRepairAuthorizeV1
    raw = canonical_json(authorize)
    duplicate = raw[:-1] + b',"reason":"torn_open_tail"}'
    with pytest.raises(ValueError, match="duplicate JSON key"):
        contracts.decode_strict(duplicate, authorize_model, 4 * 1024)

    null_value = copy.deepcopy(authorize)
    null_value["reason"] = None
    with pytest.raises(ValueError, match="top-level null"):
        contracts.decode_strict(canonical_json(null_value), authorize_model, 4 * 1024)

    missing = copy.deepcopy(authorize)
    del missing["reason"]
    with pytest.raises(ValueError, match="missing required property"):
        contracts.decode_strict(canonical_json(missing), authorize_model, 4 * 1024)

    v1 = _json_object(FIXTURES_V2 / "retention-tombstone.valid.json")
    v1["schema_version"] = "agmind.retention-tombstone.v1"
    tombstone_model = contracts.RetentionTombstoneV2
    with pytest.raises(ValueError):
        contracts.decode_strict(canonical_json(v1), tombstone_model, 16 * 1024)


def test_c2a_repair_byte_and_zero_prefix_invariants() -> None:
    authorize_model = contracts.EvidenceRepairAuthorizeV1
    authorize = _json_object(FIXTURES_V1 / "evidence-repair-authorize.valid.json")

    zero_authorize = copy.deepcopy(authorize)
    zero_authorize["verified_bytes"] = 0
    zero_authorize["last_verified_frame_sha256"] = ZERO_SHA256
    authorize_model.model_validate(zero_authorize, strict=True)

    bad_zero_authorize = copy.deepcopy(zero_authorize)
    bad_zero_authorize["last_verified_frame_sha256"] = "2" * 64
    with pytest.raises(ValueError, match="last_verified_frame_sha256"):
        authorize_model.model_validate(bad_zero_authorize, strict=True)

    over_segment = copy.deepcopy(authorize)
    over_segment["verified_bytes"] = MAX_SEGMENT_BYTES
    over_segment["discarded_bytes"] = 1
    with pytest.raises(ValueError, match="segment"):
        authorize_model.model_validate(over_segment, strict=True)
    assert not contract_schema_validator(
        _schema(SCHEMAS_V1 / "evidence-repair-authorize.schema.json")
    ).is_valid(over_segment)

    complete_model = contracts.EvidenceRepairCompleteV1
    complete = _json_object(FIXTURES_V1 / "evidence-repair-complete.valid.json")
    zero_complete = copy.deepcopy(complete)
    zero_complete["verified_bytes"] = 0
    zero_complete["last_verified_frame_sha256"] = ZERO_SHA256
    zero_complete["post_repair_prefix_sha256"] = EMPTY_SHA256
    complete_model.model_validate(zero_complete, strict=True)

    wrong_empty_prefix = copy.deepcopy(zero_complete)
    wrong_empty_prefix["post_repair_prefix_sha256"] = "4" * 64
    with pytest.raises(ValueError, match="empty"):
        complete_model.model_validate(wrong_empty_prefix, strict=True)


def test_c2a_tombstone_nul_domain_order_uniqueness_and_128_bound() -> None:
    model = contracts.RetentionTombstoneV2
    fixture = _json_object(FIXTURES_V2 / "retention-tombstone.valid.json")
    values = fixture["removed_manifest_hashes"]
    assert isinstance(values, list)
    assert fixture["manifest_run_sha256"] == _manifest_run_sha256(values)
    escaped = hashlib.sha256(
        b"AGMIND_RETENTION_RUN_V2\\0"
        + json.dumps(values, separators=(",", ":")).encode()
    ).hexdigest()
    assert fixture["manifest_run_sha256"] != escaped

    reverse_order = copy.deepcopy(fixture)
    reverse_values = list(reversed(values))
    reverse_order["removed_manifest_hashes"] = reverse_values
    reverse_order["first_removed_manifest_sha256"] = reverse_values[0]
    reverse_order["last_removed_manifest_sha256"] = reverse_values[-1]
    reverse_order["manifest_run_sha256"] = _manifest_run_sha256(reverse_values)
    assert model.model_validate(reverse_order, strict=True).removed_manifest_hashes == reverse_values

    duplicate = copy.deepcopy(fixture)
    duplicate["removed_manifest_hashes"] = [values[0], values[0]]
    duplicate["last_removed_manifest_sha256"] = values[0]
    duplicate["manifest_run_sha256"] = _manifest_run_sha256(
        duplicate["removed_manifest_hashes"]
    )
    with pytest.raises(ValueError, match="unique"):
        model.model_validate(duplicate, strict=True)

    maximum = copy.deepcopy(fixture)
    maximum_values = [f"{index:064x}" for index in range(128)]
    maximum["removed_manifest_hashes"] = maximum_values
    maximum["first_removed_manifest_sha256"] = maximum_values[0]
    maximum["last_removed_manifest_sha256"] = maximum_values[-1]
    maximum["manifest_run_sha256"] = _manifest_run_sha256(maximum_values)
    model.model_validate(maximum, strict=True)

    too_many = copy.deepcopy(maximum)
    too_many_values = [f"{index:064x}" for index in range(129)]
    too_many["removed_manifest_hashes"] = too_many_values
    too_many["last_removed_manifest_sha256"] = too_many_values[-1]
    too_many["manifest_run_sha256"] = _manifest_run_sha256(too_many_values)
    with pytest.raises(ValueError):
        model.model_validate(too_many, strict=True)
    assert not contract_schema_validator(
        _schema(SCHEMAS_V2 / "retention-tombstone.schema.json")
    ).is_valid(too_many)

    wrong_run_hash = copy.deepcopy(fixture)
    wrong_run_hash["manifest_run_sha256"] = escaped
    with pytest.raises(ValueError, match="manifest_run_sha256"):
        model.model_validate(wrong_run_hash, strict=True)
    assert not contract_schema_validator(
        _schema(SCHEMAS_V2 / "retention-tombstone.schema.json")
    ).is_valid(wrong_run_hash)


@pytest.mark.parametrize(
    ("mutation", "match"),
    (
        ({"target_bytes": 115, "blocked_bytes": 1}, "target"),
        ({"blocked_bytes": 14}, "blocked_bytes"),
        (
            {"routine_bytes": MAX_UINT64, "protected_bytes": 1, "target_bytes": 1},
            "overflow",
        ),
    ),
    ids=("not-over-target", "wrong-difference", "sum-overflow"),
)
def test_c2a_retention_blocked_exact_arithmetic(
    mutation: dict[str, int],
    match: str,
) -> None:
    model = contracts.RetentionBlockedV1
    document = _json_object(FIXTURES_V1 / "retention-blocked.valid.json")
    document.update(mutation)
    with pytest.raises(ValueError, match=match):
        model.model_validate(document, strict=True)
    assert not contract_schema_validator(
        _schema(SCHEMAS_V1 / "retention-blocked.schema.json")
    ).is_valid(document)


@pytest.mark.parametrize(
    ("fixture_path", "schema_path", "integer_field"),
    (
        (
            FIXTURES_V1 / "evidence-repair-authorize.valid.json",
            SCHEMAS_V1 / "evidence-repair-authorize.schema.json",
            "verified_bytes",
        ),
        (
            FIXTURES_V1 / "evidence-repair-complete.valid.json",
            SCHEMAS_V1 / "evidence-repair-complete.schema.json",
            "verified_bytes",
        ),
        (
            FIXTURES_V2 / "retention-tombstone.valid.json",
            SCHEMAS_V2 / "retention-tombstone.schema.json",
            "removed_bytes",
        ),
        (
            FIXTURES_V1 / "retention-blocked.valid.json",
            SCHEMAS_V1 / "retention-blocked.schema.json",
            "target_bytes",
        ),
    ),
    ids=("repair-authorize", "repair-complete", "tombstone-v2", "blocked"),
)
def test_c2a_schema_rejects_integral_float_wire_values(
    fixture_path: Path,
    schema_path: Path,
    integer_field: str,
) -> None:
    document = _json_object(fixture_path)
    value = document[integer_field]
    assert isinstance(value, int)
    document[integer_field] = float(value)
    assert not contract_schema_validator(_schema(schema_path)).is_valid(document)


@pytest.mark.parametrize(
    ("event_type", "_model_name", "fixture_path"),
    EVENT_CASES,
    ids=(
        "repair-authorized",
        "repair-completed",
        "retention-tombstone",
        "retention-blocked",
    ),
)
def test_c2a_signed_events_require_exact_context_and_are_protected(
    tmp_path: Path,
    event_type: str,
    _model_name: str,
    fixture_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / event_type)
    try:
        boot_item = ingest_envelope.decode_events_page(
            canonical_json(page_value(boot_boundary(key)))
        ).events[0]
        coordinator.accept(boot_item)
        envelope = envelope_value(
            key,
            sequence=2,
            event_type=event_type,
            normalized_fields=_json_object(fixture_path),
        )
        item = _direct_item(envelope)
        verified = coordinator.verifier.verify(
            item["envelope"],
            sequence=item["sequence"],
            event_id=item["event_id"],
            content_sha256=item["content_sha256"],
        )
        assert verified.evidence_priority == "protected"
    finally:
        coordinator.segment_store.close(flush=False)


@pytest.mark.parametrize(
    ("event_type", "_model_name", "fixture_path"),
    EVENT_CASES,
    ids=(
        "repair-authorized",
        "repair-completed",
        "retention-tombstone",
        "retention-blocked",
    ),
)
def test_c2a_signed_events_reject_nonempty_security_context(
    tmp_path: Path,
    event_type: str,
    _model_name: str,
    fixture_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / event_type)
    try:
        boot_item = ingest_envelope.decode_events_page(
            canonical_json(page_value(boot_boundary(key)))
        ).events[0]
        coordinator.accept(boot_item)
        envelope = envelope_value(
            key,
            sequence=2,
            event_type=event_type,
            normalized_fields=_json_object(fixture_path),
        )
        envelope["clock_uncertainty_ms"] = 1
        envelope["source_signature"] = key.sign(event_signing_message(envelope)).hex()
        item = _direct_item(envelope)
        with pytest.raises(ingest_envelope.OuterBindingError):
            coordinator.verifier.verify(
                item["envelope"],
                sequence=item["sequence"],
                event_id=item["event_id"],
                content_sha256=item["content_sha256"],
            )
    finally:
        coordinator.segment_store.close(flush=False)


@pytest.mark.parametrize(
    "security_field",
    ("container_id", "container_start_time", "release_id", "inventory_revision"),
)
@pytest.mark.parametrize(
    ("event_type", "_model_name", "fixture_path"),
    EVENT_CASES,
    ids=(
        "repair-authorized",
        "repair-completed",
        "retention-tombstone",
        "retention-blocked",
    ),
)
def test_c2a_signed_special_semantics_reject_explicit_null_security_fields(
    event_type: str,
    _model_name: str,
    fixture_path: Path,
    security_field: str,
) -> None:
    key = private_key(11)
    envelope = envelope_value(
        key,
        sequence=2,
        event_type=event_type,
        normalized_fields=_json_object(fixture_path),
    )
    envelope[security_field] = None
    envelope["source_signature"] = key.sign(event_signing_message(envelope)).hex()
    verify_event_signature(envelope, public_bytes(key))
    decoded = contracts.EventEnvelopeV1.model_validate(envelope, strict=True)
    assert security_field in decoded.model_fields_set
    with pytest.raises(ingest_envelope.OuterBindingError):
        ingest_envelope.EnvelopeVerifier._validate_special_semantics(decoded)


def test_c2a_signed_retention_tombstone_rejects_provisional_v1(
    tmp_path: Path,
) -> None:
    key = private_key(11)
    coordinator = _coordinator(tmp_path / "v1-tombstone")
    try:
        boot_item = ingest_envelope.decode_events_page(
            canonical_json(page_value(boot_boundary(key)))
        ).events[0]
        coordinator.accept(boot_item)
        v1_fields = _json_object(FIXTURES_V2 / "retention-tombstone.valid.json")
        v1_fields["schema_version"] = "agmind.retention-tombstone.v1"
        envelope = envelope_value(
            key,
            sequence=2,
            event_type="retention_tombstone",
            normalized_fields=v1_fields,
        )
        item = _direct_item(envelope)
        with pytest.raises(ingest_envelope.OuterBindingError):
            coordinator.verifier.verify(
                item["envelope"],
                sequence=item["sequence"],
                event_id=item["event_id"],
                content_sha256=item["content_sha256"],
            )
    finally:
        coordinator.segment_store.close(flush=False)


def test_c2a_direct_core_event_decoder_is_bounded_strict_and_outer_bound() -> None:
    key = private_key(11)
    item = _direct_item(boot_boundary(key))
    raw = canonical_json(item)
    decoder = ingest_envelope.decode_core_event
    decoded = decoder(raw)
    assert decoded.model_dump() == item

    invalid_items = []
    extra = copy.deepcopy(item)
    extra["extra"] = "forbidden"
    invalid_items.append(extra)
    wrong_sequence = copy.deepcopy(item)
    wrong_sequence["sequence"] = 2
    invalid_items.append(wrong_sequence)
    wrong_event_id = copy.deepcopy(item)
    wrong_event_id["event_id"] = "evt_" + "0" * 64
    invalid_items.append(wrong_event_id)
    wrong_content_hash = copy.deepcopy(item)
    wrong_content_hash["content_sha256"] = "0" * 64
    invalid_items.append(wrong_content_hash)
    for invalid in invalid_items:
        with pytest.raises(ValueError):
            decoder(canonical_json(invalid))

    duplicate = raw[:-1] + b',"sequence":1}'
    with pytest.raises(ValueError, match="duplicate JSON key"):
        decoder(duplicate)
    with pytest.raises(ValueError, match="byte limit"):
        decoder(b" " * (128 * 1024 - len(raw) + 1) + raw)
