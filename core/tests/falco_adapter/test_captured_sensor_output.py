"""The adapter must accept what the pinned Falco actually posts.

Every body used here was captured off the wire from the pinned Falco image running the
sensor artifacts this repository ships. See `contracts/fixtures/v1/falco/PROVENANCE.md`.
The hand-built fixtures next to them cannot prove this: they were written to match the
parser, which is how a sensor whose every IPv6 connect frame was rejected in production
sat behind a green suite.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from agmind_immune.contracts import FalcoConnectV1
from agmind_immune.falco_adapter.main import (
    AdapterRuntime,
    AdapterSettings,
    FalcoAdapterCoverageInputV1,
)
from agmind_immune.falco_adapter.parser import (
    METRICS_RULE,
    FalcoMetricsHeartbeat,
    parse_falco_body,
)

FIXTURES = Path("contracts/fixtures/v1/falco")
CAPTURED = FIXTURES / "captured-http-output.ndjson"
CAPTURED_LEGACY_RULE = FIXTURES / "captured-http-output.legacy-rule.ndjson"
SENSOR_CONFIG = Path("deploy/falco/falco.yaml")
SENSOR_RULES = Path("deploy/falco/rules.d/agmind-pcc.yaml")
VERSIONS_ENV = Path("deploy/versions.env")
COMPOSE = Path("deploy/compose/compose.yaml")

# The address-family guard whose absence let the pinned rule emit IPv6 connects that
# FalcoConnectV1 cannot represent. Written as a top-level conjunct so it also binds the
# `evt.rawres < 0` disjunct, which is the one that leaked them.
FAMILY_GUARD = "not fd.typechar=6"


def captured_bodies(path: Path) -> list[bytes]:
    bodies = [line for line in path.read_bytes().split(b"\n") if line]
    assert bodies, f"{path} carries no captured bodies"
    return bodies


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def shipped_settings() -> AdapterSettings:
    """Settings built from the sensor artifacts the deployment actually mounts."""
    return AdapterSettings(
        expected_falco_config_sha256=sha256_of(SENSOR_CONFIG),
        expected_falco_rules_sha256=sha256_of(SENSOR_RULES),
    )


async def drain(runtime: AdapterRuntime, *, turns: int = 2_000) -> None:
    for _ in range(turns):
        if runtime.outbox.empty:
            return
        await asyncio.sleep(0)
    raise AssertionError("adapter outbox did not drain")


async def eventually(predicate: Callable[[], bool], *, turns: int = 2_000) -> None:
    for _ in range(turns):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition was not reached")


def test_every_captured_body_is_accepted_by_the_parser() -> None:
    heartbeats = 0
    events = 0
    for raw in captured_bodies(CAPTURED):
        parsed = parse_falco_body(raw)
        if isinstance(parsed, FalcoMetricsHeartbeat):
            heartbeats += 1
        else:
            assert isinstance(parsed, FalcoConnectV1)
            events += 1
    assert heartbeats >= 2, "capture must exercise the metrics snapshot path"
    assert events >= 10, "capture must exercise the connect rule path"


def test_capture_covers_the_result_tuples_the_pinned_rule_produces() -> None:
    """A capture that only saw one shape would not prove much."""
    results = set()
    for raw in captured_bodies(CAPTURED):
        document = json.loads(raw)
        if document["rule"] == METRICS_RULE:
            continue
        results.add(document["output_fields"]["evt.res"])
    assert {"SUCCESS", "EINPROGRESS", "ENOENT", "ECONNREFUSED"} <= results


def test_captured_heartbeat_hashes_bind_to_the_shipped_sensor_artifacts() -> None:
    """Falco hashes the files it loaded; those are the files this repository ships.

    Edit `deploy/falco/falco.yaml` or the rule file without re-capturing and this fails —
    which is the only thing that keeps the fixture from rotting into fiction.
    """
    config_sha256 = sha256_of(SENSOR_CONFIG)
    rules_sha256 = sha256_of(SENSOR_RULES)
    heartbeats = [
        parsed
        for raw in captured_bodies(CAPTURED)
        if isinstance(parsed := parse_falco_body(raw), FalcoMetricsHeartbeat)
    ]
    assert heartbeats
    for heartbeat in heartbeats:
        assert heartbeat.config_sha256 == config_sha256
        assert heartbeat.rules_sha256 == rules_sha256
        assert heartbeat.falco_version == "0.44.1"
        assert heartbeat.engine_name == "modern_bpf"

    versions = VERSIONS_ENV.read_text(encoding="utf-8")
    assert f"FALCO_CONFIG_SHA256={config_sha256}\n" in versions
    assert f"FALCO_RULES_SHA256={rules_sha256}\n" in versions
    compose = COMPOSE.read_text(encoding="utf-8")
    assert f"AGMIND_FALCO_CONFIG_SHA256: {config_sha256}\n" in compose
    assert f"AGMIND_FALCO_RULES_SHA256: {rules_sha256}\n" in compose


@pytest.mark.asyncio
async def test_captured_stream_makes_the_adapter_ready_without_one_rejection() -> None:
    delivered: list[FalcoAdapterCoverageInputV1] = []

    async def post(path: str, body: bytes, _: float) -> None:
        if path == "/v1/events/falco-coverage":
            delivered.append(FalcoAdapterCoverageInputV1.model_validate_json(body))

    runtime = AdapterRuntime(shipped_settings(), post=post)
    await runtime.start()
    try:
        for raw in captured_bodies(CAPTURED):
            await runtime.admit_raw(raw)
        await drain(runtime)
        await eventually(lambda: runtime.ready)
    finally:
        await runtime.shutdown()

    kinds = [item.kind for item in delivered]
    assert "falco_parse_rejection" not in kinds
    assert "falco_configuration_mismatch" not in kinds
    assert "falco_heartbeat_lease" in kinds
    closed_gaps = [
        item
        for item in delivered
        if item.kind == "falco_heartbeat_gap" and item.closed_at is not None
    ]
    assert closed_gaps, "the startup heartbeat gap was never closed by a real heartbeat"


def test_the_previous_rule_really_did_post_bodies_the_contract_rejects() -> None:
    """The defect, held against real bytes rather than a story about them."""
    rejected: list[dict] = []
    for raw in captured_bodies(CAPTURED_LEGACY_RULE):
        try:
            parse_falco_body(raw)
        except (TypeError, UnicodeError, ValueError):
            rejected.append(json.loads(raw))
    assert rejected, "the legacy-rule capture no longer demonstrates the defect"
    for document in rejected:
        destination = document["output_fields"]["fd.rip"]
        assert ":" in destination, "the only shape the contract refuses here is a non-IPv4 peer"
        assert document["rule"] == "AGmind PCC Suspicious Process Outbound Connect"


def test_the_contract_still_refuses_a_non_ipv4_destination() -> None:
    """The fix narrowed the sensor. It must not have widened signed evidence."""
    ipv6_body = next(
        raw for raw in captured_bodies(CAPTURED_LEGACY_RULE) if b'"fd.rip":"::1"' in raw
    )
    with pytest.raises(ValueError, match="canonical IPv4"):
        parse_falco_body(ipv6_body)


def test_shipped_rule_restricts_the_failure_disjunct_to_non_ipv6_sockets() -> None:
    """`or evt.rawres < 0` on its own admits every address family the fd can have."""
    condition = SENSOR_RULES.read_text(encoding="utf-8")
    assert FAMILY_GUARD in condition
    assert "evt.rawres < 0" in condition
    assert condition.index(FAMILY_GUARD) < condition.index("evt.rawres < 0")
