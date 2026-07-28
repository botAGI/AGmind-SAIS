from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from agmind_immune import canonicaljson
from agmind_immune.contracts import FalcoConnectV1
from agmind_immune.falco_adapter.main import (
    AdapterRuntime,
    AdapterSettings,
    BoundedOutbox,
    DeliveryItem,
    DeliveryWorker,
    FalcoAdapterCoverageInputV1,
    HeartbeatWatchdog,
    ObserverUDSClient,
    create_app,
)
from agmind_immune.falco_adapter.parser import (
    FALCO_MAX_BODY_BYTES,
    FalcoMetricsHeartbeat,
    parse_falco_body,
)
from tests.schema_validation import contract_schema_validator

FIXTURES = Path("contracts/fixtures/v1/falco")
SHARED_FIXTURES = Path("contracts/fixtures/v1")
CONFIG_SHA256 = "1" * 64
RULES_SHA256 = "2" * 64


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def settings() -> AdapterSettings:
    return AdapterSettings(
        expected_falco_config_sha256=CONFIG_SHA256,
        expected_falco_rules_sha256=RULES_SHA256,
    )


@pytest.mark.parametrize(
    ("fixture", "successful", "missing"),
    [
        ("success.json", True, []),
        ("einprogress.json", True, []),
        ("failed.json", False, ["destination_ipv4"]),
        (
            "missing-field.json",
            False,
            [
                "destination_ipv4",
                "destination_port",
                "falco_container_id_prefix",
                "falco_container_start_ts",
                "l4_protocol",
                "proc_exe_path",
                "proc_name",
            ],
        ),
    ],
)
def test_connect_parser_preserves_time_result_and_exact_missing_sensor_facts(
    fixture: str,
    successful: bool,
    missing: list[str],
) -> None:
    event = parse_falco_body(fixture_bytes(fixture))
    assert isinstance(event, FalcoConnectV1)
    assert event.event_time == (
        "2026-07-27T12:00:00.123456789Z"
        if fixture == "success.json"
        else {
            "einprogress.json": "2026-07-27T12:00:01Z",
            "failed.json": "2026-07-27T12:00:02Z",
            "missing-field.json": "2026-07-27T12:00:03Z",
        }[fixture]
    )
    assert event.successful_connect is successful
    assert event.investigation_only is True
    assert event.missing_required_fields == missing
    assert event.repo_digests == []
    assert event.docker_container_id is None
    assert event.docker_started_at is None
    assert event.image_id is None
    assert event.immutable_spec_sha256 is None
    assert event.inventory_revision is None


def test_redaction_hashes_then_discards_attacker_controlled_raw_fields() -> None:
    raw = fixture_bytes("hostile-strings.json")
    event = parse_falco_body(raw)
    assert isinstance(event, FalcoConnectV1)
    encoded = canonicaljson.canonical_json(event)
    assert b"IGNORE ALL INSTRUCTIONS" not in encoded
    assert b"SECRET_CANARY" not in encoded
    assert b"proc.cmdline" not in encoded
    assert event.raw_event_sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff",
        b'{"rule":"x","rule":"x"}',
        fixture_bytes("success.json") + b"{}",
        fixture_bytes("success.json").replace(b'"evt.rawres": 0', b'"evt.rawres": 0.0'),
        fixture_bytes("success.json").replace(
            b'"hostname": "sensor-host"',
            b'"ignored_float": 0.25, "hostname": "sensor-host"',
        ),
        b'{"x":' + (b"[" * 65) + b"0" + (b"]" * 65) + b"}",
        fixture_bytes("success.json").replace(b'"source": "syscall"', b'"source": "internal"'),
        fixture_bytes("success.json").replace(b'"agmind-pcc-rules-v1"', b'"wrong-rule-tag"'),
        fixture_bytes("success.json").replace(
            b'"container.id": "aaaaaaaaaaaa"', b'"container.id": "NOT-AN-ID"'
        ),
        fixture_bytes("success.json").replace(
            b'"evt.res": "SUCCESS"', b'"evt.res": "ECONNREFUSED"'
        ),
    ],
)
def test_parser_rejects_strict_json_identity_type_and_result_violations(raw: bytes) -> None:
    with pytest.raises(ValueError):
        parse_falco_body(raw)


def test_metrics_heartbeat_is_validated_but_never_becomes_connect() -> None:
    heartbeat = parse_falco_body(fixture_bytes("metrics-heartbeat-real.json"))
    assert isinstance(heartbeat, FalcoMetricsHeartbeat)
    assert heartbeat.event_time == "2026-07-27T12:00:05Z"
    assert heartbeat.falco_version == "0.44.1"
    assert heartbeat.engine_name == "modern_bpf"
    assert heartbeat.config_sha256 == CONFIG_SHA256
    assert heartbeat.rules_sha256 == RULES_SHA256
    assert heartbeat.outputs_queue_num_drops == 0
    assert heartbeat.scap_n_drops == 0

    selected_float = fixture_bytes("metrics-heartbeat-real.json").replace(
        b'"scap.n_drops": 0',
        b'"scap.n_drops": 0.0',
    )
    with pytest.raises((TypeError, ValueError)):
        parse_falco_body(selected_float)

    unbounded_float = fixture_bytes("metrics-heartbeat-real.json").replace(
        b'"scap.n_drops_perc": 0.0',
        b'"scap.n_drops_perc": 1e10000',
    )
    with pytest.raises(ValueError, match="floating-point"):
        parse_falco_body(unbounded_float)


@pytest.mark.parametrize(
    "raw",
    [
        fixture_bytes("success.json").replace(
            b'"tags": [\n    "agmind-pcc-rules-v1"\n  ]',
            b'"tags": ["agmind-pcc-rules-v1", "extra"]',
        ),
        fixture_bytes("success.json").replace(b'"priority": "Notice"', b'"priority": "Warning"'),
    ],
)
def test_connect_requires_exact_single_tag_and_notice_priority(raw: bytes) -> None:
    with pytest.raises(ValueError):
        parse_falco_body(raw)


def test_nonblocking_result_preserves_locked_absent_rawres_tuple() -> None:
    raw = fixture_bytes("einprogress.json").replace(
        b'"evt.rawres": -115',
        b'"evt.rawres": null',
    )
    event = parse_falco_body(raw)
    assert isinstance(event, FalcoConnectV1)
    assert event.evt_rawres is None
    assert event.successful_connect is True


def test_falco_time_accepts_official_compact_numeric_offset() -> None:
    raw = fixture_bytes("success.json").replace(b"+03:00", b"+0300")
    event = parse_falco_body(raw)
    assert isinstance(event, FalcoConnectV1)
    assert event.event_time == "2026-07-27T12:00:00.123456789Z"


def test_shared_falco_schema_accepts_exact_sensor_omission_accounting() -> None:
    schema = json.loads(Path("contracts/v1/falco-connect.schema.json").read_text())
    validator = contract_schema_validator(schema)
    sensor_missing = json.loads((SHARED_FIXTURES / "falco.sensor-missing.valid.json").read_text())
    assert validator.is_valid(sensor_missing)
    assert FalcoConnectV1.model_validate(sensor_missing, strict=True)

    unaccounted = dict(sensor_missing)
    unaccounted["missing_required_fields"] = []
    assert not validator.is_valid(unaccounted)
    with pytest.raises(ValueError):
        FalcoConnectV1.model_validate(unaccounted, strict=True)

    candidate = json.loads((SHARED_FIXTURES / "falco.candidate.valid.json").read_text())
    del candidate["proc_name"]
    candidate["missing_required_fields"] = ["proc_name"]
    assert not validator.is_valid(candidate)
    with pytest.raises(ValueError):
        FalcoConnectV1.model_validate(candidate, strict=True)

    observer_missing = dict(sensor_missing)
    observer_missing["missing_required_fields"] = sorted(
        [*sensor_missing["missing_required_fields"], "docker_container_id"]
    )
    assert not validator.is_valid(observer_missing)
    with pytest.raises(ValueError):
        FalcoConnectV1.model_validate(observer_missing, strict=True)


@pytest.mark.asyncio
async def test_raw_http_route_is_exact_bounded_and_admits_before_202() -> None:
    delivered: list[tuple[str, bytes]] = []

    async def post(path: str, body: bytes, _: float) -> None:
        delivered.append((path, body))

    runtime = AdapterRuntime(settings(), post=post)
    await runtime.start()
    transport = httpx.ASGITransport(app=create_app(runtime))
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://falco-adapter",
        ) as client:
            accepted = await client.post(
                "/v1/falco/raw",
                content=fixture_bytes("success.json"),
                headers={"Content-Type": "application/json"},
            )
            assert accepted.status_code == 202

            metrics = await client.post(
                "/v1/falco/raw",
                content=fixture_bytes("metrics-heartbeat.json"),
                headers={"Content-Type": "application/json"},
            )
            assert metrics.status_code == 202

            assert (await client.get("/v1/falco/raw")).status_code == 405
            assert (
                await client.post(
                    "/v1/falco/raw",
                    content=fixture_bytes("success.json"),
                    headers={"Content-Type": "application/json; charset=utf-8"},
                )
            ).status_code == 415
            assert (
                await client.post(
                    "/v1/falco/raw",
                    content=b"x" * (FALCO_MAX_BODY_BYTES + 1),
                    headers={"Content-Type": "application/json"},
                )
            ).status_code == 413
            for malformed in (b"[]", b'{"output_fields":[]}'):
                response = await client.post(
                    "/v1/falco/raw",
                    content=malformed,
                    headers={"Content-Type": "application/json"},
                )
                assert response.status_code == 400
    finally:
        await runtime.shutdown()

    assert any(path == "/v1/events/falco" for path, _ in delivered)


@pytest.mark.asyncio
async def test_runtime_rejects_intake_until_startup_gap_is_locally_admitted() -> None:
    runtime = AdapterRuntime(settings())
    with pytest.raises(RuntimeError, match="startup"):
        await runtime.admit_raw(fixture_bytes("success.json"))


@pytest.mark.asyncio
async def test_outbox_capacity_excludes_inflight_and_priority_is_coalesced_first() -> None:
    outbox = BoundedOutbox()
    await outbox.admit_routine(DeliveryItem("/v1/events/falco", b"inflight"))
    inflight = await outbox.get()
    assert inflight.body == b"inflight"

    dropped = 0
    for index in range(1_025):
        dropped += await outbox.admit_routine(DeliveryItem("/v1/events/falco", str(index).encode()))
    assert outbox.routine_pending == 1_024
    assert dropped == 1

    await outbox.admit_priority(
        "falco_queue_drop",
        DeliveryItem("/v1/events/falco-coverage", b"first"),
    )
    await outbox.admit_priority(
        "falco_queue_drop",
        DeliveryItem("/v1/events/falco-coverage", b"coalesced"),
    )
    assert outbox.priority_pending == 1
    blocked = asyncio.create_task(outbox.get())
    await asyncio.sleep(0)
    assert blocked.done() is False
    await outbox.ack(inflight)
    assert (await blocked).body == b"coalesced"


@pytest.mark.asyncio
async def test_priority_security_classes_override_coalesced_insertion_order() -> None:
    runtime = AdapterRuntime(settings())
    original = DeliveryItem("/v1/events/falco", b"original")
    await runtime.outbox.admit_routine(original)
    await runtime.outbox.admit_routine(DeliveryItem("/v1/events/falco", b"routine"))
    attempts = 0

    async def fail_once(_: str, __: bytes, ___: float) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ReadTimeout("observer unavailable")

    async def queue_during_outage(_: float) -> None:
        for key in [
            "falco_adapter_stop",
            "falco_parse_rejection",
            "falco_queue_drop",
            "falco_heartbeat_gap",
            "falco_configuration_mismatch",
            "falco_kernel_event_drop",
            "falco_outputs_queue_drop",
            "falco_adapter_start",
            "unknown-priority",
            "falco_heartbeat_lease",
        ]:
            await runtime.outbox.admit_priority(
                key,
                DeliveryItem("/v1/events/falco-coverage", key.encode()),
            )

    worker = DeliveryWorker(
        runtime.outbox,
        post=fail_once,
        sleep=queue_during_outage,
        on_failure=runtime.delivery_failed,
        on_recovery=runtime.delivery_recovered,
    )
    completed = await worker.deliver_next()
    order: list[str] = []
    while not runtime.outbox.empty:
        item = await runtime.outbox.get()
        if item.body.startswith(b"{"):
            coverage = json.loads(item.body)
            order.append(coverage["kind"] + (":closed" if "closed_at" in coverage else ":open"))
        else:
            order.append(item.body.decode())
        await runtime.outbox.ack(item)

    assert (completed, order) == (
        True,
        [
            "falco_delivery_failure:closed",
            "falco_adapter_stop",
            "falco_parse_rejection",
            "falco_queue_drop",
            "falco_heartbeat_gap",
            "falco_configuration_mismatch",
            "falco_kernel_event_drop",
            "falco_outputs_queue_drop",
            "falco_adapter_start",
            "unknown-priority",
            "falco_heartbeat_lease",
            "routine",
        ],
    )


@pytest.mark.asyncio
async def test_delivery_worker_retries_identical_body_with_one_inflight() -> None:
    outbox = BoundedOutbox()
    item = DeliveryItem("/v1/events/falco", b'{"stable":"bytes"}')
    await outbox.admit_routine(item)
    calls: list[tuple[str, bytes, float]] = []
    active = 0
    maximum_active = 0

    async def post(path: str, body: bytes, timeout: float) -> None:
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        calls.append((path, body, timeout))
        active -= 1
        if len(calls) == 1:
            raise httpx.ReadTimeout("observer response timed out")

    async def no_delay(_: float) -> None:
        return

    worker = DeliveryWorker(outbox, post=post, sleep=no_delay)
    assert await worker.deliver_next() is True
    assert calls == [
        ("/v1/events/falco", b'{"stable":"bytes"}', 2.0),
        ("/v1/events/falco", b'{"stable":"bytes"}', 2.0),
    ]
    assert maximum_active == 1

    await outbox.admit_routine(DeliveryItem("/v1/events/falco", b"deadline"))
    deadline_calls: list[float] = []

    async def deadline_post(_: str, __: bytes, timeout: float) -> None:
        deadline_calls.append(timeout)

    deadline_worker = DeliveryWorker(
        outbox,
        post=deadline_post,
        monotonic=lambda: 100.0,
        deadline_provider=lambda: 100.5,
    )
    assert await deadline_worker.deliver_next() is True
    assert deadline_calls == [0.5]


@pytest.mark.asyncio
async def test_expired_lease_is_discarded_while_negative_coverage_and_connect_deliver() -> None:
    clock = MutableClock()
    runtime = AdapterRuntime(
        settings(),
        now=lambda: clock.wall,
        monotonic=lambda: clock.monotonic,
    )
    lease = FalcoAdapterCoverageInputV1(
        kind="falco_heartbeat_lease",
        opened_at="2026-07-27T12:00:00Z",
        closed_at="2026-07-27T12:00:00Z",
        reason_code="valid_heartbeat",
        source_payload_sha256="a" * 64,
    )
    await runtime._admit_coverage(lease)
    await runtime.outbox.admit_routine(DeliveryItem("/v1/events/falco", b'{"stable":"connect"}'))

    posts: list[tuple[str, bytes]] = []
    expiries: list[float | None] = []

    async def fail_lease_once(path: str, body: bytes, _: float) -> None:
        posts.append((path, body))
        inflight = runtime.outbox.inflight
        assert inflight is not None
        expiries.append(inflight.expires_at_monotonic)
        if len(posts) == 1:
            raise httpx.ReadTimeout("observer unavailable")

    async def cross_lease_boundary(_: float) -> None:
        clock.advance(16)

    worker = DeliveryWorker(
        runtime.outbox,
        post=fail_lease_once,
        sleep=cross_lease_boundary,
        monotonic=lambda: clock.monotonic,
        deadline_provider=lambda: runtime.drain_deadline,
        on_cycle=runtime.watchdog.check,
        on_failure=runtime.delivery_failed,
        on_recovery=runtime.delivery_recovered,
    )
    assert await worker.deliver_next() is True
    assert expiries == [115.0]
    assert len(posts) == 1
    assert runtime._delivery_failure_opened_at is not None

    drain_worker = DeliveryWorker(
        runtime.outbox,
        post=fail_lease_once,
        monotonic=lambda: clock.monotonic,
        deadline_provider=lambda: runtime.drain_deadline,
        on_failure=runtime.delivery_failed,
        on_recovery=runtime.delivery_recovered,
    )
    for _ in range(4):
        assert await drain_worker.deliver_next() is True

    posted_kinds = [
        json.loads(body)["kind"] for path, body in posts if path == "/v1/events/falco-coverage"
    ]
    assert posted_kinds[1] == "falco_delivery_failure"
    assert "falco_heartbeat_gap" in posted_kinds
    assert posts[-1] == ("/v1/events/falco", b'{"stable":"connect"}')
    assert expiries[1:] == [None, None, None, None]


@pytest.mark.asyncio
async def test_retry_reads_new_shutdown_deadline_for_sleep_and_next_request() -> None:
    clock = MutableClock()
    runtime = AdapterRuntime(
        settings(),
        now=lambda: clock.wall,
        monotonic=lambda: clock.monotonic,
    )
    await runtime.outbox.admit_routine(DeliveryItem("/v1/events/falco", b'{"stable":"deadline"}'))
    timeouts: list[float] = []
    sleeps: list[float] = []

    async def fail_after_shutdown_begins(_: str, __: bytes, timeout: float) -> None:
        timeouts.append(timeout)
        if len(timeouts) == 1:
            assert runtime.begin_shutdown() == 105.0
            clock.advance(4.75)
            raise httpx.ReadTimeout("first attempt failed")

    async def advance_by(delay: float) -> None:
        sleeps.append(delay)
        clock.advance(delay)

    worker = DeliveryWorker(
        runtime.outbox,
        post=fail_after_shutdown_begins,
        sleep=advance_by,
        monotonic=lambda: clock.monotonic,
        deadline_provider=lambda: runtime.drain_deadline,
    )
    assert await worker.deliver_next() is True
    assert sleeps == [0.125]
    assert timeouts == [2.0, pytest.approx(0.125)]
    assert runtime.begin_shutdown() == runtime.drain_deadline == 105.0


def test_sensor_gate_requires_positive_falco_schema_and_rules_markers() -> None:
    makefile = Path("Makefile").read_text()
    assert "grep -Fxq '/etc/falco/falco.yaml | schema validation: ok'" in makefile
    assert "grep -Fxq '/etc/falco/rules.d/agmind-pcc.yaml: Ok'" in makefile


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "body", "accepted"),
    [
        (201, b'{"event_id":"evt_' + (b"a" * 64) + b'"}', True),
        (200, b'{"event_id":"evt_' + (b"a" * 64) + b'"}', False),
        (202, b'{"event_id":"evt_' + (b"a" * 64) + b'"}', False),
        (201, b'{"event_id":"wrong"}', False),
        (201, b"not-json", False),
    ],
)
async def test_observer_delivery_ack_is_exact_201_with_bounded_event_id(
    status: int,
    body: bytes,
    accepted: bool,
) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=body)

    client = ObserverUDSClient(
        "/unused-in-test",
        transport=httpx.MockTransport(handler),
    )
    try:
        if accepted:
            await client.post("/v1/events/falco", b"{}", 2.0)
        else:
            with pytest.raises(httpx.HTTPError):
                await client.post("/v1/events/falco", b"{}", 2.0)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_malformed_201_ack_is_retried_with_identical_single_inflight_body() -> None:
    outbox = BoundedOutbox()
    first = DeliveryItem("/v1/events/falco", b'{"stable":"first"}')
    second = DeliveryItem("/v1/events/falco", b'{"stable":"second"}')
    await outbox.admit_routine(first)
    await outbox.admit_routine(second)
    bodies: list[bytes] = []
    inflight: list[DeliveryItem | None] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(await request.aread())
        inflight.append(outbox.inflight)
        if len(bodies) == 1:
            return httpx.Response(201, content=b'{"event_id":"malformed"}')
        return httpx.Response(
            201,
            content=b'{"event_id":"evt_' + (b"a" * 64) + b'"}',
        )

    client = ObserverUDSClient(
        "/unused-in-test",
        transport=httpx.MockTransport(handler),
    )

    async def no_delay(_: float) -> None:
        return

    worker = DeliveryWorker(outbox, post=client.post, sleep=no_delay)
    try:
        assert await worker.deliver_next() is True
    finally:
        await client.close()

    assert bodies == [first.body, first.body]
    assert inflight == [first, first]
    assert outbox.inflight is None
    assert outbox.routine_pending == 1


@pytest.mark.asyncio
async def test_delivery_and_queue_pressure_are_closed_intervals_after_recovery() -> None:
    clock = MutableClock()
    runtime = AdapterRuntime(
        settings(),
        now=lambda: clock.wall,
        monotonic=lambda: clock.monotonic,
    )
    routine = DeliveryItem("/v1/events/falco", b'{"stable":"bytes"}')
    await runtime.outbox.admit_routine(routine)
    calls = 0

    async def fail_once(_: str, __: bytes, ___: float) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ReadTimeout("timeout")

    async def no_delay(_: float) -> None:
        return

    worker = DeliveryWorker(
        runtime.outbox,
        post=fail_once,
        sleep=no_delay,
        on_failure=runtime.delivery_failed,
        on_recovery=runtime.delivery_recovered,
    )
    assert await worker.deliver_next() is True
    coverage = await runtime.outbox.get()
    delivery_interval = json.loads(coverage.body)
    assert delivery_interval["kind"] == "falco_delivery_failure"
    assert delivery_interval["closed_at"] >= delivery_interval["opened_at"]
    await runtime.outbox.ack(coverage)

    runtime._started = True
    runtime._accepting = True
    for _ in range(1_025):
        await runtime.admit_raw(fixture_bytes("success.json"))
    queue_open = await runtime.outbox.get()
    opened = json.loads(queue_open.body)
    assert opened["kind"] == "falco_queue_drop"
    assert "closed_at" not in opened
    await runtime.outbox.ack(queue_open)
    delivered = await runtime.outbox.get()
    await runtime.outbox.ack(delivered)
    await runtime.delivery_recovered(delivered)
    queue_interval = json.loads((await runtime.outbox.get()).body)
    assert queue_interval["kind"] == "falco_queue_drop"
    assert queue_interval["closed_at"] >= queue_interval["opened_at"]


class MutableClock:
    def __init__(self) -> None:
        self.wall = dt.datetime(2026, 7, 27, 12, 0, tzinfo=dt.UTC)
        self.monotonic = 100.0

    def advance(self, seconds: float) -> None:
        self.wall += dt.timedelta(seconds=seconds)
        self.monotonic += seconds


async def eventually(predicate: Callable[[], bool], *, turns: int = 200) -> None:
    for _ in range(turns):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition was not reached")


@pytest.mark.asyncio
async def test_lifecycle_lease_and_parse_rejection_are_fail_closed_coverage() -> None:
    clock = MutableClock()
    delivered: list[FalcoAdapterCoverageInputV1] = []

    async def post(path: str, body: bytes, _: float) -> None:
        if path == "/v1/events/falco-coverage":
            delivered.append(FalcoAdapterCoverageInputV1.model_validate_json(body, strict=True))

    runtime = AdapterRuntime(
        settings(),
        now=lambda: clock.wall,
        monotonic=lambda: clock.monotonic,
        post=post,
    )
    await runtime.start()
    try:
        await eventually(lambda: len(delivered) >= 2)
        startup_gap, start = delivered[:2]
        assert startup_gap.kind == "falco_heartbeat_gap"
        assert startup_gap.opened_at == "2026-07-27T12:00:00Z"
        assert startup_gap.closed_at is None
        assert startup_gap.reason_code == "awaiting_initial_heartbeat"
        assert start.kind == "falco_adapter_start"
        assert start.opened_at == start.closed_at == "2026-07-27T12:00:00Z"

        first_rejected = b"[]"
        clock.advance(1)
        with pytest.raises(TypeError):
            await runtime.admit_raw(first_rejected)
        await eventually(
            lambda: len([item for item in delivered if item.kind == "falco_parse_rejection"]) == 1
        )

        second_rejected = b"{}"
        clock.advance(1)
        with pytest.raises(ValueError):
            await runtime.admit_raw(second_rejected)
        await eventually(
            lambda: len([item for item in delivered if item.kind == "falco_parse_rejection"]) == 2
        )
        parse_updates = [item for item in delivered if item.kind == "falco_parse_rejection"]
        assert parse_updates[0].opened_at == "2026-07-27T12:00:01Z"
        assert parse_updates[0].dropped_count == 1
        assert parse_updates[1].opened_at == parse_updates[0].opened_at
        assert parse_updates[1].dropped_count == 2
        assert parse_updates[1].source_payload_sha256 == hashlib.sha256(second_rejected).hexdigest()

        bad_hash = fixture_bytes("metrics-heartbeat-real.json").replace(
            CONFIG_SHA256.encode(),
            ("f" * 64).encode(),
        )
        clock.advance(1)
        await runtime.admit_raw(bad_hash)
        await eventually(
            lambda: any(item.kind == "falco_configuration_mismatch" for item in delivered)
        )
        assert len([item for item in delivered if item.kind == "falco_parse_rejection"]) == 2

        clock.advance(1)
        await runtime.admit_raw(fixture_bytes("metrics-heartbeat-real.json"))
        await eventually(
            lambda: any(
                item.kind == "falco_parse_rejection" and item.closed_at is not None
                for item in delivered
            )
        )
        parse_close = [
            item
            for item in delivered
            if item.kind == "falco_parse_rejection" and item.closed_at is not None
        ][-1]
        assert parse_close.opened_at == "2026-07-27T12:00:01Z"
        assert parse_close.closed_at == "2026-07-27T12:00:04Z"
        assert parse_close.dropped_count == 2
        assert parse_close.source_payload_sha256 == hashlib.sha256(second_rejected).hexdigest()

        leases = [item for item in delivered if item.kind == "falco_heartbeat_lease"]
        assert len(leases) == 1
        assert leases[0].opened_at == leases[0].closed_at == "2026-07-27T12:00:04Z"
        assert (
            leases[0].source_payload_sha256
            == hashlib.sha256(fixture_bytes("metrics-heartbeat-real.json")).hexdigest()
        )
    finally:
        await runtime.shutdown()

    stop = [item for item in delivered if item.kind == "falco_adapter_stop"][-1]
    assert stop.opened_at == stop.closed_at == "2026-07-27T12:00:04Z"


@pytest.mark.asyncio
async def test_heartbeat_windows_use_receipt_wall_and_rebase_cumulative_counters() -> None:
    clock = MutableClock()
    emitted: list[FalcoAdapterCoverageInputV1] = []

    async def emit(value: FalcoAdapterCoverageInputV1) -> None:
        emitted.append(value)

    watchdog = HeartbeatWatchdog(
        settings(),
        emit=emit,
        now=lambda: clock.wall,
        monotonic=lambda: clock.monotonic,
    )
    parsed = parse_falco_body(fixture_bytes("metrics-heartbeat-real.json"))
    assert isinstance(parsed, FalcoMetricsHeartbeat)
    parsed = parsed.model_copy(update={"event_time": "2026-07-27T11:00:04Z"})

    clock.advance(5)
    assert await watchdog.observe(parsed) is True

    clock.advance(5)
    first_drops = parsed.model_copy(
        update={
            "event_time": "2026-07-27T11:00:09Z",
            "outputs_queue_num_drops": 2,
            "scap_n_drops": 3,
        }
    )
    assert await watchdog.observe(first_drops) is True
    first_kernel = [
        item
        for item in emitted
        if item.kind == "falco_kernel_event_drop" and item.closed_at is None
    ][-1]
    first_output = [
        item
        for item in emitted
        if item.kind == "falco_outputs_queue_drop" and item.closed_at is None
    ][-1]
    assert first_kernel.opened_at == first_output.opened_at == "2026-07-27T12:00:05Z"
    assert first_kernel.dropped_count == 3
    assert first_output.dropped_count == 2

    clock.advance(5)
    more_drops = first_drops.model_copy(
        update={
            "event_time": "2026-07-27T11:00:14Z",
            "outputs_queue_num_drops": 5,
            "scap_n_drops": 7,
        }
    )
    assert await watchdog.observe(more_drops) is True
    assert [item for item in emitted if item.kind == "falco_kernel_event_drop"][
        -1
    ].dropped_count == 7
    assert [item for item in emitted if item.kind == "falco_outputs_queue_drop"][
        -1
    ].dropped_count == 5

    clock.advance(5)
    stable = more_drops.model_copy(update={"event_time": "2026-07-27T11:00:19Z"})
    assert await watchdog.observe(stable) is True
    kernel_close = [
        item
        for item in emitted
        if item.kind == "falco_kernel_event_drop" and item.closed_at is not None
    ][-1]
    output_close = [
        item
        for item in emitted
        if item.kind == "falco_outputs_queue_drop" and item.closed_at is not None
    ][-1]
    assert kernel_close.closed_at == output_close.closed_at == "2026-07-27T12:00:20Z"
    assert kernel_close.dropped_count == 7
    assert output_close.dropped_count == 5

    lease_count = len([item for item in emitted if item.kind == "falco_heartbeat_lease"])
    clock.advance(5)
    rollback = stable.model_copy(
        update={
            "event_time": "2026-07-27T11:00:24Z",
            "outputs_queue_num_drops": 1,
            "scap_n_drops": 2,
        }
    )
    assert await watchdog.observe(rollback) is False
    mismatch_open = [
        item
        for item in emitted
        if item.kind == "falco_configuration_mismatch" and item.closed_at is None
    ][-1]
    assert mismatch_open.opened_at == "2026-07-27T12:00:20Z"

    clock.advance(5)
    bad_hash = rollback.model_copy(
        update={
            "event_time": "2026-07-27T11:00:29Z",
            "config_sha256": "f" * 64,
        }
    )
    assert await watchdog.observe(bad_hash) is False
    assert len([item for item in emitted if item.kind == "falco_heartbeat_lease"]) == (lease_count)

    clock.advance(5)
    rebased = rollback.model_copy(update={"event_time": "2026-07-27T11:00:34Z"})
    assert await watchdog.observe(rebased) is True
    mismatch_close = [
        item
        for item in emitted
        if item.kind == "falco_configuration_mismatch" and item.closed_at is not None
    ][-1]
    assert mismatch_close.opened_at == "2026-07-27T12:00:20Z"
    assert mismatch_close.closed_at == "2026-07-27T12:00:35Z"
    leases = [item for item in emitted if item.kind == "falco_heartbeat_lease"]
    assert len(leases) == lease_count + 1
    assert all(item.opened_at == item.closed_at for item in leases)
    assert leases[-1].opened_at == "2026-07-27T12:00:35Z"

    gaps_before = len([item for item in emitted if item.kind == "falco_heartbeat_gap"])
    clock.advance(15)
    await watchdog.check()
    assert len([item for item in emitted if item.kind == "falco_heartbeat_gap"]) == gaps_before
    clock.advance(0.001)
    await watchdog.check()
    timeout = [item for item in emitted if item.kind == "falco_heartbeat_gap"][-1]
    assert timeout.opened_at == "2026-07-27T12:00:35Z"
    assert timeout.closed_at is None


def test_shutdown_uses_one_common_monotonic_five_second_deadline() -> None:
    clock = MutableClock()
    runtime = AdapterRuntime(
        settings(),
        now=lambda: clock.wall,
        monotonic=lambda: clock.monotonic,
    )
    first = runtime.begin_shutdown()
    clock.advance(3)
    second = runtime.begin_shutdown()
    assert first == 105.0
    assert second == first
    assert runtime.drain_deadline == first
