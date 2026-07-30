from __future__ import annotations

import asyncio
import inspect
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from typing import get_args, get_type_hints

import pytest
from agmind_immune import controller as controller_module
from agmind_immune.controller import (
    CoreController,
    CoreControllerAuthorityError,
    CoreRetentionResult,
    RetentionOutcome,
    RetentionRetryReason,
)
from agmind_immune.coverage import MutationReadiness

from tests.phase5b_helpers import boot_boundary, private_key
from tests.test_controller import _authorities, _Clock, _page, _Transport

_FIELDS = (
    "outcome",
    "retry_reason",
    "request_kind",
    "request_id",
    "target_sequence",
    "target_event_id",
    "target_content_sha256",
    "unlinked_manifest_count",
    "unlinked_bytes",
    "projected",
    "projection_rebuilt",
    "readiness",
)
_REQUEST_ID = "11111111-1111-4111-8111-111111111111"
_EVENT_ID = "evt_" + "1" * 64
_CONTENT_SHA256 = "2" * 64


def _readiness() -> MutationReadiness:
    return MutationReadiness(
        ready=False,
        reason_codes=("test_not_ready",),
        evidence_head=3,
        acceptance_cursor=3,
        confirmed_through=3,
        projection_cursor=3,
        observer_reconcile_generation=None,
        coverage_snapshot_sha256="3" * 64,
    )


def _observation(
    **changes: object,
) -> controller_module._RetentionObservation:
    baseline = controller_module._RetentionObservation(
        outcome="tombstone_completed",
        retry_reason=None,
        request_kind="tombstone",
        request_id=_REQUEST_ID,
        target_sequence=3,
        target_event_id=_EVENT_ID,
        target_content_sha256=_CONTENT_SHA256,
        unlinked_manifest_count=1,
        unlinked_bytes=17,
        projection_rebuilt=True,
    )
    return replace(baseline, **changes)


def _controller_for_execution(
    monkeypatch: pytest.MonkeyPatch,
    execution: object,
) -> CoreController:
    controller = object.__new__(CoreController)

    async def execute_once() -> object:
        return execution

    monkeypatch.setattr(controller, "_run_retention_once", execute_once)
    return controller


def test_public_retention_contract_is_exact_frozen_slotted_and_zero_argument(
) -> None:
    assert get_args(RetentionOutcome) == (
        "not_due",
        "blocked_unchanged",
        "retry_required",
        "blocked_reported",
        "tombstone_completed",
    )
    assert get_args(RetentionRetryReason) == (
        "pending_ack",
        "ack_prefix_lag",
        "observer_retryable",
    )
    assert tuple(field.name for field in fields(CoreRetentionResult)) == _FIELDS
    assert CoreRetentionResult.__slots__ == _FIELDS
    assert CoreRetentionResult.__dataclass_params__.frozen is True
    assert inspect.iscoroutinefunction(CoreController.run_retention_once)
    assert tuple(inspect.signature(CoreController.run_retention_once).parameters) == (
        "self",
    )
    assert inspect.signature(
        object.__new__(CoreController).run_retention_once
    ).parameters == {}
    assert (
        get_type_hints(CoreController.run_retention_once)["return"]
        is CoreRetentionResult
    )

    value = CoreRetentionResult(
        outcome="not_due",
        retry_reason=None,
        request_kind=None,
        request_id=None,
        target_sequence=None,
        target_event_id=None,
        target_content_sha256=None,
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projected=0,
        projection_rebuilt=False,
        readiness=_readiness(),
    )
    with pytest.raises(AttributeError):
        _ = value.__dict__
    with pytest.raises(FrozenInstanceError):
        value.projected = 1  # type: ignore[misc]


@pytest.mark.asyncio
async def test_public_retention_result_flattens_exact_private_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readiness = _readiness()
    observation = _observation()
    execution = controller_module._RetentionExecution(
        observation=observation,
        projected=11,
        readiness=readiness,
    )
    controller = _controller_for_execution(monkeypatch, execution)

    result = await controller.run_retention_once()

    assert type(result) is CoreRetentionResult
    assert result == CoreRetentionResult(
        outcome=observation.outcome,
        retry_reason=observation.retry_reason,
        request_kind=observation.request_kind,
        request_id=observation.request_id,
        target_sequence=observation.target_sequence,
        target_event_id=observation.target_event_id,
        target_content_sha256=observation.target_content_sha256,
        unlinked_manifest_count=observation.unlinked_manifest_count,
        unlinked_bytes=observation.unlinked_bytes,
        projected=11,
        projection_rebuilt=observation.projection_rebuilt,
        readiness=readiness,
    )
    assert result.readiness is readiness
    assert not hasattr(result, "observation")


_INVALID_OBSERVATIONS = (
    _observation(outcome="invalid"),
    _observation(retry_reason="invalid"),
    _observation(outcome="not_due"),
    _observation(retry_reason="pending_ack"),
    _observation(outcome="retry_required", retry_reason=None),
    _observation(request_kind="invalid"),
    _observation(request_kind=None),
    _observation(request_id=None),
    _observation(target_sequence=None),
    _observation(target_event_id=None),
    _observation(target_content_sha256=None),
    _observation(request_id="not-a-uuid"),
    _observation(target_sequence=True),
    _observation(target_sequence=0),
    _observation(target_sequence=controller_module.MAX_UINT64 + 1),
    _observation(target_event_id="evt_invalid"),
    _observation(target_content_sha256="A" * 64),
    _observation(unlinked_manifest_count=True),
    _observation(unlinked_manifest_count=-1),
    _observation(unlinked_manifest_count=0),
    _observation(unlinked_manifest_count=129),
    _observation(unlinked_bytes=True),
    _observation(unlinked_bytes=-1),
    _observation(unlinked_bytes=0),
    _observation(projection_rebuilt=1),
    _observation(projection_rebuilt=False),
    _observation(
        outcome="blocked_reported",
        request_kind="tombstone",
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
    _observation(
        outcome="retry_required",
        retry_reason="ack_prefix_lag",
        request_kind="blocked",
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
    _observation(
        outcome="retry_required",
        retry_reason="observer_retryable",
        request_kind=None,
        request_id=None,
        target_sequence=None,
        target_event_id=None,
        target_content_sha256=None,
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
)


@pytest.mark.parametrize("observation", _INVALID_OBSERVATIONS)
@pytest.mark.asyncio
async def test_public_retention_result_rejects_cross_field_conflicts(
    monkeypatch: pytest.MonkeyPatch,
    observation: controller_module._RetentionObservation,
) -> None:
    controller = _controller_for_execution(
        monkeypatch,
        controller_module._RetentionExecution(
            observation=observation,
            projected=0,
            readiness=_readiness(),
        ),
    )

    with pytest.raises(CoreControllerAuthorityError):
        await controller.run_retention_once()


_VALID_OBSERVATIONS = (
    _observation(
        outcome="not_due",
        request_kind=None,
        request_id=None,
        target_sequence=None,
        target_event_id=None,
        target_content_sha256=None,
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
    _observation(
        outcome="blocked_unchanged",
        request_kind="blocked",
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
    _observation(
        outcome="blocked_reported",
        request_kind="blocked",
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
    _observation(
        outcome="retry_required",
        retry_reason="pending_ack",
        request_kind=None,
        request_id=None,
        target_sequence=None,
        target_event_id=None,
        target_content_sha256=None,
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
    _observation(
        outcome="retry_required",
        retry_reason="pending_ack",
        request_kind="blocked",
        target_sequence=None,
        target_event_id=None,
        target_content_sha256=None,
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
    _observation(
        outcome="retry_required",
        retry_reason="pending_ack",
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
    _observation(
        outcome="retry_required",
        retry_reason="ack_prefix_lag",
        target_sequence=None,
        target_event_id=None,
        target_content_sha256=None,
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
    _observation(
        outcome="retry_required",
        retry_reason="observer_retryable",
        request_kind="blocked",
        target_sequence=None,
        target_event_id=None,
        target_content_sha256=None,
        unlinked_manifest_count=0,
        unlinked_bytes=0,
        projection_rebuilt=False,
    ),
    _observation(),
)


@pytest.mark.parametrize("observation", _VALID_OBSERVATIONS)
@pytest.mark.asyncio
async def test_public_retention_allows_exact_result_shapes(
    monkeypatch: pytest.MonkeyPatch,
    observation: controller_module._RetentionObservation,
) -> None:
    controller = _controller_for_execution(
        monkeypatch,
        controller_module._RetentionExecution(
            observation=observation,
            projected=0,
            readiness=_readiness(),
        ),
    )
    result = await controller.run_retention_once()
    assert result.outcome == observation.outcome
    assert result.retry_reason == observation.retry_reason


@pytest.mark.parametrize(
    ("projected", "readiness"),
    (
        (True, _readiness()),
        (-1, _readiness()),
        (controller_module.MAX_UINT64 + 1, _readiness()),
        (0, object()),
    ),
)
@pytest.mark.asyncio
async def test_public_retention_rejects_inexact_execution_values(
    monkeypatch: pytest.MonkeyPatch,
    projected: object,
    readiness: object,
) -> None:
    execution = controller_module._RetentionExecution(
        observation=_observation(),
        projected=projected,
        readiness=readiness,
    )
    controller = _controller_for_execution(monkeypatch, execution)
    with pytest.raises(CoreControllerAuthorityError):
        await controller.run_retention_once()


@pytest.mark.parametrize(
    "execution",
    (
        object(),
        controller_module._RetentionExecution(
            observation=object(),
            projected=0,
            readiness=_readiness(),
        ),
    ),
)
@pytest.mark.asyncio
async def test_public_retention_rejects_inexact_private_envelopes(
    monkeypatch: pytest.MonkeyPatch,
    execution: object,
) -> None:
    controller = _controller_for_execution(monkeypatch, execution)
    with pytest.raises(CoreControllerAuthorityError):
        await controller.run_retention_once()


@pytest.mark.asyncio
async def test_public_retention_preserves_private_failure_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = object.__new__(CoreController)
    failure = RuntimeError("exact private failure")
    calls = 0

    async def fail_once() -> object:
        nonlocal calls
        calls += 1
        raise failure

    monkeypatch.setattr(controller, "_run_retention_once", fail_once)
    with pytest.raises(RuntimeError) as captured:
        await controller.run_retention_once()
    assert captured.value is failure
    assert calls == 1


class _ObservedTransport(_Transport):
    def __init__(self) -> None:
        super().__init__([_page(acked=1, reserved=1)])
        self.fetch_calls = 0
        self.close_calls = 0

    async def fetch_events(self, *, after: int, limit: int) -> bytes:
        self.fetch_calls += 1
        return await super().fetch_events(after=after, limit=limit)

    async def close(self) -> None:
        self.close_calls += 1


@pytest.mark.parametrize("contender_kind", ("poll", "retention", "close"))
@pytest.mark.asyncio
async def test_public_retention_serializes_controller_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contender_kind: str,
) -> None:
    key = private_key(11)
    acceptance, _store, journal, coverage, projection, _refs = _authorities(
        tmp_path / contender_kind,
        boot_boundary(key),
    )
    transport = _ObservedTransport()
    controller = CoreController.create(
        acceptance,
        journal,
        coverage,
        projection,
        transport,
        _Clock(),
    )
    entered = asyncio.Event()
    release = asyncio.Event()
    queued = asyncio.Event()
    execution_calls = 0

    async def gated_execution(
        *,
        _lock_authority: object,
    ) -> controller_module._RetentionObservation:
        nonlocal execution_calls
        del _lock_authority
        execution_calls += 1
        entered.set()
        if execution_calls == 1:
            await release.wait()
        return controller_module._RetentionObservation(
            outcome="not_due",
            retry_reason=None,
            request_kind=None,
            request_id=None,
            target_sequence=None,
            target_event_id=None,
            target_content_sha256=None,
            unlinked_manifest_count=0,
            unlinked_bytes=0,
            projection_rebuilt=False,
        )

    monkeypatch.setattr(
        controller,
        "_execute_retention_locked",
        gated_execution,
    )

    first = asyncio.create_task(controller.run_retention_once())
    contender: asyncio.Task[object] | None = None
    try:
        await entered.wait()

        async def contend() -> object:
            queued.set()
            if contender_kind == "poll":
                return await controller.poll_once()
            if contender_kind == "retention":
                return await controller.run_retention_once()
            await controller.close()
            return None

        contender = asyncio.create_task(contend())
        await queued.wait()
        await asyncio.sleep(0)
        assert execution_calls == 1
        assert transport.fetch_calls == 0
        assert transport.close_calls == 0

        release.set()
        first_result = await first
        assert first_result.outcome == "not_due"
        await contender
        if contender_kind == "poll":
            assert transport.fetch_calls == 1
            assert execution_calls == 1
        elif contender_kind == "retention":
            assert execution_calls == 2
        else:
            assert transport.close_calls == 1
    finally:
        release.set()
        if not first.done():
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
        if contender is not None and not contender.done():
            contender.cancel()
            with pytest.raises(asyncio.CancelledError):
                await contender
        if contender_kind != "close":
            await controller.close()
