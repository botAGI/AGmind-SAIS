"""Production entrypoint for the single-host AGmind Core runtime."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from agmind_immune.actions import ActuatorIntentClient, IntentDeliveryStateMachine
from agmind_immune.clock import CoreClockSample
from agmind_immune.config import (
    CORE_CONFIG_PATH,
    SPECIAL_USE_REGISTRY_PATH,
    CoreConfigV1,
    load_core_config,
    load_hunter_config,
)
from agmind_immune.controller import CoreController
from agmind_immune.correlation.primitives import load_pinned_special_use_registry
from agmind_immune.coverage import CoverageState
from agmind_immune.evidence.projection import ProjectionStore
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.health import HealthServer
from agmind_immune.hunter import (
    HunterClient,
    HunterInvestigationStore,
    HunterInvestigationStoreError,
)
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeVerifier,
    PinnedObserverRoot,
)
from agmind_immune.ingest.service import (
    AcceptanceCoordinator,
    HTTPXObserverCoreTransport,
)
from agmind_immune.policy import PolicyClient
from agmind_immune.runtime import CoreRuntime

_LOG = logging.getLogger("agmind_immune.main")


class _SystemCoreClock:
    """Conservative M1 clock adapter; one second of uncertainty is admitted."""

    def __init__(self) -> None:
        self._last_utc = datetime.now(UTC)
        self._last_monotonic = time.monotonic()

    def live_receipt_monotonic(self) -> float:
        return time.monotonic()

    def decision_sample(self) -> CoreClockSample:
        now_utc = datetime.now(UTC)
        now_monotonic = time.monotonic()
        wall_delta = Decimal(str((now_utc - self._last_utc).total_seconds()))
        monotonic_delta = Decimal(str(now_monotonic - self._last_monotonic))
        healthy = (
            monotonic_delta >= 0
            and wall_delta >= 0
            and abs(wall_delta - monotonic_delta) <= Decimal(1)
        )
        if healthy:
            self._last_utc = now_utc
            self._last_monotonic = now_monotonic
        return CoreClockSample(
            decision_utc=now_utc,
            decision_monotonic=now_monotonic,
            healthy=healthy,
            uncertainty_seconds=Decimal(1),
            max_uncertainty_seconds=Decimal(1),
        )


async def _open_runtime(config: CoreConfigV1) -> CoreRuntime:
    store: SegmentStore | None = None
    acknowledgements: AckJournal | None = None
    correlation: CorrelationRequestJournal | None = None
    coverage: CoverageState | None = None
    projection: ProjectionStore | None = None
    controller: CoreController | None = None
    policy: PolicyClient | None = None
    actuator: ActuatorIntentClient | None = None
    delivery: IntentDeliveryStateMachine | None = None
    hunter: HunterClient | None = None
    hunter_investigations: HunterInvestigationStore | None = None
    transport: HTTPXObserverCoreTransport | None = None
    try:
        root = PinnedObserverRoot.load(Path(config.observer_trust_root_file))
        transport = HTTPXObserverCoreTransport(Path(config.observer_socket))
        public_keys = await transport.fetch_public_keys()
        verifier = EnvelopeVerifier(
            root,
            AnchoredPublicKeyChain.from_value(root, public_keys),
        )
        store = SegmentStore(Path(config.evidence_dir))
        acceptance = AcceptanceCoordinator.open_and_recover(verifier, store)
        acknowledgements = (
            AckJournal.create_new(store)
            if store._ack_journal_state == "fresh"
            else AckJournal.open_and_recover(store)
        )
        correlation = (
            CorrelationRequestJournal.create_new(store)
            if store._correlation_journal_state == "fresh"
            else CorrelationRequestJournal.open_and_recover(store)
        )
        registry = load_pinned_special_use_registry(SPECIAL_USE_REGISTRY_PATH)
        coverage = CoverageState.open_and_recover(store)
        projection = ProjectionStore.open(
            Path(config.projection_db),
            evidence=store,
            acknowledgements=acknowledgements,
            correlation_requests=correlation,
            registry=registry,
        )
        clock = _SystemCoreClock()
        controller = CoreController.create(
            acceptance,
            acknowledgements,
            correlation,
            registry,
            coverage,
            projection,
            transport,
            clock,
        )
        transport = None
        policy = PolicyClient.create(clock)
        actuator = ActuatorIntentClient.create(Path(config.actuator_socket))
        delivery = IntentDeliveryStateMachine.open(
            config.intent_delivery_db,
            actuator,
        )
        try:
            hunter_investigations = HunterInvestigationStore.open(
                config.hunter_investigations_db
            )
        except HunterInvestigationStoreError as error:
            _LOG.warning("hunter persistence disabled outside authority: %s", error)
        if config.hunter_config_file is not None and hunter_investigations is None:
            _LOG.warning(
                "hunter disabled because durable persistence is unavailable outside authority"
            )
        elif config.hunter_config_file is not None:
            try:
                hunter = HunterClient.create(
                    load_hunter_config(Path(config.hunter_config_file))
                )
            except (ValueError, RuntimeError) as error:
                _LOG.warning("hunter disabled during bootstrap: %s", error)
        return CoreRuntime(
            controller,
            policy,
            delivery,
            actuator,
            hunter=hunter,
            hunter_investigations=hunter_investigations,
        )
    except BaseException as primary:
        async_steps = []
        if hunter is not None:
            async_steps.append(hunter.close)
        if delivery is not None:
            async_steps.append(delivery.close)
        if actuator is not None:
            async_steps.append(actuator.close)
        if policy is not None:
            async_steps.append(policy.close)
        if controller is not None:
            async_steps.append(controller.close)
        elif transport is not None:
            async_steps.append(transport.close)
        for step in async_steps:
            try:
                await step()
            except BaseException as cleanup_error:  # noqa: BLE001 - preserve primary
                primary.add_note(
                    f"secondary Core bootstrap cleanup failure ({type(cleanup_error).__name__})"
                )
        if hunter_investigations is not None:
            try:
                hunter_investigations.close()
            except BaseException as cleanup_error:  # noqa: BLE001 - preserve primary
                primary.add_note(
                    "secondary Hunter persistence cleanup failure "
                    f"({type(cleanup_error).__name__})"
                )
        if controller is None:
            for resource in (projection, coverage, correlation, acknowledgements, store):
                if resource is None:
                    continue
                try:
                    resource.close()
                except BaseException as cleanup_error:  # noqa: BLE001 - close all
                    primary.add_note(
                        "secondary Core authority cleanup failure "
                        f"({type(cleanup_error).__name__})"
                    )
        raise


async def _serve(config_path: Path) -> None:
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("agmind-core requires Linux and a non-root service user")
    config = load_core_config(config_path)
    runtime = await _open_runtime(config)
    health = HealthServer(lambda: runtime.ready)
    try:
        await health.start(config.api_bind_host, config.api_bind_port)
    except BaseException as bind_error:
        try:
            await runtime.close()
        except BaseException as cleanup_error:  # noqa: BLE001 - preserve bind failure
            bind_error.add_note(
                f"secondary Core close failure ({type(cleanup_error).__name__})"
            )
        raise
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for selected in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(selected, stop.set)
    try:
        await runtime.run(stop)
    finally:
        shutdown_error: BaseException | None = None
        try:
            await health.close()
        except BaseException as error:  # noqa: BLE001 - close both owners
            shutdown_error = error
        try:
            await runtime.close()
        except BaseException as error:  # noqa: BLE001 - close both owners
            if shutdown_error is None:
                shutdown_error = error
            else:
                shutdown_error.add_note(
                    f"secondary Core close failure ({type(error).__name__})"
                )
        if shutdown_error is not None:
            raise shutdown_error


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="agmind-core")
    parser.add_argument("--config", type=Path, default=CORE_CONFIG_PATH)
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    arguments = _arguments()
    try:
        asyncio.run(_serve(arguments.config))
    except KeyboardInterrupt:
        _LOG.info("shutdown interrupted")


if __name__ == "__main__":
    main()
