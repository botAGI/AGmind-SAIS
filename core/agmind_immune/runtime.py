"""Single-owner production loop for deterministic containment preparation."""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass

from agmind_immune.actions import (
    ActuatorIntentClient,
    ActuatorJournalClient,
    ActuatorJournalRetryable,
    ActuatorMirror,
    ActuatorMirrorFatal,
    DecisionIntentCommit,
    IntentDeliveryRetryable,
    IntentDeliveryStateMachine,
    QuarantinedIntentReceipt,
)
from agmind_immune.contracts import ActionRecordV1
from agmind_immune.controller import CoreController
from agmind_immune.hunter import (
    HunterClient,
    HunterInvestigationEquivocation,
    HunterInvestigationRecord,
    HunterInvestigationStore,
    HunterInvestigationStoreError,
    HunterResult,
)
from agmind_immune.incidents.admission import CandidateAdmissionError
from agmind_immune.ingest.service import DeliveryRetryableError
from agmind_immune.policy import PolicyClient, PolicyError

_LOG = logging.getLogger("agmind_immune.runtime")
_CANDIDATE_PAGE = 16
_HUNTER_RECOVERY_BATCH = 16
_MAX_HUNTER_SCHEDULED = 65_536
_RETENTION_INTERVAL_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class CoreRuntimeStatus:
    polls: int
    policy_commits: int
    prepared_plans: int
    quarantined_intents: int
    last_hunter_status: str | None
    hunter_persistence_status: str
    actuator_feedback_status: str
    actuator_journal_records: int
    action_records: int


class CoreRuntime:
    """Drive evidence, policy and preparation; the Hunter stays read-only."""

    def __init__(
        self,
        controller: CoreController,
        policy: PolicyClient,
        delivery: IntentDeliveryStateMachine,
        actuator: ActuatorIntentClient,
        actuator_journal: ActuatorJournalClient,
        actuator_mirror: ActuatorMirror,
        *,
        hunter: HunterClient | None = None,
        hunter_investigations: HunterInvestigationStore | None = None,
    ) -> None:
        if (
            type(controller) is not CoreController
            or type(policy) is not PolicyClient
            or type(delivery) is not IntentDeliveryStateMachine
            or type(actuator) is not ActuatorIntentClient
            or type(actuator_journal) is not ActuatorJournalClient
            or type(actuator_mirror) is not ActuatorMirror
            or delivery._client is not actuator
            or actuator_mirror._client is not actuator_journal
            or (hunter is not None and type(hunter) is not HunterClient)
            or (
                hunter_investigations is not None
                and type(hunter_investigations) is not HunterInvestigationStore
            )
        ):
            raise TypeError("Core runtime authorities are not exact")
        self._controller = controller
        self._policy = policy
        self._delivery = delivery
        self._actuator = actuator
        self._actuator_journal = actuator_journal
        self._actuator_mirror = actuator_mirror
        self._hunter = hunter
        self._hunter_investigations = hunter_investigations
        self._hunter_tasks: dict[asyncio.Task[HunterResult], str] = {}
        self._hunter_scheduled: set[str] = set()
        self._hunter_schedule_full = False
        self._commits: dict[str, DecisionIntentCommit] = {}
        self._prepared: set[str] = set()
        self._quarantined: set[str] = set()
        self._delivery_queue: deque[str] = deque()
        self._delivery_queued: set[str] = set()
        self._candidate_after: str | None = None
        self._polls = 0
        self._policy_commits = 0
        self._prepared_plans = 0
        self._next_retention_at: float | None = None
        self._last_hunter_status: str | None = None
        self._hunter_persistence_status = (
            "ready" if hunter_investigations is not None else "unavailable"
        )
        self._actuator_feedback_status = "unverified"
        self._actuator_feedback_ready = False
        self._closed = False

    @property
    def status(self) -> CoreRuntimeStatus:
        return CoreRuntimeStatus(
            polls=self._polls,
            policy_commits=self._policy_commits,
            prepared_plans=self._prepared_plans,
            quarantined_intents=len(self._quarantined),
            last_hunter_status=self._last_hunter_status,
            hunter_persistence_status=self._hunter_persistence_status,
            actuator_feedback_status=self._actuator_feedback_status,
            actuator_journal_records=self._actuator_mirror.snapshot().record_count,
            action_records=len(self._actuator_mirror.snapshot().action_records),
        )

    def action_records(
        self,
        *,
        after: int,
        limit: int,
    ) -> tuple[ActionRecordV1, ...]:
        return self._actuator_mirror.action_records(after=after, limit=limit)

    def latest_action(self, action_id: str) -> ActionRecordV1 | None:
        return self._actuator_mirror.latest_for_action(action_id)

    def hunter_investigation(
        self,
        candidate_id: str,
    ) -> HunterInvestigationRecord | None:
        store = self._hunter_investigations
        if store is None:
            raise HunterInvestigationStoreError("Hunter persistence is unavailable")
        return store.get(candidate_id)

    def hunter_investigations(
        self,
        *,
        after: str | None,
        limit: int,
    ) -> tuple[HunterInvestigationRecord, ...]:
        store = self._hunter_investigations
        if store is None:
            raise HunterInvestigationStoreError("Hunter persistence is unavailable")
        return store.page(after=after, limit=limit)

    @property
    def ready(self) -> bool:
        if (
            self._closed
            or self._polls <= 0
            or self._delivery.read_only
            or not self._actuator_feedback_ready
            or self._actuator_mirror.read_only
        ):
            return False
        try:
            return self._controller.mutation_readiness().ready is True
        except Exception:  # noqa: BLE001 - readiness must fail closed
            return False

    async def _refresh_commits(self) -> None:
        records = await self._controller.decision_intent_commits()
        hunter_recovered = 0
        for record in records:
            prior = self._commits.get(record.candidate_id)
            if prior is not None and prior != record:
                raise RuntimeError("durable candidate decision changed")
            self._commits[record.candidate_id] = record

            if (
                self._hunter is not None
                and self._hunter_investigations is not None
                and record.candidate_id not in self._hunter_scheduled
            ):
                try:
                    existing_investigation = self._hunter_investigations.get(
                        record.candidate_id
                    )
                except HunterInvestigationStoreError as error:
                    self._reserve_hunter_candidate(record.candidate_id)
                    self._hunter_persistence_status = "unavailable"
                    _LOG.warning(
                        "hunter recovery lookup failed outside authority: "
                        "candidate=%s error=%s",
                        record.candidate_id,
                        error,
                    )
                except Exception as error:  # noqa: BLE001 - enrichment is isolated
                    self._reserve_hunter_candidate(record.candidate_id)
                    self._hunter_persistence_status = "unavailable"
                    _LOG.exception(
                        "hunter recovery lookup crashed outside authority: "
                        "candidate=%s error=%s",
                        record.candidate_id,
                        error,
                    )
                else:
                    if existing_investigation is not None:
                        self._reserve_hunter_candidate(record.candidate_id)
                    elif hunter_recovered < _HUNTER_RECOVERY_BATCH:
                        await self._enqueue_hunter(record.candidate_id)
                        hunter_recovered += 1

            if (
                record.effect == "manual_approval_required"
                and record.candidate_id not in self._prepared
                and record.candidate_id not in self._quarantined
                and record.candidate_id not in self._delivery_queued
            ):
                self._delivery_queue.append(record.candidate_id)
                self._delivery_queued.add(record.candidate_id)

    def _reserve_hunter_candidate(self, candidate_id: str) -> bool:
        if candidate_id in self._hunter_scheduled:
            return False
        if len(self._hunter_scheduled) >= _MAX_HUNTER_SCHEDULED:
            self._hunter_persistence_status = "schedule_full"
            if not self._hunter_schedule_full:
                self._hunter_schedule_full = True
                _LOG.error("hunter scheduling bound reached outside authority")
            return False
        self._hunter_scheduled.add(candidate_id)
        return True

    async def _deliver(self, commit: DecisionIntentCommit) -> bool:
        if commit.effect != "manual_approval_required" or commit.candidate_id in self._prepared:
            return True
        if not self._actuator_feedback_ready or self._actuator_mirror.read_only:
            return False
        try:
            outcome = await self._delivery.deliver(commit)
        except IntentDeliveryRetryable as error:
            _LOG.warning("actuator preparation retryable: %s", error)
            return False
        if type(outcome) is QuarantinedIntentReceipt:
            self._quarantined.add(commit.candidate_id)
            _LOG.error(
                "actuator preparation terminally quarantined: candidate=%s reason=%s",
                commit.candidate_id,
                outcome.reason_code,
            )
            return True
        self._prepared.add(commit.candidate_id)
        self._prepared_plans += 1
        return True

    async def _sync_actuator_feedback(self) -> bool:
        if self._actuator_mirror.read_only:
            self._actuator_feedback_ready = False
            self._actuator_feedback_status = "fatal"
            return False
        try:
            await self._actuator_mirror.sync_once()
        except ActuatorJournalRetryable as error:
            self._actuator_feedback_ready = False
            self._actuator_feedback_status = "unavailable"
            _LOG.warning("actuator feedback retryable: %s", error)
            return False
        except ActuatorMirrorFatal as error:
            self._actuator_feedback_ready = False
            self._actuator_feedback_status = "fatal"
            _LOG.error("actuator feedback verification failed: %s", error)
            return False
        self._actuator_feedback_ready = True
        self._actuator_feedback_status = "verified"
        return True

    async def _retry_durable_deliveries(self) -> None:
        for _ in range(min(len(self._delivery_queue), 4)):
            candidate_id = self._delivery_queue.popleft()
            self._delivery_queued.discard(candidate_id)
            commit = self._commits[candidate_id]
            if not await self._deliver(commit):
                self._delivery_queue.append(candidate_id)
                self._delivery_queued.add(candidate_id)

    def _hunter_done(self, task: asyncio.Task[HunterResult]) -> None:
        candidate_id = self._hunter_tasks.pop(task, None)
        if candidate_id is None:
            _LOG.error("hunter task lost its candidate binding outside authority")
            self._hunter_persistence_status = "unavailable"
            return
        if task.cancelled():
            return
        try:
            result = task.result()
        except Exception as error:  # noqa: BLE001 - model cannot affect authority
            _LOG.warning("hunter task failed outside authority: %s", error)
            self._last_hunter_status = "unavailable"
            return
        self._last_hunter_status = result.status
        store = self._hunter_investigations
        if store is None:
            _LOG.warning(
                "hunter terminal result is not durable outside authority: candidate=%s",
                candidate_id,
            )
            self._hunter_persistence_status = "unavailable"
            return
        try:
            store.persist(candidate_id, result)
        except HunterInvestigationEquivocation as error:
            _LOG.error(
                "hunter result equivocation rejected outside authority: candidate=%s error=%s",
                candidate_id,
                error,
            )
            self._hunter_persistence_status = "equivocation"
        except HunterInvestigationStoreError as error:
            _LOG.warning(
                "hunter result persistence failed outside authority: candidate=%s error=%s",
                candidate_id,
                error,
            )
            self._hunter_persistence_status = "unavailable"
        except Exception as error:  # noqa: BLE001 - enrichment cannot affect authority
            _LOG.exception(
                "hunter persistence crashed outside authority: candidate=%s error=%s",
                candidate_id,
                error,
            )
            self._hunter_persistence_status = "unavailable"
        else:
            self._hunter_persistence_status = "durable"

    async def _enqueue_hunter(self, candidate_id: str) -> None:
        hunter = self._hunter
        if (
            hunter is None
            or self._hunter_investigations is None
            or not self._reserve_hunter_candidate(candidate_id)
        ):
            return
        try:
            bundle = await self._controller.hunter_bundle(candidate_id)
        except Exception as error:  # noqa: BLE001 - enrichment is non-authoritative
            _LOG.warning("hunter bundle unavailable outside authority: %s", error)
            self._last_hunter_status = "unavailable"
            return
        task = asyncio.create_task(
            hunter.investigate(bundle),
            name=f"agmind-hunter-{candidate_id[-12:]}",
        )
        self._hunter_tasks[task] = candidate_id
        task.add_done_callback(self._hunter_done)

    async def _process_candidate(self, candidate_id: str) -> None:
        if candidate_id in self._commits:
            return
        try:
            view = await self._controller.issue_candidate_admission(candidate_id)
            evaluation = await self._policy.evaluate(view)
            commit = await self._controller.commit_policy_evaluation(view, evaluation)
        except (CandidateAdmissionError, PolicyError) as error:
            _LOG.warning("candidate denied or deferred: %s", error)
            return
        self._commits[candidate_id] = commit
        self._policy_commits += 1
        if not await self._deliver(commit):
            self._delivery_queue.append(candidate_id)
            self._delivery_queued.add(candidate_id)
        await self._enqueue_hunter(candidate_id)

    async def _run_retention_if_due(self) -> None:
        now = asyncio.get_running_loop().time()
        deadline = self._next_retention_at
        if deadline is None:
            self._next_retention_at = now + _RETENTION_INTERVAL_SECONDS
            return
        if now < deadline:
            return
        self._next_retention_at = now + _RETENTION_INTERVAL_SECONDS
        try:
            result = await self._controller.run_retention_once()
        finally:
            self._next_retention_at = (
                asyncio.get_running_loop().time() + _RETENTION_INTERVAL_SECONDS
            )
        if result.outcome != "not_due":
            _LOG.info("retention outcome: %s", result.outcome)

    async def tick(self) -> None:
        if self._closed:
            raise RuntimeError("Core runtime is closed")
        await self._refresh_commits()
        await self._sync_actuator_feedback()
        await self._retry_durable_deliveries()
        await self._run_retention_if_due()
        try:
            await self._controller.poll_once()
        except DeliveryRetryableError as error:
            _LOG.warning("observer poll retryable: %s", error)
            return
        self._polls += 1
        candidates = await self._controller.candidate_ids(
            after=self._candidate_after,
            limit=_CANDIDATE_PAGE,
        )
        if not candidates:
            self._candidate_after = None
            return
        self._candidate_after = (
            None if len(candidates) < _CANDIDATE_PAGE else candidates[-1]
        )
        for candidate_id in candidates:
            await self._process_candidate(candidate_id)

    async def run(
        self,
        stop: asyncio.Event,
        *,
        interval_seconds: float = 0.25,
    ) -> None:
        if type(stop) is not asyncio.Event or type(interval_seconds) is not float or not 0 < interval_seconds <= 5:
            raise ValueError("Core runtime loop arguments are invalid")
        while not stop.is_set():
            await self.tick()
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
            except TimeoutError:
                pass

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        tasks = tuple(self._hunter_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        primary: BaseException | None = None
        steps = [
            self._delivery.close,
            self._actuator.close,
            self._actuator_journal.close,
            self._policy.close,
        ]
        if self._hunter is not None:
            steps.append(self._hunter.close)
        steps.append(self._controller.close)
        for step in steps:
            try:
                await step()
            except BaseException as error:  # noqa: BLE001 - close every authority
                if primary is None:
                    primary = error
                else:
                    primary.add_note(
                        f"secondary Core runtime close failure ({type(error).__name__})"
                    )
        try:
            self._actuator_mirror.close()
        except BaseException as error:  # noqa: BLE001 - close every authority
            if primary is None:
                primary = error
            else:
                primary.add_note(
                    f"secondary actuator mirror close failure ({type(error).__name__})"
                )
        if self._hunter_investigations is not None:
            try:
                self._hunter_investigations.close()
            except BaseException as error:  # noqa: BLE001 - close every authority
                if primary is None:
                    primary = error
                else:
                    primary.add_note(
                        "secondary Hunter persistence close failure "
                        f"({type(error).__name__})"
                    )
        if primary is not None:
            raise primary


__all__ = ["CoreRuntime", "CoreRuntimeStatus"]
