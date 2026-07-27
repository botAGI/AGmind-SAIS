"""
Agent Core — оркестратор AGmind-SAIS.
Цикл: collect_data -> analyze -> react -> alert.
Не использует LangGraph (как AiSOC). Обычный asyncio-цикл.
"""

from __future__ import annotations
import asyncio
import logging
import time
from typing import Optional

from app.ml_client.base import MLClient
from app.core.analyzer import SecurityAnalyzer
from app.core.schemas import AggregateAnalysis
from app.monitoring.collector import DataCollector
from app.reactor.engine import ReactorEngine
from app.core.alerts import Alerter

logger = logging.getLogger("sais.agent")


class SecurityAgent:
    """
    Главный агент безопасности.
    Управляет циклом: сбор данных -> LLM-анализ -> реактор -> алерты.
    """

    def __init__(
        self,
        config: dict,
        ml_client: MLClient,
        analyzer: SecurityAnalyzer,
        collector: DataCollector,
        reactor: ReactorEngine,
        alerter: Alerter,
    ):
        self.config = config
        self.ml_client = ml_client
        self.analyzer = analyzer
        self.collector = collector
        self.reactor = reactor
        self.alerter = alerter

        self.running = False
        self._cycle_count = 0
        self._last_analysis_time: Optional[float] = None
        self._last_result: Optional[AggregateAnalysis] = None
        self._cycle_interval = config.get("agent", {}).get("cycle_interval", 60)

    async def start(self):
        """Запуск основного цикла."""
        self.running = True
        logger.info("Agent core started, interval=%ds", self._cycle_interval)

        while self.running:
            self._cycle_count += 1
            cycle = self._cycle_count
            logger.info("[Cycle %d] Starting", cycle)

            start = time.time()
            try:
                await self._run_cycle(cycle)
            except Exception as e:
                logger.error("[Cycle %d] Fatal error: %s", cycle, e, exc_info=True)

            elapsed = time.time() - start
            logger.info("[Cycle %d] Completed in %.1fs", cycle, elapsed)

            self._last_analysis_time = time.time()

            # Ожидание до следующего цикла (с учётом времени выполнения)
            wait = max(1, self._cycle_interval - int(elapsed))
            await asyncio.sleep(wait)

    async def stop(self):
        """Остановка."""
        self.running = False
        logger.info("Agent core stopped")

    async def _run_cycle(self, cycle_id: int):
        """Один цикл: сбор -> анализ -> реакция -> алерт."""
        # 1. Сбор данных
        snapshot = await self.collector.get_live_snapshot()

        if not snapshot["system"] and not snapshot["network"] and not snapshot["logs"]["recent"]:
            logger.debug("[Cycle %d] No data collected, skipping", cycle_id)
            return

        # 2. Анализ через LLM (агрегированный)
        log_lines = [e["content"] for e in snapshot["logs"].get("recent", [])]
        result = await self.analyzer.analyze_aggregate(
            system_data=snapshot["system"],
            network_data=snapshot["network"],
            log_data=snapshot["logs"],
            log_lines=log_lines,
        )

        if result is None:
            logger.warning("[Cycle %d] Analysis returned None", cycle_id)
            return

        self._last_result = result

        sev_map = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        sev = sev_map.get(result.overall_severity.value if hasattr(result.overall_severity, 'value') else str(result.overall_severity), 1)
        logger.info(
            "[Cycle %d] Analysis: severity=%s, risk=%.2f, attention=%s",
            cycle_id, result.overall_severity, result.overall_risk_score,
            result.requires_immediate_attention,
        )

        # 3. Реактор (только если есть угрозы выше INFO)
        threshold = self.config.get("monitoring", {}).get("threat_analysis", {}).get("severity_threshold", 3)
        if sev >= threshold:
            await self.reactor.respond(result)

        # 4. Алерты (только если есть угрозы)
        if sev >= threshold:
            await self.alerter.send(result)

    async def chat(self, user_message: str) -> str:
        """Прямой чат с ML-ядром."""
        context = ""
        if self._last_result:
            context = f"Последний анализ: severity={self._last_result.overall_severity}, summary={self._last_result.logs.summary[:200]}"

        messages = [
            {"role": "system", "content": self.config.get("agent", {}).get("system_prompt_file", "Ты — КиберБезОпасович.")},
        ]
        if context:
            messages.append({"role": "system", "content": context})
        messages.append({"role": "user", "content": user_message})

        return await self.ml_client.chat(messages)

    async def get_status(self) -> dict:
        """Статус агента."""
        ml_healthy = False
        try:
            ml_healthy = await self.ml_client.check_health()
        except Exception:
            pass

        return {
            "running": self.running,
            "cycles": self._cycle_count,
            "last_analysis": self._last_analysis_time,
            "last_severity": str(self._last_result.overall_severity) if self._last_result else None,
            "ml_healthy": ml_healthy,
            "ml_provider": self.config["ml"]["provider"],
            "ml_model": self.config["ml"]["model"],
        }
