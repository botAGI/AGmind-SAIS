"""
Reactor Engine — модуль реагирования на угрозы.
Использует confidence bands из AiSOC: ≥0.80 True Positive, ≥0.60 Likely TP, ≥0.40 Needs Review, <0.40 Likely Benign.
Deterministic pre-scoring (pure functions, без LLM).
"""

from __future__ import annotations
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from app.core.schemas import (
    SystemAnalysis,
    NetworkAnalysis,
    LogAnalysis,
    SeverityLevel,
)

logger = logging.getLogger("sais.reactor")

# Confidence bands из AiSOC scoring.py
_CONF_FLOOR = 0.05
_CONF_CEIL = 0.95

# Пороги вердиктов (как в AiSOC)
VERDICT_BANDS = [
    (0.80, "true_positive"),
    (0.60, "likely_true_positive"),
    (0.40, "needs_review"),
]

# Критические ключевые слова (из AiSOC scoring.py)
_CRITICAL_KEYWORDS = [
    "ransomware", "lateral movement", "credential dump", "exfiltration",
    "mimikatz", "cobalt strike", "c2", "rootkit", "supply chain",
    "zero-day", "data breach",
]

_HIGH_KEYWORDS = [
    "phishing", "malware", "exploit", "privilege escalation",
    "brute force", "suspicious login", "anomaly", "backdoor",
]

_SUSPICIOUS_PORTS = {22, 23, 3389, 5900, 4444, 6667, 1337, 4443, 8443, 9090, 31337, 44445}


class ReactorEngine:
    """
    Движок реагирования.
    Deterministic pre-scoring (как AiSOC) + LLM confidence для финального вердикта.
    """

    # Cooldown между действиями на одну сущность
    _cooldowns: dict[str, float] = {}

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("reactor", {}).get("enabled", False)
        self.auto_mode = config.get("reactor", {}).get("auto_mode", False)
        self._actions_taken = 0
        self._actions_blocked = 0

    async def respond(self, result) -> list[dict]:
        """
        Принять решение на основе анализа.
        Использует confidence_score из Pydantic-схемы (от LLM).
        """
        if not self.enabled:
            return []

        actions_taken = []
        verdict, basis, details = self._score_and_verdict(result)

        if verdict == "true_positive" and self.auto_mode:
            action = self._auto_respond(details)
            if action:
                actions_taken.append(action)
        elif verdict in ("likely_true_positive", "needs_review"):
            logger.info("Verdict %s requires review: %s", verdict, basis)
            self._actions_blocked += 1

        self._actions_taken += len(actions_taken)
        return actions_taken

    def _score_and_verdict(self, result) -> tuple[str, list[str], dict]:
        """
        Детерминированный pre-scoring (как AiSOC).
        Возвращает (verdict, basis, details).
        """
        basis: list[str] = []
        weight = _CONF_FLOOR
        details = {}

        # 1. Severity из анализа
        if hasattr(result, 'overall_risk_score') and result.overall_risk_score:
            weight += min(float(result.overall_risk_score) * 0.6, 0.6)
            basis.append(f"overall_risk_score={result.overall_risk_score:.2f}")

        # 2. Ключевые слова
        text = str(result.model_dump() if hasattr(result, 'model_dump') else result).lower()
        critical_hits = [kw for kw in _CRITICAL_KEYWORDS if kw in text]
        high_hits = [kw for kw in _HIGH_KEYWORDS if kw in text]
        if critical_hits:
            basis.append(f"critical keywords: {critical_hits}")
            weight += 0.35
        elif high_hits:
            basis.append(f"high keywords: {high_hits}")
            weight += 0.20

        # 3. Количество событий (IOC count)
        events_count = 0
        if hasattr(result, 'logs') and hasattr(result.logs, 'events'):
            events_count += len(result.logs.events)
        if hasattr(result, 'system') and hasattr(result.system, 'events'):
            events_count += len(result.system.events)
        if hasattr(result, 'network') and hasattr(result.network, 'events'):
            events_count += len(result.network.events)

        if events_count > 1:
            basis.append(f"{events_count} events detected")
            weight += min(events_count * 0.05, 0.15)

        # Clamp
        weight = max(_CONF_FLOOR, min(_CONF_CEIL, weight))

        # Verdict
        if weight >= 0.80:
            verdict = "true_positive"
        elif weight >= 0.60:
            verdict = "likely_true_positive"
        elif weight >= 0.40:
            verdict = "needs_review"
        else:
            verdict = "likely_benign"

        if not basis:
            basis.append("no salient signals — defaulting to floor confidence")

        details = {"confidence": weight, "basis": basis, "scores": {"weight": weight}}
        return verdict, basis, details

    def _auto_respond(self, details: dict) -> Optional[dict]:
        """Автономное действие."""
        confidence = details.get("confidence", 0)
        logger.info("Auto-responding with confidence=%.2f", confidence)
        return {
            "action": "ALERT",
            "confidence": confidence,
            "verdict": "true_positive",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "EXECUTED",
        }

    def enable(self):
        self.enabled = True
        logger.warning("Reactor ENABLED")

    def disable(self):
        self.enabled = False
        logger.info("Reactor DISABLED")

    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "auto_mode": self.auto_mode,
            "actions_taken": self._actions_taken,
            "actions_blocked": self._actions_blocked,
        }
