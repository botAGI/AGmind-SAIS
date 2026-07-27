"""
Investigation Ledger — журнал расследований AGmind-SAIS.
Логирует каждый шаг: входные данные, промпт, ответ LLM, вердикт, действия реактора.
"""

from __future__ import annotations
import json
import logging
import uuid
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger("sais.ledger")


class LedgerEntry:
    """Одна запись в журнале."""

    def __init__(
        self,
        entry_id: str,
        cycle_id: int,
        timestamp: str,
        input_summary: str,
        llm_prompt: Optional[str] = None,
        llm_response: Optional[str] = None,
        verdict: Optional[dict] = None,
        reactor_actions: Optional[list[dict]] = None,
        alerts_sent: Optional[list[dict]] = None,
        error: Optional[str] = None,
    ):
        self.entry_id = entry_id
        self.cycle_id = cycle_id
        self.timestamp = timestamp
        self.input_summary = input_summary
        self.llm_prompt = llm_prompt
        self.llm_response = llm_response
        self.verdict = verdict
        self.reactor_actions = reactor_actions or []
        self.alerts_sent = alerts_sent or []
        self.error = error

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


class InvestigationLedger:
    """
    Журнал расследований. Сохраняет записи в JSONL (каждый цикл — одна строка).
    """

    def __init__(self, storage_path: str = "/var/log/sais/ledger"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._entries: list[LedgerEntry] = []

    def start_cycle(self, cycle_id: int, input_summary: str) -> str:
        """Начать цикл, вернуть entry_id."""
        entry_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        entry = LedgerEntry(
            entry_id=entry_id,
            cycle_id=cycle_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            input_summary=input_summary,
        )
        self._entries.append(entry)
        return entry_id

    def update(
        self,
        entry_id: str,
        llm_prompt: Optional[str] = None,
        llm_response: Optional[str] = None,
        verdict: Optional[dict] = None,
        reactor_actions: Optional[list[dict]] = None,
        alerts_sent: Optional[list[dict]] = None,
        error: Optional[str] = None,
    ):
        """Обновить существующую запись."""
        for entry in self._entries:
            if entry.entry_id == entry_id:
                if llm_prompt is not None:
                    entry.llm_prompt = llm_prompt
                if llm_response is not None:
                    entry.llm_response = llm_response
                if verdict is not None:
                    entry.verdict = verdict
                if reactor_actions is not None:
                    entry.reactor_actions = reactor_actions
                if alerts_sent is not None:
                    entry.alerts_sent = alerts_sent
                if error is not None:
                    entry.error = error
                break

    def finish_cycle(self, entry_id: str):
        """Завершить цикл — сохранить в JSONL."""
        for entry in self._entries:
            if entry.entry_id == entry_id:
                self._append_to_file(entry.to_dict())
                logger.debug("Ledger: saved cycle %d (%s)", entry.cycle_id, entry_id)
                break

    def _append_to_file(self, data: dict):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        filepath = self.storage_path / f"ledger-{today}.jsonl"
        try:
            with open(filepath, "a") as f:
                f.write(json.dumps(data, default=str) + "\n")
        except OSError as e:
            logger.error("Ledger write error: %s", e)

    def get_recent(self, limit: int = 10) -> list[dict]:
        """Последние N записей."""
        return [e.to_dict() for e in self._entries[-limit:]]

    def get_stats(self) -> dict:
        return {
            "cached_entries": len(self._entries),
            "storage_path": str(self.storage_path),
        }
