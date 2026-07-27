"""
Analyzer — LLM-анализатор с декларативной Pydantic-экстракцией.
Основано на LogSentinelAI: вставка JSON-схемы в system prompt -> LLM -> json.loads -> model_validate.
Поддерживает все провайдеры через единый интерфейс (Ollama/vLLM/llama.cpp/OpenAI).
"""

from __future__ import annotations
import json
import logging
import time
from typing import Optional, TypeVar, Type

from pydantic import BaseModel, ValidationError

from app.ml_client.base import MLClient
from app.core.schemas import (
    SystemAnalysis,
    NetworkAnalysis,
    LogAnalysis,
    AggregateAnalysis,
    SeverityLevel,
)

logger = logging.getLogger("sais.analyzer")

T = TypeVar("T", bound=BaseModel)


class SecurityAnalyzer:
    """
    Анализатор безопасности.
    Принимает схему (Pydantic), форматирует промпт, отправляет в LLM, валидирует ответ.
    """

    # Шаблон промпта (как у LogSentinelAI — с {model_schema} и {logs})
    SYSTEM_PROMPT_TEMPLATE = """
Ты — КиберБезОпасович, эксперт по кибербезопасности.
Анализируй предоставленные данные на предмет угроз и аномалий.

КРИТИЧЕСКИЕ ПРАВИЛА:
- ОТВЕЧАЙ ТОЛЬКО JSON. Никакого пояснительного текста до или после JSON.
- Поле events НИКОГДА не должно быть пустым. Если проблем нет — создай INFO-событие.
- confidence_score: от 0.0 до 1.0 (НЕ проценты)
- recommended_actions: конкретные команды и процедуры
- related_logs: включи оригинальные строки логов

СХЕМА JSON (строго этот формат):
{model_schema}
"""

    USER_PROMPT_TEMPLATE = """
=== ДАННЫЕ ДЛЯ АНАЛИЗА ===

{data}

<ЛОГ НАЧАЛО>
{logs}
<ЛОГ КОНЕЦ>

Верни ТОЛЬКО JSON по указанной схеме. Никакого текста кроме JSON.
"""

    def __init__(self, ml_client: MLClient, system_prompt: str = ""):
        self.ml_client = ml_client
        self._custom_system_prompt = system_prompt

    async def analyze(
        self,
        data: dict,
        model_class: Type[T],
        log_lines: Optional[list[str]] = None,
        model_name: Optional[str] = None,
    ) -> Optional[T]:
        """
        Анализ данных через LLM с декларативной экстракцией.

        Args:
            data: Данные для анализа (система/сеть/логи)
            model_class: Pydantic-класс для валидации ответа
            log_lines: Опциональные строки логов (как LogSentinelAI чанкинг)
            model_name: Опциональное имя модели

        Returns:
            Валидированный Pydantic-объект или None при ошибке
        """
        # Получаем JSON-схему Pydantic модели (как LogSentinelAI)
        schema = model_class.model_json_schema()

        # Форматируем промпт (как LogSentinelAI с {model_schema})
        system_prompt = self._custom_system_prompt or self.SYSTEM_PROMPT_TEMPLATE.format(
            model_schema=json.dumps(schema, indent=2, ensure_ascii=False)
        )

        # Форматируем данные
        data_str = json.dumps(data, indent=2, ensure_ascii=False) if isinstance(data, dict) else str(data)
        logs_str = "\n".join(log_lines[:50]) if log_lines else ""

        user_prompt = self.USER_PROMPT_TEMPLATE.format(
            data=data_str[:8000],
            logs=logs_str[:4000],
        )

        logger.debug("Sending to LLM: system=%d chars, user=%d chars",
                     len(system_prompt), len(user_prompt))

        # Отправляем в LLM
        start = time.time()
        try:
            raw_response = await self.ml_client.chat(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            elapsed = int((time.time() - start) * 1000)
            logger.info("LLM response received in %dms (%d chars)", elapsed, len(raw_response))
        except Exception as e:
            logger.error("LLM analysis failed: %s", e)
            return None

        # Парсим и валидируем (как LogSentinelAI: json.loads -> model_validate)
        result = self._parse_and_validate(raw_response, model_class)
        if result is None:
            logger.warning("Failed to parse LLM response as %s", model_class.__name__)

        return result

    @staticmethod
    def _merge_results(results: list[T], model_class: Type[T]) -> T:
        """Слияние результатов нескольких чанков.
        Берём сводку из первого чанка, собираем все events воедино.
        """
        if len(results) == 1:
            return results[0]

        merged = results[0].model_copy(deep=True)
        for r in results[1:]:
            if hasattr(merged, 'events') and hasattr(r, 'events'):
                merged.events.extend(r.events)
        return merged

    def _parse_and_validate(self, raw: str, model_class: Type[T]) -> Optional[T]:
        """
        Парсинг и валидация ответа LLM через Pydantic.
        Как LogSentinelAI: json.loads() -> model_class.model_validate()
        """
        cleaned = raw.strip()

        # Убираем markdown-обёртки если есть
        if cleaned.startswith("```"):
            # Ищем первый { после ```
            start = cleaned.find("{")
            if start >= 0:
                cleaned = cleaned[start:]
        if cleaned.endswith("```"):
            end = cleaned.rfind("}")
            if end >= 0:
                cleaned = cleaned[:end+1]

        # Пробуем распарсить JSON
        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError as e:
            logger.warning("JSON parse error: %s", e)
            # Пробуем найти JSON в ответе (если LLM добавила текст вокруг)
            try:
                start = cleaned.index("{")
                end = cleaned.rindex("}") + 1
                parsed = json.loads(cleaned[start:end])
            except (ValueError, json.JSONDecodeError) as e2:
                logger.warning("Fallback JSON parse failed: %s", e2)
                return None

        # Валидируем через Pydantic (как LogSentinelAI: model_class.model_validate(parsed))
        try:
            validated = model_class.model_validate(parsed)
            logger.debug("Validation OK: %s", model_class.__name__)
            return validated
        except ValidationError as e:
            logger.warning("Pydantic validation failed: %s", e)
            return None

    @staticmethod
    def _chunk_lines(lines: list[str], chunk_size: int = 30) -> list[list[str]]:
        """Разбить строки на чанки (как LogSentinelAI chunked_iterable)."""
        return [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]

    async def analyze(
        self,
        data: dict,
        model_class: Type[T],
        log_lines: Optional[list[str]] = None,
        model_name: Optional[str] = None,
        max_retries: int = 2,
    ) -> Optional[T]:
        """
        Анализ данных через LLM с декларативной экстракцией.

        Args:
            data: Данные для анализа
            model_class: Pydantic-класс для валидации ответа
            log_lines: Опциональные строки логов (разбиваются на чанки)
            model_name: Опциональное имя модели
            max_retries: Количество retry при ошибке (как LogSentinelAI wait_on_failure)

        Returns:
            Валидированный Pydantic-объект или None при ошибке
        """
        schema = model_class.model_json_schema()

        system_prompt = self._custom_system_prompt or self.SYSTEM_PROMPT_TEMPLATE.format(
            model_schema=json.dumps(schema, indent=2, ensure_ascii=False)
        )

        data_str = (
            json.dumps(data, indent=2, ensure_ascii=False)
            if isinstance(data, dict)
            else str(data)
        )[:8000]

        # Чанкинг логов (как LogSentinelAI chunked_iterable)
        chunks = self._chunk_lines(log_lines or [])
        all_results = []

        for chunk_idx, chunk in enumerate(chunks):
            logs_str = "\n".join(chunk)
            user_prompt = self.USER_PROMPT_TEMPLATE.format(
                data=data_str,
                logs=logs_str[:4000],
            )

            logger.debug(
                "Sending chunk %d/%d: system=%d chars, user=%d chars",
                chunk_idx + 1, len(chunks), len(system_prompt), len(user_prompt),
            )

            # Retry-цикл (как LogSentinelAI wait_on_failure)
            for attempt in range(max_retries + 1):
                try:
                    start = time.time()
                    raw_response = await self.ml_client.chat(
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                    )
                    elapsed = int((time.time() - start) * 1000)
                    logger.info(
                        "LLM chunk %d/%d in %dms (%d chars)",
                        chunk_idx + 1, len(chunks), elapsed, len(raw_response),
                    )
                    break
                except Exception as e:
                    if attempt < max_retries:
                        logger.warning(
                            "LLM attempt %d/%d failed: %s. Retrying...",
                            attempt + 1, max_retries + 1, e,
                        )
                        await asyncio.sleep(5 * (attempt + 1))
                    else:
                        logger.error(
                            "LLM chunk %d/%d failed after %d attempts: %s",
                            chunk_idx + 1, len(chunks), max_retries + 1, e,
                        )
                        return None

            # Парсим и валидируем
            result = self._parse_and_validate(raw_response, model_class)
            if result is None:
                logger.warning("Failed to parse chunk %d/%d", chunk_idx + 1, len(chunks))
                return None

            all_results.append(result)

        # Если был только один чанк — возвращаем его
        if len(all_results) == 1:
            return all_results[0]

        # Если несколько чанков — агрегируем
        return self._merge_results(all_results, model_class)
