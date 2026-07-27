"""
ML Client абстракция для AGmind-SAIS.
Поддерживает: Ollama, vLLM (OpenAI-compat), llama.cpp, любой OpenAI API.
"""

import abc
import aiohttp
import logging
from typing import Optional

logger = logging.getLogger("sais.ml_client")


class MLProviderError(Exception):
    """Ошибка провайдера ML."""


class MLClient(abc.ABC):
    """Абстрактный ML-клиент."""

    def __init__(self, config: dict):
        self.config = config
        self.model = config["ml"]["model"]
        self.base_url = config["ml"]["base_url"].rstrip("/")
        self.api_key = config["ml"].get("api_key", "")
        self.temperature = config["ml"].get("temperature", 0.7)
        self.max_tokens = config["ml"].get("max_tokens", 4096)

    @abc.abstractmethod
    async def chat(self, messages: list[dict], stream: bool = False) -> str:
        """Отправить чат-запрос, получить ответ."""
        ...

    @abc.abstractmethod
    async def check_health(self) -> bool:
        """Проверить доступность провайдера."""
        ...

    @classmethod
    def create(cls, config: dict) -> "MLClient":
        """Фабрика: создаёт клиент по типу провайдера."""
        provider = config["ml"]["provider"]
        if provider == "ollama":
            return OllamaClient(config)
        elif provider == "vllm":
            return VLLMClient(config)
        elif provider == "llamacpp":
            return LlamaCppClient(config)
        elif provider == "openai":
            return OpenAIClient(config)
        else:
            raise ValueError(f"Unknown ML provider: {provider}")


class OllamaClient(MLClient):
    """Клиент для Ollama API."""

    async def chat(self, messages: list[dict], stream: bool = False) -> str:
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    raise MLProviderError(f"Ollama error {resp.status}: {await resp.text()}")
                data = await resp.json()
                return data.get("message", {}).get("content", "")

    async def check_health(self) -> bool:
        try:
            url = f"{self.base_url}/api/tags"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200
        except Exception:
            return False


class VLLMClient(MLClient):
    """Клиент для vLLM (OpenAI-compatible API)."""

    async def chat(self, messages: list[dict], stream: bool = False) -> str:
        url = f"{self.base_url}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as resp:
                if resp.status != 200:
                    raise MLProviderError(f"vLLM error {resp.status}: {await resp.text()}")
                data = await resp.json()
                return data["choices"][0]["message"]["content"]

    async def check_health(self) -> bool:
        try:
            url = f"{self.base_url}/v1/models"
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200
        except Exception:
            return False


class LlamaCppClient(MLClient):
    """Клиент для llama.cpp server."""

    async def chat(self, messages: list[dict], stream: bool = False) -> str:
        # llama.cpp использует /v1/chat/completions (OpenAI compat) или /completion
        url = f"{self.base_url}/v1/chat/completions"
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    raise MLProviderError(f"llama.cpp error {resp.status}: {await resp.text()}")
                data = await resp.json()
                return data["choices"][0]["message"]["content"]

    async def check_health(self) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.base_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200
        except Exception:
            return False


class OpenAIClient(MLClient):
    """Универсальный клиент для OpenAI-compatible API (любой провайдер)."""

    async def chat(self, messages: list[dict], stream: bool = False) -> str:
        url = f"{self.base_url}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as resp:
                if resp.status != 200:
                    raise MLProviderError(f"OpenAI API error {resp.status}: {await resp.text()}")
                data = await resp.json()
                return data["choices"][0]["message"]["content"]

    async def check_health(self) -> bool:
        try:
            url = f"{self.base_url}/v1/models"
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200
        except Exception:
            return False
