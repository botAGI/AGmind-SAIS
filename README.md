# 🛡️ AGmind-SAIS — Security AI Sensor

Автономный контейнер безопасности с ML-ядром. 24/7 мониторинг системы, сети и логов. Выявление угроз через LLM. Автоматическое реагирование с guardrails.

## Архитектура

```
┌───────────────────────────────────────────────────┐
│                 AGmind-SAIS                         │
│                                                     │
│   ┌─────────────┐    ┌─────────────────────────┐   │
│   │   FastAPI    │    │     Agent Core (цикл)    │   │
│   │  REST API   │    │  collect → analyze → act │   │
│   │  WebSocket  │    │         │                 │   │
│   │  Web UI     │    │    ┌────┴────┐            │   │
│   └──────┬──────┘    │    │ Analyzer │            │   │
│          │           │    └────┬────┘            │   │
│   ┌──────┴──────┐    │    ┌────┴────┐            │   │
│   │ ML Client   │◄───│────│ Alerter │            │   │
│   │ abstract.   │    │    └─────────┘            │   │
│   └──────┬──────┘    └──────────┬────────────────┘   │
│          │                      │                     │
│   ┌──────┴──────┐    ┌──────────┴──────────────┐    │
│   │ Ollama      │    │ Investigation Ledger      │    │
│   │ vLLM        │    │ + Risk-Based Alerting    │    │
│   │ llama.cpp   │    │ + Guardrails             │    │
│   │ OpenAI API  │    │ + Reactor Engine         │    │
│   └─────────────┘    └──────────────────────────┘    │
└───────────────────────────────────────────────────┘
```

## Возможности

### 🧠 ML-ядро (любой провайдер)
- Ollama, vLLM, llama.cpp, OpenAI-совместимый API
- Переключение провайдера через config.yaml
- Декларативная экстракция через Pydantic-схемы

### 👁️ Мониторинг 24/7
- **Система:** CPU, RAM, диск, процессы, пользователи
- **Сеть:** соединения, порты, подозрительный трафик
- **Логи:** инкрементальное чтение syslog, auth.log, nginx

### 🎯 Анализ угроз
- LLM-анализ собранных данных
- Выявление: аномалии системы, сетевые атаки, угрозы из логов
- Классификация по severity (1-5) и confidence (0.0-1.0)
- MITRE ATT&CK техники

### ⚡ Reactor с Guardrails
- Автономные действия только при confidence ≥ 0.90
- С человеческим подтверждением при ≥ 0.60
- Поддерживаемые действия: BLOCK_IP, KILL_PROCESS, QUARANTINE_USER, ALERT_ONLY
- Cooldown на повторные действия
- Risk-Based Alerting с затуханием баллов

### 📋 Investigation Ledger
- Логирование каждого шага агента (промпты, ответы, решения)
- Полный replay задним числом
- JSONL-формат для простой интеграции

### 💬 Чат с КиберБезОпасовичем
- REST API + WebSocket
- Web UI dashboard
- Прямой доступ к ML-ядру

### 🔔 Алерты
- Telegram (Markdown, эмодзи-приоритеты)
- Webhook (JSON payload)
- Локальный лог

## Быстрый старт

### 1. Конфигурация

```yaml
# config/config.yaml
ml:
  provider: ollama          # ollama | vllm | llamacpp | openai
  model: cyberbez-bezopasovich
  base_url: "http://localhost:11434"
```

### 2. Docker

```bash
docker build -t agmind-sais .
docker run -d \
  --name sais \
  --network host \
  -v /var/log:/var/log:ro \
  -v /path/to/config.yaml:/app/config/config.yaml \
  agmind-sais
```

### 3. Или локально

```bash
pip install -r requirements.txt
python main.py
```

### 4. Открыть дашборд

```
http://localhost:8080/ui/dashboard.html
```

## API Endpoints

| Method | Path | Описание |
|--------|------|---------|
| GET | /health | Проверка здоровья |
| GET | /api/status | Полный статус |
| POST | /api/chat | Чат с ML-ядром |
| WS | /api/chat/ws | WebSocket чат |
| POST | /api/analyze | Принудительный анализ |
| GET | /api/ledger | Investigation Ledger |
| POST | /api/reactor | Управление реактором |
| GET | /api/monitor/live | Свежие данные мониторинга |

## Зависимости

- Python 3.12
- FastAPI + Uvicorn
- aiohttp
- Pydantic
- PyYAML

## Лицензия

MIT — делайте что хотите. Но отвечаете за использование сами.

---

*Сделано Gbot для проекта agmind-hat.*
