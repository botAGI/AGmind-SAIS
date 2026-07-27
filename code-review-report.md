# Code Review: AGmind-SAIS

**Дата:** 2026-07-23  
**Ревьювер:** КиберБезОпасович (cyberbez-bezopasovich)

## Общая оценка

Проект представляет собой Security AI Sensor — автономную систему мониторинга и реагирования на угрозы с LLM-ядром. Архитектура продумана, код читается хорошо, но обнаружен ряд серьёзных проблем: **1 CRITICAL**, **3 HIGH**, **5 MEDIUM**, **4 LOW**.

Главные риски: отсутствие `analyze_aggregate()` метода при его вызове (приложение упадёт на старте), неинициализированные атрибуты (race condition-ready), отсутствие rate limiting/CORS-ограничений на API, и потенциально опасный reactor при `auto_mode=true`.

---

## Security Issues

### [HIGH] — Отсутствие аутентификации и авторизации на всех эндпоинтах

**Файл:** `app/api/endpoints.py:40-143`

**Описание:** Все REST/WebSocket эндпоинты открыты без какой-либо аутентификации. Любой, кто имеет доступ к сети, может:
- Отправить произвольный запрос в LLM (`POST /api/chat`)
- Включить/выключить reactor (`POST /api/reactor`)
- Получить полный снэпшот мониторинга (`GET /api/monitor/live`)
- Получить все записи журнала расследований (`GET /api/ledger`)

**Риск:** Полный компромисс контроля над системой безопасности злоумышленником через `POST /api/reactor {"command": "enable"}` + `POST /api/reactor {"command": "set_auto", "value": true}`. Reactor может выполнять `block_ip` (iptables), `kill_process`, `quarantine_user`.

**Фикс:** Добавить API-ключ или Bearer token middleware. Минимум — проверка заголовка `X-API-Key` через FastAPI dependency:

```python
from fastapi import Header, HTTPException

API_KEY = os.environ.get("SAIS_API_KEY", "")

async def verify_api_key(x_api_key: str = Header(None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")

@app.post("/api/reactor", dependencies=[Depends(verify_api_key)])
```

---

### [HIGH] — CORS `allow_origins=["*"]` на production-ready приложении

**Файл:** `app/api/endpoints.py:49-54`

**Описание:** Middleware CORS разрешает все origins:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Комбинация `allow_origins=["*"]` + `allow_credentials=True` нарушает спецификацию CORS (браузеры проигнорируют credentials с wildcard origin). Кроме того, на production-системе безопасности это открывает XSS/Scripting-векторы.

**Риск:** CSRF-атаки, эксплуатация через вредоносные сайты. Credentials никогда не работают с `*`, что может вызвать трудноотлавливаемые баги.

**Фикс:** 
```python
allow_origins=config.get("server", {}).get("cors_origins", ["http://localhost:8080"]),
allow_credentials=True,
```

---

### [MEDIUM] — Небезопасное логирование secrets в алертах

**Файл:** `app/core/alerts.py:116-121`

**Описание:** В `_send_telegram()` при ошибке HTTP код логирует ответ сервера Telegram API:

```python
logger.error("Telegram error %d: %s", resp.status, await resp.text())
```

Ответ Telegram может содержать информацию о боте (chat_id в URL уже не секрет, но токен и подробности ошибки — да). Плюс `telegram_token` и `chat_id` хранятся в открытом виде в config.yaml (по умолчанию пустые, но могут быть заполнены).

**Риск:** Утечка bot token через логи при сетевой ошибке.

**Фикс:**
```python
logger.error("Telegram error %d", resp.status)
# Не логируем тело ответа
```

---

### [MEDIUM] — API key передаётся в заголовках без шифрования

**Файл:** `app/ml_client/base.py:64-66, app/ml_client/base.py:114-116, app/ml_client/base.py:152-154`

**Описание:** API-ключ для vLLM/OpenAI-провайдеров передаётся как Bearer token по HTTP (без HTTPS). Во всех клиентах (`VLLMClient`, `OpenAIClient`, `LlamaCppClient`) нет проверки, что `base_url` использует HTTPS перед отправкой ключа.

```python
headers["Authorization"] = f"Bearer {self.api_key}"
```

**Риск:** Перехват API-ключа MITM-атакой, если ML-провайдер развёрнут не на локальной машине.

**Фикс:** Добавить предупреждение в лог при использовании API key с HTTP URL:
```python
if self.api_key and not self.base_url.startswith("https://"):
    logger.warning("API key sent over unencrypted HTTP to %s", self.base_url)
```

---

### [MEDIUM] — Read-логи без блокировки файлов (race condition)

**Файл:** `app/monitoring/collector.py:210-253`

**Описание:** Чтение логов происходит без блокировки файлов (`fcntl.flock` или `portalocker`). При одновременной записи (logrotate, syslog-ng, systemd-journald) и чтении возможен race condition:

```python
with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
    f.seek(tracker["size"])
    new_content = f.read()
```

**Риск:** Частичное чтение строк, потеря данных, дублирование, некорректная позиция seek при ротации/truncation.

**Фикс:** Использовать `fcntl.flock(f, fcntl.LOCK_SH)` или читать через copy-on-write (чтение в tmpfile).

---

### [LOW] — Подозрительные процессы проверяются без учёта, под root ли процесс

**Файл:** `app/monitoring/collector.py:116-117`

**Описание:** Проверка подозрительных процессов:

```python
suspicious_keywords = [
    "ncat", "netcat", "nmap", ... "bash -i",
]
```

`nmap` и `tcpdump` — легитимные утилиты администрирования. Каждое их появление будет вызывать ложное срабатывание. `bash -i` по имени процесса не найдётся (это аргумент командной строки, cmdline может быть `-bash`).

**Риск:** Заливка логов noise, снижение отношения сигнал/шум.

**Фикс:** Сделать подозрительные процессы конфигурируемыми через config.yaml, добавить whitelist.

---

### [LOW] — Server host привязан к `0.0.0.0`

**Файл:** `config/config.yaml:4`

**Описание:** Сервер слушает на `0.0.0.0:8080`, что открывает доступ с любых сетевых интерфейсов. Для изолированного Docker-контейнера это норма, но по умолчанию без файрвола/обратного прокси — лишняя поверхность атаки.

**Риск:** Эксплуатация API без аутентификации с внешних сетей, если контейнер опубликован на публичный IP.

**Фикс:** Использовать `127.0.0.1` по умолчанию, документировать смену на `0.0.0.0` для Docker.

---

## Code Quality Issues

### [CRITICAL] — Missing method `analyze_aggregate()` при его вызове

**Файл:** `app/core/agent.py:132` → `app/core/analyzer.py`

**Описание:** В `agent.py:_run_cycle()` вызывается несуществующий метод:

```python
result = await self.analyzer.analyze_aggregate(
    system_data=snapshot["system"],
    network_data=snapshot["network"],
    log_data=snapshot["logs"],
    log_lines=log_lines,
)
```

В `analyzer.py` определён только `analyze()`, не `analyze_aggregate()`. Аналогичный вызов есть в `app/api/endpoints.py:101`.

При запуске приложение упадёт с `AttributeError: 'SecurityAnalyzer' object has no attribute 'analyze_aggregate'`.

**Риск:** Полная неработоспособность core-цикла агента и API-эндпоинта `/api/analyze`. Приложение запустится (uvicorn стартует), но при первом цикле — crash.

**Фикс:** Реализовать `analyze_aggregate()` в `analyzer.py` или заменить вызов на `analyze()` с соответствующими аргументами:

```python
async def analyze_aggregate(self, system_data: dict, network_data: dict, log_data: dict, log_lines: list[str]) -> Optional[AggregateAnalysis]:
    data = {"system": system_data, "network": network_data, "logs": log_data}
    return await self.analyze(data, AggregateAnalysis, log_lines=log_lines)
```

---

### [HIGH] — Отсутствие атрибута `overall_risk_score` в `AggregateAnalysis`

**Файл:** `app/core/agent.py:128-131`, `app/core/alerts.py:47,169,222`

**Описание:** В коде активно используется `result.overall_risk_score`, но pydantic-схема `AggregateAnalysis` (schemas.py:169-174) не содержит этого поля:

```python
class AggregateAnalysis(BaseModel):
    system: SystemAnalysis
    network: NetworkAnalysis
    logs: LogAnalysis
    overall_severity: SeverityLevel
    requires_immediate_attention: bool = False
```

Нет `overall_risk_score: float`. Аналогично — `ReactEngine._score_and_verdict` (reactor/engine.py:97) обращается к `result.overall_risk_score`.

**Риск:** AttributeError при каждой попытке доступа. В agent.py это уронит цикл. В alerts.py — не отправит сообщение. В reactor — не сработает pre-scoring.

**Фикс:** Добавить поле в `AggregateAnalysis`:

```python
class AggregateAnalysis(BaseModel):
    ...
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
```

---

### [HIGH] — Дублирование метода `analyze()` — переопределение вместо перегрузки

**Файл:** `app/core/analyzer.py:59-97` и `app/core/analyzer.py:111-177`

**Описание:** Метод `analyze()` определён дважды в одном классе. Второе определение полностью перезаписывает первое. Первая версия (возвращает `Optional[T]`, 3 аргумента) теряется. Вторая версия имеет дополнительные параметры (`max_retries`, `model_name`).

Из-за этого первая версия (с `chunk_lines`, `log_lines: Optional[list[str]]`) — мёртвый код. Вызовы, ожидающие первую версию, на самом деле получают вторую, что ломает контракт (вторая версия не принимает `chunk_lines`, зато принимает `max_retries`).

**Риск:** Путаница, непредсказуемое поведение, все вызовы `analyze()` идут через вторую версию (с retry-циклом и чанкингом, что может быть неожиданностью). Мёртвый код.

**Фикс:** Удалить первое определение, оставить только второе:

```python
# Удалить блок от строки 59 до строки 97 (первое определение analyze)
# Оставить только второе определение (строки 111-177)
```

---

### [MEDIUM] — Broad exception handling без re-raise

**Файлы:** `app/core/analyzer.py:85`, `app/core/agent.py:58`, `app/monitoring/collector.py:113,193,247`, `app/core/alerts.py:133,143`, `app/api/endpoints.py:78,107`

**Описание:** Повсеместно используется `except Exception:` без re-raise. Некоторые ошибки (MemoryError, KeyboardInterrupt, SystemExit) должны либо пробрасываться, либо логироваться иначе.

Особенно опасно:
- `agent.py:58` — `except Exception` в основном цикле ловит абсолютно всё и продолжает работу в потенциально повреждённом состоянии
- `analyzer.py:85` и `174` — ошибка LLM возвращает None, вызывающий код (agent.py) не проверяет корректно (там уже проверка на None есть, но состояние после ошибки не сбрасывается)

**Риск:** Маскирование серьёзных ошибок (выход из памяти, повреждённые данные), работа в неконсистентном состоянии.

**Фикс:** В критических местах логировать `exc_info=True`, для известных ошибок ловить конкретные типы:
```python
except asyncio.CancelledError:
    raise  # не swallow отмены
except (MLProviderError, aiohttp.ClientError) as e:
    logger.error("LLM failed: %s", e, exc_info=True)
    return None
except Exception as e:
    logger.critical("Unexpected error: %s", e, exc_info=True)
    return None
```

---

### [MEDIUM] — Неиспользуемый параметр `model_name` в `analyze()`

**Файл:** `app/core/analyzer.py:161`

**Описание:** Метод `analyze()` принимает `model_name: Optional[str] = None`, но никогда не использует его в теле. LLM-запрос всегда идёт на модель, заданную в `self.ml_client.model` (из конфига).

**Риск:** Вводящий в заблуждение API, ложное ожидание переключения модели на лету.

**Фикс:** Удалить параметр или реализовать переключение:
```python
if model_name:
    self.ml_client.model = model_name
```

---

### [MEDIUM] — `_chunk_lines` статический, но используется только внутри класса

**Файл:** `app/core/analyzer.py:102-104`

**Описание:** Метод `_chunk_lines(chunk_size=30)` — `@staticmethod`, но принимает `chunk_size` только со значением по умолчанию 30. Нет гибкости. Плюс дублирование: вторая версия `analyze()` вызывает `_chunk_lines` с тем же значением, так что первая версия мертва.

**Фикс:** Сделать `chunk_size` параметром `analyze()`:
```python
async def analyze(self, ..., chunk_size: int = 30, ...):
```

---

### [LOW] — Синхронный вызов blocking I/O в `_fallback_system`

**Файл:** `app/monitoring/collector.py:152-158`

**Описание:** `subprocess.run(["df", "/"], timeout=3)` обёрнут в `asyncio.to_thread`, что корректно. Но `timeout=3` может не сработать на перегруженной ФС (субпроцесс зависнет в D-state, asyncio.to_thread его не убьёт).

Дополнительно: `subprocess` импортируется внутри метода, а не в начале файла — это не ошибка для fallback, но нарушает PEP8.

**Фикс:** Импорт `subprocess` перенести наверх модуля, добавить timeout через `asyncio.wait_for`:
```python
out = await asyncio.wait_for(
    asyncio.to_thread(lambda: subprocess.run(["df", "/"], capture_output=True, text=True, timeout=3).stdout),
    timeout=10
)
```

---

### [LOW] — Неиспользуемые импорты

**Файл:** `app/core/ledger.py:11`

**Описание:** Импортирован `Any` из `typing`, но не используется (нигде в файле нет аннотации `Any`).

```python
from typing import Optional, Any
```

**Файл:** `app/core/ledger.py:6`

```python
import json, logging, uuid, time
from datetime import datetime, timezone
```

`time` импортирован, но не используется (время берётся через `datetime.now(timezone.utc)`). `uuid` используется.

**Фикс:** Удалить неиспользуемые импорты. Flake8 или ruff выявили бы это.

---

## Architecture Issues

### [HIGH] — Отсутствует анализ логов по разным файлам с разными форматами

**Файл:** `app/monitoring/collector.py:245-248`

**Описание:** Сборщик читает логи как plain text, пытается парсить `source: basename(log_path)`. Форматы `/var/log/syslog`, `/var/log/auth.log`, `/var/log/nginx/access.log` принципиально разные:
- syslog: structured RFC 5424
- auth.log: структурированный, но иной
- nginx access.log: combined log format (apache-style)
- nginx error.log: другой формат

Все они склеиваются в один список строк без префикса исходного файла (только `source: basename`). LLM не сможет корректно интерпретировать строки без контекста формата.

**Риск:** Бесполезный анализ логов,false negatives/positives.

**Фикс:** Добавить метаданные формата для каждого log_path в конфиге:
```yaml
monitoring:
  logs:
    paths:
      - path: "/var/log/auth.log"
        format: "auth"
      - path: "/var/log/nginx/access.log"
        format: "nginx_access"
```

---

### [MEDIUM] — `DataCollector` не закрывает `aiohttp.ClientSession`

**Файл:** `app/ml_client/base.py:42-50,65-80,112-126,150-164`

**Описание:** Во всех ML-клиентах `ClientSession` создаётся каждый раз при вызове `chat()` и `check_health()` без переиспользования:

```python
async with aiohttp.ClientSession() as session:
    async with session.post(url, json=payload) as resp:
```

Это создаёт накладные расходы (TCP-соединение, TLS-handshake при каждом запросе). При cycle_interval=60 и одном вызове в цикле — некритично, но при вебсокетах или `/api/chat` с частыми запросами — деградация.

**Риск:** Утечка файловых дескрипторов, задержки при каждом запросе.

**Фикс:** Создать `ClientSession` в `__init__` и переиспользовать:
```python
class MLClient(abc.ABC):
    def __init__(self, config: dict):
        ...
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
```

---

### [MEDIUM] — `ReactorEngine._cooldowns` — разделяемая изменяемая переменная класса

**Файл:** `app/reactor/engine.py:73`

**Описание:** `_cooldowns: dict[str, float] = {}` определён на уровне класса, а не экземпляра. При множественных инстансах `ReactorEngine` (например, в тестах) они будут разделять один словарь.

**Риск:** Непредсказуемое поведение cooldowns при тестировании, сложности с сбросом состояния.

**Фикс:** Перенести инициализацию в `__init__`:
```python
class ReactorEngine:
    def __init__(self, config: dict):
        self._cooldowns: dict[str, float] = {}
        ...
```

---

### [MEDIUM] — System prompt file path не проверяется на существование

**Файл:** `app/core/agent.py:172`

**Описание:** В `chat()` методе:

```python
"content": self.config.get("agent", {}).get("system_prompt_file", "Ты — КиберБезОпасович."),
```

Ключ `system_prompt_file` содержит путь к файлу, но код не читает файл, а передаёт путь как строку в system prompt LLM. LLM получит `/app/agmind-hat/cyberbez-system-prompt.md` как часть промпта, а не содержимое файла.

**Риск:** LLM получает мусор вместо system prompt. Нарушение работы агента.

**Фикс:** Реализовать чтение файла:
```python
prompt_path = self.config.get("agent", {}).get("system_prompt_file", "")
if prompt_path and os.path.exists(prompt_path):
    with open(prompt_path) as f:
        system_prompt = f.read()
else:
    system_prompt = "Ты — КиберБезОпасович, эксперт по кибербезопасности."
```

---

### [LOW] — Жёстко закодированные пути в конфиге, отсутствие env override

**Файл:** `config/config.yaml:29`

**Описание:** `system_prompt_file: "/app/agmind-hat/cyberbez-system-prompt.md"` — путь жёстко закодирован под Docker-деплой. При локальном запуске файла не существует. Нет механизма переопределения через переменные окружения.

Также путь к логам (`/var/log/sais/ledger`) жёстко закодирован в `ledger.py:34` и создаётся в `main.py:39` через `os.makedirs("/var/log/sais/ledger", exist_ok=True)`, но если приложение запущено не под root — PermissionError.

**Риск:** Ошибка запуска на не-Docker среде. Permission denied на запись логов.

**Фикс:**
1. Сделать `SAIS_LEDGER_PATH` env variable с fallback
2. Проверять права на запись при инициализации
3. Искать файл system prompt относительно `__file__` проекта

---

## Отдельные модули

### `main.py` (95 строк) ✅
Чистый entrypoint. Хорошие сигналы: graceful shutdown через signal handlers, чтение config path из env. Минус: `os.makedirs("/var/log/sais/ledger", exist_ok=True)` без проверки прав.

### `config/config.yaml` (82 строки)
Хорошо структурирован, все секции документированы. Минус: нет env override, нет секции `auth/api_keys`.

### `app/core/schemas.py` (172 строки) ✅
Pydantic-модели корректны, валидация через `Field(ge=0.0, le=1.0)`, enum'ы для severity. Отсутствует `overall_risk_score` в `AggregateAnalysis` — это баг.

### `app/core/analyzer.py` (280 строк) ❌
**Самый проблемный модуль.** Дублирование метода `analyze()` (первая версия — мёртвый код). Отсутствует критический метод `analyze_aggregate()`, который вызывается из agent и API. Параметр `model_name` не используется. JSON-парсинг с fallback — хорош.

### `app/core/agent.py` (153 строки) ❌
Основной цикл логически верен. **Критическая проблема:** вызов несуществующего `analyze_aggregate()`. System prompt file не читается, а передаётся как путь в LLM. Обращение к `overall_risk_score` которого нет в схеме.

### `app/core/ledger.py` (123 строки) ✅
Чистый модуль. Атомарный append к JSONL, корректная работа с UUID, UTC-таймстемпы. Неиспользуемые импорты — minor.

### `app/core/alerts.py` (197 строк) ✅
Хорошая структура: `AlertBuilder` отделён от `Alerter`. Telegram-форматирование с эмодзи. **Минус:** логирование тела ошибки Telegram API (потенциальная утечка), `overall_risk_score` не в схеме.

### `app/ml_client/base.py` (178 строк) ✅
Хорошая абстракция с фабрикой `create()`. Поддержка 4 провайдеров. **Минусы:** ClientSession не переиспользуется, API key без HTTPS-проверки. `LlamaCppClient` и `OpenAIClient` — идентичный код (DRY violation).

### `app/monitoring/collector.py` (340 строк) ✅
Самый объёмный модуль. `psutil` fallback, inode-based log tracking (отслеживание ротации). **Минусы:** race condition на чтении логов, sync subprocess без `asyncio.wait_for`, жёстко закодированные suspicious keywords.

### `app/reactor/engine.py` (169 строк) ✅
Чистый deterministic pre-scoring на основе confidence bands. **Минусы:** `_cooldowns` — разделяемая переменная класса, `overall_risk_score` не в схеме. `_auto_respond()` всегда возвращает `ALERT`, реальные действия (`block_ip`, `kill_process`) не реализованы.

### `app/api/endpoints.py` (143 строки) ❌
**Критично:** Нет аутентификации. CORS `*` + credentials. Вызов несуществующего `analyze_aggregate()`. WebSocket chat без лимитов. Rate limiting отсутствует.

### `app/ui/dashboard.html` (417 строк) ✅
Типичный SPA на htmx + Chart.js. Хороший тёмный терминальный стиль. **Minus:** все запросы без auth. Проверка `status.uptime` — но API не возвращает `uptime` в `/api/status` (только в `/health`).

### `Dockerfile` (66 строк) ✅
Многоступенчатая сборка, непривилегированный пользователь, HEALTHCHECK. Лучшая часть проекта. Метки OCI. **Минус:** нет `.dockerignore` (копируется весь `.`, включая `.git`, `__pycache__`).

---

## Итого

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH     | 3 |
| MEDIUM   | 5 |
| LOW      | 4 |
| **Total** | **13** |

### Ключевые проблемы, требующие немедленного исправления:

1. **🔴 `analyze_aggregate()` не существует** — приложение не работает. Пёрл.
2. **🔴 Нет аутентификации API** — reactor можно включить удалённо.
3. **🔴 `overall_risk_score` нет в схеме** — AttributeError в цикле агента и алертах.
4. **🔴 Двойное определение `analyze()`** — мёртвый код, неожиданное поведение.
5. **🟡 System prompt file не читается** — LLM получает путь вместо контента.

### Рекомендация: **Доработать перед запуском**

Проект имеет хорошую архитектурную основу, но содержит критические баги (несуществующий метод, отсутствующие поля), которые сделают приложение нерабочим при первом же цикле анализа. После исправления этих блокеров — провести интеграционное тестирование core-цикла.
