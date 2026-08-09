# AGmind-SAIS

AGmind-SAIS — разрабатываемый слой «кибер-иммунитета» для Docker-хостов.
Он собирает подписанные события безопасности, принимает решение по
детерминированной policy, требует локальное подтверждение оператора и только
после этого временно изолирует точный сетевой namespace контейнера.

Это не очередной LLM-firewall: модель не получает полномочий менять систему.
DeepSeek на DGX Spark используется только как недоверенный read-only Hunter —
для гипотез и объяснений поверх уже зафиксированных фактов.

## Главный инвариант M1

```text
signed evidence
  -> deterministic correlation
  -> OPA admission
  -> durable intent
  -> local interactive approval
  -> exact container netns
  -> nftables deny with native TTL
  -> signed action journal
  -> Core mirror / offline proof
```

Ни модель, ни Core, ни HTTP API не могут подтвердить план или напрямую вызвать
`nft`. Привилегированный actuator принимает решение только через локальный Unix
socket от пользователя `root` или группы `agmind-admin`. Правило содержит
kernel timeout и исчезает без участия control plane.

## Архитектура одного хоста

- `agmind-observerd` — host-сенсор, Docker inventory и подписанные события.
- Falco + redacting adapter — monitor-only detection без доступа к секретам.
- Core — evidence, correlation, OPA, durable intents и проверяемое зеркало
  действий; без Docker socket и `CAP_NET_ADMIN`.
- OPA — единственная policy admission boundary. Она может потребовать ручное
  подтверждение, но не сформировать команду исполнения.
- Hunter — изолированный запрос к DeepSeek V4 Flash через фиксированный relay;
  результат не входит в policy, intent или approval.
- `agmind-actuatord` — минимальная root-boundary, повторно проверяющая identity
  контейнера и применяющая точечный `nftables` timeout внутри его netns.
- `agmindctl` — host-only просмотр и интерактивное approve/reject.

## Текущий статус

M1 ориентирован на один выделенный Linux Docker-хост. Рабочий вертикальный
контур evidence → policy → intent → local approval → target-only TTL уже
реализован вместе с hardened Compose/systemd installer. Сейчас завершаются
Core action mirror, proof export/offline verification и нативный acceptance на
Beelink. До успешного Linux smoke проект не заявляет production-ready статус.

Kubernetes, multi-node coordination и DaemonSet actuator относятся к следующей
фазе. M1 специально сохраняет границы, которые можно перенести: Core/OPA как
обычные непривилегированные workloads, observer/actuator как node-local слой.

## Установка M1

Нужен выделенный Linux-хост с systemd, rootful Docker Engine, Compose v2,
cgroup v2 и nftables. macOS, Docker Desktop, rootless Docker, WSL и общий
production-хост не являются валидным acceptance-окружением.

```sh
sudo ./scripts/install-linux.sh \
  --admin-user testbot \
  --dgx-url http://192.168.1.45:8000/v1
```

Полные prerequisites, фиксированные пути и безопасное обновление описаны в
[`docs/runbooks/install-single-host.md`](docs/runbooks/install-single-host.md).

## Нативная проверка

Smoke создаёт отдельные target/control контейнеры, требует реальное локальное
подтверждение, проверяет изоляцию только target, отсутствие AGmind-правил в
host namespace и самостоятельное истечение TTL при остановленном Core и
actuator:

```sh
sudo env \
  AGMIND_DEDICATED_TEST_HOST=1 \
  AGMIND_DGX_URL=http://192.168.1.45:8000/v1 \
  /opt/agmind-sais/scripts/smoke-containment-linux.sh
```

Только финальный отчёт со `"status":"PASS"` считается нативным доказательством
M1. Инструкции: [`docs/runbooks/install-single-host.md`](docs/runbooks/install-single-host.md).

## Что проект намеренно не делает

- не исполняет текст, команды или tool calls от LLM;
- не блокирует адрес по одному model confidence score;
- не выдаёт Core или web API права approve/apply;
- не использует `--network host` для Core;
- не обещает заменить perimeter/WAF firewall во всех сценариях;
- не заявляет Kubernetes/multi-server готовность до отдельного threat model и
  нативного acceptance.

## Лицензия

MIT. Использование защитных действий в реальной инфраструктуре остаётся
ответственностью оператора.
