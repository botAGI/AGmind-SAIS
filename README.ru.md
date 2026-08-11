# AGmind-SAIS

[English](README.md) · **Русский**

**SAIS — Self-Adaptive Immune System.** Разрабатываемый слой проверяемого
«кибер-иммунитета» для Docker-хостов.

[![CI](https://github.com/botAGI/AGmind-SAIS/actions/workflows/ci.yml/badge.svg)](https://github.com/botAGI/AGmind-SAIS/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

AGmind-SAIS собирает подписанные события безопасности, принимает решение по
детерминированной policy, требует локальное подтверждение оператора и только
после этого временно изолирует точный сетевой namespace контейнера.

Это не очередной LLM-firewall: модель не получает полномочий менять систему.
Hunter — локальная обесцензуренная модель на железе оператора; она используется
только как недоверенный read-only слой — для гипотез и объяснений поверх уже
зафиксированных фактов.

> **M1** — первая фаза проекта: один выделенный Docker-хост.

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
socket от пользователя `root` или группы `agmind-admin`. Блокирующий элемент
set имеет kernel timeout и исчезает без участия control plane; служебные table,
chain и drop-правило при этом остаются в netns контейнера (пустые они ни на что
не влияют) до удаления самого netns.

## Архитектура одного хоста

- `agmind-observerd` — host-сенсор, Docker inventory и подписанные события.
- Falco + redacting adapter — monitor-only detection: сам Falco остаётся
  привилегированным syscall-сенсором в изолированной internal-сети, а adapter
  непривилегирован и редактирует события до выхода из sensor-контура; секреты
  AGmind в detection-канал не попадают.
- Core — evidence, correlation, OPA, durable intents, проверяемое зеркало
  действий и authenticated read-only API; без Docker socket и `CAP_NET_ADMIN`.
- OPA — policy admission gate: валидирует форму candidate и границы TTL и выдаёт
  только `manual_approval_required` или `deny`; сформировать команду исполнения
  она не может. Запрещённые назначения и docker-сети проверяет детерминированная
  корреляция Core, а все жёсткие лимиты — TTL, запрещённые назначения,
  docker-сети — actuator независимо проверяет ещё раз
  (`host/actuatord/limits.go`), поэтому граница остаётся fail-closed даже при
  подмене policy.
- Hunter — изолированный запрос к локальной модели через фиксированный relay;
  результат не входит в policy, intent или approval.
- `agmind-actuatord` — минимальная root-boundary, повторно проверяющая identity
  контейнера и применяющая точечный `nftables` timeout внутри его netns.
- `agmindctl` — host-only просмотр и интерактивное approve/reject.

## Текущий статус

M1 ориентирован на один выделенный Linux Docker-хост. Рабочий вертикальный
контур evidence → policy → intent → local approval → target-only TTL уже
реализован вместе с hardened Compose/systemd installer, проверяемым Core
actuator mirror, authenticated read-only API, постоянным ручным kill switch и
quiesced proof export с offline replay. Единственный незакрытый release gate —
нативный acceptance на выделенном лабораторном хосте. До его успешного
прохождения проект **не** является production-ready.

Kubernetes, multi-node coordination и DaemonSet actuator относятся к следующей
фазе. M1 специально сохраняет границы, которые можно перенести: Core/OPA как
обычные непривилегированные workloads, observer/actuator как node-local слой.

## Установка M1

Нужен выделенный Linux-хост с systemd, rootful Docker Engine, Compose v2,
cgroup v2 и nftables. macOS, Docker Desktop, rootless Docker, WSL и общий
production-хост не являются валидным acceptance-окружением.

```sh
sudo ./scripts/install-linux.sh \
  --admin-user <существующий-локальный-пользователь> \
  --hunter-url http://<хост-модели>:8000/v1
```

Полные prerequisites, фиксированные пути и безопасное обновление описаны в
[`docs/runbooks/install-single-host.md`](docs/runbooks/install-single-host.md).

## Ручной kill switch

```sh
agmindctl kill-switch status --json
agmindctl kill-switch enable
agmindctl kill-switch disable
```

`enable` и `disable` требуют точного интерактивного подтверждения. Отключение
ручного режима не снимает автоматические fail-closed блокировки actuator.

Команды `agmindctl` доступны только пользователю `root` или члену группы
`agmind-admin`, причём после установки членство в группе активно лишь в новой
login-сессии.

## Ротация Core API token

```sh
sudo agmindctl token rotate
```

Команда атомарно заменяет root-owned token и выводит только его фиксированный
путь и SHA-256 key ID. Старый bearer перестаёт приниматься без перезапуска Core;
сам token в терминал не печатается.

## Нативная проверка

Один итоговый gate создаёт отдельные target/control контейнеры, требует реальное
локальное подтверждение и связывает target-only TTL, signed `EXPIRED`, offline
proof и фактический read-only ответ Hunter-модели (endpoint обязан отдавать
модель с id `dspark`) в один отчёт:

```sh
sudo install -d -o root -g root -m 0700 /var/lib/agmind-sais/acceptance
sudo env \
  AGMIND_DEDICATED_TEST_HOST=1 \
  AGMIND_HUNTER_URL=http://<хост-модели>:8000/v1 \
  /opt/agmind-sais/scripts/verify-linux-integration.sh \
  --output /var/lib/agmind-sais/acceptance/run-001
```

Только финальный отчёт со `"status":"PASS"` считается нативным доказательством
M1. Инструкции: [`docs/runbooks/native-acceptance.md`](docs/runbooks/native-acceptance.md).

## Экспорт доказательства действия

```sh
sudo /opt/agmind-sais/scripts/export-proof-linux.sh \
  --action-id act_<32-hex-id действия из signed action journal> \
  --output /var/lib/agmind-sais/exports/act_<тот-же-id>
```

Экспорт кратко приостанавливает AGmind-сервисы для согласованного снимка, затем
делает offline verification и восстанавливает ранее активные units. Полная
процедура: [`docs/runbooks/proof-export.md`](docs/runbooks/proof-export.md).

## Что проект намеренно не делает

- не исполняет текст, команды или tool calls от LLM;
- не блокирует адрес по одному model confidence score;
- не выдаёт Core или web API права approve/apply;
- не использует `--network host` для Core;
- не обещает заменить perimeter/WAF firewall во всех сценариях;
- не заявляет Kubernetes/multi-server готовность до отдельного threat model и
  нативного acceptance.

## Безопасность и вклад

Уязвимости — приватно, по процедуре из [SECURITY.md](SECURITY.md). Правила
разработки и чеклист ревью — в [CONTRIBUTING.md](CONTRIBUTING.md).

## Лицензия

MIT — см. [LICENSE](LICENSE). Использование защитных действий в реальной
инфраструктуре остаётся ответственностью оператора.
