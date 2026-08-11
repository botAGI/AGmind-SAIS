# AGmind-SAIS

AGmind-SAIS — разрабатываемый слой проверяемого «кибер-иммунитета» для
Docker-хостов.
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
- Core — evidence, correlation, OPA, durable intents, проверяемое зеркало
  действий и authenticated read-only API; без Docker socket и `CAP_NET_ADMIN`.
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
реализован вместе с hardened Compose/systemd installer, проверяемым Core
actuator mirror, authenticated read-only API, постоянным ручным kill switch и
quiesced proof export с offline replay. Единственный незакрытый release gate —
нативный acceptance на Beelink. До его успешного прохождения проект не является
production-ready.

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

## Ручной kill switch

```sh
agmindctl kill-switch status --json
agmindctl kill-switch enable
agmindctl kill-switch disable
```

`enable` и `disable` требуют точного интерактивного подтверждения. Отключение
ручного режима не снимает автоматические fail-closed блокировки actuator.

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
proof и фактический read-only ответ `dspark` в один отчёт:

```sh
sudo install -d -o root -g root -m 0700 /var/lib/agmind-sais/acceptance
sudo env \
  AGMIND_DEDICATED_TEST_HOST=1 \
  AGMIND_DGX_URL=http://192.168.1.45:8000/v1 \
  /opt/agmind-sais/scripts/verify-linux-integration.sh \
  --output /var/lib/agmind-sais/acceptance/run-001
```

Только финальный отчёт со `"status":"PASS"` считается нативным доказательством
M1. Инструкции: [`docs/runbooks/beelink-lab.md`](docs/runbooks/beelink-lab.md).

## Экспорт доказательства действия

```sh
sudo /opt/agmind-sais/scripts/export-proof-linux.sh \
  --action-id act_0123456789abcdef0123456789abcdef \
  --output /var/lib/agmind-sais/exports/act_0123456789abcdef0123456789abcdef
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

## Лицензия

MIT. Использование защитных действий в реальной инфраструктуре остаётся
ответственностью оператора.
