# Arc Infrastructure Agent

Отдельный Linux-процесс: `cmd/arc-agent` → `services/agent`. В Core остаётся `services/core/modules/runtime`, в SDK — общий протокол. Agent не имеет Core SQLite, не обслуживает входящие RPC/HTTP и сам соединяется с NATS по TLS/NKey.

## Запуск

```sh
go build -o /tmp/arc-agent ./cmd/arc-agent
/tmp/arc-agent -config /absolute/path/agent.json
```

Примеры: [config](../../deploy/agent/config.example.json), [systemd unit](../../deploy/agent/arc-agent.service). Установка бинарника, credentials, unit-файлов и trust anchors выполняется оператором независимо от Runtime.

- Отдельный активный Core service account определения `arc-agent`, node binding и templates должны быть provisioned в Core. `RuntimeNodeRPC` включается явно; после enrollment нового node нужен restart Core.
- JSON config, 32-byte Ed25519 service seed и NKey seed принадлежат пользователю процесса, права `0600`. Public snapshot key — JSON-encoded Ed25519 public key (base64 string, как `encoding/json` для `[]byte`), полученный по доверенному offline каналу; это отдельный ключ snapshot, не обязательно Identity JWT key.
- State directory принадлежит пользователю Agent, права `0700`; journal держит exclusive `flock` до завершения процесса. Конфигурация отклоняет неизвестные/повторяющиеся поля, небезопасные templates и неподдерживаемые бинарником drivers.
- NATS permissions: publish на Identity service exchange и три concrete subjects своего node; subscribe только `_INBOX.runtime.<node-id>.>`. Agent выставляет этот `InboxPrefix` сам.

## Reconcile

Каждый раунд начинает online inventory и fresh signed pull. Нет исполнения сохранённого desired snapshot при потере Core/NATS и нет удаления по отсутствию ID в inventory. Время driver context ограничено сроком snapshot; операции на узле сериализованы. Ошибки вызывают bounded backoff до минуты, в логах — только resource ID и фиксированный code.

Journal сохраняет intent до host effect. Повтор завершённой revision у драйвера с `Inspector` сначала читает host state; drift исправляется только после нового online подтверждения. Ошибка inspect запрещает effect. Report timeout повторяет тот же event ID; последующие новые observations обновляют node liveness. Pending reports пока хранятся в памяти: после crash отправляется новый receipt, host operation остаётся идемпотентной через journal и driver. Терминальный failed operation требует новой desired revision. SIGTERM/SIGINT закрывают connection/journal, сохраняя managed workloads.

## Systemd driver

Первый встроенный host driver использует [systemctl show/start/stop](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) через фиксированный `/usr/bin/systemctl`, без shell, inherited environment, произвольных arguments, unit installation или purge. Требуются system-level права для управления systemd.

Только заранее установленный `/etc/systemd/system/arc-managed-<resource-id>.service`; `resource-id` обязан совпадать с template ID. Файл и его systemd directories — root-owned, без group/other write, без symlinks. Canonical unit ID и fragment path должны совпадать; aliases, drop-ins, reverse stop propagation и нестандартные service dependencies отвергаются. Допустимы только перечисленные в driver стандартные systemd dependencies. Unit contents и его CPU/RAM/security limits provisioned оператором; Agent не устанавливает и не изменяет unit configuration.

`running` → start, `stopped/deleted` → stop; delete сохраняет unit-файл и данные. Уже достигнутое состояние не перезапускает сервис. Явный restart и обновление unit configuration ещё не реализованы. Нельзя управлять Agent/bootstrap units или передать shell/exec через API. Docker/LXD kinds существуют в SDK, но их drivers в этом бинарнике ещё отсутствуют и config с ними отклоняется. Lifecycle операции не заменяют полноценный health/logs API; наблюдение об ошибке после уже завершённой operation пока не меняет её terminal status.

## Проверка

`bash scripts/verify-changed.sh`; focused `go test -race ./services/agent/... ./sdk/agent`; `make runtime-smoke` с NATS server версии из Compose. Последний запускает настоящий отдельный `cmd/arc-agent`, проверяет service invocation + inventory по TLS/NKey и graceful SIGTERM с освобождением journal. Host effects проверяются fake driver/command adapter; живые start/stop пользовательских units этим не заявляются.

Read-only проверка systemd: `ARC_AGENT_SYSTEMD_SMOKE=1 go test -count=1 -run TestSystemdMissingUnitReadOnly ./services/agent/drivers/systemd` — несуществующий unit отклоняется до любых start/stop. M7, production readiness, Docker/LXD и administrative Gate/Svelte UI остаются в [#13](https://github.com/pavlith/arc/issues/13).
