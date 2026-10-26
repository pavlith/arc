# Arc

Arc — русскоязычная self-hosted платформа для совместной работы команд.

Проект находится на этапе **M0 — Foundation**. Нормативные документы:

- [Требования](docs/REQUIREMENTS.md)
- [Архитектура](docs/ARCHITECTURE.md)
- [Процесс разработки](docs/DEVELOPMENT.md)

Актуальная работа и её состояние ведутся только в GitHub Issues. Статус, приоритет и этап задаются метками; отдельные GitHub Projects, Notion и Markdown-backlog не используются.

## Разработка с Codex

Краткие инструкции: `AGENTS.md`. Локальная конфигурация: `.codex/config.toml`; проектные skills: `.agents/skills/`. Настройка MCP, профилей и проверок: [Codex workflow](docs/CODEX.md). Изменения сначала попадают в ветку `dev`; `main` — стабильная ветка.

## Локальный M0-контур

Требуются Go 1.27+ и Docker Compose. Секреты для разработки генерируются локально и не входят в Git:

```bash
make bootstrap-dev
docker compose up -d postgres nats
docker compose --profile tools run --rm migrate
docker compose --profile tools run --rm rpc-smoke
```

Полная проверка M0-01 с двумя чистыми запусками: `make m0-01-smoke`.


M0-02 Identity реализован в `sdk/identity` как Core-only модуль внутри существующего
Go module; `sdk/security` и `sdk/rpc` проверяют JWT и request proof. Публичный HTTP вход реализован отдельным Gate M0-05. Внутренние NATS endpoints регистрирует `Core.BindInternal`, тестовый
клиент — `identity.TestClient` / `identity.TestCall`. Private key Core загружается
из отдельного файла seed с правами `0600`; в PostgreSQL публикуются только metadata
и public key. Первичный пользователь и offline recovery code создаются локальным
`Core.BootstrapUser`, который не опубликован в RPC.

`identity.Policy.Authorize` — обязательная граница с будущими Access/Fabric:
адаптер проверяет утверждённые deployments/операции, Gate-only exchange, текущие
права пользователя, scope/consent делегации, разрешённые tools и downstream
сужение по `Incoming`. Операции с `needs_approval` запрещаются без подтверждения.
Отсутствие адаптера закрывает доступ; production allow-all реализации нет.
Gate в M0-05 проверяет origin/CSRF и использовать cookie-контракт
`SessionCookie`; внешний access JWT проверяется через `Verifier.Access` с живой
проверкой сессии. Ресурсные side effects требуют онлайн Access в M0-03.

Для узких интеграционных guardrails нужны `initdb`, `pg_ctl`, `psql`,
`nats-server` и Go в PATH:

```sh
bash scripts/verify-changed.sh
bash scripts/test-m0-02.sh
```

Скрипт создаёт временные PostgreSQL/NATS, применяет миграции дважды, запускает
существующий M0-01 RPC/JetStream smoke и M0-02 guardrails, затем удаляет временные
данные. Без `ARC_IDENTITY_TEST_DSN` обычный `go test` явно пропускает интеграцию.
Полная M7-матрица остаётся отдельным этапом; Fabric и Gate описаны ниже.

Команды `delegations.create/revoke` требуют подписанный `idempotency_key`;
`TestClient.IdempotencyKey` позволяет сохранить ключ при повторе после timeout.
`command_results` хранит только несекретные результаты и hash payload, вместе с
доменным изменением и audit в одной транзакции; результат сохраняется не менее
24 часов. Login/refresh/exchange используют отдельный одноразовый auth-протокол,
их plaintext tokens в command results не записываются. `Authorization.ExpiresAt`
позволяет policy дополнительно сократить допустимый срок consent; Core ограничивает
его 24 часами. Очистка audit/истёкших nonce и эксплуатационная ротация секретов
требуют политики retention при M7 hardening.

M0-03 Access находится в `sdk/access`, миграция — `000003_access.up.sql`.
`Core.BindInternal` и typed `access.Client` обслуживают `access.v1.resource_types.register`,
`resources.reserve/activate/abort/begin_delete/finalize_delete`, `check`, `check_many`,
`list_accessible_roots`, `grants.add/revoke` через существующий защищённый NATS RPC.
Контекст клиента задаётся через `rpc.WithCredentials`; commands требуют стабильный
idempotency key и deadline. JWT/proof и актуальные Identity principals проверяются
на каждом запросе. `CheckMany` использует один PostgreSQL repeatable-read snapshot
для максимум 100 пар; положительного кэша нет.

До Fabric утверждения загружаются локально через `access.NewContracts`:
Ed25519 public key authority закреплён в конфигурации Core, подпись покрывает
RFC 8785 payload `access.Approval` с точными resource types/provider UUID, deployment
pairs, caller/audience/operation/action rules, точной картой downstream actions и agent tool scopes.
`source_aud/source_op` нового JWT подписываются Core из проверенного входящего token;
поэтому `free_busy` → `Access.Check` не расширяется до `read` даже для owner. Authority key
и approvals не принимаются из RPC. Назначение `identity.Core.Policy = accessCore`
связывает модули: `Authorize` проверяет утверждённые операции и downstream provenance,
а права делегации читает напрямую из SQL. Обратных вызовов Identity из Access policy
нет. Пустые зависимости и неизвестные операции закрывают доступ.

`DomainOwner.Confirm` обязан сверять resource/provider/operation/receipt с собственным
доменным commit. Реальные Calendar/Files подключат этот интерфейс и `RootLookup`;
`GuardObject` проверяет object → root по данным сервиса-владельца. Без подтверждения
`activate/abort/finalize_delete` запрещены. После crash domain-owner повторяет шаг
с тем же ключом; сохранённый результат, revision и audit фиксируются одной транзакцией
Core. Reconciler/outbox доменных сервисов остаются ответственностью этих сервисов.

```sh
make m0-03-smoke
```

Команда использует временные PostgreSQL/NATS, повторяет миграции и выполняет
регрессию M0-01 RPC/JetStream, M0-02 и M0-03 guardrails. Отдельный workflow
`m0-03.yml` также выполняет быстрые Go-тесты и `go vet`. Для локального обычного
`go test ./...` интеграция требует `ARC_ACCESS_TEST_DSN` и NATS fixtures;
готовый harness задаёт их сам. M7 и публичный Gate API здесь не реализуются.

### M0-04 SDK и Fabric

`migrations/000004_fabric.up.sql` добавляет immutable approved contracts,
scoped deployments, instance leases, route revision и transaction storage shapes.
`fabric.Core.Approve` — закрытая установка подписанного оператором JSON artifact;
публичного approval endpoint нет. `fabric.Core` подключается к
`access.Core.ContractSource`, а Identity сохраняет существующий policy boundary.

Domain service использует `sdk.NewApp`, `sdk.Handle` для query и
`sdk.HandleCommand` для команды с собственной `events.Store` и SQL-транзакцией.
`Start` требует полный набор handlers, approval, self-check и signed readiness.
`fabric.Client.CoreKey` закрепляет ключ Core для проверки подписанных control-ответов.
Контрольные subjects: `ctl.arc.fabric.register`, `.ready`, `.check` и
instance-specific `.probe.<instance_id>`; NATS credentials заранее ограничиваются
subjects утверждённого deployment. `sdk.Call` проверяет wire schemas клиента.
`fabric.Core.Routes`/`VerifySnapshot` предоставляют подписанный RouteSnapshot для
будущего Gate. HTTP server здесь отсутствует.

```bash
bash scripts/test-m0-04.sh
```

Нужны PostgreSQL tools и NATS server, как для M0-03. Проверка создаёт изолированную
БД, применяет/повторяет миграции, запускает M0-01 smoke, Identity/Access regression
и Fabric guardrails с race detector. Полная replica/reconnect/timeout/recovery
матрица остаётся M7. Таблицы replay/outbox/inbox domain-owner размещает в своей БД;
права на точные event/DLQ subjects выдаются при установке deployment.

### M0-05 Arc Gate

```sh
cd sdk
go build -o /tmp/arc-gate ./cmd/arc-gate
/tmp/arc-gate -config /path/to/gate-config.json
```

Пример без секретов: `deploy/gate/config.example.json`. Укажите реальный Gate
ServiceAccount/kid, scoped NATS credentials, service Ed25519 seed (0600), TLS
certificate/key и root public key Core (base64 JSON string, 32 bytes).
Для HTTPS reverse proxy вместо TLS files задайте точные `trusted_proxies` CIDRs;
без TLS или trusted proxy Gate не запускается. Единственный публичный порт — Gate;
существующие Compose-порты PostgreSQL/NATS ограничены loopback для разработки.

Core host связывает `identity.Core.BindInternal`, Access и
`fabric.Core.BindRoutes`; `SnapshotKid` берётся из действующих Identity signing-key
metadata, `RouteTrustKey` — отдельный Core-only ключ. Gate получает только public
trust root. Доверенная установка заранее разрешает Gate точные Identity auth/
exchange RPC, `ctl.arc.fabric.routes`, approved business subjects и подписку на
`evt.arc.fabric.routes.changed`; никаких control wildcards для публичного клиента.
`identity.Client` — production имя существующего service-proof клиента;
`TestClient/TestCall` сохраняются для совместимости.

Auth: `POST /api/v1/arc/auth/login`, `/refresh`, `/logout`,
`GET /api/v1/arc/auth/session`. Login требует разрешённый HTTPS Origin; cookie
mutations — тот же Origin и `X-CSRF-Token`. Login выдаёт session/CSRF/access JWT,
а session/refresh credentials сохраняются Secure cookies. Bearer access JWT
проверяется online в Core; domain service получает отдельный invocation + proof.
Не отправляйте одновременно Bearer и session cookie.

Таблица маршрутов заменяется атомарно после проверки signature/digest/live JWKS,
contract schemas и bindings. Cold start закрыт; notification и periodic fetch
восстанавливают обновления. Сохранённая таблица не заменяет online auth. Readiness
проверяется через `/readyz`, liveness — `/healthz`. Полная M7-матрица и DAV/WS здесь
не реализованы.

```sh
make m0-05-smoke
```

Тест создаёт временные PostgreSQL/NATS и отдельную чистую БД Gate fixture,
проверяет HTTP/CSRF/CORS/session/bearer/security, signed snapshots, race replacement,
real Identity→Gate→domain→Access, ошибки, replay и регрессии M0-01–M0-04.
Новая SQL-миграция для Gate не нужна: он использует действующие Core-контракты.
