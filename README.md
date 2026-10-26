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
Go module; `sdk/security` и `sdk/rpc` проверяют JWT и request proof. Публичного HTTP
входа нет. Внутренние NATS endpoints регистрирует `Core.BindInternal`, тестовый
клиент — `identity.TestClient` / `identity.TestCall`. Private key Core загружается
из отдельного файла seed с правами `0600`; в PostgreSQL публикуются только metadata
и public key. Первичный пользователь и offline recovery code создаются локальным
`Core.BootstrapUser`, который не опубликован в RPC.

`identity.Policy.Authorize` — обязательная граница с будущими Access/Fabric:
адаптер проверяет утверждённые deployments/операции, Gate-only exchange, текущие
права пользователя, scope/consent делегации, разрешённые tools и downstream
сужение по `Incoming`. Операции с `needs_approval` запрещаются без подтверждения.
Отсутствие адаптера закрывает доступ; production allow-all реализации нет.
Gate в M0-05 обязан проверять origin/CSRF и использовать cookie-контракт
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
Полная M7-матрица, Gate ingress, Resource ACL и Fabric остаются своим этапам.

Команды `delegations.create/revoke` требуют подписанный `idempotency_key`;
`TestClient.IdempotencyKey` позволяет сохранить ключ при повторе после timeout.
`command_results` хранит только несекретные результаты и hash payload, вместе с
доменным изменением и audit в одной транзакции; результат сохраняется не менее
24 часов. Login/refresh/exchange используют отдельный одноразовый auth-протокол,
их plaintext tokens в command results не записываются. `Authorization.ExpiresAt`
позволяет policy дополнительно сократить допустимый срок consent; Core ограничивает
его 24 часами. Очистка audit/истёкших nonce и эксплуатационная ротация секретов
требуют политики retention при M7 hardening.
