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

