# Codex для Arc

Эта инструкция описывает **реально работающие настройки репозитория**, без дополнительной архитектуры и дублирования GitHub Issues. Нормативные источники — REQUIREMENTS.md, ARCHITECTURE.md; краткая маршрутизация находится в AGENTS.md.

## Быстрый старт

1. В доверенном checkout Arc на ветке dev открой Codex CLI или IDE. Проектные настройки берутся из .codex/config.toml (только для trusted project).
2. Убедись, что Codex видит skills из .agents/skills/. Вызывай конкретный workflow: $arc-issue, $arc-contract, $arc-verify, $arc-go-service, $arc-svelte-ui.
3. Начинай реализацию с готового GitHub Issue и его критериев приёмки, а не с повторного чтения документации целиком.
4. Выполни python3 scripts/check-agent-setup.py и bash scripts/verify-changed.sh; для сравнения с веткой: bash scripts/verify-changed.sh --base origin/dev.
5. Проверяй результат и количество реально потраченных токенов по нескольким сопоставимым задачам. Экономия зависит от сценария, не гарантируется фиксированным процентом.

## Профили: индивидуальные настройки клиента

Файлы .codex/profiles/fast.config.toml и deep.config.toml — **шаблоны**. Они сами не становятся активными профилями. Для Codex CLI:

    mkdir -p ~/.codex
    cp .codex/profiles/fast.config.toml ~/.codex/fast.config.toml
    cp .codex/profiles/deep.config.toml ~/.codex/deep.config.toml
    codex --profile fast
    codex --profile deep

Используй fast для обычных UI/CRUD/документационных изменений и deep для сложной безопасности/контрактов. Настройка проекта имеет приоритет выше профиля: при необходимости переопредели reasoning явно через codex -c model_reasoning_effort='"high"' либо личную конфигурацию и проверь итоговые настройки CLI. Не закрепляй модель в репозитории: доступная модель зависит от клиента и плана.

## GitHub и OpenAI Docs MCP

Оба MCP описаны в .codex/config.toml, но **выключены по умолчанию**, чтобы не занимать контекст и не требовать OAuth на каждом старте.

- openaiDeveloperDocs — официальный read-only сервер https://developers.openai.com/mcp. Включай только для работы с документацией OpenAI/Codex.
- github — официальный удалённый GitHub MCP https://api.githubcopilot.com/mcp/. Ограничен toolsets repos, issues, pull_requests; lockdown включён; операции записи требуют подтверждения. Для активации установи enabled = true в проектной конфигурации и выполни авторизацию через codex mcp login github (если версия клиента поддерживает OAuth) либо настрой токен как переменную окружения в личной конфигурации. Проверка: codex mcp list.
- Учти: подключение GitHub в ChatGPT не означает автоматическую авторизацию GitHub MCP в локальном Codex. Секреты нельзя добавлять в git.

Если MCP недоступен, допускается стандартная команда gh с уже настроенной авторизацией вместо добавления второго сервера. Не добавляй filesystem/terminal/memory MCP: они дублируют базовые возможности агента. Playwright, PostgreSQL, Context7 и NATS MCP подключай **только при реальной потребности**; PostgreSQL — read-only.

## Защита контекста и проверка

AGENTS.md загружается автоматически, поэтому держи его коротким. Skills загружаются по запросу, не используй их все одновременно. Нормативную документацию читай по заголовкам и затронутым ID контрактов. Ограничивай объём логов, не перепечатывай длинные команды и их вывод. Перед выбором новых зависимостей проверяй фактический API и текущее состояние кода.

scripts/verify-changed.sh не создаёт Go/Svelte инфраструктуру: до появления соответствующего кода проверки этого контура честно пропускаются. После формирования M0 добавить миграционные, контрактные и security guardrails в существующий test harness, а не писать имитации зелёных тестов.

## Измерение эффекта

Для 3–5 задач сопоставимой сложности записывай потребление input/output tokens и wall time до и после настроек, фиксируя модель, профили и доступные MCP. Цель — меньше повторного поиска и отладочных проходов, а не произвольная обещанная экономия токенов.

Справка: https://developers.openai.com/codex/config-reference , https://developers.openai.com/codex/skills , https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md .
