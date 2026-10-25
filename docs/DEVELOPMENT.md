# Процесс разработки

## Источники истины

- GitHub Issues — задачи, дефекты, предложения и их состояние.
- Метки Issue — статус, приоритет, этап, область и тип работы.
- `docs/REQUIREMENTS.md` — требования и границы продукта.
- `docs/ARCHITECTURE.md` — архитектура и долговременные решения.

GitHub Projects, Notion и дублирующие Markdown-backlog-файлы не используются.

## Представления Issues

Основные очереди открываются стандартными фильтрами GitHub:

- [Backlog](https://github.com/pavlith/arc/issues?q=is%3Aissue+is%3Aopen+label%3A%22status%3A+backlog%22)
- [Ready](https://github.com/pavlith/arc/issues?q=is%3Aissue+is%3Aopen+label%3A%22status%3A+ready%22)
- [In progress](https://github.com/pavlith/arc/issues?q=is%3Aissue+is%3Aopen+label%3A%22status%3A+in-progress%22)
- [In review](https://github.com/pavlith/arc/issues?q=is%3Aissue+is%3Aopen+label%3A%22status%3A+review%22)
- [Blocked](https://github.com/pavlith/arc/issues?q=is%3Aissue+is%3Aopen+label%3Ablocked)
- [M0 / P0](https://github.com/pavlith/arc/issues?q=is%3Aissue+is%3Aopen+label%3A%22milestone%3A+M0%22+label%3A%22priority%3A+P0%22)

`blocked` — независимый признак блокировки и может сочетаться с текущим статусом.

## Жизненный цикл задачи

1. Создать Issue через подходящую форму и указать критерии приёмки.
2. Проверить автоматически назначенные метки `priority:*`, `milestone:*` и `status: backlog`.
3. Перед началом заменить статус на `status: in-progress` и назначить исполнителя.
4. В PR указать `Closes #<номер>` и фактически выполненные проверки.
5. Архитектурные или нормативные изменения одновременно внести в `docs/`.

Workflow `Triage issues` переводит связанный с Issue готовый PR в `status: review`, закрытый Issue — в `status: done`, а повторно открытый — в `status: backlog`. Статус `ready` и признак `blocked` назначаются вручную.

Во время M0–M6 выполняется минимальная проверка затронутого контура согласно требованиям. Полная матрица M7 не считается пройденной до её фактического выполнения.

## Метки

Метки описаны в `.github/labels.json` и синхронизируются workflow `Sync labels`. Workflow создаёт и обновляет перечисленные метки, но не удаляет остальные. В каждой из групп `status:*`, `priority:*` и `milestone:*` у Issue должна быть ровно одна метка.

## Codex и экономия контекста

Вначале выбрать конкретный GitHub Issue и его acceptance criteria; затем читать лишь относящиеся к нему разделы нормативных документов (маршруты указаны в AGENTS.md). При изменении контрактов синхронизировать ARCHITECTURE.md и REQUIREMENTS.md, не добавляя отдельные ADR или backlog. Использовать соответствующий skill из .agents/skills/, а не все сразу. Для проверки: bash scripts/verify-changed.sh; при отсутствии реализации зависимых компонентов явно отмечать пропуски. Настройка клиента и MCP — в [CODEX.md](CODEX.md).

