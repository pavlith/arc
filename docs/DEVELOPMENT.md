# Процесс разработки

## Источники истины

- GitHub Issues — задачи, дефекты и предложения.
- GitHub Projects — статус, приоритет, этап и порядок выполнения.
- `docs/REQUIREMENTS.md` — требования и границы продукта.
- `docs/ARCHITECTURE.md` — архитектура и долговременные решения.

Notion и дублирующие Markdown-backlog-файлы не используются.

## GitHub Project

Создайте user project `Arc` и подключите репозиторий `pavlith/arc`. Рекомендуемые поля:

| Поле | Тип | Значения |
|---|---|---|
| Status | Single select | Backlog, Ready, In progress, In review, Done |
| Priority | Single select | P0, P1, P2, P3 |
| Milestone | Single select | M0, M1, M2, M3, M4, M5, M6, M7 |

Представления:

- `Roadmap`: группировка по Milestone, сортировка по Priority.
- `Board`: колонки Status, фильтр по активному Milestone.
- `Backlog`: таблица открытых задач, сортировка Priority → Milestone.

Автоматизация Project:

- новый Issue или PR → `Backlog`;
- PR, связанный с Issue → `In review`;
- закрытый Issue или merged PR → `Done`.

## Жизненный цикл задачи

1. Создать Issue через подходящую форму и указать критерии приёмки.
2. Заполнить в Project поля Priority и Milestone.
3. Перед началом перевести задачу в `In progress` и назначить исполнителя.
4. В PR указать `Closes #<номер>` и фактически выполненные проверки.
5. Архитектурные или нормативные изменения одновременно внести в `docs/`.

Во время M0–M6 выполняется минимальная проверка затронутого контура согласно требованиям. Полная матрица M7 не считается пройденной до её фактического выполнения.

## Метки

Метки описаны в `.github/labels.json` и синхронизируются workflow `Sync labels`. Workflow создаёт и обновляет перечисленные метки, но не удаляет остальные.
