# Техническое задание: Arc

> **Версия:** 0.9 · **Статус:** M0 — архитектурная ревизия, согласованные контракты и стратегия отложенной полной верификации · **Дата:** 2026-10-26
> **Архитектура:** [ARCHITECTURE.md](ARCHITECTURE.md)  
> **Назначение:** спецификация Arc для реализации на базе [Kuayle](https://github.com/carbogninalberto/kuayle); без обязательной GitHub-ориентированной модели.  
> **Приоритеты:** `P0` — инфраструктурный минимум; `P1` — офисный MVP; `P2` — автоматизация/агенты; `P3` — расширенное управление инфраструктурой. Требования «позже» не входят в критерии MVP.

## 1. Продукт, цели, объём

Разработать **Arc** — русскоязычную self-hosted веб-платформу для небольших и средних команд: единые учётные записи, рабочие пространства, группы и ACL; задачи; личные и общие календари/контакты; файлы; иерархические страницы; далее — коннекторы, агенты и workflows. Внешние клиенты получают доступ к поддерживаемым ресурсам по HTTP, CalDAV, CardDAV, WebDAV. Обязательны контроль над данными, независимость от облака разработчика и расширение микросервисами без правки ядра.

**Целевые пользователи:** владелец инсталляции, workspace-admin, сотрудник, гость, автоматизированный сервис и AI-агент с явно делегированными полномочиями.

**Не входит в начальный scope:** enterprise IAM (SAML/SCIM/LDAP), полноценный CRM, Notion Databases, офисный редактор DOCX/XLSX в браузере, полноценный Kubernetes/Portainer, встроенная собственная почта, GitHub как обязательная зависимость, синхронизация сторонних DAV-серверов в первой поставке, недоверенный multi-tenant code execution в обычном Docker.

### 1.1 Наследование Kuayle

Сохранить и адаптировать: Go/Echo API, Svelte 5 + shadcn-svelte UI, workspaces, roles, tasks/issues, projects, Kanban/list/views, notifications, realtime, Tiptap, uploads и применимые тесты. Github App и coding Dev Machines вывести из ядра: GitHub — необязательный connector; development runtime — частный вид agent/execution runtime. Миграция должна сохранять данные существующих рабочих пространств, насколько возможно; необратимые изменения документируются и тестируются. Не заявлять как готовую функцию то, что присутствует лишь в dev-ветке Kuayle.

## 2. Функциональные требования

### 2.1 Arc Core / Identity (`P0`)

- **I-01:** глобальная регистрация/вход/выход, защищённые сессии, refresh rotation/revocation, восстановление доступа, редактирование профиля; M0 допускает admin/CLI one-time recovery token без зависимости от ещё не реализованного mail connector. Настройки публичной регистрации и приглашений.
- **I-02:** создание workspace, роли `owner/admin/member/guest`, приглашения, изменение членства; пользователь может состоять в нескольких workspace без копирования аккаунта.
- **I-03:** группы доступа (`Group`/`GroupMember`) отдельно от прикладных `Team`; owner/admin могут выдавать членство и назначать permissions.
- **I-04:** service accounts и agent identities с scoped permissions; жизненный цикл секретов и журнал выпуска/отзыва делегаций.
- **I-05:** личные корневые ресурсы существуют вне workspace; уход из организации не удаляет их и не передаёт организации.
- **I-06 (M0):** разделить `User/AgentIdentity/ServiceAccount/ServiceCredential`; per-service NATS credentials с subject permissions **не** подменяют пользовательскую ACL. Service credentials привязаны к approved definition/deployment, приватный ключ не хранится в БД.
- **I-07 (M0):** браузерная session cookie `HttpOnly/Secure/SameSite` + CSRF; API access JWT `aud=gate`, время ≤10 мин, online session check; refresh family rotation/reuse detection и отзыв всей семьи при reuse. Секреты/refresh токены не записываются в логи.
- **I-08 (M0):** Core подписывает invocation JWT EdDSA (Ed25519), `iss/aud/sub/caller/op/cnf.kid/iat/nbf/exp/jti`, TTL ≤60 сек; `op` привязан к единственной утверждённой операции и проверяется SDK; доверенные services используют подписанные client assertions TTL ≤30 сек с одноразовым `jti`. Gate не владеет ключом подписи Core.
- **I-09 (M0):** SDK отправляет per-request proof, привязанный к ключу caller, target subject, `op`, request ID, payload hash и token jti; получатель отклоняет поддельную подпись, неверный `aud`/состояние ключа и изменение payload. Для side effects — persistent nonce dedupe и idempotency.
- **I-10 (M0):** Gate обменивает активную сессию на audience-bound invocation token; межсервисная цепочка получает новый token на каждом downstream target. `actor`, `on_behalf_of`, `caller` нельзя присвоить из payload/headers; нельзя расширить исходные права.
- **I-11 (M0):** явная Delegation с `grantor`, `grantee`, scope конкретных ресурсов/actions, обязательным `expires_at`, `consent_method` и audit. Agent/service не может выдать делегацию от чужого имени. Новый `Check` проверяет активность делегации и текущие права пользователя **онлайн**.
- **I-12 (M0):** отзыв сессии, grant/membership, service key и delegation блокирует последующие проверки после commit, даже если JWT не истёк; в отсутствие Core защищённые вызовы fail-closed. Уже запущенная операция может завершиться.
- **I-13 (после M0):** полноценные approval-политики для опасных агентных действий, SSO/MFA, управление NATS JWT/credentials, long-running delegation renewal — отдельные расширения.

**Сценарии верификации Identity:** пользователь состоит в двух workspace, personal root не удаляется при выходе; повторное применение refresh token отзывает семейство; отозванная сессия не проходит Gate и последующий Access.Check. Поддельный caller/плохая подпись request proof/изменённый payload, неверный `aud`, replay client assertion, revoked service key и истёкшая делегация отвергаются. Service/agent не может выпустить себе делегацию. Подпись proof проверяется на одинаковых JSON при разном порядке ключей и отвергает изменение канонического payload. В цепочке `Gate → Task → Calendar` корректно сохраняется actor, меняются audience/caller и не расширяются действия. Отзыв membership/grant блокирует агентный вызов при ещё действующем JWT. В M0 автоматизируются test vectors подписи, `aud/op/caller`, replay и один revoke-path; полная матрица выполняется в M7.

### 2.2 Resource ACL (`P0`)

- **A-01:** выборочный Resource Registry: ACL roots (`workspace`, `personal`, `calendar`, адресная книга, самостоятельный files/pages раздел, agent/workflow); обычные дочерние объекты могут наследовать root без отдельной записи. Domain-owner подтверждает связь объекта с root, бизнес-данные остаются в собственной БД.
- **A-02:** типы ресурсов и namespaced actions регистрируются только утверждённым контрактом; один `acl_parent` без циклов, совпадение owner/scope с parent, явная граница `inherit_acl=false`. Личные ресурсы не становятся workspace-owned при вступлении в организацию.
- **A-03:** только `allow` grants пользователю, workspace-group/role, service, agent; default deny, expiry и аудит. Workspace admin может управлять ACL корпоративных ресурсов, но **не** читать содержимое без соответствующего права; при этом полномочный ACL-admin может явно выдать такой grant себе с обязательным audit. `share` не позволяет выдавать права, которых нет у инициатора. `free_busy` и `read` независимы; скрытые дочерние разделы не наследуют grants родителя при `inherit_acl=false`.
- **A-04:** `Access.Check` на каждый защищённый RPC/DAV/API/tool без positive decision cache; `CheckMany` до 100 элементов для листингов и пагинированный `ListAccessibleRoots`. Domain-owner обязан фильтровать собственные данные и не доверять `resource_id`/`parent_id` из клиентского payload.
- **A-05:** отзыв grants, membership и делегации вступает в силу для новых проверок после commit; недоступность Core даёт fail-closed; отдельные ревизии политики, неизменяемые audit events. Для уже начатых операций мгновенное прерывание не обещается.
- **A-06:** `reserve/activate/abort/begin_delete/finalize_delete` идемпотентны, ресурс до `active` не виден, при удалении новые проверки запрещаются; reconciler восстанавливает ошибки между Core и доменной БД.
- **A-07:** агент/workflow может действовать только в пересечении собственных инструментальных разрешений, действующей пользовательской делегации и текущего ACL. NATS headers не доказывают publisher identity; проверяются invocation JWT и ключевой per-request proof по §3 архитектуры.
- **A-08 (M2–M3):** персональный group/cross-workspace sharing, публичные share links с expiry/revoke, ограничения streaming и дополнительные политики — отдельно от M0.

**Сценарии верификации ACL:** полная матрица §4.5 [ARCHITECTURE.md](ARCHITECTURE.md): (1) уход из workspace не удаляет личный root; (2) `free_busy` не раскрывает событие; (3) администратор ACL без права скачать файл; (4) приватный дочерний раздел; (5) чужой `event_id/file_id` при допустимом ACL root; (6) отзыв membership/delegation; (7) неверный JWT/audience/caller; (8) fail-closed; (9) повторные reserve/activate/delete и восстановление после crash; (10) пакетные проверки без N+1 RPC. M0 guardrail обязательно покрывает owner/no-grant, revoke, cross-root spoofing, fail-closed и повтор `reserve/activate`; остальная автоматизация завершается в M7. До появления реальных DAV/file endpoints допустимы фиктивные Calendar/Files ресурсы.

### 2.3 Service Fabric / Arc SDK (`P0`)

- **F-01:** `arc-sdk` — самостоятельный Go module **над официальным `nats.go/micro` без форка**; поддерживает `Service/Endpoint`, `$SRV.PING/INFO/STATS`, queue groups, typed handlers/clients и единый lifecycle.
- **F-02:** Service Definition, immutable утверждённый Service Contract и эфемерный Service Instance — разные сущности. Manifest v1 содержит `api_major`, операции (`query/command`), subjects, JSON schemas+digest, resources/actions, auth root extractor, HTTP exposure, optional tools/workflow, события, limits; unknown fields и конфликтующие names отклоняются.
- **F-03:** Core утверждает digest **детерминированного** manifest + schemas, identity/deployment и NATS subjects. Сервис до approval не открывает business RPC subscriptions; после approval SDK регистрирует все обязательные handlers и подтверждает readiness. Неизвестный или отозванный digest, чужой service-account, ошибочная schema → deny.
- **F-04:** Core NATS `rpc.<service>.v<major>.<operation>` с queue group `q.<service>.v<major>`; JetStream `evt.<service>.<entity>.<event>.v<major>`; control subjects ограничены NATS permissions. Instance discovery/metrics через NATS Micro, actual readiness — отдельная проверка.
- **F-05:** JSON RPC envelope содержит `request_id`, version, payload, `deadline_at`, optional `idempotency_key`, trace, audience-bound invocation JWT и proof; validate input/output JSON Schema, verify caller/ACL. Query 5с, command 10с, envelope/response ≤256 KiB. Унифицированные ошибки и безопасное HTTP mapping.
- **F-06:** Изменяющая операция требует idempotency key с server-side atomic replay ≥24ч; одно и то же `(actor, operation, key)` с отличным request hash → `CONFLICT`. На timeout клиент повторяет с тем же ключом, а не с новым; exactly-once не обещается.
- **F-07:** Изменение доменных данных + outbox атомарны; JetStream worker dedup события через inbox `event_id`, retry/backoff/DLQ; inbox + внутренний DB side-effect фиксируются атомарно, для внешних эффектов возможны дубли; события версионированы и сами по себе не предоставляют доступ к данным ресурса.
- **F-08:** API breaking change требует новый major subject и HTTP prefix; build SemVer не равен API major. Contract tests проверяют обратную совместимость additive changes и сосуществование версий. Автогенерация клиентов не блокирует M0.
- **F-09:** SDK предоставляет package-level typed register/call helpers, scopes и безопасный handler pipeline. Tool/workflow и HTTP exposure — **явный opt-in**; SDK не пропускает ACL через прямой RPC и не принимает недостоверные identity headers.

M0-04 использует подписанные локальным оператором install artifacts, SQLite Fabric catalog в Core и онлайн `ContractSource` Access. Регистрация instance требует отдельные assertion/proof; readiness связывает signed probe с Micro INFO, всеми endpoints и queue groups. Domain commands проходят `HandleCommand` с атомарными result/effect/outbox и response validation до commit; event consumer фиксирует inbox/effect перед ACK. `incoming_api_major` расширяет downstream exchange без снятия audience/action checks. До rolling upgrade действует один активный digest на service/API major; Gate ingress реализуется в M0-05.

**Сценарии верификации Fabric:** два разных digest — only approved allowed; неизвестный ресурс/action/HTTP route и conflict параметризованного пути отклоняются; три реплики одной версии выполняют RPC через одну queue group; incompatible majors изолированы; invalid request/response schema отклоняются; подделка identity/proof запрещена; stop/reconnect/no responders → управляемая ошибка; при timeout после успешной записи повтор mutation с тем же ключом не создаёт дубль; публикация через outbox и повтор JetStream event не создают второго эффекта. M0 guardrail автоматизирует digest/action/schema/proof, разделение major, idempotency и duplicate event; многорепличность и полный recovery завершаются в M7.

### 2.4 Gate (`P0`)

- **G-01:** единый публичный HTTPS ingress REST/WS/DAV; NATS и приватные служебные HTTP adapters не опубликованы.
- **G-02:** external auth + online session check, audience-bound invocation exchange и caller proof; HTTP input validation/schema/size/rate limit, CORS/CSRF, unified error mapping; незаверенные `X-User-ID`/`X-Service` не используются как identity.
- **G-03:** Gate получает из Core **атомарный RouteSnapshot(revision,digest,routes,kid,signature) с проверкой подписи Core и digest** только утверждённых routes, reject rollback/conflicts и reserved paths; загрузка при cold start, refresh по событию с reconciliation при потере уведомления; runtime-анонс не публикует новый HTTP API.
- **G-04:** защищённый route без живого RPC responder → `503`, истечение deadline → `504`; ACL проверяется сервисом; недоступность Core означает `UNAVAILABLE`/HTTP `503` (без side-effect), отказ policy → `PERMISSION_DENIED`/HTTP `403` либо безопасный `404`. Unknown/неодобренный route не обслуживается; successful HTTP `201/202` только из approved contract.
- **G-05:** WebSocket subscriptions с авторизацией по ресурсу; DAV routing и большой file streaming без переноса потока файлов в NATS.

**Сценарии верификации Gate:** `POST /api/v1/tasks` → approved RPC; `401/403/409/503/504` корректны; route snapshots не откатываются; restart/cold-start/poll reconciliation работают; злоумышленник не может опубликовать `/api/v1/arc/*` либо подменить `/api/v1/task/{id}` статическим конфликтом; отказ Core блокирует новые защищённые вызовы. M0 guardrail покрывает approved route, invalid snapshot signature, reserved/conflicting route и fail-closed; полная error/restart/reconciliation matrix выполняется в M7.

Реализация M0-05: Gate работает отдельным процессом без БД; snapshot и active JWKS поступают через signed-service RPC `ctl.arc.fabric.routes` в root-signed request-bound bundle. Snapshot имеет canonical content digest, `kid`, domain-separated signature, contract artifacts и explicit HTTP bindings; rollback/conflicting revision, system paths и collisions запрещены. `__Host-` browser cookies + Origin/CSRF и `aud=gate` Bearer используют online Identity; внутренний `sessions.validate` не дублирует session state. HTTP → RPC сохраняет request/trace/deadline/idempotency, требует schema и target-scoped invocation, а owner-service выполняет ACL. Auth endpoints и limits доступны сейчас; DAV/WS, пользовательский UI и полный recovery остаются последующим этапам/M7.

### 2.5 Task / Projects / Notify (`P1`, часть используется уже при `P0`)

- **T-01:** задачи с ID, названием, rich-text, статусом, приоритетом, сроком, несколькими исполнителями, label, files, comments, history.
- **T-02:** подзадачи, связи (`blocked/blocks`, duplicate, related), triage, шаблоны, bulk-actions.
- **T-03:** workspace/team projects; Kanban, list, saved views, фильтры; cycles/sprints — необязательный модуль.
- **T-04:** уведомления, подписки, inbox, архив, realtime events; связи task ↔ page/file/event/contact.
- **T-05:** GitHub не требуется для создания/редактирования задач; интеграция доступна только через коннектор.

**Приёмка:** создание задачи через UI и API даёт одинаковую модель; исполнитель видит задачу по ACL; событие `evt.task.task.created.v1` запускает notification worker; после изменения роли запрещённая задача не отображается ни в поиске, ни в публичной ссылке без grant.

M0-06 ограничен workspace Task create/get/list, transactional command result/outbox,
Notify inbox/internal record и persisted fake outbound intent. Identity/proof,
owner/root/workspace и ACL проверяются онлайн до мутации и replay. Operator-approved
адресация не берётся из event; inbox/effect/intent атомарны, внешний retry использует
стабильный dedup key без обещания exactly-once. Полный Task/Kuayle, UI и реальные
providers отложены до M1; полная crash/load/recovery матрица — M7. Исполняемый smoke
и узкие guardrails: [M0-06](M0-06.md), `scripts/test-m0-06.sh`.

### 2.6 Calendars / CalDAV (`P1`)

- **C-01:** календарь по умолчанию у каждого пользователя; создание нескольких личных и workspace-календарей, владельцы и grants по группам.
- **C-02:** события, all-day/timezone, повторения и исключения, attendees как поля данных, вложения/ссылки и permission `free_busy`.
- **C-03:** CalDAV Server с discovery, iCalendar round-trip, ETag, sync-token, корректной инкрементальной синхронизацией и ACL.
- **C-04:** единый UI по всем доступным календарям, фильтры, права read/write/free-busy, создание и изменение событий.
- **C-05 (позже):** приглашения и scheduling по протоколу, ресурсы/переговорные, внешняя двусторонняя CalDAV sync.

**Приёмка:** личный и workspace-календарь подключаются в двух разных CalDAV-клиентах; CRUD и повторение синхронизируются без дублирования; read-only клиент не меняет события; коллега с `free_busy` не видит заголовок приватной встречи.

### 2.7 Contacts / CardDAV (`P1`)

- **K-01:** личные и workspace-адресные книги; владелец, grants, просмотр по группам.
- **K-02:** контакты: имя, организация, должность, телефоны, email, адреса, заметки, фото, произвольные поля; связи с задачами/событиями/страницами.
- **K-03:** CardDAV Server: vCard round-trip, сохранение неизвестных свойств, ETag и инкрементальная синхронизация.
- **K-04 (позже):** удалённые источники, merge/deduplication и расширенный CRM.

**Приёмка:** контакт, созданный внешним CardDAV-клиентом, появляется в UI без потери неизвестных vCard-полей; права адресной книги работают одинаково в API и CardDAV.

### 2.8 Files / WebDAV / Sharing (`P1`)

- **L-01:** личное и workspace-хранилище с папками, загрузкой, скачиванием, поиском, перемещением, удалением и метаданными.
- **L-02:** local FS или S3-compatible bytes; метаданные/ETag в DB; объёмы передаются streaming, resumable/large-file policy определяется отдельно.
- **L-03:** WebDAV Server и подключение внешних файловых клиентов с ACL, стандартными файловыми операциями и конфликтным контролем.
- **L-04:** публичная ссылка с read/expiry/revoke/password (если утверждено); режим «загрузить в папку» — последующий этап.
- **L-05:** вложения задач/страниц используют Files, а не отдельные независимые бинарные хранилища.
- **L-06 (позже):** history/restore, recycle bin, quotas, thumbnails и расширенные внешние storage connectors. Схема допускает версии с первого этапа.

**Приёмка:** файл загружается через UI и доступен авторизованным пользователям по WebDAV; outsider не скачивает даже по известному ID; отзыв share link прекращает доступ; загрузка большого файла не вызывает NATS payload overflow.

### 2.9 Pages (`P1`)

- **P-01:** иерархические страницы user/workspace, корневые разделы, наследование ACL, sidebar/tree, поиск.
- **P-02:** редактор Tiptap: заголовки, списки, таблицы, code, task-list, изображения, ссылки на ресурсы платформы, шаблоны.
- **P-03:** версии страниц и базовое восстановление, безопасная обработка HTML/вложений; внутренние ссылки на страницы и ресурсы показываются только при ACL. Публичные share links — отдельный этап после общего механизма sharing (не блокируют M1).
- **P-04 (позже):** совместное CRDT-редактирование через Yjs, Notion-подобные базы данных исключены из MVP.

**Приёмка:** пользователь создаёт и перемещает страницу в дереве; разрешения пересчитываются при переносе между разделами; embedded ссылка на запрещённый файл не раскрывает превью или содержимое.

### 2.10 Connectors (`P2`)

- **X-01:** реестр доверенных connector manifests; версии, triggers, actions, scopes, secrets, optional external sync.
- **X-02:** connections владельца `user/workspace`; OAuth/API keys, шифрование, отзыв и аудит; отсутствие автоматического sharing персональных OAuth connections.
- **X-03:** входящие webhooks, polling, исходящие API с retries/rate limits и сетевой allowlist для небезопасных destinations.
- **X-04:** первая реализация: универсальный HTTP connector и отдельный GitHub connector; внешняя CalDAV/CardDAV/WebDAV sync — дополнительный набор коннекторов.

**Приёмка:** connector объявляет action и trigger, они появляются в реестре; workflow вызывает action только при достаточных scopes; отзыв connection немедленно блокирует новые вызовы.

### 2.11 Workflows (`P2`)

- **W-01:** workflow definition, version, state, ownership/ACL; triggers: Arc event, schedule, manual, approved webhook.
- **W-02:** condition на CEL, transform/script на ограниченном Starlark, типизированные actions через Service Fabric; никакого прямого произвольного SQL/Docker/сетевого доступа из скрипта.
- **W-03:** durable runs, attempts, idempotency, timeout, retry/backoff, error state, история шагов, manual retry/cancel, audit.
- **W-04:** execution quotas, циклические вызовы/recursion limits, запрет бесконечных автоматизаций; actions от service account или ограниченной делегации пользователя.

**Приёмка:** на событие создания task workflow фиксирует один внутренний результат при duplicate delivery; внешняя отправка зависит от дедупликации провайдера; workflow с запрещённым action заканчивается `PERMISSION_DENIED` без побочных изменений; run восстанавливается после рестарта worker.

### 2.12 Agents (`P2`)

- **AG-01:** personal/workspace agents, модель и provider settings, identity, allowed tools, limits, scopes, audit, approval required для чувствительных действий.
- **AG-02:** три режима: интерактивный, bounded task run, event/scheduled; tools берутся из approved capability registry.
- **AG-03:** агенты читают/меняют задачи, календари, контакты, файлы, страницы **через те же операции и ACL**, что используют люди.
- **AG-04:** поддержка OpenAI-compatible API и локальных/удалённых моделей при наличии совместимого endpoint; MCP endpoint/adapter как отдельная поверхность авторизации.
- **AG-05 (позже):** coding agents в изолированных runtime-контейнерах (Codex, Claude Code, OpenCode, custom), browser/terminal optional. Никакой универсальной передачи Docker socket агенту.

**Приёмка:** agent без `files.read` не может прочесть файл; агент может предложить создание события, которое требует user approval; все side-effects указывают actor и `on_behalf_of`; event-driven run завершается с трассировкой.

### 2.13 Runtime Control и Arc Infrastructure Agent (`P3`, безопасный каркас в `P0`)

- **R-01 (M0):** `RuntimeNode`, `RuntimeTemplate`, `Deployment`, immutable spec revision, `RuntimeOperation`, `InstanceObservation`, схемы БД и `RuntimeProvider` интерфейс; разделить desired state в Core, наблюдения от Agent и подтверждённую Fabric readiness.
- **R-02 (M0):** bootstrap Compose/systemd готовит SQLite-тома и запускает NATS, Arc Core и Arc Gate независимо от управляющего API; **реального Arc Infrastructure Agent в M0 нет**, только fake Agent для контрактных guardrails. В M6 реальный Agent запускается отдельно и не управляет bootstrap. `arc.runtime.manage` отдельно от workspace-admin, default deny.
- **R-03 (M0):** контракт NATS desired snapshot/observations с per-node service credentials, invocation/proof, version/revision, идемпотентностью; fake Agent и negative contract tests. M0 **не** включает фактическое управление Docker из UI.
- **R-04 (M6):** единственный поддерживаемый host — один доверенный Linux/Docker node; Agent выполняет только approved templates/immutable image digests и управляет **только** подтверждённо принадлежащими deployment контейнерами. Никакого arbitrary Compose, shell, privileged containers, host mounts, Docker socket/host network в managed workloads.
- **R-05 (M6):** create/start/stop/restart/update/delete managed deployment, replica count, quotas CPU/RAM/PIDs/disk, health/logs/observations; secrets только по ссылкам, без записи чувствительных значений в БД/сообщения/логи. Destructive volume purge отдельно подтверждается.
- **R-06 (M6):** Core reconciler с lease и Agent single-writer сериализацией; monotonic spec revision, expected-revision конфликт, операции `pending/running/succeeded/failed/cancelled`, retry/backoff и idempotency. Устаревшая команда никогда не перезаписывает новый desired state.
- **R-07 (M6):** при потере Core/NATS Agent не исполняет старые кэшированные изменения, работающие контейнеры сохраняются; после восстановления выполняет safe reconciliation и пересверяет Fabric readiness. Изолированное падение Agent не останавливает workloads.
- **R-08 (M6):** update — смена immutable image digest и создание новой revision; single-node recreate допускает downtime. Автоматический rollback и zero-downtime rollout не обещаются, пока не доказана совместимость миграций.
- **R-09 (после M6 baseline):** multi-node scheduler/placement, доверенный sandbox для враждебных плагинов и кодовых агентов, автоматический безопасный rollback — дополнительные возможности.

**Интеграция M0:** миграции и interfaces компилируются; fake Agent отклоняет неправильный node/proof/revision и запрещённый template; bootstrap сервисы нельзя указать как managed; `tasks/notifications` работают без реального Docker agent. **Интеграция M6:** один happy path управления deployment и критические запреты spoof credentials/host mounts/privileged. Полная матрица replicas 2→3, crash/host/agent recovery, duplicate/stale revisions, отсутствие секретов, сохранение volumes и статусы `Degraded`/`Failed` выполняется в M7.

## 3. Нефункциональные требования и гарантии

| ID | Требование | Проверка |
|---|---|---|
| N-01 Security | TLS на внешнем ingress и внутренних NATS соединениях в production; scoped NATS creds; EdDSA invocation и request proof; audit ACL/credentials/delegations/runtime | E2E security tests, review threat model |
| N-02 Isolation | Разделение workspace/user + доменный ACL на REST, DAV, RPC, tools и поиске | Negative permission matrix |
| N-03 Reliability | Transactional outbox, idempotent consumers, retries, deadlines и graceful shutdown | Тесты потери сети, падения consumer, duplicate delivery |
| N-04 Portability | Linux + Docker Compose self-hosted; база и storage с документированным backup/restore | Сборка с чистого хоста и восстановление backup |
| N-05 Observability | JSON logs, trace/correlation IDs, health/readiness, метрики Gate/Core/RPC/JetStream | Трассировка сквозного запроса |
| N-06 Compatibility | CalDAV/CardDAV/WebDAV проходят утверждённую матрицу клиентов | Клиентские интеграционные тесты |
| N-07 UX | Svelte 5, адаптивный UI, быстрый поиск, клавиатурные операции, доступная навигация | E2E browser tests |
| N-08 Localization | Русский интерфейс обязателен, i18n архитектура с fallback en | Проверка ключевых сценариев ru/en |
| N-09 Contract Stability | Immutable manifest/schema digest, SemVer SDK vs API major, безопасное coexistence версий | Contract tests additive/breaking changes, route collisions и 2 majors |
| N-10 Operability | Migration up/rollback-policy; backup до критичных миграций, startup checks | Upgrade / failure-recovery tests |
| N-11 Runtime Boundary | Bootstrap независим от управляющего API; Agent-only Docker access, no privileged/host mount и только approved image digests | Критические privilege guardrails в M6, полная host/permission matrix в M7 |

**Нормативные M0 defaults:** RPC query 5 с, command 10 с, payload/response ≤256 KiB, replay window idempotency ≥24 ч, access JWT ≤10 мин, invocation JWT ≤60 сек, client assertion ≤30 сек, срок одноразовой делегации по умолчанию 24 ч; никакого положительного decision cache. Отзыв доступа: новая проверка после commit запрещает действие; уже начатые операции могут закончиться. Остальные числовые SLO (p95/RTO/RPO/нагрузка) определяются замерами, а не выдуманными гарантиями.

### 3.1 Хранение SQL-данных (решение 2026-10-26)

Core, Task и Notify используют GORM и отдельные локальные SQLite-файлы; Gate не имеет БД. История миграций принадлежит сервису; Gormigrate запускается явно до приёма трафика, повтор безопасен, неизвестные версии запрещены. WAL, foreign keys и busy timeout обязательны на каждом соединении. Изоляция владельцев обеспечивается отдельными файловыми mounts/правами ОС и RPC/events; общий файл, ATTACH и SQL к чужому владельцу запрещены. Мутация, audit, replay и outbox либо inbox/effect атомарны; SQLite writer lock приобретается до чтения изменяемого состояния, transient busy повторяет всю транзакцию. Многонодовая репликация независимых SQLite-файлов не поддерживается; полная recovery/load matrix остаётся M7.


## 4. План этапов и выходные артефакты

| Этап | Состав | Условие завершения |
|---|---|---|
| **M0 — Foundation** | Arc Core (Identity, ACL, Fabric, Runtime data model + fake provider), NATS/JetStream, `arc-sdk`, Arc Gate, proof-сервисы `tasks` и `notifications`, SQL migrations, approved manifest | Вертикальный smoke и обязательные security/ACL/contract/idempotency guardrails проходят без Docker management API; компоненты имеют статус `Integrated` |
| **M1 — Office Core** | Миграция Kuayle Task/Projects/Views, Pages, связи ресурсов, уведомления, RU UI | Основные happy paths для двух workspace, личного пространства, задач и страниц интегрированы без обязательной полной UI-регрессии |
| **M2 — Personal Data** | Calendars+CalDAV, Contacts+CardDAV, free/busy, группы доступа | По одному поддерживаемому внешнему клиенту проходит smoke sync; полная клиентская матрица отложена до M7 |
| **M3 — Files** | Files Service, object storage, WebDAV, shares, миграция attachments | Happy path streaming/sync/revoke интегрирован; полная WebDAV и failure matrix отложена до M7 |
| **M4 — Automation** | Events catalog, Workflow Engine, CEL/Starlark, run history | Один durable workflow проходит end-to-end; обязательны guardrails idempotency и запрета недоступного action |
| **M5 — Integration & Agents** | Connector Registry, базовые connectors, agent orchestration, tools/MCP, approvals | Один ограниченный agent/connector/workflow path использует общий контракт и ACL без обхода прав |
| **M6 — Managed Runtime** | Single-node Docker Arc Agent, approved templates, deployment UI, replicas/reconcile, ограниченный update, logging/observations | Happy path управления deployment и критические privilege guardrails интегрированы; bootstrap остаётся вне управления |
| **M7 — Verification & Hardening** | Feature freeze, полный unit/integration/contract/E2E/security/recovery/compatibility/performance цикл | Все обязательные возможности имеют статус `Verified`; итоговая регрессия зелёная, release blockers устранены |

M0–M6 образуют **Build Phase**: интерфейсы инструментов и event contracts разрабатываются на M0, даже если полные Agents и Workflows выходят позже. Допускается перекрытие этапов без изменения обязательных guardrails. M7 начинается после функциональной заморозки; новые функции в нём не добавляются, кроме изменений для тестопригодности и исправления дефектов.

## 5. Сквозные сценарии финальной приёмки M7

В M0–M6 автоматизируется только обязательное подмножество guardrails из §6; весь перечень ниже является release-регрессией M7.

1. **Два workspace:** сотрудник состоит в A и B; выходит из A; личный календарь остаётся, корпоративные ресурсы A недоступны во всех протоколах.
2. **ACL:** группа «Бухгалтерия» может редактировать общий календарь, «Менеджеры» видят только занятость; ресурс B не читается через подмену ID.
3. **Dynamic service:** заранее утверждённый manifest+schema digest, instance proof/readiness и snapshot revision позволяют Gate открыть только разрешённый route; rogue service, route collision, несовместимый major, no responders/timeout проверяются отрицательными тестами.
4. **Event delivery:** Task создан, outbox публикует событие, Notification worker выполняет действие; потребитель останавливается и затем восстанавливается без потерь или дублей.
5. **Sync:** пользователь подключает личный и shared календарь, адресную книгу и файлы к внешним DAV-клиентам с корректными permissions и конфликтным контролем.
6. **Resource links:** встреча содержит ссылку на страницу и файл; пользователь без прав видит только разрешённые сведения, содержимое ссылки скрыто.
7. **Agent:** агент запрашивает создание задачи/встречи по делегации; чувствительное действие проходит approval; все изменения аудируются.
8. **Workflow:** событие → условие CEL → обработка Starlark → типизированное действие; права не обходятся, повторное событие не дублирует side effect.
9. **Infrastructure:** UI увеличивает replica count управляемого сервиса, Agent приводит состояние к требуемому; запрет на privileged workloads и управление bootstrap.
10. **Disaster recovery:** после восстановления БД/объектов и secrets на чистом хосте Gate, Core, NATS и прикладные сервисы сохраняют согласованные данные/permissions.

## 6. Уровни готовности и политика тестирования

| Уровень | Definition of Done |
|---|---|
| `Implemented` | Код собирается; миграции применяются к пустой БД; основной сценарий пройден вручную или test client; отложенные проверки записаны как сценарии с ID |
| `Integrated` | Возможность подключена к Arc; есть logs/metrics/trace; проходит короткий smoke и обязательные guardrails затронутых security/contract/data boundaries |
| `Verified` | Автоматизированы и пройдены полные unit/integration/contract/E2E, negative permission и failure/recovery сценарии M7 |

Для завершения M0–M6 достаточно `Integrated`; требование иметь полный набор unit + integration + E2E на каждом build-этапе отменено. Production-релиз требует `Verified` для обязательного scope.

Во время M0–M6 на каждом изменении выполняются compile/build, formatting/static analysis затронутых модулей, новые миграции на пустой БД, schema/manifest validation и один smoke изменённого happy path. Целевое локальное время этого контура — до 1–2 минут. Точечный regression test добавляется при исправлении найденного дефекта.

Нельзя откладывать guardrails для invocation JWT/request proof, основных ACL deny/revoke/cross-root случаев, миграций, idempotency/outbox/inbox, contract digest/version/route collision, Runtime privilege boundary и одного вертикального сценария `login → Gate → service → Access → DB → event/consumer`. Исчерпывающие CRUD unit tests, UI/browser, DAV-клиенты, timezone/recurrence, chaos/soak/load, полная permission matrix, accessibility/i18n и backup/restore/upgrade combinations переносятся в M7.

Тестопригодность является частью `Integrated`: время/UUID/сеть/storage/providers заменяемы, бизнес-логика отделена от transport handlers, schemas/fixtures версионируются, seed data воспроизводимы, idempotency встроена сразу. Документация описывает только реально реализованное; архитектурные отклонения обновляются в обоих документах до слияния кода.

## 7. M0: конкретные deliverables и оставшиеся этапные вопросы

M0 выполняется без рефакторинга всего Kuayle: минимальные `tasks` и `notifications` — отдельные proof-services. Их цель — подтвердить жизнеспособность фундамента Arc короткими guardrails, а не завершить полную регрессию. Детальная миграция Kuayle начинается в M1.

| Порядок | Обязательная поставка M0 | Критерий готовности |
|---|---|---|
| 1 | Bootstrap NATS/SQLite/Compose, миграции, доверенные service accounts/keys и **минимальный SDK transport** (`connect/request/reply`, typed error) | Повторный startup и smoke RPC без Gate; секреты не попадают в БД/логи |
| 2 | Identity поверх транспортного SDK: login/session+refresh rotation, memberships/groups, service accounts/keys, signed invocation+request proof, delegation и token exchange (пока через test client, без Gate) | Test vectors proof/canonical payload, `aud/op/caller`, replay assertion, один revoke-path и запрет self-delegation проходят; полная negative matrix — M7 |
| 3 | Access: утверждённые resource types, grants, ACL roots, `reserve/activate/abort/delete`, `Check/CheckMany/ListAccessibleRoots` | Guardrails owner/no-grant, revoke, cross-root spoofing, fail-closed и повтор `reserve/activate`; полная матрица и recovery — M7 |
| 4 | **Доработка** `arc-sdk` + Fabric: проверяемый manifest/schema digest, Micro discovery, instance proof/readiness, RPC schema/error/versioning и JetStream | Rogue digest/action/schema отвергается; majors изолированы; idempotency и duplicate event проверены; replicas/reconnect/timeout matrix — M7 |
| 5 | Arc Gate: atomic RouteSnapshot revision, auth boundary, error mapping, reserved paths, route reconciliation | Approved route работает; invalid signature и reserved/conflicting route отвергаются; Core unavailable даёт fail-closed; полная restart/error matrix — M7 |
| 6 | Task proof-service + Outbox, Notify consumer с inbox/idempotency | Повтор события не создаёт второй **внутренний транзакционный** effect; внешний effect получает dedup key; расширенная crash matrix — M7 |
| 7 | Runtime DB/interfaces/fake Agent + logs/metrics + минимальный contract smoke | Сборка и чистая установка проходят; fake Agent отвергает плохой proof/revision, запрещённый template и bootstrap target; реального Docker management в M0 нет |

**Открыто до следующих этапов (не блокирует M0):** M1 — подробная миграция Task/Projects, судьба legacy GitHub и модель личных задач; M2 — меж-workspace sharing, DAV scheduling и совместимость клиентов; M3 — блокировки/версии/stream revoke для WebDAV; M4–M5 — Starlark sandbox, approval classes, connector secrets; после M6 baseline — multi-node runtime, автоматический rollback и zero-downtime rollouts.

**Контрольные точки ревизии v0.8:** до реализации зафиксированы `op`-bound invocation, правило `share` vs `manage_acl`, подписанный Gate snapshot, отсутствие реального Agent в M0, атомарность inbox+DB effect и честное at-least-once для внешних действий. В Build Phase измерить базовую задержку вертикального сценария; полные p50/p95 под двумя/тремя репликами выполнить в M7 и только затем решать необходимость оптимизации. Не принимать P1–P3 и полную регрессию как блокирующие M0.

**M0 baseline v0.8 пригоден для прототипирования, но ещё не проверен исполняемым кодом.** M0 получает статус `Integrated` после минимальных guardrails; статус `Verified` возможен только после M7. Любые изменения semantics в ходе проверок вносятся сразу в [ARCHITECTURE.md](ARCHITECTURE.md) и этот документ; новых ADR-файлов не требуется.

## 8. M7: обязательная финальная верификация

M7 начинается после feature freeze M0–M6 и включает:

1. Unit tests сложной бизнес-логики, policy evaluation, recurrence/conflict и преобразований данных.
2. Integration tests SQLite/GORM/Gormigrate, NATS/JetStream, object storage, migrations и внешних adapters.
3. Полные contract/security matrices Identity, ACL, Fabric, Gate, agents/workflows и Runtime.
4. Browser E2E, RU/EN, accessibility и поддерживаемые CalDAV/CardDAV/WebDAV clients.
5. Crash/network/restart, duplicate delivery, stale revisions, backup/restore и upgrade/failure recovery.
6. Нагрузочные измерения p50/p95, лимитов и длительные soak-сценарии без преждевременного объявления SLO.
7. Повторную полную регрессию после исправления release blockers.

Выход M7: обязательный scope имеет статус `Verified`, открытые дефекты классифицированы, release blockers отсутствуют, документация соответствует фактическому поведению Arc.
