# Архитектура Arc

> **Версия:** 0.9 · **Статус:** M0 — архитектурная ревизия, контракты согласованы для быстрой реализации с отложенной полной верификацией · **Дата:** 2026-10-26
> **Связанный документ:** [REQUIREMENTS.md](REQUIREMENTS.md)  
> **Основа:** переориентация [Kuayle](https://github.com/carbogninalberto/kuayle) (Go/Echo + Svelte 5) с сохранением применимых модулей.  
> **Маркировка:** **Решено** — согласованное направление; **M0 baseline** — проектный контракт для реализации и минимальной исполняемой проверки; **Открыто** — вопрос следующего этапа.

## 1. Цель и границы

**Arc** — self-hosted офисная платформа с задачами, календарями, контактами, файлами, страницами, агентами, коннекторами и автоматизациями. Новые прикладные сервисы подключаются через NATS, объявляют собственные типы ресурсов/операции/события, а внешний доступ предоставляется через единый Gate. Права не зависят от способа обращения: UI, HTTP API, DAV, NATS RPC, workflow или AI-инструмент.

**Решено:** единый **Arc Core** (`arc-core`) — модульный Go-процесс с `Identity`, `Access Control`, `Service Fabric`, `Runtime Control`; между разными процессами — NATS; внутри Core — прямые Go-интерфейсы. **NATS Server**, **Arc Gate** (`arc-gate`) и привилегированный **Arc Infrastructure Agent** (`arc-agent`) — отдельные процессы. `arc-sdk` — общая Go-библиотека, а не отдельный сервис.

### Контекст

```mermaid
flowchart TB
    Clients[Web / mobile / DAV clients / external API] --> Gate[Gate: HTTP, WS, DAV ingress]
    Gate <--> NATS[NATS Core + JetStream]
    Core[Arc Core\nIdentity | Access | Fabric | Runtime] <--> NATS
    Apps[Task | Calendar | Contacts | Files | Pages\nAgents | Workflows | Connectors] <--> NATS
    Core --> CoreDB[(Core SQLite)]
    Apps --> Domain[(SQLite per service / object storage)]
    Agent[Arc Infrastructure Agent] <--> NATS
    Agent --> Host[Container runtime / managed nodes]
```

Схема логическая. Arc Gate — единственная **публичная** точка входа к API платформы; NATS, базы данных и Arc Infrastructure Agent не публикуются в интернет. Для больших файлов и DAV допустим частный HTTP streaming-адаптер за Gate, без переноса потока байтов в NATS. Bootstrap-инфраструктура существует независимо от Runtime Control.

## 2. Границы процессов и ответственности

| Процесс/модуль | Ответственность | Не делает |
|---|---|---|
| `arc-core/identity` | Users, global sessions, credentials, workspace, memberships, groups, service accounts, делегации | Бизнес-данные задач и файлов |
| `arc-core/access` | Типы ресурсов, grants, наследование, policy decisions и ревизии | Не обходит domain-owner при чтении/изменении объекта |
| `arc-core/fabric` | Утверждённые сервисные контракты, discovery, capabilities, маршруты, версии | Не выступает обязательным proxy для межсервисных RPC |
| `arc-core/runtime` | Deployments, desired state, операции, reconcile-политики, квоты | Не владеет Docker socket |
| `arc-gate` | Публичные HTTP/WS/DAV ingress, проверка внешней аутентификации, роутинг, лимиты | Не владеет бизнес-данными или ACL-истиной |
| `arc-agent` | Разрешённые операции с контейнерами/сетями/томами, сбор наблюдений | Не выдаёт права пользователям, не принимает произвольный `docker run` |
| `arc-sdk` | NATS Micro, typed RPC/events, контракты, контекст доступа, telemetry | Не доверяет полям `user_id` от клиента без аттестации |
| Доменные сервисы | Свои таблицы, инварианты и бизнес-объекты; policy enforcement | Не читают/меняют чужие таблицы напрямую |

**Базовое допущение:** каждый SQL-владелец (Core, Task, Notify) хранит данные в отдельном SQLite-файле через GORM; Core объединяет четыре модуля в одной БД с таблицами `identity_*`, `access_*`, `fabric_*`, `runtime_*` и общей транзакцией административных изменений. Миграции Gormigrate запускаются отдельной командой до сервиса; AutoMigrate при startup запрещён. Каждый процесс получает файловый доступ только к своей БД, WAL и SHM. Gate БД не имеет. Redis из Kuayle не является обязательным источником истины и может быть исключён, если нет конкретного потребителя.

## 3. Identity, Service Accounts и Delegation — контракт M0

**Принцип:** идентичность *человека или агента* (`actor`), аутентифицированный *процесс-отправитель* (`caller`) и *право действовать за другого* (`delegation`) — разные сущности. Подключение к NATS само по себе не даёт доступа к данным. Утверждённый Identity + ACL применяется в Gate, прямых NATS RPC, DAV и agent/workflow tools.

### 3.1. Модель principals и tenancy

| Сущность | Правило |
|---|---|
| `User` | Глобальный человек; личные ресурсы не принадлежат workspace; статус active/disabled; может состоять в нескольких workspaces. |
| `Workspace` / `Membership` | Workspace-owned данные изолированы; членство имеет роль owner/admin/member/guest и статус; изменение membership транзакционно инвалидирует доступ. |
| `Group` / `GroupMember` | ACL principal внутри **одного** workspace; `Team` в Task — отдельное бизнес-понятие, не синоним группы. |
| `ServiceAccount` | Логическая техническая identity, привязана к утверждённому service definition/deployment; отключение блокирует выдачу и новые проверки. Не имеет неявных пользовательских ACL. |
| `ServiceCredential` | Ключ/credential экземпляра или deployment, закреплённый за ServiceAccount: `kid`, public key, статус, период ротации; приватный ключ хранится в secret mount, **не** в БД. |
| `AgentIdentity` | Отдельный principal; владелец и область исполнения явно указаны. Права на tools не означают прав на содержимое ресурсов. |
| `Session` / `RefreshFamily` | Серверное состояние активной пользовательской сессии и семейства refresh tokens для отзыва и детектирования повторного использования. |
| `Delegation` | Явное ограниченное согласие пользователя (`grantor`) в пользу агента/сервиса (`grantee`): область ресурсов/действий, срок, статус, условия подтверждения. Не изменяет ACL ресурсов. |

Личное владение не меняется при вступлении/выходе из workspace. Меж-workspace sharing и группы на личных ресурсах откладываются до M2. В M0 принадлежность service account к платформе не даёт ему автоматически прав внутри workspace — для автономных действий нужны адресные grants; для действий *от имени пользователя* дополнительно нужна делегация.

### 3.2. Границы доверия и четыре вида credentials

| Уровень | Механизм M0 | Проверка |
|---|---|---|
| Browser | `HttpOnly; Secure; SameSite=Lax` cookie с непрозрачным случайным session ID; CSRF для изменяющих cookie-auth запросов, origin checks | Gate обращается к Identity и проверяет сессию, включая отзыв |
| Внешний API | Короткоживущий access JWT, `aud=gate`, `sid`, `jti`; refresh family с ротацией и хранением **только хешей** refresh tokens | Gate валидирует подпись/срок и живое состояние сессии |
| NATS соединение | Отдельные NATS NKey/JWT credentials с ограничениями publish/subscribe по subjects, TLS | Проверяет `nats-server`; NATS JWT **не равен** invocation JWT платформы |
| Внутренний RPC | Подписанный Arc Core **invocation JWT**, bound к audience и ключу caller + отдельное proof на запрос | Проверяет сервис-получатель; актуальные session/delegation/grants дополнительно проверяет Access онлайн |

Пароли хранятся с Argon2id; логин, смена пароля, сброс доступа и выдача credentials журналируются без секретов. M0: защита от перебора и rate limits обязательны; MFA/SSO/SCIM — вне M0. Сессии пользователя и refresh families не включаются в экспорт workspace. При повторном применении уже ротированного refresh token отзывается всё семейство токенов; выдача нового требует интерактивной аутентификации.

**Bootstrap:** отдельные NATS credentials и TLS/trust config для Arc Core/Arc Gate/Arc Infrastructure Agent поставляются секретами Compose/systemd независимо от работающего Core. Динамический выпуск NATS users/JWT, их ротация и Auth Callout — последующий этап; нельзя создать bootstrap-цикл NATS↔Identity.

### 3.3. Подписанный invocation token (v1)

**M0 baseline:** Core подписывает JWT алгоритмом EdDSA (Ed25519), публикует **только публичные** ключи через защищённый внутренний JWKS с `kid`; приватный ключ хранится отдельно в секретном хранилище/монтируемом секрете с поддержкой ротации. SDK использует `kid`/JWKS, запрещает `alg=none` и алгоритмическую подмену. Никакой сервис, включая Gate, не получает приватный ключ подписи Core.

Минимальные claims: `iss=arc-core`, `aud=<target-service/api-major>`, `sub=<user|agent|service>:<uuid>`, `caller=<service-account-id>`, `op=<approved-operation-id>`, `iat`, `nbf`, `exp`, `jti`, `cnf.kid=<caller-public-key-id>`; опционально `sid` (непосредственная пользовательская сессия), `delegation_id`, `on_behalf_of=<user-id>`, `workspace_id` (контекст, не grant). `sub` — действующий actor; `caller` — технический процесс; `on_behalf_of` допустим **только** с действующей делегацией. Не доверять `actor/user_id/scopes` из произвольного JSON payload.

Нормативные начальные лимиты M0: внешний access JWT **≤10 мин**, invocation JWT **≤60 сек**, сервисный client assertion **≤30 сек** с одноразовым `jti`. Срок делегации обязателен, по умолчанию **24 ч** для разовых действий; максимальная длительность задаётся политикой workspace. Эти значения — проектные defaults, подлежат нагрузочному/UX тестированию, а не гарантии протокола.

**Token exchange:** Gate удостоверяет cookie/API-сессию и вызывает разрешённую Core-операцию `identity.v1.invocations.exchange_user`; Core выдаёт invocation token **только** для разрешённой target operation/audience; `op` обязательно совпадает с операцией из RPC envelope и утверждённого контракта, иначе `UNAUTHENTICATED`. Внутренний сервис получает новый token через `identity.v1.invocations.exchange_service` после проверки подписанного *client assertion* закреплённым ServiceCredential (`iss/sub=service-account-id`, `aud=identity.exchange_service`, `exp≤30c`, `jti` с запретом повторного применения). Для propagation сервис предъявляет также выданный ему входящий invocation JWT и запрашиваемый downstream audience; Core проверяет исходное происхождение actor и допускает лишь сужение scope; каждый downstream `op` независимо разрешён caller и действующим пользовательским/делегированным контекстом. При цепочке `tasks → calendar` старый audience-bound JWT **не пересылается**: Task получает новый token с actor provenance от предыдущего вызова, сохраняя или сужая права; повышение полномочий запрещено. Вызовы автономного ServiceAccount не принимаются за человеческую сессию.

**Защита от подмены caller:** стандартный NATS Micro handler не предоставляет криптографически удостоверенный `publisher identity` для отдельного сообщения; поэтому нельзя считать `X-Service-Name` или другие headers достоверными. SDK отправителя подписывает *request proof* своим ServiceCredential над `subject + request_id + SHA-256(envelope без proof) + token.jti + timestamp + nonce`. Сериализация `envelope без proof` канонизируется по JSON Canonicalization Scheme (RFC 8785); подпись Ed25519 покрывает байты по версии `proof_v1`, а не неформально склеенные строки. Формат и тест-векторы фиксируются в Go SDK и проверяются в contract tests. Wire `proof_v1`: RFC 8785 JSON-массив строк `["proof_v1", subject, request_id, hex_lower(SHA-256(JCS(envelope без поля proof))), token.jti, timestamp, nonce]`, UTF-8; signature — base64url без padding. Timestamp — RFC3339Nano, окно −30/+5 с; nonce 16–128 символов. Получатель M0 сохраняет nonce для всех защищённых RPC, включая read, до конца TTL токена +30 с; повторное использование отклоняется. Получатель сверяет `cnf.kid`, подпись, subject, тело, допустимое временное окно и статус ключа; для изменяющих/чувствительных операций хранит одноразовый proof nonce и idempotency key. Подпись защищает от подмены запроса; повторы идентичных read-запросов в коротком окне без серверной дедупликации остаются возможными и не должны приводить к side effects. Никакой ключ подписи нельзя принимать непосредственно из неподтверждённого клиентского поля.

### 3.4. Делегирование и проверка действующих прав

- Делегацию создаёт интерактивно удостоверенный пользователь либо уполномоченный доверенный workflow с уже подтверждённым consent; **сам сервис/агент не может выдать себе право выступать за пользователя**. Для создания нужна проверка, что пользователь в момент выдачи имеет все делегируемые права. `Delegation` содержит `grantor_user_id`, `grantee_kind/id`, разрешённые `actions`, конкретные `resource_ids`/scope, `expires_at`, `revoked_at`, `created_by`, `consent_method`; scope не расширяется без нового consent.
- На **каждом** защищённом вызове Access проверяет: service/account активен, invocation JWT/proof валиден, активна ли `sid` для direct-user calls или `delegation_id` для on-behalf-of, актуальный membership/ACL пользователя, перечень разрешённых tools агента, policy делегации и scope действия. Эффективные права = **пересечение**, `default deny`; отсутствие Identity/Access → `UNAVAILABLE` / fail-closed, без положительного кэша M0.
- Отзыв `Session`, `Delegation`, `ServiceCredential` и membership фиксируется транзакционно с audit/revision; **новые проверки после commit** обязаны видеть отзыв, даже пока JWT не истёк. Уже выполняемые операции могут завершиться; долгие job должны повторно получать короткие токены и проверять разрешения на каждом side effect.
- Выход пользователя из workspace не удаляет личные ресурсы и не превращает пользовательскую делегацию в бессрочную; права на корпоративные ресурсы немедленно перестают проходить новый `Check`.
- Подтверждение опасных действий агента (финансовые изменения, публичная публикация, удаление многих ресурсов) в полном объёме — M5; M0 должен различать `needs_approval` в контракте инструмента и запрещать его без подтверждённого approval.

### 3.5. Identity API и таблицы M0

| Операция (`identity.v1.*`) | Кто может вызвать |
|---|---|
| `sessions.login/refresh/logout/introspect` | Gate; `introspect` — только доверенный внутренний caller; защищённые rate limits |
| `invocations.exchange_user` | Gate после проверки активной пользовательской сессии и целевого контракта |
| `invocations.exchange_service` | Утверждённый сервис с client assertion; не может произвольно устанавливать `on_behalf_of` |
| `delegations.create/revoke/get` | Удостоверенный grantor, либо явно уполномоченный администратор для аудита/отзыва; не self-escalation |
| `service_accounts.register/disable` / `service_keys.rotate` | Arc-admin, либо доверенная связка Fabric/Runtime после утверждения deployment |
| `users/workspaces/memberships/groups.*` | Проверяемые пользовательские и административные действия по workspace-policy |
| `keys.jwks` | Только публичные verification keys через внутренний endpoint, с контролируемым rotation overlap |

Основные таблицы схемы `identity`: `users`, `password_credentials`, `sessions`, `refresh_families`, `refresh_tokens`, `workspaces`, `memberships`, `groups`, `group_members`, `service_accounts`, `service_credentials` (только public key/secret reference), `agent_identities`, `delegations`, `signing_key_metadata`, `assertion_nonces`, `audit`. Индексы/uniques: один активный membership `(workspace_id,user_id)`, группы в том же workspace, `(service_account_id,kid)` уникален, `assertion_jti` одноразов в окне срока, revoked credentials не выдаются заново. **Private signing keys, NKeys seeds, refresh plaintext, пароли и секреты OAuth не хранятся открыто в БД.**

## 4. Resource Registry и ACL — контракт M0

**Принцип:** централизованные *метаданные идентичности и доступа*, распределённое владение *содержимым* и обязательный policy enforcement на стороне сервиса-владельца. Решение не зависит от входного протокола (HTTP, DAV, NATS, MCP, workflow). `Gate` не заменяет проверку прав целевым сервисом.

### 4.1. Какие объекты становятся ресурсами

**M0 baseline — выборочные ACL roots.** В `access.resources` попадают только объекты с самостоятельными grants и границами наследования: личный/workspace root, календарь, адресная книга, раздел Files/Pages с собственными правами, управляемый агент/workflow. Обычное событие календаря, файл, задача или вложенная страница могут храниться только в доменной БД, указывая на ACL root. `business_parent` — связь предметной области, `acl_parent` — источник наследуемых разрешений; они не обязаны совпадать.

| Таблица Arc Core | Существенные поля / правила |
|---|---|
| `access.resource_types` | `type` (namespace), `provider_service`, `contract_digest`, допустимые `actions`, политика наследования; регистрируется только утверждённым Service Fabric контрактом |
| `access.resources` | `id UUID`, `type`, `provider_service`, `owner_kind=user\|workspace`, `owner_id`, `workspace_id NULL`, `acl_parent_id NULL`, `inherit_acl BOOL`, `state`, `policy_revision BIGINT`, timestamps |
| `access.grants` | `id`, `resource_id`, `principal_kind`, `principal_id`, `action`, `expires_at NULL`, `created_by`, timestamps; гранты только `allow` |
| `access.operations` | `idempotency_key`, `request_hash`, `operation`, `resource_id`, `state`, `result` для reserve/activate/delete и выдачи прав |
| `access.policy_audit` | кто/от чьего имени/когда изменил права, тип изменения, resource, policy revision; не содержит секретов |

Инварианты: `owner_kind=user` допускает личный root **без workspace**; `owner_kind=workspace` требует `owner_id=workspace_id`. Один `acl_parent` без циклов; для M0 родитель и потомок должны иметь одинаковые owner/scope. **Sharing оформляется grant, а не сменой владельца или перемещением в workspace.** `inherit_acl=false` отсекает grants предков, но не изменяет владельца и не отменяет защитные системные политики. Перенос ACL roots между родителями/владельцами — не часть M0.

Workspace-group/role grants допустимы только для ресурсов того же workspace. Личный ресурс в M0 можно явно открыть **конкретному пользователю**; групповой и меж-workspace sharing, публичные ссылки — отдельный этап. Service/Agent — независимые principal types, но право вызвать инструмент не означает права прочитать ресурс.

### 4.2. Права и точный алгоритм `Check`

Действия **строковые и типизированные контрактом**, например `calendar.read`, `calendar.free_busy`, `files.download`, `files.share`, `access.grants.manage`; `free_busy` **не** включает `read`, `manage_acl` **не** включает доступ к содержимому. Нет подразумеваемой иерархии `read → update` или обратной. У типа могут быть различные actions, но сопоставление operation→action валидирует Service Fabric, не клиент.

1. Проверить `iss/aud/sub/caller/exp/jti/cnf.kid`, подписанное request proof и статус caller key по §3; стандартные NATS headers не идентифицируют издателя сообщения. Неподтверждённый запрос → `UNAUTHENTICATED`. Далее обязательно онлайн-проверить session/delegation state через Identity/Access.
2. Получить активный ACL root, соответствующий операции и подтверждённый **доменным сервисом**. Конкретный `event_id`/`file_id` нельзя привязать к произвольному доступному `calendar_id`/`folder_id` из клиентского payload: owner-service проверяет связь с root по своей БД до выдачи данных/мутации.
3. Убедиться, что ресурс `active`, не нарушена owner/scope граница и цепочка `acl_parent` валидна; неактивный/несуществующий ресурс не даёт положительного решения.
4. Сформировать проверенные principals: сам user; актуальные membership/группы/роль **в workspace ресурса**; agent/service только со своей identity. Собрать совпадающие прямые grants и grants предков до первой границы `inherit_acl=false`, с учётом срока действия.
5. Для `owner_kind=user`: владелец обладает разрешёнными для данного типа действиями своего личного ресурса. Для workspace owner/admin: системная политика разрешает `access.grants.manage` над workspace-owned ресурсом, **но не автоматически `read`, `download` или `calendar.read`**. Однако администратор ACL, уполномоченный создавать любые grants, может выдать такой grant **себе** — это явно считается административным доступом и аудитируется; абсолютная конфиденциальность от управляющего ACL администратора в M0 **не гарантируется**. Обычное право `share` позволяет выдавать только действия, которыми инициатор уже располагает, и не включает `access.grants.manage`. Доменная операция требует собственного явного действия/grant. Восстановление доступа при потере owner — привилегированная, отдельно аудируемая процедура, не обход бизнес-ACL.
6. Для delegated agent/workflow пересечь: реальные текущие права пользователя, рамки действующей делегации, права инструмента агента и утверждённые права ServiceAccount; для автономного service account использовать только явно назначенные действия. Проверить транспортные NATS subject permissions как дополнительный, **не** исчерпывающий рубеж защиты. Успех при совпадении всех ограничений, иначе `allowed=false`; **default deny**, нет `deny`-grants в M0.

Для совместимости M0-02/M0-03 Core поддерживает локальные подписанные approvals с точными `DownstreamFrom` и `DownstreamActions` для каждой пары source/target operation. Downstream JWT содержит подписанные Core `source_aud/source_op` из проверенного входящего invocation; Access пересекает запрошенное действие с этой картой. Например, `calendar.free_busy → access.v1.check` не разрешает `calendar.read` даже владельцу. Эти поля не принимаются от клиента при exchange.

При отказе проверки по политике возвращается `PERMISSION_DENIED` (либо скрывающий ресурс `NOT_FOUND` по контракту), а при недоступности Identity/Access — `UNAVAILABLE`/HTTP `503`, **не** фиктивный отказ «нет прав». Это нужно для корректных повторов клиента и диагностики.

Все защищённые запросы выполняют `Access.Check` **онлайн** (SQLite committed policy, без положительного кэша M0), включая прямой NATS RPC. При недоступности Access — **fail closed**. Отзыв grants/membership гарантированно влияет на проверки, начавшиеся *после commit* изменения; уже выполняющиеся операции могут завершиться. Потоковые загрузки и совместное редактирование требуют дополнительных проверок в профильных этапах.

### 4.3. Внутреннее API Access v1

Subjects формируются Service Fabric из объявленных операций; ниже — стабильные имена, формат protobuf не требуется на M0 (JSON Schema + typed Go DTO).

| Операция | Назначение и ограничения |
|---|---|
| `access.v1.resource_types.register` | Только через **утверждение** service contract, проверка namespace ownership, не публичный HTTP endpoint |
| `access.v1.resources.reserve` | Проверенный caller-владелец типа, `owner`, `acl_parent`, `idempotency_key`; выделение UUID, состояние `reserved` |
| `access.v1.resources.activate` | Только тот же provider service, после commit доменного объекта; идемпотентно |
| `access.v1.resources.abort` | Отменить неактивированную резервацию; безопасный повтор |
| `access.v1.resources.begin_delete` / `finalize_delete` | `active→deleting→deleted`, проверка полномочий, подтверждение доменного удаления |
| `access.v1.check` | `actor` из invocation token, `resource_id`, `action`; возвращает `allowed`, `policy_revision`; диагностика отказа видна только доверенному аудитору |
| `access.v1.check_many` | Проверка до 100 `(resource_id,action)` в одном вызове с тем же доверенным actor; все результаты из согласованного snapshot политики |
| `access.v1.list_accessible_roots` | Пагинация + фильтры `owner/workspace/type/action`, только видимые ACL roots; не раскрывает недоступные metadata |
| `access.v1.grants.add` / `revoke` | Проверить `access.grants.manage` (полный grant authority, включая self-grant, с аудитом) либо `share` (только подмножество собственных content permissions); scope и grantable actions; транзакционное изменение, audit и `policy_revision` |

Пример **тела** `Check` (actor и caller *не* приходят из payload):

```json
{"resource_id":"<uuid>","action":"calendar.read"}
```

```json
{"allowed":true,"policy_revision":19}
```

`Check` не возвращает полный набор grants пользователю. Нельзя использовать `list_accessible_roots` вместо проверки **доменных** фильтров: Calendar/Files/Task обязаны ограничивать свои запросы по workspace и подтверждённым ACL roots. Для листингов M0 разрешается `check_many`; N+1 вызов на каждый объект запрещён проектным контрактом. При отсутствии прав domain service может скрыть существование объекта HTTP `404` вместо `403` в соответствии с установленной endpoint policy.

### 4.4. Жизненный цикл ACL root между разными БД

1. Domain service вызывает `reserve` с собственным доверенным service identity, проверенным actor, правом создавать объект под ACL parent и идемпотентным ключом. Arc Core фиксирует `reserved`; повтор возвращает тот же ID, несовпадающий payload → `CONFLICT`.
2. Domain-owner сохраняет бизнес-объект/корневую связь и запись outbox в **своей** транзакции, пока объект не опубликован пользователям.
3. `activate` переводит `reserved→active`, затем domain-owner делает объект видимым и выпускает ожидающее событие через outbox. Повтор `activate` безопасен; внешний читатель не должен видеть половинчатое создание.
4. Reconciler domain-owner повторяет недоделанные операции; при истечении TTL без доменного commit делает `abort`. Core не удаляет активный root на основании простого истечения времени.
5. При удалении `begin_delete` немедленно прекращает новые положительные проверки; domain-owner идемпотентно удаляет/архивирует содержимое и вызывает `finalize_delete`. Нужны audit и policy revision; физическая очистка не проводится раньше разрешённого retention.

Отдельной глобальной транзакции между БД нет. Lifecycle и outbox должны выдерживать падение процесса после каждого шага и повтор сообщений.

### 4.5. Матрица безопасности, которую обязаны покрывать тесты

Полностью матрица автоматизируется в M7; минимальное подмножество M0 guardrail определено в §10.2 и [REQUIREMENTS.md](REQUIREMENTS.md). Требуемые решения остаются нормативными с момента реализации, даже если исчерпывающая автоматизация отложена.

| Сценарий | Ожидаемое решение |
|---|---|
| User состоит в workspace A и B; выходит из A | Корпоративные A недоступны; личный root не удалён; B продолжает работать |
| Пользователь получил `calendar.free_busy`, но не `calendar.read` | Можно проверить занятость, нельзя читать заголовки и участников |
| Workspace admin управляет grants на финансовую папку без `files.download` | Может изменить ACL, не может скачать содержимое |
| Подраздел Pages с `inherit_acl=false` | Не наследует родительский grant; сохраняет тот же scope/owner |
| Клиент подменил `file_id`/`event_id`, оставив доступный root | Domain-owner отказывает из-за несовпадения связи |
| Агент имеет вызов `files.read`, но нет действующей делегации/прав user | `PERMISSION_DENIED`, доступ запрещён |
| Поддельный token, неверная audience, несуществующий resource, устаревший grant | Нет доступа, audit не раскрывает защищённый payload |
| Подмена caller в NATS headers, подписи proof либо тела запроса | `UNAUTHENTICATED`, нет side effect |
| Пользователь вышел или refresh family отозвана; старый invocation JWT ещё действителен | Новые Check запрещены, jwt expiry не скрывает отзыв |
| Агент выдал себе делегацию; чужой service assertion или повторное применение assertion jti | Запрещено; audit и anti-replay |
| Делегация разрешает `calendar.read`, но пользователь лишился grant | Новая проверка `PERMISSION_DENIED` |
| Access Core недоступен | Новые защищённые действия fail-closed; без кэша положительных решений |

**Граница M0:** кэш разрешений, cross-workspace/group sharing личных данных, публичные share-links, перенос ACL roots и безопасный streaming revoke не реализуются; расширение требует обновления настоящего контракта и отрицательных тестов.

## 5. Service Fabric и Arc SDK — контракт M0

**Решено:** `github.com/nats-io/nats.go/micro` используется **без форка** как transport/runtime substrate (`Service`, `AddEndpoint`, группы, queue groups, `$SRV.PING/INFO/STATS`). `arc-sdk` — самостоятельный Go module поверх `nats.go/micro`: утверждённые контракты, JSON Schema, middleware Identity/ACL, typed RPC, events/outbox и telemetry. Никакой сервис не должен знать HTTP-роутер Gate. Внутри Arc Core — прямые Go-интерфейсы, не локальные NATS RPC.

### 5.1. Каталог и жизненный цикл экземпляра

| Сущность | Кто владеет | Смысл |
|---|---|---|
| `ServiceDefinition` | Fabric/DB | Stable `service_name`, publisher, trust/installation policy; не контейнер и не экземпляр |
| `ServiceContract` | Fabric/DB | Immutable утверждённый manifest, API major, операции/схемы, resources/actions/events, HTTP exposure, `sha256` |
| `ServiceInstance` | NATS Micro + наблюдения Fabric | `instance_id`, `service_name`, `build_version`, contract digest, готовность, метрики; эфемерное состояние |
| `RouteSnapshot` | Fabric/DB | Атомарная монотонная ревизия только **одобренных** HTTP-маршрутов, не список живых контейнеров |

Последовательность запуска M0: (1) preinstalled/approved manifest и разрешённые NATS subjects уже известны Core; (2) сервис соединяется с NATS под отдельными scoped credentials, посылает `ctl.arc.fabric.register` с `service_name`, `instance_id`, `build_version`, digest и подписанным client assertion; (3) Core проверяет service-account/deployment identity, digest, действующую версию и разрешённые subject patterns, возвращает разрешение регистрации; (4) **только после этого** SDK вызывает `micro.AddService`, привязывает **все обязательные** обработчики и начинает обработку бизнес-RPC; (5) readiness устанавливается после успешного локального self-check, подтверждения NATS subscriptions и контрольного вызова по согласованному contract endpoint. `PING/INFO/STATS` дополняют наблюдения, но **не заменяют** identity proof, approval и readiness. При ошибке подключения/повторном старте — reconnect с повторной проверкой; нарушение/отзыв контракта останавливает обработку, а не открывает новые endpoint-ы.

Подписка на собственный RPC subject разрешена **NATS permissions конкретного service account**; Core не считает свободный текст `$SRV.INFO` доказательством подлинности. Одновременные совместимые replicas используют **один subject и одну явную queue group** (`q.<service>.v<major>`); несовместимый API major — иной subject и queue group. Если service instance исчез, контракт и маршруты остаются утверждёнными, а вызовы при отсутствии responders возвращают `UNAVAILABLE`. Fabric периодически согласует анонсы с NATS discovery; stale instance не считается live.

Реализация M0-04: `sdk/contract` проверяет JSON manifest v1 и artifact-local JSON schemas без сетевых/file loaders; digest включает канонический manifest и отсортированные canonical schema hashes. `sdk/fabric.Core.Approve` принимает только локально подписанный оператором install artifact, закрепляет publisher/service-account/deployment и точные RPC subjects. Контракт, resource types Access, revision и audit фиксируются одной транзакцией. Один активный digest на `(service, api_major)` исключает смешение обработчиков; несовместимые majors имеют разные subjects. Смена digest внутри major требует отзыва предыдущего approval и консервативной проверки совместимости: существующие операции/auth/responses/events сохраняются, request может добавлять optional properties. Неоднозначные resource/rule identities отклоняются до commit; rolling upgrade без этого ограничения — последующая доработка.

`access.Core.ContractSource` загружает актуальные signed approvals Fabric перед новым запросом; локальный bootstrap policy содержит только доверенные Identity/control правила. При недоступности каталога нет fallback к локальному business allowlist. Identity → policy → Access использует прямые Go-интерфейсы без обратного вызова Identity из ACL-алгоритма. Регистрация нового типа через Access ограничена текущим approval; обычная установка типов выполняется атомарно Fabric.

`sdk.NewApp`/`sdk.Handle`/`sdk.HandleCommand` связывают все обязательные handlers до `Start`. SDK подтверждает подписанный instance-specific probe и Micro INFO с точными endpoints/queue groups/digest, затем допускает business RPC. `ctl.arc.fabric.register`, `.ready`, `.check` проверяют отдельную assertion audience, полный request proof и persistent replay; account берётся из проверенной подписи. Control-ответы Core подписаны отдельным закреплённым ключом и связаны с request ID/subject/expiry. Lease — 30 секунд, heartbeat — 5 секунд; каждый RPC дополнительно онлайн проверяет approval и lease. Reconnect повторяет регистрацию/self-check/readiness, отзыв или отказ контроля закрывает обработку. Старый `NewService` остаётся низкоуровневым transport для Core и закрытого bootstrap; domain services используют `NewApp`.

### 5.2. Manifest v1: минимальная схема публикации возможностей

```yaml
manifest_version: 1
service: {name: calendar, build_version: 1.0.0, api_major: 1}
resources:
  - {type: calendar, actions: [read, create, update, delete, share, manage]}
operations:
  - id: calendar.events.create
    kind: command
    subject: rpc.calendar.v1.events.create
    request_schema: schemas/calendar.events.create.request.v1.json
    response_schema: schemas/calendar.events.create.response.v1.json
    auth: {action: calendar.create, resource_from: payload.calendar_id}
    idempotency: required
    timeout_ms: 10000
    http: {expose: true, method: POST, path: "/api/v1/calendars/{id}/events", success_status: 201}
    tool: {expose: false}
events:
  - {name: calendar.event.created, subject: evt.calendar.event.created.v1, schema: schemas/calendar.event.created.v1.json}
```

Manifest и все связанные schema bytes образуют проверяемый install artifact; SHA-256 digest считается от **детерминированной канонической сериализации** manifest + отсортированных путей/хешей schemas (не от случайного форматирования YAML). В таблице контрактов хранится digest и version, бинарные схемы сохраняются в проверяемом artifact store. Контракт **не принимает произвольные URL, SQL, source-code и shell команды**. Unknown fields manifest для v1 отклоняются. Публикация Tools и Workflow actions — **явный opt-in**, независимо от `http.expose`; сервис не расширяет полномочия по собственной инициативе.

Структура операции: stable `id`, `kind=query|command`, unique `subject`, typed request/response schema IDs+hashes, `auth.action` и проверяемый extractor идентификатора *ACL root*; optional `http`, `tool`, `workflow`, timeout/size/idempotency policy. Выбор `auth.resource_from` возможен только через ограниченный path-selector, не пользовательский исполняемый код; domain-owner **всегда** проверяет фактическую связь объекта с ACL root. Если заявлен несуществующий action или resource type, approval отказывает. Пример HTTP `calendar_id` связывается из URL с полем payload на стороне Gate и повторно проверяется сервисом. Перечень `resource_types/actions` согласуется с Access в одной транзакции утверждения manifest.

### 5.3. Namespace, RPC v1 и delivery

```text
rpc.<service>.v<major>.<operation>       # Core NATS request/reply, queue group q.<service>.v<major>
evt.<service>.<entity>.<event>.v<major> # JetStream durable fanout с разными consumer names
ctl.arc.<operation>                    # admin/bootstrap fabric/identity (explicit allowlist)
ctl.runtime.<operation>                # управляемый runtime (separate privilege)
```

Subjects состоят из **фиксированных** токенов утверждённого контракта; UUID user/workspace/resource передаются в payload/context, не в subject. `micro` контролирует `$SRV.PING/INFO/STATS`; wildcard доступ к `$SRV.>` имеют только уполномоченные admin/monitoring identities. Транспорт RPC v1 — JSON envelope + JSON Schema; типизированный Go handler объявляется package-level helper `sdk.Handle[Req, Res](service, operationID, handler)` (не generic method Go), SDK сверяет binding со схемами/subject/digest и требует обработчики для всех операций. DTO schema compatibility проверяется contract tests; `additionalProperties` и required-поля задаются в каждой schema, а не глобально.

```json
{
  "request_id": "uuid", "operation": "calendar.events.create", "schema_version": 1,
  "deadline_at": "2026-10-19T12:00:10Z", "idempotency_key": "uuid",
  "traceparent": "00-...", "auth": "<invocation-jwt>",
  "proof": {"kid": "caller-key-id", "timestamp": "...", "nonce": "...", "signature": "..."},
  "payload": {"calendar_id": "calendar-uuid", "title": "Совещание"}
}
```

Ответ: `{"request_id":"uuid","data":{...}}` **либо** `{"request_id":"uuid","error":{"code":"...","message":"...","retryable":false}}`. Нормативные ошибки `UNAUTHENTICATED`, `PERMISSION_DENIED`, `NOT_FOUND`, `VALIDATION_ERROR`, `CONFLICT`, `RATE_LIMITED`, `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `INTERNAL`; безопасное сопоставление с HTTP `401/403/404/400/409/429/503/504/500`. Служебные NATS Micro error headers адаптируются в этот envelope; клиенту не раскрываются внутренние stack traces, SQL и secrets. Отдельные HTTP-success статусы (например, 201/202) принадлежат **утверждённому route contract**, не выбираются ответом недоверенного сервиса.

**Нормативные M0 defaults:** query timeout 5 с, command 10 с; effective deadline — минимум caller budget и contract timeout; payload и response ≤256 KiB по UTF-8 bytes. Отрицательные и несовпадающие schema версии отклоняются до исполнения handler. Изменение данных требует `idempotency_key`, domain-owner атомарно хранит `(actor, operation, key, request_hash, result)` ≥24 ч, повтор с иным payload → `CONFLICT`. SDK/Gate **не повторяют автоматически мутирующий RPC с новым ключом**; сеть может вернуть timeout после успешного commit, клиент повторяет с исходным ключом. Не обещать exactly-once delivery.

Событие содержит `event_id`, `type`, `schema_version`, `aggregate_id`, `occurred_at`, `traceparent`, разрешённый минимум metadata; бизнес-payload без секретов/PII там, где в этом нет необходимости. Обязателен transactional outbox в DB доменного владельца и JetStream publish после commit; durable consumers имеют inbox dedup по `event_id`, retry/backoff и DLQ. Для *внутренних DB side effects* inbox и изменение доменных таблиц фиксируются **одной транзакцией**; внешняя отправка email/webhook не обладает гарантией exactly-once и требует идемпотентного провайдера/ключа или честно допускает дубли. Event-подписка **не** предоставляет права читать связанные resources. Долгие agent/workflow операции — асинхронная job (`202`/`job_id`), не висящий Core NATS RPC.

M0-04 `sdk/events.Store` работает в БД владельца домена: command result, доменный effect и outbox фиксируются в одной транзакции; записи replay не удаляются автоматически (≥24 ч). `HandleCommand` требует этот transaction helper и проверяет response schema до commit. `Delivery.PublishBatch` публикует committed outbox с постоянным JetStream message ID; durable consumer фиксирует inbox + внутренний effect атомарно, ACK после commit. Ошибки повторяются с backoff; после пяти доставок копия попадает в `dlq.<approved-event-subject>.<durable>`, затем original message завершается. Права publish/subscribe/DLQ должны быть заранее выделены deployment; `Permit` обязателен, события не дают ACL полномочий. Каждый владелец создаёт replay/outbox/inbox своими версионными Gormigrate migrations; записи команды и доменные изменения используют один `*gorm.DB` transaction.

Для входящей audience service exchange принимает `incoming_api_major` (по умолчанию 1); подписанный JWT обязан совпасть с `<service_definition>/v<major>`, а approved downstream map — с исходной парой audience/operation. Поле не позволяет произвольно подменить service identity или расширить права.

### 5.4. Gate discovery, versioning и безопасность маршрутов

При approval Core валидирует `(HTTP method, normalized path, API major)` и отклоняет конфликт статических, wildcard и параметризованных шаблонов. Зарезервированы `/api/v1/arc/*`, `/health*`, `/dav/*` и прочие системные префиксы; пользовательские сервисы не могут перехватывать их. Экспонирование операции **по умолчанию выключено**. Изменение approved routes требует новой версии/ревизии контрактов, а не runtime-анонса.

Gate при старте загружает `RouteSnapshot(revision, digest, routes, kid, signature)` из Core; подпись Core (Ed25519, проверяемая через доверенный JWKS) покрывает канонические `revision+digest+routes` с domain separation, а `digest` сверяется с содержимым маршрутов. Gate атомарно заменяет локальную таблицу и отвергает откат ревизии и получает уведомления об изменениях (при пропуске уведомления выполняет reconciliation). До получения проверенного initial snapshot **не отдаёт динамические маршруты**. Сохранённый snapshot не даёт права обходить онлайн-проверку сессии/ACL: если Core недоступен, защищённые операции fail-closed. Для зарегистрированного пути без живого обработчика — `503`; для превышенного deadline — `504`. Gate связывает HTTP path/query/body по schema, игнорирует недоверенные identity headers, обменивает сессию на audience-bound invocation токен и прикладывает собственный per-request proof; целевой сервис повторно выполняет authorization через SDK.

Реализованный wire contract M0-05 сохраняет `SignedSnapshot{payload,signature}` и дополняет payload полями `kid`, `digest`, `artifacts`. Digest — SHA-256 canonical `{routes,artifacts}`; signature — Ed25519 от canonical `["arc.route_snapshot.v1", payload]`. Payload содержит `revision`, `issued_at`, routes с API major и bindings, и artifacts с проверяемыми schemas. Gate отвергает одинаковую revision с другим content digest; повтор той же revision/content допустим. Старые snapshots без digest/domain separation не принимаются Gate.

Закрытый `ctl.arc.fabric.routes` использует существующий RPC SDK, service assertion с отдельной audience и полный request proof, точный bootstrap policy `fabric/v1:fabric.v1.routes`. Core выдаёт `RouteBundle(snapshot, active JWKS, request_id, expires_at, signature)`, подписанный отдельным локально закреплённым `RouteTrustKey` с domain separation `arc.route_bundle.v1`. Это связывает live JWKS и snapshot с nonce запроса, не доверяя NATS reply publisher. `SnapshotKid` обязан соответствовать действующему ключу Identity metadata; отозванный/неизвестный kid отсутствует в JWKS. Gate не подключается к БД. Неподписанный `evt.arc.fabric.routes.changed` — только hint для нового authenticated fetch; periodic reconciliation восстанавливает пропуски. Невалидный update сохраняет предыдущую immutable таблицу, но не даёт обхода online Identity/Access.

HTTP bindings — только подписанные `{source:path|query,name,field,type}`; поля скалярные, без кода/SQL/выражений. Body — JSON object; повтор поля из path/query в body и неизвестный query key запрещены. Path parameters требуют явных bindings. Schema проверяется до business RPC, response schema — до HTTP ответа. `actor/caller/on_behalf_of/scopes` и аналогичные authority fields не принимаются из payload; identity headers игнорируются. Command нельзя экспонировать через GET/HEAD.

**Совместимость:** breaking change operation, schema или semantics требует `v<major+1>` subject и отдельного HTTP version prefix; additive изменение в той же major допустимо только при подтверждении contract tests для предыдущих клиентов. `build_version` инстанса (SemVer) не тождественен `api_major`; одновременно работающие сборки обязаны подтверждать один approved digest либо использовать отдельный контракт/subjects. Несовместимые обработчики не помещать в одну queue group.

### 5.5. SDK: публичные интерфейсы и проверка M0

Разделение пакетов: `sdk/micro` (lifecycle/registration), `sdk/contracts` (binding/schema), `sdk/rpc` (client, handler, normalized errors), `sdk/events` (outbox/inbox helpers), `sdk/identity` (token exchange + caller proof), `sdk/acl` (online Check), `sdk/telemetry` (trace/metrics). Конкретный handler SDK обязан применять pipeline: **verify invocation/proof → validate schema → verify domain ownership/root → ACL Check → handler → response schema/metrics**. Бизнес-сервис не может отключить этапы безопасности для защищённой операции через конфигурацию манифеста; trusted bootstrap/health operations имеют явно выделенные политики.

Пример концептуального Go API (не обещает готовый код): `app := sdk.NewService(config)`; `sdk.Handle[CreateReq,CreateRes](app, "calendar.events.create", handler)`; `app.Start(ctx)`; клиент `rpc.Call[Req,Res](ctx, operationID, req)` со строгими deadline, auth propagation и без эскалации. Метаданные handler сверяются с установленным контрактом, а не произвольным объявлением Go-сервиса при запуске. M0 допускает ручные DTO, автоматический генератор не является блокером.

**Минимальный M0 guardrail:** исполняемые contract-проверки покрывают approve/deny manifest, invalid resource action/schema, подмену `caller`, несовместимый major, повтор `idempotency_key`, JetStream duplicate и недействительную подпись RouteSnapshot. Остальная матрица — несколько replicas, stop/reconnect/no responders, rollback snapshot, timeout после commit, потерянное notification и recovery — накапливается как сценарии и полностью автоматизируется в M7. M0 получает статус `Integrated` после guardrail, но не `Verified`.

## 6. Gate и протокольные адаптеры

Gate — stateless public ingress (несколько реплик допустимы) с TLS, auth, CORS/CSRF, rate/body limits, REST routing, WS authorization и нормализацией ошибок. Снимки маршрутов, их ревизии и безопасность описаны в §5.4; Gate не владеет ACL или бизнес-данными и не является обязательным посредником между внутренними сервисами.

M0-05 процесс `sdk/cmd/arc-gate` использует `net/http`, TLS 1.3 либо явно доверенный reverse proxy с CIDR allowlist. Forwarded IP/proto принимаются только от доверенного peer, IP выбирается справа по цепочке proxies. Read-header/read/write/idle timeouts, graceful shutdown, 200 KiB body limit (внутри RPC envelope ≤256 KiB), deadlines, bounded per-IP rate limits и явные HTTPS CORS origins включены. `/healthz` — liveness, `/readyz` — наличие принятого snapshot и результат последнего reconciliation; системные namespaces не доступны для domain routes. Compose M0-01 сохраняет только loopback-порты инфраструктуры, публичный порт принадлежит Gate.

Публичные endpoints: `POST /api/v1/arc/auth/login`, `/refresh`, `/logout`; `GET /api/v1/arc/auth/session`. Login требует допустимый Origin. Browser session и refresh — Secure/HttpOnly/SameSite=Lax `__Host-` cookies; отдельная Secure CSRF cookie сравнивается с `X-CSRF-Token`, а Core сверяет её hash с сессией при mutation. Refresh cookie не выдаётся в JSON; rotation/reuse и отзыв остаются в Identity. Bearer JWT принимается только через Core `Verifier.Access` (`aud=gate`, TTL/online state); смешение Bearer и session cookie запрещено. `identity.v1.sessions.validate` — закрытый signed-service RPC для проверки cookie/Bearer, без нового session store; browser refresh дополнительно связывает refresh family с этой сессией. Public auth не публикует recovery/admin/control endpoints.

Gate для каждого защищённого запроса вызывает online session validation и `identity.v1.invocations.exchange_user`, затем подписывает новый RPC proof своим service credential. Target audience/operation/subject и success status берутся из принятого snapshot/artifact. Внешний JWT не передаётся domain service; тот повторно проверяет invocation/proof, domain root и Access. `request_id`, `traceparent`, effective deadline и исходный idempotency key сохраняются; автоматических mutation retries нет. Публичная ошибка содержит только нормативный code и безопасное message, без текста внутренних ошибок. Static snapshots не кэшируют разрешения.

**DAV:** `CalDAV` (RFC 4791), `CardDAV` (RFC 6352), `WebDAV` для файлов — отдельные серверные adapters за Gate; операции DAV обязаны проверять общий ACL. В первой версии серверные адаптеры предоставляют синхронизацию с внешними клиентами. Подключение удалённых DAV-серверов как источников — отдельные **Connectors** с их собственной моделью sync/conflict.

- CalDAV: iCalendar, ETag, sync tokens, recurring exceptions, timezone, `free/busy` с отдельным permission; scheduling/invitations — позже после совместимости с клиентами.
- CardDAV: vCard round-trip, сохранение расширенных полей, ETag/sync tokens.
- WebDAV: hierarchy, MOVE/COPY/PROPFIND/PROPPATCH/LOCK по необходимой матрице клиентов; большой upload/download выполняется по HTTP streaming или pre-signed object URLs, не через NATS RPC.
- Публичные share links — отдельные ограниченные токены; DAV-token и browser-session не взаимозаменяемы.

## 7. Runtime Control и Arc Infrastructure Agent — контракт M0/M6

**Решено:** `arc-core/runtime` — **control plane** с desired state и административными политиками, **не** процесс с Docker socket. `arc-agent` — отдельный привилегированный **node executor**, связывающийся с Core через ограниченный NATS-протокол. Любой managed workload подчиняется approved `ServiceDefinition/ServiceContract` из Fabric; регистрацию RPC в Fabric нельзя заменять фактом запуска контейнера. Внутри Core используются Go-интерфейсы Identity/Access/Fabric/Runtime.

### 7.1. Граница управления и модель данных

| Объект | Назначение / источник истины |
|---|---|
| `RuntimeNode` | Доверенный узел с `node_id`, agent service account, capabilities, статусом и временем последнего подтверждённого наблюдения; Core DB + observations. В M6 — **один Docker host**; multi-node scheduling открыт. |
| `RuntimeTemplate` | Approved тип контейнера, допустимые образы/версии, командная строка и безопасные параметры; нельзя загружать произвольный Compose/CLI. |
| `Deployment` | `deployment_id`, `service_definition_id`, immutable `spec_revision`, `desired_state=running|stopped|deleted`, `replicas`, `target_node`, config/secret references, quotas, rollout policy. Core DB — источник desired state. |
| `RuntimeOperation` | `operation_id`, `deployment_id`, `requested_revision`, `idempotency_key`, `requested_by`, `approval`, status `pending|running|succeeded|failed|cancelled`, timestamps, error code и audit. |
| `InstanceObservation` | Эфемерное сообщение Agent: host/container ID, deployment/revision, image digest, health, restart count, observed time; **не** источник полномочий. |

Данные в SQLite Core `runtime.nodes`, `runtime.templates`, `runtime.deployments`, `runtime.deployment_revisions`, `runtime.operations`, `runtime.observations`, `runtime.leases`, `system.outbox/audit`; secret values и Docker socket туда не попадают. `ServiceDefinition` определяет логический сервис, `Deployment` — желаемый запуск, `InstanceObservation` — процесс на хосте, а `ServiceInstance` из Fabric — **подтверждённый NATS-обработчик**. Они связаны ID, но не взаимозаменяемы. `running` контейнера и Docker healthcheck **не** равны готовности API: для `Ready` дополнительно нужны утверждённый manifest/digest, активные subscriptions и подтверждённый readiness сервиса (см. §5.1).

### 7.2. Протокол управления (не произвольный Docker RPC)

1. Администратор с `arc.runtime.manage` выбирает **утверждённый** template и node. Runtime сохраняет новую immutable spec revision + audit/outbox в SQLite Core и создаёт operation. Изменение `expected_revision` при конкурирующем обновлении даёт `CONFLICT`.
2. Agent с собственной NATS identity, закреплённой за `node_id`, получает сигнал об изменении **как подсказку**, затем запрашивает через `ctl.runtime.v1.desired.get` **актуальный** подписанный/аттестованный снимок желаемого состояния, адресованный именно его node; подписанный ответ проверяется по caller proof/ключам Core (§3). Никакого исполнения команды непосредственно из payload события.
3. Agent проверяет revision, lease/срок снимка, approved image digest, отсутствие запрещённых host-параметров, права node, границы managed namespace; после этого приводит **только принадлежащие этому deployment** контейнеры к desired state через Docker Engine API.
4. Agent публикует attested `ctl.runtime.v1.node.<node-id>.report` с observation и `operation_id`; Core делает idempotent update, сверяет readiness с Fabric и завершает operation. `event_id`/`operation_id`/`revision` защищают от повторов. Сигналы могут доставляться повторно или теряться: периодический pull/reconciliation обязателен.

Здесь `ctl.runtime.v1.desired.get` — RPC Core (namespace `ctl.runtime.*`), а `ctl.runtime.v1.node.<node-id>.report` — узкосубъектный приём наблюдений. NATS permissions разрешают Agent `get` и `report` **только** от собственного узла, без прав управлять другими узлами или публиковать desired snapshots; Core единолично формирует desired state. Доступны также Core API `runtime.deployments.create/update/stop/delete/get`, `runtime.operations.get/list`, `runtime.nodes.list` — только из утверждённого контракта и с Arc-level ACL; никакого прямого публичного `/docker/*`. Все изменения используют invocation/proof и idempotency M0 (§3, §5). Для долгих операций возвращается `operation_id` (Gate `202`), а не удерживается RPC до завершения pull образа.

### 7.3. Reconciliation, операции и аварии

- **Core reconciler** под lease в Core SQLite/одним активным владельцем сравнивает desired state с последними доверенными observations и инициирует повторную сверку; **Agent reconciler** сериализует операции на конкретном узле, сохраняет локальный high-water mark revisions/operation IDs и выполняет их идемпотентно. Повтор сообщения/рестарт процесса не запускает второй идентичный rollout.
- `RuntimeOperation` — аудит выполнения, **не команда к повторному воспроизведению**. Старое событие или команда с revision ниже текущей не вправе перезаписать новую конфигурацию. При потере NATS или Core Agent **не** разворачивает новые workloads из кэшированных команд и не удаляет контейнеры; существующие остаются под restart policy Docker, состояние Core помечается stale/degraded.
- Node offline, невалидный proof, недоступный image registry, нехватка диска/CPU, ошибка health/readiness → ограниченные повторы с backoff, состояние `Degraded`/`Failed`, объяснимый error code; без бесконечного цикла pull/перезапусков. Host restart: Agent переобнаруживает **только свои** контейнеры по зафиксированным deployment identity + Docker labels/metadata и сверяет их с Core. Одна Docker label сама по себе не подтверждает право «усыновить» чужой контейнер.
- Обновление создаёт новую spec revision с immutable image digest; для M6 достаточно **single-node recreate** с явным возможным downtime. Rolling update без простоя и rollback образа — позже, при проверенной совместимости БД и состоянии. Удаление deployment **не удаляет volumes/данные автоматически**; destructive purge — отдельная подтверждаемая операция с audit и backup requirement.
- Метрики: desired vs observed replicas, age last observation, operations lag/failures, failed proofs, container restarts; события аудита не содержат credentials, env values или секретов.

### 7.4. Граница безопасности и bootstrap

**Bootstrap (вне Runtime Control):** файлы/тома SQLite, NATS/JetStream, Arc Core, Arc Gate и корневые credentials/trust anchors. В **M0 реальный Arc Infrastructure Agent не запускается**: контракт проверяется fake Agent. Начиная с **M6**, реальный Agent также запускается независимо и никогда не управляет собственным контейнером. Обязательную базовую инфраструктуру запускает независимый Compose/systemd, и её можно восстановить через CLI без работающих Core/NATS. Runtime может **показывать** их статус, но не переустанавливать, удалять или менять их конфигурацию. Доступ к управлению managed workloads — только Arc-admin с отдельным `arc.runtime.manage`; workspace-admin не получает это право по умолчанию, agent/workflow/tool — тем более. Делегирование infra-management в workspace исключено из M0/M6 baseline.

Agent единственный владеет Docker socket/эквивалентным privileged API. Его компрометация потенциально означает компрометацию всего Docker-хоста; **Docker не является безопасной границей для враждебного кода**. Минимальная политика managed containers: только approved immutable image digest, запрет `privileged`, host PID/network/IPC, Docker socket, host devices, произвольных host bind mounts, capability additions, произвольных entrypoint/command/env, неконтролируемых exposed ports; лимиты CPU/RAM/PIDs/disk, non-root, dropped capabilities, seccomp/AppArmor и network allowlist — по совместимости template. Секреты передаются короткоживущими mounts/references от доверенного provider, никогда как исходящие NATS events/logs. Config и secret changes дают новую spec revision. Public ingress — **только Gate**; host port publishing managed workloads запрещён по умолчанию. Недоверенные agent plugins/произвольный код требуют отдельной VM/microVM-изоляции или сильнее защищённого runtime, это не гарантия обычного Docker.

### 7.5. Граница этапов и тесты

**M0 (обязателен только каркас):** модель/runtime migrations, interface `RuntimeProvider`, approved template/definition metadata, воспроизводимый bootstrap Compose, fake-agent contract tests, запрет управления bootstrap, проверка privilege boundary и revision/idempotency в Go. **M0 НЕ требует** работающего Docker executor, установки контейнеров из UI, автоматического rollout и multi-node планировщика. Граница фиксирует будущий протокол, не делает Runtime обязательной зависимостью работающих задач/уведомлений.

**M6 (исполняемый single-node runtime):** реальный Docker Arc Infrastructure Agent, approved templates и image digests, desired/observed reconcile, защищённый NATS transport, операции start/stop/restart/update/replicas/delete managed deployment, UI logs/health/status, volumes retained by default; не допускается выполнение произвольных shell/host команд. При интеграции проверяется один happy path и критические запреты; полная E2E-матрица 2→3 replicas, crash/restart, agent/Core/NATS offline+reconnect, duplicate/stale operation, spoof node/proof, privileged/host mount denial, несовместимые migrations и отсутствие секретов выполняется в M7.

**Открыто после M6 baseline:** multi-node scheduler/placement, zero-downtime rolling upgrades, автоматический rollback, аппаратные квоты и безопасный execution для hostile multi-tenant code. Эти возможности не обещаются первой поставкой Runtime.

## 8. Прикладные сервисы и API-инструменты

| Сервис | Принадлежность данных | Граница функций |
|---|---|---|
| `tasks` | Workspace (или личное пространство, если явно введено позднее) | Задачи, проекты, статусы, подзадачи, доски, необязательные cycles; GitHub перестаёт быть зависимостью ядра |
| `calendars` | User/workspace | Личные/командные календари, события; CalDAV server |
| `contacts` | User/workspace | Адресные книги, контакты; CardDAV server |
| `files` | User/workspace | Папки, файлы, версии, shares; WebDAV; local FS / S3 |
| `pages` | User/workspace | Иерархические Tiptap-документы, шаблоны, история, links; no Notion databases v1 |
| `agents` | User/workspace | Интерактивные/фоновые runs, модель-провайдеры, ограниченные инструменты, approvals; coding container optional |
| `workflows` | Workspace/user при разрешении | Trigger, condition (CEL), transform/script (Starlark), action, retry, logs |
| `connectors` | User/workspace connection | External API/OAuth, webhooks, source sync, manifest/action/trigger registry |

Общие `resource_links` позволяют связывать task ↔ calendar event ↔ contact ↔ page ↔ file. Разрешение прочитать одну ссылку **не даёт** право прочитать связанный объект. Глобальный поиск индексирует разрешённые метаданные с обязательной перепроверкой ACL при выдаче результатов.

M0-06 реализует отдельные `arc-task` и `arc-notify` поверх `sdk.App` и
`sdk/events`, с отдельными owner-local SQLite-файлами и NATS credentials.
Task `create/get/list` используют workspace ACL root; list ограничен 100 задачами
текущего пользователя. Task→root/workspace проверяется по Task DB до онлайн
Access.Check и до command replay. Root создаётся через Reserve, committed domain
binding и signed provider receipt, проверяемый Access по текущему Identity key,
затем Activate. Ручных SQL grants для бизнес-разрешений нет.

Optional manifest `auth.workspace_from` задаёт payload selector workspace для
Gate exchange; workspace остаётся пользовательским выбором, проверяемым Identity
онлайн. Закрытый `identity.v1.invocations.verify` проверяет исходный invocation/proof
для audience зарегистрированного recipient ServiceAccount. Подписанный ответ
привязан к hash полного envelope, subject, claims и короткому expiry; доменный SDK
проверяет pinned Core public key. Core DB credentials сервисам не передаются.

Для начального ACL provisioning `task.roots.grants` — внутренняя approved operation
без HTTP. Только resource operation с `access.grants.manage` может иметь явно
одобренные downstream actions своего resource type; это не расширяет права actor:
Access повторно проверяет online membership и фактическую grant authority.
Bootstrap Fabric по-прежнему не принимает business policy.

Notify installation содержит operator-signed `subscriptions` с точными
provider/digest/event subject/durable. Signed `ctl.arc.fabric.event_permit` требует
ready consumer и действующие approvals обоих сервисов перед обработкой. Адресаты
берутся из активной operator-managed addressing в Notify DB, а не event.
Inbox + notification + outbound delivery intent атомарны; ACK после commit.
Persisted dedup key = SHA-256(notification,recipient,channel) используется при каждом
retry fake provider. Внешний эффект не имеет exactly-once гарантии.
Подробности запуска и M0 границы: [M0-06](M0-06.md).

## 9. Storage, наблюдаемость, отказоустойчивость

- GORM + SQLite: Core, Task и Notify имеют отдельные абсолютные `sqlite_path`, таблицы и историю Gormigrate. Между владельцами доступны только RPC/events, SQL к чужой БД запрещён. Включены WAL, foreign keys и busy timeout на каждом соединении; конфликтующие записи сериализуются транзакциями/constraints с повтором всей транзакции при SQLITE_BUSY. Несколько процессов одного владельца допускаются только на одном хосте с одним локальным файлом; независимые реплики файла и сетевые файловые системы не обеспечивают общий state.
- Файловые bytes: local storage или S3-compatible; БД хранит дерево, версии, ACL links, метаданные, ETags; не передавать большие файлы через NATS.
- Трассировка: корреляция `request_id`, `traceparent`, `actor`, `service_instance`, `resource_id` и `job_id`; структурированные logs и метрики RPC/JetStream/DAV.
- Gate допускает независимые реплики; Core с SQLite не поддерживает независимые копии БД на разных узлах; runtime jobs требуют lease/leader или идемпотентного распределения. Gate сохраняет утверждённые routes, но **не** обходит Core для получения новых прав.
- Если Core/ACL недоступен, **все защищённые запросы M0 fail-closed**; read-only grace/ревизионный кэш допускаются только после отдельного безопасного ADR и тестов. Если NATS недоступен — публичные RPC отвечают `503`, bootstrap recovery возможен вне системы.
- Резервное копирование — согласованные SQLite backups через backup API либо остановку владельца с учётом WAL, object storage, secrets/config, JetStream при необходимости; экспорт workspace **не** заменяет disaster-recovery backup.

### Ограничения стоимости M0 (после ревизии v0.8)

- **Не строить универсальный policy DSL/Zanzibar-клон**: M0 использует allow-only ACL, один `acl_parent`, `CheckMany` и online SQL lookup; запреты, произвольный граф отношений, меж-workspace sharing и positive decision cache отложены.
- **Не форкать NATS Micro и не создавать универсальный оркестратор**: Service Fabric хранит утверждённый manifest, SDK связывает handlers, Runtime имеет fake Provider до M6.
- **Не вводить подтверждение полномочий только в Gate**: каждый domain handler проверяет `op`, caller proof, принадлежность объекта ACL root и `Access.Check`.
- **Цена безопасности:** обмен invocation token и online Access.Check добавляют сетевые hop(ы) к RPC; M0 обязан измерять p50/p95 и число вызовов Core на один пользовательский запрос. Оптимизацию кэшем откладываем до замеров, а не обещаем нулевой overhead.
- **При недоступном Core:** новые защищённые действия отвечают `UNAVAILABLE`/HTTP 503 без побочных эффектов; существующие managed/доменные процессы не останавливаются из-за потери управляющего канала.

## 10. Стратегия реализации и отложенной верификации

**Решено:** M0–M6 составляют **Build Phase**. Их задача — быстро собрать работающий Arc целиком; полная тестовая кампания выполняется отдельным этапом **M7 — Verification & Hardening** после функциональной заморозки. Переносится полнота тестирования, но не проверка жизнеспособности необратимых архитектурных контрактов.

### 10.1. Три состояния готовности

| Состояние | Критерий |
|---|---|
| `Implemented` | Код собирается, миграции применяются на пустую БД, основной сценарий пройден вручную или локальным test client |
| `Integrated` | Возможность подключена к Arc, наблюдаема и проходит короткий smoke плюс обязательные guardrail-проверки затронутых архитектурных границ |
| `Verified` | Полная unit/integration/contract/E2E/security/recovery матрица автоматизирована и пройдена в M7 |

M0–M6 завершаются в состоянии не ниже `Integrated`; отсутствие полной регрессии не блокирует следующий build-этап. Production-релиз Arc требует `Verified`. Статус фиксируется по возможности/контракту, а не объявляется сразу для всего этапа.

### 10.2. Обязательный быстрый контур M0–M6

На каждом изменении выполняются только дешёвые проверки с целевым локальным временем до 1–2 минут:

- compile/build, форматирование и статический анализ затронутых модулей;
- применение новых миграций к пустой БД и повторный startup;
- один smoke основного изменённого сценария;
- schema/manifest validation для изменённых контрактов;
- точечный regression test только при исправлении уже найденного дефекта.

Одновременно с реализацией обязательны узкие автоматизированные guardrails там, где поздняя ошибка может потребовать перепроектирования: invocation JWT/request proof и test vectors; базовые отрицательные ACL/revoke/cross-root проверки; миграции; idempotency и атомарность outbox/inbox; contract digest/version/route collision; запрет опасных Runtime templates; один вертикальный сценарий `login → Gate → service → Access → DB → event/consumer`. Эти проверки должны быть детерминированы и не превращаться в полную продуктовую регрессию.

Обычные CRUD-ветви, исчерпывающие UI-проверки, клиентские DAV-матрицы, редкие timezone/recurrence случаи, chaos/soak/load, полная permission matrix, accessibility, локализация, backup/restore и upgrade combinations допускается отложить до M7. Для каждого отложенного случая при реализации сохраняется сценарий с ID, предусловиями и ожидаемым результатом в тестовом backlog.

### 10.3. Требования к тестопригодности

Отложенная автоматизация не разрешает писать нетестопригодный код. Время, UUID, сеть, файловое/object storage и внешние providers должны иметь заменяемые адаптеры; бизнес-логика отделяется от HTTP/NATS handlers; schemas и fixtures версионируются; операции принимают idempotency key; существуют воспроизводимые seed-команды. Structured logs, audit, metrics, `request_id` и `traceparent` добавляются в Build Phase, поскольку без них финальная диагностика существенно дорожает.

### 10.4. M7 — Verification & Hardening

После завершения M6 вводится feature freeze. M7 включает полную unit/integration/contract/E2E автоматизацию, security/ACL matrix, DAV client compatibility, browser/UX/i18n/accessibility, crash/network/restart и duplicate delivery, backup/restore/upgrade, нагрузочные замеры и итоговую регрессию после исправлений. Новая функциональность в M7 не добавляется, кроме изменений, необходимых для тестопригодности или устранения дефектов.

## 11. Структура кода (ориентир, не предписанные Go module boundaries)

```text
cmd/{arc-core,arc-gate,arc-agent}/
internal/core/{identity,access,fabric,runtime}/
internal/gate/{http,ws,dav,router}/
internal/infra/{agent,reconciler}/
sdk/go/{micro,rpc,events,acl,identity,contracts,telemetry}/
services/{tasks,calendars,contacts,files,pages,agents,workflows,connectors}/
contracts/          # versioned schema + manifests
migrations/         # ownership per module
ui/                 # Svelte 5 + shadcn-svelte
deploy/             # bootstrap and managed runtimes
docs/{ARCHITECTURE,REQUIREMENTS}.md
```

## 12. Реестр решений и открытые вопросы

| ID | Статус | Решение / вопрос |
|---|---|---|
| A-01–A-07 | **Решено** | Go/Echo + Svelte 5; единый Arc Core (Identity, Access, Fabric, Runtime), NATS между процессами, Arc Gate public ingress, `arc-sdk` над `micro`, доменное владение данными, отдельный привилегированный Arc Infrastructure Agent |
| M0-01 | **M0 baseline v0.8** | Выборочные ACL roots; user/workspace owner без смешивания scopes; allow-only, один `acl_parent`, `inherit=false`, отдельное `access.grants.manage` без чтения содержимого |
| M0-02 | **M0 baseline v0.8** | Онлайн `Check/CheckMany/ListAccessibleRoots`; default deny и fail-closed; новые проверки после commit отзыва видят изменение; операции в полёте могут завершиться |
| M0-03 | **M0 baseline v0.8** | Session/refresh-family revocation; отдельная NATS Service Identity; EdDSA invocation JWT ≤60 сек с `aud/caller/cnf.kid`; client assertions и per-request proof; token exchange без эскалации |
| M0-08 | **M0 baseline v0.8** | Explicit expiring Delegation; проверка online на каждом Check, пересечение actor + grantee + ACL, немедленный запрет новых действий после revoke |
| M0-04 | **M0 baseline v0.8** | Immutable contract + deterministic manifest/schema digest, instance identity + readiness, exact queue group, approval до Micro business subscriptions; отсутствие responder ≠ удаление контракта |
| M0-05 | **M0 baseline v0.8** | Typed SDK + JSON Schema, immutable operation binding; 256 KiB/5с/10с; idempotency ≥24ч; стабильные error codes; route snapshots/compatibility contract tests |
| M0-06 | **M0 baseline v0.8** | `reserve → active → deleting → deleted` (+ `abort`), reconciler, transactional outbox, идемпотентные consumers |
| M0-07 | **M0 baseline** | GORM + SQLite: отдельный файл на SQL-владельца; единая Core БД; Gate без БД; локальные WAL/constraints, явные Gormigrate migrations; runtime/bootstrap отдельно |
| M0-09 | **M0 baseline v0.8** | Runtime = desired state в Core, отдельный Arc Infrastructure Agent; M0 schema/mock contract; M6 single-node Docker executor, pull-current-revision, идемпотентный reconcile, bootstrap вне управления |
| M0-10 | **M0 baseline v0.8** | Invocation `op` bound к утверждённой операции; ACL-admin self-grant аудируется; подписанный RouteSnapshot; exactly-once только в локальной транзакции inbox+effect; настоящий Arc Infrastructure Agent не требуется до M6 |
| T-01 | **Решено v0.8** | M0–M6 — Build Phase со статусом `Integrated`; полная тестовая автоматизация и hardening вынесены в M7; production требует `Verified` |
| O-01 | **Открыто (M1)** | Точная стратегия извлечения Task/Projects и устранения legacy GitHub из Kuayle |
| O-02 | **Открыто (M2)** | Cross-workspace sharing, CalDAV scheduling, фактическая матрица совместимых клиентов |
| O-03 | **Открыто (M3)** | WebDAV locking/ranges, версии, публичные upload links, периодическая проверка прав streaming |
| O-04 | **Открыто (M4–M5)** | Лимиты Starlark, агентные approval classes, внешние секреты и sandbox для plugins |
| O-05 | **Открыто (после M6 baseline)** | Multi-node scheduling, zero-downtime rolling upgrades, автоматический rollback и sandbox для недоверенного кода |

**Статус M0 v0.8:** контракты Identity, Access, Fabric/SDK/Gate и Runtime согласованы, противоречия ревизии закрыты; речь о проектной спецификации, не о завершённой реализации. Для перехода к M1 требуются реализация и минимальные guardrails M0; полная верификация переносится в M7. После проверки прототипом принятые решения получат статус **Решено** в этом же файле; новых ADR-файлов не требуется.
