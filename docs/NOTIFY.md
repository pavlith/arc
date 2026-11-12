# Notify inbox and HTTP webhook

Notify owns its SQLite inbox, subscriptions, notifications, outbound intents and
realtime outbox. Users subscribe to Task, Pages or Files roots they can currently
read. Recipient identity comes from the verified user session. Event payloads
never choose recipients. Inbox results/counts recheck current target read access;
resource references contain no titles, bodies or download credentials.

## Approved sources

Each configured source pins a live Fabric provider, current artifact digest,
exact subject and durable consumer. Supported events are Task creation, Pages
creation/update/restore and completed Files uploads. Other catalog changes have
no notification effect. Inbox deduplication, notifications, optional delivery
intents and realtime hints commit together before ACK. User hints identify only
the recipient's own inbox and require a fresh authorized list fetch.

## Operator webhook configuration

`webhook.enabled` defaults to false. Enabled configuration requires an HTTPS
`url` without credentials/fragment, `key_file` (absolute, private regular file,
32–4096 raw secret bytes), and optional `timeout_ms` (100–5000, default 3000).
Secrets are mounted by the operator and never placed in JSON, event payloads or
logs. Restart reloads configuration/secret. Redirects are rejected; ordinary TLS
certificate validation applies. Optional `ca_file` pins a private operator CA. The URL is operator-controlled, never user input.

The JSON POST body contains exactly `version: 1`, `type: "arc.inbox.changed"`,
`recipient_user_id` and `delivery_key`. No target content, IDs or resource URLs
are sent. `Idempotency-Key` equals the persisted SHA-256 delivery key.
`X-Arc-Timestamp` contains Unix seconds; `X-Arc-Signature` is `v1=` followed by
hex HMAC-SHA256 over the timestamp, a dot, and the exact body bytes. Receivers
must validate the signature in constant time, enforce their freshness window,
and deduplicate the key durably. A retry has the same body/key and a fresh
signature timestamp. Any 2xx response accepts delivery; bodies are ignored.

A short transaction claims an intent for 30 seconds; the network request runs
after commit. Completion is fenced by a random claim token. Failure schedules
exponential retry (1 second to 5 minutes), at most 10 attempts; exhausted rows
remain inspectable with `failed_at`. A crashed claim is reclaimable after lease
expiry with the same delivery key. No provider response bodies/secrets are
persisted. Disabling delivery creates no new external intents and sends none;
previous pending webhook intents remain pending until explicitly re-enabled.
Uncertain external delivery can duplicate: this protocol makes no external
exactly-once guarantee. Fake delivery is an explicitly selected test fixture.

## Deployment and verification

Run the Notify migrator on a fresh owner database before startup. Its baseline stores only `resource_kind` / `resource_id`; it never creates or drops a duplicate `task_id` column. Old numbered migration history and previously approved v1 manifests cannot be reused in place.

Every subscription identifies its
resource kind explicitly (`task`, `page` or `file`); there is no implicit Task
default. Inbox responses use `resource_kind` + `resource_id`, never a second
`task_id`. Replacement contracts/policies require operator-signed Fabric approval.
Tests use a local TLS receiver; production outbound messages require separate
user authorization. Browser and full M7 acceptance require separate checks.
