# Shared realtime subscription contract

Owner: [#27](https://github.com/pavlith/arc/issues/27).
Delivery: stage 2 of [shortplan](shortplan.md).
The Notify event producer and an opt-in Gate WSS implementation are now in \`dev\`.\nThis is **not a deployment or acceptance claim**; exact broker permissions and\nrevocation/overflow integration checks are still outstanding.

## Ownership and transport

Gate is the only public WSS ingress and owns connections and authorization
orchestration, not notification data or persistent replay. Task and Notify
continue to own their own SQLite/outboxes and event publishing via private
NATS/JetStream. No browser sees broker credentials, NATS subjects or private
event envelopes. Realtime is an invalidation channel, not an alternative data
read API. All content must be refetched through the signed approved HTTP route.

Initial endpoint: `GET /api/v1/arc/realtime` over WSS on Gate's HTTPS origin.
This endpoint is reserved and not supplied by Fabric-discovered routes.
The browser handshake requires both `__Host-arc_session` (HttpOnly) and
`__Host-arc_csrf` (client-readable) Secure SameSite=Lax cookies, a permitted
exact `Origin`, and the WebSocket subprotocol offers `arc.realtime.v1`
and `csrf.<base64url-value>`. Gate compares the offered CSRF value with the
cookie using constant-time comparison; it **never** selects or echoes the
CSRF-bearing subprotocol. Gate passes the session secret and cookie CSRF to
Core Identity for live session validation. No URL token, Authorization header,
mixed Bearer/cookie credentials or arbitrary query fields are accepted.
CLI WebSockets are outside the first release. Strict Host/Origin and trusted
proxy resolution follow the existing Gate HTTP boundary; cleartext and
untrusted forwarded-protocol claims fail closed. Never log raw tokens,
cookies, protocol values or private event envelopes.

A client sends messages after successful upgrade, one JSON object per frame:

```json
{"op":"subscribe","request_id":"client-key","channel":"task","workspace_id":"<uuid>","acl_root_id":"<uuid>"}
```

For a personal Inbox, `channel` is `inbox`, with neither user ID nor root ID.
`unsubscribe` uses the opaque server subscription ID. `ping` requests a
`pong`; unknown commands, repeated fields and unsupported versions are denied.
Each subscription receives an ack with a fresh subscription ID; a rejected
subscription has a safe error code, never target metadata.

## Subscription authority and delivery

| Channel | Permitted producer | Subscribe and per-delivery live authorization |
|---|---|---|
| `task` | Task `evt.task.catalog.changed.v1`, `evt.task.task.created.v1` | Core active browser session, workspace membership, active Task root and `task.read` through approved Access.Check |
| `inbox` | Notify `evt.notify.inbox.changed.v1` (Notify 0.2.0 outbox producer) | Core active browser session, recipient ID exactly equals authenticated actor, no caller-controlled recipient |

Gate accepts only exact approved event subjects and an operator-installed
publisher/consumer permit. It validates the envelope, version, root/recipient
binding and shape before filtering. An event with an ambiguous or missing
workspace/root/recipient binding is discarded, not broadcast. A failure to
reauthorize closes the affected subscription/socket rather than allowing a
cached decision. A revoked session closes all subscriptions; root grant changes
close the affected Task subscriptions. Periodic live checks are required even
without events (at most 30 seconds) so silent revoked sockets do not persist.
Authorization checks also occur on each incoming subscribe and immediately
before each outgoing event, including retries.

Gate never uses business Team membership as ACL. Identity/Access are the
authorities for session/workspace/root, Task owns its business entities,
and Notify owns recipient selection and Inbox state. Gate must not query any
domain SQL, inspect another owner's credentials or infer authorization solely
from event identity.

## Message schema and operational limits

A successful invalidation message contains only:
```json
{"type":"invalidate","subscription_id":"opaque-id","entity_kind":"work","entity_id":"<uuid>","revision":4}
```
For Inbox: `entity_kind` is `inbox`; `entity_id` is the notification UUID when available. Collection changes omit `entity_id` and `revision`, requiring full Inbox refetch.
The message omits titles, descriptions, emails, Markdown, comment bodies,
private links, actor IDs and NATS envelope details. The initial receiver
performs an authorized refetch of the subscribed collection; it never applies
payload content as a document patch. Out-of-order revisions trigger refetch;
a dropped invalidation cannot silently advance a local data version.

Proposed limits for initial implementation (server-enforced):
- At most 8 subscriptions/socket (including Inbox), 1,024 concurrent sockets
  per Gate instance and 20 connection attempts/minute/client IP.
- Incoming JSON frame at most 8 KiB, outgoing invalidation at most 1 KiB.
  IDs are UUIDs except opaque connection/subscription IDs; request_id max 128.
- At most 32 queued events/socket. Slow readers or overflow receive a bounded
  close with a refetch-required reason; events are not silently dropped.
- One reader/one writer per connection, 15-second write deadline, ping/pong
  every 30 seconds and idle timeout at most 90 seconds. Origin and session are
  checked at handshake, per subscribe and before delivery.

Any broker outage, authorization timeout, malformed envelope, stream gap or
send overflow causes fail-closed disconnection. A reconnect repeats the exact
handshake and all subscription authorization. The browser must refetch its
current collections before trusting new invalidations; there is no durable
per-browser replay or exactly-once stream guarantee.

## Implementation and deployment order

1. Add a Notify-owned event for personal Inbox changes, with an additive
   migration, bounded payload and atomic notification mutation/outbox write.
   **Implemented:** Notify 0.2.0 produces `evt.notify.inbox.changed.v1` with
   recipient UUID, optional notification UUID and revision (omitted for bulk).
   Migration `000003_notify_outbox` is required; broker stream permissions,
   signed reapproval and live rollout remain separate.
2. Add Gate WebSocket handshake, bounded protocol reader/writer, private NATS
   consumer and explicit domain event → channel mapping. **Code implemented**\n   with an opt-in \`enable_realtime\` switch, disabled by default. Gate validates\n   live cookies and CSRF at the handshake, and Task's approved \`work.list\`\n   action at subscribe/delivery. It does not start until explicitly enabled.\n   Publish and subscribe only with operator-restricted exact NATS subjects.
3. Wire the exact Core/Gate service approvals: session validation, Access.Check
   and publisher/consumer subjects for Task and Notify. Gate remains DB-free.
   Broker subscriptions require approved scoped credentials and no wildcard
   publish permission.
4. Provide focused tests for cross-workspace known IDs, two users, revoked
   session/root access, missing Core/Access, invalid origin/CSRF, overflow,
   broker disconnect and reconnect. Test event payloads against current
   compiled contracts and the unchanged 200 KiB HTTP/256 KiB RPC envelope.
5. Only after the above, expose the WSS path, update Gate readiness/health
   and add the UI adapter when UI work is explicitly resumed.

Dependencies: replacement Task contract/digest for stage 1, Notify producer
digest pin, broker stream/consumer grants, exact signed installation approvals,
Core identity and Access live checks. Code push alone deploys none of these.

## Initial operator enablement (not yet accepted)

The Gate JSON config may set `"enable_realtime": true` **only after**
granting the Gate NKey exact private subscribe permission to
`evt.task.catalog.changed.v1`, `evt.task.task.created.v1` and
`evt.notify.inbox.changed.v1`. The Notify NKey requires publish permission
to its own `evt.notify.inbox.changed.v1`, and private JetStream must provision
the Notify stream. Gate will not start with a missing broker connection and
will reject upgrades when its realtime hub is unavailable. The server selects
only `arc.realtime.v1` (never the offered CSRF protocol). The CSRF token in
`Sec-WebSocket-Protocol` is formed as
`csrf.<base64url(raw cookie value bytes without padding)>`.

The initial Gate live task check invokes Task's signed `task.work.list`
operation with `limit=1` to exercise Task's own fresh root ACL enforcement
without cached grants or cross-service SQL. Inbox delivery checks the active
browser session and exact recipient ID. Every event is schema-validated
against the pinned domain artifact, then filtered to matching subscriptions.
No browser connects to NATS, and no notification content crosses the WSS
channel. If NATS permissions/streams or the signed Task/Notify/Gate deployment
are not configured, leave the switch off; code push does not imply rollout.
