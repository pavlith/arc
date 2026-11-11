# Arc TypeScript client

`@arc/client` provides typed browser access to the current Arc Gate APIs. It ships
TypeScript source as an npm workspace; no Svelte dependency or UI implementation
is required. Use the repository's existing npm workspace install and TypeScript
toolchain. No additional runtime dependency is introduced.

```ts
import { createClient } from '@arc/client';

const arc = createClient(); // Same-origin Gate and browser cookies.
const profile = await arc.identity.profile();
const workspace = await arc.identity.workspaces.bySlug({ slug: 'engineering' });
const roots = await arc.identity.taskRoots.list({ workspace_id: workspace.id });

// A workspace and a Task ACL root are different identifiers.
const root = roots.find((item) => item.can_read);
if (root) {
  const page = await arc.task.work.list({
    workspace_id: workspace.id,
    acl_root_id: root.id,
    limit: 50,
  });
  console.log(page.tasks.map((item) => item.identifier));
}
```

## API surfaces

- `arc.auth`: browser login/session/refresh/logout, invited registration and recovery.
- `arc.identity`: profile/preferences/sessions/password, workspace lifecycle/slug
  lookup, provisioning/user status, invitations, members, groups and Task roots.
- `arc.task`: every HTTP-exposed Task operation in the current signed manifest,
  including Teams/workflow, work items, projects/labels, comments/history, views,
  subtasks/links, templates/triage, bulk updates and root grants.
- `arc.notify`: every HTTP-exposed Notify Inbox and subscription operation.

Task/Notify method paths follow operation IDs after removing the service prefix,
with snake_case segments converted to camelCase. Examples: `task.work.setParent`,
`task.work.bulkUpdate`, `task.work.links.change`, `task.work.triage`,
`task.templates.use`, `notify.inbox.markAllRead`.
Legacy proof operations remain under `task.task` and `task.tasks`. The grants
command is callable as `task.roots.grants(input, options)` and its query as
`task.roots.grants.list(input, options)`. Service-only health operations are excluded.

All Identity commands and domain commands require an explicit idempotency key:

```ts
await arc.notify.inbox.update(
  { id: notification.id, revision: notification.revision, action: 'read' },
  { key: crypto.randomUUID(), signal: controller.signal },
);
```

Keep the same key and input for a retry of the same command; use a new key when
changing its input. The client neither retries commands nor refreshes sessions
automatically. IDs and dates use their JSON string representations, nullable
fields remain nullable and response wrappers/pagination match the server. Identity
lists use `after`; domain lists use their manifest-defined cursors. Follow returned
`next_cursor` even when a page is shorter than the requested limit.

Invited registration returns a one-time recovery code and requires separate login.
Recovery also returns a new one-time code. Do not log or persist these results.
Browser login returns session/CSRF metadata; refresh returns only session metadata.
Password change clears the browser session on the server. Administrative profile
responses do not imply global administrator authority; use the live self-profile.

## Transport

`createClient({ fetch, baseURL, csrfToken, timeoutMs })` supports an injected fetch
implementation and an explicit HTTP origin for non-browser environments. In a
browser the Gate must be on the current origin. A base URL cannot contain a path,
query, credentials or fragment. The library does not manage CLI Bearer tokens or
private Core RPC credentials. Server-side consumers must supply their own trusted
fetch/cookie context; native server fetch has no browser cookie jar.

Requests use same-origin cookies, no-store caching, no redirects and a default
15-second timeout. Mutations read `__Host-arc_csrf` and send `X-CSRF-Token` when
available. Per-call `signal` and `timeoutMs` control cancellation and deadlines.
Generated methods move path/query bindings out of the JSON body; false/zero
query values are retained. Mutations use `Idempotency-Key`.

`APIError` retains `status`, optional structured `code` and `requestId`, with safe
English messages. Transport failures use status 0 and `NETWORK_ERROR`, `TIMEOUT`
or `ABORTED`. Invalid success JSON produces `INVALID_RESPONSE`. No response body
or server message is logged. Input/schema constraints and authorization remain
server-enforced; generated TypeScript types are not a runtime schema validator.

Existing imports of `api`, `APIError`, `Profile`, `Workspace`, `TaskRoot`,
`Invitation`, `Task` and `TaskList` remain available. `TaskList` retains its legacy
response wrapper; `TaskListRequest` names the proof list input. `WorkItem` is the
product response type. `api<T>(path, options)` remains an untyped escape hatch;
prefer the typed methods for current contracts.

## Contract updates and verification

From the repository root:

```sh
npm --prefix client run generate --workspace @arc/client
npm --prefix client run check --workspace @arc/client
```

Generation reads the checked-in Task/Notify manifests and their HTTP request and
response schemas. It never calls a live server or infers endpoints from upstream
Kuayle. `check:contracts` rejects drift without rewriting files; `check` also runs
strict TypeScript checking independently of `client/web`. Identity/Auth are
maintained against Gate's static routes and Core DTOs; update them together with
those contracts. Files/Pages/realtime have no client methods until their APIs exist.

Live requests additionally require deployed migrations, matching signed artifacts,
routes and downstream policies. Type checking does not establish those approvals
or full browser/NATS/security acceptance. Work is tracked in
[#26](https://github.com/pavlith/arc/issues/26).
