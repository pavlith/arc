# Arc TypeScript client

`@arc/client` is the typed, no-Svelte-dependency client for Arc Gate's signed HTTP operations. It is an npm workspace in `client/ts`, generated from checked-in domain manifests and maintained static Identity/Auth bindings.

```ts
import { createClient } from '@arc/client';

const arc = createClient(); // Same-origin browser cookies and CSRF.
const profile = await arc.identity.profile();
const workspace = await arc.identity.workspaces.bySlug({ slug: 'engineering' });
const roots = await arc.identity.taskRoots.list({ workspace_id: workspace.id });
const root = roots.find((r) => r.can_read);
if (root) {
  const work = await arc.task.work.list({ workspace_id: workspace.id, acl_root_id: root.id, limit: 50 });
}
```

## Operations
`arc.auth` handles browser login, session, refresh, invited registration and recovery. `arc.identity` covers profile, preferences, sessions/password, workspaces, members/groups, invitations and managed Task roots. `arc.task`, `arc.notify`, `arc.files` and `arc.pages` expose the corresponding current Gate-approved manifest operations; byte streams and images use authenticated Gate URLs. Health and service-only operations are not browser methods.

Generated method names follow operation IDs (snake_case → camelCase); e.g. `arc.task.work.bulkUpdate`, `arc.notify.inbox.markAllRead`. The existing narrow Task read/create endpoints coexist until their signed contracts are retired. API return wrappers and ID cursors match the server. UI access checks are hints only; all authorization remains server-side.

## Transport and security
`createClient({ fetch, baseURL, csrfToken, timeoutMs })` supports injected fetch and explicit origins; browsers must use the Gate's origin. Cookie credentials use no-store, no redirects and `__Host-arc_csrf` / `X-CSRF-Token`. Mutations require `{key: idempotencyKey}`: retain the key and body when retrying the same command, use a new key for new input. Calls have cancellation, bounded deadlines and safe structured `APIError` responses. No automatic retry, session refresh, token storage or CLI Bearer handling. Never log one-time recovery codes or credentials.

Core transport types (`api`, `APIError`, `Profile`) remain exported; use `WorkItem` for the current Task response instead of retired proof aliases. No client TypeScript type grants a permission; server schema and live ACL are authoritative.

## Generation and checks
```sh
npm --prefix client ci
npm --prefix client run generate --workspace @arc/client
npm --prefix client run check --workspace @arc/client
```
`check:contracts` verifies the checked-in generated bindings without rewriting files; `check` also runs strict TypeScript. Changing an HTTP manifest requires regeneration and corresponding scoped Gate/Codex checks. Live use separately requires migrations, signed contract installation and approvals; TypeScript success is not operational acceptance. Track changes in [#26](https://github.com/pavlith/arc/issues/26).
