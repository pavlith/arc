---
name: arc-svelte-ui
description: Build Arc-specific Svelte 5 workflows, routes, state, API integration, access-aware UX and English UI text. Use for Arc product flows; use shadcn-svelte for component details, CLI, styling and form composition.
---

# Arc Svelte UI
1. Inspect `client/web/README.md`, the affected route and the active Issue. An explicit UI request or agreed scope authorizes implementation; never reinitialize the project.
2. Use `client/ts` Gate clients, correct root/workspace scopes, idempotency, browser cookies/CSRF and loading/denied/conflict/reconnect states.
3. UI permissions are hints, never server-side ACL. Keep English product text and accessible patterns.
4. Start at `client/ts/src/index.ts`, `client/web/src/lib/api/` and `client/web/src/routes/`. Load the vendored `shadcn-svelte` skill only for component CLI, imports, forms and styling; `arc-verify` selects focused checks.
