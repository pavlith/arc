---
name: arc-svelte-ui
description: Develop Arc user interfaces with Svelte 5 and shadcn-svelte. Use when changing UI components, routes, forms, state or client-side API integration.
---

# Arc Svelte UI workflow

1. Inspect existing UI package, Svelte version and component conventions before editing; the stack is Svelte 5 + shadcn-svelte.
2. Prefer existing UI primitives and existing form/API utilities; do not add another component library or reinvent shared widgets.
3. Use Svelte 5 idioms consistent with the current codebase; preserve accessibility, loading/error states and localized Russian UX.
4. Never implement a client-side authorization assumption as a replacement for server ACL checks.
5. Keep changes scoped to the requested flow. Run affected UI check/build via arc-verify; leave browser E2E and full UX matrix for M7 unless a regression requires it.
