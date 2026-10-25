---
name: arc-svelte-ui
description: Build Arc-specific Svelte 5 workflows, routes, state, API integration, access-aware UX and Russian localization. Use for Arc product flows; use shadcn-svelte for component details, CLI, styling and form composition.
---

# Arc-specific UI workflow

1. Read the active Issue and only its affected requirements. Inspect the existing UI package, routes, store conventions and Svelte version. Do not initialize UI infrastructure unless it is in scope.
2. Model Arc workflows using Svelte 5 patterns consistent with existing code, including loading, empty, error and offline states when relevant.
3. Integrate with Arc Gate/API contracts. Keep client-side permission-aware UX separate from authoritative server-side ACL checks; never trust UI state as authorization.
4. Preserve Russian-first UX, accessibility and approved shared navigation/interaction conventions.
5. For shadcn-svelte components, imports, forms, icons, CLI or theme details, delegate to the vendor `shadcn-svelte` skill. Do not copy its rules into this skill or invent a replacement design system.
6. Keep code changes scoped to the Issue. Use `arc-verify` for affected UI checks; defer broad browser E2E/M7 scenarios unless a focused guardrail requires them.
