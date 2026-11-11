# Arc web client

Svelte 5 / SvelteKit browser UI (`ui` workspace). Calls Arc Gate over its approved same-origin APIs via `@arc/client` in `../ts`. Browser cookie/CSRF authorization is separate from CLI Bearer credentials; server ACL always decides access.

From the repository root:

```sh
npm --prefix client ci
npm --prefix client run check --workspace ui
npm --prefix client run build --workspace ui
npm --prefix client run dev --workspace ui
```

`client/package-lock.json` is the npm-workspace lock; `client/web/package-lock.json` is retained for the standalone web Docker build. Keep both consistent when changing dependencies.

See [product sequence](../../docs/shortplan.md), [Gate architecture](../../docs/ARCHITECTURE.md#6-gate-and-protocol-adapters), and [client/ts](../ts/README.md). Product UI expansion remains separately authorized.
