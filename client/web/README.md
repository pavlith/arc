# Arc web client

Svelte 5 / SvelteKit browser UI (`ui` workspace). Auth, invitation/recovery, workspace/account administration, root-scoped Task CRUD/search and recipient Inbox/subscriptions use `@arc/client` and same-origin Arc Gate APIs. The shell rechecks live membership and clears workspace/root state on navigation. Imported domain sections remain in source but are explicitly unavailable until adapted; they do not mount or issue upstream API requests. Browser cookie/CSRF authorization stays separate from CLI Bearer credentials; server ACL always decides access.

From the repository root:

```sh
npm --prefix client ci
npm --prefix client run check --workspace ui
npm --prefix client run test:unit --workspace ui
npm --prefix client run build --workspace ui
npm --prefix client run dev --workspace ui
```

`client/package-lock.json` is the only client lockfile. Install and update dependencies from the workspace root. Build the web image from the repository root with `docker build -f client/web/Dockerfile .`; its builder uses the same workspace lock and validates generated contract bindings. The Caddy image is an optional static server/proxy; configure its upstream to the approved Arc Gate.

See [product sequence](../../docs/shortplan.md), [Gate architecture](../../docs/ARCHITECTURE.md#6-gate-and-protocol-adapters), and [client/ts](../ts/README.md).

Focused browser verification: build once, install the pinned Playwright Chromium, then run `npm --prefix client run test:arc --workspace ui`. The loopback preview suite uses a Gate HTTP fixture and does not prove signed Core/NATS or production deployment; execute relevant M0 guardrails separately.
