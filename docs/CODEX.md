# Codex in Arc

Read [AGENTS.md](../AGENTS.md) first. Start with the active Issue, then inspect the affected code and only the relevant headings in [Requirements](REQUIREMENTS.md) / [Architecture](ARCHITECTURE.md). Never ingest whole documents for a narrow task.

## Configuration
- [`.codex/config.toml`](../.codex/config.toml): low verbosity, bounded tool/context output and optional MCP servers disabled by default. Credentials stay in `~/.codex`, never Git.
- Copy `.codex/profiles/fast.config.toml` or `deep.config.toml` to `$CODEX_HOME/{fast,deep}.config.toml`, then use `codex --profile fast|deep`. Verify syntax with the installed Codex version.
- Use fast for isolated edits and deep for security/contract redesign, cross-service failures and ambiguous invariants. Do not blindly lower reasoning for ACL/Identity/Fabric.
- Select only the relevant `.agents/skills/` skill; `shadcn-svelte` is vendored and pinned in `skills-lock.json`. Keep existing `client/web/components.json`.
- GitHub/OpenAI MCP tools are opt-in. Prefer local Git and code; authenticate separately for any external tool.

## Work loop
Issue → relevant code/contract → coherent implementation → focused checks → authorized commit/push → four-line report. Avoid repeated repository discovery, broad tool output, long intermediate plans and redundant CI reruns. A failed focused guardrail must be diagnosed, not silenced.

See [Development](DEVELOPMENT.md) for checks, deployment boundaries and actual readiness levels.
