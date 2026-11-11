# Arc documentation

| Document | Purpose |
|---|---|
| [Requirements](REQUIREMENTS.md) | Product scope, stable requirement IDs and milestone acceptance |
| [Architecture](ARCHITECTURE.md) | Trust boundaries, protocol/storage contracts and decisions |
| [Development](DEVELOPMENT.md) | Setup, checks and issue-first delivery |
| [Sequence before GitHub](shortplan.md) | Agreed service boundaries and implementation dependencies before the optional connector |
| [Codex](CODEX.md) | Repository agent configuration, skills and optional integrations |

For a narrow task, use the context map in [AGENTS.md](../AGENTS.md#context-routing-read-the-smallest-relevant-section)
to find the relevant normative sections. Setup and verification commands live in
Development; component guides add only component-specific details.

Component instructions stay beside their implementation:

- [SDK](../sdk/README.md), [transport](../sdk/transport/README.md), [database](../sdk/database/README.md).
- [Services](../services/README.md), [Core startup](../services/core/README.md), [Linux Agent](../services/agent/README.md).
- [Shared test infrastructure](../test/README.md).

[GitHub Issues](https://github.com/pavlith/arc/issues) own actionable work and labels
own its status. Documents distinguish implemented behavior from planned contracts;
they do not duplicate Issue backlogs or historical acceptance reports.
