---
name: arc-issue
description: Work on an Arc GitHub Issue through scoping, implementation and PR handoff. Use when selecting an issue, starting a task or preparing its delivery.
---

# Arc Issue workflow

1. Read the selected Issue, labels, scope, acceptance criteria and normative references. Every change, including docs/cleanup, needs an Issue before editing. If none was supplied, reuse a matching Issue or create one for the authorized request with scope, acceptance and minimal verification; do not choose unrelated work.
2. Keep GitHub Issues as the only task tracker; never create a Markdown backlog or GitHub Project.
3. Read only the referenced sections of docs/REQUIREMENTS.md and docs/ARCHITECTURE.md.
4. Work on the requested scope in dev. Mark status: in-progress and assign the executor if authorization/tools allow; avoid creating duplicate labels.
5. Use English for Issues and engineering materials. Inspect actual code rather than treating historical claims as current evidence. Implement the smallest coherent change and invoke arc-verify for relevant checks. Do not label an unexecuted M7 check as passed.
6. Prepare a PR only when explicitly requested or consistent with the current delivery flow. Include Closes #N only for work actually completed; list checks and deferred coverage.
7. Summarize files changed, verification and blockers briefly. Never auto-merge or close a partially completed issue.
