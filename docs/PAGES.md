# Pages / Wiki backend

Tracking: [#11](https://github.com/pavlith/arc/issues/11). UI remains paused.

Pages is a separate signed Go service, SQLite owner and metadata outbox. Its
personal/workspace roots follow reserve/domain receipt/activate and the Files
scope model: personal roots bind an immutable user owner with empty workspace;
workspace roots require the exact workspace. Root types are `pages.personal`
and `pages.workspace`, actions read/create/write/delete/share plus grant manage.
Business parentage grants no ACL. Cross-root/scope moves are rejected.

## Content and hierarchy

Pages have UUID, root/workspace, optional parent, title (1–256 characters),
bounded Tiptap JSON and positive revision. Lists/search/sidebar return metadata
only, with ascending UUID cursor and limit 1–100. Search is a literal
case-sensitive title substring. Move rejects cycles, archived parents and
resulting depth beyond 32. Archive is soft deletion and requires no active
children; archived pages disappear from normal reads and previews.

Create/update validate a closed Tiptap node/mark/attribute vocabulary: headings,
paragraphs, text, lists/task lists, block quotes, rules/breaks, code and tables;
images, file attachments and resource links contain opaque Arc refs. Reject
unknown/HTML/style/event-handler attributes, unsafe URL schemes, excess depth,
more than 2,000 nodes, more than 64 KiB serialized JSON and more than four
references per document in this initial synchronous validation contract.
Images/file refs resolve through Files; links may resolve Task/Files/Pages.
Every save/template use/restore rechecks target access, preserving workspace.
Stored references carry no target title/content cache. GET returns authored
JSON; rendering uses allowed nodes and separate authorized target lookups,
never arbitrary stored HTML. Inline images use Files' safe image route.

## Changes, versions and templates

Mutations require an idempotency key; updates/move/archive/restore require the
current revision. Replay, revision CAS, immutable version, audit and catalog
outbox commit together. Revisions retain the last 100 content snapshots per
page. Restore copies title/document from a retained version into a new revision;
it preserves current parent/root, preventing an implicit permission-boundary
move. A page section is bounded to 10,000 rows including archives.

Scoped templates store title/document with their own revision and soft deletion.
They never grant target access. Template use and restore require an additional live pages.read decision before
replay and snapshot access. Their exact source-bound Access checks are approved
as a closed compound contract; create-only/write-only actors cannot read stored
snapshots. Move/archive return ID/revision/state only.

Template-based creation snapshots the current
template content and revalidates all referenced resources for the creator.

## Deployment

Apply owner migrations explicitly before `arc-pages` startup. Register Pages
service/key, approve its complete artifact and both types, exact Gate routes,
source-bound Access checks/lifecycle/grants and explicit cross-domain read edges.
Provision JetStream for `evt.pages.catalog.changed.v1`; publisher permissions
are private and metadata-only. Personal routes use `/api/v1/pages/personal/roots`
and workspace routes `/api/v1/pages/workspaces/{workspace_id}/roots`.
No production signing material, migration or external deployment is automatic.

## Verification evidence

The isolated office live fixture in `scripts/test-files-live.sh` now installs
Pages as a third independent database/service composition with a distinct NKey,
real signed approvals, current Identity/Access and HTTPS Gate routes. It covers
personal/workspace roots for two users/two workspaces, known-ID isolation,
cycle rejection, editor update, parent-preserving version restore, scoped
snapshot templates and a denied Files embed. Native tests additionally cover
read revocation before cached restore/template use, stale CAS, rollback on
outbox failure, archived visibility, JSON grammar/depth/node/escaped-size limits.
UI, production rollout and the full M7/load matrix remain deferred.
