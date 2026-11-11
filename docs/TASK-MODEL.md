# Task product model

Implementation owner: [#10](https://github.com/pavlith/arc/issues/10).

## Data adaptation

Task owns business Teams, workflow statuses, Projects, work items and views.
Identity Groups remain ACL principals. Team membership does not grant access;
all public operations use the domain-bound active workspace/root and live Access.
Teams and their workflow initially live inside an already provisioned Task root.
Multiple Teams can share a root and therefore its access boundary. Independently
private Teams require independently provisioned roots; a boolean on a Team never
creates privacy or another permission engine.

Existing Task IDs, titles, creators, timestamps, audit, command replay and outbox
data are preserved by additive migrations. Legacy proof APIs remain a narrow
projection. New product APIs and schemas are explicit approved operations rather
than an implicit reinterpretation of old credentials. Rich descriptions are data,
never executable HTML; clients render/sanitize them before display.

Kuayle source is a behavior/interface reference, not a database migration source.
There is no automatic external database import in this delivery. An explicit
importer must later map users, workspace/root boundaries and foreign IDs without
trusting upstream permission fields. No existing Arc data is rewritten into a
Kuayle database layout.

## Personal and workspace data

Initial product operations are workspace/root scoped. Existing personal resources
are untouched. Personal-task UI and independently permissioned personal Task
roots require a separate explicit extension; personal saved settings/views must
not create personal ownership of corporate tasks.

## Team workflow

Team keys are uppercase stable identifiers, unique within a workspace. Teams
have names, descriptions, colors and optimistic revisions. Archive retains data
and blocks subsequent Team/workflow commands; no workspace or personal resource
is deleted. Workflow statuses belong to exactly one Team/root/workspace, have
names, categories, colors and positions, and exactly one active default. Team
creation installs the default workflow in the same owner transaction.

Team/workflow changes require `access.grants.manage`; reading metadata requires
`task.read`. Subsequent work-item writes use explicit product operations and live
root authority. Domain mutation, audit, replay result and change hint outbox
commit together. Hints contain identifiers/revisions, not titles or descriptions;
subscribers must reacquire permission to fetch content.

## Work-item projection

`tasks` retains the immutable proof storage shape; additive `task_details` and
`task_assignees` hold product fields. New `task.work.*` operations use the same
Task IDs and titles while returning workflow category/status ID, Team, stable
creation identifier, description, priority, due date, card order and assignees.
Legacy tasks appear in the new read model with status `open`, revision 1, no Team
and their UUID as identifier until explicitly assigned to a Team by an update.
Identifiers allocated from a Team key/counter remain stable if the task moves
between Teams inside the same root. Cross-root moves are not supported.

Product reads list all tasks permitted by the root's `task.read`, including other
creators; the legacy list remains creator-filtered. Root `task.create` is the
explicit write authority for shared product edits. Such edits require both the
current product revision and base `updated_at`, so concurrent legacy title edits
also conflict rather than overwrite. Archive needs `task.delete` and returns only
scope/ID/revision/timestamp, never content. Legacy and product reads hide archived
work items and tasks in archived Teams.

Updates replace the full mutable product representation; omitted description,
priority, due date, order and assignees reset to their empty/default values.
No raw HTML is served or executed; descriptions are plain text/Markdown data.
List/search order is stable by UUID with a cursor, not a rank-sorted database
query. `sort_order` supports client board layout; changing it is a versioned edit.
The page may stop early to stay within the RPC response budget; always follow
`next_cursor` rather than assuming a short page is final.

Assignees are checked through an exact approved downstream
`access.v1.principals.validate_users` operation: actor write authority, live target
membership and target `task.read` on the same root. Task never queries Identity's
database. Validation and later mutation are separate owner transactions; a revoke
after validation may leave an assigned identifier but cannot authorize a later
read. Active tasks prevent their status from being archived; a status can instead
be renamed/reordered or tasks moved first.

## Projects, labels and Team membership

Projects belong to a root, optionally to one Team in that root. Their Team scope
is immutable after creation; name, description, status and dates are versioned.
A task may reference only a project from the same workspace/root and, for a
Team-scoped project, the same Team. Labels are root-scoped. References are checked
in the command transaction; SQLite foreign keys/triggers reinforce these bounds.
Project/label archive retains existing references and does not hide tasks or
revoke ACL. Direct metadata reads remain available to root readers. Archived
references may be retained or removed by an edit, but cannot be newly assigned.

Business Team membership is a Task-owned user/Team association, independent of
Identity Groups, workspace membership and ACL. Adding a member requires root
management authority plus live workspace membership and `task.read` for the
target user. Removal remains possible after the target user loses access.
Changes use the Team's current revision, increment it, and emit the same minimal
Team change hint. Historical associations can remain after access revocation;
they never authorize a read. Member lists contain user IDs/timestamps only;
profile data comes from the separately authorized Identity APIs.

## Discussion, history and saved-query privacy

Comment parents are immutable references within the same task/root/workspace;
thread depth is bounded. Text editing is author-only; resolution is a root-writer
operation and moderation archive uses `task.delete`. Text is returned as JSON
data, never executable HTML. History exposes product audit metadata and changed
field names, not reconstructed old values or snapshots of private content.

Saved views are owned query definitions inside the corporate root. A personal
definition is visible only to its owner; a shared definition is visible to current
root readers, and only its owner may edit or archive it. Filters never create
access authority. Private-only changes have no root-wide event; publishing,
shared changes and unsharing have minimal identifier/revision hints. Presentation
configuration belongs to the client, with typed server validation and bounded
pagination. Lists and subsequent target reads always reacquire current access.

## Delivery boundary

Each artifact/schema change requires signed Task replacement approval, exact
broker subjects and an updated Notify producer digest. New event subjects also
need explicit JetStream stream and publisher permissions. UI reuse goes through
Arc Gate/CSRF/idempotency adapters. No GitHub integration is required for any
Task product operation.

### Hierarchy

A product work item has at most one parent in its existing workspace/ACL root.
Business Teams may differ; this grants no additional access. A hierarchy has at
most 32 edges from root to leaf. Reparenting checks the complete ancestor chain
and subtree height in the command transaction, uses the child's revision and
updated timestamp, and writes metadata-only audit/invalidation. Archive retains
edges and never cascades; active children can detach from an archived parent.
Legacy proof tasks require explicit Team adoption before hierarchy attachment.

### Links

Links are scoped to the existing workspace/ACL root. `related` is symmetric;
`blocks` and `duplicate_of` are directed and acyclic within their kind. Duplicate
marking has at most one outgoing target; it does not merge data. A task has at
most 100 incident links. Link mutation advances both work revisions and emits
metadata-only invalidations in the same transaction. Archived endpoints retain
links, are hidden from link lists and may be removed from an active source.

### Shared work templates (Task 0.8.0)

Templates live inside one Task root and one immutable business Team. They do
not create another permission boundary and are visible to current root readers.
Creating, replacing and archiving templates requires `access.grants.manage`;
using a template requires `task.create` on that root. All changes use the Task
command replay/audit/outbox transaction. Definition changes use optimistic
`revision`, while archive retains the row.

The template definition is a bounded `WorkInput` with a required title and
Team; optional fields are priority, workflow status, Markdown/plain-text
description, project, labels, assignees, due date and sort order. Team scope is
immutable; status/project/labels must be live and in the same authorized
root/Team. Assignees undergo live downstream validation. Creation from a
template revalidates all references and rights, allocates a new task identifier
and uses ordinary work-item creation; archived Teams/templates cannot be used.
An optional title override changes only the new task, never the template.
