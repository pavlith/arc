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

## Delivery boundary

Each artifact/schema change requires signed Task replacement approval, exact
broker subjects and an updated Notify producer digest. New event subjects also
need explicit JetStream stream and publisher permissions. UI reuse goes through
Arc Gate/CSRF/idempotency adapters. No GitHub integration is required for any
Task product operation.
