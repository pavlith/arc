-- Service-owned domain schema, replacing legacy combined migration 000005 (never apply both).
CREATE SCHEMA IF NOT EXISTS tasks AUTHORIZATION arc_migrator;
REVOKE ALL ON SCHEMA tasks FROM PUBLIC;
CREATE TABLE tasks.roots (
 acl_root_id uuid PRIMARY KEY, workspace_id uuid NOT NULL,
 state text NOT NULL CHECK(state IN ('prepared','active')),
 UNIQUE(acl_root_id,workspace_id)
);
CREATE TABLE tasks.tasks (
 id uuid PRIMARY KEY, workspace_id uuid NOT NULL, acl_root_id uuid NOT NULL,
 title text NOT NULL CHECK(length(btrim(title)) BETWEEN 1 AND 300),
 status text NOT NULL DEFAULT 'open' CHECK(status='open'), created_by uuid NOT NULL,
 created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
 FOREIGN KEY(acl_root_id,workspace_id) REFERENCES tasks.roots(acl_root_id,workspace_id),
 CHECK(updated_at>=created_at)
);
CREATE INDEX tasks_workspace_user ON tasks.tasks(workspace_id,acl_root_id,created_by,created_at,id);
CREATE TABLE tasks.audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, task_id uuid NOT NULL REFERENCES tasks.tasks(id),
 actor uuid NOT NULL, operation text NOT NULL, request_id text NOT NULL,
 traceparent text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE tasks.command_results (
 actor text NOT NULL, operation text NOT NULL, idempotency_key text NOT NULL,
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32), result jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(actor,operation,idempotency_key)
);
CREATE TABLE tasks.outbox (
 event_id uuid PRIMARY KEY, subject text NOT NULL CHECK(subject='evt.tasks.task.created.v1'), envelope jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz
);
CREATE INDEX tasks_pending_outbox ON tasks.outbox(created_at,event_id) WHERE published_at IS NULL;
GRANT USAGE ON SCHEMA tasks TO arc_tasks;
GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA tasks TO arc_tasks;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA tasks TO arc_tasks;
