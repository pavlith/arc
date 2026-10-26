-- Service-owned domain schema, replacing legacy combined migration 000005 (never apply both).
CREATE SCHEMA IF NOT EXISTS task AUTHORIZATION arc_migrator;
REVOKE ALL ON SCHEMA task FROM PUBLIC;
CREATE TABLE task.roots (
 acl_root_id uuid PRIMARY KEY, workspace_id uuid NOT NULL,
 state text NOT NULL CHECK(state IN ('prepared','active')),
 UNIQUE(acl_root_id,workspace_id)
);
CREATE TABLE task.tasks (
 id uuid PRIMARY KEY, workspace_id uuid NOT NULL, acl_root_id uuid NOT NULL,
 title text NOT NULL CHECK(length(btrim(title)) BETWEEN 1 AND 300),
 status text NOT NULL DEFAULT 'open' CHECK(status='open'), created_by uuid NOT NULL,
 created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
 FOREIGN KEY(acl_root_id,workspace_id) REFERENCES task.roots(acl_root_id,workspace_id),
 CHECK(updated_at>=created_at)
);
CREATE INDEX task_workspace_user ON task.tasks(workspace_id,acl_root_id,created_by,created_at,id);
CREATE TABLE task.audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, task_id uuid NOT NULL REFERENCES task.tasks(id),
 actor uuid NOT NULL, operation text NOT NULL, request_id text NOT NULL,
 traceparent text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE task.command_results (
 actor text NOT NULL, operation text NOT NULL, idempotency_key text NOT NULL,
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32), result jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(actor,operation,idempotency_key)
);
CREATE TABLE task.outbox (
 event_id uuid PRIMARY KEY, subject text NOT NULL CHECK(subject='evt.task.task.created.v1'), envelope jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz
);
CREATE INDEX task_pending_outbox ON task.outbox(created_at,event_id) WHERE published_at IS NULL;
GRANT USAGE ON SCHEMA task TO arc_task;
GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA task TO arc_task;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA task TO arc_task;
