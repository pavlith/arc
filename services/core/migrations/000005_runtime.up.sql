-- Core owns desired state; privileged host execution belongs to Arc Infra.
CREATE TABLE runtime.desired_deployments (
  id text PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 128),
  service_name text NOT NULL CHECK(length(service_name) BETWEEN 1 AND 128),
  spec jsonb NOT NULL,
  replicas integer NOT NULL CHECK(replicas >= 0),
  revision bigint NOT NULL DEFAULT 1 CHECK(revision > 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON runtime.desired_deployments FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.desired_deployments TO arc_core;
