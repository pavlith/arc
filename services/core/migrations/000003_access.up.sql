CREATE TABLE access.policy_state (singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0));
INSERT INTO access.policy_state(singleton) VALUES(true);
CREATE TABLE access.resource_types (
 type text PRIMARY KEY, provider_service uuid NOT NULL REFERENCES identity.service_accounts(id),
 contract_digest text NOT NULL CHECK(contract_digest ~ '^[a-f0-9]{64}$'),
 actions text[] NOT NULL CHECK(cardinality(actions)>0), share_action text NOT NULL,
 create_action text NOT NULL, delete_action text NOT NULL, allow_inheritance boolean NOT NULL,
 CHECK(share_action=ANY(actions)), CHECK(create_action=ANY(actions)), CHECK(delete_action=ANY(actions)),
 CHECK('access.grants.manage'=ANY(actions)), UNIQUE(type,provider_service)
);
CREATE TABLE access.resources (
 id uuid PRIMARY KEY, type text NOT NULL, provider_service uuid NOT NULL,
 owner_kind text NOT NULL CHECK(owner_kind IN ('user','workspace')), owner_id uuid NOT NULL,
 owner_user_id uuid REFERENCES identity.users(id), workspace_id uuid REFERENCES identity.workspaces(id),
 acl_parent_id uuid REFERENCES access.resources(id), inherit_acl boolean NOT NULL,
 state text NOT NULL CHECK(state IN ('reserved','active','aborted','deleting','deleted')),
 policy_revision bigint NOT NULL CHECK(policy_revision>0),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(type,provider_service) REFERENCES access.resource_types(type,provider_service),
 CHECK((owner_kind='user' AND owner_user_id IS NOT NULL AND owner_id=owner_user_id AND workspace_id IS NULL)
 OR (owner_kind='workspace' AND owner_user_id IS NULL AND workspace_id IS NOT NULL AND owner_id=workspace_id)),
 CHECK(acl_parent_id IS NULL OR acl_parent_id<>id)
);
CREATE INDEX ON access.resources(acl_parent_id);
CREATE INDEX ON access.resources(workspace_id,id) WHERE state='active';
CREATE INDEX ON access.resources(owner_kind,owner_id,id) WHERE state='active';
CREATE TABLE access.grants (
 id uuid PRIMARY KEY, resource_id uuid NOT NULL REFERENCES access.resources(id),
 principal_kind text NOT NULL CHECK(principal_kind IN ('user','role','group','service','agent')),
 principal_id text NOT NULL, action text NOT NULL,
 expires_at timestamptz, revoked_at timestamptz,
 created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON access.grants(resource_id,action) WHERE revoked_at IS NULL;
CREATE TABLE access.operations (
 actor text NOT NULL, caller uuid NOT NULL REFERENCES identity.service_accounts(id),
 operation text NOT NULL, idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32), resource_id uuid REFERENCES access.resources(id),
 state text NOT NULL CHECK(state IN ('running','completed')), result jsonb,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(actor,caller,operation,idempotency_key)
);
CREATE TABLE access.policy_audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 actor text NOT NULL, caller uuid NOT NULL REFERENCES identity.service_accounts(id), on_behalf_of uuid REFERENCES identity.users(id),
 operation text NOT NULL, resource_id uuid REFERENCES access.resources(id),
 policy_revision bigint NOT NULL UNIQUE CHECK(policy_revision>0), change_kind text NOT NULL,
 grant_id uuid REFERENCES access.grants(id), change jsonb NOT NULL DEFAULT '{}',
 occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON access.policy_audit(resource_id,policy_revision);
CREATE FUNCTION access.validate_resource() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p access.resources; current_id uuid; visited uuid[]:=ARRAY[NEW.id];
BEGIN
 IF TG_OP='UPDATE' THEN
  IF (NEW.type,NEW.provider_service,NEW.owner_kind,NEW.owner_id,NEW.workspace_id,NEW.owner_user_id,NEW.acl_parent_id,NEW.inherit_acl)
   IS DISTINCT FROM (OLD.type,OLD.provider_service,OLD.owner_kind,OLD.owner_id,OLD.workspace_id,OLD.owner_user_id,OLD.acl_parent_id,OLD.inherit_acl) THEN
   RAISE EXCEPTION 'resource scope is immutable' USING ERRCODE='23514';
  END IF;
  IF NEW.state<>OLD.state AND NOT ((OLD.state='reserved' AND NEW.state IN ('active','aborted')) OR
    (OLD.state='active' AND NEW.state='deleting') OR (OLD.state='deleting' AND NEW.state='deleted')) THEN
   RAISE EXCEPTION 'invalid resource transition' USING ERRCODE='23514';
  END IF;
 END IF;
 current_id:=NEW.acl_parent_id;
 WHILE current_id IS NOT NULL LOOP
  IF current_id=ANY(visited) THEN RAISE EXCEPTION 'ACL cycle' USING ERRCODE='23514'; END IF;
  visited:=array_append(visited,current_id);
  IF cardinality(visited)>64 THEN RAISE EXCEPTION 'ACL depth exceeds 64' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT p FROM access.resources WHERE id=current_id;
  IF (p.owner_kind,p.owner_id,p.workspace_id) IS DISTINCT FROM (NEW.owner_kind,NEW.owner_id,NEW.workspace_id) THEN
   RAISE EXCEPTION 'ACL owner scope mismatch' USING ERRCODE='23514';
  END IF;
  IF TG_OP='INSERT' AND p.state<>'active' THEN RAISE EXCEPTION 'parent is not active' USING ERRCODE='23514'; END IF;
  current_id:=p.acl_parent_id;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER resource_invariants BEFORE INSERT OR UPDATE ON access.resources FOR EACH ROW EXECUTE FUNCTION access.validate_resource();
CREATE FUNCTION access.immutable_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'policy audit is append-only' USING ERRCODE='23514'; END $$;
CREATE TRIGGER immutable_policy_audit BEFORE UPDATE OR DELETE ON access.policy_audit FOR EACH ROW EXECUTE FUNCTION access.immutable_audit();
REVOKE UPDATE,DELETE ON access.policy_audit FROM arc_core;
