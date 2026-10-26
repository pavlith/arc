CREATE TABLE identity.users (
 id uuid PRIMARY KEY, email text NOT NULL UNIQUE CHECK (email = lower(email)),
 status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE identity.password_credentials (
 user_id uuid PRIMARY KEY REFERENCES identity.users(id), password_hash text NOT NULL,
 recovery_hash bytea UNIQUE, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE identity.sessions (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES identity.users(id),
 secret_hash bytea NOT NULL UNIQUE, csrf_hash bytea NOT NULL,
 expires_at timestamptz NOT NULL, revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON identity.sessions(user_id) WHERE revoked_at IS NULL;
CREATE TABLE identity.refresh_families (
 id uuid PRIMARY KEY, session_id uuid NOT NULL REFERENCES identity.sessions(id),
 expires_at timestamptz NOT NULL, revoked_at timestamptz
);
CREATE TABLE identity.refresh_tokens (
 token_hash bytea PRIMARY KEY, family_id uuid NOT NULL REFERENCES identity.refresh_families(id),
 consumed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON identity.refresh_tokens(family_id);
CREATE TABLE identity.workspaces (
 id uuid PRIMARY KEY, name text NOT NULL CHECK (length(name)>0),
 revision bigint NOT NULL DEFAULT 1
);
CREATE TABLE identity.memberships (
 workspace_id uuid NOT NULL REFERENCES identity.workspaces(id),
 user_id uuid NOT NULL REFERENCES identity.users(id),
 role text NOT NULL CHECK (role IN ('owner','admin','member','guest')),
 revoked_at timestamptz, PRIMARY KEY(workspace_id,user_id)
);
CREATE INDEX ON identity.memberships(user_id) WHERE revoked_at IS NULL;
CREATE TABLE identity.groups (
 id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES identity.workspaces(id),
 name text NOT NULL, UNIQUE(workspace_id,name), UNIQUE(workspace_id,id)
);
CREATE TABLE identity.group_members (
 workspace_id uuid NOT NULL, group_id uuid NOT NULL, user_id uuid NOT NULL,
 PRIMARY KEY(group_id,user_id),
 FOREIGN KEY(workspace_id,group_id) REFERENCES identity.groups(workspace_id,id),
 FOREIGN KEY(workspace_id,user_id) REFERENCES identity.memberships(workspace_id,user_id)
);
CREATE TABLE identity.service_accounts (
 id uuid PRIMARY KEY, service_definition text NOT NULL, deployment text NOT NULL,
 disabled_at timestamptz, UNIQUE(service_definition,deployment)
);
CREATE TABLE identity.service_credentials (
 kid text PRIMARY KEY, service_account_id uuid NOT NULL REFERENCES identity.service_accounts(id),
 public_key bytea NOT NULL CHECK (octet_length(public_key)=32), secret_reference text NOT NULL,
 not_before timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 revoked_at timestamptz, UNIQUE(service_account_id,kid), CHECK (expires_at>not_before)
);
CREATE TABLE identity.agent_identities (
 id uuid PRIMARY KEY, owner_user_id uuid NOT NULL REFERENCES identity.users(id),
 workspace_id uuid REFERENCES identity.workspaces(id), execution_scope text NOT NULL,
 disabled_at timestamptz
);
CREATE TABLE identity.delegations (
 id uuid PRIMARY KEY, grantor_user_id uuid NOT NULL REFERENCES identity.users(id),
 grantee_kind text NOT NULL CHECK(grantee_kind IN ('agent','service')), grantee_id uuid NOT NULL,
 resource_ids uuid[] NOT NULL CHECK(cardinality(resource_ids)>0),
 actions text[] NOT NULL CHECK(cardinality(actions)>0),
 expires_at timestamptz NOT NULL, revoked_at timestamptz,
 created_by uuid NOT NULL REFERENCES identity.users(id), consent_method text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK(grantor_user_id<>grantee_id), CHECK(created_by=grantor_user_id),
 CHECK(expires_at>created_at), CHECK(consent_method='interactive_session')
);
CREATE INDEX ON identity.delegations(grantee_kind,grantee_id) WHERE revoked_at IS NULL;
CREATE TABLE identity.signing_key_metadata (
 kid text PRIMARY KEY, public_key bytea NOT NULL CHECK(octet_length(public_key)=32),
 not_before timestamptz NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz,
 CHECK(expires_at>not_before)
);
CREATE TABLE identity.assertion_nonces (
 namespace text NOT NULL, nonce text NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(namespace,nonce)
);
CREATE INDEX ON identity.assertion_nonces(expires_at);
CREATE TABLE identity.audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, occurred_at timestamptz NOT NULL DEFAULT now(),
 actor text NOT NULL, operation text NOT NULL, target text NOT NULL, outcome text NOT NULL
);
CREATE INDEX ON identity.audit(occurred_at);
CREATE TABLE identity.rate_limits (
 bucket text PRIMARY KEY, window_start timestamptz NOT NULL, attempts integer NOT NULL CHECK(attempts>0)
);
ALTER TABLE identity.delegations
 ADD COLUMN grantee_service_id uuid REFERENCES identity.service_accounts(id),
 ADD COLUMN grantee_agent_id uuid REFERENCES identity.agent_identities(id),
 ADD CONSTRAINT delegation_grantee_fk CHECK (
 (grantee_kind='service' AND grantee_service_id IS NOT NULL AND grantee_service_id=grantee_id AND grantee_agent_id IS NULL) OR
 (grantee_kind='agent' AND grantee_agent_id IS NOT NULL AND grantee_agent_id=grantee_id AND grantee_service_id IS NULL));
-- Domain-command deduplication, distinct from authentication token rotation.
CREATE TABLE identity.command_results (
 actor text NOT NULL, operation text NOT NULL, idempotency_key text NOT NULL,
 request_hash bytea NOT NULL, result jsonb,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(actor,operation,idempotency_key)
);
CREATE INDEX ON identity.command_results(created_at);
