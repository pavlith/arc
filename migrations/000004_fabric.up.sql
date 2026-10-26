CREATE TABLE fabric.definitions (
 name text PRIMARY KEY, publisher text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE fabric.contracts (
 digest text PRIMARY KEY CHECK(digest ~ '^[a-f0-9]{64}$'),
 service_name text NOT NULL REFERENCES fabric.definitions(name), api_major integer NOT NULL CHECK(api_major>0),
 artifact jsonb NOT NULL, installation jsonb NOT NULL, signature bytea NOT NULL CHECK(octet_length(signature)=64),
 approved_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz,
 UNIQUE(service_name,api_major,digest)
);
CREATE UNIQUE INDEX active_service_major ON fabric.contracts(service_name,api_major) WHERE revoked_at IS NULL;
CREATE TABLE fabric.deployments (
 service_account_id uuid NOT NULL REFERENCES identity.service_accounts(id),
 digest text NOT NULL REFERENCES fabric.contracts(digest), subjects text[] NOT NULL,
 PRIMARY KEY(service_account_id,digest)
);
CREATE TABLE fabric.instances (
 instance_id text PRIMARY KEY, service_account_id uuid NOT NULL REFERENCES identity.service_accounts(id),
 digest text NOT NULL REFERENCES fabric.contracts(digest), build_version text NOT NULL,
 ready boolean NOT NULL DEFAULT false, lease_until timestamptz NOT NULL,
 observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE fabric.route_state(singleton boolean PRIMARY KEY CHECK(singleton), revision bigint NOT NULL DEFAULT 0);
INSERT INTO fabric.route_state VALUES(true,0);
CREATE FUNCTION fabric.immutable_contract() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.digest,NEW.service_name,NEW.api_major,NEW.artifact,NEW.installation,NEW.signature,NEW.approved_at)
 IS DISTINCT FROM (OLD.digest,OLD.service_name,OLD.api_major,OLD.artifact,OLD.installation,OLD.signature,OLD.approved_at)
 THEN RAISE EXCEPTION 'immutable service contract' USING ERRCODE='23514'; END IF;
 IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN RAISE EXCEPTION 'contract cannot be reactivated'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_contract BEFORE UPDATE ON fabric.contracts FOR EACH ROW EXECUTE FUNCTION fabric.immutable_contract();
-- Domain-owned DBs use these table shapes for atomic command replay and event effects.
CREATE TABLE fabric.command_results (
 actor text NOT NULL, operation text NOT NULL, idempotency_key text NOT NULL,
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32), result jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(actor,operation,idempotency_key)
);
CREATE TABLE fabric.outbox (
 event_id uuid PRIMARY KEY, subject text NOT NULL, envelope jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz
);
CREATE TABLE fabric.inbox (
 consumer text NOT NULL, event_id uuid NOT NULL, request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 received_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(consumer,event_id)
);
REVOKE DELETE ON fabric.contracts,fabric.definitions,fabric.deployments FROM arc_core;
