package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func runtimeControl() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000006_runtime_control", Migrate: func(tx *gorm.DB) error {
		statements := []string{
			`CREATE TABLE runtime_nodes (
    id TEXT PRIMARY KEY, service_account_id TEXT NOT NULL UNIQUE REFERENCES identity_service_accounts(id),
    capabilities TEXT NOT NULL CHECK(json_valid(capabilities) AND json_type(capabilities)='array'),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), last_seen_at DATETIME,
    created_at DATETIME NOT NULL)`,
			`CREATE TABLE runtime_templates (
    node_id TEXT NOT NULL REFERENCES runtime_nodes(id), id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    spec TEXT NOT NULL CHECK(json_valid(spec) AND json_type(spec)='object'),
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)), created_at DATETIME NOT NULL,
    PRIMARY KEY(node_id,id,revision))`,
			`CREATE TABLE runtime_resources (
    id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES runtime_nodes(id),
    template_id TEXT NOT NULL, template_revision INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('docker.container','lxd.instance','systemd.service')),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    state TEXT NOT NULL CHECK(state IN ('running','stopped','deleted')),
    replicas INTEGER NOT NULL CHECK(replicas BETWEEN 0 AND 100),
    spec TEXT NOT NULL CHECK(json_valid(spec) AND json_type(spec)='object'),
    operation_id TEXT NOT NULL REFERENCES runtime_operations(id) DEFERRABLE INITIALLY DEFERRED,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY(node_id,template_id,template_revision) REFERENCES runtime_templates(node_id,id,revision),
    CHECK(json_extract(spec,'$.id') IS id AND json_extract(spec,'$.node_id') IS node_id
     AND json_extract(spec,'$.revision') IS revision AND json_extract(spec,'$.kind') IS kind
     AND json_extract(spec,'$.template_id') IS template_id AND json_extract(spec,'$.template_revision') IS template_revision
     AND json_extract(spec,'$.state') IS state AND json_extract(spec,'$.replicas') IS replicas),
    CHECK((state='running' AND replicas>0) OR (state IN ('stopped','deleted') AND replicas=0)))`,
			`CREATE TABLE runtime_operations (
    id TEXT PRIMARY KEY, resource_id TEXT NOT NULL REFERENCES runtime_resources(id),
    requested_revision INTEGER NOT NULL CHECK(requested_revision BETWEEN 1 AND 9007199254740991),
    actor TEXT NOT NULL, idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    status TEXT NOT NULL CHECK(status IN ('pending','running','succeeded','failed','cancelled')),
    error_code TEXT NOT NULL DEFAULT '', result TEXT NOT NULL CHECK(json_valid(result)),
    created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL,
    UNIQUE(actor,idempotency_key), UNIQUE(resource_id,requested_revision))`,
			`CREATE TABLE runtime_revisions (
    resource_id TEXT NOT NULL REFERENCES runtime_resources(id), revision INTEGER NOT NULL,
    spec TEXT NOT NULL CHECK(json_valid(spec)), digest TEXT NOT NULL CHECK(length(digest)=64),
    operation_id TEXT NOT NULL UNIQUE REFERENCES runtime_operations(id), created_at DATETIME NOT NULL,
    PRIMARY KEY(resource_id,revision))`,
			`CREATE TABLE runtime_reports (
    node_id TEXT NOT NULL REFERENCES runtime_nodes(id), event_id TEXT NOT NULL,
    operation_id TEXT NOT NULL REFERENCES runtime_operations(id), digest TEXT NOT NULL CHECK(length(digest)=64),
    payload TEXT NOT NULL CHECK(json_valid(payload)), received_at DATETIME NOT NULL,
    PRIMARY KEY(node_id,event_id))`,
			`CREATE TABLE runtime_observations (
    resource_id TEXT PRIMARY KEY REFERENCES runtime_resources(id),
    node_id TEXT NOT NULL REFERENCES runtime_nodes(id), operation_id TEXT NOT NULL REFERENCES runtime_operations(id),
    revision INTEGER NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)), received_at DATETIME NOT NULL)`,
			`CREATE TABLE runtime_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
    target_id TEXT NOT NULL, operation_id TEXT, occurred_at DATETIME NOT NULL)`,
			`CREATE TABLE runtime_outbox (
    event_id TEXT PRIMARY KEY REFERENCES runtime_operations(id), subject TEXT NOT NULL,
    payload TEXT NOT NULL CHECK(json_valid(payload)), created_at DATETIME NOT NULL, published_at DATETIME)`,
			`CREATE TRIGGER runtime_outbox_immutable BEFORE UPDATE ON runtime_outbox BEGIN
 SELECT CASE WHEN NEW.event_id IS NOT OLD.event_id OR NEW.subject IS NOT OLD.subject
 OR NEW.payload IS NOT OLD.payload OR NEW.created_at IS NOT OLD.created_at
 OR (OLD.published_at IS NOT NULL AND NEW.published_at IS NOT OLD.published_at)
 THEN RAISE(ABORT,'immutable runtime hint') END; END`,
			`CREATE INDEX runtime_resources_node ON runtime_resources(node_id,id)`,
			`CREATE TRIGGER runtime_node_immutable BEFORE UPDATE ON runtime_nodes BEGIN
    SELECT CASE WHEN NEW.id IS NOT OLD.id OR NEW.service_account_id IS NOT OLD.service_account_id
     OR NEW.capabilities IS NOT OLD.capabilities OR NEW.created_at IS NOT OLD.created_at
     OR (OLD.active=0 AND NEW.active<>0) THEN RAISE(ABORT,'immutable runtime node binding') END; END`,
			`CREATE TRIGGER runtime_template_immutable BEFORE UPDATE ON runtime_templates BEGIN
    SELECT CASE WHEN NEW.node_id IS NOT OLD.node_id OR NEW.id IS NOT OLD.id OR NEW.revision IS NOT OLD.revision
     OR NEW.spec IS NOT OLD.spec OR NEW.created_at IS NOT OLD.created_at OR (OLD.revoked=1 AND NEW.revoked<>1)
     THEN RAISE(ABORT,'immutable runtime template') END; END`,
			`CREATE TRIGGER runtime_resource_revision BEFORE UPDATE ON runtime_resources BEGIN
    SELECT CASE WHEN NEW.id IS NOT OLD.id OR NEW.node_id IS NOT OLD.node_id OR NEW.kind IS NOT OLD.kind
     OR NEW.revision<>OLD.revision+1 OR OLD.state='deleted'
     THEN RAISE(ABORT,'invalid runtime resource revision') END; END`,
			`CREATE TRIGGER runtime_operation_immutable BEFORE UPDATE ON runtime_operations BEGIN
    SELECT CASE WHEN NEW.id IS NOT OLD.id OR NEW.resource_id IS NOT OLD.resource_id
     OR NEW.requested_revision IS NOT OLD.requested_revision OR NEW.actor IS NOT OLD.actor
     OR NEW.idempotency_key IS NOT OLD.idempotency_key OR NEW.request_hash IS NOT OLD.request_hash
     OR NEW.result IS NOT OLD.result OR NEW.created_at IS NOT OLD.created_at
     THEN RAISE(ABORT,'immutable runtime operation') END;
    SELECT CASE WHEN NEW.status<>OLD.status AND NOT
     (OLD.status IN ('pending','running') AND NEW.status IN ('running','succeeded','failed','cancelled'))
     THEN RAISE(ABORT,'invalid runtime operation transition') END; END`,
		}
		// Durable revisions, receipts and audit are append-only. Desired resources
		// retain deletion tombstones; disabling/revocation cannot erase ownership.
		for _, table := range []string{"runtime_nodes", "runtime_templates", "runtime_resources", "runtime_operations", "runtime_revisions", "runtime_reports", "runtime_audit", "runtime_outbox"} {
			statements = append(statements, "CREATE TRIGGER "+table+"_no_delete BEFORE DELETE ON "+table+" BEGIN SELECT RAISE(ABORT,'runtime history retained'); END")
		}
		for _, table := range []string{"runtime_revisions", "runtime_reports", "runtime_audit"} {
			statements = append(statements, "CREATE TRIGGER "+table+"_no_update BEFORE UPDATE ON "+table+" BEGIN SELECT RAISE(ABORT,'runtime history immutable'); END")
		}
		for _, sql := range statements {
			if err := tx.Exec(sql).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
