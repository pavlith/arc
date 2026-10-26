package migrations_test

import (
 "context"
 "path/filepath"
 "strings"
 "testing"

 "github.com/pavlith/arc/sdk/database"
 "github.com/pavlith/arc/services/core/migrations"
 "gorm.io/gorm"
)

func openCore(t *testing.T) *gorm.DB {
 t.Helper()
 db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), "core.sqlite"))
 if err != nil { t.Fatal(err) }
 t.Cleanup(func() { _ = database.Close(db) })
 if err := database.Migrate(context.Background(), db, migrations.SQLite()); err != nil { t.Fatalf("Core migrations: %v", err) }
 return db
}

func execOK(t *testing.T, db *gorm.DB, sql string, args ...any) {
 t.Helper()
 if err := db.Exec(sql, args...).Error; err != nil { t.Fatalf("expected success: %s: %v", sql, err) }
}

func execReject(t *testing.T, db *gorm.DB, sql string, args ...any) {
 t.Helper()
 if err := db.Exec(sql, args...).Error; err == nil { t.Fatalf("invalid write accepted: %s", sql) }
}

func TestCoreSQLiteMigrationsAndOwnerIsolation(t *testing.T) {
 db := openCore(t)
 for _, name := range []string{
  "identity_users", "identity_sessions", "identity_delegations",
  "identity_command_results", "access_resource_types", "access_policy_state",
  "access_operations", "access_policy_audit", "fabric_contracts",
  "fabric_instances", "fabric_route_state", "fabric_outbox",
  "runtime_desired_deployments", "schema_migrations",
 } {
  if !db.Migrator().HasTable(name) { t.Errorf("missing Core table %q", name) }
 }
 if db.Migrator().HasTable("tasks") || db.Migrator().HasTable("notifications") {
  t.Fatal("Core database contains another service's tables")
 }
 if err := database.Migrate(context.Background(), db, migrations.SQLite()); err != nil {
  t.Fatalf("migrations not repeatable: %v", err)
 }
 var count int64
 if err := db.Table("schema_migrations").Count(&count).Error; err != nil || count != 5 {
  t.Fatalf("migration history has %d entries: %v", count, err)
 }
}

func TestCoreIdentitySQLiteConstraints(t *testing.T) {
 db := openCore(t)
 execOK(t, db, "INSERT INTO identity_users(id,email) VALUES('u','user@example.com')")
 execReject(t, db, "INSERT INTO identity_users(id,email) VALUES('other','UPPER@example.com')")
 execOK(t, db, "INSERT INTO identity_workspaces(id,name) VALUES('w','workspace')")
 execOK(t, db, "INSERT INTO identity_memberships(workspace_id,user_id,role) VALUES('w','u','owner')")
 execOK(t, db, "INSERT INTO identity_groups(id,workspace_id,name) VALUES('g','w','group')")
 execOK(t, db, "INSERT INTO identity_group_members(workspace_id,group_id,user_id) VALUES('w','g','u')")
 execReject(t, db, "INSERT INTO identity_group_members(workspace_id,group_id,user_id) VALUES('other','g','u')")
 execOK(t, db, "INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES('s','task','prod')")
 execReject(t, db, "INSERT INTO identity_service_credentials(kid,service_account_id,public_key,secret_reference,not_before,expires_at) VALUES('k','s',?,'x','2026-01-01','2027-01-01')", []byte("short"))
 execReject(t, db, "INSERT INTO identity_delegations(id,grantor_user_id,grantee_kind,grantee_id,grantee_service_id,resource_ids,actions,expires_at,created_by,consent_method) VALUES('d','u','service','s','s','[]','[\\\"read\\\"]','2099-01-01','u','interactive_session')")
}

func TestCoreAccessSQLiteInvariants(t *testing.T) {
 db := openCore(t)
 execOK(t, db, "INSERT INTO identity_workspaces(id,name) VALUES('w','workspace')")
 execOK(t, db, "INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES('s','task','prod')")
 digest := strings.Repeat("a", 64)
 actions := `["share","create","delete","access.grants.manage"]`
 execReject(t, db, "INSERT INTO access_resource_types(type,provider_service,contract_digest,actions,share_action,create_action,delete_action,allow_inheritance) VALUES('task','s',?,'[]','share','create','delete',1)", digest)
 execOK(t, db, "INSERT INTO access_resource_types(type,provider_service,contract_digest,actions,share_action,create_action,delete_action,allow_inheritance) VALUES('task','s',? ,?,'share','create','delete',1)", digest, actions)
 execOK(t, db, "INSERT INTO access_resources(id,type,provider_service,owner_kind,owner_id,workspace_id,inherit_acl,state,policy_revision) VALUES('r','task','s','workspace','w','w',1,'reserved',1)")
 childSQL := "INSERT INTO access_resources(id,type,provider_service,owner_kind,owner_id,workspace_id,acl_parent_id,inherit_acl,state,policy_revision) VALUES('child','task','s','workspace','w','w','r',1,'active',1)"
 execReject(t, db, childSQL)
 execOK(t, db, "UPDATE access_resources SET state='active' WHERE id='r'")
 execOK(t, db, childSQL)
 execReject(t, db, "UPDATE access_resources SET owner_id='other' WHERE id='child'")
 execReject(t, db, "UPDATE access_resources SET state='reserved' WHERE id='r'")
 execReject(t, db, "UPDATE access_resources SET acl_parent_id='child' WHERE id='r'")
 execOK(t, db, "INSERT INTO access_policy_audit(actor,caller,operation,policy_revision,change_kind,change) VALUES('operator','s','test',1,'create','{}')")
 execReject(t, db, "UPDATE access_policy_audit SET actor='attacker' WHERE policy_revision=1")
 execReject(t, db, "DELETE FROM access_policy_audit WHERE policy_revision=1")
}

func TestCoreFabricAndRuntimeSQLiteConstraints(t *testing.T) {
 db := openCore(t)
 execOK(t, db, "INSERT INTO fabric_definitions(name,publisher) VALUES('task','team')")
 digest := strings.Repeat("b", 64)
 sig := make([]byte, 64)
 execOK(t, db, "INSERT INTO fabric_contracts(digest,service_name,api_major,artifact,installation,signature) VALUES(?,'task',1,'{}','{}',?)", digest, sig)
 execReject(t, db, "UPDATE fabric_contracts SET artifact='{} ' WHERE digest=?", digest)
 execOK(t, db, "UPDATE fabric_contracts SET revoked_at='2026-01-01' WHERE digest=?", digest)
 execReject(t, db, "UPDATE fabric_contracts SET revoked_at=NULL WHERE digest=?", digest)
 execReject(t, db, "DELETE FROM fabric_contracts WHERE digest=?", digest)
 execReject(t, db, "INSERT INTO runtime_desired_deployments(id,service_name,spec,replicas) VALUES('d','task','not-json',1)")
 execOK(t, db, "INSERT INTO runtime_desired_deployments(id,service_name,spec,replicas) VALUES('d','task','{}',1)")
 execReject(t, db, "UPDATE runtime_desired_deployments SET replicas=-1 WHERE id='d'")
}
