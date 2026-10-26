package services_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/database"
	notifymigrations "github.com/pavlith/arc/services/notify/migrations"
	taskmigrations "github.com/pavlith/arc/services/task/migrations"
	"gorm.io/gorm"
)

func serviceDB(t *testing.T, name string) *gorm.DB {
	t.Helper()
	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), name+".sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(db) })
	return db
}

func TestTaskSQLiteOwnerConstraints(t *testing.T) {
	db := serviceDB(t, "task")
	if err := database.Migrate(context.Background(), db, taskmigrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO roots(acl_root_id, workspace_id, state) VALUES('r','w','active')").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO tasks(id,workspace_id,acl_root_id,title,status,created_by,created_at,updated_at) VALUES('t','w','r','ok','open','u',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO tasks(id,workspace_id,acl_root_id,title,status,created_by,created_at,updated_at) VALUES('bad','other','r','ok','open','u',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").Error; err == nil {
		t.Fatal("cross-workspace task accepted")
	}
	if err := db.Exec("INSERT INTO tasks(id,workspace_id,acl_root_id,title,status,created_by,created_at,updated_at) VALUES('blank','w','r','   ','open','u',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").Error; err == nil {
		t.Fatal("blank task accepted")
	}
}

func TestNotifySQLiteOwnerConstraints(t *testing.T) {
	db := serviceDB(t, "notify")
	if err := database.Migrate(context.Background(), db, notifymigrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO notifications(id,recipient_user_id,event_id,kind) VALUES('n','u','e','task.created')").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO notifications(id,recipient_user_id,event_id,kind) VALUES('n2','u','e','task.created')").Error; err == nil {
		t.Fatal("duplicate notification accepted")
	}
	if err := db.Exec("INSERT INTO delivery_intents(notification_id,recipient_user_id,channel,dedup_key) VALUES('missing','u','fake','key')").Error; err == nil {
		t.Fatal("missing notification reference accepted")
	}
	if err := db.Exec("INSERT INTO subscriptions(workspace_id,acl_root_id,recipient_user_id,active) VALUES('w','r','u',2)").Error; err == nil {
		t.Fatal("invalid operator subscription accepted")
	}
}
