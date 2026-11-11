package migrations_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/services/files/migrations"
)

func TestPersonalRootUpgradeRetainsWorkspaceData(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "files.sqlite")
	db, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { database.Close(db) }()
	all := migrations.SQLite()
	if err := database.Migrate(ctx, db, all[:2]); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO roots(acl_root_id,workspace_id,state) VALUES('root','workspace','active')").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO folders(id,workspace_id,acl_root_id,name,revision,created_at,updated_at) VALUES('folder','workspace','root','Documents',7,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Close(db); err != nil {
		t.Fatal(err)
	}
	db, err = database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, db, all); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, db, all); err != nil {
		t.Fatal(err)
	}
	var retained int
	if err := db.Raw("SELECT count(*) FROM folders f JOIN roots r ON r.acl_root_id=f.acl_root_id AND r.workspace_id=f.workspace_id WHERE r.owner_id='' AND f.name='Documents' AND f.revision=7 AND r.state='active'").Row().Scan(&retained); err != nil || retained != 1 {
		t.Fatalf("workspace data changed: count=%d err=%v", retained, err)
	}
	if err := db.Exec("INSERT INTO roots(acl_root_id,workspace_id,owner_id,state) VALUES('personal','','user','active')").Error; err != nil {
		t.Fatal(err)
	}
	// A valid personal root cannot make an existing workspace folder cross scope.
	if err := db.Exec("UPDATE folders SET acl_root_id='personal' WHERE id='folder'").Error; err == nil {
		t.Fatal("cross-scope folder FK weakened by upgrade")
	}
}
