package migrations

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/database"
)

func TestVCardUpgradePreservesContactsAndReplay(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "contacts.sqlite")
	db, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Migrate(ctx, db, SQLite()[:1]); err != nil {
		t.Fatal(err)
	}
	if err = db.Exec("INSERT INTO roots(acl_root_id,workspace_id,owner_id,state,name,revision) VALUES('root','workspace','','active','Book',1)").Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, id := range []string{"active", "deleted"} {
		var deleted any
		if id == "deleted" {
			deleted = now
		}
		if err = db.Exec(`INSERT INTO contacts(id,uid,workspace_id,acl_root_id,display_name,organization,role,fields,search_text,revision,created_at,updated_at,deleted_at) VALUES(?,?,'workspace','root','Legacy','','','{"display_name":"Legacy"}','legacy',7,?,?,?)`, id, id+"@arc", now, now, deleted).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err = database.Close(db); err != nil {
		t.Fatal(err)
	}
	db, err = database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	for i := 0; i < 2; i++ {
		if err = database.Migrate(ctx, db, SQLite()); err != nil {
			t.Fatal(err)
		}
	}
	var n int64
	if err = db.Table("contacts").Where("uid=id || '@arc' AND revision=7 AND v_card_raw='' AND fields=?", `{"display_name":"Legacy"}`).Count(&n).Error; err != nil || n != 2 {
		t.Fatal("upgrade modified contacts/tombstones", n, err)
	}
	if err = db.Table("contacts").Where("deleted_at IS NOT NULL").Count(&n).Error; err != nil || n != 1 {
		t.Fatal("tombstone lost", n, err)
	}
}
