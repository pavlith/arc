package migrations

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/database"
)

func TestBaselineRequiresResourceKind(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "notify.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	for range 2 {
		if err := database.Migrate(ctx, db, SQLite()); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.Raw("SELECT count(*) FROM pragma_table_info('notifications') WHERE name='task_id'").Row().Scan(&count); err != nil || count != 0 {
		t.Fatalf("obsolete task_id: count=%d err=%v", count, err)
	}
	if err := db.Exec("INSERT INTO subscriptions(workspace_id,acl_root_id,recipient_user_id) VALUES('w','r','u')").Error; err == nil {
		t.Fatal("implicit subscription resource kind accepted")
	}
	if err := db.Exec("INSERT INTO notifications(id,recipient_user_id,event_id,kind) VALUES('n','u','e','task.created')").Error; err == nil {
		t.Fatal("implicit notification resource kind accepted")
	}
	if err := db.Exec("INSERT INTO notifications(id,recipient_user_id,event_id,kind,resource_kind,resource_id) VALUES('n','u','e','task.created','task','t')").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO delivery_intents(notification_id,recipient_user_id,channel,dedup_key) VALUES('missing','u','webhook','bad')").Error; err == nil {
		t.Fatal("orphaned delivery intent was accepted")
	}
}
