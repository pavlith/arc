package migrations

import (
	"context"
	"github.com/pavlith/arc/sdk/database"
	"path/filepath"
	"testing"
)

func TestChannelsUpgradePreservesLegacyStateAndForeignKeys(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "notify.sqlite")
	db, e := database.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer database.Close(db)
	old := SQLite()[:3]
	if e = database.Migrate(ctx, db, old); e != nil {
		t.Fatal(e)
	}
	for _, q := range []string{`INSERT INTO notifications(id,recipient_user_id,event_id,kind,task_id,revision)VALUES('n','u','e','task.created','target',4)`, `INSERT INTO delivery_intents(notification_id,recipient_user_id,channel,dedup_key,attempts,delivered_at)VALUES('n','u','fake','stable',3,CURRENT_TIMESTAMP)`} {
		if e = db.Exec(q).Error; e != nil {
			t.Fatal(e)
		}
	}
	for range 2 {
		if e = database.Migrate(ctx, db, SQLite()); e != nil {
			t.Fatal(e)
		}
	}
	var key, target string
	var attempts, revision int
	var delivered bool
	if e = db.Raw(`SELECT d.dedup_key,d.attempts,d.delivered_at IS NOT NULL,n.resource_id,n.revision FROM delivery_intents d JOIN notifications n ON n.id=d.notification_id`).Row().Scan(&key, &attempts, &delivered, &target, &revision); e != nil || key != "stable" || attempts != 3 || !delivered || target != "target" || revision != 4 {
		t.Fatal(key, attempts, delivered, target, revision, e)
	}
	if e = db.Exec(`INSERT INTO delivery_intents(notification_id,recipient_user_id,channel,dedup_key)VALUES('missing','u','webhook','bad')`).Error; e == nil {
		t.Fatal("foreign key disabled")
	}
}
