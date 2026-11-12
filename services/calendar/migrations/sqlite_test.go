package migrations

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/database"
)

func TestOccurrenceUpgradeBackfillAndReplay(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "calendar.sqlite")
	db, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Migrate(ctx, db, SQLite()[:1]); err != nil {
		t.Fatal(err)
	}
	if err = db.Exec("INSERT INTO roots(acl_root_id,workspace_id,owner_id,state,name,timezone,revision) VALUES('root','workspace','','active','Calendar','UTC',1)").Error; err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	for _, id := range []string{"active", "deleted"} {
		var deleted any
		if id == "deleted" {
			deleted = now
		}
		if err = db.Exec("INSERT INTO calendar_events(id,workspace_id,acl_root_id,title,description,timezone,all_day,start,end,start_at,end_at,busy,revision,created_at,updated_at,deleted_at) VALUES(?,'workspace','root','Original','','UTC',0,?,?,?,?,1,1,?,?,?)", id, now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339), now, now.Add(time.Hour), now, now, deleted).Error; err != nil {
			t.Fatal(err)
		}
	}
	database.Close(db)
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
	var identities int64
	if err = db.Table("calendar_events").Where("uid=id || '@arc' AND i_cal_raw='' ").Count(&identities).Error; err != nil || identities != 2 {
		t.Fatal("UID backfill lost active/tombstone identities", identities, err)
	}
	var count int64
	if err = db.Table("event_occurrences").Count(&count).Error; err != nil || count != 1 {
		t.Fatal("upgrade lost/duplicated events", count, err)
	}
	var record struct {
		EventID      string
		RecurrenceID string
	}
	if err = db.Table("event_occurrences").Take(&record).Error; err != nil || record.EventID != "active" || record.RecurrenceID != now.Format(time.RFC3339) {
		t.Fatal("bad backfill", record, err)
	}
	if err = db.Exec("INSERT INTO event_occurrences(event_id,workspace_id,acl_root_id,recurrence_id,start,end,start_at,end_at,busy) VALUES('active','other','root','foreign','a','b',?,?,1)", now, now.Add(time.Hour)).Error; err == nil {
		t.Fatal("cross-scope occurrence binding accepted")
	}
}
