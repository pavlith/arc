package migrations

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/database"
)

func TestUnifiedOrderBackfillsExistingOccurrences(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mail.sqlite")
	db, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Migrate(ctx, db, SQLite()[:3]); err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO accounts(acl_root_id,workspace_id,owner_id,lifecycle,name,host,port,login,email,state,revision,generation) VALUES('root','','owner','active','Existing','imap.test',993,'user','user@test','enabled',2,1)`).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO mail_folders(id,acl_root_id,generation,wire_name,revision,uid_validity,uid_next,remote_count,next_before_uid,low_uid,high_uid,status,updated_at) VALUES('folder','root',1,'SU5CT1g',7,77,103,1,101,101,102,'ok',CURRENT_TIMESTAMP)`).Error; err != nil {
		t.Fatal(err)
	}
	summary := []byte(`{"uid":102,"internal_date":"2026-11-13T13:00:00+03:00","subject":"Legacy"}`)
	for _, row := range []struct {
		id       string
		validity int
		present  int
	}{{"active", 77, 1}, {"retired", 76, 0}} {
		if err = db.Exec("INSERT INTO mail_messages(id,folder_id,uid_validity,uid,present,summary) VALUES(?,'folder',?,102,?,?)", row.id, row.validity, row.present, summary).Error; err != nil {
			t.Fatal(err)
		}
	}
	_ = database.Close(db)
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
	var rows []struct {
		ID           string
		UIDValidity  int `gorm:"column:uid_validity"`
		Present      int
		Summary      []byte
		InternalUnix int64
	}
	if err = db.Table("mail_messages").Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].ID != "active" || rows[0].Present != 1 || rows[0].UIDValidity != 77 || rows[1].ID != "retired" || rows[1].Present != 0 || rows[1].UIDValidity != 76 {
		t.Fatal("migration changed source identities", rows)
	}
	want := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC).UnixMicro()
	for _, row := range rows {
		if row.InternalUnix != want || !bytes.Equal(row.Summary, summary) {
			t.Fatal("chronology backfill changed metadata", row)
		}
	}
	var progress struct {
		Revision      int64
		NextBeforeUID int `gorm:"column:next_before_uid"`
	}
	if err = db.Table("mail_folders").First(&progress).Error; err != nil || progress.Revision != 7 || progress.NextBeforeUID != 101 {
		t.Fatal("migration changed progress", progress, err)
	}
}
