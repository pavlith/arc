package migrations

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/database"
)

func TestAccountProvisioningUpgradeAndReplay(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mail.sqlite")
	db, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Migrate(ctx, db, SQLite()[:1]); err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO accounts(acl_root_id,workspace_id,owner_id,lifecycle,name,host,port,login,email,state,revision,generation) VALUES('existing','','owner','active','Existing','imap.example.test',993,'user','user@example.test','paused',3,2)`).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO outbox(event_id,subject,envelope,published_at) VALUES('pending','evt.mail.accounts.changed.v1','original-pending',NULL),('published','evt.mail.accounts.changed.v1','original-published',CURRENT_TIMESTAMP)`).Error; err != nil {
		t.Fatal(err)
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
	var count int64
	if err = db.Raw("SELECT count(*) FROM accounts WHERE acl_root_id='existing' AND state='paused' AND revision=3 AND generation=2").Scan(&count).Error; err != nil || count != 1 {
		t.Fatal("upgrade changed account", count, err)
	}

	if err = db.Raw("SELECT count(*) FROM outbox WHERE (event_id='pending' AND envelope='original-pending' AND published_at IS NULL) OR (event_id='published' AND envelope='original-published' AND published_at IS NOT NULL)").Scan(&count).Error; err != nil || count != 2 {
		t.Fatal("outbox migration lost delivery state", count, err)
	}
	if err = db.Exec(`INSERT INTO outbox(event_id,subject,envelope) VALUES('messages','evt.mail.messages.changed.v1','message-hint')`).Error; err != nil {
		t.Fatal("new message topic unavailable", err)
	}
	if err = db.Exec("INSERT INTO account_provisions(actor,idempotency_key,request_hash,acl_root_id) VALUES('user:owner','key',zeroblob(32),'existing')").Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Exec("INSERT INTO account_provisions(actor,idempotency_key,request_hash,acl_root_id) VALUES('user:owner','key',zeroblob(32),'existing')").Error; err == nil {
		t.Fatal("duplicate provisioning identity accepted")
	}
}
