package inbox

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/notify/migrations"
	pagesv1 "github.com/pavlith/arc/services/pages/api/v1"
	"gorm.io/gorm"
)

func TestCatalogRecipientKindDedupAndAtomicRollback(t *testing.T) {
	ctx := context.Background()
	db, e := database.Open(ctx, filepath.Join(t.TempDir(), "notify.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer database.Close(db)
	if e = database.Migrate(ctx, db, migrations.SQLite()); e != nil {
		t.Fatal(e)
	}
	root, target := newID(), newID()
	users := map[string]string{"page": newID(), "file": newID()}
	for _, kind := range []string{"page", "file"} {
		if e = db.Exec(`INSERT INTO subscriptions(workspace_id,acl_root_id,recipient_user_id,resource_kind)VALUES('',?,?,?)`, root, users[kind], kind).Error; e != nil {
			t.Fatal(e)
		}
	}
	store := events.Store{DB: db}
	s := &Service{GormDB: db} // Disabled external delivery.
	type source struct {
		artifact              contract.Artifact
		subject, name, action string
		payload               any
	}
	for _, v := range []source{
		{pagesv1.Artifact(), pagesv1.ChangedSubject, pagesv1.ChangedName, "created", pagesv1.Changed{Scope: pagesv1.Scope{RootID: root}, EntityID: target, Revision: 1, Action: "created"}},
		{filesv1.Artifact(), filesv1.CatalogChangedSubject, filesv1.CatalogChangedName, "uploaded", filesv1.CatalogChanged{Scope: filesv1.Scope{RootID: root}, EntityKind: "file", EntityID: target, Revision: 1, Action: "uploaded"}},
	} {
		c, e := contract.Compile(v.artifact)
		if e != nil {
			t.Fatal(e)
		}
		payload, _ := json.Marshal(v.payload)
		ev := events.Envelope{ID: newID(), Type: v.name, Version: 1, AggregateID: target, OccurredAt: time.Now().UTC(), Payload: payload}
		raw, _ := json.Marshal(ev)
		for range 2 {
			if e = store.Consume(ctx, "test-"+v.action, v.subject, c, raw, s.Effect); e != nil {
				t.Fatal(e)
			}
		}
	}
	var notifications, intents, hints int64
	db.Table("notifications").Count(&notifications)
	db.Table("delivery_intents").Count(&intents)
	db.Table("outbox").Count(&hints)
	if notifications != 2 || intents != 0 || hints != 2 {
		t.Fatal(notifications, intents, hints)
	}
	var mismatch int64
	db.Raw(`SELECT COUNT(*) FROM notifications WHERE (resource_kind='page' AND recipient_user_id<>?) OR (resource_kind='file' AND recipient_user_id<>?)`, users["page"], users["file"]).Row().Scan(&mismatch)
	if mismatch != 0 {
		t.Fatal("cross-kind recipient")
	}
	// A failed effect rolls back the inbox marker, notification and realtime hint.
	c, _ := contract.Compile(pagesv1.Artifact())
	payload, _ := json.Marshal(pagesv1.Changed{Scope: pagesv1.Scope{RootID: root}, EntityID: target, Revision: 2, Action: "updated"})
	ev := events.Envelope{ID: newID(), Type: pagesv1.ChangedName, Version: 1, AggregateID: target, OccurredAt: time.Now().UTC(), Payload: payload}
	raw, _ := json.Marshal(ev)
	db.Exec(`CREATE TRIGGER reject_hint BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END`)
	if e = store.Consume(ctx, "rollback", pagesv1.ChangedSubject, c, raw, s.Effect); e == nil {
		t.Fatal("partial failure accepted")
	}
	var markers int64
	db.Table("inbox").Where("consumer='rollback'").Count(&markers)
	db.Table("notifications").Count(&notifications)
	if markers != 0 || notifications != 2 {
		t.Fatal("partial effect committed")
	}
	db.Exec(`DROP TRIGGER reject_hint`)
	if e = store.Consume(ctx, "rollback", pagesv1.ChangedSubject, c, raw, s.Effect); e != nil {
		t.Fatal(e)
	}
	// Templates and folder metadata never create notifications.
	for _, action := range []string{"moved", "archived", "template.created"} {
		q := pagesv1.Changed{Scope: pagesv1.Scope{RootID: root}, EntityID: target, Revision: 3, Action: action}
		p, _ := json.Marshal(q)
		if e = db.Transaction(func(tx *gorm.DB) error {
			return s.Effect(ctx, tx, events.Envelope{Type: pagesv1.ChangedName, AggregateID: target, Payload: p})
		}); e != nil {
			t.Fatal(e)
		}
	}
	db.Table("notifications").Count(&notifications)
	if notifications != 3 {
		t.Fatal("ignored actions created notifications")
	}
}
