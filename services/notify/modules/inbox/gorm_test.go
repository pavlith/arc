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
	"github.com/pavlith/arc/services/notify/modules/delivery"
	notifymigrations "github.com/pavlith/arc/services/notify/migrations"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
)

func TestSQLiteInboxAndDeliveryStableKey(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "notify.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, notifymigrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	workspace := "00000000-0000-4000-8000-000000000001"
	root := "00000000-0000-4000-8000-000000000002"
	user := "00000000-0000-4000-8000-000000000003"
	taskID := "00000000-0000-4000-8000-000000000004"
	eventID := "00000000-0000-4000-8000-000000000005"
	if err := db.Exec(
		"INSERT INTO subscriptions(workspace_id,acl_root_id,recipient_user_id,active) VALUES(?,?,?,1)",
		workspace, root, user).Error; err != nil {
		t.Fatal(err)
	}
	compiled, err := contract.Compile(taskv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(taskv1.CreatedEvent{
		Scope: taskv1.Scope{WorkspaceID: workspace, RootID: root}, TaskID: taskID,
	})
	raw, _ := json.Marshal(events.Envelope{
		ID: eventID, Type: taskv1.CreatedName, Version: 1,
		AggregateID: taskID, OccurredAt: time.Now().UTC(), Payload: payload,
	})
	inbox := (&Service{GormDB: db}).EffectGORM
	store := events.GormStore{DB: db}
	for i := 0; i < 2; i++ {
		if err := store.ConsumeGORM(ctx, Durable, taskv1.CreatedSubject, compiled, raw, inbox); err != nil {
			t.Fatal(err)
		}
	}
	var count int64
	if err := db.Table("notifications").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("notification dedup failed: %d (%v)", count, err)
	}
	provider := &delivery.FakeProvider{Fail: true}
	sender := &delivery.Service{GormDB: db}
	if _, err := sender.DeliverGORM(ctx, provider); err == nil {
		t.Fatal("uncertain provider timeout not reported")
	}
	if n, err := sender.DeliverGORM(ctx, provider); err != nil || n != 1 {
		t.Fatalf("retry failed: count=%d error=%v", n, err)
	}
	if len(provider.Calls) != 2 || provider.Calls[0] != provider.Calls[1] {
		t.Fatalf("provider key changed across retry: %v", provider.Calls)
	}
	var attempts int
	if err := db.Raw("SELECT attempts FROM delivery_intents").Row().Scan(&attempts); err != nil || attempts != 2 {
		t.Fatalf("attempts=%d error=%v", attempts, err)
	}
}
