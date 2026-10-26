package events_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	notifydb "github.com/pavlith/arc/services/notify/migrations"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"gorm.io/gorm"
)

func TestGormInboxConcurrentReplayConflictAndRollback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "notify.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, notifydb.SQLite()); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE effects (event_id TEXT PRIMARY KEY)").Error; err != nil {
		t.Fatal(err)
	}
	m, err := contract.Compile(taskv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(taskv1.CreatedEvent{
		Scope: taskv1.Scope{
			WorkspaceID: "00000000-0000-4000-8000-000000000001",
			RootID:      "00000000-0000-4000-8000-000000000002",
		},
		TaskID: "00000000-0000-4000-8000-000000000003",
	})
	ev := events.Envelope{
		ID:   "00000000-0000-4000-8000-000000000004",
		Type: taskv1.CreatedName, Version: 1,
		AggregateID: "00000000-0000-4000-8000-000000000003",
		OccurredAt:  time.Now().UTC(), Payload: payload,
	}
	raw, _ := json.Marshal(ev)
	store := events.Store{DB: db}
	var runs atomic.Int32
	effect := func(ctx context.Context, tx *gorm.DB, ev events.Envelope) error {
		runs.Add(1)
		return tx.Exec("INSERT INTO effects(event_id) VALUES(?)", ev.ID).Error
	}
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.Consume(ctx, "test-durable", taskv1.CreatedSubject, m, raw, effect)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent replay failed: %v", err)
		}
	}
	if runs.Load() != 1 {
		t.Fatalf("expected one effect, got %d", runs.Load())
	}
	var count int64
	if err := db.Table("effects").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("effects=%d, err=%v", count, err)
	}
	ev.Traceparent = "00-different"
	conflicting, _ := json.Marshal(ev)
	if err := store.Consume(ctx, "test-durable", taskv1.CreatedSubject, m, conflicting, effect); err == nil {
		t.Fatal("conflicting replay accepted")
	}
	// New event fails in its handler, then must be retryable with no inbox residue.
	ev.ID = "00000000-0000-4000-8000-000000000005"
	rollbackRaw, _ := json.Marshal(ev)
	if err := store.Consume(ctx, "test-durable", taskv1.CreatedSubject, m, rollbackRaw,
		func(ctx context.Context, tx *gorm.DB, ev events.Envelope) error {
			if err := tx.Exec("INSERT INTO effects(event_id) VALUES(?)", ev.ID).Error; err != nil {
				return err
			}
			return errors.New("abort")
		}); err == nil {
		t.Fatal("failed handler accepted")
	}
	if err := store.Consume(ctx, "test-durable", taskv1.CreatedSubject, m, rollbackRaw, effect); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
	if err := db.Table("effects").Count(&count).Error; err != nil || count != 2 {
		t.Fatalf("retry effect count %d (%v)", count, err)
	}
}
