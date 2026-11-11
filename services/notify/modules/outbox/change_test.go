package outbox

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/database"
	notifymigrations "github.com/pavlith/arc/services/notify/migrations"
	"gorm.io/gorm"
)

func TestNotifyOutboxJoinsTransaction(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "notify.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, notifymigrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	const (
		user         = "00000000-0000-4000-8000-000000000001"
		notification = "00000000-0000-4000-8000-000000000002"
	)
	abort := errors.New("rollback")
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := Change(ctx, tx, user, notification, 1); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal("rollback failed", err)
	}
	var n int64
	if err := db.Table("outbox").Count(&n).Error; err != nil || n != 0 {
		t.Fatal("outbox escaped rollback", n, err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		return Change(ctx, tx, user, notification, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Table("outbox").Count(&n).Error; err != nil || n != 1 {
		t.Fatal("outbox not committed", n, err)
	}
}
