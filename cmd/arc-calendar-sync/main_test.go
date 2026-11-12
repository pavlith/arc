package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/services/calendar/migrations"
	"github.com/pavlith/arc/services/calendar/models"
)

func TestOwnerSyncBootstrapUpgradeReplayAndReset(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "calendar.sqlite")
	db, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Migrate(ctx, db, migrations.SQLite()[:3]); err != nil {
		t.Fatal(err)
	}
	workspace := "40000000-0000-4000-8000-000000000001"
	root := "40000000-0000-4000-8000-000000000002"
	if err = db.Exec("INSERT INTO roots(acl_root_id,workspace_id,owner_id,state,name,timezone,revision) VALUES(?,?,'','active','Calendar','UTC',1)", root, workspace).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	rows := []models.Event{
		{ID: "40000000-0000-4000-8000-000000000003", UID: "active@fixture", WorkspaceID: workspace, RootID: root, Title: "Active", Timezone: "UTC", Start: now.Format(time.RFC3339), End: now.Add(time.Hour).Format(time.RFC3339), StartAt: now, EndAt: now.Add(time.Hour), Revision: 1, CreatedAt: now, UpdatedAt: now},
		{ID: "40000000-0000-4000-8000-000000000004", UID: "deleted@fixture", WorkspaceID: workspace, RootID: root, Title: "Deleted", Timezone: "UTC", Start: now.Format(time.RFC3339), End: now.Add(time.Hour).Format(time.RFC3339), StartAt: now, EndAt: now.Add(time.Hour), Revision: 2, CreatedAt: now, UpdatedAt: now, DeletedAt: &now},
	}
	if err = db.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if err = database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	database.Close(db)
	if n, err := run(ctx, path, false); err != nil || n != 1 {
		t.Fatal("owner bootstrap", n, err)
	}
	db, err = database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	var first models.Root
	if err = db.Where("acl_root_id=?", root).Take(&first).Error; err != nil {
		t.Fatal(err)
	}
	if !first.SyncReady || len(first.SyncEpoch) != 32 || first.SyncRevision != 0 || first.SyncFloor != 0 {
		t.Fatal(first)
	}
	var entries []struct{ Entry string }
	if err = db.Table("sync_items").Order("event_id").Find(&entries).Error; err != nil || len(entries) != 2 {
		t.Fatal("missing baseline", entries, err)
	}
	var active, deleted int64
	db.Table("sync_items").Where("json_extract(entry,'$.state')='active' AND json_extract(entry,'$.etag') IS NOT NULL").Count(&active)
	db.Table("sync_items").Where("json_extract(entry,'$.state')='deleted'").Count(&deleted)
	if active != 1 || deleted != 1 {
		t.Fatal("baseline state mismatch", active, deleted)
	}
	if n, err := run(ctx, path, false); err != nil || n != 0 {
		t.Fatal("bootstrap replay", n, err)
	}
	var repeated models.Root
	db.Where("acl_root_id=?", root).Take(&repeated)
	if repeated.SyncEpoch != first.SyncEpoch {
		t.Fatal("normal bootstrap rotated existing tokens")
	}
	if n, err := run(ctx, path, true); err != nil || n != 1 {
		t.Fatal("explicit reset", n, err)
	}
	var reset models.Root
	db.Where("acl_root_id=?", root).Take(&reset)
	if reset.SyncEpoch == first.SyncEpoch || reset.SyncRevision != 0 {
		t.Fatal("reset retained generation")
	}
	var count int64
	db.Table("audit").Where("operation='calendar.sync.reset' AND actor='operator:offline'").Count(&count)
	if count != 2 {
		t.Fatal("maintenance audit missing", count)
	}
	db.Table("sync_changes").Count(&count)
	if count != 0 {
		t.Fatal("bootstrap created fake incremental history")
	}
}
func TestSyncBootstrapRejectsMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sqlite")
	if _, err := run(context.Background(), path, false); err == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("bootstrap created an empty database", err)
	}
}
