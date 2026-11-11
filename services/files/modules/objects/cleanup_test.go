package objects

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/migrations"
	"github.com/pavlith/arc/services/files/models"
	"github.com/pavlith/arc/services/files/storage"
	"gorm.io/gorm"
)

func TestDurableCleanupAndOrphanProtection(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "files.sqlite"))
	if err != nil { t.Fatal(err) }
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil { t.Fatal(err) }
	if err := db.Exec(
		"INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'active')",
		root, workspace,
	).Error; err != nil { t.Fatal(err) }
	dir := filepath.Join(t.TempDir(), "private")
	bytes, err := storage.OpenLocal(dir)
	if err != nil { t.Fatal(err) }
	defer bytes.Close()
	compiled, err := contract.Compile(filesv1.Artifact())
	if err != nil { t.Fatal(err) }
	s := &Module{DB:db, Contract:compiled, Storage:bytes}
	var upload filesv1.Upload
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		upload, err = s.initiate(
			actorContext(t, filesv1.UploadInitiate.ID, "alice", "session-a"),
			tx, filesv1.UploadInitiateRequest{
				Scope: filesv1.Scope{WorkspaceID: workspace, RootID: root},
				Filename: "live.bin", MIME: "application/octet-stream", ExpectedSize: 5,
			},
		)
		return err
	})
	if err != nil { t.Fatal(err) }
	orphan := "00000000-0000-4000-8000-00000000f123"
	if err := bytes.Prepare(ctx, orphan); err != nil { t.Fatal(err) }
	old := time.Now().Add(-48*time.Hour)
	for _, id := range []string{upload.ID, orphan} {
		name := filepath.Join(dir, "pending", id+".part")
		if err := os.Chtimes(name, old, old); err != nil { t.Fatal(err) }
	}
	n, err := s.PruneOrphanPending(ctx)
	if err != nil || n != 1 { t.Fatalf("orphan prune count=%d err=%v", n, err) }
	if _, err := bytes.Offset(ctx, orphan); !errors.Is(err, storage.ErrMissing) {
		t.Fatalf("unreferenced bytes retained: %v", err)
	}
	if _, err := bytes.Offset(ctx, upload.ID); err != nil {
		t.Fatalf("live upload deleted solely because of old mtime: %v", err)
	}
	if err := db.Model(&models.Upload{}).Where("id=?",upload.ID).
		Update("expires_at", time.Now().Add(-time.Hour)).Error; err != nil {t.Fatal(err)}
	n, err = s.Cleanup(ctx, 100)
	if err != nil || n != 1 {t.Fatalf("expired cleanup count=%d err=%v",n,err)}
	if _, err := bytes.Offset(ctx, upload.ID); !errors.Is(err, storage.ErrMissing) {
		t.Fatalf("expired bytes retained: %v",err)
	}
	var saved models.Upload
	if err := db.Where("id=?",upload.ID).Take(&saved).Error; err != nil {t.Fatal(err)}
	if saved.State != "expired" || saved.CleanedAt == nil {
		t.Fatalf("expiration not durably recorded: state=%q cleanup=%v",saved.State,saved.CleanedAt)
	}
	n, err = s.Cleanup(ctx, 100)
	if err != nil || n != 0 {t.Fatalf("cleanup replay count=%d err=%v",n,err)}
}
