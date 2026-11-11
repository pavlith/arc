package objects

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/migrations"
	"github.com/pavlith/arc/services/files/models"
	"github.com/pavlith/arc/services/files/storage"
	"gorm.io/gorm"
)

// Tests use verified fixture claims; real Core proof/session coverage is separate.
func catalogCommand[Q any](t *testing.T, s *Module, op, key string, q Q,
	handler func(context.Context, *gorm.DB, Q) (filesv1.File, error)) (filesv1.File, error) {
	t.Helper()
	auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
		return security.Claims{Subject: "user:alice", SessionID: "session-a", WorkspaceID: workspace, Operation: op}, nil
	})
	raw, err := json.Marshal(map[string]any{"operation": op, "proof": security.Proof{Kid: "fixture"}, "auth": "fixture", "payload": q, "idempotency_key": key})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := auth(context.Background(), "rpc.files.v1."+strings.TrimPrefix(op, "files."), raw)
	if err != nil {
		t.Fatal(err)
	}
	return events.Command(ctx, events.Store{DB: s.DB}, s.Contract, op, q, handler)
}

func TestFileCatalogMutationsReplayRollbackAndArchive(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "files.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bytes")
	store, err := storage.OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	compiled, err := contract.Compile(filesv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	s := &Module{DB: db, Storage: store, Contract: compiled, Authorize: func(context.Context, string, string) error { return nil }}
	for _, rid := range []string{root, otherRoot} {
		if err := db.Create(&models.Root{RootID: rid, WorkspaceID: workspace, State: "active"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	const folder = "00000000-0000-4000-8000-00000000c001"
	const foreign = "00000000-0000-4000-8000-00000000c002"
	const archived = "00000000-0000-4000-8000-00000000c003"
	now := time.Now().UTC()
	for _, f := range []models.Folder{
		{ID: folder, RootID: root, Name: "own"}, {ID: foreign, RootID: otherRoot, Name: "other"},
		{ID: archived, RootID: root, Name: "archived", ArchivedAt: &now},
	} {
		f.WorkspaceID, f.Revision, f.CreatedAt, f.UpdatedAt = workspace, 1, now, now
		if err := db.Create(&f).Error; err != nil {
			t.Fatal(err)
		}
	}
	const fileID = "00000000-0000-4000-8000-00000000c004"
	const uploadID = "00000000-0000-4000-8000-00000000c005"
	body := bytes.Repeat([]byte("x"), 512<<10)
	if err := store.Prepare(ctx, uploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(ctx, uploadID, 0, int64(len(body)), bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	obj, err := store.Promote(ctx, uploadID, fileID, int64(len(body)), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.File{ID: fileID, WorkspaceID: workspace, RootID: root, Filename: "before.bin",
		MIME: "application/octet-stream", Size: obj.Size, SHA256: obj.SHA256, BlobKey: obj.Key, Revision: 1, State: "ready", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatal(err)
	}
	ref := filesv1.FileRef{Scope: filesv1.Scope{WorkspaceID: workspace, RootID: root}, FileID: fileID}
	q := filesv1.FileRenameRequest{FileRef: ref, Filename: " after.bin ", Revision: 1}
	renamed, err := catalogCommand(t, s, filesv1.FileRename.ID, "rename-1", q, s.renameFile)
	if err != nil || renamed.Filename != "after.bin" || renamed.Revision != 2 {
		t.Fatalf("rename: %+v %v", renamed, err)
	}
	replay, err := catalogCommand(t, s, filesv1.FileRename.ID, "rename-1", q, s.renameFile)
	if err != nil || replay != renamed {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	q.Filename = "mismatch.bin"
	if _, err := catalogCommand(t, s, filesv1.FileRename.ID, "rename-1", q, s.renameFile); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("key mismatch: %v", err)
	}
	if _, err := catalogCommand(t, s, filesv1.FileRename.ID, "stale", q, s.renameFile); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("stale revision: %v", err)
	}
	q.Revision = 2
	for _, name := range []string{"../unsafe", ".", "\x00name"} {
		q.Filename = name
		if _, err := catalogCommand(t, s, filesv1.FileRename.ID, "invalid", q, s.renameFile); rpc.ErrorCode(err) != rpc.CodeValidation {
			t.Fatalf("unsafe filename %q: %v", name, err)
		}
	}
	// Failure after the catalog UPDATE must roll back audit and replay too.
	if err := db.Exec("CREATE TRIGGER reject_file_event BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	q.Filename = "rollback.bin"
	if _, err := catalogCommand(t, s, filesv1.FileRename.ID, "rollback", q, s.renameFile); err == nil {
		t.Fatal("outbox failure accepted")
	}
	if err := db.Exec("DROP TRIGGER reject_file_event").Error; err != nil {
		t.Fatal(err)
	}
	current, err := s.getFile(ctx, ref)
	if err != nil || current != renamed {
		t.Fatalf("failed transaction changed metadata: %+v %v", current, err)
	}
	var audit, outbox, replayCount int64
	if err := db.Table("audit").Count(&audit).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Table("outbox").Count(&outbox).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Table("command_results").Count(&replayCount).Error; err != nil {
		t.Fatal(err)
	}
	if audit != 1 || outbox != 1 || replayCount != 1 {
		t.Fatalf("rollback/replay effects: %d/%d/%d", audit, outbox, replayCount)
	}
	move := filesv1.FileMoveRequest{FileRef: ref, Revision: 2}
	for _, target := range []string{foreign, archived} {
		move.FolderID = target
		if _, err := catalogCommand(t, s, filesv1.FileMove.ID, "invalid-move", move, s.moveFile); rpc.ErrorCode(err) != rpc.CodeNotFound {
			t.Fatalf("forbidden target: %v", err)
		}
	}
	move.FolderID = folder
	moved, err := catalogCommand(t, s, filesv1.FileMove.ID, "move", move, s.moveFile)
	if err != nil || moved.FolderID != folder || moved.Revision != 3 {
		t.Fatalf("move: %+v %v", moved, err)
	}
	move.FolderID, move.Revision = "", 3
	moved, err = catalogCommand(t, s, filesv1.FileMove.ID, "move-root", move, s.moveFile)
	if err != nil || moved.FolderID != "" || moved.Revision != 4 || moved.ETag != renamed.ETag {
		t.Fatalf("move to root: %+v %v", moved, err)
	}
	rootList, err := s.listFiles(ctx, filesv1.FileListRequest{Scope: ref.Scope, Limit: 100})
	if err != nil || len(rootList.Files) != 1 || rootList.Files[0].FolderID != "" {
		t.Fatalf("root move not persisted: %+v %v", rootList, err)
	}
	cross := filesv1.FileArchiveRequest{FileRef: ref, Revision: 4}
	cross.RootID = otherRoot
	if _, err := catalogCommand(t, s, filesv1.FileArchive.ID, "cross-root", cross, s.archiveFile); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("cross-root archive: %v", err)
	}
	cross.RootID = root
	cross.WorkspaceID = "00000000-0000-4000-8000-00000000c006"
	if _, err := catalogCommand(t, s, filesv1.FileArchive.ID, "cross-workspace", cross, s.archiveFile); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("cross-workspace archive: %v", err)
	}
	// Archiving during an open transfer must stop the next block.
	sent := 0
	_, err = s.StreamDownload(actorContext(t, filesv1.PrivateDownload.ID, "alice", "session-a"), ref, downloadWriter(func(p []byte) (int, error) {
		sent += len(p)
		result, err := catalogCommand(t, s, filesv1.FileArchive.ID, "archive", filesv1.FileArchiveRequest{FileRef: ref, Revision: 4}, s.archiveFile)
		if err != nil || !result.Archived || result.Revision != 5 {
			t.Fatalf("archive: %+v %v", result, err)
		}
		return len(p), nil
	}))
	if rpc.ErrorCode(err) != rpc.CodeNotFound || sent != 256<<10 {
		t.Fatalf("archived stream continued: sent=%d err=%v", sent, err)
	}
	if _, err := s.getFile(ctx, ref); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("archived GET: %v", err)
	}
	list, err := s.listFiles(ctx, filesv1.FileListRequest{Scope: ref.Scope, Limit: 100})
	if err != nil || len(list.Files) != 0 {
		t.Fatalf("archived list: %+v %v", list, err)
	}
	var denied bytes.Buffer
	if _, err := s.StreamDownload(actorContext(t, filesv1.PrivateDownload.ID, "alice", "session-a"), ref, &denied); rpc.ErrorCode(err) != rpc.CodeNotFound || denied.Len() != 0 {
		t.Fatalf("archived bytes exposed: count=%d err=%v", denied.Len(), err)
	}
	q.Revision = 5
	if _, err := catalogCommand(t, s, filesv1.FileRename.ID, "revive", q, s.renameFile); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("archived mutation: %v", err)
	}
	archivedResult, err := catalogCommand(t, s, filesv1.FileArchive.ID, "archive", filesv1.FileArchiveRequest{FileRef: ref, Revision: 4}, s.archiveFile)
	if err != nil || !archivedResult.Archived || archivedResult.Revision != 5 {
		t.Fatalf("archive replay: %+v %v", archivedResult, err)
	}
	if err := db.Table("audit").Count(&audit).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Table("outbox").Count(&outbox).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Table("command_results").Count(&replayCount).Error; err != nil {
		t.Fatal(err)
	}
	if audit != 4 || outbox != 4 || replayCount != 4 {
		t.Fatalf("final atomic effects: %d/%d/%d", audit, outbox, replayCount)
	}
	// A retained archive reference also protects old bytes from orphan recovery.
	old := now.Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "objects", fileID+".blob"), old, old); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PruneOrphanObjects(ctx); err != nil || n != 0 {
		t.Fatalf("archive GC: %d %v", n, err)
	}
	f, err := store.Open(ctx, fileID)
	if err != nil {
		t.Fatalf("archive lost bytes: %v", err)
	}
	f.Close()
	var retained models.File
	if err := db.Where("id=?", fileID).Take(&retained).Error; err != nil || retained.ArchivedAt == nil {
		t.Fatalf("archive timestamp missing: %v", err)
	}
}
