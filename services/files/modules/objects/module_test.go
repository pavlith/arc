package objects

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/migrations"
	"github.com/pavlith/arc/services/files/models"
	"github.com/pavlith/arc/services/files/storage"
	"gorm.io/gorm"
)

const (
	workspace = "00000000-0000-4000-8000-000000000001"
	root      = "00000000-0000-4000-8000-000000000002"
	otherRoot = "00000000-0000-4000-8000-000000000003"
)

// The fake verifier injects verified claims for domain-unit tests only. Live
// JWT, proof, ACL and gateway coverage belongs to the integration suite.
func actorContext(t *testing.T, operation, user, session string) context.Context {
	t.Helper()
	auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
		return security.Claims{Subject: "user:" + user, SessionID: session,
			Operation: operation, WorkspaceID: workspace}, nil
	})
	wire, err := json.Marshal(map[string]any{
		"operation":       operation,
		"proof":           security.Proof{Kid: "fixture"},
		"auth":            "fixture",
		"payload":         filesv1.Scope{WorkspaceID: workspace, RootID: root},
		"idempotency_key": "fixture-" + operation,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := auth(context.Background(), "rpc.files.v1."+strings.TrimPrefix(operation, "files."), wire)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestUploadSessionsAndReadyFileMetadata(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "files.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{root, otherRoot} {
		if err := db.Exec("INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'active')", id, workspace).Error; err != nil {
			t.Fatal(err)
		}
	}
	store, err := storage.OpenLocal(filepath.Join(t.TempDir(), "bytes"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	compiled, err := contract.Compile(filesv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	s := &Module{DB: db, Contract: compiled, Storage: store}
	scope := filesv1.Scope{WorkspaceID: workspace, RootID: root}
	h := sha256.Sum256([]byte("abcdef"))
	sha := hex.EncodeToString(h[:])
	initCtx := actorContext(t, filesv1.UploadInitiate.ID, "alice", "session-a")
	var upload filesv1.Upload
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		upload, err = s.initiate(initCtx, tx, filesv1.UploadInitiateRequest{
			Scope: scope, Filename: "notes.bin", MIME: "application/octet-stream",
			ExpectedSize: 6, ExpectedSHA256: sha,
		})
		return err
	})
	if err != nil || upload.State != "pending" || upload.Offset != 0 {
		t.Fatalf("initiate: %+v %v", upload, err)
	}
	if _, err := s.getUpload(actorContext(t, filesv1.UploadGet.ID, "alice", "other-session"),
		filesv1.UploadRef{Scope: scope, UploadID: upload.ID}); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("cross-session known-ID leaked: %v", err)
	}
	if _, err := s.getUpload(actorContext(t, filesv1.UploadGet.ID, "bob", "session-a"),
		filesv1.UploadRef{Scope: scope, UploadID: upload.ID}); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("cross-user known-ID leaked: %v", err)
	}
	if _, err := s.getUpload(actorContext(t, filesv1.UploadGet.ID, "alice", "session-a"),
		filesv1.UploadRef{Scope: filesv1.Scope{WorkspaceID: workspace, RootID: otherRoot}, UploadID: upload.ID}); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("cross-root known-ID leaked: %v", err)
	}
	if _, err := s.Storage.Append(ctx, upload.ID, 0, 6, strings.NewReader("abcdef")); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&models.Upload{}).Where("id=?", upload.ID).Update("offset", 6).Error; err != nil {
		t.Fatal(err)
	}
	var file filesv1.File
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		file, err = s.complete(actorContext(t, filesv1.UploadComplete.ID, "alice", "session-a"), tx,
			filesv1.UploadRef{Scope: scope, UploadID: upload.ID})
		return err
	})
	if err != nil || file.SHA256 != sha || file.Size != 6 || file.ID == "" {
		t.Fatalf("complete: %+v %v", file, err)
	}
	if file.ETag != "\""+sha+"\"" {
		t.Fatalf("unstable ETag: %q", file.ETag)
	}
	f, err := s.Storage.Open(ctx, file.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || string(body) != "abcdef" {
		t.Fatalf("stored bytes: %s %v", body, err)
	}
	if _, err := s.getFile(ctx, filesv1.FileRef{Scope: filesv1.Scope{WorkspaceID: workspace, RootID: otherRoot}, FileID: file.ID}); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("cross-root ready file leaked: %v", err)
	}
	list, err := s.listFiles(ctx, filesv1.FileListRequest{Scope: scope, Limit: 100})
	if err != nil || len(list.Files) != 1 || list.Files[0].ID != file.ID {
		t.Fatalf("ready list: %+v %v", list, err)
	}
	var audit, outbox int64
	_ = db.Table("audit").Count(&audit).Error
	_ = db.Table("outbox").Count(&outbox).Error
	if audit != 1 || outbox != 1 {
		t.Fatalf("file completion must audit and enqueue atomically: %d/%d", audit, outbox)
	}
	second, err := s.getUpload(actorContext(t, filesv1.UploadGet.ID, "alice", "session-a"),
		filesv1.UploadRef{Scope: scope, UploadID: upload.ID})
	if err != nil || second.State != "completed" {
		t.Fatalf("completion state: %+v %v", second, err)
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		_, err := s.complete(actorContext(t, filesv1.UploadComplete.ID, "alice", "session-a"), tx,
			filesv1.UploadRef{Scope: scope, UploadID: upload.ID})
		return err
	})
	if rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("double complete accepted: %v", err)
	}
}

func TestAbortPendingUploadAndValidation(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "files.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'active')", root, workspace).Error; err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenLocal(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	compiled, err := contract.Compile(filesv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	s := &Module{DB: db, Contract: compiled, Storage: store}
	scope := filesv1.Scope{WorkspaceID: workspace, RootID: root}
	create := func(name string) (filesv1.Upload, error) {
		var v filesv1.Upload
		err := db.Transaction(func(tx *gorm.DB) error {
			var e error
			v, e = s.initiate(actorContext(t, filesv1.UploadInitiate.ID, "alice", "session-a"), tx,
				filesv1.UploadInitiateRequest{Scope: scope, Filename: name, MIME: "application/octet-stream", ExpectedSize: 3})
			return e
		})
		return v, err
	}
	if _, err := create("../outside"); rpc.ErrorCode(err) != rpc.CodeValidation {
		t.Fatalf("unsafe filename accepted: %v", err)
	}
	v, err := create("file.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(ctx, v.ID, 0, 3, strings.NewReader("abc")); err != nil {
		t.Fatal(err)
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		_, err := s.abort(actorContext(t, filesv1.UploadAbort.ID, "alice", "session-a"), tx,
			filesv1.UploadRef{Scope: scope, UploadID: v.ID})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Offset(ctx, v.ID); !errors.Is(err, storage.ErrMissing) {
		t.Fatalf("abort left pending blob: %v", err)
	}
	if _, err := s.getFile(ctx, filesv1.FileRef{Scope: scope, FileID: v.ID}); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("aborted upload visible as ready file: %v", err)
	}
}
