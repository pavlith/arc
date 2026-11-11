package objects

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/migrations"
	"github.com/pavlith/arc/services/files/models"
	"github.com/pavlith/arc/services/files/storage"
)

type downloadWriter func([]byte) (int, error)

func (fn downloadWriter) Write(p []byte) (int, error) { return fn(p) }

func TestPrivateDownloadFailsClosedOnRevocation(t *testing.T) {
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
	store, err := storage.OpenLocal(filepath.Join(t.TempDir(), "bytes"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	compiled, err := contract.Compile(filesv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	const pending = "00000000-0000-4000-8000-000000005001"
	const blob = "00000000-0000-4000-8000-000000005002"
	content := bytes.Repeat([]byte("A"), 512<<10)
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if err := store.Prepare(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(ctx, pending, 0, int64(len(content)), bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote(ctx, pending, blob, int64(len(content)), digest); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.Create(&models.File{
		ID: blob, WorkspaceID: workspace, RootID: root,
		Filename: "private.bin", MIME: "application/octet-stream",
		Size: int64(len(content)), SHA256: digest, BlobKey: blob,
		Revision: 1, State: "ready", CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	allowed := true
	checks := 0
	s := &Module{
		DB: db, Contract: compiled, Storage: store,
		Authorize: func(_ context.Context, id, action string) error {
			checks++
			if !allowed || id != root || action != "files.read" {
				return security.ErrDenied
			}
			return nil
		},
	}
	ref := filesv1.FileRef{Scope: filesv1.Scope{WorkspaceID: workspace, RootID: root}, FileID: blob}
	verified := actorContext(t, filesv1.FileGet.ID, "alice", "session-a")
	var sent int
	_, err = s.StreamDownload(verified, ref, downloadWriter(func(p []byte) (int, error) {
		sent += len(p)
		allowed = false
		return len(p), nil
	}))
	if !errors.Is(err, security.ErrDenied) || sent != 256<<10 {
		t.Fatalf("revocation did not interrupt stream: sent=%d err=%v", sent, err)
	}
	allowed = true
	var result bytes.Buffer
	file, err := s.StreamDownload(verified, ref, &result)
	if err != nil || !bytes.Equal(result.Bytes(), content) || file.SHA256 != digest {
		t.Fatalf("complete private download: file=%+v size=%d err=%v", file, result.Len(), err)
	}
	if checks < 6 {
		t.Fatalf("stream skipped online checks: %d", checks)
	}
	var denied bytes.Buffer
	_, err = s.StreamDownload(verified, filesv1.FileRef{
		Scope: filesv1.Scope{WorkspaceID: workspace, RootID: otherRoot}, FileID: blob,
	}, &denied)
	if !errors.Is(err, security.ErrDenied) || denied.Len() != 0 {
		t.Fatalf("cross-root data leaked: bytes=%d err=%v", denied.Len(), err)
	}
	cancelled, cancel := context.WithCancel(verified)
	cancel()
	var afterCancel bytes.Buffer
	if _, err := s.StreamDownload(cancelled, ref, &afterCancel); err == nil || afterCancel.Len() != 0 {
		t.Fatalf("cancelled context streamed bytes=%d err=%v", afterCancel.Len(), err)
	}
}
