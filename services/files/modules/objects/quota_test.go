package objects

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
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

const quotaOtherWorkspace = "00000000-0000-4000-8000-00000000e001"
const quotaOtherRoot = "00000000-0000-4000-8000-00000000e002"

func quotaFixture(t *testing.T, quota Quota) *Module {
	t.Helper()
	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), "files.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(db) })
	if err := database.Migrate(context.Background(), db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenLocal(filepath.Join(t.TempDir(), "bytes"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	compiled, err := contract.Compile(filesv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []models.Root{
		{RootID: root, WorkspaceID: workspace, State: "active"},
		{RootID: otherRoot, WorkspaceID: workspace, State: "active"},
		{RootID: quotaOtherRoot, WorkspaceID: quotaOtherWorkspace, State: "active"},
	} {
		if err := db.Create(&r).Error; err != nil {
			t.Fatal(err)
		}
	}
	return &Module{DB: db, Storage: store, Contract: compiled, Quota: quota}
}

// Only the invocation verifier is a fixture; the real replay/SQL/outbox path runs.
func quotaCommand[Q, R any](t *testing.T, s *Module, user, workspace, op, key string, q Q, h func(context.Context, *gorm.DB, Q) (R, error)) (R, error) {
	t.Helper()
	auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
		return security.Claims{Subject: "user:" + user, SessionID: "session-" + user, WorkspaceID: workspace, Operation: op}, nil
	})
	raw, err := json.Marshal(map[string]any{"operation": op, "proof": security.Proof{Kid: "fixture"}, "auth": "fixture", "payload": q, "idempotency_key": key})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := auth(context.Background(), "rpc.files.v1."+strings.TrimPrefix(op, "files."), raw)
	if err != nil {
		t.Fatal(err)
	}
	return events.Command(ctx, events.Store{DB: s.DB}, s.Contract, op, q, h)
}

func quotaUpload(t *testing.T, s *Module, user, workspace, root, key string, size int64) (filesv1.Upload, error) {
	t.Helper()
	q := filesv1.UploadInitiateRequest{Scope: filesv1.Scope{WorkspaceID: workspace, RootID: root}, Filename: "quota.bin", MIME: "application/octet-stream", ExpectedSize: size}
	return quotaCommand(t, s, user, workspace, filesv1.UploadInitiate.ID, key, q, s.initiate)
}

func TestWorkspaceQuotaAcrossActorsRootsAndLifecycle(t *testing.T) {
	s := quotaFixture(t, Quota{WorkspaceBytes: 6, WorkspaceFiles: 10})
	first, err := quotaUpload(t, s, "alice", workspace, root, "first", 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := quotaUpload(t, s, "bob", workspace, otherRoot, "over", 3); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("actor/root bypass: %v", err)
	}
	if _, err := quotaUpload(t, s, "bob", quotaOtherWorkspace, quotaOtherRoot, "independent", 3); err != nil {
		t.Fatalf("other workspace charged: %v", err)
	}
	second, err := quotaUpload(t, s, "bob", workspace, otherRoot, "exact", 2)
	if err != nil {
		t.Fatalf("exact capacity: %v", err)
	}
	replay, err := quotaUpload(t, s, "alice", workspace, root, "first", 4)
	if err != nil || replay.ID != first.ID {
		t.Fatalf("quota replay: %+v %v", replay, err)
	}
	if _, err := quotaUpload(t, s, "carol", workspace, root, "full", 1); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("over capacity: %v", err)
	}
	// Committed abort frees a reservation for another actor in another root.
	ref := filesv1.UploadRef{Scope: first.Scope, UploadID: first.ID}
	if _, err := quotaCommand(t, s, "alice", workspace, filesv1.UploadAbort.ID, "abort", ref, s.abort); err != nil {
		t.Fatal(err)
	}
	third, err := quotaUpload(t, s, "carol", workspace, root, "released", 4)
	if err != nil {
		t.Fatalf("abort did not release: %v", err)
	}
	// Expiry cannot be used for completion, and is excluded from reservations.
	if err := s.DB.Model(&models.Upload{}).Where("id=?", second.ID).Update("expires_at", time.Now().UTC().Add(-time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := quotaUpload(t, s, "dave", workspace, otherRoot, "expired-release", 2); err != nil {
		t.Fatalf("expiry did not release: %v", err)
	}
	ref = filesv1.UploadRef{Scope: second.Scope, UploadID: second.ID}
	if _, err := quotaCommand(t, s, "bob", workspace, filesv1.UploadComplete.ID, "expired-complete", ref, s.complete); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("expired reservation completed: %v", err)
	}
	// Completion must replace its reservation, rather than count the file twice.
	if _, err := s.Storage.Append(context.Background(), third.ID, 0, 4, strings.NewReader("data")); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&models.Upload{}).Where("id=?", third.ID).Update("offset", 4).Error; err != nil {
		t.Fatal(err)
	}
	ref = filesv1.UploadRef{Scope: third.Scope, UploadID: third.ID}
	completed, err := quotaCommand(t, s, "carol", workspace, filesv1.UploadComplete.ID, "complete", ref, s.complete)
	if err != nil {
		t.Fatal(err)
	}
	// A zero-byte upload still fits exactly-full byte capacity if slots remain.
	if _, err := quotaUpload(t, s, "erin", workspace, root, "zero", 0); err != nil {
		t.Fatalf("completion double charged: %v", err)
	}
	archive := filesv1.FileArchiveRequest{FileRef: filesv1.FileRef{Scope: completed.Scope, FileID: completed.ID}, Revision: completed.Revision}
	if _, err := quotaCommand(t, s, "carol", workspace, filesv1.FileArchive.ID, "archive", archive, s.archiveFile); err != nil {
		t.Fatal(err)
	}
	if _, err := quotaUpload(t, s, "frank", workspace, root, "archived-charge", 1); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("archive released retained bytes: %v", err)
	}
	// Lowering limits preserves data while rejecting additions.
	s.Quota.WorkspaceBytes = 3
	if _, err := quotaUpload(t, s, "grace", workspace, root, "lowered", 0); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("lowered quota bypass: %v", err)
	}
	f, err := s.Storage.Open(context.Background(), completed.ID)
	if err != nil {
		t.Fatalf("lowered limit deleted bytes: %v", err)
	}
	f.Close()
}

func TestWorkspaceQuotaSlotsAndConcurrentReservations(t *testing.T) {
	s := quotaFixture(t, Quota{WorkspaceBytes: 1, WorkspaceFiles: 1})
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, user := range []string{"alice", "bob"} {
		wg.Add(1)
		go func(user string) {
			defer wg.Done()
			<-start
			_, err := quotaUpload(t, s, user, workspace, root, "concurrent-"+user, 0)
			errs <- err
		}(user)
	}
	close(start)
	wg.Wait()
	close(errs)
	successes, conflicts := 0, 0
	for err := range errs {
		if err == nil {
			successes++
		} else if rpc.ErrorCode(err) == rpc.CodeConflict {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent failure: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("oversubscribed slot: success=%d conflicts=%d", successes, conflicts)
	}
	var uploads, replays int64
	if err := s.DB.Model(&models.Upload{}).Count(&uploads).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Table("command_results").Count(&replays).Error; err != nil {
		t.Fatal(err)
	}
	if uploads != 1 || replays != 1 {
		t.Fatalf("failed reservation persisted: %d/%d", uploads, replays)
	}
	// A quota query failure must fail closed before new upload state or bytes.
	if err := s.DB.Migrator().DropTable(&models.File{}); err != nil {
		t.Fatal(err)
	}
	if _, err := quotaUpload(t, s, "carol", workspace, root, "failed-db", 0); err == nil {
		t.Fatal("database failure accepted")
	}
}

func TestWorkspaceQuotaConfiguration(t *testing.T) {
	effective, err := (Quota{}).Effective()
	if err != nil || effective.WorkspaceBytes != 10*storage.MaxObjectSize || effective.WorkspaceFiles != 10000 {
		t.Fatalf("defaults: %+v %v", effective, err)
	}
	for _, q := range []Quota{{WorkspaceBytes: -1}, {WorkspaceFiles: -1}, {WorkspaceBytes: 1<<50 + 1}, {WorkspaceFiles: 1000001}} {
		if _, err := q.Effective(); err == nil {
			t.Fatalf("invalid config accepted: %+v", q)
		}
	}
}

func TestPersonalQuotaFollowsRootOwnerNotGrantee(t *testing.T) {
	s := quotaFixture(t, Quota{PersonalBytes: 4, PersonalFiles: 10})
	const a = "00000000-0000-4000-8000-00000000e010"
	const b = "00000000-0000-4000-8000-00000000e011"
	const c = "00000000-0000-4000-8000-00000000e012"
	for _, root := range []models.Root{{RootID: a, OwnerID: "owner-a", State: "active"}, {RootID: b, OwnerID: "owner-a", State: "active"}, {RootID: c, OwnerID: "owner-b", State: "active"}} {
		if err := s.DB.Create(&root).Error; err != nil {
			t.Fatal(err)
		}
	}
	upload := func(actor, root, key string, size int64) error {
		q := filesv1.UploadInitiateRequest{Scope: filesv1.Scope{RootID: root}, Filename: "personal.bin", MIME: "application/octet-stream", ExpectedSize: size}
		_, err := quotaCommand(t, s, actor, "", filesv1.PersonalUploadInitiate.ID, key, q, s.initiate)
		return err
	}
	if err := upload("owner-a", a, "first", 3); err != nil {
		t.Fatal(err)
	}
	if err := upload("grantee", b, "bypass", 2); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("grantee/second root bypassed owner capacity: %v", err)
	}
	if err := upload("grantee", b, "exact", 1); err != nil {
		t.Fatal(err)
	}
	if err := upload("owner-b", c, "independent", 4); err != nil {
		t.Fatalf("other owner charged: %v", err)
	}
}
