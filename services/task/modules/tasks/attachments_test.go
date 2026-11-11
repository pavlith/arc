package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/resource"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/migrations"
	"gorm.io/gorm"
)

func TestAttachmentCASRevokeDetachAndOutboxRollback(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "task.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	scope := v1.Scope{WorkspaceID: "30000000-0000-4000-8000-000000000001", RootID: "30000000-0000-4000-8000-000000000002"}
	if err := db.Exec("INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'active')", scope.RootID, scope.WorkspaceID).Error; err != nil {
		t.Fatal(err)
	}
	compiled, err := contract.Compile(v1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	allowed := true
	s := &Service{GormDB: db, Contract: compiled, Check: func(context.Context, string, string) error { return nil }, Resolve: func(_ context.Context, r resource.Ref) (resource.Summary, error) {
		if !allowed {
			return resource.Summary{}, security.ErrDenied
		}
		return resource.Summary{Ref: r, Title: "private file", Revision: 1}, nil
	}}
	verified := func(op, key string, q any) context.Context {
		auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
			return security.Claims{Subject: "user:alice", SessionID: "session", WorkspaceID: scope.WorkspaceID, Operation: op}, nil
		})
		raw, _ := json.Marshal(map[string]any{"operation": op, "proof": security.Proof{}, "auth": "fixture", "payload": q, "idempotency_key": key})
		ctx, err := auth(ctx, "fixture", raw)
		if err != nil {
			t.Fatal(err)
		}
		return ctx
	}
	var team v1.Team
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		team, err = s.createTeam(ctx, tx, v1.TeamCreateRequest{Scope: scope, Name: "Team", Key: "TEST"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var work v1.WorkItem
	err = db.Transaction(func(tx *gorm.DB) error {
		q := v1.WorkCreateRequest{Scope: scope, WorkInput: v1.WorkInput{Title: "Task", TeamID: team.ID}}
		var err error
		work, err = s.createWork(verified(v1.WorkCreate.ID, "work", q), tx, q)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	local, err := s.previewReference(ctx, v1.ReferencePreview{GetRequest: v1.GetRequest{Scope: scope, TaskID: work.ID}, Target: resource.Ref{Kind: "task", WorkspaceID: scope.WorkspaceID, RootID: scope.RootID, ID: work.ID}})
	if err != nil || local.Title != work.Title {
		t.Fatalf("native Task preview required a broker loop: %+v %v", local, err)
	}
	q := v1.AttachmentChange{GetRequest: v1.GetRequest{Scope: scope, TaskID: work.ID}, Revision: work.Revision, ExpectedUpdatedAt: work.UpdatedAt, File: resource.Ref{Kind: "file", WorkspaceID: scope.WorkspaceID, RootID: "30000000-0000-4000-8000-000000000003", ID: "30000000-0000-4000-8000-000000000004"}}
	call := func(key string) (v1.AttachmentResult, error) {
		ctx := verified(v1.AttachmentChangeOp.ID, key, q)
		if err := s.Authorize(ctx, scope.RootID, "task.create"); err != nil {
			return v1.AttachmentResult{}, err
		}
		return events.Command(ctx, events.Store{DB: db}, compiled, v1.AttachmentChangeOp.ID, q, s.changeAttachment)
	}
	first, err := call("attach")
	if err != nil || first.Revision != 2 {
		t.Fatalf("attach: %+v %v", first, err)
	}
	if replay, err := call("attach"); err != nil || replay != first {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	allowed = false
	if _, err := call("attach"); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("replay bypassed target revoke: %v", err)
	}
	if _, err := s.previewReference(verified(v1.ReferencePreviewOp.ID, "preview", q), v1.ReferencePreview{GetRequest: q.GetRequest, Target: q.File}); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("revoked preview: %v", err)
	}
	refs, err := s.listAttachments(ctx, q.GetRequest)
	if err != nil || len(refs.Files) != 1 {
		t.Fatalf("opaque refs lost: %+v %v", refs, err)
	}
	q.Remove = true
	q.Revision = first.Revision
	q.ExpectedUpdatedAt = first.UpdatedAt
	if err := db.Exec("CREATE TRIGGER reject_attachment_event BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := call("detach"); err == nil {
		t.Fatal("outbox failure accepted")
	}
	refs, err = s.listAttachments(ctx, q.GetRequest)
	if err != nil || len(refs.Files) != 1 {
		t.Fatal("failed detach changed references")
	}
	db.Exec("DROP TRIGGER reject_attachment_event")
	if _, err := call("detach"); err != nil {
		t.Fatalf("cannot detach revoked target: %v", err)
	}
	refs, err = s.listAttachments(ctx, q.GetRequest)
	if err != nil || len(refs.Files) != 0 {
		t.Fatal("detach failed")
	}
	if _, err := call("stale"); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("stale CAS: %v", err)
	}
}
