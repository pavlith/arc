package pages

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/pages/api/v1"
	"github.com/pavlith/arc/services/pages/migrations"
	"github.com/pavlith/arc/services/pages/models"
	"gorm.io/gorm"
)

const ws = "40000000-0000-4000-8000-000000000001"
const root = "40000000-0000-4000-8000-000000000002"

var emptyDoc = json.RawMessage(`{"type":"doc","content":[{"type":"paragraph"}]}`)

func pageFixture(t *testing.T) (*Module, *bool) {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "pages.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(db) })
	for i := 0; i < 2; i++ {
		if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Create(&models.Root{RootID: root, WorkspaceID: ws, State: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	compiled, err := contract.Compile(v1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	read := true
	return &Module{DB: db, Contract: compiled, Check: func(_ context.Context, _ string, action string) error {
		if action == "pages.read" && !read {
			return security.ErrDenied
		}
		return nil
	}}, &read
}
func pageCommand[Q, R any](t *testing.T, s *Module, op, action, key string, q Q, fn func(context.Context, *gorm.DB, Q) (R, error)) (R, error) {
	t.Helper()
	var zero R
	auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
		return security.Claims{Subject: "user:reader", SessionID: "session", Operation: op, WorkspaceID: ws}, nil
	})
	raw, _ := json.Marshal(map[string]any{"operation": op, "proof": security.Proof{}, "auth": "fixture", "payload": q, "idempotency_key": key})
	ctx, err := auth(context.Background(), "fixture", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Authorize(ctx, root, action); err != nil {
		return zero, err
	}
	return events.Command(ctx, events.Store{DB: s.DB}, s.Contract, op, q, fn)
}
func TestPageHierarchyCASVersionsRestoreReplayAndRollback(t *testing.T) {
	s, read := pageFixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	create := func(title, parent string) v1.Page {
		q := v1.Create{Scope: scope, Input: v1.Input{Title: title, Document: emptyDoc}, ParentID: parent}
		p, err := pageCommand(t, s, v1.CreatePage.ID, "pages.create", "create-"+title, q, s.create)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := create("Parent", "")
	b := create("Child", a.ID)
	_, err := pageCommand(t, s, v1.MovePage.ID, "pages.write", "cycle", v1.Move{PageRef: v1.PageRef{Scope: scope, PageID: a.ID}, Revision: a.Revision, ParentID: b.ID}, s.move)
	if rpc.ErrorCode(err) != rpc.CodeValidation {
		t.Fatalf("cycle: %v", err)
	}
	_, err = pageCommand(t, s, v1.ArchivePage.ID, "pages.delete", "nonempty", v1.Archive{PageRef: v1.PageRef{Scope: scope, PageID: a.ID}, Revision: a.Revision}, s.archive)
	if rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("nonempty archive: %v", err)
	}
	moved, err := pageCommand(t, s, v1.MovePage.ID, "pages.write", "move", v1.Move{PageRef: v1.PageRef{Scope: scope, PageID: b.ID}, Revision: b.Revision}, s.move)
	if err != nil {
		t.Fatal(err)
	}
	restore := v1.Restore{VersionRef: v1.VersionRef{PageRef: v1.PageRef{Scope: scope, PageID: b.ID}, Version: 1}, Revision: moved.Revision}
	restored, err := pageCommand(t, s, v1.RestorePage.ID, "pages.write", "restore", restore, s.restore)
	if err != nil || restored.ParentID != "" || restored.Revision != 3 {
		t.Fatalf("restore moved parent or lost CAS: %+v %v", restored, err)
	}
	*read = false
	if _, err := pageCommand(t, s, v1.RestorePage.ID, "pages.write", "restore", restore, s.restore); err == nil {
		t.Fatal("cached restore bypassed read revocation")
	}
	*read = true
	q := v1.Update{PageRef: v1.PageRef{Scope: scope, PageID: b.ID}, Input: v1.Input{Title: "New", Document: emptyDoc}, Revision: restored.Revision}
	if err := s.DB.Exec("CREATE TRIGGER reject_page_event BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := pageCommand(t, s, v1.UpdatePage.ID, "pages.write", "update", q, s.update); err == nil {
		t.Fatal("outbox failure accepted")
	}
	current, err := s.get(context.Background(), q.PageRef)
	if err != nil || current.Revision != restored.Revision || current.Title != "Child" {
		t.Fatal("failed command changed page")
	}
	if err := s.DB.Exec("DROP TRIGGER reject_page_event").Error; err != nil {
		t.Fatal(err)
	}
	updated, err := pageCommand(t, s, v1.UpdatePage.ID, "pages.write", "update", q, s.update)
	if err != nil || updated.Title != "New" {
		t.Fatal(err)
	}
	if _, err := pageCommand(t, s, v1.UpdatePage.ID, "pages.write", "stale", q, s.update); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("stale revision: %v", err)
	}
	versions, err := s.versions(context.Background(), v1.VersionList{PageRef: q.PageRef, Limit: 10, Before: 1})
	if err != nil || versions.Versions == nil || len(versions.Versions) != 0 {
		t.Fatalf("empty versions: %+v %v", versions, err)
	}
	cross := q.PageRef
	cross.RootID = "40000000-0000-4000-8000-000000000003"
	if _, err := s.get(context.Background(), cross); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("cross-root known ID: %v", err)
	}
	*read = false
	archived, err := pageCommand(t, s, v1.ArchivePage.ID, "pages.delete", "archive", v1.Archive{PageRef: q.PageRef, Revision: updated.Revision}, s.archive)
	if err != nil || !archived.Archived {
		t.Fatal(err)
	}
	if _, err := s.get(context.Background(), q.PageRef); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("archived page visible: %v", err)
	}
}
func TestTemplateUseRequiresReadAndSnapshotsContent(t *testing.T) {
	s, read := pageFixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	template, err := pageCommand(t, s, v1.CreateTemplate.ID, "pages.write", "template", v1.TemplateCreate{Scope: scope, Input: v1.Input{Title: "Template", Document: emptyDoc}}, s.createTemplate)
	if err != nil {
		t.Fatal(err)
	}
	q := v1.TemplateUse{Scope: scope, TemplateID: template.ID}
	*read = false
	if _, err := pageCommand(t, s, v1.UseTemplate.ID, "pages.create", "use", q, s.useTemplate); err == nil {
		t.Fatal("create-only reader read a template")
	}
	*read = true
	p, err := pageCommand(t, s, v1.UseTemplate.ID, "pages.create", "use", q, s.useTemplate)
	if err != nil || p.Title != "Template" {
		t.Fatalf("use: %+v %v", p, err)
	}
	*read = false
	if _, err := pageCommand(t, s, v1.UseTemplate.ID, "pages.create", "use", q, s.useTemplate); err == nil {
		t.Fatal("template replay bypassed read revoke")
	}
}
