package objects

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/migrations"
	"github.com/pavlith/arc/services/files/models"
)

func TestFilenameSearchScopeLiteralMatchingAndPagination(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "files.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	s := &Module{DB: db}
	const otherWorkspace = "00000000-0000-4000-8000-00000000d001"
	const tenantRoot = "00000000-0000-4000-8000-00000000d002"
	for _, r := range []models.Root{
		{RootID: root, WorkspaceID: workspace, State: "active"},
		{RootID: otherRoot, WorkspaceID: workspace, State: "active"},
		{RootID: tenantRoot, WorkspaceID: otherWorkspace, State: "active"},
	} {
		if err := db.Create(&r).Error; err != nil {
			t.Fatal(err)
		}
	}
	const folder = "00000000-0000-4000-8000-00000000d003"
	const foreign = "00000000-0000-4000-8000-00000000d004"
	const archived = "00000000-0000-4000-8000-00000000d005"
	now := time.Now().UTC()
	for _, f := range []models.Folder{
		{ID: folder, RootID: root, Name: "own"},
		{ID: foreign, RootID: otherRoot, Name: "foreign"},
		{ID: archived, RootID: root, Name: "archived", ArchivedAt: &now},
	} {
		f.WorkspaceID, f.Revision, f.CreatedAt, f.UpdatedAt = workspace, 1, now, now
		if err := db.Create(&f).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i, f := range []models.File{
		{Filename: "Report_%.bin", RootID: root},
		{Filename: "Report.бин", RootID: root, FolderID: pointer(folder)},
		{Filename: "Report.txt", RootID: root, State: "archived", ArchivedAt: &now},
		{Filename: "Report.bin", RootID: otherRoot},
		{Filename: "Report.bin", RootID: tenantRoot, WorkspaceID: otherWorkspace},
		{Filename: "report.txt", RootID: root},
		{Filename: "Заметки.txt", RootID: root},
	} {
		f.ID = fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)
		if f.WorkspaceID == "" {
			f.WorkspaceID = workspace
		}
		if f.State == "" {
			f.State = "ready"
		}
		f.MIME, f.SHA256, f.BlobKey, f.Revision, f.CreatedAt, f.UpdatedAt = "application/octet-stream", strings.Repeat("0", 64), f.ID, 1, now, now
		if err := db.Create(&f).Error; err != nil {
			t.Fatal(err)
		}
	}
	q := filesv1.FileSearchRequest{Scope: filesv1.Scope{WorkspaceID: workspace, RootID: root}, Query: " Report ", Limit: 1}
	first, err := s.searchFiles(ctx, q)
	if err != nil || len(first.Files) != 1 || first.Files[0].Filename != "Report_%.bin" || first.NextCursor != first.Files[0].ID {
		t.Fatalf("first page: %+v %v", first, err)
	}
	q.Cursor = first.NextCursor
	second, err := s.searchFiles(ctx, q)
	if err != nil || len(second.Files) != 1 || second.Files[0].Filename != "Report.бин" || second.NextCursor != "" {
		t.Fatalf("second page/isolation: %+v %v", second, err)
	}
	q.Cursor = ""
	q.Limit = 100
	for _, tc := range []struct{ query, filename string }{
		{"%", "Report_%.bin"}, {"_", "Report_%.bin"}, {"report", "report.txt"}, {"Заметки", "Заметки.txt"},
	} {
		q.Query = tc.query
		got, err := s.searchFiles(ctx, q)
		if err != nil || len(got.Files) != 1 || got.Files[0].Filename != tc.filename {
			t.Fatalf("literal/case/Unicode %q: %+v %v", tc.query, got, err)
		}
	}
	q.Query = "Report"
	q.FolderID = folder
	filtered, err := s.searchFiles(ctx, q)
	if err != nil || len(filtered.Files) != 1 || filtered.Files[0].FolderID != folder {
		t.Fatalf("folder filter: %+v %v", filtered, err)
	}
	for _, id := range []string{foreign, archived} {
		q.FolderID = id
		if _, err := s.searchFiles(ctx, q); rpc.ErrorCode(err) != rpc.CodeNotFound {
			t.Fatalf("forbidden folder %s: %v", id, err)
		}
	}
	q.FolderID = ""
	for _, query := range []string{"' OR 1=1 --", "no match", "\\"} {
		q.Query = query
		got, err := s.searchFiles(ctx, q)
		if err != nil || got.Files == nil || len(got.Files) != 0 || got.NextCursor != "" {
			t.Fatalf("empty/literal %q: %+v %v", query, got, err)
		}
	}
	for _, query := range []string{"", "   ", strings.Repeat("я", 257), string([]byte{0xff})} {
		q.Query = query
		if _, err := s.searchFiles(ctx, q); rpc.ErrorCode(err) != rpc.CodeValidation {
			t.Fatalf("invalid query accepted: %v", err)
		}
	}
	q.Query = "Report"
	for _, limit := range []int{0, 101} {
		q.Limit = limit
		if _, err := s.searchFiles(ctx, q); rpc.ErrorCode(err) != rpc.CodeValidation {
			t.Fatalf("invalid limit: %v", err)
		}
	}
	q.Limit = 100
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.searchFiles(cancelled, q); err == nil {
		t.Fatal("cancellation ignored")
	}
	if err := db.Migrator().DropTable(&models.File{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.searchFiles(ctx, q); err == nil {
		t.Fatal("database failure became successful empty result")
	}
}
