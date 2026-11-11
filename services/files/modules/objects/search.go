package objects

import (
	"context"
	"strings"
	"unicode/utf8"

	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/models"
)

func (s *Module) searchFiles(ctx context.Context, q filesv1.FileSearchRequest) (filesv1.FilesResult, error) {
	out := filesv1.FilesResult{Files: []filesv1.File{}}
	query := strings.TrimSpace(q.Query)
	if q.Limit < 1 || q.Limit > 100 || !utf8.ValidString(query) || query == "" || utf8.RuneCountInString(query) > 256 {
		return out, invalid()
	}
	if err := s.folder(ctx, s.DB, q.Scope, q.FolderID); err != nil {
		return out, err
	}
	db := s.DB.WithContext(ctx).Model(&models.File{}).
		Where("workspace_id=? AND acl_root_id=? AND state='ready' AND id>? AND instr(filename,?)>0",
			q.WorkspaceID, q.RootID, q.Cursor, query)
	if q.FolderID != "" {
		db = db.Where("folder_id=?", q.FolderID)
	}
	var rows []models.File
	if err := db.Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, unavailable(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	for _, row := range rows {
		out.Files = append(out.Files, fileDTO(row))
	}
	return out, nil
}
