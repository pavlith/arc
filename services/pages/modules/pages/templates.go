package pages

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pavlith/arc/sdk/database"
	v1 "github.com/pavlith/arc/services/pages/api/v1"
	"github.com/pavlith/arc/services/pages/models"
	"gorm.io/gorm"
)

func templateDTO(r models.Template) v1.Template {
	return v1.Template{Scope: v1.Scope{WorkspaceID: r.WorkspaceID, RootID: r.RootID}, ID: r.ID, Input: v1.Input{Title: r.Title, Document: json.RawMessage(r.Document)}, Revision: r.Revision, Archived: r.ArchivedAt != nil}
}
func (s *Module) template(ctx context.Context, db *gorm.DB, q v1.TemplateRef) (models.Template, error) {
	var row models.Template
	err := db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL", q.TemplateID, q.WorkspaceID, q.RootID).Take(&row).Error
	return row, dbError(err)
}
func (s *Module) getTemplate(ctx context.Context, q v1.TemplateRef) (v1.Template, error) {
	row, err := s.template(ctx, s.db(ctx), q)
	return templateDTO(row), err
}
func (s *Module) createTemplate(ctx context.Context, tx *gorm.DB, q v1.TemplateCreate) (v1.Template, error) {
	in, err := s.validate(database.TransactionContext(ctx, s.DB, tx), q.Input)
	if err != nil {
		return v1.Template{}, err
	}
	var count int64
	if err := tx.Model(&models.Template{}).Where("workspace_id=? AND acl_root_id=?", q.WorkspaceID, q.RootID).Count(&count).Error; err != nil {
		return v1.Template{}, dbError(err)
	}
	if count >= 1000 {
		return v1.Template{}, invalid()
	}
	row := models.Template{ID: newID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID, Title: in.Title, Document: string(in.Document), Revision: 1}
	if err := tx.Create(&row).Error; err != nil {
		return v1.Template{}, dbError(err)
	}
	return templateDTO(row), s.changed(ctx, tx, models.Page{ID: row.ID, WorkspaceID: row.WorkspaceID, RootID: row.RootID, Revision: row.Revision}, "template.created")
}
func (s *Module) updateTemplate(ctx context.Context, tx *gorm.DB, q v1.TemplateUpdate) (v1.Template, error) {
	row, err := s.template(ctx, tx, q.TemplateRef)
	if err != nil {
		return v1.Template{}, err
	}
	if q.Revision != row.Revision || q.Revision < 1 {
		return v1.Template{}, conflict()
	}
	in, err := s.validate(database.TransactionContext(ctx, s.DB, tx), q.Input)
	if err != nil {
		return v1.Template{}, err
	}
	res := tx.Model(&models.Template{}).Where("id=? AND revision=? AND archived_at IS NULL", row.ID, q.Revision).Updates(map[string]any{"title": in.Title, "document": string(in.Document), "revision": q.Revision + 1})
	if res.Error != nil {
		return v1.Template{}, dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return v1.Template{}, conflict()
	}
	row.Title, row.Document, row.Revision = in.Title, string(in.Document), q.Revision+1
	return templateDTO(row), s.changed(ctx, tx, models.Page{ID: row.ID, WorkspaceID: row.WorkspaceID, RootID: row.RootID, Revision: row.Revision}, "template.updated")
}
func (s *Module) archiveTemplate(ctx context.Context, tx *gorm.DB, q v1.TemplateArchive) (v1.Mutation, error) {
	row, err := s.template(ctx, tx, q.TemplateRef)
	if err != nil {
		return v1.Mutation{}, err
	}
	if q.Revision != row.Revision || q.Revision < 1 {
		return v1.Mutation{}, conflict()
	}
	now := time.Now().UTC()
	res := tx.Model(&models.Template{}).Where("id=? AND revision=? AND archived_at IS NULL", row.ID, q.Revision).Updates(map[string]any{"archived_at": now, "revision": q.Revision + 1})
	if res.Error != nil {
		return v1.Mutation{}, dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return v1.Mutation{}, conflict()
	}
	err = s.changed(ctx, tx, models.Page{ID: row.ID, WorkspaceID: row.WorkspaceID, RootID: row.RootID, Revision: q.Revision + 1}, "template.archived")
	return v1.Mutation{ID: row.ID, Revision: q.Revision + 1, Archived: true, UpdatedAt: now}, err
}
func (s *Module) listTemplates(ctx context.Context, q v1.List) (v1.TemplateList, error) {
	out := v1.TemplateList{Templates: []v1.TemplateSummary{}}
	if q.Limit < 1 || q.Limit > 100 {
		return out, invalid()
	}
	db := s.db(ctx).Model(&models.Template{}).Where("workspace_id=? AND acl_root_id=? AND archived_at IS NULL AND id>?", q.WorkspaceID, q.RootID, q.Cursor)
	if q.Query != "" {
		db = db.Where("instr(title,?)>0", q.Query)
	}
	var rows []models.Template
	if err := db.Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, dbError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	for _, r := range rows {
		out.Templates = append(out.Templates, v1.TemplateSummary{Scope: q.Scope, ID: r.ID, Title: r.Title, Revision: r.Revision})
	}
	return out, nil
}
func (s *Module) useTemplate(ctx context.Context, tx *gorm.DB, q v1.TemplateUse) (v1.Page, error) {
	if q.TemplateID == "" {
		return v1.Page{}, invalid()
	}
	ctx = database.TransactionContext(ctx, s.DB, tx)
	if err := s.Authorize(ctx, q.RootID, "pages.read"); err != nil {
		return v1.Page{}, err
	}
	row, err := s.template(ctx, tx, v1.TemplateRef{Scope: q.Scope, TemplateID: q.TemplateID})
	if err != nil {
		return v1.Page{}, err
	}
	return s.create(ctx, tx, v1.Create{Scope: q.Scope, ParentID: q.ParentID, Input: v1.Input{Title: row.Title, Document: json.RawMessage(row.Document)}})
}
