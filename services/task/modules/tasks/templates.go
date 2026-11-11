package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

func templateRow(ctx context.Context, db *gorm.DB, q taskv1.TemplateScope) (models.WorkTemplate, error) {
	var row models.WorkTemplate
	err := db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL", q.TemplateID, q.WorkspaceID, q.RootID).Take(&row).Error
	if err != nil {
		return row, catalogError(err)
	}
	if _, err := catalogTeam(ctx, db, taskv1.TeamScope{Scope: q.Scope, TeamID: row.TeamID}); err != nil {
		return row, err
	}
	return row, nil
}

func toTemplate(row models.WorkTemplate) (taskv1.WorkTemplate, error) {
	var input taskv1.WorkInput
	if err := json.Unmarshal([]byte(row.Definition), &input); err != nil || input.TeamID != row.TeamID {
		return taskv1.WorkTemplate{}, unavailable(errors.New("invalid stored template"))
	}
	return taskv1.WorkTemplate{
		Scope:         taskv1.Scope{WorkspaceID: row.WorkspaceID, RootID: row.RootID},
		TemplateInput: taskv1.TemplateInput{Name: row.Name, WorkInput: input},
		ID:            row.ID, Revision: row.Revision, Archived: row.ArchivedAt != nil,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}, nil
}

// References are checked at save time and again on use. A removed grant, user,
// status, label or project must never be resurrected by an old template.
func (s *Service) validateTemplate(ctx context.Context, tx *gorm.DB, scope taskv1.Scope, q taskv1.TemplateInput) (string, string, error) {
	name := strings.TrimSpace(q.Name)
	if len(name) < 1 || len(name) > 128 {
		return "", "", invalidCatalog()
	}
	if err := validateWork(q.WorkInput); err != nil {
		return "", "", err
	}
	if _, _, err := workStatus(ctx, tx, scope, q.WorkInput); err != nil {
		return "", "", err
	}
	if err := s.validateAssignees(ctx, scope, q.AssigneeIDs); err != nil {
		return "", "", err
	}
	if q.ProjectID != "" {
		project, err := catalogProject(ctx, tx, scope, q.ProjectID)
		if err != nil {
			return "", "", err
		}
		if project.ArchivedAt != nil || project.TeamID != nil && *project.TeamID != q.TeamID {
			return "", "", catalogConflict()
		}
	}
	for _, id := range q.LabelIDs {
		label, err := catalogLabel(ctx, tx, scope, id)
		if err != nil {
			return "", "", err
		}
		if label.ArchivedAt != nil {
			return "", "", catalogConflict()
		}
	}
	raw, err := json.Marshal(q.WorkInput)
	if err != nil || len(raw) > 160000 {
		return "", "", invalidWork()
	}
	return name, string(raw), nil
}

func (s *Service) createTemplate(ctx context.Context, tx *gorm.DB, q taskv1.TemplateCreateRequest) (taskv1.WorkTemplate, error) {
	name, raw, err := s.validateTemplate(ctx, tx, q.Scope, q.TemplateInput)
	if err != nil {
		return taskv1.WorkTemplate{}, err
	}
	now := time.Now().UTC()
	row := models.WorkTemplate{
		ID: NewID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID,
		TeamID: q.TeamID, Name: name, Definition: raw,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
		return taskv1.WorkTemplate{}, catalogError(err)
	}
	if err := s.catalogChanged(ctx, tx, q.Scope, "template", row.ID, row.Revision, "created"); err != nil {
		return taskv1.WorkTemplate{}, err
	}
	return toTemplate(row)
}

func (s *Service) updateTemplate(ctx context.Context, tx *gorm.DB, q taskv1.TemplateUpdateRequest) (taskv1.WorkTemplate, error) {
	row, err := templateRow(ctx, tx, q.TemplateScope)
	if err != nil {
		return taskv1.WorkTemplate{}, err
	}
	if q.Revision < 1 {
		return taskv1.WorkTemplate{}, invalidCatalog()
	}
	if q.Revision != row.Revision {
		return taskv1.WorkTemplate{}, catalogConflict()
	}
	if q.TeamID != row.TeamID {
		return taskv1.WorkTemplate{}, invalidCatalog()
	}
	name, raw, err := s.validateTemplate(ctx, tx, q.Scope, q.TemplateInput)
	if err != nil {
		return taskv1.WorkTemplate{}, err
	}
	row.Name, row.Definition = name, raw
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.WorkTemplate{}, catalogError(err)
	}
	if err := s.catalogChanged(ctx, tx, q.Scope, "template", row.ID, row.Revision, "definition"); err != nil {
		return taskv1.WorkTemplate{}, err
	}
	return toTemplate(row)
}

func (s *Service) archiveTemplate(ctx context.Context, tx *gorm.DB, q taskv1.TemplateArchiveRequest) (taskv1.ArchivedItem, error) {
	row, err := templateRow(ctx, tx, q.TemplateScope)
	if err != nil {
		return taskv1.ArchivedItem{}, err
	}
	if q.Revision < 1 {
		return taskv1.ArchivedItem{}, invalidCatalog()
	}
	if q.Revision != row.Revision {
		return taskv1.ArchivedItem{}, catalogConflict()
	}
	now := time.Now().UTC()
	row.ArchivedAt = &now
	row.UpdatedAt = now
	row.Revision++
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.ArchivedItem{}, catalogError(err)
	}
	return taskv1.ArchivedItem{Scope: q.Scope, ID: row.ID, Revision: row.Revision, Archived: true, UpdatedAt: now},
		s.catalogChanged(ctx, tx, q.Scope, "template", row.ID, row.Revision, "archived")
}

func (s *Service) getTemplate(ctx context.Context, q taskv1.TemplateScope) (taskv1.WorkTemplate, error) {
	row, err := templateRow(ctx, s.GormDB, q)
	if err != nil {
		return taskv1.WorkTemplate{}, err
	}
	return toTemplate(row)
}

func (s *Service) listTemplates(ctx context.Context, q taskv1.CatalogPage) (taskv1.TemplatesResult, error) {
	out := taskv1.TemplatesResult{Templates: []taskv1.WorkTemplate{}}
	if q.Limit < 1 || q.Limit > 100 {
		return out, invalidCatalog()
	}
	var rows []models.WorkTemplate
	if err := s.GormDB.WithContext(ctx).Table("work_templates AS t").
		Select("t.*").Joins("JOIN teams AS tm ON tm.id=t.team_id AND tm.workspace_id=t.workspace_id AND tm.acl_root_id=t.acl_root_id AND tm.archived_at IS NULL").
		Where("t.workspace_id=? AND t.acl_root_id=? AND t.archived_at IS NULL AND t.id>?", q.WorkspaceID, q.RootID, q.Cursor).
		Order("t.id").Limit(q.Limit + 1).Scan(&rows).Error; err != nil {
		return out, catalogError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	size := 0
	for _, row := range rows {
		item, err := toTemplate(row)
		if err != nil {
			return out, err
		}
		raw, err := json.Marshal(item)
		if err != nil {
			return out, unavailable(err)
		}
		if size+len(raw) > 180000 && len(out.Templates) > 0 {
			out.NextCursor = out.Templates[len(out.Templates)-1].ID
			break
		}
		size += len(raw)
		out.Templates = append(out.Templates, item)
	}
	return out, nil
}

func (s *Service) useTemplate(ctx context.Context, tx *gorm.DB, q taskv1.TemplateUseRequest) (taskv1.WorkItem, error) {
	row, err := templateRow(ctx, tx, q.TemplateScope)
	if err != nil {
		return taskv1.WorkItem{}, err
	}
	template, err := toTemplate(row)
	if err != nil {
		return taskv1.WorkItem{}, err
	}
	in := template.WorkInput
	if q.Title != "" {
		in.Title = strings.TrimSpace(q.Title)
	}
	return s.createWork(ctx, tx, taskv1.WorkCreateRequest{Scope: q.Scope, WorkInput: in})
}

func (s *Service) bindTemplates(r *module.Registry, policy module.Policy, store events.Store) error {
	for _, bind := range []func() error{
		func() error { return module.BindCommand(r, taskv1.TemplateCreate, policy, store, s.createTemplate) },
		func() error { return module.BindCommand(r, taskv1.TemplateUpdate, policy, store, s.updateTemplate) },
		func() error { return module.BindCommand(r, taskv1.TemplateArchive, policy, store, s.archiveTemplate) },
		func() error { return module.BindQuery(r, taskv1.TemplateGet, policy, s.getTemplate) },
		func() error { return module.BindQuery(r, taskv1.TemplateList, policy, s.listTemplates) },
		func() error { return module.BindCommand(r, taskv1.TemplateUse, policy, store, s.useTemplate) },
	} {
		if err := bind(); err != nil {
			return err
		}
	}
	return nil
}

