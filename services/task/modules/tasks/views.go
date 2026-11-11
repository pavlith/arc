package tasks

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/security"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

func viewRow(ctx context.Context, db *gorm.DB, q taskv1.ViewScope) (models.SavedView, error) {
	var row models.SavedView
	err := db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL AND (owner_id=? OR is_shared=1)", q.ViewID, q.WorkspaceID, q.RootID, actorUserID(ctx)).Take(&row).Error
	return row, catalogError(err)
}
func toView(v models.SavedView) (taskv1.SavedView, error) {
	var filters taskv1.ViewFilters
	if json.Unmarshal([]byte(v.Filters), &filters) != nil {
		return taskv1.SavedView{}, security.ErrUnavailable
	}
	return taskv1.SavedView{Scope: taskv1.Scope{WorkspaceID: v.WorkspaceID, RootID: v.RootID}, ViewInput: taskv1.ViewInput{Name: v.Name, Description: v.Description, Filters: filters, IsShared: v.IsShared}, ID: v.ID, OwnerID: v.OwnerID, Revision: v.Revision, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}, nil
}
func (s *Service) validateView(ctx context.Context, tx *gorm.DB, scope taskv1.Scope, q taskv1.ViewInput) (taskv1.ViewInput, error) {
	q.Name = strings.TrimSpace(q.Name)
	if q.Name == "" || len(q.Name) > 128 || len(q.Description) > 4000 {
		return q, invalidWork()
	}
	f := &q.Filters
	if f.Layout == "" {
		f.Layout = "list"
	}
	if f.GroupBy == "" {
		f.GroupBy = "status"
	}
	if f.Sort == "" {
		f.Sort = "position"
	}
	if f.Layout != "list" && f.Layout != "board" {
		return q, invalidWork()
	}
	switch f.GroupBy {
	case "status", "priority", "assignee", "project", "none":
	default:
		return q, invalidWork()
	}
	switch f.Sort {
	case "position", "priority", "updated_at", "title":
	default:
		return q, invalidWork()
	}
	if f.Priority != nil && (*f.Priority < 0 || *f.Priority > 4) || len(f.Search) > 300 {
		return q, invalidWork()
	}
	if f.TeamID != "" {
		if _, err := catalogTeam(ctx, tx, taskv1.TeamScope{Scope: scope, TeamID: f.TeamID}); err != nil {
			return q, err
		}
	}
	if f.StatusID != "" {
		var row models.WorkflowStatus
		if err := tx.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL", f.StatusID, scope.WorkspaceID, scope.RootID).Take(&row).Error; err != nil {
			return q, catalogError(err)
		}
		if f.TeamID != "" && f.TeamID != row.TeamID {
			return q, invalidWork()
		}
	}
	if f.ProjectID != "" {
		row, err := catalogProject(ctx, tx, scope, f.ProjectID)
		if err != nil {
			return q, err
		}
		if row.ArchivedAt != nil || f.TeamID != "" && row.TeamID != nil && *row.TeamID != f.TeamID {
			return q, invalidWork()
		}
	}
	if f.LabelID != "" {
		row, err := catalogLabel(ctx, tx, scope, f.LabelID)
		if err != nil {
			return q, err
		}
		if row.ArchivedAt != nil {
			return q, invalidWork()
		}
	}
	if f.AssigneeID != "" {
		if err := s.validateAssignees(ctx, scope, []string{f.AssigneeID}); err != nil {
			return q, err
		}
	}
	return q, nil
}
func (s *Service) createView(ctx context.Context, tx *gorm.DB, q taskv1.ViewCreateRequest) (taskv1.SavedView, error) {
	in, err := s.validateView(ctx, tx, q.Scope, q.ViewInput)
	if err != nil {
		return taskv1.SavedView{}, err
	}
	raw, err := json.Marshal(in.Filters)
	if err != nil {
		return taskv1.SavedView{}, unavailable(err)
	}
	now := time.Now().UTC()
	row := models.SavedView{ID: NewID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID, OwnerID: actorUserID(ctx), Name: in.Name, Description: in.Description, Filters: string(raw), IsShared: in.IsShared, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
		return taskv1.SavedView{}, catalogError(err)
	}
	if err := s.catalogChange(ctx, tx, q.Scope, "view", row.ID, row.Revision, row.IsShared, "created"); err != nil {
		return taskv1.SavedView{}, err
	}
	return toView(row)
}
func (s *Service) updateView(ctx context.Context, tx *gorm.DB, q taskv1.ViewUpdateRequest) (taskv1.SavedView, error) {
	row, err := viewRow(ctx, tx, q.ViewScope)
	if err != nil {
		return taskv1.SavedView{}, err
	}
	if row.OwnerID != actorUserID(ctx) {
		return taskv1.SavedView{}, security.ErrDenied
	}
	if q.Revision < 1 {
		return taskv1.SavedView{}, invalidWork()
	}
	if row.Revision != q.Revision {
		return taskv1.SavedView{}, catalogConflict()
	}
	in, err := s.validateView(ctx, tx, q.Scope, q.ViewInput)
	if err != nil {
		return taskv1.SavedView{}, err
	}
	raw, err := json.Marshal(in.Filters)
	if err != nil {
		return taskv1.SavedView{}, unavailable(err)
	}
	emit := row.IsShared || in.IsShared
	row.Name, row.Description, row.Filters, row.IsShared = in.Name, in.Description, string(raw), in.IsShared
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.SavedView{}, catalogError(err)
	}
	if err := s.catalogChange(ctx, tx, q.Scope, "view", row.ID, row.Revision, emit, "definition"); err != nil {
		return taskv1.SavedView{}, err
	}
	return toView(row)
}
func (s *Service) archiveView(ctx context.Context, tx *gorm.DB, q taskv1.ViewArchiveRequest) (taskv1.ArchivedItem, error) {
	row, err := viewRow(ctx, tx, q.ViewScope)
	if err != nil {
		return taskv1.ArchivedItem{}, err
	}
	if row.OwnerID != actorUserID(ctx) {
		return taskv1.ArchivedItem{}, security.ErrDenied
	}
	if q.Revision < 1 {
		return taskv1.ArchivedItem{}, invalidWork()
	}
	if row.Revision != q.Revision {
		return taskv1.ArchivedItem{}, catalogConflict()
	}
	now := time.Now().UTC()
	row.ArchivedAt = &now
	row.UpdatedAt = now
	row.Revision++
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.ArchivedItem{}, catalogError(err)
	}
	return taskv1.ArchivedItem{Scope: q.Scope, ID: row.ID, Revision: row.Revision, Archived: true, UpdatedAt: now}, s.catalogChange(ctx, tx, q.Scope, "view", row.ID, row.Revision, row.IsShared, "archived")
}
func (s *Service) getView(ctx context.Context, q taskv1.ViewScope) (taskv1.SavedView, error) {
	row, err := viewRow(ctx, s.GormDB, q)
	if err != nil {
		return taskv1.SavedView{}, err
	}
	return toView(row)
}
func (s *Service) listViews(ctx context.Context, q taskv1.CatalogPage) (taskv1.ViewsResult, error) {
	out := taskv1.ViewsResult{Views: []taskv1.SavedView{}}
	if q.Limit < 1 || q.Limit > 100 {
		return out, invalidWork()
	}
	var rows []models.SavedView
	if err := s.GormDB.WithContext(ctx).Where("workspace_id=? AND acl_root_id=? AND archived_at IS NULL AND id>? AND (owner_id=? OR is_shared=1)", q.WorkspaceID, q.RootID, q.Cursor, actorUserID(ctx)).Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, catalogError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	size := 0
	for _, row := range rows {
		item, err := toView(row)
		if err != nil {
			return out, err
		}
		raw, err := json.Marshal(item)
		if err != nil {
			return out, unavailable(err)
		}
		if size+len(raw) > 180000 && len(out.Views) > 0 {
			out.NextCursor = out.Views[len(out.Views)-1].ID
			break
		}
		size += len(raw)
		out.Views = append(out.Views, item)
	}
	return out, nil
}
func (s *Service) bindViews(r *module.Registry, policy module.Policy, store events.Store) error {
	for _, bind := range []func() error{
		func() error { return module.BindCommand(r, taskv1.ViewCreate, policy, store, s.createView) }, func() error { return module.BindCommand(r, taskv1.ViewUpdate, policy, store, s.updateView) }, func() error { return module.BindCommand(r, taskv1.ViewArchive, policy, store, s.archiveView) }, func() error { return module.BindQuery(r, taskv1.ViewGet, policy, s.getView) }, func() error { return module.BindQuery(r, taskv1.ViewList, policy, s.listViews) },
	} {
		if err := bind(); err != nil {
			return err
		}
	}
	return nil
}
