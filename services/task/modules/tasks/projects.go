package tasks

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

func toProject(v models.Project) taskv1.Project {
	p := taskv1.Project{Scope: taskv1.Scope{WorkspaceID: v.WorkspaceID, RootID: v.RootID}, ProjectInput: taskv1.ProjectInput{Name: v.Name, Description: v.Description, Color: v.Color, Status: v.Status, StartDate: v.StartDate, DueDate: v.DueDate}, ID: v.ID, Revision: v.Revision, Archived: v.ArchivedAt != nil, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
	if v.TeamID != nil {
		p.TeamID = *v.TeamID
	}
	return p
}
func toLabel(v models.Label) taskv1.Label {
	return taskv1.Label{Scope: taskv1.Scope{WorkspaceID: v.WorkspaceID, RootID: v.RootID}, LabelInput: taskv1.LabelInput{Name: v.Name, Color: v.Color}, ID: v.ID, Revision: v.Revision, Archived: v.ArchivedAt != nil, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
}
func catalogProject(ctx context.Context, db *gorm.DB, scope taskv1.Scope, id string) (models.Project, error) {
	var row models.Project
	err := db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=?", id, scope.WorkspaceID, scope.RootID).Take(&row).Error
	return row, catalogError(err)
}
func catalogLabel(ctx context.Context, db *gorm.DB, scope taskv1.Scope, id string) (models.Label, error) {
	var row models.Label
	err := db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=?", id, scope.WorkspaceID, scope.RootID).Take(&row).Error
	return row, catalogError(err)
}
func projectInput(q taskv1.ProjectInput) (taskv1.ProjectInput, error) {
	q.Name = strings.TrimSpace(q.Name)
	if q.Status == "" {
		q.Status = "planned"
	}
	if !validCatalog(q.Name, q.Color) || len(q.Description) > 12000 || q.StartDate != nil && q.DueDate != nil && q.StartDate.After(*q.DueDate) {
		return q, invalidCatalog()
	}
	switch q.Status {
	case "planned", "active", "paused", "completed", "cancelled":
	default:
		return q, invalidCatalog()
	}
	return q, nil
}
func (s *Service) createProject(ctx context.Context, tx *gorm.DB, q taskv1.ProjectCreateRequest) (taskv1.Project, error) {
	in, err := projectInput(q.ProjectInput)
	if err != nil {
		return taskv1.Project{}, err
	}
	var team *string
	if q.TeamID != "" {
		if _, err := catalogTeam(ctx, tx, taskv1.TeamScope{Scope: q.Scope, TeamID: q.TeamID}); err != nil {
			return taskv1.Project{}, err
		}
		team = &q.TeamID
	}
	now := time.Now().UTC()
	row := models.Project{ID: NewID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID, TeamID: team, Name: in.Name, Description: in.Description, Color: in.Color, Status: in.Status, StartDate: in.StartDate, DueDate: in.DueDate, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
		return taskv1.Project{}, catalogError(err)
	}
	return toProject(row), s.catalogChanged(ctx, tx, q.Scope, "project", row.ID, row.Revision)
}
func (s *Service) updateProject(ctx context.Context, tx *gorm.DB, q taskv1.ProjectUpdateRequest) (taskv1.Project, error) {
	in, err := projectInput(q.ProjectInput)
	if err != nil {
		return taskv1.Project{}, err
	}
	row, err := catalogProject(ctx, tx, q.Scope, q.ProjectID)
	if err != nil {
		return taskv1.Project{}, err
	}
	oldTeam := ""
	if row.TeamID != nil {
		oldTeam = *row.TeamID
	}
	if q.Revision < 1 {
		return taskv1.Project{}, invalidCatalog()
	}
	if row.ArchivedAt != nil || row.Revision != q.Revision || oldTeam != q.TeamID {
		return taskv1.Project{}, catalogConflict()
	}
	row.Name, row.Description, row.Color, row.Status = in.Name, in.Description, in.Color, in.Status
	row.StartDate, row.DueDate = in.StartDate, in.DueDate
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.Project{}, catalogError(err)
	}
	return toProject(row), s.catalogChanged(ctx, tx, q.Scope, "project", row.ID, row.Revision)
}
func (s *Service) archiveProject(ctx context.Context, tx *gorm.DB, q taskv1.ProjectArchiveRequest) (taskv1.ArchivedItem, error) {
	row, err := catalogProject(ctx, tx, q.Scope, q.ProjectID)
	if err != nil {
		return taskv1.ArchivedItem{}, err
	}
	if q.Revision < 1 {
		return taskv1.ArchivedItem{}, invalidCatalog()
	}
	if row.ArchivedAt != nil || row.Revision != q.Revision {
		return taskv1.ArchivedItem{}, catalogConflict()
	}
	now := time.Now().UTC()
	row.ArchivedAt = &now
	row.UpdatedAt = now
	row.Revision++
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.ArchivedItem{}, catalogError(err)
	}
	return taskv1.ArchivedItem{Scope: q.Scope, ID: row.ID, Revision: row.Revision, Archived: true, UpdatedAt: now}, s.catalogChanged(ctx, tx, q.Scope, "project", row.ID, row.Revision)
}
func (s *Service) getProject(ctx context.Context, q taskv1.ProjectScope) (taskv1.Project, error) {
	row, err := catalogProject(ctx, s.GormDB, q.Scope, q.ProjectID)
	return toProject(row), err
}
func (s *Service) listProjects(ctx context.Context, q taskv1.ProjectListRequest) (taskv1.ProjectsResult, error) {
	out := taskv1.ProjectsResult{Projects: []taskv1.Project{}}
	if q.Limit < 1 || q.Limit > 100 {
		return out, invalidCatalog()
	}
	var rows []models.Project
	db := s.GormDB.WithContext(ctx).Where("workspace_id=? AND acl_root_id=? AND archived_at IS NULL AND id>?", q.WorkspaceID, q.RootID, q.Cursor)
	if q.TeamID != "" {
		db = db.Where("team_id=?", q.TeamID)
	}
	if err := db.Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, catalogError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	size := 0
	for _, row := range rows {
		item := toProject(row)
		raw, err := json.Marshal(item)
		if err != nil {
			return out, unavailable(err)
		}
		if size+len(raw) > 180000 && len(out.Projects) > 0 {
			out.NextCursor = out.Projects[len(out.Projects)-1].ID
			break
		}
		size += len(raw)
		out.Projects = append(out.Projects, item)
	}
	return out, nil
}
func (s *Service) createLabel(ctx context.Context, tx *gorm.DB, q taskv1.LabelCreateRequest) (taskv1.Label, error) {
	if !validCatalog(q.Name, q.Color) {
		return taskv1.Label{}, invalidCatalog()
	}
	now := time.Now().UTC()
	row := models.Label{ID: NewID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID, Name: strings.TrimSpace(q.Name), Color: q.Color, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
		return taskv1.Label{}, catalogError(err)
	}
	return toLabel(row), s.catalogChanged(ctx, tx, q.Scope, "label", row.ID, row.Revision)
}
func (s *Service) updateLabel(ctx context.Context, tx *gorm.DB, q taskv1.LabelUpdateRequest) (taskv1.Label, error) {
	if !validCatalog(q.Name, q.Color) || q.Revision < 1 {
		return taskv1.Label{}, invalidCatalog()
	}
	row, err := catalogLabel(ctx, tx, q.Scope, q.LabelID)
	if err != nil {
		return taskv1.Label{}, err
	}
	if row.ArchivedAt != nil || row.Revision != q.Revision {
		return taskv1.Label{}, catalogConflict()
	}
	row.Name, row.Color = strings.TrimSpace(q.Name), q.Color
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.Label{}, catalogError(err)
	}
	return toLabel(row), s.catalogChanged(ctx, tx, q.Scope, "label", row.ID, row.Revision)
}
func (s *Service) archiveLabel(ctx context.Context, tx *gorm.DB, q taskv1.LabelArchiveRequest) (taskv1.ArchivedItem, error) {
	row, err := catalogLabel(ctx, tx, q.Scope, q.LabelID)
	if err != nil {
		return taskv1.ArchivedItem{}, err
	}
	if q.Revision < 1 {
		return taskv1.ArchivedItem{}, invalidCatalog()
	}
	if row.ArchivedAt != nil || row.Revision != q.Revision {
		return taskv1.ArchivedItem{}, catalogConflict()
	}
	now := time.Now().UTC()
	row.ArchivedAt = &now
	row.UpdatedAt = now
	row.Revision++
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.ArchivedItem{}, catalogError(err)
	}
	return taskv1.ArchivedItem{Scope: q.Scope, ID: row.ID, Revision: row.Revision, Archived: true, UpdatedAt: now}, s.catalogChanged(ctx, tx, q.Scope, "label", row.ID, row.Revision)
}
func (s *Service) getLabel(ctx context.Context, q taskv1.LabelScope) (taskv1.Label, error) {
	row, err := catalogLabel(ctx, s.GormDB, q.Scope, q.LabelID)
	return toLabel(row), err
}
func (s *Service) listLabels(ctx context.Context, q taskv1.CatalogPage) (taskv1.LabelsResult, error) {
	out := taskv1.LabelsResult{Labels: []taskv1.Label{}}
	if q.Limit < 1 || q.Limit > 100 {
		return out, invalidCatalog()
	}
	var rows []models.Label
	if err := s.GormDB.WithContext(ctx).Where("workspace_id=? AND acl_root_id=? AND archived_at IS NULL AND id>?", q.WorkspaceID, q.RootID, q.Cursor).Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, catalogError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	for _, row := range rows {
		out.Labels = append(out.Labels, toLabel(row))
	}
	return out, nil
}
func (s *Service) bindProjects(r *module.Registry, policy module.Policy, store events.Store) error {
	for _, bind := range []func() error{
		func() error { return module.BindCommand(r, taskv1.ProjectCreate, policy, store, s.createProject) }, func() error { return module.BindCommand(r, taskv1.ProjectUpdate, policy, store, s.updateProject) }, func() error { return module.BindCommand(r, taskv1.ProjectArchive, policy, store, s.archiveProject) }, func() error { return module.BindQuery(r, taskv1.ProjectGet, policy, s.getProject) }, func() error { return module.BindQuery(r, taskv1.ProjectList, policy, s.listProjects) },
		func() error { return module.BindCommand(r, taskv1.LabelCreate, policy, store, s.createLabel) }, func() error { return module.BindCommand(r, taskv1.LabelUpdate, policy, store, s.updateLabel) }, func() error { return module.BindCommand(r, taskv1.LabelArchive, policy, store, s.archiveLabel) }, func() error { return module.BindQuery(r, taskv1.LabelGet, policy, s.getLabel) }, func() error { return module.BindQuery(r, taskv1.LabelList, policy, s.listLabels) },
	} {
		if err := bind(); err != nil {
			return err
		}
	}
	return nil
}
func setWorkReferences(ctx context.Context, tx *gorm.DB, q taskv1.GetRequest, in taskv1.WorkInput, old taskv1.WorkItem) error {
	var project *string
	if in.ProjectID != "" {
		row, err := catalogProject(ctx, tx, q.Scope, in.ProjectID)
		if err != nil {
			return err
		}
		if row.TeamID != nil && *row.TeamID != in.TeamID {
			return catalogConflict()
		}
		if row.ArchivedAt != nil && old.ProjectID != in.ProjectID {
			return catalogConflict()
		}
		project = &in.ProjectID
	}
	allowedOld := map[string]bool{}
	for _, id := range old.LabelIDs {
		allowedOld[id] = true
	}
	for _, id := range in.LabelIDs {
		label, err := catalogLabel(ctx, tx, q.Scope, id)
		if err != nil {
			return err
		}
		if label.ArchivedAt != nil && !allowedOld[id] {
			return catalogConflict()
		}
	}
	if err := tx.WithContext(ctx).Model(&models.TaskDetails{}).Where("task_id=?", q.TaskID).Update("project_id", project).Error; err != nil {
		return catalogError(err)
	}
	if err := tx.WithContext(ctx).Where("task_id=?", q.TaskID).Delete(&models.TaskLabel{}).Error; err != nil {
		return catalogError(err)
	}
	for _, id := range in.LabelIDs {
		if err := tx.WithContext(ctx).Create(&models.TaskLabel{TaskID: q.TaskID, WorkspaceID: q.WorkspaceID, RootID: q.RootID, LabelID: id}).Error; err != nil {
			return catalogError(err)
		}
	}
	return nil
}
