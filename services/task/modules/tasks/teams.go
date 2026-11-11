package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/rpc"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

var teamKey = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,11}$`)
var catalogColor = regexp.MustCompile(`^(#[0-9a-fA-F]{6})?$`)

func invalidCatalog() error {
	return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid Task catalog input"}
}
func catalogConflict() error {
	return &rpc.Error{Code: rpc.CodeConflict, Message: "Task catalog changed or conflicts with existing data"}
}
func catalogError(err error) error {
	if err == nil {
		return nil
	}
	var typed *rpc.Error
	if errors.As(err, &typed) {
		return err
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &rpc.Error{Code: rpc.CodeNotFound, Message: "Task catalog item not found"}
	}
	var sqlErr sqlite3.Error
	if errors.As(err, &sqlErr) && (sqlErr.ExtendedCode == sqlite3.ErrConstraintUnique || sqlErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey) {
		return catalogConflict()
	}
	return unavailable(err)
}
func validCatalog(name, color string) bool {
	return strings.TrimSpace(name) != "" && len(strings.TrimSpace(name)) <= 128 && catalogColor.MatchString(color)
}
func validCategory(category string) bool {
	switch category {
	case "backlog", "todo", "in_progress", "in_review", "done", "cancelled":
		return true
	}
	return false
}
func toTeam(v models.Team) taskv1.Team {
	return taskv1.Team{Scope: taskv1.Scope{WorkspaceID: v.WorkspaceID, RootID: v.RootID}, ID: v.ID, Name: v.Name, Key: v.Key, Description: v.Description, Color: v.Color, Revision: v.Revision, Archived: v.ArchivedAt != nil, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
}
func toStatus(v models.WorkflowStatus) taskv1.WorkflowStatus {
	return taskv1.WorkflowStatus{TeamScope: taskv1.TeamScope{Scope: taskv1.Scope{WorkspaceID: v.WorkspaceID, RootID: v.RootID}, TeamID: v.TeamID}, ID: v.ID, Name: v.Name, Category: v.Category, Color: v.Color, Position: v.Position, IsDefault: v.IsDefault, Revision: v.Revision, Archived: v.ArchivedAt != nil, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
}
func catalogTeam(ctx context.Context, db *gorm.DB, q taskv1.TeamScope) (models.Team, error) {
	var row models.Team
	err := db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL", q.TeamID, q.WorkspaceID, q.RootID).Take(&row).Error
	return row, catalogError(err)
}
func catalogStatus(ctx context.Context, db *gorm.DB, q taskv1.TeamScope, id string) (models.WorkflowStatus, error) {
	var row models.WorkflowStatus
	err := db.WithContext(ctx).Where("id=? AND team_id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL", id, q.TeamID, q.WorkspaceID, q.RootID).Take(&row).Error
	return row, catalogError(err)
}
func (s *Service) catalogChanged(ctx context.Context, tx *gorm.DB, scope taskv1.Scope, kind, id string, revision int64) error {
	cl, _ := rpc.VerifiedClaims(ctx)
	meta, _ := rpc.Metadata(ctx)
	now := time.Now().UTC()
	if err := tx.WithContext(ctx).Exec(`INSERT INTO product_audit(workspace_id,acl_root_id,entity_kind,entity_id,actor,operation,revision,request_id,traceparent,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, scope.WorkspaceID, scope.RootID, kind, id, cl.Subject, cl.Operation, revision, meta.RequestID, meta.Traceparent, now).Error; err != nil {
		return catalogError(err)
	}
	payload, err := json.Marshal(taskv1.CatalogChanged{Scope: scope, EntityKind: kind, EntityID: id, Revision: revision})
	if err != nil {
		return unavailable(err)
	}
	return (events.Store{DB: s.GormDB}).Enqueue(ctx, tx, s.Contract, taskv1.CatalogChangedSubject, events.Envelope{ID: NewID(), Type: taskv1.CatalogChangedName, Version: 1, AggregateID: id, OccurredAt: now, Traceparent: meta.Traceparent, Payload: payload})
}
func (s *Service) createTeam(ctx context.Context, tx *gorm.DB, q taskv1.TeamCreateRequest) (taskv1.Team, error) {
	if !validCatalog(q.Name, q.Color) || !teamKey.MatchString(q.Key) || len(q.Description) > 12000 {
		return taskv1.Team{}, invalidCatalog()
	}
	now := time.Now().UTC()
	row := models.Team{ID: NewID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID, Name: strings.TrimSpace(q.Name), Key: q.Key, Description: q.Description, Color: q.Color, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
		return taskv1.Team{}, catalogError(err)
	}
	for i, category := range []string{"backlog", "todo", "in_progress", "in_review", "done", "cancelled"} {
		names := []string{"Backlog", "Todo", "In progress", "In review", "Done", "Cancelled"}
		status := models.WorkflowStatus{ID: NewID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID, TeamID: row.ID, Name: names[i], Category: category, Position: i, IsDefault: i == 0, Revision: 1, CreatedAt: now, UpdatedAt: now}
		if err := tx.WithContext(ctx).Create(&status).Error; err != nil {
			return taskv1.Team{}, catalogError(err)
		}
	}
	return toTeam(row), s.catalogChanged(ctx, tx, q.Scope, "team", row.ID, row.Revision)
}
func (s *Service) updateTeam(ctx context.Context, tx *gorm.DB, q taskv1.TeamUpdateRequest) (taskv1.Team, error) {
	if !validCatalog(q.Name, q.Color) || q.Revision < 1 || len(q.Description) > 12000 {
		return taskv1.Team{}, invalidCatalog()
	}
	row, err := catalogTeam(ctx, tx, q.TeamScope)
	if err != nil {
		return taskv1.Team{}, err
	}
	if row.Revision != q.Revision {
		return taskv1.Team{}, catalogConflict()
	}
	row.Name, row.Description, row.Color = strings.TrimSpace(q.Name), q.Description, q.Color
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.Team{}, catalogError(err)
	}
	return toTeam(row), s.catalogChanged(ctx, tx, q.Scope, "team", row.ID, row.Revision)
}
func (s *Service) archiveTeam(ctx context.Context, tx *gorm.DB, q taskv1.TeamArchiveRequest) (taskv1.ArchivedItem, error) {
	row, err := catalogTeam(ctx, tx, q.TeamScope)
	if err != nil {
		return taskv1.ArchivedItem{}, err
	}
	if q.Revision < 1 {
		return taskv1.ArchivedItem{}, invalidCatalog()
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
	return taskv1.ArchivedItem{Scope: q.Scope, ID: row.ID, Revision: row.Revision, Archived: true, UpdatedAt: row.UpdatedAt}, s.catalogChanged(ctx, tx, q.Scope, "team", row.ID, row.Revision)
}
func (s *Service) getTeam(ctx context.Context, q taskv1.TeamScope) (taskv1.Team, error) {
	row, err := catalogTeam(ctx, s.GormDB, q)
	return toTeam(row), err
}
func (s *Service) listTeams(ctx context.Context, q taskv1.CatalogPage) (taskv1.TeamsResult, error) {
	out := taskv1.TeamsResult{Teams: []taskv1.Team{}}
	if q.Limit < 1 || q.Limit > 100 {
		return out, invalidCatalog()
	}
	var rows []models.Team
	if err := s.GormDB.WithContext(ctx).Where("workspace_id=? AND acl_root_id=? AND archived_at IS NULL AND id>?", q.WorkspaceID, q.RootID, q.Cursor).Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, catalogError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	size := 0
	for _, row := range rows {
		item := toTeam(row)
		raw, err := json.Marshal(item)
		if err != nil {
			return out, unavailable(err)
		}
		if size+len(raw) > 180000 && len(out.Teams) > 0 {
			out.NextCursor = out.Teams[len(out.Teams)-1].ID
			break
		}
		size += len(raw)
		out.Teams = append(out.Teams, item)
	}
	return out, nil
}
func setDefault(ctx context.Context, tx *gorm.DB, team, id string) error {
	return tx.WithContext(ctx).Model(&models.WorkflowStatus{}).Where("team_id=? AND id<>? AND is_default=1 AND archived_at IS NULL", team, id).Updates(map[string]any{"is_default": false, "revision": gorm.Expr("revision+1"), "updated_at": time.Now().UTC()}).Error
}
func (s *Service) createStatus(ctx context.Context, tx *gorm.DB, q taskv1.StatusCreateRequest) (taskv1.WorkflowStatus, error) {
	if !validCatalog(q.Name, q.Color) || !validCategory(q.Category) || q.Position < 0 || q.Position > 1000000 {
		return taskv1.WorkflowStatus{}, invalidCatalog()
	}
	if _, err := catalogTeam(ctx, tx, q.TeamScope); err != nil {
		return taskv1.WorkflowStatus{}, err
	}
	var count int64
	if err := tx.WithContext(ctx).Model(&models.WorkflowStatus{}).Where("team_id=? AND archived_at IS NULL", q.TeamID).Count(&count).Error; err != nil {
		return taskv1.WorkflowStatus{}, catalogError(err)
	}
	if count >= 100 {
		return taskv1.WorkflowStatus{}, catalogConflict()
	}
	now := time.Now().UTC()
	row := models.WorkflowStatus{ID: NewID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID, TeamID: q.TeamID, Name: strings.TrimSpace(q.Name), Category: q.Category, Color: q.Color, Position: q.Position, IsDefault: q.IsDefault, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if q.IsDefault {
		if err := setDefault(ctx, tx, q.TeamID, row.ID); err != nil {
			return taskv1.WorkflowStatus{}, catalogError(err)
		}
	}
	if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
		return taskv1.WorkflowStatus{}, catalogError(err)
	}
	return toStatus(row), s.catalogChanged(ctx, tx, q.Scope, "status", row.ID, row.Revision)
}
func (s *Service) updateStatus(ctx context.Context, tx *gorm.DB, q taskv1.StatusUpdateRequest) (taskv1.WorkflowStatus, error) {
	if !validCatalog(q.Name, q.Color) || !validCategory(q.Category) || q.Position < 0 || q.Position > 1000000 || q.Revision < 1 {
		return taskv1.WorkflowStatus{}, invalidCatalog()
	}
	if _, err := catalogTeam(ctx, tx, q.TeamScope); err != nil {
		return taskv1.WorkflowStatus{}, err
	}
	row, err := catalogStatus(ctx, tx, q.TeamScope, q.StatusID)
	if err != nil {
		return taskv1.WorkflowStatus{}, err
	}
	if row.Revision != q.Revision || row.IsDefault && !q.IsDefault {
		return taskv1.WorkflowStatus{}, catalogConflict()
	}
	if q.IsDefault {
		if err := setDefault(ctx, tx, q.TeamID, row.ID); err != nil {
			return taskv1.WorkflowStatus{}, catalogError(err)
		}
	}
	row.Name, row.Category, row.Color, row.Position, row.IsDefault = strings.TrimSpace(q.Name), q.Category, q.Color, q.Position, q.IsDefault
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.WorkflowStatus{}, catalogError(err)
	}
	return toStatus(row), s.catalogChanged(ctx, tx, q.Scope, "status", row.ID, row.Revision)
}
func (s *Service) deleteStatus(ctx context.Context, tx *gorm.DB, q taskv1.StatusDeleteRequest) (taskv1.ArchivedItem, error) {
	if _, err := catalogTeam(ctx, tx, q.TeamScope); err != nil {
		return taskv1.ArchivedItem{}, err
	}
	row, err := catalogStatus(ctx, tx, q.TeamScope, q.StatusID)
	if err != nil {
		return taskv1.ArchivedItem{}, err
	}
	if q.Revision < 1 {
		return taskv1.ArchivedItem{}, invalidCatalog()
	}
	if row.Revision != q.Revision || row.IsDefault {
		return taskv1.ArchivedItem{}, catalogConflict()
	}
	var used int64
	if err := tx.WithContext(ctx).Model(&models.TaskDetails{}).Where("status_id=? AND archived_at IS NULL", row.ID).Count(&used).Error; err != nil {
		return taskv1.ArchivedItem{}, catalogError(err)
	}
	if used > 0 {
		return taskv1.ArchivedItem{}, catalogConflict()
	}
	now := time.Now().UTC()
	row.ArchivedAt = &now
	row.UpdatedAt = now
	row.Revision++
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.ArchivedItem{}, catalogError(err)
	}
	return taskv1.ArchivedItem{Scope: q.Scope, ID: row.ID, TeamID: q.TeamID, Revision: row.Revision, Archived: true, UpdatedAt: row.UpdatedAt}, s.catalogChanged(ctx, tx, q.Scope, "status", row.ID, row.Revision)
}
func (s *Service) listStatuses(ctx context.Context, q taskv1.TeamScope) (taskv1.StatusesResult, error) {
	out := taskv1.StatusesResult{Statuses: []taskv1.WorkflowStatus{}}
	if _, err := catalogTeam(ctx, s.GormDB, q); err != nil {
		return out, err
	}
	var rows []models.WorkflowStatus
	if err := s.GormDB.WithContext(ctx).Where("team_id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL", q.TeamID, q.WorkspaceID, q.RootID).Order("position,id").Find(&rows).Error; err != nil {
		return out, catalogError(err)
	}
	for _, row := range rows {
		out.Statuses = append(out.Statuses, toStatus(row))
	}
	return out, nil
}
func (s *Service) bindTeams(r *module.Registry, policy module.Policy, store events.Store) error {
	for _, bind := range []func() error{
		func() error { return module.BindCommand(r, taskv1.TeamCreate, policy, store, s.createTeam) },
		func() error { return module.BindCommand(r, taskv1.TeamUpdate, policy, store, s.updateTeam) },
		func() error { return module.BindCommand(r, taskv1.TeamArchive, policy, store, s.archiveTeam) },
		func() error { return module.BindQuery(r, taskv1.TeamGet, policy, s.getTeam) },
		func() error { return module.BindQuery(r, taskv1.TeamList, policy, s.listTeams) },
		func() error { return module.BindCommand(r, taskv1.StatusCreate, policy, store, s.createStatus) },
		func() error { return module.BindCommand(r, taskv1.StatusUpdate, policy, store, s.updateStatus) },
		func() error { return module.BindCommand(r, taskv1.StatusDelete, policy, store, s.deleteStatus) },
		func() error { return module.BindQuery(r, taskv1.StatusList, policy, s.listStatuses) },
	} {
		if err := bind(); err != nil {
			return err
		}
	}
	return nil
}
