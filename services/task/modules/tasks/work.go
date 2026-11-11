package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

func invalidWork() error {
	return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid Task work item input"}
}
func validateWork(q taskv1.WorkInput) error {
	if len(q.LabelIDs) > 50 {
		return invalidWork()
	}
	labels := map[string]bool{}
	for _, id := range q.LabelIDs {
		if id == "" || labels[id] {
			return invalidWork()
		}
		labels[id] = true
	}
	if strings.TrimSpace(q.Title) == "" || len(strings.TrimSpace(q.Title)) > 300 || len(q.Description) > 60000 || q.Priority < 0 || q.Priority > 4 || q.SortOrder < 0 || q.SortOrder > 1000000000000 || len(q.AssigneeIDs) > 20 {
		return invalidWork()
	}
	encoded, err := json.Marshal(q)
	if err != nil || len(encoded) > 160000 {
		return invalidWork()
	}
	seen := map[string]bool{}
	for _, id := range q.AssigneeIDs {
		if id == "" || seen[id] {
			return invalidWork()
		}
		seen[id] = true
	}
	return nil
}
func (s *Service) validateAssignees(ctx context.Context, scope taskv1.Scope, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	ctx, err := InvocationContext(ctx, s.Identity, identity.Target{Audience: "access/v1", Operation: "access.v1.principals.validate_users"})
	if err != nil {
		return err
	}
	res, err := (&access.Client{RPC: s.Identity.RPC}).ValidateUsers(ctx, access.ValidateUsersRequest{ResourceID: scope.RootID, ActorAction: "task.create", UserAction: "task.read", UserIDs: ids})
	if err != nil {
		return err
	}
	if !res.Valid {
		return security.ErrDenied
	}
	return nil
}
func workStatus(ctx context.Context, db *gorm.DB, scope taskv1.Scope, q taskv1.WorkInput) (models.Team, models.WorkflowStatus, error) {
	ts := taskv1.TeamScope{Scope: scope, TeamID: q.TeamID}
	team, err := catalogTeam(ctx, db, ts)
	if err != nil {
		return team, models.WorkflowStatus{}, err
	}
	if q.StatusID != "" {
		status, err := catalogStatus(ctx, db, ts, q.StatusID)
		return team, status, err
	}
	var status models.WorkflowStatus
	err = db.WithContext(ctx).Where("team_id=? AND workspace_id=? AND acl_root_id=? AND is_default=1 AND archived_at IS NULL", q.TeamID, scope.WorkspaceID, scope.RootID).Take(&status).Error
	return team, status, catalogError(err)
}
func replaceAssignees(ctx context.Context, tx *gorm.DB, id string, users []string) error {
	if err := tx.WithContext(ctx).Where("task_id=?", id).Delete(&models.TaskAssignee{}).Error; err != nil {
		return catalogError(err)
	}
	for _, uid := range users {
		if err := tx.WithContext(ctx).Create(&models.TaskAssignee{TaskID: id, UserID: uid}).Error; err != nil {
			return catalogError(err)
		}
	}
	return nil
}
func workItem(ctx context.Context, db *gorm.DB, q taskv1.GetRequest) (taskv1.WorkItem, error) {
	var row models.Task
	if err := db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=?", q.TaskID, q.WorkspaceID, q.RootID).Take(&row).Error; err != nil {
		return taskv1.WorkItem{}, catalogError(err)
	}
	out := taskv1.WorkItem{Task: toTask(row), Identifier: row.ID, AssigneeIDs: []string{}, LabelIDs: []string{}, Revision: 1}
	var detail models.TaskDetails
	err := db.WithContext(ctx).Where("task_id=? AND workspace_id=? AND acl_root_id=?", row.ID, q.WorkspaceID, q.RootID).Take(&detail).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return out, nil
	}
	if err != nil {
		return out, catalogError(err)
	}
	if detail.ArchivedAt != nil {
		return out, &rpc.Error{Code: rpc.CodeNotFound, Message: "Task is archived"}
	}
	_, status, err := workStatus(ctx, db, q.Scope, taskv1.WorkInput{TeamID: detail.TeamID, StatusID: detail.StatusID})
	if err != nil {
		return out, err
	}
	var parents []struct{ ParentID string }
	if err := db.WithContext(ctx).Table("task_parents").Select("parent_id").Where("task_id=? AND workspace_id=? AND acl_root_id=?", row.ID, q.WorkspaceID, q.RootID).Scan(&parents).Error; err != nil {
		return out, catalogError(err)
	}
	if len(parents) > 0 {
		out.ParentID = parents[0].ParentID
	}
	out.Status = status.Category
	out.TeamID = detail.TeamID
	out.StatusID = detail.StatusID
	out.Identifier = detail.Identifier
	out.Description = detail.Description
	out.Priority = detail.Priority
	out.DueDate = detail.DueDate
	out.SortOrder = detail.SortOrder
	out.Revision = detail.Revision
	if detail.ProjectID != nil {
		out.ProjectID = *detail.ProjectID
	}
	if err := db.WithContext(ctx).Model(&models.TaskLabel{}).Where("task_id=?", row.ID).Order("label_id").Pluck("label_id", &out.LabelIDs).Error; err != nil {
		return out, catalogError(err)
	}
	if err := db.WithContext(ctx).Model(&models.TaskAssignee{}).Where("task_id=?", row.ID).Order("user_id").Pluck("user_id", &out.AssigneeIDs).Error; err != nil {
		return out, catalogError(err)
	}
	return out, nil
}
func (s *Service) createWork(ctx context.Context, tx *gorm.DB, q taskv1.WorkCreateRequest) (taskv1.WorkItem, error) {
	if err := validateWork(q.WorkInput); err != nil {
		return taskv1.WorkItem{}, err
	}
	team, status, err := workStatus(ctx, tx, q.Scope, q.WorkInput)
	if err != nil {
		return taskv1.WorkItem{}, err
	}
	if err := s.validateAssignees(ctx, q.Scope, q.AssigneeIDs); err != nil {
		return taskv1.WorkItem{}, err
	}
	base, err := s.createGORM(ctx, tx, taskv1.CreateRequest{Scope: q.Scope, Title: strings.TrimSpace(q.Title)})
	if err != nil {
		return taskv1.WorkItem{}, err
	}
	var number int64
	if err := tx.WithContext(ctx).Raw("UPDATE teams SET sequence=sequence+1 WHERE id=? RETURNING sequence", team.ID).Row().Scan(&number); err != nil {
		return taskv1.WorkItem{}, catalogError(err)
	}
	detail := models.TaskDetails{TaskID: base.ID, WorkspaceID: q.WorkspaceID, RootID: q.RootID, TeamID: team.ID, StatusID: status.ID, Identifier: fmt.Sprintf("%s-%d", team.Key, number), Description: q.Description, Priority: q.Priority, DueDate: q.DueDate, SortOrder: q.SortOrder, Revision: 1}
	if err := tx.WithContext(ctx).Create(&detail).Error; err != nil {
		return taskv1.WorkItem{}, catalogError(err)
	}
	if err := replaceAssignees(ctx, tx, base.ID, q.AssigneeIDs); err != nil {
		return taskv1.WorkItem{}, err
	}
	if err := setWorkReferences(ctx, tx, taskv1.GetRequest{Scope: q.Scope, TaskID: base.ID}, q.WorkInput, taskv1.WorkItem{}); err != nil {
		return taskv1.WorkItem{}, err
	}
	if err := s.catalogChanged(ctx, tx, q.Scope, "work", base.ID, detail.Revision, "created"); err != nil {
		return taskv1.WorkItem{}, err
	}
	return workItem(ctx, tx, taskv1.GetRequest{Scope: q.Scope, TaskID: base.ID})
}
func (s *Service) updateWork(ctx context.Context, tx *gorm.DB, q taskv1.WorkUpdateRequest) (taskv1.WorkItem, error) {
	if err := validateWork(q.WorkInput); err != nil {
		return taskv1.WorkItem{}, err
	}
	current, err := workItem(ctx, tx, q.GetRequest)
	if err != nil {
		return taskv1.WorkItem{}, err
	}
	if q.Revision < 1 || q.ExpectedUpdatedAt.IsZero() {
		return taskv1.WorkItem{}, invalidWork()
	}
	if current.Revision != q.Revision || !current.UpdatedAt.Equal(q.ExpectedUpdatedAt) {
		return taskv1.WorkItem{}, catalogConflict()
	}
	team, status, err := workStatus(ctx, tx, q.Scope, q.WorkInput)
	if err != nil {
		return taskv1.WorkItem{}, err
	}
	if err := s.validateAssignees(ctx, q.Scope, q.AssigneeIDs); err != nil {
		return taskv1.WorkItem{}, err
	}
	var detail models.TaskDetails
	err = tx.WithContext(ctx).Where("task_id=?", q.TaskID).Take(&detail).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var number int64
		if err := tx.WithContext(ctx).Raw("UPDATE teams SET sequence=sequence+1 WHERE id=? RETURNING sequence", team.ID).Row().Scan(&number); err != nil {
			return taskv1.WorkItem{}, catalogError(err)
		}
		detail = models.TaskDetails{TaskID: q.TaskID, WorkspaceID: q.WorkspaceID, RootID: q.RootID, Identifier: fmt.Sprintf("%s-%d", team.Key, number)}
	} else if err != nil {
		return taskv1.WorkItem{}, catalogError(err)
	}
	detail.TeamID = team.ID
	detail.ProjectID = nil // References are checked against the new Team before being restored below.
	detail.StatusID = status.ID
	detail.Description = q.Description
	detail.Priority = q.Priority
	detail.DueDate = q.DueDate
	detail.SortOrder = q.SortOrder
	detail.Revision = q.Revision + 1
	if err := tx.WithContext(ctx).Save(&detail).Error; err != nil {
		return taskv1.WorkItem{}, catalogError(err)
	}
	now := time.Now().UTC()
	if !now.After(current.UpdatedAt) {
		now = current.UpdatedAt.Add(time.Nanosecond)
	}
	if err := tx.WithContext(ctx).Model(&models.Task{}).Where("id=? AND workspace_id=? AND acl_root_id=?", q.TaskID, q.WorkspaceID, q.RootID).Updates(map[string]any{"title": strings.TrimSpace(q.Title), "updated_at": now}).Error; err != nil {
		return taskv1.WorkItem{}, catalogError(err)
	}
	if err := replaceAssignees(ctx, tx, q.TaskID, q.AssigneeIDs); err != nil {
		return taskv1.WorkItem{}, err
	}
	if err := setWorkReferences(ctx, tx, q.GetRequest, q.WorkInput, current); err != nil {
		return taskv1.WorkItem{}, err
	}
	updated, err := workItem(ctx, tx, q.GetRequest)
	if err != nil {
		return taskv1.WorkItem{}, err
	}
	return updated, s.catalogChanged(ctx, tx, q.Scope, "work", q.TaskID, detail.Revision, workChangedFields(current, updated)...)
}
func (s *Service) archiveWork(ctx context.Context, tx *gorm.DB, q taskv1.WorkArchiveRequest) (taskv1.ArchivedItem, error) {
	current, err := workItem(ctx, tx, q.GetRequest)
	if err != nil {
		return taskv1.ArchivedItem{}, err
	}
	if q.Revision < 1 || q.ExpectedUpdatedAt.IsZero() {
		return taskv1.ArchivedItem{}, invalidWork()
	}
	if current.TeamID == "" || current.Revision != q.Revision || !current.UpdatedAt.Equal(q.ExpectedUpdatedAt) {
		return taskv1.ArchivedItem{}, catalogConflict()
	}
	now := time.Now().UTC()
	if !now.After(current.UpdatedAt) {
		now = current.UpdatedAt.Add(time.Nanosecond)
	}
	if err := tx.WithContext(ctx).Model(&models.TaskDetails{}).Where("task_id=?", q.TaskID).Updates(map[string]any{"archived_at": now, "revision": q.Revision + 1}).Error; err != nil {
		return taskv1.ArchivedItem{}, catalogError(err)
	}
	if err := tx.WithContext(ctx).Model(&models.Task{}).Where("id=?", q.TaskID).Update("updated_at", now).Error; err != nil {
		return taskv1.ArchivedItem{}, catalogError(err)
	}
	current.Revision++
	current.UpdatedAt = now
	current.Archived = true
	return taskv1.ArchivedItem{Scope: q.Scope, ID: q.TaskID, Revision: current.Revision, Archived: true, UpdatedAt: now}, s.catalogChanged(ctx, tx, q.Scope, "work", q.TaskID, current.Revision, "archived")
}
func workChangedFields(a, b taskv1.WorkItem) []string {
	fields := map[string][2]any{"title": {a.Title, b.Title}, "description": {a.Description, b.Description}, "team_id": {a.TeamID, b.TeamID}, "status_id": {a.StatusID, b.StatusID}, "priority": {a.Priority, b.Priority}, "due_date": {a.DueDate, b.DueDate}, "sort_order": {a.SortOrder, b.SortOrder}, "project_id": {a.ProjectID, b.ProjectID}, "label_ids": {a.LabelIDs, b.LabelIDs}, "assignee_ids": {a.AssigneeIDs, b.AssigneeIDs}}
	out := []string{}
	for name, pair := range fields {
		if !reflect.DeepEqual(pair[0], pair[1]) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
func (s *Service) getWork(ctx context.Context, q taskv1.GetRequest) (taskv1.WorkItem, error) {
	var out taskv1.WorkItem
	err := s.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error { var err error; out, err = workItem(ctx, tx, q); return err })
	return out, catalogError(err)
}
func (s *Service) listWork(ctx context.Context, q taskv1.WorkListRequest) (taskv1.WorkListResult, error) {
	out := taskv1.WorkListResult{Tasks: []taskv1.WorkItem{}}
	if q.TopLevel && q.ParentID != "" {
		return out, invalidWork()
	}
	if q.Limit < 1 || q.Limit > 100 || len(q.Search) > 300 || q.Priority != nil && (*q.Priority < 0 || *q.Priority > 4) {
		return out, invalidWork()
	}
	err := s.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		db := tx.Table("tasks t").Select("t.id").Joins("LEFT JOIN task_details d ON d.task_id=t.id").Joins("LEFT JOIN teams tm ON tm.id=d.team_id").Where("t.workspace_id=? AND t.acl_root_id=? AND t.id>? AND d.archived_at IS NULL AND (d.team_id IS NULL OR tm.archived_at IS NULL)", q.WorkspaceID, q.RootID, q.Cursor)
		if q.ParentID != "" {
			db = db.Where("EXISTS(SELECT 1 FROM task_parents p WHERE p.task_id=t.id AND p.parent_id=?)", q.ParentID)
		}
		if q.TopLevel {
			db = db.Where("NOT EXISTS(SELECT 1 FROM task_parents p WHERE p.task_id=t.id)")
		}
		if q.TeamID != "" {
			db = db.Where("d.team_id=?", q.TeamID)
		}
		if q.StatusID != "" {
			db = db.Where("d.status_id=?", q.StatusID)
		}
		if q.Priority != nil {
			db = db.Where("COALESCE(d.priority,0)=?", *q.Priority)
		}
		if q.AssigneeID != "" {
			db = db.Where("EXISTS(SELECT 1 FROM task_assignees a WHERE a.task_id=t.id AND a.user_id=?)", q.AssigneeID)
		}
		if q.ProjectID != "" {
			db = db.Where("d.project_id=?", q.ProjectID)
		}
		if q.LabelID != "" {
			db = db.Where("EXISTS(SELECT 1 FROM task_labels l WHERE l.task_id=t.id AND l.label_id=?)", q.LabelID)
		}
		if q.Search != "" {
			db = db.Where("(instr(lower(t.title),lower(?))>0 OR instr(lower(COALESCE(d.description,'')),lower(?))>0)", q.Search, q.Search)
		}
		var ids []string
		if err := db.Order("t.id").Limit(q.Limit+1).Pluck("t.id", &ids).Error; err != nil {
			return err
		}
		if len(ids) > q.Limit {
			ids = ids[:q.Limit]
			out.NextCursor = ids[len(ids)-1]
		}
		size := 0
		for _, id := range ids {
			row, err := workItem(ctx, tx, taskv1.GetRequest{Scope: q.Scope, TaskID: id})
			if err != nil {
				return err
			}
			raw, err := json.Marshal(row)
			if err != nil {
				return err
			}
			if size+len(raw) > 180000 && len(out.Tasks) > 0 {
				out.NextCursor = out.Tasks[len(out.Tasks)-1].ID
				break
			}
			size += len(raw)
			out.Tasks = append(out.Tasks, row)
		}
		return nil
	})
	return out, catalogError(err)
}
func (s *Service) bindWork(r *module.Registry, policy module.Policy, store events.Store) error {
	for _, bind := range []func() error{
		func() error { return module.BindCommand(r, taskv1.WorkSetParent, policy, store, s.setParent) },
		func() error { return module.BindCommand(r, taskv1.WorkCreate, policy, store, s.createWork) },
		func() error { return module.BindCommand(r, taskv1.WorkUpdate, policy, store, s.updateWork) },
		func() error { return module.BindCommand(r, taskv1.WorkArchive, policy, store, s.archiveWork) },
		func() error { return module.BindQuery(r, taskv1.WorkGet, policy, s.getWork) },
		func() error { return module.BindQuery(r, taskv1.WorkList, policy, s.listWork) },
	} {
		if err := bind(); err != nil {
			return err
		}
	}
	return nil
}
