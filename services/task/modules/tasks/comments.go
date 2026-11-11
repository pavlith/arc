package tasks

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

func actorUserID(ctx context.Context) string {
	cl, _ := rpc.VerifiedClaims(ctx)
	return strings.TrimPrefix(cl.Subject, "user:")
}
func toComment(v models.Comment) taskv1.Comment {
	out := taskv1.Comment{GetRequest: taskv1.GetRequest{Scope: taskv1.Scope{WorkspaceID: v.WorkspaceID, RootID: v.RootID}, TaskID: v.TaskID}, ID: v.ID, AuthorID: v.AuthorID, Body: v.Body, Resolved: v.Resolved, Revision: v.Revision, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
	if v.ParentID != nil {
		out.ParentID = *v.ParentID
	}
	return out
}
func commentRow(ctx context.Context, db *gorm.DB, q taskv1.CommentScope) (models.Comment, error) {
	var row models.Comment
	err := db.WithContext(ctx).Where("id=? AND task_id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL", q.CommentID, q.TaskID, q.WorkspaceID, q.RootID).Take(&row).Error
	return row, catalogError(err)
}
func validComment(body string) bool { return strings.TrimSpace(body) != "" && len(body) <= 15000 }
func (s *Service) createComment(ctx context.Context, tx *gorm.DB, q taskv1.CommentCreateRequest) (taskv1.Comment, error) {
	if !validComment(q.Body) {
		return taskv1.Comment{}, invalidWork()
	}
	if _, err := workItem(ctx, tx, q.GetRequest); err != nil {
		return taskv1.Comment{}, err
	}
	var parent *string
	if q.ParentID != "" {
		id := q.ParentID
		for depth := 0; id != ""; depth++ {
			if depth >= 32 {
				return taskv1.Comment{}, invalidWork()
			}
			row, err := commentRow(ctx, tx, taskv1.CommentScope{GetRequest: q.GetRequest, CommentID: id})
			if err != nil {
				return taskv1.Comment{}, err
			}
			id = ""
			if row.ParentID != nil {
				id = *row.ParentID
			}
		}
		parent = &q.ParentID
	}
	now := time.Now().UTC()
	row := models.Comment{ID: NewID(), TaskID: q.TaskID, WorkspaceID: q.WorkspaceID, RootID: q.RootID, ParentID: parent, AuthorID: actorUserID(ctx), Body: q.Body, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
		return taskv1.Comment{}, catalogError(err)
	}
	return toComment(row), s.catalogChanged(ctx, tx, q.Scope, "comment", row.ID, row.Revision, "created")
}
func (s *Service) updateComment(ctx context.Context, tx *gorm.DB, q taskv1.CommentUpdateRequest) (taskv1.Comment, error) {
	if !validComment(q.Body) || q.Revision < 1 {
		return taskv1.Comment{}, invalidWork()
	}
	row, err := commentRow(ctx, tx, q.CommentScope)
	if err != nil {
		return taskv1.Comment{}, err
	}
	if row.AuthorID != actorUserID(ctx) {
		return taskv1.Comment{}, security.ErrDenied
	}
	if row.Revision != q.Revision {
		return taskv1.Comment{}, catalogConflict()
	}
	row.Body = q.Body
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.Comment{}, catalogError(err)
	}
	return toComment(row), s.catalogChanged(ctx, tx, q.Scope, "comment", row.ID, row.Revision, "body")
}
func (s *Service) resolveComment(ctx context.Context, tx *gorm.DB, q taskv1.CommentResolveRequest) (taskv1.CatalogMutationResult, error) {
	row, err := commentRow(ctx, tx, q.CommentScope)
	if err != nil {
		return taskv1.CatalogMutationResult{}, err
	}
	if q.Revision < 1 {
		return taskv1.CatalogMutationResult{}, invalidWork()
	}
	if row.Revision != q.Revision {
		return taskv1.CatalogMutationResult{}, catalogConflict()
	}
	row.Resolved = q.Resolved
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return taskv1.CatalogMutationResult{}, catalogError(err)
	}
	return taskv1.CatalogMutationResult{Scope: q.Scope, ID: row.ID, Revision: row.Revision, UpdatedAt: row.UpdatedAt}, s.catalogChanged(ctx, tx, q.Scope, "comment", row.ID, row.Revision, "resolved")
}
func (s *Service) archiveComment(ctx context.Context, tx *gorm.DB, q taskv1.CommentArchiveRequest) (taskv1.ArchivedItem, error) {
	row, err := commentRow(ctx, tx, q.CommentScope)
	if err != nil {
		return taskv1.ArchivedItem{}, err
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
	return taskv1.ArchivedItem{Scope: q.Scope, ID: row.ID, Revision: row.Revision, Archived: true, UpdatedAt: now}, s.catalogChanged(ctx, tx, q.Scope, "comment", row.ID, row.Revision, "archived")
}
func (s *Service) listComments(ctx context.Context, q taskv1.CommentPage) (taskv1.CommentsResult, error) {
	out := taskv1.CommentsResult{Comments: []taskv1.Comment{}}
	if q.Limit < 1 || q.Limit > 100 {
		return out, invalidWork()
	}
	var rows []models.Comment
	if err := s.GormDB.WithContext(ctx).Where("task_id=? AND workspace_id=? AND acl_root_id=? AND id>? AND archived_at IS NULL", q.TaskID, q.WorkspaceID, q.RootID, q.Cursor).Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, catalogError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	size := 0
	for _, row := range rows {
		item := toComment(row)
		raw, err := json.Marshal(item)
		if err != nil {
			return out, unavailable(err)
		}
		if size+len(raw) > 180000 && len(out.Comments) > 0 {
			out.NextCursor = out.Comments[len(out.Comments)-1].ID
			break
		}
		size += len(raw)
		out.Comments = append(out.Comments, item)
	}
	return out, nil
}
func (s *Service) workHistory(ctx context.Context, q taskv1.HistoryRequest) (taskv1.HistoryResult, error) {
	out := taskv1.HistoryResult{History: []taskv1.HistoryEntry{}}
	if q.Limit < 1 || q.Limit > 100 || q.Cursor < 0 {
		return out, invalidWork()
	}
	var rows []struct {
		ID            int64
		Actor         string
		Operation     string
		EntityID      string
		Revision      int64
		FieldsChanged string
		CreatedAt     time.Time
	}
	if err := s.GormDB.WithContext(ctx).Raw(`SELECT id,actor,operation,entity_id,revision,fields_changed,created_at FROM product_audit
		WHERE workspace_id=? AND acl_root_id=? AND id>? AND ((entity_kind='work' AND entity_id=?) OR
		(entity_kind='comment' AND entity_id IN(SELECT id FROM task_comments WHERE task_id=? AND workspace_id=? AND acl_root_id=?))) ORDER BY id LIMIT ?`, q.WorkspaceID, q.RootID, q.Cursor, q.TaskID, q.TaskID, q.WorkspaceID, q.RootID, q.Limit+1).Scan(&rows).Error; err != nil {
		return out, catalogError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	for _, row := range rows {
		fields := []string{}
		if json.Unmarshal([]byte(row.FieldsChanged), &fields) != nil {
			return out, security.ErrUnavailable
		}
		out.History = append(out.History, taskv1.HistoryEntry{ID: row.ID, Actor: row.Actor, Operation: row.Operation, EntityID: row.EntityID, Revision: row.Revision, FieldsChanged: fields, CreatedAt: row.CreatedAt})
	}
	return out, nil
}
func (s *Service) bindComments(r *module.Registry, policy module.Policy, store events.Store) error {
	for _, bind := range []func() error{
		func() error { return module.BindCommand(r, taskv1.CommentCreate, policy, store, s.createComment) }, func() error { return module.BindCommand(r, taskv1.CommentUpdate, policy, store, s.updateComment) }, func() error { return module.BindCommand(r, taskv1.CommentResolve, policy, store, s.resolveComment) }, func() error { return module.BindCommand(r, taskv1.CommentArchive, policy, store, s.archiveComment) }, func() error { return module.BindQuery(r, taskv1.CommentList, policy, s.listComments) }, func() error { return module.BindQuery(r, taskv1.WorkHistory, policy, s.workHistory) },
	} {
		if err := bind(); err != nil {
			return err
		}
	}
	return nil
}
