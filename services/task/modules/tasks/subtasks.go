package tasks

import (
	"context"
	"time"

	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

// Reparenting is serialized with the child's revision and its complete subtree.
// Root/workspace cannot change; the database also enforces both endpoint scopes.
func (s *Service) setParent(ctx context.Context, tx *gorm.DB, q taskv1.ParentChangeRequest) (taskv1.ParentChangeResult, error) {
	empty := taskv1.ParentChangeResult{}
	if q.Revision < 1 || q.ExpectedUpdatedAt.IsZero() || q.ParentID == q.TaskID {
		return empty, invalidWork()
	}
	current, err := workItem(ctx, tx, q.GetRequest)
	if err != nil {
		return empty, err
	}
	if current.Revision != q.Revision || !current.UpdatedAt.Equal(q.ExpectedUpdatedAt) {
		return empty, catalogConflict()
	}
	// Require a Team before attaching a work item to a hierarchy.
	if current.TeamID == "" {
		return empty, invalidWork()
	}
	if q.ParentID != "" {
		parent, err := workItem(ctx, tx, taskv1.GetRequest{Scope: q.Scope, TaskID: q.ParentID})
		if err != nil {
			return empty, err
		}
		if parent.TeamID == "" {
			return empty, invalidWork()
		}
		id := q.ParentID
		ancestors := 0
		for id != "" {
			if id == q.TaskID || ancestors >= 32 {
				return empty, invalidWork()
			}
			ancestors++
			var rows []struct{ ParentID string }
			if err := tx.WithContext(ctx).Table("task_parents").Select("parent_id").Where("task_id=? AND workspace_id=? AND acl_root_id=?", id, q.WorkspaceID, q.RootID).Scan(&rows).Error; err != nil {
				return empty, catalogError(err)
			}
			id = ""
			if len(rows) > 0 {
				id = rows[0].ParentID
			}
		}
		// Include descendants when bounding the resulting tree to 32 edges.
		var height int
		err = tx.WithContext(ctx).Raw(`WITH RECURSIVE descendants(id,depth) AS (
   SELECT ?,0 UNION ALL SELECT p.task_id,d.depth+1 FROM task_parents p JOIN descendants d ON p.parent_id=d.id WHERE d.depth<33
  ) SELECT COALESCE(MAX(depth),0) FROM descendants`, q.TaskID).Row().Scan(&height)
		if err != nil {
			return empty, catalogError(err)
		}
		if ancestors+height > 32 {
			return empty, invalidWork()
		}
	}
	if err := tx.WithContext(ctx).Exec("DELETE FROM task_parents WHERE task_id=? AND workspace_id=? AND acl_root_id=?", q.TaskID, q.WorkspaceID, q.RootID).Error; err != nil {
		return empty, catalogError(err)
	}
	if q.ParentID != "" {
		if err := tx.WithContext(ctx).Exec("INSERT INTO task_parents(task_id,parent_id,workspace_id,acl_root_id) VALUES(?,?,?,?)", q.TaskID, q.ParentID, q.WorkspaceID, q.RootID).Error; err != nil {
			return empty, catalogError(err)
		}
	}
	now := time.Now().UTC()
	if !now.After(current.UpdatedAt) {
		now = current.UpdatedAt.Add(time.Nanosecond)
	}
	res := tx.WithContext(ctx).Model(&models.TaskDetails{}).Where("task_id=? AND revision=?", q.TaskID, q.Revision).Update("revision", q.Revision+1)
	if res.Error != nil {
		return empty, catalogError(res.Error)
	}
	if res.RowsAffected != 1 {
		return empty, catalogConflict()
	}
	if err := tx.WithContext(ctx).Model(&models.Task{}).Where("id=?", q.TaskID).Update("updated_at", now).Error; err != nil {
		return empty, catalogError(err)
	}
	return taskv1.ParentChangeResult{GetRequest: q.GetRequest, ParentID: q.ParentID, Revision: q.Revision + 1, UpdatedAt: now}, s.catalogChanged(ctx, tx, q.Scope, "work", q.TaskID, q.Revision+1, "parent_id")
}
