package tasks

import (
	"context"
	"time"

	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

func (s *Service) changeLink(ctx context.Context, tx *gorm.DB, q taskv1.LinkChangeRequest) (taskv1.LinkChangeResult, error) {
	empty := taskv1.LinkChangeResult{}
	if q.TargetID == q.TaskID || q.Revision < 1 || q.ExpectedUpdatedAt.IsZero() {
		return empty, invalidWork()
	}
	switch q.Kind {
	case "related", "blocks", "duplicate_of":
	default:
		return empty, invalidWork()
	}
	source, err := workItem(ctx, tx, q.GetRequest)
	if err != nil {
		return empty, err
	}
	if source.TeamID == "" {
		return empty, invalidWork()
	}
	if source.Revision != q.Revision || !source.UpdatedAt.Equal(q.ExpectedUpdatedAt) {
		return empty, catalogConflict()
	}
	targetReq := taskv1.GetRequest{Scope: q.Scope, TaskID: q.TargetID}
	if !q.Remove {
		target, err := workItem(ctx, tx, targetReq)
		if err != nil {
			return empty, err
		}
		if target.TeamID == "" {
			return empty, invalidWork()
		}
	}
	// Removal may reference an archived endpoint, but never one outside the root.
	var target models.Task
	if err := tx.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=?", q.TargetID, q.WorkspaceID, q.RootID).Take(&target).Error; err != nil {
		return empty, catalogError(err)
	}
	var targetDetail models.TaskDetails
	if err := tx.WithContext(ctx).Where("task_id=? AND workspace_id=? AND acl_root_id=?", q.TargetID, q.WorkspaceID, q.RootID).Take(&targetDetail).Error; err != nil {
		return empty, catalogError(err)
	}
	a, b := q.TaskID, q.TargetID
	if q.Kind == "related" && a > b {
		a, b = b, a
	}
	if q.Remove {
		if err := tx.WithContext(ctx).Exec("DELETE FROM task_links WHERE source_id=? AND target_id=? AND kind=? AND workspace_id=? AND acl_root_id=?", a, b, q.Kind, q.WorkspaceID, q.RootID).Error; err != nil {
			return empty, catalogError(err)
		}
	} else {
		var exists int64
		if err := tx.WithContext(ctx).Table("task_links").Where("source_id=? AND target_id=? AND kind=?", a, b, q.Kind).Count(&exists).Error; err != nil {
			return empty, catalogError(err)
		}
		if exists == 0 {
			for _, id := range []string{q.TaskID, q.TargetID} {
				var count int64
				if err := tx.WithContext(ctx).Table("task_links").Where("source_id=? OR target_id=?", id, id).Count(&count).Error; err != nil {
					return empty, catalogError(err)
				}
				if count >= 100 {
					return empty, invalidWork()
				}
			}
			if q.Kind != "related" {
				var cycle bool
				err := tx.WithContext(ctx).Raw(`WITH RECURSIVE reachable(id) AS (SELECT ? UNION SELECT l.target_id FROM task_links l JOIN reachable r ON l.source_id=r.id WHERE l.kind=? AND l.workspace_id=? AND l.acl_root_id=?) SELECT EXISTS(SELECT 1 FROM reachable WHERE id=?)`, b, q.Kind, q.WorkspaceID, q.RootID, a).Row().Scan(&cycle)
				if err != nil {
					return empty, catalogError(err)
				}
				if cycle {
					return empty, invalidWork()
				}
			}
			if err := tx.WithContext(ctx).Exec("INSERT INTO task_links(source_id,target_id,kind,workspace_id,acl_root_id) VALUES(?,?,?,?,?)", a, b, q.Kind, q.WorkspaceID, q.RootID).Error; err != nil {
				return empty, catalogError(err)
			}
		}
	}
	now := time.Now().UTC()
	for _, at := range []time.Time{source.UpdatedAt, target.UpdatedAt} {
		if !now.After(at) {
			now = at.Add(time.Nanosecond)
		}
	}
	for _, id := range []string{q.TaskID, q.TargetID} {
		if err := tx.WithContext(ctx).Model(&models.TaskDetails{}).Where("task_id=?", id).Update("revision", gorm.Expr("revision+1")).Error; err != nil {
			return empty, catalogError(err)
		}
		if err := tx.WithContext(ctx).Model(&models.Task{}).Where("id=?", id).Update("updated_at", now).Error; err != nil {
			return empty, catalogError(err)
		}
	}
	if err := s.catalogChanged(ctx, tx, q.Scope, "work", q.TaskID, q.Revision+1, "links"); err != nil {
		return empty, err
	}
	if err := s.catalogChanged(ctx, tx, q.Scope, "work", q.TargetID, targetDetail.Revision+1, "links"); err != nil {
		return empty, err
	}
	return taskv1.LinkChangeResult{GetRequest: q.GetRequest, TargetID: q.TargetID, Revision: q.Revision + 1, TargetRevision: targetDetail.Revision + 1, UpdatedAt: now}, nil
}
func (s *Service) listLinks(ctx context.Context, q taskv1.GetRequest) (taskv1.LinkListResult, error) {
	out := taskv1.LinkListResult{Links: []taskv1.Link{}}
	err := s.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := workItem(ctx, tx, q); err != nil {
			return err
		}
		// Archived endpoints remain removable through known IDs but disappear from lists.
		return tx.Table("task_links l").Select("l.source_id,l.target_id,l.kind").Joins("JOIN task_details a ON a.task_id=l.source_id AND a.archived_at IS NULL").Joins("JOIN task_details b ON b.task_id=l.target_id AND b.archived_at IS NULL").Joins("JOIN teams ta ON ta.id=a.team_id AND ta.archived_at IS NULL").Joins("JOIN teams tb ON tb.id=b.team_id AND tb.archived_at IS NULL").Where("l.workspace_id=? AND l.acl_root_id=? AND (l.source_id=? OR l.target_id=?)", q.WorkspaceID, q.RootID, q.TaskID, q.TaskID).Order("l.kind,l.source_id,l.target_id").Limit(100).Scan(&out.Links).Error
	})
	return out, catalogError(err)
}
