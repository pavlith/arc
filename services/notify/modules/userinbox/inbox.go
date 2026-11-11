package userinbox

import (
	"context"
	"time"

	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	"github.com/pavlith/arc/services/notify/models"
	"gorm.io/gorm"
)

func state(row models.Notification) notifyv1.NotificationState {
	return notifyv1.NotificationState{ID: row.ID, ReadAt: row.ReadAt, ArchivedAt: row.ArchivedAt, SnoozedUntil: row.SnoozedUntil, Revision: row.Revision}
}
func (m *Module) list(ctx context.Context, q notifyv1.InboxPage) (notifyv1.InboxResult, error) {
	out := notifyv1.InboxResult{Notifications: []notifyv1.Notification{}}
	uid, err := user(ctx)
	if err != nil {
		return out, err
	}
	if q.Limit < 1 || q.Limit > 100 {
		return out, invalid()
	}
	switch q.Tab {
	case "", "all", "unread", "archived", "snoozed":
	default:
		return out, invalid()
	}
	now := time.Now().UTC()
	allowed := map[string]bool{}
	err = m.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		after := q.Cursor
		for len(out.Notifications) <= q.Limit {
			db := tx.Where("recipient_user_id=? AND id>? AND workspace_id<>'' AND acl_root_id<>'' AND task_id<>''", uid, after)
			switch q.Tab {
			case "archived":
				db = db.Where("archived_at IS NOT NULL")
			case "snoozed":
				db = db.Where("archived_at IS NULL AND snoozed_until>?", now)
			default:
				db = db.Where("archived_at IS NULL AND (snoozed_until IS NULL OR snoozed_until<=?)", now)
				if q.Tab == "unread" {
					db = db.Where("read_at IS NULL")
				}
			}
			var rows []models.Notification
			if err := db.Order("id").Limit(128).Find(&rows).Error; err != nil {
				return fail(err)
			}
			if len(rows) == 0 {
				break
			}
			roots := []string{}
			for _, row := range rows {
				roots = append(roots, row.RootID)
			}
			if err := m.allowRoots(ctx, roots, allowed); err != nil {
				return err
			}
			for _, row := range rows {
				after = row.ID
				if !allowed[row.RootID] {
					continue
				}
				out.Notifications = append(out.Notifications, notifyv1.Notification{NotificationState: state(row), Scope: notifyv1.Scope{WorkspaceID: row.WorkspaceID, RootID: row.RootID}, TaskID: row.TaskID, Kind: row.Kind, CreatedAt: row.CreatedAt})
				if len(out.Notifications) > q.Limit {
					break
				}
			}
		}
		if len(out.Notifications) > q.Limit {
			out.Notifications = out.Notifications[:q.Limit]
			out.NextCursor = out.Notifications[len(out.Notifications)-1].ID
		}
		var counts []struct {
			RootID string
			Count  int64
		}
		if err := tx.Model(&models.Notification{}).Select("acl_root_id AS root_id,count(*) AS count").Where("recipient_user_id=? AND read_at IS NULL AND archived_at IS NULL AND (snoozed_until IS NULL OR snoozed_until<=?) AND workspace_id<>'' AND acl_root_id<>'' AND task_id<>''", uid, now).Group("acl_root_id").Scan(&counts).Error; err != nil {
			return fail(err)
		}
		roots := []string{}
		for _, row := range counts {
			roots = append(roots, row.RootID)
		}
		if err := m.allowRoots(ctx, roots, allowed); err != nil {
			return err
		}
		for _, row := range counts {
			if allowed[row.RootID] {
				out.UnreadCount += row.Count
			}
		}
		return nil
	})
	if err != nil {
		return notifyv1.InboxResult{}, err
	}
	return out, nil
}
func (m *Module) update(ctx context.Context, tx *gorm.DB, q notifyv1.NotificationChange) (notifyv1.NotificationState, error) {
	uid, err := user(ctx)
	if err != nil {
		return notifyv1.NotificationState{}, err
	}
	if q.Revision < 1 {
		return notifyv1.NotificationState{}, invalid()
	}
	var row models.Notification
	if err := tx.WithContext(ctx).Where("id=? AND recipient_user_id=?", q.ID, uid).Take(&row).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return notifyv1.NotificationState{}, missing()
		}
		return notifyv1.NotificationState{}, fail(err)
	}
	if row.Revision != q.Revision {
		return notifyv1.NotificationState{}, conflict()
	}
	now := time.Now().UTC()
	if q.Action != "snooze" && q.Until != nil {
		return notifyv1.NotificationState{}, invalid()
	}
	switch q.Action {
	case "read":
		row.ReadAt = &now
	case "unread":
		row.ReadAt = nil
	case "archive":
		row.ArchivedAt = &now
	case "unarchive":
		row.ArchivedAt = nil
	case "snooze":
		if q.Until == nil || !q.Until.After(now) || q.Until.After(now.Add(365*24*time.Hour)) {
			return notifyv1.NotificationState{}, invalid()
		}
		row.SnoozedUntil = q.Until
	case "unsnooze":
		row.SnoozedUntil = nil
	default:
		return notifyv1.NotificationState{}, invalid()
	}
	row.Revision++
	if err := tx.WithContext(ctx).Save(&row).Error; err != nil {
		return notifyv1.NotificationState{}, fail(err)
	}
	return state(row), audit(ctx, tx, uid, "notifications."+q.Action, row.ID)
}
func (m *Module) markAll(ctx context.Context, tx *gorm.DB, _ notifyv1.Empty) (notifyv1.MarkAllResult, error) {
	uid, err := user(ctx)
	if err != nil {
		return notifyv1.MarkAllResult{}, err
	}
	now := time.Now().UTC()
	base := func() *gorm.DB {
		return tx.WithContext(ctx).Model(&models.Notification{}).Where("recipient_user_id=? AND read_at IS NULL AND archived_at IS NULL AND (snoozed_until IS NULL OR snoozed_until<=?) AND workspace_id<>'' AND acl_root_id<>'' AND task_id<>''", uid, now)
	}
	var roots []string
	if err := base().Distinct("acl_root_id").Pluck("acl_root_id", &roots).Error; err != nil {
		return notifyv1.MarkAllResult{}, fail(err)
	}
	allowed := map[string]bool{}
	if err := m.allowRoots(ctx, roots, allowed); err != nil {
		return notifyv1.MarkAllResult{}, err
	}
	var count int64
	for _, root := range roots {
		if !allowed[root] {
			continue
		}
		res := base().Where("acl_root_id=?", root).Updates(map[string]any{"read_at": now, "revision": gorm.Expr("revision+1")})
		if res.Error != nil {
			return notifyv1.MarkAllResult{}, fail(res.Error)
		}
		count += res.RowsAffected
	}
	return notifyv1.MarkAllResult{Updated: count}, audit(ctx, tx, uid, "notifications.mark_all_read", uid)
}
