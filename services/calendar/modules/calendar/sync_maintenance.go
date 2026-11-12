package calendar

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/models"
	"gorm.io/gorm"
)

// RebuildSync is an offline owner hook, not an RPC or a user-authorized method.
// Run with the service stopped after upgrade/restore/representation changes.
// It rotates the collection generation and rebuilds metadata without rewriting
// events, UID reservations or domain outbox. Failure rolls back the whole reset.
func (s *Module) RebuildSync(ctx context.Context, scope v1.Scope) error {
	if s == nil || s.DB == nil || !validScope(scope) {
		return invalid()
	}
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Reserve the SQLite writer before reading the baseline.
		result := tx.Exec("UPDATE roots SET sync_ready=0 WHERE workspace_id=? AND acl_root_id=?", scope.WorkspaceID, scope.RootID)
		if result.Error != nil {
			return dbError(result.Error)
		}
		if result.RowsAffected != 1 {
			return security.ErrDenied
		}
		for _, table := range []string{"sync_changes", "sync_items"} {
			if err := tx.Table(table).Where("workspace_id=? AND acl_root_id=?", scope.WorkspaceID, scope.RootID).Delete(nil).Error; err != nil {
				return dbError(err)
			}
		}
		cursor := ""
		for {
			var rows []models.Event
			if err := tx.Where("workspace_id=? AND acl_root_id=? AND id>?", scope.WorkspaceID, scope.RootID, cursor).Order("id").Limit(100).Find(&rows).Error; err != nil {
				return dbError(err)
			}
			if len(rows) == 0 {
				break
			}
			for _, row := range rows {
				if err := ctx.Err(); err != nil {
					return err
				}
				item, err := syncMetadata(row)
				if err != nil {
					return err
				}
				raw, err := json.Marshal(item)
				if err != nil {
					return err
				}
				if err = tx.Exec("INSERT INTO sync_items(workspace_id,acl_root_id,event_id,sequence,entry) VALUES(?,?,?,0,?)", scope.WorkspaceID, scope.RootID, row.ID, string(raw)).Error; err != nil {
					return dbError(err)
				}
			}
			cursor = rows[len(rows)-1].ID
		}
		epoch := strings.ReplaceAll(newID(), "-", "")
		if err := tx.Exec("UPDATE roots SET sync_epoch=?,sync_revision=0,sync_floor=0,sync_ready=1 WHERE workspace_id=? AND acl_root_id=?", epoch, scope.WorkspaceID, scope.RootID).Error; err != nil {
			return dbError(err)
		}
		return dbError(tx.Exec("INSERT INTO audit(workspace_id,acl_root_id,entity_id,actor,operation,revision,created_at) VALUES(?,?,?,'operator:offline','calendar.sync.reset',0,?)", scope.WorkspaceID, scope.RootID, scope.RootID, time.Now().UTC()).Error)
	})
}

// BootstrapSync skips initialized roots unless the operator explicitly resets.
func (s *Module) BootstrapSync(ctx context.Context, reset bool) (int, error) {
	if s == nil || s.DB == nil {
		return 0, invalid()
	}

	count := 0
	cursor := ""
	for {
		var roots []models.Root
		query := s.DB.WithContext(ctx).Where("acl_root_id>?", cursor).Order("acl_root_id").Limit(100)
		if !reset {
			query = query.Where("sync_ready=0")
		}
		if err := query.Find(&roots).Error; err != nil {
			return count, dbError(err)
		}
		if len(roots) == 0 {
			break
		}
		for _, root := range roots {
			if err := s.RebuildSync(ctx, v1.Scope{WorkspaceID: root.WorkspaceID, RootID: root.RootID}); err != nil {
				return count, err
			}
			count++
		}
		cursor = roots[len(roots)-1].RootID
	}
	return count, nil
}
