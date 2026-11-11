package userinbox

import (
	"context"

	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	"github.com/pavlith/arc/services/notify/models"
	"gorm.io/gorm"
)

func (m *Module) subscribe(ctx context.Context, tx *gorm.DB, q notifyv1.Scope) (notifyv1.Subscription, error) {
	uid, err := user(ctx)
	if err != nil {
		return notifyv1.Subscription{}, err
	}
	if q.Action() == "" {
		return notifyv1.Subscription{}, invalid()
	}
	checkCtx, err := m.downstream(ctx, "access.v1.check")
	if err != nil {
		return notifyv1.Subscription{}, err
	}
	decision, err := (&access.Client{RPC: m.Identity.RPC}).Check(checkCtx, access.CheckRequest{ResourceID: q.RootID, Action: q.Action()})
	if err != nil {
		return notifyv1.Subscription{}, err
	}
	if !decision.Allowed {
		return notifyv1.Subscription{}, security.ErrDenied
	}
	var count int64
	if err := tx.WithContext(ctx).Model(&models.Subscription{}).Where("recipient_user_id=? AND active=1 AND NOT(workspace_id=? AND acl_root_id=?)", uid, q.WorkspaceID, q.RootID).Count(&count).Error; err != nil {
		return notifyv1.Subscription{}, fail(err)
	}
	if count >= 1000 {
		return notifyv1.Subscription{}, invalid()
	}
	if err := tx.WithContext(ctx).Exec(`INSERT INTO subscriptions(workspace_id,acl_root_id,recipient_user_id,active,resource_kind) VALUES(?,?,?,1,?) ON CONFLICT(workspace_id,acl_root_id,recipient_user_id) DO UPDATE SET active=1,resource_kind=excluded.resource_kind`, q.WorkspaceID, q.RootID, uid, q.Kind()).Error; err != nil {
		return notifyv1.Subscription{}, fail(err)
	}
	return notifyv1.Subscription{Scope: q, Active: true}, audit(ctx, tx, uid, "subscriptions.subscribe", q.RootID)
}
func (m *Module) unsubscribe(ctx context.Context, tx *gorm.DB, q notifyv1.Scope) (notifyv1.Subscription, error) {
	if q.Action() == "" {
		return notifyv1.Subscription{}, invalid()
	}
	uid, err := user(ctx)
	if err != nil {
		return notifyv1.Subscription{}, err
	}
	if err := tx.WithContext(ctx).Model(&models.Subscription{}).Where("workspace_id=? AND acl_root_id=? AND recipient_user_id=? AND resource_kind=?", q.WorkspaceID, q.RootID, uid, q.ResourceKind).Update("active", false).Error; err != nil {
		return notifyv1.Subscription{}, fail(err)
	}
	return notifyv1.Subscription{Scope: q, Active: false}, audit(ctx, tx, uid, "subscriptions.unsubscribe", q.RootID)
}
func (m *Module) subscriptions(ctx context.Context, q notifyv1.InboxPage) (notifyv1.SubscriptionsResult, error) {
	out := notifyv1.SubscriptionsResult{Subscriptions: []notifyv1.Subscription{}}
	uid, err := user(ctx)
	if err != nil {
		return out, err
	}
	if q.Limit < 1 || q.Limit > 100 || q.Tab != "" {
		return out, invalid()
	}
	allowed := map[string]bool{}
	err = m.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		after := q.Cursor
		for len(out.Subscriptions) <= q.Limit {
			var rows []models.Subscription
			if err := tx.Where("recipient_user_id=? AND active=1 AND acl_root_id>?", uid, after).Order("acl_root_id").Limit(128).Find(&rows).Error; err != nil {
				return fail(err)
			}
			if len(rows) == 0 {
				break
			}
			roots := []notifyv1.Scope{}
			for _, row := range rows {
				roots = append(roots, notifyv1.Scope{RootID: row.RootID, ResourceKind: row.ResourceKind})
			}
			if err := m.allowRoots(ctx, roots, allowed); err != nil {
				return err
			}
			for _, row := range rows {
				after = row.RootID
				if !allowed[(notifyv1.Scope{RootID: row.RootID, ResourceKind: row.ResourceKind}).Key()] {
					continue
				}
				out.Subscriptions = append(out.Subscriptions, notifyv1.Subscription{Scope: notifyv1.Scope{WorkspaceID: row.WorkspaceID, RootID: row.RootID, ResourceKind: row.ResourceKind}, Active: true})
				if len(out.Subscriptions) > q.Limit {
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return notifyv1.SubscriptionsResult{}, err
	}
	if len(out.Subscriptions) > q.Limit {
		out.Subscriptions = out.Subscriptions[:q.Limit]
		out.NextCursor = out.Subscriptions[len(out.Subscriptions)-1].RootID
	}
	return out, nil
}
