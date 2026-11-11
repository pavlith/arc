package access

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// ListGrants returns stored direct grants, not effective permissions or implicit
// owner rights. Authorization, expiry and rows use one policy/time snapshot.
func (c *Core) ListGrants(ctx context.Context, q ListGrantsRequest) (ListGrantsResult, error) {
	if c != nil && c.ContractSource != nil {
		next, err := c.resolveContracts(ctx)
		if err != nil {
			return ListGrantsResult{}, err
		}
		return next.ListGrants(ctx, q)
	}
	cl, err := c.claims(ctx, "grants.list")
	if err != nil {
		return ListGrantsResult{}, err
	}
	if !validUUID(q.ResourceID) || q.Cursor != "" && !validUUID(q.Cursor) || q.Limit < 1 || q.Limit > 100 {
		return ListGrantsResult{}, ErrValidation
	}
	fixed := *c
	at := c.now()
	fixed.Now = func() time.Time { return at }
	out := ListGrantsResult{ResourceID: q.ResourceID, Grants: []Grant{}}
	err = fixed.snapshotGORM(ctx, func(tx *gorm.DB, revision int64) error {
		if err := fixed.liveGORM(tx, cl); err != nil {
			return err
		}
		allowed, err := fixed.evaluateGORM(tx, cl, CheckRequest{ResourceID: q.ResourceID, Action: "access.grants.manage"})
		if err != nil {
			return err
		}
		if !allowed {
			return ErrDenied
		}
		if err := tx.Raw(`SELECT id,resource_id,principal_kind,principal_id,action,expires_at
			FROM access_grants WHERE resource_id=? AND id>? AND revoked_at IS NULL
			AND (expires_at IS NULL OR expires_at>?) ORDER BY id LIMIT ?`,
			q.ResourceID, q.Cursor, at, q.Limit+1).Scan(&out.Grants).Error; err != nil {
			return err
		}
		out.Revision = revision
		if len(out.Grants) > q.Limit {
			out.Grants = out.Grants[:q.Limit]
			out.NextCursor = out.Grants[len(out.Grants)-1].ID
		}
		return nil
	})
	if err != nil {
		return ListGrantsResult{}, err
	}
	return out, nil
}
