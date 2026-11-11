package access

import (
	"context"
	"errors"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/services/core/modules/identity"
	"gorm.io/gorm"
)

func (c *Core) Check(ctx context.Context, q CheckRequest) (Decision, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return Decision{}, e
		}
		return next.Check(ctx, q)
	}
	return c.checkGORM(ctx, q)
}
func (c *Core) CheckMany(ctx context.Context, q CheckManyRequest) (CheckManyResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return CheckManyResult{}, e
		}
		return next.CheckMany(ctx, q)
	}
	return c.checkManyGORM(ctx, q)
}
func (c *Core) ListAccessibleRoots(ctx context.Context, q ListRequest) (ListResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return ListResult{}, e
		}
		return next.ListAccessibleRoots(ctx, q)
	}
	return c.listGORM(ctx, q)
}
func (c *Core) userScope(ctx context.Context, user string, resources, actions []string) error {
	return c.userScopeGORM(ctx, user, resources, actions)
}

// TaskRoots is an in-process Identity query for a verified workspace member.
// Its cursor is an accessible root ID, and every returned root passes live ACL.
func (c *Core) TaskRoots(ctx context.Context, user, workspace, after string) ([]identity.TaskRoot, error) {
	return c.taskRootsForAction(ctx, user, workspace, after, "task.read")
}

// ManagedTaskRoots discovers ACL administration scopes without granting content
// read access or exposing task data to an ACL-only manager.
func (c *Core) ManagedTaskRoots(ctx context.Context, user, workspace, after string) ([]identity.TaskRoot, error) {
	return c.taskRootsForAction(ctx, user, workspace, after, "access.grants.manage")
}

func (c *Core) taskRootsForAction(ctx context.Context, user, workspace, after, action string) ([]identity.TaskRoot, error) {
	if c != nil && c.ContractSource != nil {
		next, err := c.resolveContracts(ctx)
		if err != nil {
			return nil, err
		}
		return next.taskRootsForAction(ctx, user, workspace, after, action)
	}
	if err := c.ready(); err != nil {
		return nil, err
	}
	if !validUUID(user) || !validUUID(workspace) || after != "" && !validUUID(after) {
		return nil, ErrDenied
	}
	out := []identity.TaskRoot{}
	fixed := *c
	at := c.now()
	fixed.Now = func() time.Time { return at }
	err := fixed.snapshotGORM(ctx, func(tx *gorm.DB, _ int64) error {
		ctx := database.TransactionContext(ctx, c.GormDB, tx)
		for len(out) < 100 {
			var ids []string
			if err := tx.Raw(`SELECT id FROM access_resources WHERE type='task.workspace'
			AND workspace_id=? AND state='active' AND id>? ORDER BY id LIMIT 128`, workspace, after).Scan(&ids).Error; err != nil {
				return ErrUnavailable
			}
			if len(ids) == 0 {
				break
			}
			for _, id := range ids {
				after = id
				err := fixed.userScopeGORM(ctx, user, []string{id}, []string{action})
				if errors.Is(err, ErrDenied) {
					continue
				}
				if err != nil {
					return err
				}
				item := identity.TaskRoot{ID: id}
				for permission, allowed := range map[string]*bool{
					"task.read":            &item.CanRead,
					"task.create":          &item.CanWrite,
					"access.grants.manage": &item.CanManage,
				} {
					if permission == action {
						*allowed = true
						continue
					}
					checkErr := fixed.userScopeGORM(ctx, user, []string{id}, []string{permission})
					if checkErr != nil && !errors.Is(checkErr, ErrDenied) {
						return checkErr
					}
					*allowed = checkErr == nil
				}
				out = append(out, item)
				if len(out) == 100 {
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
