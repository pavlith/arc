package access

import (
	"context"
	"errors"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/services/core/modules/identity"
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
	if c != nil && c.ContractSource != nil {
		next, err := c.resolveContracts(ctx)
		if err != nil {
			return nil, err
		}
		return next.TaskRoots(ctx, user, workspace, after)
	}
	if err := c.ready(); err != nil {
		return nil, err
	}
	if !validUUID(user) || !validUUID(workspace) || after != "" && !validUUID(after) {
		return nil, ErrDenied
	}
	out := []identity.TaskRoot{}
	db := database.FromContext(ctx, c.GormDB).WithContext(ctx)
	for len(out) < 100 {
		var ids []string
		if err := db.Raw(`SELECT id FROM access_resources WHERE type='task.workspace'
			AND workspace_id=? AND state='active' AND id>? ORDER BY id LIMIT 128`, workspace, after).Scan(&ids).Error; err != nil {
			return nil, ErrUnavailable
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			after = id
			err := c.userScopeGORM(ctx, user, []string{id}, []string{"task.read"})
			if errors.Is(err, ErrDenied) {
				continue
			}
			if err != nil {
				return nil, err
			}
			writeErr := c.userScopeGORM(ctx, user, []string{id}, []string{"task.create"})
			if writeErr != nil && !errors.Is(writeErr, ErrDenied) {
				return nil, writeErr
			}
			out = append(out, identity.TaskRoot{ID: id, CanWrite: writeErr == nil})
			if len(out) == 100 {
				break
			}
		}
	}
	return out, nil
}
