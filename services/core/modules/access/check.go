package access

import (
	"context"
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
