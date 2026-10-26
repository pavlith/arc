package access

import (
	"context"
)

// share cannot turn an expiring permission or consent into a lasting grant.

func (c *Core) AddGrant(ctx context.Context, q GrantRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.AddGrant(ctx, q)
	}
	return c.addGrantGORM(ctx, q)
}
func (c *Core) RevokeGrant(ctx context.Context, q RevokeRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.RevokeGrant(ctx, q)
	}
	return c.revokeGrantGORM(ctx, q)
}
