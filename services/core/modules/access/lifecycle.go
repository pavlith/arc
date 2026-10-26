package access

import (
	"context"
)

func (c *Core) RegisterType(ctx context.Context, q RegisterRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.RegisterType(ctx, q)
	}
	return c.registerTypeGORM(ctx, q)
}
func (c *Core) Reserve(ctx context.Context, q ReserveRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.Reserve(ctx, q)
	}
	return c.reserveGORM(ctx, q)
}
func (c *Core) Activate(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.Activate(ctx, q)
	}
	return c.transitionGORM(ctx, "activate", q)
}
func (c *Core) Abort(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.Abort(ctx, q)
	}
	return c.transitionGORM(ctx, "abort", q)
}
func (c *Core) BeginDelete(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.BeginDelete(ctx, q)
	}
	return c.transitionGORM(ctx, "begin_delete", q)
}
func (c *Core) FinalizeDelete(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.FinalizeDelete(ctx, q)
	}
	return c.transitionGORM(ctx, "finalize_delete", q)
}
