package access

import (
	"context"

	"github.com/pavlith/arc/pkgs/rpc"
)

// Client uses the existing transport. The caller supplies an invocation, proof,
// deadline and (for commands) a stable idempotency key through rpc.WithCredentials.
type Client struct{ RPC *rpc.Client }

func invokeRPC[Req, Res any](ctx context.Context, c *Client, operation string, q Req) (Res, error) {
	if c == nil || c.RPC == nil {
		var zero Res
		return zero, &rpc.Error{Code: rpc.CodeUnavailable, Message: "access unavailable"}
	}
	return rpc.Call[Req, Res](ctx, c.RPC, "access.v1."+operation, "rpc.access.v1."+operation, q)
}
func (c *Client) RegisterType(ctx context.Context, q RegisterRequest) (MutationResult, error) {
	return invokeRPC[RegisterRequest, MutationResult](ctx, c, "resource_types.register", q)
}
func (c *Client) Reserve(ctx context.Context, q ReserveRequest) (MutationResult, error) {
	return invokeRPC[ReserveRequest, MutationResult](ctx, c, "resources.reserve", q)
}
func (c *Client) Activate(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	return invokeRPC[LifecycleRequest, MutationResult](ctx, c, "resources.activate", q)
}
func (c *Client) Abort(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	return invokeRPC[LifecycleRequest, MutationResult](ctx, c, "resources.abort", q)
}
func (c *Client) BeginDelete(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	return invokeRPC[LifecycleRequest, MutationResult](ctx, c, "resources.begin_delete", q)
}
func (c *Client) FinalizeDelete(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	return invokeRPC[LifecycleRequest, MutationResult](ctx, c, "resources.finalize_delete", q)
}
func (c *Client) Check(ctx context.Context, q CheckRequest) (Decision, error) {
	return invokeRPC[CheckRequest, Decision](ctx, c, "check", q)
}
func (c *Client) CheckMany(ctx context.Context, q CheckManyRequest) (CheckManyResult, error) {
	return invokeRPC[CheckManyRequest, CheckManyResult](ctx, c, "check_many", q)
}
func (c *Client) ListAccessibleRoots(ctx context.Context, q ListRequest) (ListResult, error) {
	return invokeRPC[ListRequest, ListResult](ctx, c, "list_accessible_roots", q)
}
func (c *Client) AddGrant(ctx context.Context, q GrantRequest) (MutationResult, error) {
	return invokeRPC[GrantRequest, MutationResult](ctx, c, "grants.add", q)
}
func (c *Client) RevokeGrant(ctx context.Context, q RevokeRequest) (MutationResult, error) {
	return invokeRPC[RevokeRequest, MutationResult](ctx, c, "grants.revoke", q)
}

var _ Checker = (*Client)(nil)
