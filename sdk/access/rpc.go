package access

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/rpc"
)

func wireError(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, ErrConflict) {
		return &rpc.Error{Code: rpc.CodeConflict, Message: "access conflict"}
	}
	if errors.Is(e, ErrValidation) {
		return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid access request"}
	}
	return rpc.SecurityError(normalize(e))
}
func (c *Core) Authenticate(ctx context.Context, subject string, raw []byte) (context.Context, error) {
	if e := c.ready(); e != nil {
		return nil, wireError(e)
	}
	return rpc.InvocationAuthorizer(c.Identity.Verifier(), "access/v1")(ctx, subject, raw)
}
func bind[Req, Res any](s *sdk.Service, c *Core, name string, mutation bool, h func(context.Context, Req) (Res, error)) error {
	timeout := 5 * time.Second
	if mutation {
		timeout = 10 * time.Second
	}
	return rpc.Handle(s, rpc.Operation{ID: "access.v1." + name, Subject: "rpc.access.v1." + name, Endpoint: strings.ReplaceAll(name, ".", "_"), QueueGroup: "q.access.v1", Timeout: timeout, Protected: true, Mutation: mutation, Authorize: c.Authenticate}, func(ctx context.Context, r Req) (Res, error) { out, e := h(ctx, r); return out, wireError(e) })
}
func (c *Core) BindInternal(s *sdk.Service) error {
	if e := c.ready(); e != nil {
		return e
	}
	registrations := []func() error{
		func() error { return bind(s, c, "resource_types.register", true, c.RegisterType) },
		func() error { return bind(s, c, "resources.reserve", true, c.Reserve) },
		func() error { return bind(s, c, "resources.activate", true, c.Activate) },
		func() error { return bind(s, c, "resources.abort", true, c.Abort) },
		func() error { return bind(s, c, "resources.begin_delete", true, c.BeginDelete) },
		func() error { return bind(s, c, "resources.finalize_delete", true, c.FinalizeDelete) },
		func() error { return bind(s, c, "check", false, c.Check) },
		func() error { return bind(s, c, "check_many", false, c.CheckMany) },
		func() error { return bind(s, c, "list_accessible_roots", false, c.ListAccessibleRoots) },
		func() error { return bind(s, c, "grants.add", true, c.AddGrant) },
		func() error { return bind(s, c, "grants.revoke", true, c.RevokeGrant) },
	}
	for _, register := range registrations {
		if e := register(); e != nil {
			return e
		}
	}
	return nil
}

// GuardObject belongs in the domain-owner's handler. Lookup queries that owner's
// DB; the caller-supplied root is only checked against that authoritative result.
type RootLookup interface {
	Root(context.Context, string) (string, error)
}
type Checker interface {
	Check(context.Context, CheckRequest) (Decision, error)
}

func GuardObject(ctx context.Context, checker Checker, lookup RootLookup, objectID, claimedRoot, action string) (Decision, error) {
	if checker == nil || lookup == nil {
		return Decision{}, ErrUnavailable
	}
	root, e := lookup.Root(ctx, objectID)
	if e != nil {
		return Decision{}, normalize(e)
	}
	if root == "" || root != claimedRoot {
		return Decision{}, ErrDenied
	}
	decision, e := checker.Check(ctx, CheckRequest{root, action})
	if e != nil {
		return Decision{}, e
	}
	if !decision.Allowed {
		return decision, ErrDenied
	}
	return decision, nil
}
