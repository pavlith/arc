package userinbox

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	"gorm.io/gorm"
)

type Module struct {
	GormDB   *gorm.DB
	Identity identity.Client
}

func (*Module) ID() string { return "user_inbox" }
func user(ctx context.Context) (string, error) {
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok || !strings.HasPrefix(cl.Subject, "user:") || cl.SessionID == "" || cl.DelegationID != "" || cl.OnBehalfOf != "" {
		return "", security.ErrDenied
	}
	return strings.TrimPrefix(cl.Subject, "user:"), nil
}
func fail(err error) error {
	if err == nil {
		return nil
	}
	return rpc.SecurityError(security.ErrUnavailable)
}
func invalid() error  { return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid Notify input"} }
func conflict() error { return &rpc.Error{Code: rpc.CodeConflict, Message: "notification changed"} }
func missing() error  { return &rpc.Error{Code: rpc.CodeNotFound, Message: "notification unavailable"} }
func (m *Module) Register(r *module.Registry) error {
	if m == nil || m.GormDB == nil || m.Identity.RPC == nil {
		return module.ErrInvalid
	}
	policy := module.Policy{Trusted: func(ctx context.Context, op string) error {
		cl, ok := rpc.VerifiedClaims(ctx)
		if !ok || cl.Operation != op {
			return security.ErrDenied
		}
		_, err := user(ctx)
		if err != nil {
			return err
		}
		if op == notifyv1.Subscribe.ID {
			meta, ok := rpc.Metadata(ctx)
			var q notifyv1.Scope
			if !ok || json.Unmarshal(meta.Payload, &q) != nil {
				return security.ErrDenied
			}
			return m.readScope(ctx, q)
		}
		return nil
	}}
	store := events.Store{DB: m.GormDB}
	for _, bind := range []func() error{
		func() error { return module.BindQuery(r, notifyv1.InboxList, policy, m.list) }, func() error { return module.BindCommand(r, notifyv1.InboxUpdate, policy, store, m.update) }, func() error { return module.BindCommand(r, notifyv1.InboxMarkAll, policy, store, m.markAll) },
		func() error { return module.BindCommand(r, notifyv1.Subscribe, policy, store, m.subscribe) }, func() error { return module.BindCommand(r, notifyv1.Unsubscribe, policy, store, m.unsubscribe) }, func() error { return module.BindQuery(r, notifyv1.SubscriptionList, policy, m.subscriptions) },
	} {
		if err := bind(); err != nil {
			return err
		}
	}
	return nil
}
func (m *Module) downstream(ctx context.Context, operation string) (context.Context, error) {
	incoming, ok := rpc.InvocationToken(ctx)
	cl, verified := rpc.VerifiedClaims(ctx)
	if !ok || !verified {
		return nil, security.ErrUnauthenticated
	}
	v, err := identity.Call[identity.ServiceExchange, identity.TokenResult](ctx, m.Identity, "identity.v1.invocations.exchange_service", identity.ServiceExchange{IncomingToken: incoming, IncomingOperation: cl.Operation, Target: identity.Target{Audience: "access/v1", Operation: operation, WorkspaceID: cl.WorkspaceID}})
	if err != nil {
		return nil, err
	}
	parts := strings.Split(v.Token, ".")
	if len(parts) != 3 {
		return nil, security.ErrUnavailable
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, security.ErrUnavailable
	}
	var claims security.Claims
	if json.Unmarshal(raw, &claims) != nil || claims.JTI == "" {
		return nil, security.ErrUnavailable
	}
	meta, _ := rpc.Metadata(ctx)
	ctx = rpc.WithOutgoing(ctx, rpc.Outgoing{RequestID: meta.RequestID, Traceparent: meta.Traceparent})
	return rpc.WithCredentials(ctx, rpc.Credentials{Token: v.Token, Proof: func(subject string, raw []byte) (security.Proof, error) {
		return security.SignProof(m.Identity.PrivateKey, subject, raw, claims.JTI, security.Proof{Kid: m.Identity.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: rand.Text()})
	}}), nil
}

// Decisions are reused only within this in-flight request, never across requests.
func (m *Module) allowRoots(ctx context.Context, roots []notifyv1.Scope, allowed map[string]bool) error {
	pending := []access.CheckRequest{}
	seen := map[string]bool{}
	for _, root := range roots {
		if _, ok := allowed[root.Key()]; !ok && !seen[root.Key()] {
			pending = append(pending, access.CheckRequest{ResourceID: root.RootID, Action: root.Action()})
			seen[root.Key()] = true
		}
	}
	for len(pending) > 0 {
		n := len(pending)
		if n > 100 {
			n = 100
		}
		checks := pending[:n]
		pending = pending[n:]
		checkCtx, err := m.downstream(ctx, "access.v1.check_many")
		if err != nil {
			return err
		}
		result, err := (&access.Client{RPC: m.Identity.RPC}).CheckMany(checkCtx, access.CheckManyRequest{Checks: checks})
		if err != nil {
			return err
		}
		if len(result.Decisions) != len(checks) {
			return security.ErrUnavailable
		}
		for i, check := range checks {
			allowed[keyForAction(check.Action)+":"+check.ResourceID] = result.Decisions[i].Allowed
		}
	}
	return nil
}
func audit(ctx context.Context, tx *gorm.DB, uid, op, target string) error {
	return fail(tx.WithContext(ctx).Exec(`INSERT INTO user_audit(actor,operation,target,created_at) VALUES(?,?,?,?)`, "user:"+uid, op, target, time.Now().UTC()).Error)
}

func keyForAction(action string) string {
	switch action {
	case "task.read":
		return "task"
	case "pages.read":
		return "page"
	case "files.read":
		return "file"
	}
	return ""
}

func (m *Module) readScope(ctx context.Context, q notifyv1.Scope) error {
	if q.Action() == "" {
		return security.ErrDenied
	}
	checkCtx, err := m.downstream(ctx, "access.v1.check")
	if err != nil {
		return err
	}
	d, err := (&access.Client{RPC: m.Identity.RPC}).Check(checkCtx, access.CheckRequest{ResourceID: q.RootID, Action: q.Action()})
	if err != nil {
		return err
	}
	if !d.Allowed {
		return security.ErrDenied
	}
	return nil
}
