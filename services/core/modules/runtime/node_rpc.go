package runtime

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
)

// verifiedNodePolicy cannot use a custom ControlPolicy's Node implementation:
// the network boundary always derives its caller from verified invocation claims.
type verifiedNodePolicy struct{ verifier security.Verifier }

func (verifiedNodePolicy) Manager(context.Context) (string, error) { return "", security.ErrDenied }
func (p verifiedNodePolicy) Node(ctx context.Context) (string, error) {
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok || cl.Audience != agent.NodeAudience || cl.Caller == "" || cl.Subject != "service:"+cl.Caller || cl.DelegationID != "" || cl.OnBehalfOf != "" || cl.SessionID != "" || cl.WorkspaceID != "" || cl.SourceAudience != "" || cl.SourceOperation != "" || cl.ExpiresAt <= p.verifier.Time().Unix() {
		return "", security.ErrUnauthenticated
	}
	switch cl.Operation {
	case agent.OperationInventory, agent.OperationPull, agent.OperationReport:
	default:
		return "", security.ErrDenied
	}
	if p.verifier.State == nil {
		return "", security.ErrUnavailable
	}
	if err := p.verifier.State.CheckInvocation(ctx, cl); err != nil {
		return "", err
	}
	return cl.Caller, nil
}
func nodeWireError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrConflict):
		return &rpc.Error{Code: rpc.CodeConflict, Message: "runtime revision or receipt conflict"}
	case errors.Is(err, ErrInvalid):
		return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid Runtime request"}
	case errors.Is(err, sql.ErrNoRows):
		return &rpc.Error{Code: rpc.CodeNotFound, Message: "Runtime resource not found"}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return &rpc.Error{Code: rpc.CodeDeadlineExceeded, Message: "Runtime deadline exceeded", Retryable: true}
	case errors.Is(err, security.ErrUnauthenticated), errors.Is(err, security.ErrDenied), errors.Is(err, security.ErrUnavailable):
		return rpc.SecurityError(err)
	default:
		return &rpc.Error{Code: rpc.CodeInternal, Message: "internal error"}
	}
}

// BindNodeRPC binds only nodes approved before Core startup. Enrollment requires
// a Core restart to add subscriptions; disabling/revocation is checked live.
// On any binding error the caller must stop the owning service (Core.Start does).
func (c *Control) BindNodeRPC(service rpc.EndpointService, verifier security.Verifier) error {
	if c == nil || c.db == nil || service == nil || verifier.Keys == nil || verifier.State == nil || verifier.Nonces == nil {
		return security.ErrUnavailable
	}
	var nodes []string
	err := c.db.Table("runtime_nodes n").Joins("JOIN identity_service_accounts s ON s.id=n.service_account_id").Where("n.active=1 AND s.disabled_at IS NULL AND s.service_definition='arc-agent'").Order("n.id").Limit(1025).Pluck("n.id", &nodes).Error
	if err != nil || len(nodes) > 1024 {
		return security.ErrUnavailable
	}
	for _, node := range nodes {
		if !agent.ValidID(node) {
			return security.ErrUnavailable
		}
	}
	scoped := *c
	scoped.policy = verifiedNodePolicy{verifier: verifier}
	for _, node := range nodes {
		for _, operation := range []string{agent.OperationInventory, agent.OperationPull, agent.OperationReport} {
			subject, _ := agent.NodeSubject(node, operation)
			config := rpc.Operation{ID: operation, Endpoint: "runtime_" + node + "_" + strings.ReplaceAll(operation, ".", "_"), Subject: subject, QueueGroup: "q.runtime.v1", Timeout: 5 * time.Second, Protected: true, Mutation: operation == agent.OperationReport, Authorize: rpc.InvocationAuthorizer(verifier, agent.NodeAudience)}
			switch operation {
			case agent.OperationInventory:
				err = rpc.Handle(service, config, func(ctx context.Context, r agent.InventoryRequest) (agent.InventoryPage, error) {
					if r.NodeID != node {
						return agent.InventoryPage{}, nodeWireError(security.ErrDenied)
					}
					out, err := scoped.Inventory(ctx, r)
					return out, nodeWireError(err)
				})
			case agent.OperationPull:
				err = rpc.Handle(service, config, func(ctx context.Context, r agent.PullRequest) (agent.SignedSnapshot, error) {
					if r.NodeID != node {
						return agent.SignedSnapshot{}, nodeWireError(security.ErrDenied)
					}
					out, err := scoped.Pull(ctx, r)
					return out, nodeWireError(err)
				})
			case agent.OperationReport:
				err = rpc.Handle(service, config, func(ctx context.Context, r agent.Report) (struct{}, error) {
					if r.Observation.NodeID != node {
						return struct{}{}, nodeWireError(security.ErrDenied)
					}
					meta, ok := rpc.Metadata(ctx)
					if !ok || meta.IdempotencyKey != r.EventID {
						return struct{}{}, nodeWireError(ErrInvalid)
					}
					return struct{}{}, nodeWireError(scoped.Report(ctx, r))
				})
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}
