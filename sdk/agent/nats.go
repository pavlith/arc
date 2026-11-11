package agent

import (
	"context"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
)

const (
	NodeAudience       = "runtime/v1"
	OperationInventory = "runtime.v1.node.inventory"
	OperationPull      = "runtime.v1.desired.get"
	OperationReport    = "runtime.v1.node.report"
	OperationProfilePlan = "runtime.v1.node.profile.plan"
)

// NodeSubject is concrete: no wildcard subscriptions or node chosen by headers.
func NodeSubject(node, operation string) (string, error) {
	if !ValidID(node) {
		return "", ErrInvalid
	}
	var suffix string
	switch operation {
	case OperationInventory:
		suffix = "inventory"
	case OperationPull:
		suffix = "desired.get"
	case OperationReport:
		suffix = "report"
	case OperationProfilePlan:
		suffix = "profile.plan"
	default:
		return "", ErrInvalid
	}
	return "ctl.runtime.v1.node." + node + "." + suffix, nil
}

// InvocationCredentials obtains a fresh, operation-bound invocation plus proof
// signer from Identity. Assertions alone are not accepted by Runtime endpoints.
type InvocationCredentials func(context.Context, string) (rpc.Credentials, error)

type NodeClient struct {
	rpc         *rpc.Client
	node        string
	credentials InvocationCredentials
}

var _ RuntimeProvider = (*NodeClient)(nil)
var _ ProfilePlanProvider = (*NodeClient)(nil)

// NewNodeClient does not own the connection. Connect through sdk.Connect with
// this node's TLS/NKey credentials and identity-scoped Config.InboxPrefix;
// never share an administrator connection.
func NewNodeClient(client *rpc.Client, node string, credentials InvocationCredentials) (*NodeClient, error) {
	if client == nil || !ValidID(node) || credentials == nil {
		return nil, ErrInvalid
	}
	return &NodeClient{rpc: client, node: node, credentials: credentials}, nil
}
func nodeCall[Req, Res any](ctx context.Context, c *NodeClient, op string, request Req, idem string) (Res, error) {
	var zero Res
	if ctx == nil || c == nil || c.rpc == nil || c.credentials == nil {
		return zero, security.ErrUnavailable
	}
	subject, err := NodeSubject(c.node, op)
	if err != nil {
		return zero, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	credentials, err := c.credentials(ctx, op)
	if err != nil {
		return zero, err
	}
	credentials.IdempotencyKey = idem
	return rpc.Call[Req, Res](rpc.WithCredentials(ctx, credentials), c.rpc, op, subject, request)
}
func (c *NodeClient) Inventory(ctx context.Context, request InventoryRequest) (InventoryPage, error) {
	if c == nil || request.NodeID != c.node {
		return InventoryPage{}, ErrInvalid
	}
	return nodeCall[InventoryRequest, InventoryPage](ctx, c, OperationInventory, request, "")
}

// Pull returns an attested response; the executor must independently verify the
// Core signature, fresh request ID and local template allowlist before effects.
func (c *NodeClient) Pull(ctx context.Context, request PullRequest) (SignedSnapshot, error) {
	if c == nil || request.NodeID != c.node {
		return SignedSnapshot{}, ErrInvalid
	}
	return nodeCall[PullRequest, SignedSnapshot](ctx, c, OperationPull, request, "")
}
// PullProfile retrieves only signed, read-only, administrator-approved plans.
// Callers must verify Core's signature, node ID, request ID and expiration.
func (c *NodeClient) PullProfile(ctx context.Context, request ProfilePlanRequest) (SignedProfilePlan, error) {
	if c == nil || request.NodeID != c.node || !ValidID(request.ProfileID) {
		return SignedProfilePlan{}, ErrInvalid
	}
	return nodeCall[ProfilePlanRequest, SignedProfilePlan](ctx, c, OperationProfilePlan, request, "")
}
func (c *NodeClient) Report(ctx context.Context, report Report) error {
	if c == nil || report.Observation.NodeID != c.node || !ValidID(report.EventID) {
		return ErrInvalid
	}
	_, err := nodeCall[Report, struct{}](ctx, c, OperationReport, report, report.EventID)
	return err
}
