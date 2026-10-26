package health

import (
	"context"

	"github.com/pavlith/arc/pkgs/module"
	"github.com/pavlith/arc/pkgs/rpc"
	"github.com/pavlith/arc/pkgs/security"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
)

type Module struct {
	ServiceID string
}

func (*Module) ID() string { return "health" }
func (m *Module) Register(r *module.Registry) error {
	if m == nil || m.ServiceID == "" {
		return module.ErrInvalid
	}
	trusted := module.Policy{Trusted: func(ctx context.Context, op string) error {
		cl, ok := rpc.VerifiedClaims(ctx)
		if !ok || cl.Operation != op || op != notifyv1.Health ||
			cl.Subject != "service:"+m.ServiceID {
			return security.ErrDenied
		}
		return nil
	}}
	return module.BindQuery(r, notifyv1.HealthQuery, trusted,
		func(context.Context, notifyv1.Empty) (notifyv1.Empty, error) {
			return notifyv1.Empty{}, nil
		})
}
