// Package runtime manages Core desired state. It never receives a Docker socket.
package runtime

import (
	"context"
	"errors"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

var ErrConflict = errors.New("runtime: revision conflict")
var ErrInvalid = errors.New("runtime: invalid deployment")

// Authorize MUST check operator/deployment capability in live Core state.
// A missing authorizer always denies writes; command callers never choose actor identity.
type Authorize func(context.Context, string, string) error

type Module struct {
	GormDB    *gorm.DB
	Authorize Authorize
	// Control is optional until a trusted live policy is explicitly installed.
	Control      *Control
	NodeVerifier *security.Verifier
}

func (m *Module) ID() string { return "runtime" }

// M0 binds no Runtime endpoints. The explicit M6 node verifier enables only
// the closed per-node protocol, never administrative or host-driver APIs.
func (m *Module) Bind(service *sdk.Service) (func(), error) {
	if m == nil || m.GormDB == nil || m.Authorize == nil {
		return nil, security.ErrUnavailable
	}
	if m.NodeVerifier != nil {
		if m.Control == nil {
			return nil, security.ErrUnavailable
		}
		return nil, m.Control.BindNodeRPC(service, *m.NodeVerifier)
	}
	return nil, nil
}
