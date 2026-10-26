// Package runtime manages Core desired state. It never receives a Docker socket.
package runtime

import (
	"context"
	"encoding/json"
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
}

// Desired is an immutable snapshot of the desired deployment spec.
// The host-local executor must independently verify the approved operation.
type Desired struct {
	ID          string          `json:"id"`
	ServiceName string          `json:"service_name"`
	Spec        json.RawMessage `json:"spec"`
	Replicas    int             `json:"replicas"`
	Revision    int64           `json:"revision"`
}

func (m *Module) ID() string { return "runtime" }

// Runtime exposes no privileged NATS/Docker endpoint in M0. It is an in-process
// Core module; any future RPC must use a separately approved protected contract.
func (m *Module) Bind(_ *sdk.Service) (func(), error) {
	if m == nil || m.GormDB == nil || m.Authorize == nil {
		return nil, security.ErrUnavailable
	}
	return nil, nil
}

// Put is compare-and-swap with a monotonic revision. expected=0 creates only;
// greater revisions update only the exact existing state. No side effects occur
// in a Docker engine and the caller must supply an online checked permission.
func (m *Module) Put(ctx context.Context, want Desired, expected int64) (Desired, error) {
	if m == nil || m.GormDB == nil || m.Authorize == nil {
		return Desired{}, security.ErrUnavailable
	}
	if want.ID == "" || want.ServiceName == "" || len(want.Spec) == 0 ||
		!json.Valid(want.Spec) || want.Replicas < 0 || expected < 0 {
		return Desired{}, ErrInvalid
	}
	if err := m.Authorize(ctx, "runtime.deployments.write", want.ID); err != nil {
		return Desired{}, err
	}
	canonical, err := security.CanonicalJSON(want.Spec)
	if err != nil {
		return Desired{}, ErrInvalid
	}
	want.Spec = canonical
	return m.putGORM(ctx, want, expected)
}

func (m *Module) Get(ctx context.Context, id string) (Desired, error) {
	if m == nil || m.GormDB == nil || m.Authorize == nil {
		return Desired{}, security.ErrUnavailable
	}
	if id == "" {
		return Desired{}, ErrInvalid
	}
	if err := m.Authorize(ctx, "runtime.deployments.read", id); err != nil {
		return Desired{}, err
	}
	return m.getGORM(ctx, id)
}
