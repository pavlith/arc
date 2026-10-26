// Package runtime manages Core desired state. It never receives a Docker socket.
package runtime

import (
    "context"
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"

    "github.com/pavlith/arc/pkgs"
    "github.com/pavlith/arc/pkgs/security"
)

var ErrConflict = errors.New("runtime: revision conflict")
var ErrInvalid = errors.New("runtime: invalid deployment")

// Authorize MUST check operator/deployment capability in live Core state.
// A missing authorizer always denies writes; command callers never choose actor identity.
type Authorize func(context.Context, string, string) error

type Module struct {
    DB *sql.DB
    Authorize Authorize
}

// Desired is an immutable snapshot of the desired deployment spec.
// The host-local executor must independently verify the approved operation.
type Desired struct {
    ID string `json:"id"`
    ServiceName string `json:"service_name"`
    Spec json.RawMessage `json:"spec"`
    Replicas int `json:"replicas"`
    Revision int64 `json:"revision"`
}

func (m *Module) ID() string { return "runtime" }

// Runtime exposes no privileged NATS/Docker endpoint in M0. It is an in-process
// Core module; any future RPC must use a separately approved protected contract.
func (m *Module) Bind(_ *pkgs.Service) (func(), error) {
    if m == nil || m.DB == nil { return nil, security.ErrUnavailable }
    return nil, nil
}

// Put is compare-and-swap with a monotonic revision. expected=0 creates only;
// greater revisions update only the exact existing state. No side effects occur
// in a Docker engine and the caller must supply an online checked permission.
func (m *Module) Put(ctx context.Context, want Desired, expected int64) (Desired, error) {
    if m == nil || m.DB == nil || m.Authorize == nil { return Desired{}, security.ErrUnavailable }
    if want.ID == "" || want.ServiceName == "" || len(want.Spec) == 0 ||
        !json.Valid(want.Spec) || want.Replicas < 0 || expected < 0 {
        return Desired{}, ErrInvalid
    }
    if err := m.Authorize(ctx, "runtime.deployments.write", want.ID); err != nil { return Desired{}, err }
    canonical, err := security.CanonicalJSON(want.Spec)
    if err != nil { return Desired{}, ErrInvalid }
    want.Spec = canonical
    tx, err := m.DB.BeginTx(ctx, nil)
    if err != nil { return Desired{}, security.ErrUnavailable }
    defer tx.Rollback()
    err = tx.QueryRowContext(ctx, `
INSERT INTO runtime.desired_deployments(id,service_name,spec,replicas,revision)
VALUES($1,$2,$3,$4,1)
ON CONFLICT(id) DO UPDATE SET
    service_name=EXCLUDED.service_name, spec=EXCLUDED.spec, replicas=EXCLUDED.replicas,
    revision=runtime.desired_deployments.revision+1, updated_at=now()
WHERE runtime.desired_deployments.revision=$5
RETURNING revision
`, want.ID, want.ServiceName, []byte(want.Spec), want.Replicas, expected).Scan(&want.Revision)
    if errors.Is(err, sql.ErrNoRows) { return Desired{}, ErrConflict }
    if err != nil { return Desired{}, fmt.Errorf("runtime: persist desired state: %w", err) }
    if err := tx.Commit(); err != nil { return Desired{}, security.ErrUnavailable }
    return want, nil
}

func (m *Module) Get(ctx context.Context, id string) (Desired, error) {
    if m == nil || m.DB == nil { return Desired{}, security.ErrUnavailable }
    if id == "" { return Desired{}, ErrInvalid }
    var out Desired
    if err := m.DB.QueryRowContext(ctx,
        `SELECT id,service_name,spec,replicas,revision FROM runtime.desired_deployments WHERE id=$1`, id,
    ).Scan(&out.ID,&out.ServiceName,&out.Spec,&out.Replicas,&out.Revision); err != nil {
        return Desired{}, err
    }
    return out, nil
}
