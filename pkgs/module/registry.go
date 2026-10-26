// Package module binds typed domain capabilities to a single approved service.
// A Module is not a ServiceAccount, a deployment or a Fabric registration.
package module

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/pavlith/arc/pkgs"
	"github.com/pavlith/arc/pkgs/contract"
	"github.com/pavlith/arc/pkgs/events"
	"github.com/pavlith/arc/pkgs/rpc"
	"github.com/pavlith/arc/pkgs/security"
	"github.com/pavlith/arc/pkgs/telemetry"
)

var ErrInvalid = errors.New("module: invalid definition or binding")
var moduleID = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// Module installs its handlers and workers during composition, before Start.
type Module interface {
	ID() string
	Register(*Registry) error
}

// Query and Command preserve the exact approved operation ID while typing DTOs.
type Query[Req, Res any] struct{ ID string }
type Command[Req, Res any] struct{ ID string }

// Policy is operation-specific; Resource MUST prove ownership/root binding and
// perform an online ACL decision. Trusted MUST verify the permitted service actor.
// Neither callback is an authentication substitute; the SDK verifies proof first.
type Policy struct {
	Resource func(context.Context, string, string) error
	Trusted  func(context.Context, string) error
}

// Worker performs background work only under explicit service/event permissions.
// In particular, JetStream consumers must configure events.Delivery.Permit.
type Worker struct {
	ID  string
	Run func(context.Context) error
}

type policyEntry struct {
	module string
	policy Policy
}

type Registry struct {
	app      *pkgs.App
	contract *contract.Compiled
	service  string
	observer telemetry.Observer
	mu       sync.RWMutex
	sealed   bool
	current  string
	policies map[string]policyEntry
	workers  map[string]Worker
}

func NewRegistry(app *pkgs.App, compiled *contract.Compiled, observer telemetry.Observer) (*Registry, error) {
	if app == nil || compiled == nil {
		return nil, ErrInvalid
	}
	return &Registry{app: app, contract: compiled,
		service: compiled.Manifest.Service.Name, observer: observer,
		policies: make(map[string]policyEntry), workers: make(map[string]Worker)}, nil
}

// Install scopes subsequent bindings to one module and rejects repeated IDs.
func (r *Registry) Install(m Module) error {
	if r == nil || m == nil || !moduleID.MatchString(m.ID()) {
		return ErrInvalid
	}
	r.mu.Lock()
	if r.sealed || r.current != "" {
		r.mu.Unlock()
		return ErrInvalid
	}
	id := m.ID()
	r.current = id
	r.mu.Unlock()
	err := m.Register(r)
	r.mu.Lock()
	r.current = ""
	r.mu.Unlock()
	if err != nil {
		return fmt.Errorf("module %s: %w", id, err)
	}
	return nil
}

func (r *Registry) preflight(id, kind string, p Policy) error {
	if r == nil || r.app == nil || r.sealed || r.current == "" || r.policies[id].module != "" {
		return ErrInvalid
	}
	spec, err := r.contract.Operation(id)
	if err != nil || spec.Kind != kind {
		return ErrInvalid
	}
	switch spec.Auth.Mode {
	case "resource":
		if p.Resource == nil || p.Trusted != nil {
			return ErrInvalid
		}
	case "service":
		if p.Trusted == nil || p.Resource != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func BindQuery[Req, Res any](r *Registry, op Query[Req, Res], p Policy, h rpc.Handler[Req, Res]) error {
	if r == nil || h == nil {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.preflight(op.ID, "query", p); err != nil {
		return err
	}
	mod := r.current
	if err := pkgs.Handle(r.app, op.ID, func(ctx context.Context, req Req) (res Res, err error) {
		start := time.Now()
		defer r.observe(ctx, mod, op.ID, "query", start, &err)
		return h(ctx, req)
	}); err != nil {
		return err
	}
	r.policies[op.ID] = policyEntry{module: mod, policy: p}
	return nil
}

// BindCommand always uses the domain owner's transactional replay/outbox Store.
func BindCommand[Req, Res any](r *Registry, op Command[Req, Res],
	p Policy, store events.Store, h func(context.Context, *sql.Tx, Req) (Res, error)) error {
	if r == nil || h == nil || store.DB == nil || store.Schema == "" {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.preflight(op.ID, "command", p); err != nil {
		return err
	}
	mod := r.current
	if err := pkgs.HandleCommand(r.app, op.ID, store, func(ctx context.Context, tx *sql.Tx, req Req) (res Res, err error) {
		start := time.Now()
		defer r.observe(ctx, mod, op.ID, "command", start, &err)
		return h(ctx, tx, req)
	}); err != nil {
		return err
	}
	r.policies[op.ID] = policyEntry{module: mod, policy: p}
	return nil
}

func (r *Registry) observe(ctx context.Context, module, op, kind string, start time.Time, err *error) {
	if r.observer == nil {
		return
	}
	code := rpc.Code("")
	if *err != nil {
		code = rpc.ErrorCode(*err)
	}
	r.observer.Observe(ctx, telemetry.Observation{
		Service: r.service, Module: module, Operation: op, Kind: kind,
		Duration: time.Since(start), ErrorCode: code,
	})
}

func (r *Registry) AddWorker(w Worker) error {
	if r == nil || w.Run == nil || !moduleID.MatchString(w.ID) {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sealed || r.current == "" || r.workers[w.ID].Run != nil {
		return ErrInvalid
	}
	r.workers[w.ID] = w
	return nil
}

func (r *Registry) Seal() error {
	if r == nil {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sealed || r.current != "" || len(r.policies) != len(r.contract.Manifest.Operations) {
		return ErrInvalid
	}
	for _, op := range r.contract.Manifest.Operations {
		if r.policies[op.ID].module == "" {
			return ErrInvalid
		}
	}
	r.sealed = true
	return nil
}

func (r *Registry) Workers() []Worker {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Worker, 0, len(r.workers))
	for _, w := range r.workers {
		out = append(out, w)
	}
	return out
}

// AuthorizeResource is called ONLY by pkgs.App after signed invocation proof,
// service lease and request schema verification. It fails closed by operation.
func (r *Registry) AuthorizeResource(ctx context.Context, root, action string) error {
	claims, ok := rpc.VerifiedClaims(ctx)
	if !ok {
		return rpc.SecurityError(security.ErrUnauthenticated)
	}
	r.mu.RLock()
	bound := r.policies[claims.Operation]
	sealed := r.sealed
	spec, err := r.contract.Operation(claims.Operation)
	r.mu.RUnlock()
	if !sealed || err != nil || spec.Auth.Mode != "resource" || spec.Auth.Action != action ||
		bound.policy.Resource == nil {
		return rpc.SecurityError(security.ErrUnavailable)
	}
	return bound.policy.Resource(ctx, root, action)
}

func (r *Registry) AuthorizeTrusted(ctx context.Context, operation string) error {
	claims, ok := rpc.VerifiedClaims(ctx)
	if !ok || claims.Operation != operation {
		return rpc.SecurityError(security.ErrUnauthenticated)
	}
	r.mu.RLock()
	bound := r.policies[operation]
	sealed := r.sealed
	spec, err := r.contract.Operation(operation)
	r.mu.RUnlock()
	if !sealed || err != nil || spec.Auth.Mode != "service" || bound.policy.Trusted == nil {
		return rpc.SecurityError(security.ErrUnavailable)
	}
	return bound.policy.Trusted(ctx, operation)
}
