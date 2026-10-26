package sdk

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/sdk/transport"
)

type Registration struct {
	Service  string `json:"service_name"`
	Instance string `json:"instance_id"`
	Build    string `json:"build_version"`
	Digest   string `json:"digest"`
}
type ReadyEvidence struct {
	MicroID string `json:"micro_id"`
}
type Registry interface {
	Register(context.Context, *nats.Conn, Registration) error
	Ready(context.Context, Registration, ReadyEvidence) error
	Check(context.Context, Registration) error
}
type AppConfig struct {
	Connection Config
	Artifact   contract.Artifact
	Instance   string
	Registry   Registry
	Authorize  func(context.Context, string, []byte) (context.Context, error)
	// Resource authorizes the exact extracted ACL root/action, after invocation verification.
	Resource func(context.Context, string, string) error
	// Trusted authorizes an explicit service operation; no implicit unprotected endpoints.
	Trusted   func(context.Context, string) error
	SelfCheck func(context.Context) error
}
type App struct {
	cfg          AppConfig
	compiled     *contract.Compiled
	bindings     map[string]func(*Service) error
	service      *Service
	mu           sync.RWMutex
	live         bool
	starting     bool
	stopped      bool
	registration Registration
}

func NewApp(cfg AppConfig) (*App, error) {
	if cfg.Registry == nil || cfg.Authorize == nil || cfg.Instance == "" || strings.ContainsAny(cfg.Instance, ".*> \r\n\t") || cfg.SelfCheck == nil {
		return nil, errors.New("sdk: incomplete approved app configuration")
	}
	m, e := contract.Compile(cfg.Artifact)
	if e != nil {
		return nil, e
	}
	return &App{cfg: cfg, compiled: m, bindings: map[string]func(*Service) error{}, registration: Registration{m.Manifest.Service.Name, cfg.Instance, m.Manifest.Service.BuildVersion, m.Digest}}, nil
}

// Handle binds only installed operations. No subscription is created until Start.
func Handle[Req, Res any](app *App, id string, h rpc.Handler[Req, Res]) error {
	return bindHandle(app, id, h, false)
}

// HandleCommand requires the domain transaction that owns effects, replay and outbox.
func HandleCommand[Req, Res any](app *App, id string, store events.Store, h func(context.Context, *sql.Tx, Req) (Res, error)) error {
	if app == nil || h == nil {
		return contract.ErrInvalid
	}
	return bindHandle(app, id, func(ctx context.Context, q Req) (Res, error) {
		return events.Command(ctx, store, app.compiled, id, q, h)
	}, true)
}
func bindHandle[Req, Res any](app *App, id string, h rpc.Handler[Req, Res], command bool) error {
	if app == nil || h == nil {
		return contract.ErrInvalid
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	o, e := app.compiled.Operation(id)
	if e != nil || app.starting || app.bindings[id] != nil || (o.Kind == "command") != command {
		return contract.ErrInvalid
	}
	if o.Auth.Mode == "resource" && app.cfg.Resource == nil || o.Auth.Mode == "service" && app.cfg.Trusted == nil {
		return errors.New("sdk: missing operation authorization")
	}
	app.bindings[id] = func(s *Service) error {
		op := rpc.Operation{ID: id, Endpoint: strings.ReplaceAll(id, ".", "_"), Subject: o.Subject, QueueGroup: fmt.Sprintf("q.%s.v%d", app.compiled.Manifest.Service.Name, app.compiled.Manifest.Service.APIMajor), Timeout: time.Duration(o.TimeoutMS) * time.Millisecond, Protected: true, Mutation: o.Kind == "command", ValidateRequest: func(b []byte) error { return app.compiled.Validate(o.RequestSchema, b) }, ValidateResponse: func(b []byte) error { return app.compiled.Validate(o.ResponseSchema, b) }}
		op.Authorize = func(ctx context.Context, subject string, raw []byte) (context.Context, error) {
			app.mu.RLock()
			live := app.live
			app.mu.RUnlock()
			if !live || !s.Connection().IsConnected() {
				return nil, rpc.SecurityError(security.ErrUnavailable)
			}
			if e := app.cfg.Registry.Check(ctx, app.registration); e != nil {
				return nil, rpc.SecurityError(e)
			}
			authorized, e := app.cfg.Authorize(ctx, subject, raw)
			if e != nil {
				return nil, e
			}
			if authorized == nil {
				return nil, rpc.SecurityError(security.ErrUnavailable)
			}
			cl, ok := rpc.VerifiedClaims(authorized)
			if !ok || cl.Audience != fmt.Sprintf("%s/v%d", app.compiled.Manifest.Service.Name, app.compiled.Manifest.Service.APIMajor) || cl.Operation != id {
				return nil, rpc.SecurityError(security.ErrUnauthenticated)
			}
			return authorized, nil
		}
		return rpc.Handle(s, op, func(ctx context.Context, q Req) (Res, error) {
			var zero Res
			if o.Auth.Mode == "resource" {
				meta, ok := rpc.Metadata(ctx)
				if !ok {
					return zero, rpc.SecurityError(security.ErrUnavailable)
				}
				root, e := contract.Extract(meta.Payload, o.Auth.ResourceFrom)
				if e != nil {
					return zero, &rpc.Error{Code: rpc.CodeValidation, Message: "invalid ACL root"}
				}
				if e = app.cfg.Resource(ctx, root, o.Auth.Action); e != nil {
					return zero, rpc.SecurityError(e)
				}
			} else {
				if e := app.cfg.Trusted(ctx, id); e != nil {
					return zero, rpc.SecurityError(e)
				}
			}
			return h(ctx, q)
		})
	}
	return nil
}
func (a *App) Start(ctx context.Context) error {
	runtimeCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	a.mu.Lock()
	if a.starting || len(a.bindings) != len(a.compiled.Manifest.Operations) {
		a.mu.Unlock()
		return errors.New("sdk: incomplete or started app")
	}
	a.starting = true
	a.mu.Unlock()
	nc, e := Connect(ctx, a.cfg.Connection)
	if e != nil {
		return e
	}
	fail := func(err error) error {
		a.mu.Lock()
		a.live = false
		a.mu.Unlock()
		if a.service != nil {
			_ = a.service.Stop()
		} else {
			nc.Close()
		}
		return err
	}
	if e = a.cfg.Registry.Register(ctx, nc, a.registration); e != nil {
		return fail(e)
	}
	m, e := transport.New(nc, transport.Config{Name: a.compiled.Manifest.Service.Name, Version: a.compiled.Manifest.Service.BuildVersion, Metadata: map[string]string{"contract_digest": a.compiled.Digest, "instance_id": a.registration.Instance, "api_major": fmt.Sprint(a.compiled.Manifest.Service.APIMajor)}})
	if e != nil {
		return fail(e)
	}
	a.service = &Service{connection: nc, micro: m}
	for _, o := range a.compiled.Manifest.Operations {
		if e = a.bindings[o.ID](a.service); e != nil {
			return fail(e)
		}
	}
	if e = nc.FlushWithContext(ctx); e != nil {
		return fail(e)
	}
	if nc.LastError() != nil {
		return fail(nc.LastError())
	}
	if e = a.cfg.SelfCheck(ctx); e != nil {
		return fail(e)
	}
	if e = a.cfg.Registry.Ready(ctx, a.registration, ReadyEvidence{MicroID: m.Info().ID}); e != nil {
		return fail(e)
	}
	a.mu.Lock()
	a.live = true
	a.mu.Unlock()
	nc.SetDisconnectErrHandler(func(_ *nats.Conn, _ error) { a.mu.Lock(); a.live = false; a.mu.Unlock() })
	nc.SetReconnectHandler(func(_ *nats.Conn) { go a.reconnect(runtimeCtx) })
	// Each request also revalidates its current signed instance lease.
	go a.renew(runtimeCtx)
	return nil
}
func (a *App) renew(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = a.Stop()
			return
		case <-ticker.C:
			a.mu.RLock()
			live, stopped := a.live, a.stopped
			a.mu.RUnlock()
			if stopped {
				return
			}
			if !live {
				continue
			}
			checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			e := a.cfg.Registry.Check(checkCtx, a.registration)
			cancel()
			if e != nil {
				_ = a.Stop()
				return
			}
		}
	}
}
func (a *App) Stop() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	a.live = false
	a.stopped = true
	s := a.service
	a.mu.Unlock()
	if s != nil {
		return s.Stop()
	}
	return nil
}
func (a *App) Connection() *nats.Conn {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.service == nil {
		return nil
	}
	return a.service.Connection()
}

// Call uses the installed subject and schemas; callers cannot select arbitrary routes.
func Call[Req, Res any](ctx context.Context, client *rpc.Client, artifact contract.Artifact, id string, q Req) (Res, error) {
	var zero Res
	m, e := contract.Compile(artifact)
	if e != nil {
		return zero, e
	}
	o, e := m.Operation(id)
	if e != nil {
		return zero, e
	}
	return rpc.CallValidated[Req, Res](ctx, client, id, o.Subject, q, func(raw []byte) error { return m.Validate(o.RequestSchema, raw) }, func(raw []byte) error { return m.Validate(o.ResponseSchema, raw) })
}

func (a *App) reconnect(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	a.mu.RLock()
	stopped := a.stopped
	s := a.service
	a.mu.RUnlock()
	if stopped || s == nil {
		return
	}
	nc := s.Connection()
	if e := a.cfg.Registry.Register(ctx, nc, a.registration); e != nil {
		_ = a.Stop()
		return
	}
	if e := nc.FlushWithContext(ctx); e != nil {
		_ = a.Stop()
		return
	}
	if e := a.cfg.SelfCheck(ctx); e != nil {
		_ = a.Stop()
		return
	}
	if e := a.cfg.Registry.Ready(ctx, a.registration, ReadyEvidence{MicroID: s.micro.Info().ID}); e != nil {
		_ = a.Stop()
		return
	}
	a.mu.Lock()
	if !a.stopped {
		a.live = true
	}
	a.mu.Unlock()
}
