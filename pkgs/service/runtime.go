// Package service composes approved Arc services from typed modules.
// This is an optional high-level layer over the same protected NATS Micro runtime.
package service

import (
    "context"
    "errors"
    "fmt"
    "sync"

    "github.com/nats-io/nats.go"
    "github.com/pavlith/arc/pkgs"
    "github.com/pavlith/arc/pkgs/contract"
    "github.com/pavlith/arc/pkgs/module"
    "github.com/pavlith/arc/pkgs/security"
    "github.com/pavlith/arc/pkgs/telemetry"
)

type Kind string
const (
    Core Kind = "core"
    Edge Kind = "edge"
    Domain Kind = "domain"
    Agent Kind = "agent"
)

// Definition describes composition, not authorization or a new Fabric identity.
type Definition struct {
    Name string
    APIMajor int
    Kind Kind
    Modules []module.Module
}

type Config struct {
    Definition Definition
    Runtime pkgs.AppConfig
    Observer telemetry.Observer
}

var ErrInvalid = errors.New("service: invalid definition")
var ErrStopped = errors.New("service: stopped")
var ErrWorkerExited = errors.New("service: worker stopped unexpectedly")

type App struct {
    runtime *pkgs.App
    registry *module.Registry
    workers []module.Worker
    mu sync.Mutex
    cancel context.CancelFunc
    wg sync.WaitGroup
    stopOnce sync.Once
    started bool
    stopped bool
    workErr error
    stopErr error
    done chan struct{}
}

// Compose requires complete approved bindings BEFORE any transport subscriptions.
func Compose(cfg Config) (*App, error) {
    def := cfg.Definition
    if def.Name == "" || def.APIMajor < 1 || len(def.Modules) == 0 ||
        (def.Kind != Core && def.Kind != Edge && def.Kind != Domain && def.Kind != Agent) ||
        cfg.Runtime.Resource != nil || cfg.Runtime.Trusted != nil {
        return nil, ErrInvalid
    }
    compiled, err := contract.Compile(cfg.Runtime.Artifact)
    if err != nil { return nil, err }
    if compiled.Manifest.Service.Name != def.Name ||
        compiled.Manifest.Service.APIMajor != def.APIMajor {
        return nil, fmt.Errorf("%w: approved artifact does not match service identity", ErrInvalid)
    }

    // No authorization callback is user-replaceable after composition.
    var bindings *module.Registry
    cfg.Runtime.Resource = func(ctx context.Context, root, action string) error {
        if bindings == nil { return security.ErrUnavailable }
        return bindings.AuthorizeResource(ctx, root, action)
    }
    cfg.Runtime.Trusted = func(ctx context.Context, operation string) error {
        if bindings == nil { return security.ErrUnavailable }
        return bindings.AuthorizeTrusted(ctx, operation)
    }

    runtime, err := pkgs.NewApp(cfg.Runtime)
    if err != nil { return nil, err }
    bindings, err = module.NewRegistry(runtime, compiled, cfg.Observer)
    if err != nil { return nil, err }
    seen := make(map[string]struct{}, len(def.Modules))
    for _, m := range def.Modules {
        if m == nil { return nil, ErrInvalid }
        id := m.ID()
        if _, ok := seen[id]; ok { return nil, fmt.Errorf("%w: duplicate module %s", ErrInvalid, id) }
        seen[id] = struct{}{}
        if err := bindings.Install(m); err != nil { return nil, err }
    }
    if err := bindings.Seal(); err != nil { return nil, fmt.Errorf("%w: incomplete contract: %v", ErrInvalid, err) }
    return &App{runtime: runtime, registry: bindings, workers: bindings.Workers(), done: make(chan struct{})}, nil
}

// Start publishes endpoints only after Fabric approval and readiness checks.
func (a *App) Start(ctx context.Context) error {
    if a == nil || ctx == nil { return ErrInvalid }
    a.mu.Lock()
    defer a.mu.Unlock()
    if a.started || a.stopped { return ErrStopped }
    workerCtx, cancel := context.WithCancel(ctx)
    if err := a.runtime.Start(workerCtx); err != nil {
        cancel()
        return err
    }
    a.started = true
    a.cancel = cancel
    for _, w := range a.workers {
        w := w
        a.wg.Add(1)
        go func() {
            defer a.wg.Done()
            err := w.Run(workerCtx)
            if workerCtx.Err() == nil {
                if err == nil { err = ErrWorkerExited }
                a.mu.Lock()
                a.workErr = errors.Join(a.workErr, fmt.Errorf("worker %s: %w", w.ID, err))
                a.mu.Unlock()
                // Stop on a separate goroutine; Stop waits for all workers.
                go a.Stop()
            }
        }()
    }
    go func() { <-workerCtx.Done(); _ = a.Stop() }()
    return nil
}

// Stop is idempotent and does not return before all owned workers exit.
func (a *App) Stop() error {
    if a == nil { return nil }
    a.stopOnce.Do(func() {
        a.mu.Lock()
        a.stopped = true
        cancel := a.cancel
        a.mu.Unlock()
        if cancel != nil { cancel() }
        err := a.runtime.Stop()
        a.wg.Wait()
        a.mu.Lock()
        a.stopErr = errors.Join(err, a.workErr)
        close(a.done)
        a.mu.Unlock()
    })
    <-a.done
    a.mu.Lock()
    defer a.mu.Unlock()
    return a.stopErr
}

func (a *App) Wait(ctx context.Context) error {
    if a == nil || ctx == nil { return ErrInvalid }
    a.mu.Lock()
    started := a.started
    a.mu.Unlock()
    if !started { return ErrInvalid }
    select {
    case <-a.done: return a.Err()
    case <-ctx.Done(): return ctx.Err()
    }
}

func (a *App) Err() error {
    if a == nil { return ErrInvalid }
    a.mu.Lock()
    defer a.mu.Unlock()
    return errors.Join(a.workErr, a.stopErr)
}

func (a *App) Connection() *nats.Conn {
    if a == nil { return nil }
    return a.runtime.Connection()
}
