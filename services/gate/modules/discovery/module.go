// Package discovery synchronizes Gate's approved, signed Fabric route snapshot.
// NATS events are untrusted hints; the gateway always fetches an authenticated snapshot.
package discovery

import (
    "context"
    "errors"
    "sync"

    "github.com/nats-io/nats.go"
    edge "github.com/pavlith/arc/services/gate/modules/http"
)

var ErrInvalid = errors.New("discovery: missing Gate")

type Module struct {
    Gateway *edge.Gate
    Connection *nats.Conn
    mu sync.Mutex
    cancel context.CancelFunc
    done chan struct{}
    closeHints func()
    started bool
}

func New(g *edge.Gate, nc *nats.Conn) (*Module,error) {
    if g==nil { return nil,ErrInvalid }
    return &Module{Gateway:g,Connection:nc},nil
}

func (m *Module) ID() string { return "discovery" }

func (m *Module) Start(ctx context.Context) error {
    if m==nil || ctx==nil { return ErrInvalid }
    m.mu.Lock()
    defer m.mu.Unlock()
    if m.started { return ErrInvalid }
    var hints <-chan struct{}
    var closeHints func()
    if m.Connection!=nil {
        var err error
        hints,closeHints,err=edge.SubscribeChanges(m.Connection)
        if err!=nil { return err }
        if err=m.Connection.FlushWithContext(ctx);err!=nil {
            closeHints()
            return err
        }
    }
    runCtx,cancel:=context.WithCancel(ctx)
    m.cancel=cancel
    m.closeHints=closeHints
    m.done=make(chan struct{})
    m.started=true
    go func(){ defer close(m.done); m.Gateway.Run(runCtx,hints) }()
    return nil
}

func (m *Module) Stop() {
    if m==nil { return }
    m.mu.Lock()
    cancel,done,closeHints:=m.cancel,m.done,m.closeHints
    m.cancel=nil
    m.closeHints=nil
    m.mu.Unlock()
    if cancel!=nil {cancel()}
    if done!=nil {<-done}
    if closeHints!=nil {closeHints()}
}
