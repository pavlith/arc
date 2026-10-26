package inbox

import (
    "context"
    "database/sql"
    "errors"
    "time"

    "github.com/nats-io/nats.go"
    "github.com/pavlith/arc/pkgs/contract"
    "github.com/pavlith/arc/pkgs/events"
    "github.com/pavlith/arc/pkgs/module"
    "github.com/pavlith/arc/pkgs/security"
    tasksv1 "github.com/pavlith/arc/services/task/api/v1"
)

type Module struct {
    DB *sql.DB
    Contract *contract.Compiled // Approved producer artifact (Tasks).
    Permit func(context.Context) error
    Connection func() *nats.Conn
}
func (*Module) ID() string {return "inbox"}
func (m *Module) Register(r *module.Registry) error {
    if m==nil || m.DB==nil || m.Contract==nil || m.Permit==nil ||
      m.Connection==nil {return module.ErrInvalid}
    hasEvent:=false
    for _,e:=range m.Contract.Manifest.Events {
        if e.Name==tasksv1.CreatedName && e.Subject==tasksv1.CreatedSubject {hasEvent=true}
    }
    if !hasEvent {return module.ErrInvalid}
    return r.AddWorker(module.Worker{ID:"notification-inbox",Run:m.Run})
}
func (m *Module) Run(ctx context.Context) error {
    nc:=m.Connection()
    if nc==nil{return security.ErrUnavailable}
    js,err:=nc.JetStream()
    if err!=nil{return err}
    delivery:=events.Delivery{
       Store:events.Store{DB:m.DB,Schema:"notifications"},
       Contract:m.Contract,Permit:m.Permit,
    }
    effect:=(&Service{DB:m.DB}).Effect
    ticker:=time.NewTicker(100*time.Millisecond)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():return nil
        case <-ticker.C:
            work,cancel:=context.WithTimeout(ctx,5*time.Second)
            err=delivery.Pull(work,js,tasksv1.CreatedSubject,Durable,effect)
            cancel()
            if err==nil || errors.Is(err,nats.ErrTimeout) ||
               errors.Is(err,context.DeadlineExceeded) || ctx.Err()!=nil {continue}
            // Never process another message when the exact event permit is revoked.
            if pe:=m.Permit(ctx);pe!=nil{return pe}
            if errors.Is(err,security.ErrDenied)||errors.Is(err,security.ErrUnauthenticated){return err}
            // JetStream/DB outages are retried; inbox dedup persists across restarts.
        }
    }
}
