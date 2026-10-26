package delivery

import (
    "context"
    "database/sql"
    "errors"
    "time"

    "github.com/pavlith/arc/pkgs/module"
    "github.com/pavlith/arc/pkgs/security"
)

type Module struct {
    DB *sql.DB
    Provider Provider
    Permit func(context.Context) error
}
func (*Module) ID() string {return "delivery"}
func (m *Module) Register(r *module.Registry) error {
    if m==nil || m.DB==nil || m.Provider==nil || m.Permit==nil {return module.ErrInvalid}
    return r.AddWorker(module.Worker{ID:"notification-delivery",Run:m.Run})
}
func (m *Module) Run(ctx context.Context) error {
    writer:=&Service{DB:m.DB}
    ticker:=time.NewTicker(100*time.Millisecond)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():return nil
        case <-ticker.C:
            work,cancel:=context.WithTimeout(ctx,5*time.Second)
            if err:=m.Permit(work);err!=nil {
                cancel()
                if ctx.Err()!=nil{return nil}
                return err // fail closed on unapproved consumer/producer.
            }
            _,err:=writer.Deliver(work,m.Provider)
            cancel()
            if err!=nil && ctx.Err()==nil {
                if errors.Is(err,security.ErrDenied)||errors.Is(err,security.ErrUnauthenticated){return err}
                // DB/provider errors retain stable persisted delivery_intents keys.
            }
        }
    }
}
