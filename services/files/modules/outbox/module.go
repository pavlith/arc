// Package outbox publishes committed Files metadata events with live Fabric permits.
package outbox

import (
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

type Module struct {
	GormDB       *gorm.DB
	Contract     *contract.Compiled
	Registry     sdk.Registry
	Registration sdk.Registration
	Connection   func() *nats.Conn
}

func (*Module) ID() string { return "outbox" }

func (m *Module) Register(r *module.Registry) error {
	if m == nil || m.GormDB == nil || m.Contract == nil || m.Registry == nil ||
		m.Connection == nil || m.Registration.Service != "files" ||
		m.Registration.Digest != m.Contract.Digest {
		return module.ErrInvalid
	}
	return r.AddWorker(module.Worker{ID: "files-outbox", Run: m.Run})
}
func (m *Module) Run(ctx context.Context) error {
	nc := m.Connection()
	if nc == nil {
		return security.ErrUnavailable
	}
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	delivery := events.Delivery{
		Store: events.Store{DB: m.GormDB}, Contract: m.Contract,
		Permit: func(ctx context.Context) error { return m.Registry.Check(ctx, m.Registration) },
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			work, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err = delivery.PublishBatch(work, js, 100)
			cancel()
			if err != nil && ctx.Err() == nil {
				if fail := m.Registry.Check(ctx, m.Registration); fail != nil {
					return fail
				}
				if errors.Is(err, security.ErrDenied) || errors.Is(err, security.ErrUnauthenticated) {
					return err
				}
			}
		}
	}
}
