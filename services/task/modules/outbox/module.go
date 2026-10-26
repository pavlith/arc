// Package outbox publishes committed task events after approval and readiness.
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
		m.Registration.Digest != m.Contract.Digest || m.Registration.Service != "task" ||
		m.Connection == nil {
		return module.ErrInvalid
	}
	return r.AddWorker(module.Worker{ID: "task-outbox", Run: m.Run})
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
	gormDelivery := events.Delivery{
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

			_, err = gormDelivery.PublishBatch(work, js, 100)

			cancel()
			if err != nil && ctx.Err() == nil {
				// Approval/lease revocation is terminal, not a retryable data failure.
				if pe := m.Registry.Check(ctx, m.Registration); pe != nil {
					return pe
				}
				if errors.Is(err, security.ErrDenied) || errors.Is(err, security.ErrUnauthenticated) {
					return err
				}
				// JetStream and database failures are retried with stable event IDs.
			}
		}
	}
}
