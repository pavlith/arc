package inbox

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/security"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"gorm.io/gorm"
)

type Module struct {
	DB         *sql.DB
	GormDB     *gorm.DB
	Contract   *contract.Compiled // Approved producer artifact (Tasks).
	Permit     func(context.Context) error
	Connection func() *nats.Conn
}

func (*Module) ID() string { return "inbox" }
func (m *Module) Register(r *module.Registry) error {
	if m == nil || (m.DB == nil && m.GormDB == nil) || m.Contract == nil || m.Permit == nil ||
		m.Connection == nil {
		return module.ErrInvalid
	}
	hasEvent := false
	for _, e := range m.Contract.Manifest.Events {
		if e.Name == taskv1.CreatedName && e.Subject == taskv1.CreatedSubject {
			hasEvent = true
		}
	}
	if !hasEvent {
		return module.ErrInvalid
	}
	return r.AddWorker(module.Worker{ID: "notification-inbox", Run: m.Run})
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
		Store:    events.Store{DB: m.DB, Schema: "notify"},
		Contract: m.Contract, Permit: m.Permit,
	}
	gormDelivery := events.GormDelivery{
		Store: events.GormStore{DB: m.GormDB},
		Contract: m.Contract, Permit: m.Permit,
	}
	effect := (&Service{DB: m.DB}).Effect
	gormEffect := (&Service{GormDB: m.GormDB}).EffectGORM
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			work, cancel := context.WithTimeout(ctx, 5*time.Second)
			if m.GormDB != nil {
				err = gormDelivery.Pull(work, js, taskv1.CreatedSubject, Durable, gormEffect)
			} else {
				err = delivery.Pull(work, js, taskv1.CreatedSubject, Durable, effect)
			}
			cancel()
			if err == nil || errors.Is(err, nats.ErrTimeout) ||
				errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				continue
			}
			// Never process another message when the exact event permit is revoked.
			if pe := m.Permit(ctx); pe != nil {
				return pe
			}
			if errors.Is(err, security.ErrDenied) || errors.Is(err, security.ErrUnauthenticated) {
				return err
			}
			// JetStream/DB outages are retried; inbox dedup persists across restarts.
		}
	}
}
