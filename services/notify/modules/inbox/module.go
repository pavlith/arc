package inbox

import (
	"context"
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
	GormDB     *gorm.DB
	Subject    string
	Durable    string
	Channel    string
	Contract   *contract.Compiled // Approved producer artifact (Tasks).
	Permit     func(context.Context) error
	Connection func() *nats.Conn
}

func (m *Module) ID() string {
	if m.durable() == Durable {
		return "inbox"
	}
	return "inbox-" + m.durable()
}
func (m *Module) Register(r *module.Registry) error {
	if m == nil || m.GormDB == nil || m.Contract == nil || m.Permit == nil ||
		m.Connection == nil {
		return module.ErrInvalid
	}
	hasEvent := false
	for _, e := range m.Contract.Manifest.Events {
		if e.Subject == m.subject() {
			hasEvent = true
		}
	}
	if !hasEvent {
		return module.ErrInvalid
	}
	return r.AddWorker(module.Worker{ID: "notification-inbox-" + m.durable(), Run: m.Run})
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
		Store:    events.Store{DB: m.GormDB},
		Contract: m.Contract, Permit: m.Permit,
	}
	gormEffect := (&Service{GormDB: m.GormDB, Channel: m.Channel}).Effect
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			work, cancel := context.WithTimeout(ctx, 5*time.Second)

			err = gormDelivery.Pull(work, js, m.subject(), m.durable(), gormEffect)

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

func (m *Module) subject() string {
	if m.Subject != "" {
		return m.Subject
	}
	return taskv1.CreatedSubject
}
func (m *Module) durable() string {
	if m.Durable != "" {
		return m.Durable
	}
	return Durable
}
