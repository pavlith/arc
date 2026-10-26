package module

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/pavlith/arc/pkgs/contract"
	"github.com/pavlith/arc/pkgs/events"
)

// Event types are tied to an immutable, approved event subject.
type Event[Payload any] struct {
	Name    string
	Subject string
}

// EnqueueEvent adds a typed payload to the domain transaction's outbox.
// It does not publish before commit and cannot authorize a consumer.
func EnqueueEvent[T any](ctx context.Context, store events.Store, tx *sql.Tx,
	artifact *contract.Compiled, def Event[T], envelope events.Envelope, payload T) error {
	if def.Name == "" || def.Subject == "" || envelope.Type != "" && envelope.Type != def.Name {
		return ErrInvalid
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	envelope.Type = def.Name
	envelope.Payload = raw
	return store.Enqueue(ctx, tx, artifact, def.Subject, envelope)
}

// ConsumeEvent verifies the source artifact and atomically commits inbox+effect.
// Deployments must separately prove EventPermit for the exact source/durable.
func ConsumeEvent[T any](ctx context.Context, store events.Store, consumer string,
	artifact *contract.Compiled, def Event[T], raw []byte,
	handler func(context.Context, *sql.Tx, events.Envelope, T) error) error {
	if def.Name == "" || def.Subject == "" || handler == nil {
		return ErrInvalid
	}
	return store.Consume(ctx, consumer, def.Subject, artifact, raw,
		func(ctx context.Context, tx *sql.Tx, envelope events.Envelope) error {
			if envelope.Type != def.Name {
				return ErrInvalid
			}
			var payload T
			if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
				return ErrInvalid
			}
			return handler(ctx, tx, envelope, payload)
		})
}
