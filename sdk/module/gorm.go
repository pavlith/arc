package module

import (
	"context"
	"time"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/events"
	"gorm.io/gorm"
)

// BindCommand keeps the typed module contract and telemetry but executes
// the handler under the owner-local SQLite GORM replay transaction.
func BindCommand[Req, Res any](r *Registry, op Command[Req, Res],
	p Policy, store events.Store, h func(context.Context, *gorm.DB, Req) (Res, error)) error {
	if r == nil || h == nil || store.DB == nil {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.preflight(op.ID, "command", p); err != nil {
		return err
	}
	mod := r.current
	if err := sdk.HandleCommand(r.app, op.ID, store, func(ctx context.Context, tx *gorm.DB, req Req) (res Res, err error) {
		start := time.Now()
		defer r.observe(ctx, mod, op.ID, "command", start, &err)
		return h(ctx, tx, req)
	}); err != nil {
		return err
	}
	r.policies[op.ID] = policyEntry{module: mod, policy: p}
	return nil
}
