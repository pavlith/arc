package sdk

import (
	"context"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"gorm.io/gorm"
)

// HandleGORMCommand binds a domain command to the owner's GORM transaction.
// Authorization is still performed by App before replay or domain effects.
func HandleGORMCommand[Req, Res any](app *App, id string, store events.GormStore,
	handler func(context.Context, *gorm.DB, Req) (Res, error)) error {
	if app == nil || store.DB == nil || handler == nil {
		return contract.ErrInvalid
	}
	return bindHandle(app, id, func(ctx context.Context, q Req) (Res, error) {
		return events.CommandGORM(ctx, store, app.compiled, id, q, handler)
	}, true)
}
