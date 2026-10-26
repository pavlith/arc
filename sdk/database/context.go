package database

import (
	"context"

	"gorm.io/gorm"
)

type transactionKey struct{}
type transaction struct{ owner, db *gorm.DB }

// TransactionContext shares an owner transaction across in-process Core modules.
// It never permits a different service's handle to join that transaction.
func TransactionContext(ctx context.Context, owner, tx *gorm.DB) context.Context {
	return context.WithValue(ctx, transactionKey{}, transaction{owner, tx})
}

// FromContext returns the owner's current transaction, or its ordinary handle.
func FromContext(ctx context.Context, owner *gorm.DB) *gorm.DB {
	if tx, ok := ctx.Value(transactionKey{}).(transaction); ok && tx.owner == owner {
		return tx.db
	}
	return owner
}
