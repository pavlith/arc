package identity

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

type transactionKey struct{}

// command commits a domain mutation, its audit and deduplication result together.
// Only non-secret domain responses use this path. Authentication uses its own
// one-time token/reuse protocol and never stores a plaintext token response.
func command[Req, Res any](ctx context.Context, c *Core, op string, r Req, h func(context.Context, Req) (Res, error)) (Res, error) {
	var zero Res
	var auth UserSession
	switch req := any(r).(type) {
	case DelegationRequest:
		auth = req.Session
	case DelegationIDRequest:
		auth = req.Session
	default:
		return zero, ErrDenied
	}
	s, e := c.user(ctx, auth)
	if e != nil {
		return zero, e
	}
	meta, ok := rpc.Metadata(ctx)
	if !ok || meta.IdempotencyKey == "" || len(meta.IdempotencyKey) > 128 {
		return zero, ErrDenied
	}
	raw, e := security.CanonicalJSON(meta.Payload)
	if e != nil {
		return zero, ErrDenied
	}
	digest := hash(string(raw))
	var out Res
	e = c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_command_results(actor,operation,idempotency_key,request_hash) VALUES( ?,?,?,?) ON CONFLICT DO NOTHING`, "user:"+s.UserID, op, meta.IdempotencyKey, digest).Error; e != nil {
			return e
		}
		var storedHash, result []byte
		if e := t.WithContext(ctx).Raw(`SELECT request_hash,result FROM identity_command_results WHERE actor=? AND operation=? AND idempotency_key=?`, "user:"+s.UserID, op, meta.IdempotencyKey).Row().Scan(&storedHash, &result); e != nil {
			return e
		}
		if !bytes.Equal(digest, storedHash) {
			return ErrConflict
		}
		if result != nil {
			return json.Unmarshal(result, &out)
		}
		var e error
		out, e = h(context.WithValue(database.TransactionContext(ctx, c.GormDB, t), transactionKey{}, t), r)
		if e != nil {
			return e
		}
		result, e = json.Marshal(out)
		if e != nil {
			return e
		}
		e = t.WithContext(ctx).Exec(`UPDATE identity_command_results SET result=? WHERE actor=? AND operation=? AND idempotency_key=?`, result, "user:"+s.UserID, op, meta.IdempotencyKey).Error
		return e
	})
	return out, e
}
