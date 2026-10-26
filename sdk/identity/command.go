package identity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
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
	e = c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.command_results(actor,operation,idempotency_key,request_hash) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, "user:"+s.UserID, op, meta.IdempotencyKey, digest); e != nil {
			return e
		}
		var storedHash, result []byte
		if e := t.QueryRowContext(ctx, `SELECT request_hash,result FROM identity.command_results WHERE actor=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`, "user:"+s.UserID, op, meta.IdempotencyKey).Scan(&storedHash, &result); e != nil {
			return e
		}
		if !bytes.Equal(digest, storedHash) {
			return ErrConflict
		}
		if result != nil {
			return json.Unmarshal(result, &out)
		}
		var e error
		out, e = h(context.WithValue(ctx, transactionKey{}, t), r)
		if e != nil {
			return e
		}
		result, e = json.Marshal(out)
		if e != nil {
			return e
		}
		_, e = t.ExecContext(ctx, `UPDATE identity.command_results SET result=$4 WHERE actor=$1 AND operation=$2 AND idempotency_key=$3`, "user:"+s.UserID, op, meta.IdempotencyKey, result)
		return e
	})
	return out, e
}
