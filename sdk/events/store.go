// Package events provides transactional command replay, outbox and inbox helpers.
// Store.DB must be the domain owner's database; migration 000004 supplies the test/Core layout.
package events

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
)

type Store struct {
	DB     *sql.DB
	Schema string
}

func (s Store) table(name string) (string, error) {
	if s.DB == nil || !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(s.Schema) {
		return "", security.ErrUnavailable
	}
	return `"` + s.Schema + `"."` + name + `"`, nil
}

// Command binds replay identity to verified invocation claims and stores the result
// in the same domain transaction as handler effects and outbox records.
func Command[Req, Res any](ctx context.Context, s Store, m *contract.Compiled, id string, q Req, h func(context.Context, *sql.Tx, Req) (Res, error)) (Res, error) {
	var zero Res
	cl, ok := rpc.VerifiedClaims(ctx)
	meta, hasMeta := rpc.Metadata(ctx)
	if !ok || !hasMeta || meta.IdempotencyKey == "" || len(meta.IdempotencyKey) > 128 || cl.Operation != id {
		return zero, rpc.SecurityError(security.ErrUnauthenticated)
	}
	o, e := m.Operation(id)
	if e != nil || o.Kind != "command" {
		return zero, contract.ErrInvalid
	}
	table, e := s.table("command_results")
	if e != nil {
		return zero, e
	}
	raw, e := security.CanonicalJSON(meta.Payload)
	if e != nil {
		return zero, contract.ErrInvalid
	}
	hash := sha256.Sum256(raw)
	t, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return zero, rpc.SecurityError(security.ErrUnavailable)
	}
	defer t.Rollback()
	// Lock collisions only serialize work; equality still uses the full primary key.
	lockKey, _ := json.Marshal([]string{cl.Subject, id, meta.IdempotencyKey})
	if _, e = t.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(lockKey)); e != nil {
		return zero, rpc.SecurityError(security.ErrUnavailable)
	}
	var stored, result []byte
	e = t.QueryRowContext(ctx, `SELECT request_hash,result FROM `+table+` WHERE actor=$1 AND operation=$2 AND idempotency_key=$3`, cl.Subject, id, meta.IdempotencyKey).Scan(&stored, &result)
	if e == nil {
		if string(stored) != string(hash[:]) {
			return zero, &rpc.Error{Code: rpc.CodeConflict, Message: "idempotency payload mismatch"}
		}
		if json.Unmarshal(result, &zero) != nil {
			return zero, rpc.SecurityError(security.ErrUnavailable)
		}
		return zero, nil
	}
	if e != sql.ErrNoRows {
		return zero, rpc.SecurityError(security.ErrUnavailable)
	}
	resultValue, e := h(ctx, t, q)
	if e != nil {
		return zero, e
	}
	result, e = json.Marshal(resultValue)
	if e != nil || m.Validate(o.ResponseSchema, result) != nil {
		return zero, &rpc.Error{Code: rpc.CodeInternal, Message: "response schema mismatch"}
	}
	_, e = t.ExecContext(ctx, `INSERT INTO `+table+`(actor,operation,idempotency_key,request_hash,result) VALUES($1,$2,$3,$4,$5)`, cl.Subject, id, meta.IdempotencyKey, hash[:], result)
	if e != nil {
		return zero, rpc.SecurityError(security.ErrUnavailable)
	}
	if e = t.Commit(); e != nil {
		return zero, rpc.SecurityError(security.ErrUnavailable)
	}
	return resultValue, nil
}

type Envelope struct {
	ID          string          `json:"event_id"`
	Type        string          `json:"type"`
	Version     int             `json:"schema_version"`
	AggregateID string          `json:"aggregate_id"`
	OccurredAt  time.Time       `json:"occurred_at"`
	Traceparent string          `json:"traceparent,omitempty"`
	Payload     json.RawMessage `json:"payload"`
}

func Validate(m *contract.Compiled, subject string, e Envelope) error {
	if !regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`).MatchString(e.ID) || e.Version != 1 || e.AggregateID == "" || e.OccurredAt.IsZero() {
		return contract.ErrInvalid
	}
	for _, ev := range m.Manifest.Events {
		if ev.Name == e.Type && ev.Subject == subject {
			return m.Validate(ev.Schema, e.Payload)
		}
	}
	return contract.ErrInvalid
}
func (s Store) Enqueue(ctx context.Context, t *sql.Tx, m *contract.Compiled, subject string, e Envelope) error {
	if t == nil {
		return security.ErrUnavailable
	}
	table, err := s.table("outbox")
	if err != nil {
		return err
	}
	if err = Validate(m, subject, e); err != nil {
		return err
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > rpc.MaxMessageSize {
		return contract.ErrInvalid
	}
	_, err = t.ExecContext(ctx, `INSERT INTO `+table+`(event_id,subject,envelope) VALUES($1,$2,$3)`, e.ID, subject, raw)
	return err
}

// Consume atomically commits inbox and internal domain effects. Event metadata
// never supplies an invocation or permission to fetch private resource contents.
func (s Store) Consume(ctx context.Context, consumer, subject string, m *contract.Compiled, raw []byte, h func(context.Context, *sql.Tx, Envelope) error) error {
	if consumer == "" || h == nil {
		return contract.ErrInvalid
	}
	var ev Envelope
	if contract.Strict(raw, &ev) != nil || Validate(m, subject, ev) != nil {
		return contract.ErrInvalid
	}
	table, e := s.table("inbox")
	if e != nil {
		return e
	}
	canonical, e := security.CanonicalJSON(raw)
	if e != nil {
		return e
	}
	hash := sha256.Sum256(canonical)
	t, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer t.Rollback()
	res, e := t.ExecContext(ctx, `INSERT INTO `+table+`(consumer,event_id,request_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, consumer, ev.ID, hash[:])
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		var old []byte
		if e = t.QueryRowContext(ctx, `SELECT request_hash FROM `+table+` WHERE consumer=$1 AND event_id=$2`, consumer, ev.ID).Scan(&old); e != nil {
			return e
		}
		if string(old) != string(hash[:]) {
			return errors.New("conflicting event_id")
		}
		return nil
	}
	if e = h(ctx, t, ev); e != nil {
		return e
	}
	return t.Commit()
}
