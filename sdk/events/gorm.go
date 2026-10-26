package events

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

// Store persists command replay and inbox/outbox in the calling domain's
// own SQLite file. It never accepts a SQL schema or a cross-service DB handle.
type Store struct{ DB *gorm.DB }

// Command executes the handler and its replay result in one transaction.
// Reserving the unique command key as the FIRST statement serializes competing
// writers without advisory locks. An aborted transaction leaves no
// reservation or domain effect. All retries recheck the verified payload hash.
func Command[Req, Res any](ctx context.Context, s Store, m *contract.Compiled, id string, q Req,
	handler func(context.Context, *gorm.DB, Req) (Res, error)) (Res, error) {
	var zero Res
	if ctx == nil || s.DB == nil || m == nil || handler == nil {
		return zero, security.ErrUnavailable
	}
	cl, ok := rpc.VerifiedClaims(ctx)
	meta, hasMeta := rpc.Metadata(ctx)
	if !ok || !hasMeta || meta.IdempotencyKey == "" || len(meta.IdempotencyKey) > 128 || cl.Operation != id {
		return zero, rpc.SecurityError(security.ErrUnauthenticated)
	}
	op, err := m.Operation(id)
	if err != nil || op.Kind != "command" {
		return zero, contract.ErrInvalid
	}
	raw, err := security.CanonicalJSON(meta.Payload)
	if err != nil {
		return zero, contract.ErrInvalid
	}
	hash := sha256.Sum256(raw)
	var value Res
	err = database.RetryBusy(ctx, func() error {
		return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			reservation := tx.Exec(
				`INSERT INTO command_results(actor,operation,idempotency_key,request_hash,result)
				VALUES(?,?,?,?,NULL) ON CONFLICT(actor,operation,idempotency_key) DO NOTHING`,
				cl.Subject, id, meta.IdempotencyKey, hash[:])
			if reservation.Error != nil {
				return reservation.Error
			}
			if reservation.RowsAffected == 0 {
				var oldHash, result []byte
				err := tx.Raw(
					`SELECT request_hash,result FROM command_results
					 WHERE actor=? AND operation=? AND idempotency_key=?`,
					cl.Subject, id, meta.IdempotencyKey).Row().Scan(&oldHash, &result)
				if err != nil {
					return err
				}
				if !bytes.Equal(oldHash, hash[:]) {
					return &rpc.Error{Code: rpc.CodeConflict, Message: "idempotency payload mismatch"}
				}
				if err := json.Unmarshal(result, &value); err != nil {
					return rpc.SecurityError(security.ErrUnavailable)
				}
				return nil
			}
			generated, err := handler(ctx, tx, q)
			if err != nil {
				return err
			}
			result, err := json.Marshal(generated)
			if err != nil || m.Validate(op.ResponseSchema, result) != nil {
				return &rpc.Error{Code: rpc.CodeInternal, Message: "response schema mismatch"}
			}
			wrote := tx.Exec(
				`UPDATE command_results SET result=? WHERE actor=? AND operation=? AND idempotency_key=?`,
				result, cl.Subject, id, meta.IdempotencyKey)
			if wrote.Error != nil || wrote.RowsAffected != 1 {
				return security.ErrUnavailable
			}
			value = generated
			return nil
		})
	})
	if err != nil {
		if database.IsBusy(err) || errors.Is(err, sql.ErrNoRows) {
			return zero, rpc.SecurityError(security.ErrUnavailable)
		}
		return zero, err
	}
	return value, nil
}

// Enqueue joins the handler's transaction. Publishing happens only after
// this transaction commits; a publish retry reuses the stored event ID.
func (s Store) Enqueue(ctx context.Context, tx *gorm.DB, m *contract.Compiled, subject string, ev Envelope) error {
	if s.DB == nil || tx == nil || m == nil {
		return security.ErrUnavailable
	}
	if err := Validate(m, subject, ev); err != nil {
		return err
	}
	raw, err := json.Marshal(ev)
	if err != nil || len(raw) > rpc.MaxMessageSize {
		return contract.ErrInvalid
	}
	return tx.WithContext(ctx).Exec(
		"INSERT INTO outbox(event_id,subject,envelope) VALUES(?,?,?)", ev.ID, subject, raw).Error
}

// Consume atomically persists the verified event hash and domain effects.
// Identical redelivery is a no-op; an event ID with different canonical content
// is rejected. The unique inbox key is acquired BEFORE reading prior results.
func (s Store) Consume(ctx context.Context, consumer, subject string,
	m *contract.Compiled, raw []byte, handler func(context.Context, *gorm.DB, Envelope) error) error {
	if ctx == nil || s.DB == nil || consumer == "" || m == nil || handler == nil {
		return contract.ErrInvalid
	}
	var ev Envelope
	if contract.Strict(raw, &ev) != nil || Validate(m, subject, ev) != nil {
		return contract.ErrInvalid
	}
	canonical, err := security.CanonicalJSON(raw)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(canonical)
	return database.RetryBusy(ctx, func() error {
		return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			insert := tx.Exec(
				`INSERT INTO inbox(consumer,event_id,request_hash) VALUES(?,?,?)
				ON CONFLICT(consumer,event_id) DO NOTHING`,
				consumer, ev.ID, hash[:])
			if insert.Error != nil {
				return insert.Error
			}
			if insert.RowsAffected == 0 {
				var stored []byte
				if err := tx.Raw(
					"SELECT request_hash FROM inbox WHERE consumer=? AND event_id=?",
					consumer, ev.ID).Row().Scan(&stored); err != nil {
					return err
				}
				if !bytes.Equal(stored, hash[:]) {
					return errors.New("conflicting event_id")
				}
				return nil
			}
			return handler(ctx, tx, ev)
		})
	})
}
