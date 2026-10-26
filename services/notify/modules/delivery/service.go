// Package delivery persists external delivery attempts and stable retry keys.
package delivery

import (
 "context"
 "crypto/sha256"
 "database/sql"
 "encoding/hex"
 "encoding/json"
 "sync"
 "github.com/pavlith/arc/pkgs/security"
)

type Service struct {DB *sql.DB}
func DedupKey(notification, recipient, channel string) string {
	b, _ := json.Marshal([]string{notification, recipient, channel})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Provider interface {
	Send(context.Context, string, string) error
}

// Deliver sends bounded persisted intents. Timeout keeps the same key on retry.
// Provider calls cannot be atomic with SQL; a non-idempotent provider may duplicate.
func (s *Service) Deliver(ctx context.Context, p Provider) (int, error) {
	if p == nil {
		return 0, security.ErrUnavailable
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT notification_id,recipient_user_id,dedup_key FROM notifications.delivery_intents WHERE delivered_at IS NULL ORDER BY notification_id LIMIT 100 FOR UPDATE SKIP LOCKED`)
	if e != nil {
		return 0, e
	}
	type intent struct{ id, user, key string }
	batch := []intent{}
	for rows.Next() {
		var v intent
		if e = rows.Scan(&v.id, &v.user, &v.key); e != nil {
			rows.Close()
			return 0, e
		}
		batch = append(batch, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	var sendErr error
	n := 0
	for _, v := range batch {
		e = p.Send(ctx, v.user, v.key)
		if e != nil {
			sendErr = e
		}
		_, qe := tx.ExecContext(ctx, `UPDATE notifications.delivery_intents SET attempts=attempts+1,delivered_at=CASE WHEN $2 THEN now() ELSE NULL END WHERE notification_id=$1`, v.id, e == nil)
		if qe != nil {
			return 0, qe
		}
		if e == nil {
			n++
		}
	}
	if e = tx.Commit(); e != nil {
		return 0, e
	}
	return n, sendErr
}

// FakeProvider is the only M0 external adapter. It records invocations and accepts
// each key once; Fail can simulate an uncertain timeout after the effect.
type FakeProvider struct {
	mu       sync.Mutex
	Calls    []string
	Accepted map[string]bool
	Fail     bool
}

func (p *FakeProvider) Send(ctx context.Context, recipient, key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Calls = append(p.Calls, key)
	if p.Accepted == nil {
		p.Accepted = map[string]bool{}
	}
	p.Accepted[key] = true
	if p.Fail {
		p.Fail = false
		return context.DeadlineExceeded
	}
	return nil
}
