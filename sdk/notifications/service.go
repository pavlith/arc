// Package notifications implements atomic inbox/notification/intent effects.
package notifications

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/sdk/tasks"
	"sync"
)

const Durable = "notifications-task-created-v1"

type Service struct{ DB *sql.DB }

// Effect uses operator-managed active addressing, never a recipient from the event.
// No private task data is fetched or copied into the notification.
func (s *Service) Effect(ctx context.Context, tx *sql.Tx, ev events.Envelope) error {
	var q tasks.CreatedEvent
	if json.Unmarshal(ev.Payload, &q) != nil || q.TaskID != ev.AggregateID {
		return security.ErrDenied
	}
	rows, e := tx.QueryContext(ctx, `SELECT recipient_user_id FROM notifications.subscriptions WHERE workspace_id=$1 AND acl_root_id=$2 AND active`, q.WorkspaceID, q.RootID)
	if e != nil {
		return e
	}
	recipients := []string{}
	for rows.Next() {
		var user string
		if e = rows.Scan(&user); e != nil {
			rows.Close()
			return e
		}
		recipients = append(recipients, user)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, user := range recipients {
		id := tasks.NewID()
		_, e = tx.ExecContext(ctx, `INSERT INTO notifications.notifications(id,recipient_user_id,event_id,kind) VALUES($1,$2,$3,'task.created')`, id, user, ev.ID)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO notifications.delivery_intents(notification_id,recipient_user_id,channel,dedup_key) VALUES($1,$2,'fake',$3)`, id, user, DedupKey(id, user, "fake"))
		if e != nil {
			return e
		}
	}
	return nil
}
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
