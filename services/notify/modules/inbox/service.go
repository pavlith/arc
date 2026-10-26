// Package inbox implements event-driven notification effects under the Notifications owner schema.
package inbox

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/notify/modules/delivery"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"gorm.io/gorm"
)

const Durable = "notify-task-created-v1"

type Service struct {
	DB     *sql.DB
	GormDB *gorm.DB
}

// Effect uses operator-managed active addressing, never a recipient from the event.
// No private task data is fetched or copied into the notification.
func (s *Service) Effect(ctx context.Context, tx *sql.Tx, ev events.Envelope) error {
	var q taskv1.CreatedEvent
	if json.Unmarshal(ev.Payload, &q) != nil || q.TaskID != ev.AggregateID {
		return security.ErrDenied
	}
	rows, e := tx.QueryContext(ctx, `SELECT recipient_user_id FROM notify.subscriptions WHERE workspace_id=$1 AND acl_root_id=$2 AND active`, q.WorkspaceID, q.RootID)
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
		id := newID()
		_, e = tx.ExecContext(ctx, `INSERT INTO notify.notifications(id,recipient_user_id,event_id,kind) VALUES($1,$2,$3,'task.created')`, id, user, ev.ID)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO notify.delivery_intents(notification_id,recipient_user_id,channel,dedup_key) VALUES($1,$2,'fake',$3)`, id, user, delivery.DedupKey(id, user, "fake"))
		if e != nil {
			return e
		}
	}
	return nil
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
