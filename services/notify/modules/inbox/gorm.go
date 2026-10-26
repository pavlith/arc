package inbox

import (
	"context"
	"encoding/json"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/notify/models"
	"github.com/pavlith/arc/services/notify/modules/delivery"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"gorm.io/gorm"
)

// EffectGORM persists only operator-selected recipient effects in the same
// owner-local transaction as the inbox deduplication record.
func (s *Service) EffectGORM(ctx context.Context, tx *gorm.DB, ev events.Envelope) error {
	var q taskv1.CreatedEvent
	if json.Unmarshal(ev.Payload, &q) != nil || q.TaskID != ev.AggregateID {
		return security.ErrDenied
	}
	rows, err := tx.WithContext(ctx).Raw(
		"SELECT recipient_user_id FROM subscriptions WHERE workspace_id=? AND acl_root_id=? AND active=1",
		q.WorkspaceID, q.RootID).Rows()
	if err != nil {
		return err
	}
	recipients := []string{}
	for rows.Next() {
		var recipient string
		if err := rows.Scan(&recipient); err != nil {
			rows.Close()
			return err
		}
		recipients = append(recipients, recipient)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, recipient := range recipients {
		id := newID()
		if err := tx.WithContext(ctx).Create(&models.Notification{
			ID: id, RecipientID: recipient, EventID: ev.ID, Kind: "task.created",
		}).Error; err != nil {
			return err
		}
		if err := tx.WithContext(ctx).Create(&models.DeliveryIntent{
			NotificationID: id, RecipientID: recipient,
			Channel: "fake", DedupKey: delivery.DedupKey(id, recipient, "fake"),
		}).Error; err != nil {
			return err
		}
	}
	return nil
}
