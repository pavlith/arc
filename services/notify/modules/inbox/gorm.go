package inbox

import (
	"context"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/services/notify/models"
	"github.com/pavlith/arc/services/notify/modules/delivery"
	inboxevents "github.com/pavlith/arc/services/notify/modules/outbox"
	"gorm.io/gorm"
)

// Effect persists only operator-selected recipient effects in the same
// owner-local transaction as the inbox deduplication record.
func (s *Service) Effect(ctx context.Context, tx *gorm.DB, ev events.Envelope) error {
	kind, workspace, root, target, _, err := eventTarget(ev)
	if err != nil {
		return err
	}
	if kind == "" {
		return nil
	}
	rows, err := tx.WithContext(ctx).Raw(
		"SELECT recipient_user_id FROM subscriptions WHERE workspace_id=? AND acl_root_id=? AND active=1 AND resource_kind=?",
		workspace, root, kind).Rows()
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
			ID: id, RecipientID: recipient, EventID: ev.ID, Kind: kind + "." + eventAction(ev),
			WorkspaceID: workspace, RootID: root, ResourceKind: kind, ResourceID: target, Revision: 1,
		}).Error; err != nil {
			return err
		}
		if s.Channel != "" {
			if err := tx.WithContext(ctx).Create(&models.DeliveryIntent{
				NotificationID: id, RecipientID: recipient,
				Channel: s.Channel, DedupKey: delivery.DedupKey(id, recipient, s.Channel),
			}).Error; err != nil {
				return err
			}
		}
		if err := inboxevents.Change(ctx, tx, recipient, id, 1); err != nil {
			return err
		}
	}
	return nil
}
