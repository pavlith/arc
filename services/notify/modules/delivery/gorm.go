package delivery

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

type claim struct {
	NotificationID, RecipientUserID, Channel, DedupKey string
	Attempts                                           int
}

// Deliver commits a fenced lease before any external I/O. A crash can repeat an
// uncertain effect, always with the original persisted provider key.
func (s *Service) Deliver(ctx context.Context, p Provider) (int, error) {
	if s.GormDB == nil || p == nil {
		return 0, security.ErrUnavailable
	}
	channel := Channel(p)
	if channel == "" {
		return 0, nil
	}
	now := s.now()
	token := rand.Text()
	var row claim
	found := false
	err := database.RetryBusy(ctx, func() error {
		return s.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			found = false
			// Acquire the owner writer lock before selecting a candidate.
			if err := tx.Exec(`UPDATE delivery_intents SET attempts=attempts WHERE rowid=(SELECT rowid FROM delivery_intents WHERE channel=? AND delivered_at IS NULL AND failed_at IS NULL LIMIT 1)`, channel).Error; err != nil {
				return err
			}
			res := tx.Raw(`SELECT notification_id,recipient_user_id,channel,dedup_key,attempts FROM delivery_intents WHERE channel=? AND delivered_at IS NULL AND failed_at IS NULL AND (next_attempt_at IS NULL OR next_attempt_at<=?) AND (lease_until IS NULL OR lease_until<=?) ORDER BY notification_id LIMIT 1`, channel, now, now).Scan(&row)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				return nil
			}
			if row.Attempts >= 10 {
				return tx.Exec(`UPDATE delivery_intents SET failed_at=?,claim_token=NULL,lease_until=NULL WHERE notification_id=? AND recipient_user_id=? AND channel=?`, now, row.NotificationID, row.RecipientUserID, channel).Error
			}
			found = true
			return tx.Exec(`UPDATE delivery_intents SET attempts=attempts+1,claim_token=?,lease_until=? WHERE notification_id=? AND recipient_user_id=? AND channel=?`, token, now.Add(30*time.Second), row.NotificationID, row.RecipientUserID, channel).Error
		})
	})
	if err != nil || !found {
		return 0, err
	}
	work, cancel := context.WithTimeout(ctx, 5*time.Second)
	sendErr := p.Send(work, row.RecipientUserID, row.DedupKey)
	cancel()
	// Use a bounded cleanup context even when the caller deadline expired.
	finish, done := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer done()
	fields := map[string]any{"claim_token": nil, "lease_until": nil}
	if sendErr == nil {
		fields["delivered_at"] = s.now()
	} else if row.Attempts+1 >= 10 {
		fields["failed_at"] = s.now()
	} else {
		delay := time.Second * time.Duration(1<<min(row.Attempts, 8))
		fields["next_attempt_at"] = s.now().Add(delay)
	}
	var affected int64
	err = database.RetryBusy(finish, func() error {
		r := s.GormDB.WithContext(finish).Table("delivery_intents").Where("notification_id=? AND recipient_user_id=? AND channel=? AND claim_token=?", row.NotificationID, row.RecipientUserID, channel, token).Updates(fields)
		affected = r.RowsAffected
		return r.Error
	})
	if err != nil {
		return 0, err
	}
	if sendErr != nil {
		return 0, sendErr
	}
	if affected == 1 {
		return 1, nil
	}
	return 0, nil
}
func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
