package delivery

import (
	"context"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

// Deliver retries durable fake delivery intents with the persisted stable
// provider key. An uncertain provider timeout can be replayed safely only
// because the provider itself deduplicates the key.
func (s *Service) Deliver(ctx context.Context, provider Provider) (int, error) {
	if provider == nil || s.GormDB == nil {
		return 0, security.ErrUnavailable
	}
	n := 0
	var sendErr error
	err := database.RetryBusy(ctx, func() error {
		return s.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Obtain the SQLite writer lock before reading the pending batch.
			locked := tx.Exec(`UPDATE delivery_intents SET attempts=attempts
				WHERE rowid=(SELECT rowid FROM delivery_intents WHERE delivered_at IS NULL
				ORDER BY notification_id LIMIT 1)`)
			if locked.Error != nil {
				return locked.Error
			}
			rows, err := tx.Raw(`SELECT notification_id,recipient_user_id,dedup_key
				FROM delivery_intents WHERE delivered_at IS NULL ORDER BY notification_id LIMIT 100`).Rows()
			if err != nil {
				return err
			}
			type intent struct{ id, recipient, key string }
			batch := []intent{}
			for rows.Next() {
				var v intent
				if err := rows.Scan(&v.id, &v.recipient, &v.key); err != nil {
					rows.Close()
					return err
				}
				batch = append(batch, v)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			for _, v := range batch {
				providerErr := provider.Send(ctx, v.recipient, v.key)
				if providerErr != nil {
					sendErr = providerErr
				}
				var delivered any
				if providerErr == nil {
					delivered = time.Now().UTC()
					n++
				}
				if err := tx.Exec(`UPDATE delivery_intents SET attempts=attempts+1,delivered_at=?
					WHERE notification_id=? AND recipient_user_id=? AND channel='fake'`,
					delivered, v.id, v.recipient).Error; err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	return n, sendErr
}
