package migrations

import (
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
)

// Backfill a stable, timezone-independent sort key without SQLite JSON/version
// assumptions. Existing occurrence identities, summaries and tombstones stay intact.
func unifiedOrder(tx *gorm.DB) error {
	if err := tx.Exec("ALTER TABLE mail_messages ADD COLUMN internal_unix INTEGER NOT NULL DEFAULT 0").Error; err != nil {
		return err
	}
	after := ""
	for {
		var rows []struct {
			ID      string
			Summary []byte
		}
		if err := tx.Table("mail_messages").Select("id,summary").Where("id>?", after).Order("id").Limit(128).Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			var summary struct {
				InternalDate *time.Time `json:"internal_date"`
			}
			if json.Unmarshal(row.Summary, &summary) != nil || summary.InternalDate == nil {
				return errors.New("mail: invalid indexed internal date")
			}
			if err := tx.Exec("UPDATE mail_messages SET internal_unix=? WHERE id=?", summary.InternalDate.UnixMicro(), row.ID).Error; err != nil {
				return err
			}
			after = row.ID
		}
	}
	return tx.Exec("CREATE INDEX mail_message_chronology ON mail_messages(folder_id,present,uid_validity,internal_unix DESC,id DESC)").Error
}
