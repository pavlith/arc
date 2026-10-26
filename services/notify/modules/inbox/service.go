// Package inbox implements event-driven notification effects under the Notify owner database.
package inbox

import (
	"crypto/rand"
	"fmt"

	"gorm.io/gorm"
)

const Durable = "notify-task-created-v1"

type Service struct {
	GormDB *gorm.DB
}

// Effect uses operator-managed active addressing, never a recipient from the event.
// No private task data is fetched or copied into the notification.

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
