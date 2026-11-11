package outbox

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	"gorm.io/gorm"
)

var compiledOnce sync.Once
var compiled *contract.Compiled
var compileErr error

func ownContract() (*contract.Compiled, error) {
	compiledOnce.Do(func() { compiled, compileErr = contract.Compile(notifyv1.Artifact()) })
	return compiled, compileErr
}

// Change joins the caller's existing Notify-owner SQLite transaction.
// Only metadata crosses the broker; readers must reauthorize their refetch.
// For a collection invalidation notificationID is empty and revision is zero.
func Change(ctx context.Context, tx *gorm.DB, recipientID, notificationID string, revision int64) error {
	if ctx == nil || tx == nil || recipientID == "" ||
		(notificationID == "" && revision != 0) ||
		(notificationID != "" && revision < 1) {
		return security.ErrUnavailable
	}
	m, err := ownContract()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(notifyv1.InboxChanged{
		RecipientID: recipientID, NotificationID: notificationID, Revision: revision,
	})
	if err != nil {
		return err
	}
	aggregateID := notificationID
	if aggregateID == "" {
		aggregateID = recipientID
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return err
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	meta, _ := rpc.Metadata(ctx)
	ev := events.Envelope{
		ID:   fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]),
		Type: notifyv1.InboxChangedName, Version: 1, AggregateID: aggregateID,
		OccurredAt: time.Now().UTC(), Traceparent: meta.Traceparent, Payload: payload,
	}
	return (events.Store{DB: tx}).Enqueue(ctx, tx, m, notifyv1.InboxChangedSubject, ev)
}
