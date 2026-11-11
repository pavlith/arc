package v1

// InboxChanged is an invalidation hint, not notification content.
// The recipient is selected only by the Notify owner. A missing notification
// ID means the whole personal Inbox must be refetched (mark-all).
type InboxChanged struct {
	RecipientID    string `json:"recipient_user_id"`
	NotificationID string `json:"notification_id,omitempty"`
	Revision       int64  `json:"revision,omitempty"`
}

const InboxChangedName = "notify.inbox.changed"
const InboxChangedSubject = "evt.notify.inbox.changed.v1"
