package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

type Scope struct {
	WorkspaceID string `json:"workspace_id"`
	RootID      string `json:"acl_root_id"`
}
type InboxPage struct {
	Limit  int    `json:"limit"`
	Cursor string `json:"cursor,omitempty"`
	Tab    string `json:"tab,omitempty"`
}
type NotificationState struct {
	ID           string     `json:"id"`
	ReadAt       *time.Time `json:"read_at"`
	ArchivedAt   *time.Time `json:"archived_at"`
	SnoozedUntil *time.Time `json:"snoozed_until"`
	Revision     int64      `json:"revision"`
}
type Notification struct {
	NotificationState
	Scope
	TaskID    string    `json:"task_id"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
}
type InboxResult struct {
	Notifications []Notification `json:"notifications"`
	UnreadCount   int64          `json:"unread_count"`
	NextCursor    string         `json:"next_cursor,omitempty"`
}
type NotificationChange struct {
	ID       string     `json:"id"`
	Action   string     `json:"action"`
	Until    *time.Time `json:"until,omitempty"`
	Revision int64      `json:"revision"`
}
type MarkAllResult struct {
	Updated int64 `json:"updated"`
}
type Subscription struct {
	Scope
	Active bool `json:"active"`
}
type SubscriptionsResult struct {
	Subscriptions []Subscription `json:"subscriptions"`
	NextCursor    string         `json:"next_cursor,omitempty"`
}

var (
	InboxList        = module.Query[InboxPage, InboxResult]{ID: "notify.inbox.list"}
	InboxUpdate      = module.Command[NotificationChange, NotificationState]{ID: "notify.inbox.update"}
	InboxMarkAll     = module.Command[Empty, MarkAllResult]{ID: "notify.inbox.mark_all_read"}
	Subscribe        = module.Command[Scope, Subscription]{ID: "notify.subscriptions.subscribe"}
	Unsubscribe      = module.Command[Scope, Subscription]{ID: "notify.subscriptions.unsubscribe"}
	SubscriptionList = module.Query[InboxPage, SubscriptionsResult]{ID: "notify.subscriptions.list"}
)
