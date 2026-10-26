// Package models defines GORM persistence records for the Notify owner.
package models

import "time"

type Inbox struct {
	Consumer    string    `gorm:"column:consumer;primaryKey"`
	EventID     string    `gorm:"column:event_id;primaryKey"`
	RequestHash []byte    `gorm:"column:request_hash;not null"`
	ReceivedAt  time.Time `gorm:"column:received_at;not null"`
}

func (Inbox) TableName() string { return "inbox" }

type Subscription struct {
	WorkspaceID string `gorm:"column:workspace_id;primaryKey"`
	RootID      string `gorm:"column:acl_root_id;primaryKey"`
	RecipientID string `gorm:"column:recipient_user_id;primaryKey"`
	Active      bool   `gorm:"column:active;not null"`
}

func (Subscription) TableName() string { return "subscriptions" }

type Notification struct {
	ID          string     `gorm:"column:id;primaryKey"`
	RecipientID string     `gorm:"column:recipient_user_id;not null"`
	EventID     string     `gorm:"column:event_id;not null"`
	Kind        string     `gorm:"column:kind;not null"`
	CreatedAt   time.Time  `gorm:"column:created_at;not null"`
	ReadAt      *time.Time `gorm:"column:read_at"`
}

func (Notification) TableName() string { return "notifications" }

type DeliveryIntent struct {
	NotificationID string     `gorm:"column:notification_id;primaryKey"`
	RecipientID    string     `gorm:"column:recipient_user_id;primaryKey"`
	Channel        string     `gorm:"column:channel;primaryKey"`
	DedupKey       string     `gorm:"column:dedup_key;not null"`
	Attempts       int        `gorm:"column:attempts;not null"`
	DeliveredAt    *time.Time `gorm:"column:delivered_at"`
}

func (DeliveryIntent) TableName() string { return "delivery_intents" }
