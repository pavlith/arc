// Package models defines GORM persistence records, not public RPC DTOs.
package models

import "time"

type Root struct {
	RootID      string `gorm:"column:acl_root_id;primaryKey"`
	WorkspaceID string `gorm:"column:workspace_id;not null"`
	State       string `gorm:"column:state;not null"`
}

func (Root) TableName() string { return "roots" }

type Task struct {
	ID          string    `gorm:"column:id;primaryKey"`
	WorkspaceID string    `gorm:"column:workspace_id;not null"`
	RootID      string    `gorm:"column:acl_root_id;not null"`
	Title       string    `gorm:"column:title;not null"`
	Status      string    `gorm:"column:status;not null"`
	CreatedBy   string    `gorm:"column:created_by;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null"`
}

func (Task) TableName() string { return "tasks" }

type Audit struct {
	ID          int64     `gorm:"column:id;primaryKey;autoIncrement"`
	TaskID      string    `gorm:"column:task_id;not null"`
	Actor       string    `gorm:"column:actor;not null"`
	Operation   string    `gorm:"column:operation;not null"`
	RequestID   string    `gorm:"column:request_id;not null"`
	Traceparent string    `gorm:"column:traceparent;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
}

func (Audit) TableName() string { return "audit" }

type CommandResult struct {
	Actor          string    `gorm:"column:actor;primaryKey"`
	Operation      string    `gorm:"column:operation;primaryKey"`
	IdempotencyKey string    `gorm:"column:idempotency_key;primaryKey"`
	RequestHash    []byte    `gorm:"column:request_hash;not null"`
	Result         []byte    `gorm:"column:result"`
	CreatedAt      time.Time `gorm:"column:created_at;not null"`
}

func (CommandResult) TableName() string { return "command_results" }

type Outbox struct {
	EventID     string     `gorm:"column:event_id;primaryKey"`
	Subject     string     `gorm:"column:subject;not null"`
	Envelope    []byte     `gorm:"column:envelope;not null"`
	CreatedAt   time.Time  `gorm:"column:created_at;not null"`
	PublishedAt *time.Time `gorm:"column:published_at"`
}

func (Outbox) TableName() string { return "outbox" }
