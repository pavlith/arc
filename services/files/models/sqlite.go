// Package models contains Files-owned persistence records.
package models

import "time"

type Root struct {
	RootID      string `gorm:"column:acl_root_id;primaryKey"`
	WorkspaceID string `gorm:"column:workspace_id;not null"`
	State       string `gorm:"column:state;not null"`
}
func (Root) TableName() string { return "roots" }

type Folder struct {
	ID          string     `gorm:"column:id;primaryKey"`
	WorkspaceID string     `gorm:"column:workspace_id;not null"`
	RootID      string     `gorm:"column:acl_root_id;not null"`
	ParentID    *string    `gorm:"column:parent_id"`
	Name        string     `gorm:"column:name;not null"`
	Revision    int64      `gorm:"column:revision;not null"`
	CreatedAt   time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time  `gorm:"column:updated_at;not null"`
	ArchivedAt  *time.Time `gorm:"column:archived_at"`
}
func (Folder) TableName() string { return "folders" }

type Audit struct {
	ID          int64     `gorm:"column:id;primaryKey;autoIncrement"`
	WorkspaceID string    `gorm:"column:workspace_id;not null"`
	RootID      string    `gorm:"column:acl_root_id;not null"`
	FolderID    string    `gorm:"column:folder_id;not null"`
	Actor       string    `gorm:"column:actor;not null"`
	Operation   string    `gorm:"column:operation;not null"`
	Revision    int64     `gorm:"column:revision;not null"`
	RequestID   string    `gorm:"column:request_id;not null"`
	Traceparent string    `gorm:"column:traceparent;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
}
func (Audit) TableName() string { return "audit" }
