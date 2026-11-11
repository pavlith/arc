package models

import "time"

type Comment struct {
	ID          string `gorm:"primaryKey"`
	TaskID      string
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	ParentID    *string
	AuthorID    string
	Body        string
	Resolved    bool
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  *time.Time
}

func (Comment) TableName() string { return "task_comments" }

type SavedView struct {
	ID          string `gorm:"primaryKey"`
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	OwnerID     string
	Name        string
	Description string
	Filters     string
	IsShared    bool
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  *time.Time
}

func (SavedView) TableName() string { return "saved_views" }
