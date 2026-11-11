package models

import "time"

type TaskDetails struct {
	TaskID      string `gorm:"column:task_id;primaryKey"`
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	TeamID      string
	StatusID    string
	Identifier  string
	Description string
	Priority    int
	DueDate     *time.Time
	SortOrder   int64
	Revision    int64
	ArchivedAt  *time.Time
}

func (TaskDetails) TableName() string { return "task_details" }

type TaskAssignee struct {
	TaskID string `gorm:"column:task_id;primaryKey"`
	UserID string `gorm:"column:user_id;primaryKey"`
}

func (TaskAssignee) TableName() string { return "task_assignees" }
