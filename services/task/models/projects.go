package models

import "time"

type Project struct {
	ID          string `gorm:"primaryKey"`
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	TeamID      *string
	Name        string
	Description string
	Color       string
	Status      string
	StartDate   *time.Time
	DueDate     *time.Time
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  *time.Time
}

func (Project) TableName() string { return "projects" }

type Label struct {
	ID          string `gorm:"primaryKey"`
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	Name        string
	Color       string
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  *time.Time
}

func (Label) TableName() string { return "labels" }

type TaskLabel struct {
	TaskID      string `gorm:"primaryKey"`
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	LabelID     string `gorm:"primaryKey"`
}

func (TaskLabel) TableName() string { return "task_labels" }
