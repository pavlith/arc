package models

import "time"

type WorkTemplate struct {
	ID          string `gorm:"primaryKey"`
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	TeamID      string
	Name        string
	Definition  string
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  *time.Time
}

func (WorkTemplate) TableName() string { return "work_templates" }
