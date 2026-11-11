package models

import (
	"time"
)

type Root struct {
	RootID      string `gorm:"column:acl_root_id;primaryKey"`
	WorkspaceID string
	OwnerID     string
	State       string
}

func (Root) TableName() string { return "roots" }

type Page struct {
	ID          string `gorm:"primaryKey"`
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	ParentID    *string
	Title       string
	Document    string
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  *time.Time
}

func (Page) TableName() string { return "pages" }

type Template struct {
	ID          string `gorm:"primaryKey"`
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	Title       string
	Document    string
	Revision    int64
	ArchivedAt  *time.Time
}

func (Template) TableName() string { return "templates" }
