// Package models contains the Contacts owner's persistent records.
package models

import "time"

type Root struct {
	RootID      string `gorm:"column:acl_root_id;primaryKey"`
	WorkspaceID string
	OwnerID     string
	State       string
	Name        string
	Revision    int64
}

func (Root) TableName() string { return "roots" }

type Contact struct {
	ID           string `gorm:"primaryKey"`
	UID          string
	WorkspaceID  string
	RootID       string `gorm:"column:acl_root_id"`
	DisplayName  string
	Organization string
	Role         string
	Fields       string
	SearchText   string
	Revision     int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

func (Contact) TableName() string { return "contacts" }
