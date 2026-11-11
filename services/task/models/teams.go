package models

import "time"

type Team struct {
	ID          string `gorm:"column:id;primaryKey"`
	WorkspaceID string `gorm:"column:workspace_id"`
	RootID      string `gorm:"column:acl_root_id"`
	Name        string
	Key         string
	Description string
	Color       string
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  *time.Time
}

func (Team) TableName() string { return "teams" }

type WorkflowStatus struct {
	ID          string `gorm:"column:id;primaryKey"`
	WorkspaceID string `gorm:"column:workspace_id"`
	RootID      string `gorm:"column:acl_root_id"`
	TeamID      string
	Name        string
	Category    string
	Color       string
	Position    int
	IsDefault   bool
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  *time.Time
}

func (WorkflowStatus) TableName() string { return "workflow_statuses" }

type TeamMember struct {
	TeamID      string `gorm:"primaryKey"`
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	UserID      string `gorm:"primaryKey"`
	CreatedAt   time.Time
}

func (TeamMember) TableName() string { return "team_members" }
