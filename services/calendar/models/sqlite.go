package models

import "time"

type Root struct {
	SyncEpoch    string
	SyncRevision int64
	SyncFloor    int64
	SyncReady    bool
	RootID       string `gorm:"column:acl_root_id;primaryKey"`
	WorkspaceID  string
	OwnerID      string
	State        string
	Name         string
	Timezone     string
	Revision     int64
}

func (Root) TableName() string { return "roots" }

type Event struct {
	UID         string
	ICalRaw     string
	ID          string `gorm:"primaryKey"`
	WorkspaceID string
	RootID      string `gorm:"column:acl_root_id"`
	Title       string
	Description string
	Timezone    string
	AllDay      bool
	Start       string
	End         string
	StartAt     time.Time
	EndAt       time.Time
	Busy        bool
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	RRule       string
	Exceptions  string `gorm:"default:[]"`
	DeletedAt   *time.Time
}

func (Event) TableName() string { return "calendar_events" }

type Occurrence struct {
	ID           int64 `gorm:"primaryKey"`
	EventID      string
	WorkspaceID  string
	RootID       string `gorm:"column:acl_root_id"`
	RecurrenceID string
	Start        string
	End          string
	StartAt      time.Time
	EndAt        time.Time
	Busy         bool
}

func (Occurrence) TableName() string { return "event_occurrences" }
