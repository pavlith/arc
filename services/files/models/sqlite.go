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

// File and Upload are persisted in Files' own database; blob keys never cross
// the HTTP or RPC metadata boundary.
type File struct {
	ID          string    `gorm:"column:id;primaryKey"`
	WorkspaceID string    `gorm:"column:workspace_id;not null"`
	RootID      string    `gorm:"column:acl_root_id;not null"`
	FolderID    *string   `gorm:"column:folder_id"`
	Filename    string    `gorm:"column:filename;not null"`
	MIME        string    `gorm:"column:mime;not null"`
	Size        int64     `gorm:"column:size;not null"`
	SHA256      string    `gorm:"column:sha256;not null"`
	BlobKey     string    `gorm:"column:blob_key;not null"`
	Revision    int64     `gorm:"column:revision;not null"`
	State       string    `gorm:"column:state;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null"`
}

func (File) TableName() string { return "files" }

type Upload struct {
	ID             string     `gorm:"column:id;primaryKey"`
	WorkspaceID    string     `gorm:"column:workspace_id;not null"`
	RootID         string     `gorm:"column:acl_root_id;not null"`
	FolderID       *string    `gorm:"column:folder_id"`
	ActorID        string     `gorm:"column:actor_id;not null"`
	SessionID      string     `gorm:"column:session_id;not null"`
	Filename       string     `gorm:"column:filename;not null"`
	DeclaredMIME   string     `gorm:"column:declared_mime;not null"`
	ExpectedSize   int64      `gorm:"column:expected_size;not null"`
	ExpectedSHA256 string     `gorm:"column:expected_sha256;not null"`
	TempKey        string     `gorm:"column:temp_key;not null"`
	Offset         int64      `gorm:"column:offset;not null"`
	State          string     `gorm:"column:state;not null"`
	IdempotencyKey string     `gorm:"column:idempotency_key;not null"`
	ExpiresAt      time.Time  `gorm:"column:expires_at;not null"`
	CreatedAt      time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt      time.Time  `gorm:"column:updated_at;not null"`
	CleanedAt      *time.Time `gorm:"column:cleaned_at"`
}

func (Upload) TableName() string { return "uploads" }
