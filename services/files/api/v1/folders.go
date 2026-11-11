// Package v1 owns Files' signed v1 contract and typed DTOs.
package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

type Scope struct {
	WorkspaceID string `json:"workspace_id"`
	RootID      string `json:"acl_root_id"`
}

type Folder struct {
	Scope
	ID        string    `json:"id"`
	ParentID  string    `json:"parent_id,omitempty"`
	Name      string    `json:"name"`
	Revision  int64     `json:"revision"`
	Archived  bool      `json:"archived"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type FolderCreateRequest struct {
	Scope
	ParentID string `json:"parent_id,omitempty"`
	Name     string `json:"name"`
}

type FolderRef struct {
	Scope
	FolderID string `json:"folder_id"`
}

type FolderListRequest struct {
	Scope
	ParentID string `json:"parent_id,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit"`
}

type FoldersResult struct {
	Folders    []Folder `json:"folders"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

type FolderRenameRequest struct {
	FolderRef
	Name     string `json:"name"`
	Revision int64  `json:"revision"`
}

type FolderMoveRequest struct {
	FolderRef
	ParentID string `json:"parent_id,omitempty"`
	Revision int64  `json:"revision"`
}

type FolderArchiveRequest struct {
	FolderRef
	Revision int64 `json:"revision"`
}

type CatalogChanged struct {
	Scope
	EntityKind string `json:"entity_kind"`
	EntityID   string `json:"entity_id"`
	Revision   int64  `json:"revision"`
	Action     string `json:"action"`
}

const (
	CatalogChangedName    = "files.catalog.changed"
	CatalogChangedSubject = "evt.files.catalog.changed.v1"
)

var (
	FolderCreate  = module.Command[FolderCreateRequest, Folder]{ID: "files.folders.create"}
	FolderGet     = module.Query[FolderRef, Folder]{ID: "files.folders.get"}
	FolderList    = module.Query[FolderListRequest, FoldersResult]{ID: "files.folders.list"}
	FolderRename  = module.Command[FolderRenameRequest, Folder]{ID: "files.folders.rename"}
	FolderMove    = module.Command[FolderMoveRequest, Folder]{ID: "files.folders.move"}
	FolderArchive = module.Command[FolderArchiveRequest, Folder]{ID: "files.folders.archive"}
	Changed       = module.Event[CatalogChanged]{Name: CatalogChangedName, Subject: CatalogChangedSubject}
)
