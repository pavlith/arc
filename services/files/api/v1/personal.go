package v1

import "github.com/pavlith/arc/sdk/module"

var (
	PersonalFolderCreate    = module.Command[FolderCreateRequest, Folder]{ID: "files.personal.folders.create"}
	PersonalFolderGet       = module.Query[FolderRef, Folder]{ID: "files.personal.folders.get"}
	PersonalFolderList      = module.Query[FolderListRequest, FoldersResult]{ID: "files.personal.folders.list"}
	PersonalFolderRename    = module.Command[FolderRenameRequest, Folder]{ID: "files.personal.folders.rename"}
	PersonalFolderMove      = module.Command[FolderMoveRequest, Folder]{ID: "files.personal.folders.move"}
	PersonalFolderArchive   = module.Command[FolderArchiveRequest, Folder]{ID: "files.personal.folders.archive"}
	PersonalUploadInitiate  = module.Command[UploadInitiateRequest, Upload]{ID: "files.personal.uploads.initiate"}
	PersonalUploadGet       = module.Query[UploadRef, Upload]{ID: "files.personal.uploads.get"}
	PersonalUploadAbort     = module.Command[UploadRef, Upload]{ID: "files.personal.uploads.abort"}
	PersonalUploadComplete  = module.Command[UploadRef, File]{ID: "files.personal.uploads.complete"}
	PersonalFileRename      = module.Command[FileRenameRequest, File]{ID: "files.personal.files.rename"}
	PersonalFileMove        = module.Command[FileMoveRequest, File]{ID: "files.personal.files.move"}
	PersonalFileArchive     = module.Command[FileArchiveRequest, File]{ID: "files.personal.files.archive"}
	PersonalFileGet         = module.Query[FileRef, File]{ID: "files.personal.files.get"}
	PersonalFileSearch      = module.Query[FileSearchRequest, FilesResult]{ID: "files.personal.files.search"}
	PersonalFileList        = module.Query[FileListRequest, FilesResult]{ID: "files.personal.files.list"}
	PersonalPrivateChunk    = module.Command[PrivateChunkRequest, Upload]{ID: "files.personal.uploads.chunk"}
	PersonalPrivateDownload = module.Query[FileRef, File]{ID: "files.personal.files.download"}
)

type GrantRequest struct {
	Scope
	PrincipalID string `json:"principal_id,omitempty"`
	Action      string `json:"action,omitempty"`
	GrantID     string `json:"grant_id,omitempty"`
}
type GrantResult struct {
	ResourceID string `json:"resource_id,omitempty"`
	GrantID    string `json:"grant_id,omitempty"`
	State      string `json:"state,omitempty"`
	Revision   int64  `json:"policy_revision"`
}

var RootGrants = module.Command[GrantRequest, GrantResult]{ID: "files.roots.grants"}
var PersonalRootGrants = module.Command[GrantRequest, GrantResult]{ID: "files.personal.roots.grants"}
