package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

type File struct {
	Scope
	ID        string    `json:"id"`
	FolderID  string    `json:"folder_id,omitempty"`
	Filename  string    `json:"filename"`
	MIME      string    `json:"mime"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	ETag      string    `json:"etag"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type FileRef struct {
	Scope
	FileID string `json:"file_id"`
}

type FileListRequest struct {
	Scope
	FolderID string `json:"folder_id,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit"`
}

type FilesResult struct {
	Files      []File `json:"files"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type UploadInitiateRequest struct {
	Scope
	FolderID       string `json:"folder_id,omitempty"`
	Filename       string `json:"filename"`
	MIME           string `json:"mime"`
	ExpectedSize   int64  `json:"expected_size"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

type UploadRef struct {
	Scope
	UploadID string `json:"upload_id"`
}

type Upload struct {
	Scope
	ID             string    `json:"id"`
	FolderID       string    `json:"folder_id,omitempty"`
	Filename       string    `json:"filename"`
	MIME           string    `json:"mime"`
	ExpectedSize   int64     `json:"expected_size"`
	ExpectedSHA256 string    `json:"expected_sha256"`
	Offset         int64     `json:"offset"`
	ExpiresAt      time.Time `json:"expires_at"`
	State          string    `json:"state"`
}

var (
	UploadInitiate = module.Command[UploadInitiateRequest, Upload]{ID: "files.uploads.initiate"}
	UploadGet      = module.Query[UploadRef, Upload]{ID: "files.uploads.get"}
	UploadAbort    = module.Command[UploadRef, Upload]{ID: "files.uploads.abort"}
	UploadComplete = module.Command[UploadRef, File]{ID: "files.uploads.complete"}
	FileGet        = module.Query[FileRef, File]{ID: "files.files.get"}
	FileList       = module.Query[FileListRequest, FilesResult]{ID: "files.files.list"}
)
