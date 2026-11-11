package v1

import "github.com/pavlith/arc/sdk/module"

// PrivateChunkRequest is only the signed metadata envelope. No bytes enter NATS.
type PrivateChunkRequest struct {
	UploadRef
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

var (
	PrivateChunk    = module.Command[PrivateChunkRequest, Upload]{ID: "files.uploads.chunk"}
	PrivateDownload = module.Query[PrivateDownloadRequest, File]{ID: "files.files.download"}
)

type PrivateDownloadRequest struct {
	FileRef
	Image bool `json:"image,omitempty"`
}
