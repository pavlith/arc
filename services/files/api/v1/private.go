package v1

import "github.com/pavlith/arc/sdk/module"

// PrivateChunkRequest is only the signed metadata envelope. No bytes enter NATS.
type PrivateChunkRequest struct {
	UploadRef
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

type PrivateUnavailable struct {
	Unavailable bool `json:"unavailable"`
}

var (
	PrivateChunk = module.Command[PrivateChunkRequest, PrivateUnavailable]{ID: "files.uploads.chunk"}
	PrivateDownload = module.Query[FileRef, PrivateUnavailable]{ID: "files.files.download"}
)
