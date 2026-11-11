package v1

import (
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/resource"
	"time"
)

type AttachmentChange struct {
	GetRequest
	File              resource.Ref `json:"file"`
	Remove            bool         `json:"remove"`
	Revision          int64        `json:"revision"`
	ExpectedUpdatedAt time.Time    `json:"expected_updated_at"`
}
type AttachmentResult struct {
	GetRequest
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
}
type AttachmentList struct {
	Files []resource.Ref `json:"files"`
}
type ReferencePreview struct {
	GetRequest
	Target resource.Ref `json:"target"`
}

var AttachmentChangeOp = module.Command[AttachmentChange, AttachmentResult]{ID: "task.work.attachments.change"}
var AttachmentListOp = module.Query[GetRequest, AttachmentList]{ID: "task.work.attachments.list"}
var ReferencePreviewOp = module.Query[ReferencePreview, resource.Summary]{ID: "task.work.references.preview"}
