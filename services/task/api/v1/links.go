package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

type LinkChangeRequest struct {
	WorkArchiveRequest
	TargetID string `json:"target_id"`
	Kind     string `json:"kind"`
	Remove   bool   `json:"remove"`
}
type Link struct {
	SourceID string `json:"source_id"`
	TargetID string `json:"target_id"`
	Kind     string `json:"kind"`
}
type LinkListResult struct {
	Links []Link `json:"links"`
}
type LinkChangeResult struct {
	GetRequest
	TargetID       string    `json:"target_id"`
	Revision       int64     `json:"revision"`
	TargetRevision int64     `json:"target_revision"`
	UpdatedAt      time.Time `json:"updated_at"`
}

var (
	WorkLinkChange = module.Command[LinkChangeRequest, LinkChangeResult]{ID: "task.work.links.change"}
	WorkLinks      = module.Query[GetRequest, LinkListResult]{ID: "task.work.links.list"}
)
