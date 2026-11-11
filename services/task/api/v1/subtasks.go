package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

type ParentChangeRequest struct {
	GetRequest
	ParentID          string    `json:"parent_id"`
	Revision          int64     `json:"revision"`
	ExpectedUpdatedAt time.Time `json:"expected_updated_at"`
}
type ParentChangeResult struct {
	GetRequest
	ParentID  string    `json:"parent_id"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
}

var WorkSetParent = module.Command[ParentChangeRequest, ParentChangeResult]{ID: "task.work.set_parent"}
