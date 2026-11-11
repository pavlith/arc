package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

// Triage resolves an active backlog work item as accepted (todo) or declined
// (cancelled). Other workflow transitions remain part of normal work updates.
type WorkTriageRequest struct {
	GetRequest
	StatusID          string    `json:"status_id"`
	Revision          int64     `json:"revision"`
	ExpectedUpdatedAt time.Time `json:"expected_updated_at"`
}

var WorkTriage = module.Command[WorkTriageRequest, WorkItem]{ID: "task.work.triage"}
