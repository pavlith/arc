package agent

import "context"

// RuntimeProvider is the typed node-to-Core boundary. Implementations must
// authenticate the node independently of request fields and fail closed offline.
type RuntimeProvider interface {
	Inventory(context.Context, InventoryRequest) (InventoryPage, error)
	Pull(context.Context, PullRequest) (SignedSnapshot, error)
	Report(context.Context, Report) error
}

// Inventory discovers resource IDs after reconnect. Its entries are hints only;
// each effect still requires a separately verified, fresh signed pull.
type InventoryRequest struct {
	NodeID  string `json:"node_id"`
	AfterID string `json:"after_id,omitempty"`
	Host *HostFacts `json:"host,omitempty"`
}
type InventoryPage struct {
	ResourceIDs []string `json:"resource_ids"`
	NextID      string   `json:"next_id,omitempty"`
}

type PullRequest struct {
	NodeID     string `json:"node_id"`
	ResourceID string `json:"resource_id"`
	RequestID  string `json:"request_id"`
}

type OperationStatus string

const (
	Pending    OperationStatus = "pending"
	InProgress OperationStatus = "running"
	Succeeded  OperationStatus = "succeeded"
	Failed     OperationStatus = "failed"
	Cancelled  OperationStatus = "cancelled"
)

// ReportJournal holds a receipt before sending it to Core. A crash must not
// turn an uncertain acknowledgement into a new operation/event identifier.
type ReportJournal interface {
	LoadPending(context.Context, string) (Report, bool, error)
	SavePending(context.Context, string, Report) error
	DeletePending(context.Context, string) error
}

// Report carries bounded host metadata. It never contains logs, credentials or
// arbitrary driver error text. Observations do not assert Fabric readiness.
type Report struct {
	EventID     string          `json:"event_id"`
	OperationID string          `json:"operation_id"`
	SpecDigest  string          `json:"spec_digest"`
	Status      OperationStatus `json:"status"`
	ErrorCode   string          `json:"error_code,omitempty"`
	Observation Observation     `json:"observation"`
}
