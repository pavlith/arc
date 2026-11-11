package inbox

import (
	"encoding/json"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/resource"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	pagesv1 "github.com/pavlith/arc/services/pages/api/v1"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
)

func eventTarget(ev events.Envelope) (kind, workspace, root, target string, revision int64, err error) {
	switch ev.Type {
	case taskv1.CreatedName:
		var q taskv1.CreatedEvent
		if json.Unmarshal(ev.Payload, &q) != nil {
			return "", "", "", "", 0, security.ErrDenied
		}
		kind, workspace, root, target, revision = "task", q.WorkspaceID, q.RootID, q.TaskID, 1
	case pagesv1.ChangedName:
		var q pagesv1.Changed
		if json.Unmarshal(ev.Payload, &q) != nil {
			return "", "", "", "", 0, security.ErrDenied
		}
		if q.Action != "created" && q.Action != "updated" && q.Action != "restored" {
			return
		}
		kind, workspace, root, target, revision = "page", q.WorkspaceID, q.RootID, q.EntityID, q.Revision
	case filesv1.CatalogChangedName:
		var q filesv1.CatalogChanged
		if json.Unmarshal(ev.Payload, &q) != nil {
			return "", "", "", "", 0, security.ErrDenied
		}
		if q.EntityKind != "file" || q.Action != "uploaded" {
			return
		}
		kind, workspace, root, target, revision = "file", q.WorkspaceID, q.RootID, q.EntityID, q.Revision
	default:
		return "", "", "", "", 0, security.ErrDenied
	}
	if target != ev.AggregateID || revision < 1 || !(resource.Ref{Kind: kind, WorkspaceID: workspace, RootID: root, ID: target}).Valid() {
		err = security.ErrDenied
	}
	return
}
func eventAction(ev events.Envelope) string {
	if ev.Type == taskv1.CreatedName {
		return "created"
	}
	var v struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal(ev.Payload, &v)
	return v.Action
}
func legacyTask(kind, target string) string {
	if kind == "task" {
		return target
	}
	return ""
}
