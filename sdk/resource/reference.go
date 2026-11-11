// Package resource defines opaque cross-domain references; a reference grants no access.
package resource

import "regexp"

type Ref struct {
	Kind        string `json:"kind"`
	WorkspaceID string `json:"workspace_id"`
	RootID      string `json:"acl_root_id"`
	ID          string `json:"id"`
}
type Summary struct {
	Ref      Ref    `json:"ref"`
	Title    string `json:"title"`
	Revision int64  `json:"revision"`
}

var uuid = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

func (r Ref) Valid() bool {
	return uuid.MatchString(r.RootID) && uuid.MatchString(r.ID) && (r.WorkspaceID == "" || uuid.MatchString(r.WorkspaceID)) && (r.Kind == "file" || r.Kind == "page" || r.Kind == "task" && r.WorkspaceID != "")
}
func (r Ref) Target() (audience, operation, action, field string) {
	switch r.Kind {
	case "file":
		if r.WorkspaceID == "" {
			return "files/v1", "files.personal.files.get", "files.read", "file_id"
		}
		return "files/v1", "files.files.get", "files.read", "file_id"
	case "task":
		return "task/v1", "task.work.get", "task.read", "task_id"
	case "page":
		if r.WorkspaceID == "" {
			return "pages/v1", "pages.personal.pages.get", "pages.read", "page_id"
		}
		return "pages/v1", "pages.pages.get", "pages.read", "page_id"
	}
	return "", "", "", ""
}

// ReadTarget is a closed protocol list for signed cross-domain read permissions.
func ReadTarget(audience, operation, action string) bool {
	for _, r := range []Ref{{Kind: "file"}, {Kind: "file", WorkspaceID: "workspace"}, {Kind: "task"}, {Kind: "page"}, {Kind: "page", WorkspaceID: "workspace"}} {
		a, o, x, _ := r.Target()
		if a == audience && o == operation && x == action {
			return true
		}
	}
	return false
}
