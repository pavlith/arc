package v1

import (
	"encoding/json"
	"github.com/pavlith/arc/sdk/contract"
	"strings"
	"testing"
)

func TestPersonalOperationsDoNotSelectWorkspace(t *testing.T) {
	c, err := contract.Compile(Artifact())
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range c.Manifest.Operations {
		if !strings.HasPrefix(op.ID, "files.personal.") {
			continue
		}
		if op.Auth.ResourceType != "files.personal" || op.Auth.WorkspaceFrom != "" {
			t.Fatalf("workspace binding on %s", op.ID)
		}
		for _, b := range op.HTTP.Bindings {
			if b.Field == "workspace_id" {
				t.Fatalf("personal path accepts workspace: %s", op.ID)
			}
		}
		// The workspace property is always explicitly constrained to empty, never a UUID.
		var schema map[string]any
		if err := json.Unmarshal(Artifact().Schemas[op.RequestSchema], &schema); err != nil {
			t.Fatal(err)
		}
		props := schema["properties"].(map[string]any)
		if props["workspace_id"].(map[string]any)["const"] != "" {
			t.Fatalf("personal schema accepts workspace: %s", op.ID)
		}
		if op.HTTP.Expose && !strings.HasPrefix(op.HTTP.Path, "/api/v1/files/personal/roots/") {
			t.Fatalf("personal path: %s", op.HTTP.Path)
		}
	}
}
