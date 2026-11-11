package v1

import (
	"testing"

	"github.com/pavlith/arc/sdk/contract"
)

func TestFilesSignedContractSurface(t *testing.T) {
	compiled, err := contract.Compile(Artifact())
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Manifest.Operations) != 14 {
		t.Fatalf("unexpected Files operations: %d", len(compiled.Manifest.Operations))
	}
	seen := make(map[string]bool)
	for _, op := range compiled.Manifest.Operations {
		if seen[op.ID] {
			t.Fatalf("duplicate operation: %s", op.ID)
		}
		seen[op.ID] = true
		if op.Auth.ResourceType != "files.workspace" || op.Auth.ResourceFrom != "payload.acl_root_id" ||
			op.Auth.WorkspaceFrom != "payload.workspace_id" || (op.HTTP.Expose == (op.ID == "files.uploads.chunk" || op.ID == "files.files.download")) {
			t.Fatalf("missing live resource binding: %s", op.ID)
		}
	}
	for _, id := range []string{
		"files.folders.create", "files.folders.get", "files.folders.list",
		"files.folders.rename", "files.folders.move", "files.folders.archive",
		"files.uploads.initiate", "files.uploads.get", "files.uploads.abort",
		"files.uploads.complete", "files.files.get", "files.files.list",
		"files.uploads.chunk", "files.files.download",
	} {
		if !seen[id] {
			t.Fatalf("unsigned operation %s", id)
		}
	}
	// Private byte operations have no generated browser route and NATS handlers
	// fail closed without accepting raw payload bytes.
	for _, id := range []string{"files.uploads.chunk", "files.files.download"} {
		op, err := compiled.Operation(id)
		if err != nil || op.HTTP.Expose {
			t.Fatalf("private operation accidentally exposed: %s", id)
		}
	}
}
