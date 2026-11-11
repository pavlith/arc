package v1

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pavlith/arc/sdk/contract"
)

func TestFilesSignedContractSurface(t *testing.T) {
	compiled, err := contract.Compile(Artifact())
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Manifest.Operations) != 39 {
		t.Fatalf("unexpected Files operations: %d", len(compiled.Manifest.Operations))
	}
	seen := make(map[string]bool)
	for _, op := range compiled.Manifest.Operations {
		if seen[op.ID] {
			t.Fatalf("duplicate operation: %s", op.ID)
		}
		seen[op.ID] = true
		resource, ws, baseID := "files.workspace", "payload.workspace_id", op.ID
		if strings.HasPrefix(op.ID, "files.personal.") {
			resource, ws = "files.personal", ""
			baseID = strings.Replace(op.ID, "files.personal.", "files.", 1)
		}
		if op.Auth.ResourceType != resource || op.Auth.ResourceFrom != "payload.acl_root_id" ||
			op.Auth.WorkspaceFrom != ws || (op.HTTP.Expose == (baseID == "files.uploads.chunk" || baseID == "files.files.download")) {
			t.Fatalf("missing live resource binding: %s", op.ID)
		}
	}
	for _, id := range []string{
		"files.folders.create", "files.folders.get", "files.folders.list",
		"files.folders.rename", "files.folders.move", "files.folders.archive",
		"files.uploads.initiate", "files.uploads.get", "files.uploads.abort",
		"files.uploads.complete", "files.files.get", "files.files.list",
		"files.uploads.chunk", "files.files.download",
		"files.files.rename", "files.files.move", "files.files.archive", "files.files.search",
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

func TestFileMutationContracts(t *testing.T) {
	compiled, err := contract.Compile(Artifact())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ op, action, method, suffix string }{
		{"files.files.rename", "files.write", "PATCH", ""},
		{"files.files.move", "files.write", "POST", "/move"},
		{"files.files.archive", "files.delete", "DELETE", ""},
	} {
		op, err := compiled.Operation(tc.op)
		if err != nil {
			t.Fatal(err)
		}
		if op.Kind != "command" || op.Auth.Action != tc.action || op.Idempotency != "required" ||
			op.HTTP.Method != tc.method || op.HTTP.Path != "/api/v1/files/workspaces/{workspace_id}/roots/{acl_root_id}/files/{file_id}"+tc.suffix {
			t.Fatalf("incorrect mutation contract: %+v", op)
		}
		q := map[string]any{"workspace_id": "00000000-0000-4000-8000-000000000001", "acl_root_id": "00000000-0000-4000-8000-000000000002", "file_id": "00000000-0000-4000-8000-000000000003", "revision": 1}
		if tc.op == "files.files.rename" {
			q["filename"] = "renamed.bin"
		}
		raw, _ := json.Marshal(q)
		if err := compiled.Validate(op.RequestSchema, raw); err != nil {
			t.Fatalf("valid mutation rejected: %s %v", tc.op, err)
		}
		delete(q, "revision")
		raw, _ = json.Marshal(q)
		if compiled.Validate(op.RequestSchema, raw) == nil {
			t.Fatalf("missing revision accepted: %s", tc.op)
		}
		q["revision"] = 0
		raw, _ = json.Marshal(q)
		if compiled.Validate(op.RequestSchema, raw) == nil {
			t.Fatalf("zero revision accepted: %s", tc.op)
		}
		q["revision"] = 1
		q["target_root_id"] = "00000000-0000-4000-8000-000000000004"
		raw, _ = json.Marshal(q)
		if compiled.Validate(op.RequestSchema, raw) == nil {
			t.Fatalf("root override accepted: %s", tc.op)
		}
	}
}

func TestFileSearchContract(t *testing.T) {
	compiled, err := contract.Compile(Artifact())
	if err != nil {
		t.Fatal(err)
	}
	op, err := compiled.Operation(FileSearch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Kind != "query" || op.Auth.Action != "files.read" || op.HTTP.Method != "GET" ||
		op.HTTP.Path != "/api/v1/files/workspaces/{workspace_id}/roots/{acl_root_id}/search" {
		t.Fatalf("incorrect search contract: %+v", op)
	}
	queryBound := false
	for _, b := range op.HTTP.Bindings {
		if b.Field == "query" && b.Name == "query" && b.Source == "query" && b.Type == "string" {
			queryBound = true
		}
	}
	if !queryBound {
		t.Fatal("search query lacks HTTP binding")
	}
	q := map[string]any{"workspace_id": "00000000-0000-4000-8000-000000000001", "acl_root_id": "00000000-0000-4000-8000-000000000002", "query": "Report", "limit": 10}
	raw, _ := json.Marshal(q)
	if err := compiled.Validate(op.RequestSchema, raw); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"", string(make([]byte, 257))} {
		q["query"] = query
		raw, _ = json.Marshal(q)
		if compiled.Validate(op.RequestSchema, raw) == nil {
			t.Fatal("invalid search query accepted")
		}
	}
	delete(q, "query")
	raw, _ = json.Marshal(q)
	if compiled.Validate(op.RequestSchema, raw) == nil {
		t.Fatal("missing search query accepted")
	}
}
