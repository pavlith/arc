package gate

import (
	"encoding/json"
	"testing"

	"github.com/pavlith/arc/sdk/contract"
)

func TestWorkspaceScopePreservesExplicitPersonalScope(t *testing.T) {
	for _, tc := range []struct {
		payload, selector, want string
		valid                   bool
	}{
		{`{"workspace_id":""}`, "payload.workspace_id", "", true},
		{`{"workspace_id":"40000000-0000-4000-8000-000000000001"}`, "payload.workspace_id", "40000000-0000-4000-8000-000000000001", true},
		{`{"scope":{"workspace_id":""}}`, "payload.scope.workspace_id", "", true},
		{`{}`, "payload.workspace_id", "", false},
		{`{"workspace_id":null}`, "payload.workspace_id", "", false},
		{`{"workspace_id":123}`, "payload.workspace_id", "", false},
		{`{"workspace_id":{}}`, "payload.workspace_id", "", false},
		{`{"workspace_id":""}`, "workspace_id", "", false},
	} {
		got, err := workspaceScope(json.RawMessage(tc.payload), tc.selector)
		if (err == nil) != tc.valid || got != tc.want {
			t.Fatalf("%s/%s: %q %v", tc.payload, tc.selector, got, err)
		}
	}
	if _, err := contract.Extract([]byte(`{"acl_root_id":""}`), "payload.acl_root_id"); err == nil {
		t.Fatal("empty resource selector accepted")
	}
}
