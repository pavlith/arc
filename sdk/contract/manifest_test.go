package contract_test

import (
	"encoding/json"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/testcontract"
	"testing"
)

func TestArtifactGuardrails(t *testing.T) {
	a := testcontract.Artifact(1)
	c, e := contract.Compile(a)
	if e != nil {
		t.Fatal(e)
	}
	var obj map[string]any
	_ = json.Unmarshal(a.Manifest, &obj)
	a.Manifest, _ = json.MarshalIndent(obj, "", "  ")
	d, e := contract.Compile(a)
	if e != nil || c.Digest != d.Digest {
		t.Fatal("non deterministic manifest digest", e)
	}
	if c.Validate("schemas/request.json", []byte(`{"root_id":"r","value":"ok"}`)) != nil {
		t.Fatal("valid schema denied")
	}
	for _, raw := range []string{`{"root_id":"r"}`, `{"root_id":"r","value":3}`, `{"root_id":"r","value":"ok","extra":1}`} {
		if c.Validate("schemas/request.json", []byte(raw)) == nil {
			t.Fatal("invalid schema accepted", raw)
		}
	}
	tests := map[string]func(*contract.Manifest){
		"unknown_action":         func(m *contract.Manifest) { m.Operations[0].Auth.Action = "books.export" },
		"foreign_type":           func(m *contract.Manifest) { m.Operations[0].Auth.ResourceType = "files.root" },
		"wildcard_subject":       func(m *contract.Manifest) { m.Operations[0].Subject = "rpc.books.v1.>" },
		"wrong_major":            func(m *contract.Manifest) { m.Service.APIMajor = 2 },
		"unprotected":            func(m *contract.Manifest) { m.Operations[0].Auth.Mode = "none" },
		"executable_selector":    func(m *contract.Manifest) { m.Operations[0].Auth.ResourceFrom = "sql:select root" },
		"command_without_replay": func(m *contract.Manifest) { m.Operations[1].Idempotency = "none" },
		"reserved_route":         func(m *contract.Manifest) { m.Operations[0].HTTP.Path = "/api/v1/identity/login" },
		"conflicting_routes":     func(m *contract.Manifest) { m.Operations[1].HTTP.Path = "/api/v1/books/read/{other}" },
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			a := testcontract.Artifact(1)
			var m contract.Manifest
			_ = json.Unmarshal(a.Manifest, &m)
			mut(&m)
			a.Manifest, _ = json.Marshal(m)
			if _, e := contract.Compile(a); e == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	a = testcontract.Artifact(1)
	a.Manifest = append(a.Manifest[:len(a.Manifest)-1], []byte(`,"unknown":true}`)...)
	if _, e = contract.Compile(a); e == nil {
		t.Fatal("unknown manifest field accepted")
	}
	for _, raw := range []string{`{"$ref":"https://example.com/schema"}`, `{"$ref":"file:///etc/passwd"}`, `{"type":"missing"}`} {
		a = testcontract.Artifact(1)
		a.Schemas["schemas/request.json"] = json.RawMessage(raw)
		if _, e = contract.Compile(a); e == nil {
			t.Fatal("invalid or external schema accepted")
		}
	}
	a = testcontract.Artifact(1)
	a.Schemas["schemas/request.json"] = json.RawMessage(`{"type":"object","description":"changed"}`)
	changed, e := contract.Compile(a)
	if e != nil || changed.Digest == c.Digest {
		t.Fatal("schema not bound to digest", e)
	}
}

func TestConservativeSchemaCompatibility(t *testing.T) {
	old := testcontract.Artifact(1)
	next := testcontract.Artifact(1)
	var req map[string]any
	_ = json.Unmarshal(next.Schemas["schemas/request.json"], &req)
	req["properties"].(map[string]any)["optional_note"] = map[string]any{"type": "string"}
	next.Schemas["schemas/request.json"], _ = json.Marshal(req)
	if !contract.Compatible(old, next) {
		t.Fatal("optional request field rejected")
	}
	req["required"] = []string{"root_id", "value", "optional_note"}
	next.Schemas["schemas/request.json"], _ = json.Marshal(req)
	if contract.Compatible(old, next) {
		t.Fatal("breaking required field accepted")
	}
	if contract.Compatible(old, testcontract.Artifact(2)) {
		t.Fatal("major mismatch accepted")
	}
}
