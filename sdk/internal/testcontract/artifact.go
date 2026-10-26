// Package testcontract supplies a minimal domain-owner contract for guardrails.
package testcontract

import (
	"encoding/json"
	"fmt"
	"github.com/pavlith/arc/sdk/contract"
)

func Artifact(major int) contract.Artifact {
	name := "books"
	typ := fmt.Sprintf("books.root_v%d", major)
	m := contract.Manifest{ManifestVersion: 1, Service: contract.Service{Name: name, BuildVersion: "1.0.0", APIMajor: major}, Resources: []contract.Resource{{Type: typ, Actions: []string{"books.read", "books.create", "books.share", "books.delete", "access.grants.manage"}, ShareAction: "books.share", CreateAction: "books.create", DeleteAction: "books.delete", AllowInheritance: true}}}
	for _, kind := range []string{"read", "create"} {
		o := contract.Operation{ID: name + "." + kind, Subject: fmt.Sprintf("rpc.books.v%d.%s", major, kind), Kind: "query", RequestSchema: "schemas/request.json", ResponseSchema: "schemas/response.json", Auth: contract.Auth{Mode: "resource", ResourceType: typ, Action: name + "." + kind, ResourceFrom: "payload.root_id"}, Idempotency: "none", TimeoutMS: 5000}
		if kind == "create" {
			o.Kind = "command"
			o.Idempotency = "required"
			o.TimeoutMS = 10000
		}
		o.HTTP = contract.HTTP{Expose: true, Method: "GET", Path: fmt.Sprintf("/api/v%d/books/%s/{id}", major, kind), SuccessStatus: 200}
		m.Operations = append(m.Operations, o)
	}
	m.Events = []contract.Event{{Name: "books.item.created", Subject: fmt.Sprintf("evt.books.item.created.v%d", major), Schema: "schemas/event.json"}}
	raw, _ := json.Marshal(m)
	return contract.Artifact{Manifest: raw, Schemas: map[string]json.RawMessage{
		"schemas/request.json":  json.RawMessage(`{"type":"object","properties":{"root_id":{"type":"string","minLength":1},"value":{"type":"string","minLength":1}},"required":["root_id","value"],"additionalProperties":false}`),
		"schemas/response.json": json.RawMessage(`{"type":"object","properties":{"value":{"type":"string","minLength":1}},"required":["value"],"additionalProperties":false}`),
		"schemas/event.json":    json.RawMessage(`{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}`)}}
}
