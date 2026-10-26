package v1

import (
	"encoding/json"
	"github.com/pavlith/arc/sdk/contract"
)

const Health = "notify.health"

func Artifact() contract.Artifact {
	m := contract.Manifest{ManifestVersion: 1, Service: contract.Service{Name: "notify", BuildVersion: "0.0.6", APIMajor: 1}, Resources: []contract.Resource{{Type: "notify.service", Actions: []string{"notify.health", "notify.create", "notify.share", "notify.delete", "access.grants.manage"}, ShareAction: "notify.share", CreateAction: "notify.create", DeleteAction: "notify.delete"}}, Operations: []contract.Operation{{ID: Health, Subject: "rpc.notify.v1.health", Kind: "query", RequestSchema: "schemas/empty.json", ResponseSchema: "schemas/empty.json", Auth: contract.Auth{Mode: "service", Action: "notify.health"}, Idempotency: "none", TimeoutMS: 5000}}}
	b, _ := json.Marshal(m)
	return contract.Artifact{Manifest: b, Schemas: map[string]json.RawMessage{"schemas/empty.json": json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)}}
}
