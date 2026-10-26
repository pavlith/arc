package notifications

import (
	"encoding/json"
	"github.com/pavlith/arc/sdk/contract"
)

const Health = "notifications.health"

func Artifact() contract.Artifact {
	m := contract.Manifest{ManifestVersion: 1, Service: contract.Service{Name: "notifications", BuildVersion: "0.0.6", APIMajor: 1}, Resources: []contract.Resource{{Type: "notifications.service", Actions: []string{"notifications.health", "notifications.create", "notifications.share", "notifications.delete", "access.grants.manage"}, ShareAction: "notifications.share", CreateAction: "notifications.create", DeleteAction: "notifications.delete"}}, Operations: []contract.Operation{{ID: Health, Subject: "rpc.notifications.v1.health", Kind: "query", RequestSchema: "schemas/empty.json", ResponseSchema: "schemas/empty.json", Auth: contract.Auth{Mode: "service", Action: "notifications.health"}, Idempotency: "none", TimeoutMS: 5000}}}
	b, _ := json.Marshal(m)
	return contract.Artifact{Manifest: b, Schemas: map[string]json.RawMessage{"schemas/empty.json": json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)}}
}
