package tasks

import (
	"embed"
	"encoding/json"
	"github.com/pavlith/arc/sdk/contract"
)

//go:embed contract/manifest.json contract/schemas/*.json
var files embed.FS

const Admin = "tasks.roots.grants"
const Create = "tasks.tasks.create"
const Get = "tasks.tasks.get"
const List = "tasks.tasks.list"
const Created = "evt.tasks.task.created.v1"

func Artifact() contract.Artifact {
	b, _ := files.ReadFile("contract/manifest.json")
	a := contract.Artifact{Manifest: b, Schemas: map[string]json.RawMessage{}}
	entries, _ := files.ReadDir("contract/schemas")
	for _, e := range entries {
		b, _ := files.ReadFile("contract/schemas/" + e.Name())
		a.Schemas["schemas/"+e.Name()] = b
	}
	return a
}
