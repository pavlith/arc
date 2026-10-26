package v1

import (
	"embed"
	"encoding/json"
	"github.com/pavlith/arc/sdk/contract"
)

//go:embed contract/manifest.json contract/schemas/*.json
var files embed.FS

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
