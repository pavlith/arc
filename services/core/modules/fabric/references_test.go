package fabric

import (
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/testcontract"
	"github.com/pavlith/arc/services/core/modules/access"
	"testing"
)

func TestReferenceReadEdgesAreExactUserReads(t *testing.T) {
	c, err := contract.Compile(testcontract.Artifact(1))
	if err != nil {
		t.Fatal(err)
	}
	source := "books/v1:" + c.Manifest.Operations[0].ID
	r := access.Rule{Caller: "provider", Audience: "files/v1", Operation: "files.files.get", ActorKinds: []string{"user"}, Actions: []string{"files.read"}, DownstreamFrom: []string{source}, DownstreamActions: map[string][]string{source: {"files.read"}}}
	if !referenceReadRule(r, "provider", "books/v1", c) {
		t.Fatal("exact user read rejected")
	}
	for _, change := range []func(*access.Rule){
		func(r *access.Rule) { r.Operation = "files.uploads.abort" }, func(r *access.Rule) { r.Actions = []string{"files.write"} },
		func(r *access.Rule) { r.ActorKinds = []string{"service"} }, func(r *access.Rule) { r.Caller = "other" },
		func(r *access.Rule) { r.DownstreamFrom = []string{"books/v1:missing"} }, func(r *access.Rule) {
			r.DownstreamActions = map[string][]string{source: {"files.read"}, "other": {"files.read"}}
		},
	} {
		bad := r
		change(&bad)
		if referenceReadRule(bad, "provider", "books/v1", c) {
			t.Fatalf("unsafe edge accepted: %+v", bad)
		}
	}
}
