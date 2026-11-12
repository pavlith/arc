package v1

import (
	"github.com/pavlith/arc/sdk/contract"
	"testing"
)

func TestCalendarSignedContract(t *testing.T) {
	c, err := contract.Compile(Artifact())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Manifest.Operations) != 32 || len(c.Manifest.Resources) != 2 {
		t.Fatal("unexpected Calendar surface")
	}
	for _, op := range c.Manifest.Operations {
		if op.Auth.Action == "calendar.free_busy" && op.ResponseSchema != "schemas/busy-result.json" {
			t.Fatal("free/busy returns event data")
		}
	}
}
