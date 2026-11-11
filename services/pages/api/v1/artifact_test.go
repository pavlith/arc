package v1

import (
	"testing"

	"github.com/pavlith/arc/sdk/contract"
)

func TestPagesSignedContract(t *testing.T) {
	c, err := contract.Compile(Artifact())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Manifest.Operations) != 32 || len(c.Manifest.Resources) != 2 {
		t.Fatal("unexpected Pages surface")
	}
}
