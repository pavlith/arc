package fabric

import (
	"encoding/json"
	"github.com/pavlith/arc/sdk/testcontract"
	"sync"
	"testing"
)

func TestCompiledArtifactsUseFullInputAndBoundedCache(t *testing.T) {
	c := &Core{}
	a := testcontract.Artifact(1)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.compileArtifact(a); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	first, err := c.compileArtifact(a)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	json.Unmarshal(a.Manifest, &raw)
	raw["service"].(map[string]any)["build_version"] = "1.0.99"
	a.Manifest, _ = json.Marshal(raw)
	second, err := c.compileArtifact(a)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest {
		t.Fatal("changed artifact reused previous compilation")
	}
	a.Manifest = []byte(`{"manifest_version":99}`)
	if _, err := c.compileArtifact(a); err == nil {
		t.Fatal("invalid changed manifest accepted from cache")
	}
}
