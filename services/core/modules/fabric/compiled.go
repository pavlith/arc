package fabric

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/pavlith/arc/sdk/contract"
)

// compileArtifact caches immutable schema compilation by the complete artifact.
// Installation signatures, active rows, credentials and policy are checked by
// every caller on each invocation; their authorization decisions are never cached.
func (c *Core) compileArtifact(a contract.Artifact) (*contract.Compiled, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, contract.ErrInvalid
	}
	key := sha256.Sum256(raw)
	c.compileMu.Lock()
	cached := c.compiled[key]
	c.compileMu.Unlock()
	if cached != nil {
		return cached, nil
	}
	compiled, err := contract.Compile(a)
	if err != nil {
		return nil, err
	}
	c.compileMu.Lock()
	defer c.compileMu.Unlock()
	if c.compiled == nil {
		c.compiled = map[[32]byte]*contract.Compiled{}
	}
	if len(c.compiled) >= 32 {
		for old := range c.compiled {
			delete(c.compiled, old)
			break
		}
	}
	c.compiled[key] = compiled
	return compiled, nil
}
