// Package delivery persists external delivery attempts and stable retry keys.
package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"gorm.io/gorm"
)

type Service struct {
	GormDB *gorm.DB
}

func DedupKey(notification, recipient, channel string) string {
	b, _ := json.Marshal([]string{notification, recipient, channel})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Provider interface {
	Send(context.Context, string, string) error
}

// Deliver sends bounded persisted intents. Timeout keeps the same key on retry.
// Provider calls cannot be atomic with SQL; a non-idempotent provider may duplicate.

// FakeProvider is the only M0 external adapter. It records invocations and accepts
// each key once; Fail can simulate an uncertain timeout after the effect.
type FakeProvider struct {
	mu       sync.Mutex
	Calls    []string
	Accepted map[string]bool
	Fail     bool
}

func (p *FakeProvider) Send(ctx context.Context, recipient, key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Calls = append(p.Calls, key)
	if p.Accepted == nil {
		p.Accepted = map[string]bool{}
	}
	p.Accepted[key] = true
	if p.Fail {
		p.Fail = false
		return context.DeadlineExceeded
	}
	return nil
}
