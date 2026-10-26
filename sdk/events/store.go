// Package events provides transactional replay, outbox and inbox helpers.
package events

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/pavlith/arc/sdk/contract"
)

type Envelope struct {
	ID          string          `json:"event_id"`
	Type        string          `json:"type"`
	Version     int             `json:"schema_version"`
	AggregateID string          `json:"aggregate_id"`
	OccurredAt  time.Time       `json:"occurred_at"`
	Traceparent string          `json:"traceparent,omitempty"`
	Payload     json.RawMessage `json:"payload"`
}

func Validate(m *contract.Compiled, subject string, e Envelope) error {
	if !regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`).MatchString(e.ID) || e.Version != 1 || e.AggregateID == "" || e.OccurredAt.IsZero() {
		return contract.ErrInvalid
	}
	for _, ev := range m.Manifest.Events {
		if ev.Name == e.Type && ev.Subject == subject {
			return m.Validate(ev.Schema, e.Payload)
		}
	}
	return contract.ErrInvalid
}
