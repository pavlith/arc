package rpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/security"
)

const (
	SchemaVersion  = 1
	MaxMessageSize = 256 << 10
)

type requestEnvelope struct {
	RequestID      string          `json:"request_id"`
	Operation      string          `json:"operation"`
	SchemaVersion  int             `json:"schema_version"`
	DeadlineAt     time.Time       `json:"deadline_at"`
	Auth           string          `json:"auth,omitempty"`
	Proof          *security.Proof `json:"proof,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	Traceparent    string          `json:"traceparent,omitempty"`
	Payload        json.RawMessage `json:"payload"`
}

type responseEnvelope struct {
	RequestID string          `json:"request_id"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     *Error          `json:"error,omitempty"`
}

func newRequestID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("rpc: generate request id: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], raw[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], raw[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], raw[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], raw[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], raw[10:16])
	return string(encoded), nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("multiple JSON values")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return errors.New("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func ValidateSubject(subject string) error {
	if subject == "ctl.arc.fabric.routes" {
		return nil
	}
	if len(subject) == 0 || len(subject) > 255 || strings.ContainsAny(subject, "*> \t\r\n") {
		return errors.New("rpc: invalid subject")
	}
	tokens := strings.Split(subject, ".")
	if len(tokens) < 4 || tokens[0] != "rpc" || !validToken(tokens[1]) {
		return errors.New("rpc: subject must match rpc.<service>.v<major>.<operation>")
	}
	if len(tokens[2]) < 2 || tokens[2][0] != 'v' {
		return errors.New("rpc: subject has invalid API major")
	}
	for _, char := range tokens[2][1:] {
		if char < '0' || char > '9' {
			return errors.New("rpc: subject has invalid API major")
		}
	}
	for _, token := range tokens[3:] {
		if !validToken(token) {
			return errors.New("rpc: subject has invalid operation token")
		}
	}
	return nil
}

func validToken(token string) bool {
	if token == "" {
		return false
	}
	for _, char := range token {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func validOperation(operation string) bool {
	if operation == "" || len(operation) > 255 || strings.ContainsAny(operation, "*> \t\r\n") {
		return false
	}
	for _, token := range strings.Split(operation, ".") {
		if !validToken(token) {
			return false
		}
	}
	return true
}

type outgoingKey struct{}
type Outgoing struct {
	RequestID   string
	Traceparent string
}

func WithOutgoing(ctx context.Context, m Outgoing) context.Context {
	return context.WithValue(ctx, outgoingKey{}, m)
}
