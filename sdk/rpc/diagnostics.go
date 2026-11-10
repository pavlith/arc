package rpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/pavlith/arc/sdk/security"
)

var diagnosticID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
var diagnosticTrace = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

// StartCorrelation creates a diagnostic root for background work. A valid
// incoming ID/trace is preserved; generation failure never prevents the work.
func StartCorrelation(ctx context.Context) context.Context {
	m := Correlation(ctx)
	if m.RequestID == "" {
		m.RequestID, _ = newRequestID()
	}
	if m.Traceparent == "" {
		var ids [24]byte
		if _, err := rand.Read(ids[:]); err == nil {
			ids[0] |= 0x80
			ids[16] |= 0x80
			m.Traceparent = "00-" + hex.EncodeToString(ids[:16]) + "-" + hex.EncodeToString(ids[16:]) + "-00"
		}
	}
	return WithOutgoing(ctx, m)
}

// Correlation returns bounded diagnostic identifiers only, never payload,
// idempotency keys or credentials. These identifiers confer no authority.
// Malformed metadata is omitted from diagnostics without changing signed bytes.
func Correlation(ctx context.Context) Outgoing {
	if ctx == nil {
		return Outgoing{}
	}
	m, ok := ctx.Value(outgoingKey{}).(Outgoing)
	if !ok {
		if incoming, exists := Metadata(ctx); exists {
			m = Outgoing{RequestID: incoming.RequestID, Traceparent: incoming.Traceparent}
		}
	}
	return safeCorrelation(m)
}

func safeCorrelation(m Outgoing) Outgoing {
	if !diagnosticID.MatchString(m.RequestID) {
		m.RequestID = ""
	}
	if !diagnosticTrace.MatchString(m.Traceparent) ||
		strings.HasPrefix(m.Traceparent, "00-00000000000000000000000000000000-") ||
		m.Traceparent[36:52] == "0000000000000000" {
		m.Traceparent = ""
	}
	return m
}

// DiagnosticCode maps errors to fixed codes without exposing their text.
func DiagnosticCode(err error) Code {
	if err == nil {
		return ""
	}
	var typed *Error
	if errors.As(err, &typed) && typed != nil && validCode(typed.Code) {
		return typed.Code
	}
	switch {
	case errors.Is(err, security.ErrUnauthenticated):
		return CodeUnauthenticated
	case errors.Is(err, security.ErrDenied):
		return CodePermissionDenied
	case errors.Is(err, security.ErrUnavailable):
		return CodeUnavailable
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return CodeDeadlineExceeded
	default:
		return CodeInternal
	}
}
