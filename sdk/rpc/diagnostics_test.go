package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/test/testlog"
)

const testTrace = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"

type diagnosticRequest struct{ raw, reply []byte }

func (r *diagnosticRequest) Data() []byte { return r.raw }
func (r *diagnosticRequest) Respond(raw []byte) error {
	r.reply = append([]byte(nil), raw...)
	return nil
}

func TestRPCDiagnosticsIncludeAuthorizationFailuresWithoutSecrets(t *testing.T) {
	logs := testlog.Capture(t)
	for _, mode := range []string{"success", "denied", "panic", "invalid correlation", "malformed", "oversized response"} {
		t.Run(mode, func(t *testing.T) {
			envelope := requestEnvelope{
				RequestID: "diagnostic-request", Traceparent: testTrace,
				Operation: "test.v1.echo", SchemaVersion: 1, DeadlineAt: time.Now().Add(time.Second),
				Auth: "credential.secret-marker", IdempotencyKey: "secret-marker",
				Payload: json.RawMessage(`{"private":"secret-marker"}`),
			}
			if mode == "invalid correlation" {
				envelope.RequestID, envelope.Traceparent = "\nBearer secret-marker", "secret-marker"
			}
			raw, _ := json.Marshal(envelope)
			if mode == "malformed" {
				raw = []byte(`{"private":"secret-marker"`)
			}
			r := &diagnosticRequest{raw: raw}
			handled := false
			op := Operation{ID: envelope.Operation, Timeout: time.Second, Protected: true, Authorize: func(ctx context.Context, _ string, signed []byte) (context.Context, error) {
				if string(signed) != string(raw) {
					t.Fatal("diagnostics modified signed bytes")
				}
				if mode != "invalid correlation" && Correlation(ctx) != (Outgoing{RequestID: envelope.RequestID, Traceparent: testTrace}) {
					t.Fatal("authorization's downstream RPC context lost correlation")
				}
				if mode == "denied" {
					return nil, &Error{Code: CodePermissionDenied, Message: "secret-marker"}
				}
				return ctx, nil
			}}
			handleRequest(r, op, func(ctx context.Context, req map[string]string) (map[string]string, error) {
				handled = true
				if mode == "panic" {
					panic("secret-marker")
				}
				if mode == "oversized response" {
					return map[string]string{"private": strings.Repeat("x", MaxMessageSize)}, nil
				}
				return req, nil
			})
			entries := logs.Entries()
			entry := entries[len(entries)-1]
			want := ""
			switch mode {
			case "denied":
				want = string(CodePermissionDenied)
			case "panic", "oversized response":
				want = string(CodeInternal)
			case "malformed":
				want = string(CodeValidation)
			}
			if entry["msg"] != "arc rpc" || entry["operation"] != op.ID || entry["error_code"] != want || entry["duration_ms"].(float64) < 0 {
				t.Fatal("missing operation/error/latency diagnostics", entry)
			}
			if mode == "invalid correlation" || mode == "malformed" {
				if entry["request_id"] != "" || entry["traceparent"] != "" {
					t.Fatal("unbounded metadata entered diagnostics", entry)
				}
			} else if entry["request_id"] != envelope.RequestID || entry["traceparent"] != testTrace {
				t.Fatal("correlation missing", entry)
			}
			if mode == "denied" && handled {
				t.Fatal("diagnostics bypassed authorization")
			}
		})
	}
	if strings.Contains(string(logs.Bytes()), "secret-marker") {
		t.Fatal("diagnostics leaked credentials, payload, error/panic text or idempotency key")
	}
}

func TestDiagnosticCodeAndCorrelationAreBounded(t *testing.T) {
	for _, err := range []error{errors.New("secret-marker"), &Error{Code: "secret-marker", Message: "secret-marker"}} {
		if DiagnosticCode(err) != CodeInternal {
			t.Fatal("unbounded error code")
		}
	}
	if DiagnosticCode(security.ErrDenied) != CodePermissionDenied || DiagnosticCode(context.DeadlineExceeded) != CodeDeadlineExceeded || DiagnosticCode(nil) != "" {
		t.Fatal("incorrect fixed error mapping")
	}
	for _, trace := range []string{"00-00000000000000000000000000000000-0123456789abcdef-01", "00-0123456789abcdef0123456789abcdef-0000000000000000-01", testTrace + "\nsecret-marker"} {
		if Correlation(WithOutgoing(context.Background(), Outgoing{RequestID: strings.Repeat("x", 129), Traceparent: trace})) != (Outgoing{}) {
			t.Fatal("invalid correlation was not omitted")
		}
	}
}
