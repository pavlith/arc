package rpc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestValidateSubject(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		subject string
		valid   bool
	}{
		{name: "runtime inventory", subject: "ctl.runtime.v1.node.node-one.inventory", valid: true},
		{name: "runtime pull", subject: "ctl.runtime.v1.node.node-one.desired.get", valid: true},
		{name: "runtime report", subject: "ctl.runtime.v1.node.node-one.report", valid: true},
		{name: "runtime wildcard", subject: "ctl.runtime.v1.node.*.report", valid: false},
		{name: "runtime unknown", subject: "ctl.runtime.v1.node.node-one.exec", valid: false},
		{name: "runtime wrong major", subject: "ctl.runtime.v2.node.node-one.report", valid: false},
		{name: "runtime empty node", subject: "ctl.runtime.v1.node..report", valid: false},
		{name: "runtime non-node ctl", subject: "ctl.runtime.v1.shell", valid: false},
		{name: "runtime numeric node", subject: "ctl.runtime.v1.node.1node.report", valid: false},
		{name: "valid", subject: "rpc.bootstrap.v1.echo", valid: true},
		{name: "wildcard", subject: "rpc.bootstrap.v1.*", valid: false},
		{name: "missing major", subject: "rpc.bootstrap.echo", valid: false},
		{name: "uppercase", subject: "rpc.Bootstrap.v1.echo", valid: false},
		{name: "empty token", subject: "rpc.bootstrap.v1..echo", valid: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSubject(test.subject)
			if (err == nil) != test.valid {
				t.Fatalf("ValidateSubject(%q) error = %v, valid = %v", test.subject, err, test.valid)
			}
		})
	}
}

func TestPublicErrorDoesNotLeakInternalDetails(t *testing.T) {
	t.Parallel()
	for _, source := range []error{
		errors.New("password=secret SQL syntax error"),
		&Error{Code: CodeInternal, Message: "password=secret SQL syntax error"},
	} {
		err := publicError(source)
		if err.Code != CodeInternal || err.Message != "internal error" || strings.Contains(err.Message, "secret") {
			t.Fatalf("unsafe public error: %#v", err)
		}
	}
}

func TestTransportErrorsAreTyped(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if code := ErrorCode(transportError(ctx, context.DeadlineExceeded)); code != CodeDeadlineExceeded {
		t.Fatalf("deadline code = %q", code)
	}
	if code := ErrorCode(transportError(context.Background(), nats.ErrNoResponders)); code != CodeUnavailable {
		t.Fatalf("no responders code = %q", code)
	}
}

func TestDecodeStrictRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	var envelope requestEnvelope
	err := decodeStrict([]byte(`{"request_id":"id","operation":"bootstrap.echo","schema_version":1,"deadline_at":"2026-10-25T00:00:00Z","payload":{},"untrusted_header":"forged"}`), &envelope)
	if err == nil {
		t.Fatal("unknown field was accepted")
	}
}
