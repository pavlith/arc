package telemetry

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/test/testlog"
)

func TestSlogIncludesSafeCorrelationAndFixedCodes(t *testing.T) {
	logs := testlog.Capture(t)
	ctx := rpc.WithOutgoing(context.Background(), rpc.Outgoing{RequestID: "operation-request", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"})
	Slog{Logger: slog.Default()}.Observe(ctx, Observation{Service: "task", Module: "tasks", Operation: "task.v1.task.create", Kind: "command", Duration: time.Millisecond, ErrorCode: "secret-marker"})
	entry := logs.Entries()[0]
	if entry["request_id"] != "operation-request" || entry["traceparent"] == "" || entry["duration_ms"] != float64(1) || entry["error_code"] != string(rpc.CodeInternal) {
		t.Fatal("incomplete operation diagnostics", entry)
	}
	if strings.Contains(string(logs.Bytes()), "secret-marker") {
		t.Fatal("arbitrary error code reached logs")
	}
}
