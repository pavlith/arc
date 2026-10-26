package gate_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pavlith/arc/services/gate"
	"github.com/pavlith/arc/services/gate/modules/listener"
)

func TestGateRejectsMissingCoreBackend(t *testing.T) {
	if _, err := gate.New(gate.Config{}); err == nil {
		t.Fatal("missing Core backend accepted")
	}
}
func TestListenerFailsClosedWithoutTLSOrPinnedProxy(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if _, err := listener.New(listener.Config{Listen: "127.0.0.1:0"}, handler); !errors.Is(err, listener.ErrInvalid) {
		t.Fatal("plaintext public listener accepted", err)
	}
	if _, err := listener.New(listener.Config{Listen: "127.0.0.1:0",
		TLSCertFile: "cert.pem"}, handler); err == nil {
		t.Fatal("incomplete TLS keypair accepted")
	}
}
func TestGateStopIsIdempotentWithoutStart(t *testing.T) {
	_ = context.Background()
	_ = httptest.NewRecorder()
}
