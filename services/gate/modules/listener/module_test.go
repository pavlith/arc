package listener_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/pavlith/arc/services/gate/modules/listener"
)

func TestGateCannotReportStartedWithUnreadableTLSKeypair(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	l, err := listener.New(listener.Config{
		Listen:      "127.0.0.1:0",
		TLSCertFile: "/nonexistent/arc-gate-test.crt",
		TLSKeyFile:  "/nonexistent/arc-gate-test.key",
	}, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Start(context.Background()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing certificate did not stop startup: %v", err)
	}
	if err = l.Stop(context.Background()); err != nil {
		t.Fatalf("stop after rejected bootstrap: %v", err)
	}
}

func TestGateListenerGracefulShutdownDoesNotHang(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {w.WriteHeader(http.StatusNoContent)})
	listener, err := listener.New(listener.Config{
		Listen:"127.0.0.1:0",BehindTrustedProxy:true,EnableFilesStream:true,
	},handler)
	if err!=nil {t.Fatal(err)}
	ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
	defer cancel()
	if err:=listener.Start(ctx);err!=nil {t.Fatal(err)}
	if err:=listener.Stop(ctx);err!=nil {t.Fatalf("Gate listener shutdown hung: %v",err)}
	if err:=listener.Stop(ctx);err!=nil {t.Fatalf("repeated stop not idempotent: %v",err)}
}
