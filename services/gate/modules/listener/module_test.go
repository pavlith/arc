package listener_test

import (
    "context"
    "errors"
    "net/http"
    "os"
    "testing"

    "github.com/pavlith/arc/services/gate/modules/listener"
)

func TestGateCannotReportStartedWithUnreadableTLSKeypair(t *testing.T) {
    handler:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(200)})
    l,err:=listener.New(listener.Config{
        Listen:"127.0.0.1:0",
        TLSCertFile:"/nonexistent/arc-gate-test.crt",
        TLSKeyFile:"/nonexistent/arc-gate-test.key",
    },handler)
    if err!=nil{t.Fatal(err)}
    if err=l.Start(context.Background());!errors.Is(err,os.ErrNotExist){
        t.Fatalf("missing certificate did not stop startup: %v",err)
    }
    if err=l.Stop(context.Background());err!=nil{
        t.Fatalf("stop after rejected bootstrap: %v",err)
    }
}
