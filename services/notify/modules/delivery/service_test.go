package delivery_test

import (
 "context"
 "errors"
 "testing"

 "github.com/pavlith/arc/pkgs/security"
 "github.com/pavlith/arc/services/notify/modules/delivery"
)

func TestStableExternalRetryKey(t *testing.T){
 a:=delivery.DedupKey("n","u","fake")
 if a!=delivery.DedupKey("n","u","fake")||
    a==delivery.DedupKey("n","v","fake")||
    a==delivery.DedupKey("n","u","email"){
  t.Fatal("delivery idempotency key is unstable or ambiguous")
 }
 if _,err:=(&delivery.Service{}).Deliver(context.Background(),nil);!errors.Is(err,security.ErrUnavailable){
  t.Fatal("missing provider not rejected",err)
 }
}
