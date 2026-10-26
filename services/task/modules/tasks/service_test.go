package tasks_test

import (
 "context"
 "database/sql"
 "errors"
 "testing"

 "github.com/pavlith/arc/pkgs/security"
 "github.com/pavlith/arc/services/task/modules/tasks"
)

func TestNoVerifiedInvocationNoACL(t *testing.T){
 svc:=&tasks.Service{DB:&sql.DB{},Check:func(context.Context,string,string)error{
   t.Fatal("ACL called with unverified actor")
   return nil
 }}
 if err:=svc.Authorize(context.Background(),"root","tasks.read");!errors.Is(err,security.ErrUnauthenticated){
  t.Fatal("unverified invocation accepted",err)
 }
}
