package core_test

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "database/sql"
    "errors"
    "reflect"
    "testing"

    "github.com/pavlith/arc/pkgs/security"
    "github.com/pavlith/arc/services/core"
)

func TestCoreWiringAndFailClosedConfiguration(t *testing.T) {
    if _,err:=core.New(core.Config{});!errors.Is(err,core.ErrInvalid){t.Fatal("missing trust inputs accepted",err)}
    pub,key,err:=ed25519.GenerateKey(rand.Reader)
    if err!=nil{t.Fatal(err)}
    db:=&sql.DB{}
    cfg:=core.Config{
        DB:db,Version:"0.1.0",IdentitySigningKid:"identity-test",
        IdentitySigningKey:key,InstallationApprovalKey:pub,
        SnapshotKid:"snapshot-test",SnapshotSigningKey:key,
        RouteTrustKey:key,
        RuntimeAuthorize:func(context.Context,string,string)error{return security.ErrDenied},
    }
    s,err:=core.New(cfg)
    if err!=nil{t.Fatal(err)}
    if !reflect.DeepEqual(s.Modules(),[]string{"identity","access","fabric","runtime"}){t.Fatal("Core modules",s.Modules())}
    if s.Identity.Policy!=s.Access||s.Access.ContractSource!=s.Fabric||s.Fabric.Identity!=s.Identity {
        t.Fatal("Core direct interface wiring is incorrect")
    }
    if err:=s.Stop();err!=nil{t.Fatal(err)}
}
