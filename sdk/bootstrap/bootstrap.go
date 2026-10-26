// Package bootstrap contains process-scoped infrastructure setup for Arc.
// Every service calls Open separately and owns its resources and lifecycle.
// This package knows no business services, service modules or Fabric rules.
package bootstrap

import (
 "context"
 "crypto/ed25519"
 "database/sql"
 "encoding/json"
 "errors"
 "io"
 "os"
 "strings"
 "sync"

 _ "github.com/jackc/pgx/v5/stdlib"
 "github.com/nats-io/nats.go"
 "github.com/pavlith/arc/sdk"
 "github.com/pavlith/arc/sdk/contract"
 "github.com/pavlith/arc/sdk/rpc"
)

var ErrInvalid = errors.New("bootstrap: invalid configuration")

// Config is the common part of an independently deployed service's config.
type Config struct {
 NATS sdk.Config `json:"nats"`
 DSNFile string `json:"dsn_file"`
 ServiceID string `json:"service_id"`
 Kid string `json:"kid"`
 KeyFile string `json:"key_file"`
 CoreKeyFile string `json:"core_key_file"`
 Instance string `json:"instance"`
}

// ReadConfig accepts a service-specific struct, with this Config embedded,
// and rejects unknown properties and oversized configuration files.
func ReadConfig(path string, out any) error {
 if path==""||out==nil{return ErrInvalid}
 f,err:=os.Open(path)
 if err!=nil{return errors.New("bootstrap: configuration unavailable")}
 defer f.Close()
 raw,err:=io.ReadAll(io.LimitReader(f,(1<<20)+1))
 if err!=nil||len(raw)>1<<20{return ErrInvalid}
 if err:=contract.Strict(raw,out);err!=nil{return ErrInvalid}
 return nil
}

type Resources struct {
 DB *sql.DB
 Control *nats.Conn
 RPC *rpc.Client
 Key ed25519.PrivateKey
 CoreTrust ed25519.PublicKey
 mu sync.Mutex
 closed bool
}

// Open initializes only this process's SQL owner connection and authenticated
// Core control connection. sdk/service starts its separate, approved NATS Micro
// connection after service-specific composition; nothing is registered here.
func Open(ctx context.Context,cfg Config)(*Resources,error){
 if ctx==nil||cfg.ServiceID==""||cfg.Kid==""||cfg.Instance==""||
  cfg.KeyFile==""||cfg.CoreKeyFile==""||cfg.DSNFile==""{
  return nil,ErrInvalid
 }
 keyInfo,err:=os.Stat(cfg.KeyFile)
 if err!=nil||!keyInfo.Mode().IsRegular()||keyInfo.Mode().Perm()&0077!=0 {
  return nil,errors.New("bootstrap: signing key not available securely")
 }
 seed,err:=os.ReadFile(cfg.KeyFile)
 if err!=nil||len(seed)!=ed25519.SeedSize {return nil,ErrInvalid}
 private:=ed25519.NewKeyFromSeed(seed)
 for i:=range seed{seed[i]=0}
 trusted,err:=os.ReadFile(cfg.CoreKeyFile)
 if err!=nil{return nil,errors.New("bootstrap: Core trust root unavailable")}
 var core ed25519.PublicKey
 if err=json.Unmarshal(trusted,&core);err!=nil||len(core)!=ed25519.PublicKeySize{
  return nil,ErrInvalid
 }
 dsn,err:=os.ReadFile(cfg.DSNFile)
 if err!=nil{return nil,errors.New("bootstrap: owner DSN unavailable")}
 if strings.TrimSpace(string(dsn))==""{return nil,ErrInvalid}
 db,err:=sql.Open("pgx",strings.TrimSpace(string(dsn)))
 for i:=range dsn{dsn[i]=0}
 if err!=nil{return nil,ErrInvalid}
 db.SetMaxOpenConns(12)
 if err=db.PingContext(ctx);err!=nil{
  _=db.Close()
  return nil,errors.New("bootstrap: owner DB unreachable")
 }
 nc,err:=sdk.Connect(ctx,cfg.NATS)
 if err!=nil{_ = db.Close();return nil,errors.New("bootstrap: private NATS connection failed")}
 client,err:=rpc.NewClient(nc)
 if err!=nil{nc.Close();_ = db.Close();return nil,err}
 return &Resources{DB:db,Control:nc,RPC:client,Key:private,CoreTrust:core},nil
}

// A caller passes its own Fabric Registry. SDK bootstrap deliberately does not
// instantiate concrete Core clients or choose a service implementation.
func (r *Resources) RuntimeConfig(cfg Config, registry sdk.Registry) sdk.AppConfig {
 return sdk.AppConfig{Connection:cfg.NATS,Instance:cfg.Instance,Registry:registry}
}

func (r *Resources) Close() error {
 if r==nil{return nil}
 r.mu.Lock()
 defer r.mu.Unlock()
 if r.closed{return nil}
 r.closed=true
 if r.Control!=nil {r.Control.Close()}
 if r.DB!=nil{return r.DB.Close()}
 return nil
}
