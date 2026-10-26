package task

import (
 "context"
 "errors"

 "github.com/pavlith/arc/sdk/bootstrap"
 "github.com/pavlith/arc/services/core/modules/fabric"
 "github.com/pavlith/arc/services/core/modules/identity"
)

// BootstrapConfig is the configuration of the standalone arc-tasks process.
// Other services never import it to start Tasks.
type BootstrapConfig struct {
 bootstrap.Config
}

func Run(ctx context.Context, path string) error {
 var cfg BootstrapConfig
 if err:=bootstrap.ReadConfig(path,&cfg);err!=nil{return err}
 deps,err:=bootstrap.Open(ctx,cfg.Config)
 if err!=nil{return err}
 defer deps.Close()

 // Each deployed service has its own ServiceAccount, owner DB, connections
 // and approved Fabric registry. No shared process-level service switch.
 registry:=&fabric.Client{
  Account:cfg.ServiceID,Kid:cfg.Kid,Key:deps.Key,CoreKey:deps.CoreTrust,
 }
 app,err:=New(Config{
  DB:deps.DB,Runtime:deps.RuntimeConfig(cfg.Config,registry),
  Identity:identity.Client{
   RPC:deps.RPC,ServiceID:cfg.ServiceID,Kid:cfg.Kid,PrivateKey:deps.Key,
  },
  CoreTrust:deps.CoreTrust,
 })
 if err!=nil{return err}
 if err=app.Start(ctx);err!=nil{
  _=app.Stop()
  return err
 }
 defer app.Stop()
 err=app.App.Wait(ctx)
 if errors.Is(err,context.Canceled)&&ctx.Err()!=nil{return nil}
 return err
}
