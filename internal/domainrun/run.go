// Package domainrun is the private bootstrap for standalone Tasks/Notifications
// processes. SDK owns transport; services own their composition and workers.
package domainrun

import (
 "context"
 "crypto/ed25519"
 "database/sql"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "strings"

 _ "github.com/jackc/pgx/v5/stdlib"
 "github.com/pavlith/arc/sdk"
 "github.com/pavlith/arc/sdk/contract"
 "github.com/pavlith/arc/sdk/rpc"
 "github.com/pavlith/arc/services/core/modules/fabric"
 "github.com/pavlith/arc/services/core/modules/identity"
 "github.com/pavlith/arc/services/notify"
 "github.com/pavlith/arc/services/notify/modules/delivery"
 "github.com/pavlith/arc/services/task"
)

// Config preserves the deployed M0 JSON interface and distinct service roles.
type Config struct {
 NATS sdk.Config `json:"nats"`
 DSNFile string `json:"dsn_file"`
 ServiceID string `json:"service_id"`
 Kid string `json:"kid"`
 KeyFile string `json:"key_file"`
 CoreKeyFile string `json:"core_key_file"`
 Instance string `json:"instance"`
 Subscription fabric.EventSubscription `json:"subscription"`
}

type Running struct {
 Stop func() error
 Wait func(context.Context) error
}

func Start(ctx context.Context,kind string,cfg Config)(*Running,error){
 if ctx==nil||cfg.ServiceID==""||cfg.Kid==""||cfg.Instance==""{
  return nil,errors.New("domain: missing service identity")
 }
 key,err:=identity.LoadSigningKey(cfg.KeyFile)
 if err!=nil{return nil,errors.New("domain: service key unavailable")}
 raw,err:=os.ReadFile(cfg.CoreKeyFile)
 if err!=nil{return nil,errors.New("domain: Core trust root unavailable")}
 var core ed25519.PublicKey
 if json.Unmarshal(raw,&core)!=nil||len(core)!=ed25519.PublicKeySize{
  return nil,errors.New("domain: invalid Core trust root")
 }
 raw,err=os.ReadFile(cfg.DSNFile)
 if err!=nil{return nil,errors.New("domain: DSN unavailable")}
 db,err:=sql.Open("pgx",strings.TrimSpace(string(raw)))
 if err!=nil{return nil,errors.New("domain: owner DB unavailable")}
 db.SetMaxOpenConns(12)
 closeDB:=func(){_ = db.Close()}
 if err=db.PingContext(ctx);err!=nil{closeDB();return nil,errors.New("domain: owner DB unreachable")}

 nc,err:=sdk.Connect(ctx,cfg.NATS)
 if err!=nil{closeDB();return nil,errors.New("domain: private NATS connection failed")}
 cleanup:=func(){nc.Close();closeDB()}
 rc,err:=rpc.NewClient(nc)
 if err!=nil{cleanup();return nil,err}
 client:=identity.Client{RPC:rc,ServiceID:cfg.ServiceID,Kid:cfg.Kid,PrivateKey:key}
 reg:=&fabric.Client{Account:cfg.ServiceID,Kid:cfg.Kid,Key:key,CoreKey:core}
 runtime:=sdk.AppConfig{
   Connection:cfg.NATS,Instance:cfg.Instance,Registry:reg,
 }
 var start func(context.Context)error
 var stop func()error
 var wait func(context.Context)error
 switch kind{
 case "tasks":
  service,err:=task.New(task.Config{
   DB:db,Runtime:runtime,Identity:client,CoreTrust:core,
  })
  if err!=nil{cleanup();return nil,fmt.Errorf("domain: tasks composition: %w",err)}
  start=service.Start
  stop=service.Stop
  wait=service.App.Wait
 case "notifications":
  service,err:=notify.New(notify.Config{
   DB:db,Runtime:runtime,Identity:client,CoreTrust:core,
   Registry:reg,Subscription:cfg.Subscription,Provider:&delivery.FakeProvider{},
  })
  if err!=nil{cleanup();return nil,fmt.Errorf("domain: notifications composition: %w",err)}
  start=service.Start
  stop=service.Stop
  wait=service.App.Wait
 default:
  cleanup()
  return nil,errors.New("domain: unknown service")
 }
 if err=start(ctx);err!=nil{
  _=stop()
  cleanup()
  return nil,err
 }
 return &Running{
  Stop:func()error{
   err:=stop()
   cleanup()
   return err
  },
  Wait:wait,
 },nil
}

func Run(ctx context.Context,kind,file string)error{
 raw,err:=os.ReadFile(file)
 if err!=nil{return err}
 var cfg Config
 if err=contract.Strict(raw,&cfg);err!=nil{return errors.New("domain: invalid configuration")}
 run,err:=Start(ctx,kind,cfg)
 if err!=nil{return err}
 defer run.Stop()
 err=run.Wait(ctx)
 if errors.Is(err,context.Canceled)&&ctx.Err()!=nil{return nil}
 return err
}

