package main

import (
 "context"
 "flag"
 "log"
 "os"
 "os/signal"
 "syscall"

 "github.com/pavlith/arc/services/notify"
)

func main() {
 file:=flag.String("config","","path to Notifications JSON configuration")
 flag.Parse()
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
 defer stop()
 if err:=notify.Run(ctx,*file);err!=nil{
  log.Print(err)
  os.Exit(1)
 }
}
