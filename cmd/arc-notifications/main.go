package main

import (
	"context"
	"flag"
	"github.com/pavlith/arc/internal/domainrun"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	file := flag.String("config", "", "path to domain JSON configuration")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := domainrun.Run(ctx, "notifications", *file); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
