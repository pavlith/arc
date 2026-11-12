package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pavlith/arc/services/contacts"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	file := flag.String("config", "", "path to Contacts JSON configuration")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := contacts.Run(ctx, *file); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
