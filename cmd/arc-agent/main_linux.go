package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pavlith/arc/services/agent"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	config := flag.String("config", "", "absolute path to private Agent JSON configuration")
	checkConfig := flag.Bool("check-config", false, "validate the local configuration and exit")
	flag.Parse()
	if *checkConfig {
		if _, err := agent.ReadConfig(*config); err != nil {
			slog.Error("invalid agent configuration", "error", err)
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := agent.RunFile(ctx, *config); err != nil {
		slog.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}
