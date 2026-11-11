package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pavlith/arc/services/agent"
	"github.com/pavlith/arc/services/agent/host"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	config := flag.String("config", "", "absolute path to private Agent JSON configuration")
	checkConfig := flag.Bool("check-config", false, "validate the local configuration and exit")
	hostInfo := flag.Bool("host-info", false, "print read-only host facts as JSON (no config required)")
	flag.Parse()
	if *hostInfo {
		facts, err := host.Collect(context.Background())
		if err != nil || json.NewEncoder(os.Stdout).Encode(facts) != nil {
			slog.Error("host inventory unavailable")
			os.Exit(1)
		}
		return
	}
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
