package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pavlith/arc/services/agent"
	"github.com/pavlith/arc/services/agent/modules/apt"
	"github.com/pavlith/arc/services/agent/modules/host"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	config := flag.String("config", "", "absolute path to private Agent JSON configuration")
	checkConfig := flag.Bool("check-config", false, "validate the local configuration and exit")
	hostInfo := flag.Bool("host-info", false, "print read-only host facts as JSON (no config required)")
	aptPlan := flag.String("apt-plan", "", "simulate package installation (comma-separated names, no changes)")
	previewProfile := flag.String("preview-profile", "", "preview a Core-approved profile by ID (read-only)")
	profileRevision := flag.Int64("profile-revision", 0, "approved profile revision for preview")
	flag.Parse()
	if *previewProfile != "" {
		if *profileRevision < 1 || *hostInfo || *checkConfig || *aptPlan != "" {
			slog.Error("invalid profile preview options")
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		plan, err := agent.PreviewProfileFile(ctx, *config, *previewProfile, *profileRevision)
		if err != nil || json.NewEncoder(os.Stdout).Encode(plan) != nil {
			slog.Error("approved profile preview unavailable")
			os.Exit(1)
		}
		return
	}
	if *hostInfo {
		facts, err := host.Collect(context.Background())
		if err != nil || json.NewEncoder(os.Stdout).Encode(facts) != nil {
			slog.Error("host inventory unavailable")
			os.Exit(1)
		}
		return
	}
	if *aptPlan != "" {
		plan, err := apt.New().PlanInstall(context.Background(), strings.Split(*aptPlan, ","))
		if err != nil || json.NewEncoder(os.Stdout).Encode(plan) != nil {
			slog.Error("APT plan unavailable")
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
