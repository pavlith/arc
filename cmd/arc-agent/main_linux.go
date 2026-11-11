package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pavlith/arc/services/agent"
	"github.com/pavlith/arc/services/agent/modules/apt"
	"github.com/pavlith/arc/services/agent/modules/enrollment"
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
	enrollmentKeygen := flag.String("enrollment-keygen", "", "create a private Ed25519 service seed (no NATS connection)")
	enrollmentClaim := flag.String("enrollment-claim", "", "sign the one-time offer ID using secret token read from stdin")
	enrollmentKeyFile := flag.String("enrollment-key-file", "", "private Ed25519 service seed to use for an offline claim")
	flag.Parse()
	if *enrollmentClaim != "" {
		if *enrollmentKeygen != "" || *hostInfo || *checkConfig ||
			*aptPlan != "" || *previewProfile != "" || *enrollmentKeyFile == "" {
			slog.Error("invalid enrollment claim options")
			os.Exit(2)
		}
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 128))
		if err != nil || len(raw) > 127 {
			slog.Error("enrollment token unavailable on stdin")
			os.Exit(1)
		}
		token := strings.TrimSpace(string(raw))
		clear(raw)
		signature, err := agent.SignEnrollmentFile(*enrollmentKeyFile, *enrollmentClaim, token)
		if err != nil {
			slog.Error("enrollment proof unavailable")
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(struct {
			OfferID   string `json:"offer_id"`
			Signature string `json:"signature"`
		}{OfferID: *enrollmentClaim, Signature: signature}); err != nil {
			slog.Error("public proof output failed")
			os.Exit(1)
		}
		return
	}
	if *enrollmentKeygen != "" {
		if *hostInfo || *checkConfig || *aptPlan != "" || *previewProfile != "" || *enrollmentKeyFile != "" {
			slog.Error("key generation cannot be combined with other commands")
			os.Exit(2)
		}
		public, err := enrollment.CreateKeyFile(*enrollmentKeygen)
		if err != nil {
			slog.Error("secure enrollment seed creation failed")
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(struct {
			PublicKey string `json:"public_key"`
		}{PublicKey: public}); err != nil {
			slog.Error("public key output failed")
			os.Exit(1)
		}
		return
	}
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
