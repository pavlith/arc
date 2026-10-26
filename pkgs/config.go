package pkgs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

const defaultConnectTimeout = 5 * time.Second

// Config contains only paths to credentials and trust roots. Secret material is
// never copied into configuration values that are commonly logged.
type Config struct {
	URL          string
	Name         string
	NKeySeedFile string
	TLSCAFile    string
}

// Connect establishes a TLS and NKey-authenticated connection to NATS.
func Connect(ctx context.Context, cfg Config) (*nats.Conn, error) {
	if ctx == nil {
		return nil, errors.New("pkgs: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.URL == "" || cfg.Name == "" || cfg.NKeySeedFile == "" || cfg.TLSCAFile == "" {
		return nil, errors.New("pkgs: URL, name, NKey seed file, and TLS CA file are required")
	}

	nkeyOption, err := nats.NkeyOptionFromSeed(cfg.NKeySeedFile)
	if err != nil {
		return nil, fmt.Errorf("pkgs: load NKey credential: %w", err)
	}

	timeout := defaultConnectTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
		}
	}

	nc, err := nats.Connect(
		cfg.URL,
		nats.Name(cfg.Name),
		nkeyOption,
		nats.RootCAs(cfg.TLSCAFile),
		nats.Timeout(timeout),
		nats.NoEcho(),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(250*time.Millisecond),
		nats.PermissionErrOnSubscribe(true),
	)
	if err != nil {
		return nil, fmt.Errorf("pkgs: connect to NATS: %w", err)
	}
	return nc, nil
}
