package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/rpc"
)

type echoRequest struct {
	Value string `json:"value"`
}

type echoResponse struct {
	Value string `json:"value"`
}

func main() {
	url := flag.String("url", "tls://127.0.0.1:4222", "NATS URL")
	ca := flag.String("ca", ".secrets/dev/ca.crt", "TLS CA path")
	serviceSeed := flag.String("service-seed", ".secrets/dev/nats-echo-service.seed", "service NKey seed path")
	clientSeed := flag.String("client-seed", ".secrets/dev/nats-smoke-client.seed", "client NKey seed path")
	jetStreamSeed := flag.String("jetstream-seed", ".secrets/dev/nats-jetstream-admin.seed", "JetStream NKey seed path")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := run(ctx, *url, *ca, *serviceSeed, *clientSeed, *jetStreamSeed); err != nil {
		fmt.Fprintln(os.Stderr, "M0-01 smoke failed:", err)
		os.Exit(1)
	}
	fmt.Println("M0-01 NATS RPC and JetStream smoke succeeded")
}

func run(ctx context.Context, url, ca, serviceSeed, clientSeed, jetStreamSeed string) error {
	service, err := connectService(ctx, sdk.ServiceConfig{
		Connection: sdk.Config{URL: url, Name: "arc-bootstrap", NKeySeedFile: serviceSeed, TLSCAFile: ca},
		Name:       "arc-bootstrap",
		Version:    "0.1.0",
	})
	if err != nil {
		return err
	}
	defer service.Stop()

	err = rpc.Handle(service, rpc.Operation{
		ID:         "bootstrap.echo",
		Endpoint:   "echo",
		Subject:    "rpc.bootstrap.v1.echo",
		QueueGroup: "q.bootstrap.v1",
		Timeout:    5 * time.Second,
	}, func(_ context.Context, request echoRequest) (echoResponse, error) {
		if request.Value == "" {
			return echoResponse{}, &rpc.Error{Code: rpc.CodeValidation, Message: "value is required"}
		}
		return echoResponse{Value: request.Value}, nil
	})
	if err != nil {
		return fmt.Errorf("register echo endpoint: %w", err)
	}

	clientConnection, err := connect(ctx, sdk.Config{URL: url, Name: "arc-smoke-client", NKeySeedFile: clientSeed, TLSCAFile: ca})
	if err != nil {
		return err
	}
	defer clientConnection.Close()
	client, err := rpc.NewClient(clientConnection)
	if err != nil {
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := rpc.Call[echoRequest, echoResponse](callCtx, client, "bootstrap.echo", "rpc.bootstrap.v1.echo", echoRequest{Value: "arc"})
	if err != nil {
		return fmt.Errorf("call echo endpoint: %w", err)
	}
	if response.Value != "arc" {
		return errors.New("echo response mismatch")
	}
	errorCtx, errorCancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = rpc.Call[echoRequest, echoResponse](errorCtx, client, "bootstrap.echo", "rpc.bootstrap.v1.echo", echoRequest{})
	errorCancel()
	if rpc.ErrorCode(err) != rpc.CodeValidation {
		return fmt.Errorf("typed handler error guardrail: got %v", err)
	}
	unauthorizedSubscription, err := clientConnection.SubscribeSync("rpc.bootstrap.v1.echo")
	if err != nil && !errors.Is(err, nats.ErrPermissionViolation) {
		return fmt.Errorf("test scoped client subscription: %w", err)
	}
	if err == nil {
		defer unauthorizedSubscription.Unsubscribe()
		if _, err := unauthorizedSubscription.NextMsg(time.Second); !errors.Is(err, nats.ErrPermissionViolation) {
			return fmt.Errorf("client subscription permission guardrail: got %v", err)
		}
	}
	if err := service.Stop(); err != nil {
		return fmt.Errorf("stop echo service: %w", err)
	}
	noResponderCtx, noResponderCancel := context.WithTimeout(ctx, time.Second)
	_, err = rpc.Call[echoRequest, echoResponse](noResponderCtx, client, "bootstrap.echo", "rpc.bootstrap.v1.echo", echoRequest{Value: "arc"})
	noResponderCancel()
	if rpc.ErrorCode(err) != rpc.CodeUnavailable {
		return fmt.Errorf("no responders typed error guardrail: got %v", err)
	}

	jetStreamConnection, err := connect(ctx, sdk.Config{URL: url, Name: "arc-jetstream-bootstrap", NKeySeedFile: jetStreamSeed, TLSCAFile: ca})
	if err != nil {
		return err
	}
	defer jetStreamConnection.Close()
	js, err := jetStreamConnection.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		return fmt.Errorf("open JetStream context: %w", err)
	}
	if _, err := js.StreamInfo("ARC_EVENTS"); errors.Is(err, nats.ErrStreamNotFound) {
		if _, err := js.AddStream(&nats.StreamConfig{
			Name:       "ARC_EVENTS",
			Subjects:   []string{"evt.>"},
			Storage:    nats.FileStorage,
			Retention:  nats.LimitsPolicy,
			Duplicates: 24 * time.Hour,
		}); err != nil {
			return fmt.Errorf("create JetStream stream: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect JetStream stream: %w", err)
	}
	if _, err := js.Publish("evt.bootstrap.smoke.completed.v1", []byte(`{"schema_version":1}`)); err != nil {
		return fmt.Errorf("publish JetStream smoke event: %w", err)
	}
	return nil
}

func connectService(ctx context.Context, cfg sdk.ServiceConfig) (*sdk.Service, error) {
	var lastErr error
	for ctx.Err() == nil {
		attemptCtx, cancel := context.WithTimeout(ctx, time.Second)
		service, err := sdk.NewService(attemptCtx, cfg)
		cancel()
		if err == nil {
			return service, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("connect service: %w", lastErr)
}

func connect(ctx context.Context, cfg sdk.Config) (*nats.Conn, error) {
	var lastErr error
	for ctx.Err() == nil {
		attemptCtx, cancel := context.WithTimeout(ctx, time.Second)
		connection, err := sdk.Connect(attemptCtx, cfg)
		cancel()
		if err == nil {
			return connection, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("connect: %w", lastErr)
}
