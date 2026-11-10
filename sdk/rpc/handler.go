package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/pavlith/arc/sdk/transport"
)

type Operation struct {
	ID         string
	Endpoint   string
	Subject    string
	QueueGroup string
	Timeout    time.Duration
	// Authorize validates the signed envelope before invoking the domain handler.
	Authorize        func(context.Context, string, []byte) (context.Context, error)
	Protected        bool
	Mutation         bool
	ValidateRequest  func([]byte) error
	ValidateResponse func([]byte) error
}

type EndpointService interface {
	AddEndpoint(string, transport.Handler, ...transport.EndpointOpt) error
}

type Handler[Req, Res any] func(context.Context, Req) (Res, error)

func Handle[Req, Res any](service EndpointService, operation Operation, handler Handler[Req, Res]) error {
	if service == nil || handler == nil || !validOperation(operation.ID) || operation.Endpoint == "" || operation.Timeout <= 0 {
		return errors.New("rpc: invalid handler configuration")
	}
	if err := ValidateSubject(operation.Subject); err != nil {
		return err
	}
	if operation.QueueGroup == "" {
		return errors.New("rpc: queue group is required")
	}

	endpointHandler := transport.Handler(func(request transport.Request) {
		handleRequest(request, operation, handler)
	})
	return service.AddEndpoint(
		operation.Endpoint,
		endpointHandler,
		transport.WithEndpointSubject(operation.Subject),
		transport.WithEndpointQueueGroup(operation.QueueGroup),
	)
}

func handleRequest[Req, Res any](request transport.Request, operation Operation, handler Handler[Req, Res]) {
	start := time.Now()
	ctx := context.Background()
	code := CodeInternal
	defer func() {
		correlation := Correlation(ctx)
		slog.InfoContext(ctx, "arc rpc", "operation", operation.ID,
			"request_id", correlation.RequestID, "traceparent", correlation.Traceparent,
			"duration_ms", float64(time.Since(start))/float64(time.Millisecond), "error_code", code)
	}()
	requestID := "unknown"
	fail := func(err *Error) { code = respondError(request, requestID, err) }
	if len(request.Data()) > MaxMessageSize {
		fail(&Error{Code: CodeValidation, Message: "request exceeds 256 KiB"})
		return
	}
	var envelope requestEnvelope
	if err := decodeStrict(request.Data(), &envelope); err != nil {
		fail(&Error{Code: CodeValidation, Message: "invalid request envelope"})
		return
	}
	requestID = envelope.RequestID
	ctx = WithOutgoing(ctx, safeCorrelation(Outgoing{RequestID: requestID, Traceparent: envelope.Traceparent}))
	if requestID == "" || envelope.Operation != operation.ID || envelope.SchemaVersion != SchemaVersion {
		fail(&Error{Code: CodeValidation, Message: "request metadata mismatch"})
		return
	}
	if envelope.DeadlineAt.IsZero() || !envelope.DeadlineAt.After(time.Now()) {
		fail(&Error{Code: CodeDeadlineExceeded, Message: "request deadline exceeded", Retryable: true})
		return
	}
	if operation.Mutation && (envelope.IdempotencyKey == "" || len(envelope.IdempotencyKey) > 128) {
		fail(&Error{Code: CodeValidation, Message: "idempotency key required"})
		return
	}
	var payload Req
	decode := decodeStrict
	if operation.ValidateRequest != nil {
		decode = json.Unmarshal
	}
	if err := decode(envelope.Payload, &payload); err != nil {
		fail(&Error{Code: CodeValidation, Message: "invalid request payload"})
		return
	}

	effectiveDeadline := envelope.DeadlineAt
	contractDeadline := time.Now().Add(operation.Timeout)
	if contractDeadline.Before(effectiveDeadline) {
		effectiveDeadline = contractDeadline
	}
	ctx, cancel := context.WithDeadline(ctx, effectiveDeadline)
	defer cancel()

	if operation.Protected && operation.Authorize == nil {
		fail(&Error{Code: CodeUnavailable, Message: "security unavailable"})
		return
	}
	if operation.Authorize != nil {
		authorized, err := operation.Authorize(ctx, operation.Subject, request.Data())
		if err != nil {
			fail(publicError(err))
			return
		}
		if authorized == nil {
			fail(&Error{Code: CodeUnavailable, Message: "security unavailable"})
			return
		}
		ctx = authorized
	}
	ctx = context.WithValue(ctx, metadataKey{}, RequestMetadata{RequestID: envelope.RequestID, Traceparent: envelope.Traceparent, IdempotencyKey: envelope.IdempotencyKey, Payload: envelope.Payload})
	if operation.ValidateRequest != nil && operation.ValidateRequest(envelope.Payload) != nil {
		fail(&Error{Code: CodeValidation, Message: "request schema mismatch"})
		return
	}
	response, err := invoke(ctx, handler, payload)
	if err != nil {
		fail(publicError(err))
		return
	}
	data, err := json.Marshal(response)
	if err != nil {
		fail(&Error{Code: CodeInternal, Message: "internal error"})
		return
	}
	if operation.ValidateResponse != nil && operation.ValidateResponse(data) != nil {
		fail(&Error{Code: CodeInternal, Message: "response schema mismatch"})
		return
	}
	code = respond(request, responseEnvelope{RequestID: requestID, Data: data})
}

func invoke[Req, Res any](ctx context.Context, handler Handler[Req, Res], request Req) (response Res, err error) {
	defer func() {
		if recover() != nil {
			err = &Error{Code: CodeInternal, Message: "internal error"}
		}
	}()
	return handler(ctx, request)
}

func respondError(request transport.Request, requestID string, err *Error) Code {
	return respond(request, responseEnvelope{RequestID: requestID, Error: publicError(err)})
}

func respond(request transport.Request, envelope responseEnvelope) Code {
	code := Code("")
	if envelope.Error != nil {
		code = envelope.Error.Code
	}
	data, err := json.Marshal(envelope)
	if err != nil || len(data) > MaxMessageSize {
		code = CodeInternal
		data, _ = json.Marshal(responseEnvelope{
			RequestID: envelope.RequestID,
			Error:     &Error{Code: CodeInternal, Message: "internal error"},
		})
	}
	if err := request.Respond(data); err != nil && code == "" {
		code = CodeUnavailable
	}
	return code
}
