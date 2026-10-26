package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/nats-io/nats.go/micro"
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
	AddEndpoint(string, micro.Handler, ...micro.EndpointOpt) error
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

	endpointHandler := micro.HandlerFunc(func(request micro.Request) {
		handleRequest(request, operation, handler)
	})
	return service.AddEndpoint(
		operation.Endpoint,
		endpointHandler,
		micro.WithEndpointSubject(operation.Subject),
		micro.WithEndpointQueueGroup(operation.QueueGroup),
	)
}

func handleRequest[Req, Res any](request micro.Request, operation Operation, handler Handler[Req, Res]) {
	requestID := "unknown"
	if len(request.Data()) > MaxMessageSize {
		respondError(request, requestID, &Error{Code: CodeValidation, Message: "request exceeds 256 KiB"})
		return
	}
	var envelope requestEnvelope
	if err := decodeStrict(request.Data(), &envelope); err != nil {
		respondError(request, requestID, &Error{Code: CodeValidation, Message: "invalid request envelope"})
		return
	}
	requestID = envelope.RequestID
	if requestID == "" || envelope.Operation != operation.ID || envelope.SchemaVersion != SchemaVersion {
		respondError(request, requestID, &Error{Code: CodeValidation, Message: "request metadata mismatch"})
		return
	}
	if envelope.DeadlineAt.IsZero() || !envelope.DeadlineAt.After(time.Now()) {
		respondError(request, requestID, &Error{Code: CodeDeadlineExceeded, Message: "request deadline exceeded", Retryable: true})
		return
	}
	if operation.Mutation && (envelope.IdempotencyKey == "" || len(envelope.IdempotencyKey) > 128) {
		respondError(request, requestID, &Error{Code: CodeValidation, Message: "idempotency key required"})
		return
	}
	var payload Req
	decode := decodeStrict
	if operation.ValidateRequest != nil {
		decode = json.Unmarshal
	}
	if err := decode(envelope.Payload, &payload); err != nil {
		respondError(request, requestID, &Error{Code: CodeValidation, Message: "invalid request payload"})
		return
	}

	effectiveDeadline := envelope.DeadlineAt
	contractDeadline := time.Now().Add(operation.Timeout)
	if contractDeadline.Before(effectiveDeadline) {
		effectiveDeadline = contractDeadline
	}
	ctx, cancel := context.WithDeadline(context.Background(), effectiveDeadline)
	defer cancel()

	if operation.Protected && operation.Authorize == nil {
		respondError(request, requestID, &Error{Code: CodeUnavailable, Message: "security unavailable"})
		return
	}
	if operation.Authorize != nil {
		authorized, err := operation.Authorize(ctx, operation.Subject, request.Data())
		if err != nil {
			respondError(request, requestID, publicError(err))
			return
		}
		if authorized == nil {
			respondError(request, requestID, &Error{Code: CodeUnavailable, Message: "security unavailable"})
			return
		}
		ctx = authorized
	}
	ctx = context.WithValue(ctx, metadataKey{}, RequestMetadata{RequestID: envelope.RequestID, Traceparent: envelope.Traceparent, IdempotencyKey: envelope.IdempotencyKey, Payload: envelope.Payload})
	if operation.ValidateRequest != nil && operation.ValidateRequest(envelope.Payload) != nil {
		respondError(request, requestID, &Error{Code: CodeValidation, Message: "request schema mismatch"})
		return
	}
	response, err := invoke(ctx, handler, payload)
	if err != nil {
		respondError(request, requestID, publicError(err))
		return
	}
	data, err := json.Marshal(response)
	if err != nil {
		respondError(request, requestID, &Error{Code: CodeInternal, Message: "internal error"})
		return
	}
	if operation.ValidateResponse != nil && operation.ValidateResponse(data) != nil {
		respondError(request, requestID, &Error{Code: CodeInternal, Message: "response schema mismatch"})
		return
	}
	respond(request, responseEnvelope{RequestID: requestID, Data: data})
}

func invoke[Req, Res any](ctx context.Context, handler Handler[Req, Res], request Req) (response Res, err error) {
	defer func() {
		if recover() != nil {
			err = &Error{Code: CodeInternal, Message: "internal error"}
		}
	}()
	return handler(ctx, request)
}

func respondError(request micro.Request, requestID string, err *Error) {
	respond(request, responseEnvelope{RequestID: requestID, Error: publicError(err)})
}

func respond(request micro.Request, envelope responseEnvelope) {
	data, err := json.Marshal(envelope)
	if err != nil || len(data) > MaxMessageSize {
		data, _ = json.Marshal(responseEnvelope{
			RequestID: envelope.RequestID,
			Error:     &Error{Code: CodeInternal, Message: "internal error"},
		})
	}
	_ = request.Respond(data)
}
