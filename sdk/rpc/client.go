package rpc

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
)

type Client struct {
	connection *nats.Conn
}

func NewClient(connection *nats.Conn) (*Client, error) {
	if connection == nil {
		return nil, errors.New("rpc: nil NATS connection")
	}
	return &Client{connection: connection}, nil
}

func Call[Req, Res any](ctx context.Context, client *Client, operation, subject string, request Req) (Res, error) {
	return CallValidated[Req, Res](ctx, client, operation, subject, request, nil, nil)
}

// CallValidated validates wire payloads before decoding DTOs. Schema policy owns
// additive fields; envelope fields always remain strict.
func CallValidated[Req, Res any](ctx context.Context, client *Client, operation, subject string, request Req, validateRequest, validateResponse func([]byte) error) (Res, error) {
	var zero Res
	if ctx == nil || client == nil || client.connection == nil {
		return zero, &Error{Code: CodeValidation, Message: "client and context are required"}
	}
	if !validOperation(operation) {
		return zero, &Error{Code: CodeValidation, Message: "invalid operation"}
	}
	if err := ValidateSubject(subject); err != nil {
		return zero, &Error{Code: CodeValidation, Message: "invalid RPC subject"}
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return zero, &Error{Code: CodeValidation, Message: "request deadline is required"}
	}
	requestID, err := newRequestID()
	if err != nil {
		return zero, &Error{Code: CodeInternal, Message: "cannot create request"}
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return zero, &Error{Code: CodeValidation, Message: "request is not JSON encodable"}
	}
	if validateRequest != nil && validateRequest(payload) != nil {
		return zero, &Error{Code: CodeValidation, Message: "request schema mismatch"}
	}
	envelope := requestEnvelope{
		RequestID:     requestID,
		Operation:     operation,
		SchemaVersion: SchemaVersion,
		DeadlineAt:    deadline.UTC(),
		Payload:       payload,
	}
	if credentials, ok := ctx.Value(credentialsKey{}).(Credentials); ok {
		if credentials.Proof == nil || credentials.Token == "" {
			return zero, &Error{Code: CodeUnauthenticated, Message: "missing credentials"}
		}
		envelope.Auth = credentials.Token
		envelope.IdempotencyKey = credentials.IdempotencyKey
		unsigned, err := json.Marshal(envelope)
		if err != nil {
			return zero, err
		}
		p, err := credentials.Proof(subject, unsigned)
		if err != nil {
			return zero, err
		}
		envelope.Proof = &p
	}
	wireRequest, err := json.Marshal(envelope)
	if err != nil {
		return zero, &Error{Code: CodeInternal, Message: "cannot encode request"}
	}
	if len(wireRequest) > MaxMessageSize {
		return zero, &Error{Code: CodeValidation, Message: "request exceeds 256 KiB"}
	}

	message, err := client.connection.RequestWithContext(ctx, subject, wireRequest)
	if err != nil {
		return zero, transportError(ctx, err)
	}
	if len(message.Data) > MaxMessageSize {
		return zero, &Error{Code: CodeInternal, Message: "response exceeds 256 KiB"}
	}
	if message.Header.Get(micro.ErrorHeader) != "" {
		return zero, microError(message.Header.Get(micro.ErrorCodeHeader))
	}
	var response responseEnvelope
	if err := decodeStrict(message.Data, &response); err != nil {
		return zero, &Error{Code: CodeInternal, Message: "invalid response envelope"}
	}
	if response.RequestID != requestID {
		return zero, &Error{Code: CodeInternal, Message: "response request id mismatch"}
	}
	if response.Error != nil && len(response.Data) != 0 {
		return zero, &Error{Code: CodeInternal, Message: "ambiguous response envelope"}
	}
	if response.Error != nil {
		if !validCode(response.Error.Code) {
			return zero, &Error{Code: CodeInternal, Message: "invalid response error code"}
		}
		return zero, publicError(response.Error)
	}
	if len(response.Data) == 0 {
		return zero, &Error{Code: CodeInternal, Message: "response data is missing"}
	}
	decode := decodeStrict
	if validateResponse != nil {
		if validateResponse(response.Data) != nil {
			return zero, &Error{Code: CodeInternal, Message: "response schema mismatch"}
		}
		decode = json.Unmarshal
	}
	if err := decode(response.Data, &zero); err != nil {
		return zero, &Error{Code: CodeInternal, Message: "invalid response data"}
	}
	return zero, nil
}

func microError(code string) error {
	typedCode := Code(code)
	if !validCode(typedCode) {
		return &Error{Code: CodeInternal, Message: "service error"}
	}
	if typedCode == CodeInternal {
		return &Error{Code: CodeInternal, Message: "internal error"}
	}
	return &Error{Code: typedCode, Message: "service error"}
}

func transportError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
		return &Error{Code: CodeDeadlineExceeded, Message: "request deadline exceeded", Retryable: true}
	}
	if errors.Is(err, nats.ErrNoResponders) {
		return &Error{Code: CodeUnavailable, Message: "service unavailable", Retryable: true}
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return &Error{Code: CodeUnavailable, Message: "request canceled", Retryable: false}
	}
	return &Error{Code: CodeUnavailable, Message: "transport unavailable", Retryable: true}
}
