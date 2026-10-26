package rpc

import (
	"errors"
	"fmt"
)

type Code string

const (
	CodeUnauthenticated  Code = "UNAUTHENTICATED"
	CodePermissionDenied Code = "PERMISSION_DENIED"
	CodeNotFound         Code = "NOT_FOUND"
	CodeValidation       Code = "VALIDATION_ERROR"
	CodeConflict         Code = "CONFLICT"
	CodeRateLimited      Code = "RATE_LIMITED"
	CodeUnavailable      Code = "UNAVAILABLE"
	CodeDeadlineExceeded Code = "DEADLINE_EXCEEDED"
	CodeInternal         Code = "INTERNAL"
)

type Error struct {
	Code      Code   `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("rpc %s: %s", e.Code, e.Message)
}

func ErrorCode(err error) Code {
	var rpcErr *Error
	if errors.As(err, &rpcErr) && rpcErr != nil {
		return rpcErr.Code
	}
	return CodeInternal
}

func validCode(code Code) bool {
	switch code {
	case CodeUnauthenticated, CodePermissionDenied, CodeNotFound, CodeValidation,
		CodeConflict, CodeRateLimited, CodeUnavailable, CodeDeadlineExceeded, CodeInternal:
		return true
	default:
		return false
	}
}

func publicError(err error) *Error {
	var rpcErr *Error
	if errors.As(err, &rpcErr) && rpcErr != nil && validCode(rpcErr.Code) {
		if rpcErr.Code == CodeInternal {
			return &Error{Code: CodeInternal, Message: "internal error", Retryable: false}
		}
		return &Error{Code: rpcErr.Code, Message: rpcErr.Message, Retryable: rpcErr.Retryable}
	}
	return &Error{Code: CodeInternal, Message: "internal error", Retryable: false}
}
