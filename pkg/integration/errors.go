package integration

import (
	"errors"
	"fmt"
)

// ErrorCode defines machine-readable failure classifications.
type ErrorCode string

const (
	ErrNotInstalled       ErrorCode = "not-installed"
	ErrUnsupportedVersion ErrorCode = "unsupported-version"
	ErrInvalidConfig      ErrorCode = "invalid-config"
	ErrPolicyDenied       ErrorCode = "policy-denied"
	ErrTimeout            ErrorCode = "timeout"
	ErrProcessFailed      ErrorCode = "process-failed"
	ErrOutputLimit        ErrorCode = "output-limit"
	ErrParseError         ErrorCode = "parse-error"
	ErrCancelled          ErrorCode = "cancelled"
	ErrInternal           ErrorCode = "internal"
)

// Error represents a structured error returned from an integration operation.
type Error struct {
	Code          ErrorCode `json:"code"`
	IntegrationID string    `json:"integration_id"`
	Message       string    `json:"message"`
	Err           error     `json:"-"`
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.IntegrationID, e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s:%s] %s", e.IntegrationID, e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// NewError creates an integration Error with an optional underlying cause.
func NewError(code ErrorCode, integrationID, message string, cause error) *Error {
	return &Error{
		Code:          code,
		IntegrationID: integrationID,
		Message:       message,
		Err:           cause,
	}
}

// IsErrorCode checks whether an error is or wraps an integration Error with the given code.
func IsErrorCode(err error, code ErrorCode) bool {
	var intErr *Error
	if errors.As(err, &intErr) {
		return intErr.Code == code
	}
	return false
}
