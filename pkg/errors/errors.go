package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// AppError represents an application-level error with HTTP status code
type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Detail     string `json:"detail,omitempty"`
	StatusCode int    `json:"-"`
}

func (e *AppError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Detail)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Common error codes
const (
	ErrCodeUnauthorized        = "unauthorized"
	ErrCodeForbidden           = "forbidden"
	ErrCodeNotFound            = "not_found"
	ErrCodeBadRequest          = "bad_request"
	ErrCodeConflict            = "conflict"
	ErrCodePolicyDenied        = "policy_denied"
	ErrCodeInvalidSignature    = "invalid_signature"
	ErrCodeExpired             = "expired"
	ErrCodeRateLimited         = "rate_limited"
	ErrCodeInternalError       = "internal_error"
	ErrCodeInvalidNonce        = "invalid_nonce"
	ErrCodeInvalidTimestamp    = "invalid_timestamp"
	ErrCodeWalletNotFound      = "wallet_not_found"
	ErrCodePolicyNotFound      = "policy_not_found"
	ErrCodeSignerNotFound      = "signer_not_found"
	ErrCodeSignerRevoked       = "signer_revoked"
	ErrCodeSignerExpired       = "signer_expired"
	ErrCodeInsufficientQuorum  = "insufficient_quorum"
	ErrCodeKeyOperationFailed  = "key_operation_failed"
	ErrCodeChainNotSupported   = "chain_not_supported"
	ErrCodeTransactionFailed   = "transaction_failed"
	ErrCodeIdempotencyKeyReused = "idempotency_key_reused"
)

// Predefined errors
var (
	ErrUnauthorized = &AppError{
		Code:       ErrCodeUnauthorized,
		Message:    "Authentication required",
		StatusCode: http.StatusUnauthorized,
	}

	ErrForbidden = &AppError{
		Code:       ErrCodeForbidden,
		Message:    "Access denied",
		StatusCode: http.StatusForbidden,
	}

	ErrNotFound = &AppError{
		Code:       ErrCodeNotFound,
		Message:    "Resource not found",
		StatusCode: http.StatusNotFound,
	}

	ErrBadRequest = &AppError{
		Code:       ErrCodeBadRequest,
		Message:    "Invalid request parameters",
		StatusCode: http.StatusBadRequest,
	}

	ErrInternalError = &AppError{
		Code:       ErrCodeInternalError,
		Message:    "Internal server error",
		StatusCode: http.StatusInternalServerError,
	}

	ErrConflict = &AppError{
		Code:       ErrCodeConflict,
		Message:    "Request conflict",
		StatusCode: http.StatusConflict,
	}
)

// New creates a new AppError
func New(code, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
	}
}

// NewWithDetail creates a new AppError with additional detail
func NewWithDetail(code, message, detail string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Detail:     detail,
		StatusCode: statusCode,
	}
}

// PolicyDenied creates a policy denied error
func PolicyDenied(reason string) *AppError {
	return &AppError{
		Code:       ErrCodePolicyDenied,
		Message:    "Policy denied",
		Detail:     reason,
		StatusCode: http.StatusForbidden,
	}
}

// InvalidSignature creates an invalid signature error
func InvalidSignature(detail string) *AppError {
	return &AppError{
		Code:       ErrCodeInvalidSignature,
		Message:    "Invalid authorization signature",
		Detail:     detail,
		StatusCode: http.StatusUnauthorized,
	}
}

// WalletNotFound creates a wallet not found error
func WalletNotFound(walletID string) *AppError {
	return &AppError{
		Code:       ErrCodeWalletNotFound,
		Message:    "Wallet not found",
		Detail:     fmt.Sprintf("wallet_id: %s", walletID),
		StatusCode: http.StatusNotFound,
	}
}

// IsAppError checks if an error is an AppError
func IsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}
