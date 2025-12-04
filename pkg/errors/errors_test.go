package errors

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AppError
		expected string
	}{
		{
			name: "error without detail",
			err: &AppError{
				Code:    ErrCodeUnauthorized,
				Message: "Authentication required",
			},
			expected: "unauthorized: Authentication required",
		},
		{
			name: "error with detail",
			err: &AppError{
				Code:    ErrCodeBadRequest,
				Message: "Invalid request",
				Detail:  "missing required field 'name'",
			},
			expected: "bad_request: Invalid request (missing required field 'name')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestNew(t *testing.T) {
	err := New("test_code", "Test message", http.StatusTeapot)

	assert.Equal(t, "test_code", err.Code)
	assert.Equal(t, "Test message", err.Message)
	assert.Equal(t, http.StatusTeapot, err.StatusCode)
	assert.Empty(t, err.Detail)
}

func TestNewWithDetail(t *testing.T) {
	err := NewWithDetail(
		"test_code",
		"Test message",
		"Additional details",
		http.StatusBadRequest,
	)

	assert.Equal(t, "test_code", err.Code)
	assert.Equal(t, "Test message", err.Message)
	assert.Equal(t, "Additional details", err.Detail)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
}

func TestPolicyDenied(t *testing.T) {
	err := PolicyDenied("value exceeds limit")

	assert.Equal(t, ErrCodePolicyDenied, err.Code)
	assert.Equal(t, "Policy denied", err.Message)
	assert.Equal(t, "value exceeds limit", err.Detail)
	assert.Equal(t, http.StatusForbidden, err.StatusCode)
}

func TestInvalidSignature(t *testing.T) {
	err := InvalidSignature("signature verification failed")

	assert.Equal(t, ErrCodeInvalidSignature, err.Code)
	assert.Equal(t, "Invalid authorization signature", err.Message)
	assert.Equal(t, "signature verification failed", err.Detail)
	assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
}

func TestWalletNotFound(t *testing.T) {
	err := WalletNotFound("wallet-123")

	assert.Equal(t, ErrCodeWalletNotFound, err.Code)
	assert.Equal(t, "Wallet not found", err.Message)
	assert.Contains(t, err.Detail, "wallet-123")
	assert.Equal(t, http.StatusNotFound, err.StatusCode)
}

func TestIsAppError(t *testing.T) {
	t.Run("returns AppError when error is AppError", func(t *testing.T) {
		originalErr := New("test", "test", http.StatusBadRequest)
		appErr, ok := IsAppError(originalErr)

		require.True(t, ok)
		assert.Equal(t, originalErr, appErr)
	})

	t.Run("returns false when error is not AppError", func(t *testing.T) {
		stdErr := errors.New("standard error")
		appErr, ok := IsAppError(stdErr)

		assert.False(t, ok)
		assert.Nil(t, appErr)
	})

	t.Run("works with wrapped errors", func(t *testing.T) {
		originalErr := New("test", "test", http.StatusBadRequest)
		wrappedErr := fmt.Errorf("wrapped: %w", originalErr)

		appErr, ok := IsAppError(wrappedErr)

		require.True(t, ok)
		assert.Equal(t, originalErr, appErr)
	})
}

func TestPredefinedErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        *AppError
		code       string
		statusCode int
	}{
		{
			name:       "ErrUnauthorized",
			err:        ErrUnauthorized,
			code:       ErrCodeUnauthorized,
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "ErrForbidden",
			err:        ErrForbidden,
			code:       ErrCodeForbidden,
			statusCode: http.StatusForbidden,
		},
		{
			name:       "ErrNotFound",
			err:        ErrNotFound,
			code:       ErrCodeNotFound,
			statusCode: http.StatusNotFound,
		},
		{
			name:       "ErrBadRequest",
			err:        ErrBadRequest,
			code:       ErrCodeBadRequest,
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "ErrInternalError",
			err:        ErrInternalError,
			code:       ErrCodeInternalError,
			statusCode: http.StatusInternalServerError,
		},
		{
			name:       "ErrConflict",
			err:        ErrConflict,
			code:       ErrCodeConflict,
			statusCode: http.StatusConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.code, tt.err.Code)
			assert.Equal(t, tt.statusCode, tt.err.StatusCode)
			assert.NotEmpty(t, tt.err.Message)
		})
	}
}

func TestErrorCodeConstants(t *testing.T) {
	// Verify all error codes are unique and non-empty
	codes := []string{
		ErrCodeUnauthorized,
		ErrCodeForbidden,
		ErrCodeNotFound,
		ErrCodeBadRequest,
		ErrCodeConflict,
		ErrCodePolicyDenied,
		ErrCodeInvalidSignature,
		ErrCodeExpired,
		ErrCodeRateLimited,
		ErrCodeInternalError,
		ErrCodeInvalidNonce,
		ErrCodeInvalidTimestamp,
		ErrCodeWalletNotFound,
		ErrCodePolicyNotFound,
		ErrCodeSignerNotFound,
		ErrCodeSignerRevoked,
		ErrCodeSignerExpired,
		ErrCodeInsufficientQuorum,
		ErrCodeKeyOperationFailed,
		ErrCodeChainNotSupported,
		ErrCodeTransactionFailed,
		ErrCodeIdempotencyKeyReused,
	}

	uniqueCodes := make(map[string]bool)
	for _, code := range codes {
		assert.NotEmpty(t, code, "error code should not be empty")
		assert.False(t, uniqueCodes[code], "error code %s is duplicate", code)
		uniqueCodes[code] = true
	}
}

func TestAppError_ImplementsError(t *testing.T) {
	// Verify AppError implements the error interface
	var err error = &AppError{
		Code:    "test",
		Message: "test message",
	}

	assert.NotEmpty(t, err.Error())
}
