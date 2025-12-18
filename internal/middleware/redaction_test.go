package middleware

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactHeaders(t *testing.T) {
	t.Run("redacts sensitive headers and preserves others", func(t *testing.T) {
		h := make(http.Header)
		h.Set("Authorization", "Bearer abc.def.ghi")
		h.Set("X-App-Secret", "bw_sk_test_123")
		h.Set("Content-Type", "application/json")

		redacted := RedactHeaders(h)

		assert.Equal(t, "Bearer [REDACTED]", redacted.Get("Authorization"))
		assert.Equal(t, "[REDACTED]", redacted.Get("X-App-Secret"))
		assert.Equal(t, "application/json", redacted.Get("Content-Type"))

		// Original must be unchanged
		assert.Equal(t, "Bearer abc.def.ghi", h.Get("Authorization"))
		assert.Equal(t, "bw_sk_test_123", h.Get("X-App-Secret"))
	})

	t.Run("handles non-scheme Authorization values", func(t *testing.T) {
		h := make(http.Header)
		h.Set("Authorization", "abc")

		redacted := RedactHeaders(h)
		assert.Equal(t, "[REDACTED]", redacted.Get("Authorization"))
	})
}

func TestStripSensitiveHeaders(t *testing.T) {
	h := make(http.Header)
	h.Set("Authorization", "Bearer abc")
	h.Set("x-app-secret", "bw_sk_test_123")
	h.Set("Content-Type", "application/json")

	StripCredentialHeaders(h)

	assert.Empty(t, h.Get("Authorization"))
	assert.Empty(t, h.Get("X-App-Secret"))
	assert.Equal(t, "application/json", h.Get("Content-Type"))
}
