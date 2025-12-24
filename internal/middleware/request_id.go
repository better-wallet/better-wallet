package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/better-wallet/better-wallet/internal/logger"
)

// RequestID generates a unique request ID for each incoming request.
// The request ID is:
//   - Stored in context for use by other middleware and handlers
//   - Added to the response as X-Request-ID header for client correlation
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for existing request ID from upstream proxy/load balancer
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		// Add to context for downstream use
		ctx := logger.WithRequestID(r.Context(), requestID)

		// Add to response headers for client correlation
		w.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// generateRequestID creates a random 32-character hex string (16 bytes of entropy).
// Uses crypto/rand for cryptographic randomness.
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback should never happen with crypto/rand, but be safe
		return "fallback-request-id"
	}
	return hex.EncodeToString(b)
}
