package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/better-wallet/better-wallet/internal/logger"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/errors"
)

// IdempotencyMiddleware handles idempotency for API requests
// Stores first response for 24 hours
type IdempotencyMiddleware struct {
	repo idempotencyRepo
}

type idempotencyRepo interface {
	Get(ctx context.Context, appID, key, method, url string) (*storage.IdempotencyRecord, error)
	Store(ctx context.Context, record *storage.IdempotencyRecord) error
}

// NewIdempotencyMiddleware creates a new idempotency middleware
func NewIdempotencyMiddleware(repo idempotencyRepo) *IdempotencyMiddleware {
	return &IdempotencyMiddleware{
		repo: repo,
	}
}

// Handle wraps an HTTP handler with idempotency checking
func (m *IdempotencyMiddleware) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only apply to mutation requests (POST, PATCH, DELETE)
		if r.Method != http.MethodPost && r.Method != http.MethodPatch && r.Method != http.MethodDelete {
			next.ServeHTTP(w, r)
			return
		}

		// Get idempotency key from header
		idempotencyKey := r.Header.Get("x-idempotency-key")
		if idempotencyKey == "" {
			// No idempotency key - proceed normally
			next.ServeHTTP(w, r)
			return
		}

		// Validate key length (max 256 characters)
		if len(idempotencyKey) > 256 {
			writeError(w, errors.NewWithDetail(
				errors.ErrCodeBadRequest,
				"Idempotency key too long",
				"Maximum length is 256 characters",
				http.StatusBadRequest,
			))
			return
		}

		// Scope idempotency to the authenticated user (when present) to prevent
		// replaying user-scoped operations without a user context.
		//
		// Note: the header value is still validated for length; the scoped key is
		// an internal storage detail.
		scopedKey := idempotencyKey
		if userSub, ok := GetUserSub(r.Context()); ok && userSub != "" {
			scopedKey = userSub + ":" + idempotencyKey
		}

		// Get app ID from header
		appID := r.Header.Get("x-app-id")
		if appID == "" {
			writeError(w, errors.NewWithDetail(
				errors.ErrCodeBadRequest,
				"Missing app ID",
				"x-app-id header is required",
				http.StatusBadRequest,
			))
			return
		}

		// Read and hash the request body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, errors.NewWithDetail(
				errors.ErrCodeBadRequest,
				"Failed to read request body",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}

		// Restore body for next handler
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Compute body hash
		bodyHash := computeBodyHash(bodyBytes)

		// Check if this key was used before (scoped to app+key+method+url)
		record, err := m.repo.Get(r.Context(), appID, scopedKey, r.Method, r.URL.Path)
		if err == nil {
			// Key exists - check if body matches
			if record.BodyHash == bodyHash {
				// Same request - return cached response
				m.returnCachedResponse(w, record)
				return
			}

			// Different body with same key - error
			writeError(w, errors.NewWithDetail(
				errors.ErrCodeIdempotencyKeyReused,
				"Idempotency key reused with different body",
				"The same idempotency key was used with a different request body. Use a new key for different requests.",
				http.StatusBadRequest,
			))
			return
		}

		// Key doesn't exist - capture and store response
		recorder := NewResponseRecorder(w)

		// Call next handler
		next.ServeHTTP(recorder, r)

		// Store the response for future requests
		expiresAt := time.Now().Add(24 * time.Hour)
		err = m.repo.Store(r.Context(), &storage.IdempotencyRecord{
			AppID:      appID,
			Method:     r.Method,
			URL:        r.URL.Path,
			Key:        scopedKey,
			BodyHash:   bodyHash,
			StatusCode: recorder.StatusCode,
			Headers:    recorder.Headers,
			Body:       recorder.Body.Bytes(),
			ExpiresAt:  expiresAt,
		})

		if err != nil {
			// Log error but don't fail the request - response already sent
			logger.Error(r.Context(), "failed to store idempotency record",
				"app_id", appID,
				"key", scopedKey,
				"method", r.Method,
				"url", r.URL.Path,
				"error", err,
			)
		}

		// Response was already written by recorder
	})
}

// returnCachedResponse writes a cached response to the client
func (m *IdempotencyMiddleware) returnCachedResponse(
	w http.ResponseWriter,
	record *storage.IdempotencyRecord,
) {
	// Preserve the current request ID (set by the RequestID middleware) so we
	// don't replay a stale value from the cached response.
	currentRequestID := w.Header().Get("X-Request-ID")

	// Copy cached headers.
	for key, values := range record.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Ensure the response X-Request-ID matches the current request.
	w.Header().Del("X-Request-ID")
	if currentRequestID != "" {
		w.Header().Set("X-Request-ID", currentRequestID)
	}

	// Add idempotency replay header
	w.Header().Set("X-Idempotency-Replay", "true")

	// Write status code
	w.WriteHeader(record.StatusCode)

	// Write body
	w.Write(record.Body)
}

// computeBodyHash creates a SHA-256 hash of the request body
func computeBodyHash(body []byte) string {
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

// writeError writes an error response
func writeError(w http.ResponseWriter, err *errors.AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)

	// Write error JSON
	errorJSON := []byte(`{"error":{"code":"` + err.Code + `","message":"` + err.Message + `"}}`)
	w.Write(errorJSON)
}
