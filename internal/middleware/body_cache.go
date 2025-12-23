package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

// MaxBodySize is the maximum request body size (10 MB)
const MaxBodySize = 10 * 1024 * 1024

// LimitBody middleware enforces a size limit on request bodies and buffers them
// for re-reading. Bodies exceeding MaxBodySize return 413 Request Entity Too Large.
//
// This is a standard Go HTTP pattern: after reading r.Body, restore it with
// io.NopCloser so downstream handlers can read it again.
func LimitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only limit methods that carry a body
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			// Continue to read and limit body
		default:
			next.ServeHTTP(w, r)
			return
		}

		// MaxBytesReader returns error when limit exceeded
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Restore body for downstream handlers (standard Go pattern)
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}
