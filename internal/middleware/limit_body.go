package middleware

import (
	"net/http"
)

// MaxBodySize is the maximum allowed request body size (1MB)
const MaxBodySize = 1 << 20 // 1MB

// LimitBody limits the size of request bodies to prevent DoS attacks
func LimitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)
		next.ServeHTTP(w, r)
	})
}
