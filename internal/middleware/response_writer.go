package middleware

import (
	"bytes"
	"net/http"
)

// StatusRecorder wraps http.ResponseWriter to capture the response status code.
// It is safe to call WriteHeader multiple times - only the first call takes effect.
type StatusRecorder struct {
	http.ResponseWriter
	StatusCode int
	written    bool
}

// NewStatusRecorder creates a new StatusRecorder with a default status of 200 OK.
func NewStatusRecorder(w http.ResponseWriter) *StatusRecorder {
	return &StatusRecorder{
		ResponseWriter: w,
		StatusCode:     http.StatusOK,
	}
}

// WriteHeader captures the status code and writes it to the underlying ResponseWriter.
// Only the first call takes effect; subsequent calls are ignored.
func (r *StatusRecorder) WriteHeader(code int) {
	if !r.written {
		r.StatusCode = code
		r.written = true
		r.ResponseWriter.WriteHeader(code)
	}
}

// Write writes data to the underlying ResponseWriter.
// If WriteHeader has not been called, it calls WriteHeader with StatusOK.
func (r *StatusRecorder) Write(b []byte) (int, error) {
	if !r.written {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

// ResponseRecorder extends StatusRecorder to also capture the response body and headers.
// Used by the idempotency middleware to cache and replay responses.
type ResponseRecorder struct {
	*StatusRecorder
	Body    *bytes.Buffer
	Headers http.Header
}

// NewResponseRecorder creates a new ResponseRecorder.
func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		StatusRecorder: NewStatusRecorder(w),
		Body:           &bytes.Buffer{},
		Headers:        make(http.Header),
	}
}

// WriteHeader captures headers before writing the status code.
func (r *ResponseRecorder) WriteHeader(code int) {
	if !r.StatusRecorder.written {
		// Capture headers before first write
		for key, values := range r.ResponseWriter.Header() {
			r.Headers[key] = values
		}
	}
	r.StatusRecorder.WriteHeader(code)
}

// Write captures the response body while writing to the underlying ResponseWriter.
func (r *ResponseRecorder) Write(b []byte) (int, error) {
	if !r.StatusRecorder.written {
		r.WriteHeader(http.StatusOK)
	}
	r.Body.Write(b)
	return r.ResponseWriter.Write(b)
}
