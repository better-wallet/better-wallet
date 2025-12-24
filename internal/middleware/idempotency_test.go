package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/internal/storage"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeBodyHash(t *testing.T) {
	t.Run("hashes body content", func(t *testing.T) {
		body := []byte("test body content")
		hash := computeBodyHash(body)

		// Verify it's a valid hex-encoded SHA-256 hash (64 chars)
		assert.Len(t, hash, 64)

		// Verify against known hash
		expected := sha256.Sum256(body)
		expectedHex := hex.EncodeToString(expected[:])
		assert.Equal(t, expectedHex, hash)
	})

	t.Run("hashes empty body", func(t *testing.T) {
		body := []byte{}
		hash := computeBodyHash(body)

		// Empty SHA-256 hash
		expected := sha256.Sum256(body)
		expectedHex := hex.EncodeToString(expected[:])
		assert.Equal(t, expectedHex, hash)
	})

	t.Run("same content produces same hash", func(t *testing.T) {
		body := []byte("identical content")
		hash1 := computeBodyHash(body)
		hash2 := computeBodyHash(body)
		assert.Equal(t, hash1, hash2)
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		hash1 := computeBodyHash([]byte("content 1"))
		hash2 := computeBodyHash([]byte("content 2"))
		assert.NotEqual(t, hash1, hash2)
	})
}

func TestWriteError(t *testing.T) {
	t.Run("writes error JSON", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		err := apperrors.New("test_error", "Test error message", http.StatusBadRequest)

		writeError(recorder, err)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
		assert.Contains(t, recorder.Body.String(), "test_error")
		assert.Contains(t, recorder.Body.String(), "Test error message")
	})
}

func TestResponseRecorder(t *testing.T) {
	t.Run("captures status code", func(t *testing.T) {
		w := httptest.NewRecorder()
		recorder := NewResponseRecorder(w)

		recorder.WriteHeader(http.StatusCreated)
		assert.Equal(t, http.StatusCreated, recorder.StatusCode)
	})

	t.Run("captures body", func(t *testing.T) {
		w := httptest.NewRecorder()
		recorder := NewResponseRecorder(w)

		n, err := recorder.Write([]byte("test response body"))
		require.NoError(t, err)
		assert.Equal(t, 18, n)
		assert.Equal(t, "test response body", recorder.Body.String())
	})

	t.Run("Write sets default status code if not written", func(t *testing.T) {
		w := httptest.NewRecorder()
		recorder := NewResponseRecorder(w)

		recorder.Write([]byte("data"))
		assert.Equal(t, http.StatusOK, recorder.StatusCode)
	})

	t.Run("WriteHeader is idempotent", func(t *testing.T) {
		w := httptest.NewRecorder()
		recorder := NewResponseRecorder(w)

		recorder.WriteHeader(http.StatusCreated)
		recorder.WriteHeader(http.StatusBadRequest) // Should be ignored

		assert.Equal(t, http.StatusCreated, recorder.StatusCode)
	})

	t.Run("Header returns underlying header", func(t *testing.T) {
		w := httptest.NewRecorder()
		recorder := NewResponseRecorder(w)

		recorder.Header().Set("X-Test", "value")
		assert.Equal(t, "value", w.Header().Get("X-Test"))
	})

	t.Run("captures headers on first write", func(t *testing.T) {
		w := httptest.NewRecorder()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom", "header-value")

		recorder := NewResponseRecorder(w)

		recorder.Write([]byte("data"))
		assert.NotEmpty(t, recorder.Headers)
	})
}

func TestIdempotencyMiddleware_SkipsNonMutationRequests(t *testing.T) {
	middleware := &IdempotencyMiddleware{
		repo: nil, // Not needed for GET requests
	}

	t.Run("skips GET requests", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		recorder := httptest.NewRecorder()

		middleware.Handle(handler).ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "success", recorder.Body.String())
	})

	t.Run("skips PUT requests", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodPut, "/test", nil)
		recorder := httptest.NewRecorder()

		middleware.Handle(handler).ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})

	t.Run("skips OPTIONS requests", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodOptions, "/test", nil)
		recorder := httptest.NewRecorder()

		middleware.Handle(handler).ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})

	t.Run("skips HEAD requests", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodHead, "/test", nil)
		recorder := httptest.NewRecorder()

		middleware.Handle(handler).ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}

func TestIdempotencyMiddleware_NoKeyProceedsNormally(t *testing.T) {
	middleware := &IdempotencyMiddleware{
		repo: nil,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	})

	t.Run("POST without idempotency key proceeds normally", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("request body"))
		recorder := httptest.NewRecorder()

		middleware.Handle(handler).ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusCreated, recorder.Code)
		assert.Equal(t, "request body", recorder.Body.String())
	})

	t.Run("PATCH without idempotency key proceeds normally", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/test", strings.NewReader("patch data"))
		recorder := httptest.NewRecorder()

		middleware.Handle(handler).ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusCreated, recorder.Code)
	})

	t.Run("DELETE without idempotency key proceeds normally", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/test", nil)
		recorder := httptest.NewRecorder()

		middleware.Handle(handler).ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusCreated, recorder.Code)
	})
}

func TestIdempotencyMiddleware_KeyValidation(t *testing.T) {
	middleware := &IdempotencyMiddleware{
		repo: nil,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("rejects key longer than 256 characters", func(t *testing.T) {
		longKey := strings.Repeat("a", 257)
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("body"))
		req.Header.Set("x-idempotency-key", longKey)
		recorder := httptest.NewRecorder()

		middleware.Handle(handler).ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "too long")
	})

	t.Run("accepts key at max length (256 characters)", func(t *testing.T) {
		maxKey := strings.Repeat("a", 256)
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("body"))
		req.Header.Set("x-idempotency-key", maxKey)
		req.Header.Set("x-app-id", "test-app-id")
		recorder := httptest.NewRecorder()

		// This will fail because repo is nil, but it shouldn't fail on key validation
		// The error will be a panic/nil pointer, indicating key validation passed
		defer func() {
			r := recover()
			// If we recovered from panic, it means the key validation passed
			// and it tried to access the nil repo
			assert.NotNil(t, r)
		}()

		middleware.Handle(handler).ServeHTTP(recorder, req)
	})

	t.Run("requires app ID header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("body"))
		req.Header.Set("x-idempotency-key", "test-key")
		// No x-app-id header
		recorder := httptest.NewRecorder()

		middleware.Handle(handler).ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "app")
	})
}

func TestNewIdempotencyMiddleware(t *testing.T) {
	t.Run("creates middleware with repo", func(t *testing.T) {
		middleware := NewIdempotencyMiddleware(nil)
		require.NotNil(t, middleware)
	})
}

type fakeIdempotencyRepo struct {
	mu      sync.Mutex
	records map[string]*storage.IdempotencyRecord
}

func newFakeIdempotencyRepo() *fakeIdempotencyRepo {
	return &fakeIdempotencyRepo{
		records: make(map[string]*storage.IdempotencyRecord),
	}
}

func (f *fakeIdempotencyRepo) key(appID, key, method, url string) string {
	return fmt.Sprintf("%s|%s|%s|%s", appID, key, method, url)
}

func (f *fakeIdempotencyRepo) Get(ctx context.Context, appID, key, method, url string) (*storage.IdempotencyRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	rec, ok := f.records[f.key(appID, key, method, url)]
	if !ok || time.Now().After(rec.ExpiresAt) {
		return nil, fmt.Errorf("not found")
	}

	clone := *rec
	clone.Body = append([]byte(nil), rec.Body...)
	clone.Headers = make(http.Header)
	for k, v := range rec.Headers {
		clone.Headers[k] = append([]string(nil), v...)
	}
	return &clone, nil
}

func (f *fakeIdempotencyRepo) Store(ctx context.Context, record *storage.IdempotencyRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	clone := *record
	clone.Body = append([]byte(nil), record.Body...)
	clone.Headers = make(http.Header)
	for k, v := range record.Headers {
		clone.Headers[k] = append([]string(nil), v...)
	}
	f.records[f.key(record.AppID, record.Key, record.Method, record.URL)] = &clone
	return nil
}

func TestIdempotencyMiddleware_ReplaysCachedResponse(t *testing.T) {
	repo := newFakeIdempotencyRepo()
	middleware := NewIdempotencyMiddleware(repo)

	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"count":` + fmt.Sprint(callCount) + `}`))
	})

	req1 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"a":1}`))
	req1.Header.Set("x-idempotency-key", "key-1")
	req1.Header.Set("x-app-id", "app-1")
	rec1 := httptest.NewRecorder()

	middleware.Handle(handler).ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusCreated, rec1.Code)
	require.Equal(t, 1, callCount)
	require.Empty(t, rec1.Header().Get("X-Idempotency-Replay"))

	req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"a":1}`))
	req2.Header.Set("x-idempotency-key", "key-1")
	req2.Header.Set("x-app-id", "app-1")
	rec2 := httptest.NewRecorder()

	middleware.Handle(handler).ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusCreated, rec2.Code)
	require.Equal(t, 1, callCount, "handler should not be called on replay")
	require.Equal(t, "true", rec2.Header().Get("X-Idempotency-Replay"))
	require.Equal(t, rec1.Body.String(), rec2.Body.String())
}

func TestIdempotencyMiddleware_ReplayUsesCurrentRequestID(t *testing.T) {
	repo := newFakeIdempotencyRepo()
	idempotency := NewIdempotencyMiddleware(repo)

	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"count":` + fmt.Sprint(callCount) + `}`))
	})

	chain := RequestID(idempotency.Handle(handler))

	req1 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"a":1}`))
	req1.Header.Set("x-idempotency-key", "key-reqid")
	req1.Header.Set("x-app-id", "app-1")
	req1.Header.Set("X-Request-ID", "req-1")
	rec1 := httptest.NewRecorder()

	chain.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusCreated, rec1.Code)
	require.Equal(t, 1, callCount)
	require.Equal(t, "req-1", rec1.Header().Get("X-Request-ID"))

	req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"a":1}`))
	req2.Header.Set("x-idempotency-key", "key-reqid")
	req2.Header.Set("x-app-id", "app-1")
	req2.Header.Set("X-Request-ID", "req-2")
	rec2 := httptest.NewRecorder()

	chain.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusCreated, rec2.Code)
	require.Equal(t, 1, callCount, "handler should not be called on replay")
	require.Equal(t, "true", rec2.Header().Get("X-Idempotency-Replay"))

	values := rec2.Header().Values("X-Request-ID")
	require.Equal(t, []string{"req-2"}, values)
}

func TestIdempotencyMiddleware_RejectsDifferentBodySameKey(t *testing.T) {
	repo := newFakeIdempotencyRepo()
	middleware := NewIdempotencyMiddleware(repo)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	req1 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"a":1}`))
	req1.Header.Set("x-idempotency-key", "key-2")
	req1.Header.Set("x-app-id", "app-1")
	rec1 := httptest.NewRecorder()
	middleware.Handle(handler).ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)

	req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"a":2}`))
	req2.Header.Set("x-idempotency-key", "key-2")
	req2.Header.Set("x-app-id", "app-1")
	rec2 := httptest.NewRecorder()
	middleware.Handle(handler).ServeHTTP(rec2, req2)

	require.Equal(t, http.StatusBadRequest, rec2.Code)
	require.Contains(t, rec2.Body.String(), apperrors.ErrCodeIdempotencyKeyReused)
}

func TestIdempotencyMiddleware_ScopesKeyByUser(t *testing.T) {
	repo := newFakeIdempotencyRepo()
	middleware := NewIdempotencyMiddleware(repo)

	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	req1 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"a":1}`))
	req1.Header.Set("x-idempotency-key", "key-3")
	req1.Header.Set("x-app-id", "app-1")
	req1 = req1.WithContext(context.WithValue(req1.Context(), UserSubKey, "user-a"))
	rec1 := httptest.NewRecorder()
	middleware.Handle(handler).ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)

	req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"a":2}`))
	req2.Header.Set("x-idempotency-key", "key-3")
	req2.Header.Set("x-app-id", "app-1")
	req2 = req2.WithContext(context.WithValue(req2.Context(), UserSubKey, "user-b"))
	rec2 := httptest.NewRecorder()
	middleware.Handle(handler).ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)

	require.Equal(t, 2, callCount, "different users should not conflict on idempotency key")
	require.Empty(t, rec2.Header().Get("X-Idempotency-Replay"))
}
