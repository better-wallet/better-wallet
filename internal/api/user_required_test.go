package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/stretchr/testify/require"
)

func TestRequireUserMiddleware(t *testing.T) {
	s := &Server{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := s.requireUserMiddleware(next)

	t.Run("requires user by default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/wallets", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("allows app-only wallet creation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/wallets", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("allows app-only policy creation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/policies", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("allows app-only wallet rpc", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/wallets/11111111-1111-1111-1111-111111111111/rpc", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("allows app-only wallet rpc (trailing slash)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/wallets/11111111-1111-1111-1111-111111111111/rpc/", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("requires user for other wallet operations", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/wallets/11111111-1111-1111-1111-111111111111/sign", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("passes through when user present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/wallets", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.UserSubKey, "user-123"))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})
}
