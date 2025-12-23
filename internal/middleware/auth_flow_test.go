package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/better-wallet/better-wallet/tests/mocks"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware_ValidJWT_StripsAuthorizationHeader(t *testing.T) {
	jwksServer := mocks.NewMockJWKSServer("https://issuer.example.com", "test-audience")
	defer jwksServer.Close()

	_, err := jwksServer.AddRSAKey("test-key-1")
	require.NoError(t, err)

	token, err := jwksServer.CreateValidJWT("user-123", nil)
	require.NoError(t, err)

	app := &types.App{
		Settings: types.AppSettings{
			Auth: &types.AppAuthSettings{
				Kind:     types.AuthKindOIDC,
				Issuer:   jwksServer.Issuer(),
				Audience: jwksServer.Audience(),
				JWKSURI:  jwksServer.JWKSURI(),
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), AppKey, app))
	rec := httptest.NewRecorder()

	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sub, ok := GetUserSub(r.Context())
		require.True(t, ok)
		require.Equal(t, "user-123", sub)
		require.Empty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	})

	NewAuthMiddleware().Authenticate(handler).ServeHTTP(rec, req)

	require.True(t, called)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestAuthMiddleware_ExpiredJWTIsRejected(t *testing.T) {
	jwksServer := mocks.NewMockJWKSServer("https://issuer.example.com", "test-audience")
	defer jwksServer.Close()

	_, err := jwksServer.AddRSAKey("test-key-1")
	require.NoError(t, err)

	token, err := jwksServer.CreateExpiredJWT("user-123")
	require.NoError(t, err)

	app := &types.App{
		Settings: types.AppSettings{
			Auth: &types.AppAuthSettings{
				Kind:     types.AuthKindOIDC,
				Issuer:   jwksServer.Issuer(),
				Audience: jwksServer.Audience(),
				JWKSURI:  jwksServer.JWKSURI(),
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), AppKey, app))
	rec := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected handler call for expired token")
	})

	NewAuthMiddleware().Authenticate(handler).ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthMiddleware_JWKSUnavailableRejectsToken(t *testing.T) {
	jwksServer := mocks.NewMockJWKSServer("https://issuer.example.com", "test-audience")
	defer jwksServer.Close()

	_, err := jwksServer.AddRSAKey("test-key-1")
	require.NoError(t, err)

	token, err := jwksServer.CreateValidJWT("user-123", nil)
	require.NoError(t, err)

	jwksServer.SetStatusCode(http.StatusInternalServerError)

	app := &types.App{
		Settings: types.AppSettings{
			Auth: &types.AppAuthSettings{
				Kind:     types.AuthKindOIDC,
				Issuer:   jwksServer.Issuer(),
				Audience: jwksServer.Audience(),
				JWKSURI:  jwksServer.JWKSURI(),
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), AppKey, app))
	rec := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected handler call when JWKS is unavailable")
	})

	NewAuthMiddleware().Authenticate(handler).ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}
