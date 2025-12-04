package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthMiddleware(t *testing.T) {
	middleware := NewAuthMiddleware()
	require.NotNil(t, middleware)
	require.NotNil(t, middleware.jwksCache)
	require.NotNil(t, middleware.httpClient)
}

func TestValidateAudience(t *testing.T) {
	middleware := NewAuthMiddleware()

	tests := []struct {
		name             string
		claims           jwt.MapClaims
		expectedAudience string
		valid            bool
	}{
		{
			name:             "string audience matches",
			claims:           jwt.MapClaims{"aud": "my-app"},
			expectedAudience: "my-app",
			valid:            true,
		},
		{
			name:             "string audience does not match",
			claims:           jwt.MapClaims{"aud": "other-app"},
			expectedAudience: "my-app",
			valid:            false,
		},
		{
			name:             "array audience contains expected",
			claims:           jwt.MapClaims{"aud": []interface{}{"app1", "my-app", "app3"}},
			expectedAudience: "my-app",
			valid:            true,
		},
		{
			name:             "array audience does not contain expected",
			claims:           jwt.MapClaims{"aud": []interface{}{"app1", "app2", "app3"}},
			expectedAudience: "my-app",
			valid:            false,
		},
		{
			name:             "missing audience",
			claims:           jwt.MapClaims{},
			expectedAudience: "my-app",
			valid:            false,
		},
		{
			name:             "wrong audience type",
			claims:           jwt.MapClaims{"aud": 12345},
			expectedAudience: "my-app",
			valid:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := middleware.validateAudience(tt.claims, tt.expectedAudience)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestParseRSAKey(t *testing.T) {
	middleware := NewAuthMiddleware()

	t.Run("valid RSA key", func(t *testing.T) {
		// Generate a test RSA key
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Create JWK representation
		jwk := map[string]interface{}{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
		}

		parsedKey, err := middleware.parseRSAKey(jwk)
		require.NoError(t, err)
		require.NotNil(t, parsedKey)
		assert.Equal(t, rsaKey.N, parsedKey.N)
		assert.Equal(t, rsaKey.E, parsedKey.E)
	})

	t.Run("missing n parameter", func(t *testing.T) {
		jwk := map[string]interface{}{
			"kty": "RSA",
			"e":   "AQAB",
		}

		_, err := middleware.parseRSAKey(jwk)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'n' parameter")
	})

	t.Run("missing e parameter", func(t *testing.T) {
		jwk := map[string]interface{}{
			"kty": "RSA",
			"n":   "someModulus",
		}

		_, err := middleware.parseRSAKey(jwk)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'e' parameter")
	})

	t.Run("invalid base64 for n", func(t *testing.T) {
		jwk := map[string]interface{}{
			"kty": "RSA",
			"n":   "!!!invalid-base64!!!",
			"e":   "AQAB",
		}

		_, err := middleware.parseRSAKey(jwk)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode n")
	})

	t.Run("invalid base64 for e", func(t *testing.T) {
		jwk := map[string]interface{}{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString([]byte("modulus")),
			"e":   "!!!invalid-base64!!!",
		}

		_, err := middleware.parseRSAKey(jwk)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode e")
	})
}

func TestParseECKey(t *testing.T) {
	middleware := NewAuthMiddleware()

	t.Run("valid P-256 key", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		jwk := map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes()),
		}

		parsedKey, err := middleware.parseECKey(jwk)
		require.NoError(t, err)
		require.NotNil(t, parsedKey)
		assert.Equal(t, privateKey.X, parsedKey.X)
		assert.Equal(t, privateKey.Y, parsedKey.Y)
	})

	t.Run("valid P-384 key", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		jwk := map[string]interface{}{
			"kty": "EC",
			"crv": "P-384",
			"x":   base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes()),
		}

		parsedKey, err := middleware.parseECKey(jwk)
		require.NoError(t, err)
		require.NotNil(t, parsedKey)
	})

	t.Run("valid P-521 key", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		jwk := map[string]interface{}{
			"kty": "EC",
			"crv": "P-521",
			"x":   base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes()),
		}

		parsedKey, err := middleware.parseECKey(jwk)
		require.NoError(t, err)
		require.NotNil(t, parsedKey)
	})

	t.Run("missing crv parameter", func(t *testing.T) {
		jwk := map[string]interface{}{
			"kty": "EC",
			"x":   "someX",
			"y":   "someY",
		}

		_, err := middleware.parseECKey(jwk)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'crv' parameter")
	})

	t.Run("missing x parameter", func(t *testing.T) {
		jwk := map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"y":   "someY",
		}

		_, err := middleware.parseECKey(jwk)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'x' parameter")
	})

	t.Run("missing y parameter", func(t *testing.T) {
		jwk := map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   "someX",
		}

		_, err := middleware.parseECKey(jwk)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'y' parameter")
	})

	t.Run("unsupported curve", func(t *testing.T) {
		jwk := map[string]interface{}{
			"kty": "EC",
			"crv": "secp256k1",
			"x":   base64.RawURLEncoding.EncodeToString([]byte("x")),
			"y":   base64.RawURLEncoding.EncodeToString([]byte("y")),
		}

		_, err := middleware.parseECKey(jwk)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported curve")
	})

	t.Run("invalid base64 for x", func(t *testing.T) {
		jwk := map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   "!!!invalid!!!",
			"y":   base64.RawURLEncoding.EncodeToString([]byte("y")),
		}

		_, err := middleware.parseECKey(jwk)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode x")
	})

	t.Run("invalid base64 for y", func(t *testing.T) {
		jwk := map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString([]byte("x")),
			"y":   "!!!invalid!!!",
		}

		_, err := middleware.parseECKey(jwk)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode y")
	})
}

func TestGetUserSub(t *testing.T) {
	t.Run("returns subject when present", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserSubKey, "user-123")
		sub, ok := GetUserSub(ctx)
		assert.True(t, ok)
		assert.Equal(t, "user-123", sub)
	})

	t.Run("returns false when not present", func(t *testing.T) {
		ctx := context.Background()
		sub, ok := GetUserSub(ctx)
		assert.False(t, ok)
		assert.Empty(t, sub)
	})

	t.Run("returns false when wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserSubKey, 12345)
		sub, ok := GetUserSub(ctx)
		assert.False(t, ok)
		assert.Empty(t, sub)
	})
}

func TestAuthMiddleware_Authenticate(t *testing.T) {
	middleware := NewAuthMiddleware()

	t.Run("missing app context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("should not reach next handler")
		})

		handler := middleware.Authenticate(nextHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("app without auth settings", func(t *testing.T) {
		app := &types.App{
			Settings: types.AppSettings{
				Auth: nil,
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), AppKey, app)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("should not reach next handler")
		})

		handler := middleware.Authenticate(nextHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("missing authorization header", func(t *testing.T) {
		app := &types.App{
			Settings: types.AppSettings{
				Auth: &types.AppAuthSettings{
					Kind:     "oidc",
					Issuer:   "https://example.com",
					Audience: "my-app",
					JWKSURI:  "https://example.com/.well-known/jwks.json",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), AppKey, app)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("should not reach next handler")
		})

		handler := middleware.Authenticate(nextHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("invalid authorization header format", func(t *testing.T) {
		app := &types.App{
			Settings: types.AppSettings{
				Auth: &types.AppAuthSettings{
					Kind:     "oidc",
					Issuer:   "https://example.com",
					Audience: "my-app",
					JWKSURI:  "https://example.com/.well-known/jwks.json",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Basic sometoken")
		ctx := context.WithValue(req.Context(), AppKey, app)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("should not reach next handler")
		})

		handler := middleware.Authenticate(nextHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("malformed token", func(t *testing.T) {
		app := &types.App{
			Settings: types.AppSettings{
				Auth: &types.AppAuthSettings{
					Kind:     "oidc",
					Issuer:   "https://example.com",
					Audience: "my-app",
					JWKSURI:  "https://example.com/.well-known/jwks.json",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer not.a.validtoken")
		ctx := context.WithValue(req.Context(), AppKey, app)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("should not reach next handler")
		})

		handler := middleware.Authenticate(nextHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestValidateJWT(t *testing.T) {
	middleware := NewAuthMiddleware()

	t.Run("nil auth settings returns error", func(t *testing.T) {
		sub, err := middleware.ValidateJWT("sometoken", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auth settings not configured")
		assert.Empty(t, sub)
	})

	t.Run("invalid token format returns error", func(t *testing.T) {
		authSettings := &types.AppAuthSettings{
			Kind:     "oidc",
			Issuer:   "https://example.com",
			Audience: "my-app",
			JWKSURI:  "https://example.com/.well-known/jwks.json",
		}

		sub, err := middleware.ValidateJWT("not-a-valid-token", authSettings)
		require.Error(t, err)
		assert.Empty(t, sub)
	})
}

func TestJWKSCache(t *testing.T) {
	t.Run("cache initialization", func(t *testing.T) {
		cache := &JWKSCache{
			Keys:      make(map[string]map[string]interface{}),
			ExpiresAt: make(map[string]time.Time),
		}

		require.NotNil(t, cache.Keys)
		require.NotNil(t, cache.ExpiresAt)
	})

	t.Run("cache stores and retrieves keys", func(t *testing.T) {
		cache := &JWKSCache{
			Keys:      make(map[string]map[string]interface{}),
			ExpiresAt: make(map[string]time.Time),
		}

		issuer := "https://example.com"
		kid := "test-key-1"
		testKey := "test-public-key"

		// Store key
		cache.Keys[issuer] = map[string]interface{}{
			kid: testKey,
		}
		cache.ExpiresAt[issuer] = time.Now().Add(1 * time.Hour)

		// Retrieve key
		keys, ok := cache.Keys[issuer]
		require.True(t, ok)

		key, found := keys[kid]
		require.True(t, found)
		assert.Equal(t, testKey, key)
	})
}

func TestAuthMiddleware_WriteError(t *testing.T) {
	middleware := NewAuthMiddleware()

	rr := httptest.NewRecorder()
	appErr := apperrors.New("test_error", "Test error message", http.StatusBadRequest)

	middleware.writeError(rr, appErr)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response map[string]interface{}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&response))
	assert.Equal(t, "test_error", response["code"])
	assert.Equal(t, "Test error message", response["message"])
}
