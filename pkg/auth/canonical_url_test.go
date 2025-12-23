package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildCanonicalPayload_URLModes(t *testing.T) {
	t.Run("relative_mode_uses_request_uri", func(t *testing.T) {
		t.Setenv("BETTER_WALLET_CANONICAL_URL_MODE", "relative")

		req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/wallets?cursor=abc", bytes.NewBufferString("{}"))
		req.Header.Set("x-app-id", "app-1")

		payload, _, err := BuildCanonicalPayload(req)
		require.NoError(t, err)
		require.Equal(t, "/v1/wallets?cursor=abc", payload.URL)
	})

	t.Run("absolute_mode_prefers_forwarded_headers", func(t *testing.T) {
		t.Setenv("BETTER_WALLET_CANONICAL_URL_MODE", "")

		req := httptest.NewRequest(http.MethodPost, "http://internal.local/v1/wallets?limit=10", bytes.NewBufferString("{}"))
		req.Header.Set("x-app-id", "app-1")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		payload, _, err := BuildCanonicalPayload(req)
		require.NoError(t, err)
		require.Equal(t, "https://api.example.com/v1/wallets?limit=10", payload.URL)
	})

	t.Run("absolute_mode_falls_back_to_relative_without_host", func(t *testing.T) {
		t.Setenv("BETTER_WALLET_CANONICAL_URL_MODE", "")

		req := httptest.NewRequest(http.MethodGet, "http://example.com/v1/wallets?x=1", nil)
		req.Host = ""

		payload, _, err := BuildCanonicalPayload(req)
		require.NoError(t, err)
		require.Equal(t, "/v1/wallets?x=1", payload.URL)
	})
}
