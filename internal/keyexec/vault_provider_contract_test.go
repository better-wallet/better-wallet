package keyexec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type vaultTransitRequest struct {
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

type vaultSecretResponse struct {
	RequestID     string                 `json:"request_id"`
	LeaseID       string                 `json:"lease_id"`
	LeaseDuration int                    `json:"lease_duration"`
	Renewable     bool                   `json:"renewable"`
	Data          map[string]interface{} `json:"data"`
}

func newVaultTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/transit/encrypt/"):
			var req vaultTransitRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			resp := vaultSecretResponse{
				RequestID:     "req-encrypt",
				LeaseDuration: 0,
				Renewable:     false,
				Data: map[string]interface{}{
					"ciphertext": "vault:v1:" + req.Plaintext,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case strings.HasPrefix(r.URL.Path, "/v1/transit/decrypt/"):
			var req vaultTransitRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			cipher := strings.TrimPrefix(req.Ciphertext, "vault:v1:")
			resp := vaultSecretResponse{
				RequestID:     "req-decrypt",
				LeaseDuration: 0,
				Renewable:     false,
				Data: map[string]interface{}{
					"plaintext": cipher,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestVaultProvider_EncryptDecrypt_RoundTrip(t *testing.T) {
	server := newVaultTestServer(t)
	defer server.Close()

	provider, err := NewVaultProvider(server.URL, "token", "test-key")
	require.NoError(t, err)

	ctx := context.Background()
	plaintext := []byte("vault-secret")

	ciphertext, err := provider.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	decrypted, err := provider.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestVaultProvider_Encrypt_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":["boom"]}`))
	}))
	defer server.Close()

	provider, err := NewVaultProvider(server.URL, "token", "test-key")
	require.NoError(t, err)

	_, err = provider.Encrypt(context.Background(), []byte("data"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault transit encrypt failed")
}

func TestVaultProvider_Decrypt_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":["boom"]}`))
	}))
	defer server.Close()

	provider, err := NewVaultProvider(server.URL, "token", "test-key")
	require.NoError(t, err)

	_, err = provider.Decrypt(context.Background(), []byte("vault:v1:abcd"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault transit decrypt failed")
}
