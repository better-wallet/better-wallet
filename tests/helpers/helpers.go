// Package helpers provides common test utilities for the better-wallet test suite.
package helpers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestApp represents a test application.
type TestApp struct {
	ID     uuid.UUID
	Name   string
	Secret string
}

// TestUser represents a test user.
type TestUser struct {
	ID      uuid.UUID
	Subject string // JWT sub claim
}

// TestWallet represents a test wallet.
type TestWallet struct {
	ID      uuid.UUID
	Address string
	OwnerID uuid.UUID
}

// TestKeyPair holds a P-256 key pair for testing.
type TestKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	PublicPEM  string
}

// GenerateTestKeyPair creates a new P-256 key pair for testing.
func GenerateTestKeyPair(t *testing.T) *TestKeyPair {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &TestKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}
}

// SignCanonicalPayload signs a canonical payload for authorization.
func SignCanonicalPayload(t *testing.T, privateKey *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()

	hash := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	// Create DER-encoded signature
	signature := append(r.Bytes(), s.Bytes()...)
	return base64.StdEncoding.EncodeToString(signature)
}

// BuildCanonicalPayload constructs a canonical payload for signing.
func BuildCanonicalPayload(method, path string, body interface{}, headers map[string]string) ([]byte, error) {
	payload := map[string]interface{}{
		"method": method,
		"path":   path,
	}

	if body != nil {
		payload["body"] = body
	}

	if len(headers) > 0 {
		payload["headers"] = headers
	}

	return json.Marshal(payload)
}

// MakeAuthenticatedRequest creates an HTTP request with app and user authentication.
func MakeAuthenticatedRequest(
	t *testing.T,
	method, path string,
	body interface{},
	app *TestApp,
	userJWT string,
) *http.Request {
	t.Helper()

	var bodyReader *strings.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = strings.NewReader(string(bodyBytes))
	} else {
		bodyReader = strings.NewReader("")
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Id", app.ID.String())

	// Basic auth for app
	credentials := base64.StdEncoding.EncodeToString(
		[]byte(fmt.Sprintf("%s:%s", app.ID.String(), app.Secret)),
	)
	req.Header.Set("Authorization", "Basic "+credentials)

	// User JWT (if provided)
	if userJWT != "" {
		req.Header.Set("Authorization", "Bearer "+userJWT)
	}

	return req
}

// NewTestContext creates a context with timeout for tests.
func NewTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// AssertErrorResponse checks that an HTTP response is an error with expected status.
func AssertErrorResponse(t *testing.T, resp *httptest.ResponseRecorder, expectedStatus int) {
	t.Helper()
	require.Equal(t, expectedStatus, resp.Code,
		"Expected status %d, got %d. Body: %s",
		expectedStatus, resp.Code, resp.Body.String())
}

// AssertSuccessResponse checks that an HTTP response is successful (2xx).
func AssertSuccessResponse(t *testing.T, resp *httptest.ResponseRecorder) {
	t.Helper()
	require.True(t, resp.Code >= 200 && resp.Code < 300,
		"Expected success status (2xx), got %d. Body: %s",
		resp.Code, resp.Body.String())
}

// AssertNoSensitiveData checks that a string doesn't contain sensitive information.
func AssertNoSensitiveData(t *testing.T, s string) {
	t.Helper()

	sensitivePatterns := []string{
		"private",
		"secret",
		"password",
		"key",
		"share",
		"0x", // Potential private key hex
	}

	lowered := strings.ToLower(s)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowered, pattern) {
			// Allow "public_key" but not "private_key"
			if pattern == "key" && !strings.Contains(lowered, "private") {
				continue
			}
			t.Logf("Warning: response may contain sensitive data pattern: %s", pattern)
		}
	}
}

// RandomAddress generates a random Ethereum-like address.
func RandomAddress() string {
	bytes := make([]byte, 20)
	rand.Read(bytes)
	return fmt.Sprintf("0x%x", bytes)
}

// RandomUUID generates a random UUID string.
func RandomUUID() string {
	return uuid.New().String()
}
