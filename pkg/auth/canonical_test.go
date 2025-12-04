package auth

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildCanonicalPayload(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		url            string
		body           string
		headers        map[string]string
		expectedURL    string
		expectedBody   string
		expectedMethod string
	}{
		{
			name:   "POST with JSON body",
			method: "POST",
			url:    "/v1/wallets",
			body:   `{"chain_type":"ethereum"}`,
			headers: map[string]string{
				"x-app-id": "test-app-id",
			},
			expectedURL:    "/v1/wallets",
			expectedBody:   `{"chain_type":"ethereum"}`,
			expectedMethod: "POST",
		},
		{
			name:   "POST with idempotency key",
			method: "POST",
			url:    "/v1/wallets/123/rpc",
			body:   `{"method":"eth_sendTransaction"}`,
			headers: map[string]string{
				"x-app-id":          "test-app-id",
				"x-idempotency-key": "test-key-123",
			},
			expectedURL:    "/v1/wallets/123/rpc",
			expectedBody:   `{"method":"eth_sendTransaction"}`,
			expectedMethod: "POST",
		},
		{
			name:           "GET with query parameters",
			method:         "GET",
			url:            "/v1/wallets?limit=10&cursor=abc",
			body:           "",
			headers:        map[string]string{"x-app-id": "test-app-id"},
			expectedURL:    "/v1/wallets?limit=10&cursor=abc",
			expectedBody:   "",
			expectedMethod: "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(tt.method, tt.url, bytes.NewBufferString(tt.body))
			req.Host = "example.com"

			// Add headers
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Build canonical payload
			payload, canonicalBytes, err := BuildCanonicalPayload(req)
			require.NoError(t, err)
			require.NotNil(t, payload)
			require.NotEmpty(t, canonicalBytes)

			// Verify fields
			assert.Equal(t, "v1", payload.Version)
			assert.Equal(t, tt.expectedMethod, payload.Method)
			assert.Equal(t, tt.expectedURL, payload.URL)
			assert.Equal(t, tt.expectedBody, payload.Body)

			// Verify headers are included
			if appID, ok := tt.headers["x-app-id"]; ok {
				assert.Equal(t, appID, payload.Headers["x-app-id"])
			}
			if key, ok := tt.headers["x-idempotency-key"]; ok {
				assert.Equal(t, key, payload.Headers["x-idempotency-key"])
			}

			// Verify canonical bytes are valid JSON
			reconstructed, err := CanonicalPayloadFromBytes(canonicalBytes)
			require.NoError(t, err)
			assert.Equal(t, payload.Version, reconstructed.Version)
			assert.Equal(t, payload.Method, reconstructed.Method)
			assert.Equal(t, payload.URL, reconstructed.URL)
		})
	}
}

func TestSerializeCanonical(t *testing.T) {
	tests := []struct {
		name     string
		payload  *CanonicalPayload
		contains []string // Substrings that should appear in the canonical form
	}{
		{
			name: "keys are sorted",
			payload: &CanonicalPayload{
				Version: "v1",
				Method:  "POST",
				URL:     "https://api.example.com/v1/wallets",
				Body:    `{"key":"value"}`,
				Headers: map[string]string{
					"x-app-id": "app-123",
				},
			},
			contains: []string{
				`"body"`,
				`"headers"`,
				`"method"`,
				`"url"`,
				`"version"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, err := SerializeCanonical(tt.payload)
			require.NoError(t, err)

			canonicalStr := string(canonical)

			// Verify all expected substrings appear
			for _, substr := range tt.contains {
				assert.Contains(t, canonicalStr, substr)
			}

			// Verify it's valid JSON
			reconstructed, err := CanonicalPayloadFromBytes(canonical)
			require.NoError(t, err)
			assert.Equal(t, tt.payload.Version, reconstructed.Version)
		})
	}
}

func TestExtractSignatures(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		headerKey string
		expected  []string
	}{
		{
			name:      "single signature",
			header:    "c2lnbmF0dXJlMQ==",
			headerKey: "x-authorization-signature",
			expected:  []string{"c2lnbmF0dXJlMQ=="},
		},
		{
			name:      "multiple signatures",
			header:    "c2lnMQ==,c2lnMg==,c2lnMw==",
			headerKey: "x-authorization-signature",
			expected:  []string{"c2lnMQ==", "c2lnMg==", "c2lnMw=="},
		},
		{
			name:      "signatures with spaces",
			header:    "c2lnMQ==, c2lnMg==, c2lnMw==",
			headerKey: "x-authorization-signature",
			expected:  []string{"c2lnMQ==", "c2lnMg==", "c2lnMw=="},
		},
		{
			name:      "no header",
			header:    "",
			headerKey: "",
			expected:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			if tt.header != "" && tt.headerKey != "" {
				req.Header.Set(tt.headerKey, tt.header)
			}

			signatures := ExtractSignatures(req)
			assert.Equal(t, tt.expected, signatures)
		})
	}
}

func TestHashPayload(t *testing.T) {
	payload1 := []byte(`{"version":"v1","method":"POST"}`)
	payload2 := []byte(`{"version":"v1","method":"POST"}`)
	payload3 := []byte(`{"version":"v1","method":"GET"}`)

	hash1 := HashPayload(payload1)
	hash2 := HashPayload(payload2)
	hash3 := HashPayload(payload3)

	// Same content = same hash
	assert.Equal(t, hash1, hash2)

	// Different content = different hash
	assert.NotEqual(t, hash1, hash3)

	// Hash is hex-encoded SHA-256 (64 characters)
	assert.Len(t, hash1, 64)
}

func TestCanonicalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name: "object with sorted keys",
			input: map[string]interface{}{
				"z": "last",
				"a": "first",
				"m": "middle",
			},
			expected: `{"a":"first","m":"middle","z":"last"}`,
		},
		{
			name: "nested object",
			input: map[string]interface{}{
				"outer": map[string]interface{}{
					"z": "inner-last",
					"a": "inner-first",
				},
			},
			expected: `{"outer":{"a":"inner-first","z":"inner-last"}}`,
		},
		{
			name:     "array",
			input:    []interface{}{"first", "second", "third"},
			expected: `["first","second","third"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := canonicalJSON(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}
