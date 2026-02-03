package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditContext(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expectedIP *string
		expectedUA *string
	}{
		{
			name: "extracts X-Forwarded-For header",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.100",
				"User-Agent":      "TestClient/1.0",
			},
			remoteAddr: "127.0.0.1:8080",
			expectedIP: strPtr("192.168.1.100"),
			expectedUA: strPtr("TestClient/1.0"),
		},
		{
			name: "extracts first IP from X-Forwarded-For with multiple IPs",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.100, 10.0.0.1, 172.16.0.1",
			},
			remoteAddr: "127.0.0.1:8080",
			expectedIP: strPtr("192.168.1.100"),
		},
		{
			name: "extracts X-Real-IP when X-Forwarded-For is missing",
			headers: map[string]string{
				"X-Real-IP": "192.168.1.200",
			},
			remoteAddr: "127.0.0.1:8080",
			expectedIP: strPtr("192.168.1.200"),
		},
		{
			name:       "falls back to RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.50:12345",
			expectedIP: strPtr("192.168.1.50"),
		},
		{
			name:       "handles RemoteAddr without port",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.50",
			expectedIP: strPtr("192.168.1.50"),
		},
		{
			name: "no User-Agent header",
			headers: map[string]string{
				"X-Real-IP": "192.168.1.100",
			},
			remoteAddr: "127.0.0.1:8080",
			expectedIP: strPtr("192.168.1.100"),
			expectedUA: nil,
		},
		{
			name: "invalid X-Forwarded-For falls back to X-Real-IP",
			headers: map[string]string{
				"X-Forwarded-For": "not-an-ip",
				"X-Real-IP":       "192.168.1.100",
			},
			remoteAddr: "127.0.0.1:8080",
			expectedIP: strPtr("192.168.1.100"),
		},
		{
			name: "invalid X-Forwarded-For and X-Real-IP falls back to RemoteAddr",
			headers: map[string]string{
				"X-Forwarded-For": "not-an-ip",
				"X-Real-IP":       "also-not-an-ip",
			},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: strPtr("10.0.0.1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a handler that captures context values
			var capturedCtx context.Context
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedCtx = r.Context()
				w.WriteHeader(http.StatusOK)
			})

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Apply middleware
			handler := AuditContext(nextHandler)
			handler.ServeHTTP(rr, req)

			// Verify response
			assert.Equal(t, http.StatusOK, rr.Code)

			// Verify context values
			if tt.expectedIP != nil {
				clientIP := GetClientIP(capturedCtx)
				require.NotNil(t, clientIP)
				assert.Equal(t, *tt.expectedIP, *clientIP)
			}

			if tt.expectedUA != nil {
				userAgent := GetUserAgent(capturedCtx)
				require.NotNil(t, userAgent)
				assert.Equal(t, *tt.expectedUA, *userAgent)
			} else {
				userAgent := GetUserAgent(capturedCtx)
				if _, hasUA := tt.headers["User-Agent"]; !hasUA {
					assert.Nil(t, userAgent)
				}
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	t.Run("returns IP when set in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ClientIPKey, "192.168.1.100")
		ip := GetClientIP(ctx)
		require.NotNil(t, ip)
		assert.Equal(t, "192.168.1.100", *ip)
	})

	t.Run("returns nil when not set in context", func(t *testing.T) {
		ctx := context.Background()
		ip := GetClientIP(ctx)
		assert.Nil(t, ip)
	})

	t.Run("returns nil when wrong type in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ClientIPKey, 12345)
		ip := GetClientIP(ctx)
		assert.Nil(t, ip)
	})
}

func TestGetUserAgent(t *testing.T) {
	t.Run("returns User-Agent when set in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserAgentKey, "Mozilla/5.0")
		ua := GetUserAgent(ctx)
		require.NotNil(t, ua)
		assert.Equal(t, "Mozilla/5.0", *ua)
	})

	t.Run("returns nil when not set in context", func(t *testing.T) {
		ctx := context.Background()
		ua := GetUserAgent(ctx)
		assert.Nil(t, ua)
	})

	t.Run("returns nil when wrong type in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserAgentKey, 12345)
		ua := GetUserAgent(ctx)
		assert.Nil(t, ua)
	})
}

func TestGetClientIP_Function(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		xri        string
		remoteAddr string
		expected   string
	}{
		{
			name:       "X-Forwarded-For single IP",
			xff:        "192.168.1.100",
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For multiple IPs",
			xff:        "192.168.1.100, 10.0.0.1, 172.16.0.1",
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.100",
		},
		{
			name:       "X-Real-IP",
			xri:        "192.168.1.200",
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.200",
		},
		{
			name:       "RemoteAddr with port",
			remoteAddr: "192.168.1.50:12345",
			expected:   "192.168.1.50",
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "192.168.1.50",
			expected:   "192.168.1.50",
		},
		{
			name:       "invalid X-Forwarded-For with spaces",
			xff:        " 192.168.1.100 ",
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.100",
		},
		{
			name:       "IPv6 in X-Forwarded-For",
			xff:        "2001:db8::1",
			remoteAddr: "127.0.0.1:8080",
			expected:   "2001:db8::1",
		},
		{
			name:       "IPv6 in RemoteAddr",
			remoteAddr: "[::1]:8080",
			expected:   "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			ip := getClientIP(req)
			assert.Equal(t, tt.expected, ip)
		})
	}
}

// Helper function to create string pointer
func strPtr(s string) *string {
	return &s
}
