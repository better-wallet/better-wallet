package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// AuditContextKey is the context key for audit information
type AuditContextKey string

const (
	// ClientIPKey is the context key for client IP
	ClientIPKey AuditContextKey = "client_ip"
	// UserAgentKey is the context key for user agent
	UserAgentKey AuditContextKey = "user_agent"
)

// AuditContext middleware captures client IP and User-Agent for audit logging
func AuditContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Extract client IP (handle X-Forwarded-For for proxied requests)
		clientIP := getClientIP(r)
		if clientIP != "" {
			ctx = context.WithValue(ctx, ClientIPKey, clientIP)
		}

		// Extract User-Agent
		userAgent := r.Header.Get("User-Agent")
		if userAgent != "" {
			ctx = context.WithValue(ctx, UserAgentKey, userAgent)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getClientIP extracts the client IP from the request
// Handles X-Forwarded-For, X-Real-IP headers for proxied requests
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (most common with load balancers/proxies)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
		// We want the first (original client)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, try using RemoteAddr directly
		if net.ParseIP(r.RemoteAddr) != nil {
			return r.RemoteAddr
		}
		return ""
	}

	return ip
}

// GetClientIP retrieves the client IP from context
func GetClientIP(ctx context.Context) *string {
	if ip, ok := ctx.Value(ClientIPKey).(string); ok {
		return &ip
	}
	return nil
}

// GetUserAgent retrieves the user agent from context
func GetUserAgent(ctx context.Context) *string {
	if ua, ok := ctx.Value(UserAgentKey).(string); ok {
		return &ua
	}
	return nil
}
