package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/config"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
)

// Context keys
type contextKey string

const AppIDKey contextKey = "app_id"

// AppAuthMiddleware handles app-level authentication
type AppAuthMiddleware struct {
	config *config.Config
}

// NewAppAuthMiddleware creates a new app-level authentication middleware
func NewAppAuthMiddleware(cfg *config.Config) *AppAuthMiddleware {
	return &AppAuthMiddleware{
		config: cfg,
	}
}

// Authenticate validates app-level credentials
// Requires: Authorization: Basic <base64(app_id:app_secret)> AND X-App-Id: <app_id>
func (m *AppAuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check X-App-Id header
		appIDHeader := r.Header.Get("X-App-Id")
		if appIDHeader == "" {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Missing X-App-Id header",
				"",
				http.StatusUnauthorized,
			))
			return
		}

		if appIDHeader != m.config.AppID {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid app ID",
				"",
				http.StatusUnauthorized,
			))
			return
		}

		// Check Authorization header (Basic Auth)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Missing Authorization header",
				"",
				http.StatusUnauthorized,
			))
			return
		}

		// Parse Basic Auth
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Basic" {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid Authorization header format",
				"Expected 'Basic <credentials>'",
				http.StatusUnauthorized,
			))
			return
		}

		// Decode base64 credentials
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid base64 encoding",
				"",
				http.StatusUnauthorized,
			))
			return
		}

		// Split into app_id:app_secret
		credentials := strings.SplitN(string(decoded), ":", 2)
		if len(credentials) != 2 {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid credentials format",
				"Expected 'app_id:app_secret'",
				http.StatusUnauthorized,
			))
			return
		}

		appID := credentials[0]
		appSecret := credentials[1]

		// Validate credentials
		if appID != m.config.AppID || appSecret != m.config.AppSecret {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid app credentials",
				"",
				http.StatusUnauthorized,
			))
			return
		}

		// Credentials valid, store app ID in context and proceed
		ctx := context.WithValue(r.Context(), AppIDKey, appID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetAppID retrieves the app ID from context
func GetAppID(ctx context.Context) string {
	if appID, ok := ctx.Value(AppIDKey).(string); ok {
		return appID
	}
	return ""
}

// writeError writes an error response
func (m *AppAuthMiddleware) writeError(w http.ResponseWriter, err *apperrors.AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	json.NewEncoder(w).Encode(err)
}
