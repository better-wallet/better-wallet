package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/storage"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Note: AppID is stored in context using both middleware keys (for backward compatibility)
// and storage.AppIDContextKey (for automatic repo scoping)

// Context keys
type contextKey string

const AppIDKey contextKey = "app_id"
const AppKey contextKey = "app"

// AppAuthMiddleware handles app-level authentication
type AppAuthMiddleware struct {
	appRepo    appRepo
	secretRepo appSecretRepo
}

type appRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*types.App, error)
}

type appSecretRepo interface {
	GetBySecretPrefix(ctx context.Context, prefix string) ([]*types.AppSecret, error)
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error
}

// NewAppAuthMiddleware creates a new app-level authentication middleware
func NewAppAuthMiddleware(store *storage.Store) *AppAuthMiddleware {
	return &AppAuthMiddleware{
		appRepo:    storage.NewAppRepository(store),
		secretRepo: storage.NewAppSecretRepository(store),
	}
}

// Authenticate validates app-level credentials from database
// Requires:
// - X-App-Id: <app_id>
// - X-App-Secret: <app_secret>
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

		// Parse app ID as UUID
		appUUID, err := uuid.Parse(appIDHeader)
		if err != nil {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid app ID format",
				"App ID must be a valid UUID",
				http.StatusUnauthorized,
			))
			return
		}

		// App auth is header-based to avoid collisions with user auth (Authorization: Bearer).
		// We intentionally do not accept Authorization: Basic.
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Basic ") {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Authorization: Basic is not supported",
				"Use X-App-Secret",
				http.StatusUnauthorized,
			))
			return
		}

		appSecret := r.Header.Get("X-App-Secret")
		if appSecret == "" {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Missing app credentials",
				"Provide X-App-Secret",
				http.StatusUnauthorized,
			))
			return
		}

		// Get app from database
		app, err := m.appRepo.GetByID(r.Context(), appUUID)
		if err != nil || app == nil {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid app credentials",
				"",
				http.StatusUnauthorized,
			))
			return
		}

		// Check app status
		if app.Status != types.AppStatusActive {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeForbidden,
				"App is not active",
				"",
				http.StatusForbidden,
			))
			return
		}

		// Validate secret
		if !m.validateSecret(r.Context(), appUUID, appSecret) {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid app credentials",
				"",
				http.StatusUnauthorized,
			))
			return
		}

		// Reduce risk of accidental leakage in downstream logs/telemetry.
		r.Header.Del("X-App-Secret")

		// Credentials valid, store app info in context and proceed
		// Set both middleware context keys (for backward compatibility) and storage context key (for automatic repo scoping)
		ctx := context.WithValue(r.Context(), AppIDKey, appIDHeader)
		ctx = context.WithValue(ctx, AppKey, app)
		ctx = storage.WithAppID(ctx, appUUID) // Enable automatic app-scoped repository operations
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateSecret validates the app secret against stored hashes
func (m *AppAuthMiddleware) validateSecret(ctx context.Context, appID uuid.UUID, secret string) bool {
	// Get secret prefix for lookup (first 14 chars: "bw_sk_" + 8)
	if len(secret) < 14 {
		return false
	}
	prefix := secret[:14]

	// Find secrets with matching prefix
	secrets, err := m.secretRepo.GetBySecretPrefix(ctx, prefix)
	if err != nil {
		return false
	}

	// Try to match secret hash
	for _, appSecret := range secrets {
		if appSecret.AppID != appID {
			continue
		}

		// Verify secret hash using bcrypt
		if err := bcrypt.CompareHashAndPassword([]byte(appSecret.SecretHash), []byte(secret)); err == nil {
			// Update last used timestamp (fire and forget)
			go m.secretRepo.UpdateLastUsed(context.Background(), appSecret.ID)
			return true
		}
	}

	return false
}

// GetAppID retrieves the app ID from context
func GetAppID(ctx context.Context) string {
	if appID, ok := ctx.Value(AppIDKey).(string); ok {
		return appID
	}
	return ""
}

// GetApp retrieves the app from context
func GetApp(ctx context.Context) *types.App {
	if app, ok := ctx.Value(AppKey).(*types.App); ok {
		return app
	}
	return nil
}

// writeError writes an error response
func (m *AppAuthMiddleware) writeError(w http.ResponseWriter, err *apperrors.AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	json.NewEncoder(w).Encode(err)
}
