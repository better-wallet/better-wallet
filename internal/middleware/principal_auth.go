package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type principalContextKey struct{}

// dummyHash is used for timing-attack prevention when key not found
var dummyHash = []byte("$2a$10$dummyhashtopreventtimingattacks")

// PrincipalStore defines the interface for principal data access
type PrincipalStore interface {
	GetAPIKeyByPrefix(ctx context.Context, prefix string) (*types.PrincipalAPIKey, string, error)
	GetPrincipalByID(ctx context.Context, id uuid.UUID) (*types.Principal, error)
	UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error
}

// PrincipalAuthMiddleware handles principal authentication via API key
type PrincipalAuthMiddleware struct {
	store PrincipalStore
}

// NewPrincipalAuthMiddleware creates a new principal auth middleware
func NewPrincipalAuthMiddleware(store PrincipalStore) *PrincipalAuthMiddleware {
	return &PrincipalAuthMiddleware{store: store}
}

// Authenticate validates the API key and adds principal to context
func (m *PrincipalAuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSONError(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeJSONError(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse token: prefix.secret
		parts := strings.SplitN(token, ".", 2)
		if len(parts) != 2 || parts[1] == "" {
			writeJSONError(w, "invalid api key format", http.StatusUnauthorized)
			return
		}

		prefix, secret := parts[0], parts[1]

		// Look up API key by prefix
		apiKey, keyHash, err := m.store.GetAPIKeyByPrefix(r.Context(), prefix)
		if err != nil {
			slog.Error("failed to get api key", "error", err, "prefix", prefix)
			writeJSONError(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// Timing-attack prevention: always do bcrypt comparison
		hashToCompare := dummyHash
		if apiKey != nil {
			hashToCompare = []byte(keyHash)
		}

		if err := bcrypt.CompareHashAndPassword(hashToCompare, []byte(secret)); err != nil || apiKey == nil {
			writeJSONError(w, "invalid api key", http.StatusUnauthorized)
			return
		}

		// Check status
		if apiKey.Status != types.AgentStatusActive {
			writeJSONError(w, "api key is not active", http.StatusUnauthorized)
			return
		}

		// Get principal
		principal, err := m.store.GetPrincipalByID(r.Context(), apiKey.PrincipalID)
		if err != nil {
			slog.Error("failed to get principal", "error", err, "principal_id", apiKey.PrincipalID)
			writeJSONError(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if principal == nil {
			slog.Warn("principal not found for valid api key", "principal_id", apiKey.PrincipalID)
			writeJSONError(w, "principal not found", http.StatusUnauthorized)
			return
		}

		// Update last used (async with timeout)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = m.store.UpdateAPIKeyLastUsed(ctx, apiKey.ID)
		}()

		// Add principal to context
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetPrincipal retrieves the principal from context
func GetPrincipal(ctx context.Context) *types.Principal {
	if v := ctx.Value(principalContextKey{}); v != nil {
		if p, ok := v.(*types.Principal); ok {
			return p
		}
	}
	return nil
}

// writeJSONError writes a JSON error response with proper Content-Type
func writeJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + message + `"}`))
}
