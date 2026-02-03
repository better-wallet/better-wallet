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

type agentCredentialContextKey struct{}
type agentWalletContextKey struct{}

// AgentStore defines the interface for agent data access
type AgentStore interface {
	GetCredentialByPrefix(ctx context.Context, prefix string) (*types.AgentCredential, string, error)
	GetWalletByID(ctx context.Context, id uuid.UUID) (*types.AgentWallet, error)
	UpdateCredentialLastUsed(ctx context.Context, id uuid.UUID) error
}

// AgentAuthMiddleware handles agent credential authentication
type AgentAuthMiddleware struct {
	store AgentStore
}

// NewAgentAuthMiddleware creates a new agent auth middleware
func NewAgentAuthMiddleware(store AgentStore) *AgentAuthMiddleware {
	return &AgentAuthMiddleware{store: store}
}

// Authenticate validates the agent credential and adds it to context
func (m *AgentAuthMiddleware) Authenticate(next http.Handler) http.Handler {
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
			writeJSONError(w, "invalid credential format", http.StatusUnauthorized)
			return
		}

		prefix, secret := parts[0], parts[1]

		// Look up credential by prefix
		credential, keyHash, err := m.store.GetCredentialByPrefix(r.Context(), prefix)
		if err != nil {
			slog.Error("failed to get credential", "error", err, "prefix", prefix)
			writeJSONError(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// Timing-attack prevention: always do bcrypt comparison
		hashToCompare := dummyHash
		if credential != nil {
			hashToCompare = []byte(keyHash)
		}

		if err := bcrypt.CompareHashAndPassword(hashToCompare, []byte(secret)); err != nil || credential == nil {
			writeJSONError(w, "invalid credential", http.StatusUnauthorized)
			return
		}

		// Check credential status
		switch credential.Status {
		case types.AgentStatusActive:
			// OK
		case types.AgentStatusPaused:
			writeJSONErrorWithCode(w, "agent credential is paused", "CREDENTIAL_PAUSED")
			return
		case types.AgentStatusRevoked:
			writeJSONErrorWithCode(w, "agent credential is revoked", "CREDENTIAL_REVOKED")
			return
		default:
			writeJSONError(w, "agent credential is not active", http.StatusForbidden)
			return
		}

		// Get wallet and check status
		wallet, err := m.store.GetWalletByID(r.Context(), credential.WalletID)
		if err != nil {
			slog.Error("failed to get wallet", "error", err, "wallet_id", credential.WalletID)
			writeJSONError(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if wallet == nil {
			slog.Warn("wallet not found for credential", "wallet_id", credential.WalletID)
			writeJSONError(w, "wallet not found", http.StatusNotFound)
			return
		}

		// Check wallet status
		switch wallet.Status {
		case types.AgentStatusActive:
			// OK
		case types.AgentStatusPaused:
			writeJSONErrorWithCode(w, "wallet is paused", "WALLET_PAUSED")
			return
		case types.AgentStatusKilled:
			writeJSONErrorWithCode(w, "wallet is killed", "WALLET_KILLED")
			return
		default:
			writeJSONError(w, "wallet is not active", http.StatusForbidden)
			return
		}

		// Update last used (async with timeout)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = m.store.UpdateCredentialLastUsed(ctx, credential.ID)
		}()

		// Add credential and wallet to context
		ctx := context.WithValue(r.Context(), agentCredentialContextKey{}, credential)
		ctx = context.WithValue(ctx, agentWalletContextKey{}, wallet)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetAgentCredential retrieves the agent credential from context
func GetAgentCredential(ctx context.Context) *types.AgentCredential {
	if v := ctx.Value(agentCredentialContextKey{}); v != nil {
		if c, ok := v.(*types.AgentCredential); ok {
			return c
		}
	}
	return nil
}

// GetAgentWallet retrieves the agent wallet from context
func GetAgentWallet(ctx context.Context) *types.AgentWallet {
	if v := ctx.Value(agentWalletContextKey{}); v != nil {
		if w, ok := v.(*types.AgentWallet); ok {
			return w
		}
	}
	return nil
}

// writeJSONErrorWithCode writes a JSON error response with an error code
func writeJSONErrorWithCode(w http.ResponseWriter, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"` + message + `","code":"` + code + `"}`))
}
