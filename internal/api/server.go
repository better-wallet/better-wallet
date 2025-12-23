package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/better-wallet/better-wallet/internal/config"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/crypto"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
)

// Server represents the HTTP server
type Server struct {
	config                *config.Config
	walletService         WalletService
	appAuthMiddleware     *middleware.AppAuthMiddleware
	userAuthMiddleware    *middleware.AuthMiddleware
	idempotencyMiddleware *middleware.IdempotencyMiddleware
	httpServer            *http.Server
	store                 *storage.Store
	authKeyStore          AuthorizationKeyStore
}

// NewServer creates a new API server
func NewServer(
	cfg *config.Config,
	walletService WalletService,
	appAuthMiddleware *middleware.AppAuthMiddleware,
	userAuthMiddleware *middleware.AuthMiddleware,
	idempotencyMiddleware *middleware.IdempotencyMiddleware,
	store *storage.Store,
) *Server {
	return &Server{
		config:                cfg,
		walletService:         walletService,
		appAuthMiddleware:     appAuthMiddleware,
		userAuthMiddleware:    userAuthMiddleware,
		idempotencyMiddleware: idempotencyMiddleware,
		store:                 store,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	rootMux := http.NewServeMux()

	// Health check endpoint (no auth required)
	rootMux.HandleFunc("/health", s.handleHealth)

	// API v1 routes (auth must run BEFORE idempotency to prevent replay bypass).
	v1Mux := http.NewServeMux()
	v1Mux.Handle("/v1/wallets", http.HandlerFunc(s.handleWallets))

	// Wallet operations - routing to appropriate handler
	v1Mux.Handle("/v1/wallets/", http.HandlerFunc(s.handleWalletOperationsRouter))

	// Policy management routes
	v1Mux.Handle("/v1/policies", http.HandlerFunc(s.handlePolicies))

	v1Mux.Handle("/v1/policies/", http.HandlerFunc(s.handlePolicyOperations))

	// Key quorum management routes
	v1Mux.Handle("/v1/key-quorums", http.HandlerFunc(s.handleKeyQuorums))

	v1Mux.Handle("/v1/key-quorums/", http.HandlerFunc(s.handleKeyQuorumOperations))

	// User management routes
	v1Mux.Handle("/v1/users", http.HandlerFunc(s.handleUsers))

	v1Mux.Handle("/v1/users/", http.HandlerFunc(s.handleUserOperations))

	// Transaction query routes
	v1Mux.Handle("/v1/transactions", http.HandlerFunc(s.handleTransactions))

	v1Mux.Handle("/v1/transactions/", http.HandlerFunc(s.handleTransactionOperations))

	// Authorization key management routes
	v1Mux.Handle("/v1/authorization-keys", http.HandlerFunc(s.handleAuthorizationKeys))

	v1Mux.Handle("/v1/authorization-keys/", http.HandlerFunc(s.handleAuthorizationKeyOperations))

	// Condition set management routes
	v1Mux.Handle("/v1/condition_sets", http.HandlerFunc(s.handleConditionSets))

	v1Mux.Handle("/v1/condition_sets/", http.HandlerFunc(s.handleConditionSetOperations))

	v1Handler := s.appAuthMiddleware.Authenticate(
		s.userAuthMiddleware.Authenticate(
			s.requireUserMiddleware(
				s.idempotencyMiddleware.Handle(v1Mux),
			),
		),
	)
	rootMux.Handle("/v1/", v1Handler)

	s.httpServer = &http.Server{
		Addr: fmt.Sprintf(":%d", s.config.Port),
		// Chain middleware: AuditContext -> Logging -> Routes
		Handler:      middleware.AuditContext(s.loggingMiddleware(rootMux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Printf("Starting server on port %d...\n", s.config.Port)
	return s.httpServer.ListenAndServe()
}

func (s *Server) requireUserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUserRequiredRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		if _, ok := middleware.GetUserSub(r.Context()); !ok {
			s.writeError(w, apperrors.ErrUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func isUserRequiredRequest(r *http.Request) bool {
	path := r.URL.Path
	method := r.Method

	// Allow app-only creation of app-managed wallets.
	if path == "/v1/wallets" && method == http.MethodPost {
		return false
	}

	// Allow app-only creation of app-owned policies.
	if path == "/v1/policies" && method == http.MethodPost {
		return false
	}

	// Allow wallet RPC without user JWT (authorization signature is required by the handler).
	normalizedPath := strings.TrimSuffix(path, "/")
	if method == http.MethodPost && strings.HasPrefix(normalizedPath, "/v1/wallets/") {
		parts := strings.Split(strings.TrimPrefix(normalizedPath, "/v1/wallets/"), "/")
		if len(parts) == 2 && parts[1] == "rpc" {
			return false
		}
	}

	// Default: require user for all other v1 endpoints.
	return true
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		fmt.Printf("%s %s - started\n", r.Method, r.URL.Path)

		next.ServeHTTP(w, r)

		fmt.Printf("%s %s - completed in %v\n", r.Method, r.URL.Path, time.Since(start))
	})
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// hpkeEncrypt encrypts data using HPKE with the recipient's public key
func (s *Server) hpkeEncrypt(recipientPublicKeyB64 string, plaintext []byte) (*crypto.HPKEEncryptedData, error) {
	return crypto.EncryptWithHPKE(recipientPublicKeyB64, plaintext)
}
