package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/config"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/crypto"
)

// Server represents the HTTP server
type Server struct {
	config                *config.Config
	walletService         *app.WalletService
	appAuthMiddleware     *middleware.AppAuthMiddleware
	userAuthMiddleware    *middleware.AuthMiddleware
	idempotencyMiddleware *middleware.IdempotencyMiddleware
	httpServer            *http.Server
	store                 *storage.Store
}

// NewServer creates a new API server
func NewServer(
	cfg *config.Config,
	walletService *app.WalletService,
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
	mux := http.NewServeMux()

	// Health check endpoint (no auth required)
	mux.HandleFunc("/health", s.handleHealth)

	// API v1 routes (with app-level + user-level authentication; owner signatures verified in handler)
	// Chain: App Auth -> User Auth -> Handler
	mux.Handle("/v1/wallets",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(http.HandlerFunc(s.handleWallets))))

	// Wallet operations - routing to appropriate handler
	mux.Handle("/v1/wallets/",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(
				http.HandlerFunc(s.handleWalletOperationsRouter))))

	// Policy management routes
	mux.Handle("/v1/policies",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(http.HandlerFunc(s.handlePolicies))))

	mux.Handle("/v1/policies/",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(
				http.HandlerFunc(s.handlePolicyOperations))))

	// Key quorum management routes
	mux.Handle("/v1/key-quorums",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(http.HandlerFunc(s.handleKeyQuorums))))

	mux.Handle("/v1/key-quorums/",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(
				http.HandlerFunc(s.handleKeyQuorumOperations))))

	// User management routes
	mux.Handle("/v1/users",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(http.HandlerFunc(s.handleUsers))))

	mux.Handle("/v1/users/",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(
				http.HandlerFunc(s.handleUserOperations))))

	// Transaction query routes
	mux.Handle("/v1/transactions",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(http.HandlerFunc(s.handleTransactions))))

	mux.Handle("/v1/transactions/",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(
				http.HandlerFunc(s.handleTransactionOperations))))

	// Authorization key management routes
	mux.Handle("/v1/authorization-keys",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(http.HandlerFunc(s.handleAuthorizationKeys))))

	mux.Handle("/v1/authorization-keys/",
		s.appAuthMiddleware.Authenticate(
			s.userAuthMiddleware.Authenticate(
				http.HandlerFunc(s.handleAuthorizationKeyOperations))))

	s.httpServer = &http.Server{
		Addr: fmt.Sprintf(":%d", s.config.Port),
		// Chain middleware: AuditContext -> Logging -> Idempotency -> Routes
		Handler:      middleware.AuditContext(s.loggingMiddleware(s.idempotencyMiddleware.Handle(mux))),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Printf("Starting server on port %d...\n", s.config.Port)
	return s.httpServer.ListenAndServe()
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
