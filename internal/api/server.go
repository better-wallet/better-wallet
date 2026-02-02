package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/config"
	"github.com/better-wallet/better-wallet/internal/logger"
	"github.com/better-wallet/better-wallet/internal/middleware"
)

// Server represents the HTTP server
type Server struct {
	config                  *config.Config
	agentService            *app.AgentService
	principalAuthMiddleware *middleware.PrincipalAuthMiddleware
	agentAuthMiddleware     *middleware.AgentAuthMiddleware
	agentHandlers           *AgentHandlers
	agentSigningHandlers    *AgentSigningHandlers
	httpServer              *http.Server
}

// NewServer creates a new API server
func NewServer(
	cfg *config.Config,
	agentService *app.AgentService,
	principalAuthMiddleware *middleware.PrincipalAuthMiddleware,
	agentAuthMiddleware *middleware.AgentAuthMiddleware,
) *Server {
	return &Server{
		config:                  cfg,
		agentService:            agentService,
		principalAuthMiddleware: principalAuthMiddleware,
		agentAuthMiddleware:     agentAuthMiddleware,
		agentHandlers:           NewAgentHandlers(agentService),
		agentSigningHandlers:    NewAgentSigningHandlers(agentService),
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	rootMux := http.NewServeMux()

	// Health check endpoint (no auth required)
	rootMux.HandleFunc("/health", s.handleHealth)

	// Principal registration endpoint (no auth required - this is how new principals get their API key)
	rootMux.Handle("/v1/principals", middleware.LimitBody(http.HandlerFunc(s.agentHandlers.HandlePrincipals)))

	// Management API routes (Principal auth required)
	// These are used by humans/orgs to manage wallets and credentials
	mgmtMux := http.NewServeMux()
	mgmtMux.Handle("/v1/wallets", http.HandlerFunc(s.agentHandlers.HandleWallets))
	mgmtMux.Handle("/v1/wallets/", http.HandlerFunc(s.agentHandlers.HandleWalletOperations))
	mgmtMux.Handle("/v1/credentials/", http.HandlerFunc(s.agentHandlers.HandleCredentialOperations))

	mgmtHandler := middleware.LimitBody(
		s.principalAuthMiddleware.Authenticate(mgmtMux),
	)
	rootMux.Handle("/v1/wallets", mgmtHandler)
	rootMux.Handle("/v1/wallets/", mgmtHandler)
	rootMux.Handle("/v1/credentials/", mgmtHandler)

	// Agent Signing API routes (Agent credential auth required)
	// These are used by AI agents to request signing operations
	agentMux := http.NewServeMux()
	agentMux.Handle("/v1/agent/rpc", http.HandlerFunc(s.agentSigningHandlers.HandleRPC))

	agentHandler := middleware.LimitBody(
		s.agentAuthMiddleware.Authenticate(agentMux),
	)
	rootMux.Handle("/v1/agent/", agentHandler)

	s.httpServer = &http.Server{
		Addr: fmt.Sprintf(":%d", s.config.Port),
		// Chain middleware: RequestID -> AuditContext -> Logging -> Routes
		Handler:      middleware.RequestID(middleware.AuditContext(s.loggingMiddleware(rootMux))),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("starting server", "port", s.config.Port)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// loggingMiddleware logs HTTP requests with structured logging
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log := logger.FromContext(r.Context())

		// Wrap response writer to capture status code
		rw := middleware.NewStatusRecorder(w)

		next.ServeHTTP(rw, r)

		log.Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.StatusCode,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
