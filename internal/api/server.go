package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/config"
	"github.com/better-wallet/better-wallet/internal/logger"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus metrics
var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_active_connections",
			Help: "Number of active HTTP connections",
		},
	)
	signingOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signing_operations_total",
			Help: "Total number of signing operations",
		},
		[]string{"method", "status"},
	)
	walletsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "wallets_total",
			Help: "Total number of wallets",
		},
	)
	credentialsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "credentials_total",
			Help: "Total number of credentials",
		},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(activeConnections)
	prometheus.MustRegister(signingOperationsTotal)
	prometheus.MustRegister(walletsTotal)
	prometheus.MustRegister(credentialsTotal)
}

// Server represents the HTTP server
type Server struct {
	config                  *config.Config
	agentService            *app.AgentService
	principalAuthMiddleware *middleware.PrincipalAuthMiddleware
	agentAuthMiddleware     *middleware.AgentAuthMiddleware
	agentHandlers           *AgentHandlers
	agentSigningHandlers    *AgentSigningHandlers
	httpServer              *http.Server
	store                   *storage.Store
	rateLimiter             *middleware.RateLimiter
	ready                   atomic.Bool
}

// NewServer creates a new API server
func NewServer(
	cfg *config.Config,
	agentService *app.AgentService,
	principalAuthMiddleware *middleware.PrincipalAuthMiddleware,
	agentAuthMiddleware *middleware.AgentAuthMiddleware,
) *Server {
	s := &Server{
		config:                  cfg,
		agentService:            agentService,
		principalAuthMiddleware: principalAuthMiddleware,
		agentAuthMiddleware:     agentAuthMiddleware,
		agentHandlers:           NewAgentHandlers(agentService),
		agentSigningHandlers:    NewAgentSigningHandlers(agentService),
		rateLimiter:             middleware.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst, cfg.RateLimitEnabled),
	}
	s.ready.Store(false)
	return s
}

// SetStore sets the storage for health checks
func (s *Server) SetStore(store *storage.Store) {
	s.store = store
}

// Start starts the HTTP server
func (s *Server) Start() error {
	rootMux := http.NewServeMux()

	// Health check endpoints (no auth required)
	rootMux.HandleFunc("/health", s.handleHealth)
	rootMux.HandleFunc("/ready", s.handleReady)
	rootMux.HandleFunc("/live", s.handleLive)

	// Prometheus metrics endpoint
	rootMux.Handle("/metrics", promhttp.Handler())

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

	// Build middleware chain
	handler := middleware.RequestID(
		middleware.AuditContext(
			s.securityHeaders(
				s.rateLimiter.Limit(
					s.metricsMiddleware(
						s.loggingMiddleware(rootMux),
					),
				),
			),
		),
	)

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Mark server as ready
	s.ready.Store(true)

	slog.Info("starting server", "port", s.config.Port)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.ready.Store(false)
	return s.httpServer.Shutdown(ctx)
}

// securityHeaders adds security headers to all responses
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HSTS - enforce HTTPS
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// CORS headers
		origin := r.Header.Get("Origin")
		if origin != "" && s.isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isAllowedOrigin checks if the origin is allowed for CORS
func (s *Server) isAllowedOrigin(origin string) bool {
	// In production, this should check against a configured list
	allowedOrigins := s.config.AllowedOrigins
	if len(allowedOrigins) == 0 {
		return false
	}
	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

// metricsMiddleware collects Prometheus metrics
func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		activeConnections.Inc()
		defer activeConnections.Dec()

		// Wrap response writer to capture status code
		rw := middleware.NewStatusRecorder(w)

		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", rw.StatusCode)
		path := s.normalizePath(r.URL.Path)

		httpRequestsTotal.WithLabelValues(r.Method, path, status).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}

// normalizePath normalizes URL paths for metrics (to avoid high cardinality)
func (s *Server) normalizePath(path string) string {
	// Normalize paths with UUIDs
	switch {
	case len(path) > 12 && path[:12] == "/v1/wallets/":
		return "/v1/wallets/{id}"
	case len(path) > 17 && path[:17] == "/v1/credentials/":
		return "/v1/credentials/{id}"
	default:
		return path
	}
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

// HealthResponse represents the health check response
type HealthResponse struct {
	Status   string            `json:"status"`
	Version  string            `json:"version,omitempty"`
	Checks   map[string]string `json:"checks,omitempty"`
	Uptime   string            `json:"uptime,omitempty"`
}

var serverStartTime = time.Now()

// handleHealth handles basic health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(HealthResponse{
		Status:  "ok",
		Version: s.config.Version,
		Uptime:  time.Since(serverStartTime).String(),
	})
}

// handleReady handles readiness probe (Kubernetes)
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)
	allHealthy := true

	// Check if server is ready
	if !s.ready.Load() {
		checks["server"] = "not_ready"
		allHealthy = false
	} else {
		checks["server"] = "ok"
	}

	// Check database connection
	if s.store != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.store.DB().Ping(ctx); err != nil {
			checks["database"] = "unhealthy"
			allHealthy = false
		} else {
			checks["database"] = "ok"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if allHealthy {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(HealthResponse{
			Status: "ready",
			Checks: checks,
		})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(HealthResponse{
			Status: "not_ready",
			Checks: checks,
		})
	}
}

// handleLive handles liveness probe (Kubernetes)
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(HealthResponse{
		Status: "alive",
	})
}
