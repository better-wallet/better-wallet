package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/better-wallet/better-wallet/internal/api"
	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/config"
	"github.com/better-wallet/better-wallet/internal/keyexec"
	"github.com/better-wallet/better-wallet/internal/logger"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/internal/policy"
	"github.com/better-wallet/better-wallet/internal/storage"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if err := logger.Init(); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Initialize database
	store, err := storage.New(cfg.PostgresDSN)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	slog.Info("connected to database")

	// Initialize key executor based on backend type
	var keyExec keyexec.KeyExecutor
	switch cfg.ExecutionBackend {
	case "kms":
		keyExec, err = keyexec.NewKMSExecutor(&keyexec.KMSConfig{
			Provider:          cfg.KMSProvider,
			LocalMasterKeyHex: cfg.KMSLocalMasterKey,
			AWSKMSKeyID:       cfg.KMSAWSKeyID,
			AWSKMSRegion:      cfg.KMSAWSRegion,
			VaultAddress:      cfg.KMSVaultAddress,
			VaultToken:        cfg.KMSVaultToken,
			VaultTransitKey:   cfg.KMSVaultTransitKey,
		})
		if err != nil {
			slog.Error("failed to initialize KMS executor", "error", err)
			os.Exit(1)
		}
	case "tee":
		keyExec, err = keyexec.NewTEEExecutor(&keyexec.TEEConfig{
			Platform:     cfg.TEEPlatform,
			VsockCID:     cfg.TEEVsockCID,
			VsockPort:    cfg.TEEVsockPort,
			MasterKeyHex: cfg.TEEMasterKeyHex,
		})
		if err != nil {
			slog.Error("failed to initialize TEE executor", "error", err)
			os.Exit(1)
		}
	default:
		slog.Error("unknown execution backend", "backend", cfg.ExecutionBackend)
		os.Exit(1)
	}

	slog.Info("initialized key executor", "backend", cfg.ExecutionBackend)

	// Initialize policy engine
	policyEngine := policy.NewEngine()

	// Initialize application services
	walletService := app.NewWalletService(store, keyExec, policyEngine)

	// Initialize middleware
	appAuthMiddleware := middleware.NewAppAuthMiddleware(store)
	userAuthMiddleware := middleware.NewAuthMiddleware()
	idempotencyRepo := storage.NewIdempotencyRepo(store)
	idempotencyMiddleware := middleware.NewIdempotencyMiddleware(idempotencyRepo)

	// Initialize API server
	server := api.NewServer(cfg, walletService, appAuthMiddleware, userAuthMiddleware, idempotencyMiddleware, store)

	// Start server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Start()
	}()

	// Setup signal handling for graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Wait for either server error or shutdown signal
	select {
	case err := <-serverErrors:
		slog.Error("server error", "error", err)
		os.Exit(1)

	case sig := <-shutdown:
		slog.Info("received shutdown signal", "signal", sig.String())

		// Create a context with timeout for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Attempt graceful shutdown
		if err := server.Shutdown(ctx); err != nil {
			slog.Error("error during shutdown", "error", err)
			slog.Warn("forcing shutdown")
		}

		slog.Info("server stopped")
	}
}
