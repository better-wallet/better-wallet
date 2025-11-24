package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/better-wallet/better-wallet/internal/api"
	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/config"
	"github.com/better-wallet/better-wallet/internal/keyexec"
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

	// Initialize database
	store, err := storage.New(cfg.PostgresDSN)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer store.Close()

	fmt.Println("Connected to database successfully")

	// Initialize key executor based on backend type
	var keyExec keyexec.KeyExecutor
	switch cfg.ExecutionBackend {
	case "kms":
		keyExec, err = keyexec.NewKMSExecutor(cfg.KMSKeyID)
		if err != nil {
			log.Fatalf("Failed to initialize KMS executor: %v", err)
		}
	case "tee":
		log.Fatalf("TEE backend not yet implemented")
	default:
		log.Fatalf("Unknown execution backend: %s", cfg.ExecutionBackend)
	}

	fmt.Printf("Initialized %s key executor\n", cfg.ExecutionBackend)

	// Initialize policy engine
	policyEngine := policy.NewEngine()

	// Initialize application services
	walletService := app.NewWalletService(store, keyExec, policyEngine)

	// Initialize middleware
	appAuthMiddleware := middleware.NewAppAuthMiddleware(cfg)
	userAuthMiddleware := middleware.NewAuthMiddleware(cfg)

	// Initialize API server
	server := api.NewServer(cfg, walletService, appAuthMiddleware, userAuthMiddleware)

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
		log.Fatalf("Server error: %v", err)

	case sig := <-shutdown:
		fmt.Printf("\nReceived signal %v, starting graceful shutdown...\n", sig)

		// Create a context with timeout for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Attempt graceful shutdown
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Error during shutdown: %v", err)
			log.Printf("Forcing shutdown...")
		}

		fmt.Println("Server stopped")
	}
}
