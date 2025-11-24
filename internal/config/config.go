package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration
type Config struct {
	// Database
	PostgresDSN string

	// App-Level Authentication
	AppID     string
	AppSecret string

	// User Authentication
	AuthKind     string // oidc or jwt
	AuthIssuer   string
	AuthAudience string
	AuthJWKSURI  string

	// Key Execution Backend
	ExecutionBackend       string // kms or tee
	KMSKeyID               string
	TEEAttestationRequired bool

	// EVM Configuration
	RPCEndpoint string

	// Server
	Port int

	// Rate Limiting
	RateLimitQPS int
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		PostgresDSN:            getEnv("POSTGRES_DSN", ""),
		AppID:                  getEnv("APP_ID", ""),
		AppSecret:              getEnv("APP_SECRET", ""),
		AuthKind:               getEnv("AUTH_KIND", "oidc"),
		AuthIssuer:             getEnv("AUTH_ISSUER", ""),
		AuthAudience:           getEnv("AUTH_AUDIENCE", ""),
		AuthJWKSURI:            getEnv("AUTH_JWKS_URI", ""),
		ExecutionBackend:       getEnv("EXECUTION_BACKEND", "kms"),
		KMSKeyID:               getEnv("KMS_KEY_ID", ""),
		TEEAttestationRequired: getEnvBool("TEE_ATTESTATION_REQUIRED", false),
		RPCEndpoint:            getEnv("RPC_ENDPOINT", ""),
		Port:                   getEnvInt("PORT", 8080),
		RateLimitQPS:           getEnvInt("RATE_LIMIT_QPS", 100),
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Database validation
	if c.PostgresDSN == "" {
		return fmt.Errorf("POSTGRES_DSN is required")
	}

	// App-level auth validation
	if c.AppID == "" {
		return fmt.Errorf("APP_ID is required")
	}

	if c.AppSecret == "" {
		return fmt.Errorf("APP_SECRET is required")
	}

	// User auth validation
	if c.AuthKind != "oidc" && c.AuthKind != "jwt" {
		return fmt.Errorf("AUTH_KIND must be 'oidc' or 'jwt', got: %s", c.AuthKind)
	}

	if c.AuthIssuer == "" {
		return fmt.Errorf("AUTH_ISSUER is required")
	}

	if c.AuthAudience == "" {
		return fmt.Errorf("AUTH_AUDIENCE is required")
	}

	if c.AuthJWKSURI == "" {
		return fmt.Errorf("AUTH_JWKS_URI is required")
	}

	// Execution backend validation
	if c.ExecutionBackend != "kms" && c.ExecutionBackend != "tee" {
		return fmt.Errorf("EXECUTION_BACKEND must be 'kms' or 'tee', got: %s", c.ExecutionBackend)
	}

	if c.ExecutionBackend == "kms" && c.KMSKeyID == "" {
		return fmt.Errorf("KMS_KEY_ID is required when EXECUTION_BACKEND is 'kms'")
	}

	// RPC validation
	if c.RPCEndpoint == "" {
		return fmt.Errorf("RPC_ENDPOINT is required")
	}

	return nil
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvInt gets an integer environment variable with a default value
func getEnvInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// getEnvBool gets a boolean environment variable with a default value
func getEnvBool(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	valueStr = strings.ToLower(valueStr)
	return valueStr == "true" || valueStr == "1" || valueStr == "yes"
}
