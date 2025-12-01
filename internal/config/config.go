package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds infrastructure-level configuration
// Per-app configuration (auth, rpc, rate limits) is stored in apps.settings
type Config struct {
	// Database
	PostgresDSN string

	// Key Execution Backend
	ExecutionBackend       string // kms or tee
	KMSKeyID               string
	TEEAttestationRequired bool

	// Server
	Port int
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		PostgresDSN:            getEnv("POSTGRES_DSN", ""),
		ExecutionBackend:       getEnv("EXECUTION_BACKEND", "kms"),
		KMSKeyID:               getEnv("KMS_KEY_ID", ""),
		TEEAttestationRequired: getEnvBool("TEE_ATTESTATION_REQUIRED", false),
		Port:                   getEnvInt("PORT", 8080),
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.PostgresDSN == "" {
		return fmt.Errorf("POSTGRES_DSN is required")
	}

	if c.ExecutionBackend != "kms" && c.ExecutionBackend != "tee" {
		return fmt.Errorf("EXECUTION_BACKEND must be 'kms' or 'tee', got: %s", c.ExecutionBackend)
	}

	if c.ExecutionBackend == "kms" && c.KMSKeyID == "" {
		return fmt.Errorf("KMS_KEY_ID is required when EXECUTION_BACKEND is 'kms'")
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
