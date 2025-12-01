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
	ExecutionBackend string // kms or tee

	// KMS Backend Config
	KMSKeyID string

	// TEE Backend Config (AWS Nitro Enclave)
	TEEVsockCID            uint32 // Enclave CID (assigned by Nitro)
	TEEVsockPort           uint32 // Enclave port (default 5000)
	TEEMasterKeyHex        string // Master key for encrypting shares in database
	TEEAttestationRequired bool   // Require attestation verification
	TEEDevMode             bool   // Enable TCP fallback for development (connect to localhost)

	// Server
	Port int
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		PostgresDSN:            getEnv("POSTGRES_DSN", ""),
		ExecutionBackend:       getEnv("EXECUTION_BACKEND", "kms"),
		KMSKeyID:               getEnv("KMS_KEY_ID", ""),
		TEEVsockCID:            uint32(getEnvInt("TEE_VSOCK_CID", 0)),
		TEEVsockPort:           uint32(getEnvInt("TEE_VSOCK_PORT", 5000)),
		TEEMasterKeyHex:        getEnv("TEE_MASTER_KEY_HEX", ""),
		TEEAttestationRequired: getEnvBool("TEE_ATTESTATION_REQUIRED", false),
		TEEDevMode:             getEnvBool("TEE_DEV_MODE", false),
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

	if c.ExecutionBackend == "tee" {
		// vsock is not yet implemented - require dev mode until it is
		if !c.TEEDevMode {
			return fmt.Errorf("TEE backend requires TEE_DEV_MODE=true (vsock not yet implemented for production Nitro deployment)")
		}
		if c.TEEMasterKeyHex == "" {
			return fmt.Errorf("TEE_MASTER_KEY_HEX is required when EXECUTION_BACKEND is 'tee'")
		}
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
