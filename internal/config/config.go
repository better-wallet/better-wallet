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

	// TEE Backend Config
	// Platform-agnostic design allows self-hosted users to choose their TEE provider
	TEEPlatform            string // TEE platform: "dev", "aws-nitro" (future: "azure-sgx", "gcp-confidential")
	TEEVsockCID            uint32 // Enclave CID (required for aws-nitro)
	TEEVsockPort           uint32 // Enclave port (default 5000)
	TEEMasterKeyHex        string // Master key for encrypting shares in database
	TEEAttestationRequired bool   // Require attestation verification

	// Server
	Port int
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		PostgresDSN:            getEnv("POSTGRES_DSN", ""),
		ExecutionBackend:       getEnv("EXECUTION_BACKEND", "kms"),
		KMSKeyID:               getEnv("KMS_KEY_ID", ""),
		TEEPlatform:            getEnv("TEE_PLATFORM", "dev"), // Default to dev platform
		TEEVsockCID:            uint32(getEnvInt("TEE_VSOCK_CID", 0)),
		TEEVsockPort:           uint32(getEnvInt("TEE_VSOCK_PORT", 5000)),
		TEEMasterKeyHex:        getEnv("TEE_MASTER_KEY_HEX", ""),
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

	if c.ExecutionBackend == "tee" {
		if c.TEEMasterKeyHex == "" {
			return fmt.Errorf("TEE_MASTER_KEY_HEX is required when EXECUTION_BACKEND is 'tee'")
		}

		// Validate platform-specific requirements
		switch c.TEEPlatform {
		case "dev":
			// Development mode using TCP - no additional config needed
		case "aws-nitro":
			// AWS Nitro Enclave using vsock (Linux only)
			if c.TEEVsockCID == 0 {
				return fmt.Errorf("TEE_VSOCK_CID is required when TEE_PLATFORM is 'aws-nitro'")
			}
		default:
			return fmt.Errorf("unsupported TEE_PLATFORM: %s (supported: dev, aws-nitro)", c.TEEPlatform)
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
