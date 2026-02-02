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

	// EVM RPC (supports all EVM-compatible chains)
	RPCURL string

	// Key Execution Backend
	ExecutionBackend string // kms or tee

	// KMS Backend Config
	// Provider-agnostic design allows self-hosted users to choose their KMS provider
	KMSProvider       string // KMS provider: "local", "aws-kms", "vault" (default: "local")
	KMSLocalMasterKey string // Master key for local provider

	// AWS KMS config
	KMSAWSKeyID  string // AWS KMS Key ID or ARN
	KMSAWSRegion string // AWS region

	// Vault config
	KMSVaultAddress    string // Vault server address
	KMSVaultToken      string // Vault token
	KMSVaultTransitKey string // Vault Transit key name

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
		RPCURL:                 getEnv("RPC_URL", ""),
		ExecutionBackend:       getEnv("EXECUTION_BACKEND", "kms"),
		KMSProvider:            getEnv("KMS_PROVIDER", "local"),
		KMSLocalMasterKey:      getEnv("KMS_LOCAL_MASTER_KEY", getEnv("KMS_KEY_ID", "")), // Backward compat
		KMSAWSKeyID:            getEnv("KMS_AWS_KEY_ID", ""),
		KMSAWSRegion:           getEnv("KMS_AWS_REGION", ""),
		KMSVaultAddress:        getEnv("KMS_VAULT_ADDRESS", ""),
		KMSVaultToken:          getEnv("KMS_VAULT_TOKEN", ""),
		KMSVaultTransitKey:     getEnv("KMS_VAULT_TRANSIT_KEY", ""),
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

	if c.ExecutionBackend == "kms" {
		// Validate KMS provider-specific requirements
		switch c.KMSProvider {
		case "local", "":
			if c.KMSLocalMasterKey == "" {
				return fmt.Errorf("KMS_LOCAL_MASTER_KEY (or KMS_KEY_ID) is required when KMS_PROVIDER is 'local'")
			}
		case "aws-kms":
			if c.KMSAWSKeyID == "" {
				return fmt.Errorf("KMS_AWS_KEY_ID is required when KMS_PROVIDER is 'aws-kms'")
			}
			if c.KMSAWSRegion == "" {
				return fmt.Errorf("KMS_AWS_REGION is required when KMS_PROVIDER is 'aws-kms'")
			}
		case "vault":
			if c.KMSVaultAddress == "" {
				return fmt.Errorf("KMS_VAULT_ADDRESS is required when KMS_PROVIDER is 'vault'")
			}
			if c.KMSVaultToken == "" {
				return fmt.Errorf("KMS_VAULT_TOKEN is required when KMS_PROVIDER is 'vault'")
			}
			if c.KMSVaultTransitKey == "" {
				return fmt.Errorf("KMS_VAULT_TRANSIT_KEY is required when KMS_PROVIDER is 'vault'")
			}
		default:
			return fmt.Errorf("unsupported KMS_PROVIDER: %s (supported: local, aws-kms, vault)", c.KMSProvider)
		}
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
