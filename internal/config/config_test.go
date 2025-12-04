package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid KMS local config",
			config: &Config{
				PostgresDSN:       "postgres://localhost:5432/test",
				ExecutionBackend:  "kms",
				KMSProvider:       "local",
				KMSLocalMasterKey: "test-master-key-32-bytes-long!!",
				Port:              8080,
			},
			wantErr: false,
		},
		{
			name: "valid KMS AWS config",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "kms",
				KMSProvider:      "aws-kms",
				KMSAWSKeyID:      "alias/my-key",
				KMSAWSRegion:     "us-east-1",
				Port:             8080,
			},
			wantErr: false,
		},
		{
			name: "valid KMS Vault config",
			config: &Config{
				PostgresDSN:        "postgres://localhost:5432/test",
				ExecutionBackend:   "kms",
				KMSProvider:        "vault",
				KMSVaultAddress:    "http://localhost:8200",
				KMSVaultToken:      "s.token123",
				KMSVaultTransitKey: "my-transit-key",
				Port:               8080,
			},
			wantErr: false,
		},
		{
			name: "valid TEE dev config",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "tee",
				TEEPlatform:      "dev",
				TEEMasterKeyHex:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Port:             8080,
			},
			wantErr: false,
		},
		{
			name: "valid TEE aws-nitro config",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "tee",
				TEEPlatform:      "aws-nitro",
				TEEVsockCID:      5,
				TEEVsockPort:     5000,
				TEEMasterKeyHex:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Port:             8080,
			},
			wantErr: false,
		},
		{
			name: "missing PostgresDSN",
			config: &Config{
				ExecutionBackend:  "kms",
				KMSProvider:       "local",
				KMSLocalMasterKey: "test-key",
			},
			wantErr: true,
			errMsg:  "POSTGRES_DSN is required",
		},
		{
			name: "invalid execution backend",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "invalid",
			},
			wantErr: true,
			errMsg:  "EXECUTION_BACKEND must be 'kms' or 'tee'",
		},
		{
			name: "KMS local missing master key",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "kms",
				KMSProvider:      "local",
			},
			wantErr: true,
			errMsg:  "KMS_LOCAL_MASTER_KEY",
		},
		{
			name: "KMS AWS missing key ID",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "kms",
				KMSProvider:      "aws-kms",
				KMSAWSRegion:     "us-east-1",
			},
			wantErr: true,
			errMsg:  "KMS_AWS_KEY_ID is required",
		},
		{
			name: "KMS AWS missing region",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "kms",
				KMSProvider:      "aws-kms",
				KMSAWSKeyID:      "alias/my-key",
			},
			wantErr: true,
			errMsg:  "KMS_AWS_REGION is required",
		},
		{
			name: "KMS Vault missing address",
			config: &Config{
				PostgresDSN:        "postgres://localhost:5432/test",
				ExecutionBackend:   "kms",
				KMSProvider:        "vault",
				KMSVaultToken:      "token",
				KMSVaultTransitKey: "key",
			},
			wantErr: true,
			errMsg:  "KMS_VAULT_ADDRESS is required",
		},
		{
			name: "KMS Vault missing token",
			config: &Config{
				PostgresDSN:        "postgres://localhost:5432/test",
				ExecutionBackend:   "kms",
				KMSProvider:        "vault",
				KMSVaultAddress:    "http://localhost:8200",
				KMSVaultTransitKey: "key",
			},
			wantErr: true,
			errMsg:  "KMS_VAULT_TOKEN is required",
		},
		{
			name: "KMS Vault missing transit key",
			config: &Config{
				PostgresDSN:     "postgres://localhost:5432/test",
				ExecutionBackend: "kms",
				KMSProvider:     "vault",
				KMSVaultAddress: "http://localhost:8200",
				KMSVaultToken:   "token",
			},
			wantErr: true,
			errMsg:  "KMS_VAULT_TRANSIT_KEY is required",
		},
		{
			name: "unsupported KMS provider",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "kms",
				KMSProvider:      "unsupported",
			},
			wantErr: true,
			errMsg:  "unsupported KMS_PROVIDER",
		},
		{
			name: "TEE missing master key",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "tee",
				TEEPlatform:      "dev",
			},
			wantErr: true,
			errMsg:  "TEE_MASTER_KEY_HEX is required",
		},
		{
			name: "TEE aws-nitro missing vsock CID",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "tee",
				TEEPlatform:      "aws-nitro",
				TEEMasterKeyHex:  "0123456789abcdef",
			},
			wantErr: true,
			errMsg:  "TEE_VSOCK_CID is required",
		},
		{
			name: "unsupported TEE platform",
			config: &Config{
				PostgresDSN:      "postgres://localhost:5432/test",
				ExecutionBackend: "tee",
				TEEPlatform:      "unsupported",
				TEEMasterKeyHex:  "0123456789abcdef",
			},
			wantErr: true,
			errMsg:  "unsupported TEE_PLATFORM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	// Save original env vars and restore after test
	originalEnv := map[string]string{
		"POSTGRES_DSN":        os.Getenv("POSTGRES_DSN"),
		"EXECUTION_BACKEND":   os.Getenv("EXECUTION_BACKEND"),
		"KMS_PROVIDER":        os.Getenv("KMS_PROVIDER"),
		"KMS_LOCAL_MASTER_KEY": os.Getenv("KMS_LOCAL_MASTER_KEY"),
		"KMS_KEY_ID":          os.Getenv("KMS_KEY_ID"),
		"PORT":                os.Getenv("PORT"),
	}
	defer func() {
		for k, v := range originalEnv {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	t.Run("valid configuration from environment", func(t *testing.T) {
		os.Setenv("POSTGRES_DSN", "postgres://localhost:5432/test")
		os.Setenv("EXECUTION_BACKEND", "kms")
		os.Setenv("KMS_PROVIDER", "local")
		os.Setenv("KMS_LOCAL_MASTER_KEY", "test-master-key")
		os.Setenv("PORT", "9090")

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, "postgres://localhost:5432/test", cfg.PostgresDSN)
		assert.Equal(t, "kms", cfg.ExecutionBackend)
		assert.Equal(t, "local", cfg.KMSProvider)
		assert.Equal(t, "test-master-key", cfg.KMSLocalMasterKey)
		assert.Equal(t, 9090, cfg.Port)
	})

	t.Run("default values", func(t *testing.T) {
		os.Setenv("POSTGRES_DSN", "postgres://localhost:5432/test")
		os.Setenv("KMS_LOCAL_MASTER_KEY", "test-key")
		os.Unsetenv("EXECUTION_BACKEND")
		os.Unsetenv("KMS_PROVIDER")
		os.Unsetenv("PORT")

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, "kms", cfg.ExecutionBackend)      // default
		assert.Equal(t, "local", cfg.KMSProvider)         // default
		assert.Equal(t, 8080, cfg.Port)                   // default
	})

	t.Run("backward compatibility with KMS_KEY_ID", func(t *testing.T) {
		os.Setenv("POSTGRES_DSN", "postgres://localhost:5432/test")
		os.Unsetenv("KMS_LOCAL_MASTER_KEY")
		os.Setenv("KMS_KEY_ID", "legacy-key")
		os.Setenv("KMS_PROVIDER", "local")

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, "legacy-key", cfg.KMSLocalMasterKey)
	})

	t.Run("missing required POSTGRES_DSN", func(t *testing.T) {
		os.Unsetenv("POSTGRES_DSN")

		cfg, err := Load()
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "POSTGRES_DSN is required")
	})
}

func TestGetEnv(t *testing.T) {
	key := "TEST_GET_ENV_VAR"
	defer os.Unsetenv(key)

	t.Run("returns default when env not set", func(t *testing.T) {
		os.Unsetenv(key)
		result := getEnv(key, "default-value")
		assert.Equal(t, "default-value", result)
	})

	t.Run("returns env value when set", func(t *testing.T) {
		os.Setenv(key, "actual-value")
		result := getEnv(key, "default-value")
		assert.Equal(t, "actual-value", result)
	})

	t.Run("returns default when env is empty string", func(t *testing.T) {
		os.Setenv(key, "")
		result := getEnv(key, "default-value")
		assert.Equal(t, "default-value", result)
	})
}

func TestGetEnvInt(t *testing.T) {
	key := "TEST_GET_ENV_INT_VAR"
	defer os.Unsetenv(key)

	t.Run("returns default when env not set", func(t *testing.T) {
		os.Unsetenv(key)
		result := getEnvInt(key, 42)
		assert.Equal(t, 42, result)
	})

	t.Run("returns parsed int when set", func(t *testing.T) {
		os.Setenv(key, "100")
		result := getEnvInt(key, 42)
		assert.Equal(t, 100, result)
	})

	t.Run("returns default when value is not a valid int", func(t *testing.T) {
		os.Setenv(key, "not-a-number")
		result := getEnvInt(key, 42)
		assert.Equal(t, 42, result)
	})

	t.Run("returns default when value is empty", func(t *testing.T) {
		os.Setenv(key, "")
		result := getEnvInt(key, 42)
		assert.Equal(t, 42, result)
	})

	t.Run("handles negative numbers", func(t *testing.T) {
		os.Setenv(key, "-10")
		result := getEnvInt(key, 42)
		assert.Equal(t, -10, result)
	})
}

func TestGetEnvBool(t *testing.T) {
	key := "TEST_GET_ENV_BOOL_VAR"
	defer os.Unsetenv(key)

	tests := []struct {
		name     string
		envValue string
		setEnv   bool
		defValue bool
		expected bool
	}{
		{
			name:     "returns default when env not set",
			setEnv:   false,
			defValue: true,
			expected: true,
		},
		{
			name:     "true value",
			envValue: "true",
			setEnv:   true,
			defValue: false,
			expected: true,
		},
		{
			name:     "TRUE value (case insensitive)",
			envValue: "TRUE",
			setEnv:   true,
			defValue: false,
			expected: true,
		},
		{
			name:     "1 value",
			envValue: "1",
			setEnv:   true,
			defValue: false,
			expected: true,
		},
		{
			name:     "yes value",
			envValue: "yes",
			setEnv:   true,
			defValue: false,
			expected: true,
		},
		{
			name:     "YES value (case insensitive)",
			envValue: "YES",
			setEnv:   true,
			defValue: false,
			expected: true,
		},
		{
			name:     "false value",
			envValue: "false",
			setEnv:   true,
			defValue: true,
			expected: false,
		},
		{
			name:     "0 value",
			envValue: "0",
			setEnv:   true,
			defValue: true,
			expected: false,
		},
		{
			name:     "no value",
			envValue: "no",
			setEnv:   true,
			defValue: true,
			expected: false,
		},
		{
			name:     "empty string returns default",
			envValue: "",
			setEnv:   true,
			defValue: true,
			expected: true,
		},
		{
			name:     "invalid value returns false",
			envValue: "invalid",
			setEnv:   true,
			defValue: true,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				os.Setenv(key, tt.envValue)
			} else {
				os.Unsetenv(key)
			}
			result := getEnvBool(key, tt.defValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTEEConfig(t *testing.T) {
	t.Run("TEE dev platform with defaults", func(t *testing.T) {
		cfg := &Config{
			PostgresDSN:      "postgres://localhost:5432/test",
			ExecutionBackend: "tee",
			TEEPlatform:      "dev",
			TEEMasterKeyHex:  "0123456789abcdef",
			TEEVsockPort:     5000, // default
		}
		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("TEE attestation required flag", func(t *testing.T) {
		cfg := &Config{
			PostgresDSN:            "postgres://localhost:5432/test",
			ExecutionBackend:       "tee",
			TEEPlatform:            "dev",
			TEEMasterKeyHex:        "0123456789abcdef",
			TEEAttestationRequired: true,
		}
		err := cfg.Validate()
		require.NoError(t, err)
		assert.True(t, cfg.TEEAttestationRequired)
	})
}
