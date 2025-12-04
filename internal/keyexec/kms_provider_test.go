package keyexec

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalKMSProvider(t *testing.T) {
	t.Run("creates provider with valid key", func(t *testing.T) {
		provider, err := NewLocalKMSProvider("test-master-key-32-bytes-long!!")
		require.NoError(t, err)
		require.NotNil(t, provider)
		assert.Equal(t, "local", provider.Provider())
	})

	t.Run("returns error with empty key", func(t *testing.T) {
		provider, err := NewLocalKMSProvider("")
		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "master key is required")
	})
}

func TestLocalKMSProvider_EncryptDecrypt(t *testing.T) {
	provider, err := NewLocalKMSProvider("test-master-key-32-bytes-long!!")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("encrypts and decrypts data", func(t *testing.T) {
		plaintext := []byte("Hello, World! This is a secret message.")

		ciphertext, err := provider.Encrypt(ctx, plaintext)
		require.NoError(t, err)
		assert.NotEmpty(t, ciphertext)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := provider.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypts and decrypts empty data", func(t *testing.T) {
		plaintext := []byte{}

		ciphertext, err := provider.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		decrypted, err := provider.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		// Empty slice decrypted may return nil or empty slice, both are valid
		assert.Len(t, decrypted, 0)
	})

	t.Run("encrypts and decrypts large data", func(t *testing.T) {
		plaintext := make([]byte, 1024*1024) // 1 MB
		_, err := rand.Read(plaintext)
		require.NoError(t, err)

		ciphertext, err := provider.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		decrypted, err := provider.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("different encryptions produce different ciphertexts", func(t *testing.T) {
		plaintext := []byte("Same plaintext")

		ciphertext1, err := provider.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		ciphertext2, err := provider.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		// Due to random nonce, ciphertexts should be different
		assert.NotEqual(t, ciphertext1, ciphertext2)
	})
}

func TestLocalKMSProvider_DecryptErrors(t *testing.T) {
	provider, err := NewLocalKMSProvider("test-master-key-32-bytes-long!!")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("returns error for ciphertext too short", func(t *testing.T) {
		shortCiphertext := []byte("short")
		_, err := provider.Decrypt(ctx, shortCiphertext)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext too short")
	})

	t.Run("returns error for corrupted ciphertext", func(t *testing.T) {
		plaintext := []byte("Test data")
		ciphertext, err := provider.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		// Corrupt the ciphertext
		ciphertext[len(ciphertext)-1] ^= 0xFF

		_, err = provider.Decrypt(ctx, ciphertext)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt")
	})

	t.Run("returns error for wrong key decryption", func(t *testing.T) {
		provider2, err := NewLocalKMSProvider("different-key-32-bytes-long!!!!!")
		require.NoError(t, err)

		plaintext := []byte("Test data")
		ciphertext, err := provider.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		// Try to decrypt with different key
		_, err = provider2.Decrypt(ctx, ciphertext)
		assert.Error(t, err)
	})
}

func TestLocalKMSProvider_Provider(t *testing.T) {
	provider, err := NewLocalKMSProvider("test-key")
	require.NoError(t, err)

	assert.Equal(t, "local", provider.Provider())
}

func TestNewAWSKMSProvider(t *testing.T) {
	t.Run("returns error with empty key ID", func(t *testing.T) {
		provider, err := NewAWSKMSProvider("", "us-east-1")
		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "AWS KMS key ID is required")
	})

	t.Run("returns error with empty region", func(t *testing.T) {
		provider, err := NewAWSKMSProvider("alias/my-key", "")
		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "AWS region is required")
	})

	// Note: Full AWS KMS testing requires AWS credentials and is typically
	// done in integration tests, not unit tests
}

func TestNewVaultProvider(t *testing.T) {
	t.Run("returns error with empty address", func(t *testing.T) {
		provider, err := NewVaultProvider("", "token", "key")
		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "Vault address is required")
	})

	t.Run("returns error with empty token", func(t *testing.T) {
		provider, err := NewVaultProvider("http://localhost:8200", "", "key")
		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "Vault token is required")
	})

	t.Run("returns error with empty transit key", func(t *testing.T) {
		provider, err := NewVaultProvider("http://localhost:8200", "token", "")
		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "Vault transit key name is required")
	})

	// Note: Full Vault testing requires a running Vault server and is typically
	// done in integration tests, not unit tests
}

func TestNewKMSProvider(t *testing.T) {
	t.Run("creates local provider by default", func(t *testing.T) {
		cfg := &KMSConfig{
			Provider:          "",
			LocalMasterKeyHex: "test-key-32-bytes-long!!!!!!!!!!!",
		}

		provider, err := NewKMSProvider(cfg)
		require.NoError(t, err)
		assert.Equal(t, "local", provider.Provider())
	})

	t.Run("creates local provider when specified", func(t *testing.T) {
		cfg := &KMSConfig{
			Provider:          "local",
			LocalMasterKeyHex: "test-key-32-bytes-long!!!!!!!!!!!",
		}

		provider, err := NewKMSProvider(cfg)
		require.NoError(t, err)
		assert.Equal(t, "local", provider.Provider())
	})

	t.Run("returns error for aws-kms without key ID", func(t *testing.T) {
		cfg := &KMSConfig{
			Provider:     "aws-kms",
			AWSKMSRegion: "us-east-1",
		}

		_, err := NewKMSProvider(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AWS KMS key ID is required")
	})

	t.Run("returns error for vault without address", func(t *testing.T) {
		cfg := &KMSConfig{
			Provider:        "vault",
			VaultToken:      "token",
			VaultTransitKey: "key",
		}

		_, err := NewKMSProvider(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Vault address is required")
	})

	t.Run("returns error for unsupported provider", func(t *testing.T) {
		cfg := &KMSConfig{
			Provider: "unsupported-provider",
		}

		_, err := NewKMSProvider(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported KMS provider")
	})
}

func TestKMSProviderTypeConstants(t *testing.T) {
	assert.Equal(t, KMSProviderType("local"), KMSProviderLocal)
	assert.Equal(t, KMSProviderType("aws-kms"), KMSProviderAWSKMS)
	assert.Equal(t, KMSProviderType("vault"), KMSProviderVault)
}

func TestKMSConfig(t *testing.T) {
	t.Run("config struct initialization", func(t *testing.T) {
		cfg := &KMSConfig{
			Provider:          "local",
			LocalMasterKeyHex: "test-key",
			AWSKMSKeyID:       "alias/my-key",
			AWSKMSRegion:      "us-west-2",
			VaultAddress:      "http://localhost:8200",
			VaultToken:        "s.token",
			VaultTransitKey:   "my-key",
		}

		assert.Equal(t, "local", cfg.Provider)
		assert.Equal(t, "test-key", cfg.LocalMasterKeyHex)
		assert.Equal(t, "alias/my-key", cfg.AWSKMSKeyID)
		assert.Equal(t, "us-west-2", cfg.AWSKMSRegion)
		assert.Equal(t, "http://localhost:8200", cfg.VaultAddress)
		assert.Equal(t, "s.token", cfg.VaultToken)
		assert.Equal(t, "my-key", cfg.VaultTransitKey)
	})
}

func TestKeyMaterial(t *testing.T) {
	t.Run("struct initialization", func(t *testing.T) {
		km := &KeyMaterial{
			Address:     "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			AuthShare:   []byte("auth-share-data"),
			ExecShare:   []byte("exec-share-data"),
			Threshold:   2,
			TotalShares: 2,
		}

		assert.Equal(t, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", km.Address)
		assert.Equal(t, []byte("auth-share-data"), km.AuthShare)
		assert.Equal(t, []byte("exec-share-data"), km.ExecShare)
		assert.Equal(t, 2, km.Threshold)
		assert.Equal(t, 2, km.TotalShares)
	})
}
