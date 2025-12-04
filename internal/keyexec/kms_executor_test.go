package keyexec

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKMSExecutor(t *testing.T) {
	t.Run("creates executor with local provider", func(t *testing.T) {
		cfg := &KMSConfig{
			Provider:          "local",
			LocalMasterKeyHex: "test-master-key-32-bytes-long!!",
		}

		executor, err := NewKMSExecutor(cfg)
		require.NoError(t, err)
		require.NotNil(t, executor)
		assert.Equal(t, "local", executor.Provider())
	})

	t.Run("creates executor with default provider", func(t *testing.T) {
		cfg := &KMSConfig{
			LocalMasterKeyHex: "test-master-key-32-bytes-long!!",
		}

		executor, err := NewKMSExecutor(cfg)
		require.NoError(t, err)
		require.NotNil(t, executor)
		assert.Equal(t, "local", executor.Provider())
	})

	t.Run("returns error for unsupported provider", func(t *testing.T) {
		cfg := &KMSConfig{
			Provider: "invalid-provider",
		}

		executor, err := NewKMSExecutor(cfg)
		assert.Error(t, err)
		assert.Nil(t, executor)
		assert.Contains(t, err.Error(), "unsupported KMS provider")
	})

	t.Run("returns error for aws-kms without key ID", func(t *testing.T) {
		cfg := &KMSConfig{
			Provider:     "aws-kms",
			AWSKMSRegion: "us-east-1",
		}

		executor, err := NewKMSExecutor(cfg)
		assert.Error(t, err)
		assert.Nil(t, executor)
	})

	t.Run("returns error for vault without address", func(t *testing.T) {
		cfg := &KMSConfig{
			Provider:        "vault",
			VaultToken:      "token",
			VaultTransitKey: "key",
		}

		executor, err := NewKMSExecutor(cfg)
		assert.Error(t, err)
		assert.Nil(t, executor)
	})
}

func TestKMSExecutor_GenerateAndSplitKey(t *testing.T) {
	cfg := &KMSConfig{
		Provider:          "local",
		LocalMasterKeyHex: "test-master-key-32-bytes-long!!",
	}

	executor, err := NewKMSExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("generates key material", func(t *testing.T) {
		keyMaterial, err := executor.GenerateAndSplitKey(ctx)
		require.NoError(t, err)
		require.NotNil(t, keyMaterial)

		// Verify address is valid Ethereum address
		assert.True(t, common.IsHexAddress(keyMaterial.Address))

		// Verify shares are populated
		assert.NotEmpty(t, keyMaterial.AuthShare)
		assert.NotEmpty(t, keyMaterial.ExecShare)

		// Verify threshold and total shares
		assert.Equal(t, 2, keyMaterial.Threshold)
		assert.Equal(t, 2, keyMaterial.TotalShares)
	})

	t.Run("generates unique keys", func(t *testing.T) {
		km1, err := executor.GenerateAndSplitKey(ctx)
		require.NoError(t, err)

		km2, err := executor.GenerateAndSplitKey(ctx)
		require.NoError(t, err)

		// Addresses should be different
		assert.NotEqual(t, km1.Address, km2.Address)
	})
}

func TestKMSExecutor_SignTransaction(t *testing.T) {
	cfg := &KMSConfig{
		Provider:          "local",
		LocalMasterKeyHex: "test-master-key-32-bytes-long!!",
	}

	executor, err := NewKMSExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("signs transaction successfully", func(t *testing.T) {
		keyMaterial, err := executor.GenerateAndSplitKey(ctx)
		require.NoError(t, err)

		// Create a transaction
		to := common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(1),
			Nonce:     0,
			GasTipCap: big.NewInt(1000000000),
			GasFeeCap: big.NewInt(2000000000),
			Gas:       21000,
			To:        &to,
			Value:     big.NewInt(1000000000000000000),
			Data:      nil,
		})

		signedTx, err := executor.SignTransaction(ctx, keyMaterial, tx, 1)
		require.NoError(t, err)
		require.NotNil(t, signedTx)

		// Verify signature is present
		v, r, s := signedTx.RawSignatureValues()
		assert.NotNil(t, v)
		assert.NotNil(t, r)
		assert.NotNil(t, s)

		// Recover signer address and verify it matches
		signer := types.NewLondonSigner(big.NewInt(1))
		from, err := types.Sender(signer, signedTx)
		require.NoError(t, err)
		assert.Equal(t, keyMaterial.Address, from.Hex())
	})

	t.Run("returns error for invalid shares", func(t *testing.T) {
		invalidKeyMaterial := &KeyMaterial{
			Address:     "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			AuthShare:   []byte("invalid-share"),
			ExecShare:   []byte("invalid-share"),
			Threshold:   2,
			TotalShares: 2,
		}

		to := common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(1),
			Nonce:     0,
			GasTipCap: big.NewInt(1000000000),
			GasFeeCap: big.NewInt(2000000000),
			Gas:       21000,
			To:        &to,
			Value:     big.NewInt(1000000000000000000),
		})

		_, err := executor.SignTransaction(ctx, invalidKeyMaterial, tx, 1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to reconstruct key")
	})
}

func TestKMSExecutor_SignMessage(t *testing.T) {
	cfg := &KMSConfig{
		Provider:          "local",
		LocalMasterKeyHex: "test-master-key-32-bytes-long!!",
	}

	executor, err := NewKMSExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("signs message successfully", func(t *testing.T) {
		keyMaterial, err := executor.GenerateAndSplitKey(ctx)
		require.NoError(t, err)

		message := []byte("Hello, World!")
		signature, err := executor.SignMessage(ctx, keyMaterial, message)
		require.NoError(t, err)
		require.NotNil(t, signature)

		// Ethereum signature is 65 bytes (r, s, v)
		assert.Len(t, signature, 65)
	})

	t.Run("signs empty message", func(t *testing.T) {
		keyMaterial, err := executor.GenerateAndSplitKey(ctx)
		require.NoError(t, err)

		message := []byte{}
		signature, err := executor.SignMessage(ctx, keyMaterial, message)
		require.NoError(t, err)
		assert.Len(t, signature, 65)
	})

	t.Run("same message produces same signature with same key", func(t *testing.T) {
		keyMaterial, err := executor.GenerateAndSplitKey(ctx)
		require.NoError(t, err)

		message := []byte("Test message")
		sig1, err := executor.SignMessage(ctx, keyMaterial, message)
		require.NoError(t, err)

		sig2, err := executor.SignMessage(ctx, keyMaterial, message)
		require.NoError(t, err)

		// Signatures should be equal (deterministic signing)
		assert.Equal(t, sig1, sig2)
	})

	t.Run("returns error for invalid shares", func(t *testing.T) {
		invalidKeyMaterial := &KeyMaterial{
			Address:     "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			AuthShare:   []byte("invalid-share"),
			ExecShare:   []byte("invalid-share"),
			Threshold:   2,
			TotalShares: 2,
		}

		message := []byte("Test message")
		_, err := executor.SignMessage(ctx, invalidKeyMaterial, message)
		assert.Error(t, err)
	})
}

func TestKMSExecutor_SignHash(t *testing.T) {
	cfg := &KMSConfig{
		Provider:          "local",
		LocalMasterKeyHex: "test-master-key-32-bytes-long!!",
	}

	executor, err := NewKMSExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("signs 32-byte hash successfully", func(t *testing.T) {
		keyMaterial, err := executor.GenerateAndSplitKey(ctx)
		require.NoError(t, err)

		// Create a 32-byte hash
		hash := make([]byte, 32)
		for i := range hash {
			hash[i] = byte(i)
		}

		signature, err := executor.SignHash(ctx, keyMaterial, hash)
		require.NoError(t, err)
		assert.Len(t, signature, 65)
	})

	t.Run("returns error for non-32-byte hash", func(t *testing.T) {
		keyMaterial, err := executor.GenerateAndSplitKey(ctx)
		require.NoError(t, err)

		shortHash := make([]byte, 16)
		_, err = executor.SignHash(ctx, keyMaterial, shortHash)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "hash must be exactly 32 bytes")

		longHash := make([]byte, 64)
		_, err = executor.SignHash(ctx, keyMaterial, longHash)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "hash must be exactly 32 bytes")
	})

	t.Run("returns error for invalid shares", func(t *testing.T) {
		invalidKeyMaterial := &KeyMaterial{
			Address:     "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			AuthShare:   []byte("invalid"),
			ExecShare:   []byte("invalid"),
			Threshold:   2,
			TotalShares: 2,
		}

		hash := make([]byte, 32)
		_, err := executor.SignHash(ctx, invalidKeyMaterial, hash)
		assert.Error(t, err)
	})
}

func TestKMSExecutor_EncryptDecrypt(t *testing.T) {
	cfg := &KMSConfig{
		Provider:          "local",
		LocalMasterKeyHex: "test-master-key-32-bytes-long!!",
	}

	executor, err := NewKMSExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("encrypts and decrypts data", func(t *testing.T) {
		plaintext := []byte("Hello, secret world!")

		ciphertext, err := executor.Encrypt(ctx, plaintext)
		require.NoError(t, err)
		assert.NotEmpty(t, ciphertext)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := executor.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypts and decrypts empty data", func(t *testing.T) {
		plaintext := []byte{}

		ciphertext, err := executor.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		decrypted, err := executor.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Len(t, decrypted, 0)
	})

	t.Run("different encryptions produce different ciphertexts", func(t *testing.T) {
		plaintext := []byte("Same data")

		cipher1, err := executor.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		cipher2, err := executor.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		// Due to random nonce, ciphertexts should differ
		assert.NotEqual(t, cipher1, cipher2)
	})
}

func TestKMSExecutor_Provider(t *testing.T) {
	cfg := &KMSConfig{
		Provider:          "local",
		LocalMasterKeyHex: "test-master-key-32-bytes-long!!",
	}

	executor, err := NewKMSExecutor(cfg)
	require.NoError(t, err)

	assert.Equal(t, "local", executor.Provider())
}

func TestKMSExecutor_zeroKey(t *testing.T) {
	cfg := &KMSConfig{
		Provider:          "local",
		LocalMasterKeyHex: "test-master-key-32-bytes-long!!",
	}

	executor, err := NewKMSExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Generate a key and then zero it
	keyMaterial, err := executor.GenerateAndSplitKey(ctx)
	require.NoError(t, err)

	// Reconstruct the key (internal method, tested through signing)
	// The zeroKey method is called via defer in signing methods
	// This test ensures the executor doesn't panic when zeroing keys
	message := []byte("Test")
	_, err = executor.SignMessage(ctx, keyMaterial, message)
	require.NoError(t, err)
}
