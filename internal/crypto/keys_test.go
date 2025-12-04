package crypto

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateEthereumKey(t *testing.T) {
	t.Run("generates valid key", func(t *testing.T) {
		key, err := GenerateEthereumKey()
		require.NoError(t, err)
		require.NotNil(t, key)

		// Verify it's a valid secp256k1 key
		assert.NotNil(t, key.D)
		assert.NotNil(t, key.X)
		assert.NotNil(t, key.Y)
	})

	t.Run("generates unique keys", func(t *testing.T) {
		key1, err := GenerateEthereumKey()
		require.NoError(t, err)

		key2, err := GenerateEthereumKey()
		require.NoError(t, err)

		// Keys should be different
		assert.NotEqual(t, key1.D.Bytes(), key2.D.Bytes())
	})
}

func TestGetEthereumAddress(t *testing.T) {
	t.Run("derives valid address", func(t *testing.T) {
		key, err := GenerateEthereumKey()
		require.NoError(t, err)

		address := GetEthereumAddress(key)

		// Address should be 20 bytes
		assert.Len(t, address.Bytes(), 20)
		// Address should not be zero
		assert.NotEqual(t, common.Address{}, address)
	})

	t.Run("same key produces same address", func(t *testing.T) {
		key, err := GenerateEthereumKey()
		require.NoError(t, err)

		addr1 := GetEthereumAddress(key)
		addr2 := GetEthereumAddress(key)

		assert.Equal(t, addr1, addr2)
	})

	t.Run("different keys produce different addresses", func(t *testing.T) {
		key1, err := GenerateEthereumKey()
		require.NoError(t, err)

		key2, err := GenerateEthereumKey()
		require.NoError(t, err)

		addr1 := GetEthereumAddress(key1)
		addr2 := GetEthereumAddress(key2)

		assert.NotEqual(t, addr1, addr2)
	})
}

func TestPrivateKeyToBytes(t *testing.T) {
	t.Run("converts key to bytes", func(t *testing.T) {
		key, err := GenerateEthereumKey()
		require.NoError(t, err)

		bytes := PrivateKeyToBytes(key)

		// Private key should be 32 bytes
		assert.Len(t, bytes, 32)
		// Should not be all zeros
		assert.NotEqual(t, make([]byte, 32), bytes)
	})

	t.Run("same key produces same bytes", func(t *testing.T) {
		key, err := GenerateEthereumKey()
		require.NoError(t, err)

		bytes1 := PrivateKeyToBytes(key)
		bytes2 := PrivateKeyToBytes(key)

		assert.Equal(t, bytes1, bytes2)
	})
}

func TestBytesToPrivateKey(t *testing.T) {
	t.Run("converts bytes to key", func(t *testing.T) {
		originalKey, err := GenerateEthereumKey()
		require.NoError(t, err)

		keyBytes := PrivateKeyToBytes(originalKey)
		restoredKey, err := BytesToPrivateKey(keyBytes)
		require.NoError(t, err)

		// Keys should be equal
		assert.Equal(t, originalKey.D.Bytes(), restoredKey.D.Bytes())
	})

	t.Run("invalid bytes return error", func(t *testing.T) {
		// Too short
		_, err := BytesToPrivateKey([]byte{1, 2, 3})
		assert.Error(t, err)

		// Zero key (invalid)
		_, err = BytesToPrivateKey(make([]byte, 32))
		assert.Error(t, err)
	})

	t.Run("roundtrip preserves address", func(t *testing.T) {
		originalKey, err := GenerateEthereumKey()
		require.NoError(t, err)

		originalAddr := GetEthereumAddress(originalKey)

		keyBytes := PrivateKeyToBytes(originalKey)
		restoredKey, err := BytesToPrivateKey(keyBytes)
		require.NoError(t, err)

		restoredAddr := GetEthereumAddress(restoredKey)

		assert.Equal(t, originalAddr, restoredAddr)
	})
}

func TestKeyRoundtrip(t *testing.T) {
	// Test the complete roundtrip: generate -> to bytes -> from bytes -> derive address
	key, err := GenerateEthereumKey()
	require.NoError(t, err)

	originalAddress := GetEthereumAddress(key)

	// Convert to bytes and back
	keyBytes := PrivateKeyToBytes(key)
	restoredKey, err := BytesToPrivateKey(keyBytes)
	require.NoError(t, err)

	restoredAddress := GetEthereumAddress(restoredKey)

	// Addresses should match
	assert.Equal(t, originalAddress.Hex(), restoredAddress.Hex())
}

func TestKeyTypeAssertion(t *testing.T) {
	key, err := GenerateEthereumKey()
	require.NoError(t, err)

	// Verify the key's public key can be cast to *ecdsa.PublicKey
	pubKey := key.Public()
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.NotNil(t, ecdsaPubKey)
}
