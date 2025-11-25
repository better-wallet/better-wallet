package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHPKEEncryptDecrypt(t *testing.T) {
	// Generate recipient key pair
	privKey, pubKey, err := GenerateRecipientKeyPair()
	require.NoError(t, err)

	// Encode public key to base64
	pubKeyBytes := pubKey.Bytes()
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// Test data
	plaintext := []byte("this is a secret private key: 0x1234567890abcdef")

	// Encrypt
	encrypted, err := EncryptWithHPKE(pubKeyB64, plaintext)
	require.NoError(t, err)
	assert.Equal(t, "HPKE", encrypted.EncryptionType)
	assert.NotEmpty(t, encrypted.Ciphertext)
	assert.NotEmpty(t, encrypted.EncapsulatedKey)

	// Decrypt
	decrypted, err := DecryptWithHPKE(privKey, encrypted.EncapsulatedKey, encrypted.Ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestHPKEEncryptInvalidPublicKey(t *testing.T) {
	// Invalid base64
	_, err := EncryptWithHPKE("invalid-base64!@#", []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode recipient public key")

	// Valid base64 but invalid key format
	invalidKey := base64.StdEncoding.EncodeToString([]byte("not a valid key"))
	_, err = EncryptWithHPKE(invalidKey, []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse recipient public key")
}

func TestHPKEDecryptInvalidData(t *testing.T) {
	privKey, _, err := GenerateRecipientKeyPair()
	require.NoError(t, err)

	// Invalid encapsulated key
	_, err = DecryptWithHPKE(privKey, "invalid-base64!@#", "validbase64==")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode encapsulated key")

	// Invalid ciphertext
	validB64 := base64.StdEncoding.EncodeToString([]byte("test"))
	_, err = DecryptWithHPKE(privKey, validB64, "invalid-base64!@#")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode ciphertext")
}

func TestHPKEEncryptionDeterminism(t *testing.T) {
	// Generate recipient key pair
	_, pubKey, err := GenerateRecipientKeyPair()
	require.NoError(t, err)

	pubKeyBytes := pubKey.Bytes()
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	plaintext := []byte("test message")

	// Encrypt twice
	encrypted1, err := EncryptWithHPKE(pubKeyB64, plaintext)
	require.NoError(t, err)

	encrypted2, err := EncryptWithHPKE(pubKeyB64, plaintext)
	require.NoError(t, err)

	// HPKE should produce different ciphertexts due to random ephemeral keys
	assert.NotEqual(t, encrypted1.Ciphertext, encrypted2.Ciphertext)
	assert.NotEqual(t, encrypted1.EncapsulatedKey, encrypted2.EncapsulatedKey)
}
