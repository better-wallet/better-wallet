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

func TestGenerateRecipientKeyPair(t *testing.T) {
	t.Run("generates valid P-256 key pair", func(t *testing.T) {
		privKey, pubKey, err := GenerateRecipientKeyPair()
		require.NoError(t, err)
		require.NotNil(t, privKey)
		require.NotNil(t, pubKey)

		// Verify keys are related
		assert.Equal(t, privKey.PublicKey(), pubKey)
	})

	t.Run("generates unique keys each time", func(t *testing.T) {
		priv1, pub1, err := GenerateRecipientKeyPair()
		require.NoError(t, err)

		priv2, pub2, err := GenerateRecipientKeyPair()
		require.NoError(t, err)

		// Keys should be different
		assert.NotEqual(t, priv1.Bytes(), priv2.Bytes())
		assert.NotEqual(t, pub1.Bytes(), pub2.Bytes())
	})
}

func TestHPKEWithPEMPublicKey(t *testing.T) {
	// Test with PEM-encoded public key
	privKey, pubKey, err := GenerateRecipientKeyPair()
	require.NoError(t, err)

	// Create PEM-encoded public key
	pubKeyBytes := pubKey.Bytes()
	pemBlock := "-----BEGIN PUBLIC KEY-----\n" +
		base64.StdEncoding.EncodeToString(pubKeyBytes) +
		"\n-----END PUBLIC KEY-----"
	pemB64 := base64.StdEncoding.EncodeToString([]byte(pemBlock))

	plaintext := []byte("test with PEM")

	// Encrypt with PEM key
	encrypted, err := EncryptWithHPKE(pemB64, plaintext)
	require.NoError(t, err)

	// Decrypt
	decrypted, err := DecryptWithHPKE(privKey, encrypted.EncapsulatedKey, encrypted.Ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestHPKEWithVariousDataSizes(t *testing.T) {
	privKey, pubKey, err := GenerateRecipientKeyPair()
	require.NoError(t, err)

	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey.Bytes())

	testCases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"tiny", 1},
		{"small", 100},
		{"medium", 10000},
		{"large", 100000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := make([]byte, tc.size)
			// Fill with pattern
			for i := range plaintext {
				plaintext[i] = byte(i % 256)
			}

			encrypted, err := EncryptWithHPKE(pubKeyB64, plaintext)
			require.NoError(t, err)

			decrypted, err := DecryptWithHPKE(privKey, encrypted.EncapsulatedKey, encrypted.Ciphertext)
			require.NoError(t, err)

			if tc.size == 0 {
				assert.Len(t, decrypted, 0)
			} else {
				assert.Equal(t, plaintext, decrypted)
			}
		})
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	// Generate recipient key pair
	privKey, pubKey, err := GenerateRecipientKeyPair()
	require.NoError(t, err)

	// Generate another key pair
	wrongPrivKey, _, err := GenerateRecipientKeyPair()
	require.NoError(t, err)

	// Ensure keys are different
	require.NotEqual(t, privKey.Bytes(), wrongPrivKey.Bytes())

	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey.Bytes())

	plaintext := []byte("secret message")

	// Encrypt with first public key
	encrypted, err := EncryptWithHPKE(pubKeyB64, plaintext)
	require.NoError(t, err)

	// Try to decrypt with wrong private key
	_, err = DecryptWithHPKE(wrongPrivKey, encrypted.EncapsulatedKey, encrypted.Ciphertext)
	assert.Error(t, err)
}

func TestDecryptWithCorruptedData(t *testing.T) {
	privKey, pubKey, err := GenerateRecipientKeyPair()
	require.NoError(t, err)

	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey.Bytes())

	plaintext := []byte("test data")

	encrypted, err := EncryptWithHPKE(pubKeyB64, plaintext)
	require.NoError(t, err)

	t.Run("corrupted ciphertext", func(t *testing.T) {
		// Decode, corrupt, and re-encode
		cipherBytes, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
		require.NoError(t, err)

		if len(cipherBytes) > 0 {
			cipherBytes[len(cipherBytes)-1] ^= 0xFF
		}

		corruptedB64 := base64.StdEncoding.EncodeToString(cipherBytes)

		_, err = DecryptWithHPKE(privKey, encrypted.EncapsulatedKey, corruptedB64)
		assert.Error(t, err)
	})

	t.Run("corrupted encapsulated key", func(t *testing.T) {
		encKeyBytes, err := base64.StdEncoding.DecodeString(encrypted.EncapsulatedKey)
		require.NoError(t, err)

		if len(encKeyBytes) > 0 {
			encKeyBytes[0] ^= 0xFF
		}

		corruptedEncB64 := base64.StdEncoding.EncodeToString(encKeyBytes)

		_, err = DecryptWithHPKE(privKey, corruptedEncB64, encrypted.Ciphertext)
		assert.Error(t, err)
	})
}

func TestHPKEEncryptedDataStruct(t *testing.T) {
	t.Run("struct initialization", func(t *testing.T) {
		data := HPKEEncryptedData{
			Ciphertext:      "base64-ciphertext",
			EncapsulatedKey: "base64-enc-key",
			EncryptionType:  "HPKE",
		}

		assert.Equal(t, "base64-ciphertext", data.Ciphertext)
		assert.Equal(t, "base64-enc-key", data.EncapsulatedKey)
		assert.Equal(t, "HPKE", data.EncryptionType)
	})
}

func TestDecryptWithTruncatedCiphertext(t *testing.T) {
	privKey, pubKey, err := GenerateRecipientKeyPair()
	require.NoError(t, err)

	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey.Bytes())

	plaintext := []byte("test data that is long enough to truncate")

	encrypted, err := EncryptWithHPKE(pubKeyB64, plaintext)
	require.NoError(t, err)

	// Truncate ciphertext to be too short
	cipherBytes, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	require.NoError(t, err)

	if len(cipherBytes) > 5 {
		truncatedB64 := base64.StdEncoding.EncodeToString(cipherBytes[:5])
		_, err = DecryptWithHPKE(privKey, encrypted.EncapsulatedKey, truncatedB64)
		assert.Error(t, err)
	}
}
