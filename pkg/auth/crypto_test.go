package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateP256KeyPair(t *testing.T) {
	t.Run("generates valid key pair", func(t *testing.T) {
		privBytes, pubBytes, err := GenerateP256KeyPair()
		require.NoError(t, err)
		require.NotNil(t, privBytes)
		require.NotNil(t, pubBytes)

		// Verify private key can be parsed
		privKey, err := x509.ParseECPrivateKey(privBytes)
		require.NoError(t, err)
		assert.NotNil(t, privKey)
		assert.Equal(t, "P-256", privKey.Curve.Params().Name)

		// Verify public key can be parsed
		pubKeyI, err := x509.ParsePKIXPublicKey(pubBytes)
		require.NoError(t, err)
		pubKey, ok := pubKeyI.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, "P-256", pubKey.Curve.Params().Name)
	})

	t.Run("generates unique keys each time", func(t *testing.T) {
		priv1, pub1, err := GenerateP256KeyPair()
		require.NoError(t, err)

		priv2, pub2, err := GenerateP256KeyPair()
		require.NoError(t, err)

		// Keys should be different
		assert.NotEqual(t, priv1, priv2)
		assert.NotEqual(t, pub1, pub2)
	})
}

func TestEncryptWithHPKE(t *testing.T) {
	t.Run("encrypts data successfully", func(t *testing.T) {
		// Generate recipient key pair
		_, recipientPubKey, err := GenerateP256KeyPair()
		require.NoError(t, err)

		plaintext := []byte("Hello, HPKE!")

		enc, ciphertext, err := EncryptWithHPKE(plaintext, recipientPubKey)
		require.NoError(t, err)
		require.NotNil(t, enc)
		require.NotNil(t, ciphertext)

		// Encapsulated key should not be empty
		assert.NotEmpty(t, enc)
		// Ciphertext should not be empty
		assert.NotEmpty(t, ciphertext)
		// Ciphertext should not match plaintext
		assert.NotEqual(t, plaintext, ciphertext)
	})

	t.Run("different encryptions produce different ciphertexts", func(t *testing.T) {
		_, recipientPubKey, err := GenerateP256KeyPair()
		require.NoError(t, err)

		plaintext := []byte("Same plaintext")

		enc1, cipher1, err := EncryptWithHPKE(plaintext, recipientPubKey)
		require.NoError(t, err)

		enc2, cipher2, err := EncryptWithHPKE(plaintext, recipientPubKey)
		require.NoError(t, err)

		// Due to ephemeral keys, results should be different
		assert.NotEqual(t, enc1, enc2)
		assert.NotEqual(t, cipher1, cipher2)
	})

	t.Run("returns error for invalid public key", func(t *testing.T) {
		plaintext := []byte("Test data")
		invalidPubKey := []byte("not a valid public key")

		_, _, err := EncryptWithHPKE(plaintext, invalidPubKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse")
	})

	t.Run("handles empty plaintext", func(t *testing.T) {
		_, recipientPubKey, err := GenerateP256KeyPair()
		require.NoError(t, err)

		plaintext := []byte{}

		enc, ciphertext, err := EncryptWithHPKE(plaintext, recipientPubKey)
		require.NoError(t, err)
		assert.NotEmpty(t, enc)
		assert.NotEmpty(t, ciphertext) // Even empty plaintext produces ciphertext (tag)
	})
}

func TestDecryptWithHPKE(t *testing.T) {
	t.Run("decrypts data successfully", func(t *testing.T) {
		// Generate recipient key pair
		recipientPrivKey, recipientPubKey, err := GenerateP256KeyPair()
		require.NoError(t, err)

		plaintext := []byte("Secret message to decrypt")

		// Encrypt
		enc, ciphertext, err := EncryptWithHPKE(plaintext, recipientPubKey)
		require.NoError(t, err)

		// Decrypt
		decrypted, err := DecryptWithHPKE(ciphertext, enc, recipientPrivKey)
		require.NoError(t, err)

		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("decrypts empty plaintext", func(t *testing.T) {
		recipientPrivKey, recipientPubKey, err := GenerateP256KeyPair()
		require.NoError(t, err)

		plaintext := []byte{}

		enc, ciphertext, err := EncryptWithHPKE(plaintext, recipientPubKey)
		require.NoError(t, err)

		decrypted, err := DecryptWithHPKE(ciphertext, enc, recipientPrivKey)
		require.NoError(t, err)
		assert.Len(t, decrypted, 0)
	})

	t.Run("returns error for wrong private key", func(t *testing.T) {
		_, recipientPubKey, err := GenerateP256KeyPair()
		require.NoError(t, err)

		// Generate a different key pair for decryption
		wrongPrivKey, _, err := GenerateP256KeyPair()
		require.NoError(t, err)

		plaintext := []byte("Test data")

		enc, ciphertext, err := EncryptWithHPKE(plaintext, recipientPubKey)
		require.NoError(t, err)

		// Try to decrypt with wrong key
		_, err = DecryptWithHPKE(ciphertext, enc, wrongPrivKey)
		assert.Error(t, err)
	})

	t.Run("returns error for invalid private key", func(t *testing.T) {
		_, recipientPubKey, err := GenerateP256KeyPair()
		require.NoError(t, err)

		plaintext := []byte("Test data")
		enc, ciphertext, err := EncryptWithHPKE(plaintext, recipientPubKey)
		require.NoError(t, err)

		invalidPrivKey := []byte("invalid")
		_, err = DecryptWithHPKE(ciphertext, enc, invalidPrivKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse")
	})

	t.Run("returns error for corrupted ciphertext", func(t *testing.T) {
		recipientPrivKey, recipientPubKey, err := GenerateP256KeyPair()
		require.NoError(t, err)

		plaintext := []byte("Test data")

		enc, ciphertext, err := EncryptWithHPKE(plaintext, recipientPubKey)
		require.NoError(t, err)

		// Corrupt the ciphertext
		ciphertext[len(ciphertext)-1] ^= 0xFF

		_, err = DecryptWithHPKE(ciphertext, enc, recipientPrivKey)
		assert.Error(t, err)
	})
}

func TestHPKERoundtrip(t *testing.T) {
	// Test complete roundtrip with various data sizes
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"small", []byte("Hello, World!")},
		{"medium", make([]byte, 1000)},
		{"large", make([]byte, 100000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill non-empty test data with random bytes
			if len(tc.data) > 0 && tc.data[0] == 0 {
				rand.Read(tc.data)
			}

			recipientPrivKey, recipientPubKey, err := GenerateP256KeyPair()
			require.NoError(t, err)

			enc, ciphertext, err := EncryptWithHPKE(tc.data, recipientPubKey)
			require.NoError(t, err)

			decrypted, err := DecryptWithHPKE(ciphertext, enc, recipientPrivKey)
			require.NoError(t, err)

			// For empty data, check length instead of equality (nil vs empty slice)
			if len(tc.data) == 0 {
				assert.Len(t, decrypted, 0)
			} else {
				assert.Equal(t, tc.data, decrypted)
			}
		})
	}
}

func TestPublicKeyToPEM(t *testing.T) {
	t.Run("converts raw P-256 public key to PEM", func(t *testing.T) {
		// Generate a key pair
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecdhPub, err := privKey.PublicKey.ECDH()
		require.NoError(t, err)
		rawPubKey := ecdhPub.Bytes()

		// Convert to PEM
		pemKey, err := PublicKeyToPEM(rawPubKey)
		require.NoError(t, err)
		assert.NotEmpty(t, pemKey)
		assert.Contains(t, pemKey, "-----BEGIN PUBLIC KEY-----")
		assert.Contains(t, pemKey, "-----END PUBLIC KEY-----")

		// Verify the PEM can be parsed back
		pubKey, err := parsePublicKey(pemKey)
		require.NoError(t, err)
		assert.Equal(t, privKey.PublicKey.X, pubKey.X)
		assert.Equal(t, privKey.PublicKey.Y, pubKey.Y)
	})

	t.Run("returns error for invalid raw key", func(t *testing.T) {
		invalidKey := []byte("not a valid key")

		_, err := PublicKeyToPEM(invalidKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse public key")
	})

	t.Run("returns error for truncated key", func(t *testing.T) {
		// P-256 uncompressed public key should be 65 bytes
		truncatedKey := make([]byte, 32)

		_, err := PublicKeyToPEM(truncatedKey)
		assert.Error(t, err)
	})
}

func TestVerifySignatureWithRawSignature(t *testing.T) {
	verifier := NewSignatureVerifier()
	privKey, pubKey := generateTestKeyPair(t)

	payload := []byte(`{"version":"v1","method":"POST"}`)

	t.Run("verifies ASN1/DER encoded signature", func(t *testing.T) {
		// SignPayload produces DER-encoded signature
		signature, err := SignPayload(payload, privKey)
		require.NoError(t, err)

		verified, err := verifier.VerifySignature(signature, payload, pubKey)
		require.NoError(t, err)
		assert.True(t, verified)
	})

	t.Run("returns error for invalid base64 signature", func(t *testing.T) {
		_, err := verifier.VerifySignature("not-valid-base64!!!", payload, pubKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decode signature")
	})

	t.Run("returns error for invalid public key PEM", func(t *testing.T) {
		signature, err := SignPayload(payload, privKey)
		require.NoError(t, err)

		_, err = verifier.VerifySignature(signature, payload, "invalid-pem")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse public key")
	})
}

func TestVerifyMultiSignatureErrors(t *testing.T) {
	verifier := NewSignatureVerifier()

	t.Run("returns error for no signatures", func(t *testing.T) {
		payload := []byte("test")
		keys := []KeyQuorumKey{}

		_, err := verifier.VerifyMultiSignature([]string{}, payload, keys, 1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no signatures provided")
	})

	t.Run("returns error for invalid threshold", func(t *testing.T) {
		payload := []byte("test")
		keys := []KeyQuorumKey{}

		_, err := verifier.VerifyMultiSignature([]string{"sig"}, payload, keys, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid threshold")

		_, err = verifier.VerifyMultiSignature([]string{"sig"}, payload, keys, -1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid threshold")
	})
}

func TestVerifyOwnerSignatureErrors(t *testing.T) {
	verifier := NewSignatureVerifier()
	payload := []byte("test")

	t.Run("returns error for unsupported owner type", func(t *testing.T) {
		owner := &Owner{
			Type: OwnerType("unknown"),
		}

		err := verifier.VerifyOwnerSignature([]string{"sig"}, payload, owner)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported owner type")
	})
}

func TestOwnerTypeConstants(t *testing.T) {
	assert.Equal(t, OwnerType("single_key"), OwnerTypeSingleKey)
	assert.Equal(t, OwnerType("key_quorum"), OwnerTypeKeyQuorum)
	assert.Equal(t, OwnerType("user"), OwnerTypeUser)
}
