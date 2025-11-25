package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestKeyPair generates a P-256 key pair for testing
func generateTestKeyPair(t *testing.T) (privateKeyPEM, publicKeyPEM string) {
	// Generate private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Encode private key
	privBytes, err := x509.MarshalECPrivateKey(privKey)
	require.NoError(t, err)

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	// Encode public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return string(privPEM), string(pubPEM)
}

func TestVerifySignature(t *testing.T) {
	verifier := NewSignatureVerifier()
	privKey, pubKey := generateTestKeyPair(t)

	payload := []byte(`{"version":"v1","method":"POST","url":"https://api.example.com/v1/wallets"}`)

	// Sign the payload
	signature, err := SignPayload(payload, privKey)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Verify the signature
	verified, err := verifier.VerifySignature(signature, payload, pubKey)
	require.NoError(t, err)
	assert.True(t, verified)

	// Verify with wrong payload should fail
	wrongPayload := []byte(`{"version":"v1","method":"GET"}`)
	verified, err = verifier.VerifySignature(signature, wrongPayload, pubKey)
	require.NoError(t, err)
	assert.False(t, verified)
}

func TestVerifyMultiSignature(t *testing.T) {
	verifier := NewSignatureVerifier()

	// Generate 3 key pairs
	priv1, pub1 := generateTestKeyPair(t)
	priv2, pub2 := generateTestKeyPair(t)
	priv3, pub3 := generateTestKeyPair(t)

	keys := []KeyQuorumKey{
		{ID: uuid.New(), PublicKey: pub1},
		{ID: uuid.New(), PublicKey: pub2},
		{ID: uuid.New(), PublicKey: pub3},
	}

	payload := []byte(`{"version":"v1","method":"POST"}`)

	tests := []struct {
		name           string
		signers        []string // private keys to sign with
		threshold      int
		expectedValid  int
		shouldMeetQuorum bool
	}{
		{
			name:           "2 of 3 threshold met",
			signers:        []string{priv1, priv2},
			threshold:      2,
			expectedValid:  2,
			shouldMeetQuorum: true,
		},
		{
			name:           "2 of 3 threshold not met",
			signers:        []string{priv1},
			threshold:      2,
			expectedValid:  1,
			shouldMeetQuorum: false,
		},
		{
			name:           "all signatures",
			signers:        []string{priv1, priv2, priv3},
			threshold:      3,
			expectedValid:  3,
			shouldMeetQuorum: true,
		},
		{
			name:           "1 of 3 threshold",
			signers:        []string{priv1},
			threshold:      1,
			expectedValid:  1,
			shouldMeetQuorum: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate signatures
			signatures := make([]string, 0, len(tt.signers))
			for _, privKey := range tt.signers {
				sig, err := SignPayload(payload, privKey)
				require.NoError(t, err)
				signatures = append(signatures, sig)
			}

			// Verify multi-signature
			validCount, err := verifier.VerifyMultiSignature(signatures, payload, keys, tt.threshold)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedValid, validCount)

			// Verify key quorum
			err = verifier.VerifyKeyQuorum(signatures, payload, keys, tt.threshold)
			if tt.shouldMeetQuorum {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "insufficient signatures")
			}
		})
	}
}

func TestVerifyOwnerSignature(t *testing.T) {
	verifier := NewSignatureVerifier()
	payload := []byte(`{"version":"v1","method":"POST"}`)

	t.Run("single key owner", func(t *testing.T) {
		privKey, pubKey := generateTestKeyPair(t)

		owner := &Owner{
			Type:      OwnerTypeSingleKey,
			PublicKey: pubKey,
		}

		// Sign
		sig, err := SignPayload(payload, privKey)
		require.NoError(t, err)

		// Verify
		err = verifier.VerifyOwnerSignature([]string{sig}, payload, owner)
		assert.NoError(t, err)

		// Wrong payload
		wrongPayload := []byte(`{"version":"v1","method":"GET"}`)
		err = verifier.VerifyOwnerSignature([]string{sig}, wrongPayload, owner)
		assert.Error(t, err)
	})

	t.Run("key quorum owner", func(t *testing.T) {
		priv1, pub1 := generateTestKeyPair(t)
		priv2, pub2 := generateTestKeyPair(t)
		_, pub3 := generateTestKeyPair(t)

		owner := &Owner{
			Type: OwnerTypeKeyQuorum,
			QuorumKeys: []KeyQuorumKey{
				{ID: uuid.New(), PublicKey: pub1},
				{ID: uuid.New(), PublicKey: pub2},
				{ID: uuid.New(), PublicKey: pub3},
			},
			QuorumThreshold: 2,
		}

		// Sign with 2 keys (meets threshold)
		sig1, err := SignPayload(payload, priv1)
		require.NoError(t, err)
		sig2, err := SignPayload(payload, priv2)
		require.NoError(t, err)

		err = verifier.VerifyOwnerSignature([]string{sig1, sig2}, payload, owner)
		assert.NoError(t, err)

		// Sign with only 1 key (doesn't meet threshold)
		err = verifier.VerifyOwnerSignature([]string{sig1}, payload, owner)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient signatures")
	})

	t.Run("no signatures", func(t *testing.T) {
		_, pubKey := generateTestKeyPair(t)

		owner := &Owner{
			Type:      OwnerTypeSingleKey,
			PublicKey: pubKey,
		}

		err := verifier.VerifyOwnerSignature([]string{}, payload, owner)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no signatures provided")
	})
}

func TestParsePublicKey(t *testing.T) {
	t.Run("valid P-256 public key", func(t *testing.T) {
		_, pubKeyPEM := generateTestKeyPair(t)

		pubKey, err := parsePublicKey(pubKeyPEM)
		require.NoError(t, err)
		assert.NotNil(t, pubKey)
		assert.Equal(t, "P-256", pubKey.Curve.Params().Name)
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := parsePublicKey("not a valid pem")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("invalid public key format", func(t *testing.T) {
		invalidPEM := `-----BEGIN PUBLIC KEY-----
invalid base64 data
-----END PUBLIC KEY-----`
		_, err := parsePublicKey(invalidPEM)
		assert.Error(t, err)
	})
}

func TestSignPayload(t *testing.T) {
	privKey, _ := generateTestKeyPair(t)
	payload := []byte(`{"test":"data"}`)

	t.Run("valid signing", func(t *testing.T) {
		sig, err := SignPayload(payload, privKey)
		require.NoError(t, err)
		assert.NotEmpty(t, sig)

		// Signature should be base64-encoded
		// Minimum length for P-256 signature
		assert.Greater(t, len(sig), 50)
	})

	t.Run("invalid private key", func(t *testing.T) {
		_, err := SignPayload(payload, "invalid")
		assert.Error(t, err)
	})
}

func TestKeyQuorumKeyUniqueness(t *testing.T) {
	// Verify that the same key is not used twice in multi-sig
	verifier := NewSignatureVerifier()
	privKey, pubKey := generateTestKeyPair(t)

	keys := []KeyQuorumKey{
		{ID: uuid.New(), PublicKey: pubKey},
		{ID: uuid.New(), PublicKey: pubKey}, // Same key, different ID
	}

	payload := []byte(`{"test":"data"}`)

	// Sign once
	sig, err := SignPayload(payload, privKey)
	require.NoError(t, err)

	// Even though we have 2 entries with the same key,
	// only 1 should count as valid
	validCount, err := verifier.VerifyMultiSignature(
		[]string{sig},
		payload,
		keys,
		1,
	)
	require.NoError(t, err)

	// Should only count as 1 valid signature
	assert.Equal(t, 1, validCount)
}
