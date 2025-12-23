package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/google/uuid"
)

// SignatureVerifier handles signature verification for authorization
type SignatureVerifier struct{}

// NewSignatureVerifier creates a new signature verifier
func NewSignatureVerifier() *SignatureVerifier {
	return &SignatureVerifier{}
}

// VerifySignature verifies a single P-256 ECDSA signature
// signature: base64-encoded signature (DER or raw r||s format)
// payload: the canonical payload bytes to verify
// publicKeyPEM: PEM-encoded P-256 public key
func (v *SignatureVerifier) VerifySignature(
	signature string,
	payload []byte,
	publicKeyPEM string,
) (bool, error) {
	// Decode base64 signature
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Parse public key
	pubKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Hash the payload (SHA-256)
	hash := sha256.Sum256(payload)

	// Try to verify as DER-encoded signature first
	if verified := ecdsa.VerifyASN1(pubKey, hash[:], sigBytes); verified {
		return true, nil
	}

	// Try raw r||s format (64 bytes for P-256)
	if len(sigBytes) == 64 {
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if verified := ecdsa.Verify(pubKey, hash[:], r, s); verified {
			return true, nil
		}
	}

	return false, nil
}

// VerifyMultiSignature verifies multiple signatures against a key quorum
// Returns the number of valid signatures and any error
func (v *SignatureVerifier) VerifyMultiSignature(
	signatures []string,
	payload []byte,
	keys []KeyQuorumKey,
	threshold int,
) (int, error) {
	if len(signatures) == 0 {
		return 0, fmt.Errorf("no signatures provided")
	}

	if threshold <= 0 {
		return 0, fmt.Errorf("invalid threshold: %d", threshold)
	}

	validCount := 0
	usedKeys := make(map[uuid.UUID]bool)

	// Try each signature against each unused key
	for _, sig := range signatures {
		for _, key := range keys {
			// Skip if this key was already used
			if usedKeys[key.ID] {
				continue
			}

			// Try to verify with this key
			verified, err := v.VerifySignature(sig, payload, key.PublicKey)
			if err != nil {
				// Log but continue trying other keys
				continue
			}

			if verified {
				validCount++
				usedKeys[key.ID] = true
				// Move to next signature
				break
			}
		}
	}

	return validCount, nil
}

// KeyQuorumKey represents a public key in a key quorum
type KeyQuorumKey struct {
	ID        uuid.UUID
	PublicKey string
}

// VerifyKeyQuorum verifies that signatures meet the quorum threshold
func (v *SignatureVerifier) VerifyKeyQuorum(
	signatures []string,
	payload []byte,
	keys []KeyQuorumKey,
	threshold int,
) error {
	validCount, err := v.VerifyMultiSignature(signatures, payload, keys, threshold)
	if err != nil {
		return err
	}

	if validCount < threshold {
		return fmt.Errorf(
			"insufficient signatures: got %d valid signatures, need %d (threshold)",
			validCount,
			threshold,
		)
	}

	return nil
}

// VerifyOwnerSignature verifies signatures for a wallet owner
// Supports both single owner keys and key quorums
func (v *SignatureVerifier) VerifyOwnerSignature(
	signatures []string,
	payload []byte,
	owner *Owner,
) error {
	if len(signatures) == 0 {
		return fmt.Errorf("no signatures provided")
	}

	switch owner.Type {
	case OwnerTypeSingleKey:
		// Single key - verify first signature
		verified, err := v.VerifySignature(signatures[0], payload, owner.PublicKey)
		if err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
		if !verified {
			return fmt.Errorf("invalid signature")
		}
		return nil

	case OwnerTypeKeyQuorum:
		// Key quorum - verify against threshold
		return v.VerifyKeyQuorum(
			signatures,
			payload,
			owner.QuorumKeys,
			owner.QuorumThreshold,
		)

	default:
		return fmt.Errorf("unsupported owner type: %s", owner.Type)
	}
}

// Owner represents a wallet or resource owner
type Owner struct {
	Type            OwnerType
	PublicKey       string         // For single key owners
	QuorumKeys      []KeyQuorumKey // For key quorum owners
	QuorumThreshold int            // For key quorum owners
}

// OwnerType represents the type of owner
type OwnerType string

const (
	OwnerTypeSingleKey OwnerType = "single_key"
	OwnerTypeKeyQuorum OwnerType = "key_quorum"
	OwnerTypeUser      OwnerType = "user"
)

// PublicKeyToPEM converts raw public key bytes to PEM format
func PublicKeyToPEM(publicKeyBytes []byte) (string, error) {
	pubKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	// Marshal to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// parsePublicKey parses a PEM-encoded P-256 public key
func parsePublicKey(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	// Decode PEM
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Ensure it's an ECDSA key
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}

	// Verify it's P-256 (prime256v1)
	if ecdsaPubKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("public key is not P-256, got: %s", ecdsaPubKey.Curve.Params().Name)
	}

	return ecdsaPubKey, nil
}

// SignPayload signs a canonical payload with a private key (for testing)
// This should only be used in tests or for generating signatures
func SignPayload(payload []byte, privateKeyPEM string) (string, error) {
	// Parse private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Hash the payload
	hash := sha256.Sum256(payload)

	// Sign using crypto/rand
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// Encode to base64
	return base64.StdEncoding.EncodeToString(sigBytes), nil
}
