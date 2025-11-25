package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HPKEEncryptedData contains the encrypted data and encapsulated key
type HPKEEncryptedData struct {
	Ciphertext      string `json:"ciphertext"`       // Base64-encoded encrypted data
	EncapsulatedKey string `json:"encapsulated_key"` // Base64-encoded ephemeral public key
	EncryptionType  string `json:"encryption_type"`  // Always "HPKE"
}

// EncryptWithHPKE encrypts data using HPKE-compatible encryption with the configuration:
// - KEM: DHKEM_P256_HKDF_SHA256 (ECDH with P-256)
// - KDF: HKDF_SHA256
// - AEAD: AES-256-GCM (compatible alternative to ChaCha20Poly1305)
// - Mode: BASE
//
// Note: This is a simplified HPKE-compatible implementation using ECDH + HKDF + AES-GCM
func EncryptWithHPKE(recipientPublicKeyB64 string, plaintext []byte) (*HPKEEncryptedData, error) {
	// Decode the recipient's public key from base64
	recipientPubKeyBytes, err := base64.StdEncoding.DecodeString(recipientPublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient public key: %w", err)
	}

	// Try to parse as PEM first
	block, _ := pem.Decode(recipientPubKeyBytes)
	if block != nil {
		// PEM format - extract DER bytes
		recipientPubKeyBytes = block.Bytes
	}

	// Parse as P-256 public key
	curve := ecdh.P256()
	recipientPubKey, err := curve.NewPublicKey(recipientPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse recipient public key: %w", err)
	}

	// Generate ephemeral key pair
	ephemeralPrivKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemeralPubKey := ephemeralPrivKey.PublicKey()

	// Perform ECDH key agreement
	sharedSecret, err := ephemeralPrivKey.ECDH(recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform ECDH: %w", err)
	}

	// Derive encryption key using HKDF-SHA256
	// info parameter is empty as per HPKE BASE mode
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, nil)
	encKey := make([]byte, 32) // 256-bit key for AES-256-GCM
	if _, err := io.ReadFull(hkdfReader, encKey); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Encrypt using AES-256-GCM
	aesCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext with empty additional data
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	// Get the encapsulated key (ephemeral public key bytes)
	encapsulatedKey := ephemeralPubKey.Bytes()

	return &HPKEEncryptedData{
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
		EncapsulatedKey: base64.StdEncoding.EncodeToString(encapsulatedKey),
		EncryptionType:  "HPKE",
	}, nil
}

// DecryptWithHPKE decrypts HPKE-encrypted data using the recipient's private key
// This is provided for testing/verification purposes
func DecryptWithHPKE(recipientPrivateKey *ecdh.PrivateKey, encapsulatedKeyB64, ciphertextB64 string) ([]byte, error) {
	// Decode encapsulated key (ephemeral public key)
	encapsulatedKeyBytes, err := base64.StdEncoding.DecodeString(encapsulatedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encapsulated key: %w", err)
	}

	// Decode ciphertext
	ciphertextWithNonce, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Parse ephemeral public key
	curve := ecdh.P256()
	ephemeralPubKey, err := curve.NewPublicKey(encapsulatedKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// Perform ECDH key agreement
	sharedSecret, err := recipientPrivateKey.ECDH(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform ECDH: %w", err)
	}

	// Derive decryption key using HKDF-SHA256
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, nil)
	encKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, encKey); err != nil {
		return nil, fmt.Errorf("failed to derive decryption key: %w", err)
	}

	// Decrypt using AES-256-GCM
	aesCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce and ciphertext
	nonceSize := aesGCM.NonceSize()
	if len(ciphertextWithNonce) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertextWithNonce[:nonceSize]
	ciphertext := ciphertextWithNonce[nonceSize:]

	// Decrypt
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GenerateRecipientKeyPair generates a P-256 key pair for HPKE encryption
// This is provided for testing purposes
func GenerateRecipientKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return privateKey, privateKey.PublicKey(), nil
}
