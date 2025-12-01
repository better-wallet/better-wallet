package keyexec

import (
	"context"
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/core/types"
)

// KeyExecutor defines the interface for key execution backends
type KeyExecutor interface {
	// GenerateAndSplitKey generates a new key and splits it into shares
	GenerateAndSplitKey(ctx context.Context) (*KeyMaterial, error)

	// Sign signs a transaction using the key material
	SignTransaction(ctx context.Context, keyMaterial *KeyMaterial, tx *types.Transaction, chainID int64) (*types.Transaction, error)

	// SignMessage signs a raw message (will hash the message internally)
	SignMessage(ctx context.Context, keyMaterial *KeyMaterial, message []byte) ([]byte, error)

	// SignHash signs a pre-hashed 32-byte value directly (no additional hashing)
	// Use this for EIP-191 personal_sign and EIP-712 typed data where the hash is computed externally
	SignHash(ctx context.Context, keyMaterial *KeyMaterial, hash []byte) ([]byte, error)

	// Encrypt encrypts data (for storing shares)
	Encrypt(ctx context.Context, data []byte) ([]byte, error)

	// Decrypt decrypts data (for retrieving shares)
	Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error)
}

// KeyMaterial represents the key material needed for signing
type KeyMaterial struct {
	// Address is the Ethereum address derived from the key
	Address string

	// AuthShare is stored in the database (encrypted)
	AuthShare []byte

	// ExecShare is stored in KMS/TEE
	ExecShare []byte

	// Metadata for key rotation and versioning
	Version int
}

// RecoveredKey represents a fully reconstructed private key
type RecoveredKey struct {
	PrivateKey *ecdsa.PrivateKey
	Address    string
}
