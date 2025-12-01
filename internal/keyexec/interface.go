package keyexec

import (
	"context"

	"github.com/ethereum/go-ethereum/core/types"
)

// KeyExecutor defines the interface for key execution backends
// Uses 2-of-2 Shamir's Secret Sharing: auth_share + exec_share
type KeyExecutor interface {
	// GenerateAndSplitKey generates a new key and splits it using Shamir's Secret Sharing (2-of-2)
	// Returns KeyMaterial with AuthShare (stored in DB) and ExecShare (managed by backend)
	GenerateAndSplitKey(ctx context.Context) (*KeyMaterial, error)

	// SignTransaction signs a transaction using the key material
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
// Uses 2-of-2 scheme: both auth_share and exec_share are required
type KeyMaterial struct {
	// Address is the Ethereum address derived from the key
	Address string

	// AuthShare is stored in the database (encrypted with KMS)
	// Retrieved when user authenticates
	AuthShare []byte

	// ExecShare is managed by the execution backend:
	// - KMS mode: encrypted and stored in database
	// - TEE mode: sealed inside enclave memory
	ExecShare []byte

	// Threshold is the minimum number of shares required (always 2)
	Threshold int

	// TotalShares is the total number of shares (always 2)
	TotalShares int
}
