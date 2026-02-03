package keyexec

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/better-wallet/better-wallet/internal/crypto"
)

// KMSExecutor implements KeyExecutor using a pluggable KMS provider
// Supports multiple backends: local (AES-GCM), AWS KMS, HashiCorp Vault, etc.
type KMSExecutor struct {
	provider KMSProvider
}

// NewKMSExecutor creates a new KMS executor with the specified provider
func NewKMSExecutor(cfg *KMSConfig) (*KMSExecutor, error) {
	provider, err := NewKMSProvider(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS provider: %w", err)
	}

	return &KMSExecutor{
		provider: provider,
	}, nil
}

// Provider returns the KMS provider name
func (k *KMSExecutor) Provider() string {
	return k.provider.Provider()
}

// GenerateAndSplitKey generates a new key and splits it using Shamir's Secret Sharing (2-of-2)
func (k *KMSExecutor) GenerateAndSplitKey(ctx context.Context) (*KeyMaterial, error) {
	// Generate new Ethereum private key
	privateKey, err := crypto.GenerateEthereumKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Get the address
	address := crypto.GetEthereumAddress(privateKey)

	// Convert private key to bytes
	privateKeyBytes := crypto.PrivateKeyToBytes(privateKey)

	// Split the key using Shamir's Secret Sharing (2-of-2)
	shareSet, err := crypto.SplitKeyDefault(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to split key with SSS: %w", err)
	}

	// Clear private key bytes from memory
	for i := range privateKeyBytes {
		privateKeyBytes[i] = 0
	}

	return &KeyMaterial{
		Address:     address.Hex(),
		AuthShare:   shareSet.AuthShare,
		ExecShare:   shareSet.ExecShare,
		Threshold:   shareSet.Threshold,
		TotalShares: shareSet.TotalShares,
	}, nil
}

// SignTransaction signs a transaction using the key material
func (k *KMSExecutor) SignTransaction(ctx context.Context, keyMaterial *KeyMaterial, tx *types.Transaction, chainID int64) (*types.Transaction, error) {
	// Reconstruct the private key from shares
	privateKey, err := k.reconstructKey(keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct key: %w", err)
	}
	defer k.zeroKey(privateKey) // Clear from memory after use

	// Create signer
	signer := types.NewLondonSigner(big.NewInt(chainID))

	// Sign the transaction
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	return signedTx, nil
}

// SignMessage signs a raw message (hashes internally)
func (k *KMSExecutor) SignMessage(ctx context.Context, keyMaterial *KeyMaterial, message []byte) ([]byte, error) {
	// Reconstruct the private key from shares
	privateKey, err := k.reconstructKey(keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct key: %w", err)
	}
	defer k.zeroKey(privateKey)

	// Hash the message
	hash := ethcrypto.Keccak256Hash(message)

	// Sign the hash
	signature, err := ethcrypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return signature, nil
}

// SignHash signs a pre-hashed 32-byte value directly (no additional hashing)
// Use this for EIP-191 personal_sign and EIP-712 typed data where the hash is computed externally
func (k *KMSExecutor) SignHash(ctx context.Context, keyMaterial *KeyMaterial, hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be exactly 32 bytes, got %d", len(hash))
	}

	// Reconstruct the private key from shares
	privateKey, err := k.reconstructKey(keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct key: %w", err)
	}
	defer k.zeroKey(privateKey)

	// Sign the hash directly without additional hashing
	signature, err := ethcrypto.Sign(hash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash: %w", err)
	}

	return signature, nil
}

// Encrypt encrypts data using the KMS provider
func (k *KMSExecutor) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	return k.provider.Encrypt(ctx, data)
}

// Decrypt decrypts data using the KMS provider
func (k *KMSExecutor) Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error) {
	return k.provider.Decrypt(ctx, encryptedData)
}

// reconstructKey combines the auth and exec shares to reconstruct the private key
func (k *KMSExecutor) reconstructKey(keyMaterial *KeyMaterial) (*ecdsa.PrivateKey, error) {
	// Use Shamir's Secret Sharing to combine auth and exec shares
	privateKeyBytes, err := crypto.CombineAuthAndExec(keyMaterial.AuthShare, keyMaterial.ExecShare)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}

	// Convert bytes back to private key
	privateKey, err := crypto.BytesToPrivateKey(privateKeyBytes)
	if err != nil {
		// Clear private key bytes on error
		for i := range privateKeyBytes {
			privateKeyBytes[i] = 0
		}
		return nil, fmt.Errorf("failed to convert to private key: %w", err)
	}

	// Clear private key bytes from memory
	for i := range privateKeyBytes {
		privateKeyBytes[i] = 0
	}

	return privateKey, nil
}

// zeroKey securely zeros out the private key from memory
func (k *KMSExecutor) zeroKey(privateKey *ecdsa.PrivateKey) {
	if privateKey != nil && privateKey.D != nil {
		privateKey.D.SetInt64(0)
	}
}
