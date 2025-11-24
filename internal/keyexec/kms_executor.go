package keyexec

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/better-wallet/better-wallet/internal/crypto"
)

// KMSExecutor implements KeyExecutor using KMS/Vault-like encryption
// This is a simplified implementation - production would use actual KMS (AWS KMS, HashiCorp Vault, etc.)
type KMSExecutor struct {
	masterKey []byte // In production, this would be in KMS/HSM
}

// NewKMSExecutor creates a new KMS executor
func NewKMSExecutor(masterKeyHex string) (*KMSExecutor, error) {
	// In production, this would connect to KMS and retrieve the master key
	// For MVP, we use a provided master key
	if masterKeyHex == "" {
		return nil, fmt.Errorf("master key is required")
	}

	// For simplicity, we'll generate a 32-byte key from the provided string
	// In production, use proper KMS key derivation
	masterKey := make([]byte, 32)
	copy(masterKey, []byte(masterKeyHex))

	return &KMSExecutor{
		masterKey: masterKey,
	}, nil
}

// GenerateAndSplitKey generates a new key and splits it into shares
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

	// Split the key into two shares
	authShare, execShare, err := crypto.SplitKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to split key: %w", err)
	}

	return &KeyMaterial{
		Address:   address.Hex(),
		AuthShare: authShare,
		ExecShare: execShare,
		Version:   1,
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

// SignMessage signs a raw message
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

// Encrypt encrypts data using the master key
func (k *KMSExecutor) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and append nonce
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using the master key
func (k *KMSExecutor) Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// reconstructKey combines the shares to reconstruct the private key
func (k *KMSExecutor) reconstructKey(keyMaterial *KeyMaterial) (*ecdsa.PrivateKey, error) {
	// Combine the two shares
	privateKeyBytes, err := crypto.CombineShares(keyMaterial.AuthShare, keyMaterial.ExecShare)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}

	// Convert bytes back to private key
	privateKey, err := crypto.BytesToPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to private key: %w", err)
	}

	return privateKey, nil
}

// zeroKey securely zeros out the private key from memory
func (k *KMSExecutor) zeroKey(privateKey *ecdsa.PrivateKey) {
	if privateKey != nil && privateKey.D != nil {
		privateKey.D.SetInt64(0)
	}
}
