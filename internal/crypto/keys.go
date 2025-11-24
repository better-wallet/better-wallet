package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// GenerateEthereumKey generates a new Ethereum private key
func GenerateEthereumKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return privateKey, nil
}

// GetEthereumAddress derives the Ethereum address from a private key
func GetEthereumAddress(privateKey *ecdsa.PrivateKey) common.Address {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		panic("failed to cast public key to ECDSA")
	}
	return crypto.PubkeyToAddress(*publicKeyECDSA)
}

// PrivateKeyToBytes converts a private key to bytes
func PrivateKeyToBytes(privateKey *ecdsa.PrivateKey) []byte {
	return crypto.FromECDSA(privateKey)
}

// BytesToPrivateKey converts bytes to a private key
func BytesToPrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	return crypto.ToECDSA(b)
}

// SplitKey splits a key into shares using simple XOR (simplified for MVP)
// In production, use proper secret sharing like Shamir's Secret Sharing
func SplitKey(key []byte) (share1, share2 []byte, err error) {
	if len(key) == 0 {
		return nil, nil, fmt.Errorf("key cannot be empty")
	}

	// Generate random share1
	share1 = make([]byte, len(key))
	if _, err := rand.Read(share1); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random share: %w", err)
	}

	// Create share2 as XOR of key and share1
	share2 = make([]byte, len(key))
	for i := range key {
		share2[i] = key[i] ^ share1[i]
	}

	return share1, share2, nil
}

// CombineShares combines two shares to reconstruct the original key
func CombineShares(share1, share2 []byte) ([]byte, error) {
	if len(share1) != len(share2) {
		return nil, fmt.Errorf("shares must have the same length")
	}

	key := make([]byte, len(share1))
	for i := range share1 {
		key[i] = share1[i] ^ share2[i]
	}

	return key, nil
}
