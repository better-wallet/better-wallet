package crypto

import (
	"crypto/ecdsa"
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
