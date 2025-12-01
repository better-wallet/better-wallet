package crypto

import (
	"fmt"

	"github.com/hashicorp/vault/shamir"
)

const (
	// DefaultThreshold is the minimum number of shares required to reconstruct the secret
	DefaultThreshold = 2
	// DefaultTotalShares is the total number of shares to generate
	DefaultTotalShares = 2
)

// ShareSet represents a set of shares from Shamir's Secret Sharing
// Uses 2-of-2 scheme: both shares are required to reconstruct the key
type ShareSet struct {
	// AuthShare is stored in PostgreSQL (encrypted with KMS)
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

// SplitKeySSS splits a key using Shamir's Secret Sharing scheme
// Returns a ShareSet containing auth and exec shares
// Both shares are required to reconstruct the original key (2-of-2)
func SplitKeySSS(key []byte, threshold, totalShares int) (*ShareSet, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	if threshold != 2 {
		return nil, fmt.Errorf("threshold must be 2 for 2-of-2 scheme, got %d", threshold)
	}
	if totalShares != 2 {
		return nil, fmt.Errorf("totalShares must be 2 for 2-of-2 scheme, got %d", totalShares)
	}

	// Split the key using Shamir's Secret Sharing (2-of-2)
	shares, err := shamir.Split(key, totalShares, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to split key with Shamir's Secret Sharing: %w", err)
	}

	return &ShareSet{
		AuthShare:   shares[0],
		ExecShare:   shares[1],
		Threshold:   threshold,
		TotalShares: totalShares,
	}, nil
}

// SplitKeyDefault splits a key using default 2-of-2 Shamir's Secret Sharing
func SplitKeyDefault(key []byte) (*ShareSet, error) {
	return SplitKeySSS(key, DefaultThreshold, DefaultTotalShares)
}

// CombineSharesSSS reconstructs the original key from shares using Shamir's Secret Sharing
// Requires exactly 2 shares for 2-of-2 scheme
func CombineSharesSSS(shares [][]byte) ([]byte, error) {
	if len(shares) != 2 {
		return nil, fmt.Errorf("exactly 2 shares are required for 2-of-2 scheme, got %d", len(shares))
	}

	// Validate shares
	for i, share := range shares {
		if len(share) == 0 {
			return nil, fmt.Errorf("share %d is empty", i)
		}
	}

	// Combine shares using Shamir's algorithm
	key, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}

	return key, nil
}

// CombineAuthAndExec combines auth and exec shares for signing operations
// This is the only path for wallet operations in 2-of-2 scheme
func CombineAuthAndExec(authShare, execShare []byte) ([]byte, error) {
	return CombineSharesSSS([][]byte{authShare, execShare})
}

// ValidateShare checks if a share appears to be valid
// Note: This only checks format, not cryptographic validity
func ValidateShare(share []byte) error {
	if len(share) == 0 {
		return fmt.Errorf("share cannot be empty")
	}
	// Shamir shares have a 1-byte index prefix followed by the share data
	// For a 32-byte private key, the share should be at least 33 bytes
	if len(share) < 33 {
		return fmt.Errorf("share too short: expected at least 33 bytes, got %d", len(share))
	}
	return nil
}
