package storage

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// WalletShareRepository handles wallet share data operations
type WalletShareRepository struct {
	store *Store
}

// NewWalletShareRepository creates a new WalletShareRepository
func NewWalletShareRepository(store *Store) *WalletShareRepository {
	return &WalletShareRepository{store: store}
}

// Create creates a new wallet share
func (r *WalletShareRepository) Create(ctx context.Context, share *types.WalletShare) error {
	return r.CreateTx(ctx, r.store.pool, share)
}

// CreateTx creates a new wallet share using the provided transaction or connection
func (r *WalletShareRepository) CreateTx(ctx context.Context, db DBTX, share *types.WalletShare) error {
	query := `
		INSERT INTO wallet_shares (wallet_id, share_type, blob_encrypted, kms_key_id, threshold, total_shares)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	// Set defaults for threshold and total_shares
	threshold := share.Threshold
	totalShares := share.TotalShares
	if threshold == 0 {
		threshold = 2 // Default threshold for 2-of-3 SSS
	}
	if totalShares == 0 {
		totalShares = 3 // Default total shares for SSS
	}

	// Base64 encode the encrypted blob for storage in text column
	blobBase64 := base64.StdEncoding.EncodeToString(share.BlobEncrypted)

	_, err := db.Exec(ctx, query,
		share.WalletID,
		share.ShareType,
		blobBase64,
		share.KMSKeyID,
		threshold,
		totalShares,
	)

	if err != nil {
		return fmt.Errorf("failed to create wallet share: %w", err)
	}

	return nil
}

// GetByWalletID retrieves all shares for a wallet
func (r *WalletShareRepository) GetByWalletID(ctx context.Context, walletID uuid.UUID) ([]*types.WalletShare, error) {
	query := `
		SELECT wallet_id, share_type, blob_encrypted, kms_key_id,
		       COALESCE(threshold, 2) as threshold, COALESCE(total_shares, 3) as total_shares
		FROM wallet_shares
		WHERE wallet_id = $1
	`

	rows, err := r.store.pool.Query(ctx, query, walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet shares: %w", err)
	}
	defer rows.Close()

	var shares []*types.WalletShare
	for rows.Next() {
		var share types.WalletShare
		var kmsKeyID *string
		var blobBase64 string

		err := rows.Scan(
			&share.WalletID,
			&share.ShareType,
			&blobBase64,
			&kmsKeyID,
			&share.Threshold,
			&share.TotalShares,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan wallet share: %w", err)
		}

		// Base64 decode the encrypted blob
		share.BlobEncrypted, err = base64.StdEncoding.DecodeString(blobBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode blob: %w", err)
		}

		if kmsKeyID != nil {
			share.KMSKeyID = *kmsKeyID
		}

		shares = append(shares, &share)
	}

	return shares, nil
}

// Delete deletes all shares for a wallet
func (r *WalletShareRepository) Delete(ctx context.Context, walletID uuid.UUID) error {
	query := `DELETE FROM wallet_shares WHERE wallet_id = $1`

	_, err := r.store.pool.Exec(ctx, query, walletID)
	if err != nil {
		return fmt.Errorf("failed to delete wallet shares: %w", err)
	}

	return nil
}
