package storage

import (
	"context"
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
		INSERT INTO wallet_shares (wallet_id, share_type, blob_encrypted, kms_key_id, version)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := db.Exec(ctx, query,
		share.WalletID,
		share.ShareType,
		share.BlobEncrypted,
		share.KMSKeyID,
		share.Version,
	)

	if err != nil {
		return fmt.Errorf("failed to create wallet share: %w", err)
	}

	return nil
}

// GetByWalletID retrieves all shares for a wallet
func (r *WalletShareRepository) GetByWalletID(ctx context.Context, walletID uuid.UUID) ([]*types.WalletShare, error) {
	query := `
		SELECT wallet_id, share_type, blob_encrypted, kms_key_id, version
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

		err := rows.Scan(
			&share.WalletID,
			&share.ShareType,
			&share.BlobEncrypted,
			&kmsKeyID,
			&share.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan wallet share: %w", err)
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
