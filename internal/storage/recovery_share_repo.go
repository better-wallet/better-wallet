package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// RecoveryShareRepository handles recovery share metadata operations
type RecoveryShareRepository struct {
	store *Store
}

// NewRecoveryShareRepository creates a new RecoveryShareRepository
func NewRecoveryShareRepository(store *Store) *RecoveryShareRepository {
	return &RecoveryShareRepository{store: store}
}

// Create creates a new recovery share info record
func (r *RecoveryShareRepository) Create(ctx context.Context, info *types.RecoveryShareInfo) error {
	return r.CreateTx(ctx, r.store.pool, info)
}

// CreateTx creates a new recovery share info using the provided transaction or connection
func (r *RecoveryShareRepository) CreateTx(ctx context.Context, db DBTX, info *types.RecoveryShareInfo) error {
	query := `
		INSERT INTO recovery_share_info (wallet_id, share_index, encryption_method, hint, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (wallet_id) DO UPDATE SET
			share_index = EXCLUDED.share_index,
			encryption_method = EXCLUDED.encryption_method,
			hint = EXCLUDED.hint,
			updated_at = NOW()
	`

	createdAt := info.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	_, err := db.Exec(ctx, query,
		info.WalletID,
		info.ShareIndex,
		info.EncryptionMethod,
		info.Hint,
		createdAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create recovery share info: %w", err)
	}

	return nil
}

// GetByWalletID retrieves recovery share info for a wallet
func (r *RecoveryShareRepository) GetByWalletID(ctx context.Context, walletID uuid.UUID) (*types.RecoveryShareInfo, error) {
	query := `
		SELECT wallet_id, share_index, encryption_method, hint, created_at, updated_at
		FROM recovery_share_info
		WHERE wallet_id = $1
	`

	var info types.RecoveryShareInfo
	var hint *string

	err := r.store.pool.QueryRow(ctx, query, walletID).Scan(
		&info.WalletID,
		&info.ShareIndex,
		&info.EncryptionMethod,
		&hint,
		&info.CreatedAt,
		&info.UpdatedAt,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get recovery share info: %w", err)
	}

	if hint != nil {
		info.Hint = *hint
	}

	return &info, nil
}

// Update updates recovery share info
func (r *RecoveryShareRepository) Update(ctx context.Context, info *types.RecoveryShareInfo) error {
	query := `
		UPDATE recovery_share_info
		SET encryption_method = $2, hint = $3, updated_at = NOW()
		WHERE wallet_id = $1
	`

	result, err := r.store.pool.Exec(ctx, query,
		info.WalletID,
		info.EncryptionMethod,
		info.Hint,
	)

	if err != nil {
		return fmt.Errorf("failed to update recovery share info: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("recovery share info not found for wallet %s", info.WalletID)
	}

	return nil
}

// Delete deletes recovery share info for a wallet
func (r *RecoveryShareRepository) Delete(ctx context.Context, walletID uuid.UUID) error {
	query := `DELETE FROM recovery_share_info WHERE wallet_id = $1`

	_, err := r.store.pool.Exec(ctx, query, walletID)
	if err != nil {
		return fmt.Errorf("failed to delete recovery share info: %w", err)
	}

	return nil
}

// HasRecoveryShare checks if a wallet has recovery share info
func (r *RecoveryShareRepository) HasRecoveryShare(ctx context.Context, walletID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM recovery_share_info WHERE wallet_id = $1)`

	var exists bool
	err := r.store.pool.QueryRow(ctx, query, walletID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check recovery share existence: %w", err)
	}

	return exists, nil
}
