package storage

import (
	"context"
	"fmt"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WalletRepository handles wallet data operations
type WalletRepository struct {
	store *Store
}

// NewWalletRepository creates a new WalletRepository
func NewWalletRepository(store *Store) *WalletRepository {
	return &WalletRepository{store: store}
}

// Create creates a new wallet
func (r *WalletRepository) Create(ctx context.Context, wallet *types.Wallet) error {
	return r.CreateTx(ctx, r.store.pool, wallet)
}

// CreateTx creates a new wallet using the provided transaction or connection
func (r *WalletRepository) CreateTx(ctx context.Context, db DBTX, wallet *types.Wallet) error {
	query := `
		INSERT INTO wallets (id, user_id, chain_type, owner_id, exec_backend, address)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at
	`

	err := db.QueryRow(ctx, query,
		wallet.ID,
		wallet.UserID,
		wallet.ChainType,
		wallet.OwnerID,
		wallet.ExecBackend,
		wallet.Address,
	).Scan(&wallet.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	return nil
}

// GetByID retrieves a wallet by ID
func (r *WalletRepository) GetByID(ctx context.Context, id uuid.UUID) (*types.Wallet, error) {
	query := `
		SELECT id, user_id, chain_type, owner_id, exec_backend, address, created_at
		FROM wallets
		WHERE id = $1
	`

	var wallet types.Wallet
	err := r.store.pool.QueryRow(ctx, query, id).Scan(
		&wallet.ID,
		&wallet.UserID,
		&wallet.ChainType,
		&wallet.OwnerID,
		&wallet.ExecBackend,
		&wallet.Address,
		&wallet.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet by ID: %w", err)
	}

	return &wallet, nil
}

// GetByUserID retrieves all wallets for a user
func (r *WalletRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*types.Wallet, error) {
	query := `
		SELECT id, user_id, chain_type, owner_id, exec_backend, address, created_at
		FROM wallets
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.store.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallets by user ID: %w", err)
	}
	defer rows.Close()

	var wallets []*types.Wallet
	for rows.Next() {
		var wallet types.Wallet
		err := rows.Scan(
			&wallet.ID,
			&wallet.UserID,
			&wallet.ChainType,
			&wallet.OwnerID,
			&wallet.ExecBackend,
			&wallet.Address,
			&wallet.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan wallet: %w", err)
		}
		wallets = append(wallets, &wallet)
	}

	return wallets, nil
}

// GetByAddress retrieves a wallet by address
func (r *WalletRepository) GetByAddress(ctx context.Context, address string) (*types.Wallet, error) {
	query := `
		SELECT id, user_id, chain_type, owner_id, exec_backend, address, created_at
		FROM wallets
		WHERE address = $1
	`

	var wallet types.Wallet
	err := r.store.pool.QueryRow(ctx, query, address).Scan(
		&wallet.ID,
		&wallet.UserID,
		&wallet.ChainType,
		&wallet.OwnerID,
		&wallet.ExecBackend,
		&wallet.Address,
		&wallet.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet by address: %w", err)
	}

	return &wallet, nil
}

// Delete deletes a wallet by ID
func (r *WalletRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM wallets WHERE id = $1`

	tag, err := r.store.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete wallet: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("wallet not found")
	}

	return nil
}
