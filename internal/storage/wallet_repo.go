package storage

import (
	"context"
	"fmt"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WalletRepository handles wallet data operations
// All operations are automatically scoped to the app_id from context
type WalletRepository struct {
	store *Store
}

// NewWalletRepository creates a new WalletRepository
func NewWalletRepository(store *Store) *WalletRepository {
	return &WalletRepository{store: store}
}

// Create creates a new wallet
// The wallet's AppID field must be set before calling this
func (r *WalletRepository) Create(ctx context.Context, wallet *types.Wallet) error {
	return r.CreateTx(ctx, r.store.pool, wallet)
}

// CreateTx creates a new wallet using the provided transaction or connection
func (r *WalletRepository) CreateTx(ctx context.Context, db DBTX, wallet *types.Wallet) error {
	query := `
		INSERT INTO wallets (id, user_id, chain_type, owner_id, exec_backend, address, app_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at
	`

	err := db.QueryRow(ctx, query,
		wallet.ID,
		wallet.UserID,
		wallet.ChainType,
		wallet.OwnerID,
		wallet.ExecBackend,
		wallet.Address,
		wallet.AppID,
	).Scan(&wallet.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	return nil
}

// GetByID retrieves a wallet by ID, automatically scoped to app_id from context
func (r *WalletRepository) GetByID(ctx context.Context, id uuid.UUID) (*types.Wallet, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, user_id, chain_type, owner_id, exec_backend, address, app_id, created_at
		FROM wallets
		WHERE id = $1 AND app_id = $2
	`

	var wallet types.Wallet
	err = r.store.pool.QueryRow(ctx, query, id, appID).Scan(
		&wallet.ID,
		&wallet.UserID,
		&wallet.ChainType,
		&wallet.OwnerID,
		&wallet.ExecBackend,
		&wallet.Address,
		&wallet.AppID,
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

// GetByUserID retrieves all wallets for a user, automatically scoped to app_id from context
func (r *WalletRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*types.Wallet, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, user_id, chain_type, owner_id, exec_backend, address, app_id, created_at
		FROM wallets
		WHERE user_id = $1 AND app_id = $2
		ORDER BY created_at DESC
	`

	rows, err := r.store.pool.Query(ctx, query, userID, appID)
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
			&wallet.AppID,
			&wallet.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan wallet: %w", err)
		}
		wallets = append(wallets, &wallet)
	}

	return wallets, nil
}

// GetByAddress retrieves a wallet by address, automatically scoped to app_id from context
func (r *WalletRepository) GetByAddress(ctx context.Context, address string) (*types.Wallet, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, user_id, chain_type, owner_id, exec_backend, address, app_id, created_at
		FROM wallets
		WHERE address = $1 AND app_id = $2
	`

	var wallet types.Wallet
	err = r.store.pool.QueryRow(ctx, query, address, appID).Scan(
		&wallet.ID,
		&wallet.UserID,
		&wallet.ChainType,
		&wallet.OwnerID,
		&wallet.ExecBackend,
		&wallet.Address,
		&wallet.AppID,
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

// Delete deletes a wallet by ID, automatically scoped to app_id from context
func (r *WalletRepository) Delete(ctx context.Context, id uuid.UUID) error {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return err
	}

	query := `DELETE FROM wallets WHERE id = $1 AND app_id = $2`

	tag, err := r.store.pool.Exec(ctx, query, id, appID)
	if err != nil {
		return fmt.Errorf("failed to delete wallet: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("wallet not found")
	}

	return nil
}

// List retrieves wallets with pagination, automatically scoped to app_id from context
// List lists wallets with user_id filtering to maintain per-user isolation
// - If userID is provided: returns wallets for that user AND app-managed wallets (user_id IS NULL)
// - If userID is nil and onlyAppManaged is true: returns only app-managed wallets (user_id IS NULL)
// - If userID is nil and onlyAppManaged is false: returns all wallets (admin use only)
func (r *WalletRepository) List(ctx context.Context, userID *uuid.UUID, onlyAppManaged bool, chainType string, cursor *string, limit int) ([]*types.Wallet, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	var query string
	var args []interface{}
	argPos := 1

	if userID != nil {
		// Filter by specific user OR include app-managed wallets (user_id IS NULL)
		query = fmt.Sprintf(`
			SELECT id, user_id, chain_type, owner_id, exec_backend, address, app_id, created_at
			FROM wallets
			WHERE app_id = $%d AND (user_id = $%d OR user_id IS NULL)
		`, argPos, argPos+1)
		args = []interface{}{appID, *userID}
		argPos = 3
	} else if onlyAppManaged {
		// Only return app-managed wallets (user_id IS NULL) - for callers with no user record
		query = fmt.Sprintf(`
			SELECT id, user_id, chain_type, owner_id, exec_backend, address, app_id, created_at
			FROM wallets
			WHERE app_id = $%d AND user_id IS NULL
		`, argPos)
		args = []interface{}{appID}
		argPos = 2
	} else {
		// List all wallets for the app (admin use only - not exposed via normal API)
		query = fmt.Sprintf(`
			SELECT id, user_id, chain_type, owner_id, exec_backend, address, app_id, created_at
			FROM wallets
			WHERE app_id = $%d
		`, argPos)
		args = []interface{}{appID}
		argPos = 2
	}

	if chainType != "" {
		query += fmt.Sprintf(" AND chain_type = $%d", argPos)
		args = append(args, chainType)
		argPos++
	}

	if cursor != nil && *cursor != "" {
		query += fmt.Sprintf(" AND created_at < $%d", argPos)
		args = append(args, *cursor)
		argPos++
	}

	query += " ORDER BY created_at DESC"
	query += fmt.Sprintf(" LIMIT $%d", argPos)
	args = append(args, limit+1) // Fetch one extra to check for next page

	rows, err := r.store.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list wallets: %w", err)
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
			&wallet.AppID,
			&wallet.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan wallet: %w", err)
		}
		wallets = append(wallets, &wallet)
	}

	return wallets, nil
}
