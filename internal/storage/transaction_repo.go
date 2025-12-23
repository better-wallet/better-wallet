package storage

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Transaction represents a transaction record
type Transaction struct {
	ID                   uuid.UUID
	WalletID             uuid.UUID
	ChainID              int64
	TxHash               *string
	Status               string // pending, submitted, confirmed, failed
	Method               string // eth_sendTransaction, eth_signTransaction
	ToAddress            *string
	Value                *string
	Data                 *string
	Nonce                *int64
	GasLimit             *int64
	MaxFeePerGas         *string
	MaxPriorityFeePerGas *string
	SignedTx             []byte
	ErrorMessage         *string
	AppID                *uuid.UUID
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// TransactionRepository handles transaction storage
type TransactionRepository struct {
	store *Store
}

// NewTransactionRepository creates a new transaction repository
func NewTransactionRepository(store *Store) *TransactionRepository {
	return &TransactionRepository{store: store}
}

// Create creates a new transaction record
func (r *TransactionRepository) Create(ctx context.Context, tx *Transaction) error {
	if tx.AppID == nil {
		appID, err := RequireAppID(ctx)
		if err != nil {
			return err
		}
		tx.AppID = &appID
	}

	query := `
		INSERT INTO transactions (
			id, wallet_id, chain_id, tx_hash, status, method,
			to_address, value, data, nonce, gas_limit,
			max_fee_per_gas, max_priority_fee_per_gas, signed_tx, error_message, app_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)
	`

	var signedTx *string
	if len(tx.SignedTx) > 0 {
		encoded := hex.EncodeToString(tx.SignedTx)
		signedTx = &encoded
	}

	_, err := r.store.pool.Exec(ctx, query,
		tx.ID,
		tx.WalletID,
		tx.ChainID,
		tx.TxHash,
		tx.Status,
		tx.Method,
		tx.ToAddress,
		tx.Value,
		tx.Data,
		tx.Nonce,
		tx.GasLimit,
		tx.MaxFeePerGas,
		tx.MaxPriorityFeePerGas,
		signedTx,
		tx.ErrorMessage,
		tx.AppID,
	)

	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}

	return nil
}

// GetByID retrieves a transaction by ID
func (r *TransactionRepository) GetByID(ctx context.Context, id uuid.UUID) (*Transaction, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, wallet_id, chain_id, tx_hash, status, method,
			to_address, value, data, nonce, gas_limit,
			max_fee_per_gas, max_priority_fee_per_gas, signed_tx, error_message,
			app_id, created_at, updated_at
		FROM transactions
		WHERE id = $1 AND app_id = $2
	`

	var tx Transaction
	err = r.store.pool.QueryRow(ctx, query, id, appID).Scan(
		&tx.ID,
		&tx.WalletID,
		&tx.ChainID,
		&tx.TxHash,
		&tx.Status,
		&tx.Method,
		&tx.ToAddress,
		&tx.Value,
		&tx.Data,
		&tx.Nonce,
		&tx.GasLimit,
		&tx.MaxFeePerGas,
		&tx.MaxPriorityFeePerGas,
		&tx.SignedTx,
		&tx.ErrorMessage,
		&tx.AppID,
		&tx.CreatedAt,
		&tx.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	return &tx, nil
}

// GetByIDAndAppID retrieves a transaction by ID scoped to an app
func (r *TransactionRepository) GetByIDAndAppID(ctx context.Context, id, appID uuid.UUID) (*Transaction, error) {
	query := `
		SELECT id, wallet_id, chain_id, tx_hash, status, method,
			to_address, value, data, nonce, gas_limit,
			max_fee_per_gas, max_priority_fee_per_gas, signed_tx, error_message,
			app_id, created_at, updated_at
		FROM transactions
		WHERE id = $1 AND app_id = $2
	`

	var tx Transaction
	err := r.store.pool.QueryRow(ctx, query, id, appID).Scan(
		&tx.ID,
		&tx.WalletID,
		&tx.ChainID,
		&tx.TxHash,
		&tx.Status,
		&tx.Method,
		&tx.ToAddress,
		&tx.Value,
		&tx.Data,
		&tx.Nonce,
		&tx.GasLimit,
		&tx.MaxFeePerGas,
		&tx.MaxPriorityFeePerGas,
		&tx.SignedTx,
		&tx.ErrorMessage,
		&tx.AppID,
		&tx.CreatedAt,
		&tx.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	return &tx, nil
}

// GetByTxHash retrieves a transaction by its on-chain hash
func (r *TransactionRepository) GetByTxHash(ctx context.Context, txHash string) (*Transaction, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, wallet_id, chain_id, tx_hash, status, method,
			to_address, value, data, nonce, gas_limit,
			max_fee_per_gas, max_priority_fee_per_gas, signed_tx, error_message,
			app_id, created_at, updated_at
		FROM transactions
		WHERE tx_hash = $1 AND app_id = $2
	`

	var tx Transaction
	err = r.store.pool.QueryRow(ctx, query, txHash, appID).Scan(
		&tx.ID,
		&tx.WalletID,
		&tx.ChainID,
		&tx.TxHash,
		&tx.Status,
		&tx.Method,
		&tx.ToAddress,
		&tx.Value,
		&tx.Data,
		&tx.Nonce,
		&tx.GasLimit,
		&tx.MaxFeePerGas,
		&tx.MaxPriorityFeePerGas,
		&tx.SignedTx,
		&tx.ErrorMessage,
		&tx.AppID,
		&tx.CreatedAt,
		&tx.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get transaction by hash: %w", err)
	}

	return &tx, nil
}

// ListByWalletID retrieves transactions for a wallet
func (r *TransactionRepository) ListByWalletID(ctx context.Context, walletID uuid.UUID, limit int) ([]*Transaction, error) {
	if limit <= 0 {
		limit = 100
	}

	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, wallet_id, chain_id, tx_hash, status, method,
			to_address, value, data, nonce, gas_limit,
			max_fee_per_gas, max_priority_fee_per_gas, signed_tx, error_message,
			app_id, created_at, updated_at
		FROM transactions
		WHERE wallet_id = $1 AND app_id = $2
		ORDER BY created_at DESC
		LIMIT $3
	`

	rows, err := r.store.pool.Query(ctx, query, walletID, appID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list transactions: %w", err)
	}
	defer rows.Close()

	var transactions []*Transaction
	for rows.Next() {
		var tx Transaction
		if err := rows.Scan(
			&tx.ID,
			&tx.WalletID,
			&tx.ChainID,
			&tx.TxHash,
			&tx.Status,
			&tx.Method,
			&tx.ToAddress,
			&tx.Value,
			&tx.Data,
			&tx.Nonce,
			&tx.GasLimit,
			&tx.MaxFeePerGas,
			&tx.MaxPriorityFeePerGas,
			&tx.SignedTx,
			&tx.ErrorMessage,
			&tx.AppID,
			&tx.CreatedAt,
			&tx.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %w", err)
		}
		transactions = append(transactions, &tx)
	}

	return transactions, nil
}

// ListByWalletIDs retrieves transactions for multiple wallets
func (r *TransactionRepository) ListByWalletIDs(ctx context.Context, walletIDs []uuid.UUID, limit int) ([]*Transaction, error) {
	if limit <= 0 {
		limit = 100
	}

	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, wallet_id, chain_id, tx_hash, status, method,
			to_address, value, data, nonce, gas_limit,
			max_fee_per_gas, max_priority_fee_per_gas, signed_tx, error_message,
			app_id, created_at, updated_at
		FROM transactions
		WHERE wallet_id = ANY($1) AND app_id = $2
		ORDER BY created_at DESC
		LIMIT $3
	`

	rows, err := r.store.pool.Query(ctx, query, walletIDs, appID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list transactions: %w", err)
	}
	defer rows.Close()

	var transactions []*Transaction
	for rows.Next() {
		var tx Transaction
		if err := rows.Scan(
			&tx.ID,
			&tx.WalletID,
			&tx.ChainID,
			&tx.TxHash,
			&tx.Status,
			&tx.Method,
			&tx.ToAddress,
			&tx.Value,
			&tx.Data,
			&tx.Nonce,
			&tx.GasLimit,
			&tx.MaxFeePerGas,
			&tx.MaxPriorityFeePerGas,
			&tx.SignedTx,
			&tx.ErrorMessage,
			&tx.AppID,
			&tx.CreatedAt,
			&tx.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %w", err)
		}
		transactions = append(transactions, &tx)
	}

	return transactions, nil
}

// GetByAppID retrieves all transactions for an app
func (r *TransactionRepository) GetByAppID(ctx context.Context, appID uuid.UUID, limit int) ([]*Transaction, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT id, wallet_id, chain_id, tx_hash, status, method,
			to_address, value, data, nonce, gas_limit,
			max_fee_per_gas, max_priority_fee_per_gas, signed_tx, error_message,
			app_id, created_at, updated_at
		FROM transactions
		WHERE app_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.store.pool.Query(ctx, query, appID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get transactions by app ID: %w", err)
	}
	defer rows.Close()

	var transactions []*Transaction
	for rows.Next() {
		var tx Transaction
		if err := rows.Scan(
			&tx.ID,
			&tx.WalletID,
			&tx.ChainID,
			&tx.TxHash,
			&tx.Status,
			&tx.Method,
			&tx.ToAddress,
			&tx.Value,
			&tx.Data,
			&tx.Nonce,
			&tx.GasLimit,
			&tx.MaxFeePerGas,
			&tx.MaxPriorityFeePerGas,
			&tx.SignedTx,
			&tx.ErrorMessage,
			&tx.AppID,
			&tx.CreatedAt,
			&tx.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %w", err)
		}
		transactions = append(transactions, &tx)
	}

	return transactions, nil
}

// UpdateStatus updates the status of a transaction
func (r *TransactionRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string, txHash *string, errorMessage *string) error {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return err
	}

	query := `
		UPDATE transactions
		SET status = $2, tx_hash = COALESCE($3, tx_hash), error_message = $4, updated_at = NOW()
		WHERE id = $1 AND app_id = $5
	`

	_, err = r.store.pool.Exec(ctx, query, id, status, txHash, errorMessage, appID)
	if err != nil {
		return fmt.Errorf("failed to update transaction status: %w", err)
	}

	return nil
}
