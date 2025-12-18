package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SessionSignerRepository handles session signer persistence
type SessionSignerRepository struct {
	store *Store
}

// NewSessionSignerRepository creates a new repository
func NewSessionSignerRepository(store *Store) *SessionSignerRepository {
	return &SessionSignerRepository{store: store}
}

// CreateTx inserts a session signer using provided transaction/connection
func (r *SessionSignerRepository) CreateTx(ctx context.Context, db DBTX, ss *types.SessionSigner) error {
	if ss.AppID == nil {
		appID, err := RequireAppID(ctx)
		if err != nil {
			return err
		}
		ss.AppID = &appID
	}

	query := `
		INSERT INTO session_signers (
			id, wallet_id, signer_id, policy_override_id, allowed_methods,
			max_value, max_txs, ttl_expires_at, app_id, created_at, revoked_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10)
		RETURNING created_at
	`

	return db.QueryRow(ctx, query,
		ss.ID,
		ss.WalletID,
		ss.SignerID,
		ss.PolicyOverrideID,
		ss.AllowedMethods,
		ss.MaxValue,
		ss.MaxTxs,
		ss.TTLExpiresAt,
		ss.AppID,
		ss.RevokedAt,
	).Scan(&ss.CreatedAt)
}

// GetActiveByWallet retrieves active (non-revoked, unexpired) session signers for a wallet
func (r *SessionSignerRepository) GetActiveByWallet(ctx context.Context, walletID uuid.UUID, now time.Time) ([]*types.SessionSigner, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
        SELECT id, wallet_id, signer_id, policy_override_id, allowed_methods, max_value, max_txs, ttl_expires_at, app_id, created_at, revoked_at
        FROM session_signers
        WHERE wallet_id = $1
          AND (revoked_at IS NULL)
          AND ttl_expires_at > $2
		  AND app_id = $3
    `

	rows, err := r.store.pool.Query(ctx, query, walletID, now, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to query session signers: %w", err)
	}
	defer rows.Close()

	var signers []*types.SessionSigner
	for rows.Next() {
		ss := &types.SessionSigner{}
		if err := rows.Scan(
			&ss.ID,
			&ss.WalletID,
			&ss.SignerID,
			&ss.PolicyOverrideID,
			&ss.AllowedMethods,
			&ss.MaxValue,
			&ss.MaxTxs,
			&ss.TTLExpiresAt,
			&ss.AppID,
			&ss.CreatedAt,
			&ss.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan session signer: %w", err)
		}
		signers = append(signers, ss)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session signer rows error: %w", err)
	}

	return signers, nil
}

// GetByID retrieves a session signer by ID
func (r *SessionSignerRepository) GetByID(ctx context.Context, id uuid.UUID) (*types.SessionSigner, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
        SELECT id, wallet_id, signer_id, policy_override_id, allowed_methods, max_value, max_txs, ttl_expires_at, app_id, created_at, revoked_at
        FROM session_signers
        WHERE id = $1 AND app_id = $2
    `

	ss := &types.SessionSigner{}
	err = r.store.pool.QueryRow(ctx, query, id, appID).Scan(
		&ss.ID,
		&ss.WalletID,
		&ss.SignerID,
		&ss.PolicyOverrideID,
		&ss.AllowedMethods,
		&ss.MaxValue,
		&ss.MaxTxs,
		&ss.TTLExpiresAt,
		&ss.AppID,
		&ss.CreatedAt,
		&ss.RevokedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session signer: %w", err)
	}

	return ss, nil
}

// GetByIDAndAppID retrieves a session signer by ID scoped to an app
func (r *SessionSignerRepository) GetByIDAndAppID(ctx context.Context, id, appID uuid.UUID) (*types.SessionSigner, error) {
	query := `
        SELECT id, wallet_id, signer_id, policy_override_id, allowed_methods, max_value, max_txs, ttl_expires_at, app_id, created_at, revoked_at
        FROM session_signers
        WHERE id = $1 AND app_id = $2
    `

	ss := &types.SessionSigner{}
	err := r.store.pool.QueryRow(ctx, query, id, appID).Scan(
		&ss.ID,
		&ss.WalletID,
		&ss.SignerID,
		&ss.PolicyOverrideID,
		&ss.AllowedMethods,
		&ss.MaxValue,
		&ss.MaxTxs,
		&ss.TTLExpiresAt,
		&ss.AppID,
		&ss.CreatedAt,
		&ss.RevokedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session signer: %w", err)
	}

	return ss, nil
}

// ListByWallet returns all session signers (including expired/revoked) for a wallet
func (r *SessionSignerRepository) ListByWallet(ctx context.Context, walletID uuid.UUID) ([]*types.SessionSigner, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, wallet_id, signer_id, policy_override_id, allowed_methods, max_value, max_txs, ttl_expires_at, app_id, created_at, revoked_at
		FROM session_signers
		WHERE wallet_id = $1 AND app_id = $2
		ORDER BY created_at DESC
	`
	rows, err := r.store.pool.Query(ctx, query, walletID, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to list session signers: %w", err)
	}
	defer rows.Close()

	var signers []*types.SessionSigner
	for rows.Next() {
		ss := &types.SessionSigner{}
		if err := rows.Scan(
			&ss.ID,
			&ss.WalletID,
			&ss.SignerID,
			&ss.PolicyOverrideID,
			&ss.AllowedMethods,
			&ss.MaxValue,
			&ss.MaxTxs,
			&ss.TTLExpiresAt,
			&ss.AppID,
			&ss.CreatedAt,
			&ss.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan session signer: %w", err)
		}
		signers = append(signers, ss)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session signer rows error: %w", err)
	}
	return signers, nil
}

// ListByAppID returns all session signers for an app
func (r *SessionSignerRepository) ListByAppID(ctx context.Context, appID uuid.UUID) ([]*types.SessionSigner, error) {
	query := `
		SELECT id, wallet_id, signer_id, policy_override_id, allowed_methods, max_value, max_txs, ttl_expires_at, app_id, created_at, revoked_at
		FROM session_signers
		WHERE app_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.store.pool.Query(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to list session signers: %w", err)
	}
	defer rows.Close()

	var signers []*types.SessionSigner
	for rows.Next() {
		ss := &types.SessionSigner{}
		if err := rows.Scan(
			&ss.ID,
			&ss.WalletID,
			&ss.SignerID,
			&ss.PolicyOverrideID,
			&ss.AllowedMethods,
			&ss.MaxValue,
			&ss.MaxTxs,
			&ss.TTLExpiresAt,
			&ss.AppID,
			&ss.CreatedAt,
			&ss.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan session signer: %w", err)
		}
		signers = append(signers, ss)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session signer rows error: %w", err)
	}
	return signers, nil
}

// Revoke sets revoked_at for a session signer
func (r *SessionSignerRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return err
	}

	query := `
		UPDATE session_signers
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL AND app_id = $2
	`
	cmd, err := r.store.pool.Exec(ctx, query, id, appID)
	if err != nil {
		return fmt.Errorf("failed to revoke session signer: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("session signer not found or already revoked")
	}
	return nil
}
