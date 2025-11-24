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

// GetActiveByWallet retrieves active (non-revoked, unexpired) session signers for a wallet
func (r *SessionSignerRepository) GetActiveByWallet(ctx context.Context, walletID uuid.UUID, now time.Time) ([]*types.SessionSigner, error) {
	query := `
        SELECT id, wallet_id, signer_id, policy_override_id, allowed_methods, max_value, max_txs, ttl_expires_at, created_at, revoked_at
        FROM session_signers
        WHERE wallet_id = $1
          AND (revoked_at IS NULL)
          AND ttl_expires_at > $2
    `

	rows, err := r.store.pool.Query(ctx, query, walletID, now)
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
	query := `
        SELECT id, wallet_id, signer_id, policy_override_id, allowed_methods, max_value, max_txs, ttl_expires_at, created_at, revoked_at
        FROM session_signers
        WHERE id = $1
    `

	ss := &types.SessionSigner{}
	err := r.store.pool.QueryRow(ctx, query, id).Scan(
		&ss.ID,
		&ss.WalletID,
		&ss.SignerID,
		&ss.PolicyOverrideID,
		&ss.AllowedMethods,
		&ss.MaxValue,
		&ss.MaxTxs,
		&ss.TTLExpiresAt,
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
