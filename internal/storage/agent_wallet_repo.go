package storage

import (
	"context"
	"errors"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AgentWalletRepo struct {
	db DBTX
}

func NewAgentWalletRepo(db DBTX) *AgentWalletRepo {
	return &AgentWalletRepo{db: db}
}

func (r *AgentWalletRepo) Create(ctx context.Context, wallet *types.AgentWallet) error {
	query := `
		INSERT INTO agent_wallets (id, principal_id, name, chain_type, address, exec_backend, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.db.Exec(ctx, query,
		wallet.ID, wallet.PrincipalID, wallet.Name, wallet.ChainType, wallet.Address,
		wallet.ExecBackend, wallet.Status, wallet.CreatedAt, wallet.UpdatedAt,
	)
	return err
}

func (r *AgentWalletRepo) GetByID(ctx context.Context, id uuid.UUID) (*types.AgentWallet, error) {
	query := `
		SELECT id, principal_id, name, chain_type, address, exec_backend, status, created_at, updated_at
		FROM agent_wallets WHERE id = $1
	`
	var w types.AgentWallet
	err := r.db.QueryRow(ctx, query, id).Scan(
		&w.ID, &w.PrincipalID, &w.Name, &w.ChainType, &w.Address,
		&w.ExecBackend, &w.Status, &w.CreatedAt, &w.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func (r *AgentWalletRepo) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*types.AgentWallet, error) {
	query := `
		SELECT id, principal_id, name, chain_type, address, exec_backend, status, created_at, updated_at
		FROM agent_wallets WHERE principal_id = $1 ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var wallets []*types.AgentWallet
	for rows.Next() {
		var w types.AgentWallet
		if err := rows.Scan(&w.ID, &w.PrincipalID, &w.Name, &w.ChainType, &w.Address,
			&w.ExecBackend, &w.Status, &w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, err
		}
		wallets = append(wallets, &w)
	}
	return wallets, rows.Err()
}

func (r *AgentWalletRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := r.db.Exec(ctx, `UPDATE agent_wallets SET status = $1, updated_at = NOW() WHERE id = $2`, status, id)
	return err
}

// WalletKeyRepo handles wallet key data access
type WalletKeyRepo struct {
	db DBTX
}

func NewWalletKeyRepo(db DBTX) *WalletKeyRepo {
	return &WalletKeyRepo{db: db}
}

func (r *WalletKeyRepo) Create(ctx context.Context, key *types.WalletKey) error {
	query := `INSERT INTO wallet_keys (wallet_id, encrypted_key, kms_key_id, created_at) VALUES ($1, $2, $3, $4)`
	_, err := r.db.Exec(ctx, query, key.WalletID, key.EncryptedKey, key.KMSKeyID, key.CreatedAt)
	return err
}

func (r *WalletKeyRepo) GetByWalletID(ctx context.Context, walletID uuid.UUID) (*types.WalletKey, error) {
	query := `SELECT wallet_id, encrypted_key, kms_key_id, created_at FROM wallet_keys WHERE wallet_id = $1`
	var k types.WalletKey
	err := r.db.QueryRow(ctx, query, walletID).Scan(&k.WalletID, &k.EncryptedKey, &k.KMSKeyID, &k.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}
