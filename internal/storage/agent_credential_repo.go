package storage

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AgentCredentialRepo struct {
	db DBTX
}

func NewAgentCredentialRepo(db DBTX) *AgentCredentialRepo {
	return &AgentCredentialRepo{db: db}
}

func (r *AgentCredentialRepo) Create(ctx context.Context, cred *types.AgentCredential, keyHash string) error {
	capabilitiesJSON, err := json.Marshal(cred.Capabilities)
	if err != nil {
		return err
	}
	limitsJSON, err := json.Marshal(cred.Limits)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO agent_credentials (id, wallet_id, name, key_hash, key_prefix, capabilities, limits, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err = r.db.Exec(ctx, query,
		cred.ID, cred.WalletID, cred.Name, keyHash, cred.KeyPrefix,
		capabilitiesJSON, limitsJSON, cred.Status, cred.CreatedAt,
	)
	return err
}

func (r *AgentCredentialRepo) GetByID(ctx context.Context, id uuid.UUID) (*types.AgentCredential, error) {
	query := `
		SELECT id, wallet_id, name, key_prefix, capabilities, limits, status, last_used_at, created_at, paused_at, revoked_at
		FROM agent_credentials WHERE id = $1
	`
	var cred types.AgentCredential
	var capabilitiesJSON, limitsJSON []byte
	err := r.db.QueryRow(ctx, query, id).Scan(
		&cred.ID, &cred.WalletID, &cred.Name, &cred.KeyPrefix,
		&capabilitiesJSON, &limitsJSON, &cred.Status,
		&cred.LastUsedAt, &cred.CreatedAt, &cred.PausedAt, &cred.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(capabilitiesJSON, &cred.Capabilities); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(limitsJSON, &cred.Limits); err != nil {
		return nil, err
	}
	return &cred, nil
}

func (r *AgentCredentialRepo) GetByPrefixWithHash(ctx context.Context, prefix string) (*types.AgentCredential, string, error) {
	query := `
		SELECT id, wallet_id, name, key_hash, key_prefix, capabilities, limits, status, last_used_at, created_at, paused_at, revoked_at
		FROM agent_credentials WHERE key_prefix = $1
	`
	var cred types.AgentCredential
	var keyHash string
	var capabilitiesJSON, limitsJSON []byte
	err := r.db.QueryRow(ctx, query, prefix).Scan(
		&cred.ID, &cred.WalletID, &cred.Name, &keyHash, &cred.KeyPrefix,
		&capabilitiesJSON, &limitsJSON, &cred.Status,
		&cred.LastUsedAt, &cred.CreatedAt, &cred.PausedAt, &cred.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal(capabilitiesJSON, &cred.Capabilities); err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal(limitsJSON, &cred.Limits); err != nil {
		return nil, "", err
	}
	return &cred, keyHash, nil
}

func (r *AgentCredentialRepo) ListByWallet(ctx context.Context, walletID uuid.UUID) ([]*types.AgentCredential, error) {
	query := `
		SELECT id, wallet_id, name, key_prefix, capabilities, limits, status, last_used_at, created_at, paused_at, revoked_at
		FROM agent_credentials WHERE wallet_id = $1 ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, walletID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*types.AgentCredential
	for rows.Next() {
		var cred types.AgentCredential
		var capabilitiesJSON, limitsJSON []byte
		if err := rows.Scan(
			&cred.ID, &cred.WalletID, &cred.Name, &cred.KeyPrefix,
			&capabilitiesJSON, &limitsJSON, &cred.Status,
			&cred.LastUsedAt, &cred.CreatedAt, &cred.PausedAt, &cred.RevokedAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(capabilitiesJSON, &cred.Capabilities); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(limitsJSON, &cred.Limits); err != nil {
			return nil, err
		}
		creds = append(creds, &cred)
	}
	return creds, rows.Err()
}

func (r *AgentCredentialRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	var query string
	switch status {
	case types.AgentStatusPaused:
		query = `UPDATE agent_credentials SET status = $1, paused_at = NOW() WHERE id = $2`
	case types.AgentStatusRevoked:
		query = `UPDATE agent_credentials SET status = $1, revoked_at = NOW() WHERE id = $2`
	default:
		query = `UPDATE agent_credentials SET status = $1 WHERE id = $2`
	}
	_, err := r.db.Exec(ctx, query, status, id)
	return err
}

func (r *AgentCredentialRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE agent_credentials SET last_used_at = NOW() WHERE id = $1`, id)
	return err
}
