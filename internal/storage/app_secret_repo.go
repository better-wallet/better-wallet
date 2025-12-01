package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// AppSecretRepository handles app secret data access for authentication middleware
// Note: App secret CRUD operations are handled by Dashboard (tRPC), this repo is read-only for API auth
type AppSecretRepository struct {
	store *Store
}

// NewAppSecretRepository creates a new app secret repository
func NewAppSecretRepository(store *Store) *AppSecretRepository {
	return &AppSecretRepository{store: store}
}

// GetBySecretPrefix retrieves active secrets by prefix (used for auth validation)
func (r *AppSecretRepository) GetBySecretPrefix(ctx context.Context, prefix string) ([]*types.AppSecret, error) {
	query := `
		SELECT id, app_id, secret_hash, secret_prefix, status, last_used_at, created_at, rotated_at, expires_at
		FROM app_secrets
		WHERE secret_prefix = $1 AND status = 'active'
	`

	rows, err := r.store.pool.Query(ctx, query, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets by prefix: %w", err)
	}
	defer rows.Close()

	var secrets []*types.AppSecret
	for rows.Next() {
		var secret types.AppSecret
		if err := rows.Scan(
			&secret.ID,
			&secret.AppID,
			&secret.SecretHash,
			&secret.SecretPrefix,
			&secret.Status,
			&secret.LastUsedAt,
			&secret.CreatedAt,
			&secret.RotatedAt,
			&secret.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}
		secrets = append(secrets, &secret)
	}

	return secrets, nil
}

// UpdateLastUsed updates the last_used_at timestamp for a secret
func (r *AppSecretRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE app_secrets SET last_used_at = $2 WHERE id = $1`
	_, err := r.store.pool.Exec(ctx, query, id, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}
	return nil
}
