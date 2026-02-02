package storage

import (
	"context"
	"errors"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PrincipalRepo handles principal data access
type PrincipalRepo struct {
	db DBTX
}

func NewPrincipalRepo(db DBTX) *PrincipalRepo {
	return &PrincipalRepo{db: db}
}

func (r *PrincipalRepo) Create(ctx context.Context, principal *types.Principal) error {
	query := `
		INSERT INTO principals (id, name, email, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.Exec(ctx, query,
		principal.ID, principal.Name, principal.Email, principal.EmailVerified,
		principal.CreatedAt, principal.UpdatedAt,
	)
	return err
}

func (r *PrincipalRepo) GetByID(ctx context.Context, id uuid.UUID) (*types.Principal, error) {
	query := `SELECT id, name, email, email_verified, created_at, updated_at FROM principals WHERE id = $1`
	var p types.Principal
	err := r.db.QueryRow(ctx, query, id).Scan(&p.ID, &p.Name, &p.Email, &p.EmailVerified, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *PrincipalRepo) GetByEmail(ctx context.Context, email string) (*types.Principal, error) {
	query := `SELECT id, name, email, email_verified, created_at, updated_at FROM principals WHERE email = $1`
	var p types.Principal
	err := r.db.QueryRow(ctx, query, email).Scan(&p.ID, &p.Name, &p.Email, &p.EmailVerified, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// PrincipalAPIKeyRepo handles principal API key data access
type PrincipalAPIKeyRepo struct {
	db DBTX
}

func NewPrincipalAPIKeyRepo(db DBTX) *PrincipalAPIKeyRepo {
	return &PrincipalAPIKeyRepo{db: db}
}

func (r *PrincipalAPIKeyRepo) Create(ctx context.Context, key *types.PrincipalAPIKey, keyHash string) error {
	query := `
		INSERT INTO principal_api_keys (id, principal_id, key_hash, key_prefix, name, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.Exec(ctx, query,
		key.ID, key.PrincipalID, keyHash, key.KeyPrefix, key.Name, key.Status, key.CreatedAt,
	)
	return err
}

func (r *PrincipalAPIKeyRepo) GetByPrefix(ctx context.Context, prefix string) (*types.PrincipalAPIKey, string, error) {
	query := `
		SELECT id, principal_id, key_hash, key_prefix, name, status, last_used_at, created_at, revoked_at
		FROM principal_api_keys WHERE key_prefix = $1 AND status = 'active'
	`
	var key types.PrincipalAPIKey
	var keyHash string
	err := r.db.QueryRow(ctx, query, prefix).Scan(
		&key.ID, &key.PrincipalID, &keyHash, &key.KeyPrefix, &key.Name,
		&key.Status, &key.LastUsedAt, &key.CreatedAt, &key.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return &key, keyHash, nil
}

func (r *PrincipalAPIKeyRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE principal_api_keys SET last_used_at = NOW() WHERE id = $1`, id)
	return err
}

func (r *PrincipalAPIKeyRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE principal_api_keys SET status = 'revoked', revoked_at = NOW() WHERE id = $1`, id)
	return err
}
