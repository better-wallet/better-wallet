package storage

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuthorizationKeyRepository handles authorization key persistence
type AuthorizationKeyRepository struct {
	store *Store
}

// NewAuthorizationKeyRepository creates a new authorization key repository
func NewAuthorizationKeyRepository(store *Store) *AuthorizationKeyRepository {
	return &AuthorizationKeyRepository{store: store}
}

// Create creates a new authorization key
func (r *AuthorizationKeyRepository) Create(ctx context.Context, key *types.AuthorizationKey) error {
	if key.AppID == nil {
		appID, err := RequireAppID(ctx)
		if err != nil {
			return err
		}
		key.AppID = &appID
	}

	query := `
		INSERT INTO authorization_keys (id, public_key, algorithm, owner_entity, status, app_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		RETURNING created_at
	`

	publicKeyHex, err := encodeAuthorizationKeyPublicKey(key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode authorization key public key: %w", err)
	}

	err = r.store.pool.QueryRow(
		ctx,
		query,
		key.ID,
		publicKeyHex,
		key.Algorithm,
		key.OwnerEntity,
		key.Status,
		key.AppID,
	).Scan(&key.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create authorization key: %w", err)
	}

	return nil
}

// CreateTx creates a new authorization key within a transaction
func (r *AuthorizationKeyRepository) CreateTx(ctx context.Context, tx DBTX, key *types.AuthorizationKey) error {
	if key.AppID == nil {
		appID, err := RequireAppID(ctx)
		if err != nil {
			return err
		}
		key.AppID = &appID
	}

	query := `
		INSERT INTO authorization_keys (id, public_key, algorithm, owner_entity, status, app_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		RETURNING created_at
	`

	publicKeyHex, err := encodeAuthorizationKeyPublicKey(key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode authorization key public key: %w", err)
	}

	err = tx.QueryRow(
		ctx,
		query,
		key.ID,
		publicKeyHex,
		key.Algorithm,
		key.OwnerEntity,
		key.Status,
		key.AppID,
	).Scan(&key.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create authorization key: %w", err)
	}

	return nil
}

// GetByID retrieves an authorization key by ID
func (r *AuthorizationKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*types.AuthorizationKey, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, public_key, algorithm, owner_entity, status, app_id, created_at, rotated_at
		FROM authorization_keys
		WHERE id = $1 AND app_id = $2
	`

	key := &types.AuthorizationKey{}
	var publicKeyHex string
	err = r.store.pool.QueryRow(ctx, query, id, appID).Scan(
		&key.ID,
		&publicKeyHex,
		&key.Algorithm,
		&key.OwnerEntity,
		&key.Status,
		&key.AppID,
		&key.CreatedAt,
		&key.RotatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get authorization key: %w", err)
	}

	key.PublicKey, err = decodeAuthorizationKeyPublicKey(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode authorization key public key: %w", err)
	}

	return key, nil
}

// GetByIDAndAppID retrieves an authorization key by ID scoped to an app
func (r *AuthorizationKeyRepository) GetByIDAndAppID(ctx context.Context, id, appID uuid.UUID) (*types.AuthorizationKey, error) {
	query := `
		SELECT id, public_key, algorithm, owner_entity, status, app_id, created_at, rotated_at
		FROM authorization_keys
		WHERE id = $1 AND app_id = $2
	`

	key := &types.AuthorizationKey{}
	var publicKeyHex string
	err := r.store.pool.QueryRow(ctx, query, id, appID).Scan(
		&key.ID,
		&publicKeyHex,
		&key.Algorithm,
		&key.OwnerEntity,
		&key.Status,
		&key.AppID,
		&key.CreatedAt,
		&key.RotatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get authorization key: %w", err)
	}

	key.PublicKey, err = decodeAuthorizationKeyPublicKey(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode authorization key public key: %w", err)
	}

	return key, nil
}

// GetActiveByOwnerEntity retrieves all active keys for an owner entity
func (r *AuthorizationKeyRepository) GetActiveByOwnerEntity(ctx context.Context, ownerEntity string) ([]*types.AuthorizationKey, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}
	return r.GetActiveByOwnerEntityAndAppID(ctx, ownerEntity, appID)
}

// GetActiveByOwnerEntityAndAppID retrieves all active keys for an owner entity scoped to an app
func (r *AuthorizationKeyRepository) GetActiveByOwnerEntityAndAppID(ctx context.Context, ownerEntity string, appID uuid.UUID) ([]*types.AuthorizationKey, error) {
	query := `
		SELECT id, public_key, algorithm, owner_entity, status, app_id, created_at, rotated_at
		FROM authorization_keys
		WHERE owner_entity = $1 AND status = 'active' AND app_id = $2
		ORDER BY created_at DESC
	`

	rows, err := r.store.pool.Query(ctx, query, ownerEntity, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to query authorization keys: %w", err)
	}
	defer rows.Close()

	var keys []*types.AuthorizationKey
	for rows.Next() {
		key := &types.AuthorizationKey{}
		var publicKeyHex string
		if err := rows.Scan(
			&key.ID,
			&publicKeyHex,
			&key.Algorithm,
			&key.OwnerEntity,
			&key.Status,
			&key.AppID,
			&key.CreatedAt,
			&key.RotatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan authorization key: %w", err)
		}
		key.PublicKey, err = decodeAuthorizationKeyPublicKey(publicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode authorization key public key: %w", err)
		}
		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating authorization keys: %w", err)
	}

	return keys, nil
}

// GetByAppID retrieves all authorization keys for an app
func (r *AuthorizationKeyRepository) GetByAppID(ctx context.Context, appID uuid.UUID) ([]*types.AuthorizationKey, error) {
	query := `
		SELECT id, public_key, algorithm, owner_entity, status, app_id, created_at, rotated_at
		FROM authorization_keys
		WHERE app_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.store.pool.Query(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to query authorization keys: %w", err)
	}
	defer rows.Close()

	var keys []*types.AuthorizationKey
	for rows.Next() {
		key := &types.AuthorizationKey{}
		var publicKeyHex string
		if err := rows.Scan(
			&key.ID,
			&publicKeyHex,
			&key.Algorithm,
			&key.OwnerEntity,
			&key.Status,
			&key.AppID,
			&key.CreatedAt,
			&key.RotatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan authorization key: %w", err)
		}
		key.PublicKey, err = decodeAuthorizationKeyPublicKey(publicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode authorization key public key: %w", err)
		}
		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating authorization keys: %w", err)
	}

	return keys, nil
}

// GetActiveByAppID retrieves all active authorization keys for an app
func (r *AuthorizationKeyRepository) GetActiveByAppID(ctx context.Context, appID uuid.UUID) ([]*types.AuthorizationKey, error) {
	query := `
		SELECT id, public_key, algorithm, owner_entity, status, app_id, created_at, rotated_at
		FROM authorization_keys
		WHERE app_id = $1 AND status = 'active'
		ORDER BY created_at DESC
	`

	rows, err := r.store.pool.Query(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to query authorization keys: %w", err)
	}
	defer rows.Close()

	var keys []*types.AuthorizationKey
	for rows.Next() {
		key := &types.AuthorizationKey{}
		var publicKeyHex string
		if err := rows.Scan(
			&key.ID,
			&publicKeyHex,
			&key.Algorithm,
			&key.OwnerEntity,
			&key.Status,
			&key.AppID,
			&key.CreatedAt,
			&key.RotatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan authorization key: %w", err)
		}
		key.PublicKey, err = decodeAuthorizationKeyPublicKey(publicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode authorization key public key: %w", err)
		}
		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating authorization keys: %w", err)
	}

	return keys, nil
}

// UpdateStatus updates the status of an authorization key
func (r *AuthorizationKeyRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return err
	}

	query := `
		UPDATE authorization_keys
		SET status = $1, rotated_at = CASE WHEN $1 = 'rotated' THEN NOW() ELSE rotated_at END
		WHERE id = $2 AND app_id = $3
	`

	result, err := r.store.pool.Exec(ctx, query, status, id, appID)
	if err != nil {
		return fmt.Errorf("failed to update authorization key status: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("authorization key not found")
	}

	return nil
}

// RotateKey marks a key as rotated
func (r *AuthorizationKeyRepository) RotateKey(ctx context.Context, id uuid.UUID) error {
	return r.UpdateStatus(ctx, id, types.StatusRotated)
}

// RevokeKey marks a key as revoked
func (r *AuthorizationKeyRepository) RevokeKey(ctx context.Context, id uuid.UUID) error {
	return r.UpdateStatus(ctx, id, types.StatusRevoked)
}

func encodeAuthorizationKeyPublicKey(publicKey []byte) (string, error) {
	if len(publicKey) == 0 {
		return "", fmt.Errorf("public key is empty")
	}
	return hex.EncodeToString(publicKey), nil
}

func decodeAuthorizationKeyPublicKey(publicKeyHex string) ([]byte, error) {
	publicKeyHex = strings.TrimSpace(publicKeyHex)
	publicKeyHex = strings.TrimPrefix(publicKeyHex, "0x")
	if publicKeyHex == "" {
		return nil, fmt.Errorf("public key hex is empty")
	}
	if len(publicKeyHex)%2 != 0 {
		return nil, fmt.Errorf("public key hex must have even length")
	}
	decoded, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("public key hex must be valid hex: %w", err)
	}
	return decoded, nil
}
