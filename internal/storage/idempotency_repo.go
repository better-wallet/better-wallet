package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// IdempotencyRepository handles idempotency key storage
type IdempotencyRepository struct {
	store *Store
}

// NewIdempotencyRepository creates a new repository
func NewIdempotencyRepository(store *Store) *IdempotencyRepository {
	return &IdempotencyRepository{store: store}
}

// CheckAndRecord inserts the idempotency key if not present; if already present it returns an error
func (r *IdempotencyRepository) CheckAndRecord(ctx context.Context, appID, key, method, url, requestDigest string) error {
	query := `
        INSERT INTO idempotency_keys (app_id, idempotency_key, method, url, request_digest)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (app_id, idempotency_key) DO NOTHING
        RETURNING id
    `

	var id int64
	err := r.store.pool.QueryRow(ctx, query, appID, key, method, url, requestDigest).Scan(&id)
	if err != nil {
		// On conflict (existing key) Scan returns ErrNoRows
		if err == pgx.ErrNoRows {
			return fmt.Errorf("idempotency key already used")
		}
		return fmt.Errorf("failed to record idempotency key: %w", err)
	}

	return nil
}
