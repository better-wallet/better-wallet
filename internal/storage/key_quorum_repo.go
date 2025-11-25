package storage

import (
	"context"
	"fmt"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// KeyQuorumRepository handles key quorum data operations
type KeyQuorumRepository struct {
	store *Store
}

// NewKeyQuorumRepository creates a new KeyQuorumRepository
func NewKeyQuorumRepository(store *Store) *KeyQuorumRepository {
	return &KeyQuorumRepository{store: store}
}

// Create creates a new key quorum
func (r *KeyQuorumRepository) Create(ctx context.Context, kq *types.KeyQuorum) error {
	query := `
		INSERT INTO key_quorums (id, threshold, key_ids, status, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := r.store.pool.Exec(
		ctx,
		query,
		kq.ID,
		kq.Threshold,
		kq.KeyIDs,
		kq.Status,
		kq.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create key quorum: %w", err)
	}
	return nil
}

// GetByID retrieves a key quorum by ID
func (r *KeyQuorumRepository) GetByID(ctx context.Context, id uuid.UUID) (*types.KeyQuorum, error) {
	query := `
		SELECT id, threshold, key_ids, status, created_at
		FROM key_quorums
		WHERE id = $1
	`

	var kq types.KeyQuorum
	err := r.store.pool.QueryRow(ctx, query, id).Scan(
		&kq.ID,
		&kq.Threshold,
		&kq.KeyIDs,
		&kq.Status,
		&kq.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get key quorum: %w", err)
	}
	return &kq, nil
}

// Update updates a key quorum
func (r *KeyQuorumRepository) Update(ctx context.Context, kq *types.KeyQuorum) error {
	query := `
		UPDATE key_quorums
		SET threshold = $2, key_ids = $3, status = $4
		WHERE id = $1
	`
	result, err := r.store.pool.Exec(
		ctx,
		query,
		kq.ID,
		kq.Threshold,
		kq.KeyIDs,
		kq.Status,
	)
	if err != nil {
		return fmt.Errorf("failed to update key quorum: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("key quorum not found")
	}
	return nil
}

// Delete deletes a key quorum
func (r *KeyQuorumRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM key_quorums WHERE id = $1`
	result, err := r.store.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete key quorum: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("key quorum not found")
	}
	return nil
}
