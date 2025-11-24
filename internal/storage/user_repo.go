package storage

import (
	"context"
	"fmt"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// UserRepository handles user data operations
type UserRepository struct {
	store *Store
}

// NewUserRepository creates a new UserRepository
func NewUserRepository(store *Store) *UserRepository {
	return &UserRepository{store: store}
}

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, externalSub string) (*types.User, error) {
	query := `
		INSERT INTO users (external_sub)
		VALUES ($1)
		RETURNING id, external_sub, created_at
	`

	var user types.User
	err := r.store.pool.QueryRow(ctx, query, externalSub).Scan(
		&user.ID,
		&user.ExternalSub,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &user, nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*types.User, error) {
	query := `
		SELECT id, external_sub, created_at
		FROM users
		WHERE id = $1
	`

	var user types.User
	err := r.store.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.ExternalSub,
		&user.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

// GetByExternalSub retrieves a user by external sub
func (r *UserRepository) GetByExternalSub(ctx context.Context, externalSub string) (*types.User, error) {
	query := `
		SELECT id, external_sub, created_at
		FROM users
		WHERE external_sub = $1
	`

	var user types.User
	err := r.store.pool.QueryRow(ctx, query, externalSub).Scan(
		&user.ID,
		&user.ExternalSub,
		&user.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by external_sub: %w", err)
	}

	return &user, nil
}

// GetOrCreate gets a user by external sub or creates it if it doesn't exist
func (r *UserRepository) GetOrCreate(ctx context.Context, externalSub string) (*types.User, error) {
	user, err := r.GetByExternalSub(ctx, externalSub)
	if err != nil {
		return nil, err
	}
	if user != nil {
		return user, nil
	}

	return r.Create(ctx, externalSub)
}
