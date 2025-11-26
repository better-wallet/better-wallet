package storage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ConditionSetRepository handles condition set data operations
type ConditionSetRepository struct {
	store *Store
}

// NewConditionSetRepository creates a new ConditionSetRepository
func NewConditionSetRepository(store *Store) *ConditionSetRepository {
	return &ConditionSetRepository{store: store}
}

// Create creates a new condition set
func (r *ConditionSetRepository) Create(ctx context.Context, cs *types.ConditionSet) error {
	valuesJSON, err := json.Marshal(cs.Values)
	if err != nil {
		return fmt.Errorf("failed to marshal values: %w", err)
	}

	query := `
		INSERT INTO condition_sets (id, name, description, values, owner_id)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at, updated_at
	`

	err = r.store.pool.QueryRow(ctx, query,
		cs.ID,
		cs.Name,
		cs.Description,
		valuesJSON,
		cs.OwnerID,
	).Scan(&cs.CreatedAt, &cs.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create condition set: %w", err)
	}

	return nil
}

// GetByID retrieves a condition set by ID
func (r *ConditionSetRepository) GetByID(ctx context.Context, id uuid.UUID) (*types.ConditionSet, error) {
	query := `
		SELECT id, name, description, values, owner_id, created_at, updated_at
		FROM condition_sets
		WHERE id = $1
	`

	var cs types.ConditionSet
	var valuesJSON []byte
	var description *string

	err := r.store.pool.QueryRow(ctx, query, id).Scan(
		&cs.ID,
		&cs.Name,
		&description,
		&valuesJSON,
		&cs.OwnerID,
		&cs.CreatedAt,
		&cs.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get condition set by ID: %w", err)
	}

	if description != nil {
		cs.Description = *description
	}

	if err := json.Unmarshal(valuesJSON, &cs.Values); err != nil {
		return nil, fmt.Errorf("failed to unmarshal values: %w", err)
	}

	return &cs, nil
}

// GetByOwnerIDs retrieves condition sets owned by any of the given owner IDs
func (r *ConditionSetRepository) GetByOwnerIDs(ctx context.Context, ownerIDs []uuid.UUID) ([]*types.ConditionSet, error) {
	if len(ownerIDs) == 0 {
		return []*types.ConditionSet{}, nil
	}

	query := `
		SELECT id, name, description, values, owner_id, created_at, updated_at
		FROM condition_sets
		WHERE owner_id = ANY($1)
		ORDER BY created_at DESC
	`

	rows, err := r.store.pool.Query(ctx, query, ownerIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get condition sets by owner IDs: %w", err)
	}
	defer rows.Close()

	var sets []*types.ConditionSet
	for rows.Next() {
		var cs types.ConditionSet
		var valuesJSON []byte
		var description *string

		err := rows.Scan(
			&cs.ID,
			&cs.Name,
			&description,
			&valuesJSON,
			&cs.OwnerID,
			&cs.CreatedAt,
			&cs.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan condition set: %w", err)
		}

		if description != nil {
			cs.Description = *description
		}

		if err := json.Unmarshal(valuesJSON, &cs.Values); err != nil {
			return nil, fmt.Errorf("failed to unmarshal values: %w", err)
		}

		sets = append(sets, &cs)
	}

	return sets, nil
}

// Update updates a condition set
func (r *ConditionSetRepository) Update(ctx context.Context, cs *types.ConditionSet) error {
	valuesJSON, err := json.Marshal(cs.Values)
	if err != nil {
		return fmt.Errorf("failed to marshal values: %w", err)
	}

	query := `
		UPDATE condition_sets
		SET name = $1, description = $2, values = $3, updated_at = NOW()
		WHERE id = $4
		RETURNING updated_at
	`

	err = r.store.pool.QueryRow(ctx, query,
		cs.Name,
		cs.Description,
		valuesJSON,
		cs.ID,
	).Scan(&cs.UpdatedAt)

	if err == pgx.ErrNoRows {
		return fmt.Errorf("condition set not found")
	}
	if err != nil {
		return fmt.Errorf("failed to update condition set: %w", err)
	}

	return nil
}

// Delete deletes a condition set by ID
func (r *ConditionSetRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM condition_sets WHERE id = $1`

	result, err := r.store.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete condition set: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("condition set not found")
	}

	return nil
}
