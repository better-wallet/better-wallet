package storage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// AppRepository handles app data access for authentication middleware
type AppRepository struct {
	store *Store
}

// NewAppRepository creates a new app repository
func NewAppRepository(store *Store) *AppRepository {
	return &AppRepository{store: store}
}

// GetByID retrieves an app by ID (used for auth validation)
func (r *AppRepository) GetByID(ctx context.Context, id uuid.UUID) (*types.App, error) {
	query := `
		SELECT id, name, description, owner_id, status, settings, created_at, updated_at
		FROM apps
		WHERE id = $1
	`

	var app types.App
	var settingsJSON []byte
	err := r.store.pool.QueryRow(ctx, query, id).Scan(
		&app.ID,
		&app.Name,
		&app.Description,
		&app.OwnerUserID,
		&app.Status,
		&settingsJSON,
		&app.CreatedAt,
		&app.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get app: %w", err)
	}

	// Parse settings JSON
	if len(settingsJSON) > 0 {
		if err := json.Unmarshal(settingsJSON, &app.Settings); err != nil {
			return nil, fmt.Errorf("failed to parse app settings: %w", err)
		}
	}

	return &app, nil
}
