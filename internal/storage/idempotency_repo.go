package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// IdempotencyRepo handles idempotency key storage with response caching
type IdempotencyRepo struct {
	store *Store
}

// NewIdempotencyRepo creates a new repository
func NewIdempotencyRepo(store *Store) *IdempotencyRepo {
	return &IdempotencyRepo{store: store}
}

// IdempotencyRecord represents a cached idempotency record
type IdempotencyRecord struct {
	AppID      string
	Key        string
	Method     string // HTTP method (POST, PATCH, DELETE)
	URL        string // Request URL path
	BodyHash   string
	StatusCode int
	Headers    http.Header
	Body       []byte
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// Get retrieves an idempotency record by app_id, key, method, and url
// Returns error if not found or expired
func (r *IdempotencyRepo) Get(ctx context.Context, appID, key, method, url string) (*IdempotencyRecord, error) {
	query := `
		SELECT method, url, body_hash, status_code, headers, body, expires_at, created_at
		FROM idempotency_records
		WHERE app_id = $1 AND key = $2 AND method = $3 AND url = $4 AND expires_at > NOW()
	`

	var record IdempotencyRecord
	var headersJSON []byte

	err := r.store.pool.QueryRow(ctx, query, appID, key, method, url).Scan(
		&record.Method,
		&record.URL,
		&record.BodyHash,
		&record.StatusCode,
		&headersJSON,
		&record.Body,
		&record.ExpiresAt,
		&record.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("idempotency key not found")
		}
		return nil, fmt.Errorf("failed to get idempotency record: %w", err)
	}

	record.AppID = appID
	record.Key = key

	// Parse headers from JSON
	if err := json.Unmarshal(headersJSON, &record.Headers); err != nil {
		return nil, fmt.Errorf("failed to unmarshal headers: %w", err)
	}
	if record.Headers == nil {
		record.Headers = make(http.Header)
	}

	return &record, nil
}

// Store saves an idempotency record
func (r *IdempotencyRepo) Store(ctx context.Context, record *IdempotencyRecord) error {
	query := `
		INSERT INTO idempotency_records (
			app_id, key, method, url, body_hash, status_code, headers, body, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (app_id, key, method, url) DO NOTHING
	`

	// Encode headers to JSON
	headersJSON, err := json.Marshal(record.Headers)
	if err != nil {
		return fmt.Errorf("failed to marshal headers: %w", err)
	}

	_, err = r.store.pool.Exec(ctx, query,
		record.AppID,
		record.Key,
		record.Method,
		record.URL,
		record.BodyHash,
		record.StatusCode,
		headersJSON,
		record.Body,
		record.ExpiresAt,
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to store idempotency record: %w", err)
	}

	return nil
}

// Exists checks if an idempotency key exists (without retrieving full record)
func (r *IdempotencyRepo) Exists(ctx context.Context, appID, key string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM idempotency_records
			WHERE app_id = $1 AND key = $2 AND expires_at > NOW()
		)
	`

	var exists bool
	err := r.store.pool.QueryRow(ctx, query, appID, key).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check idempotency key: %w", err)
	}

	return exists, nil
}

// Cleanup removes expired idempotency records
// This should be called periodically (e.g., via cron job)
func (r *IdempotencyRepo) Cleanup(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM idempotency_records
		WHERE expires_at < NOW()
	`

	result, err := r.store.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired records: %w", err)
	}

	return result.RowsAffected(), nil
}
