package storage

import (
	"context"
	"fmt"

	"github.com/better-wallet/better-wallet/pkg/types"
)

// AuditRepository handles audit log operations
type AuditRepository struct {
	store *Store
}

// NewAuditRepository creates a new AuditRepository
func NewAuditRepository(store *Store) *AuditRepository {
	return &AuditRepository{store: store}
}

// Create creates a new audit log entry
func (r *AuditRepository) Create(ctx context.Context, log *types.AuditLog) error {
	query := `
		INSERT INTO audit_logs (
			actor, action, resource_type, resource_id, policy_result,
			signer_id, tx_hash, request_digest, request_nonce, client_ip, user_agent
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at
	`

	err := r.store.pool.QueryRow(ctx, query,
		log.Actor,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		log.PolicyResult,
		log.SignerID,
		log.TxHash,
		log.RequestDigest,
		log.RequestNonce,
		log.ClientIP,
		log.UserAgent,
	).Scan(&log.ID, &log.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// QueryOptions represents options for querying audit logs
type QueryOptions struct {
	Actor        *string
	ResourceType *string
	ResourceID   *string
	Action       *string
	Limit        int
	Offset       int
}

// Query retrieves audit logs with filtering and pagination
func (r *AuditRepository) Query(ctx context.Context, opts QueryOptions) ([]*types.AuditLog, error) {
	query := `
		SELECT id, actor, action, resource_type, resource_id, policy_result,
		       signer_id, tx_hash, request_digest, request_nonce, client_ip, user_agent, created_at
		FROM audit_logs
		WHERE 1=1
	`

	args := make([]interface{}, 0)
	argCount := 1

	if opts.Actor != nil {
		query += fmt.Sprintf(" AND actor = $%d", argCount)
		args = append(args, *opts.Actor)
		argCount++
	}

	if opts.ResourceType != nil {
		query += fmt.Sprintf(" AND resource_type = $%d", argCount)
		args = append(args, *opts.ResourceType)
		argCount++
	}

	if opts.ResourceID != nil {
		query += fmt.Sprintf(" AND resource_id = $%d", argCount)
		args = append(args, *opts.ResourceID)
		argCount++
	}

	if opts.Action != nil {
		query += fmt.Sprintf(" AND action = $%d", argCount)
		args = append(args, *opts.Action)
		argCount++
	}

	query += " ORDER BY created_at DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, opts.Limit)
		argCount++
	}

	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, opts.Offset)
	}

	rows, err := r.store.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*types.AuditLog
	for rows.Next() {
		var log types.AuditLog
		err := rows.Scan(
			&log.ID,
			&log.Actor,
			&log.Action,
			&log.ResourceType,
			&log.ResourceID,
			&log.PolicyResult,
			&log.SignerID,
			&log.TxHash,
			&log.RequestDigest,
			&log.RequestNonce,
			&log.ClientIP,
			&log.UserAgent,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		logs = append(logs, &log)
	}

	return logs, nil
}
