package storage

import (
	"context"
	"math/big"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

type AgentRateLimitRepo struct {
	db DBTX
}

func NewAgentRateLimitRepo(db DBTX) *AgentRateLimitRepo {
	return &AgentRateLimitRepo{db: db}
}

func (r *AgentRateLimitRepo) GetOrCreate(ctx context.Context, credentialID uuid.UUID, windowType string, windowStart time.Time) (*types.AgentRateLimit, error) {
	query := `
		INSERT INTO agent_rate_limits (credential_id, window_type, window_start, tx_count, total_value)
		VALUES ($1, $2, $3, 0, '0')
		ON CONFLICT (credential_id, window_type, window_start)
		DO UPDATE SET credential_id = agent_rate_limits.credential_id
		RETURNING credential_id, window_type, window_start, tx_count, total_value
	`
	var rl types.AgentRateLimit
	err := r.db.QueryRow(ctx, query, credentialID, windowType, windowStart).Scan(
		&rl.CredentialID, &rl.WindowType, &rl.WindowStart, &rl.TxCount, &rl.TotalValue,
	)
	if err != nil {
		return nil, err
	}
	return &rl, nil
}

func (r *AgentRateLimitRepo) IncrementUsage(ctx context.Context, credentialID uuid.UUID, windowType string, windowStart time.Time, value *big.Int) error {
	query := `
		UPDATE agent_rate_limits
		SET tx_count = tx_count + 1, total_value = (CAST(total_value AS NUMERIC) + $1)::TEXT
		WHERE credential_id = $2 AND window_type = $3 AND window_start = $4
	`
	_, err := r.db.Exec(ctx, query, value.String(), credentialID, windowType, windowStart)
	return err
}

func (r *AgentRateLimitRepo) GetCurrentUsage(ctx context.Context, credentialID uuid.UUID) (hourly *types.AgentRateLimit, daily *types.AgentRateLimit, err error) {
	now := time.Now().UTC()
	hourlyStart := now.Truncate(time.Hour)
	dailyStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	hourly, err = r.GetOrCreate(ctx, credentialID, types.WindowTypeHourly, hourlyStart)
	if err != nil {
		return nil, nil, err
	}
	daily, err = r.GetOrCreate(ctx, credentialID, types.WindowTypeDaily, dailyStart)
	if err != nil {
		return nil, nil, err
	}
	return hourly, daily, nil
}
