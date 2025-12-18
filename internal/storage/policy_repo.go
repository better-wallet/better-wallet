package storage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PolicyRepository handles policy data operations
type PolicyRepository struct {
	store *Store
}

// NewPolicyRepository creates a new PolicyRepository
func NewPolicyRepository(store *Store) *PolicyRepository {
	return &PolicyRepository{store: store}
}

// Create creates a new policy
func (r *PolicyRepository) Create(ctx context.Context, policy *types.Policy) error {
	if policy.AppID == nil {
		appID, err := RequireAppID(ctx)
		if err != nil {
			return err
		}
		policy.AppID = &appID
	}

	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}

	query := `
		INSERT INTO policies (id, name, chain_type, version, rules, owner_id, app_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at
	`

	err = r.store.pool.QueryRow(ctx, query,
		policy.ID,
		policy.Name,
		policy.ChainType,
		policy.Version,
		rulesJSON,
		policy.OwnerID,
		policy.AppID,
	).Scan(&policy.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	return nil
}

// GetByID retrieves a policy by ID
func (r *PolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*types.Policy, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, name, chain_type, version, rules, owner_id, app_id, created_at
		FROM policies
		WHERE id = $1 AND app_id = $2
	`

	var policy types.Policy
	var rulesJSON []byte

	err = r.store.pool.QueryRow(ctx, query, id, appID).Scan(
		&policy.ID,
		&policy.Name,
		&policy.ChainType,
		&policy.Version,
		&rulesJSON,
		&policy.OwnerID,
		&policy.AppID,
		&policy.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy by ID: %w", err)
	}

	if err := json.Unmarshal(rulesJSON, &policy.Rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	return &policy, nil
}

// GetByIDAndAppID retrieves a policy by ID scoped to an app
func (r *PolicyRepository) GetByIDAndAppID(ctx context.Context, id, appID uuid.UUID) (*types.Policy, error) {
	query := `
		SELECT id, name, chain_type, version, rules, owner_id, app_id, created_at
		FROM policies
		WHERE id = $1 AND app_id = $2
	`

	var policy types.Policy
	var rulesJSON []byte

	err := r.store.pool.QueryRow(ctx, query, id, appID).Scan(
		&policy.ID,
		&policy.Name,
		&policy.ChainType,
		&policy.Version,
		&rulesJSON,
		&policy.OwnerID,
		&policy.AppID,
		&policy.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy by ID: %w", err)
	}

	if err := json.Unmarshal(rulesJSON, &policy.Rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	return &policy, nil
}

// GetByWalletID retrieves all policies associated with a wallet
func (r *PolicyRepository) GetByWalletID(ctx context.Context, walletID uuid.UUID) ([]*types.Policy, error) {
	appID, err := RequireAppID(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT p.id, p.name, p.chain_type, p.version, p.rules, p.owner_id, p.app_id, p.created_at
		FROM policies p
		INNER JOIN wallet_policies wp ON p.id = wp.policy_id
		WHERE wp.wallet_id = $1 AND p.app_id = $2
	`

	rows, err := r.store.pool.Query(ctx, query, walletID, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policies by wallet ID: %w", err)
	}
	defer rows.Close()

	var policies []*types.Policy
	for rows.Next() {
		var policy types.Policy
		var rulesJSON []byte

		err := rows.Scan(
			&policy.ID,
			&policy.Name,
			&policy.ChainType,
			&policy.Version,
			&rulesJSON,
			&policy.OwnerID,
			&policy.AppID,
			&policy.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}

		if err := json.Unmarshal(rulesJSON, &policy.Rules); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
		}

		policies = append(policies, &policy)
	}

	return policies, nil
}

// GetByAppID retrieves all policies for an app
func (r *PolicyRepository) GetByAppID(ctx context.Context, appID uuid.UUID) ([]*types.Policy, error) {
	query := `
		SELECT id, name, chain_type, version, rules, owner_id, app_id, created_at
		FROM policies
		WHERE app_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.store.pool.Query(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policies by app ID: %w", err)
	}
	defer rows.Close()

	var policies []*types.Policy
	for rows.Next() {
		var policy types.Policy
		var rulesJSON []byte

		err := rows.Scan(
			&policy.ID,
			&policy.Name,
			&policy.ChainType,
			&policy.Version,
			&rulesJSON,
			&policy.OwnerID,
			&policy.AppID,
			&policy.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}

		if err := json.Unmarshal(rulesJSON, &policy.Rules); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
		}

		policies = append(policies, &policy)
	}

	return policies, nil
}

// AttachToWallet associates a policy with a wallet
func (r *PolicyRepository) AttachToWallet(ctx context.Context, walletID, policyID uuid.UUID) error {
	query := `
		INSERT INTO wallet_policies (wallet_id, policy_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`

	_, err := r.store.pool.Exec(ctx, query, walletID, policyID)
	if err != nil {
		return fmt.Errorf("failed to attach policy to wallet: %w", err)
	}

	return nil
}

// AttachToWalletTx attaches a policy to a wallet within a transaction
func (r *PolicyRepository) AttachToWalletTx(ctx context.Context, tx pgx.Tx, walletID, policyID uuid.UUID) error {
	query := `
		INSERT INTO wallet_policies (wallet_id, policy_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`

	_, err := tx.Exec(ctx, query, walletID, policyID)
	if err != nil {
		return fmt.Errorf("failed to attach policy to wallet: %w", err)
	}

	return nil
}

// DetachFromWallet removes a policy association from a wallet
func (r *PolicyRepository) DetachFromWallet(ctx context.Context, walletID, policyID uuid.UUID) error {
	query := `
		DELETE FROM wallet_policies
		WHERE wallet_id = $1 AND policy_id = $2
	`

	_, err := r.store.pool.Exec(ctx, query, walletID, policyID)
	if err != nil {
		return fmt.Errorf("failed to detach policy from wallet: %w", err)
	}

	return nil
}
