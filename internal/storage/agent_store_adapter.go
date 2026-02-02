package storage

import (
	"context"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// AgentStoreAdapter combines repositories to implement middleware store interfaces
type AgentStoreAdapter struct {
	principalRepo   *PrincipalRepo
	apiKeyRepo      *PrincipalAPIKeyRepo
	walletRepo      *AgentWalletRepo
	credentialRepo  *AgentCredentialRepo
}

// NewAgentStoreAdapter creates a new store adapter
func NewAgentStoreAdapter(
	principalRepo *PrincipalRepo,
	apiKeyRepo *PrincipalAPIKeyRepo,
	walletRepo *AgentWalletRepo,
	credentialRepo *AgentCredentialRepo,
) *AgentStoreAdapter {
	return &AgentStoreAdapter{
		principalRepo:  principalRepo,
		apiKeyRepo:     apiKeyRepo,
		walletRepo:     walletRepo,
		credentialRepo: credentialRepo,
	}
}

// PrincipalStore interface implementation

// GetAPIKeyByPrefix retrieves an API key by its prefix
func (a *AgentStoreAdapter) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*types.PrincipalAPIKey, string, error) {
	return a.apiKeyRepo.GetByPrefix(ctx, prefix)
}

// GetPrincipalByID retrieves a principal by ID
func (a *AgentStoreAdapter) GetPrincipalByID(ctx context.Context, id uuid.UUID) (*types.Principal, error) {
	return a.principalRepo.GetByID(ctx, id)
}

// UpdateAPIKeyLastUsed updates the last used timestamp for an API key
func (a *AgentStoreAdapter) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	return a.apiKeyRepo.UpdateLastUsed(ctx, id)
}

// AgentStore interface implementation

// GetCredentialByPrefix retrieves a credential by its prefix
func (a *AgentStoreAdapter) GetCredentialByPrefix(ctx context.Context, prefix string) (*types.AgentCredential, string, error) {
	return a.credentialRepo.GetByPrefixWithHash(ctx, prefix)
}

// GetWalletByID retrieves a wallet by ID
func (a *AgentStoreAdapter) GetWalletByID(ctx context.Context, id uuid.UUID) (*types.AgentWallet, error) {
	return a.walletRepo.GetByID(ctx, id)
}

// UpdateCredentialLastUsed updates the last used timestamp for a credential
func (a *AgentStoreAdapter) UpdateCredentialLastUsed(ctx context.Context, id uuid.UUID) error {
	return a.credentialRepo.UpdateLastUsed(ctx, id)
}
