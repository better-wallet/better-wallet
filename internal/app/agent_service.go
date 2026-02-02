package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/better-wallet/better-wallet/internal/keyexec"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AgentService handles agent wallet operations
type AgentService struct {
	principalRepo   *storage.PrincipalRepo
	apiKeyRepo      *storage.PrincipalAPIKeyRepo
	walletRepo      *storage.AgentWalletRepo
	walletKeyRepo   *storage.WalletKeyRepo
	credentialRepo  *storage.AgentCredentialRepo
	rateLimitRepo   *storage.AgentRateLimitRepo
	keyExecutor     keyexec.KeyExecutor
}

// NewAgentService creates a new agent service
func NewAgentService(
	principalRepo *storage.PrincipalRepo,
	apiKeyRepo *storage.PrincipalAPIKeyRepo,
	walletRepo *storage.AgentWalletRepo,
	walletKeyRepo *storage.WalletKeyRepo,
	credentialRepo *storage.AgentCredentialRepo,
	rateLimitRepo *storage.AgentRateLimitRepo,
	keyExecutor keyexec.KeyExecutor,
) *AgentService {
	return &AgentService{
		principalRepo:  principalRepo,
		apiKeyRepo:     apiKeyRepo,
		walletRepo:     walletRepo,
		walletKeyRepo:  walletKeyRepo,
		credentialRepo: credentialRepo,
		rateLimitRepo:  rateLimitRepo,
		keyExecutor:    keyExecutor,
	}
}

// CreatePrincipalRequest represents a request to create a principal
type CreatePrincipalRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// CreatePrincipalResponse represents the response from creating a principal
type CreatePrincipalResponse struct {
	Principal *types.Principal `json:"principal"`
	APIKey    string           `json:"api_key"` // Only returned once at creation
}

// CreatePrincipal creates a new principal with an API key
func (s *AgentService) CreatePrincipal(ctx context.Context, req CreatePrincipalRequest) (*CreatePrincipalResponse, error) {
	// Validate input
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}

	now := time.Now().UTC()
	principalID := uuid.New()

	principal := &types.Principal{
		ID:            principalID,
		Name:          req.Name,
		Email:         req.Email,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.principalRepo.Create(ctx, principal); err != nil {
		return nil, fmt.Errorf("failed to create principal: %w", err)
	}

	// Generate API key
	apiKey, keyHash, err := s.generateAPIKey("aw_pk_")
	if err != nil {
		return nil, fmt.Errorf("failed to generate api key: %w", err)
	}

	apiKeyRecord := &types.PrincipalAPIKey{
		ID:          uuid.New(),
		PrincipalID: principalID,
		KeyPrefix:   apiKey[:16], // First 16 chars as prefix
		Name:        "Default API Key",
		Status:      types.AgentStatusActive,
		CreatedAt:   now,
	}

	if err := s.apiKeyRepo.Create(ctx, apiKeyRecord, keyHash); err != nil {
		return nil, fmt.Errorf("failed to create api key: %w", err)
	}

	return &CreatePrincipalResponse{
		Principal: principal,
		APIKey:    apiKey,
	}, nil
}

// CreateAgentWalletRequest represents a request to create an agent wallet
type CreateAgentWalletRequest struct {
	PrincipalID uuid.UUID `json:"principal_id"`
	Name        string    `json:"name"`
	ChainType   string    `json:"chain_type"`
}

// CreateAgentWalletResponse represents the response from creating an agent wallet
type CreateAgentWalletResponse struct {
	Wallet *types.AgentWallet `json:"wallet"`
}

// CreateWallet creates a new agent wallet
func (s *AgentService) CreateWallet(ctx context.Context, req CreateAgentWalletRequest) (*CreateAgentWalletResponse, error) {
	// Validate input
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if req.PrincipalID == uuid.Nil {
		return nil, fmt.Errorf("principal_id is required")
	}

	if req.ChainType == "" {
		req.ChainType = types.ChainTypeEthereum
	}
	if req.ChainType != types.ChainTypeEthereum {
		return nil, fmt.Errorf("unsupported chain type: %s", req.ChainType)
	}

	// Generate key material
	keyMaterial, err := s.keyExecutor.GenerateAndSplitKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encrypt the key for storage
	encryptedKey, err := s.keyExecutor.Encrypt(ctx, keyMaterial.AuthShare)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	now := time.Now().UTC()
	walletID := uuid.New()

	wallet := &types.AgentWallet{
		ID:          walletID,
		PrincipalID: req.PrincipalID,
		Name:        req.Name,
		ChainType:   req.ChainType,
		Address:     keyMaterial.Address,
		ExecBackend: types.ExecBackendKMS,
		Status:      types.AgentStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.walletRepo.Create(ctx, wallet); err != nil {
		return nil, fmt.Errorf("failed to create wallet: %w", err)
	}

	walletKey := &types.WalletKey{
		WalletID:     walletID,
		EncryptedKey: encryptedKey,
		KMSKeyID:     "",
		CreatedAt:    now,
	}
	if err := s.walletKeyRepo.Create(ctx, walletKey); err != nil {
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	return &CreateAgentWalletResponse{Wallet: wallet}, nil
}

// GetWallet retrieves a wallet by ID
func (s *AgentService) GetWallet(ctx context.Context, walletID uuid.UUID) (*types.AgentWallet, error) {
	return s.walletRepo.GetByID(ctx, walletID)
}

// ListWallets lists all wallets for a principal
func (s *AgentService) ListWallets(ctx context.Context, principalID uuid.UUID) ([]*types.AgentWallet, error) {
	return s.walletRepo.ListByPrincipal(ctx, principalID)
}

// CreateAgentCredentialRequest represents a request to create an agent credential
type CreateAgentCredentialRequest struct {
	WalletID     uuid.UUID               `json:"wallet_id"`
	Name         string                  `json:"name"`
	Capabilities types.AgentCapabilities `json:"capabilities"`
	Limits       types.AgentLimits       `json:"limits"`
}

// CreateAgentCredentialResponse represents the response from creating a credential
type CreateAgentCredentialResponse struct {
	Credential *types.AgentCredential `json:"credential"`
	Secret     string                 `json:"secret"` // Only returned once at creation
}

// CreateCredential creates a new agent credential
func (s *AgentService) CreateCredential(ctx context.Context, req CreateAgentCredentialRequest) (*CreateAgentCredentialResponse, error) {
	// Validate input
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if req.WalletID == uuid.Nil {
		return nil, fmt.Errorf("wallet_id is required")
	}

	// Generate credential secret
	secret, keyHash, err := s.generateAPIKey("aw_ag_")
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential: %w", err)
	}

	now := time.Now().UTC()
	credentialID := uuid.New()

	credential := &types.AgentCredential{
		ID:           credentialID,
		WalletID:     req.WalletID,
		Name:         req.Name,
		KeyPrefix:    secret[:16], // First 16 chars as prefix
		Capabilities: req.Capabilities,
		Limits:       req.Limits,
		Status:       types.AgentStatusActive,
		CreatedAt:    now,
	}

	if err := s.credentialRepo.Create(ctx, credential, keyHash); err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	return &CreateAgentCredentialResponse{
		Credential: credential,
		Secret:     secret,
	}, nil
}

// GetCredential retrieves a credential by ID
func (s *AgentService) GetCredential(ctx context.Context, credentialID uuid.UUID) (*types.AgentCredential, error) {
	return s.credentialRepo.GetByID(ctx, credentialID)
}

// ListCredentials lists all credentials for a wallet
func (s *AgentService) ListCredentials(ctx context.Context, walletID uuid.UUID) ([]*types.AgentCredential, error) {
	return s.credentialRepo.ListByWallet(ctx, walletID)
}

// PauseCredential pauses an agent credential
func (s *AgentService) PauseCredential(ctx context.Context, credentialID uuid.UUID) error {
	return s.credentialRepo.UpdateStatus(ctx, credentialID, types.AgentStatusPaused)
}

// ResumeCredential resumes a paused agent credential
func (s *AgentService) ResumeCredential(ctx context.Context, credentialID uuid.UUID) error {
	return s.credentialRepo.UpdateStatus(ctx, credentialID, types.AgentStatusActive)
}

// RevokeCredential permanently revokes an agent credential
func (s *AgentService) RevokeCredential(ctx context.Context, credentialID uuid.UUID) error {
	return s.credentialRepo.UpdateStatus(ctx, credentialID, types.AgentStatusRevoked)
}

// PauseWallet pauses all operations for a wallet
func (s *AgentService) PauseWallet(ctx context.Context, walletID uuid.UUID) error {
	return s.walletRepo.UpdateStatus(ctx, walletID, types.AgentStatusPaused)
}

// ResumeWallet resumes a paused wallet
func (s *AgentService) ResumeWallet(ctx context.Context, walletID uuid.UUID) error {
	return s.walletRepo.UpdateStatus(ctx, walletID, types.AgentStatusActive)
}

// KillWallet permanently kills a wallet (cannot be resumed)
func (s *AgentService) KillWallet(ctx context.Context, walletID uuid.UUID) error {
	return s.walletRepo.UpdateStatus(ctx, walletID, types.AgentStatusKilled)
}

// CheckRateLimits checks if the credential is within rate limits
func (s *AgentService) CheckRateLimits(ctx context.Context, credential *types.AgentCredential, value *big.Int) error {
	hourly, daily, err := s.rateLimitRepo.GetCurrentUsage(ctx, credential.ID)
	if err != nil {
		return fmt.Errorf("failed to get rate limits: %w", err)
	}

	// Check hourly tx count
	if credential.Limits.MaxTxPerHour > 0 && hourly.TxCount >= credential.Limits.MaxTxPerHour {
		return fmt.Errorf("hourly transaction limit exceeded")
	}

	// Check daily tx count
	if credential.Limits.MaxTxPerDay > 0 && daily.TxCount >= credential.Limits.MaxTxPerDay {
		return fmt.Errorf("daily transaction limit exceeded")
	}

	// Check per-tx value first (simplest check)
	if credential.Limits.MaxValuePerTx != "" {
		maxPerTx, ok := new(big.Int).SetString(credential.Limits.MaxValuePerTx, 10)
		if !ok {
			return fmt.Errorf("invalid max_value_per_tx format")
		}
		if value.Cmp(maxPerTx) > 0 {
			return fmt.Errorf("transaction value limit exceeded")
		}
	}

	// Check hourly value
	if credential.Limits.MaxValuePerHour != "" {
		maxHourly, ok := new(big.Int).SetString(credential.Limits.MaxValuePerHour, 10)
		if !ok {
			return fmt.Errorf("invalid max_value_per_hour format")
		}
		currentHourly := big.NewInt(0)
		if hourly.TotalValue != "" && hourly.TotalValue != "0" {
			currentHourly, ok = new(big.Int).SetString(hourly.TotalValue, 10)
			if !ok {
				return fmt.Errorf("invalid hourly total value in database")
			}
		}
		newTotal := new(big.Int).Add(currentHourly, value)
		if newTotal.Cmp(maxHourly) > 0 {
			return fmt.Errorf("hourly value limit exceeded")
		}
	}

	// Check daily value
	if credential.Limits.MaxValuePerDay != "" {
		maxDaily, ok := new(big.Int).SetString(credential.Limits.MaxValuePerDay, 10)
		if !ok {
			return fmt.Errorf("invalid max_value_per_day format")
		}
		currentDaily := big.NewInt(0)
		if daily.TotalValue != "" && daily.TotalValue != "0" {
			currentDaily, ok = new(big.Int).SetString(daily.TotalValue, 10)
			if !ok {
				return fmt.Errorf("invalid daily total value in database")
			}
		}
		newTotal := new(big.Int).Add(currentDaily, value)
		if newTotal.Cmp(maxDaily) > 0 {
			return fmt.Errorf("daily value limit exceeded")
		}
	}

	return nil
}

// RecordTransaction records a transaction and updates rate limits
func (s *AgentService) RecordTransaction(ctx context.Context, credentialID uuid.UUID, value *big.Int) error {
	now := time.Now().UTC()
	hourlyStart := now.Truncate(time.Hour)
	dailyStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Ensure rate limit records exist
	if _, err := s.rateLimitRepo.GetOrCreate(ctx, credentialID, types.WindowTypeHourly, hourlyStart); err != nil {
		return err
	}
	if _, err := s.rateLimitRepo.GetOrCreate(ctx, credentialID, types.WindowTypeDaily, dailyStart); err != nil {
		return err
	}

	// Increment usage
	if err := s.rateLimitRepo.IncrementUsage(ctx, credentialID, types.WindowTypeHourly, hourlyStart, value); err != nil {
		return err
	}
	if err := s.rateLimitRepo.IncrementUsage(ctx, credentialID, types.WindowTypeDaily, dailyStart, value); err != nil {
		return err
	}

	return nil
}

// generateAPIKey generates a new API key with the given prefix
func (s *AgentService) generateAPIKey(prefix string) (string, string, error) {
	// Generate random bytes for the secret
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	secret := base64.URLEncoding.EncodeToString(secretBytes)

	// Full key is prefix + secret
	fullKey := prefix + secret

	// Hash the full key for storage
	hash, err := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash key: %w", err)
	}

	return fullKey, string(hash), nil
}
