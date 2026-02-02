package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/better-wallet/better-wallet/internal/eth"
	"github.com/better-wallet/better-wallet/internal/keyexec"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AgentService handles agent wallet operations
type AgentService struct {
	principalRepo  *storage.PrincipalRepo
	apiKeyRepo     *storage.PrincipalAPIKeyRepo
	walletRepo     *storage.AgentWalletRepo
	walletKeyRepo  *storage.WalletKeyRepo
	credentialRepo *storage.AgentCredentialRepo
	rateLimitRepo  *storage.AgentRateLimitRepo
	keyExecutor    keyexec.KeyExecutor
	ethClient      *eth.Client
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
	ethClient *eth.Client,
) *AgentService {
	return &AgentService{
		principalRepo:  principalRepo,
		apiKeyRepo:     apiKeyRepo,
		walletRepo:     walletRepo,
		walletKeyRepo:  walletKeyRepo,
		credentialRepo: credentialRepo,
		rateLimitRepo:  rateLimitRepo,
		keyExecutor:    keyExecutor,
		ethClient:      ethClient,
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
	apiKey, keyPrefix, keyHash, err := s.generateAPIKey("aw_pk_")
	if err != nil {
		return nil, fmt.Errorf("failed to generate api key: %w", err)
	}

	apiKeyRecord := &types.PrincipalAPIKey{
		ID:          uuid.New(),
		PrincipalID: principalID,
		KeyPrefix:   keyPrefix,
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

	// Encode both shares together: [4-byte auth len][auth share][exec share]
	combinedShares := encodeShares(keyMaterial.AuthShare, keyMaterial.ExecShare)

	// Encrypt the combined shares for storage
	encryptedKey, err := s.keyExecutor.Encrypt(ctx, combinedShares)
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
	secret, keyPrefix, keyHash, err := s.generateAPIKey("aw_ag_")
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential: %w", err)
	}

	now := time.Now().UTC()
	credentialID := uuid.New()

	credential := &types.AgentCredential{
		ID:           credentialID,
		WalletID:     req.WalletID,
		Name:         req.Name,
		KeyPrefix:    keyPrefix,
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
// Returns: fullKey (prefix.secret), keyPrefix (for lookup), secretHash (for verification)
func (s *AgentService) generateAPIKey(prefix string) (fullKey, keyPrefix, secretHash string, err error) {
	// Generate random bytes for the secret
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	secret := base64.URLEncoding.EncodeToString(secretBytes)

	// Generate a short random prefix identifier
	prefixIDBytes := make([]byte, 8)
	if _, err := rand.Read(prefixIDBytes); err != nil {
		return "", "", "", fmt.Errorf("failed to generate prefix id: %w", err)
	}
	prefixID := base64.URLEncoding.EncodeToString(prefixIDBytes)[:12]

	// Full key is prefix + prefixID + "." + secret (e.g., "aw_pk_ABC123XYZ.secret...")
	keyPrefix = prefix + prefixID
	fullKey = keyPrefix + "." + secret

	// Hash only the secret for storage (prefix is used for lookup)
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to hash secret: %w", err)
	}

	return fullKey, keyPrefix, string(hash), nil
}

// encodeShares encodes auth and exec shares together for storage
// Format: [4-byte auth len (big endian)][auth share][exec share]
func encodeShares(authShare, execShare []byte) []byte {
	result := make([]byte, 4+len(authShare)+len(execShare))
	binary.BigEndian.PutUint32(result[:4], uint32(len(authShare)))
	copy(result[4:4+len(authShare)], authShare)
	copy(result[4+len(authShare):], execShare)
	return result
}

// decodeShares decodes auth and exec shares from storage format
func decodeShares(data []byte) (authShare, execShare []byte, err error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("data too short")
	}
	authLen := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(4+authLen) {
		return nil, nil, fmt.Errorf("data too short for auth share")
	}
	authShare = data[4 : 4+authLen]
	execShare = data[4+authLen:]
	return authShare, execShare, nil
}

// getKeyMaterial retrieves and decrypts the key material for a wallet
func (s *AgentService) getKeyMaterial(ctx context.Context, walletID uuid.UUID) (*keyexec.KeyMaterial, error) {
	// Get wallet key from database
	walletKey, err := s.walletKeyRepo.GetByWalletID(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet key: %w", err)
	}
	if walletKey == nil {
		return nil, fmt.Errorf("wallet key not found")
	}

	// Decrypt the combined shares
	decryptedData, err := s.keyExecutor.Decrypt(ctx, walletKey.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Decode the shares
	authShare, execShare, err := decodeShares(decryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode shares: %w", err)
	}

	// Get wallet for address
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}

	return &keyexec.KeyMaterial{
		Address:     wallet.Address,
		AuthShare:   authShare,
		ExecShare:   execShare,
		Threshold:   2,
		TotalShares: 2,
	}, nil
}

// TransactionParams represents parameters for eth_sendTransaction
type TransactionParams struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Value    string `json:"value"`
	Data     string `json:"data"`
	Gas      string `json:"gas"`
	GasPrice string `json:"gasPrice"`
	Nonce    string `json:"nonce"`
	ChainID  string `json:"chainId"` // Optional: for offline signing
}

// SignTransactionRequest represents a request to sign a transaction
type SignTransactionRequest struct {
	WalletID uuid.UUID
	ChainID  int64
	Params   TransactionParams
}

// SignTransaction signs an Ethereum transaction
func (s *AgentService) SignTransaction(ctx context.Context, req SignTransactionRequest) (string, error) {
	// Get key material
	keyMaterial, err := s.getKeyMaterial(ctx, req.WalletID)
	if err != nil {
		return "", err
	}

	// Check if this is a contract deployment (empty to)
	isContractDeploy := req.Params.To == ""

	// Parse 'to' address (only for non-deploy transactions)
	var to common.Address
	if !isContractDeploy {
		to = common.HexToAddress(req.Params.To)
	}

	value := big.NewInt(0)
	if req.Params.Value != "" {
		var ok bool
		value, ok = new(big.Int).SetString(req.Params.Value, 0)
		if !ok {
			return "", fmt.Errorf("invalid value: %s", req.Params.Value)
		}
	}

	var data []byte
	if req.Params.Data != "" {
		data, err = hex.DecodeString(stripHexPrefix(req.Params.Data))
		if err != nil {
			return "", fmt.Errorf("invalid data: %w", err)
		}
	}

	// Auto-fetch nonce if not provided
	var nonce uint64
	if req.Params.Nonce != "" {
		nonceVal, ok := new(big.Int).SetString(req.Params.Nonce, 0)
		if !ok {
			return "", fmt.Errorf("invalid nonce: %s", req.Params.Nonce)
		}
		nonce = nonceVal.Uint64()
	} else if s.ethClient != nil {
		nonce, err = s.ethClient.GetNonce(ctx, keyMaterial.Address)
		if err != nil {
			return "", fmt.Errorf("failed to get nonce: %w", err)
		}
	} else {
		return "", fmt.Errorf("nonce is required when RPC is not configured")
	}

	// Auto-fetch gas price if not provided
	var gasPrice *big.Int
	if req.Params.GasPrice != "" {
		var ok bool
		gasPrice, ok = new(big.Int).SetString(req.Params.GasPrice, 0)
		if !ok {
			return "", fmt.Errorf("invalid gasPrice: %s", req.Params.GasPrice)
		}
	} else if s.ethClient != nil {
		gasPrice, err = s.ethClient.SuggestGasPrice(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to get gas price: %w", err)
		}
	} else {
		return "", fmt.Errorf("gasPrice is required when RPC is not configured")
	}

	// Auto-estimate gas if not provided
	var gas uint64
	if req.Params.Gas != "" {
		gasVal, ok := new(big.Int).SetString(req.Params.Gas, 0)
		if !ok {
			return "", fmt.Errorf("invalid gas: %s", req.Params.Gas)
		}
		gas = gasVal.Uint64()
	} else if s.ethClient != nil {
		// For contract deployment, pass empty string to EstimateGas (will use nil To)
		gas, err = s.ethClient.EstimateGas(ctx, keyMaterial.Address, req.Params.To, value, data)
		if err != nil {
			// Fall back to default gas for simple transfers (not for contract deploy)
			if isContractDeploy {
				return "", fmt.Errorf("failed to estimate gas for contract deployment: %w", err)
			}
			gas = 21000
		}
	} else {
		return "", fmt.Errorf("gas is required when RPC is not configured")
	}

	// Validate chain ID
	if req.ChainID == 0 {
		return "", fmt.Errorf("chainId is required")
	}

	// Create transaction
	var tx *ethtypes.Transaction
	if isContractDeploy {
		// Contract creation: use NewContractCreation
		tx = ethtypes.NewContractCreation(nonce, value, gas, gasPrice, data)
	} else {
		// Regular transaction
		tx = ethtypes.NewTransaction(nonce, to, value, gas, gasPrice, data)
	}

	// Sign transaction
	signedTx, err := s.keyExecutor.SignTransaction(ctx, keyMaterial, tx, req.ChainID)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Encode signed transaction to hex
	txBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to encode transaction: %w", err)
	}

	return "0x" + hex.EncodeToString(txBytes), nil
}

// SendTransactionRequest represents a request to sign and broadcast a transaction
type SendTransactionRequest struct {
	WalletID uuid.UUID
	ChainID  int64
	Params   TransactionParams
}

// SendTransactionResponse represents the response from sending a transaction
type SendTransactionResponse struct {
	TxHash   string `json:"tx_hash"`
	SignedTx string `json:"signed_tx"`
}

// SendTransaction signs and broadcasts an Ethereum transaction
func (s *AgentService) SendTransaction(ctx context.Context, req SendTransactionRequest) (*SendTransactionResponse, error) {
	// First sign the transaction
	signedTxHex, err := s.SignTransaction(ctx, SignTransactionRequest{
		WalletID: req.WalletID,
		ChainID:  req.ChainID,
		Params:   req.Params,
	})
	if err != nil {
		return nil, err
	}

	// If no eth client, just return the signed tx
	if s.ethClient == nil {
		return &SendTransactionResponse{
			SignedTx: signedTxHex,
		}, nil
	}

	// Decode the signed transaction
	txBytes, err := hex.DecodeString(stripHexPrefix(signedTxHex))
	if err != nil {
		return nil, fmt.Errorf("failed to decode signed tx: %w", err)
	}

	var tx ethtypes.Transaction
	if err := tx.UnmarshalBinary(txBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tx: %w", err)
	}

	// Broadcast to network
	txHash, err := s.ethClient.SendRawTransaction(ctx, &tx)
	if err != nil {
		return nil, fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	return &SendTransactionResponse{
		TxHash:   txHash,
		SignedTx: signedTxHex,
	}, nil
}

// GetBalance returns the balance of a wallet in wei
func (s *AgentService) GetBalance(ctx context.Context, walletID uuid.UUID) (string, error) {
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return "", fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return "", fmt.Errorf("wallet not found")
	}

	if s.ethClient == nil {
		return "", fmt.Errorf("ethereum RPC not configured")
	}

	balance, err := s.ethClient.GetBalance(ctx, wallet.Address)
	if err != nil {
		return "", err
	}

	return "0x" + balance.Text(16), nil
}

// GetChainID returns the configured chain ID, or 0 if RPC is not configured
func (s *AgentService) GetChainID() int64 {
	if s.ethClient != nil {
		return s.ethClient.ChainID()
	}
	return 0 // RPC not configured
}

// HasRPCClient returns true if an RPC client is configured
func (s *AgentService) HasRPCClient() bool {
	return s.ethClient != nil
}

// SignPersonalMessageRequest represents a request to sign a personal message
type SignPersonalMessageRequest struct {
	WalletID uuid.UUID
	Message  []byte
}

// SignPersonalMessage signs a message using EIP-191 personal_sign
func (s *AgentService) SignPersonalMessage(ctx context.Context, req SignPersonalMessageRequest) (string, error) {
	// Get key material
	keyMaterial, err := s.getKeyMaterial(ctx, req.WalletID)
	if err != nil {
		return "", err
	}

	// Create EIP-191 prefixed message hash
	// "\x19Ethereum Signed Message:\n" + len(message) + message
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(req.Message))
	prefixedMessage := append([]byte(prefix), req.Message...)
	hash := crypto.Keccak256(prefixedMessage)

	// Sign the hash
	signature, err := s.keyExecutor.SignHash(ctx, keyMaterial, hash)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %w", err)
	}

	// Adjust v value for Ethereum (add 27)
	if len(signature) == 65 {
		signature[64] += 27
	}

	return "0x" + hex.EncodeToString(signature), nil
}

// SignTypedDataRequest represents a request to sign EIP-712 typed data
type SignTypedDataRequest struct {
	WalletID  uuid.UUID
	TypedData json.RawMessage
}

// SignTypedData signs EIP-712 typed data using full EIP-712 compliance
func (s *AgentService) SignTypedData(ctx context.Context, req SignTypedDataRequest) (string, error) {
	// Get key material
	keyMaterial, err := s.getKeyMaterial(ctx, req.WalletID)
	if err != nil {
		return "", err
	}

	// Parse typed data using go-ethereum's apitypes
	var typedData apitypes.TypedData
	if err := json.Unmarshal(req.TypedData, &typedData); err != nil {
		return "", fmt.Errorf("failed to parse typed data: %w", err)
	}

	// Compute EIP-712 hash using go-ethereum's full implementation
	// This handles type dependency ordering, arrays, and all EIP-712 features
	hash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return "", fmt.Errorf("failed to compute typed data hash: %w", err)
	}

	// Sign the hash
	signature, err := s.keyExecutor.SignHash(ctx, keyMaterial, hash)
	if err != nil {
		return "", fmt.Errorf("failed to sign typed data: %w", err)
	}

	// Adjust v value for Ethereum (add 27)
	if len(signature) == 65 {
		signature[64] += 27
	}

	return "0x" + hex.EncodeToString(signature), nil
}

// stripHexPrefix removes 0x prefix from hex string
func stripHexPrefix(s string) string {
	if len(s) >= 2 && s[0:2] == "0x" {
		return s[2:]
	}
	return s
}
