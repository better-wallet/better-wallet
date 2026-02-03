package types

import (
	"time"

	"github.com/google/uuid"
)

// Principal represents a human or organization that owns agent wallets
type Principal struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// PrincipalAPIKey represents an API key for principal authentication
type PrincipalAPIKey struct {
	ID          uuid.UUID  `json:"id"`
	PrincipalID uuid.UUID  `json:"principal_id"`
	KeyPrefix   string     `json:"key_prefix"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// AgentWallet represents a blockchain wallet owned by a principal
type AgentWallet struct {
	ID          uuid.UUID `json:"id"`
	PrincipalID uuid.UUID `json:"principal_id"`
	Name        string    `json:"name"`
	ChainType   string    `json:"chain_type"`
	Address     string    `json:"address"`
	ExecBackend string    `json:"exec_backend"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// WalletKey represents encrypted key material for a wallet
type WalletKey struct {
	WalletID     uuid.UUID `json:"wallet_id"`
	EncryptedKey []byte    `json:"encrypted_key"`
	KMSKeyID     string    `json:"kms_key_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// AgentCredential represents a capability token granted to an AI agent
type AgentCredential struct {
	ID           uuid.UUID         `json:"id"`
	WalletID     uuid.UUID         `json:"wallet_id"`
	Name         string            `json:"name"`
	KeyPrefix    string            `json:"key_prefix"`
	Capabilities AgentCapabilities `json:"capabilities"`
	Limits       AgentLimits       `json:"limits"`
	Status       string            `json:"status"`
	LastUsedAt   *time.Time        `json:"last_used_at,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	PausedAt     *time.Time        `json:"paused_at,omitempty"`
	RevokedAt    *time.Time        `json:"revoked_at,omitempty"`
}

// AgentCapabilities defines what an agent can do
type AgentCapabilities struct {
	Chains           []string `json:"chains"`
	Operations       []string `json:"operations"`
	AllowedContracts []string `json:"allowed_contracts"`
	AllowedMethods   []string `json:"allowed_methods"`
}

// AgentLimits defines hard limits for an agent
type AgentLimits struct {
	MaxValuePerTx   string `json:"max_value_per_tx"`
	MaxValuePerHour string `json:"max_value_per_hour"`
	MaxValuePerDay  string `json:"max_value_per_day"`
	MaxTxPerHour    int    `json:"max_tx_per_hour"`
	MaxTxPerDay     int    `json:"max_tx_per_day"`
}

// AgentPolicy represents constraint rules for agent operations
type AgentPolicy struct {
	ID        uuid.UUID      `json:"id"`
	WalletID  uuid.UUID      `json:"wallet_id"`
	Name      string         `json:"name"`
	ChainType string         `json:"chain_type"`
	Rules     map[string]any `json:"rules"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// AgentRateLimit tracks rate limits for an agent credential
type AgentRateLimit struct {
	CredentialID uuid.UUID `json:"credential_id"`
	WindowType   string    `json:"window_type"`
	WindowStart  time.Time `json:"window_start"`
	TxCount      int       `json:"tx_count"`
	TotalValue   string    `json:"total_value"`
}

// AgentAuditLog represents an audit trail entry for agent operations
type AgentAuditLog struct {
	ID           int64          `json:"id"`
	CredentialID *uuid.UUID     `json:"credential_id,omitempty"`
	WalletID     *uuid.UUID     `json:"wallet_id,omitempty"`
	PrincipalID  *uuid.UUID     `json:"principal_id,omitempty"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	PolicyResult *string        `json:"policy_result,omitempty"`
	TxHash       *string        `json:"tx_hash,omitempty"`
	ErrorMessage *string        `json:"error_message,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	ClientIP     *string        `json:"client_ip,omitempty"`
	UserAgent    *string        `json:"user_agent,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// AgentTransaction represents a transaction submitted by an agent
type AgentTransaction struct {
	ID           uuid.UUID `json:"id"`
	CredentialID uuid.UUID `json:"credential_id"`
	WalletID     uuid.UUID `json:"wallet_id"`
	ChainID      int64     `json:"chain_id"`
	TxHash       *string   `json:"tx_hash,omitempty"`
	Status       string    `json:"status"`
	Method       string    `json:"method"`
	ToAddress    *string   `json:"to_address,omitempty"`
	Value        *string   `json:"value,omitempty"`
	Data         *string   `json:"data,omitempty"`
	SignedTx     *string   `json:"signed_tx,omitempty"`
	ErrorMessage *string   `json:"error_message,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Status constants for Agent Wallet system
const (
	AgentStatusActive  = "active"
	AgentStatusPaused  = "paused"
	AgentStatusRevoked = "revoked"
	AgentStatusKilled  = "killed"
)

// Window type constants
const (
	WindowTypeHourly = "hourly"
	WindowTypeDaily  = "daily"
)

// Operation constants
const (
	OperationTransfer       = "transfer"
	OperationSwap           = "swap"
	OperationSignMessage    = "sign_message"
	OperationSignTypedData  = "sign_typed_data"
	OperationContractDeploy = "contract_deploy"
)
