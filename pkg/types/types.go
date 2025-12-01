package types

import (
	"time"

	"github.com/google/uuid"
)

// User represents an end user in the system
type User struct {
	ID          uuid.UUID `json:"id"`
	ExternalSub string    `json:"external_sub"`
	CreatedAt   time.Time `json:"created_at"`
}

// AuthorizationKey represents a key used for signing authorization requests
type AuthorizationKey struct {
	ID          uuid.UUID  `json:"id"`
	PublicKey   []byte     `json:"public_key"`
	Algorithm   string     `json:"algorithm"` // p256, ed25519
	OwnerEntity string     `json:"owner_entity"`
	Status      string     `json:"status"` // active, rotated, revoked
	AppID       *uuid.UUID `json:"app_id,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	RotatedAt   *time.Time `json:"rotated_at,omitempty"`
}

// KeyQuorum represents a threshold signature requirement
type KeyQuorum struct {
	ID        uuid.UUID   `json:"id"`
	Threshold int         `json:"threshold"`
	KeyIDs    []uuid.UUID `json:"key_ids"`
	Status    string      `json:"status"` // active, inactive
	AppID     *uuid.UUID  `json:"app_id,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
}

// Wallet represents a blockchain wallet
type Wallet struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	ChainType   string     `json:"chain_type"`   // ethereum, solana, etc.
	OwnerID     uuid.UUID  `json:"owner_id"`     // references authorization_keys or key_quorums
	ExecBackend string     `json:"exec_backend"` // kms, tee
	Address     string     `json:"address"`
	AppID       *uuid.UUID `json:"app_id,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// WalletShare represents encrypted key material
type WalletShare struct {
	WalletID      uuid.UUID `json:"wallet_id"`
	ShareType     string    `json:"share_type"` // auth_share, exec_share, enclave_share
	BlobEncrypted []byte    `json:"blob_encrypted"`
	KMSKeyID      string    `json:"kms_key_id,omitempty"`
	Version       int       `json:"version"`
}

// Policy represents a policy that controls wallet operations
type Policy struct {
	ID        uuid.UUID              `json:"id"`
	Name      string                 `json:"name"`
	ChainType string                 `json:"chain_type"`
	Version   string                 `json:"version"`
	Rules     map[string]interface{} `json:"rules"`
	OwnerID   uuid.UUID              `json:"owner_id"` // Authorization key ID that owns this policy
	AppID     *uuid.UUID             `json:"app_id,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// WalletPolicy links wallets to policies
type WalletPolicy struct {
	WalletID uuid.UUID `json:"wallet_id"`
	PolicyID uuid.UUID `json:"policy_id"`
}

// SessionSigner represents a delegated short-term signing capability
type SessionSigner struct {
	ID               uuid.UUID  `json:"id"`
	WalletID         uuid.UUID  `json:"wallet_id"`
	SignerID         string     `json:"signer_id"`
	PolicyOverrideID *uuid.UUID `json:"policy_override_id,omitempty"`
	AllowedMethods   []string   `json:"allowed_methods,omitempty"`
	MaxValue         *string    `json:"max_value,omitempty"` // numeric string
	MaxTxs           *int       `json:"max_txs,omitempty"`
	TTLExpiresAt     time.Time  `json:"ttl_expires_at"`
	AppID            *uuid.UUID `json:"app_id,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

// AuditLog represents an audit trail entry
type AuditLog struct {
	ID            int64      `json:"id"`
	Actor         string     `json:"actor"`
	Action        string     `json:"action"`
	ResourceType  string     `json:"resource_type"`
	ResourceID    string     `json:"resource_id"`
	PolicyResult  *string    `json:"policy_result,omitempty"`
	SignerID      *string    `json:"signer_id,omitempty"`
	TxHash        *string    `json:"tx_hash,omitempty"`
	RequestDigest *string    `json:"request_digest,omitempty"`
	ClientIP      *string    `json:"client_ip,omitempty"`
	UserAgent     *string    `json:"user_agent,omitempty"`
	AppID         *uuid.UUID `json:"app_id,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// RecoveryInfo stores recovery-related information
type RecoveryInfo struct {
	WalletID      uuid.UUID `json:"wallet_id"`
	Method        string    `json:"method"` // auto, passkey, external_kms
	BlobEncrypted []byte    `json:"blob_encrypted"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ChainType constants
const (
	ChainTypeEthereum = "ethereum"
	ChainTypeSolana   = "solana"
	ChainTypeBitcoin  = "bitcoin"
)

// ExecBackend constants
const (
	ExecBackendKMS = "kms"
	ExecBackendTEE = "tee"
)

// AuthKind constants
const (
	AuthKindOIDC = "oidc"
	AuthKindJWT  = "jwt"
)

// KeyAlgorithm constants
const (
	AlgorithmP256 = "p256" // NIST P-256 (prime256v1) - Only supported algorithm
)

// ShareType constants
const (
	ShareTypeAuth    = "auth_share"
	ShareTypeExec    = "exec_share"
	ShareTypeEnclave = "enclave_share"
)

// Status constants
const (
	StatusActive   = "active"
	StatusRotated  = "rotated"
	StatusRevoked  = "revoked"
	StatusInactive = "inactive"
)

// IdempotencyKey represents an idempotency key for preventing duplicate requests
type IdempotencyKey struct {
	Key          string                 `json:"key"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   *uuid.UUID             `json:"resource_id,omitempty"`
	Status       string                 `json:"status"` // pending, completed, failed
	ResponseCode *int                   `json:"response_code,omitempty"`
	ResponseBody map[string]interface{} `json:"response_body,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	ExpiresAt    time.Time              `json:"expires_at"`
}

// ConditionSet represents a reusable set of values for policy conditions
// Used with the "in_condition_set" operator
type ConditionSet struct {
	ID          uuid.UUID     `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Values      []interface{} `json:"values"` // Array of addresses, chain IDs, etc.
	OwnerID     uuid.UUID     `json:"owner_id"`
	AppID       *uuid.UUID    `json:"app_id,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// App represents a multi-tenant application
type App struct {
	ID          uuid.UUID   `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	OwnerUserID uuid.UUID   `json:"owner_user_id"`
	Status      string      `json:"status"` // active, suspended, deleted
	Settings    AppSettings `json:"settings"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// AppSettings contains per-app configuration
type AppSettings struct {
	Auth      *AppAuthSettings      `json:"auth,omitempty"`
	RPC       *AppRPCSettings       `json:"rpc,omitempty"`
	RateLimit *AppRateLimitSettings `json:"rate_limit,omitempty"`
}

// AppAuthSettings contains authentication configuration for an app
type AppAuthSettings struct {
	Kind     string `json:"kind"`      // oidc or jwt
	Issuer   string `json:"issuer"`    // Token issuer URL
	Audience string `json:"audience"`  // Expected audience
	JWKSURI  string `json:"jwks_uri"`  // JWKS endpoint URL
}

// AppRPCSettings contains RPC endpoint configuration for an app
type AppRPCSettings struct {
	// Endpoints maps chain_id to RPC URL
	// e.g., {"1": "https://eth.example.com", "137": "https://polygon.example.com"}
	Endpoints map[string]string `json:"endpoints"`
}

// AppRateLimitSettings contains rate limiting configuration for an app
type AppRateLimitSettings struct {
	QPS int `json:"qps"` // Queries per second limit
}

// AppSecret represents an API secret for app authentication
type AppSecret struct {
	ID           uuid.UUID  `json:"id"`
	AppID        uuid.UUID  `json:"app_id"`
	SecretHash   string     `json:"-"` // Never expose in JSON
	SecretPrefix string     `json:"secret_prefix"`
	Status       string     `json:"status"` // active, rotated, revoked
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	RotatedAt    *time.Time `json:"rotated_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// AppStatus constants
const (
	AppStatusActive    = "active"
	AppStatusSuspended = "suspended"
	AppStatusDeleted   = "deleted"
)
