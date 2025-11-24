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
	CreatedAt   time.Time  `json:"created_at"`
	RotatedAt   *time.Time `json:"rotated_at,omitempty"`
}

// KeyQuorum represents a threshold signature requirement
type KeyQuorum struct {
	ID        uuid.UUID   `json:"id"`
	Threshold int         `json:"threshold"`
	KeyIDs    []uuid.UUID `json:"key_ids"`
	Status    string      `json:"status"` // active, inactive
	CreatedAt time.Time   `json:"created_at"`
}

// Wallet represents a blockchain wallet
type Wallet struct {
	ID          uuid.UUID `json:"id"`
	UserID      uuid.UUID `json:"user_id"`
	ChainType   string    `json:"chain_type"`   // ethereum, solana, etc.
	OwnerID     uuid.UUID `json:"owner_id"`     // references authorization_keys or key_quorums
	ExecBackend string    `json:"exec_backend"` // kms, tee
	Address     string    `json:"address"`
	CreatedAt   time.Time `json:"created_at"`
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
	OwnerID   uuid.UUID              `json:"owner_id"`
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
	CreatedAt        time.Time  `json:"created_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

// AuditLog represents an audit trail entry
type AuditLog struct {
	ID            int64     `json:"id"`
	Actor         string    `json:"actor"`
	Action        string    `json:"action"`
	ResourceType  string    `json:"resource_type"`
	ResourceID    string    `json:"resource_id"`
	PolicyResult  *string   `json:"policy_result,omitempty"`
	SignerID      *string   `json:"signer_id,omitempty"`
	TxHash        *string   `json:"tx_hash,omitempty"`
	RequestDigest *string   `json:"request_digest,omitempty"`
	RequestNonce  *string   `json:"request_nonce,omitempty"`
	ClientIP      *string   `json:"client_ip,omitempty"`
	UserAgent     *string   `json:"user_agent,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
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
