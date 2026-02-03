package storage

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLogRepo handles audit log operations
type AuditLogRepo struct {
	db *pgxpool.Pool
}

// NewAuditLogRepo creates a new audit log repository
func NewAuditLogRepo(db *pgxpool.Pool) *AuditLogRepo {
	return &AuditLogRepo{db: db}
}

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	CredentialID *uuid.UUID             `json:"credential_id,omitempty"`
	WalletID     *uuid.UUID             `json:"wallet_id,omitempty"`
	PrincipalID  *uuid.UUID             `json:"principal_id,omitempty"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	PolicyResult *string                `json:"policy_result,omitempty"`
	TxHash       *string                `json:"tx_hash,omitempty"`
	ErrorMessage *string                `json:"error_message,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	ClientIP     string                 `json:"client_ip,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
}

// Log creates a new audit log entry
func (r *AuditLogRepo) Log(ctx context.Context, entry *AuditLogEntry) error {
	var metadataJSON []byte
	var err error
	if entry.Metadata != nil {
		metadataJSON, err = json.Marshal(entry.Metadata)
		if err != nil {
			return err
		}
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO agent_audit_logs (
			credential_id, wallet_id, principal_id, action, resource_type, resource_id,
			policy_result, tx_hash, error_message, metadata, client_ip, user_agent, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`,
		entry.CredentialID,
		entry.WalletID,
		entry.PrincipalID,
		entry.Action,
		entry.ResourceType,
		entry.ResourceID,
		entry.PolicyResult,
		entry.TxHash,
		entry.ErrorMessage,
		metadataJSON,
		entry.ClientIP,
		entry.UserAgent,
		time.Now(),
	)
	return err
}

// Audit action constants
const (
	AuditActionWalletCreated        = "wallet_created"
	AuditActionWalletPaused         = "wallet_paused"
	AuditActionWalletResumed        = "wallet_resumed"
	AuditActionWalletKilled         = "wallet_killed"
	AuditActionCredentialCreated    = "credential_created"
	AuditActionCredentialPaused     = "credential_paused"
	AuditActionCredentialResumed    = "credential_resumed"
	AuditActionCredentialRevoked    = "credential_revoked"
	AuditActionSigningRequested     = "signing_requested"
	AuditActionSigningCompleted     = "signing_completed"
	AuditActionSigningFailed        = "signing_failed"
	AuditActionTransactionSent      = "transaction_sent"
	AuditActionTransactionFailed    = "transaction_failed"
	AuditActionPolicyCheckPassed    = "policy_check_passed"
	AuditActionPolicyCheckFailed    = "policy_check_failed"
	AuditActionRateLimitExceeded    = "rate_limit_exceeded"
	AuditActionAuthenticationFailed = "authentication_failed"
)

// Resource type constants
const (
	ResourceTypeWallet      = "wallet"
	ResourceTypeCredential  = "credential"
	ResourceTypeTransaction = "transaction"
	ResourceTypePrincipal   = "principal"
)
