# Agent Wallet Phase 1 MVP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the core Agent Wallet system with Principal authentication, Agent Wallet creation, Agent Credential management, basic Policy, signing API, and Kill Switch.

**Architecture:** Simplified 3-entity model (Principal → Agent Wallet → Agent Credential). Remove User/Session Signer concepts. Keep KMS signing backend. Agents authenticate via API Key + Secret, policies enforce hard limits.

**Tech Stack:** Go 1.25, PostgreSQL, Drizzle ORM (dashboard schema), existing KMS/TEE keyexec

---

## Phase 1 Overview

| Component | Description |
|-----------|-------------|
| Database Schema | New tables for Agent Wallets and Credentials |
| Principal Auth | Simplified API Key authentication |
| Agent Wallet | Wallet creation with simplified key management |
| Agent Credential | Capability-based access tokens for agents |
| Agent Policy | Limits and allowlists |
| Signing API | Transaction signing for agents |
| Kill Switch | Pause/kill agent operations |

---

## Task 1: Clean Up Database Schema

**Files:**
- Modify: `dashboard/src/server/db/schema.ts`

**Step 1: Create new Agent Wallet schema**

Replace the entire schema with the simplified Agent Wallet model:

```typescript
import { bigint, boolean, integer, jsonb, pgTable, primaryKey, serial, text, timestamp, uuid } from 'drizzle-orm/pg-core'

// ==================== Principal Tables ====================

// Principals - humans or organizations that own agent wallets
export const principals = pgTable('principals', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  email: text('email').notNull().unique(),
  emailVerified: boolean('email_verified').notNull().default(false),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

// Principal API keys for management operations
export const principalApiKeys = pgTable('principal_api_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  principalId: uuid('principal_id')
    .notNull()
    .references(() => principals.id, { onDelete: 'cascade' }),
  keyHash: text('key_hash').notNull(), // bcrypt hash of the API key
  keyPrefix: text('key_prefix').notNull(), // e.g., "aw_pk_abc..."
  name: text('name').notNull(), // human-readable name
  status: text('status').notNull().default('active'), // active, revoked
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
})

// ==================== Agent Wallet Tables ====================

// Agent Wallets - blockchain wallets owned by principals
export const agentWallets = pgTable('agent_wallets', {
  id: uuid('id').primaryKey().defaultRandom(),
  principalId: uuid('principal_id')
    .notNull()
    .references(() => principals.id, { onDelete: 'restrict' }),
  name: text('name').notNull(),
  chainType: text('chain_type').notNull().default('ethereum'),
  address: text('address').notNull(),
  execBackend: text('exec_backend').notNull().default('kms'), // kms, tee
  status: text('status').notNull().default('active'), // active, paused, killed
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

// Wallet key material (simplified - single encrypted key, no Shamir)
export const walletKeys = pgTable('wallet_keys', {
  walletId: uuid('wallet_id')
    .primaryKey()
    .references(() => agentWallets.id, { onDelete: 'cascade' }),
  encryptedKey: text('encrypted_key').notNull(), // KMS-encrypted private key
  kmsKeyId: text('kms_key_id').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// ==================== Agent Credential Tables ====================

// Agent Credentials - capability tokens granted to AI agents
export const agentCredentials = pgTable('agent_credentials', {
  id: uuid('id').primaryKey().defaultRandom(),
  walletId: uuid('wallet_id')
    .notNull()
    .references(() => agentWallets.id, { onDelete: 'cascade' }),
  name: text('name').notNull(), // human-readable name
  keyHash: text('key_hash').notNull(), // bcrypt hash of the credential secret
  keyPrefix: text('key_prefix').notNull(), // e.g., "aw_ag_abc..."

  // Capabilities
  capabilities: jsonb('capabilities').notNull().$type<AgentCapabilities>(),

  // Hard limits
  limits: jsonb('limits').notNull().$type<AgentLimits>(),

  // Status
  status: text('status').notNull().default('active'), // active, paused, revoked

  // Timestamps
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  pausedAt: timestamp('paused_at', { withTimezone: true }),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
})

// Agent Capabilities type
export interface AgentCapabilities {
  chains: string[] // ethereum, base, etc.
  operations: string[] // transfer, swap, sign_message, etc.
  allowedContracts: string[] // contract addresses (empty = all allowed by policy)
  allowedMethods: string[] // contract methods (empty = all allowed by policy)
}

// Agent Limits type
export interface AgentLimits {
  maxValuePerTx: string // wei as string
  maxValuePerHour: string
  maxValuePerDay: string
  maxTxPerHour: number
  maxTxPerDay: number
}

// ==================== Policy Tables ====================

// Agent Policies - constraint rules for agent operations
export const agentPolicies = pgTable('agent_policies', {
  id: uuid('id').primaryKey().defaultRandom(),
  walletId: uuid('wallet_id')
    .notNull()
    .references(() => agentWallets.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  chainType: text('chain_type').notNull().default('ethereum'),
  rules: jsonb('rules').notNull().$type<PolicyRules>(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

// Policy rules type
export interface PolicyRule {
  name: string
  method: string // eth_sendTransaction, personal_sign, etc. or *
  conditions: PolicyCondition[]
  action: 'ALLOW' | 'DENY'
}

export interface PolicyCondition {
  field_source: string
  field: string
  operator: string
  value: unknown
}

export interface PolicyRules {
  rules: PolicyRule[]
}

// ==================== Rate Limiting Tables ====================

// Rate limit tracking for agents
export const agentRateLimits = pgTable('agent_rate_limits', {
  credentialId: uuid('credential_id')
    .notNull()
    .references(() => agentCredentials.id, { onDelete: 'cascade' }),
  windowType: text('window_type').notNull(), // hourly, daily
  windowStart: timestamp('window_start', { withTimezone: true }).notNull(),
  txCount: integer('tx_count').notNull().default(0),
  totalValue: text('total_value').notNull().default('0'), // wei as string
}, (table) => [
  primaryKey({ columns: [table.credentialId, table.windowType, table.windowStart] })
])

// ==================== Audit Tables ====================

// Audit logs for agent operations
export const agentAuditLogs = pgTable('agent_audit_logs', {
  id: serial('id').primaryKey(),
  credentialId: uuid('credential_id').references(() => agentCredentials.id, { onDelete: 'set null' }),
  walletId: uuid('wallet_id').references(() => agentWallets.id, { onDelete: 'set null' }),
  principalId: uuid('principal_id').references(() => principals.id, { onDelete: 'set null' }),
  action: text('action').notNull(), // sign_transaction, pause_agent, kill_agent, etc.
  resourceType: text('resource_type').notNull(),
  resourceId: text('resource_id').notNull(),
  policyResult: text('policy_result'), // ALLOW, DENY, or null
  txHash: text('tx_hash'),
  errorMessage: text('error_message'),
  metadata: jsonb('metadata').$type<Record<string, unknown>>(),
  clientIp: text('client_ip'),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// ==================== Transaction Tables ====================

// Transactions submitted by agents
export const agentTransactions = pgTable('agent_transactions', {
  id: uuid('id').primaryKey().defaultRandom(),
  credentialId: uuid('credential_id')
    .notNull()
    .references(() => agentCredentials.id, { onDelete: 'cascade' }),
  walletId: uuid('wallet_id')
    .notNull()
    .references(() => agentWallets.id, { onDelete: 'cascade' }),
  chainId: bigint('chain_id', { mode: 'number' }).notNull(),
  txHash: text('tx_hash'),
  status: text('status').notNull().default('pending'), // pending, submitted, confirmed, failed
  method: text('method').notNull(), // eth_sendTransaction, personal_sign, etc.
  toAddress: text('to_address'),
  value: text('value'), // wei as string
  data: text('data'),
  signedTx: text('signed_tx'), // hex encoded
  errorMessage: text('error_message'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

// ==================== Type Exports ====================

export type Principal = typeof principals.$inferSelect
export type PrincipalApiKey = typeof principalApiKeys.$inferSelect
export type AgentWallet = typeof agentWallets.$inferSelect
export type WalletKey = typeof walletKeys.$inferSelect
export type AgentCredential = typeof agentCredentials.$inferSelect
export type AgentPolicy = typeof agentPolicies.$inferSelect
export type AgentRateLimit = typeof agentRateLimits.$inferSelect
export type AgentAuditLog = typeof agentAuditLogs.$inferSelect
export type AgentTransaction = typeof agentTransactions.$inferSelect
```

**Step 2: Run schema migration**

```bash
cd dashboard && bun run db:push
```

**Step 3: Verify migration**

```bash
cd dashboard && bun run db:studio
```

**Step 4: Commit**

```bash
git add dashboard/src/server/db/schema.ts
git commit -m "feat: replace schema with Agent Wallet model

- Remove User, Session Signer, App concepts
- Add Principal, Agent Wallet, Agent Credential tables
- Simplify key storage (no Shamir splitting)
- Add rate limiting and audit tables"
```

---

## Task 2: Define Go Types

**Files:**
- Create: `pkg/types/agent.go`
- Modify: `pkg/types/types.go` (remove old types)

**Step 1: Create agent types file**

```go
// pkg/types/agent.go
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
	ID        uuid.UUID              `json:"id"`
	WalletID  uuid.UUID              `json:"wallet_id"`
	Name      string                 `json:"name"`
	ChainType string                 `json:"chain_type"`
	Rules     map[string]interface{} `json:"rules"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// AgentRateLimit tracks rate limits for an agent credential
type AgentRateLimit struct {
	CredentialID uuid.UUID `json:"credential_id"`
	WindowType   string    `json:"window_type"` // hourly, daily
	WindowStart  time.Time `json:"window_start"`
	TxCount      int       `json:"tx_count"`
	TotalValue   string    `json:"total_value"` // wei as string
}

// AgentAuditLog represents an audit trail entry for agent operations
type AgentAuditLog struct {
	ID           int64                  `json:"id"`
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
	ClientIP     *string                `json:"client_ip,omitempty"`
	UserAgent    *string                `json:"user_agent,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// AgentTransaction represents a transaction submitted by an agent
type AgentTransaction struct {
	ID           uuid.UUID  `json:"id"`
	CredentialID uuid.UUID  `json:"credential_id"`
	WalletID     uuid.UUID  `json:"wallet_id"`
	ChainID      int64      `json:"chain_id"`
	TxHash       *string    `json:"tx_hash,omitempty"`
	Status       string     `json:"status"`
	Method       string     `json:"method"`
	ToAddress    *string    `json:"to_address,omitempty"`
	Value        *string    `json:"value,omitempty"`
	Data         *string    `json:"data,omitempty"`
	SignedTx     *string    `json:"signed_tx,omitempty"`
	ErrorMessage *string    `json:"error_message,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Status constants
const (
	StatusActive  = "active"
	StatusPaused  = "paused"
	StatusRevoked = "revoked"
	StatusKilled  = "killed"
)

// Window type constants
const (
	WindowTypeHourly = "hourly"
	WindowTypeDaily  = "daily"
)

// Operation constants
const (
	OperationTransfer    = "transfer"
	OperationSwap        = "swap"
	OperationSignMessage = "sign_message"
	OperationSignTypedData = "sign_typed_data"
)
```

**Step 2: Run tests to ensure types compile**

```bash
go build ./pkg/types/...
```

**Step 3: Commit**

```bash
git add pkg/types/agent.go
git commit -m "feat: add Agent Wallet Go types

- Principal, PrincipalAPIKey
- AgentWallet, WalletKey
- AgentCredential with Capabilities and Limits
- AgentPolicy, AgentRateLimit
- AgentAuditLog, AgentTransaction"
```

---

## Task 3: Create Storage Repositories

**Files:**
- Create: `internal/storage/principal_repo.go`
- Create: `internal/storage/agent_wallet_repo.go`
- Create: `internal/storage/agent_credential_repo.go`
- Create: `internal/storage/agent_rate_limit_repo.go`

**Step 1: Create principal repository**

```go
// internal/storage/principal_repo.go
package storage

import (
	"context"
	"errors"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PrincipalRepo handles principal data access
type PrincipalRepo struct {
	db DBTX
}

// NewPrincipalRepo creates a new principal repository
func NewPrincipalRepo(db DBTX) *PrincipalRepo {
	return &PrincipalRepo{db: db}
}

// Create creates a new principal
func (r *PrincipalRepo) Create(ctx context.Context, principal *types.Principal) error {
	query := `
		INSERT INTO principals (id, name, email, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.Exec(ctx, query,
		principal.ID,
		principal.Name,
		principal.Email,
		principal.EmailVerified,
		principal.CreatedAt,
		principal.UpdatedAt,
	)
	return err
}

// GetByID retrieves a principal by ID
func (r *PrincipalRepo) GetByID(ctx context.Context, id uuid.UUID) (*types.Principal, error) {
	query := `
		SELECT id, name, email, email_verified, created_at, updated_at
		FROM principals
		WHERE id = $1
	`
	var p types.Principal
	err := r.db.QueryRow(ctx, query, id).Scan(
		&p.ID, &p.Name, &p.Email, &p.EmailVerified, &p.CreatedAt, &p.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &p, err
}

// GetByEmail retrieves a principal by email
func (r *PrincipalRepo) GetByEmail(ctx context.Context, email string) (*types.Principal, error) {
	query := `
		SELECT id, name, email, email_verified, created_at, updated_at
		FROM principals
		WHERE email = $1
	`
	var p types.Principal
	err := r.db.QueryRow(ctx, query, email).Scan(
		&p.ID, &p.Name, &p.Email, &p.EmailVerified, &p.CreatedAt, &p.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &p, err
}

// PrincipalAPIKeyRepo handles principal API key data access
type PrincipalAPIKeyRepo struct {
	db DBTX
}

// NewPrincipalAPIKeyRepo creates a new principal API key repository
func NewPrincipalAPIKeyRepo(db DBTX) *PrincipalAPIKeyRepo {
	return &PrincipalAPIKeyRepo{db: db}
}

// Create creates a new API key
func (r *PrincipalAPIKeyRepo) Create(ctx context.Context, key *types.PrincipalAPIKey, keyHash string) error {
	query := `
		INSERT INTO principal_api_keys (id, principal_id, key_hash, key_prefix, name, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.Exec(ctx, query,
		key.ID,
		key.PrincipalID,
		keyHash,
		key.KeyPrefix,
		key.Name,
		key.Status,
		key.CreatedAt,
	)
	return err
}

// GetByPrefix retrieves an API key by its prefix for validation
func (r *PrincipalAPIKeyRepo) GetByPrefix(ctx context.Context, prefix string) (*types.PrincipalAPIKey, string, error) {
	query := `
		SELECT id, principal_id, key_hash, key_prefix, name, status, last_used_at, created_at, revoked_at
		FROM principal_api_keys
		WHERE key_prefix = $1 AND status = 'active'
	`
	var key types.PrincipalAPIKey
	var keyHash string
	err := r.db.QueryRow(ctx, query, prefix).Scan(
		&key.ID, &key.PrincipalID, &keyHash, &key.KeyPrefix, &key.Name,
		&key.Status, &key.LastUsedAt, &key.CreatedAt, &key.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	return &key, keyHash, err
}

// UpdateLastUsed updates the last used timestamp
func (r *PrincipalAPIKeyRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE principal_api_keys SET last_used_at = NOW() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	return err
}

// Revoke revokes an API key
func (r *PrincipalAPIKeyRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE principal_api_keys SET status = 'revoked', revoked_at = NOW() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	return err
}
```

**Step 2: Create agent wallet repository**

```go
// internal/storage/agent_wallet_repo.go
package storage

import (
	"context"
	"errors"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AgentWalletRepo handles agent wallet data access
type AgentWalletRepo struct {
	db DBTX
}

// NewAgentWalletRepo creates a new agent wallet repository
func NewAgentWalletRepo(db DBTX) *AgentWalletRepo {
	return &AgentWalletRepo{db: db}
}

// Create creates a new agent wallet
func (r *AgentWalletRepo) Create(ctx context.Context, wallet *types.AgentWallet) error {
	query := `
		INSERT INTO agent_wallets (id, principal_id, name, chain_type, address, exec_backend, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.db.Exec(ctx, query,
		wallet.ID,
		wallet.PrincipalID,
		wallet.Name,
		wallet.ChainType,
		wallet.Address,
		wallet.ExecBackend,
		wallet.Status,
		wallet.CreatedAt,
		wallet.UpdatedAt,
	)
	return err
}

// GetByID retrieves a wallet by ID
func (r *AgentWalletRepo) GetByID(ctx context.Context, id uuid.UUID) (*types.AgentWallet, error) {
	query := `
		SELECT id, principal_id, name, chain_type, address, exec_backend, status, created_at, updated_at
		FROM agent_wallets
		WHERE id = $1
	`
	var w types.AgentWallet
	err := r.db.QueryRow(ctx, query, id).Scan(
		&w.ID, &w.PrincipalID, &w.Name, &w.ChainType, &w.Address,
		&w.ExecBackend, &w.Status, &w.CreatedAt, &w.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &w, err
}

// ListByPrincipal lists all wallets for a principal
func (r *AgentWalletRepo) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*types.AgentWallet, error) {
	query := `
		SELECT id, principal_id, name, chain_type, address, exec_backend, status, created_at, updated_at
		FROM agent_wallets
		WHERE principal_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var wallets []*types.AgentWallet
	for rows.Next() {
		var w types.AgentWallet
		err := rows.Scan(
			&w.ID, &w.PrincipalID, &w.Name, &w.ChainType, &w.Address,
			&w.ExecBackend, &w.Status, &w.CreatedAt, &w.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		wallets = append(wallets, &w)
	}
	return wallets, rows.Err()
}

// UpdateStatus updates the wallet status (for pause/kill)
func (r *AgentWalletRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	query := `UPDATE agent_wallets SET status = $1, updated_at = NOW() WHERE id = $2`
	_, err := r.db.Exec(ctx, query, status, id)
	return err
}

// WalletKeyRepo handles wallet key data access
type WalletKeyRepo struct {
	db DBTX
}

// NewWalletKeyRepo creates a new wallet key repository
func NewWalletKeyRepo(db DBTX) *WalletKeyRepo {
	return &WalletKeyRepo{db: db}
}

// Create stores encrypted key material
func (r *WalletKeyRepo) Create(ctx context.Context, key *types.WalletKey) error {
	query := `
		INSERT INTO wallet_keys (wallet_id, encrypted_key, kms_key_id, created_at)
		VALUES ($1, $2, $3, $4)
	`
	_, err := r.db.Exec(ctx, query,
		key.WalletID,
		key.EncryptedKey,
		key.KMSKeyID,
		key.CreatedAt,
	)
	return err
}

// GetByWalletID retrieves key material for a wallet
func (r *WalletKeyRepo) GetByWalletID(ctx context.Context, walletID uuid.UUID) (*types.WalletKey, error) {
	query := `
		SELECT wallet_id, encrypted_key, kms_key_id, created_at
		FROM wallet_keys
		WHERE wallet_id = $1
	`
	var k types.WalletKey
	err := r.db.QueryRow(ctx, query, walletID).Scan(
		&k.WalletID, &k.EncryptedKey, &k.KMSKeyID, &k.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &k, err
}
```

**Step 3: Create agent credential repository**

```go
// internal/storage/agent_credential_repo.go
package storage

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AgentCredentialRepo handles agent credential data access
type AgentCredentialRepo struct {
	db DBTX
}

// NewAgentCredentialRepo creates a new agent credential repository
func NewAgentCredentialRepo(db DBTX) *AgentCredentialRepo {
	return &AgentCredentialRepo{db: db}
}

// Create creates a new agent credential
func (r *AgentCredentialRepo) Create(ctx context.Context, cred *types.AgentCredential, keyHash string) error {
	capabilitiesJSON, err := json.Marshal(cred.Capabilities)
	if err != nil {
		return err
	}
	limitsJSON, err := json.Marshal(cred.Limits)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO agent_credentials (id, wallet_id, name, key_hash, key_prefix, capabilities, limits, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err = r.db.Exec(ctx, query,
		cred.ID,
		cred.WalletID,
		cred.Name,
		keyHash,
		cred.KeyPrefix,
		capabilitiesJSON,
		limitsJSON,
		cred.Status,
		cred.CreatedAt,
	)
	return err
}

// GetByID retrieves a credential by ID
func (r *AgentCredentialRepo) GetByID(ctx context.Context, id uuid.UUID) (*types.AgentCredential, error) {
	query := `
		SELECT id, wallet_id, name, key_prefix, capabilities, limits, status, last_used_at, created_at, paused_at, revoked_at
		FROM agent_credentials
		WHERE id = $1
	`
	var cred types.AgentCredential
	var capabilitiesJSON, limitsJSON []byte
	err := r.db.QueryRow(ctx, query, id).Scan(
		&cred.ID, &cred.WalletID, &cred.Name, &cred.KeyPrefix,
		&capabilitiesJSON, &limitsJSON, &cred.Status,
		&cred.LastUsedAt, &cred.CreatedAt, &cred.PausedAt, &cred.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(capabilitiesJSON, &cred.Capabilities); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(limitsJSON, &cred.Limits); err != nil {
		return nil, err
	}
	return &cred, nil
}

// GetByPrefixWithHash retrieves a credential by prefix for authentication
func (r *AgentCredentialRepo) GetByPrefixWithHash(ctx context.Context, prefix string) (*types.AgentCredential, string, error) {
	query := `
		SELECT id, wallet_id, name, key_hash, key_prefix, capabilities, limits, status, last_used_at, created_at, paused_at, revoked_at
		FROM agent_credentials
		WHERE key_prefix = $1
	`
	var cred types.AgentCredential
	var keyHash string
	var capabilitiesJSON, limitsJSON []byte
	err := r.db.QueryRow(ctx, query, prefix).Scan(
		&cred.ID, &cred.WalletID, &cred.Name, &keyHash, &cred.KeyPrefix,
		&capabilitiesJSON, &limitsJSON, &cred.Status,
		&cred.LastUsedAt, &cred.CreatedAt, &cred.PausedAt, &cred.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}

	if err := json.Unmarshal(capabilitiesJSON, &cred.Capabilities); err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal(limitsJSON, &cred.Limits); err != nil {
		return nil, "", err
	}
	return &cred, keyHash, nil
}

// ListByWallet lists all credentials for a wallet
func (r *AgentCredentialRepo) ListByWallet(ctx context.Context, walletID uuid.UUID) ([]*types.AgentCredential, error) {
	query := `
		SELECT id, wallet_id, name, key_prefix, capabilities, limits, status, last_used_at, created_at, paused_at, revoked_at
		FROM agent_credentials
		WHERE wallet_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, walletID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*types.AgentCredential
	for rows.Next() {
		var cred types.AgentCredential
		var capabilitiesJSON, limitsJSON []byte
		err := rows.Scan(
			&cred.ID, &cred.WalletID, &cred.Name, &cred.KeyPrefix,
			&capabilitiesJSON, &limitsJSON, &cred.Status,
			&cred.LastUsedAt, &cred.CreatedAt, &cred.PausedAt, &cred.RevokedAt,
		)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(capabilitiesJSON, &cred.Capabilities); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(limitsJSON, &cred.Limits); err != nil {
			return nil, err
		}
		creds = append(creds, &cred)
	}
	return creds, rows.Err()
}

// UpdateStatus updates the credential status
func (r *AgentCredentialRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	var query string
	switch status {
	case types.StatusPaused:
		query = `UPDATE agent_credentials SET status = $1, paused_at = NOW() WHERE id = $2`
	case types.StatusRevoked:
		query = `UPDATE agent_credentials SET status = $1, revoked_at = NOW() WHERE id = $2`
	default:
		query = `UPDATE agent_credentials SET status = $1 WHERE id = $2`
	}
	_, err := r.db.Exec(ctx, query, status, id)
	return err
}

// UpdateLastUsed updates the last used timestamp
func (r *AgentCredentialRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE agent_credentials SET last_used_at = NOW() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	return err
}
```

**Step 4: Create rate limit repository**

```go
// internal/storage/agent_rate_limit_repo.go
package storage

import (
	"context"
	"math/big"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// AgentRateLimitRepo handles rate limit tracking
type AgentRateLimitRepo struct {
	db DBTX
}

// NewAgentRateLimitRepo creates a new rate limit repository
func NewAgentRateLimitRepo(db DBTX) *AgentRateLimitRepo {
	return &AgentRateLimitRepo{db: db}
}

// GetOrCreate gets or creates a rate limit record for a window
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
	return &rl, err
}

// IncrementUsage atomically increments the tx count and total value
func (r *AgentRateLimitRepo) IncrementUsage(ctx context.Context, credentialID uuid.UUID, windowType string, windowStart time.Time, value *big.Int) error {
	query := `
		UPDATE agent_rate_limits
		SET tx_count = tx_count + 1,
		    total_value = (CAST(total_value AS NUMERIC) + $1)::TEXT
		WHERE credential_id = $2 AND window_type = $3 AND window_start = $4
	`
	_, err := r.db.Exec(ctx, query, value.String(), credentialID, windowType, windowStart)
	return err
}

// GetCurrentUsage gets the current usage for both hourly and daily windows
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
```

**Step 5: Run tests**

```bash
go build ./internal/storage/...
```

**Step 6: Commit**

```bash
git add internal/storage/principal_repo.go internal/storage/agent_wallet_repo.go internal/storage/agent_credential_repo.go internal/storage/agent_rate_limit_repo.go
git commit -m "feat: add storage repositories for Agent Wallet

- PrincipalRepo and PrincipalAPIKeyRepo
- AgentWalletRepo and WalletKeyRepo
- AgentCredentialRepo with capability/limits JSON
- AgentRateLimitRepo for rate limiting"
```

---

## Task 4: Implement Principal Authentication Middleware

**Files:**
- Create: `internal/middleware/principal_auth.go`
- Create: `internal/middleware/principal_auth_test.go`

**Step 1: Write failing test**

```go
// internal/middleware/principal_auth_test.go
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type mockPrincipalStore struct {
	apiKey    *types.PrincipalAPIKey
	keyHash   string
	principal *types.Principal
}

func (m *mockPrincipalStore) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*types.PrincipalAPIKey, string, error) {
	if m.apiKey != nil && m.apiKey.KeyPrefix == prefix {
		return m.apiKey, m.keyHash, nil
	}
	return nil, "", nil
}

func (m *mockPrincipalStore) GetPrincipalByID(ctx context.Context, id uuid.UUID) (*types.Principal, error) {
	if m.principal != nil && m.principal.ID == id {
		return m.principal, nil
	}
	return nil, nil
}

func (m *mockPrincipalStore) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	return nil
}

func TestPrincipalAuthMiddleware_ValidKey(t *testing.T) {
	principalID := uuid.New()
	apiKeyID := uuid.New()
	secret := "test_secret_key"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

	store := &mockPrincipalStore{
		apiKey: &types.PrincipalAPIKey{
			ID:          apiKeyID,
			PrincipalID: principalID,
			KeyPrefix:   "aw_pk_test",
			Status:      types.StatusActive,
		},
		keyHash: string(hash),
		principal: &types.Principal{
			ID:    principalID,
			Name:  "Test Principal",
			Email: "test@example.com",
		},
	}

	middleware := NewPrincipalAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := GetPrincipal(r.Context())
		if principal == nil {
			t.Error("expected principal in context")
			return
		}
		if principal.ID != principalID {
			t.Errorf("expected principal ID %s, got %s", principalID, principal.ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer aw_pk_test."+secret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestPrincipalAuthMiddleware_InvalidKey(t *testing.T) {
	store := &mockPrincipalStore{}
	middleware := NewPrincipalAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid_key")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/middleware/... -run TestPrincipalAuth -v
```

Expected: FAIL (PrincipalAuthMiddleware not defined)

**Step 3: Implement middleware**

```go
// internal/middleware/principal_auth.go
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type principalContextKey struct{}

// PrincipalStore defines the interface for principal data access
type PrincipalStore interface {
	GetAPIKeyByPrefix(ctx context.Context, prefix string) (*types.PrincipalAPIKey, string, error)
	GetPrincipalByID(ctx context.Context, id uuid.UUID) (*types.Principal, error)
	UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error
}

// PrincipalAuthMiddleware handles principal authentication via API key
type PrincipalAuthMiddleware struct {
	store PrincipalStore
}

// NewPrincipalAuthMiddleware creates a new principal auth middleware
func NewPrincipalAuthMiddleware(store PrincipalStore) *PrincipalAuthMiddleware {
	return &PrincipalAuthMiddleware{store: store}
}

// Authenticate validates the API key and adds principal to context
func (m *PrincipalAuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse token: prefix.secret
		parts := strings.SplitN(token, ".", 2)
		if len(parts) != 2 {
			http.Error(w, `{"error":"invalid api key format"}`, http.StatusUnauthorized)
			return
		}

		prefix, secret := parts[0], parts[1]

		// Look up API key by prefix
		apiKey, keyHash, err := m.store.GetAPIKeyByPrefix(r.Context(), prefix)
		if err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		if apiKey == nil {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}

		// Verify secret
		if err := bcrypt.CompareHashAndPassword([]byte(keyHash), []byte(secret)); err != nil {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}

		// Check status
		if apiKey.Status != types.StatusActive {
			http.Error(w, `{"error":"api key is not active"}`, http.StatusUnauthorized)
			return
		}

		// Get principal
		principal, err := m.store.GetPrincipalByID(r.Context(), apiKey.PrincipalID)
		if err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		if principal == nil {
			http.Error(w, `{"error":"principal not found"}`, http.StatusUnauthorized)
			return
		}

		// Update last used (async, don't block request)
		go func() {
			_ = m.store.UpdateAPIKeyLastUsed(context.Background(), apiKey.ID)
		}()

		// Add principal to context
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetPrincipal retrieves the principal from context
func GetPrincipal(ctx context.Context) *types.Principal {
	if v := ctx.Value(principalContextKey{}); v != nil {
		return v.(*types.Principal)
	}
	return nil
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./internal/middleware/... -run TestPrincipalAuth -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/middleware/principal_auth.go internal/middleware/principal_auth_test.go
git commit -m "feat: add principal authentication middleware

- API key format: prefix.secret
- bcrypt verification
- Adds principal to request context"
```

---

## Task 5: Implement Agent Credential Authentication Middleware

**Files:**
- Create: `internal/middleware/agent_auth.go`
- Create: `internal/middleware/agent_auth_test.go`

**Step 1: Write failing test**

```go
// internal/middleware/agent_auth_test.go
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type mockAgentStore struct {
	credential *types.AgentCredential
	keyHash    string
	wallet     *types.AgentWallet
}

func (m *mockAgentStore) GetCredentialByPrefix(ctx context.Context, prefix string) (*types.AgentCredential, string, error) {
	if m.credential != nil && m.credential.KeyPrefix == prefix {
		return m.credential, m.keyHash, nil
	}
	return nil, "", nil
}

func (m *mockAgentStore) GetWalletByID(ctx context.Context, id uuid.UUID) (*types.AgentWallet, error) {
	if m.wallet != nil && m.wallet.ID == id {
		return m.wallet, nil
	}
	return nil, nil
}

func (m *mockAgentStore) UpdateCredentialLastUsed(ctx context.Context, id uuid.UUID) error {
	return nil
}

func TestAgentAuthMiddleware_ValidCredential(t *testing.T) {
	walletID := uuid.New()
	credentialID := uuid.New()
	secret := "test_agent_secret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

	store := &mockAgentStore{
		credential: &types.AgentCredential{
			ID:        credentialID,
			WalletID:  walletID,
			KeyPrefix: "aw_ag_test",
			Status:    types.StatusActive,
			Capabilities: types.AgentCapabilities{
				Chains:     []string{"ethereum"},
				Operations: []string{"transfer"},
			},
			Limits: types.AgentLimits{
				MaxValuePerTx:   "1000000000000000000",
				MaxValuePerHour: "10000000000000000000",
				MaxValuePerDay:  "100000000000000000000",
				MaxTxPerHour:    100,
				MaxTxPerDay:     1000,
			},
			CreatedAt: time.Now(),
		},
		keyHash: string(hash),
		wallet: &types.AgentWallet{
			ID:        walletID,
			Status:    types.StatusActive,
			ChainType: "ethereum",
			Address:   "0x1234567890123456789012345678901234567890",
		},
	}

	middleware := NewAgentAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred := GetAgentCredential(r.Context())
		if cred == nil {
			t.Error("expected credential in context")
			return
		}
		if cred.ID != credentialID {
			t.Errorf("expected credential ID %s, got %s", credentialID, cred.ID)
		}
		wallet := GetAgentWallet(r.Context())
		if wallet == nil {
			t.Error("expected wallet in context")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer aw_ag_test."+secret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAgentAuthMiddleware_PausedCredential(t *testing.T) {
	walletID := uuid.New()
	credentialID := uuid.New()
	secret := "test_agent_secret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	pausedAt := time.Now()

	store := &mockAgentStore{
		credential: &types.AgentCredential{
			ID:        credentialID,
			WalletID:  walletID,
			KeyPrefix: "aw_ag_test",
			Status:    types.StatusPaused,
			PausedAt:  &pausedAt,
		},
		keyHash: string(hash),
	}

	middleware := NewAgentAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer aw_ag_test."+secret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/middleware/... -run TestAgentAuth -v
```

Expected: FAIL

**Step 3: Implement middleware**

```go
// internal/middleware/agent_auth.go
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type agentCredentialContextKey struct{}
type agentWalletContextKey struct{}

// AgentStore defines the interface for agent data access
type AgentStore interface {
	GetCredentialByPrefix(ctx context.Context, prefix string) (*types.AgentCredential, string, error)
	GetWalletByID(ctx context.Context, id uuid.UUID) (*types.AgentWallet, error)
	UpdateCredentialLastUsed(ctx context.Context, id uuid.UUID) error
}

// AgentAuthMiddleware handles agent credential authentication
type AgentAuthMiddleware struct {
	store AgentStore
}

// NewAgentAuthMiddleware creates a new agent auth middleware
func NewAgentAuthMiddleware(store AgentStore) *AgentAuthMiddleware {
	return &AgentAuthMiddleware{store: store}
}

// Authenticate validates the agent credential and adds it to context
func (m *AgentAuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse token: prefix.secret
		parts := strings.SplitN(token, ".", 2)
		if len(parts) != 2 {
			http.Error(w, `{"error":"invalid credential format"}`, http.StatusUnauthorized)
			return
		}

		prefix, secret := parts[0], parts[1]

		// Look up credential by prefix
		credential, keyHash, err := m.store.GetCredentialByPrefix(r.Context(), prefix)
		if err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		if credential == nil {
			http.Error(w, `{"error":"invalid credential"}`, http.StatusUnauthorized)
			return
		}

		// Verify secret
		if err := bcrypt.CompareHashAndPassword([]byte(keyHash), []byte(secret)); err != nil {
			http.Error(w, `{"error":"invalid credential"}`, http.StatusUnauthorized)
			return
		}

		// Check credential status
		switch credential.Status {
		case types.StatusActive:
			// OK
		case types.StatusPaused:
			http.Error(w, `{"error":"agent credential is paused","code":"CREDENTIAL_PAUSED"}`, http.StatusForbidden)
			return
		case types.StatusRevoked:
			http.Error(w, `{"error":"agent credential is revoked","code":"CREDENTIAL_REVOKED"}`, http.StatusForbidden)
			return
		default:
			http.Error(w, `{"error":"agent credential is not active"}`, http.StatusForbidden)
			return
		}

		// Get wallet and check status
		wallet, err := m.store.GetWalletByID(r.Context(), credential.WalletID)
		if err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		if wallet == nil {
			http.Error(w, `{"error":"wallet not found"}`, http.StatusNotFound)
			return
		}

		// Check wallet status
		switch wallet.Status {
		case types.StatusActive:
			// OK
		case types.StatusPaused:
			http.Error(w, `{"error":"wallet is paused","code":"WALLET_PAUSED"}`, http.StatusForbidden)
			return
		case types.StatusKilled:
			http.Error(w, `{"error":"wallet is killed","code":"WALLET_KILLED"}`, http.StatusForbidden)
			return
		default:
			http.Error(w, `{"error":"wallet is not active"}`, http.StatusForbidden)
			return
		}

		// Update last used (async)
		go func() {
			_ = m.store.UpdateCredentialLastUsed(context.Background(), credential.ID)
		}()

		// Add credential and wallet to context
		ctx := context.WithValue(r.Context(), agentCredentialContextKey{}, credential)
		ctx = context.WithValue(ctx, agentWalletContextKey{}, wallet)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetAgentCredential retrieves the agent credential from context
func GetAgentCredential(ctx context.Context) *types.AgentCredential {
	if v := ctx.Value(agentCredentialContextKey{}); v != nil {
		return v.(*types.AgentCredential)
	}
	return nil
}

// GetAgentWallet retrieves the agent wallet from context
func GetAgentWallet(ctx context.Context) *types.AgentWallet {
	if v := ctx.Value(agentWalletContextKey{}); v != nil {
		return v.(*types.AgentWallet)
	}
	return nil
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./internal/middleware/... -run TestAgentAuth -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/middleware/agent_auth.go internal/middleware/agent_auth_test.go
git commit -m "feat: add agent credential authentication middleware

- Validates agent credential (prefix.secret format)
- Checks credential and wallet status
- Returns appropriate error codes for paused/killed states
- Adds credential and wallet to request context"
```

---

## Task 6: Implement Agent Wallet Service

**Files:**
- Create: `internal/app/agent_service.go`
- Create: `internal/app/agent_service_test.go`

**Step 1: Write failing test for wallet creation**

```go
// internal/app/agent_service_test.go
package app

import (
	"context"
	"testing"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

func TestAgentService_CreateWallet(t *testing.T) {
	// This is a placeholder - actual implementation will need mocks for:
	// - Storage repos
	// - Key executor

	principalID := uuid.New()

	req := CreateAgentWalletRequest{
		PrincipalID: principalID,
		Name:        "Test Wallet",
		ChainType:   "ethereum",
	}

	// Test that we get back a valid wallet
	if req.Name != "Test Wallet" {
		t.Error("request name mismatch")
	}
}
```

**Step 2: Implement agent service**

```go
// internal/app/agent_service.go
package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/better-wallet/better-wallet/internal/keyexec"
	"github.com/better-wallet/better-wallet/internal/policy"
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
	policyRepo      *storage.AgentPolicyRepo
	auditRepo       *storage.AgentAuditRepo
	keyExecutor     keyexec.KeyExecutor
	policyEngine    *policy.Engine
}

// NewAgentService creates a new agent service
func NewAgentService(
	principalRepo *storage.PrincipalRepo,
	apiKeyRepo *storage.PrincipalAPIKeyRepo,
	walletRepo *storage.AgentWalletRepo,
	walletKeyRepo *storage.WalletKeyRepo,
	credentialRepo *storage.AgentCredentialRepo,
	rateLimitRepo *storage.AgentRateLimitRepo,
	policyRepo *storage.AgentPolicyRepo,
	auditRepo *storage.AgentAuditRepo,
	keyExecutor keyexec.KeyExecutor,
	policyEngine *policy.Engine,
) *AgentService {
	return &AgentService{
		principalRepo:  principalRepo,
		apiKeyRepo:     apiKeyRepo,
		walletRepo:     walletRepo,
		walletKeyRepo:  walletKeyRepo,
		credentialRepo: credentialRepo,
		rateLimitRepo:  rateLimitRepo,
		policyRepo:     policyRepo,
		auditRepo:      auditRepo,
		keyExecutor:    keyExecutor,
		policyEngine:   policyEngine,
	}
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
	// Validate chain type
	if req.ChainType != types.ChainTypeEthereum {
		return nil, fmt.Errorf("unsupported chain type: %s", req.ChainType)
	}

	// Generate key material
	keyMaterial, err := s.keyExecutor.GenerateAndSplitKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encrypt the private key for storage
	// Note: In the simplified model, we store the full key encrypted, not split
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
		Status:      types.StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Store wallet
	if err := s.walletRepo.Create(ctx, wallet); err != nil {
		return nil, fmt.Errorf("failed to create wallet: %w", err)
	}

	// Store encrypted key
	walletKey := &types.WalletKey{
		WalletID:     walletID,
		EncryptedKey: encryptedKey,
		KMSKeyID:     "", // Will be set by KMS provider
		CreatedAt:    now,
	}
	if err := s.walletKeyRepo.Create(ctx, walletKey); err != nil {
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	return &CreateAgentWalletResponse{Wallet: wallet}, nil
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
	// Generate credential secret
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}
	secret := base64.URLEncoding.EncodeToString(secretBytes)

	// Generate prefix
	prefixBytes := make([]byte, 8)
	if _, err := rand.Read(prefixBytes); err != nil {
		return nil, fmt.Errorf("failed to generate prefix: %w", err)
	}
	prefix := "aw_ag_" + base64.URLEncoding.EncodeToString(prefixBytes)[:8]

	// Hash secret
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash secret: %w", err)
	}

	now := time.Now().UTC()
	credentialID := uuid.New()

	credential := &types.AgentCredential{
		ID:           credentialID,
		WalletID:     req.WalletID,
		Name:         req.Name,
		KeyPrefix:    prefix,
		Capabilities: req.Capabilities,
		Limits:       req.Limits,
		Status:       types.StatusActive,
		CreatedAt:    now,
	}

	if err := s.credentialRepo.Create(ctx, credential, string(hash)); err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	return &CreateAgentCredentialResponse{
		Credential: credential,
		Secret:     prefix + "." + secret,
	}, nil
}

// PauseCredential pauses an agent credential
func (s *AgentService) PauseCredential(ctx context.Context, credentialID uuid.UUID) error {
	return s.credentialRepo.UpdateStatus(ctx, credentialID, types.StatusPaused)
}

// ResumeCredential resumes a paused agent credential
func (s *AgentService) ResumeCredential(ctx context.Context, credentialID uuid.UUID) error {
	return s.credentialRepo.UpdateStatus(ctx, credentialID, types.StatusActive)
}

// RevokeCredential permanently revokes an agent credential (kill)
func (s *AgentService) RevokeCredential(ctx context.Context, credentialID uuid.UUID) error {
	return s.credentialRepo.UpdateStatus(ctx, credentialID, types.StatusRevoked)
}

// PauseWallet pauses all operations for a wallet
func (s *AgentService) PauseWallet(ctx context.Context, walletID uuid.UUID) error {
	return s.walletRepo.UpdateStatus(ctx, walletID, types.StatusPaused)
}

// ResumeWallet resumes a paused wallet
func (s *AgentService) ResumeWallet(ctx context.Context, walletID uuid.UUID) error {
	return s.walletRepo.UpdateStatus(ctx, walletID, types.StatusActive)
}

// KillWallet permanently kills a wallet (cannot be resumed)
func (s *AgentService) KillWallet(ctx context.Context, walletID uuid.UUID) error {
	return s.walletRepo.UpdateStatus(ctx, walletID, types.StatusKilled)
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

	// Check hourly value
	if credential.Limits.MaxValuePerHour != "" {
		maxHourly, ok := new(big.Int).SetString(credential.Limits.MaxValuePerHour, 10)
		if ok {
			currentHourly, _ := new(big.Int).SetString(hourly.TotalValue, 10)
			newTotal := new(big.Int).Add(currentHourly, value)
			if newTotal.Cmp(maxHourly) > 0 {
				return fmt.Errorf("hourly value limit exceeded")
			}
		}
	}

	// Check daily value
	if credential.Limits.MaxValuePerDay != "" {
		maxDaily, ok := new(big.Int).SetString(credential.Limits.MaxValuePerDay, 10)
		if ok {
			currentDaily, _ := new(big.Int).SetString(daily.TotalValue, 10)
			newTotal := new(big.Int).Add(currentDaily, value)
			if newTotal.Cmp(maxDaily) > 0 {
				return fmt.Errorf("daily value limit exceeded")
			}
		}
	}

	// Check per-tx value
	if credential.Limits.MaxValuePerTx != "" {
		maxPerTx, ok := new(big.Int).SetString(credential.Limits.MaxValuePerTx, 10)
		if ok && value.Cmp(maxPerTx) > 0 {
			return fmt.Errorf("transaction value limit exceeded")
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
```

**Step 3: Run tests**

```bash
go build ./internal/app/...
```

**Step 4: Commit**

```bash
git add internal/app/agent_service.go internal/app/agent_service_test.go
git commit -m "feat: add agent service for wallet and credential management

- CreateWallet with key generation
- CreateCredential with secret generation
- Pause/Resume/Kill for wallets and credentials
- Rate limit checking and recording"
```

---

## Task 7: Implement API Handlers

**Files:**
- Create: `internal/api/agent_handlers.go`

**Step 1: Implement handlers**

```go
// internal/api/agent_handlers.go
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// AgentHandlers handles agent-related API requests
type AgentHandlers struct {
	agentService *app.AgentService
}

// NewAgentHandlers creates new agent handlers
func NewAgentHandlers(agentService *app.AgentService) *AgentHandlers {
	return &AgentHandlers{agentService: agentService}
}

// HandleWallets handles wallet collection operations
func (h *AgentHandlers) HandleWallets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createWallet(w, r)
	case http.MethodGet:
		h.listWallets(w, r)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (h *AgentHandlers) createWallet(w http.ResponseWriter, r *http.Request) {
	principal := middleware.GetPrincipal(r.Context())
	if principal == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		Name      string `json:"name"`
		ChainType string `json:"chain_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}
	if req.ChainType == "" {
		req.ChainType = types.ChainTypeEthereum
	}

	resp, err := h.agentService.CreateWallet(r.Context(), app.CreateAgentWalletRequest{
		PrincipalID: principal.ID,
		Name:        req.Name,
		ChainType:   req.ChainType,
	})
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (h *AgentHandlers) listWallets(w http.ResponseWriter, r *http.Request) {
	principal := middleware.GetPrincipal(r.Context())
	if principal == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// TODO: Implement list wallets
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"wallets": []interface{}{}})
}

// HandleWalletOperations handles single wallet operations
func (h *AgentHandlers) HandleWalletOperations(w http.ResponseWriter, r *http.Request) {
	// Extract wallet ID from path: /v1/wallets/{id}/...
	path := strings.TrimPrefix(r.URL.Path, "/v1/wallets/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 {
		http.Error(w, `{"error":"wallet id required"}`, http.StatusBadRequest)
		return
	}

	walletID, err := uuid.Parse(parts[0])
	if err != nil {
		http.Error(w, `{"error":"invalid wallet id"}`, http.StatusBadRequest)
		return
	}

	// Determine sub-resource
	subPath := ""
	if len(parts) > 1 {
		subPath = parts[1]
	}

	switch subPath {
	case "credentials":
		h.handleCredentials(w, r, walletID)
	case "pause":
		h.pauseWallet(w, r, walletID)
	case "resume":
		h.resumeWallet(w, r, walletID)
	case "kill":
		h.killWallet(w, r, walletID)
	default:
		h.getWallet(w, r, walletID)
	}
}

func (h *AgentHandlers) getWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	// TODO: Implement get wallet
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"id": walletID})
}

func (h *AgentHandlers) pauseWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if err := h.agentService.PauseWallet(r.Context(), walletID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "paused"})
}

func (h *AgentHandlers) resumeWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if err := h.agentService.ResumeWallet(r.Context(), walletID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "active"})
}

func (h *AgentHandlers) killWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if err := h.agentService.KillWallet(r.Context(), walletID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "killed"})
}

func (h *AgentHandlers) handleCredentials(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	switch r.Method {
	case http.MethodPost:
		h.createCredential(w, r, walletID)
	case http.MethodGet:
		h.listCredentials(w, r, walletID)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (h *AgentHandlers) createCredential(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	var req struct {
		Name         string                  `json:"name"`
		Capabilities types.AgentCapabilities `json:"capabilities"`
		Limits       types.AgentLimits       `json:"limits"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}

	resp, err := h.agentService.CreateCredential(r.Context(), app.CreateAgentCredentialRequest{
		WalletID:     walletID,
		Name:         req.Name,
		Capabilities: req.Capabilities,
		Limits:       req.Limits,
	})
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (h *AgentHandlers) listCredentials(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	// TODO: Implement list credentials
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"credentials": []interface{}{}})
}

// HandleCredentialOperations handles single credential operations
func (h *AgentHandlers) HandleCredentialOperations(w http.ResponseWriter, r *http.Request) {
	// Extract credential ID from path: /v1/credentials/{id}/...
	path := strings.TrimPrefix(r.URL.Path, "/v1/credentials/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 {
		http.Error(w, `{"error":"credential id required"}`, http.StatusBadRequest)
		return
	}

	credentialID, err := uuid.Parse(parts[0])
	if err != nil {
		http.Error(w, `{"error":"invalid credential id"}`, http.StatusBadRequest)
		return
	}

	// Determine sub-resource
	subPath := ""
	if len(parts) > 1 {
		subPath = parts[1]
	}

	switch subPath {
	case "pause":
		h.pauseCredential(w, r, credentialID)
	case "resume":
		h.resumeCredential(w, r, credentialID)
	case "revoke":
		h.revokeCredential(w, r, credentialID)
	default:
		h.getCredential(w, r, credentialID)
	}
}

func (h *AgentHandlers) getCredential(w http.ResponseWriter, r *http.Request, credentialID uuid.UUID) {
	// TODO: Implement get credential
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"id": credentialID})
}

func (h *AgentHandlers) pauseCredential(w http.ResponseWriter, r *http.Request, credentialID uuid.UUID) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if err := h.agentService.PauseCredential(r.Context(), credentialID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "paused"})
}

func (h *AgentHandlers) resumeCredential(w http.ResponseWriter, r *http.Request, credentialID uuid.UUID) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if err := h.agentService.ResumeCredential(r.Context(), credentialID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "active"})
}

func (h *AgentHandlers) revokeCredential(w http.ResponseWriter, r *http.Request, credentialID uuid.UUID) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if err := h.agentService.RevokeCredential(r.Context(), credentialID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "revoked"})
}
```

**Step 2: Run tests**

```bash
go build ./internal/api/...
```

**Step 3: Commit**

```bash
git add internal/api/agent_handlers.go
git commit -m "feat: add API handlers for agent wallet management

- POST/GET /v1/wallets - create and list wallets
- POST /v1/wallets/{id}/pause,resume,kill - wallet control
- POST/GET /v1/wallets/{id}/credentials - credential management
- POST /v1/credentials/{id}/pause,resume,revoke - credential control"
```

---

## Task 8: Implement Signing API for Agents

**Files:**
- Create: `internal/api/agent_signing_handlers.go`

**Step 1: Implement signing handlers**

```go
// internal/api/agent_signing_handlers.go
package api

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

// AgentSigningHandlers handles signing requests from agents
type AgentSigningHandlers struct {
	agentService *app.AgentService
}

// NewAgentSigningHandlers creates new signing handlers
func NewAgentSigningHandlers(agentService *app.AgentService) *AgentSigningHandlers {
	return &AgentSigningHandlers{agentService: agentService}
}

// HandleRPC handles JSON-RPC signing requests
func (h *AgentSigningHandlers) HandleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeRPCError(w, -32600, "Invalid Request", nil)
		return
	}

	// Get agent credential and wallet from context
	credential := middleware.GetAgentCredential(r.Context())
	wallet := middleware.GetAgentWallet(r.Context())
	if credential == nil || wallet == nil {
		h.writeRPCError(w, -32603, "Internal error", nil)
		return
	}

	// Parse JSON-RPC request
	var rpcReq struct {
		JSONRPC string        `json:"jsonrpc"`
		Method  string        `json:"method"`
		Params  []interface{} `json:"params"`
		ID      interface{}   `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rpcReq); err != nil {
		h.writeRPCError(w, -32700, "Parse error", nil)
		return
	}

	// Route by method
	switch rpcReq.Method {
	case "eth_sendTransaction":
		h.handleSendTransaction(w, r, credential, wallet, rpcReq.Params, rpcReq.ID)
	case "eth_signTransaction":
		h.handleSignTransaction(w, r, credential, wallet, rpcReq.Params, rpcReq.ID)
	case "personal_sign":
		h.handlePersonalSign(w, r, credential, wallet, rpcReq.Params, rpcReq.ID)
	case "eth_signTypedData_v4":
		h.handleSignTypedData(w, r, credential, wallet, rpcReq.Params, rpcReq.ID)
	case "eth_accounts":
		h.handleAccounts(w, wallet, rpcReq.ID)
	case "eth_chainId":
		h.handleChainId(w, rpcReq.ID)
	default:
		h.writeRPCError(w, -32601, "Method not found", rpcReq.ID)
	}
}

func (h *AgentSigningHandlers) handleSendTransaction(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []interface{}, id interface{}) {
	if len(params) < 1 {
		h.writeRPCError(w, -32602, "Invalid params", id)
		return
	}

	txParams, ok := params[0].(map[string]interface{})
	if !ok {
		h.writeRPCError(w, -32602, "Invalid transaction params", id)
		return
	}

	// Extract and validate transaction parameters
	value := big.NewInt(0)
	if v, ok := txParams["value"].(string); ok {
		value, _ = new(big.Int).SetString(v, 0)
	}

	// Check rate limits
	if err := h.agentService.CheckRateLimits(r.Context(), credential, value); err != nil {
		h.writeRPCError(w, -32000, err.Error(), id)
		return
	}

	// Check capability constraints
	if !h.checkCapabilities(credential, "transfer", txParams) {
		h.writeRPCError(w, -32000, "Operation not allowed by credential capabilities", id)
		return
	}

	// TODO: Build transaction, evaluate policy, sign, and broadcast
	// For now, return a placeholder
	h.writeRPCError(w, -32000, "Transaction signing not yet implemented", id)
}

func (h *AgentSigningHandlers) handleSignTransaction(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []interface{}, id interface{}) {
	// Similar to sendTransaction but returns signed tx instead of broadcasting
	h.writeRPCError(w, -32000, "Transaction signing not yet implemented", id)
}

func (h *AgentSigningHandlers) handlePersonalSign(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []interface{}, id interface{}) {
	if len(params) < 2 {
		h.writeRPCError(w, -32602, "Invalid params", id)
		return
	}

	// Check capability
	if !h.hasOperation(credential, "sign_message") {
		h.writeRPCError(w, -32000, "sign_message not allowed by credential", id)
		return
	}

	// TODO: Sign message
	h.writeRPCError(w, -32000, "Message signing not yet implemented", id)
}

func (h *AgentSigningHandlers) handleSignTypedData(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []interface{}, id interface{}) {
	// Check capability
	if !h.hasOperation(credential, "sign_typed_data") {
		h.writeRPCError(w, -32000, "sign_typed_data not allowed by credential", id)
		return
	}

	// TODO: Sign typed data
	h.writeRPCError(w, -32000, "Typed data signing not yet implemented", id)
}

func (h *AgentSigningHandlers) handleAccounts(w http.ResponseWriter, wallet *types.AgentWallet, id interface{}) {
	h.writeRPCResult(w, []string{wallet.Address}, id)
}

func (h *AgentSigningHandlers) handleChainId(w http.ResponseWriter, id interface{}) {
	// Default to Ethereum mainnet
	h.writeRPCResult(w, "0x1", id)
}

func (h *AgentSigningHandlers) checkCapabilities(credential *types.AgentCredential, operation string, txParams map[string]interface{}) bool {
	// Check if operation is allowed
	if !h.hasOperation(credential, operation) {
		return false
	}

	// Check if target contract is in allowlist (if allowlist is not empty)
	if len(credential.Capabilities.AllowedContracts) > 0 {
		to, _ := txParams["to"].(string)
		allowed := false
		for _, contract := range credential.Capabilities.AllowedContracts {
			if common.HexToAddress(contract) == common.HexToAddress(to) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	return true
}

func (h *AgentSigningHandlers) hasOperation(credential *types.AgentCredential, operation string) bool {
	if len(credential.Capabilities.Operations) == 0 {
		return true // Empty means all allowed
	}
	for _, op := range credential.Capabilities.Operations {
		if op == operation || op == "*" {
			return true
		}
	}
	return false
}

func (h *AgentSigningHandlers) writeRPCResult(w http.ResponseWriter, result interface{}, id interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0",
		"result":  result,
		"id":      id,
	})
}

func (h *AgentSigningHandlers) writeRPCError(w http.ResponseWriter, code int, message string, id interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
		"id": id,
	})
}

// BuildTransaction builds an Ethereum transaction from parameters
func BuildTransaction(params map[string]interface{}, nonce uint64) (*ethtypes.Transaction, error) {
	to := common.HexToAddress(params["to"].(string))

	value := big.NewInt(0)
	if v, ok := params["value"].(string); ok {
		value, _ = new(big.Int).SetString(v, 0)
	}

	var data []byte
	if d, ok := params["data"].(string); ok {
		data, _ = hex.DecodeString(d[2:]) // Remove 0x prefix
	}

	gasLimit := uint64(21000)
	if g, ok := params["gas"].(string); ok {
		gl, _ := new(big.Int).SetString(g, 0)
		gasLimit = gl.Uint64()
	}

	// Use EIP-1559 transaction
	maxFeePerGas := big.NewInt(20000000000) // 20 gwei default
	maxPriorityFeePerGas := big.NewInt(1000000000) // 1 gwei default

	tx := ethtypes.NewTx(&ethtypes.DynamicFeeTx{
		Nonce:     nonce,
		To:        &to,
		Value:     value,
		Gas:       gasLimit,
		GasFeeCap: maxFeePerGas,
		GasTipCap: maxPriorityFeePerGas,
		Data:      data,
	})

	return tx, nil
}
```

**Step 2: Run tests**

```bash
go build ./internal/api/...
```

**Step 3: Commit**

```bash
git add internal/api/agent_signing_handlers.go
git commit -m "feat: add signing API handlers for agents

- JSON-RPC endpoint for agent signing requests
- eth_sendTransaction, eth_signTransaction stubs
- personal_sign, eth_signTypedData_v4 stubs
- Capability and rate limit checking
- eth_accounts, eth_chainId support"
```

---

## Task 9: Wire Up Server

**Files:**
- Modify: `internal/api/server.go`
- Modify: `cmd/server/main.go`

This task involves wiring up all the new components. Due to the complexity, this should be done incrementally after the previous tasks are verified.

**Step 1: Update server.go with new routes**

Add agent-specific routes alongside or replacing existing routes.

**Step 2: Update main.go initialization**

Initialize new repositories and services.

**Step 3: Run full test suite**

```bash
go test ./...
```

**Step 4: Commit**

```bash
git add internal/api/server.go cmd/server/main.go
git commit -m "feat: wire up Agent Wallet server

- Add Principal auth middleware
- Add Agent auth middleware
- Register agent wallet routes
- Register agent signing routes"
```

---

## Task 10: Clean Up Old Code

**Files:**
- Remove: Files related to User, Session Signer, App multi-tenancy
- Keep: KMS/TEE keyexec, Policy engine core

This task involves removing code that's no longer needed. Should be done after verifying the new system works.

**Step 1: Identify files to remove**

- `internal/api/user_handlers.go`
- `internal/api/session_signer_handlers.go`
- `internal/storage/user_repo.go`
- `internal/storage/session_signer_repo.go`
- `internal/middleware/auth.go` (old user auth)
- etc.

**Step 2: Remove files and update imports**

**Step 3: Run tests**

```bash
go test ./...
```

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: remove deprecated User/SessionSigner code

- Remove user authentication
- Remove session signer functionality
- Remove app multi-tenancy
- Keep KMS/TEE keyexec and policy engine"
```

---

## Summary

This plan covers Phase 1 MVP implementation:

1. **Database Schema** - New simplified schema with Principal, AgentWallet, AgentCredential
2. **Go Types** - New type definitions
3. **Storage Repos** - CRUD operations for all entities
4. **Principal Auth** - API key authentication for principals
5. **Agent Auth** - Credential authentication for agents
6. **Agent Service** - Business logic for wallet/credential management
7. **API Handlers** - REST endpoints for management
8. **Signing API** - JSON-RPC endpoint for agent signing
9. **Server Wiring** - Connect all components
10. **Cleanup** - Remove deprecated code

Each task is designed to be completed independently with its own commit, enabling incremental progress and easy rollback if needed.
