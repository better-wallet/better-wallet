import { bigint, boolean, index, integer, jsonb, pgTable, primaryKey, serial, text, timestamp, unique, uuid } from 'drizzle-orm/pg-core'

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
  keyHash: text('key_hash').notNull(),
  keyPrefix: text('key_prefix').notNull(),
  name: text('name').notNull(),
  status: text('status').notNull().default('active'),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
}, (table) => [
  index('principal_api_keys_principal_id_idx').on(table.principalId),
])

// ==================== Agent Wallet Tables ====================

export const agentWallets = pgTable('agent_wallets', {
  id: uuid('id').primaryKey().defaultRandom(),
  principalId: uuid('principal_id')
    .notNull()
    .references(() => principals.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  chainType: text('chain_type').notNull().default('ethereum'),
  address: text('address').notNull(),
  execBackend: text('exec_backend').notNull().default('kms'),
  status: text('status').notNull().default('active'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  unique().on(table.address, table.chainType),
  index('agent_wallets_principal_id_idx').on(table.principalId),
])

export const walletKeys = pgTable('wallet_keys', {
  walletId: uuid('wallet_id')
    .primaryKey()
    .references(() => agentWallets.id, { onDelete: 'cascade' }),
  encryptedKey: text('encrypted_key').notNull(),
  kmsKeyId: text('kms_key_id').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// ==================== Agent Credential Tables ====================

export const agentCredentials = pgTable('agent_credentials', {
  id: uuid('id').primaryKey().defaultRandom(),
  walletId: uuid('wallet_id')
    .notNull()
    .references(() => agentWallets.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  keyHash: text('key_hash').notNull(),
  keyPrefix: text('key_prefix').notNull(),
  capabilities: jsonb('capabilities').notNull().$type<AgentCapabilities>(),
  limits: jsonb('limits').notNull().$type<AgentLimits>(),
  status: text('status').notNull().default('active'),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  pausedAt: timestamp('paused_at', { withTimezone: true }),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
}, (table) => [
  index('agent_credentials_wallet_id_idx').on(table.walletId),
])

export interface AgentCapabilities {
  chains: string[]
  operations: string[]
  allowedContracts: string[]
  allowedMethods: string[]
}

export interface AgentLimits {
  maxValuePerTx: string
  maxValuePerHour: string
  maxValuePerDay: string
  maxTxPerHour: number
  maxTxPerDay: number
}

// ==================== Policy Tables ====================

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
}, (table) => [
  index('agent_policies_wallet_id_idx').on(table.walletId),
])

export interface PolicyRule {
  name: string
  method: string
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

export const agentRateLimits = pgTable('agent_rate_limits', {
  credentialId: uuid('credential_id')
    .notNull()
    .references(() => agentCredentials.id, { onDelete: 'cascade' }),
  windowType: text('window_type').notNull(),
  windowStart: timestamp('window_start', { withTimezone: true }).notNull(),
  txCount: integer('tx_count').notNull().default(0),
  totalValue: text('total_value').notNull().default('0'),
}, (table) => [
  primaryKey({ columns: [table.credentialId, table.windowType, table.windowStart] })
])

// ==================== Audit Tables ====================

export const agentAuditLogs = pgTable('agent_audit_logs', {
  id: serial('id').primaryKey(),
  credentialId: uuid('credential_id').references(() => agentCredentials.id, { onDelete: 'set null' }),
  walletId: uuid('wallet_id').references(() => agentWallets.id, { onDelete: 'set null' }),
  principalId: uuid('principal_id').references(() => principals.id, { onDelete: 'set null' }),
  action: text('action').notNull(),
  resourceType: text('resource_type').notNull(),
  resourceId: text('resource_id').notNull(),
  policyResult: text('policy_result'),
  txHash: text('tx_hash'),
  errorMessage: text('error_message'),
  metadata: jsonb('metadata').$type<Record<string, unknown>>(),
  clientIp: text('client_ip'),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// ==================== Transaction Tables ====================

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
  status: text('status').notNull().default('pending'),
  method: text('method').notNull(),
  toAddress: text('to_address'),
  value: text('value'),
  data: text('data'),
  signedTx: text('signed_tx'),
  errorMessage: text('error_message'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index('agent_transactions_wallet_id_idx').on(table.walletId),
  index('agent_transactions_credential_id_idx').on(table.credentialId),
])

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
