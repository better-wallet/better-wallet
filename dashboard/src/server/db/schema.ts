import { bigint, boolean, integer, jsonb, pgTable, primaryKey, serial, text, timestamp, unique, uuid } from 'drizzle-orm/pg-core'

// ==================== Better Auth Tables ====================

export const user = pgTable('user', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  email: text('email').notNull().unique(),
  emailVerified: boolean('email_verified').notNull().default(false),
  image: text('image'),
  role: text('role').notNull().default('user'), // 'user' | 'provider'
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
})

export const session = pgTable('session', {
  id: text('id').primaryKey(),
  expiresAt: timestamp('expires_at').notNull(),
  token: text('token').notNull().unique(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  userId: text('user_id')
    .notNull()
    .references(() => user.id, { onDelete: 'cascade' }),
})

export const account = pgTable('account', {
  id: text('id').primaryKey(),
  accountId: text('account_id').notNull(),
  providerId: text('provider_id').notNull(),
  userId: text('user_id')
    .notNull()
    .references(() => user.id, { onDelete: 'cascade' }),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  idToken: text('id_token'),
  accessTokenExpiresAt: timestamp('access_token_expires_at'),
  refreshTokenExpiresAt: timestamp('refresh_token_expires_at'),
  scope: text('scope'),
  password: text('password'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
})

export const verification = pgTable('verification', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  value: text('value').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
})

// ==================== Dashboard Tables ====================

// Wallet users - bridge between dashboard users and wallet system
export const walletUsers = pgTable('wallet_users', {
  id: uuid('id').primaryKey().defaultRandom(),
  dashboardUserId: text('dashboard_user_id')
    .notNull()
    .unique()
    .references(() => user.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// Apps - multi-tenant application management
export const apps = pgTable('apps', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description'),
  ownerId: uuid('owner_id')
    .notNull()
    .references(() => walletUsers.id, { onDelete: 'restrict' }),
  status: text('status').notNull().default('active'), // 'active' | 'suspended' | 'deleted'
  settings: jsonb('settings').notNull().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

// App secrets - API key management
export const appSecrets = pgTable('app_secrets', {
  id: uuid('id').primaryKey().defaultRandom(),
  appId: uuid('app_id')
    .notNull()
    .references(() => apps.id, { onDelete: 'cascade' }),
  secretHash: text('secret_hash').notNull(),
  secretPrefix: text('secret_prefix').notNull(), // e.g., "bw_sk_abc..."
  status: text('status').notNull().default('active'), // 'active' | 'rotated' | 'revoked'
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  rotatedAt: timestamp('rotated_at', { withTimezone: true }),
  expiresAt: timestamp('expires_at', { withTimezone: true }),
})

// App members - team management
export const appMembers = pgTable(
  'app_members',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    appId: uuid('app_id')
      .notNull()
      .references(() => apps.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => walletUsers.id, { onDelete: 'cascade' }),
    role: text('role').notNull().default('developer'), // 'admin' | 'developer' | 'viewer'
    invitedBy: uuid('invited_by').references(() => walletUsers.id),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [unique().on(table.appId, table.userId)]
)

// Type exports
export type User = typeof user.$inferSelect
export type WalletUser = typeof walletUsers.$inferSelect
export type App = typeof apps.$inferSelect
export type AppSecret = typeof appSecrets.$inferSelect
export type AppMember = typeof appMembers.$inferSelect

// App settings type
export interface AppSettings {
  auth?: {
    kind: 'oidc' | 'jwt'
    issuer: string
    audience: string
    jwks_uri: string
  }
  rpc?: {
    endpoints: Record<string, string>
  }
  rate_limit?: {
    qps: number
  }
}

// ==================== Wallet Backend Tables ====================
// These tables are shared with the Go backend

// External users (from JWT sub claim, not dashboard users)
export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  externalSub: text('external_sub').notNull(),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// Authorization keys for signing requests
export const authorizationKeys = pgTable('authorization_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  publicKey: text('public_key').notNull(), // hex encoded
  algorithm: text('algorithm').notNull().default('p256'),
  ownerEntity: text('owner_entity').notNull(),
  status: text('status').notNull().default('active'), // active, rotated, revoked
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  rotatedAt: timestamp('rotated_at', { withTimezone: true }),
})

// Key quorums for M-of-N threshold signatures
export const keyQuorums = pgTable('key_quorums', {
  id: uuid('id').primaryKey().defaultRandom(),
  threshold: integer('threshold').notNull(),
  keyIds: jsonb('key_ids').notNull().$type<string[]>(),
  status: text('status').notNull().default('active'), // active, inactive
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// Wallets
export const wallets = pgTable('wallets', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  chainType: text('chain_type').notNull().default('ethereum'),
  ownerId: uuid('owner_id').notNull(), // references authorization_keys or key_quorums
  execBackend: text('exec_backend').notNull().default('kms'), // kms, tee
  address: text('address').notNull(),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// Wallet shares (encrypted key material)
export const walletShares = pgTable(
  'wallet_shares',
  {
    walletId: uuid('wallet_id')
      .notNull()
      .references(() => wallets.id, { onDelete: 'cascade' }),
    shareType: text('share_type').notNull(), // auth_share, exec_share, enclave_share
    blobEncrypted: text('blob_encrypted').notNull(), // base64 encoded
    kmsKeyId: text('kms_key_id'),
    threshold: integer('threshold').default(2),
    totalShares: integer('total_shares').default(3),
  },
  (table) => [primaryKey({ columns: [table.walletId, table.shareType] })]
)

// Policies
export const policies = pgTable('policies', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  chainType: text('chain_type').notNull().default('ethereum'),
  version: text('version').notNull().default('1.0'),
  rules: jsonb('rules').notNull().$type<PolicyRules>(),
  ownerId: uuid('owner_id').notNull(), // references authorization_keys
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// Policy rules type
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

// Wallet-Policy junction table
export const walletPolicies = pgTable(
  'wallet_policies',
  {
    walletId: uuid('wallet_id')
      .notNull()
      .references(() => wallets.id, { onDelete: 'cascade' }),
    policyId: uuid('policy_id')
      .notNull()
      .references(() => policies.id, { onDelete: 'cascade' }),
  },
  (table) => [primaryKey({ columns: [table.walletId, table.policyId] })]
)

// Session signers (temporary delegated signing)
export const sessionSigners = pgTable('session_signers', {
  id: uuid('id').primaryKey().defaultRandom(),
  walletId: uuid('wallet_id')
    .notNull()
    .references(() => wallets.id, { onDelete: 'cascade' }),
  signerId: text('signer_id').notNull(), // references authorization_keys.id as string
  policyOverrideId: uuid('policy_override_id').references(() => policies.id),
  allowedMethods: jsonb('allowed_methods').$type<string[]>(),
  maxValue: text('max_value'), // numeric string (wei)
  maxTxs: integer('max_txs'),
  ttlExpiresAt: timestamp('ttl_expires_at', { withTimezone: true }).notNull(),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
})

// Condition sets (reusable value sets for policies)
export const conditionSets = pgTable('condition_sets', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description'),
  values: jsonb('values').notNull().$type<unknown[]>(),
  ownerId: uuid('owner_id').notNull(),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

// Audit logs
export const auditLogs = pgTable('audit_logs', {
  id: serial('id').primaryKey(),
  actor: text('actor').notNull(),
  action: text('action').notNull(),
  resourceType: text('resource_type').notNull(),
  resourceId: text('resource_id').notNull(),
  policyResult: text('policy_result'),
  signerId: text('signer_id'),
  txHash: text('tx_hash'),
  requestDigest: text('request_digest'),
  clientIp: text('client_ip'),
  userAgent: text('user_agent'),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'set null' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// Idempotency keys
export const idempotencyKeys = pgTable('idempotency_keys', {
  key: text('key').primaryKey(),
  resourceType: text('resource_type').notNull(),
  resourceId: uuid('resource_id'),
  status: text('status').notNull().default('pending'), // pending, completed, failed
  responseCode: integer('response_code'),
  responseBody: jsonb('response_body'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  completedAt: timestamp('completed_at', { withTimezone: true }),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
})

// Additional type exports
export type ExternalUser = typeof users.$inferSelect
export type Wallet = typeof wallets.$inferSelect
export type AuthorizationKey = typeof authorizationKeys.$inferSelect
export type KeyQuorum = typeof keyQuorums.$inferSelect
export type Policy = typeof policies.$inferSelect
export type SessionSigner = typeof sessionSigners.$inferSelect
export type ConditionSet = typeof conditionSets.$inferSelect
export type AuditLog = typeof auditLogs.$inferSelect
