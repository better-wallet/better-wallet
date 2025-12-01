import {
  bigint,
  bigserial,
  boolean,
  customType,
  inet,
  integer,
  jsonb,
  numeric,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core'

// Custom type for bytea
const bytea = customType<{ data: Buffer }>({
  dataType() {
    return 'bytea'
  },
})

// Custom type for uuid array
const uuidArray = customType<{ data: string[] }>({
  dataType() {
    return 'uuid[]'
  },
})

// Custom type for text array
const textArray = customType<{ data: string[] }>({
  dataType() {
    return 'text[]'
  },
})

// ==================== Better Auth Tables ====================

export const user = pgTable('user', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  email: text('email').notNull().unique(),
  emailVerified: boolean('email_verified').notNull().default(false),
  image: text('image'),
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

// ==================== Better Wallet Tables ====================

export const walletUsers = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  externalSub: text('external_sub').notNull().unique(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

export const apps = pgTable('apps', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description'),
  ownerUserId: uuid('owner_user_id')
    .notNull()
    .references(() => walletUsers.id, { onDelete: 'restrict' }),
  status: text('status').notNull().default('active'),
  settings: jsonb('settings').notNull().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

export const appSecrets = pgTable('app_secrets', {
  id: uuid('id').primaryKey().defaultRandom(),
  appId: uuid('app_id')
    .notNull()
    .references(() => apps.id, { onDelete: 'cascade' }),
  secretHash: text('secret_hash').notNull(),
  secretPrefix: text('secret_prefix').notNull(),
  status: text('status').notNull().default('active'),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  rotatedAt: timestamp('rotated_at', { withTimezone: true }),
  expiresAt: timestamp('expires_at', { withTimezone: true }),
})

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
    role: text('role').notNull().default('developer'),
    invitedBy: uuid('invited_by').references(() => walletUsers.id),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [unique().on(table.appId, table.userId)]
)

export const authorizationKeys = pgTable('authorization_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  publicKey: bytea('public_key').notNull(),
  algorithm: text('algorithm').notNull(),
  ownerEntity: text('owner_entity').notNull(),
  status: text('status').notNull().default('active'),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  rotatedAt: timestamp('rotated_at', { withTimezone: true }),
})

export const keyQuorums = pgTable('key_quorums', {
  id: uuid('id').primaryKey().defaultRandom(),
  threshold: integer('threshold').notNull(),
  keyIds: uuidArray('key_ids').notNull(),
  status: text('status').notNull().default('active'),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

export const wallets = pgTable('wallets', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => walletUsers.id, { onDelete: 'cascade' }),
  chainType: text('chain_type').notNull().default('ethereum'),
  ownerId: uuid('owner_id')
    .notNull()
    .references(() => authorizationKeys.id, { onDelete: 'restrict' }),
  execBackend: text('exec_backend').notNull().default('kms'),
  address: text('address').notNull(),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

export const walletShares = pgTable(
  'wallet_shares',
  {
    walletId: uuid('wallet_id')
      .notNull()
      .references(() => wallets.id, { onDelete: 'cascade' }),
    shareType: text('share_type').notNull(), // 'auth' or 'exec'
    blobEncrypted: bytea('blob_encrypted').notNull(),
    kmsKeyId: text('kms_key_id'),
    threshold: integer('threshold').notNull().default(2), // SSS threshold (2-of-2)
    totalShares: integer('total_shares').notNull().default(2), // SSS total shares (2-of-2)
  },
  (table) => [primaryKey({ columns: [table.walletId, table.shareType] })]
)

export const policies = pgTable('policies', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  chainType: text('chain_type').notNull(),
  version: text('version').notNull().default('1.0'),
  rules: jsonb('rules').notNull(),
  ownerId: uuid('owner_id').notNull(),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

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

export const sessionSigners = pgTable(
  'session_signers',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    walletId: uuid('wallet_id')
      .notNull()
      .references(() => wallets.id, { onDelete: 'cascade' }),
    signerId: text('signer_id').notNull(),
    policyOverrideId: uuid('policy_override_id').references(() => policies.id),
    allowedMethods: textArray('allowed_methods'),
    maxValue: numeric('max_value'),
    maxTxs: integer('max_txs'),
    ttlExpiresAt: timestamp('ttl_expires_at', { withTimezone: true }).notNull(),
    appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (table) => [unique().on(table.walletId, table.signerId)]
)

export const auditLogs = pgTable('audit_logs', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  actor: text('actor').notNull(),
  action: text('action').notNull(),
  resourceType: text('resource_type').notNull(),
  resourceId: text('resource_id').notNull(),
  policyResult: text('policy_result'),
  signerId: text('signer_id'),
  txHash: text('tx_hash'),
  requestDigest: text('request_digest'),
  clientIp: inet('client_ip'),
  userAgent: text('user_agent'),
  appId: uuid('app_id'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// Note: recoveryShareInfo table removed - using 2-of-2 scheme without recovery share
// Recovery share support will be added with on-device mode (2-of-3 scheme)

export const transactions = pgTable('transactions', {
  id: uuid('id').primaryKey().defaultRandom(),
  walletId: uuid('wallet_id')
    .notNull()
    .references(() => wallets.id, { onDelete: 'cascade' }),
  chainId: bigint('chain_id', { mode: 'number' }).notNull(),
  txHash: text('tx_hash'),
  status: text('status').notNull().default('pending'),
  method: text('method').notNull(),
  toAddress: text('to_address'),
  value: text('value'),
  data: text('data'),
  nonce: bigint('nonce', { mode: 'number' }),
  gasLimit: bigint('gas_limit', { mode: 'number' }),
  maxFeePerGas: text('max_fee_per_gas'),
  maxPriorityFeePerGas: text('max_priority_fee_per_gas'),
  signedTx: bytea('signed_tx'),
  errorMessage: text('error_message'),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

export const idempotencyRecords = pgTable(
  'idempotency_records',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    appId: varchar('app_id', { length: 256 }).notNull(),
    key: varchar('key', { length: 256 }).notNull(),
    method: varchar('method', { length: 10 }).notNull(),
    url: varchar('url', { length: 2048 }).notNull(),
    bodyHash: varchar('body_hash', { length: 64 }).notNull(),
    statusCode: integer('status_code').notNull(),
    headers: jsonb('headers').notNull().default({}),
    body: bytea('body').notNull(),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    expiresAt: timestamp('expires_at').notNull(),
  },
  (table) => [unique().on(table.appId, table.key, table.method, table.url)]
)

export const conditionSets = pgTable('condition_sets', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description'),
  values: jsonb('values').notNull().default([]),
  ownerId: uuid('owner_id')
    .notNull()
    .references(() => authorizationKeys.id, { onDelete: 'restrict' }),
  appId: uuid('app_id').references(() => apps.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})
