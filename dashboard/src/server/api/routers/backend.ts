import { and, desc, eq, sql } from 'drizzle-orm'
import { z } from 'zod'
import { db } from '@/server/db'
import * as schema from '@/server/db/schema'
import { createTRPCRouter, protectedProcedure } from '../trpc'
import { createAppWallet } from '@/lib/wallet-api'

// Policy evaluation helper types
interface TestContext {
  method: string
  chainType?: string
  to?: string
  value?: string
  data?: string
  chainId?: number
  decodedCalldata?: Record<string, unknown>
  typedDataDomain?: Record<string, unknown>
  typedDataMessage?: Record<string, unknown>
  personalMessage?: string
}

// Helper to get field value from test context
function getFieldValue(fieldSource: string, field: string, ctx: TestContext): unknown {
  switch (fieldSource) {
    case 'ethereum_transaction':
      switch (field) {
        case 'to':
          return ctx.to?.toLowerCase()
        case 'value':
          return ctx.value
        case 'data':
          return ctx.data
        case 'chain_id':
          return ctx.chainId
        case 'from':
          return undefined // Not available in test context
        default:
          return undefined
      }
    case 'ethereum_calldata':
      return ctx.decodedCalldata?.[field]
    case 'ethereum_typed_data_domain':
      return ctx.typedDataDomain?.[field]
    case 'ethereum_typed_data_message':
      return ctx.typedDataMessage?.[field]
    case 'ethereum_message':
      if (field === 'content') return ctx.personalMessage
      return undefined
    case 'system':
      if (field === 'current_unix_timestamp') return Math.floor(Date.now() / 1000)
      return undefined
    default:
      return undefined
  }
}

// Helper to evaluate a condition
function evaluateCondition(operator: string, actual: unknown, expected: unknown): { matched: boolean } {
  // Handle null/undefined
  if (actual === undefined || actual === null) {
    if (operator === 'eq') return { matched: expected === null || expected === undefined }
    if (operator === 'neq') return { matched: expected !== null && expected !== undefined }
    return { matched: false }
  }

  switch (operator) {
    case 'eq':
      // Case-insensitive comparison for addresses
      if (typeof actual === 'string' && typeof expected === 'string') {
        return { matched: actual.toLowerCase() === expected.toLowerCase() }
      }
      return { matched: actual === expected }

    case 'neq':
      if (typeof actual === 'string' && typeof expected === 'string') {
        return { matched: actual.toLowerCase() !== expected.toLowerCase() }
      }
      return { matched: actual !== expected }

    case 'lt':
      return { matched: compareBigInt(actual, expected) < 0 }

    case 'lte':
      return { matched: compareBigInt(actual, expected) <= 0 }

    case 'gt':
      return { matched: compareBigInt(actual, expected) > 0 }

    case 'gte':
      return { matched: compareBigInt(actual, expected) >= 0 }

    case 'in':
      if (!Array.isArray(expected)) return { matched: false }
      const actualLower = typeof actual === 'string' ? actual.toLowerCase() : actual
      return {
        matched: expected.some((v) => {
          const vLower = typeof v === 'string' ? v.toLowerCase() : v
          return actualLower === vLower
        }),
      }

    case 'in_condition_set':
      // For simplicity, treat expected as the condition set values array
      if (!Array.isArray(expected)) return { matched: false }
      const actualLower2 = typeof actual === 'string' ? actual.toLowerCase() : actual
      return {
        matched: expected.some((v) => {
          const vLower = typeof v === 'string' ? v.toLowerCase() : v
          return actualLower2 === vLower
        }),
      }

    default:
      return { matched: false }
  }
}

// Helper to compare values as BigInt (for wei values)
function compareBigInt(a: unknown, b: unknown): number {
  try {
    const aBig = BigInt(String(a))
    const bBig = BigInt(String(b))
    if (aBig < bBig) return -1
    if (aBig > bBig) return 1
    return 0
  } catch {
    // Fall back to number comparison
    const aNum = Number(a)
    const bNum = Number(b)
    return aNum - bNum
  }
}

// Generate a random secret
function generateSecret(): { secret: string; prefix: string } {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let randomPart = ''
  for (let i = 0; i < 32; i++) {
    randomPart += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  const secret = `bw_sk_${randomPart}`
  const prefix = `${secret.substring(0, 10)}...`
  return { secret, prefix }
}

// Hash a secret for storage
async function hashSecret(secret: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(secret)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Create a temporary secret for internal API calls, execute the callback, then revoke it.
 * This ensures we can call the wallet backend API without storing plain secrets.
 */
async function withTemporarySecret<T>(appId: string, callback: (secret: string) => Promise<T>): Promise<T> {
  const { secret, prefix } = generateSecret()
  const secretHash = await hashSecret(secret)

  // Create temporary secret
  const [tempSecret] = await db
    .insert(schema.appSecrets)
    .values({
      appId,
      secretHash,
      secretPrefix: `[internal] ${prefix}`,
      status: 'active',
    })
    .returning()

  try {
    // Execute the callback with the plain secret
    const result = await callback(secret)
    return result
  } finally {
    // Always revoke the temporary secret after use
    await db.update(schema.appSecrets).set({ status: 'revoked' }).where(eq(schema.appSecrets.id, tempSecret.id))
  }
}

// Helper to check if user has access to an app
async function checkAppAccess(userId: string, appId: string) {
  // Find the wallet user for this dashboard user
  const walletUser = await db.query.walletUsers.findFirst({
    where: eq(schema.walletUsers.dashboardUserId, userId),
  })

  if (!walletUser) {
    throw new Error('User not found')
  }

  // Check if user owns the app or is a member
  const app = await db.query.apps.findFirst({
    where: eq(schema.apps.id, appId),
  })

  if (!app) {
    throw new Error('App not found')
  }

  if (app.ownerId === walletUser.id) {
    return { app, walletUser, role: 'owner' as const }
  }

  const membership = await db.query.appMembers.findFirst({
    where: and(eq(schema.appMembers.appId, appId), eq(schema.appMembers.userId, walletUser.id)),
  })

  if (!membership) {
    throw new Error('Access denied')
  }

  return { app, walletUser, role: membership.role as 'admin' | 'developer' | 'viewer' }
}

export const backendRouter = createTRPCRouter({
  // Health check - just check database connection
  health: protectedProcedure.query(async () => {
    try {
      await db.execute(sql`SELECT 1`)
      return { status: 'ok', api: true, database: true, execution_backend: true }
    } catch {
      return { status: 'down', api: true, database: false, execution_backend: false }
    }
  }),

  // Stats for an app
  stats: protectedProcedure.input(z.object({ appId: z.string() })).query(async ({ ctx, input }) => {
    await checkAppAccess(ctx.session.user.id, input.appId)

    const [walletsCount, policiesCount, usersCount, transactionsCount] = await Promise.all([
      db.select({ count: sql<number>`count(*)` }).from(schema.wallets).where(eq(schema.wallets.appId, input.appId)),
      db.select({ count: sql<number>`count(*)` }).from(schema.policies).where(eq(schema.policies.appId, input.appId)),
      db.select({ count: sql<number>`count(*)` }).from(schema.users).where(eq(schema.users.appId, input.appId)),
      db.select({ count: sql<number>`count(*)` }).from(schema.transactions).where(eq(schema.transactions.appId, input.appId)),
    ])

    return {
      wallets_count: Number(walletsCount[0]?.count ?? 0),
      policies_count: Number(policiesCount[0]?.count ?? 0),
      users_count: Number(usersCount[0]?.count ?? 0),
      transactions_count: Number(transactionsCount[0]?.count ?? 0),
    }
  }),

  // Analytics - detailed stats with time series
  analytics: protectedProcedure
    .input(z.object({ appId: z.string(), days: z.number().optional().default(30) }))
    .query(async ({ ctx, input }) => {
      await checkAppAccess(ctx.session.user.id, input.appId)

      const startDate = new Date()
      startDate.setDate(startDate.getDate() - input.days)

      // Get daily user registrations
      const dailyUsers = await db.execute(sql`
        SELECT DATE(created_at) as date, COUNT(*) as count
        FROM users
        WHERE app_id = ${input.appId}::uuid AND created_at >= ${startDate.toISOString()}
        GROUP BY DATE(created_at)
        ORDER BY date ASC
      `)

      // Get daily wallet creations
      const dailyWallets = await db.execute(sql`
        SELECT DATE(created_at) as date, COUNT(*) as count
        FROM wallets
        WHERE app_id = ${input.appId}::uuid AND created_at >= ${startDate.toISOString()}
        GROUP BY DATE(created_at)
        ORDER BY date ASC
      `)

      // Get daily transactions
      const dailyTransactions = await db.execute(sql`
        SELECT DATE(created_at) as date, COUNT(*) as count, status
        FROM transactions
        WHERE app_id = ${input.appId}::uuid AND created_at >= ${startDate.toISOString()}
        GROUP BY DATE(created_at), status
        ORDER BY date ASC
      `)

      // Get transaction volume (sum of values)
      const dailyVolume = await db.execute(sql`
        SELECT DATE(created_at) as date, SUM(CAST(NULLIF(value, '') AS NUMERIC)) as volume
        FROM transactions
        WHERE app_id = ${input.appId}::uuid AND created_at >= ${startDate.toISOString()} AND status = 'confirmed'
        GROUP BY DATE(created_at)
        ORDER BY date ASC
      `)

      // Get wallet distribution by chain type
      const walletsByChain = await db.execute(sql`
        SELECT chain_type, COUNT(*) as count
        FROM wallets
        WHERE app_id = ${input.appId}::uuid
        GROUP BY chain_type
      `)

      // Get transaction status distribution
      const transactionsByStatus = await db.execute(sql`
        SELECT status, COUNT(*) as count
        FROM transactions
        WHERE app_id = ${input.appId}::uuid
        GROUP BY status
      `)

      // Get policy decisions from audit logs
      const policyDecisions = await db.execute(sql`
        SELECT policy_result, COUNT(*) as count
        FROM audit_logs
        WHERE app_id = ${input.appId}::uuid AND policy_result IS NOT NULL AND created_at >= ${startDate.toISOString()}
        GROUP BY policy_result
      `)

      return {
        dailyUsers: (dailyUsers as unknown as { date: string; count: string }[]).map((r) => ({
          date: r.date,
          count: Number(r.count),
        })),
        dailyWallets: (dailyWallets as unknown as { date: string; count: string }[]).map((r) => ({
          date: r.date,
          count: Number(r.count),
        })),
        dailyTransactions: (dailyTransactions as unknown as { date: string; count: string; status: string }[]).map((r) => ({
          date: r.date,
          count: Number(r.count),
          status: r.status,
        })),
        dailyVolume: (dailyVolume as unknown as { date: string; volume: string }[]).map((r) => ({
          date: r.date,
          volume: r.volume ? Number(r.volume) : 0,
        })),
        walletsByChain: (walletsByChain as unknown as { chain_type: string; count: string }[]).map((r) => ({
          chainType: r.chain_type,
          count: Number(r.count),
        })),
        transactionsByStatus: (transactionsByStatus as unknown as { status: string; count: string }[]).map((r) => ({
          status: r.status,
          count: Number(r.count),
        })),
        policyDecisions: (policyDecisions as unknown as { policy_result: string; count: string }[]).map((r) => ({
          result: r.policy_result,
          count: Number(r.count),
        })),
      }
    }),

  // ==================== Wallets ====================
  wallets: createTRPCRouter({
    list: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          limit: z.number().min(1).max(100).optional().default(50),
          chainType: z.string().optional(),
        })
      )
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const conditions = [eq(schema.wallets.appId, input.appId)]
        if (input.chainType) {
          conditions.push(eq(schema.wallets.chainType, input.chainType))
        }

        const walletList = await db.query.wallets.findMany({
          where: and(...conditions),
          orderBy: desc(schema.wallets.createdAt),
          limit: input.limit,
        })

        // Get policy IDs for each wallet
        const walletsWithPolicies = await Promise.all(
          walletList.map(async (wallet) => {
            const walletPolicies = await db.query.walletPolicies.findMany({
              where: eq(schema.walletPolicies.walletId, wallet.id),
            })
            return {
              ...wallet,
              policy_ids: walletPolicies.map((wp) => wp.policyId),
              created_at: wallet.createdAt.getTime(),
            }
          })
        )

        return { data: walletsWithPolicies }
      }),

    get: protectedProcedure
      .input(z.object({ appId: z.string(), id: z.string() }))
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const wallet = await db.query.wallets.findFirst({
          where: and(eq(schema.wallets.id, input.id), eq(schema.wallets.appId, input.appId)),
        })

        if (!wallet) {
          throw new Error('Wallet not found')
        }

        const walletPolicies = await db.query.walletPolicies.findMany({
          where: eq(schema.walletPolicies.walletId, wallet.id),
        })

        return {
          ...wallet,
          policy_ids: walletPolicies.map((wp) => wp.policyId),
          created_at: wallet.createdAt.getTime(),
        }
      }),

    delete: protectedProcedure
      .input(z.object({ appId: z.string(), id: z.string() }))
      .mutation(async ({ ctx, input }) => {
        const { role } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        await db.delete(schema.wallets).where(and(eq(schema.wallets.id, input.id), eq(schema.wallets.appId, input.appId)))

        return { success: true }
      }),

    /**
     * Create an App-Managed Wallet (Server Wallet)
     *
     * Creates a wallet without an owner, controlled entirely by the app via API secret.
     * Use cases:
     * - AI Agents
     * - Automated trading bots
     * - Gas station wallets
     * - Server-side operations
     *
     * No authorization signature is required for operations on these wallets.
     */
    create: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          chainType: z.enum(['ethereum', 'solana']).default('ethereum'),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const { role } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        // Create a temporary secret, call the wallet API, then revoke the secret
        const wallet = await withTemporarySecret(input.appId, async (secret) => {
          return createAppWallet(input.appId, secret, input.chainType)
        })

        return {
          id: wallet.id,
          address: wallet.address,
          chainType: wallet.chain_type,
          createdAt: wallet.created_at,
        }
      }),

    updatePolicies: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          walletId: z.string(),
          policyIds: z.array(z.string()),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const { role } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        // Verify wallet belongs to this app
        const wallet = await db.query.wallets.findFirst({
          where: and(eq(schema.wallets.id, input.walletId), eq(schema.wallets.appId, input.appId)),
        })

        if (!wallet) {
          throw new Error('Wallet not found')
        }

        // Verify all policies belong to this app
        if (input.policyIds.length > 0) {
          const policies = await db.query.policies.findMany({
            where: and(
              eq(schema.policies.appId, input.appId),
              sql`${schema.policies.id} = ANY(ARRAY[${sql.join(
                input.policyIds.map((id) => sql`${id}::uuid`),
                sql`, `
              )}])`
            ),
          })

          if (policies.length !== input.policyIds.length) {
            throw new Error('One or more policies not found in this app')
          }
        }

        // Delete existing wallet-policy associations
        await db.delete(schema.walletPolicies).where(eq(schema.walletPolicies.walletId, input.walletId))

        // Insert new associations
        if (input.policyIds.length > 0) {
          await db.insert(schema.walletPolicies).values(
            input.policyIds.map((policyId) => ({
              walletId: input.walletId,
              policyId,
            }))
          )
        }

        return { success: true }
      }),
  }),

  // ==================== Policies ====================
  policies: createTRPCRouter({
    list: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          limit: z.number().min(1).max(100).optional().default(50),
          chainType: z.string().optional(),
        })
      )
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const conditions = [eq(schema.policies.appId, input.appId)]
        if (input.chainType) {
          conditions.push(eq(schema.policies.chainType, input.chainType))
        }

        const policyList = await db.query.policies.findMany({
          where: and(...conditions),
          orderBy: desc(schema.policies.createdAt),
          limit: input.limit,
        })

        return {
          data: policyList.map((p) => ({
            ...p,
            rules: (p.rules as schema.PolicyRules).rules ?? [],
            created_at: p.createdAt.getTime(),
          })),
        }
      }),

    get: protectedProcedure
      .input(z.object({ appId: z.string(), id: z.string() }))
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const policy = await db.query.policies.findFirst({
          where: and(eq(schema.policies.id, input.id), eq(schema.policies.appId, input.appId)),
        })

        if (!policy) {
          throw new Error('Policy not found')
        }

        return {
          ...policy,
          rules: (policy.rules as schema.PolicyRules).rules ?? [],
          created_at: policy.createdAt.getTime(),
        }
      }),

    create: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          name: z.string(),
          chainType: z.string().optional().default('ethereum'),
          version: z.string().optional().default('1.0'),
          rules: z.array(
            z.object({
              name: z.string(),
              method: z.string(),
              conditions: z.array(
                z.object({
                  field_source: z.string(),
                  field: z.string(),
                  operator: z.string(),
                  value: z.unknown(),
                })
              ),
              action: z.enum(['ALLOW', 'DENY']),
            })
          ),
          ownerId: z.string().optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const { role, walletUser } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        const [policy] = await db
          .insert(schema.policies)
          .values({
            name: input.name,
            chainType: input.chainType,
            version: input.version,
            rules: { rules: input.rules },
            ownerId: input.ownerId ?? walletUser.id,
            appId: input.appId,
          })
          .returning()

        return {
          ...policy,
          rules: input.rules,
          created_at: policy.createdAt.getTime(),
        }
      }),

    update: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          id: z.string(),
          name: z.string().optional(),
          rules: z
            .array(
              z.object({
                name: z.string(),
                method: z.string(),
                conditions: z.array(
                  z.object({
                    field_source: z.string(),
                    field: z.string(),
                    operator: z.string(),
                    value: z.unknown(),
                  })
                ),
                action: z.enum(['ALLOW', 'DENY']),
              })
            )
            .optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const { role } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        const updateData: Partial<typeof schema.policies.$inferInsert> = {}
        if (input.name) updateData.name = input.name
        if (input.rules) updateData.rules = { rules: input.rules }

        const [policy] = await db
          .update(schema.policies)
          .set(updateData)
          .where(and(eq(schema.policies.id, input.id), eq(schema.policies.appId, input.appId)))
          .returning()

        if (!policy) {
          throw new Error('Policy not found')
        }

        return {
          ...policy,
          rules: (policy.rules as schema.PolicyRules).rules ?? [],
          created_at: policy.createdAt.getTime(),
        }
      }),

    delete: protectedProcedure
      .input(z.object({ appId: z.string(), id: z.string() }))
      .mutation(async ({ ctx, input }) => {
        const { role } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        await db.delete(schema.policies).where(and(eq(schema.policies.id, input.id), eq(schema.policies.appId, input.appId)))

        return { success: true }
      }),
  }),

  // ==================== Authorization Keys ====================
  authorizationKeys: createTRPCRouter({
    list: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          limit: z.number().min(1).max(100).optional().default(50),
          status: z.enum(['active', 'rotated', 'revoked']).optional(),
        })
      )
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const conditions = [eq(schema.authorizationKeys.appId, input.appId)]
        if (input.status) {
          conditions.push(eq(schema.authorizationKeys.status, input.status))
        }

        const keys = await db.query.authorizationKeys.findMany({
          where: and(...conditions),
          orderBy: desc(schema.authorizationKeys.createdAt),
          limit: input.limit,
        })

        return {
          data: keys.map((k) => ({
            ...k,
            public_key: k.publicKey,
            owner_entity: k.ownerEntity,
            created_at: k.createdAt.getTime(),
            rotated_at: k.rotatedAt?.getTime(),
          })),
        }
      }),

    get: protectedProcedure
      .input(z.object({ appId: z.string(), id: z.string() }))
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const key = await db.query.authorizationKeys.findFirst({
          where: and(eq(schema.authorizationKeys.id, input.id), eq(schema.authorizationKeys.appId, input.appId)),
        })

        if (!key) {
          throw new Error('Authorization key not found')
        }

        return {
          ...key,
          public_key: key.publicKey,
          owner_entity: key.ownerEntity,
          created_at: key.createdAt.getTime(),
          rotated_at: key.rotatedAt?.getTime(),
        }
      }),

    create: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          publicKey: z.string(),
          ownerEntity: z.string().optional().default('dashboard'),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const { role } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        const [key] = await db
          .insert(schema.authorizationKeys)
          .values({
            publicKey: input.publicKey,
            ownerEntity: input.ownerEntity,
            appId: input.appId,
          })
          .returning()

        return {
          ...key,
          public_key: key.publicKey,
          owner_entity: key.ownerEntity,
          created_at: key.createdAt.getTime(),
        }
      }),

    revoke: protectedProcedure
      .input(z.object({ appId: z.string(), id: z.string() }))
      .mutation(async ({ ctx, input }) => {
        const { role } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        await db
          .update(schema.authorizationKeys)
          .set({ status: 'revoked' })
          .where(and(eq(schema.authorizationKeys.id, input.id), eq(schema.authorizationKeys.appId, input.appId)))

        return { success: true }
      }),
  }),

  // ==================== Condition Sets ====================
  conditionSets: createTRPCRouter({
    list: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          limit: z.number().min(1).max(100).optional().default(50),
        })
      )
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const sets = await db.query.conditionSets.findMany({
          where: eq(schema.conditionSets.appId, input.appId),
          orderBy: desc(schema.conditionSets.createdAt),
          limit: input.limit,
        })

        return {
          data: sets.map((s) => ({
            ...s,
            owner_id: s.ownerId,
            created_at: s.createdAt.getTime(),
            updated_at: s.updatedAt.getTime(),
          })),
        }
      }),

    get: protectedProcedure
      .input(z.object({ appId: z.string(), id: z.string() }))
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const set = await db.query.conditionSets.findFirst({
          where: and(eq(schema.conditionSets.id, input.id), eq(schema.conditionSets.appId, input.appId)),
        })

        if (!set) {
          throw new Error('Condition set not found')
        }

        return {
          ...set,
          owner_id: set.ownerId,
          created_at: set.createdAt.getTime(),
          updated_at: set.updatedAt.getTime(),
        }
      }),

    create: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          name: z.string(),
          description: z.string().optional(),
          values: z.array(z.unknown()),
          ownerId: z.string().optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const { role, walletUser } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        const [set] = await db
          .insert(schema.conditionSets)
          .values({
            name: input.name,
            description: input.description,
            values: input.values,
            ownerId: input.ownerId ?? walletUser.id,
            appId: input.appId,
          })
          .returning()

        return {
          ...set,
          owner_id: set.ownerId,
          created_at: set.createdAt.getTime(),
          updated_at: set.updatedAt.getTime(),
        }
      }),

    update: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          id: z.string(),
          name: z.string().optional(),
          description: z.string().optional(),
          values: z.array(z.unknown()).optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const { role } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        const updateData: Partial<typeof schema.conditionSets.$inferInsert> = {
          updatedAt: new Date(),
        }
        if (input.name) updateData.name = input.name
        if (input.description !== undefined) updateData.description = input.description
        if (input.values) updateData.values = input.values

        const [set] = await db
          .update(schema.conditionSets)
          .set(updateData)
          .where(and(eq(schema.conditionSets.id, input.id), eq(schema.conditionSets.appId, input.appId)))
          .returning()

        if (!set) {
          throw new Error('Condition set not found')
        }

        return {
          ...set,
          owner_id: set.ownerId,
          created_at: set.createdAt.getTime(),
          updated_at: set.updatedAt.getTime(),
        }
      }),

    delete: protectedProcedure
      .input(z.object({ appId: z.string(), id: z.string() }))
      .mutation(async ({ ctx, input }) => {
        const { role } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        await db
          .delete(schema.conditionSets)
          .where(and(eq(schema.conditionSets.id, input.id), eq(schema.conditionSets.appId, input.appId)))

        return { success: true }
      }),
  }),

  // ==================== Audit Logs ====================
  auditLogs: createTRPCRouter({
    list: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          limit: z.number().min(1).max(100).optional().default(50),
          actor: z.string().optional(),
          action: z.string().optional(),
          resourceType: z.string().optional(),
        })
      )
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const conditions = [eq(schema.auditLogs.appId, input.appId)]
        if (input.actor) conditions.push(eq(schema.auditLogs.actor, input.actor))
        if (input.action) conditions.push(eq(schema.auditLogs.action, input.action))
        if (input.resourceType) conditions.push(eq(schema.auditLogs.resourceType, input.resourceType))

        const logs = await db.query.auditLogs.findMany({
          where: and(...conditions),
          orderBy: desc(schema.auditLogs.createdAt),
          limit: input.limit,
        })

        return {
          data: logs.map((l) => ({
            ...l,
            resource_type: l.resourceType,
            resource_id: l.resourceId,
            policy_result: l.policyResult,
            signer_id: l.signerId,
            tx_hash: l.txHash,
            request_digest: l.requestDigest,
            client_ip: l.clientIp,
            user_agent: l.userAgent,
            app_id: l.appId,
            created_at: l.createdAt.getTime(),
          })),
        }
      }),
  }),

  // ==================== External Users ====================
  users: createTRPCRouter({
    list: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          limit: z.number().min(1).max(100).optional().default(50),
        })
      )
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const userList = await db.query.users.findMany({
          where: eq(schema.users.appId, input.appId),
          orderBy: desc(schema.users.createdAt),
          limit: input.limit,
        })

        // Get wallet counts for each user
        const usersWithWalletCounts = await Promise.all(
          userList.map(async (u) => {
            const walletCount = await db
              .select({ count: sql<number>`count(*)` })
              .from(schema.wallets)
              .where(eq(schema.wallets.userId, u.id))
            return {
              id: u.id,
              external_sub: u.externalSub,
              created_at: u.createdAt.getTime(),
              wallet_count: Number(walletCount[0]?.count ?? 0),
            }
          })
        )

        return { data: usersWithWalletCounts }
      }),

    get: protectedProcedure
      .input(z.object({ appId: z.string(), id: z.string() }))
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const user = await db.query.users.findFirst({
          where: and(eq(schema.users.id, input.id), eq(schema.users.appId, input.appId)),
        })

        if (!user) {
          throw new Error('User not found')
        }

        // Get user's wallets
        const userWallets = await db.query.wallets.findMany({
          where: eq(schema.wallets.userId, user.id),
          orderBy: desc(schema.wallets.createdAt),
        })

        return {
          id: user.id,
          external_sub: user.externalSub,
          created_at: user.createdAt.getTime(),
          wallets: userWallets.map((w) => ({
            id: w.id,
            address: w.address,
            chain_type: w.chainType,
            created_at: w.createdAt.getTime(),
          })),
        }
      }),
  }),

  // ==================== Session Signers ====================
  sessionSigners: createTRPCRouter({
    list: protectedProcedure
      .input(z.object({ appId: z.string(), walletId: z.string() }))
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        // Verify wallet belongs to this app
        const wallet = await db.query.wallets.findFirst({
          where: and(eq(schema.wallets.id, input.walletId), eq(schema.wallets.appId, input.appId)),
        })

        if (!wallet) {
          throw new Error('Wallet not found')
        }

        const signers = await db.query.sessionSigners.findMany({
          where: eq(schema.sessionSigners.walletId, input.walletId),
          orderBy: desc(schema.sessionSigners.createdAt),
        })

        return signers.map((s) => ({
          id: s.id,
          signer_public_key: s.signerId,
          policy_override_id: s.policyOverrideId,
          allowed_methods: s.allowedMethods,
          max_value: s.maxValue,
          max_txs: s.maxTxs,
          ttl_expires_at: s.ttlExpiresAt.toISOString(),
          created_at: s.createdAt.toISOString(),
          revoked_at: s.revokedAt?.toISOString(),
        }))
      }),

    delete: protectedProcedure
      .input(z.object({ appId: z.string(), walletId: z.string(), signerId: z.string() }))
      .mutation(async ({ ctx, input }) => {
        const { role } = await checkAppAccess(ctx.session.user.id, input.appId)
        if (role === 'viewer') {
          throw new Error('Permission denied')
        }

        // Verify wallet belongs to this app
        const wallet = await db.query.wallets.findFirst({
          where: and(eq(schema.wallets.id, input.walletId), eq(schema.wallets.appId, input.appId)),
        })

        if (!wallet) {
          throw new Error('Wallet not found')
        }

        // Revoke by setting revokedAt
        await db
          .update(schema.sessionSigners)
          .set({ revokedAt: new Date() })
          .where(and(eq(schema.sessionSigners.id, input.signerId), eq(schema.sessionSigners.walletId, input.walletId)))

        return { success: true }
      }),
  }),

  // ==================== Policy Testing ====================
  policyTest: createTRPCRouter({
    simulate: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          // Policy rules to test
          rules: z.array(
            z.object({
              name: z.string(),
              method: z.string(),
              conditions: z.array(
                z.object({
                  field_source: z.string(),
                  field: z.string(),
                  operator: z.string(),
                  value: z.unknown(),
                })
              ),
              action: z.enum(['ALLOW', 'DENY']),
            })
          ),
          // Test context
          testContext: z.object({
            method: z.string(), // eth_sendTransaction, eth_signTypedData_v4, etc.
            chainType: z.string().optional().default('ethereum'),
            // Transaction fields
            to: z.string().optional(),
            value: z.string().optional(), // wei as string
            data: z.string().optional(), // hex calldata
            chainId: z.number().optional(),
            // For decoded calldata
            decodedCalldata: z.record(z.string(), z.unknown()).optional(),
            // For typed data
            typedDataDomain: z.record(z.string(), z.unknown()).optional(),
            typedDataMessage: z.record(z.string(), z.unknown()).optional(),
            // For personal sign
            personalMessage: z.string().optional(),
          }),
        })
      )
      .mutation(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        // Simulate policy evaluation on the frontend
        // This mimics the Go backend's policy engine logic
        const { rules, testContext } = input

        interface MatchResult {
          ruleIndex: number
          ruleName: string
          action: 'ALLOW' | 'DENY'
          matchedConditions: string[]
        }

        const results: {
          decision: 'ALLOW' | 'DENY'
          reason: string
          matchedRule: MatchResult | null
          evaluationTrace: { rule: string; matched: boolean; reason: string }[]
        } = {
          decision: 'DENY',
          reason: 'No policy rule explicitly allows this action',
          matchedRule: null,
          evaluationTrace: [],
        }

        // Evaluate each rule
        for (let i = 0; i < rules.length; i++) {
          const rule = rules[i]

          // Check method match
          if (rule.method !== '*' && rule.method !== testContext.method) {
            results.evaluationTrace.push({
              rule: rule.name,
              matched: false,
              reason: `Method mismatch: rule expects "${rule.method}", got "${testContext.method}"`,
            })
            continue
          }

          // Evaluate conditions
          let allConditionsMatch = true
          const matchedConditions: string[] = []
          let failReason = ''

          for (const condition of rule.conditions) {
            const fieldValue = getFieldValue(condition.field_source, condition.field, testContext)
            const conditionResult = evaluateCondition(condition.operator, fieldValue, condition.value)

            if (conditionResult.matched) {
              matchedConditions.push(`${condition.field_source}.${condition.field} ${condition.operator} ${JSON.stringify(condition.value)}`)
            } else {
              allConditionsMatch = false
              failReason = `Condition failed: ${condition.field_source}.${condition.field} ${condition.operator} ${JSON.stringify(condition.value)} (actual: ${JSON.stringify(fieldValue)})`
              break
            }
          }

          if (allConditionsMatch) {
            results.decision = rule.action
            results.reason = `Matched rule: ${rule.name}`
            results.matchedRule = {
              ruleIndex: i,
              ruleName: rule.name,
              action: rule.action,
              matchedConditions,
            }
            results.evaluationTrace.push({
              rule: rule.name,
              matched: true,
              reason: `All conditions matched, action: ${rule.action}`,
            })
            break // First matching rule wins
          } else {
            results.evaluationTrace.push({
              rule: rule.name,
              matched: false,
              reason: failReason,
            })
          }
        }

        return results
      }),
  }),

  // ==================== Transactions ====================
  transactions: createTRPCRouter({
    list: protectedProcedure
      .input(
        z.object({
          appId: z.string(),
          limit: z.number().min(1).max(100).optional().default(50),
          status: z.enum(['pending', 'submitted', 'confirmed', 'failed']).optional(),
          walletId: z.string().optional(),
        })
      )
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const conditions = [eq(schema.transactions.appId, input.appId)]
        if (input.status) {
          conditions.push(eq(schema.transactions.status, input.status))
        }
        if (input.walletId) {
          conditions.push(eq(schema.transactions.walletId, input.walletId))
        }

        const txList = await db.query.transactions.findMany({
          where: and(...conditions),
          orderBy: desc(schema.transactions.createdAt),
          limit: input.limit,
        })

        // Get wallet addresses for each transaction
        const walletIds = [...new Set(txList.map((tx) => tx.walletId))]
        const walletMap = new Map<string, string>()

        if (walletIds.length > 0) {
          const walletsData = await db.query.wallets.findMany({
            where: sql`${schema.wallets.id} = ANY(ARRAY[${sql.join(
              walletIds.map((id) => sql`${id}::uuid`),
              sql`, `
            )}])`,
          })
          for (const w of walletsData) {
            walletMap.set(w.id, w.address)
          }
        }

        return {
          data: txList.map((tx) => ({
            id: tx.id,
            wallet_id: tx.walletId,
            wallet_address: walletMap.get(tx.walletId) ?? '',
            chain_id: tx.chainId,
            tx_hash: tx.txHash,
            status: tx.status,
            method: tx.method,
            to_address: tx.toAddress,
            value: tx.value,
            data: tx.data,
            nonce: tx.nonce,
            gas_limit: tx.gasLimit,
            max_fee_per_gas: tx.maxFeePerGas,
            max_priority_fee_per_gas: tx.maxPriorityFeePerGas,
            error_message: tx.errorMessage,
            created_at: tx.createdAt.getTime(),
            updated_at: tx.updatedAt.getTime(),
          })),
        }
      }),

    get: protectedProcedure
      .input(z.object({ appId: z.string(), id: z.string() }))
      .query(async ({ ctx, input }) => {
        await checkAppAccess(ctx.session.user.id, input.appId)

        const tx = await db.query.transactions.findFirst({
          where: and(eq(schema.transactions.id, input.id), eq(schema.transactions.appId, input.appId)),
        })

        if (!tx) {
          throw new Error('Transaction not found')
        }

        // Get wallet info
        const wallet = await db.query.wallets.findFirst({
          where: eq(schema.wallets.id, tx.walletId),
        })

        return {
          id: tx.id,
          wallet_id: tx.walletId,
          wallet_address: wallet?.address ?? '',
          chain_id: tx.chainId,
          tx_hash: tx.txHash,
          status: tx.status,
          method: tx.method,
          to_address: tx.toAddress,
          value: tx.value,
          data: tx.data,
          nonce: tx.nonce,
          gas_limit: tx.gasLimit,
          max_fee_per_gas: tx.maxFeePerGas,
          max_priority_fee_per_gas: tx.maxPriorityFeePerGas,
          signed_tx: tx.signedTx,
          error_message: tx.errorMessage,
          created_at: tx.createdAt.getTime(),
          updated_at: tx.updatedAt.getTime(),
        }
      }),

    // Stats for analytics
    stats: protectedProcedure.input(z.object({ appId: z.string() })).query(async ({ ctx, input }) => {
      await checkAppAccess(ctx.session.user.id, input.appId)

      const [total, pending, submitted, confirmed, failed] = await Promise.all([
        db.select({ count: sql<number>`count(*)` }).from(schema.transactions).where(eq(schema.transactions.appId, input.appId)),
        db
          .select({ count: sql<number>`count(*)` })
          .from(schema.transactions)
          .where(and(eq(schema.transactions.appId, input.appId), eq(schema.transactions.status, 'pending'))),
        db
          .select({ count: sql<number>`count(*)` })
          .from(schema.transactions)
          .where(and(eq(schema.transactions.appId, input.appId), eq(schema.transactions.status, 'submitted'))),
        db
          .select({ count: sql<number>`count(*)` })
          .from(schema.transactions)
          .where(and(eq(schema.transactions.appId, input.appId), eq(schema.transactions.status, 'confirmed'))),
        db
          .select({ count: sql<number>`count(*)` })
          .from(schema.transactions)
          .where(and(eq(schema.transactions.appId, input.appId), eq(schema.transactions.status, 'failed'))),
      ])

      // Get daily transactions for last 7 days
      const sevenDaysAgo = new Date()
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7)

      const dailyTxs = await db.execute(sql`
        SELECT
          DATE(created_at) as date,
          COUNT(*) as count
        FROM transactions
        WHERE app_id = ${input.appId}::uuid
          AND created_at >= ${sevenDaysAgo.toISOString()}
        GROUP BY DATE(created_at)
        ORDER BY date ASC
      `)

      return {
        total: Number(total[0]?.count ?? 0),
        pending: Number(pending[0]?.count ?? 0),
        submitted: Number(submitted[0]?.count ?? 0),
        confirmed: Number(confirmed[0]?.count ?? 0),
        failed: Number(failed[0]?.count ?? 0),
        daily: (dailyTxs as unknown as { date: string; count: string }[]).map((row) => ({
          date: row.date,
          count: Number(row.count),
        })),
      }
    }),
  }),
})
