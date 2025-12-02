import { and, desc, eq, sql } from 'drizzle-orm'
import { z } from 'zod'
import { db } from '@/server/db'
import * as schema from '@/server/db/schema'
import { createTRPCRouter, protectedProcedure } from '../trpc'

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

    const [walletsCount, policiesCount, usersCount] = await Promise.all([
      db.select({ count: sql<number>`count(*)` }).from(schema.wallets).where(eq(schema.wallets.appId, input.appId)),
      db.select({ count: sql<number>`count(*)` }).from(schema.policies).where(eq(schema.policies.appId, input.appId)),
      db.select({ count: sql<number>`count(*)` }).from(schema.users).where(eq(schema.users.appId, input.appId)),
    ])

    return {
      wallets_count: Number(walletsCount[0]?.count ?? 0),
      policies_count: Number(policiesCount[0]?.count ?? 0),
      users_count: Number(usersCount[0]?.count ?? 0),
      transactions_count: 0, // TODO: Add transactions table if needed
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
})
