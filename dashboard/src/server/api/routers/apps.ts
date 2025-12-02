import { TRPCError } from '@trpc/server'
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import { db } from '@/server/db'
import { type AppSettings, appMembers, apps, walletUsers } from '@/server/db/schema'
import { createTRPCRouter, protectedProcedure } from '../trpc'

// App Settings schema
const appAuthSettingsSchema = z.object({
  kind: z.enum(['oidc', 'jwt']),
  issuer: z.string().url(),
  audience: z.string(),
  jwks_uri: z.string().url(),
})

const appRPCSettingsSchema = z.object({
  endpoints: z.record(z.string(), z.string().url()),
})

const appRateLimitSettingsSchema = z.object({
  qps: z.number().int().positive(),
})

const appSettingsSchema = z.object({
  auth: appAuthSettingsSchema.optional(),
  rpc: appRPCSettingsSchema.optional(),
  rate_limit: appRateLimitSettingsSchema.optional(),
})

// Helper function to get or create wallet user from auth user
async function getOrCreateWalletUser(dashboardUserId: string) {
  const existing = await db.select().from(walletUsers).where(eq(walletUsers.dashboardUserId, dashboardUserId)).limit(1)

  if (existing[0]) {
    return existing[0]
  }

  const [newUser] = await db
    .insert(walletUsers)
    .values({
      dashboardUserId,
    })
    .returning()

  return newUser
}

// Helper to check app access
async function checkAppAccess(
  appId: string,
  walletUserId: string,
  requiredRoles?: string[]
): Promise<{ app: typeof apps.$inferSelect; role: 'owner' | 'admin' | 'developer' | 'viewer' }> {
  const app = await db.select().from(apps).where(eq(apps.id, appId)).limit(1)

  if (!app[0]) {
    throw new TRPCError({ code: 'NOT_FOUND', message: 'App not found' })
  }

  if (app[0].status === 'deleted') {
    throw new TRPCError({ code: 'NOT_FOUND', message: 'App not found' })
  }

  // Check if owner
  if (app[0].ownerId === walletUserId) {
    return { app: app[0], role: 'owner' }
  }

  // Check membership
  const membership = await db
    .select()
    .from(appMembers)
    .where(and(eq(appMembers.appId, appId), eq(appMembers.userId, walletUserId)))
    .limit(1)

  if (!membership[0]) {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'Access denied' })
  }

  const role = membership[0].role as 'admin' | 'developer' | 'viewer'

  if (requiredRoles && !requiredRoles.includes(role) && !requiredRoles.includes('owner')) {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'Insufficient permissions' })
  }

  return { app: app[0], role }
}

export const appsRouter = createTRPCRouter({
  // List apps the user owns or is a member of
  list: protectedProcedure.query(async ({ ctx }) => {
    const walletUser = await getOrCreateWalletUser(ctx.user.id)

    // Get apps where user is owner
    const ownedApps = await db
      .select()
      .from(apps)
      .where(and(eq(apps.ownerId, walletUser.id), eq(apps.status, 'active')))

    // Get apps where user is a member
    const memberApps = await db
      .select({
        app: apps,
        role: appMembers.role,
      })
      .from(appMembers)
      .innerJoin(apps, eq(appMembers.appId, apps.id))
      .where(and(eq(appMembers.userId, walletUser.id), eq(apps.status, 'active')))

    return {
      owned: ownedApps,
      member: memberApps.map((m) => ({
        ...m.app,
        memberRole: m.role,
      })),
    }
  }),

  // Get a specific app by ID
  get: protectedProcedure.input(z.object({ id: z.string().uuid() })).query(async ({ ctx, input }) => {
    const walletUser = await getOrCreateWalletUser(ctx.user.id)
    const { app, role } = await checkAppAccess(input.id, walletUser.id)
    return { ...app, role }
  }),

  // Create a new app
  create: protectedProcedure
    .input(
      z.object({
        name: z.string().min(1).max(100),
        description: z.string().max(500).optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const walletUser = await getOrCreateWalletUser(ctx.user.id)

      const [newApp] = await db
        .insert(apps)
        .values({
          name: input.name,
          description: input.description,
          ownerId: walletUser.id,
        })
        .returning()

      return newApp
    }),

  // Update an app
  update: protectedProcedure
    .input(
      z.object({
        id: z.string().uuid(),
        name: z.string().min(1).max(100).optional(),
        description: z.string().max(500).optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const walletUser = await getOrCreateWalletUser(ctx.user.id)
      await checkAppAccess(input.id, walletUser.id, ['owner', 'admin'])

      const updateData: Partial<typeof apps.$inferInsert> = {
        updatedAt: new Date(),
      }

      if (input.name !== undefined) updateData.name = input.name
      if (input.description !== undefined) updateData.description = input.description

      const [updatedApp] = await db.update(apps).set(updateData).where(eq(apps.id, input.id)).returning()

      return updatedApp
    }),

  // Update app settings (auth, rpc, rate_limit)
  updateSettings: protectedProcedure
    .input(
      z.object({
        id: z.string().uuid(),
        settings: appSettingsSchema,
      })
    )
    .mutation(async ({ ctx, input }) => {
      const walletUser = await getOrCreateWalletUser(ctx.user.id)
      await checkAppAccess(input.id, walletUser.id, ['owner', 'admin'])

      const [updatedApp] = await db
        .update(apps)
        .set({ settings: input.settings as AppSettings, updatedAt: new Date() })
        .where(eq(apps.id, input.id))
        .returning()

      return updatedApp
    }),

  // Delete an app (soft delete)
  delete: protectedProcedure.input(z.object({ id: z.string().uuid() })).mutation(async ({ ctx, input }) => {
    const walletUser = await getOrCreateWalletUser(ctx.user.id)
    const { role } = await checkAppAccess(input.id, walletUser.id, ['owner'])

    if (role !== 'owner') {
      throw new TRPCError({ code: 'FORBIDDEN', message: 'Only owner can delete app' })
    }

    await db.update(apps).set({ status: 'deleted', updatedAt: new Date() }).where(eq(apps.id, input.id))

    return { success: true }
  }),
})

// Export helper for other routers
export { getOrCreateWalletUser, checkAppAccess }
