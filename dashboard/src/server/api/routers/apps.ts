import { TRPCError } from '@trpc/server'
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import { db } from '@/server/db'
import { appMembers, apps, walletUsers } from '@/server/db/schema'
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

export type AppSettings = z.infer<typeof appSettingsSchema>

export const appsRouter = createTRPCRouter({
  // List apps the user owns or is a member of
  list: protectedProcedure.query(async ({ ctx }) => {
    // First, find or create the wallet user based on the session user
    const walletUser = await getOrCreateWalletUser(ctx.user.id, ctx.user.email)

    // Get apps where user is owner
    const ownedApps = await db
      .select()
      .from(apps)
      .where(and(eq(apps.ownerUserId, walletUser.id), eq(apps.status, 'active')))

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
    const walletUser = await getOrCreateWalletUser(ctx.user.id, ctx.user.email)

    // Check if user is owner or member
    const app = await db.select().from(apps).where(eq(apps.id, input.id)).limit(1)

    if (!app[0]) {
      throw new TRPCError({ code: 'NOT_FOUND', message: 'App not found' })
    }

    // Check access
    const isOwner = app[0].ownerUserId === walletUser.id
    if (!isOwner) {
      const membership = await db
        .select()
        .from(appMembers)
        .where(and(eq(appMembers.appId, input.id), eq(appMembers.userId, walletUser.id)))
        .limit(1)

      if (!membership[0]) {
        throw new TRPCError({ code: 'FORBIDDEN', message: 'Access denied' })
      }
    }

    return app[0]
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
      const walletUser = await getOrCreateWalletUser(ctx.user.id, ctx.user.email)

      const [newApp] = await db
        .insert(apps)
        .values({
          name: input.name,
          description: input.description,
          ownerUserId: walletUser.id,
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
        settings: appSettingsSchema.optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const walletUser = await getOrCreateWalletUser(ctx.user.id, ctx.user.email)

      // Check ownership
      const app = await db.select().from(apps).where(eq(apps.id, input.id)).limit(1)

      if (!app[0]) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'App not found' })
      }

      if (app[0].ownerUserId !== walletUser.id) {
        // Check if user is admin member
        const membership = await db
          .select()
          .from(appMembers)
          .where(
            and(eq(appMembers.appId, input.id), eq(appMembers.userId, walletUser.id), eq(appMembers.role, 'admin'))
          )
          .limit(1)

        if (!membership[0]) {
          throw new TRPCError({ code: 'FORBIDDEN', message: 'Only owner or admin can update app' })
        }
      }

      const updateData: Partial<typeof apps.$inferInsert> = {
        updatedAt: new Date(),
      }

      if (input.name !== undefined) updateData.name = input.name
      if (input.description !== undefined) updateData.description = input.description
      if (input.settings !== undefined) updateData.settings = input.settings

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
      const walletUser = await getOrCreateWalletUser(ctx.user.id, ctx.user.email)

      const app = await db.select().from(apps).where(eq(apps.id, input.id)).limit(1)

      if (!app[0]) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'App not found' })
      }

      if (app[0].ownerUserId !== walletUser.id) {
        const membership = await db
          .select()
          .from(appMembers)
          .where(
            and(eq(appMembers.appId, input.id), eq(appMembers.userId, walletUser.id), eq(appMembers.role, 'admin'))
          )
          .limit(1)

        if (!membership[0]) {
          throw new TRPCError({ code: 'FORBIDDEN', message: 'Only owner or admin can update settings' })
        }
      }

      const [updatedApp] = await db
        .update(apps)
        .set({ settings: input.settings, updatedAt: new Date() })
        .where(eq(apps.id, input.id))
        .returning()

      return updatedApp
    }),

  // Delete an app (soft delete by setting status to 'deleted')
  delete: protectedProcedure.input(z.object({ id: z.string().uuid() })).mutation(async ({ ctx, input }) => {
    const walletUser = await getOrCreateWalletUser(ctx.user.id, ctx.user.email)

    // Only owner can delete
    const app = await db.select().from(apps).where(eq(apps.id, input.id)).limit(1)

    if (!app[0]) {
      throw new TRPCError({ code: 'NOT_FOUND', message: 'App not found' })
    }

    if (app[0].ownerUserId !== walletUser.id) {
      throw new TRPCError({ code: 'FORBIDDEN', message: 'Only owner can delete app' })
    }

    await db.update(apps).set({ status: 'deleted', updatedAt: new Date() }).where(eq(apps.id, input.id))

    return { success: true }
  }),
})

// Helper function to get or create wallet user from auth user
async function getOrCreateWalletUser(authUserId: string, email: string) {
  // Try to find existing wallet user by external_sub (auth user id)
  const existing = await db.select().from(walletUsers).where(eq(walletUsers.externalSub, authUserId)).limit(1)

  if (existing[0]) {
    return existing[0]
  }

  // Create new wallet user
  const [newUser] = await db
    .insert(walletUsers)
    .values({
      externalSub: authUserId,
    })
    .returning()

  return newUser
}
