import { TRPCError } from '@trpc/server'
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import { db } from '@/server/db'
import { appMembers, appSecrets, apps, walletUsers } from '@/server/db/schema'
import { createTRPCRouter, protectedProcedure } from '../trpc'

// Generate a random secret with prefix
function generateSecret(): { secret: string; prefix: string } {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let randomPart = ''
  for (let i = 0; i < 32; i++) {
    randomPart += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  const secret = `bw_sk_${randomPart}`
  const prefix = secret.substring(0, 8)
  return { secret, prefix }
}

// Simple hash function (in production, use bcrypt)
async function hashSecret(secret: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(secret)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

export const appSecretsRouter = createTRPCRouter({
  // List secrets for an app (only shows prefix, not the actual secret)
  list: protectedProcedure.input(z.object({ appId: z.string().uuid() })).query(async ({ ctx, input }) => {
    await checkAppAccess(ctx.user.id, input.appId, ['admin'])

    const secrets = await db
      .select({
        id: appSecrets.id,
        secretPrefix: appSecrets.secretPrefix,
        status: appSecrets.status,
        lastUsedAt: appSecrets.lastUsedAt,
        createdAt: appSecrets.createdAt,
        rotatedAt: appSecrets.rotatedAt,
        expiresAt: appSecrets.expiresAt,
      })
      .from(appSecrets)
      .where(eq(appSecrets.appId, input.appId))

    return secrets
  }),

  // Create a new secret for an app
  create: protectedProcedure.input(z.object({ appId: z.string().uuid() })).mutation(async ({ ctx, input }) => {
    await checkAppAccess(ctx.user.id, input.appId, ['admin'])

    const { secret, prefix } = generateSecret()
    const secretHash = await hashSecret(secret)

    const [newSecret] = await db
      .insert(appSecrets)
      .values({
        appId: input.appId,
        secretHash,
        secretPrefix: prefix,
      })
      .returning()

    // Return the full secret only on creation - it won't be shown again
    return {
      id: newSecret.id,
      secret, // Only returned on creation!
      secretPrefix: prefix,
      createdAt: newSecret.createdAt,
    }
  }),

  // Rotate a secret (creates new one, marks old as rotated)
  rotate: protectedProcedure.input(z.object({ id: z.string().uuid() })).mutation(async ({ ctx, input }) => {
    // Get the secret to find the app ID
    const existingSecret = await db.select().from(appSecrets).where(eq(appSecrets.id, input.id)).limit(1)

    if (!existingSecret[0]) {
      throw new TRPCError({ code: 'NOT_FOUND', message: 'Secret not found' })
    }

    await checkAppAccess(ctx.user.id, existingSecret[0].appId, ['admin'])

    // Mark old secret as rotated
    await db.update(appSecrets).set({ status: 'rotated', rotatedAt: new Date() }).where(eq(appSecrets.id, input.id))

    // Create new secret
    const { secret, prefix } = generateSecret()
    const secretHash = await hashSecret(secret)

    const [newSecret] = await db
      .insert(appSecrets)
      .values({
        appId: existingSecret[0].appId,
        secretHash,
        secretPrefix: prefix,
      })
      .returning()

    return {
      id: newSecret.id,
      secret, // Only returned on creation!
      secretPrefix: prefix,
      createdAt: newSecret.createdAt,
      rotatedFromId: input.id,
    }
  }),

  // Revoke a secret
  revoke: protectedProcedure.input(z.object({ id: z.string().uuid() })).mutation(async ({ ctx, input }) => {
    const existingSecret = await db.select().from(appSecrets).where(eq(appSecrets.id, input.id)).limit(1)

    if (!existingSecret[0]) {
      throw new TRPCError({ code: 'NOT_FOUND', message: 'Secret not found' })
    }

    await checkAppAccess(ctx.user.id, existingSecret[0].appId, ['admin'])

    await db.update(appSecrets).set({ status: 'revoked' }).where(eq(appSecrets.id, input.id))

    return { success: true }
  }),
})

// Helper to check if user has access to an app with required role
async function checkAppAccess(authUserId: string, appId: string, requiredRoles?: string[]) {
  // Get wallet user
  const walletUser = await db.select().from(walletUsers).where(eq(walletUsers.externalSub, authUserId)).limit(1)

  if (!walletUser[0]) {
    throw new TRPCError({ code: 'UNAUTHORIZED', message: 'User not found' })
  }

  // Check if owner
  const app = await db.select().from(apps).where(eq(apps.id, appId)).limit(1)

  if (!app[0]) {
    throw new TRPCError({ code: 'NOT_FOUND', message: 'App not found' })
  }

  if (app[0].ownerUserId === walletUser[0].id) {
    return // Owner has full access
  }

  // Check membership
  const membership = await db
    .select()
    .from(appMembers)
    .where(and(eq(appMembers.appId, appId), eq(appMembers.userId, walletUser[0].id)))
    .limit(1)

  if (!membership[0]) {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'Access denied' })
  }

  if (requiredRoles && !requiredRoles.includes(membership[0].role)) {
    throw new TRPCError({ code: 'FORBIDDEN', message: `Required role: ${requiredRoles.join(' or ')}` })
  }
}
