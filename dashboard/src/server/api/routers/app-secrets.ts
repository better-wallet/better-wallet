import { TRPCError } from '@trpc/server'
import { eq } from 'drizzle-orm'
import { z } from 'zod'
import bcrypt from 'bcryptjs'
import { db } from '@/server/db'
import { appSecrets } from '@/server/db/schema'
import { createTRPCRouter, protectedProcedure } from '../trpc'
import { checkAppAccess, getOrCreateWalletUser } from './apps'

// Generate a random secret with prefix
// Note: The prefix must be exactly 14 characters to match the Go backend's lookup
// Go middleware takes secret[:14] for prefix lookup, so we store "bw_sk_" + 8 chars = 14 chars
function generateSecret(): { secret: string; prefix: string } {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let randomPart = ''
  for (let i = 0; i < 32; i++) {
    randomPart += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  const secret = `bw_sk_${randomPart}`
  // Store first 14 chars as prefix to match Go backend's lookup (secret[:14])
  const prefix = secret.substring(0, 14)
  return { secret, prefix }
}

// Hash secret using bcrypt to match Go backend
async function hashSecret(secret: string): Promise<string> {
  return bcrypt.hash(secret, 10)
}

export const appSecretsRouter = createTRPCRouter({
  // List secrets for an app (only shows prefix, not the actual secret)
  list: protectedProcedure.input(z.object({ appId: z.string().uuid() })).query(async ({ ctx, input }) => {
    const walletUser = await getOrCreateWalletUser(ctx.user.id)
    await checkAppAccess(input.appId, walletUser.id, ['owner', 'admin'])

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
    const walletUser = await getOrCreateWalletUser(ctx.user.id)
    await checkAppAccess(input.appId, walletUser.id, ['owner', 'admin'])

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

    const walletUser = await getOrCreateWalletUser(ctx.user.id)
    await checkAppAccess(existingSecret[0].appId, walletUser.id, ['owner', 'admin'])

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

    const walletUser = await getOrCreateWalletUser(ctx.user.id)
    await checkAppAccess(existingSecret[0].appId, walletUser.id, ['owner', 'admin'])

    await db.update(appSecrets).set({ status: 'revoked' }).where(eq(appSecrets.id, input.id))

    return { success: true }
  }),
})
