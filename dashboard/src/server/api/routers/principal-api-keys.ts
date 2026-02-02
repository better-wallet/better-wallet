import { eq, desc, and } from 'drizzle-orm'
import { z } from 'zod'
import { TRPCError } from '@trpc/server'
import { randomBytes } from 'crypto'
import bcrypt from 'bcryptjs'
import { db } from '@/server/db'
import { principals, principalApiKeys } from '@/server/db/schema'
import { createTRPCRouter, protectedProcedure } from '../trpc'

// Helper to get principal for current user
async function getPrincipalForUser(email: string) {
  const [principal] = await db
    .select()
    .from(principals)
    .where(eq(principals.email, email))
    .limit(1)
  return principal
}

// Generate API key: aw_pk_<prefix>.<secret>
function generateApiKey(): { fullKey: string; keyPrefix: string; keyHash: string } {
  const prefixId = randomBytes(9).toString('base64url').slice(0, 12)
  const secret = randomBytes(24).toString('base64url')
  const keyPrefix = `aw_pk_${prefixId}`
  const fullKey = `${keyPrefix}.${secret}`
  const keyHash = bcrypt.hashSync(secret, 10)
  return { fullKey, keyPrefix, keyHash }
}

export const principalApiKeysRouter = createTRPCRouter({
  // List API keys for current principal
  list: protectedProcedure.query(async ({ ctx }) => {
    const principal = await getPrincipalForUser(ctx.user.email!)
    if (!principal) {
      return []
    }

    const keys = await db
      .select({
        id: principalApiKeys.id,
        principalId: principalApiKeys.principalId,
        keyPrefix: principalApiKeys.keyPrefix,
        name: principalApiKeys.name,
        status: principalApiKeys.status,
        lastUsedAt: principalApiKeys.lastUsedAt,
        createdAt: principalApiKeys.createdAt,
        revokedAt: principalApiKeys.revokedAt,
      })
      .from(principalApiKeys)
      .where(eq(principalApiKeys.principalId, principal.id))
      .orderBy(desc(principalApiKeys.createdAt))

    return keys
  }),

  // Create new API key
  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(100),
    }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      // Generate API key
      const { fullKey, keyPrefix, keyHash } = generateApiKey()

      const [apiKey] = await db
        .insert(principalApiKeys)
        .values({
          principalId: principal.id,
          keyPrefix,
          keyHash,
          name: input.name,
          status: 'active',
        })
        .returning()

      // Return with full key (only shown once)
      return {
        ...apiKey!,
        apiKey: fullKey,
      }
    }),

  // Revoke API key
  revoke: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      const [updated] = await db
        .update(principalApiKeys)
        .set({
          status: 'revoked',
          revokedAt: new Date(),
        })
        .where(and(
          eq(principalApiKeys.id, input.id),
          eq(principalApiKeys.principalId, principal.id)
        ))
        .returning()

      if (!updated) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'API key not found' })
      }

      return updated
    }),
})
