import { eq, and, desc } from 'drizzle-orm'
import { z } from 'zod'
import { TRPCError } from '@trpc/server'
import { randomBytes } from 'crypto'
import bcrypt from 'bcryptjs'
import { db } from '@/server/db'
import { principals, agentWallets, agentCredentials, type AgentCapabilities, type AgentLimits } from '@/server/db/schema'
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

// Helper to verify wallet belongs to principal
async function verifyWalletAccess(walletId: string, principalId: string) {
  const [wallet] = await db
    .select()
    .from(agentWallets)
    .where(and(
      eq(agentWallets.id, walletId),
      eq(agentWallets.principalId, principalId)
    ))
    .limit(1)
  return wallet
}

// Generate credential key: aw_ag_<prefix>.<secret>
function generateCredentialKey(): { fullKey: string; keyPrefix: string; keyHash: string } {
  const prefixId = randomBytes(9).toString('base64url').slice(0, 12)
  const secret = randomBytes(24).toString('base64url')
  const keyPrefix = `aw_ag_${prefixId}`
  const fullKey = `${keyPrefix}.${secret}`
  const keyHash = bcrypt.hashSync(secret, 10)
  return { fullKey, keyPrefix, keyHash }
}

const capabilitiesSchema = z.object({
  chains: z.array(z.string()).default([]),
  operations: z.array(z.string()).default([]),
  allowedContracts: z.array(z.string()).default([]),
  allowedMethods: z.array(z.string()).default([]),
})

const limitsSchema = z.object({
  maxValuePerTx: z.string().default(''),
  maxValuePerHour: z.string().default(''),
  maxValuePerDay: z.string().default(''),
  maxTxPerHour: z.number().int().min(0).default(0),
  maxTxPerDay: z.number().int().min(0).default(0),
})

export const agentCredentialsRouter = createTRPCRouter({
  // List credentials for a wallet
  list: protectedProcedure
    .input(z.object({ walletId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        return []
      }

      // Verify wallet access
      const wallet = await verifyWalletAccess(input.walletId, principal.id)
      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Wallet not found' })
      }

      const credentials = await db
        .select({
          id: agentCredentials.id,
          walletId: agentCredentials.walletId,
          name: agentCredentials.name,
          keyPrefix: agentCredentials.keyPrefix,
          capabilities: agentCredentials.capabilities,
          limits: agentCredentials.limits,
          status: agentCredentials.status,
          lastUsedAt: agentCredentials.lastUsedAt,
          createdAt: agentCredentials.createdAt,
          pausedAt: agentCredentials.pausedAt,
          revokedAt: agentCredentials.revokedAt,
        })
        .from(agentCredentials)
        .where(eq(agentCredentials.walletId, input.walletId))
        .orderBy(desc(agentCredentials.createdAt))

      return credentials
    }),

  // Get single credential
  get: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      const [credential] = await db
        .select()
        .from(agentCredentials)
        .where(eq(agentCredentials.id, input.id))
        .limit(1)

      if (!credential) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Credential not found' })
      }

      // Verify wallet access
      const wallet = await verifyWalletAccess(credential.walletId, principal.id)
      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Credential not found' })
      }

      return credential
    }),

  // Create new credential
  create: protectedProcedure
    .input(z.object({
      walletId: z.string().uuid(),
      name: z.string().min(1).max(100),
      capabilities: capabilitiesSchema,
      limits: limitsSchema,
    }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      // Verify wallet access
      const wallet = await verifyWalletAccess(input.walletId, principal.id)
      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Wallet not found' })
      }

      // Generate credential key
      const { fullKey, keyPrefix, keyHash } = generateCredentialKey()

      const [credential] = await db
        .insert(agentCredentials)
        .values({
          walletId: input.walletId,
          name: input.name,
          keyPrefix,
          keyHash,
          capabilities: input.capabilities as AgentCapabilities,
          limits: input.limits as AgentLimits,
          status: 'active',
        })
        .returning()

      // Return credential with full key (only shown once)
      return {
        ...credential!,
        credential: fullKey,
      }
    }),

  // Update credential
  update: protectedProcedure
    .input(z.object({
      id: z.string().uuid(),
      name: z.string().min(1).max(100).optional(),
      capabilities: capabilitiesSchema.optional(),
      limits: limitsSchema.optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      // Get credential
      const [credential] = await db
        .select()
        .from(agentCredentials)
        .where(eq(agentCredentials.id, input.id))
        .limit(1)

      if (!credential) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Credential not found' })
      }

      // Verify wallet access
      const wallet = await verifyWalletAccess(credential.walletId, principal.id)
      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Credential not found' })
      }

      const updateData: Record<string, unknown> = {}
      if (input.name) updateData.name = input.name
      if (input.capabilities) updateData.capabilities = input.capabilities
      if (input.limits) updateData.limits = input.limits

      const [updated] = await db
        .update(agentCredentials)
        .set(updateData)
        .where(eq(agentCredentials.id, input.id))
        .returning()

      return updated
    }),

  // Pause credential
  pause: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      // Get credential
      const [credential] = await db
        .select()
        .from(agentCredentials)
        .where(eq(agentCredentials.id, input.id))
        .limit(1)

      if (!credential) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Credential not found' })
      }

      // Verify wallet access
      const wallet = await verifyWalletAccess(credential.walletId, principal.id)
      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Credential not found' })
      }

      if (credential.status !== 'active') {
        throw new TRPCError({ code: 'BAD_REQUEST', message: 'Credential is not active' })
      }

      const [updated] = await db
        .update(agentCredentials)
        .set({
          status: 'paused',
          pausedAt: new Date(),
        })
        .where(eq(agentCredentials.id, input.id))
        .returning()

      return updated
    }),

  // Resume credential
  resume: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      // Get credential
      const [credential] = await db
        .select()
        .from(agentCredentials)
        .where(eq(agentCredentials.id, input.id))
        .limit(1)

      if (!credential) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Credential not found' })
      }

      // Verify wallet access
      const wallet = await verifyWalletAccess(credential.walletId, principal.id)
      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Credential not found' })
      }

      if (credential.status !== 'paused') {
        throw new TRPCError({ code: 'BAD_REQUEST', message: 'Credential is not paused' })
      }

      const [updated] = await db
        .update(agentCredentials)
        .set({
          status: 'active',
          pausedAt: null,
        })
        .where(eq(agentCredentials.id, input.id))
        .returning()

      return updated
    }),

  // Revoke credential (permanent)
  revoke: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      // Get credential
      const [credential] = await db
        .select()
        .from(agentCredentials)
        .where(eq(agentCredentials.id, input.id))
        .limit(1)

      if (!credential) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Credential not found' })
      }

      // Verify wallet access
      const wallet = await verifyWalletAccess(credential.walletId, principal.id)
      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Credential not found' })
      }

      if (credential.status === 'revoked') {
        throw new TRPCError({ code: 'BAD_REQUEST', message: 'Credential is already revoked' })
      }

      const [updated] = await db
        .update(agentCredentials)
        .set({
          status: 'revoked',
          revokedAt: new Date(),
        })
        .where(eq(agentCredentials.id, input.id))
        .returning()

      return updated
    }),
})
